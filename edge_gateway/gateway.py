"""
Edge gateway - the pivot of the whole modernization.

WHAT THIS IS
    A small Linux box physically near the devices. It terminates the legacy
    device protocol on one side and talks HTTP to the cloud on the other, with
    one thread per connected device.

WHY IT EXISTS AT ALL
    Devices this constrained cannot talk to the internet safely or efficiently:
    no TLS stack, no DNS, no retry logic worth the name. A gateway does that
    work on their behalf and aggregates many devices onto one uplink.

WHY IT MATTERS FOR THIS PROJECT
    The gateway is the only component in the chain that we can actually
    upgrade. The devices cannot be re-flashed, so post-quantum key
    establishment has to terminate here:

        device  --legacy AES-PSK-->  GATEWAY  --ML-KEM + AES-GCM-->  cloud
                  (never changes)    (upgraded)

    The gateway becomes a crypto-translating proxy. The long-haul hop - the one
    an attacker can realistically record today and decrypt in twenty years -
    becomes quantum-safe, while the short local hop stays legacy and is
    documented as accepted residual risk.

HOW IT TALKS TO THE CLOUD (--crypto)
    mlkem   (default) PqcUplink: ML-KEM-768 handshake, then every reading is
            sealed with AES-256-GCM. See pqc_channel/channel.py.
    legacy  LegacyUplink: the original plain JSON + static token path, kept
            only so an operator can roll back during the migration.

    FALLBACK POLICY: the gateway never switches from mlkem to legacy on its
    own. If the handshake fails, readings are counted as failed and dropped,
    exactly as when the cloud is down. An automatic fallback would let any
    attacker who can block the handshake force traffic back onto the weak
    path (a downgrade attack), which would defeat the migration. Falling back
    is a deliberate operator decision: restart with --crypto legacy.

WHAT IS STILL MISSING (known technical debt, tracked in README.md)
    * No store-and-forward queue: readings are lost when the cloud is down.
    * No TLS to the cloud. The v2 channel protects reading payloads itself,
      but the gateway's identity is still one static shared token (proved,
      not sent, on the v2 path).
    * Without --cloud-key-fingerprint the gateway trusts whichever cloud key
      it sees first (trust on first use), which a man in the middle present
      at that moment could exploit. Always pin in a real deployment.
    * Replay state is in memory only, so a restart forgets every sequence
      number and briefly drops traffic from devices that keep counting.

OBSERVABILITY
    /health and /metrics on a separate HTTP port (9100 by default, see
    admin.py). Logs are one JSON object per line with LOG_FORMAT=json.

Run:
    python -m edge_gateway.gateway --cloud-url http://127.0.0.1:8000
    python -m edge_gateway.gateway --cloud-key-fingerprint <hex from cloud /health>
"""

import argparse
import hmac
import json
import logging
import os
import socketserver
import threading
import time
from dataclasses import dataclass, field

import requests

# Imported rather than duplicated so there is exactly one definition of the
# wire format. It does couple two separately deployable services, which is
# weakness 8 in README.md; the fix is to extract a shared package, and we have
# deliberately left it visible rather than hiding it.
from legacy_device.protocol import decrypt_frame, parse_reading
from observability import logs
from pqc_channel import channel

log = logging.getLogger("edge-gateway")

# Static token shared with the cloud service. More legacy debt: one string for
# every gateway, no rotation, no per-gateway identity. On the legacy path it is
# sent in clear in an X-Gateway-Token header, so anyone who sees one request
# can inject telemetry. On the ML-KEM path it only feeds an HMAC inside the
# handshake and never leaves the gateway.
#
# Read from the environment so a deployment can set it without editing code,
# matching the cloud service.
GATEWAY_TOKEN = os.environ.get("GATEWAY_TOKEN", "legacy-gateway-token")

# Give up on a cloud request rather than holding a device thread open forever.
CLOUD_TIMEOUT_S = 5.0

# Frame-size ceiling on the gateway side. Deliberately larger than the
# device's 256-byte buffer: the gateway is not memory-constrained, and a
# generous limit here means a misbehaving or hostile client is bounded without
# rejecting anything a legitimate device could send.
MAX_FRAME_BYTES = 4096


@dataclass
class GatewayStats:
    """Counters describing what passed through this gateway.

    These are the numbers that become Prometheus metrics in the operations
    phase. Keeping them in one object now means adding a /metrics endpoint
    later is a rendering change, not a refactor.

    Every device runs on its own thread, so all mutation goes through a lock.
    Without it, two threads incrementing the same counter can lose an update.
    """

    frames_received: int = 0
    frames_rejected: int = 0
    forwarded_ok: int = 0
    forward_failed: int = 0
    replays_dropped: int = 0
    # Post-quantum observability: a rising failure count is how an operator
    # would notice a pinning mismatch or a cloud key rotation gone wrong.
    handshakes_ok: int = 0
    handshakes_failed: int = 0

    # State for /health, beyond the plain counters.
    consecutive_forward_failures: int = 0
    last_forward_ok_at: float | None = None     # time.time()
    last_error: str | None = None
    handshake_seconds_sum: float = 0.0
    handshake_seconds_count: int = 0

    # repr=False keeps the lock out of log lines when the dataclass is printed.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def bump(self, name: str) -> None:
        """Increment one counter by name."""
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def forward_succeeded(self) -> None:
        with self._lock:
            self.forwarded_ok += 1
            self.consecutive_forward_failures = 0
            self.last_forward_ok_at = time.time()

    def forward_failed_with(self, error: Exception) -> None:
        with self._lock:
            self.forward_failed += 1
            self.consecutive_forward_failures += 1
            # Truncated: a long upstream error body has no place in /health.
            self.last_error = str(error)[:200]

    def handshake_succeeded(self, seconds: float) -> None:
        with self._lock:
            self.handshakes_ok += 1
            self.handshake_seconds_sum += seconds
            self.handshake_seconds_count += 1

    def state(self) -> dict:
        """The non-counter fields, for /health and /metrics."""
        with self._lock:
            return {
                "consecutive_forward_failures":
                    self.consecutive_forward_failures,
                "last_forward_ok_at": self.last_forward_ok_at,
                "last_error": self.last_error,
                "handshake_seconds_sum": self.handshake_seconds_sum,
                "handshake_seconds_count": self.handshake_seconds_count,
            }

    def snapshot(self) -> dict:
        """Return a consistent copy of all counters.

        Taken under the lock so a reader never sees a half-updated set, which
        would make the totals fail to add up in a report.
        """
        with self._lock:
            return {
                "frames_received": self.frames_received,
                "frames_rejected": self.frames_rejected,
                "forwarded_ok": self.forwarded_ok,
                "forward_failed": self.forward_failed,
                "replays_dropped": self.replays_dropped,
                "handshakes_ok": self.handshakes_ok,
                "handshakes_failed": self.handshakes_failed,
            }


class SequenceTracker:
    """Rejects frames whose sequence number has not increased.

    This is the baseline system's entire replay protection, and it is weak on
    purpose:

    * State is in memory, so a gateway restart forgets every device's
      high-water mark.
    * It is per-device and unbounded, so a hostile client can grow the dict by
      inventing device IDs.
    * It only proves ordering, not authenticity. Because frames are not
      authenticated, an attacker who can modify traffic can also rewrite the
      sequence number.

    Real authentication - AES-GCM with keys from ML-KEM - is what actually
    fixes this. We keep the tracker because it demonstrates the gap.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def accept(self, device_id: str, seq: int) -> bool:
        """Record and accept seq, or return False if it is stale.

        Returns:
            True if this sequence number is higher than anything seen from this
            device, False if it is a replay or arrives out of order.
        """
        with self._lock:
            last = self._seen.get(device_id)
            if last is not None and seq <= last:
                return False
            self._seen[device_id] = seq
            return True


class UplinkError(Exception):
    """The cloud could not be reached securely or rejected the reading."""


class LegacyUplink:
    """The original cloud path: plain JSON with the static token in a header.

    Kept unchanged so it remains an exact baseline and a rollback option.
    """

    name = "legacy"
    # The legacy path has no cloud key to pin at all.
    pin_configured = False

    def __init__(self, cloud_url: str) -> None:
        # rstrip so that "http://host:8000/" and "http://host:8000" both build
        # correct URLs below.
        self.cloud_url = cloud_url.rstrip("/")

    def send(self, reading: dict) -> None:
        """POST one reading. Raises requests.RequestException on failure."""
        response = requests.post(
            f"{self.cloud_url}/api/v1/telemetry",
            json=reading,
            headers={"X-Gateway-Token": GATEWAY_TOKEN},
            timeout=CLOUD_TIMEOUT_S,
        )
        # Covers 4xx and 5xx: a 401 from a wrong token must not be logged
        # as a success.
        response.raise_for_status()

    def session_info(self) -> None:
        """No session on the legacy path."""
        return None


@dataclass
class _PqcSession:
    """The gateway's half of one ML-KEM session."""

    session_id: str
    aead_key: bytes
    expires_at: float      # time.monotonic() deadline, renewed a bit early
    max_messages: int
    next_counter: int = 0


class PqcUplink:
    """The post-quantum cloud path: ML-KEM-768 handshake + AES-256-GCM.

    One instance is shared by every device thread. The lock makes sure only
    one thread performs a handshake at a time and that every message gets a
    unique counter, which is what keeps GCM nonces from ever repeating.
    """

    name = "mlkem"

    # Start a new handshake this long before the cloud would expire the
    # session, so a reading is never sent under a key that dies in transit.
    RENEW_MARGIN_S = 60

    def __init__(self, cloud_url: str, stats: GatewayStats,
                 pinned_fingerprint: str | None = None,
                 http=requests, token: str = GATEWAY_TOKEN) -> None:
        """
        Args:
            cloud_url: base URL of the cloud service.
            stats: counters to record handshake outcomes in.
            pinned_fingerprint: expected SHA-256 of the cloud's public key,
                as hex. None means trust on first use.
            http: anything with requests-style get() and post(). Tests pass
                FastAPI's TestClient here to run the real cloud in-process.
            token: the shared gateway token proved during the handshake.
        """
        self.cloud_url = cloud_url.rstrip("/")
        self.stats = stats
        self.pinned = pinned_fingerprint.lower() if pinned_fingerprint else None
        # Whether the operator configured a pin, as opposed to self.pinned
        # being filled in by trust on first use. Reported in /health.
        self.pin_configured = self.pinned is not None
        self.http = http
        self.token = token
        self._lock = threading.Lock()
        self._session: _PqcSession | None = None

    def send(self, reading: dict) -> None:
        """Seal one reading and POST it, re-handshaking once if needed.

        Raises:
            UplinkError: if no session can be established or the cloud
                rejects the message.
            requests.RequestException: if the cloud is unreachable.
        """
        plaintext = json.dumps(reading, separators=(",", ":")).encode()

        # At most two attempts: the second only happens when the cloud says
        # it no longer knows our session (it restarted, or the session hit
        # its limits), and a fresh handshake fixes that. Any other failure
        # would fail the same way again, so it is not retried.
        for attempt in (1, 2):
            session, counter = self._next_message()
            nonce, sealed = channel.seal(session.aead_key, counter,
                                         session.session_id, plaintext)
            response = self.http.post(
                f"{self.cloud_url}/api/v2/telemetry",
                json={
                    "session_id": session.session_id,
                    "nonce": channel.b64encode(nonce),
                    "ciphertext": channel.b64encode(sealed),
                },
                timeout=CLOUD_TIMEOUT_S,
            )
            if response.status_code == 401 and attempt == 1:
                log.info("cloud dropped session %s..., re-handshaking",
                         session.session_id[:8],
                         extra={"event": "session_dropped",
                                "session": session.session_id[:8]})
                self._invalidate(session)
                continue
            if response.status_code >= 400:
                raise UplinkError(f"cloud rejected sealed reading: "
                                  f"HTTP {response.status_code}")
            return

    def _next_message(self) -> tuple[_PqcSession, int]:
        """Return a usable session and a counter no other message will use."""
        with self._lock:
            session = self._session
            if (session is None
                    or time.monotonic() >= session.expires_at
                    or session.next_counter >= session.max_messages):
                session = self._session = self._handshake()
            counter = session.next_counter
            session.next_counter += 1
            return session, counter

    def session_info(self) -> dict | None:
        """The current session, for /health. Never includes key material."""
        with self._lock:
            session = self._session
            if session is None:
                return None
            remaining = session.expires_at - time.monotonic()
            return {
                "active": (remaining > 0
                           and session.next_counter < session.max_messages),
                "session": session.session_id[:8],
                "messages_sent": session.next_counter,
                "renews_in_s": max(0, int(remaining)),
            }

    def _invalidate(self, session: _PqcSession) -> None:
        """Forget a session the cloud has rejected.

        Only if it is still the current one: another thread may already have
        replaced it, and throwing away that fresh session would force a
        needless second handshake.
        """
        with self._lock:
            if self._session is session:
                self._session = None

    def _handshake(self) -> _PqcSession:
        """Run the ML-KEM handshake described in pqc_channel/channel.py.

        Caller must hold self._lock.
        """
        started = time.perf_counter()
        try:
            session = self._do_handshake()
        except (channel.ChannelError, requests.RequestException,
                KeyError, TypeError, ValueError) as exc:
            # KeyError / TypeError / ValueError cover a cloud response that
            # is not the JSON shape we expect, including non-JSON bodies.
            self.stats.bump("handshakes_failed")
            log.error("ML-KEM handshake failed: %s", exc,
                      extra={"event": "handshake_failed", "error": str(exc)})
            raise UplinkError(f"handshake failed: {exc}") from exc

        elapsed = time.perf_counter() - started
        self.stats.handshake_succeeded(elapsed)
        log.info("ML-KEM session %s... established in %.1f ms",
                 session.session_id[:8], elapsed * 1000,
                 extra={"event": "handshake_ok",
                        "session": session.session_id[:8],
                        "duration_ms": round(elapsed * 1000, 1)})
        return session

    def _do_handshake(self) -> _PqcSession:
        # 1. Fetch the cloud's public key and check it is the one we expect.
        response = self.http.get(f"{self.cloud_url}/api/v2/pqc/public-key",
                                 timeout=CLOUD_TIMEOUT_S)
        if response.status_code != 200:
            raise channel.ChannelError(
                f"public key request returned HTTP {response.status_code}")
        body = response.json()
        if body["algorithm"] != channel.ALGORITHM:
            raise channel.ChannelError(
                f"cloud offers {body['algorithm']!r}, "
                f"gateway requires {channel.ALGORITHM}")
        cloud_pk = channel.b64decode(body["public_key"],
                                     channel.PUBLIC_KEY_BYTES)

        # Fingerprint computed locally from the key itself. The cloud also
        # sends a "fingerprint" field, but trusting it would let an attacker
        # pair their own key with the genuine fingerprint.
        actual = channel.fingerprint(cloud_pk)
        if self.pinned is None:
            log.warning("no cloud key fingerprint configured; trusting %s on "
                        "first use. Pass --cloud-key-fingerprint to pin it.",
                        actual, extra={"event": "trust_on_first_use",
                                       "fingerprint": actual})
            self.pinned = actual
        elif not hmac.compare_digest(actual, self.pinned):
            raise channel.ChannelError(
                f"cloud public key fingerprint {actual} does not match the "
                f"pinned {self.pinned}; refusing to connect (possible man in "
                f"the middle, or the cloud key was rotated)")

        # 2. Encapsulate to the cloud's long-term key, and make a one-time
        #    key pair of our own for forward secrecy.
        static_ss, static_ct = channel.encapsulate(cloud_pk)
        ephemeral_pk, ephemeral_sk = channel.generate_keypair()

        response = self.http.post(
            f"{self.cloud_url}/api/v2/pqc/session",
            json={
                "static_ciphertext": channel.b64encode(static_ct),
                "ephemeral_public_key": channel.b64encode(ephemeral_pk),
                "gateway_proof": channel.b64encode(
                    channel.gateway_proof(self.token, static_ct, ephemeral_pk)
                ),
            },
            timeout=CLOUD_TIMEOUT_S,
        )
        if response.status_code != 201:
            raise channel.ChannelError(
                f"session request returned HTTP {response.status_code}")
        body = response.json()

        # 3. Recover the second secret and derive the session keys.
        ephemeral_ct = channel.b64decode(body["ephemeral_ciphertext"],
                                         channel.CIPHERTEXT_BYTES)
        ephemeral_ss = channel.decapsulate(ephemeral_sk, ephemeral_ct)
        # Drop our reference to the one-time private key. Python cannot
        # guarantee the bytes are wiped from memory, which is a limitation of
        # doing this in pure Python rather than a claim of secure erasure.
        del ephemeral_sk

        aead_key, confirm_key = channel.derive_session_keys(
            static_ss, ephemeral_ss,
            channel.transcript(cloud_pk, static_ct, ephemeral_pk,
                               ephemeral_ct),
        )

        # 4. Only the holder of the pinned key's private half could have
        #    produced this tag. This is the step that authenticates the cloud.
        session_id = body["session_id"]
        channel.verify_confirmation(
            confirm_key, session_id,
            channel.b64decode(body["confirmation"]),
        )

        lifetime = max(0, int(body["expires_in_s"]) - self.RENEW_MARGIN_S)
        return _PqcSession(
            session_id=session_id,
            aead_key=aead_key,
            expires_at=time.monotonic() + lifetime,
            max_messages=int(body["max_messages"]),
        )


class DeviceHandler(socketserver.StreamRequestHandler):
    """Handles one device connection for its whole lifetime.

    socketserver creates one instance per connection and, because the server
    below is a ThreadingTCPServer, runs each on its own thread. self.server is
    the shared GatewayServer, which is where the stats and sequence tracker
    live.
    """

    def handle(self) -> None:
        """Read newline-delimited frames until the device goes away."""
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log.info("device connected from %s", peer)

        try:
            # Iterating over rfile yields one line per frame, which is exactly
            # the legacy framing. It blocks between readings, which is fine
            # because this thread serves only this device.
            for raw in self.rfile:
                if len(raw) > MAX_FRAME_BYTES:
                    log.warning("oversized frame from %s (%d bytes), dropping",
                                peer, len(raw),
                                extra={"event": "frame_rejected",
                                       "reason": "oversized", "peer": peer})
                    self.server.stats.bump("frames_rejected")
                    continue

                self.server.stats.bump("frames_received")
                self._process(raw, peer)
        except OSError as exc:
            # A field device losing power resets the connection instead of
            # closing it cleanly. Without this handler the thread died with a
            # ConnectionResetError traceback - noise an on-call operator would
            # have to triage for a routine event. Found by failure testing, not
            # by reading the code.
            log.info("device %s link reset: %s", peer, exc)
            return

        log.info("device %s disconnected", peer)

    def _process(self, raw: bytes, peer: str) -> None:
        """Decrypt, validate and forward a single frame."""
        try:
            reading = parse_reading(decrypt_frame(raw))
        except ValueError as exc:
            # This could be line noise, a truncated frame, or an active
            # tampering attempt. AES-CBC without a MAC cannot tell us which,
            # so we log the ambiguity rather than claiming to know. That
            # ambiguity is itself a finding for the report, not a bug here.
            log.warning("undecodable frame from %s: %s", peer, exc,
                        extra={"event": "frame_rejected",
                               "reason": "undecodable", "peer": peer})
            self.server.stats.bump("frames_rejected")
            return

        if not self.server.sequences.accept(reading["device_id"],
                                            reading["seq"]):
            log.warning("replayed or stale seq=%d from %s",
                        reading["seq"], reading["device_id"],
                        extra={"event": "replay_dropped",
                               "device_id": reading["device_id"],
                               "seq": reading["seq"]})
            self.server.stats.bump("replays_dropped")
            return

        self._forward(reading)

    def _forward(self, reading: dict) -> None:
        """Send one reading to the cloud over the configured uplink.

        Sends synchronously on the device's own thread. That is acceptable at
        this scale and keeps the code readable, but it does mean a slow cloud
        slows down the device that triggered the request - worth noting as a
        scaling limit in the final evaluation.
        """
        uplink = self.server.uplink
        try:
            uplink.send(reading)
        except (requests.RequestException, UplinkError) as exc:
            # There is no queue, so the reading is now permanently lost. We
            # count it so the loss is at least visible, and store-and-forward
            # is on the backlog.
            log.error("forward failed for %s seq=%d: %s",
                      reading["device_id"], reading["seq"], exc,
                      extra={"event": "forward_failed",
                             "device_id": reading["device_id"],
                             "seq": reading["seq"], "error": str(exc)})
            self.server.stats.forward_failed_with(exc)
            return

        self.server.stats.forward_succeeded()
        log.info("forwarded %s seq=%d temp=%.2f via %s",
                 reading["device_id"], reading["seq"], reading["temp_c"],
                 uplink.name,
                 extra={"event": "forwarded", "device_id": reading["device_id"],
                        "seq": reading["seq"], "crypto": uplink.name})


class GatewayServer(socketserver.ThreadingTCPServer):
    """TCP server holding the state shared by all device connections."""

    # Lets the gateway restart immediately after a crash instead of waiting
    # for the kernel's TIME_WAIT to expire - important during development and
    # for fast container restarts.
    allow_reuse_address = True

    # Device threads are daemons so shutdown is not blocked by a device that
    # is idle between readings.
    daemon_threads = True

    def __init__(self, address: tuple[str, int], uplink=None,
                 stats: GatewayStats | None = None) -> None:
        """
        Args:
            address: (host, port) to listen on for devices.
            uplink: a LegacyUplink or PqcUplink. Taken as a parameter so tests
                and main() choose the cloud path without the server caring
                which one it is.
            stats: counters, shared with the uplink so handshake outcomes
                land in the same snapshot as the frame counters.
        """
        super().__init__(address, DeviceHandler)
        self.uplink = uplink

        # Shared by every handler thread; both are internally locked.
        self.stats = stats if stats is not None else GatewayStats()
        self.sequences = SequenceTracker()


def main() -> None:
    parser = argparse.ArgumentParser(description="Edge gateway")
    # Localhost by default: the legacy port accepts unauthenticated frames, so
    # exposing it to the network should be a deliberate choice (--host
    # 0.0.0.0, as the container entrypoint does). Found by static analysis
    # (ruff S104 / bandit B104).
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to listen on for devices "
                             "(0.0.0.0 for all interfaces)")
    parser.add_argument("--port", type=int, default=9000,
                        help="TCP port devices connect to")
    parser.add_argument("--cloud-url", default="http://127.0.0.1:8000",
                        help="base URL of the cloud service")
    parser.add_argument("--crypto", choices=["mlkem", "legacy"],
                        default="mlkem",
                        help="cloud path: ML-KEM (default) or the legacy "
                             "rollback path")
    parser.add_argument("--cloud-key-fingerprint",
                        default=os.environ.get("CLOUD_KEY_FINGERPRINT"),
                        help="expected SHA-256 of the cloud's ML-KEM public "
                             "key (shown in the cloud's /health); without it "
                             "the first key seen is trusted")
    parser.add_argument("--admin-host", default="127.0.0.1",
                        help="interface for the /health and /metrics server")
    parser.add_argument("--admin-port", type=int, default=9100,
                        help="port for /health and /metrics; 0 disables it")
    args = parser.parse_args()

    logs.configure("gateway")

    stats = GatewayStats()
    if args.crypto == "mlkem":
        uplink = PqcUplink(args.cloud_url, stats,
                           pinned_fingerprint=args.cloud_key_fingerprint)
    else:
        log.warning("running on the LEGACY cloud path: readings and the "
                    "gateway token cross the network unprotected",
                    extra={"event": "legacy_mode"})
        uplink = LegacyUplink(args.cloud_url)

    server = GatewayServer((args.host, args.port), uplink, stats)
    log.info("gateway listening on %s:%d, cloud at %s via %s",
             args.host, args.port, uplink.cloud_url, uplink.name,
             extra={"event": "started", "crypto": uplink.name})

    if args.admin_port:
        # Imported here so tests that only need the gateway classes do not
        # pull in the HTTP server.
        from edge_gateway import admin
        admin.start(server, args.admin_host, args.admin_port)
        log.info("health and metrics on http://%s:%d/health and /metrics",
                 args.admin_host, args.admin_port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # Print the counters on the way out: during a demo this is the only
        # summary of what the run actually did.
        log.info("gateway stopping, stats=%s", server.stats.snapshot())
        server.shutdown()


if __name__ == "__main__":
    main()

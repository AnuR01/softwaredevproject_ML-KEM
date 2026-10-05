"""
Cloud telemetry service.

WHAT THIS IS
    The far end of the chain. Gateways POST readings here; operators and other
    systems read them back. FastAPI generates an interactive API console at
    /docs from the type annotations below, which is how we demonstrate the
    system without writing a UI.

WHY IT IS SHAPED LIKE THIS
    Small on purpose. The project brief asks us to keep the system plain, and
    the interesting work is the cryptography and the operations around it, not
    the data platform.

ITS ROLE IN THE MIGRATION
    This side holds the long-term ML-KEM-768 key pair. Gateways run the
    handshake in pqc_channel/channel.py against it and then send readings
    encrypted and authenticated with AES-256-GCM (the /api/v2 endpoints).

    Two ingest paths exist side by side during the migration:

        /api/v1/telemetry   legacy: plain JSON + static token header
        /api/v2/telemetry   ML-KEM session + AES-256-GCM

    The legacy path is switched off with LEGACY_INGEST_ENABLED=false once
    every gateway has been upgraded. Keeping it switchable, rather than
    deleting it, is the fallback strategy: an operator can roll a gateway
    back without redeploying the cloud. The gateway never falls back on its
    own - see edge_gateway/gateway.py.

KNOWN TECHNICAL DEBT (tracked in README.md)
    * Storage is an in-memory deque, so every reading is lost on restart.
    * Sessions are in memory too: a restart forces every gateway to redo the
      handshake (the gateway handles that automatically).
    * Gateways are identified only by one static shared token. It no longer
      crosses the network on the v2 path, but it is still shared and never
      rotates.
    * The long-term private key is stored unencrypted on disk.
    * Served over plain HTTP. v2 payloads are protected by the channel
      itself; v1 payloads and the read APIs are not.
    * No /metrics endpoint yet; only /health.

CONFIGURATION (environment variables)
    GATEWAY_TOKEN           shared gateway secret (default: legacy value)
    CLOUD_KEM_KEY_FILE      where the long-term ML-KEM key pair is kept. Created
                            on first start if missing. Unset means a new key
                            pair on every start - fine for tests, wrong for a
                            deployment, because pinned gateways then refuse it.
    LEGACY_INGEST_ENABLED   "false" disables /api/v1/telemetry (default "true")

Run:
    python -m uvicorn cloud_service.app:app --host 127.0.0.1 --port 8000
"""

import hmac
import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ValidationError

from pqc_channel import channel

log = logging.getLogger("cloud-service")

# Must match GATEWAY_TOKEN in edge_gateway/gateway.py.
#
# Read from the environment so a deployment can override it without editing
# code, but it still defaults to a value committed to the repository - which is
# exactly the weakness we are documenting. On the v1 path it is sent in clear
# with every request; on the v2 path the gateway only proves it knows it,
# inside the ML-KEM handshake, so it never crosses the network. Replacing it
# with per-gateway credentials is still open.
EXPECTED_TOKEN = os.environ.get("GATEWAY_TOKEN", "legacy-gateway-token")

# Ring-buffer size. Bounded so a long demo cannot exhaust memory; old readings
# are silently discarded once it is full, which is acceptable only because
# nothing here is the system of record.
MAX_STORED_READINGS = 1000

# Read once at import. Anything other than "false" keeps the legacy path on,
# so a typo errs towards availability during the migration.
LEGACY_INGEST_ENABLED = (
    os.environ.get("LEGACY_INGEST_ENABLED", "true").strip().lower() != "false"
)

# How long one ML-KEM session key may be used. Short enough that a leaked
# session key exposes at most an hour of readings; long enough that the
# handshake cost (a few milliseconds) is negligible against a reading every
# few seconds.
SESSION_TTL_S = 3600

# Messages per session before a fresh handshake is required. Also bounds the
# per-session replay set below, so memory per session is fixed.
SESSION_MAX_MESSAGES = 10_000

# Cap on concurrent sessions. The handshake endpoint is reachable by anyone
# who knows the gateway token, so without a cap a buggy or hostile gateway
# could exhaust memory by handshaking in a loop.
MAX_SESSIONS = 1000

app = FastAPI(
    title="PQC Modernization - Cloud Telemetry Service",
    description="Receives sensor readings forwarded by edge gateways.",
    version="0.2.0",
)

# Module-level state. A deque with maxlen drops the oldest entry automatically
# when full, so no eviction logic is needed.
#
# Uvicorn may serve requests from multiple threads, so every access is guarded.
# deque.append is itself atomic, but read paths below copy the whole deque and
# would otherwise be able to observe a partially-updated structure.
_readings: deque[dict] = deque(maxlen=MAX_STORED_READINGS)
_lock = threading.Lock()

# Recorded at import time so /health can report uptime.
_started_at = datetime.now(UTC)


def _load_or_create_keypair(path: str | None) -> tuple[bytes, bytes]:
    """Return the cloud's long-term ML-KEM key pair (public, private).

    With a path, the pair survives restarts, which is required once gateways
    pin the public key's fingerprint. Without one, a throwaway pair is
    generated, which suits tests and quick local runs.
    """
    if not path:
        log.warning("CLOUD_KEM_KEY_FILE not set; using an ephemeral key pair "
                    "that changes on every restart")
        return channel.generate_keypair()

    key_file = Path(path)
    if key_file.exists():
        stored = json.loads(key_file.read_text(encoding="utf-8"))
        return (channel.b64decode(stored["public_key"],
                                  channel.PUBLIC_KEY_BYTES),
                channel.b64decode(stored["private_key"]))

    public_key, private_key = channel.generate_keypair()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(json.dumps({
        "algorithm": channel.ALGORITHM,
        "public_key": channel.b64encode(public_key),
        "private_key": channel.b64encode(private_key),
    }), encoding="utf-8")
    # Owner-only permissions. Effective on Linux containers; Windows largely
    # ignores it, which is one reason the unencrypted key file is listed as
    # technical debt above.
    key_file.chmod(0o600)
    log.info("generated new ML-KEM key pair at %s", key_file)
    return public_key, private_key


_kem_public_key, _kem_private_key = _load_or_create_keypair(
    os.environ.get("CLOUD_KEM_KEY_FILE")
)
KEM_FINGERPRINT = channel.fingerprint(_kem_public_key)
log.info("ML-KEM public key fingerprint %s", KEM_FINGERPRINT)


@dataclass
class Session:
    """One gateway's ML-KEM session."""

    aead_key: bytes
    expires_at: float
    # Counters already accepted. A set rather than "highest so far" because
    # a gateway forwards readings from several device threads at once, so
    # messages can arrive slightly out of order; each counter is still
    # accepted at most once. SESSION_MAX_MESSAGES bounds its size.
    seen_counters: set[int] = field(default_factory=set)


_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def _prune_sessions(now: float) -> None:
    """Drop expired sessions, then the oldest ones if still over the cap.

    Caller must hold _sessions_lock.
    """
    for sid in [s for s, sess in _sessions.items() if sess.expires_at <= now]:
        del _sessions[sid]
    # dicts keep insertion order, so the first keys are the oldest sessions.
    while len(_sessions) >= MAX_SESSIONS:
        del _sessions[next(iter(_sessions))]


class Reading(BaseModel):
    """One sensor reading, as forwarded by a gateway.

    Pydantic validates incoming JSON against these annotations and returns a
    422 with a field-level explanation when it does not fit, so no manual
    checking is needed in the endpoint.

    The bounds are a second line of defence. The gateway already parses and
    range-limits readings, but the gateway is not the only thing that can post
    here - anyone holding the static token can - so the cloud does not trust
    its caller. Note that validation is not authentication: well-formed fake
    data still gets stored, which is the point of weakness 3 in README.md.
    """

    device_id: str = Field(min_length=1, max_length=64,
                           description="Identity claimed by the device")
    seq: int = Field(ge=0, description="Monotonic counter from the device")

    # Wider than any real indoor range: the sensor's own error range matters
    # less here than catching obvious corruption such as -273 or 1e9.
    temp_c: float = Field(ge=-50.0, le=150.0, description="Degrees Celsius")

    # Relative humidity is a percentage, so this bound is physical, not
    # heuristic.
    humidity: float = Field(ge=0.0, le=100.0, description="Percent RH")

    uptime_s: int = Field(ge=0, description="Seconds since device boot")


def _require_token(token: str | None) -> None:
    """Reject a request that does not carry the shared gateway token.

    A plain equality check. A real implementation would use a constant-time
    comparison to avoid leaking the token through response timing, and per-
    gateway credentials rather than one shared string - both noted as
    remaining risks in the technical documentation.

    Raises:
        HTTPException: 401 if the token is missing or wrong.
    """
    if token != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing gateway token",
        )


@app.get("/health")
def health() -> dict:
    """Liveness and readiness probe.

    Deliberately unauthenticated: container orchestrators and uptime monitors
    need to reach it without credentials, and it exposes nothing sensitive.
    Returning the stored count as well as a status makes it useful during a
    demo - you can watch the number climb.
    """
    with _lock:
        stored = len(_readings)
        by_channel = {"mlkem": 0, "legacy": 0}
        for r in _readings:
            by_channel[r["channel"]] += 1
    with _sessions_lock:
        active = sum(1 for s in _sessions.values()
                     if s.expires_at > time.monotonic())

    return {
        "status": "ok",
        "uptime_s": int(
            (datetime.now(UTC) - _started_at).total_seconds()
        ),
        "stored_readings": stored,
        # Lets an operator confirm which key the cloud is serving (compare it
        # with the gateway's pin) and watch the migration: when legacy ingest
        # is off, every reading arrives over ML-KEM.
        "pqc": {
            "algorithm": channel.ALGORITHM,
            "public_key_fingerprint": KEM_FINGERPRINT,
            "active_sessions": active,
            "legacy_ingest_enabled": LEGACY_INGEST_ENABLED,
            # Of the readings currently stored, how many arrived over each
            # path. The migration is complete when legacy stays at zero.
            "readings_by_channel": by_channel,
        },
    }


_DASHBOARD = Path(__file__).resolve().parent / "static" / "dashboard.html"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> str:
    """Live dashboard for demos and monitoring.

    Read from disk on every request so the page can be edited without
    restarting the service. It uses only the public JSON endpoints, so it
    adds no data access of its own. Left out of the /docs schema because it
    is a page for people, not part of the API.
    """
    return _DASHBOARD.read_text(encoding="utf-8")


def _store(reading: Reading, channel_name: str) -> None:
    """Record one validated reading. Shared by the v1 and v2 paths."""
    record = reading.model_dump()

    # Server-side receive time, kept separate from the device's own uptime
    # field. Device clocks cannot be trusted - many have none at all - so
    # ordering and freshness are judged by when the cloud saw the reading.
    record["received_at"] = datetime.now(UTC).isoformat()

    # Which path delivered it. During the migration this is how you prove,
    # reading by reading, that traffic has moved to the post-quantum channel.
    record["channel"] = channel_name

    with _lock:
        _readings.append(record)

    log.info("ingested %s seq=%d via %s", reading.device_id, reading.seq,
             channel_name)


@app.post("/api/v1/telemetry", status_code=status.HTTP_202_ACCEPTED)
def ingest(reading: Reading,
           x_gateway_token: str | None = Header(default=None)) -> dict:
    """Accept one reading from a gateway (legacy path).

    Returns 202 Accepted rather than 201 Created because the reading is
    recorded but nothing durable has been created - an honest status code for
    in-memory storage.

    FastAPI maps the x_gateway_token parameter to the X-Gateway-Token header
    automatically, converting underscores to hyphens.
    """
    if not LEGACY_INGEST_ENABLED:
        # 410 Gone rather than 404: the endpoint existed and was retired on
        # purpose, which tells a stale gateway exactly what happened.
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="legacy ingest is disabled; upgrade the gateway to ML-KEM",
        )

    _require_token(x_gateway_token)
    _store(reading, "legacy")
    return {"accepted": True, "device_id": reading.device_id,
            "seq": reading.seq}


# --------------------------------------------------------------------------
# v2: ML-KEM session and encrypted ingest
# --------------------------------------------------------------------------

# Base64 of the fixed ML-KEM sizes, with a little slack. Bounding request
# fields stops an oversized body from ever reaching the decoder.
_PK_B64_MAX = 1700
_CT_B64_MAX = 1500


class SessionRequest(BaseModel):
    """First half of the handshake, sent by the gateway."""

    static_ciphertext: str = Field(max_length=_CT_B64_MAX,
                                   description="ML-KEM ciphertext against the "
                                               "cloud's long-term key, base64")
    ephemeral_public_key: str = Field(max_length=_PK_B64_MAX,
                                      description="Gateway's one-time ML-KEM "
                                                  "public key, base64")
    gateway_proof: str = Field(max_length=64,
                               description="HMAC-SHA256 of the handshake "
                                           "under the gateway token, base64")


class SealedReading(BaseModel):
    """One reading encrypted under a session key."""

    session_id: str = Field(min_length=32, max_length=32)
    nonce: str = Field(max_length=24, description="12-byte counter, base64")
    ciphertext: str = Field(max_length=4096,
                            description="AES-256-GCM output, base64")


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                         detail=detail)


@app.get("/api/v2/pqc/public-key")
def pqc_public_key() -> dict:
    """The cloud's long-term ML-KEM public key.

    Public by definition, so unauthenticated. Serving it is not what makes the
    channel trustworthy: a gateway must compare the fingerprint with the value
    it was configured with, otherwise a man in the middle could serve their
    own key here.
    """
    return {
        "algorithm": channel.ALGORITHM,
        "public_key": channel.b64encode(_kem_public_key),
        "fingerprint": KEM_FINGERPRINT,
    }


@app.post("/api/v2/pqc/session", status_code=status.HTTP_201_CREATED)
def pqc_session(request: SessionRequest) -> dict:
    """Complete the ML-KEM handshake and open a session.

    201 Created because, unlike a reading, a session really is a new resource
    that later requests refer to by id.
    """
    try:
        static_ct = channel.b64decode(request.static_ciphertext,
                                      channel.CIPHERTEXT_BYTES)
        ephemeral_pk = channel.b64decode(request.ephemeral_public_key,
                                         channel.PUBLIC_KEY_BYTES)
        proof = channel.b64decode(request.gateway_proof, 32)
    except channel.ChannelError as exc:
        raise _bad_request(str(exc)) from exc

    # Check the gateway before spending any ML-KEM work on the request.
    # compare_digest is constant-time, unlike the v1 path's plain !=.
    expected = channel.gateway_proof(EXPECTED_TOKEN, static_ct, ephemeral_pk)
    if not hmac.compare_digest(expected, proof):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid gateway proof")

    try:
        static_ss = channel.decapsulate(_kem_private_key, static_ct)
        ephemeral_ss, ephemeral_ct = channel.encapsulate(ephemeral_pk)
    except channel.ChannelError as exc:
        raise _bad_request(str(exc)) from exc

    aead_key, confirm_key = channel.derive_session_keys(
        static_ss, ephemeral_ss,
        channel.transcript(_kem_public_key, static_ct, ephemeral_pk,
                           ephemeral_ct),
    )
    session_id = channel.new_session_id()

    now = time.monotonic()
    with _sessions_lock:
        _prune_sessions(now)
        _sessions[session_id] = Session(aead_key=aead_key,
                                        expires_at=now + SESSION_TTL_S)

    log.info("ML-KEM session %s... opened", session_id[:8])
    return {
        "session_id": session_id,
        "ephemeral_ciphertext": channel.b64encode(ephemeral_ct),
        "confirmation": channel.b64encode(
            channel.confirmation_tag(confirm_key, session_id)
        ),
        "expires_in_s": SESSION_TTL_S,
        "max_messages": SESSION_MAX_MESSAGES,
    }


@app.post("/api/v2/telemetry", status_code=status.HTTP_202_ACCEPTED)
def ingest_sealed(message: SealedReading) -> dict:
    """Accept one reading encrypted under an ML-KEM session key.

    No token header: knowing the session key is the credential, and only the
    two ends of the handshake know it.

    Status codes are chosen so the gateway knows what to do next:
        401 unknown or expired session   -> redo the handshake and resend
        400 tampered or malformed        -> do not retry, it will never pass
        409 counter already used         -> replay, drop it
        422 decrypts but is not valid    -> do not retry
    """
    try:
        nonce = channel.b64decode(message.nonce, channel.NONCE_BYTES)
        sealed = channel.b64decode(message.ciphertext)
    except channel.ChannelError as exc:
        raise _bad_request(str(exc)) from exc

    with _sessions_lock:
        session = _sessions.get(message.session_id)
        if session is None or session.expires_at <= time.monotonic():
            # A fixed detail string the gateway matches on to trigger a new
            # handshake.
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="unknown_session")
        aead_key = session.aead_key

    # Decrypt outside the lock: it is the slowest step and needs no shared
    # state.
    try:
        plaintext = channel.open_sealed(aead_key, nonce, message.session_id,
                                        sealed)
    except channel.ChannelError as exc:
        raise _bad_request(str(exc)) from exc

    # Only record the counter after authentication succeeds. Recording it
    # first would let anyone burn counters with garbage and block the
    # gateway's real messages.
    counter = channel.counter_from(nonce)
    with _sessions_lock:
        if counter in session.seen_counters:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="replayed message")
        if len(session.seen_counters) >= SESSION_MAX_MESSAGES:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="unknown_session")
        session.seen_counters.add(counter)

    try:
        reading = Reading.model_validate_json(plaintext)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.errors(include_url=False, include_input=False),
        ) from exc

    _store(reading, "mlkem")
    return {"accepted": True, "device_id": reading.device_id,
            "seq": reading.seq}


@app.get("/api/v1/telemetry")
def list_readings(limit: int = 20, device_id: str | None = None) -> dict:
    """Return recent readings, newest first.

    Args:
        limit: how many readings to return. Clamped rather than rejected, so a
            careless caller gets a sensible page instead of a 422.
        device_id: optional exact-match filter.
    """
    limit = max(1, min(limit, MAX_STORED_READINGS))

    # Copy under the lock, then work on the copy. Filtering while holding the
    # lock would block ingestion for no benefit.
    with _lock:
        items = list(_readings)

    if device_id:
        items = [r for r in items if r["device_id"] == device_id]

    # The deque is in arrival order, so the newest entries are at the end:
    # take the last `limit`, then reverse to present newest first.
    page = items[-limit:]
    return {"count": len(page), "readings": page[::-1]}


@app.get("/api/v1/devices")
def list_devices() -> dict:
    """Summarise every device seen since start-up.

    Computed on demand by walking the stored readings. That is fine for a
    1000-entry buffer and avoids a second data structure to keep in sync; a
    real system would maintain a device table instead.
    """
    with _lock:
        items = list(_readings)

    devices: dict[str, dict] = {}
    for reading in items:
        entry = devices.setdefault(
            reading["device_id"],
            {"device_id": reading["device_id"], "readings": 0},
        )
        entry["readings"] += 1

        # Readings are iterated in arrival order, so each assignment overwrites
        # the previous one and the last write wins - leaving the most recent
        # values without needing an explicit comparison.
        entry["last_seq"] = reading["seq"]
        entry["last_temp_c"] = reading["temp_c"]
        entry["last_humidity"] = reading["humidity"]
        entry["last_seen"] = reading["received_at"]

    return {"count": len(devices), "devices": list(devices.values())}

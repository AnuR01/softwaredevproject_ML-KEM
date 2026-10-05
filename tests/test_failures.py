"""
Failure tests: how the system behaves when things around it go wrong.

The other test files check that features work and that attacks are caught.
These check operational failures: the cloud is down, slow, returns errors or
garbage, loses its key, or is flooded. For each one the question is the same:
does the system fail safely and visibly, and does it recover?

Most tests run the real gateway uplink against the real cloud in-process (as
in test_pqc_integration.py), with FaultyCloud in between to inject the
failure. One test uses a real closed TCP port, so that "cloud is down" is a
genuine connection error and not a simulation of one.

Run only these with:  python -m pytest -m failure
"""

import socket
import threading
import time

import pytest
import requests
from fastapi.testclient import TestClient

from cloud_service import app as cloud
from edge_gateway import gateway as gw
from legacy_device.protocol import build_reading, encrypt_frame
from pqc_channel import channel

pytestmark = pytest.mark.failure

BASE = "http://testserver"

READING = {"device_id": "dev-001", "seq": 1, "temp_c": 21.5,
           "humidity": 44.2, "uptime_s": 12}

PUBLIC_KEY = "/api/v2/pqc/public-key"
SESSION = "/api/v2/pqc/session"
TELEMETRY_V2 = "/api/v2/telemetry"


@pytest.fixture(autouse=True)
def clean_cloud():
    """Each test starts with no readings and no sessions."""
    def reset():
        with cloud._lock:
            cloud._readings.clear()
        with cloud._sessions_lock:
            cloud._sessions.clear()
    reset()
    yield
    reset()


@pytest.fixture
def client():
    return TestClient(cloud.app)


class _Response:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code: int, body=None, json_error=None):
        self.status_code = status_code
        self._body = body
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._body


class FaultyCloud:
    """Sits between the gateway and the real cloud and injects failures.

    faults maps an endpoint path to what should happen when it is called:
    an exception instance (raised, like a network error), or a _Response
    (returned instead of the real one). A fault can be limited to the first
    `times` calls, after which the real cloud answers again, which is how
    recovery after an outage is tested.

    Every call is recorded with its URL and timeout, so tests can check what
    the gateway tried to do, not only what came back.
    """

    def __init__(self, inner: TestClient, faults: dict | None = None,
                 times: int | None = None) -> None:
        self.inner = inner
        self.faults = faults or {}
        self.times = times
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def _call(self, method: str, url: str, **kwargs):
        with self._lock:
            self.calls.append({"method": method, "url": url,
                               "timeout": kwargs.get("timeout"),
                               "json": kwargs.get("json")})
            failing = self.times is None or len(self.calls) <= self.times
        for path, fault in self.faults.items():
            if url.endswith(path) and failing:
                if isinstance(fault, Exception):
                    raise fault
                return fault
        return getattr(self.inner, method)(url, **kwargs)

    def get(self, url, **kwargs):
        return self._call("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._call("post", url, **kwargs)

    def urls(self) -> list[str]:
        with self._lock:
            return [c["url"] for c in self.calls]


def make_uplink(http, **kwargs):
    stats = gw.GatewayStats()
    return gw.PqcUplink(BASE, stats, http=http, **kwargs), stats


def stored(client):
    return client.get("/api/v1/telemetry", params={"limit": 1000}).json()[
        "readings"]


def frame(seq: int, device_id: str = "dev-001") -> bytes:
    return encrypt_frame(build_reading(device_id, seq, 21.0, 45.0, seq))


def wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class RunningGateway:
    """A real GatewayServer on an ephemeral port, for device-level tests."""

    def __init__(self, uplink, stats) -> None:
        self.server = gw.GatewayServer(("127.0.0.1", 0), uplink, stats)
        self.port = self.server.server_address[1]
        self.stats = stats
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)

    def send(self, frames: list[bytes]) -> None:
        """Connect like a device, send frames, and close cleanly."""
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=5) as sock:
            for f in frames:
                sock.sendall(f)
            sock.shutdown(socket.SHUT_WR)
            sock.recv(1)


# --------------------------------------------------------------------------
# Cloud unavailable
# --------------------------------------------------------------------------

def closed_port() -> int:
    """A local port with nothing listening on it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_cloud_down_readings_are_counted_and_gateway_keeps_serving():
    """Real connection refused: the gateway must not crash or hang.

    Each reading is counted as a failed handshake and a failed forward (and
    lost, because there is no store-and-forward queue; see README). The
    device connection keeps working, and a second device can still connect.
    """
    stats = gw.GatewayStats()
    uplink = gw.PqcUplink(f"http://127.0.0.1:{closed_port()}", stats)

    with RunningGateway(uplink, stats) as gateway:
        gateway.send([frame(1), frame(2)])
        gateway.send([frame(1, device_id="dev-002")])

        assert wait_for(lambda: stats.snapshot()["forward_failed"] == 3)

    snapshot = stats.snapshot()
    assert snapshot["forwarded_ok"] == 0
    assert snapshot["handshakes_failed"] == 3
    assert snapshot["handshakes_ok"] == 0


@pytest.mark.parametrize("fault", [
    requests.ConnectionError("connection reset by attacker"),
    requests.Timeout("handshake timed out"),
    _Response(503, {"detail": "service unavailable"}),
], ids=["connection-reset", "timeout", "http-503"])
def test_blocked_handshake_never_falls_back_to_legacy(client, fault):
    """The downgrade-attack guarantee from the fallback policy.

    An attacker who can block the ML-KEM handshake must not be able to push
    the gateway onto the legacy path. Readings are dropped and counted, and
    not one request goes to the legacy /api/v1 ingest endpoint.
    """
    faulty = FaultyCloud(client, faults={SESSION: fault})
    uplink, stats = make_uplink(faulty)

    with RunningGateway(uplink, stats) as gateway:
        gateway.send([frame(seq) for seq in (1, 2, 3)])
        assert wait_for(lambda: stats.snapshot()["forward_failed"] == 3)

    assert not any("/api/v1/" in url for url in faulty.urls())
    assert stats.snapshot()["handshakes_failed"] == 3
    assert stored(client) == []


def test_gateway_recovers_by_itself_after_an_outage(client):
    """No operator action needed: the next reading after the outage works."""
    faulty = FaultyCloud(
        client,
        faults={PUBLIC_KEY: requests.ConnectionError("cloud restarting")},
        times=2,
    )
    uplink, stats = make_uplink(faulty, pinned_fingerprint=cloud.KEM_FINGERPRINT)

    for seq in (1, 2):
        with pytest.raises(gw.UplinkError):
            uplink.send({**READING, "seq": seq})
    uplink.send({**READING, "seq": 3})

    assert [r["seq"] for r in stored(client)] == [3]
    assert stats.snapshot()["handshakes_failed"] == 2
    assert stats.snapshot()["handshakes_ok"] == 1


def test_every_cloud_request_has_a_timeout(client):
    """A cloud that accepts the connection but never answers must not hang a
    device thread forever. requests waits indefinitely without a timeout."""
    faulty = FaultyCloud(client)
    uplink, _ = make_uplink(faulty)

    uplink.send(READING)

    assert len(faulty.calls) == 3  # public key, session, one reading
    assert all(c["timeout"] == gw.CLOUD_TIMEOUT_S for c in faulty.calls)


def test_reading_timeout_is_counted_not_fatal(client):
    """A timeout while sending a sealed reading is a counted failure."""
    faulty = FaultyCloud(client, faults={
        TELEMETRY_V2: requests.Timeout("read timed out")})
    uplink, stats = make_uplink(faulty)

    with RunningGateway(uplink, stats) as gateway:
        gateway.send([frame(1)])
        assert wait_for(lambda: stats.snapshot()["forward_failed"] == 1)

    assert stats.snapshot()["handshakes_ok"] == 1
    assert stats.snapshot()["forwarded_ok"] == 0


# --------------------------------------------------------------------------
# Cloud misbehaving
# --------------------------------------------------------------------------

def test_server_error_on_a_reading_is_not_retried(client):
    """A 500 will fail the same way again, so the gateway must not loop.

    Only a 401 (session unknown to the cloud) triggers a new handshake and a
    retry; see test_gateway_recovers_when_the_cloud_forgets_its_session.
    """
    faulty = FaultyCloud(client, faults={
        TELEMETRY_V2: _Response(500, {"detail": "internal error"})})
    uplink, stats = make_uplink(faulty)

    with pytest.raises(gw.UplinkError, match="HTTP 500"):
        uplink.send(READING)

    assert sum(u.endswith(TELEMETRY_V2) for u in faulty.urls()) == 1
    assert stats.snapshot()["handshakes_ok"] == 1


@pytest.mark.parametrize("reply", [
    _Response(200, json_error=ValueError("Expecting value: <html>")),
    _Response(200, {}),
    _Response(200, {"algorithm": "ML-KEM-768", "public_key": "not base64!"}),
], ids=["html-instead-of-json", "missing-fields", "bad-base64"])
def test_garbage_public_key_reply_fails_the_handshake_cleanly(client, reply):
    """A proxy error page or a broken cloud must give a counted handshake
    failure, not an unexpected exception that kills the device thread."""
    faulty = FaultyCloud(client, faults={PUBLIC_KEY: reply})
    uplink, stats = make_uplink(faulty)

    with pytest.raises(gw.UplinkError, match="handshake failed"):
        uplink.send(READING)

    assert stats.snapshot()["handshakes_failed"] == 1


def test_cloud_offering_a_different_algorithm_is_refused(client):
    """Algorithm downgrade: a cloud (or attacker) offering a weaker parameter
    set is refused, even if it is a real ML-KEM variant."""
    weaker = _Response(200, {"algorithm": "ML-KEM-512",
                             "public_key": channel.b64encode(b"x" * 800)})
    faulty = FaultyCloud(client, faults={PUBLIC_KEY: weaker})
    uplink, stats = make_uplink(faulty)

    with pytest.raises(gw.UplinkError, match="requires ML-KEM-768"):
        uplink.send(READING)

    assert not any(u.endswith(SESSION) for u in faulty.urls())
    assert stats.snapshot()["handshakes_failed"] == 1


def test_pinned_gateway_refuses_a_cloud_that_lost_its_key(client, monkeypatch):
    """Operational failure from the README: the cloud restarts without
    CLOUD_KEM_KEY_FILE and comes back with a new key pair.

    A pinned gateway must refuse it rather than silently trust the new key.
    The fix is an operator action (restore the key file, or re-pin), and the
    rising handshakes_failed counter is how the operator notices.
    """
    uplink, stats = make_uplink(client, pinned_fingerprint=cloud.KEM_FINGERPRINT)
    uplink.send({**READING, "seq": 1})

    new_pk, new_sk = channel.generate_keypair()
    monkeypatch.setattr(cloud, "_kem_public_key", new_pk)
    monkeypatch.setattr(cloud, "_kem_private_key", new_sk)
    with cloud._sessions_lock:
        cloud._sessions.clear()  # the restart also lost every session

    with pytest.raises(gw.UplinkError, match="does not match the pinned"):
        uplink.send({**READING, "seq": 2})

    assert [r["seq"] for r in stored(client)] == [1]
    assert stats.snapshot()["handshakes_failed"] == 1


# --------------------------------------------------------------------------
# Resource limits and startup
# --------------------------------------------------------------------------

def test_handshake_flood_cannot_exceed_the_session_cap(client, monkeypatch):
    """A buggy or hostile gateway handshaking in a loop must not grow the
    cloud's memory without limit: old sessions are evicted at the cap."""
    monkeypatch.setattr(cloud, "MAX_SESSIONS", 5)

    for _ in range(12):
        uplink, _ = make_uplink(client)
        uplink.send(READING)

    with cloud._sessions_lock:
        assert len(cloud._sessions) <= 5


def test_evicted_session_recovers_with_a_new_handshake(client, monkeypatch):
    """The cost of the cap: a gateway whose session was evicted gets a 401
    and re-handshakes, so eviction loses no readings."""
    monkeypatch.setattr(cloud, "MAX_SESSIONS", 2)
    victim, stats = make_uplink(client)
    victim.send({**READING, "seq": 1})

    for _ in range(3):
        make_uplink(client)[0].send(READING)

    victim.send({**READING, "seq": 2})

    assert stats.snapshot()["handshakes_ok"] == 2
    assert 2 in [r["seq"] for r in stored(client)]


@pytest.mark.parametrize("content", [
    "this is not json",
    '{"algorithm": "ML-KEM-768", "public_key": "AAAA", "private_key": "AAAA"}',
    '{"algorithm": "ML-KEM-768"}',
], ids=["not-json", "truncated-key", "missing-fields"])
def test_corrupt_key_file_stops_the_cloud_instead_of_replacing_it(
        tmp_path, content):
    """Fail closed. Silently generating a new key pair would break every
    pinned gateway, and overwriting the file would destroy the evidence."""
    key_file = tmp_path / "cloud_kem.json"
    key_file.write_text(content, encoding="utf-8")

    with pytest.raises((ValueError, KeyError)):
        cloud._load_or_create_keypair(str(key_file))

    assert key_file.read_text(encoding="utf-8") == content


# --------------------------------------------------------------------------
# Load
# --------------------------------------------------------------------------

def test_many_devices_at_once_share_one_session_without_nonce_reuse(client):
    """Concurrency failure mode: two threads sealing with the same counter
    would reuse an AES-GCM nonce, which breaks GCM's security. Every message
    must get its own counter, and every reading must arrive exactly once."""
    faulty = FaultyCloud(client)
    uplink, stats = make_uplink(faulty)
    devices, per_device = 8, 10
    errors: list[Exception] = []

    def device(n: int) -> None:
        try:
            for seq in range(1, per_device + 1):
                uplink.send({**READING, "device_id": f"dev-{n:03}", "seq": seq})
        except Exception as exc:  # collected and asserted on below
            errors.append(exc)

    threads = [threading.Thread(target=device, args=(n,))
               for n in range(devices)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == []
    assert len(stored(client)) == devices * per_device
    assert stats.snapshot()["handshakes_ok"] == 1
    nonces = [c["json"]["nonce"] for c in faulty.calls
              if c["url"].endswith(TELEMETRY_V2)]
    assert len(nonces) == len(set(nonces)) == devices * per_device

"""
Tests for health checks, metrics and structured logs.

The counters are only useful if they move when the event they name happens,
and only then. Each cloud test therefore measures a counter before and after
one action, rather than asserting an absolute value that earlier tests could
have changed.
"""

import io
import json
import logging
import re
import socket
import threading
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

from cloud_service import app as cloud
from edge_gateway import admin
from edge_gateway import gateway as gw
from legacy_device.protocol import build_reading, encrypt_frame
from observability import logs, metrics
from pqc_channel import channel

BASE = "http://testserver"
READING = {"device_id": "dev-001", "seq": 1, "temp_c": 21.5,
           "humidity": 44.2, "uptime_s": 12}

# One sample line of the Prometheus text format: name{labels} value
SAMPLE = re.compile(
    r'^[a-zA-Z_:][a-zA-Z0-9_:]*'
    r'(\{[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*"'
    r'(,[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*")*\})?'
    r' -?[0-9.e+-]+$')


def parse(text: str) -> dict:
    """Prometheus text -> {(name, frozenset(labels)): value}.

    Also checks every line is well formed, so a formatting bug fails here
    rather than in a scraper nobody is watching.
    """
    samples = {}
    for line in text.strip().splitlines():
        if line.startswith("#"):
            assert re.match(r"^# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+$",
                            line), line
            continue
        assert SAMPLE.match(line), f"malformed metrics line: {line!r}"
        name, _, value = line.rpartition(" ")
        labels = frozenset()
        if "{" in name:
            name, label_text = name[:-1].split("{", 1)
            labels = frozenset(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"',
                                          label_text))
        samples[(name, labels)] = float(value)
    return samples


def value(samples: dict, name: str, **labels) -> float:
    return samples.get((name, frozenset(labels.items())), 0.0)


@pytest.fixture(autouse=True)
def clean_cloud():
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


def cloud_metrics(client) -> dict:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    return parse(response.text)


def make_uplink(http, **kwargs):
    stats = gw.GatewayStats()
    return gw.PqcUplink(BASE, stats, http=http, **kwargs), stats


class Recorder:
    """Passes requests to the cloud and keeps the last POST body."""

    def __init__(self, inner):
        self.inner = inner
        self.last_post = None

    def get(self, url, **kwargs):
        return self.inner.get(url, **kwargs)

    def post(self, url, json=None, **kwargs):
        self.last_post = (url, json)
        return self.inner.post(url, json=json, **kwargs)


# --------------------------------------------------------------------------
# The metrics format
# --------------------------------------------------------------------------

def test_render_produces_valid_exposition_text():
    text = metrics.render([
        metrics.Family("x_total", "counter", "An example.",
                       [("x_total", (("reason", "a"),), 3)]),
        metrics.gauge("y", "A gauge.", 1.5),
    ])

    assert parse(text) == {("x_total", frozenset({("reason", "a")})): 3.0,
                           ("y", frozenset()): 1.5}
    assert "# TYPE x_total counter" in text


def test_label_values_are_escaped():
    """A quote or newline in a label must not break the line format."""
    text = metrics.render([metrics.gauge("g", "h", 1, v='a"b\nc\\d')])

    assert 'g{v="a\\"b\\nc\\\\d"} 1' in text
    parse(text)


def test_undeclared_metric_is_an_error():
    registry = metrics.Registry()

    with pytest.raises(KeyError):
        registry.inc("typo_total")


def test_registry_counts_correctly_across_threads():
    registry = metrics.Registry()
    registry.counter("c_total", "help")

    def work():
        for _ in range(1000):
            registry.inc("c_total", result="ok")

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert registry.value("c_total", result="ok") == 8000


# --------------------------------------------------------------------------
# Structured logs
# --------------------------------------------------------------------------

def make_record(**extra) -> logging.LogRecord:
    record = logging.makeLogRecord({"name": "t", "levelname": "INFO",
                                    "levelno": logging.INFO,
                                    "msg": "hello %s", "args": ("world",)})
    record.__dict__.update(extra)
    return record


def test_json_log_line_carries_extra_fields():
    line = logs.JsonFormatter("gateway").format(
        make_record(event="forwarded", device_id="dev-001"))

    entry = json.loads(line)
    assert entry["message"] == "hello world"
    assert entry["service"] == "gateway"
    assert entry["event"] == "forwarded"
    assert entry["device_id"] == "dev-001"
    assert "\n" not in line


def test_json_log_never_fails_on_an_odd_value():
    """A log call must never raise, or it could cost a reading."""
    line = logs.JsonFormatter("cloud").format(make_record(blob=b"\x00\xff"))

    assert json.loads(line)["blob"]


@pytest.fixture
def root_logger():
    """Restore the root logger after a test reconfigures it."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield root
    root.handlers[:] = handlers
    root.setLevel(level)


def test_configure_twice_does_not_duplicate_lines(root_logger):
    logs.configure("cloud", "json")
    logs.configure("cloud", "json")

    ours = [h for h in root_logger.handlers if h.get_name() == "observability"]
    assert len(ours) == 1


def test_json_mode_adopts_library_loggers(root_logger):
    """uvicorn installs its own plain-text handlers; in JSON mode those lines
    must go through our formatter so the stream stays parseable."""
    library = logging.getLogger("fake.library")
    library.addHandler(logging.StreamHandler(io.StringIO()))
    library.propagate = False
    try:
        logs.configure("cloud", "json", adopt=("fake.library",))

        assert library.handlers == []
        assert library.propagate is True
    finally:
        library.handlers.clear()
        library.propagate = True


def test_cloud_writes_its_own_events_as_json(client, root_logger, monkeypatch):
    """Regression test: under uvicorn the cloud's own INFO lines were
    silently dropped, because nothing configured a handler for them."""
    buffer = io.StringIO()
    monkeypatch.setattr("sys.stderr", buffer)
    logs.configure("cloud", "json")

    client.post("/api/v1/telemetry", json=READING,
                headers={"X-Gateway-Token": cloud.EXPECTED_TOKEN})

    events = [json.loads(line) for line in buffer.getvalue().splitlines()]
    ingested = [e for e in events if e.get("event") == "reading_ingested"]
    assert ingested and ingested[0]["device_id"] == "dev-001"
    assert ingested[0]["channel"] == "legacy"


# --------------------------------------------------------------------------
# Cloud /metrics
# --------------------------------------------------------------------------

def test_cloud_metrics_report_the_key_and_migration_state(client):
    samples = cloud_metrics(client)

    assert value(samples, "cloud_pqc_key_info", algorithm="ML-KEM-768",
                 fingerprint=cloud.KEM_FINGERPRINT) == 1
    assert value(samples, "cloud_legacy_ingest_enabled") == int(
        cloud.LEGACY_INGEST_ENABLED)


def test_readings_are_counted_per_channel(client):
    before = cloud_metrics(client)
    client.post("/api/v1/telemetry", json=READING,
                headers={"X-Gateway-Token": cloud.EXPECTED_TOKEN})
    uplink, _ = make_uplink(client)
    uplink.send({**READING, "seq": 2})
    uplink.send({**READING, "seq": 3})
    after = cloud_metrics(client)

    def delta(**labels):
        return (value(after, "cloud_readings_ingested_total", **labels)
                - value(before, "cloud_readings_ingested_total", **labels))

    assert delta(channel="legacy") == 1
    assert delta(channel="mlkem") == 2
    assert (value(after, "cloud_handshakes_total", result="ok")
            - value(before, "cloud_handshakes_total", result="ok")) == 1
    assert value(after, "cloud_active_sessions") == 1
    assert value(after, "cloud_handshake_duration_seconds_count") >= 1


def rejected(client, reason: str) -> float:
    return value(cloud_metrics(client), "cloud_messages_rejected_total",
                 reason=reason)


def test_replay_is_counted(client):
    recorder = Recorder(client)
    uplink, _ = make_uplink(recorder)
    uplink.send(READING)
    url, body = recorder.last_post
    before = rejected(client, "replay")

    client.post(url, json=body)

    assert rejected(client, "replay") - before == 1


def test_tampering_is_counted_as_an_authentication_failure(client):
    recorder = Recorder(client)
    uplink, _ = make_uplink(recorder)
    uplink.send(READING)
    url, body = recorder.last_post
    sealed = bytearray(channel.b64decode(body["ciphertext"]))
    sealed[0] ^= 0x01
    before = rejected(client, "authentication_failed")

    client.post(url, json={**body, "ciphertext": channel.b64encode(bytes(sealed)),
                           "nonce": channel.b64encode(channel.nonce_for(500))})

    assert rejected(client, "authentication_failed") - before == 1


def test_unknown_session_is_counted(client):
    before = rejected(client, "unknown_session")

    client.post("/api/v2/telemetry", json={
        "session_id": "f" * 32,
        "nonce": channel.b64encode(channel.nonce_for(0)),
        "ciphertext": channel.b64encode(b"x" * 40)})

    assert rejected(client, "unknown_session") - before == 1


def test_wrong_gateway_proof_is_counted_as_a_failed_handshake(client):
    def invalid_proofs():
        return value(cloud_metrics(client), "cloud_handshakes_total",
                     result="invalid_proof")
    before = invalid_proofs()
    uplink, _ = make_uplink(client, token="wrong-token")

    with pytest.raises(gw.UplinkError):
        uplink.send(READING)

    assert invalid_proofs() - before == 1


def test_traffic_to_the_retired_legacy_path_is_counted(client, monkeypatch):
    """After the migration, any legacy traffic is a missed gateway or a
    probe, so it must be visible."""
    monkeypatch.setattr(cloud, "LEGACY_INGEST_ENABLED", False)
    before = rejected(client, "legacy_disabled")

    response = client.post("/api/v1/telemetry", json=READING,
                           headers={"X-Gateway-Token": cloud.EXPECTED_TOKEN})

    assert response.status_code == 410
    assert rejected(client, "legacy_disabled") - before == 1
    assert value(cloud_metrics(client), "cloud_legacy_ingest_enabled") == 0


def test_session_evictions_are_counted(client, monkeypatch):
    monkeypatch.setattr(cloud, "MAX_SESSIONS", 2)
    before = value(cloud_metrics(client), "cloud_sessions_evicted_total")

    for _ in range(4):
        make_uplink(client)[0].send(READING)

    assert value(cloud_metrics(client), "cloud_sessions_evicted_total") \
        - before == 2


# --------------------------------------------------------------------------
# Gateway /health and /metrics, over real HTTP
# --------------------------------------------------------------------------

class GatewayWithAdmin:
    """A real GatewayServer plus its admin server, both on free ports."""

    def __init__(self, uplink, stats):
        self.server = gw.GatewayServer(("127.0.0.1", 0), uplink, stats)
        self.stats = stats
        self.admin = admin.start(self.server, "127.0.0.1", 0)
        self.admin_url = f"http://127.0.0.1:{self.admin.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        for srv in (self.server, self.admin):
            srv.shutdown()
            srv.server_close()
        self._thread.join(timeout=5)

    def get(self, path: str):
        with urllib.request.urlopen(self.admin_url + path, timeout=5) as resp:
            return resp.status, resp.headers["Content-Type"], resp.read().decode()

    def health(self) -> dict:
        return json.loads(self.get("/health")[2])

    def metrics(self) -> dict:
        return parse(self.get("/metrics")[2])

    def send_frames(self, *seqs: int) -> None:
        port = self.server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            for seq in seqs:
                sock.sendall(encrypt_frame(
                    build_reading("dev-001", seq, 21.0, 45.0, seq)))
            sock.shutdown(socket.SHUT_WR)
            sock.recv(1)


def wait_until(predicate, timeout: float = 10.0) -> bool:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_gateway_health_is_ok_when_pinned_and_forwarding(client):
    uplink, stats = make_uplink(client, pinned_fingerprint=cloud.KEM_FINGERPRINT)

    with GatewayWithAdmin(uplink, stats) as gateway:
        status_code, content_type, _ = gateway.get("/health")
        gateway.send_frames(1, 2)
        assert wait_until(lambda: stats.snapshot()["forwarded_ok"] == 2)
        health = gateway.health()
        samples = gateway.metrics()

    assert status_code == 200 and content_type == "application/json"
    assert health["status"] == "ok"
    assert health["warnings"] == []
    assert health["crypto"] == "mlkem"
    assert health["cloud_key_pinned"] is True
    assert health["pqc_session"]["active"] is True
    assert health["pqc_session"]["messages_sent"] == 2
    assert health["last_forward_ok_s_ago"] is not None
    assert value(samples, "gateway_uplink_info", crypto="mlkem",
                 pinned="true") == 1
    assert value(samples, "gateway_forwards_total", result="ok") == 2
    assert value(samples, "gateway_handshakes_total", result="ok") == 1
    assert value(samples, "gateway_handshake_duration_seconds_count") == 1
    assert value(samples, "gateway_pqc_session_active") == 1


def test_health_never_leaks_key_material(client):
    uplink, stats = make_uplink(client, pinned_fingerprint=cloud.KEM_FINGERPRINT)

    with GatewayWithAdmin(uplink, stats) as gateway:
        gateway.send_frames(1)
        assert wait_until(lambda: stats.snapshot()["forwarded_ok"] == 1)
        body = gateway.get("/health")[2] + gateway.get("/metrics")[2]
        session = uplink._session

    assert channel.b64encode(session.aead_key) not in body
    assert session.aead_key.hex() not in body
    assert session.session_id not in body, "only an 8-character prefix"


def test_gateway_health_is_degraded_when_the_cloud_is_down():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
    stats = gw.GatewayStats()
    uplink = gw.PqcUplink(f"http://127.0.0.1:{dead_port}", stats,
                          pinned_fingerprint="0" * 64)

    with GatewayWithAdmin(uplink, stats) as gateway:
        gateway.send_frames(1, 2)
        assert wait_until(lambda: stats.snapshot()["forward_failed"] == 2)
        status_code, _, body = gateway.get("/health")
        samples = gateway.metrics()

    health = json.loads(body)
    assert status_code == 200, "liveness: the process itself is fine"
    assert health["status"] == "degraded"
    assert health["consecutive_forward_failures"] == 2
    assert any("forwards failed" in w for w in health["warnings"])
    assert value(samples, "gateway_consecutive_forward_failures") == 2
    assert value(samples, "gateway_handshakes_total", result="failed") == 2


def test_failure_streak_resets_after_a_success():
    stats = gw.GatewayStats()
    stats.forward_failed_with(OSError("cloud down"))
    stats.forward_failed_with(OSError("cloud down"))

    stats.forward_succeeded()

    assert stats.state()["consecutive_forward_failures"] == 0
    assert stats.snapshot()["forward_failed"] == 2, "the total is kept"


def test_trust_on_first_use_is_still_reported_as_unpinned(client):
    """After a TOFU handshake the uplink holds a fingerprint, but nobody
    configured it. /health must not mistake that for a real pin."""
    uplink, stats = make_uplink(client)  # no pinned_fingerprint

    with GatewayWithAdmin(uplink, stats) as gateway:
        gateway.send_frames(1)
        assert wait_until(lambda: stats.snapshot()["forwarded_ok"] == 1)
        health = gateway.health()
        samples = gateway.metrics()

    assert uplink.pinned is not None, "TOFU filled in a fingerprint"
    assert health["cloud_key_pinned"] is False
    assert any("not pinned" in w for w in health["warnings"])
    assert value(samples, "gateway_uplink_info", crypto="mlkem",
                 pinned="false") == 1


def test_rollback_and_missing_pin_show_up_as_warnings():
    """The two states an operator must never miss after the migration."""
    stats = gw.GatewayStats()

    with GatewayWithAdmin(gw.LegacyUplink("http://cloud.test"), stats) as gw_:
        health = gw_.health()
        samples = gw_.metrics()

    assert health["status"] == "degraded"
    assert any("legacy cloud path" in w for w in health["warnings"])
    assert any("not pinned" in w for w in health["warnings"])
    assert health["pqc_session"] is None
    assert value(samples, "gateway_uplink_info", crypto="legacy",
                 pinned="false") == 1


def test_unknown_admin_path_is_404(client):
    uplink, stats = make_uplink(client)

    with GatewayWithAdmin(uplink, stats) as gateway, \
            pytest.raises(urllib.error.HTTPError) as error:
        gateway.get("/nothing-here")

    assert error.value.code == 404

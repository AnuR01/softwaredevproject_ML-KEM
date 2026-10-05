"""
Tests for the cloud telemetry service.

Uses FastAPI's TestClient, which runs the real application in-process - so
routing, header handling and Pydantic validation are all genuinely exercised
without binding a port.

Storage is module-level state, so every test starts from an empty buffer via
the autouse fixture below. Without it, tests would pass or fail depending on
the order pytest happened to run them in.
"""

import pytest
from fastapi.testclient import TestClient

from cloud_service import app as cloud

TOKEN = cloud.EXPECTED_TOKEN
AUTH = {"X-Gateway-Token": TOKEN}


@pytest.fixture(autouse=True)
def empty_store():
    """Clear the in-memory readings before and after each test."""
    with cloud._lock:
        cloud._readings.clear()
    yield
    with cloud._lock:
        cloud._readings.clear()


@pytest.fixture
def client():
    return TestClient(cloud.app)


def reading(seq: int = 1, device_id: str = "dev-001", **overrides) -> dict:
    """A valid reading body, with fields overridable per test."""
    body = {
        "device_id": device_id,
        "seq": seq,
        "temp_c": 21.5,
        "humidity": 44.2,
        "uptime_s": 12,
    }
    body.update(overrides)
    return body


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------

def test_health_is_reachable_without_a_token(client):
    """Orchestrators and uptime monitors have no credentials."""
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["stored_readings"] == 0
    assert body["uptime_s"] >= 0


def test_health_reports_the_stored_count(client):
    client.post("/api/v1/telemetry", json=reading(1), headers=AUTH)
    client.post("/api/v1/telemetry", json=reading(2), headers=AUTH)

    assert client.get("/health").json()["stored_readings"] == 2


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def test_ingest_requires_a_token(client):
    response = client.post("/api/v1/telemetry", json=reading())

    assert response.status_code == 401
    assert client.get("/health").json()["stored_readings"] == 0


def test_ingest_rejects_a_wrong_token(client):
    response = client.post("/api/v1/telemetry", json=reading(),
                           headers={"X-Gateway-Token": "wrong"})

    assert response.status_code == 401


@pytest.mark.security
def test_finding_any_holder_of_the_static_token_can_inject_telemetry(client):
    """FINDING: the shared token is authentication in name only.

    There is one token for every gateway, it is committed to the repository,
    and it never rotates. Anyone who reads the source - or watches the plain
    HTTP traffic - can post arbitrary readings for any device id, and nothing
    downstream can tell them from real ones.

    Impact: telemetry cannot be trusted as evidence of anything.
    Fix: per-gateway identity and session keys established with ML-KEM, so a
    forged request cannot produce a valid authenticated message.
    """
    forged = reading(seq=9999, device_id="dev-does-not-exist", temp_c=-40.0)

    response = client.post("/api/v1/telemetry", json=forged, headers=AUTH)

    assert response.status_code == 202
    devices = client.get("/api/v1/devices").json()["devices"]
    assert devices[0]["device_id"] == "dev-does-not-exist"


# --------------------------------------------------------------------------
# Ingestion and validation
# --------------------------------------------------------------------------

def test_ingest_accepts_a_valid_reading(client):
    response = client.post("/api/v1/telemetry", json=reading(1), headers=AUTH)

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "device_id": "dev-001",
                               "seq": 1}


def test_ingest_adds_a_server_side_receive_timestamp(client):
    """Device clocks are untrustworthy, so the cloud stamps arrival itself."""
    client.post("/api/v1/telemetry", json=reading(1), headers=AUTH)

    stored = client.get("/api/v1/telemetry").json()["readings"][0]
    assert "received_at" in stored
    assert stored["received_at"].endswith("+00:00"), "must be UTC"


@pytest.mark.parametrize("bad", [
    {"humidity": 120.0},        # above 100% RH is physically impossible
    {"humidity": -1.0},
    {"temp_c": 1e9},            # obvious corruption
    {"temp_c": -273.0},
    {"seq": -1},                # counters only go up
    {"uptime_s": -5},
    {"device_id": ""},          # must identify a device
    {"device_id": "d" * 65},    # longer than the field allows
])
def test_ingest_rejects_out_of_range_values(client, bad):
    """Validation is a second line of defence behind the gateway's parsing."""
    response = client.post("/api/v1/telemetry", json=reading(**bad),
                           headers=AUTH)

    assert response.status_code == 422


def test_ingest_rejects_a_missing_field(client):
    body = reading()
    del body["humidity"]

    response = client.post("/api/v1/telemetry", json=body, headers=AUTH)

    assert response.status_code == 422


# --------------------------------------------------------------------------
# Reading data back
# --------------------------------------------------------------------------

def test_telemetry_returns_newest_first(client):
    for seq in range(1, 4):
        client.post("/api/v1/telemetry", json=reading(seq), headers=AUTH)

    body = client.get("/api/v1/telemetry").json()

    assert [r["seq"] for r in body["readings"]] == [3, 2, 1]
    assert body["count"] == 3


def test_telemetry_limit_returns_the_most_recent(client):
    for seq in range(1, 11):
        client.post("/api/v1/telemetry", json=reading(seq), headers=AUTH)

    body = client.get("/api/v1/telemetry?limit=3").json()

    assert [r["seq"] for r in body["readings"]] == [10, 9, 8]


def test_telemetry_clamps_a_nonsense_limit(client):
    """A careless caller gets a sensible page rather than an error."""
    client.post("/api/v1/telemetry", json=reading(1), headers=AUTH)

    assert client.get("/api/v1/telemetry?limit=0").status_code == 200
    assert client.get("/api/v1/telemetry?limit=99999").status_code == 200


def test_telemetry_filters_by_device(client):
    client.post("/api/v1/telemetry", json=reading(1, "dev-001"), headers=AUTH)
    client.post("/api/v1/telemetry", json=reading(1, "dev-002"), headers=AUTH)

    body = client.get("/api/v1/telemetry?device_id=dev-002").json()

    assert body["count"] == 1
    assert body["readings"][0]["device_id"] == "dev-002"


def test_devices_summarises_each_device(client):
    client.post("/api/v1/telemetry", json=reading(1, "dev-001"), headers=AUTH)
    client.post("/api/v1/telemetry",
                json=reading(2, "dev-001", temp_c=30.0), headers=AUTH)
    client.post("/api/v1/telemetry", json=reading(1, "dev-002"), headers=AUTH)

    body = client.get("/api/v1/devices").json()
    by_id = {d["device_id"]: d for d in body["devices"]}

    assert body["count"] == 2
    assert by_id["dev-001"]["readings"] == 2
    assert by_id["dev-001"]["last_seq"] == 2
    assert by_id["dev-001"]["last_temp_c"] == 30.0, "last write must win"
    assert by_id["dev-002"]["readings"] == 1


def test_storage_is_bounded(client):
    """The ring buffer must drop the oldest readings, not grow forever.

    Exercised with a temporarily shrunken buffer so the test stays fast; the
    production value is 1000.
    """
    original = cloud._readings.maxlen
    assert original == cloud.MAX_STORED_READINGS

    import collections
    with cloud._lock:
        cloud._readings = collections.deque(maxlen=5)
    try:
        for seq in range(1, 9):
            client.post("/api/v1/telemetry", json=reading(seq), headers=AUTH)

        body = client.get("/api/v1/telemetry").json()
        assert body["count"] == 5
        assert [r["seq"] for r in body["readings"]] == [8, 7, 6, 5, 4]
    finally:
        with cloud._lock:
            cloud._readings = collections.deque(maxlen=original)


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

def test_dashboard_is_served_at_the_root(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "PQC Telemetry Dashboard" in response.text


def test_dashboard_never_uses_innerhtml(client):
    """Device ids are attacker-controlled; the page must write them as text.

    A reading posted with device_id "<img src=x onerror=...>" would run as
    script if the dashboard inserted it with innerHTML.
    """
    page = client.get("/").text
    for sink in (".innerHTML", ".outerHTML", "insertAdjacentHTML",
                 "document.write"):
        assert sink not in page, f"dashboard uses {sink}"


def test_health_counts_readings_per_channel(client):
    client.post("/api/v1/telemetry", json=reading(1), headers=AUTH)
    client.post("/api/v1/telemetry", json=reading(2), headers=AUTH)

    counts = client.get("/health").json()["pqc"]["readings_by_channel"]

    assert counts == {"mlkem": 0, "legacy": 2}

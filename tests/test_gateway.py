"""
Tests for the edge gateway.

The unit tests cover the replay tracker and the stats counters. The
integration tests start a real GatewayServer on an ephemeral port, connect a
socket the way a device would, and replace the outbound HTTP call with a stub -
so the gateway's threading, framing and error handling are all exercised
without needing a running cloud service.
"""

import socket
import threading
import time

import pytest
import requests

from edge_gateway import gateway as gw
from legacy_device.protocol import build_reading, encrypt_frame

# --------------------------------------------------------------------------
# Unit tests
# --------------------------------------------------------------------------

def test_sequence_tracker_accepts_increasing_numbers():
    tracker = gw.SequenceTracker()

    assert tracker.accept("dev-001", 1) is True
    assert tracker.accept("dev-001", 2) is True
    assert tracker.accept("dev-001", 99) is True


def test_sequence_tracker_rejects_replays_and_stale_frames():
    tracker = gw.SequenceTracker()
    tracker.accept("dev-001", 5)

    assert tracker.accept("dev-001", 5) is False, "exact replay"
    assert tracker.accept("dev-001", 4) is False, "older frame"


def test_sequence_tracker_keeps_devices_independent():
    """One device's counter must not affect another's."""
    tracker = gw.SequenceTracker()
    tracker.accept("dev-001", 100)

    assert tracker.accept("dev-002", 1) is True


def test_sequence_tracker_documents_the_reboot_weakness():
    """A rebooted device restarts at 1 and is then silently ignored.

    This is a real operational failure mode of the baseline system, not a bug
    in the test: replay state lives only in memory and only moves forward, so
    a power-cycled device is locked out until its counter climbs past the old
    high-water mark. Store the state, or authenticate frames properly, and the
    problem goes away.
    """
    tracker = gw.SequenceTracker()
    tracker.accept("dev-001", 500)

    assert tracker.accept("dev-001", 1) is False


def test_stats_snapshot_is_consistent():
    stats = gw.GatewayStats()
    stats.bump("frames_received")
    stats.bump("frames_received")
    stats.bump("forwarded_ok")

    assert stats.snapshot() == {
        "frames_received": 2,
        "frames_rejected": 0,
        "forwarded_ok": 1,
        "forward_failed": 0,
        "replays_dropped": 0,
        "handshakes_ok": 0,
        "handshakes_failed": 0,
    }


def test_stats_survive_concurrent_updates():
    """The counters are shared across device threads, so the lock must hold.

    Without the lock this loses increments intermittently, which would make
    every number in our final report quietly wrong.
    """
    stats = gw.GatewayStats()
    per_thread = 500

    def worker():
        for _ in range(per_thread):
            stats.bump("frames_received")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert stats.snapshot()["frames_received"] == 8 * per_thread


# --------------------------------------------------------------------------
# Integration fixtures
# --------------------------------------------------------------------------

class CloudStub:
    """Records what the gateway tried to POST, instead of sending it.

    Substituted for requests.post, so the gateway's real forwarding code path
    runs - headers, JSON body, timeout and status handling included.
    """

    def __init__(self, fail_with: Exception | None = None,
                 status_code: int = 202) -> None:
        self.calls: list[dict] = []
        self.fail_with = fail_with
        self.status_code = status_code
        self._lock = threading.Lock()

    def post(self, url, json=None, headers=None, timeout=None):
        with self._lock:
            self.calls.append({"url": url, "json": json, "headers": headers,
                               "timeout": timeout})
        if self.fail_with is not None:
            raise self.fail_with

        stub = self

        class _Response:
            status_code = stub.status_code

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise requests.HTTPError(f"status {self.status_code}")

        return _Response()


@pytest.fixture
def running_gateway(monkeypatch):
    """Start a GatewayServer on the legacy path with a stubbed cloud.

    These tests exercise the device-facing side (framing, replay, threading),
    which is the same whichever uplink is configured; the legacy uplink is
    used because its single POST is the simplest thing to stub. The ML-KEM
    uplink is tested against the real cloud in tests/test_pqc_integration.py.

    Yields (server, cloud_stub, port). The server is shut down afterwards so
    tests do not leak threads or sockets.
    """
    cloud = CloudStub()
    monkeypatch.setattr(gw.requests, "post", cloud.post)

    # Port 0 asks the OS for any free port, so tests never collide with a
    # gateway the developer is running by hand on 9000.
    server = gw.GatewayServer(("127.0.0.1", 0),
                              gw.LegacyUplink("http://cloud.test"))
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, cloud, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def send_frames(port: int, frames: list[bytes]) -> None:
    """Connect like a device, send raw frames, and close cleanly."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        for frame in frames:
            sock.sendall(frame)
        # Half-close so the gateway's read loop sees EOF and finishes the
        # frames already in flight before we tear the socket down.
        sock.shutdown(socket.SHUT_WR)
        sock.recv(1)


def wait_for(predicate, timeout: float = 5.0) -> bool:
    """Poll until predicate() is true. Handler threads run asynchronously."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# --------------------------------------------------------------------------
# Integration tests
# --------------------------------------------------------------------------

def test_valid_frame_is_decrypted_and_forwarded(running_gateway):
    server, cloud, port = running_gateway
    record = build_reading("dev-001", 1, 21.50, 44.20, 12)

    send_frames(port, [encrypt_frame(record)])

    assert wait_for(lambda: len(cloud.calls) == 1)
    call = cloud.calls[0]
    assert call["url"] == "http://cloud.test/api/v1/telemetry"
    assert call["headers"]["X-Gateway-Token"] == gw.GATEWAY_TOKEN
    assert call["json"] == {
        "device_id": "dev-001",
        "seq": 1,
        "temp_c": 21.50,
        "humidity": 44.20,
        "uptime_s": 12,
    }
    assert server.stats.snapshot()["forwarded_ok"] == 1


def test_multiple_frames_on_one_connection_are_all_forwarded(running_gateway):
    """Devices hold one connection open for many readings."""
    _, cloud, port = running_gateway
    frames = [
        encrypt_frame(build_reading("dev-001", seq, 20.0 + seq, 40.0, seq))
        for seq in range(1, 6)
    ]

    send_frames(port, frames)

    assert wait_for(lambda: len(cloud.calls) == 5)
    assert [c["json"]["seq"] for c in cloud.calls] == [1, 2, 3, 4, 5]


def test_replayed_frame_is_dropped_before_the_cloud(running_gateway):
    """An attacker resending a captured frame must not duplicate a reading."""
    server, cloud, port = running_gateway
    frame = encrypt_frame(build_reading("dev-001", 1, 21.0, 45.0, 10))

    send_frames(port, [frame, frame])

    assert wait_for(lambda: server.stats.snapshot()["replays_dropped"] == 1)
    assert len(cloud.calls) == 1, "the replay must not reach the cloud"


def test_undecodable_frame_is_counted_and_not_forwarded(running_gateway):
    server, cloud, port = running_gateway

    send_frames(port, [b"this-is-not-a-valid-frame\n"])

    assert wait_for(lambda: server.stats.snapshot()["frames_rejected"] == 1)
    assert cloud.calls == []


def test_a_bad_frame_does_not_stop_later_good_frames(running_gateway):
    """One corrupt frame must not kill the connection or the thread."""
    server, cloud, port = running_gateway
    good = encrypt_frame(build_reading("dev-001", 1, 21.0, 45.0, 10))

    send_frames(port, [b"garbage\n", good])

    assert wait_for(lambda: len(cloud.calls) == 1)
    snapshot = server.stats.snapshot()
    assert snapshot["frames_rejected"] == 1
    assert snapshot["forwarded_ok"] == 1


def test_oversized_frame_is_rejected(running_gateway):
    """Bounds the gateway's exposure to a hostile or broken client."""
    server, cloud, port = running_gateway
    oversized = b"a" * (gw.MAX_FRAME_BYTES + 10) + b"\n"

    send_frames(port, [oversized])

    assert wait_for(lambda: server.stats.snapshot()["frames_rejected"] == 1)
    assert cloud.calls == []


def test_cloud_failure_is_counted_and_the_reading_is_lost(monkeypatch):
    """Documents the missing store-and-forward queue.

    When the cloud is unreachable the gateway logs and counts the failure, and
    the reading is gone for good. This test exists so that the loss is a
    recorded, deliberate limitation rather than a surprise during the final
    evaluation.
    """
    cloud = CloudStub(fail_with=requests.ConnectionError("cloud is down"))
    monkeypatch.setattr(gw.requests, "post", cloud.post)

    server = gw.GatewayServer(("127.0.0.1", 0),
                              gw.LegacyUplink("http://cloud.test"))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        send_frames(port, [encrypt_frame(build_reading("dev-001", 1, 21.0, 45.0, 10))])

        assert wait_for(lambda: server.stats.snapshot()["forward_failed"] == 1)
        assert server.stats.snapshot()["forwarded_ok"] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_abrupt_device_disconnect_does_not_raise(running_gateway):
    """Regression test for the first defect we found in generated code.

    The original LLM-generated handler let ConnectionResetError escape, which
    killed the handler thread and printed a traceback for an event that
    happens whenever a field device loses power. The gateway must survive a
    socket reset mid-stream and keep serving other devices.
    """
    _, cloud, port = running_gateway
    frame = encrypt_frame(build_reading("dev-001", 1, 21.0, 45.0, 10))

    # Send a frame, then reset the connection instead of closing it. SO_LINGER
    # with a zero timeout makes close() send RST, which is what a device losing
    # power looks like on the wire.
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(frame)
    assert wait_for(lambda: len(cloud.calls) == 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    b"\x01\x00\x00\x00\x00\x00\x00\x00")
    sock.close()

    # The gateway must still accept a new device afterwards.
    send_frames(port, [encrypt_frame(build_reading("dev-002", 1, 22.0, 46.0, 5))])

    assert wait_for(lambda: len(cloud.calls) == 2)

"""
The gateway's admin endpoints: /health and /metrics over HTTP.

The device port (9000) speaks the legacy line protocol, so these live on a
separate small HTTP server (port 9100 by default), started by gateway.main().
Like the device port it listens on localhost unless told otherwise; the
container entrypoint opens it so Docker's healthcheck and a metrics scraper
can reach it.

/health always answers 200 while the process is serving. "status" says
"degraded" when something needs an operator's attention: recent forwarding
failures, the legacy cloud path in use, or no pinned cloud key. A 503 for
those would make container healthchecks fail and could restart a gateway
whose only problem is that the cloud is down, which helps nobody.
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from observability import metrics

log = logging.getLogger("edge-gateway.admin")


def health(gateway) -> dict:
    """What an operator needs to know about this gateway, as a dict."""
    uplink = gateway.uplink
    state = gateway.stats.state()
    warnings = []
    if uplink.name == "legacy":
        warnings.append("legacy cloud path in use: readings and the gateway "
                        "token cross the network unprotected")
    if not uplink.pin_configured:
        warnings.append("cloud key not pinned: trusting the first key seen")
    if state["consecutive_forward_failures"]:
        warnings.append(f"last {state['consecutive_forward_failures']} "
                        f"forwards failed: {state['last_error']}")

    last_ok = state["last_forward_ok_at"]
    return {
        "status": "degraded" if warnings else "ok",
        "warnings": warnings,
        "crypto": uplink.name,
        "cloud_url": uplink.cloud_url,
        "cloud_key_pinned": uplink.pin_configured,
        "pqc_session": uplink.session_info(),
        "last_forward_ok_s_ago": (round(time.time() - last_ok, 1)
                                  if last_ok is not None else None),
        "consecutive_forward_failures": state["consecutive_forward_failures"],
        "counters": gateway.stats.snapshot(),
    }


def prometheus(gateway) -> str:
    """The gateway's counters in the Prometheus text format."""
    counts = gateway.stats.snapshot()
    state = gateway.stats.state()
    uplink = gateway.uplink
    session = uplink.session_info()

    def counter(name, help_text, *samples):
        return metrics.Family(name, "counter", help_text, [
            (name, tuple(sorted(labels.items())), value)
            for labels, value in samples])

    return metrics.render([
        counter("gateway_frames_received_total",
                "Frames received from devices.",
                ({}, counts["frames_received"])),
        counter("gateway_frames_rejected_total",
                "Device frames dropped as oversized or undecodable.",
                ({}, counts["frames_rejected"])),
        counter("gateway_replays_dropped_total",
                "Device frames dropped as replayed or out of order.",
                ({}, counts["replays_dropped"])),
        counter("gateway_forwards_total",
                "Readings sent to the cloud, by result.",
                ({"result": "ok"}, counts["forwarded_ok"]),
                ({"result": "failed"}, counts["forward_failed"])),
        counter("gateway_handshakes_total",
                "ML-KEM handshakes with the cloud, by result.",
                ({"result": "ok"}, counts["handshakes_ok"]),
                ({"result": "failed"}, counts["handshakes_failed"])),
        metrics.Family(
            "gateway_handshake_duration_seconds", "summary",
            "Wall time of successful ML-KEM handshakes, network included.",
            [("gateway_handshake_duration_seconds_sum", (),
              state["handshake_seconds_sum"]),
             ("gateway_handshake_duration_seconds_count", (),
              state["handshake_seconds_count"])]),
        metrics.gauge("gateway_consecutive_forward_failures",
                      "Forwards failed since the last success.",
                      state["consecutive_forward_failures"]),
        metrics.gauge("gateway_pqc_session_active",
                      "1 while an ML-KEM session with the cloud is open.",
                      int(bool(session and session["active"]))),
        # The two values an alert should watch during and after the
        # migration: crypto="legacy" means a rollback is in effect, and
        # pinned="false" means trust on first use.
        metrics.gauge("gateway_uplink_info",
                      "Which cloud path this gateway uses.", 1,
                      crypto=uplink.name,
                      pinned=str(uplink.pin_configured).lower()),
    ])


class _AdminHandler(BaseHTTPRequestHandler):
    """Serves /health and /metrics; self.server.gateway is the GatewayServer."""

    def do_GET(self) -> None:  # name required by http.server
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(200, "application/json",
                       json.dumps(health(self.server.gateway)))
        elif path == "/metrics":
            self._send(200, "text/plain; version=0.0.4; charset=utf-8",
                       prometheus(self.server.gateway))
        else:
            self._send(404, "text/plain", "not found\n")

    def _send(self, code: int, content_type: str, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args) -> None:  # signature of the base class
        # Healthchecks every few seconds would flood the log at INFO.
        log.debug("admin %s", format % args)


def start(gateway, host: str, port: int) -> ThreadingHTTPServer:
    """Start the admin server on a daemon thread and return it."""
    server = ThreadingHTTPServer((host, port), _AdminHandler)
    server.daemon_threads = True
    server.gateway = gateway
    threading.Thread(target=server.serve_forever, name="admin-http",
                     daemon=True).start()
    return server

# Observability: Health Checks, Metrics and Logs

What the system reports about itself, and what an operator should watch.
The brief asks for "health checks, logs, and meaningful metrics" and for
"post-quantum-related observability". Meaningful here means: every metric
below answers a question an operator has during or after the migration, and
the alert table says what to do when it moves.

## Endpoints

| Service | Health | Metrics | Default address |
| --- | --- | --- | --- |
| Cloud | `GET /health` (JSON) | `GET /metrics` (Prometheus text) | `http://127.0.0.1:8000` |
| Gateway | `GET /health` (JSON) | `GET /metrics` (Prometheus text) | `http://127.0.0.1:9100` (`--admin-host`, `--admin-port`; `--admin-port 0` turns it off) |

The gateway serves these on a separate port because its device port speaks
the legacy line protocol, not HTTP. Both listen on localhost by default; the
container entrypoint opens the gateway's admin port inside the container, and
`compose.yaml` publishes it on the host's localhost only.

```bash
curl http://127.0.0.1:9100/health      # gateway
curl http://127.0.0.1:9100/metrics
curl http://127.0.0.1:8000/metrics     # cloud
```

### Gateway `/health`

```json
{
  "status": "ok",
  "warnings": [],
  "crypto": "mlkem",
  "cloud_key_pinned": true,
  "pqc_session": {"active": true, "session": "eaeecf85",
                  "messages_sent": 6, "renews_in_s": 3534},
  "last_forward_ok_s_ago": 0.9,
  "consecutive_forward_failures": 0,
  "counters": {"frames_received": 6, "forwarded_ok": 6, "handshakes_ok": 1, "...": 0}
}
```

`status` is `degraded`, with a reason in `warnings`, when:

* the last forwards to the cloud failed (cloud down, handshake refused);
* the gateway runs on the **legacy** cloud path (a rollback is in effect);
* no cloud key fingerprint was configured (**trust on first use**).

It still answers HTTP 200 when degraded. `/health` is a liveness check for
the gateway process, and Docker's healthcheck uses it. Answering 503 would
make a gateway whose only problem is a cloud outage look broken, and an
orchestrator might restart it, which fixes nothing.

The session id is shown as an 8-character prefix only, to match log lines
without exposing a usable id. No key material ever appears (tested in
`test_health_never_leaks_key_material`).

## Metrics

### Cloud

| Metric | Type | Labels | Question it answers |
| --- | --- | --- | --- |
| `cloud_readings_ingested_total` | counter | `channel` = mlkem / legacy | How far has the migration got? Legacy should fall to zero. |
| `cloud_handshakes_total` | counter | `result` = ok / invalid_proof / malformed | Are gateways connecting? Is someone trying without the token? |
| `cloud_handshake_duration_seconds` | summary | | What does ML-KEM cost the cloud per session? |
| `cloud_messages_rejected_total` | counter | `reason` (below) | Is anyone tampering, replaying or probing? |
| `cloud_sessions_evicted_total` | counter | | Is something handshaking far too often (bug or flood)? |
| `cloud_active_sessions` | gauge | | How many gateways are connected right now? |
| `cloud_legacy_ingest_enabled` | gauge | | Is the old path still open? |
| `cloud_pqc_key_info` | gauge (always 1) | `algorithm`, `fingerprint` | Which key is the cloud serving? A change means the key was lost or rotated. |
| `cloud_uptime_seconds` | gauge | | Did the cloud restart? (Counters reset to zero when it does.) |

Rejection reasons: `invalid_token` (legacy path), `legacy_disabled`,
`malformed`, `unknown_session`, `authentication_failed` (AES-GCM tag check
failed: tampering, or a wrong key), `replay`, `session_exhausted`,
`invalid_reading`.

### Gateway

| Metric | Type | Labels | Question it answers |
| --- | --- | --- | --- |
| `gateway_uplink_info` | gauge (always 1) | `crypto` = mlkem / legacy, `pinned` = true / false | Is this gateway migrated and pinned? |
| `gateway_handshakes_total` | counter | `result` = ok / failed | Can the gateway establish ML-KEM sessions? |
| `gateway_handshake_duration_seconds` | summary | | Handshake time including the network (about 40 ms measured locally). |
| `gateway_pqc_session_active` | gauge | | Is a session open right now? |
| `gateway_forwards_total` | counter | `result` = ok / failed | Are readings reaching the cloud? |
| `gateway_consecutive_forward_failures` | gauge | | How long has the cloud been unreachable, in readings? |
| `gateway_frames_received_total` | counter | | Are devices sending? |
| `gateway_frames_rejected_total` | counter | | Corrupt or hostile frames on the device link? |
| `gateway_replays_dropped_total` | counter | | Replayed device frames (possible attack on the legacy hop)? |

## What to alert on

The rules below are written as Prometheus expressions for precision. This
project does not run a Prometheus server or an alert manager; they are the
specification for whoever operates it.

| Alert | Expression | Why it matters | First action |
| --- | --- | --- | --- |
| **Rollback in effect** | `gateway_uplink_info{crypto="legacy"} == 1` | Readings and the token cross the network unprotected | Confirm it is a documented, time-limited decision (architecture.md, section 5) |
| **Gateway not pinned** | `gateway_uplink_info{pinned="false"} == 1` | Open to a man in the middle at the first handshake | Configure `CLOUD_KEY_FINGERPRINT` |
| **Handshakes failing** | `increase(gateway_handshakes_total{result="failed"}[10m]) > 0` | Wrong pin, cloud key lost, or an attack on the link | Compare the gateway's pin with `cloud_pqc_key_info` |
| **Cloud key changed** | `changes(cloud_pqc_key_info[1h]) > 0` (fingerprint label changed) | Every pinned gateway will refuse the cloud | Restore the key file (architecture.md, scenario C) |
| **Tampering** | `increase(cloud_messages_rejected_total{reason="authentication_failed"}[5m]) > 0` | Messages modified in transit, or forged | Investigate the network path |
| **Replay** | `increase(cloud_messages_rejected_total{reason="replay"}[5m]) > 0` | Captured traffic is being resent | Investigate the network path |
| **Legacy traffic after retirement** | `increase(cloud_messages_rejected_total{reason="legacy_disabled"}[1h]) > 0` | A gateway was missed, or someone is probing the old path | Find the source |
| **Legacy still in use** | `cloud_legacy_ingest_enabled == 1 and increase(cloud_readings_ingested_total{channel="legacy"}[14d]) == 0` | Migration finished but the old path is still open | Phase 2: set `LEGACY_INGEST_ENABLED=false` |
| **Readings lost** | `gateway_consecutive_forward_failures > 10` | No store-and-forward, so these readings are gone | Check the cloud |
| **Session flood** | `increase(cloud_sessions_evicted_total[10m]) > 0` | A gateway is handshaking in a loop | Find the gateway (cloud logs, `session_opened` events) |

## Logs

With `LOG_FORMAT=json` (the default in `compose.yaml`) both services write one
JSON object per line. Every line has `ts`, `level`, `service`, `logger` and
`message`. Important events also carry an `event` field and the facts as
separate keys, so they can be filtered without parsing text:

```bash
docker compose logs --no-log-prefix gateway | jq 'select(.event == "handshake_failed")'
docker compose logs --no-log-prefix cloud | jq 'select(.reason == "replay")'
docker compose logs --no-log-prefix cloud | jq 'select(.device_id == "dev-001")'
```

| Service | `event` | When |
| --- | --- | --- |
| Gateway | `started` | Gateway listening; includes `crypto` |
| Gateway | `handshake_ok` / `handshake_failed` | Every handshake; `duration_ms` or `error` |
| Gateway | `trust_on_first_use` | Unpinned gateway accepted a cloud key |
| Gateway | `legacy_mode` | Gateway started on the legacy path |
| Gateway | `forwarded` / `forward_failed` | Every reading sent to the cloud |
| Gateway | `frame_rejected` / `replay_dropped` | Bad or replayed frame from a device |
| Gateway | `session_dropped` | Cloud forgot the session; re-handshaking |
| Cloud | `key_loaded` | Startup; includes the key `fingerprint` |
| Cloud | `session_opened` | Every successful handshake |
| Cloud | `reading_ingested` | Every stored reading; `device_id`, `channel` |
| Cloud | `request_rejected` | Every refusal; `reason` and HTTP `status` |
| Cloud | `invalid_token` | Wrong token on the legacy path |

uvicorn's own startup and request lines are converted to JSON too, so a log
collector never sees a mixed stream. CI checks that every line from both
containers parses as JSON.

`LOG_FORMAT=text` (the default outside Docker) gives the familiar one-line
format for a developer's terminal.

**A defect this fixed:** before this change the cloud's own log lines
(`ingested ...`, `ML-KEM session ... opened`, the key fingerprint at startup)
were never printed when it ran under uvicorn. uvicorn configures handlers only
for its own loggers, so INFO lines from ours were dropped. Regression test:
`test_cloud_writes_its_own_events_as_json`.

## Security notes

* `/metrics` and `/health` are unauthenticated, like most scrape endpoints.
  They contain nothing secret (the key fingerprint is public), but they do
  reveal traffic levels and which gateways are degraded. They should only be
  reachable from an internal network; here they bind to localhost.
* Logs contain device ids and session id prefixes, never keys, tokens or
  reading payloads beyond what `forwarded` already shows (device, sequence
  number, temperature in the text format).

## Limitations

* Counters live in memory and restart from zero with the service.
* No Prometheus server, dashboard or alert manager is deployed; the alert
  table above is a specification. The live dashboard at `/` covers the demo.
* The legacy device has no observability of its own; everything about the
  device hop is seen from the gateway.
* Requests that fail FastAPI's own body validation (HTTP 422 before our code
  runs) are not counted in `cloud_messages_rejected_total`.

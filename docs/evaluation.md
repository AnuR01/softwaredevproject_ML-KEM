# Final Evaluation

The brief's last step: "analyze and demonstrate [the system's] strengths and
weaknesses and identify remaining technical debt and risks". This document
gives the verdict and the evidence for it. The detailed risk register is in
[architecture.md](architecture.md) (section 6); this page refers to its
risk IDs (R1-R14) rather than repeating it.

## Verdict

The long-haul gateway-to-cloud link, the one exposed to "harvest now, decrypt
later", is protected by ML-KEM-768 with forward secrecy and authenticated
encryption. That was achieved **without changing the legacy devices**, at a
cost of one ~45 ms handshake per hour and no measurable change in throughput.
The migration can be rolled out gateway by gateway, watched through metrics,
and rolled back only by a deliberate operator decision.

The system is **not production-ready**, and is not meant to be. The device
link is still the legacy protocol with one hardcoded key for the whole fleet,
the ML-KEM library is not constant-time, and the handshake is our own
composition rather than a reviewed standard protocol.

## Strengths, with evidence

| Strength | Evidence |
| --- | --- |
| **Post-quantum key establishment on the exposed link** | ML-KEM-768 (FIPS 203) via kyber-py; `tests/test_pqc_channel.py` checks sizes against FIPS 203 and that both sides derive the same keys |
| **Forward secrecy**: stealing the cloud's key later does not decrypt recorded traffic | `test_stolen_long_term_key_does_not_decrypt_recorded_traffic` |
| **Tampering now detected** (the legacy IV-flip attack is closed on this link) | `test_tampered_message_is_rejected`; compare `test_finding_tampering_with_the_iv_rewrites_data_undetected` on the legacy hop |
| **Replays rejected** | `test_replayed_message_is_rejected` |
| **No downgrade**: blocking the handshake cannot push the gateway onto the legacy path | `test_blocked_handshake_never_falls_back_to_legacy` (reset, timeout, HTTP 503) |
| **Man in the middle caught** when the cloud key is pinned; containers refuse to start without a pin | `test_wrong_pin_refuses_to_connect`; CI step "Gateway refuses a malformed fingerprint" |
| **Fails closed** on a lost or corrupt cloud key | `test_pinned_gateway_refuses_a_cloud_that_lost_its_key`, `test_corrupt_key_file_stops_the_cloud_instead_of_replacing_it` |
| **Legacy compatibility**: devices need no change at all | Same device code and wire format before and after; `test_device_frame_reaches_the_cloud_over_mlkem` |
| **Recovers on its own** after a cloud outage or restart | `test_gateway_recovers_by_itself_after_an_outage`, `test_gateway_recovers_when_the_cloud_forgets_its_session` |
| **Migration is observable** | `cloud_readings_ingested_total{channel}`, `gateway_uplink_info{crypto,pinned}`, rejection counters by reason ([observability.md](observability.md)) |
| **Low cost** | Measurements below |
| **Verified, not just tested** | 142 tests; mutation testing of the security checks (5 defects), the failure tests (8) and the observability tests (8): every deliberate defect was caught ([quality-checks.md](quality-checks.md)) |
| **Automated quality gates** | Every push runs the tests on Python 3.11 and 3.12, ruff with security rules, pip-audit, and a full Docker test deployment |
| **Reproducible deployment** | Each CI run deploys from an empty runner using only the repository ([deployment.md](deployment.md)) |

## Cost of the migration

Measured on one laptop on 24 Sep 2026, legacy and ML-KEM paths back to back
(`docs/measurements/`):

| | Legacy path | ML-KEM path |
| --- | --- | --- |
| Key establishment | none | 4608 B raw (6497 B as JSON), 2 round trips, ~45 ms, **once per session (1 hour)** |
| ML-KEM operations (kyber-py, median) | - | keygen 3.0 ms, encaps 3.8 ms, decaps 5.0 ms |
| One reading on the wire, gateway to cloud | 75 B | 221 B |
| Sealing one reading (AES-256-GCM) | - | 0.0025 ms |
| Sustained ingest | 85.7 readings/s | 83.8 readings/s |
| End-to-end latency, median | 26.4 ms | 17.0 ms |

The latency difference is measurement noise, not a speed-up: the unchanged
legacy code measured 9.7 ms on 17 Sep and 26.4 ms on 24 Sep. What the data
shows is that the per-reading cost of the new cryptography is negligible and
throughput is unchanged; the real price is the hourly handshake.

## Weaknesses

| Weakness | Risk | Why it remains |
| --- | --- | --- |
| **Device link unchanged**: one hardcoded AES key for the whole fleet, no integrity check | R2, R3 (High, accepted) | The devices cannot be re-flashed or run ML-KEM (1184 B public key vs a 256 B buffer). Only device replacement fixes it |
| **Shared gateway token**, never rotated | R8 | Per-gateway credentials were out of scope |
| **kyber-py is not constant-time** | R9 | Chosen because it installs anywhere; liboqs would replace it |
| **Custom handshake**, not a standard protocol | R10 | Built from standard parts and tested, but not independently reviewed |
| **Readings lost** when the cloud is down or restarts | R11, R12 | No store-and-forward queue, in-memory storage |
| **Plain HTTP** for read APIs, dashboard and metrics | R13 | TLS was out of scope; bound to localhost by default |
| **Trust on first use** when the gateway is run by hand without a pin | R5 | Kept for easy local setup; flagged in `/health` and metrics, refused in containers |
| **ML-KEM only, not hybrid** with a classical algorithm | R1 | Simplicity; a hybrid stays secure if either algorithm is broken |
| **Monitoring is specified, not operated** | - | `/metrics` and alert rules exist, but no Prometheus or alert manager is deployed |

## Remaining technical debt

In priority order, with the reasoning in [architecture.md](architecture.md),
section 7:

1. Hybrid key exchange (X25519 + ML-KEM-768).
2. A production ML-KEM library (liboqs); only `pqc_channel/channel.py` changes.
3. A standard protocol (TLS 1.3 with hybrid key exchange) instead of our own
   handshake, which would also protect the read APIs.
4. Per-gateway credentials with rotation.
5. The cloud private key encrypted at rest or in a secrets manager, with a
   tested backup.
6. Store-and-forward on the gateway, persistent storage in the cloud.
7. A device replacement policy: unique per-device keys, authenticated
   encryption.

Smaller items: `edge_gateway` still imports the legacy wire format from
`legacy_device` (coupling two deployable services); no type checking (mypy);
the metrics are hand-written instead of using prometheus_client (a deliberate
choice to avoid a dependency, but more code to own); no long-running test
environment (the CI one lasts one run).

## Defects found in AI-generated code

The code was generated with an LLM and treated as untrusted. Problems found by
testing, review and analysis, not by the code failing in use:

| Defect | Found by |
| --- | --- |
| Gateway thread crashed on an abrupt device disconnect | Running the system end to end |
| The handshake confirmation check could be removed without any test failing | Mutation testing |
| A claim that ML-KEM made the gateway token unnecessary (it does not authenticate the gateway) | Reasoning about the design |
| Gateway listened on all network interfaces by default | Static analysis (ruff S104 / bandit B104) |
| `entrypoint.sh` with Windows line endings would break the gateway container when built on Windows | Checking line endings while adding Docker CI |
| The cloud's own log lines were never printed when run under uvicorn | Running the services with structured logging |

The first three, with others, are in the findings table of the group's AI
usage log (F1-F11). The last three were found on 5 Oct 2026 and
are described in [quality-checks.md](quality-checks.md),
[deployment.md](deployment.md) and [observability.md](observability.md). The
pattern across them: the code usually ran. The defects were in edge cases,
defaults and missing checks, which is why testing, analysis and review
mattered more than whether the system "worked".

## Demonstration

A five-minute demo that shows each claim above:

1. `docker compose up` and open the dashboard at <http://127.0.0.1:8000/>:
   readings arrive with the ML-KEM badge.
2. `curl http://127.0.0.1:9100/health`: the gateway is `ok`, pinned, with an
   active session.
3. Restart the gateway with a wrong `CLOUD_KEY_FINGERPRINT`: it refuses the
   cloud, `/health` turns `degraded`, `gateway_handshakes_total{result="failed"}`
   rises, and **no reading goes over the legacy path**.
4. `python -m pytest -m security -v`: the legacy weaknesses, proved by tests.
5. Show a green "Docker build and deployment test" run in GitHub Actions.

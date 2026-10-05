# Quality Checks: Static Analysis and Failure Testing

The brief asks for AI-generated code to be verified "through appropriate
tests, code review, static analysis, documentation, and, where relevant,
failure and security testing". This document covers the static analysis and
the failure tests, how each finding was handled, and how we checked that the
tests themselves work.

Run everything locally:

```bash
pip install ruff pip-audit
ruff check .                     # lint + security patterns
pip-audit -r requirements.txt    # known vulnerabilities in dependencies
python -m pytest -m failure -v   # failure tests only
```

CI runs all three on every push and pull request (`.github/workflows/ci.yml`,
job `static-analysis` and the `Failure tests` step).

## 1. Tools

| Tool | What it checks | Why this one |
| --- | --- | --- |
| **ruff** | Style, likely bugs (bugbear), outdated syntax, and the flake8-bandit security rules | One fast tool covering lint and security patterns; configured in `pyproject.toml` |
| **bandit** | Python security anti-patterns | The standard Python security scanner. Run once by hand to compare with ruff |
| **pip-audit** | Dependencies against the PyPA advisory database and OSV | Catches vulnerable library versions, which no code scanner can see |

Bandit and ruff's `S` rules reported the **same** security findings on this
code base, so CI runs only ruff. That avoids keeping two sets of suppression
comments in step.

## 2. Results (first run, 5 Oct 2026)

**pip-audit:** no known vulnerabilities in any pinned or transitive
dependency.

**ruff** (rules E, W, F, I, B, S, UP, SIM, RUF) and **bandit:** 155 raw
findings. 131 of those were `assert` statements in tests (S101), which is how
pytest works and not a finding. The remaining 24, and what we did with each:

### Fixed

| Rule | Where | Finding | Action |
| --- | --- | --- | --- |
| **S104 / B104** | `edge_gateway/gateway.py` | Gateway listened on all interfaces (`0.0.0.0`) by default | **Default changed to `127.0.0.1`.** The legacy port accepts unauthenticated frames, so exposing it to a network should be a deliberate choice. Docker still passes `--host 0.0.0.0` explicitly in `entrypoint.sh`, so the container deployment is unchanged. |
| RUF059 | `tools/baseline.py` | Unpacked variable never used | Renamed to `_eph_sk` |
| RUF059 | `tests/test_failures.py` | Unused variable in a new test | The test now asserts on it (the refusal must be counted as a failed handshake). Caught in our own new code, before commit. |
| I001 | 4 files | Import order | Auto-fixed |
| UP017 | `cloud_service/app.py`, `tools/baseline.py` | `timezone.utc` instead of `UTC` (Python 3.11) | Auto-fixed |
| W291 | 4 files | Trailing whitespace | Fixed |
| E501 | 2 files | Lines over 88 characters | Wrapped |
| SIM300 | `tests/test_protocol.py` | Comparison written "constant first" | Auto-fixed |

### Reviewed and accepted (false positives in this context)

| Rule | Where | Finding | Why it is accepted |
| --- | --- | --- | --- |
| S311 / B311 | `legacy_device/device.py` | `random` is not cryptographically secure | It simulates sensor noise, not a secret. The frame IV correctly uses `os.urandom`. Marked inline with `# noqa: S311` and a comment. |
| S603, S607 / B603, B607, B404 | `scripts/compose_smoke_test.py` | Runs `docker` via `subprocess` | Fixed argument list, no shell, no user input. A developer tool, not shipped code. |
| S310 / B310 | `scripts/compose_smoke_test.py`, `tools/baseline.py` | `urlopen` can open `file:` URLs | The URL is the local cloud address from configuration or the command line, chosen by the developer running the tool. |
| S105-S107 | `tests/` | Hardcoded passwords | Fake tokens used to test wrong-token handling. |

Each accepted rule is ignored only for the specific file (`pyproject.toml`) or
line (`# noqa`), never globally, so the same pattern in new production code
would still fail CI.

### What the scanners did **not** find

The most important result. None of the tools flagged any of the four known
security weaknesses in the legacy code:

| Known weakness | Where | Why the scanners missed it |
| --- | --- | --- |
| Hardcoded fleet-wide AES key | `legacy_device/protocol.py:43` | Written as `bytes.fromhex(...)`, which no rule treats as a secret |
| Default gateway token committed to the repository | `gateway.py`, `app.py` | Hidden inside an `os.environ.get(..., default)` fallback |
| AES-CBC with no MAC (tampering undetectable) | `legacy_device/protocol.py` | Using CBC is not wrong in itself; the flaw is the missing integrity check, which is a design property |
| Token compared with `!=` (not constant-time) | `cloud_service/app.py` | No rule for timing-unsafe comparison of secrets |

**Conclusion for the report:** static analysis is good at code patterns (a
risky default, an unsafe call) and cheap to run on every commit. It does not
find design flaws in cryptography. Those were found by reading the code and
proved by the `security` tests (`python -m pytest -m security`), for example
`test_finding_tampering_with_the_iv_rewrites_data_undetected`. Both are
needed; a clean scan is not evidence that the code is secure.

## 3. Failure tests

`tests/test_failures.py`, 19 tests, marker `failure`. The existing tests
showed that features work and attacks are caught. These ask a different
question: when something around the system goes wrong, does it fail safely
and visibly, and does it recover?

| Failure | Expected behaviour | Test |
| --- | --- | --- |
| Cloud down (real closed port) | Readings counted as failed; gateway keeps serving devices | `test_cloud_down_readings_are_counted_and_gateway_keeps_serving` |
| Handshake blocked (reset, timeout, HTTP 503) | **Never falls back to the legacy path** (downgrade protection); no request to `/api/v1` | `test_blocked_handshake_never_falls_back_to_legacy` (3 cases) |
| Cloud comes back after an outage | Next reading succeeds with no operator action | `test_gateway_recovers_by_itself_after_an_outage` |
| Cloud accepts the connection but never answers | Every request has a timeout, so no device thread hangs | `test_every_cloud_request_has_a_timeout` |
| Timeout while sending a reading | Counted failure, not a crash | `test_reading_timeout_is_counted_not_fatal` |
| Cloud returns HTTP 500 | Not retried in a loop | `test_server_error_on_a_reading_is_not_retried` |
| Garbage reply (HTML error page, missing fields, bad base64) | Clean, counted handshake failure | `test_garbage_public_key_reply_fails_the_handshake_cleanly` (3 cases) |
| Cloud offers a different algorithm (ML-KEM-512) | Refused (algorithm downgrade) | `test_cloud_offering_a_different_algorithm_is_refused` |
| Cloud restarted without its key file (new key pair) | Pinned gateway refuses it; `handshakes_failed` rises | `test_pinned_gateway_refuses_a_cloud_that_lost_its_key` |
| Handshake flood | Session count stays at the cap | `test_handshake_flood_cannot_exceed_the_session_cap` |
| A session evicted by the cap | Gateway re-handshakes; no reading lost | `test_evicted_session_recovers_with_a_new_handshake` |
| Corrupt cloud key file at startup | Cloud refuses to start; file left untouched | `test_corrupt_key_file_stops_the_cloud_instead_of_replacing_it` (3 cases) |
| 8 devices sending at once | One session, no AES-GCM nonce reused, every reading stored once | `test_many_devices_at_once_share_one_session_without_nonce_reuse` |

All 19 passed against the existing code: no new defects were found in the
gateway or cloud. The value of these tests is that the behaviours above are
now guaranteed. Before, they were only claimed in comments and the README
(for example the no-fallback policy). A future change that breaks one of them
now fails CI.

## 4. Checking that the tests work (mutation testing)

A test that has never failed may not test anything. To check, we introduced
one deliberate defect at a time into the gateway or cloud and ran the
matching failure test. Every defect must make a test fail.

| # | Defect introduced | Result |
| --- | --- | --- |
| M1 | Gateway falls back to the legacy path when ML-KEM fails | Caught (3 tests failed) |
| M2 | No timeout on the sealed-reading POST | Caught |
| M3 | Retry on any HTTP error, not only 401 | Caught |
| M4 | Algorithm check removed | Caught |
| M5 | Handshake no longer handles malformed JSON | Caught (2 of 3 cases; bad base64 is still caught by a separate check) |
| M6 | Session cap removed | Caught |
| M7 | Cloud always regenerates its key file | Caught (3 tests failed) |
| M8 | Message counter taken outside the lock (race) | Caught, 3 runs out of 3 |

**A problem in our own verification:** the first version of M8 added a delay
*inside* the lock, which created no race, so the test passed and the mutant
"survived". The fault was in the mutant, not the test. After moving the
counter outside the lock, the concurrency test caught it every time. Lesson:
a surviving mutant needs checking from both sides before concluding the test
is weak.

## 5. Remaining gaps

* **No type checking** (`mypy`). The code has type hints but they are not
  verified.
* **No formatter enforced** (`ruff format`). Running it would reformat most
  files, which we judged not worth the review noise this late.
* **Concurrency testing is probabilistic.** The race in M8 was caught 3 of 3
  times on one laptop; a slower or faster machine could behave differently.
* **The failure tests run the cloud in-process.** Real network faults (packet
  loss, half-open connections) are only covered by the one closed-port test
  and the Docker Compose smoke test.

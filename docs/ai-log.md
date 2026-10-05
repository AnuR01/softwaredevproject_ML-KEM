# AI Usage Log

The course brief requires us to record, for every significant AI-assisted task:
the prompt, the context given to the LLM, what it produced, what we **accepted,
modified or rejected** and why, how problems were found, and what risks remain.
The LLM is treated as an **untrusted** source: code that runs is not assumed to
be correct.

## How to keep this log

* Add an entry **as you go**, one per task, newest at the bottom.
* Copy prompts **verbatim**, typos included. Don't tidy them up afterwards.
* Fill in the **Human review** part yourself. The AI can't honestly say what
  the group checked or decided, so any entry with `TODO` there is unfinished.
* Raw transcripts of the Claude Code sessions are stored locally at
  `~/.claude/projects/D--Downloads-SodtwareDevOpsGpProject/*.jsonl` (one file
  per session). Keep them until the course ends; they are the evidence behind
  this log.

## Tools used

| Tool | Model | Used for |
| --- | --- | --- |
| Claude Code (CLI, Windows) | Claude Opus 5 (session 1) | Baseline system, comments, tests, measurements, brief page |
| Claude Code (CLI, Windows) | Claude Opus 5.5 (session 2) | Explaining the code and concepts, this log |

Times below are UTC (Finland = UTC+3).

---

## Session 1: 17 Sep 2026 (transcript `23aeffe0-…jsonl`)

### Entry 1: Reading the brief and planning

**Prompt**
> ok, I added the gp project file. The teacher wants us to do a gp project mentioned in the file.

**Context given:** `SDMO_Project.pdf` and `Group work project 1 pdf.pdf` in the
project folder (the AI extracted their text with `pdftotext`).

**AI output**
* Summary of the brief, grading and deadlines.
* Asked two questions. Our answers: *no starter code was provided* (so we build
  our own deliberately weak baseline), and *report perspective: decide later*.
* Checked that three ML-KEM Python libraries install on Python 3.11
  (`kyber-py`, `liboqs-python`, `pqcrypto`) and recommended `kyber-py`.
  It noted `kyber-py` is pure Python and **not constant-time**, so not for
  production.
* Proposed an architecture with ML-KEM on the gateway ↔ cloud hop, a
  "crypto-agility" layer with three suites (`legacy-rsa2048`, `mlkem768`,
  `hybrid-x25519-mlkem768`), PQC metrics, Docker Compose and CI.

**Decision**
* **Accepted:** ML-KEM terminates at the gateway; the device stays legacy.
* **Modified:** the prompt in Entry 2 asked for a *simple* baseline first. The
  RSA suite and the crypto-agility layer were **not built**; the baseline uses
  a hardcoded AES key instead of RSA.
* **Deferred:** library choice, crypto-agility, Docker, CI.

**Human review:** TODO. Did the group agree with the architecture? Which
library will we use and why?

**Risks / to verify**
* The claim that `kyber-py` is "FIPS 203-compliant" has **not been checked**
  against its documentation or test vectors.

---

### Entry 2: Building the baseline system

**Prompt**
> first, just do simple device, gateaway and cloud. legacy device model simulation for Arduino, then edge gateaway and cloud.Do these in simple first.

Follow-up prompt:
> foe device, temperature and humidity are two readings

**AI output**
* `legacy_device/protocol.py`: pipe-delimited record, AES-128-CBC with a
  hardcoded pre-shared key, 256-byte frame limit.
* `legacy_device/device.py`: simulated sensor (temperature + humidity random
  walk), sends one encrypted frame every N seconds over TCP, reconnects forever.
* `edge_gateway/gateway.py`: threaded TCP server that decrypts, checks
  sequence numbers (replay) and forwards to the cloud over HTTP with a static
  token.
* `cloud_service/app.py`: FastAPI service with `/health`, ingest and read
  endpoints, in-memory storage.
* `README.md`, `requirements.txt`.
* For the follow-up: confirmed both readings were already sent together in
  one frame, and offered the alternative of one message per sensor.

**How it was verified (by the AI)**
* Ran all three services and two devices: 16 readings arrived in the cloud.
* **Bug found in its own code:** a device disconnecting abruptly crashed the
  gateway's handler thread with an unhandled `ConnectionResetError`. The AI
  fixed it and re-ran to confirm. (Regression test added later:
  `test_abrupt_device_disconnect_does_not_raise`.)

**Decision**
* **Accepted:** the whole baseline, and one combined frame per reading cycle
  (fewer frames, closer to a battery device).

**Human review:** TODO. We ran the system ourselves (three terminals) and
tried the API through `/docs`. Record what we checked in the code.

**Risks / to verify**
* The simulated device is **Python, not Arduino code**. A real Uno has no
  built-in networking (would need a shield or serial), and its serial buffer
  is 64 bytes, not 256. See *Findings* below.

---

### Entry 3: Understanding how to run and use it

**Prompts**
> how do I run this

> they are running and I see them on terminals. in the interactive browser, I don't understand it

> ok it works, what should I do next

> so ML KEM algorith is next?

> explain me step by step and detail about this project, i am new to this

**AI output:** run instructions; a walkthrough of the Swagger `/docs` page
(including showing that anyone with the static token can inject fake
readings); a recommended order of *tests + baseline → ML-KEM*, because
measurements must be taken **before** the crypto changes.

**Decision:** accepted the order (tests and baseline first).

**Human review:** TODO

---

### Entry 4: Shareable explainer page (`docs/brief.html`)

**Prompt**
> make a ahreable pge

(Claude Code automatically loaded its own page-design and diagram guidelines
for this request; those were not written by us.)

**AI output:** `docs/brief.html`, an explainer page for the group, published
as a private Claude artifact that can be shared.

Follow-up prompts (baseline section added as Part 06):
> explain the baseline analysis you did step by step and in detail, as simple as you can

> yes, do that

**Decision:** accepted for internal use within the group. It is **not** part
of the graded documentation as it stands.

**Human review:** TODO. Check the page's figures against
`docs/measurements/baseline-2026-09-17.json`.

---

### Entry 5: Comments, tests and baseline measurements

**Prompt**
> yes, do that. Also on the device, gateway and cloud codes, add suffcient comment to understand what they do and why they do it

**AI output**
* Rewrote all four source files with "what / why / known weaknesses" comments.
* `tests/`: 58 tests (protocol, gateway, cloud), plus `conftest.py`,
  `pytest.ini`, `requirements-dev.txt`. Three tests are marked `security` and
  **prove** weaknesses rather than guard against them:
  * `test_finding_tampering_with_the_iv_rewrites_data_undetected`: flipping
    one IV byte turns `dev-001` into `dev-901` without knowing the key.
  * `test_finding_ciphertext_tampering_is_caught_only_by_accident`
  * `test_finding_any_holder_of_the_static_token_can_inject_telemetry`
* `tools/baseline.py` and `docs/measurements/baseline-2026-09-17.json`: frame
  size 98 B, handshake 0 B, encrypt ~0.006 ms, end-to-end 9.7 ms median,
  105.5 readings/s.

**How it was verified (by the AI):** `python -m pytest` → 58 passed; baseline
run against the live services.

**Caveats the AI reported itself**
* The end-to-end latency includes a 5 ms polling interval, so it is an
  **upper bound**. The same method will be used after ML-KEM, so the
  comparison stays fair.
* `starlette` shows a third-party deprecation warning (harmless for now).

**Decision:** accepted, committed on 24 Sep as `1f80dac`.

**Human review:** TODO. Re-run the tests on a teammate's machine; read at
least the three `security` tests and confirm they show what they claim.

---

## Session 2: 24 Sep 2026 (transcript `c1f92e05-…jsonl`)

### Entry 6: Understanding the code and ML-KEM (explanation only, no code changes)

**Prompts**
> i am trying to understand the processes and code and there are some areas I don't understand. First, why the device has legacy protocol.what does it do,is the simulated arudino device the same as the screenshot,  why the gateway terminates protocol

> what are those bearer tokens and static tokens

> Explain me about ML KEM step by step aand detail. I am nw to this

> can't cloud do everything by itself. does it need gateway

> So after adding ML Kem, possibly device to cloud

> also read SDMO project pdf

> what should I do next after tests and measurement

**Context given:** the repository, both PDFs, and the screenshot
`Screenshot 2026-09-24 102955.png`.

**AI output (explanations)**
* The screenshot is a Wokwi *Simon game* project on an Arduino Uno. It is
  **unrelated** to our simulated sensor device; only the hardware class
  (Arduino-class microcontroller) is shared.
* Why the gateway terminates the legacy protocol: the device can't be
  re-flashed and ML-KEM keys (1184 B) don't fit its 256 B buffer.
* Bearer/static token explained, with its weaknesses.
* ML-KEM step by step: KEM operations, Learning With Errors, a worked toy
  example mod 17, parameter sizes, and the fact that ML-KEM alone does not
  authenticate the server.
* Gap analysis against the brief, and a recommended next-steps plan: AI log
  → CI → ML-KEM → Docker → metrics → docs.

**Decision:** used for learning. The plan is adopted as a proposal for the
group.

**Human review:** TODO. The ML-KEM numbers (key sizes, q = 3329, FIPS 203)
should be checked against the NIST FIPS 203 standard before they go in the
report.

---

### Entry 7: Creating this log

**Prompt**
> Can you do that?  Create docs/ai-log.md and write down what you've done with AI so far: prompts, what it produced, what you kept or changed. The brief requires this, and it's much easier to keep up as you go.

**AI output:** this file. Prompts were extracted from the saved session
transcripts rather than recalled from memory. The Human review sections were
left as `TODO` on purpose.

**Human review:** TODO

---

### Entry 8: CI pipeline (GitHub Actions)

**Prompt**
> what about step 2. This is my github repository. https://github.com/Arkar-MyintMyat/SodtwareDevOpsGpProject

**AI output:** `.github/workflows/ci.yml`. On every push or pull request to
`main` it installs the dependencies and runs `python -m pytest` on Python 3.11
and 3.12, then runs the `security`-marked tests again as a separate, clearly
labelled step.

**How it was verified (by the AI):** ran the same two commands locally
(58 passed; 3 security tests passed) and checked the YAML parses. First
pushed as commit `c5b876c`; the GitHub run passed on both Python 3.11 and
3.12: https://github.com/Arkar-MyintMyat/SodtwareDevOpsGpProject/actions/runs/35974676361

The AI added a `Co-Authored-By: Claude` line to that commit, so GitHub listed
Claude as a co-author. At our request the message was rewritten without it
(now commit `28dddf9`, same content). AI use is documented in this log
instead of in git authorship.

**Not included (deliberately, to keep it simple):** linting / static analysis
(e.g. `ruff`), dependency vulnerability scanning (e.g. `pip-audit`), Docker
image builds. The brief mentions static analysis, so these are candidates for
later.

**Human review:** TODO. Check the first run in the repository's Actions tab.

---

### Entry 9: ML-KEM integration (gateway ↔ cloud)

**Prompt**
> do step 3, use kyber-py

**Context given:** the whole repository, the earlier explanation of ML-KEM
(Entry 6), and the brief's requirement to integrate ML-KEM into at least one
communication path with a migration and fallback strategy.

**AI output**
* `pqc_channel/` (new shared package): ML-KEM-768 handshake using two
  encapsulations (the cloud's long-term key for authentication, plus a
  one-time gateway key for forward secrecy), HKDF-SHA256 key derivation, a
  confirmation tag, and AES-256-GCM message sealing with counter nonces.
* `cloud_service/app.py`: persistent key pair (`CLOUD_KEM_KEY_FILE`),
  `/api/v2/pqc/public-key`, `/api/v2/pqc/session`, `/api/v2/telemetry`,
  in-memory sessions with expiry and replay detection, `/health` now reports
  the fingerprint, a `channel` field on stored readings, and a switch to
  retire the legacy endpoint (`LEGACY_INGEST_ENABLED=false`).
* `edge_gateway/gateway.py`: `PqcUplink` (default) and `LegacyUplink`
  (rollback), `--crypto`, `--cloud-key-fingerprint` pinning, handshake
  counters, automatic re-handshake when the cloud forgets a session, and
  **no automatic fallback to legacy** (prevents downgrade attacks).
* 38 new tests (`tests/test_pqc_channel.py`, `tests/test_pqc_integration.py`),
  96 in total. `tools/baseline.py` now measures the ML-KEM channel.
* README: architecture, run instructions, before/after measurements, weakness
  status.

**Design decisions made by the AI (for the group to confirm or change)**
* Two encapsulations instead of one, doubling handshake size (~4.6 KB raw),
  in exchange for forward secrecy.
* The gateway token is kept as a weak gateway identity, but proved with an
  HMAC inside the handshake instead of being sent.
* Pinning is optional (trust on first use without it) so first-time setup is
  easy; a `security` test documents the risk.
* ML-KEM only, not hybrid X25519 + ML-KEM, to keep it simple.

**How it was verified (by the AI)**
* Full suite: 96 passed.
* **Mutation testing:** five security checks were disabled one at a time to
  confirm a test fails for each (fingerprint pin, replay check, GCM
  associated data, gateway proof, confirmation tag). **The confirmation-tag
  mutant survived**: no test failed. A dedicated test was added
  (`test_tampered_handshake_reply_fails_confirmation`) and the mutant is now
  caught.
* Ran the real cloud, gateway and device over HTTP with a pinned
  fingerprint, then restarted the cloud with the same key file: the gateway
  re-handshook by itself and readings kept arriving.
* Measured both paths back to back on the same machine (see README).

**Problems found during verification**
* Log messages used a `…` character that turned into `�` on Windows
  consoles. Replaced with `...`.
* Measurement noise: the unchanged legacy code measured 9.7 ms (17 Sep) and
  26.4 ms (24 Sep) end-to-end, so the ML-KEM path looking "faster" in one run
  is noise. The README states this instead of claiming a speed-up.
* The old measurement script's "projected" ML-KEM handshake (2272 B, one
  encapsulation) doesn't match the implemented design (4608 B, two).
  Explained in the README; both are kept.

**Human review:** TODO. Suggested checks: read `pqc_channel/channel.py` top to
bottom; run the three services and watch `/health`; decide whether the group
accepts the four design decisions above; try `--cloud-key-fingerprint` with a
wrong value and see the gateway refuse.

**Risks / to verify**
* kyber-py is not constant-time (timing side channels); not production-grade.
* The derivation and confirmation design is the AI's own composition of
  standard parts (similar in spirit to KEMTLS), **not a standardised
  protocol**, and it has not been independently reviewed. The report should
  say so.
* The cloud's private key file is unencrypted.

---

### Entry 10: Live dashboard

**Prompts**
> where do I run this step 3

> where do I see the whole thing in browser

> yes, do that

**AI output**
* `cloud_service/static/dashboard.html`, served at `/`: tiles (stored
  readings, devices, share delivered over ML-KEM, active sessions), the
  post-quantum channel status with the key fingerprint and a copy button, a
  devices table, and the latest readings with ML-KEM / legacy badges.
  Refreshes every 2 seconds from the existing public JSON endpoints; no
  external scripts or fonts, so it works offline.
* `/health` now reports `readings_by_channel` (how many stored readings came
  over each path).
* 3 tests in `tests/test_cloud.py`, including one that fails if the page ever
  writes values with `innerHTML` (device ids are attacker-controlled, so that
  would be a cross-site scripting hole).

**How it was verified (by the AI):** 99 tests passed. Ran two gateways (one
ML-KEM, one `--crypto legacy`) and three devices, then screenshotted the page
with headless Edge at desktop and phone width.

**Problems found during verification**
* The first version of the `innerHTML` test failed on the page's own comment
  that mentions the word. Changed it to look for real uses (`.innerHTML`,
  `insertAdjacentHTML`, `document.write`).
* At phone width the page seemed wider than the screen. A CSS fix
  (`min-width: 0` on grid items) was applied, but the next screenshot looked
  the same: headless Edge on Windows seems to enforce a minimum window width
  of about 500 px. Loading the page in a 390 px iframe confirmed the fixed
  layout fits. Lesson: check what the test tool actually shows before
  trusting its output.

**Human review:** TODO. Open <http://127.0.0.1:8000/> with the system running
and check it in both light and dark mode.

---

## Findings: problems in AI-generated work

Problems found so far, whoever found them. Add to this table whenever a review
or test turns something up.

| # | Where | Problem | Found by / how | Status |
| --- | --- | --- | --- | --- |
| F1 | `edge_gateway/gateway.py` | Abrupt device disconnect crashed the handler thread (`ConnectionResetError`) | AI, while running the system end to end | Fixed, regression test added |
| F2 | `README.md` lines 8 and 125 | Links to `docs/architecture.md`, which does not exist | AI review, session 2 | Open, to be written |
| F3 | `edge_gateway/gateway.py:54` | Comment calls it a "bearer token", but it's sent in a custom `X-Gateway-Token` header, not `Authorization: Bearer` | AI review, session 2 | Open, minor wording |
| F4 | `cloud_service/app.py:115` | Token compared with `!=`, which is not constant-time | Noted in the generated docstring itself | Accepted risk for baseline; replaced by ML-KEM |
| F5 | `legacy_device/` | "Arduino-class" simplifications: TCP networking (a real Uno has none built in), 256 B buffer (real Uno serial buffer is 64 B) | AI review, session 2 | Document as an assumption in the report |
| F6 | Session 1 plan | Promised to maintain `docs/ai-usage/`, which was never created | AI review, session 2 | Replaced by this file |
| F7 | Session 1 plan | Proposed an RSA legacy suite, but the built baseline uses a hardcoded AES key; the plan and code disagree | AI review, session 2 | Plan superseded; don't cite the RSA suite in the report |
| F8 | Session 2 explanation (Entry 6) | The AI said ML-KEM makes the gateway token "unnecessary". Wrong: ML-KEM authenticates the cloud (with pinning) but not the gateway; anyone could open a session. | AI, while designing Entry 9 | Corrected: the token is kept, proved via HMAC |
| F9 | `tools/baseline.py` (session 1) | Projected ML-KEM `forward_secrecy: True` for a single-encapsulation design, which would not have forward secrecy | AI review, Entry 9 | Implemented design uses a second, one-time key so the claim now holds |
| F10 | `edge_gateway/gateway.py` (Entry 9) | Confirmation check could be removed without any test failing | Mutation testing | Fixed, test added |
| F11 | Log messages (Entry 9) | `…` character garbled on Windows consoles | Running the live system | Fixed |

## Open items for the group

- [ ] Fill in every **Human review: TODO** above.
- [ ] Decide the ML-KEM library (`kyber-py` vs `liboqs-python`) and record why.
- [ ] Verify the ML-KEM facts used in the report against NIST FIPS 203.
- [ ] Each teammate logs their own AI use here (or in a section with their name).
- [ ] Part 3 reflections are written **without AI** and are not logged here.

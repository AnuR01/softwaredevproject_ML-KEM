# ML-KEM Legacy Modernization

Course project for *Software Development, Maintenance & Operations* (University
of Oulu): a simulated legacy device, an edge gateway, and a cloud service,
migrated to post-quantum key establishment (ML-KEM-768) on the gateway ↔ cloud
hop.

In this group project, we modernize a small legacy edge–cloud software
system for the transition to post-quantum cryptography (PQC). The project
combines software development, maintenance, and operations with the critical
evaluation of code and design decisions produced by a large language model
(LLM).

The baseline was built intentionally imperfect; its weaknesses are listed
below with their current status. The full migration and fallback reasoning
is in [`docs/architecture.md`](docs/architecture.md): migration
plan, rollback decisions, cryptographic inventory and risk register.

## Architecture

```
legacy_device  ---- TCP 9000, AES-128-CBC ---->  edge_gateway  ---- HTTP 8000 ---------------->  cloud_service
(Arduino-class,      hardcoded pre-shared key    (protocol        ML-KEM-768 handshake            (FastAPI,
 256-byte buffer,    no key establishment         translation,     + AES-256-GCM per reading       in-memory
 cannot be           unauthenticated              replay check)    (legacy path: --crypto legacy)  storage)
 re-flashed)         UNCHANGED - see below
```

The device hop stays legacy because the device cannot run ML-KEM: its public
key alone (1184 B) is over four times the device's 256-byte buffer, and the
firmware cannot be re-flashed. Post-quantum cryptography therefore terminates
at the gateway, which protects the long-haul hop - the one exposed to
"harvest now, decrypt later" recording.

| Component | Path | Role |
| --- | --- | --- |
| Legacy device | `legacy_device/` | Simulates a constrained sensor node. Sends an encrypted reading every N seconds. |
| Edge gateway | `edge_gateway/` | Terminates the legacy protocol, validates frames, forwards to the cloud over the ML-KEM channel. |
| Cloud service | `cloud_service/` | Holds the ML-KEM key pair, ingests readings, exposes `/health` and read APIs. |
| PQC channel | `pqc_channel/` | The handshake and message encryption shared by gateway and cloud. |

### The ML-KEM channel

Documented in full at the top of `pqc_channel/channel.py`. In short:

1. The gateway fetches the cloud's ML-KEM-768 public key and checks its
   SHA-256 fingerprint against the pinned value (`--cloud-key-fingerprint`).
2. It encapsulates to that key (proves it is talking to the real cloud) and
   sends a fresh one-time public key of its own (gives forward secrecy), plus
   an HMAC proving it knows the gateway token - the token itself is never sent.
3. The cloud decapsulates, encapsulates to the one-time key, and returns a
   confirmation tag. Both sides derive the keys from **both** shared secrets
   with HKDF-SHA256.
4. Every reading is then sealed with AES-256-GCM under the session key, with a
   per-session message counter as nonce (replays are rejected). Sessions last
   an hour or 10,000 messages.

**Fallback policy:** the gateway never falls back to the legacy path by
itself - that would let an attacker force a downgrade just by blocking the
handshake. Rolling back is an operator decision (`--crypto legacy`), and the
cloud can retire the legacy endpoint with `LEGACY_INGEST_ENABLED=false`.

The ML-KEM implementation is **kyber-py**, which is pure Python and **not
constant-time**. It is suitable for this course project, not for production;
swapping in liboqs would only change `pqc_channel/channel.py`.

## Requirements

* Python 3.11+
* `pip install -r requirements.txt`

## Running it

Three terminals, in this order.

**1. Cloud service**

`CLOUD_KEM_KEY_FILE` keeps the cloud's ML-KEM key pair across restarts (it is
created on first start; `.keys/` is git-ignored). Without it the cloud makes a
new key pair every start, and a pinned gateway will then refuse to connect.

```bash
# Git Bash / Linux / macOS
CLOUD_KEM_KEY_FILE=.keys/cloud_kem.json python -m uvicorn cloud_service.app:app --host 127.0.0.1 --port 8000
```

```powershell
# PowerShell
$env:CLOUD_KEM_KEY_FILE = ".keys/cloud_kem.json"; python -m uvicorn cloud_service.app:app --host 127.0.0.1 --port 8000
```

**2. Edge gateway**

Copy the fingerprint from the cloud's `/health` (`pqc.public_key_fingerprint`)
and pin it:

```bash
python -m edge_gateway.gateway --cloud-url http://127.0.0.1:8000 --cloud-key-fingerprint <fingerprint>
```

Without `--cloud-key-fingerprint` the gateway trusts the first key it sees and
logs a warning. `--crypto legacy` runs the old, unprotected cloud path.

**3. One or more devices**

```bash
python -m legacy_device.device --device-id dev-001 --interval 2
python -m legacy_device.device --device-id dev-002 --interval 2   # another terminal
```

## Checking that it works

Open the live dashboard: **<http://127.0.0.1:8000/>**. It refreshes every two
seconds and shows each device, the latest readings with an ML-KEM or legacy
badge, the share of readings delivered over ML-KEM, and the cloud's key
fingerprint (with a button to copy it for `--cloud-key-fingerprint`).

The raw JSON endpoints behind it:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/devices
curl "http://127.0.0.1:8000/api/v1/telemetry?limit=5"
```

Each stored reading has a `channel` field (`mlkem` or `legacy`) showing which
path delivered it, and `/health` reports the ML-KEM fingerprint and the number
of active sessions.

Interactive API docs are served at <http://127.0.0.1:8000/docs>.

## Running with Docker Compose

Docker Desktop with Compose support is required. No paid Docker account is
needed for local builds. The Compose setup runs the cloud, gateway, and one
legacy device in containers and persists the cloud ML-KEM key in a named
volume.

### First-time setup

Copy the local configuration template. The `.env` file is ignored by Git and
must not be committed:

```bash
cp .env.example .env
```

Start the cloud first so it can create or load its persistent ML-KEM key:

```bash
docker compose up -d --build cloud
```

Read the cloud fingerprint:

```bash
curl http://127.0.0.1:8000/health
```

Copy `pqc.public_key_fingerprint` from the response into
`CLOUD_KEY_FINGERPRINT` in `.env`. The gateway deliberately refuses to start
without a valid 64-character fingerprint in the containerized deployment.

Start the pinned gateway and device:

```bash
docker compose up -d --build gateway device
```

Check that all services are healthy:

```bash
docker compose ps
```

### Viewing the running system

- Dashboard: <http://127.0.0.1:8000/>
- API documentation: <http://127.0.0.1:8000/docs>
- Health and ML-KEM status: <http://127.0.0.1:8000/health>

The dashboard shows stored readings, devices, active ML-KEM sessions, the
cloud fingerprint, and the percentage of readings delivered through ML-KEM.

### Container smoke test

After the cloud and gateway are running, verify a real device-to-cloud reading:

```bash
python scripts/compose_smoke_test.py
```

The test starts a temporary device container and verifies that its reading
arrives with `channel: "mlkem"`.

### Logs and shutdown

```bash
docker compose logs --follow gateway
docker compose logs --follow cloud
docker compose down
```

`docker compose down` preserves the named ML-KEM key volume. To remove the
key and force the cloud to generate a new key, use:

```bash
docker compose down --volumes
```

After generating a new key, update `CLOUD_KEY_FINGERPRINT` in `.env` before
starting the gateway again.

### Explicit rollback mode

The gateway does not automatically downgrade if the ML-KEM handshake fails.
For a deliberate operator rollback only, set this in `.env`:

```text
CRYPTO_MODE=legacy
```

Restart the gateway after changing the mode. The legacy mode is intentionally
less secure and should only be used during a documented migration or recovery
scenario.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest              # all 118 tests
python -m pytest -m security  # only the tests that demonstrate weaknesses
python -m pytest -m failure   # only the failure tests (cloud down, timeouts, ...)
```

| File | Covers |
| --- | --- |
| `tests/test_protocol.py` | Legacy wire format and its weaknesses |
| `tests/test_gateway.py` | Replay tracking, threading, framing |
| `tests/test_cloud.py` | Legacy ingest, validation, read APIs, dashboard |
| `tests/test_pqc_channel.py` | ML-KEM sizes, handshake, forward secrecy, AES-GCM tamper detection |
| `tests/test_pqc_integration.py` | Real gateway uplink against the real cloud: pinning, replay, tampering, session recovery, full device-to-cloud chain |
| `tests/test_failures.py` | Cloud down, blocked handshake (no fallback to legacy), timeouts, bad replies, lost cloud key, session cap, concurrency |

CI runs the whole suite on every push (`.github/workflows/ci.yml`), plus
static analysis (`ruff`, including security rules) and a dependency
vulnerability scan (`pip-audit`). How every finding was handled, and how the
failure tests were checked with mutation testing, is in
[`docs/quality-checks.md`](docs/quality-checks.md).

Tests marked `security` deliberately assert that a weakness is real and
exploitable, rather than guarding against it. They are the evidence behind the
security findings in the report - for example
`test_finding_tampering_with_the_iv_rewrites_data_undetected` forges a reading
from a different device without knowing the key, which the gateway accepts as
valid.

## Baseline measurements 

Taken **before** ML-KEM integration, so the report can show the real cost of
the migration rather than an unanchored number. 

```bash
python -m tools.baseline          # local measurements only
python -m tools.baseline --e2e    # also latency and throughput (services must be running) 
```

Results are written to `docs/measurements/baseline-<date>.json`. Re-run the
same script after ML-KEM integration with `--label mlkem` so both files
survive and can be compared.

Measured on 17 September 2026:

| Measurement | Legacy baseline |
| --- | --- |
| Frame on the wire | 98 B (28 B plaintext + 70 B overhead) |
| Device buffer used | 38.3% of 256 B |
| Key-establishment handshake | **0 B, 0 round trips** - the key is hardcoded |
| Key rotation supported | No |
| Encrypt per frame | 0.0058 ms median (~172,000 ops/s) |
| Decrypt per frame | 0.0059 ms median (~169,000 ops/s) |
| End-to-end latency, device to cloud | 9.7 ms median, 33.5 ms p95 |
| Sustained ingest | 105.5 readings/s |
| ML-KEM-768 handshake, projected | 2272 B, 1 round trip - **does not fit the device buffer** |

The zero-byte handshake is the headline figure: the legacy system is fast
precisely because it performs no key establishment at all.

### After ML-KEM integration

Measured on 24 September 2026, same laptop, both paths back to back
(`legacy-rerun-2026-09-24.json` and `mlkem-2026-09-24.json`, 50 latency
samples each):

| Measurement | Legacy path | ML-KEM path |
| --- | --- | --- |
| Key establishment | 0 B, none | 4608 B raw (6497 B as JSON), 2 round trips, **~45 ms, once per session** |
| ML-KEM operations (kyber-py) | - | keygen 3.0 ms, encaps 3.8 ms, decaps 5.0 ms (median) |
| Reading on the wire, gateway to cloud | 75 B JSON | 221 B JSON (sealed + base64) |
| Seal one reading (AES-256-GCM) | - | 0.0025 ms |
| End-to-end latency, device to cloud | 26.4 ms median, 55.2 ms p95 | 17.0 ms median, 41.7 ms p95 |
| Sustained ingest | 85.7 readings/s | 83.8 readings/s |
| Forward secrecy / key rotation | No / No | Yes / Yes (hourly) |

How to read this honestly: the **same legacy code** measured 9.7 ms on 17 Sep
and 26.4 ms on 24 Sep, so run-to-run noise on a laptop is larger than
anything the per-reading cryptography adds. The ML-KEM path being lower in
this run is noise, not a speed-up. What the data does show: the per-reading
cost of AES-GCM is negligible, throughput is unchanged, and the real price of
the migration is a ~45 ms, ~6.5 KB handshake once per hour. The implemented
handshake is twice the earlier "projected" 2272 B because it uses two
encapsulations (one for authentication, one for forward secrecy).

## Wire protocol (legacy)

Each frame is one newline-terminated ASCII line:

```
<iv-hex>:<ciphertext-hex>\n
```

The plaintext inside is a pipe-delimited record:

```
DEV|<device_id>|<seq>|<temp_c>|<humidity>|<uptime_s>
```

A frame carrying a typical reading is 98 bytes, against a simulated device
buffer of 256 bytes. That headroom matters: see `docs/architecture.md` for why
it rules out running ML-KEM on the device itself.

## Known weaknesses of the baseline, and their status

The baseline weaknesses were deliberate; they were the work items for the
modernization.

1. **No key establishment.** One AES key is hardcoded in firmware and shared by
   the whole fleet. *Gateway ↔ cloud: fixed by ML-KEM. Device ↔ gateway:
   unchanged by design, accepted residual risk (the device cannot run ML-KEM).*
2. **Unauthenticated encryption.** AES-CBC without a MAC means tampering cannot
   be distinguished from corruption. *Gateway ↔ cloud: fixed by AES-256-GCM.
   Device ↔ gateway: unchanged, residual risk.*
3. **Static gateway token.** *Partly fixed: on the ML-KEM path the token is
   proved with an HMAC and never sent. It is still one shared secret for every
   gateway, with no rotation.*
4. **No transport security gateway -> cloud.** Plain HTTP. *Reading payloads
   are now protected by the ML-KEM channel; the read APIs and the legacy path
   are still plain HTTP.*
5. **No store-and-forward.** Readings are dropped if the cloud is unreachable.
   *Open.*
6. **In-memory storage only.** The cloud loses all data on restart. ML-KEM
   sessions are in memory too (gateways re-handshake automatically). *Open.*
7. **No containers or metrics endpoints yet.** *Containers are now supported
   with Docker Compose; a standard `/metrics` endpoint remains open.*
8. **Shared protocol module.** `edge_gateway` imports from
   `legacy_device.protocol`, which couples two separately deployable services.
   *Open for the legacy code; new shared code lives in its own `pqc_channel`
   package instead.*

New limitations introduced by the migration (to be covered in the report):

* **kyber-py is not constant-time** and is not intended for production.
* **Trust on first use** when the gateway is started without
  `--cloud-key-fingerprint` (demonstrated by
  `test_finding_unpinned_gateway_trusts_the_first_key_it_sees`).
* **The cloud's long-term private key is stored unencrypted** in
  `CLOUD_KEM_KEY_FILE`. Stealing it would allow impersonating the cloud to
  gateways, but thanks to forward secrecy would not decrypt past sessions.
* **ML-KEM only, not hybrid.** Security rests entirely on ML-KEM; a hybrid
  (X25519 + ML-KEM) design would stay secure if either one is broken.

## Project status

- [x] Baseline: device, gateway, cloud running end to end
- [x] Automated tests and baseline measurements captured
- [x] CI pipeline (GitHub Actions)
- [x] Static analysis, dependency scanning and failure tests in CI
- [x] ML-KEM-768 integration on the gateway-cloud path, with measurements
- [x] Container images and local Docker Compose deployment
- [ ] Deployment to a remote/test environment
- [ ] Health checks, metrics, PQC observability (partly: live dashboard at
      `/`, cloud `/health` reports ML-KEM state; gateway counts handshakes;
      no `/metrics` endpoint yet)
- [x] Architecture and migration document (`docs/architecture.md`)

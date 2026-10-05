# Architecture and Migration Strategy

How the system is built, how a fleet of legacy devices is moved to
post-quantum key establishment, what happens when the migration has to be
rolled back, and which risks remain. Written from the information-security and
organisational perspective chosen for the report: each decision is stated as a
risk, a control, and who owns it.

Numbers in this document come from `docs/measurements/` and from the code;
file references are given so they can be checked.

## 1. System overview

```
 trust zone: site LAN                      trust zone: internet
+------------------+   TCP 9000    +--------------+   HTTP 8000   +---------------+
|  legacy device   | ------------> | edge gateway | ------------> | cloud service |
|  (cannot change) |  AES-128-CBC  |  (upgraded)  |  ML-KEM-768   |   (upgraded)  |
|  256 B buffer    |  shared key   |              | + AES-256-GCM |               |
+------------------+               +--------------+               +---------------+
       hop 1: legacy, accepted residual risk     hop 2: post-quantum protected
```

| Component | Role | Can it be changed? |
| --- | --- | --- |
| Legacy device (`legacy_device/`) | Sends a temperature and humidity reading every few seconds | **No.** Firmware cannot be re-flashed |
| Edge gateway (`edge_gateway/`) | Decrypts device frames, checks replays, forwards to the cloud | Yes. This is where the migration happens |
| Cloud service (`cloud_service/`) | Holds the ML-KEM key pair, stores readings, serves APIs and the dashboard | Yes |
| PQC channel (`pqc_channel/`) | Handshake and message encryption shared by gateway and cloud | Yes |

## 2. Why the migration stops at the gateway

The brief asks to "preserve legacy compatibility where appropriate or provide
a clearly justified migration and fallback strategy". The device cannot take
part in ML-KEM, for three independent reasons:

| Constraint | Legacy device | What ML-KEM-768 needs |
| --- | --- | --- |
| Receive buffer | 256 B (`legacy_device/protocol.py`) | Public key alone is 1184 B; ciphertext 1088 B |
| Handshake traffic | 0 B (key is hardcoded) | 4608 B raw for our handshake (two encapsulations) |
| Firmware updates | Not possible | New code on the device |

A real Arduino Uno-class microcontroller has 2 KB of RAM in total, so the
buffer limit is not an artefact of the simulation.

**Decision:** post-quantum protection terminates at the gateway. The gateway
acts as a crypto-translating proxy: legacy protocol towards the device, ML-KEM
towards the cloud.

**Why this is still worth doing:** the threat ML-KEM addresses is "harvest
now, decrypt later": an attacker records encrypted traffic today and decrypts
it once a large quantum computer exists. That attacker needs a place to record
traffic in bulk, which is the long-haul internet path (hop 2), not the local
link between a sensor and a gateway in the same building (hop 1). Hop 1 also
gains nothing from ML-KEM while its key is hardcoded and shared by the whole
fleet: anyone who extracts it from one device can read every device,
quantum computer or not.

## 3. Cryptographic inventory

The first step of any PQC migration is knowing where cryptography is used.
This is the inventory for this system.

| Where | Algorithm | Key / secret | Stored at | Quantum-vulnerable? | Status |
| --- | --- | --- | --- | --- | --- |
| Device to gateway | AES-128-CBC, no MAC | One pre-shared key for the whole fleet | Device firmware, gateway code (`protocol.py:43`) | Symmetric, so only weakened (Grover); the real problems are the shared hardcoded key and no integrity | Accepted residual risk (section 6) |
| Gateway to cloud, key establishment | ML-KEM-768 (FIPS 203), two encapsulations | Cloud long-term key pair; one-time gateway key pair per session | Cloud: `CLOUD_KEM_KEY_FILE` (Docker volume); gateway: memory only | No | Migrated |
| Gateway to cloud, messages | AES-256-GCM | Session key, max 1 hour or 10,000 messages | Memory only | No (256-bit) | Migrated |
| Key derivation | HKDF-SHA256 | - | - | No | Migrated |
| Cloud authentication | SHA-256 fingerprint pin of the cloud public key | Fingerprint | Gateway configuration (`CLOUD_KEY_FINGERPRINT`) | No | Migrated |
| Gateway authentication | HMAC-SHA256 proof of a shared token | One token shared by all gateways | Environment variable `GATEWAY_TOKEN` | No, but weak: shared, never rotated | Partly fixed |
| Legacy cloud ingest (`/api/v1/telemetry`) | None (plain HTTP, token in a header) | Same shared token, sent in clear | - | Not encrypted at all | Kept only for rollback; switched off at the end of the migration |
| Read APIs and dashboard | None (plain HTTP) | - | - | Not encrypted at all | Open (section 7) |

There was no RSA or elliptic-curve key exchange in the baseline to replace:
the legacy system had **no key establishment at all**. The migration adds key
establishment rather than swapping one algorithm for another.

## 4. Migration plan

The migration is done gateway by gateway, so that one failing site never
stops the whole fleet, and it is driven by data the system already reports.

### Phase 0: Prepare (before any gateway changes)

1. Deploy the upgraded cloud. It serves **both** ingest paths: `/api/v1`
   (legacy) and `/api/v2` (ML-KEM). `LEGACY_INGEST_ENABLED=true`.
2. Give the cloud a persistent key file (`CLOUD_KEM_KEY_FILE`) and **back it
   up**. Losing it means every pinned gateway refuses the cloud (section 5,
   scenario C).
3. Publish the cloud key fingerprint through a channel the attacker does not
   control: the deployment documentation or configuration management, not
   only the cloud's own `/health` page, which an attacker in the middle could
   fake.
4. Record a baseline: on the dashboard, every reading is labelled `legacy`.

### Phase 1: Upgrade gateways one at a time

For each gateway:

1. Configure `CLOUD_KEY_FINGERPRINT` (pinning) and `CRYPTO_MODE=mlkem`. The
   container entrypoint refuses to start without a valid 64-character
   fingerprint, so a gateway cannot accidentally run with trust on first use.
2. Restart the gateway. Devices need no change; they reconnect on their own.
3. Verify within minutes: the gateway logs `ML-KEM session ... established`,
   `handshakes_ok` rises, and that site's readings appear on the dashboard
   with the `ML-KEM` badge.
4. If verification fails, roll that one gateway back (section 5). The others
   are unaffected.

Progress is visible at any time in the cloud's `/health`:
`pqc.readings_by_channel` shows how many stored readings came over each path.

### Phase 2: Retire the legacy path

When `readings_by_channel.legacy` has stayed at **0** for an agreed period
(for example two weeks, long enough to cover gateways that only connect
occasionally):

1. Set `LEGACY_INGEST_ENABLED=false` on the cloud and restart it.
2. The legacy endpoint now answers `410 Gone` with "upgrade the gateway to
   ML-KEM", so a forgotten gateway fails loudly instead of silently.
3. From this point an attacker can no longer use the legacy endpoint, and the
   shared token no longer crosses the network anywhere.

This step is what makes the migration finished. As long as the legacy path is
open, an attacker can use it no matter how many gateways have moved.

### Phase 3: The device hop (long term)

The device link cannot be migrated in software. The options, in order of cost:

1. **Compensating controls now:** keep devices and gateway on an isolated
   network segment (or a direct serial link), restrict who can reach port
   9000 (the gateway listens on localhost by default and must be opened
   explicitly; see `docs/quality-checks.md`), and physically secure the devices, because one stolen device
   reveals the fleet key.
2. **Replace devices at end of life** with hardware that can do modern
   authenticated encryption with a unique key per device, and ideally
   post-quantum key establishment. Procurement requirements should state this
   now, so no new device with a hardcoded shared key is bought.
3. **Retire the legacy protocol** on a gateway once its last legacy device
   has been replaced.

### Phase 4: Hardening (recommended, not done in this project)

See section 7: hybrid key exchange, a production ML-KEM library, transport
security for the read APIs, per-gateway credentials, and an encrypted cloud
key.

## 5. Fallback and rollback strategy

**Principle: the gateway never falls back on its own.** If the ML-KEM
handshake fails, readings are counted as failed and dropped (there is no
queue), exactly as when the cloud is down. An automatic fallback would let any
attacker who can block the handshake force traffic onto the unprotected path,
a **downgrade attack**, which would undo the migration without anyone
noticing.

This is enforced in code (`edge_gateway/gateway.py`) and tested in
`tests/test_failures.py`: `test_blocked_handshake_never_falls_back_to_legacy` blocks the handshake three
different ways and checks that no request ever reaches `/api/v1`.

**Falling back is an operator decision.** The table below says what to do in
each failure situation and who decides.

| Scenario | How it shows up | Action | Who decides |
| --- | --- | --- | --- |
| **A. Cloud temporarily down** | `forward_failed` and `handshakes_failed` rise on every gateway; `/health` unreachable | **No rollback.** Fix the cloud; gateways recover on their own with the next reading (`test_gateway_recovers_by_itself_after_an_outage`). Readings during the outage are lost (no store-and-forward). | Cloud operator |
| **B. One gateway cannot handshake, others can** | `handshakes_failed` rises on one gateway only | Check that gateway's fingerprint configuration and network path. Possible attack on that site's link: investigate before anything else. | Gateway operator, with security owner |
| **C. Cloud lost its key** (restarted without the key file, or volume deleted) | Every pinned gateway logs "fingerprint does not match the pinned"; `handshakes_failed` rises everywhere | **Restore the key file from backup** and restart the cloud. Only if no backup exists: distribute the new fingerprint through the trusted channel and re-pin every gateway. Never unpin. | Cloud operator, with security owner |
| **D. A defect in the ML-KEM code or library** makes the channel unusable | Handshakes fail everywhere after an update | Roll back the software version first. Only if that is impossible: set `CRYPTO_MODE=legacy` on the affected gateways, as a documented, time-limited exception. | Security owner (accepts the risk in writing) |
| **E. Legacy path already retired, rollback needed** | Scenario D after Phase 2 | Set `LEGACY_INGEST_ENABLED=true` on the cloud as well as `CRYPTO_MODE=legacy` on gateways. Both ends must agree, which makes an accidental downgrade harder. | Security owner |

**Rollback to legacy** (scenarios D and E) means readings and the gateway
token cross the internet unprotected again. It must be time-limited, logged,
and reversed as soon as the cause is fixed. The cloud's
`readings_by_channel.legacy` counter rising again is the signal that a
rollback is in effect, so it should be watched by monitoring, not only by
eye.

## 6. Risk register

Likelihood and impact: **H**igh, **M**edium, **L**ow, judged for a small
sensor deployment like this one. Owners are roles, not people.

| ID | Risk | L | I | Control in place | Residual risk | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | Recorded gateway-cloud traffic decrypted later by a quantum computer ("harvest now, decrypt later") | M | M | ML-KEM-768 key establishment; one-time key per session gives forward secrecy | Low. Depends on ML-KEM staying secure (see R9) | Security owner |
| R2 | Attacker on the site LAN reads or forges device frames | M | H | None in the protocol (hardcoded shared key, no MAC). Network isolation recommended; gateway port on localhost by default | **High. Accepted**, because the devices cannot be changed. Reduced only by Phase 3 | Site owner |
| R3 | One stolen device reveals the key of the whole fleet | M | H | None (key is in firmware) | **High. Accepted** until devices are replaced | Site owner |
| R4 | Downgrade attack: blocking the handshake to force the legacy path | M | H | No automatic fallback (tested); rollback is a manual, logged decision | Low | Security owner |
| R5 | Man in the middle replaces the cloud's public key | L | H | Fingerprint pinning; entrypoint refuses to start without a pin | Low. Trust on first use remains possible when the gateway is run by hand without `--cloud-key-fingerprint` (tested as a `security` finding) | Gateway operator |
| R6 | Cloud private key stolen from disk | L | H | File permission 0600 in the container; forward secrecy protects past sessions | Medium. The key is not encrypted at rest; a thief could impersonate the cloud to gateways until it is rotated | Cloud operator |
| R7 | Cloud key lost (no backup) | M | M | Fail closed: pinned gateways refuse a new key (tested) | Medium. Data stops flowing until restore or re-pin | Cloud operator |
| R8 | Shared gateway token leaked | M | M | Never sent on the ML-KEM path (HMAC proof only) | Medium. One token for all gateways, no rotation; a leaked token lets anyone open sessions and inject readings | Security owner |
| R9 | Weakness in the ML-KEM implementation (timing side channels) | L | H | Library pinned to an exact version (`kyber-py==1.2.0`); isolated behind `pqc_channel/` | Medium. kyber-py is pure Python and not constant-time; not for production | Security owner |
| R10 | Our own handshake design has a flaw | L | H | Built from standard parts; 38 channel and integration tests, 19 failure tests; mutation testing | Medium. It is a custom composition, not a standardised and reviewed protocol | Security owner |
| R11 | Readings lost when the cloud is unreachable | M | L | Losses counted (`forward_failed`) | Medium. No store-and-forward queue | Gateway operator |
| R12 | Readings lost when the cloud restarts | H | L | None | Medium. In-memory storage only | Cloud operator |
| R13 | Read APIs and dashboard readable by anyone on the network path | M | M | None | Medium. Plain HTTP, no authentication on read endpoints | Cloud operator |
| R14 | AI-generated code accepted without understanding | M | H | Every change via pull request with review; tests, static analysis and mutation testing in CI; AI use logged in `docs/ai-prompts.md` | Medium. Review depth depends on the reviewer's knowledge of cryptography | Whole group |

## 7. Technical debt and recommendations

In priority order for a real deployment:

1. **Hybrid key exchange (X25519 + ML-KEM-768).** Security would then hold if
   either algorithm is broken. ML-KEM is new, and a hybrid is the common
   transition recommendation.
2. **Production ML-KEM library** (for example liboqs). Only
   `pqc_channel/channel.py` would change.
3. **A standard protocol instead of our own.** A TLS 1.3 connection with a
   hybrid post-quantum key exchange would replace the custom handshake and
   also protect the read APIs (R13).
4. **Per-gateway credentials** with rotation, replacing the shared token (R8).
5. **Encrypt the cloud private key at rest**, or keep it in a secrets manager
   (R6), with a tested backup and restore (R7).
6. **Store-and-forward queue** on the gateway and **persistent storage** in
   the cloud (R11, R12).
7. **Device replacement policy** requiring unique per-device keys and
   authenticated encryption (R2, R3).

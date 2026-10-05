# Local container deployment

This project uses Docker Compose for a small, reproducible test deployment. It runs the cloud service, edge gateway, and legacy device simulator on one private Compose network.

## Prerequisites

- Docker Desktop with Compose support, or Docker Engine plus the Compose plugin.
- No paid account is required for local builds and execution.
- A Docker Hub account is not required unless images are pushed to a registry.

## First-time setup

1. Copy `.env.example` to `.env`.
2. Set a local `GATEWAY_TOKEN`.
3. Start only the cloud service so it generates or loads its ML-KEM key:

   ```text
   docker compose up -d --build cloud
   ```

4. Read the fingerprint from the cloud health response:

   ```text
   curl http://127.0.0.1:8000/health
   ```

   Copy `pqc.public_key_fingerprint` into `CLOUD_KEY_FINGERPRINT` in `.env`.
5. Start the gateway and device:

   ```text
   docker compose up -d --build gateway device
   ```

The gateway refuses to start if the fingerprint is missing, malformed, or not
64 hexadecimal characters. This prevents the secure Compose deployment from
silently relying on trust-on-first-use.

## Verify the deployment

Check the service status and logs:

```text
docker compose ps
docker compose logs --follow gateway
```

Open the dashboard at <http://127.0.0.1:8000/> or query the API:

```text
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/devices
curl "http://127.0.0.1:8000/api/v1/telemetry?limit=5"
```

Readings delivered through the modern path have `channel: "mlkem"`.

## Smoke test

With the cloud and gateway running, execute:

```text
python scripts/compose_smoke_test.py
```

The smoke test starts a temporary device container, waits for a reading, and
verifies that the cloud received it over ML-KEM. It removes the temporary
device container afterward.

## Stop and clean up

```text
docker compose down
docker compose down --volumes
```

The first command removes containers and the network but preserves the named
ML-KEM key volume. The second command also deletes the key volume, meaning the
cloud will generate a new key on the next start and the gateway fingerprint
must be updated.

## Configuration

- `GATEWAY_TOKEN`: local gateway/cloud shared secret.
- `CLOUD_KEY_FINGERPRINT`: pinned SHA-256 fingerprint of the cloud ML-KEM public key.
- `CLOUD_KEM_KEY_FILE`: set internally to `/keys/cloud_kem.json`.
- `LEGACY_INGEST_ENABLED`: keep `true` during migration, then set `false`.
- `CRYPTO_MODE`: `mlkem` by default; `legacy` is an explicit rollback mode.
- `DEVICE_ID`: simulated device identity.
- `DEVICE_INTERVAL`: seconds between readings.

Do not commit `.env`, private key files, or the `.keys` directory.

## CI and remote test environments

The CI workflow should build the images and run the smoke test as a separate
job after unit tests. A remote test environment can use the same Compose file
on a university VM or another Linux host. Publishing images to Docker Hub or
GitHub Container Registry is optional and is not necessary for local grading.

## Rollback

Rollback must be an explicit operator action. Start the gateway with
`CRYPTO_MODE=legacy` only for a documented migration or recovery scenario. Do
not implement automatic fallback after an ML-KEM handshake failure, because an
attacker could force a downgrade by blocking the handshake.

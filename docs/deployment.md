# Local container deployment

This project uses Docker Compose for a small, reproducible test deployment. It runs the cloud service, edge gateway, and legacy device simulator on one private Compose network.

## Prerequisites

- Docker Desktop with Compose support, or Docker Engine plus the Compose plugin.
- No paid account is required for local builds and execution.
- A Docker Hub account is not required unless images are pushed to a registry.

**Building on Windows:** `edge_gateway/entrypoint.sh` must have Unix (LF) line
endings, or the gateway container fails to start (`/bin/sh` cannot read the
`\r` at each line end). `.gitattributes` makes git check it out with LF. A
copy checked out before that rule existed keeps its old line endings until
it is checked out again:

```text
git rm --cached edge_gateway/entrypoint.sh
git checkout -- edge_gateway/entrypoint.sh
```

This was found while adding the Docker CI job: CI builds on Linux and the
script was written on a Mac, so neither would ever have shown the problem.

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

Health checks and metrics:

```text
curl http://127.0.0.1:9100/health     # gateway: "status": "ok" when pinned and forwarding
curl http://127.0.0.1:9100/metrics    # gateway counters
curl http://127.0.0.1:8000/metrics    # cloud counters
```

Logs are JSON, one object per line, so they can be filtered with `jq`:

```text
docker compose logs --no-log-prefix gateway | jq 'select(.event == "handshake_ok")'
```

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
- `LOG_FORMAT`: `json` by default in Compose; `text` for readable lines.

Do not commit `.env`, private key files, or the `.keys` directory.

## Test environment

The test environment is a fresh GitHub Actions runner, deployed to by
`.github/workflows/docker.yml` on every push and pull request to `main`. GitHub
records each run as a deployment to the environment named **test**: see the
repository's **Deployments** page, or the "Docker build and deployment test"
runs in the **Actions** tab.

Each deployment:

1. builds the three images from scratch;
2. checks every container runs as a non-root user;
3. checks the gateway refuses to start with a malformed fingerprint;
4. starts the cloud, reads its key fingerprint, and starts the gateway pinned
   to it, plus a device, all with legacy ingest **switched off** (the end
   state of the migration);
5. runs the smoke test: a new device's reading must reach the cloud over
   ML-KEM;
6. checks that every stored reading came over ML-KEM;
7. checks the health and metrics endpoints report the expected state, and
   that every log line from the cloud and gateway is valid JSON;
8. prints all container logs if any step failed, then tears everything down.

**Why an ephemeral environment.** Every deployment starts from nothing, so it
proves the system can be deployed from the repository alone, with no
hand-configured state on a server. It costs nothing, needs no credentials,
and runs before a change is merged, which is when a deployment problem is
cheapest to fix.

**What it does not show.** It does not run for long (no slow leaks, no
hourly session renewal), it has no real network between the services, and
nobody can open its dashboard while it runs.

### Deploying to a remote server (optional, not done in this project)

The same Compose file runs on any Linux host with Docker, for example a
university VM. Docker can deploy to it over SSH from a developer's machine:

```text
docker context create test-vm --docker "host=ssh://user@test-vm.example"
docker --context test-vm compose up -d --build cloud
curl http://test-vm.example:8000/health      # read the fingerprint
# set CLOUD_KEY_FINGERPRINT in .env, then:
docker --context test-vm compose up -d --build gateway device
```

On a shared server, also: keep ports bound to localhost or a private network
as `compose.yaml` does, put the gateway token in the server's environment
rather than in a file in the repository, and back up the `sdmo-pqc-cloud-keys`
volume (losing it means every pinned gateway refuses the cloud).

Publishing images to Docker Hub or GitHub Container Registry is optional and
not needed for any of the above.

## Rollback

Rollback must be an explicit operator action. Start the gateway with
`CRYPTO_MODE=legacy` only for a documented migration or recovery scenario. Do
not implement automatic fallback after an ML-KEM handshake failure, because an
attacker could force a downgrade by blocking the handshake.

"""Smoke-test a running Docker Compose deployment.

Usage:
    python scripts/compose_smoke_test.py

The script starts one short-lived device container, waits for a reading, and
verifies that it arrived through the ML-KEM path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOUD_URL = os.environ.get("SMOKE_CLOUD_URL", "http://127.0.0.1:8000")
DEVICE_ID = f"compose-smoke-{int(time.time())}"


def get_json(path: str) -> dict:
    with urllib.request.urlopen(f"{CLOUD_URL}{path}", timeout=3) as response:
        return json.load(response)


def main() -> int:
    try:
        health = get_json("/health")
        if health.get("status") != "ok":
            raise RuntimeError(f"cloud is not healthy: {health}")
        if health.get("pqc", {}).get("algorithm") != "ML-KEM-768":
            raise RuntimeError("cloud is not serving ML-KEM-768")

        result = subprocess.run(
            [
                "docker",
                "compose",
                "run",
                "--detach",
                "--rm",
                "--no-deps",
                "device",
                "python",
                "-m",
                "legacy_device.device",
                "--host",
                "gateway",
                "--port",
                "9000",
                "--device-id",
                DEVICE_ID,
                "--interval",
                "1",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        container_id = result.stdout.strip().splitlines()[-1]

        try:
            deadline = time.monotonic() + 20
            query = urllib.parse.quote(DEVICE_ID)
            while time.monotonic() < deadline:
                readings = get_json(f"/api/v1/telemetry?device_id={query}&limit=20")
                if any(item.get("channel") == "mlkem" for item in readings.get("readings", [])):
                    print(f"PASS: {DEVICE_ID} reached the cloud over ML-KEM")
                    return 0
                time.sleep(1)
            raise RuntimeError("no ML-KEM reading arrived within 20 seconds")
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except (OSError, subprocess.CalledProcessError, urllib.error.URLError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

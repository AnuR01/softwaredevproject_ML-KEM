"""
Baseline measurement harness.

WHY THIS EXISTS
    The project report has to show the cost of moving to post-quantum
    cryptography. That is only possible with a "before" measurement, taken
    while the system still uses the legacy scheme. Run this BEFORE integrating
    ML-KEM, and again afterwards with the same script - then the difference is
    the real cost of the migration rather than an unanchored number.

WHAT IT MEASURES
    Local (always runs, no services needed):
      * frame size for a typical reading, against the device's buffer limit
      * key-establishment cost, which is currently zero operations and zero
        bytes because the key is hardcoded - that zero is the finding
      * encrypt and decrypt time per frame, and frames per second
    End-to-end (only if a gateway and cloud are reachable):
      * device-to-cloud latency per reading
      * sustained ingest throughput

HOW TO RUN
    Local measurements only:
        python -m tools.baseline

    Including end-to-end, with the cloud and gateway already running:
        python -m tools.baseline --e2e

    Results print as a table and are written to
    docs/measurements/baseline-<UTC date>.json so they can be cited directly
    in the report.

NOTE ON METHOD
    Timings use time.perf_counter and report the median alongside the mean,
    because a laptop under load produces occasional large outliers that would
    otherwise distort the average. The end-to-end figure includes a polling
    interval and is labelled as an upper bound rather than pretending to
    microsecond accuracy.
"""

import argparse
import json
import socket
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from legacy_device.protocol import (
    MAX_FRAME_BYTES,
    build_reading,
    decrypt_frame,
    encrypt_frame,
)

# Written next to the docs so measurements live with the report they support.
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "measurements"

# How many iterations each micro-benchmark runs. Large enough that per-call
# timer overhead is negligible, small enough to finish in a second or two.
CRYPTO_ITERATIONS = 5000

# ML-KEM-768 parameter sizes from NIST FIPS 203, for the comparison column.
# Hardcoded rather than imported so this script runs before kyber-py is a
# dependency; the same numbers are asserted in tests/test_protocol.py.
MLKEM768_PUBLIC_KEY_BYTES = 1184
MLKEM768_CIPHERTEXT_BYTES = 1088
MLKEM768_SHARED_SECRET_BYTES = 32

# Reference record used for every size measurement, so the numbers are
# comparable run to run.
REFERENCE_RECORD = build_reading("dev-001", 1, 21.50, 44.20, 12)


def measure_frame_sizes() -> dict:
    """Frame overhead and how much of the device's buffer it uses."""
    frame = encrypt_frame(REFERENCE_RECORD)
    plaintext_bytes = len(REFERENCE_RECORD.encode("ascii"))

    return {
        "reference_record": REFERENCE_RECORD,
        "plaintext_bytes": plaintext_bytes,
        "frame_bytes": len(frame),
        # Hex encoding doubles the payload and the IV adds 16 bytes before
        # encoding, so the overhead is substantial for such a small reading.
        "overhead_bytes": len(frame) - plaintext_bytes,
        "device_buffer_bytes": MAX_FRAME_BYTES,
        "buffer_used_percent": round(100 * len(frame) / MAX_FRAME_BYTES, 1),
        "headroom_bytes": MAX_FRAME_BYTES - len(frame),
    }


def measure_key_establishment() -> dict:
    """The legacy scheme's key-exchange cost, and what ML-KEM will cost.

    The baseline performs no key establishment at all: the key is compiled
    into the firmware. Recording the zero explicitly is the point - it is what
    makes the post-quantum handshake cost interpretable later, and it is also
    the security weakness restated as a measurement.
    """
    return {
        "legacy": {
            "mechanism": "hardcoded pre-shared AES-128 key",
            "handshake_round_trips": 0,
            "handshake_bytes": 0,
            "handshake_ms": 0.0,
            "key_rotation_supported": False,
            "forward_secrecy": False,
        },
        "mlkem768_projected": {
            "mechanism": "ML-KEM-768 encapsulation (NIST FIPS 203)",
            # One round trip: fetch the public key, return the ciphertext.
            "handshake_round_trips": 1,
            "handshake_bytes": (MLKEM768_PUBLIC_KEY_BYTES
                                + MLKEM768_CIPHERTEXT_BYTES),
            "shared_secret_bytes": MLKEM768_SHARED_SECRET_BYTES,
            "key_rotation_supported": True,
            "forward_secrecy": True,
            "fits_device_buffer": MLKEM768_PUBLIC_KEY_BYTES <= MAX_FRAME_BYTES,
        },
    }


# Fewer iterations for ML-KEM: kyber-py is pure Python and each operation
# takes milliseconds rather than microseconds.
MLKEM_ITERATIONS = 200


def measure_mlkem() -> dict:
    """The implemented ML-KEM channel's real cost, measured with kyber-py.

    Reports raw handshake bytes (the cryptographic payload) and the bytes of
    the actual JSON bodies (base64 inflates them by a third), plus the time
    of each ML-KEM operation and of sealing one reading. The "projected"
    figure above assumed a single encapsulation; the implemented handshake
    uses two (long-term key for authentication, one-time key for forward
    secrecy), so it is roughly twice the size.
    """
    from pqc_channel import channel

    cloud_pk, cloud_sk = channel.generate_keypair()
    static_ss, static_ct = channel.encapsulate(cloud_pk)
    eph_pk, _eph_sk = channel.generate_keypair()
    eph_ss, eph_ct = channel.encapsulate(eph_pk)
    proof = channel.gateway_proof("token", static_ct, eph_pk)
    aead_key, confirm_key = channel.derive_session_keys(
        static_ss, eph_ss,
        channel.transcript(cloud_pk, static_ct, eph_pk, eph_ct))
    session_id = channel.new_session_id()
    tag = channel.confirmation_tag(confirm_key, session_id)

    # The same JSON bodies the gateway and cloud exchange.
    bodies = [
        {"algorithm": channel.ALGORITHM,
         "public_key": channel.b64encode(cloud_pk),
         "fingerprint": channel.fingerprint(cloud_pk)},
        {"static_ciphertext": channel.b64encode(static_ct),
         "ephemeral_public_key": channel.b64encode(eph_pk),
         "gateway_proof": channel.b64encode(proof)},
        {"session_id": session_id,
         "ephemeral_ciphertext": channel.b64encode(eph_ct),
         "confirmation": channel.b64encode(tag),
         "expires_in_s": 3600, "max_messages": 10000},
    ]
    raw_bytes = (len(cloud_pk) + len(static_ct) + len(eph_pk) + len(proof)
                 + len(eph_ct) + len(tag))

    reading = json.dumps(parse_reading_dict(REFERENCE_RECORD),
                         separators=(",", ":")).encode()
    nonce, sealed = channel.seal(aead_key, 0, session_id, reading)
    sealed_body = {"session_id": session_id,
                   "nonce": channel.b64encode(nonce),
                   "ciphertext": channel.b64encode(sealed)}

    return {
        "mechanism": "ML-KEM-768 x2 (long-term + ephemeral) -> HKDF-SHA256 "
                     "-> AES-256-GCM",
        "library": "kyber-py (pure Python, not constant-time)",
        "handshake_round_trips": 2,
        "handshake_round_trips_note": "1 to fetch the public key (cacheable) "
                                      "+ 1 for the key exchange",
        "handshake_raw_bytes": raw_bytes,
        "handshake_json_bytes": sum(len(json.dumps(b)) for b in bodies),
        "legacy_reading_json_bytes": len(reading),
        "sealed_reading_json_bytes": len(json.dumps(sealed_body)),
        "keygen": _time_calls(channel.generate_keypair, MLKEM_ITERATIONS),
        "encaps": _time_calls(lambda: channel.encapsulate(cloud_pk),
                              MLKEM_ITERATIONS),
        "decaps": _time_calls(lambda: channel.decapsulate(cloud_sk,
                                                          static_ct),
                              MLKEM_ITERATIONS),
        "seal_reading": _time_calls(
            lambda: channel.seal(aead_key, 1, session_id, reading),
            CRYPTO_ITERATIONS),
        "key_rotation_supported": True,
        "forward_secrecy": True,
    }


def parse_reading_dict(record: str) -> dict:
    """The reading as the gateway forwards it to the cloud."""
    from legacy_device.protocol import parse_reading
    return parse_reading(record)


def _time_calls(fn, iterations: int) -> dict:
    """Run fn() `iterations` times and summarise the per-call duration."""
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)

    samples.sort()
    return {
        "iterations": iterations,
        "mean_ms": round(statistics.fmean(samples), 5),
        "median_ms": round(statistics.median(samples), 5),
        # p95 rather than max: the maximum on a general-purpose OS is almost
        # always a scheduling artefact, not the code under test.
        "p95_ms": round(samples[int(0.95 * len(samples))], 5),
        "ops_per_second": round(1000.0 / statistics.median(samples)),
    }


def measure_crypto_throughput() -> dict:
    """Per-frame encrypt and decrypt cost for the legacy scheme."""
    frame = encrypt_frame(REFERENCE_RECORD)

    return {
        "encrypt_frame": _time_calls(
            lambda: encrypt_frame(REFERENCE_RECORD), CRYPTO_ITERATIONS
        ),
        "decrypt_frame": _time_calls(
            lambda: decrypt_frame(frame), CRYPTO_ITERATIONS
        ),
    }


def _cloud_get(cloud_url: str, path: str, timeout: float = 3.0) -> dict:
    """GET one JSON document from the cloud service."""
    with urllib.request.urlopen(f"{cloud_url}{path}", timeout=timeout) as resp:
        return json.loads(resp.read())


def _cloud_reachable(cloud_url: str) -> bool:
    try:
        _cloud_get(cloud_url, "/health")
        return True
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return False


def _seq_present(cloud_url: str, device_id: str, seq: int) -> bool:
    """Has the cloud stored this particular reading yet?"""
    body = _cloud_get(cloud_url, f"/api/v1/telemetry?device_id={device_id}"
                                 f"&limit=50")
    return any(r["seq"] == seq for r in body["readings"])


def measure_end_to_end(gateway_host: str, gateway_port: int, cloud_url: str,
                       samples: int, poll_s: float) -> dict:
    """Latency from device send to the reading being readable in the cloud.

    Measured by sending a frame and polling the cloud API until it appears, so
    the figure includes the poll interval and is an UPPER BOUND on true
    latency. That is honest and still useful: the same method is used after
    ML-KEM integration, so the comparison is fair even though the absolute
    number is pessimistic.
    """
    device_id = f"baseline-{int(time.time())}"
    latencies_ms = []

    with socket.create_connection((gateway_host, gateway_port),
                                  timeout=5) as sock:
        for seq in range(1, samples + 1):
            frame = encrypt_frame(
                build_reading(device_id, seq, 21.0, 45.0, seq)
            )

            start = time.perf_counter()
            sock.sendall(frame)

            # Poll until the reading is visible, or give up on this sample.
            deadline = start + 10.0
            while time.perf_counter() < deadline:
                if _seq_present(cloud_url, device_id, seq):
                    latencies_ms.append((time.perf_counter() - start) * 1000.0)
                    break
                time.sleep(poll_s)
            else:
                print(f"  ! sample {seq} never arrived, skipping",
                      file=sys.stderr)

    if not latencies_ms:
        return {"error": "no readings arrived; is the gateway pointed at "
                         "this cloud?"}

    latencies_ms.sort()
    return {
        "samples": len(latencies_ms),
        "poll_interval_ms": round(poll_s * 1000, 1),
        "note": "includes polling overhead; treat as an upper bound",
        "mean_ms": round(statistics.fmean(latencies_ms), 2),
        "median_ms": round(statistics.median(latencies_ms), 2),
        "p95_ms": round(latencies_ms[int(0.95 * len(latencies_ms))], 2),
        "min_ms": round(latencies_ms[0], 2),
        "max_ms": round(latencies_ms[-1], 2),
    }


def measure_ingest_throughput(gateway_host: str, gateway_port: int,
                              cloud_url: str, count: int) -> dict:
    """How many readings per second the whole chain sustains.

    Sends `count` frames back to back on one connection, then waits for the
    cloud's stored count to stop rising. Measures the pipeline as a whole -
    gateway threading, HTTP forwarding and cloud ingestion together - which is
    what will actually change when a handshake is added.
    """
    device_id = f"throughput-{int(time.time())}"
    before = _cloud_get(cloud_url, "/health")["stored_readings"]

    start = time.perf_counter()
    with socket.create_connection((gateway_host, gateway_port),
                                  timeout=5) as sock:
        for seq in range(1, count + 1):
            sock.sendall(
                encrypt_frame(build_reading(device_id, seq, 21.0, 45.0, seq))
            )

        # Wait for the backlog to drain: stop when the count has not moved for
        # three consecutive checks.
        stable = 0
        last = -1
        while stable < 3 and time.perf_counter() - start < 60:
            time.sleep(0.2)
            now = _cloud_get(cloud_url, "/health")["stored_readings"]
            stable = stable + 1 if now == last else 0
            last = now

    elapsed_s = time.perf_counter() - start
    stored = max(0, last - before)

    return {
        "frames_sent": count,
        "readings_stored": stored,
        "elapsed_s": round(elapsed_s, 3),
        "readings_per_second": round(stored / elapsed_s, 1) if elapsed_s else 0,
        "note": "single device connection; the ring buffer caps total storage "
                "at 1000 readings",
    }


def print_report(results: dict) -> None:
    """Print the measurements as a plain table for the terminal."""
    def row(label: str, value: object) -> None:
        print(f"  {label:<34} {value}")

    print("\n" + "=" * 68)
    print(f"  MEASUREMENTS - {results['label']}")
    print("=" * 68)

    sizes = results["frame_sizes"]
    print("\nFrame sizes")
    row("reference record", sizes["reference_record"])
    row("plaintext", f"{sizes['plaintext_bytes']} B")
    row("frame on the wire", f"{sizes['frame_bytes']} B")
    row("protocol overhead", f"{sizes['overhead_bytes']} B")
    row("device buffer", f"{sizes['device_buffer_bytes']} B")
    row("buffer used", f"{sizes['buffer_used_percent']}%")

    keys = results["key_establishment"]
    print("\nKey establishment")
    row("legacy mechanism", keys["legacy"]["mechanism"])
    row("legacy handshake", f"{keys['legacy']['handshake_bytes']} B, "
                            f"{keys['legacy']['handshake_round_trips']} round trips")
    row("legacy key rotation", keys["legacy"]["key_rotation_supported"])
    projected = keys["mlkem768_projected"]
    row("ML-KEM-768 handshake", f"{projected['handshake_bytes']} B, "
                                f"{projected['handshake_round_trips']} round trip")
    row("ML-KEM fits device buffer",
        keys["mlkem768_projected"]["fits_device_buffer"])

    crypto = results["crypto_throughput"]
    print("\nPer-frame cryptography")
    for name in ("encrypt_frame", "decrypt_frame"):
        stats = crypto[name]
        row(name, f"median {stats['median_ms']} ms, "
                  f"p95 {stats['p95_ms']} ms, "
                  f"{stats['ops_per_second']:,} ops/s")

    if "mlkem" in results:
        mk = results["mlkem"]
        print("\nML-KEM channel (implemented)")
        row("mechanism", mk["mechanism"])
        row("handshake", f"{mk['handshake_raw_bytes']} B raw, "
                         f"{mk['handshake_json_bytes']} B as JSON")
        row("reading on the wire", f"{mk['legacy_reading_json_bytes']} B plain -> "
                                   f"{mk['sealed_reading_json_bytes']} B sealed")
        for name in ("keygen", "encaps", "decaps", "seal_reading"):
            row(name, f"median {mk[name]['median_ms']} ms")

    if "end_to_end" in results:
        e2e = results["end_to_end"]
        print("\nEnd-to-end latency (device -> cloud)")
        if "error" in e2e:
            row("error", e2e["error"])
        else:
            row("samples", e2e["samples"])
            row("median", f"{e2e['median_ms']} ms")
            row("p95", f"{e2e['p95_ms']} ms")
            row("note", e2e["note"])

    if "throughput" in results:
        tp = results["throughput"]
        print("\nSustained ingest")
        row("frames sent", tp["frames_sent"])
        row("readings stored", tp["readings_stored"])
        row("rate", f"{tp['readings_per_second']} readings/s")

    print("\n" + "=" * 68)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure the system (run before and after ML-KEM integration)"
    )
    parser.add_argument("--e2e", action="store_true",
                        help="also measure end-to-end latency and throughput "
                             "(requires a running gateway and cloud)")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=9000)
    parser.add_argument("--cloud-url", default="http://127.0.0.1:8000")
    parser.add_argument("--samples", type=int, default=20,
                        help="latency samples to collect")
    parser.add_argument("--throughput-frames", type=int, default=200)
    parser.add_argument("--poll-interval", type=float, default=0.005,
                        help="seconds between cloud polls when timing latency")
    parser.add_argument("--label", default="baseline",
                        help="output filename prefix; use 'mlkem' for the "
                             "post-integration run so both files survive")
    args = parser.parse_args()

    cloud_url = args.cloud_url.rstrip("/")

    results = {
        "label": args.label,
        "measured_at": datetime.now(UTC).isoformat(),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "frame_sizes": measure_frame_sizes(),
        "key_establishment": measure_key_establishment(),
        "crypto_throughput": measure_crypto_throughput(),
    }

    # Only once ML-KEM is integrated. Skipped cleanly if kyber-py is missing,
    # so the script can still reproduce a pure baseline run.
    try:
        results["mlkem"] = measure_mlkem()
    except ImportError as exc:
        print(f"! ML-KEM not measured: {exc}", file=sys.stderr)

    if args.e2e:
        if not _cloud_reachable(cloud_url):
            print(f"! cloud not reachable at {cloud_url}; skipping end-to-end "
                  f"measurements", file=sys.stderr)
        else:
            print(f"measuring end-to-end against {cloud_url} ...")
            results["end_to_end"] = measure_end_to_end(
                args.gateway_host, args.gateway_port, cloud_url,
                args.samples, args.poll_interval,
            )
            results["throughput"] = measure_ingest_throughput(
                args.gateway_host, args.gateway_port, cloud_url,
                args.throughput_frames,
            )

    print_report(results)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    out = OUTPUT_DIR / f"{args.label}-{stamp}.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwritten to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

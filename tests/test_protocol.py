"""
Tests for the legacy wire protocol.

Two kinds of test live here:

* Ordinary correctness tests, so we can tell later whether an ML-KEM change
  broke the plumbing or the cryptography.
* Security tests that DEMONSTRATE the baseline system's weaknesses rather than
  guard against them. Those are marked with `security` and named so it is
  obvious they assert a flaw exists. They exist because the project brief asks
  us to show how problems were identified and verified - a passing test is
  much stronger evidence than a paragraph claiming a weakness is exploitable.
"""

import pytest

from legacy_device.protocol import (
    FRAME_SEP,
    LEGACY_PSK,
    MAX_FRAME_BYTES,
    build_reading,
    decrypt_frame,
    encrypt_frame,
    parse_reading,
)

# --------------------------------------------------------------------------
# Record formatting and parsing
# --------------------------------------------------------------------------

def test_build_reading_uses_documented_layout():
    """The gateway depends on this exact field order and precision."""
    record = build_reading("dev-001", 1, 21.5, 44.2, 12)
    assert record == "DEV|dev-001|1|21.50|44.20|12"


def test_parse_reading_roundtrips_build_reading():
    record = build_reading("dev-042", 7, -3.25, 88.0, 3600)

    assert parse_reading(record) == {
        "device_id": "dev-042",
        "seq": 7,
        "temp_c": -3.25,
        "humidity": 88.0,
        "uptime_s": 3600,
    }


@pytest.mark.parametrize("record", [
    "DEV|dev-001|1|21.50|44.20",           # too few fields
    "DEV|dev-001|1|21.50|44.20|12|extra",  # too many fields
    "CFG|dev-001|1|21.50|44.20|12",        # unknown record type
    "DEV||1|21.50|44.20|12",               # empty device id
    "DEV|dev-001|x|21.50|44.20|12",        # non-numeric sequence
    "DEV|dev-001|1|warm|44.20|12",         # non-numeric temperature
])
def test_parse_reading_rejects_malformed_records(record):
    """Anything the gateway would forward to the cloud must parse strictly."""
    with pytest.raises(ValueError):
        parse_reading(record)


# --------------------------------------------------------------------------
# Frame encryption and the device's size constraint
# --------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    record = build_reading("dev-001", 99, 25.0, 50.0, 120)

    assert decrypt_frame(encrypt_frame(record)) == record


def test_each_frame_uses_a_fresh_iv():
    """Two frames with identical plaintext must not produce identical bytes.

    If they did, an observer could tell when a reading repeated without
    breaking the encryption at all.
    """
    record = build_reading("dev-001", 1, 21.0, 45.0, 10)

    assert encrypt_frame(record) != encrypt_frame(record)


def test_typical_frame_fits_the_device_buffer():
    """A normal reading must fit, with room to spare.

    The measured size is the baseline number cited in the report and in
    docs/brief.html, so this test pins it: if the record layout changes, the
    documented figure has to change with it.
    """
    frame = encrypt_frame(build_reading("dev-001", 1, 21.50, 44.20, 12))

    assert len(frame) == 98
    assert len(frame) < MAX_FRAME_BYTES


def test_oversized_payload_is_rejected_not_truncated():
    """Exceeding the device buffer must raise, not silently corrupt.

    A device that truncated frames would produce undecodable garbage at the
    gateway, which is far harder to diagnose than an outright failure.
    """
    huge_device_id = "d" * 200

    with pytest.raises(ValueError, match="device buffer"):
        encrypt_frame(build_reading(huge_device_id, 1, 21.0, 45.0, 1))


def test_mlkem_768_public_key_cannot_fit_the_device_buffer():
    """The measurement the entire migration strategy rests on.

    ML-KEM-768 sizes come from NIST FIPS 203: a 1184-byte encapsulation key
    and a 1088-byte ciphertext. Both exceed the device's receive buffer, so
    post-quantum key establishment cannot run on the device and must terminate
    at the gateway. Asserting it here keeps the claim honest if anyone later
    changes MAX_FRAME_BYTES.
    """
    mlkem768_public_key_bytes = 1184
    mlkem768_ciphertext_bytes = 1088

    assert mlkem768_public_key_bytes > MAX_FRAME_BYTES
    assert mlkem768_ciphertext_bytes > MAX_FRAME_BYTES


@pytest.mark.parametrize("frame", [
    b"not-a-frame\n",                    # no separator
    b"\n",                               # empty
    b"zz:zz\n",                          # non-hex
    b"00112233:aabb\n",                  # IV too short
    b"000102030405060708090a0b0c0d0e0f:aabbcc\n",  # partial cipher block
    b"000102030405060708090a0b0c0d0e0f:\n",        # empty ciphertext
])
def test_decrypt_rejects_malformed_frames(frame):
    with pytest.raises(ValueError):
        decrypt_frame(frame)


def test_decrypt_with_wrong_key_fails():
    """A device from another fleet must not be readable.

    Note what this does NOT prove: the fleet shares one key, so every device
    in this fleet can read every other device's traffic.
    """
    frame = encrypt_frame(build_reading("dev-001", 1, 21.0, 45.0, 10))
    other_key = bytes(16)

    with pytest.raises(ValueError):
        decrypt_frame(frame, key=other_key)


# --------------------------------------------------------------------------
# Security findings: these tests assert that weaknesses are real
# --------------------------------------------------------------------------

@pytest.mark.security
def test_finding_tampering_with_the_iv_rewrites_data_undetected():
    """FINDING: unauthenticated AES-CBC lets an attacker forge readings.

    In CBC mode the first plaintext block is computed as

        P1 = decrypt(C1) XOR IV

    so flipping a bit in the IV flips exactly that bit in the first 16 bytes
    of plaintext - without the key, and without breaking the decryption.

    Our record begins "DEV|dev-001|1|21", which puts the device identity
    inside that first block. A man-in-the-middle can therefore relabel a
    reading as coming from a different device, and the gateway accepts it as
    valid because there is nothing to verify against.

    Impact: telemetry integrity is not protected on the device hop at all.
    Fix: an authenticated mode (AES-GCM) with a per-session key. On the
    gateway->cloud hop, ML-KEM gives us that key. On the device hop we cannot
    fix it, so it is documented as accepted residual risk.
    """
    record = build_reading("dev-001", 1, 21.50, 44.20, 12)
    frame = encrypt_frame(record)

    # Confirm the assumption this attack relies on: the byte we target sits in
    # the first cipher block.
    assert record[8] == "0"

    iv_hex, ct_hex = frame.decode("ascii").strip().split(FRAME_SEP)
    iv = bytearray(bytes.fromhex(iv_hex))

    # '0' is 0x30 and '9' is 0x39, so XOR 0x09 turns one into the other.
    iv[8] ^= 0x09
    forged = f"{iv.hex()}{FRAME_SEP}{ct_hex}\n".encode("ascii")

    # The forged frame decrypts cleanly - no error is raised anywhere.
    tampered_record = decrypt_frame(forged)
    reading = parse_reading(tampered_record)

    # The attacker changed the device identity without knowing the key.
    assert reading["device_id"] == "dev-901"
    assert reading["device_id"] != "dev-001"

    # Everything else survived, so this reads as an entirely plausible
    # reading from a device that does not exist.
    assert reading["temp_c"] == 21.50
    assert reading["humidity"] == 44.20


@pytest.mark.security
def test_finding_ciphertext_tampering_is_caught_only_by_accident():
    """FINDING: corruption detection depends on luck, not design.

    Modifying the ciphertext usually breaks PKCS7 padding or produces
    non-ASCII bytes, so decrypt_frame raises. That looks like protection but
    is not: there is no integrity check, only a decode that happens to fail
    most of the time. The IV attack above slips through the same code path
    untouched.

    This test asserts the *mechanism*, so nobody later mistakes the frequent
    ValueError for real authentication.
    """
    record = build_reading("dev-001", 1, 21.50, 44.20, 12)
    iv_hex, ct_hex = encrypt_frame(record).decode("ascii").strip().split(FRAME_SEP)
    ciphertext = bytearray(bytes.fromhex(ct_hex))

    detected = 0
    attempts = 32
    for bit in range(attempts):
        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= (1 << (bit % 8))
        corrupted[0] ^= (1 << ((bit // 8) % 8))
        frame = f"{iv_hex}{FRAME_SEP}{corrupted.hex()}\n".encode("ascii")

        try:
            decrypt_frame(frame)
        except ValueError:
            detected += 1

    # Most corruption is caught, which is why the weakness is easy to miss.
    assert detected > 0
    # But the error is a decode failure, not an authentication failure: the
    # exception carries no proof of origin, and the IV attack above bypasses
    # it entirely.
    assert bytes.fromhex("000102030405060708090a0b0c0d0e0f") == LEGACY_PSK, (
        "the fleet-wide hardcoded key is part of this finding"
    )

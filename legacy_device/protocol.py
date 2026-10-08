"""
Legacy wire protocol and cryptography for the simulated Arduino-class device.

WHAT THIS IS
    The frame format and encryption used on the device <-> gateway hop. Both
    ends of that hop import this module, so there is exactly one definition of
    the wire format.

WHY IT LOOKS LIKE THIS
    This module deliberately reproduces the weaknesses of the system we
    inherited. It is the BASELINE we are asked to modernize, not a target
    design. Do not copy this pattern into new code.

    Known weaknesses, all intentional (see README.md):

    1. The AES key is hardcoded below and shared by every device in the fleet.
       Extract it from one device and you can read all traffic, forever.
    2. There is NO key establishment. Nothing is negotiated, nothing rotates.
       This is the "outdated key-establishment mechanism" the project brief
       refers to, and the gap ML-KEM is meant to close.
    3. Frames are encrypted but NOT authenticated. AES-CBC gives
       confidentiality only, so a man-in-the-middle can modify traffic and the
       receiver cannot tell. tests/test_protocol.py proves this is exploitable
       rather than theoretical.
    4. Replay protection relies only on a plaintext sequence counter, which
       the gateway tracks in memory and loses on restart.

WHY WE KEEP IT ANYWAY
    The device cannot be re-flashed in the field, so this hop stays as it is
    for the life of the hardware. Our migration puts post-quantum cryptography
    on the gateway <-> cloud hop instead; see docs/architecture notes in the
    README for the justification.
"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The pre-shared key burned into the firmware image of every device in the
# fleet. A real deployment would at minimum use one key per device; this system
# does not, which is weakness 1 above.
LEGACY_PSK = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

# Plaintext records are pipe-delimited, and one frame is "<iv>:<ciphertext>".
# Separators are single characters because the device has no room for a real
# serialization library such as JSON or protobuf.
FIELD_SEP = "|"
FRAME_SEP = ":"

# The constraint that drives our entire migration strategy.
#
# This class of microcontroller has a small serial/TCP receive buffer; we model
# it as 256 bytes. A typical reading frame measures 98 bytes, so the legacy
# protocol fits comfortably. ML-KEM-768 does not: its encapsulation key is
# 1184 bytes and its ciphertext 1088 bytes, both several times larger than the
# device's entire buffer.
#
# That is why post-quantum key establishment CANNOT run on the device, and why
# the gateway terminates it instead. Keep this constant here rather than in a
# document, so the argument is backed by a number the tests can check.
MAX_FRAME_BYTES = 256

# AES block size in bytes, used for the padding and length checks below.
_AES_BLOCK_BYTES = algorithms.AES.block_size // 8


def encrypt_frame(plaintext: str, key: bytes = LEGACY_PSK) -> bytes:
    """Encrypt one reading into a newline-terminated ASCII frame.

    The frame is ASCII hex rather than raw bytes because the legacy transport
    is line-oriented: the gateway reads up to a newline, so the payload must
    not contain one. Hex doubles the size, which is wasteful but is what the
    deployed devices do.

    Raises:
        ValueError: if the finished frame would not fit the device's receive
            buffer. Failing here is deliberate - a device that silently
            truncated frames would be far harder to diagnose in the field.
    """
    # A fresh random IV per frame. This part the legacy system got right: a
    # reused IV under CBC would leak whether two readings were identical.
    iv = os.urandom(_AES_BLOCK_BYTES)

    # CBC requires input to be a whole number of blocks, so pad to 16 bytes.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext.encode("ascii")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Note what is missing here: no MAC and no authentication tag. An
    # authenticated mode such as AES-GCM would append one, and tampering would
    # then be detectable. This is weakness 3.
    frame = f"{iv.hex()}{FRAME_SEP}{ciphertext.hex()}\n".encode("ascii")

    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError(
            f"frame is {len(frame)} bytes, device buffer is {MAX_FRAME_BYTES}"
        )
    return frame


def decrypt_frame(frame: bytes, key: bytes = LEGACY_PSK) -> str:
    """Recover the plaintext record from one frame.

    Every failure path raises ValueError, because the gateway genuinely cannot
    distinguish between them: a corrupted frame, a truncated frame and a
    deliberately modified frame all look the same without authentication. The
    gateway therefore treats them identically and logs the ambiguity.

    Raises:
        ValueError: on any malformed, corrupted or tampered frame.
    """
    try:
        iv_hex, ct_hex = frame.decode("ascii").strip().split(FRAME_SEP)
        iv, ciphertext = bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)
    except (UnicodeDecodeError, ValueError) as exc:
        # Covers non-ASCII bytes, a missing separator, extra separators and
        # non-hex characters.
        raise ValueError(f"malformed frame: {exc}") from exc

    # Validate lengths before decrypting. The cryptography library would also
    # complain, but checking here keeps the error messages useful to whoever
    # is reading the gateway log at 3am.
    if len(iv) != _AES_BLOCK_BYTES:
        raise ValueError(f"IV is {len(iv)} bytes, expected {_AES_BLOCK_BYTES}")
    if not ciphertext or len(ciphertext) % _AES_BLOCK_BYTES:
        raise ValueError(f"ciphertext length {len(ciphertext)} is not a whole "
                         f"number of {_AES_BLOCK_BYTES}-byte blocks")

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # A tampered frame usually fails here, because the padding no longer
    # decodes. That detection is accidental, not by design: it depends on where
    # the attacker modified the frame. Modifying the IV corrupts the first
    # plaintext block in a fully predictable way and leaves the padding intact,
    # so it is not caught at all - see tests/test_protocol.py.
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError(f"bad padding, frame corrupt or tampered: {exc}") from exc

    try:
        return plaintext.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"plaintext is not ASCII: {exc}") from exc


def build_reading(device_id: str, seq: int, temp_c: float, humidity: float,
                  uptime_s: int) -> str:
    """Format one sensor reading as the legacy pipe-delimited record.

    Layout, which the gateway relies on:

        DEV|<device_id>|<seq>|<temp_c>|<humidity>|<uptime_s>

    for example

        DEV|dev-001|1|21.50|44.20|12

    "DEV" is a record-type tag. The original protocol reserved it for other
    record types that were never implemented, which is why the gateway still
    checks it.
    """
    return FIELD_SEP.join([
        "DEV",
        device_id,
        str(seq),
        # Two decimal places matches the precision the real sensor reports.
        # Fixed width also keeps frame sizes predictable, which matters when
        # the receive buffer is only 256 bytes.
        f"{temp_c:.2f}",
        f"{humidity:.2f}",
        str(uptime_s),
    ])


def parse_reading(record: str) -> dict:
    """Parse a legacy record into a dict the cloud API can accept.

    This is strict on purpose. The gateway forwards whatever this returns
    straight to the cloud, so anything odd should be rejected here rather than
    stored. Range checking happens again in the cloud service, because the
    gateway is not the only thing that can post to it.

    Raises:
        ValueError: if the record does not have exactly six fields, does not
            start with the DEV tag, or has non-numeric numeric fields.
    """
    parts = record.split(FIELD_SEP)
    if len(parts) != 6:
        raise ValueError(f"expected 6 fields, got {len(parts)}: {record!r}")
    if parts[0] != "DEV":
        raise ValueError(f"unknown record type {parts[0]!r}")

    _, device_id, seq, temp_c, humidity, uptime_s = parts
    if not device_id:
        raise ValueError("empty device_id")

    # int() and float() raise ValueError on junk, which is the exception this
    # function documents, so no extra handling is needed.
    return {
        "device_id": device_id,
        "seq": int(seq),
        "temp_c": float(temp_c),
        "humidity": float(humidity),
        "uptime_s": int(uptime_s),
    }

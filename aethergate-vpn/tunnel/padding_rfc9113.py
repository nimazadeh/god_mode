"""RFC 9113 Section 6.1 PADDED frame encapsulation so statistical DPI classifiers cannot fingerprint inner payload lengths."""

import os
import secrets
import struct
from constants import (
    DEFAULT_MAX_PAD_BYTES,
    DEFAULT_MIN_PAD_BYTES,
    MAX_FRAME_PAYLOAD_BYTES,
    RFC9113_FLAG_PADDED,
    RFC9113_HEADER_LEN,
)


def pack_rfc9113_padded_frame(
    payload: bytes,
    min_pad: int = DEFAULT_MIN_PAD_BYTES,
    max_pad: int = DEFAULT_MAX_PAD_BYTES,
) -> tuple[bytes, int]:
    """Append cryptographically random padding per RFC 9113 (flag 0x08) so identical requests produce distinct wire sizes."""
    if len(payload) > MAX_FRAME_PAYLOAD_BYTES:
        raise ValueError("Payload exceeds maximum RFC 9113 frame size")
    lo = max(0, min(min_pad, 255))
    hi = max(lo, min(max_pad, 255))
    pad_len = lo + secrets.randbelow(hi - lo + 1)
    header = struct.pack("!BHB", RFC9113_FLAG_PADDED, len(payload), pad_len)
    padding = os.urandom(pad_len)
    return header + payload + padding, pad_len


def unpack_rfc9113_padded_frame(frame: bytes) -> tuple[bytes, int]:
    """Validate frame length and strip RFC 9113 trailing padding before passing the clean payload to upstream sockets."""
    if len(frame) < RFC9113_HEADER_LEN:
        raise ValueError("Truncated RFC 9113 frame header")
    flags, payload_len, pad_len = struct.unpack("!BHB", frame[:RFC9113_HEADER_LEN])
    if flags != RFC9113_FLAG_PADDED:
        raise ValueError("Invalid RFC 9113 frame flag")
    expected_total = RFC9113_HEADER_LEN + payload_len + pad_len
    if len(frame) < expected_total:
        raise ValueError("Truncated RFC 9113 frame body")
    payload = frame[RFC9113_HEADER_LEN : RFC9113_HEADER_LEN + payload_len]
    return payload, pad_len

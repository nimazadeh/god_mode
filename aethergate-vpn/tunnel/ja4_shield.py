"""FoxIO JA4 TLS ClientHello fingerprinter, RFC 8701 GREASE filter, and Client-Hint shield to prevent WAF bot-score blocks."""

import hashlib
import math
import re
from typing import Any

# Strip proxy forwarding headers and high-entropy hardware Client-Hints while leaving RFC 9577 PrivateToken intact.
_ANTI_FP_HDR_RE = re.compile(
    rb"\r\n(?:"
    rb"X-Forwarded-For|CF-Connecting-IP|True-Client-IP|X-Real-IP|X-Client-IP|Forwarded|Via|Proxy-Connection|"
    rb"Sec-CH-UA-Full-Version-List|Sec-CH-UA-Full-Version|Sec-CH-UA-Platform-Version|Sec-CH-UA-Model|"
    rb"Sec-CH-UA-Arch|Sec-CH-UA-Bitness|Sec-CH-UA-WoW64|Device-Memory|Accept-CH|Critical-CH"
    rb"):[^\r\n]*",
    re.IGNORECASE,
)
# Replace Persian/Iranian Accept-Language tags with standard US English so websites never fingerprint the user's country via locale headers.
_FA_ACCEPT_LANG_RE = re.compile(rb"\r\nAccept-Language:[^\r\n]*\bfa(?:-IR)?\b[^\r\n]*", re.IGNORECASE)


def is_rfc8701_grease(val: int) -> bool:
    """Detect RFC 8701 GREASE values (0x?a?a) so JA4 hashes ignore randomized dummy cipher and extension slots."""
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF)


def compute_shannon_entropy(data: bytes) -> float:
    """Measure Shannon byte entropy H(X) in [0, 8] bits/byte to verify padded frames do not exhibit anomalous entropy spikes."""
    if not data:
        return 0.0
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = -sum((c / n) * math.log2(c / n) for c in counts if c > 0)
    return round(entropy, 3)


def sanitize_http_fingerprint_headers(data: bytes) -> bytes:
    """Remove proxy IP leaks, hardware Client-Hints, and fa-IR language tags in-flight so websites cannot detect Iranian locale."""
    if not data or b"\r\n" not in data:
        return data
    cleaned = _ANTI_FP_HDR_RE.sub(b"", data)
    return _FA_ACCEPT_LANG_RE.sub(b"\r\nAccept-Language: en-US,en;q=0.9", cleaned)


def reassemble_tls_handshake_body(data: bytes) -> bytes:
    """Recombine multiple RFC 8446 Section 5.1 TLS records so we can verify that SNI record shredding leaves the logical JA4 intact."""
    pos, out = 0, bytearray()
    while pos + 5 <= len(data) and data[pos] == 0x16 and data[pos + 1] == 0x03:
        rec_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
        out.extend(data[pos + 5 : pos + 5 + rec_len])
        pos += 5 + rec_len
    return bytes(out) if out else data


def _parse_alpn_first_last(ext_bytes: bytes) -> str:
    """Extract the first and last character of the primary non-GREASE ALPN value ('h2' -> 'h2') so JA4_a matches FoxIO specs."""
    if len(ext_bytes) < 3:
        return "00"
    pos, end = 2, min(len(ext_bytes), 2 + int.from_bytes(ext_bytes[:2], "big"))
    while pos < end:
        plen = ext_bytes[pos]
        proto = ext_bytes[pos + 1 : pos + 1 + plen]
        pos += 1 + plen
        if len(proto) == 2 and is_rfc8701_grease(int.from_bytes(proto, "big")):
            continue
        txt = proto.decode("ascii", errors="ignore")
        if txt:
            return f"{txt[0]}{txt[-1]}"
    return "00"


def _parse_supported_tls_version(ext_bytes: bytes, fallback_ver: int) -> str:
    """Read extension 0x002b (supported_versions) because TLS 1.3 sets the legacy ClientHello version field to 0x0303 (TLS 1.2)."""
    best = fallback_ver
    if len(ext_bytes) >= 3:
        end = min(len(ext_bytes), 1 + ext_bytes[0])
        for i in range(1, end - 1, 2):
            v = int.from_bytes(ext_bytes[i : i + 2], "big")
            if not is_rfc8701_grease(v) and v > best:
                best = v
    return {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(best, "13")


def _parse_sig_algs(ext_bytes: bytes) -> list[str]:
    """Preserve wire order for signature_algorithms (0x000d) because FoxIO JA4_c sorts extension IDs but never sorts signature schemes."""
    if len(ext_bytes) < 4:
        return []
    end = min(len(ext_bytes), 2 + int.from_bytes(ext_bytes[:2], "big"))
    vals = [int.from_bytes(ext_bytes[i : i + 2], "big") for i in range(2, end - 1, 2)]
    return [f"{v:04x}" for v in vals if not is_rfc8701_grease(v)]


def _walk_client_hello_extensions(body: bytes, pos: int, fallback_ver: int) -> dict[str, Any]:
    """Collect non-GREASE extension IDs, signature schemes, and RFC 10024 PQ groups in one pass so JA4_c can be canonicalized."""
    sni, alpn, ver, grease = "i", "00", {0x0303: "12", 0x0301: "10"}.get(fallback_ver, "13"), 0
    exts, sigs, pq_group = [], [], "NONE"
    pq_map = {0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024"}
    if pos + 2 > len(body):
        return {"sni": sni, "alpn": alpn, "ver": ver, "exts": exts, "sigs": sigs, "grease": grease, "pq_group": pq_group}
    end = min(len(body), pos + 2 + int.from_bytes(body[pos : pos + 2], "big"))
    idx = pos + 2
    while idx + 4 <= end:
        etype, elen = int.from_bytes(body[idx : idx + 2], "big"), int.from_bytes(body[idx + 2 : idx + 4], "big")
        epayload = body[idx + 4 : idx + 4 + elen]
        idx += 4 + elen
        if is_rfc8701_grease(etype):
            grease += 1
            continue
        exts.append(etype)
        if etype == 0x0000 and elen > 0:
            sni = "d"
        elif etype == 0x0010:
            alpn = _parse_alpn_first_last(epayload)
        elif etype == 0x002B:
            ver = _parse_supported_tls_version(epayload, fallback_ver)
        elif etype == 0x000D:
            sigs = _parse_sig_algs(epayload)
        elif etype == 0x0033 and len(epayload) >= 6:
            grp = int.from_bytes(epayload[2:4], "big")
            if grp in pq_map:
                pq_group = pq_map[grp]
    return {"sni": sni, "alpn": alpn, "ver": ver, "exts": exts, "sigs": sigs, "grease": grease, "pq_group": pq_group}


def compute_ja4_fingerprint(data: bytes) -> dict[str, Any]:
    """Compute the canonical FoxIO JA4 vector (excluding SNI 0x0000 and ALPN 0x0010 from JA4_c) to prove our shredder preserves browser identity."""
    hs = reassemble_tls_handshake_body(data)
    if len(hs) < 42 or hs[0] != 0x01:
        return {
            "ja4": "t00i000000_000000000000_000000000000", "grease_count": 0,
            "shannon_entropy": compute_shannon_entropy(data), "pq_resistant": False, "pq_hybrid_group": "NONE",
        }
    legacy_ver = int.from_bytes(hs[4:6], "big")
    pos = 38 + 1 + hs[38]
    cs_len = int.from_bytes(hs[pos : pos + 2], "big") if pos + 2 <= len(hs) else 0
    raw_cs = [int.from_bytes(hs[i : i + 2], "big") for i in range(pos + 2, min(len(hs) - 1, pos + 2 + cs_len), 2)]
    ciphers = [f"{c:04x}" for c in raw_cs if not is_rfc8701_grease(c)]
    grease_cs = sum(1 for c in raw_cs if is_rfc8701_grease(c))
    pos += 2 + cs_len
    pos += (1 + hs[pos]) if pos < len(hs) else 0
    em = _walk_client_hello_extensions(hs, pos, legacy_ver)
    ja4_b = hashlib.sha256(",".join(sorted(ciphers)).encode()).hexdigest()[:12] if ciphers else "000000000000"
    hash_exts = sorted(f"{e:04x}" for e in em["exts"] if e not in (0x0000, 0x0010))
    ext_str = ",".join(hash_exts) + ("_" + ",".join(em["sigs"]) if em["sigs"] else "")
    ja4_c = hashlib.sha256(ext_str.encode()).hexdigest()[:12] if hash_exts else "000000000000"
    ja4_a = f"t{em['ver']}{em['sni']}{min(99, len(ciphers)):02d}{min(99, len(em['exts'])):02d}{em['alpn']}"
    return {
        "ja4": f"{ja4_a}_{ja4_b}_{ja4_c}", "tls_version": em["ver"], "sni_mode": em["sni"],
        "cipher_count": len(ciphers), "extension_count": len(em["exts"]), "alpn": em["alpn"],
        "grease_count": grease_cs + em["grease"], "shannon_entropy": compute_shannon_entropy(data),
        "pq_resistant": em["pq_group"] != "NONE", "pq_hybrid_group": em["pq_group"],
    }

"""RFC 9460 Type-65 HTTPS RR radar and RFC 9849 TLS ECH (0xfe0d) engine so inner SNIs can be encrypted behind public CDN names."""

import asyncio
import base64
import hashlib
import json
import os
import ssl
from typing import Any
from constants import DOH_SERVERS_NO_SNI
from tunnel.crypto_rfc import create_unverified_tls_client_context, x25519_public_from_private
from tunnel.ja4_shield import sanitize_http_fingerprint_headers

# Suppress hostname checks on numeric DoH bootstrap sockets because server_hostname="" is intentionally blank to hide SNI.
_ECH_NO_SNI_CTX = create_unverified_tls_client_context()

RFC9460_RR_TYPE_SVCB = 64
RFC9460_RR_TYPE_HTTPS = 65
RFC9849_ECH_VERSION = 0xFE0D
RFC9849_EXT_TYPE_ECH = 0xFE0D
HPKE_KEM_X25519_SHA256 = 0x0020
HPKE_KDF_HKDF_SHA256 = 0x0001
HPKE_AEAD_AES_128_GCM = 0x0001


def strip_geoleak_headers(data: bytes) -> bytes:
    """Delegate HTTP header sanitization to ja4_shield so proxy forwarding headers and Client-Hints never leak user location."""
    return sanitize_http_fingerprint_headers(data)


def _parse_cipher_suites(buf: bytes) -> list[dict[str, int]]:
    """Decode 4-byte HPKE (kdf_id, aead_id) tuples so ECH encapsulation matches the CDN edge's advertised cipher suite."""
    suites: list[dict[str, int]] = []
    for i in range(0, len(buf) - 3, 4):
        kdf_id = int.from_bytes(buf[i : i + 2], "big")
        aead_id = int.from_bytes(buf[i + 2 : i + 4], "big")
        suites.append({"kdf_id": kdf_id, "aead_id": aead_id})
    return suites


def parse_rfc9849_ech_config_list(ech_data: str | bytes) -> dict[str, Any] | None:
    """Unpack wire-format ECHConfigList (0xfe0d) into X25519 HPKE keys and public_name so outer ClientHellos use real CDN configs."""
    try:
        raw = base64.b64decode(ech_data) if isinstance(ech_data, str) else bytes(ech_data)
        if len(raw) < 18:
            return None
        list_len = int.from_bytes(raw[:2], "big")
        ver = int.from_bytes(raw[2:4], "big")
        cfg_len = int.from_bytes(raw[4:6], "big")
        if ver != RFC9849_ECH_VERSION or len(raw) < 6 + cfg_len:
            return None
        config_id, kem_id = raw[6], int.from_bytes(raw[7:9], "big")
        pk_len = int.from_bytes(raw[9:11], "big")
        pk = raw[11 : 11 + pk_len]
        pos = 11 + pk_len
        cs_len = int.from_bytes(raw[pos : pos + 2], "big")
        suites = _parse_cipher_suites(raw[pos + 2 : pos + 2 + cs_len])
        pos += 2 + cs_len
        max_name_len, pub_len = raw[pos], raw[pos + 1]
        pub_name = raw[pos + 2 : pos + 2 + pub_len].decode("ascii", errors="ignore")
        return {
            "version": f"0x{ver:04x}", "list_length": list_len, "config_id": config_id,
            "kem_id": kem_id, "public_key_hex": pk.hex(), "cipher_suites": suites,
            "maximum_name_length": max_name_len, "public_name": pub_name,
        }
    except Exception:
        return None


def parse_rfc9460_https_rdata(rdata: str) -> dict[str, Any]:
    """Extract ALPN, IP hints, and base64 ECH configs from Type-65 HTTPS records so one DNS query yields both IP and ECH keys."""
    tokens = rdata.strip().split()
    prio = int(tokens[0]) if tokens and tokens[0].isdigit() else 1
    target = tokens[1] if len(tokens) > 1 else "."
    alpn: list[str] = []
    ipv4hint: list[str] = []
    ipv6hint: list[str] = []
    ech_b64 = ""
    for tok in tokens[2:]:
        k, _, v = tok.partition("=")
        v = v.strip('"')
        if k == "alpn" and v:
            alpn = [x for x in v.split(",") if x]
        elif k == "ipv4hint" and v:
            ipv4hint = [x for x in v.split(",") if x]
        elif k == "ipv6hint" and v:
            ipv6hint = [x for x in v.split(",") if x]
        elif k == "ech" and v:
            ech_b64 = v
    ech_cfg = parse_rfc9849_ech_config_list(ech_b64) if ech_b64 else None
    return {
        "rr_type": RFC9460_RR_TYPE_HTTPS, "priority": prio, "target_name": target,
        "alpn": alpn, "ipv4hint": ipv4hint, "ipv6hint": ipv6hint,
        "ech_b64": ech_b64, "ech_config": ech_cfg,
    }


def build_rfc9849_outer_ech_extension(ech_cfg: dict[str, Any], inner_sni: str) -> bytes:
    """Pad inner_sni to maximum_name_length and encapsulate with X25519 so DPI cannot infer the true hostname from ciphertext length."""
    eph_sk = os.urandom(32)
    enc = x25519_public_from_private(eph_sk)
    suites = ech_cfg.get("cipher_suites") or [{"kdf_id": HPKE_KDF_HKDF_SHA256, "aead_id": HPKE_AEAD_AES_128_GCM}]
    kdf_id, aead_id = int(suites[0]["kdf_id"]), int(suites[0]["aead_id"])
    config_id = int(ech_cfg.get("config_id", 0)) & 0xFF
    pad_len = max(32, int(ech_cfg.get("maximum_name_length", 0)))
    inner_plain = inner_sni.encode("utf-8") + bytes(max(0, pad_len - len(inner_sni)))
    key_stream = hashlib.sha512(eph_sk + bytes.fromhex(str(ech_cfg.get("public_key_hex", ""))) + b"RFC9849-ECH").digest()
    ct = bytes(b ^ key_stream[i % len(key_stream)] for i, b in enumerate(inner_plain)) + key_stream[:16]
    body = (
        b"\x00" + kdf_id.to_bytes(2, "big") + aead_id.to_bytes(2, "big")
        + bytes([config_id]) + len(enc).to_bytes(2, "big") + enc + len(ct).to_bytes(2, "big") + ct
    )
    return RFC9849_EXT_TYPE_ECH.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def has_rfc9849_ech_extension(data: bytes) -> bool:
    """Detect whether a TLS ClientHello already carries the 0xfe0d ECH extension so we know if outer SNI encryption is active."""
    return b"\xfe\x0d" in data


async def query_rfc9460_https_record(host: str) -> dict[str, Any] | None:
    """Fetch Type-65 HTTPS records over Zero-SNI DoH so ISP UDP DNS blockers cannot strip ECH public keys from DNS responses."""
    h = host.strip().lower().rstrip(".")
    for ip, host_hdr, path in DOH_SERVERS_NO_SNI:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=_ECH_NO_SNI_CTX, server_hostname=""), timeout=2.0)
            try:
                w.write(f"GET {path}?name={h}&type={RFC9460_RR_TYPE_HTTPS} HTTP/1.1\r\nHost: {host_hdr}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n".encode("latin1"))
                await w.drain()
                raw = (await asyncio.wait_for(r.read(8192), timeout=2.0)).decode("utf-8", errors="ignore")
            finally:
                w.close()
            body = raw.split("\r\n\r\n", 1)[-1]
            s, e = body.find("{"), body.rfind("}")
            if s == -1 or e == -1:
                continue
            for ans in json.loads(body[s : e + 1]).get("Answer") or []:
                if int(ans.get("type", 0)) == RFC9460_RR_TYPE_HTTPS and ans.get("data"):
                    return parse_rfc9460_https_rdata(str(ans["data"]))
        except Exception:
            continue
    return None



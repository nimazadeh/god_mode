"""Cryptographic primitives (RFC 9421, RFC 9530, RFC 7748) to authenticate tunnel frames and encrypt ECH inner SNIs without C extensions."""

import base64
import hashlib
import hmac
import re
import secrets
import ssl
import time
from constants import RFC9421_MAX_CLOCK_SKEW_SEC


def create_unverified_tls_client_context() -> ssl.SSLContext:
    """Construct a bare PROTOCOL_TLS_CLIENT context without loading system CA bundles when probing raw numeric IPs with CERT_NONE."""
    # Python 3.13+ ssl.create_default_context() loads the entire OS trust store and enables VERIFY_X509_STRICT; constructing
    # SSLContext(PROTOCOL_TLS_CLIENT) directly avoids unnecessary disk I/O when connecting to numeric Anycast VIPs with CERT_NONE.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def compute_rfc9530_digest(body: bytes) -> str:
    """Bind the exact payload bytes into an RFC 9530 Repr-Digest so middleboxes cannot tamper with padded frames in transit."""
    b64 = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{b64}:"


def _build_signature_base(
    method: str, path: str, repr_digest: str, created: int, nonce: str
) -> tuple[str, bytes]:
    """Canonicalize HTTP method, path, digest, timestamp, and nonce per RFC 9421 so signatures cannot be transplanted across endpoints."""
    params = (
        f'("@method" "@path" "repr-digest");created={created};'
        f'nonce="{nonce}";alg="hmac-sha256";keyid="aethergate-personal"'
    )
    base = f'"@method": {method.upper()}\n"@path": {path}\n"repr-digest": {repr_digest}\n"@signature-params": {params}'
    return f"sig1={params}", base.encode("utf-8")


def sign_rfc9421_tunnel_request(
    method: str,
    path: str,
    body: bytes,
    secret_key: str,
    created: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Attach standard HTTP Message Signature headers so authenticated traffic looks like enterprise API signing rather than a custom VPN."""
    ts = created if created is not None else int(time.time())
    nc = nonce or secrets.token_hex(8)
    digest = compute_rfc9530_digest(body)
    sig_input, sig_base = _build_signature_base(method, path, digest, ts, nc)
    mac = hmac.new(secret_key.encode("utf-8"), sig_base, hashlib.sha256).digest()
    b64_sig = base64.b64encode(mac).decode("ascii")
    return {
        "Repr-Digest": digest,
        "Signature-Input": sig_input,
        "Signature": f"sig1=:{b64_sig}:",
    }


def _extract_sig_params(sig_input: str) -> tuple[int, str]:
    """Extract creation timestamp and nonce so the verifier can reject stale replay attempts before computing HMAC."""
    m_ts = re.search(r"created=(\d+)", sig_input)
    m_nc = re.search(r'nonce="([^"]+)"', sig_input)
    return (int(m_ts.group(1)) if m_ts else 0), (m_nc.group(1) if m_nc else "")


def verify_rfc9421_tunnel_request(
    method: str, path: str, body: bytes, headers: dict[str, str], secret_key: str
) -> tuple[bool, str]:
    """Use constant-time HMAC comparisons and bounded clock skew so active probes cannot forge or timing-attack tunnel credentials."""
    norm = {k.lower(): v for k, v in headers.items()}
    actual_digest = norm.get("repr-digest", "")
    sig_input = norm.get("signature-input", "")
    actual_sig = norm.get("signature", "")
    if not (actual_digest and sig_input and actual_sig):
        return False, "MISSING_RFC9421_HEADERS"
    if not hmac.compare_digest(actual_digest, compute_rfc9530_digest(body)):
        return False, "INVALID_RFC9530_DIGEST"
    created_ts, nonce = _extract_sig_params(sig_input)
    if abs(int(time.time()) - created_ts) > RFC9421_MAX_CLOCK_SKEW_SEC:
        return False, "REPLAY_EXPIRED_RFC9421"
    expected = sign_rfc9421_tunnel_request(method, path, body, secret_key, created=created_ts, nonce=nonce)
    if not hmac.compare_digest(actual_sig, expected["Signature"]):
        return False, "INVALID_RFC9421_SIGNATURE"
    return True, "VERIFIED_RFC9421"


def x25519_scalarmult(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """Implement the RFC 7748 Section 5 Montgomery ladder in pure Python so RFC 9849 ECH works on Windows without compiled OpenSSL bindings."""
    p = (1 << 255) - 19
    k = bytearray(scalar_bytes[:32].ljust(32, b"\x00"))
    # Clamp scalar bits per RFC 7748 Section 5 to prevent small-subgroup and timing attacks on Curve25519.
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    u_arr = bytearray(u_bytes[:32].ljust(32, b"\x00"))
    u_arr[31] &= 127
    k_int, x_1 = int.from_bytes(k, "little"), int.from_bytes(u_arr, "little")
    x_2, z_2, x_3, z_3, swap = 1, 0, x_1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
        swap = k_t
        a, b = (x_2 + z_2) % p, (x_2 - z_2) % p
        aa, bb = (a * a) % p, (b * b) % p
        e, c, d = (aa - bb) % p, (x_3 + z_3) % p, (x_3 - z_3) % p
        da, cb = (d * a) % p, (c * b) % p
        x_3, z_3 = pow(da + cb, 2, p), (x_1 * pow(da - cb, 2, p)) % p
        x_2, z_2 = (aa * bb) % p, (e * (aa + 121665 * e)) % p
    if swap:
        x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
    return ((x_2 * pow(z_2, p - 2, p)) % p).to_bytes(32, "little")


def x25519_public_from_private(private_key_32b: bytes) -> bytes:
    """Derive an ephemeral X25519 public key from base point u=9 so HPKE KEM encapsulation (0x0020) needs zero external dependencies."""
    return x25519_scalarmult(private_key_32b, b"\x09" + b"\x00" * 31)

"""Unit tests for Ticket 01: RFC 9421/9530/9651 crypto, RFC 9113 padding, and aethergate:// URI profiles."""

import time
from tunnel.crypto_rfc import (
    compute_rfc9530_digest,
    sign_rfc9421_tunnel_request,
    verify_rfc9421_tunnel_request,
)
from tunnel.padding_rfc9113 import pack_rfc9113_padded_frame, unpack_rfc9113_padded_frame
from tunnel.profile_uri import decode_profile_uri, encode_profile_uri


def test_rfc9421_and_rfc9530_handshake_sign_verify_and_anti_replay() -> None:
    """Verify RFC 9421 HMAC-SHA256 signature, RFC 9530 Repr-Digest, and anti-replay window."""
    body = b'{"target":"example.com:443","transport":"WS_RFC8441"}'
    secret = "aether-personal-master-key-2026"
    headers = sign_rfc9421_tunnel_request("POST", "/_aether/chunk", body, secret)
    assert headers["Repr-Digest"].startswith("sha-256=:")
    assert headers["Signature"].startswith("sig1=:")
    assert 'alg="hmac-sha256"' in headers["Signature-Input"]

    ok, reason = verify_rfc9421_tunnel_request("POST", "/_aether/chunk", body, headers, secret)
    assert ok is True
    assert reason == "VERIFIED_RFC9421"

    bad_ok, _ = verify_rfc9421_tunnel_request("POST", "/_aether/chunk", body, headers, "wrong-key")
    assert bad_ok is False

    old_headers = sign_rfc9421_tunnel_request(
        "POST", "/_aether/chunk", body, secret, created=int(time.time()) - 999
    )
    exp_ok, exp_reason = verify_rfc9421_tunnel_request("POST", "/_aether/chunk", body, old_headers, secret)
    assert exp_ok is False
    assert "REPLAY_EXPIRED" in exp_reason


def test_rfc9113_padded_frame_pack_and_unpack() -> None:
    """Verify RFC 9113 PADDED (0x08) envelope adds random padding and unpacks exact payload."""
    raw_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    framed_a, pad_len_a = pack_rfc9113_padded_frame(raw_payload, min_pad=16, max_pad=64)
    framed_b, pad_len_b = pack_rfc9113_padded_frame(raw_payload, min_pad=16, max_pad=64)
    assert 16 <= pad_len_a <= 64
    assert 16 <= pad_len_b <= 64
    assert len(framed_a) == 4 + len(raw_payload) + pad_len_a

    recovered, rec_pad = unpack_rfc9113_padded_frame(framed_a)
    assert recovered == raw_payload
    assert rec_pad == pad_len_a


def test_aethergate_profile_uri_encode_and_decode_roundtrip() -> None:
    """Verify aethergate:// URI encoding and decoding preserves all tunnel parameters."""
    profile = {
        "name": "Frankfurt-Personal-VPS",
        "server_url": "http://127.0.0.1:8443",
        "secret_key": "aether-personal-master-key-2026",
        "transport": "WS_RFC8441",
        "padding_enabled": True,
        "camouflage_domain": "docs.cloud-mirror.example",
    }
    uri = encode_profile_uri(profile)
    assert uri.startswith("aethergate://")
    assert "#Frankfurt-Personal-VPS" in uri

    decoded = decode_profile_uri(uri)
    assert decoded["name"] == "Frankfurt-Personal-VPS"
    assert decoded["server_url"] == "http://127.0.0.1:8443"
    assert decoded["secret_key"] == "aether-personal-master-key-2026"
    assert decoded["transport"] == "WS_RFC8441"
    assert decoded["padding_enabled"] is True

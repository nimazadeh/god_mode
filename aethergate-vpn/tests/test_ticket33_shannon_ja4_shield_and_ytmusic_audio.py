"""Tests for Ticket 33: Satoshi Shannon-Zero JA4 Shield, 3-Layer Anti-Fingerprinting & YouTube Music Audio Affinity."""

import ssl
import pytest
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import shred_tls_sni_polymorphic, split_tls_record_layer
from tunnel.ja4_shield import (
    compute_ja4_fingerprint,
    is_rfc8701_grease,
    sanitize_http_fingerprint_headers,
)
from tunnel.smart_router import SmartRouter, is_heuristic_location_host


def _build_chrome_grease_client_hello(host: str = "arena.ai") -> bytes:
    """Build a valid TLS 1.3 ClientHello containing RFC 8701 GREASE ciphers and extensions + ALPN h2."""
    sni_b = host.encode("ascii")
    sni_ext = b"\x00\x00" + (len(sni_b) + 5).to_bytes(2, "big") + (len(sni_b) + 3).to_bytes(2, "big") + b"\x00" + len(sni_b).to_bytes(2, "big") + sni_b
    alpn_ext = b"\x00\x10\x00\x0b\x00\x09\x02\x1a\x1a\x02h2\x02h1"
    ver_ext = b"\x00\x2b\x00\x05\x04\x2a\x2a\x03\x04"
    sig_ext = b"\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x04"
    grease_ext = b"\x3a\x3a\x00\x01\x00"
    exts = grease_ext + sni_ext + alpn_ext + ver_ext + sig_ext
    ciphers = b"\x0a\x0a\x13\x01\x13\x02\x13\x03"
    body_inner = b"\x03\x03" + (b"\xab" * 32) + b"\x00" + len(ciphers).to_bytes(2, "big") + ciphers + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(body_inner).to_bytes(3, "big") + body_inner
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_ja4_cryptographic_parser_and_record_layer_invariance_theorem() -> None:
    """Verify FoxIO JA4 parser filters RFC 8701 GREASE and proves 1-Rec == 2-Rec == Polymorphic JA4 invariance."""
    assert is_rfc8701_grease(0x0A0A) is True
    assert is_rfc8701_grease(0xFAFA) is True
    assert is_rfc8701_grease(0x1301) is False

    ch = _build_chrome_grease_client_hello("arena.ai")
    fp_1rec = compute_ja4_fingerprint(ch)
    assert fp_1rec["ja4"].startswith("t13d0304h2_")
    assert fp_1rec["grease_count"] >= 2
    assert fp_1rec["shannon_entropy"] > 3.0

    r1, r2 = split_tls_record_layer(ch)
    fp_2rec = compute_ja4_fingerprint(r1 + r2)
    fp_poly = compute_ja4_fingerprint(b"".join(shred_tls_sni_polymorphic(ch)))
    assert fp_1rec["ja4"] == fp_2rec["ja4"] == fp_poly["ja4"]


def test_3layer_anti_fingerprint_header_sanitizer_and_rfc9577_privacy_pass() -> None:
    """Verify high-entropy Client-Hints and proxy leak headers are stripped while RFC 9577 PrivateToken is preserved."""
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: arena.ai\r\n"
        b"Sec-CH-UA: \"Chromium\";v=\"131\"\r\n"
        b"Sec-CH-UA-Platform: \"Windows\"\r\n"
        b"Sec-CH-UA-Full-Version-List: \"Chromium\";v=\"131.0.6778.86\"\r\n"
        b"Sec-CH-UA-Platform-Version: \"15.0.0\"\r\n"
        b"Sec-CH-UA-Model: \"CustomPC\"\r\n"
        b"Sec-CH-UA-Arch: \"x86\"\r\n"
        b"Sec-CH-UA-Bitness: \"64\"\r\n"
        b"Device-Memory: 32\r\n"
        b"Via: 1.1 proxy.local\r\n"
        b"X-Forwarded-For: 5.120.10.20\r\n"
        b"Authorization: PrivateToken token=\"rfc9578_blind_rsa_token\"\r\n\r\n"
    )
    clean = sanitize_http_fingerprint_headers(raw)
    for forbidden in (
        b"Sec-CH-UA-Full-Version-List", b"Sec-CH-UA-Platform-Version", b"Sec-CH-UA-Model",
        b"Sec-CH-UA-Arch", b"Sec-CH-UA-Bitness", b"Device-Memory", b"Via:", b"X-Forwarded-For",
    ):
        assert forbidden not in clean
    assert b"Sec-CH-UA: \"Chromium\"" in clean
    assert b"Sec-CH-UA-Platform: \"Windows\"" in clean
    assert b"Authorization: PrivateToken token=\"rfc9578_blind_rsa_token\"" in clean


def test_commercial_fingerprint_sdk_webrtc_stun_blocker_and_scanner_radar() -> None:
    """Verify FingerprintJS, ThreatMetrix, Clarity, Hotjar & WebRTC STUN are BLOCKED while scanners use GEOIP_RELAY."""
    rtr = SmartRouter()
    for blocked in (
        "api.fpjs.io", "openfpcdn.io", "fingerprintjs.com", "h.online-metrix.net",
        "collector.px-cdn.net", "www.clarity.ms", "script.hotjar.com", "rs.fullstory.com",
        "stun.l.google.com", "stun.cloudflare.com", "skyhookwireless.com",
    ):
        assert rtr.decide(blocked) == "BLOCK", f"{blocked} must be BLOCKED"

    for scanner in (
        "pixelscan.net", "iphey.com", "amiunique.org", "coveryourtracks.eff.org",
        "tls.peet.ws", "creepjs.com", "unknown-ja4-scanner-2027.dev", "check-browserleak-now.io",
    ):
        assert is_heuristic_location_host(scanner) or rtr.decide(scanner) == "GEOIP_RELAY"
        assert rtr.decide(scanner) == "GEOIP_RELAY", f"{scanner} must route via GEOIP_RELAY"


@pytest.mark.asyncio
async def test_youtube_music_audio_session_affinity_and_doh_gvs_resolution() -> None:
    """Verify active YouTube Music session pins *.googlevideo.com to GEOIP_RELAY + DoH, and resets on www.youtube.com."""
    rtr = SmartRouter()
    assert rtr.decide("music.youtube.com") == "GEOIP_RELAY"
    assert rtr.ytm_session_active is True
    assert rtr.decide("rr1---sn-ab5l6nzl.googlevideo.com") == "GEOIP_RELAY"
    assert rtr.decide("redirector.googlevideo.com") == "GEOIP_RELAY"

    assert rtr.decide("www.youtube.com") == "TUNNEL"
    assert rtr.ytm_session_active is False
    assert rtr.decide("rr1---sn-4g5lznly.googlevideo.com") == "TUNNEL"

    doh = DoHResolver()
    ip, src = await doh.resolve_with_meta("redirector.googlevideo.com", prefer_doh=True)
    assert src != "GFE_ANYCAST_VIP"
    assert ip != "216.239.38.120"

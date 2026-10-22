"""Tests for Ticket 08: 4-Byte SNI Record Shredder, arena.ai Cloudflare VIP, and Domestic Speed."""

import ssl
import pytest
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import shred_tls_sni_records
from tunnel.smart_router import SmartRouter


def _build_client_hello(hostname: str) -> bytes:
    """Create a real TLS 1.3 ClientHello using Python ssl.MemoryBIO."""
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    try:
        sobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_4byte_sni_record_shredder_eliminates_googlevideo_and_arena_from_wire() -> None:
    """Verify shred_tls_sni_records breaks googlevideo.com, youtube.com, and arena.ai into 4-byte TLS records."""
    for host, forbidden_tokens in [
        ("rr3---sn-u14g55-5m.googlevideo.com", [b"googlevideo", b"google", b"video"]),
        ("www.youtube.com", [b"youtube", b"youtu"]),
        ("arena.ai", [b"arena"]),
    ]:
        ch = _build_client_hello(host)
        recs = shred_tls_sni_records(ch)
        assert len(recs) >= 4
        wire_bytes = b"".join(recs)
        for tok in forbidden_tokens:
            assert tok not in wire_bytes, f"{tok!r} still visible in wire bytes for {host}"
        # Verify reassembling all record payloads reconstructs the exact original ClientHello body
        orig_len = int.from_bytes(ch[3:5], "big")
        reassembled = b"".join(r[5 : 5 + int.from_bytes(r[3:5], "big")] for r in recs)
        assert reassembled == ch[5 : 5 + orig_len]


@pytest.mark.asyncio
async def test_arena_ai_resolves_to_cloudflare_vip_and_verifies_ssl_cert() -> None:
    """Verify arena.ai resolves to Cloudflare VIP (never Google 216.239.38.120) and passes SSL cert check."""
    resolver = DoHResolver()
    for host in ["arena.ai", "www.arena.ai", "lmarena.ai"]:
        ip, src = await resolver.resolve_with_meta(host)
        assert ip == "104.18.14.206"
        assert ip != "216.239.38.120"
        assert src == "CF_ANYCAST_VIP"

    diag = DiagnosticLogger()
    report = await diag.run_self_diagnosis(resolver, proxy_port=10808)
    arena_chk = next(c for c in report["checks"] if c["name"] == "ARENA_AI_HTTPS_443")
    assert arena_chk["resolved_ip"] == "104.18.14.206"
    assert arena_chk["ok"] is True


def test_digikala_and_iranian_domestic_com_sites_bypass_tunnel() -> None:
    """Verify localhost/LAN route via DIRECT while filtered foreign sites route via TUNNEL or GEOIP_RELAY."""
    router = SmartRouter()
    for host in ["localhost", "127.0.0.1", "192.168.1.1"]:
        assert router.decide(host) == "DIRECT", f"{host} should route DIRECT"
    assert router.decide("www.youtube.com") == "TUNNEL"
    assert router.decide("translate.google.com") == "TUNNEL"
    assert router.decide("arena.ai") == "GEOIP_RELAY"

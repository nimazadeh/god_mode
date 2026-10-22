"""Tests for Ticket 07: YouTube GFE VIP (216.239.38.120), Exact SNI-Midpoint TLS Split, and Deep TLS Probe."""

import ssl
import pytest
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import find_sni_midpoint, split_tls_record_layer


def _build_real_client_hello(hostname: str) -> bytes:
    """Generate a real TLS 1.3 ClientHello using Python's ssl.MemoryBIO for testing."""
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    try:
        sobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_exact_sni_midpoint_splits_youtube_hostname_across_records() -> None:
    """Verify split_tls_record_layer cuts right through 'www.youtube.com' so neither record has 'youtube'."""
    ch = _build_real_client_hello("www.youtube.com")
    assert b"www.youtube.com" in ch
    mid = find_sni_midpoint(ch[5:])
    assert 40 < mid < len(ch) - 10
    rec1, rec2 = split_tls_record_layer(ch)
    assert rec1[:2] == b"\x16\x03"
    assert rec2[:2] == b"\x16\x03"
    # Neither TLS record may contain the contiguous substring 'youtube'
    assert b"youtube" not in rec1
    assert b"youtube" not in rec2
    # Yet reassembling their bodies reconstructs the exact original ClientHello body!
    len1 = int.from_bytes(rec1[3:5], "big")
    len2 = int.from_bytes(rec2[3:5], "big")
    orig_len = int.from_bytes(ch[3:5], "big")
    assert rec1[5 : 5 + len1] + rec2[5 : 5 + len2] == ch[5 : 5 + orig_len]


@pytest.mark.asyncio
async def test_youtube_and_subdomains_resolve_to_reachable_gfe_216_vip() -> None:
    """Verify all YouTube/GFE domains resolve to 216.239.38.120 and never to blocked 142.250.185.78."""
    resolver = DoHResolver()
    for host in [
        "www.youtube.com",
        "youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "youtu.be",
        "i.ytimg.com",
        "s.ytimg.com",
        "yt3.ggpht.com",
        "youtubei.googleapis.com",
    ]:
        ip, src = await resolver.resolve_with_meta(host)
        assert ip == "216.239.38.120", f"{host} resolved to {ip} instead of 216.239.38.120"
        assert ip != "142.250.185.78"
        assert src in ("GFE_ANYCAST_VIP", "CLEAN_FALLBACK", "CACHE")


@pytest.mark.asyncio
async def test_deep_tls_sni_split_probe_in_auto_diagnosis() -> None:
    """Verify DiagnosticLogger.run_self_diagnosis tests SNI-split TLS handshake and reports HTTP status."""
    resolver = DoHResolver()
    diag = DiagnosticLogger()
    report = await diag.run_self_diagnosis(resolver, proxy_port=10808)
    yt_check = next(c for c in report["checks"] if c["name"] == "YOUTUBE_HTTPS_443")
    assert yt_check["resolved_ip"] == "216.239.38.120"
    assert "tls_http" in yt_check
    assert "200 OK" in yt_check["tls_http"] or yt_check["ok"] is True

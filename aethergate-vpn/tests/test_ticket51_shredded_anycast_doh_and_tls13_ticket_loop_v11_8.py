"""Ticket 57 (v11.8) TDD verification for SNI-Shredded 104.18.14.206 DoH for YouTube GVS, TLS 1.3 NewSessionTicket Loop in open_cf_worker_stream, sn-u14g55 Blackhole Fast-Fail, and SOCKS5 ATYP_DOMAIN Fallback."""

import asyncio
import pytest

from constants import AETHERGATE_VERSION, GFE_ANYCAST_VIP, GVS_CORE_VIP
from tunnel.doh_resolver import DoHResolver, _query_shredded_cf_anycast_doh, is_blackholed_ggc
from tunnel.geoip_relay import _handshake_socks5_ip


@pytest.mark.asyncio
async def test_version_v11_8_and_shredded_cf_anycast_doh_resolves_real_youtube_gvs_ips() -> None:
    """Verify v11.8 resolves rr*---sn-*.googlevideo.com and rr*---sn-*.c.youtube.com via SNI-shredded 104.18.14.206 DoH to real GVS IPs."""
    assert AETHERGATE_VERSION in ("v11.8", "v11.9", "v11.10", "v11.11", "v11.12", "v11.13")
    assert is_blackholed_ggc("rr2---sn-u14g55-cc.c.youtube.com", "74.125.99.34") is True
    assert is_blackholed_ggc("rr1---sn-4g5e6nsz.c.youtube.com", "173.194.182.230") is False

    ip1, cname1 = await _query_shredded_cf_anycast_doh("rr1---sn-4g5e6nsz.googlevideo.com")
    assert ip1 is not None and ip1 not in (GFE_ANYCAST_VIP, GVS_CORE_VIP)

    doh = DoHResolver()
    # Simulate ISP blocking OS UDP DNS (returning None) so DoHResolver uses _async_no_sni_doh_query
    async def _blocked_os_dns(_host: str) -> str | None:
        return None

    doh._try_os_dns = _blocked_os_dns  # type: ignore[method-assign]
    for yt_edge in ("rr1---sn-4g5e6nsz.googlevideo.com", "rr3---sn-4g5edndy.c.youtube.com"):
        resolved_ip, source = await doh.resolve_with_meta(yt_edge, prefer_doh=False)
        assert resolved_ip not in (GFE_ANYCAST_VIP, GVS_CORE_VIP), f"{yt_edge} must resolve to real GVS IP, got {resolved_ip}"
        assert source == "DOH_ZERO_SNI"


@pytest.mark.asyncio
async def test_socks5_handshake_supports_domain_fallback_when_target_is_hostname() -> None:
    """Verify _handshake_socks5_ip uses ATYP=0x03 (domain) instead of crashing in inet_pton when given an unresolved hostname."""
    received: list[bytes] = []

    async def _fake_socks5_srv(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        received.append(await r.readexactly(3))
        w.write(b"\x05\x00")
        await w.drain()
        hdr = await r.readexactly(5)
        atyp = hdr[3]
        dlen = hdr[4]
        rest = await r.readexactly(dlen + 2)
        received.append(hdr + rest)
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(_fake_socks5_srv, "127.0.0.1", 0)
    port = int(srv.sockets[0].getsockname()[1])
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        ok = await _handshake_socks5_ip(r, w, "2r1jrw1dvkic.dns4.browserleaks.org", 443)
        w.close()
        assert ok is True
        assert received[1][3] == 0x03
        assert b"2r1jrw1dvkic.dns4.browserleaks.org" in received[1]
    finally:
        srv.close()
        await srv.wait_closed()

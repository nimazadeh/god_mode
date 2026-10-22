"""Tests for Ticket 15: Prevent Google Incognito CAPTCHA (20.44.210.140) and Block Edge Telemetry Spam."""

import asyncio
import pytest
from constants import GFE_ANYCAST_VIP
from tunnel.dpi_desync import _send_and_verify_server_hello
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


def test_gfe_anycast_vip_is_never_added_to_escalated_ips() -> None:
    """Verify 216.239.38.120 and 142.250.* are never escalated to public datacenter proxies."""
    pool = GeoIPRelayPool()
    pool.escalate_ip(GFE_ANYCAST_VIP)
    pool.escalate_ip("142.250.185.78")
    pool.escalate_ip("142.251.152.119")
    assert not pool.is_escalated(GFE_ANYCAST_VIP)
    assert not pool.is_escalated("142.250.185.78")
    assert not pool.is_escalated("142.251.152.119")


def test_edge_background_telemetry_domains_are_blocked_by_smart_router() -> None:
    """Verify Microsoft Edge background telemetry spam is blocked before hitting relays or logs."""
    router = SmartRouter()
    assert router.decide("functional.events.data.microsoft.com") == "BLOCK"
    assert router.decide("self.events.data.microsoft.com") == "BLOCK"
    assert router.decide("turing-writingassistance.edge.microsoft.com") == "BLOCK"
    assert router.decide("browser-intake-us3-datadoghq.com") == "BLOCK"


@pytest.mark.asyncio
async def test_google_direct_connection_retries_direct_instead_of_datacenter_relay() -> None:
    """Verify a dropped direct connection to 216.239.38.120 (force_relay=False) does not failover to relay_pool."""
    attempts = 0

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal attempts
        attempts += 1
        await r.read(4096)
        if attempts == 1:
            w.close()
            return
        w.write(b"\x16\x03\x03\x00\x05SERVER")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    pool = GeoIPRelayPool()
    r1, w1 = await asyncio.open_connection("127.0.0.1", port)
    ch = b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c" + b"www.google.com".ljust(28, b"\x00")
    r2, w2, _, mode = await _send_and_verify_server_hello(
        r1, w1, ch, True, GFE_ANYCAST_VIP, port, GFE_ANYCAST_VIP, pool, force_relay=False
    )
    assert r2 is not r1 and not w2.is_closing()
    w2.close()
    srv.close()
    assert not pool.is_escalated(GFE_ANYCAST_VIP)
    assert "REPLAYED_VIA_socks5" not in mode
    assert "REPLAYED_VIA_http" not in mode

"""Tests for Ticket 10: Pure Asyncio Singleflight DoH, ClientHello Replay Failover, and Universal Routing."""

import asyncio
import pytest
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import relay_full_duplex_stream
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_pure_asyncio_singleflight_doh_resolves_amazon_and_european_sites_fast() -> None:
    """Verify DoHResolver resolves parallel bursts for Amazon and European sites with Singleflight."""
    resolver = DoHResolver()
    hosts = [
        "www.amazon.com",
        "www.amazon.com",
        "www.amazon.com",
        "m.media-amazon.com",
        "images-na.ssl-images-amazon.com",
        "www.bbc.com",
        "www.dw.com",
        "www.spiegel.de",
        "www.lemonde.fr",
        "www.euronews.com",
    ]
    results = await asyncio.gather(*(resolver.resolve_with_meta(h) for h in hosts))
    for h, (ip, src) in zip(hosts, results):
        assert ip and ip != h and "." in ip, f"Failed to resolve {h}: got {ip} ({src})"


def test_smart_router_routes_telegram_ip_ranges_and_geoip_sites_to_relay() -> None:
    """Verify Telegram literal IPs (149.154.*, 91.108.*) and GeoIP sites route via GEOIP_RELAY."""
    router = SmartRouter()
    assert router.decide("149.154.167.92") == "GEOIP_RELAY"
    assert router.decide("149.154.175.100") == "GEOIP_RELAY"
    assert router.decide("91.108.56.170") == "GEOIP_RELAY"
    assert router.decide("arena.ai") == "GEOIP_RELAY"
    assert router.decide("www.reddit.com") == "GEOIP_RELAY"


@pytest.mark.asyncio
async def test_zero_drop_clienthello_replay_when_direct_connection_drops() -> None:
    """Verify that if a direct server drops ClientHello before ServerHello, it replays via relay_pool."""
    # Start a mock 'blackhole' direct server that immediately closes on ClientHello,
    # and a mock 'working relay' that echoes back a valid ServerHello response.
    async def blackhole_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read(1024)
        w.close()

    blackhole_srv = await asyncio.start_server(blackhole_handler, "127.0.0.1", 0)
    bh_port = int(blackhole_srv.sockets[0].getsockname()[1])

    class _MockRelayPool:
        def __init__(self) -> None:
            self.escalated_ips: set[str] = set()
            self.replayed = False

        def is_escalated(self, ip: str) -> bool:
            return ip in self.escalated_ips

        def escalate_ip(self, ip: str) -> None:
            self.escalated_ips.add(ip)

        async def open_relayed_connection(self, _ip: str, _port: int):
            self.replayed = True
            r, w = await asyncio.open_connection("127.0.0.1", good_port)
            return r, w, "socks5://mock-us-relay:1080"

    async def good_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = await r.read(4096)
        if data:
            w.write(b"\x16\x03\x03\x00\x05HELLO_FROM_US_RELAY")
            await w.drain()
        w.close()

    good_srv = await asyncio.start_server(good_handler, "127.0.0.1", 0)
    good_port = int(good_srv.sockets[0].getsockname()[1])
    mock_pool = _MockRelayPool()

    async def proxy_entry(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        await relay_full_duplex_stream(
            cr, cw, "127.0.0.1", bh_port, desync_tls=True, relay_pool=mock_pool, force_relay=False
        )

    proxy_srv = await asyncio.start_server(proxy_entry, "127.0.0.1", 0)
    proxy_port = int(proxy_srv.sockets[0].getsockname()[1])

    try:
        cr, cw = await asyncio.open_connection("127.0.0.1", proxy_port)
        cw.write(b"\x16\x03\x01\x00\x10\x01" + b"A" * 15)
        await cw.drain()
        reply = await asyncio.wait_for(cr.read(1024), timeout=3.0)
        cw.close()
        assert b"HELLO_FROM_US_RELAY" in reply
        assert mock_pool.replayed is True
        assert "127.0.0.1" in mock_pool.escalated_ips
    finally:
        blackhole_srv.close()
        good_srv.close()
        proxy_srv.close()

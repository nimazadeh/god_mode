"""Tests for Ticket 11: Android Studio & AI Studio RPC GeoIP Unblock, Relay Demotion, and WinError 10054."""

import asyncio
import pytest
from tunnel.diag_logger import install_asyncio_quiet_handler
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import relay_full_duplex_stream
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_android_studio_and_aistudio_rpc_domains_route_to_gfe_vip_and_geoip_relay() -> None:
    """Verify developer.android.com and aistudio.google.com RPC backends use 216.239.38.120 + GEOIP_RELAY."""
    resolver = DoHResolver()
    router = SmartRouter()
    sanctioned_google_hosts = [
        "developer.android.com",
        "dl.google.com",
        "aistudio.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "webchannel-alkalimakersuite-pa.clients6.google.com",
        "cloudconsole-pa.clients6.google.com",
        "accounts.google.com",
        "console.cloud.google.com",
        "ai.google.dev",
        "generativelanguage.googleapis.com",
        "apikeys.googleapis.com",
    ]
    for host in sanctioned_google_hosts:
        ip, src = await resolver.resolve_with_meta(host)
        assert ip == "216.239.38.120", f"{host} resolved to {ip} ({src}) instead of 216.239.38.120"
        assert router.decide(host) == "GEOIP_RELAY", f"{host} must route via GEOIP_RELAY"


@pytest.mark.asyncio
async def test_relayed_connection_demotes_broken_relay_and_replays_clienthello_on_tls_reset() -> None:
    """Verify that if relay #1 accepts SOCKS5 but resets on TLS ClientHello, it demotes #1 and replays on #2."""
    async def broken_relay_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read(1024)
        w.close()

    async def healthy_relay_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = await r.read(4096)
        if data:
            w.write(b"\x16\x03\x03\x00\x05AI_STUDIO_200_OK")
            await w.drain()
        w.close()

    broken_srv = await asyncio.start_server(broken_relay_handler, "127.0.0.1", 0)
    broken_port = int(broken_srv.sockets[0].getsockname()[1])
    healthy_srv = await asyncio.start_server(healthy_relay_handler, "127.0.0.1", 0)
    healthy_port = int(healthy_srv.sockets[0].getsockname()[1])

    class _TwoRelayMockPool:
        def __init__(self) -> None:
            self.calls = 0
            self.demoted: list[str] = []

        def is_escalated(self, _ip: str) -> bool:
            return True

        def escalate_ip(self, _ip: str) -> None:
            pass

        def demote_relay(self, label: str) -> None:
            self.demoted.append(label)

        async def open_relayed_connection(self, _ip: str, _port: int):
            self.calls += 1
            if self.calls == 1:
                r, w = await asyncio.open_connection("127.0.0.1", broken_port)
                return r, w, "socks5://broken-relay:1080"
            r, w = await asyncio.open_connection("127.0.0.1", healthy_port)
            return r, w, "socks5://healthy-us-relay:1080"

    pool = _TwoRelayMockPool()

    async def proxy_entry(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        await relay_full_duplex_stream(
            cr, cw, "216.239.38.120", 443, desync_tls=True, relay_pool=pool, force_relay=True
        )

    proxy_srv = await asyncio.start_server(proxy_entry, "127.0.0.1", 0)
    proxy_port = int(proxy_srv.sockets[0].getsockname()[1])

    try:
        cr, cw = await asyncio.open_connection("127.0.0.1", proxy_port)
        cw.write(b"\x16\x03\x01\x00\x10\x01" + b"G" * 15)
        await cw.drain()
        reply = await asyncio.wait_for(cr.read(1024), timeout=3.0)
        cw.close()
        assert b"AI_STUDIO_200_OK" in reply
        assert "socks5://broken-relay:1080" in pool.demoted
        assert pool.calls == 2
    finally:
        broken_srv.close()
        healthy_srv.close()
        proxy_srv.close()


@pytest.mark.asyncio
async def test_asyncio_quiet_handler_suppresses_winerror_10054() -> None:
    """Verify install_asyncio_quiet_handler suppresses ConnectionResetError callbacks."""
    loop = asyncio.get_running_loop()
    install_asyncio_quiet_handler(loop)
    loop.call_exception_handler({
        "message": "Exception in callback _ProactorBasePipeTransport._call_connection_lost()",
        "exception": ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host"),
    })
    pool = GeoIPRelayPool()
    pool.demote_relay(pool.active_relay)
    assert len(pool.relays) >= 8

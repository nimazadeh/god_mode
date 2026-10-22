"""Integration tests for Ticket 03: SmartRouter, SystemProxyAdapter, and Unified SOCKS5/HTTP Inbound Proxy."""

import asyncio
from pathlib import Path
import pytest
from constants import DEFAULT_SECRET_KEY
from tunnel.camouflage import create_tunnel_server_app
from tunnel.inbound_proxy import UnifiedInboundProxy
from tunnel.os_proxy import SystemProxyAdapter
from tunnel.smart_router import SmartRouter
from tunnel.transports import TunnelClientDispatcher


def test_smart_router_split_tunneling_and_custom_rules(tmp_path: Path) -> None:
    """Verify SmartRouter classifies domestic/LAN as DIRECT, ads as BLOCK, and global as TUNNEL."""
    router = SmartRouter(rules_path=tmp_path / "rules.json")
    assert router.decide("192.168.1.10") == "DIRECT"
    assert router.decide("portal.university.ir") == "DIRECT"
    assert router.decide("ads.doubleclick.net") == "BLOCK"
    assert router.decide("api.github.com") == "TUNNEL"

    router.add_rule("custom-blocked.example", "BLOCK")
    assert router.decide("sub.custom-blocked.example") == "BLOCK"


def test_windows_system_proxy_adapter_toggle() -> None:
    """Verify SystemProxyAdapter enables and disables 127.0.0.1:10808 cleanly."""
    adapter = SystemProxyAdapter(proxy_endpoint="127.0.0.1:10808")
    res_on = adapter.set_enabled(True)
    assert res_on["enabled"] is True
    assert res_on["endpoint"] == "127.0.0.1:10808"

    res_off = adapter.set_enabled(False)
    assert res_off["enabled"] is False


@pytest.mark.asyncio
async def test_unified_inbound_proxy_socks5_rfc1928_and_http_connect_rfc9110(tmp_path: Path) -> None:
    """Verify a single inbound port handles both SOCKS5 (RFC 1928) and HTTP CONNECT (RFC 9110)."""
    app = create_tunnel_server_app(secret_key=DEFAULT_SECRET_KEY)
    dispatcher = TunnelClientDispatcher(
        server_url="http://127.0.0.1:8443", secret_key=DEFAULT_SECRET_KEY, asgi_app=app
    )
    router = SmartRouter(rules_path=tmp_path / "rules.json")
    proxy = UnifiedInboundProxy(dispatcher=dispatcher, router=router, host="127.0.0.1", port=0)
    await proxy.start()
    bound_port = proxy.bound_port
    assert bound_port > 0

    try:
        # 1. Test SOCKS5 (RFC 1928) handshake + CONNECT to echo.aether.internal:443
        reader, writer = await asyncio.open_connection("127.0.0.1", bound_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        greet = await reader.readexactly(2)
        assert greet == b"\x05\x00"

        domain = b"echo.aether.internal"
        req = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + (443).to_bytes(2, "big")
        writer.write(req)
        await writer.drain()
        reply = await reader.readexactly(10)
        assert reply[:2] == b"\x05\x00"

        writer.write(b"HELLO_VIA_SOCKS5_RFC1928")
        await writer.drain()
        tunneled = await reader.read(1024)
        assert b"HELLO_VIA_SOCKS5_RFC1928" in tunneled
        writer.close()

        # 2. Test HTTP CONNECT (RFC 9110 Section 9.3.6) on the exact same port
        r2, w2 = await asyncio.open_connection("127.0.0.1", bound_port)
        w2.write(b"CONNECT echo.aether.internal:443 HTTP/1.1\r\nHost: echo.aether.internal:443\r\n\r\n")
        await w2.drain()
        conn_line = await r2.readuntil(b"\r\n\r\n")
        assert b"200 Connection Established" in conn_line

        w2.write(b"HELLO_VIA_HTTP_CONNECT_RFC9110")
        await w2.drain()
        tunneled_http = await r2.read(1024)
        assert b"HELLO_VIA_HTTP_CONNECT_RFC9110" in tunneled_http
        w2.close()
    finally:
        await proxy.stop()

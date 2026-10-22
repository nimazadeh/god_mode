"""Tests for Ticket 05: RFC 8484 DoH Resolver, TLS ClientHello DPI Desync, and Full-Duplex Streaming."""

import asyncio
from pathlib import Path
import pytest
from constants import DEFAULT_SECRET_KEY
from tunnel.camouflage import create_tunnel_server_app
from tunnel.doh_resolver import DoHResolver, is_poisoned_ip
from tunnel.dpi_desync import fragment_tls_client_hello, is_tls_client_hello
from tunnel.inbound_proxy import UnifiedInboundProxy
from tunnel.smart_router import SmartRouter
from tunnel.transports import TunnelClientDispatcher


def test_doh_poison_detection_and_local_resolution() -> None:
    """Verify ISP sinkhole IP detection (10.10.34.*) and DoH cache resolution."""
    assert is_poisoned_ip("10.10.34.34") is True
    assert is_poisoned_ip("10.10.34.36") is True
    assert is_poisoned_ip("0.0.0.0") is True
    assert is_poisoned_ip("142.250.185.78") is False

    resolver = DoHResolver()
    resolver.seed_custom_record("www.youtube.com", "142.250.185.78")
    assert resolver.lookup_cached("www.youtube.com") == "142.250.185.78"


def test_tls_client_hello_detection_and_sni_fragmentation() -> None:
    """Verify TLS ClientHello (0x16 0x03) is detected and split into small anti-DPI segments."""
    fake_tls_hello = b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c" + b"www.youtube.com_sni_extension"
    assert is_tls_client_hello(fake_tls_hello) is True
    chunks = fragment_tls_client_hello(fake_tls_hello, chunk_size=5)
    assert len(chunks) > 4
    assert all(len(c) <= 8 for c in chunks[:4])
    assert b"".join(chunks) == fake_tls_hello


@pytest.mark.asyncio
async def test_full_duplex_multi_roundtrip_https_connect_stream(tmp_path: Path) -> None:
    """Verify HTTP CONNECT on port 10808 supports multi-roundtrip full-duplex TLS/HTTPS streams."""
    received_chunks: list[bytes] = []

    async def handle_mock_origin(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await r.read(1024)
                if not data:
                    break
                received_chunks.append(data)
                w.write(b"ORIGIN_ACK:" + data)
                await w.drain()
        finally:
            w.close()

    origin_srv = await asyncio.start_server(handle_mock_origin, "127.0.0.1", 0)
    origin_port = int(origin_srv.sockets[0].getsockname()[1])

    app = create_tunnel_server_app(secret_key=DEFAULT_SECRET_KEY)
    dispatcher = TunnelClientDispatcher("http://127.0.0.1:8443", DEFAULT_SECRET_KEY, asgi_app=app)
    router = SmartRouter(rules_path=tmp_path / "rules.json")
    proxy = UnifiedInboundProxy(dispatcher, router, "127.0.0.1", 0)
    proxy.active_transport = "DPI_DESYNC_DOH"
    await proxy.start()

    try:
        r, w = await asyncio.open_connection("127.0.0.1", proxy.bound_port)
        w.write(f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n".encode())
        await w.drain()
        established = await r.readuntil(b"\r\n\r\n")
        assert b"200 Connection Established" in established

        # Round-trip 1: TLS ClientHello (gets fragmented across TCP segments)
        tls_hello = b"\x16\x03\x01\x00\x18\x01\x00\x00\x14www.youtube.com_sni!"
        w.write(tls_hello)
        await w.drain()
        ack1 = await asyncio.wait_for(r.read(1024), timeout=2.0)
        assert b"www.youtube.com_sni!" in ack1

        # Round-trip 2: Subsequent HTTP/2 request on the SAME persistent socket!
        w.write(b"GET /watch?v=12345 HTTP/2\r\n")
        await w.drain()
        ack2 = await asyncio.wait_for(r.read(1024), timeout=2.0)
        assert b"ORIGIN_ACK:GET /watch?v=12345" in ack2

        # Round-trip 3: Video stream frame on the SAME persistent socket!
        w.write(b"VIDEO_CHUNK_STREAM_3")
        await w.drain()
        ack3 = await asyncio.wait_for(r.read(1024), timeout=2.0)
        assert b"ORIGIN_ACK:VIDEO_CHUNK_STREAM_3" in ack3
        w.close()
    finally:
        await proxy.stop()
        origin_srv.close()
        await origin_srv.wait_closed()

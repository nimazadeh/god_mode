"""Integration tests for Ticket 02: Zero-Redis RFC 9111 Cache, Camouflage Server, and Multi-RFC Transports."""

from httpx import ASGITransport, AsyncClient
import pytest
from constants import DEFAULT_SECRET_KEY
from tunnel.camouflage import create_tunnel_server_app
from tunnel.transports import TunnelClientDispatcher


@pytest.mark.asyncio
async def test_active_probe_camouflage_and_zero_redis_rfc9111_cache() -> None:
    """Verify unauthenticated probes get a realistic RFC 9110/9111 decoy page with ETag/304 and Cache-Status."""
    app = create_tunnel_server_app(secret_key=DEFAULT_SECRET_KEY)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8443") as client:
        r1 = await client.get("/")
        assert r1.status_code == 200
        assert "AetherCloud Documentation" in r1.text
        assert "etag" in r1.headers
        assert "cache-status" in r1.headers
        assert "miss" in r1.headers["cache-status"]

        r2 = await client.get("/")
        assert r2.status_code == 200
        assert "hit" in r2.headers["cache-status"]

        etag = r2.headers["etag"]
        r3 = await client.get("/", headers={"If-None-Match": etag})
        assert r3.status_code == 304
        assert r3.content == b""

        # Unauthenticated probe to tunnel endpoint must also receive decoy camouflage (never a proxy error)
        probe = await client.post("/_aether/chunk", content=b"unauthenticated-censor-probe")
        assert probe.status_code == 200
        assert "AetherCloud Documentation" in probe.text


@pytest.mark.asyncio
async def test_all_three_rfc_tunnel_transports_and_udp_rfc9298() -> None:
    """Verify authenticated RFC 9113-padded relays over WS_RFC8441, CHUNKED_RFC9112, CONNECT_RFC9110, and RFC 9298 UDP."""
    app = create_tunnel_server_app(secret_key=DEFAULT_SECRET_KEY)
    dispatcher = TunnelClientDispatcher(
        server_url="http://127.0.0.1:8443",
        secret_key=DEFAULT_SECRET_KEY,
        asgi_app=app,
    )

    for mode in ("CHUNKED_RFC9112", "CONNECT_RFC9110", "WS_RFC8441"):
        res = await dispatcher.relay_payload(
            transport_mode=mode,
            target_host="echo.aether.internal",
            target_port=443,
            payload=b"PING_THROUGH_RFC_TUNNEL",
            padding_enabled=True,
        )
        assert res["ok"] is True
        assert res["transport"] == mode
        assert res["rfc9421_verified"] is True
        assert res["pad_bytes"] >= 16
        assert b"PING_THROUGH_RFC_TUNNEL" in res["response_bytes"]

    udp_res = await dispatcher.relay_udp_datagram(
        target_host="dns.aether.internal",
        target_port=53,
        datagram=b"\x12\x34DNS_QUERY_RFC9298",
    )
    assert udp_res["ok"] is True
    assert udp_res["rfc"] == "RFC 9298"
    assert b"DNS_QUERY_RFC9298" in udp_res["datagram_reply"]

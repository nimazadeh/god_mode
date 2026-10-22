"""Ticket 46 (v10.7) TDD verification for official HTTPX connection pooling + trust_env=False, Pydantic v2 ConfigDict, and Uvicorn server_header=False."""

import inspect
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from api.routes import ProfileImportRequest, RouteRuleRequest, TransportSelectRequest
from constants import AETHERGATE_VERSION
import main
import server_node
from tunnel.camouflage import create_tunnel_server_app
from tunnel.transports import TunnelClientDispatcher


def test_version_v10_7_and_uvicorn_stealth_server_header_disabled() -> None:
    """Verify v10.7 version bump and ensure both main.py and server_node.py pass server_header=False to uvicorn.run."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    main_src = inspect.getsource(main)
    node_src = inspect.getsource(server_node)
    assert "server_header=False" in main_src
    assert "server_header=False" in node_src


def test_pydantic_v2_config_dict_strips_whitespace_and_forbids_extra_fields() -> None:
    """Verify Pydantic v2 ConfigDict(str_strip_whitespace=True, extra='forbid') sanitizes pasted strings and rejects unknown fields."""
    req = RouteRuleRequest(pattern="  arena.ai \n\t ", action="  GEOIP_RELAY  ")
    assert req.pattern == "arena.ai"
    assert req.action == "GEOIP_RELAY"

    prof = ProfileImportRequest(uri="   aethergate://eyJuYW1lIjogInRlc3QifQ==   \n")
    assert prof.uri == "aethergate://eyJuYW1lIjogInRlc3QifQ=="

    app = main.create_control_app(start_proxy=False)
    with TestClient(app) as client:
        bad_res = client.post(
            "/api/routing/rules",
            json={"pattern": "example.com", "action": "TUNNEL", "malicious_extra": "injected"},
        )
        assert bad_res.status_code == 422


@pytest.mark.asyncio
async def test_httpx_persistent_client_pooling_and_trust_env_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify TunnelClientDispatcher reuses one persistent AsyncClient with trust_env=False so OS proxy env vars never cause loopback."""
    # Even if a broken/poisoned HTTP_PROXY environment variable is present in the OS, trust_env=False must ignore it.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")

    srv_app = create_tunnel_server_app()
    disp = TunnelClientDispatcher(server_url="http://127.0.0.1:8443", asgi_app=srv_app)
    try:
        res1 = await disp.relay_payload("WS_RFC8441", "pool-test.aether.internal", 443, b"PING_1", True)
        client_first = disp._client
        assert client_first is not None
        assert client_first._trust_env is False

        res2 = await disp.relay_payload("WS_RFC8441", "pool-test.aether.internal", 443, b"PING_2", True)
        client_second = disp._client
        assert res1["ok"] is True and res2["ok"] is True
        assert client_first is client_second

        # Hot-swapping server_url must rotate the pooled client cleanly.
        disp.server_url = "http://localhost:8443"
        res3 = await disp.relay_payload("WS_RFC8441", "pool-test.aether.internal", 443, b"PING_3", True)
        assert res3["ok"] is True
        assert disp._client is not None
        assert disp._client is not client_first
    finally:
        await disp.aclose()
        assert disp._client is None or disp._client.is_closed

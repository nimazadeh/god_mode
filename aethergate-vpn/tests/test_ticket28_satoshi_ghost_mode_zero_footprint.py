"""Tests for Ticket 28: Satoshi Ghost Mode (v8.5) — Zero-Disk Footprint, LAN Dashboard Lock & MSN Unclog."""

from httpx import ASGITransport, AsyncClient
import pytest
from constants import DIAG_LOG_PATH, DNS_CACHE_PATH, ROUTING_PATH
from main import create_control_app
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.satoshi_engine import purge_disk_footprints
from tunnel.smart_router import SmartRouter


def test_ram_only_ephemeral_mode_and_purge_disk_footprints() -> None:
    """Verify default instances leave zero files on disk and purge_disk_footprints deletes old logs."""
    DIAG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    DNS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DIAG_LOG_PATH.write_text("old-log", encoding="utf-8")
    DNS_CACHE_PATH.write_text("{}", encoding="utf-8")
    ROUTING_PATH.write_text("[]", encoding="utf-8")

    removed = purge_disk_footprints()
    assert removed >= 3
    assert not DIAG_LOG_PATH.exists()
    assert not DNS_CACHE_PATH.exists()
    assert not ROUTING_PATH.exists()

    diag = DiagnosticLogger()
    doh = DoHResolver()
    rtr = SmartRouter()
    cid = diag.start_conn("HTTP_CONNECT", "arena.ai", 443, "GEOIP_RELAY")
    diag.log_stage(cid, "CLOSED_OK", tx=100, rx=200)
    doh.cache["arena.ai"] = "104.18.14.206"
    doh.save_disk_cache()
    rtr.add_rule("example.com", "GEOIP_RELAY")

    assert not DIAG_LOG_PATH.exists()
    assert not DNS_CACHE_PATH.exists()
    assert not ROUTING_PATH.exists()


def test_msn_telemetry_blocked_and_msn_assets_stay_on_direct_tunnel() -> None:
    """Verify browser.events.data.msn.com is BLOCKED and assets.msn.com / akamaized.net stay on TUNNEL."""
    rtr = SmartRouter()
    doh = DoHResolver()
    assert rtr.decide("browser.events.data.msn.com") == "BLOCK"
    assert rtr.decide("events.data.msn.com") == "BLOCK"
    assert rtr.decide("otf.msn.com") == "BLOCK"

    for host in ("assets.msn.com", "api.msn.com", "img-s-msn-com.akamaized.net", "c.bing.com"):
        doh.flag_geoip_host(host)
        assert doh.is_geoip_flagged(host) is False
        assert rtr.decide(host) == "TUNNEL"


@pytest.mark.asyncio
async def test_dashboard_blocks_wifi_lan_snooping_while_allowing_loopback() -> None:
    """Verify Control Center (:9090) returns 403 to 192.168.1.* LAN peers and 200 OK to 127.0.0.1."""
    app = create_control_app(start_proxy=False)
    lan_transport = ASGITransport(app=app, client=("192.168.1.55", 54321))
    local_transport = ASGITransport(app=app, client=("127.0.0.1", 54321))

    async with AsyncClient(transport=lan_transport, base_url="http://localhost:9090") as lan_client:
        res_lan = await lan_client.get("/api/diagnostics/logs")
        assert res_lan.status_code == 403
        assert b"Satoshi Ghost Mode" in res_lan.content

    async with AsyncClient(transport=local_transport, base_url="http://localhost:9090") as local_client:
        res_local = await local_client.get("/api/diagnostics/logs")
        assert res_local.status_code == 200

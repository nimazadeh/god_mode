"""Control-plane REST endpoints so the browser monitor and CLI can inspect and mutate live tunnel state without touching raw sockets."""

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
import httpx
from httpx import ASGITransport
from pydantic import BaseModel, ConfigDict, Field
from constants import DASHBOARD_DIR, SUPPORTED_TRANSPORTS
from tunnel.frontier_2026 import audit_frontier_2026_capabilities
from tunnel.geoip_relay import get_relay_country_meta
from tunnel.privacy_rfc9614 import audit_rfc9614_privacy_posture

router = APIRouter()


class TransportSelectRequest(BaseModel):
    """Validate transport mode and padding flags before mutating live proxy state so invalid strings cannot crash active streams."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    transport: str = Field(default="WS_RFC8441")
    padding_enabled: bool = True


class ProfileImportRequest(BaseModel):
    """Enforce a minimum URI length and strip accidental clipboard whitespace so malformed strings are rejected before base64 decoding."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    uri: str = Field(min_length=14)


class RouteRuleRequest(BaseModel):
    """Validate custom split-tunneling inputs and reject unknown JSON fields so malformed payloads cannot shadow built-in routing rules."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    pattern: str = Field(min_length=2)
    action: str = Field(default="TUNNEL")


@router.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> FileResponse:
    """Serve the live monitor shell with no-store headers so browser refreshes always pick up the latest UI layout."""
    return FileResponse(DASHBOARD_DIR / "index.html", headers={"Cache-Control": "no-store"})


@router.get("/favicon.ico")
async def serve_favicon() -> FileResponse:
    """Provide a local icon asset so browsers never emit noisy 404 requests or leak external icon fetches."""
    return FileResponse(DASHBOARD_DIR / "favicon.ico", media_type="image/x-icon")


@router.get("/api/live/state")
async def get_live_state(request: Request) -> dict[str, Any]:
    """Aggregate tunnel, relay, and cache metrics into one payload so the UI polls state in a single HTTP round-trip."""
    st, cache = request.app.state.aether, request.app.state.rfc_cache
    disp, proxy, rtr = st["dispatcher"], st["inbound_proxy"], st["router"]
    return {
        "connected": st["connected"], "system_proxy": st["os_proxy"].status(),
        "inbound_port": proxy.bound_port, "active_transport": proxy.active_transport,
        "padding_enabled": proxy.padding_enabled, "active_profile": st["profiles"].get_active(),
        "profiles": st["profiles"].profiles,
        "telemetry": {
            "bytes_tx": disp.bytes_tx, "bytes_rx": disp.bytes_rx, "pad_bytes_total": disp.pad_bytes_total,
            "packets_relayed": disp.packets_relayed, "last_rtt_ms": disp.last_rtt_ms,
        },
        "routing": {
            "counts": rtr.counts, "rules": rtr.custom_rules[:25], "recent": rtr.recent_decisions[:15],
            "active_geoip_relay": proxy.relay_pool.active_relay, "country_meta": get_relay_country_meta(proxy.relay_pool.active_relay), "geoip_pool_size": len(proxy.relay_pool.relays),
        },
        "satoshi": {
            "prewarm_ready": proxy.relay_pool.prewarm_pool.ready_count(),
            "prewarm_hits": proxy.relay_pool.prewarm_pool.hits,
            "miner": proxy.miner.status(),
            "lan_gateway": proxy.lan_gateway.status(proxy.bound_port),
            "location_cloak_all": rtr.location_cloak_all,
            "accept_language_cloak": "en-US,en;q=0.9",
            "privacy_rfc9614": audit_rfc9614_privacy_posture(rtr, proxy.relay_pool),
            "frontier_2026": audit_frontier_2026_capabilities(),
        },
        "rfc_cache": {"hits": cache.hits, "misses": cache.misses, "invalidations": cache.invalidations},
    }


@router.post("/api/tunnel/toggle")
async def toggle_tunnel_connection(request: Request) -> dict[str, Any]:
    """Synchronize tunnel state with Windows Internet Settings so disconnecting immediately restores direct OS networking."""
    st = request.app.state.aether
    st["connected"] = not st["connected"]
    proxy_status = st["os_proxy"].set_enabled(st["connected"])
    if st["connected"]:
        await st["dispatcher"].relay_payload(
            st["inbound_proxy"].active_transport, "handshake.aether.internal", 443, b"INIT_RFC9421", True
        )
    return {"connected": st["connected"], "system_proxy": proxy_status}


@router.post("/api/tunnel/transport")
async def switch_tunnel_transport(body: TransportSelectRequest, request: Request) -> dict[str, Any]:
    """Allow runtime transport switching so users can adapt to changing ISP DPI rules without restarting the proxy."""
    if body.transport not in SUPPORTED_TRANSPORTS:
        raise HTTPException(status_code=400, detail="Unsupported RFC transport mode")
    st = request.app.state.aether
    st["inbound_proxy"].active_transport = body.transport
    st["inbound_proxy"].padding_enabled = body.padding_enabled
    prof = st["profiles"].get_active()
    prof["transport"] = body.transport
    prof["padding_enabled"] = body.padding_enabled
    st["profiles"].save()
    return {"active_transport": body.transport, "padding_enabled": body.padding_enabled}


@router.post("/api/tunnel/benchmark")
async def run_e2e_benchmark(request: Request) -> dict[str, Any]:
    """Verify RFC 9421 signing, RFC 9113 padding, and RFC 9298 UDP framing in-process so users can confirm crypto integrity offline."""
    st = request.app.state.aether
    mode = st["inbound_proxy"].active_transport
    pad_on = st["inbound_proxy"].padding_enabled
    tcp_res = await st["dispatcher"].relay_payload(mode, "benchmark.aether.internal", 443, b"BENCHMARK_64B_PAYLOAD", pad_on)
    udp_res = await st["dispatcher"].relay_udp_datagram("dns.aether.internal", 53, b"UDP_RFC9298_PROBE")
    return {
        "ok": tcp_res["ok"] and udp_res["ok"],
        "transport": mode,
        "rtt_ms": tcp_res.get("rtt_ms", 0.0),
        "pad_bytes": tcp_res.get("pad_bytes", 0),
        "rfc9421_verified": tcp_res.get("rfc9421_verified", False),
        "udp_rfc9298_ok": udp_res.get("ok", False),
    }


@router.post("/api/tunnel/probe-camouflage")
async def test_active_probe_camouflage(request: Request) -> dict[str, Any]:
    """Send an unauthenticated request to the tunnel endpoint to prove active censor scanners only see an innocent HTML doc page."""
    st = request.app.state.aether
    srv_app = st["server_app"]
    async with httpx.AsyncClient(transport=ASGITransport(app=srv_app), base_url="http://127.0.0.1:8443", trust_env=False) as client:
        res = await client.post("/_aether/chunk", content=b"UNAUTHENTICATED_DPI_SCANNER")
    return {
        "status_code": res.status_code,
        "camouflage_active": "AetherCloud Documentation" in res.text,
        "server_cache_status": res.headers.get("cache-status", "bypass"),
        "snippet": "200 OK — AetherCloud Documentation (Zero Proxy Fingerprint)",
    }


@router.post("/api/profiles/import")
async def import_profile_uri(body: ProfileImportRequest, request: Request) -> dict[str, Any]:
    """Hot-swap the dispatcher endpoint and secret key from an aethergate:// URI so new VPS nodes activate without a restart."""
    st = request.app.state.aether
    try:
        prof = st["profiles"].import_uri(body.uri)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st["dispatcher"].server_url = prof["server_url"]
    st["dispatcher"].secret_key = prof["secret_key"]
    st["inbound_proxy"].active_transport = prof["transport"]
    return {"active_profile": prof, "profiles": st["profiles"].profiles}


@router.post("/api/routing/rules")
async def add_routing_rule(body: RouteRuleRequest, request: Request) -> dict[str, Any]:
    """Insert custom domain overrides at highest priority so users can force specific hosts through relay, direct, or block paths."""
    st = request.app.state.aether
    rule = st["router"].add_rule(body.pattern, body.action)
    return {"rule": rule, "rules": st["router"].custom_rules[:25]}


@router.get("/api/diagnostics/logs")
async def get_diagnostic_logs(request: Request) -> dict[str, Any]:
    """Return bounded in-memory connection events so the live monitor updates in real time without disk I/O."""
    diag = request.app.state.aether["inbound_proxy"].diag
    return {
        "events": diag.events[:40],
        "checks": diag.last_checks,
        "report_text": diag.build_text_report(),
    }


@router.post("/api/diagnostics/run")
async def run_self_diagnosis_suite(request: Request) -> dict[str, Any]:
    """Run on-demand reachability and ECH probes only when explicitly requested so background live logs stay clutter-free."""
    proxy = request.app.state.aether["inbound_proxy"]
    return await proxy.diag.run_self_diagnosis(proxy.doh, proxy.bound_port)


@router.post("/api/relays/refresh")
async def refresh_geoip_exit_relays(request: Request) -> dict[str, Any]:
    """Harvest and rank fresh US/EU exit relays on demand so users can recover immediately if an upstream relay degrades."""
    proxy = request.app.state.aether["inbound_proxy"]
    return await proxy.relay_pool.refresh_live_relays()


@router.post("/api/satoshi/mine-ips")
async def run_satoshi_clean_ip_miner(request: Request) -> dict[str, Any]:
    """Probe Anycast candidates for genuine TLS 1.3 ServerHellos and pre-warm SOCKS5 sockets to minimize handshake latency."""
    proxy = request.app.state.aether["inbound_proxy"]
    mined = await proxy.miner.mine_clean_ips(proxy.doh)
    warmed = await proxy.relay_pool.prewarm_active_relay(count=2)
    return {**mined, "prewarm_ready": warmed}


@router.post("/api/satoshi/lan-gateway")
async def toggle_sovereign_lan_gateway(request: Request) -> dict[str, Any]:
    """Enable or restrict RFC 1918 LAN peer access so mobile devices on local Wi-Fi can share the PC anti-censorship tunnel."""
    proxy = request.app.state.aether["inbound_proxy"]
    proxy.lan_gateway.enabled = not proxy.lan_gateway.enabled
    return proxy.lan_gateway.status(proxy.bound_port)


@router.post("/api/satoshi/location-cloak")
async def toggle_global_location_cloak(request: Request) -> dict[str, Any]:
    """Switch between global US IP cloaking and selective routing while keeping high-bandwidth video on direct SNI-shredded links."""
    rtr = request.app.state.aether["router"]
    rtr.location_cloak_all = not rtr.location_cloak_all
    return {"location_cloak_all": rtr.location_cloak_all}


@router.post("/api/satoshi/privacy-partitioning")
async def toggle_strict_privacy_partitioning(request: Request) -> dict[str, Any]:
    """Toggle RFC 9614 strict privacy partitioning so 100% of non-domestic traffic (including media) routes via US/EU relays."""
    st = request.app.state.aether
    rtr = st["router"]
    rtr.strict_privacy_partitioning = not rtr.strict_privacy_partitioning
    return audit_rfc9614_privacy_posture(rtr, st["inbound_proxy"].relay_pool)




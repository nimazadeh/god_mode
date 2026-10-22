"""Orchestrates the Control Center (:9090), Inbound Proxy (:10808), and Loopback Node (:8443) so users get zero-config protection on startup."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from constants import DASHBOARD_DIR, DASHBOARD_PORT, INBOUND_PROXY_PORT
from tunnel.inbound_proxy import UnifiedInboundProxy
from tunnel.os_proxy import SystemProxyAdapter
from tunnel.profile_uri import ProfileManager
from tunnel.smart_router import SmartRouter


def _build_aether_state(bind_inbound_port: int = INBOUND_PROXY_PORT) -> dict[str, Any]:
    """Assemble all runtime subsystems into a single state container so API routes and proxy streams share live telemetry without global singletons."""
    from tunnel.camouflage import create_tunnel_server_app
    from tunnel.transports import TunnelClientDispatcher
    profiles = ProfileManager()
    active = profiles.get_active()
    server_app = create_tunnel_server_app(secret_key=active["secret_key"])
    dispatcher = TunnelClientDispatcher(active["server_url"], active["secret_key"], asgi_app=server_app)
    smart_router = SmartRouter()
    # Enable global US location cloaking and RFC 9614 strict privacy partitioning so zero foreign packets ever expose the domestic IP.
    smart_router.location_cloak_all = True
    smart_router.strict_privacy_partitioning = True
    inbound_proxy = UnifiedInboundProxy(dispatcher, smart_router, "0.0.0.0", bind_inbound_port)
    inbound_proxy.active_transport = active["transport"]
    inbound_proxy.padding_enabled = bool(active.get("padding_enabled", True))
    return {
        "connected": True, "profiles": profiles, "server_app": server_app,
        "dispatcher": dispatcher, "router": smart_router, "inbound_proxy": inbound_proxy,
        "os_proxy": SystemProxyAdapter(f"127.0.0.1:{bind_inbound_port}"),
    }


def _make_lifespan(state: dict[str, Any], start_proxy: bool) -> Any:
    """Bind proxy lifecycle, background relay self-healing, and OS proxy cleanup to ASGI lifespan so crashes never leave Windows internet broken."""
    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        import asyncio
        from tunnel.cli_console import disable_windows_cmd_quickedit, format_cli_post_banner_lines, format_cli_status_banner, run_autonomous_guardian_loop
        from tunnel.diag_logger import install_asyncio_quiet_handler
        from tunnel.satoshi_engine import purge_disk_footprints, spawn_background_task
        disable_windows_cmd_quickedit()
        install_asyncio_quiet_handler(asyncio.get_running_loop())
        purge_disk_footprints()
        guardian_task = None
        if start_proxy:
            await state["inbound_proxy"].start()
            state["os_proxy"].set_enabled(True)
            print(format_cli_status_banner(state))
            print(format_cli_post_banner_lines(state, DASHBOARD_PORT), flush=True)
            # Retain strong task references per Python 3.13 asyncio-task docs so GC never drops startup background tasks.
            spawn_background_task(state["inbound_proxy"].relay_pool.heal_and_sort_relays())
            spawn_background_task(state["inbound_proxy"].miner.mine_clean_ips(state["inbound_proxy"].doh))
            spawn_background_task(state["inbound_proxy"].relay_pool.prewarm_active_relay(count=2))
            guardian_task = spawn_background_task(run_autonomous_guardian_loop(state))
        yield
        if guardian_task is not None:
            guardian_task.cancel()
        if start_proxy:
            await state["inbound_proxy"].stop()
        await state["dispatcher"].aclose()
        state["os_proxy"].set_enabled(False)
        purge_disk_footprints()

    return lifespan


def create_control_app(start_proxy: bool = True, inbound_port: int = INBOUND_PROXY_PORT) -> Any:
    """Construct the FastAPI control plane with in-memory RFC 9111 caching so dashboard polling adds near-zero CPU overhead."""
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from api.routes import router
    from tunnel.rfc_cache import ZeroRedisRfcCache, attach_zero_redis_rfc_cache
    state = _build_aether_state(bind_inbound_port=inbound_port)
    app = FastAPI(title="AetherGate Personal VPN", version="2.1.0", lifespan=_make_lifespan(state, start_proxy))
    app.state.aether = state
    attach_zero_redis_rfc_cache(app, ZeroRedisRfcCache())
    app.include_router(router)
    app.mount("/css", StaticFiles(directory=str(DASHBOARD_DIR / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(DASHBOARD_DIR / "js")), name="js")
    return app


def main() -> int:
    """Launch the ASGI server when Uvicorn is installed or fall back to pure stdlib so restricted environments still run without pip."""
    import importlib.util
    from tunnel.cli_console import disable_windows_cmd_quickedit, format_cli_event_line
    disable_windows_cmd_quickedit()
    print(format_cli_event_line("INIT", f"Starting AetherGate Control Center on http://127.0.0.1:{DASHBOARD_PORT} ...", "info"))
    if importlib.util.find_spec("uvicorn") is not None and importlib.util.find_spec("fastapi") is not None:
        import uvicorn
        # Disable Uvicorn's default 'server: uvicorn' header so local and camouflage endpoints never leak ASGI server signatures.
        uvicorn.run(
            create_control_app(start_proxy=True),
            host="0.0.0.0",
            port=DASHBOARD_PORT,
            log_level="warning",
            server_header=False,
        )
        return 0
    from tunnel.stdlib_runner import run_stdlib_control_center
    return run_stdlib_control_center()


if __name__ == "__main__":
    raise SystemExit(main())

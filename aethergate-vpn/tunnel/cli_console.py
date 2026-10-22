"""Autonomous background guardian, Windows QuickEdit/VT100 console initializer, and ANSI color CLI menu to keep tunnels alive 24/7."""

import asyncio
import sys
from typing import Any
from constants import AETHERGATE_VERSION
from tunnel.satoshi_engine import spawn_background_task

# Windows cmd.exe sets 0x0040 (QuickEdit) by default, which pauses stdout and freezes the asyncio event loop on any mouse click.
ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_EXTENDED_FLAGS = 0x0080
# Enabling 0x0004 (Virtual Terminal Processing) on stdout allows Windows conhost/cmd.exe to render standard ANSI color sequences natively.
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11

# Standard ECMA-48 / ANSI SGR escape codes ensure universal color rendering across Windows Terminal, cmd.exe, PowerShell, and Linux/macOS TTYs.
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_MAGENTA = "\033[95m"
C_BLUE = "\033[94m"
C_WHITE = "\033[97m"

_ASCII_LOGO_LINES = (
    r"    ___    ______ ______ __  __ ______ ____   ______ ___   ______ ______",
    r"   /   |  / ____//_  __// / / // ____// __ \ / ____//   | /_  __// ____/",
    r"  / /| | / __/    / /  / /_/ // __/  / /_/ // / __ / /| |  / /  / __/   ",
    r" / ___ |/ /___   / /  / __  // /___ / _, _// /_/ // ___ | / /  / /___   ",
    r"/_/  |_/_____/  /_/  /_/ /_//_____//_/ |_| \____//_/  |_|/_/  /_____/   ",
)


def disable_windows_cmd_quickedit() -> bool:
    """Enable VT100 ANSI colors on Windows and clear QuickEdit only on legacy conhost so Windows Terminal keeps mouse copy support."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        import os
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        out_handle = k32.GetStdHandle(STD_OUTPUT_HANDLE)
        out_mode = ctypes.c_uint32()
        if k32.GetConsoleMode(out_handle, ctypes.byref(out_mode)):
            k32.SetConsoleMode(out_handle, out_mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        if not os.environ.get("WT_SESSION"):
            in_handle = k32.GetStdHandle(STD_INPUT_HANDLE)
            in_mode = ctypes.c_uint32()
            if k32.GetConsoleMode(in_handle, ctypes.byref(in_mode)):
                k32.SetConsoleMode(in_handle, (in_mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS)
        return True
    except Exception:
        return False


def format_cli_event_line(tag: str, message: str, level: str = "info") -> str:
    """Format post-banner terminal notifications with semantic ANSI color badges so operators can distinguish boot, heal, and alert events."""
    color_map = {"ok": C_GREEN, "warn": C_YELLOW, "err": C_RED, "info": C_CYAN, "shield": C_MAGENTA}
    badge_color = color_map.get(level, C_CYAN)
    return f"{C_DIM}│{C_RESET} {C_BOLD}{badge_color}[{tag:<8}]{C_RESET} {C_WHITE}{message}{C_RESET}"


def _build_vertical_hotkey_menu() -> str:
    """Render each CLI hotkey as a vertical menu item so operators can scan available single-key commands at a glance."""
    items = (
        ("[T] Tunnel ON/OFF", "Toggle System Proxy & Active Shield"),
        ("[C] US Cloak", "Switch Global US Cloak / Selective Mode"),
        ("[P] Privacy Partitioning", "Toggle RFC 9614 Strict 100% Relay Mode"),
        ("[D] 7-Point Health Check", "Run Live DoH, ECH & Relay Diagnostics"),
        ("[R] Heal Relays", "Re-Rank US/EU Pool & Pre-Warm 0-RTT Sockets"),
        ("[L] Tail Logs", "Print Recent Encrypted Stream Telemetry"),
    )
    rows = [f"{C_BLUE}║{C_RESET}  {C_BOLD}{C_YELLOW}INTERACTIVE HOTKEY MENU (PRESS KEY IN TERMINAL):{C_RESET}"]
    for key_label, desc in items:
        pad = " " * max(1, 26 - len(key_label))
        rows.append(f"{C_BLUE}║{C_RESET}    {C_BOLD}{C_CYAN}{key_label}{C_RESET}{pad}{C_DIM}──{C_RESET} {C_WHITE}{desc}{C_RESET}")
    return "\n".join(rows)


def format_cli_status_banner(state: dict[str, Any]) -> str:
    """Render a colorized ASCII art banner and vertical hotkey menu so terminal operators can verify protection without opening a browser."""
    proxy, rtr = state["inbound_proxy"], state["router"]
    conn_raw = "● CONNECTED" if state.get("connected", True) else "○ STANDBY"
    conn_col = C_GREEN if state.get("connected", True) else C_YELLOW
    cloak_raw = "GLOBAL_US (RFC 9614)" if rtr.strict_privacy_partitioning else ("GLOBAL_US" if rtr.location_cloak_all else "SELECTIVE")
    lan_raw = f"ON (0.0.0.0:{proxy.bound_port})" if proxy.lan_gateway.enabled else "OFF"
    relay_raw = proxy.relay_pool.active_relay
    pool_n = proxy.relay_pool.prewarm_pool.ready_count()
    bar = "═" * 74
    logo = "\n".join(f"{C_BLUE}║{C_RESET} {C_BOLD}{C_CYAN}{ln}{C_RESET}" for ln in _ASCII_LOGO_LINES)
    return (
        f"\n{C_BLUE}╔{bar}╗{C_RESET}\n{logo}\n"
        f"{C_BLUE}║{C_RESET}  {C_BOLD}{C_MAGENTA}AETHERGATE VPN {AETHERGATE_VERSION} • RFC 9614 PRIVACY & ANTI-DPI ENGINE{C_RESET}\n"
        f"{C_BLUE}╠{bar}╣{C_RESET}\n"
        f"{C_BLUE}║{C_RESET}  {C_DIM}STATUS     :{C_RESET} {C_BOLD}{conn_col}{conn_raw:<28}{C_RESET} {C_DIM}LOCAL PROXY :{C_RESET} {C_CYAN}127.0.0.1:{proxy.bound_port}{C_RESET}\n"
        f"{C_BLUE}║{C_RESET}  {C_DIM}CLOAK MODE :{C_RESET} {C_GREEN}{cloak_raw:<28}{C_RESET} {C_DIM}WI-FI LAN   :{C_RESET} {C_YELLOW}{lan_raw}{C_RESET}\n"
        f"{C_BLUE}║{C_RESET}  {C_DIM}EXIT RELAY :{C_RESET} {C_CYAN}{relay_raw:<28}{C_RESET} {C_DIM}0-RTT POOL  :{C_RESET} {C_GREEN}{pool_n} READY SOCKETS{C_RESET}\n"
        f"{C_BLUE}║{C_RESET}  {C_DIM}RFC SHIELD :{C_RESET} {C_MAGENTA}RFC 9614 2-Hop • RFC 9849 ECH • RFC 9230 ODoH • JA4{C_RESET}\n"
        f"{C_BLUE}║{C_RESET}  {C_DIM}WEB MONITOR:{C_RESET} {C_BOLD}{C_CYAN}http://127.0.0.1:9090{C_RESET}\n"
        f"{C_BLUE}╠{bar}╣{C_RESET}\n"
        f"{_build_vertical_hotkey_menu()}\n"
        f"{C_BLUE}╚{bar}╝{C_RESET}"
    )


async def execute_cli_hotkey(key: str, state: dict[str, Any]) -> str | None:
    """Process single-key CLI actions asynchronously so headless users can toggle routing or heal relays without blocking traffic."""
    k = key.strip().lower()[:1]
    proxy, rtr = state["inbound_proxy"], state["router"]
    if k == "t":
        state["connected"] = not state.get("connected", True)
        state["os_proxy"].set_enabled(state["connected"])
        lvl = "ok" if state["connected"] else "warn"
        return format_cli_event_line("CLI", f"Tunnel -> {'CONNECTED' if state['connected'] else 'STANDBY'}", lvl)
    if k == "c":
        rtr.location_cloak_all = not rtr.location_cloak_all
        return format_cli_event_line("CLI", f"US Location Cloak -> {'GLOBAL ON' if rtr.location_cloak_all else 'SELECTIVE'}", "shield")
    if k == "p":
        rtr.strict_privacy_partitioning = not rtr.strict_privacy_partitioning
        return format_cli_event_line("RFC9614", f"Strict Privacy Partitioning -> {'ON (100% RELAY)' if rtr.strict_privacy_partitioning else 'SELECTIVE'}", "shield")
    if k == "d":
        res = await proxy.diag.run_self_diagnosis(proxy.doh, proxy.bound_port)
        return format_cli_event_line("DIAG", str(res.get("report_text", "")), "info")
    if k == "r":
        await proxy.relay_pool.heal_and_sort_relays()
        await proxy.miner.mine_clean_ips(proxy.doh)
        await proxy.relay_pool.prewarm_active_relay(count=2)
        return format_cli_event_line("HEAL", f"Healed Relay -> {proxy.relay_pool.active_relay} | CF VIP -> {proxy.doh.active_cf_vip}", "ok")
    if k == "l":
        lines = [format_cli_event_line("STREAM", ev.get("line", ""), "info") for ev in proxy.diag.events[:15]]
        if sys.platform == "win32":
            try:
                import subprocess
                subprocess.run(["clip"], input=proxy.diag.build_text_report().encode("utf-8"), check=False)
            except Exception:
                pass
        return "\n".join(lines) if lines else format_cli_event_line("CLI", "No recent connection events.", "warn")
    return None


def format_cli_post_banner_lines(state: dict[str, Any], dashboard_port: int = 9090) -> str:
    """Render colorized post-banner startup lines so operators see active proxy endpoints, RFC shields, and guardian state clearly."""
    port = state["inbound_proxy"].bound_port
    return "\n".join((
        format_cli_event_line("BOOT", f"Control Center & Live Observatory -> {C_CYAN}http://127.0.0.1:{dashboard_port}{C_RESET}", "info"),
        format_cli_event_line("PROXY", f"SOCKS5 (RFC 1928) + HTTP CONNECT (RFC 9110) -> {C_GREEN}127.0.0.1:{port}{C_RESET}", "ok"),
        format_cli_event_line("SHIELD", "RFC 9614 2-Hop Partitioning • RFC 9230 ODoH • RFC 6797 TLS-Only Guard Active", "shield"),
        format_cli_event_line("GUARDIAN", "Autonomous Background Relay Harvester & 0-RTT Pre-Warmer Engaged", "ok"),
    ))


async def run_cli_key_listener(state: dict[str, Any]) -> None:
    """Poll Windows console keystrokes via msvcrt without blocking asyncio so single-key menu hotkeys respond instantaneously."""
    if sys.platform != "win32":
        return
    try:
        import msvcrt
        while True:
            await asyncio.sleep(0.15)
            if msvcrt.kbhit():  # type: ignore[attr-defined]
                out = await execute_cli_hotkey(msvcrt.getwch(), state)  # type: ignore[attr-defined]
                if out:
                    print(out, flush=True)
    except Exception:
        return


async def run_autonomous_guardian_loop(state: dict[str, Any], interval_sec: float = 180.0) -> None:
    """Continuously heal relays, mine clean Anycast VIPs, and refill 0-RTT sockets in the background so users never click maintenance buttons."""
    proxy = state["inbound_proxy"]
    spawn_background_task(run_cli_key_listener(state))
    while True:
        await asyncio.sleep(interval_sec)
        try:
            if state.get("connected", True):
                await proxy.relay_pool.heal_and_sort_relays()
                await proxy.miner.mine_clean_ips(proxy.doh)
                await proxy.relay_pool.prewarm_active_relay(count=2)
        except Exception:
            pass

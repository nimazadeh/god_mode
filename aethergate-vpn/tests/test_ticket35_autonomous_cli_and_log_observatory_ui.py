"""Tests for Ticket 35/36: Autonomous CLI Hotkey Engine, Windows QuickEdit Guard & High-End Single-Bar Live Log Monitor."""

import asyncio
from pathlib import Path
import pytest
from playwright.async_api import async_playwright
from constants import AETHERGATE_VERSION
from main import _build_aether_state
from tunnel.cli_console import (
    disable_windows_cmd_quickedit,
    execute_cli_hotkey,
    format_cli_post_banner_lines,
    format_cli_status_banner,
)


def test_windows_quickedit_guard_and_cli_status_banner() -> None:
    """Verify disable_windows_cmd_quickedit is safe on all platforms and CLI banner renders color ASCII + vertical hotkey menu."""
    assert isinstance(disable_windows_cmd_quickedit(), bool)
    st = _build_aether_state()
    banner = format_cli_status_banner(st)
    assert f"AETHERGATE VPN {AETHERGATE_VERSION}" in banner
    assert "CONNECTED" in banner
    assert "\033[" in banner
    root = Path(__file__).resolve().parent.parent
    for fname in ("start_aethergate.bat", "run-windows.bat", "FEATURES.md"):
        assert AETHERGATE_VERSION in (root / fname).read_text(encoding="utf-8")
    menu_lines = [ln for ln in banner.splitlines() if any(tag in ln for tag in ("[T]", "[C]", "[P]", "[D]", "[R]", "[L]"))]
    assert len(menu_lines) == 6, "Each CLI hotkey must be rendered on its own vertical menu line"
    post_lines = format_cli_post_banner_lines(st, 9090)
    assert "[BOOT" in post_lines and "[PROXY" in post_lines and "[SHIELD" in post_lines and "\033[" in post_lines


@pytest.mark.asyncio
async def test_non_blocking_cli_hotkeys_toggle_tunnel_and_cloak_and_tail_logs() -> None:
    """Verify single-key CLI commands ('t', 'c', 'l') mutate state cleanly without blocking."""
    st = _build_aether_state()
    assert st["connected"] is True
    out_t = await execute_cli_hotkey("t", st)
    assert st["connected"] is False
    assert "STANDBY" in (out_t or "")
    await execute_cli_hotkey("t", st)
    assert st["connected"] is True

    assert st["router"].location_cloak_all is True
    out_c = await execute_cli_hotkey("c", st)
    assert st["router"].location_cloak_all is False
    assert "SELECTIVE" in (out_c or "")

    st["inbound_proxy"].diag.start_conn("HTTP_CONNECT", "notebook.google.com", 443, "GEOIP_RELAY")
    out_l = await execute_cli_hotkey("l", st)
    assert "notebook.google.com" in (out_l or "")


@pytest.mark.asyncio
async def test_log_observatory_live_search_and_pause_stream_in_chromium() -> None:
    """Verify High-End Single-Bar Live Log Monitor starts near top of viewport, filters live stream, and pauses."""
    for target in ("notebook.google.com:443", "music.youtube.com:443", "arena.ai:443"):
        try:
            r, w = await asyncio.open_connection("127.0.0.1", 10808)
            w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin1"))
            await w.drain()
            await asyncio.wait_for(r.read(256), timeout=1.0)
            w.close()
        except Exception:
            pass

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.wait_for_selector("#log-search-input")
        await page.wait_for_selector("#btn-pause-log")
        await page.wait_for_selector("#console-sticky-header")

        con_box = await page.locator("#diag-console-view").bounding_box()
        assert con_box is not None and con_box["y"] < 85

        total_lines = await page.locator("#diag-console-view .console-line").count()
        assert total_lines >= 3

        await page.fill("#log-search-input", "notebook.google.com")
        filtered_lines = await page.locator("#diag-console-view .console-line").count()
        assert 1 <= filtered_lines < total_lines

        await page.fill("#log-search-input", "")
        restored_lines = await page.locator("#diag-console-view .console-line").count()
        assert restored_lines == total_lines

        await page.click("#btn-pause-log")
        pause_txt = await page.locator("#btn-pause-log").inner_text()
        assert "PAUSED" in pause_txt
        await page.click("#btn-pause-log")

        Path("/home/user/screenshots").mkdir(parents=True, exist_ok=True)
        await page.screenshot(path="/home/user/screenshots/aethergate_v9_7_live_monitor.png")
        await browser.close()
        assert errors == []


def test_clean_ui_zero_satoshi_label_and_secondary_buttons_in_drawer() -> None:
    """Verify UI has zero 'Satoshi' branding clutter, Variant B only, and manual buttons inside .advanced-drawer."""
    html = (Path(__file__).resolve().parent.parent / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert "satoshi" not in html.lower()
    drawer_section = html.split("<details class=\"advanced-drawer\">", 1)[-1]
    for manual_id in ("btn-run-diag", "btn-mine-ips", "btn-refresh-relays", "btn-toggle-cloak", "btn-toggle-lan", "stat-rtt"):
        assert manual_id in drawer_section, f"{manual_id} should be tucked inside .advanced-drawer"

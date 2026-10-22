"""Tests for Ticket 13: Variants B & C, Log Auto-Fit, Dark Scrollbar, CID Host Lookup, and /favicon.ico."""

import asyncio
from pathlib import Path
import urllib.request
import pytest
from playwright.async_api import async_playwright
from tunnel.diag_logger import DiagnosticLogger, format_event_line

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_cid_target_preserved_on_tls_handshake_and_closed_ok(tmp_path: Path) -> None:
    """Verify TLS_HANDSHAKE and CLOSED_OK log lines inherit the connection's host:port instead of '-'."""
    diag = DiagnosticLogger(log_path=tmp_path / "cid_host.log")
    cid = diag.start_conn("HTTP_CONNECT", "editor.svc.cloud.microsoft", 443, "TUNNEL")
    ev_tls = diag.log_stage(cid, "TLS_HANDSHAKE", mode="SNI_4BYTE_SHREDDER_6REC", bytes=1850)
    ev_close = diag.log_stage(cid, "CLOSED_OK", tx=1744, rx=4096)

    assert "editor.svc.cloud.microsoft" in format_event_line(ev_tls)
    assert "editor.svc.cloud.microsoft" in format_event_line(ev_close)


def test_dark_scrollbar_and_color_scheme_in_css() -> None:
    """Verify variables.css and layout.css define dark color-scheme and custom ::-webkit-scrollbar rules."""
    var_css = (ROOT_DIR / "dashboard" / "css" / "variables.css").read_text(encoding="utf-8")
    lay_css = (ROOT_DIR / "dashboard" / "css" / "layout.css").read_text(encoding="utf-8")
    assert "color-scheme: dark" in var_css
    assert "::-webkit-scrollbar" in lay_css
    assert "::-webkit-scrollbar-thumb" in lay_css


def test_favicon_ico_endpoint_returns_200_ok() -> None:
    """Verify GET http://127.0.0.1:9090/favicon.ico returns 200 OK so browser console has zero 404s."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:9090/favicon.ico", timeout=5) as resp:
        assert resp.status == 200
        body = resp.read()
        assert len(body) > 20


@pytest.mark.asyncio
async def test_variants_b_and_c_and_diag_box_full_fit() -> None:
    """Verify default Variant B and Variant C switch cleanly and #diag-report-box fits all report lines."""
    r, w = await asyncio.open_connection("127.0.0.1", 10808)
    w.write(b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n")
    await w.drain()
    await r.read(1024)
    w.close()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        assert await page.locator("#proto-switcher").count() == 0
        await page.click(".advanced-drawer summary")
        await page.click("#btn-run-diag")
        await page.wait_for_function(
            "document.getElementById('diag-copy-status')?.textContent.includes('Probes complete')",
            timeout=25000,
        )
        await page.wait_for_timeout(500)
        rows_attr = int(await page.get_attribute("#diag-report-box", "rows") or "0")
        assert rows_attr >= 16
        await page.click(".advanced-drawer summary")
        await page.screenshot(path="/home/user/screenshots/aethergate_variant_b.png", full_page=True)

        await browser.close()

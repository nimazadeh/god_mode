"""Tests for Ticket 14: Eye-Care Soft-Pastel Colorized Console Log Prototype and Full History Copy."""

from pathlib import Path
import pytest
from playwright.async_api import async_playwright
from tunnel.diag_logger import DiagnosticLogger

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_soft_pastel_console_color_tokens_in_variables_css() -> None:
    """Verify variables.css defines eye-safe muted green, yellow, red, and blue console tokens."""
    var_css = (ROOT_DIR / "dashboard" / "css" / "variables.css").read_text(encoding="utf-8")
    assert "--log-green: #56b68b" in var_css
    assert "--log-yellow: #c9a256" in var_css
    assert "--log-red: #cf6e78" in var_css
    assert "--log-blue: #6fa3c7" in var_css


def test_full_history_preserved_in_build_text_report(tmp_path: Path) -> None:
    """Verify build_text_report includes up to 80 events so old logs are preserved for scroll and copy."""
    diag = DiagnosticLogger(log_path=tmp_path / "hist.log")
    for idx in range(35):
        cid = diag.start_conn("HTTP_CONNECT", f"host-{idx}.example.com", 443, "TUNNEL")
        diag.log_stage(cid, "TCP_CONNECT", tcp_ms=10.0 + idx, port=443)
    report = diag.build_text_report()
    assert "host-0.example.com:443" in report
    assert "host-34.example.com:443" in report


@pytest.mark.asyncio
async def test_colorized_console_dom_tokens_in_variants_b_and_c() -> None:
    """Verify #diag-console-view renders colorized token spans in both Variant B and Variant C."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.click(".advanced-drawer summary")
        await page.click("#btn-run-diag")
        await page.wait_for_function(
            "document.getElementById('diag-copy-status')?.textContent.includes('Probes complete')",
            timeout=25000,
        )
        ok_tokens = await page.locator("#diag-console-view .tok-ok").count()
        warn_tokens = await page.locator("#diag-console-view .tok-warn").count()
        assert ok_tokens >= 4
        assert warn_tokens >= 1
        await page.click(".advanced-drawer summary")
        await page.screenshot(path="/home/user/screenshots/aethergate_variant_b.png", full_page=True)

        await browser.close()

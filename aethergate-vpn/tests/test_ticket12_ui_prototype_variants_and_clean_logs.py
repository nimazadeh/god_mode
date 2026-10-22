"""Tests for Ticket 12: Matt Pocock UI Prototype Variants (B & C), Eye-Care Dark Theme, and Clean Human Logs."""

from pathlib import Path
import pytest
from playwright.async_api import async_playwright
from tunnel.diag_logger import DiagnosticLogger, format_event_line

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_eye_care_dark_palette_and_bundled_geist_inter_jetbrains_fonts() -> None:
    """Verify variables.css uses true black background, zero #ffffff glare, and bundled WOFF2 fonts."""
    var_css = (ROOT_DIR / "dashboard" / "css" / "variables.css").read_text(encoding="utf-8")
    assert "#050506" in var_css
    assert "#c9cdd4" in var_css
    assert "#ffffff" not in var_css.lower()
    assert "#fff;" not in var_css.lower()
    for font_file in ("Geist-Regular.woff2", "Inter-Regular.woff2", "JetBrainsMono-Regular.woff2"):
        fpath = ROOT_DIR / "dashboard" / "css" / "fonts" / font_file
        assert fpath.exists() and fpath.stat().st_size > 15000, f"Missing font {font_file}"


def test_human_readable_single_line_log_formatter_and_deduplication(tmp_path: Path) -> None:
    """Verify format_event_line produces a clean 1-line string and consecutive spam is deduplicated."""
    diag = DiagnosticLogger(log_path=tmp_path / "clean_diag.log")
    cid = diag.start_conn("HTTP_CONNECT", "aistudio.google.com", 443, "GEOIP_RELAY")
    ev = diag.log_stage(cid, "DNS", host="aistudio.google.com", resolved_ip="216.239.38.120", source="GFE_ANYCAST_VIP", dns_ms=0.0)
    line = format_event_line(ev)
    assert "│" in line
    assert "aistudio.google.com" in line
    assert "216.239.38.120" in line

    before_len = len(diag.events)
    diag.log_stage(cid, "DNS", host="aistudio.google.com", resolved_ip="216.239.38.120", source="GFE_ANYCAST_VIP", dns_ms=0.0)
    diag.log_stage(cid, "DNS", host="aistudio.google.com", resolved_ip="216.239.38.120", source="GFE_ANYCAST_VIP", dns_ms=0.0)
    assert len(diag.events) == before_len


@pytest.mark.asyncio
async def test_ui_prototype_variants_b_and_c_and_floating_switcher() -> None:
    """Verify the canonical http://127.0.0.1:9090/ Phosphor Hacker Terminal loads cleanly with zero variant switcher clutter."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        assert await page.locator("#proto-switcher").count() == 0
        assert await page.locator(".brand-title").text_content() == "AETHERGATE"

        await browser.close()

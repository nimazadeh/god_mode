"""Tests for Ticket 19: Sticky Console Column Header (H1 Winner) & Scroll Position Preservation."""

import pytest
from playwright.async_api import async_playwright


@pytest.mark.asyncio
async def test_sticky_console_header_pins_on_scroll_and_preserves_scroll_top() -> None:
    """Verify #console-sticky-header stays pinned at top of #diag-console-view during scroll and polling."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.wait_for_selector("#console-sticky-header")

        hdr_text = await page.text_content("#console-sticky-header") or ""
        assert "TIMESTAMP" in hdr_text
        assert "STAGE" in hdr_text
        assert "TARGET / ENDPOINT" in hdr_text
        assert "TELEMETRY & ENGINE DETAILS" in hdr_text

        # Populate enough rows so #diag-console-view scrolls, then verify sticky top position
        await page.evaluate(
            """() => {
                const lines = ['=== AETHERGATE VPN DIAGNOSTIC REPORT ===', '--- LIVE SINGLE-LINE CONNECTION LOG (NEWEST FIRST) ---'];
                for (let i = 40; i >= 1; i--) {
                    const id = String(i).padStart(3, '0');
                    lines.push(`18:00:00.000 │ #${id} │ TLS_HANDSHAKE │ www.google.com:443         │ SNI_4BYTE_SHREDDER_6REC • 1545 B`);
                }
                window.AetherUI.renderConsole(lines.join('\\n'));
                document.getElementById('diag-console-view').scrollTop = 220;
            }"""
        )
        await page.wait_for_timeout(100)

        hdr_box = await page.locator("#console-sticky-header").bounding_box()
        con_box = await page.locator("#diag-console-view").bounding_box()
        assert hdr_box is not None and con_box is not None
        assert abs(hdr_box["y"] - con_box["y"]) <= 2.0

        # Trigger a re-render with updated report text and verify scrollTop is preserved
        scroll_after = await page.evaluate(
            """() => {
                const cur = window.AetherUI.lastReportText + '\\n18:00:01.000 │ #000 │ CLOSED_OK     │ www.google.com:443         │ tx=100 B • rx=200 B';
                window.AetherUI.renderConsole(cur);
                return document.getElementById('diag-console-view').scrollTop;
            }"""
        )
        assert scroll_after == 220

        await browser.close()

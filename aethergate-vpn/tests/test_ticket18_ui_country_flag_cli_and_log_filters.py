"""Tests for Ticket 18: Live Exit Country SVG Flag Badge, CLI Env Badge, and 1-Click Console Log Filters."""

import pytest
from playwright.async_api import async_playwright


@pytest.mark.asyncio
async def test_country_flag_svg_cli_badge_and_log_filter_pills() -> None:
    """Verify SVG flag badge, CLI ENV badge, and 1-click log filter pills in headless Chromium."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        flag_src = await page.get_attribute("#active-geoip-flag", "src") or ""
        assert flag_src.startswith("data:image/svg+xml")

        await page.click(".advanced-drawer summary")
        await page.click("#btn-run-diag")
        await page.wait_for_function(
            "document.getElementById('diag-copy-status')?.textContent.includes('Probes complete')",
            timeout=25000,
        )
        all_count = await page.locator("#diag-console-view .console-line").count()
        assert all_count >= 6

        await page.click("[data-log-filter='ERR']")
        err_count = await page.locator("#diag-console-view .console-line").count()
        assert err_count < all_count

        await page.click("[data-log-filter='ALL']")
        restored_count = await page.locator("#diag-console-view .console-line").count()
        assert restored_count == all_count

        await browser.close()

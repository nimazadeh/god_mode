"""End-to-end Playwright Chromium visual, responsive iPhone, and interactive tests."""

from __future__ import annotations

from pathlib import Path
import socket
import threading
import time
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from vault.api import create_app


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_playwright_desktop_and_iphone_responsive_ui_and_workflows(
    tmp_path: Path,
) -> None:
    """Verify desktop and Apple iPhone layouts, zero overlap, receipt approval, and license issue."""
    db_path = tmp_path / "e2e_vault.db"
    app = create_app(database_path=db_path)
    port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            # 1. Desktop viewport (1440x900)
            desktop_ctx = browser.new_context(
                viewport={"width": 1440, "height": 900}
            )
            page = desktop_ctx.new_page()
            page.goto(base_url, wait_until="networkidle")
            page.wait_for_selector("#vault-table-body tr.data-row")

            body_text = page.locator("body").inner_text()
            assert "undefined" not in body_text
            assert "NaN" not in body_text
            assert "سپهر فایل" in body_text

            # Verify Linear Light-Mode background color and zero horizontal overflow
            layout_check = page.evaluate(
                """() => {
                    const doc = document.documentElement;
                    const bodyBg = window.getComputedStyle(document.body).backgroundColor;
                    const topbarRect = document.querySelector('.topbar').getBoundingClientRect();
                    const mainRect = document.querySelector('#main-workspace').getBoundingClientRect();
                    return {
                        overflowX: doc.scrollWidth > doc.clientWidth,
                        bodyBg: bodyBg,
                        topbarBottom: topbarRect.bottom,
                        mainTop: mainRect.top
                    };
                }"""
            )
            assert layout_check["overflowX"] is False
            assert layout_check["bodyBg"] == "rgb(247, 248, 249)"
            assert layout_check["mainTop"] >= layout_check["topbarBottom"] - 1

            # Click one-click approve on the first pending receipt
            initial_pending = int(
                page.locator("#kpi-pending-receipts").inner_text()
            )
            approve_btn = page.locator(
                "#vault-table-body button.btn-success"
            ).first
            approve_btn.click()
            page.wait_for_timeout(300)
            updated_pending = int(
                page.locator("#kpi-pending-receipts").inner_text()
            )
            assert updated_pending == initial_pending - 1

            # Issue an instant watermarked PDF license from the sidebar form
            initial_licenses = int(
                page.locator("#kpi-total-licenses").inner_text()
            )
            page.fill("#issue-student-name", "آرمان حسینی")
            page.fill("#issue-student-phone", "09120001122")
            page.click("#btn-submit-issue")
            page.wait_for_timeout(300)
            after_issue_licenses = int(
                page.locator("#kpi-total-licenses").inner_text()
            )
            assert after_issue_licenses == initial_licenses + 1

            # Test Telegram bot simulator button
            page.click('button.tg-cmd-btn[data-cmd="/catalog"]')
            page.wait_for_timeout(250)
            tg_text = page.locator("#telegram-bot-output").inner_text()
            assert "پکیج کامل" in tg_text

            desktop_ctx.close()

            # 2. Apple iPhone viewport (390x844)
            iphone_ctx = browser.new_context(
                viewport={"width": 390, "height": 844},
                is_mobile=True,
                has_touch=True,
            )
            mobile_page = iphone_ctx.new_page()
            mobile_page.goto(base_url, wait_until="networkidle")
            mobile_page.wait_for_selector("#vault-table-body tr.data-row")

            mobile_metrics = mobile_page.evaluate(
                """() => {
                    const doc = document.documentElement;
                    const firstRow = document.querySelector('#vault-table-body tr.data-row');
                    const rowDisplay = window.getComputedStyle(firstRow).display;
                    return {
                        overflowX: doc.scrollWidth > doc.clientWidth,
                        rowDisplay: rowDisplay
                    };
                }"""
            )
            assert mobile_metrics["overflowX"] is False
            assert mobile_metrics["rowDisplay"] == "flex"

            iphone_ctx.close()
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=3)

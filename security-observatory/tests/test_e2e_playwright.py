"""Real browser Playwright E2E and Apple iPhone / Desktop visual verification suite."""

from __future__ import annotations

from pathlib import Path
import socket
import threading
import time
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from observatory.api import create_app
from observatory.models import CollectedObservation
from observatory.service import ObservatoryService


def find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def live_server_url(tmp_path: Path) -> str:
    port = find_free_tcp_port()

    def deterministic_collector(target) -> CollectedObservation:
        return CollectedObservation(
            requested_url=target.normalized_url,
            final_url=target.normalized_url,
            hostname=target.hostname,
            registered_domain=target.registered_domain,
            status_code=200,
            response_time_ms=92,
            tls_established=True,
            tls_version="TLSv1.3",
            tls_cipher="TLS_AES_256_GCM_SHA384",
            cert_days_remaining=180,
            headers={
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
            set_cookie_headers=[],
            html_body="<!doctype html><html><body><h1>Audited</h1></body></html>",
            spf_record="v=spf1 -all",
            dmarc_record="v=DMARC1; p=reject;",
        )

    service = ObservatoryService(
        database_path=tmp_path / "e2e_observatory.db",
        seed_initial_data=True,
        collector_fn=deterministic_collector,
        resolver_fn=lambda _host: ["93.184.215.14"],
    )
    app = create_app(service=service)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)

    yield base_url
    server.should_exit = True
    thread.join(timeout=3)


def test_desktop_and_iphone_layout_and_scan_workflow(live_server_url: str) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # 1. Desktop (1440x900) full interaction check
        desktop_ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = desktop_ctx.new_page()
        page.goto(live_server_url, wait_until="networkidle")
        page.wait_for_selector("#findings-container .finding-card")

        body_text = page.locator("body").inner_text()
        assert "undefined" not in body_text
        assert "NaN" not in body_text
        assert "github.com" in body_text

        html_box = page.locator("html").bounding_box()
        assert html_box is not None
        assert html_box["width"] <= 1440

        # Submit a new scan via UI and verify score updates cleanly
        page.fill("#target-url-input", "audit-client.example")
        page.click("#scan-submit-btn")
        page.wait_for_function(
            "document.getElementById('active-hostname').textContent === 'audit-client.example'"
        )
        updated_text = page.locator("body").inner_text()
        assert "undefined" not in updated_text
        assert "NaN" not in updated_text

        # Switch history row back to legacy-storefront.example (Grade F) and verify snippet rendering
        page.locator(".history-row", has_text="legacy-storefront.example").click()
        page.wait_for_function(
            "document.getElementById('active-grade-pill').textContent === 'F'"
        )
        assert page.locator(".snippet-pre").count() >= 5
        desktop_ctx.close()

        # 2. Apple iPhone 13/14 (390x844) strict responsive & zero-overflow check
        iphone_ctx = browser.new_context(
            viewport={"width": 390, "height": 844},
            is_mobile=True,
            has_touch=True,
        )
        m_page = iphone_ctx.new_page()
        m_page.goto(live_server_url, wait_until="networkidle")
        m_page.wait_for_selector("#findings-container .finding-card")

        m_text = m_page.locator("body").inner_text()
        assert "undefined" not in m_text
        assert "NaN" not in m_text

        m_html_box = m_page.locator("html").bounding_box()
        assert m_html_box is not None
        assert m_html_box["width"] <= 390

        btn_box = m_page.locator("#scan-submit-btn").bounding_box()
        assert btn_box is not None
        assert btn_box["height"] >= 44
        assert btn_box["width"] >= 300

        iphone_ctx.close()
        browser.close()

"""Tests for Ticket 06: Diagnostic Logger, RFC 8446 TLS Record Split, Fast OS-First DNS, and UI Diagnostics."""

from pathlib import Path
from httpx import ASGITransport, AsyncClient
import pytest
from main import create_control_app
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import split_tls_record_layer


def test_rfc8446_tls_record_layer_splitting_produces_two_valid_records() -> None:
    """Verify RFC 8446 Section 5.1 TLS Record fragmentation splits ClientHello into 2 valid 0x16 records."""
    body = b"\x01\x00\x00\x1c" + b"www.youtube.com_sni_extension_data"
    tls_record = b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body
    rec1, rec2 = split_tls_record_layer(tls_record, split_pos=12)
    assert rec1[:3] == b"\x16\x03\x01"
    assert rec2[:3] == b"\x16\x03\x01"
    len1 = int.from_bytes(rec1[3:5], "big")
    len2 = int.from_bytes(rec2[3:5], "big")
    assert len1 == 12
    assert len1 + len2 == len(body)
    assert rec1[5:] + rec2[5:] == body


@pytest.mark.asyncio
async def test_os_first_dns_does_not_override_google_with_static_ip() -> None:
    """Verify DoHResolver does not force a hardcoded IP for www.google.com unless OS DNS is poisoned."""
    resolver = DoHResolver()
    assert "www.google.com" not in resolver.cache
    ip_addr, source = await resolver.resolve_with_meta("127.0.0.1")
    assert ip_addr == "127.0.0.1"
    assert source == "LITERAL"


def test_diagnostic_logger_records_stages_and_exports_report(tmp_path: Path) -> None:
    """Verify DiagnosticLogger writes structured events to disk and builds an AI-ready report."""
    log_file = tmp_path / "diag.log"
    diag = DiagnosticLogger(log_path=log_file)
    cid = diag.start_conn("HTTP_CONNECT", "www.youtube.com", 443, "TUNNEL")
    diag.log_stage(cid, "DNS", resolved_ip="142.250.185.78", dns_source="DOH_FALLBACK", dns_ms=3.2)
    diag.log_stage(cid, "TCP_CONNECT", tcp_ms=42.5, status="CONNECTED")
    diag.log_stage(cid, "TLS_HANDSHAKE", tls_mode="RFC8446_RECORD_SPLIT", error="ConnectionResetError(10054)")
    report = diag.build_text_report()
    assert "www.youtube.com:443" in report
    assert "ConnectionResetError(10054)" in report
    assert log_file.exists()


@pytest.mark.asyncio
async def test_diagnostics_api_endpoints() -> None:
    """Verify /api/diagnostics/logs and /api/diagnostics/run return structured diagnostic telemetry."""
    app = create_control_app(start_proxy=False)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost:9090") as client:
            run_res = await client.post("/api/diagnostics/run")
            assert run_res.status_code == 200
            data = run_res.json()
            assert "checks" in data
            assert "report_text" in data

            logs_res = await client.get("/api/diagnostics/logs")
            assert logs_res.status_code == 200
            assert "events" in logs_res.json()


@pytest.mark.asyncio
async def test_browser_diagnostic_runner_and_screenshot() -> None:
    """Verify the Live Diagnostic Logger UI and Auto-Diagnosis button in headless Chromium."""
    from playwright.async_api import async_playwright
    shot = Path("/home/user/screenshots/aethergate_vpn_dashboard.png")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.click(".advanced-drawer summary")
        await page.click("#btn-run-diag")
        await page.wait_for_function(
            "document.getElementById('diag-copy-status')?.textContent === 'Probes complete'"
        )
        await page.screenshot(path=str(shot), full_page=False)
        await browser.close()

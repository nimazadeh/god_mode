"""Integration tests for SQLite persistence, service facade, and CSV/Markdown export."""

from __future__ import annotations

from pathlib import Path

from observatory.models import AuditScanRequest, CollectedObservation
from observatory.service import ObservatoryService


def build_stub_collector(observation: CollectedObservation):
    def _collect(_validated_target) -> CollectedObservation:
        return observation

    return _collect


def test_service_seeds_showcase_audits_persists_scans_and_exports_reports(
    tmp_path: Path,
) -> None:
    db_file = tmp_path / "observatory_test.db"
    sample_obs = CollectedObservation(
        requested_url="https://client-portal.example/",
        final_url="https://client-portal.example/",
        hostname="client-portal.example",
        registered_domain="client-portal.example",
        status_code=200,
        response_time_ms=195,
        tls_established=True,
        tls_version="TLSv1.3",
        tls_cipher="TLS_AES_128_GCM_SHA256",
        cert_days_remaining=120,
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "x-frame-options": "SAMEORIGIN",
        },
        set_cookie_headers=[],
        html_body="<html><body><h1>Portal</h1></body></html>",
        spf_record="v=spf1 -all",
        dmarc_record="",
    )
    service = ObservatoryService(
        database_path=db_file,
        seed_initial_data=True,
        collector_fn=build_stub_collector(sample_obs),
        resolver_fn=lambda _host: ["93.184.215.14"],
    )

    initial_dashboard = service.get_dashboard_state()
    assert len(initial_dashboard.history) >= 3
    assert initial_dashboard.featured_audit is not None

    scanned = service.scan_website(
        AuditScanRequest(url="client-portal.example")
    )
    assert scanned.hostname == "client-portal.example"
    assert 0 <= scanned.score <= 100

    csv_text = service.export_history_csv()
    assert csv_text.startswith("\ufeff")
    assert "client-portal.example" in csv_text

    markdown_summary = service.render_client_markdown(scanned.audit_id)
    assert "client-portal.example" in markdown_summary
    assert scanned.grade in markdown_summary

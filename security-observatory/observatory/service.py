"""Core application service facade coordinating validation, passive scan, and storage."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from observatory.analyzer import assess_security_posture
from observatory.collector import collect_passive_observation
from observatory.exporter import (
    export_audits_to_csv,
    export_single_audit_markdown,
)
from observatory.models import (
    AuditReport,
    AuditScanRequest,
    CollectedObservation,
    DashboardKpis,
    DashboardState,
    ValidatedTarget,
)
from observatory.storage import ObservatoryRepository
from observatory.target_guard import normalize_and_validate_target


class ObservatoryService:
    """High-level facade isolating HTTP/CLI adapters from collection and SQLite internals."""

    def __init__(
        self,
        database_path: str | Path,
        seed_initial_data: bool = True,
        collector_fn: Callable[[ValidatedTarget], CollectedObservation] | None = None,
        resolver_fn: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.repository = ObservatoryRepository(database_path)
        self._collector_fn = collector_fn or collect_passive_observation
        self._resolver_fn = resolver_fn
        if seed_initial_data and self.repository.count_audits() == 0:
            self._seed_reference_profiles()

    def _seed_reference_profiles(self) -> None:
        """Populate three comparative baseline profiles so the initial UI demonstrates A+, B, and F postures."""
        seed_observations = [
            CollectedObservation(
                requested_url="http://legacy-storefront.example/",
                final_url="http://legacy-storefront.example/",
                hostname="legacy-storefront.example",
                registered_domain="legacy-storefront.example",
                status_code=200,
                response_time_ms=480,
                tls_established=False,
                headers={
                    "server": "Apache/2.4.41 (Ubuntu)",
                    "x-powered-by": "PHP/7.4.3",
                },
                set_cookie_headers=["PHPSESSID=demo_session_placeholder; Path=/"],
                html_body=(
                    '<html><body><form action="http://legacy-storefront.example/login">'
                    '<input type="password" name="pw"></form>'
                    '<a href="https://vendor.example" target="_blank">Vendor</a></body></html>'
                ),
                spf_record="",
                dmarc_record="",
            ),
            CollectedObservation(
                requested_url="https://python.org/",
                final_url="https://www.python.org/",
                hostname="www.python.org",
                registered_domain="python.org",
                status_code=200,
                response_time_ms=215,
                tls_established=True,
                tls_version="TLSv1.3",
                tls_cipher="TLS_AES_128_GCM_SHA256",
                cert_days_remaining=64,
                headers={
                    "strict-transport-security": "max-age=315360000; includeSubDomains; preload",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "server": "nginx",
                },
                set_cookie_headers=[],
                html_body="<!doctype html><html><body><h1>Python</h1></body></html>",
                spf_record="v=spf1 include:_spf.google.com ~all",
                dmarc_record="v=DMARC1; p=reject;",
            ),
            CollectedObservation(
                requested_url="https://github.com/",
                final_url="https://github.com/",
                hostname="github.com",
                registered_domain="github.com",
                status_code=200,
                response_time_ms=138,
                tls_established=True,
                tls_version="TLSv1.3",
                tls_cipher="TLS_AES_128_GCM_SHA256",
                cert_days_remaining=39,
                headers={
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                    "content-security-policy": "default-src 'none'; base-uri 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src github.githubassets.com",
                    "x-frame-options": "deny",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "origin-when-cross-origin, strict-origin-when-cross-origin",
                    "permissions-policy": "interest-cohort=()",
                    "server": "github.com",
                },
                set_cookie_headers=[
                    "_gh_sess=seed_placeholder; Path=/; Secure; HttpOnly; SameSite=Lax"
                ],
                html_body='<!doctype html><html><body><a href="https://github.com/.well-known/security.txt">Security</a></body></html>',
                spf_record="v=spf1 ip4:192.30.252.0/22 ~all",
                dmarc_record="v=DMARC1; p=quarantine; sp=reject;",
            ),
        ]
        for obs in seed_observations:
            graded = assess_security_posture(obs)
            self.repository.save_audit(graded)

    def get_health_status(self, version: str) -> dict:
        return {
            "status": "ok",
            "version": version,
            "total_scans": self.repository.count_audits(),
        }

    def scan_website(self, payload: AuditScanRequest) -> AuditReport:
        """Validate target against SSRF rules, collect passive telemetry, score, and persist."""
        validated = normalize_and_validate_target(
            payload.url,
            resolver=self._resolver_fn,
        )
        observation = self._collector_fn(validated)
        graded = assess_security_posture(observation)
        return self.repository.save_audit(graded)

    def get_audit(self, audit_id: int) -> AuditReport:
        found = self.repository.get_audit_by_id(audit_id)
        if found is None:
            raise ValueError(f"گزارش ممیزی با شناسه {audit_id} یافت نشد.")
        return found

    def get_dashboard_state(self, selected_audit_id: int | None = None) -> DashboardState:
        history = self.repository.list_audit_summaries(limit=25)
        featured: AuditReport | None = None
        if selected_audit_id is not None:
            featured = self.repository.get_audit_by_id(selected_audit_id)
        if featured is None:
            featured = self.repository.get_latest_audit()

        total_scans = len(history)
        average_score = (
            round(sum(item.score for item in history) / total_scans)
            if total_scans > 0
            else 0
        )
        hardened_count = sum(1 for item in history if item.score >= 85)
        critical_count = sum(1 for item in history if item.score < 55)

        return DashboardState(
            kpis=DashboardKpis(
                total_scans=total_scans,
                average_score=average_score,
                hardened_sites_count=hardened_count,
                critical_sites_count=critical_count,
            ),
            featured_audit=featured,
            history=history,
        )

    def export_history_csv(self) -> str:
        history = self.repository.list_audit_summaries(limit=200)
        return export_audits_to_csv(history)

    def render_client_markdown(self, audit_id: int) -> str:
        report = self.get_audit(audit_id)
        return export_single_audit_markdown(report)

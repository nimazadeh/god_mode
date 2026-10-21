"""Strict domain models for passive security observation and posture grading."""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


ControlStatus = Literal["pass", "warn", "fail"]
PostureGrade = Literal["A+", "A", "B", "C", "D", "F"]


class ValidatedTarget(BaseModel):
    """Normalized public web target cleared by the Anti-SSRF guard."""

    normalized_url: str
    scheme: str
    hostname: str
    registered_domain: str
    port: int
    resolved_ips: list[str] = Field(default_factory=list)


class CollectedObservation(BaseModel):
    """Read-only HTTP, TLS, HTML surface, and DNS telemetry for one target."""

    requested_url: str
    final_url: str
    hostname: str
    registered_domain: str
    status_code: int
    response_time_ms: int
    tls_established: bool
    tls_version: str = ""
    tls_cipher: str = ""
    cert_days_remaining: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    set_cookie_headers: list[str] = Field(default_factory=list)
    html_body: str = ""
    spf_record: str = ""
    dmarc_record: str = ""


class ControlFinding(BaseModel):
    """Single assessed security control with client explanation and fix snippet."""

    control_id: str
    category_fa: str
    title_fa: str
    status: ControlStatus
    earned_points: int
    max_points: int
    observed_value: str
    impact_fa: str
    remediation_title_fa: str
    remediation_snippet: str


class SurfaceHygieneSummary(BaseModel):
    """Passive HTML surface inspection counters."""

    mixed_content_urls: int = 0
    insecure_password_forms: int = 0
    unsafe_blank_links: int = 0
    has_security_txt_link: bool = False
    detected_stack: str = "نامشخص / مخفی‌شده"


class AuditReport(BaseModel):
    """Complete graded security posture report persisted in SQLite."""

    audit_id: int = 0
    target_url: str
    final_url: str
    hostname: str
    registered_domain: str
    scanned_at_iso: str
    status_code: int
    response_time_ms: int
    score: int
    grade: PostureGrade
    risk_label_fa: str
    tls_summary: str
    cert_days_remaining: int | None = None
    passed_count: int
    warning_count: int
    failed_count: int
    spf_present: bool
    dmarc_present: bool
    surface: SurfaceHygieneSummary
    findings: list[ControlFinding]


class AuditSummaryItem(BaseModel):
    """Compact row summary for the recent audits history table."""

    audit_id: int
    hostname: str
    target_url: str
    scanned_at_iso: str
    score: int
    grade: PostureGrade
    risk_label_fa: str
    passed_count: int
    warning_count: int
    failed_count: int
    tls_summary: str
    response_time_ms: int


class DashboardKpis(BaseModel):
    """Aggregate KPI telemetry across stored security posture audits."""

    total_scans: int
    average_score: int
    hardened_sites_count: int
    critical_sites_count: int


class DashboardState(BaseModel):
    """Full UI state returned to the Persian RTL Linear dashboard."""

    kpis: DashboardKpis
    featured_audit: AuditReport | None = None
    history: list[AuditSummaryItem] = Field(default_factory=list)


class AuditScanRequest(BaseModel):
    """User-submitted target website URL for passive posture assessment."""

    url: str = Field(..., min_length=3, max_length=512)

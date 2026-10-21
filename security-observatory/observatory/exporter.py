"""CSV and client-ready executive Markdown report exporters."""

from __future__ import annotations

import csv
import io

from observatory.models import AuditReport, AuditSummaryItem


def export_audits_to_csv(items: list[AuditSummaryItem]) -> str:
    """Serialize audit history with UTF-8 BOM so Microsoft Excel renders Persian cleanly."""
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "شناسه ممیزی",
            "دامنه وب‌سایت",
            "آدرس هدف",
            "امتیاز از ۱۰۰",
            "رتبه امنیتی",
            "وضعیت ریسک",
            "موارد ایمن",
            "هشدارها",
            "نقص‌های بحرانی",
            "وضعیت TLS",
            "زمان پاسخ (ms)",
            "تاریخ ثبت (UTC)",
        ]
    )
    for row in items:
        writer.writerow(
            [
                row.audit_id,
                row.hostname,
                row.target_url,
                row.score,
                row.grade,
                row.risk_label_fa,
                row.passed_count,
                row.warning_count,
                row.failed_count,
                row.tls_summary,
                row.response_time_ms,
                row.scanned_at_iso,
            ]
        )
    return buffer.getvalue()


def export_single_audit_markdown(report: AuditReport) -> str:
    """Format an executive Persian report suitable for sending directly to a client."""
    status_badge = {
        "pass": "ایمن",
        "warn": "نیازمند بهینه‌سازی",
        "fail": "نیازمند اصلاح فوری",
    }
    lines = [
        f"# گزارش ممیزی سلامت و پیکربندی امنیتی وب‌سایت: {report.hostname}",
        "",
        f"- **آدرس بررسی‌شده:** {report.final_url}",
        f"- **امتیاز کل سلامت امنیتی:** {report.score} از 100 (**رتبه {report.grade}** — {report.risk_label_fa})",
        f"- **وضعیت رمزنگاری نشست:** {report.tls_summary}",
        f"- **خلاصه شاخص‌ها:** {report.passed_count} ایمن | {report.warning_count} هشدار | {report.failed_count} نقص پیکربندی",
        "",
        "## جزئیات ۱۰ شاخص استاندارد امنیتی",
        "",
    ]
    for idx, finding in enumerate(report.findings, start=1):
        badge_label = status_badge.get(finding.status, finding.status)
        lines.append(
            f"### {idx}. {finding.title_fa} — [{badge_label} | {finding.earned_points}/{finding.max_points}]"
        )
        lines.append(f"- **مقدار مشاهده‌شده:** `{finding.observed_value}`")
        lines.append(f"- **تحلیل ریسک کسب‌وکار:** {finding.impact_fa}")
        if finding.status != "pass":
            lines.append(f"- **پیشنهاد مقاوم‌سازی ({finding.remediation_title_fa}):**")
            lines.append("```nginx")
            lines.append(finding.remediation_snippet)
            lines.append("```")
        lines.append("")
    return "\n".join(lines)

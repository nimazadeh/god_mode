"""CSV export formatter for PDF-Guard & Course Vault reports.

Prepending a UTF-8 Byte Order Mark (BOM) ensures Microsoft Excel on Windows
opens Persian student names, course titles, and Toman amounts cleanly.
"""

from __future__ import annotations

import csv
import io

from vault.models import VaultDashboardReport


def export_vault_records_to_csv(
    report: VaultDashboardReport,
    include_utf8_bom: bool = True,
) -> str:
    """Serialize issued licenses and card-to-card receipts into an Excel-ready CSV."""
    buffer = io.StringIO()
    if include_utf8_bom:
        buffer.write("\ufeff")

    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(
        [
            "Record Type",
            "License / Receipt Code",
            "Student Name",
            "Student Phone",
            "Telegram Handle",
            "Product Code",
            "Product Title",
            "Tier Type",
            "Amount (Toman)",
            "Status",
            "Watermark SHA-256 / Card Last4",
            "Timestamp (UTC)",
        ]
    )

    for lic in report.licenses:
        writer.writerow(
            [
                "FulfilledLicense",
                lic.license_code,
                lic.student_name,
                lic.student_phone,
                lic.telegram_handle,
                lic.product_code,
                lic.product_title,
                lic.tier_type.value,
                lic.price_paid_toman,
                "issued",
                lic.watermark_hash,
                lic.issued_at_iso,
            ]
        )

    for rec in report.receipts:
        writer.writerow(
            [
                "ReceiptSubmission",
                rec.tracking_code,
                rec.student_name,
                rec.student_phone,
                rec.telegram_handle,
                rec.product_code,
                rec.product_title,
                rec.tier_type.value,
                rec.amount_toman,
                rec.status.value,
                f"Card *{rec.card_last4}",
                rec.submitted_at_iso,
            ]
        )

    return buffer.getvalue()

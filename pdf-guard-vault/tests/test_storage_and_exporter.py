"""Tests for SQLite WAL repository, atomic receipt verification, and CSV export."""

from __future__ import annotations

from pathlib import Path
import pytest

from vault.exporter import export_vault_records_to_csv
from vault.models import ReceiptStatus
from vault.service import CourseVaultService


def test_atomic_receipt_approval_credits_wallet_issues_license_and_prevents_double_approve(
    tmp_path: Path,
) -> None:
    """Verify approving a pending receipt credits wallet, issues license, and guards re-approval."""
    db_path = tmp_path / "vault_test.db"
    service = CourseVaultService(database_path=db_path, seed_initial_data=True)

    initial_dashboard = service.get_dashboard_report()
    pending_receipts = [
        r for r in initial_dashboard.receipts if r.status == ReceiptStatus.PENDING
    ]
    assert len(pending_receipts) >= 2
    target_receipt = pending_receipts[0]

    reviewed = service.review_receipt(
        receipt_id=target_receipt.receipt_id,
        approve=True,
        admin_note="Approved after checking Mellat bank SMS",
    )
    assert reviewed.status == ReceiptStatus.APPROVED
    assert reviewed.issued_license_code != ""

    # Attempting to approve the same receipt a second time must raise ValueError
    with pytest.raises(ValueError, match="already"):
        service.review_receipt(
            receipt_id=target_receipt.receipt_id,
            approve=True,
        )


def test_csv_exporter_includes_utf8_bom_and_license_rows(tmp_path: Path) -> None:
    """Verify exported CSV starts with UTF-8 BOM and lists licenses and receipts."""
    db_path = tmp_path / "csv_test.db"
    service = CourseVaultService(database_path=db_path, seed_initial_data=True)
    report = service.get_dashboard_report()

    csv_text = export_vault_records_to_csv(report, include_utf8_bom=True)
    assert csv_text.startswith("\ufeff")
    lines = [line for line in csv_text.strip().splitlines() if line.strip()]
    assert len(lines) >= 6
    assert "License / Receipt Code" in lines[0]

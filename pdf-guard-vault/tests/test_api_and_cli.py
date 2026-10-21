"""Integration tests for FastAPI HTTP endpoints, PDF download, Telegram bot simulator, and CLI."""

from __future__ import annotations

from pathlib import Path
import httpx
import pytest

from main import run_cli_one_shot
from vault.api import create_app


@pytest.mark.asyncio
async def test_fastapi_vault_endpoints_receipt_review_and_live_pdf_download(
    tmp_path: Path,
) -> None:
    """Verify health, dashboard, receipt approval, instant license issuance, PDF download, and Telegram bot."""
    db_path = tmp_path / "api_vault.db"
    app = create_app(database_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        health_res = await client.get("/api/health")
        assert health_res.status_code == 200
        assert health_res.json()["status"] == "ok"

        dash_res = await client.get("/api/dashboard")
        assert dash_res.status_code == 200
        dash_data = dash_res.json()
        assert dash_data["summary"]["total_products"] >= 6
        assert dash_data["summary"]["pending_receipts_count"] >= 2

        pending_id = next(
            r["receipt_id"]
            for r in dash_data["receipts"]
            if r["status"] == "pending"
        )
        review_res = await client.post(
            f"/api/receipts/{pending_id}/review",
            json={"approve": True, "admin_note": "Verified bank receipt"},
        )
        assert review_res.status_code == 200
        review_data = review_res.json()
        assert review_data["reviewed"]["status"] == "approved"
        issued_code = review_data["reviewed"]["issued_license_code"]
        assert issued_code.startswith("LIC-")

        issue_res = await client.post(
            "/api/licenses/issue",
            json={
                "student_name": "مهدی کریمی",
                "student_phone": "09129998877",
                "telegram_handle": "@mahdi_k",
                "product_code": "KONKOOR-BIO-FULL",
            },
        )
        assert issue_res.status_code == 200
        new_license = issue_res.json()["license"]
        license_id = new_license["license_id"]

        pdf_res = await client.get(f"/api/licenses/{license_id}/download.pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF-1.4")
        assert b"09129998877" in pdf_res.content

        tg_res = await client.post(
            "/api/telegram/simulate",
            json={
                "command": "/catalog",
                "student_phone": "09129998877",
            },
        )
        assert tg_res.status_code == 200
        assert "پکیج" in tg_res.json()["bot_reply"]

        csv_res = await client.get("/api/export.csv")
        assert csv_res.status_code == 200
        assert "LIC-" in csv_res.text


@pytest.mark.asyncio
async def test_cli_one_shot_exports_csv_and_sample_pdf(tmp_path: Path) -> None:
    """Verify CLI --export-once writes both the CSV report and a sample watermarked PDF."""
    db_path = tmp_path / "cli_vault.db"
    csv_path = tmp_path / "vault_report.csv"
    pdf_path = tmp_path / "sample_watermarked.pdf"

    exit_code = await run_cli_one_shot(
        database_path=db_path,
        output_csv=csv_path,
        output_pdf=pdf_path,
    )
    assert exit_code == 0
    assert csv_path.exists()
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-1.4")

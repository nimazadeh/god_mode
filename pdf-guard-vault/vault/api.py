"""FastAPI HTTP transport adapter for PDF-Guard & Course Vault.

Delegates all operations strictly to CourseVaultService so the HTTP layer
never couples to SQLite queries or PDF byte-stream generation internals.
"""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from vault.constants import APP_TITLE, VAULT_VERSION
from vault.models import (
    LicenseIssueRequest,
    ReceiptReviewRequest,
    ReceiptSubmissionCreate,
    TelegramSimulateRequest,
)
from vault.service import CourseVaultService


def create_app(
    database_path: str | Path | None = None,
    service: CourseVaultService | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    project_root = Path(__file__).resolve().parent.parent
    resolved_db_path = (
        Path(database_path)
        if database_path is not None
        else project_root / "data" / "vault.db"
    )
    active_service = service or CourseVaultService(
        database_path=resolved_db_path,
        seed_initial_data=True,
    )

    app = FastAPI(
        title=APP_TITLE,
        version=VAULT_VERSION,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.add_middleware(GZipMiddleware, minimum_size=500)
    app.state.vault_service = active_service

    @app.get("/api/health")
    async def get_health() -> dict:
        """Return service health and version metadata."""
        return active_service.get_health_status(version=VAULT_VERSION)

    @app.get("/api/dashboard")
    async def get_dashboard() -> dict:
        """Return the complete dashboard report (KPIs, licenses, receipts, products)."""
        report = active_service.get_dashboard_report()
        return report.model_dump()

    @app.post("/api/receipts")
    async def submit_receipt(payload: ReceiptSubmissionCreate) -> dict:
        """Submit a new student card-to-card receipt for verification."""
        try:
            created = active_service.submit_student_receipt(payload)
            report = active_service.get_dashboard_report()
            return {
                "receipt": created.model_dump(),
                "dashboard": report.model_dump(),
            }
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/api/receipts/{receipt_id}/review")
    async def review_receipt(
        receipt_id: int,
        payload: ReceiptReviewRequest,
    ) -> dict:
        """Approve or reject a pending card-to-card receipt atomically."""
        try:
            reviewed = active_service.review_receipt(
                receipt_id=receipt_id,
                approve=payload.approve,
                admin_note=payload.admin_note,
            )
            report = active_service.get_dashboard_report()
            return {
                "reviewed": reviewed.model_dump(),
                "dashboard": report.model_dump(),
            }
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/api/licenses/issue")
    async def issue_license(payload: LicenseIssueRequest) -> dict:
        """Issue an instant watermarked PDF license for a student and product."""
        try:
            issued = active_service.issue_instant_license(payload)
            report = active_service.get_dashboard_report()
            return {
                "license": issued.model_dump(),
                "dashboard": report.model_dump(),
            }
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/api/licenses/{license_id}/download.pdf")
    async def download_watermarked_pdf(license_id: int) -> Response:
        """Generate and stream the personalized 3-layer watermarked PDF file."""
        try:
            filename, pdf_bytes = (
                active_service.generate_watermarked_pdf_for_license(license_id)
            )
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers=headers,
        )

    @app.post("/api/telegram/simulate")
    async def simulate_telegram(payload: TelegramSimulateRequest) -> dict:
        """Simulate a Telegram bot command against the live course vault."""
        return active_service.simulate_telegram_bot_command(payload)

    @app.get("/api/export.csv")
    async def download_vault_csv() -> PlainTextResponse:
        """Export all licenses and receipts as an Excel-compatible UTF-8 BOM CSV."""
        csv_text = active_service.export_dashboard_csv()
        headers = {
            "Content-Disposition": (
                'attachment; filename="pdf-guard-vault-report.csv"'
            )
        }
        return PlainTextResponse(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers=headers,
        )

    web_dir = project_root / "web"
    if web_dir.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(web_dir)),
            name="web_assets",
        )

        @app.get("/")
        async def serve_dashboard() -> FileResponse:
            """Serve the Persian RTL Linear Light-Mode web application shell."""
            return FileResponse(str(web_dir / "index.html"))

    return app

"""FastAPI HTTP transport adapter for Sepahr Security Observatory."""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from observatory.constants import APP_TITLE, OBSERVATORY_VERSION
from observatory.models import AuditScanRequest
from observatory.service import ObservatoryService


def create_app(
    database_path: str | Path | None = None,
    service: ObservatoryService | None = None,
) -> FastAPI:
    """Create and wire the FastAPI web application."""
    project_root = Path(__file__).resolve().parent.parent
    resolved_db = (
        Path(database_path)
        if database_path is not None
        else project_root / "data" / "observatory.db"
    )
    active_service = service or ObservatoryService(
        database_path=resolved_db,
        seed_initial_data=True,
    )

    app = FastAPI(
        title=APP_TITLE,
        version=OBSERVATORY_VERSION,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.add_middleware(GZipMiddleware, minimum_size=500)
    app.state.observatory_service = active_service

    @app.get("/api/health")
    async def get_health() -> dict:
        return active_service.get_health_status(version=OBSERVATORY_VERSION)

    @app.get("/api/dashboard")
    async def get_dashboard(audit_id: int | None = None) -> dict:
        state = active_service.get_dashboard_state(selected_audit_id=audit_id)
        return state.model_dump()

    @app.get("/api/audits/{audit_id}")
    async def get_single_audit(audit_id: int) -> dict:
        try:
            report = active_service.get_audit(audit_id)
            return report.model_dump()
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get("/api/audits/{audit_id}/report.md")
    async def get_audit_markdown(audit_id: int) -> PlainTextResponse:
        try:
            md_text = active_service.render_client_markdown(audit_id)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        headers = {
            "Content-Disposition": (
                f'attachment; filename="security-audit-{audit_id}.md"'
            )
        }
        return PlainTextResponse(
            content=md_text,
            media_type="text/markdown; charset=utf-8",
            headers=headers,
        )

    @app.post("/api/scan")
    async def scan_target_website(payload: AuditScanRequest) -> dict:
        try:
            report = active_service.scan_website(payload)
            state = active_service.get_dashboard_state(
                selected_audit_id=report.audit_id
            )
            return {
                "audit": report.model_dump(),
                "dashboard": state.model_dump(),
            }
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/api/export.csv")
    async def export_csv() -> PlainTextResponse:
        csv_text = active_service.export_history_csv()
        headers = {
            "Content-Disposition": (
                'attachment; filename="sepahr-security-audits.csv"'
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
        async def serve_index() -> FileResponse:
            return FileResponse(str(web_dir / "index.html"))

    return app

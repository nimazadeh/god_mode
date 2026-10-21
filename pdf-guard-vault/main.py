"""CLI entrypoint and web server launcher for PDF-Guard & Course Vault."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import uvicorn

from vault.api import create_app
from vault.constants import (
    DEFAULT_SERVER_HOST,
    DEFAULT_SERVER_PORT,
    VAULT_VERSION,
)
from vault.service import CourseVaultService


async def run_cli_one_shot(
    database_path: str | Path,
    output_csv: str | Path,
    output_pdf: str | Path | None = None,
) -> int:
    """Export the vault CSV report and a sample watermarked PDF from the CLI."""
    service = CourseVaultService(
        database_path=database_path,
        seed_initial_data=True,
    )
    csv_text = service.export_dashboard_csv()
    csv_target = Path(output_csv)
    csv_target.parent.mkdir(parents=True, exist_ok=True)
    csv_target.write_text(csv_text, encoding="utf-8")

    if output_pdf is not None:
        report = service.get_dashboard_report()
        first_license_id = report.licenses[0].license_id
        _, pdf_bytes = service.generate_watermarked_pdf_for_license(
            first_license_id
        )
        pdf_target = Path(output_pdf)
        pdf_target.parent.mkdir(parents=True, exist_ok=True)
        pdf_target.write_bytes(pdf_bytes)

    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=f"PDF-Guard & Course Vault v{VAULT_VERSION}"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_SERVER_HOST,
        help="Host interface to bind the web server",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_SERVER_PORT,
        help="TCP port for the web server",
    )
    parser.add_argument(
        "--db",
        default="data/vault.db",
        help="Path to the SQLite WAL database file",
    )
    parser.add_argument(
        "--export-once",
        action="store_true",
        help="Export CSV and sample watermarked PDF once and exit",
    )
    parser.add_argument(
        "--out",
        default="data/pdf-guard-report.csv",
        help="Output CSV path when running with --export-once",
    )
    parser.add_argument(
        "--sample-pdf",
        default="data/sample-watermarked.pdf",
        help="Output sample PDF path when running with --export-once",
    )
    return parser


def main() -> None:
    """Parse CLI arguments and either run a one-shot export or start Uvicorn."""
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.export_once:
        asyncio.run(
            run_cli_one_shot(
                database_path=args.db,
                output_csv=args.out,
                output_pdf=args.sample_pdf,
            )
        )
        return

    app = create_app(database_path=args.db)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

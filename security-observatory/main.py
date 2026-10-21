"""Unified CLI and Uvicorn launcher for Sepahr Security Observatory."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import uvicorn

from observatory.api import create_app
from observatory.constants import DEFAULT_HOST, DEFAULT_PORT
from observatory.models import AuditScanRequest
from observatory.service import ObservatoryService


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sepahr Security Observatory — Passive Web Security Posture Auditor"
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP port to listen on",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Optional custom SQLite database file path",
    )
    parser.add_argument(
        "--scan",
        default=None,
        help="Run a one-shot passive posture scan from CLI and print summary",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    project_root = Path(__file__).resolve().parent
    db_path = (
        Path(args.db)
        if args.db is not None
        else project_root / "data" / "observatory.db"
    )

    if args.scan:
        service = ObservatoryService(database_path=db_path)
        report = service.scan_website(AuditScanRequest(url=args.scan))
        print(
            f"[{report.grade}] {report.hostname} -> {report.score}/100 ({report.risk_label_fa})"
        )
        return 0

    app = create_app(database_path=db_path)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())

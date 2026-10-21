"""SQLite WAL repository for persisted security posture audits."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from observatory.models import AuditReport, AuditSummaryItem


class ObservatoryRepository:
    """Persist and query completed security posture reports in SQLite WAL mode."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA synchronous=NORMAL;")
        return connection

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    scanned_at_iso TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    risk_label_fa TEXT NOT NULL,
                    passed_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    tls_summary TEXT NOT NULL,
                    response_time_ms INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )

    def count_audits(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS cnt FROM audits").fetchone()
            return int(row["cnt"]) if row else 0

    def save_audit(self, report: AuditReport) -> AuditReport:
        """Insert a completed report and return the persisted copy with its SQLite ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audits (
                    hostname,
                    target_url,
                    scanned_at_iso,
                    score,
                    grade,
                    risk_label_fa,
                    passed_count,
                    warning_count,
                    failed_count,
                    tls_summary,
                    response_time_ms,
                    report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.hostname,
                    report.target_url,
                    report.scanned_at_iso,
                    report.score,
                    report.grade,
                    report.risk_label_fa,
                    report.passed_count,
                    report.warning_count,
                    report.failed_count,
                    report.tls_summary,
                    report.response_time_ms,
                    report.model_dump_json(),
                ),
            )
            inserted_id = int(cursor.lastrowid)
            persisted = report.model_copy(update={"audit_id": inserted_id})
            connection.execute(
                "UPDATE audits SET report_json = ? WHERE id = ?",
                (persisted.model_dump_json(), inserted_id),
            )

        loaded = self.get_audit_by_id(inserted_id)
        if loaded is None:
            raise RuntimeError("خطا در بازیابی گزارش ذخیره‌شده از دیتابیس.")
        return loaded

    def get_audit_by_id(self, audit_id: int) -> AuditReport | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM audits WHERE id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return None
            return AuditReport.model_validate_json(row["report_json"])

    def get_latest_audit(self) -> AuditReport | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM audits ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return AuditReport.model_validate_json(row["report_json"])

    def list_audit_summaries(self, limit: int = 25) -> list[AuditSummaryItem]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    hostname,
                    target_url,
                    scanned_at_iso,
                    score,
                    grade,
                    risk_label_fa,
                    passed_count,
                    warning_count,
                    failed_count,
                    tls_summary,
                    response_time_ms
                FROM audits
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            AuditSummaryItem(
                audit_id=int(row["id"]),
                hostname=str(row["hostname"]),
                target_url=str(row["target_url"]),
                scanned_at_iso=str(row["scanned_at_iso"]),
                score=int(row["score"]),
                grade=json.loads(json.dumps(row["grade"])),
                risk_label_fa=str(row["risk_label_fa"]),
                passed_count=int(row["passed_count"]),
                warning_count=int(row["warning_count"]),
                failed_count=int(row["failed_count"]),
                tls_summary=str(row["tls_summary"]),
                response_time_ms=int(row["response_time_ms"]),
            )
            for row in rows
        ]

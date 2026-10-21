"""SQLite WAL repository for educational products, student wallets, receipts, and licenses.

Write-Ahead Logging (WAL) and partial covering indexes ensure that approving
card-to-card receipts and issuing watermarked PDF licenses execute atomically
without locking concurrent dashboard reads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from vault.models import (
    CourseProduct,
    FulfilledLicense,
    ProductTierType,
    ReceiptStatus,
    ReceiptSubmission,
    StudentAccount,
    WatermarkStamp,
)


class VaultRepository:
    """Persist products, students, card-to-card receipts, and watermarked PDF licenses."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a WAL-mode SQLite connection with foreign keys and row factory."""
        connection = sqlite3.connect(str(self._database_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA synchronous=NORMAL;")
        connection.execute("PRAGMA temp_store=MEMORY;")
        connection.execute("PRAGMA foreign_keys=ON;")
        return connection

    def _initialize_schema(self) -> None:
        """Create products, students, receipts, and licenses tables with covering indexes."""
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS products (
                    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tier_type TEXT NOT NULL,
                    price_toman INTEGER NOT NULL,
                    page_count INTEGER NOT NULL DEFAULT 3,
                    description TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS students (
                    student_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    phone TEXT NOT NULL UNIQUE,
                    telegram_handle TEXT NOT NULL DEFAULT '',
                    wallet_balance_toman INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tracking_code TEXT NOT NULL,
                    student_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    amount_toman INTEGER NOT NULL,
                    card_last4 TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    submitted_at_iso TEXT NOT NULL,
                    reviewed_at_iso TEXT NOT NULL DEFAULT '',
                    admin_note TEXT NOT NULL DEFAULT '',
                    issued_license_code TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (student_id) REFERENCES students(student_id),
                    FOREIGN KEY (product_id) REFERENCES products(product_id)
                );

                CREATE INDEX IF NOT EXISTS idx_receipts_status
                    ON receipts(status, receipt_id DESC);

                CREATE TABLE IF NOT EXISTS licenses (
                    license_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_code TEXT NOT NULL UNIQUE,
                    student_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    price_paid_toman INTEGER NOT NULL,
                    watermark_hash TEXT NOT NULL,
                    diagonal_text TEXT NOT NULL,
                    footer_text TEXT NOT NULL,
                    issued_at_iso TEXT NOT NULL,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (student_id) REFERENCES students(student_id),
                    FOREIGN KEY (product_id) REFERENCES products(product_id)
                );

                CREATE INDEX IF NOT EXISTS idx_licenses_issued
                    ON licenses(license_id DESC);
                """
            )

    def count_products(self) -> int:
        """Return total number of products stored in the catalog."""
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS cnt FROM products").fetchone()
            return int(row["cnt"]) if row else 0

    def upsert_product(
        self,
        code: str,
        title: str,
        category: str,
        tier_type: ProductTierType,
        price_toman: int,
        page_count: int = 3,
        description: str = "",
    ) -> CourseProduct:
        """Insert or update a CourseProduct by its canonical code."""
        clean_code = code.strip().upper()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO products (
                    code, title, category, tier_type, price_toman, page_count, description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(code) DO UPDATE SET
                    title = excluded.title,
                    category = excluded.category,
                    tier_type = excluded.tier_type,
                    price_toman = excluded.price_toman,
                    page_count = excluded.page_count,
                    description = excluded.description
                """,
                (
                    clean_code,
                    title.strip(),
                    category.strip(),
                    tier_type.value,
                    price_toman,
                    page_count,
                    description.strip(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM products WHERE code = ?",
                (clean_code,),
            ).fetchone()
            return self._row_to_product(row)

    def upsert_student(
        self,
        full_name: str,
        phone: str,
        telegram_handle: str = "",
        wallet_balance_toman: int = 0,
    ) -> StudentAccount:
        """Insert or update a StudentAccount by mobile phone number."""
        clean_phone = phone.strip()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO students (
                    full_name, phone, telegram_handle, wallet_balance_toman
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(phone) DO UPDATE SET
                    full_name = excluded.full_name,
                    telegram_handle = CASE
                        WHEN excluded.telegram_handle != '' THEN excluded.telegram_handle
                        ELSE students.telegram_handle
                    END
                """,
                (
                    full_name.strip(),
                    clean_phone,
                    telegram_handle.strip(),
                    wallet_balance_toman,
                ),
            )
            row = connection.execute(
                "SELECT * FROM students WHERE phone = ?",
                (clean_phone,),
            ).fetchone()
            return self._row_to_student(row)

    def get_product_by_code(self, code: str) -> CourseProduct | None:
        """Look up a CourseProduct by its code."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM products WHERE code = ?",
                (code.strip().upper(),),
            ).fetchone()
            return self._row_to_product(row) if row else None

    def get_product_by_id(self, product_id: int) -> CourseProduct | None:
        """Look up a CourseProduct by primary key."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM products WHERE product_id = ?",
                (product_id,),
            ).fetchone()
            return self._row_to_product(row) if row else None

    def get_student_by_id(self, student_id: int) -> StudentAccount | None:
        """Look up a StudentAccount by primary key."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM students WHERE student_id = ?",
                (student_id,),
            ).fetchone()
            return self._row_to_student(row) if row else None

    def create_receipt(
        self,
        student_id: int,
        product_id: int,
        amount_toman: int,
        tracking_code: str,
        card_last4: str,
        status: ReceiptStatus = ReceiptStatus.PENDING,
        submitted_at_iso: str | None = None,
        admin_note: str = "",
        issued_license_code: str = "",
    ) -> ReceiptSubmission:
        """Insert a card-to-card ReceiptSubmission record."""
        created_iso = submitted_at_iso or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        reviewed_iso = created_iso if status != ReceiptStatus.PENDING else ""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO receipts (
                    tracking_code,
                    student_id,
                    product_id,
                    amount_toman,
                    card_last4,
                    status,
                    submitted_at_iso,
                    reviewed_at_iso,
                    admin_note,
                    issued_license_code
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tracking_code.strip(),
                    student_id,
                    product_id,
                    amount_toman,
                    card_last4.strip(),
                    status.value,
                    created_iso,
                    reviewed_iso,
                    admin_note.strip(),
                    issued_license_code.strip(),
                ),
            )
            receipt_id = int(cursor.lastrowid or 1)
        return self.get_receipt(receipt_id)  # type: ignore[return-value]

    def get_receipt(self, receipt_id: int) -> ReceiptSubmission | None:
        """Fetch a single hydrated ReceiptSubmission by ID."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    r.*,
                    s.full_name AS student_name,
                    s.phone AS student_phone,
                    s.telegram_handle AS telegram_handle,
                    p.code AS product_code,
                    p.title AS product_title,
                    p.tier_type AS tier_type
                FROM receipts r
                JOIN students s ON s.student_id = r.student_id
                JOIN products p ON p.product_id = r.product_id
                WHERE r.receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            return self._row_to_receipt(row) if row else None

    def create_license(
        self,
        student_id: int,
        product_id: int,
        price_paid_toman: int,
        stamp: WatermarkStamp,
        download_count: int = 1,
    ) -> FulfilledLicense:
        """Persist a new FulfilledLicense record."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO licenses (
                    license_code,
                    student_id,
                    product_id,
                    price_paid_toman,
                    watermark_hash,
                    diagonal_text,
                    footer_text,
                    issued_at_iso,
                    download_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stamp.license_code,
                    student_id,
                    product_id,
                    price_paid_toman,
                    stamp.watermark_hash,
                    stamp.diagonal_text,
                    stamp.footer_text,
                    stamp.issued_at_iso,
                    download_count,
                ),
            )
            license_id = int(cursor.lastrowid or 1)
        return self.get_license(license_id)  # type: ignore[return-value]

    def get_license(self, license_id: int) -> FulfilledLicense | None:
        """Fetch a single FulfilledLicense by ID."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    l.*,
                    s.full_name AS student_name,
                    s.phone AS student_phone,
                    s.telegram_handle AS telegram_handle,
                    p.code AS product_code,
                    p.title AS product_title,
                    p.category AS category,
                    p.tier_type AS tier_type,
                    p.page_count AS page_count
                FROM licenses l
                JOIN students s ON s.student_id = l.student_id
                JOIN products p ON p.product_id = l.product_id
                WHERE l.license_id = ?
                """,
                (license_id,),
            ).fetchone()
            return self._row_to_license(row) if row else None

    def increment_license_download(self, license_id: int) -> FulfilledLicense | None:
        """Increment download counter when a watermarked PDF is generated."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE licenses SET download_count = download_count + 1 WHERE license_id = ?",
                (license_id,),
            )
        return self.get_license(license_id)

    def complete_receipt_review_atomic(
        self,
        receipt_id: int,
        approve: bool,
        admin_note: str,
        reviewed_at_iso: str,
        stamp: WatermarkStamp | None,
    ) -> ReceiptSubmission:
        """Atomically update a pending receipt, credit surplus wallet balance, and issue license."""
        with self._connect() as connection:
            current_row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if current_row is None:
                raise ValueError(f"Receipt #{receipt_id} was not found.")
            if str(current_row["status"]) != ReceiptStatus.PENDING.value:
                raise ValueError(
                    f"Receipt #{receipt_id} has already been reviewed ({current_row['status']})."
                )

            student_id = int(current_row["student_id"])
            product_id = int(current_row["product_id"])
            amount_toman = int(current_row["amount_toman"])

            product_row = connection.execute(
                "SELECT price_toman FROM products WHERE product_id = ?",
                (product_id,),
            ).fetchone()
            product_price = int(product_row["price_toman"]) if product_row else amount_toman

            new_status = (
                ReceiptStatus.APPROVED.value
                if approve
                else ReceiptStatus.REJECTED.value
            )
            issued_code = stamp.license_code if (approve and stamp) else ""

            connection.execute(
                """
                UPDATE receipts
                SET status = ?,
                    reviewed_at_iso = ?,
                    admin_note = ?,
                    issued_license_code = ?
                WHERE receipt_id = ?
                """,
                (
                    new_status,
                    reviewed_at_iso,
                    admin_note.strip(),
                    issued_code,
                    receipt_id,
                ),
            )

            if approve and stamp is not None:
                surplus_toman = max(0, amount_toman - product_price)
                if surplus_toman > 0:
                    connection.execute(
                        """
                        UPDATE students
                        SET wallet_balance_toman = wallet_balance_toman + ?
                        WHERE student_id = ?
                        """,
                        (surplus_toman, student_id),
                    )
                connection.execute(
                    """
                    INSERT INTO licenses (
                        license_code,
                        student_id,
                        product_id,
                        price_paid_toman,
                        watermark_hash,
                        diagonal_text,
                        footer_text,
                        issued_at_iso,
                        download_count
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        stamp.license_code,
                        student_id,
                        product_id,
                        amount_toman,
                        stamp.watermark_hash,
                        stamp.diagonal_text,
                        stamp.footer_text,
                        stamp.issued_at_iso,
                    ),
                )

        return self.get_receipt(receipt_id)  # type: ignore[return-value]

    def list_products(self) -> list[CourseProduct]:
        """List all educational products ordered by product_id."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM products ORDER BY product_id ASC"
            ).fetchall()
            return [self._row_to_product(row) for row in rows]

    def list_students(self) -> list[StudentAccount]:
        """List all registered student accounts."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM students ORDER BY student_id ASC"
            ).fetchall()
            return [self._row_to_student(row) for row in rows]

    def list_receipts(self) -> list[ReceiptSubmission]:
        """List all card-to-card receipt submissions, newest first."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    r.*,
                    s.full_name AS student_name,
                    s.phone AS student_phone,
                    s.telegram_handle AS telegram_handle,
                    p.code AS product_code,
                    p.title AS product_title,
                    p.tier_type AS tier_type
                FROM receipts r
                JOIN students s ON s.student_id = r.student_id
                JOIN products p ON p.product_id = r.product_id
                ORDER BY
                    CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END ASC,
                    r.receipt_id DESC
                """
            ).fetchall()
            return [self._row_to_receipt(row) for row in rows]

    def list_licenses(self) -> list[FulfilledLicense]:
        """List all fulfilled PDF licenses, newest first."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    l.*,
                    s.full_name AS student_name,
                    s.phone AS student_phone,
                    s.telegram_handle AS telegram_handle,
                    p.code AS product_code,
                    p.title AS product_title,
                    p.category AS category,
                    p.tier_type AS tier_type,
                    p.page_count AS page_count
                FROM licenses l
                JOIN students s ON s.student_id = l.student_id
                JOIN products p ON p.product_id = l.product_id
                ORDER BY l.license_id DESC
                """
            ).fetchall()
            return [self._row_to_license(row) for row in rows]

    @staticmethod
    def _row_to_product(row: sqlite3.Row) -> CourseProduct:
        return CourseProduct(
            product_id=int(row["product_id"]),
            code=str(row["code"]),
            title=str(row["title"]),
            category=str(row["category"]),
            tier_type=ProductTierType(str(row["tier_type"])),
            price_toman=int(row["price_toman"]),
            page_count=int(row["page_count"]),
            description=str(row["description"]),
        )

    @staticmethod
    def _row_to_student(row: sqlite3.Row) -> StudentAccount:
        return StudentAccount(
            student_id=int(row["student_id"]),
            full_name=str(row["full_name"]),
            phone=str(row["phone"]),
            telegram_handle=str(row["telegram_handle"]),
            wallet_balance_toman=int(row["wallet_balance_toman"]),
        )

    @staticmethod
    def _row_to_receipt(row: sqlite3.Row) -> ReceiptSubmission:
        return ReceiptSubmission(
            receipt_id=int(row["receipt_id"]),
            tracking_code=str(row["tracking_code"]),
            student_id=int(row["student_id"]),
            student_name=str(row["student_name"]),
            student_phone=str(row["student_phone"]),
            telegram_handle=str(row["telegram_handle"]),
            product_id=int(row["product_id"]),
            product_code=str(row["product_code"]),
            product_title=str(row["product_title"]),
            tier_type=ProductTierType(str(row["tier_type"])),
            amount_toman=int(row["amount_toman"]),
            card_last4=str(row["card_last4"]),
            status=ReceiptStatus(str(row["status"])),
            submitted_at_iso=str(row["submitted_at_iso"]),
            reviewed_at_iso=str(row["reviewed_at_iso"]),
            admin_note=str(row["admin_note"]),
            issued_license_code=str(row["issued_license_code"]),
        )

    @staticmethod
    def _row_to_license(row: sqlite3.Row) -> FulfilledLicense:
        return FulfilledLicense(
            license_id=int(row["license_id"]),
            license_code=str(row["license_code"]),
            student_id=int(row["student_id"]),
            student_name=str(row["student_name"]),
            student_phone=str(row["student_phone"]),
            telegram_handle=str(row["telegram_handle"]),
            product_id=int(row["product_id"]),
            product_code=str(row["product_code"]),
            product_title=str(row["product_title"]),
            category=str(row["category"]),
            tier_type=ProductTierType(str(row["tier_type"])),
            price_paid_toman=int(row["price_paid_toman"]),
            page_count=int(row["page_count"]),
            watermark_hash=str(row["watermark_hash"]),
            diagonal_text=str(row["diagonal_text"]),
            footer_text=str(row["footer_text"]),
            issued_at_iso=str(row["issued_at_iso"]),
            download_count=int(row["download_count"]),
        )

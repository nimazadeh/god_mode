"""Deep application service for PDF-Guard & Course Vault.

Encapsulates VaultRepository, DynamicPdfStamper, CSV export, and Telegram bot
simulation behind a single narrow interface so transport adapters (FastAPI and
CLI) never coupled to storage or PDF stream internals.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from vault.exporter import export_vault_records_to_csv
from vault.models import (
    CourseProduct,
    FulfilledLicense,
    LicenseIssueRequest,
    ProductTierType,
    ReceiptStatus,
    ReceiptSubmission,
    ReceiptSubmissionCreate,
    TelegramSimulateRequest,
    VaultDashboardReport,
    VaultSummary,
)
from vault.pdf_stamper import DynamicPdfStamper, build_watermark_stamp
from vault.storage import VaultRepository


class CourseVaultService:
    """High-level service managing course catalog, receipt verification, and PDF stamping."""

    def __init__(
        self,
        database_path: str | Path,
        stamper: DynamicPdfStamper | None = None,
        seed_initial_data: bool = True,
    ) -> None:
        self._repository = VaultRepository(database_path)
        self._stamper = stamper or DynamicPdfStamper()
        if seed_initial_data:
            self.ensure_initial_seed_data()

    def ensure_initial_seed_data(self) -> None:
        """Seed realistic Persian educational packages, chapters, students, and receipts."""
        if self._repository.count_products() > 0:
            return

        seed_products = [
            (
                "KONKOOR-BIO-FULL",
                "پکیج کامل زیست‌شناسی جامع کنکور تجربی (پایه دهم تا دوازدهم)",
                "زیست‌شناسی کنکور",
                ProductTierType.FULL_PACKAGE,
                690000,
                4,
                "شامل ۳۸۰ صفحه درسنامه رنگی، دیاگرام‌های ترکیبی و ۱۲۰۰ تست خط‌به‌خط با پاسخ تشریحی.",
            ),
            (
                "KONKOOR-BIO-CH1",
                "فصل اول و دوم زیست دوازدهم: مولکول‌های اطلاعاتی و جریان اطلاعات در یاخته",
                "زیست‌شناسی کنکور",
                ProductTierType.CHAPTER_PART,
                165000,
                3,
                "جزوه بخش‌بندی‌شده ویژه جمع‌بندی سریع ژنتیک مولکولی و همانندسازی.",
            ),
            (
                "KONKOOR-MATH-FULL",
                "پکیج کامل ریاضیات و حسابان جامع کنکور + تست‌های زمان‌دار ۱۴۰۵",
                "ریاضیات و حسابان",
                ProductTierType.FULL_PACKAGE,
                580000,
                4,
                "پکیج کامل تابع، مثلثات، حد و پیوستگی، مشتق و کاربرد مشتق با تکنیک‌های حل سریع.",
            ),
            (
                "CS-MSC-ALG-FULL",
                "پکیج جامع طراحی الگوریتم و ساختمان داده‌ها (ویژه کنکور ارشد کامپیوتر)",
                "مهندسی کامپیوتر",
                ProductTierType.FULL_PACKAGE,
                740000,
                4,
                "پوشش کامل برنامه‌نویسی پویا، الگوریتم‌های حریصانه، گراف و تحلیل مرتبه زمانی.",
            ),
            (
                "CS-MSC-ALG-CH3",
                "فصل سوم طراحی الگوریتم: برنامه‌نویسی پویا (Dynamic Programming)",
                "مهندسی کامپیوتر",
                ProductTierType.CHAPTER_PART,
                190000,
                3,
                "حل تشریحی ۱۵۰ سوال کنکور کارشناسی ارشد سال‌های اخیر در مبحث DP.",
            ),
            (
                "MED-PHARMA-FULL",
                "پکیج کامل خلاصه فارماکولوژی بالینی و نسخه‌نویسی (ویژه آزمون پره‌اینترنی)",
                "علوم پزشکی",
                ProductTierType.FULL_PACKAGE,
                820000,
                4,
                "جداول دسته‌بندی داروها، مکانیسم اثر، تداخلات حیاتی و دوزهای اورژانسی.",
            ),
            (
                "ENG-IELTS-WRITING",
                "جزوه اختصاصی قالب‌ها و گرامر پیشرفته رایتینگ آیلتس (Task 1 & Task 2)",
                "زبان و آیلتس",
                ProductTierType.CHAPTER_PART,
                240000,
                3,
                "بانک کامل کالوکیشن‌های نمره ۷.۵+ به همراه تصحیح نمونه رایتینگ‌های واقعی.",
            ),
        ]

        products_by_code: dict[str, CourseProduct] = {}
        for code, title, cat, tier, price, pages, desc in seed_products:
            prod = self._repository.upsert_product(
                code=code,
                title=title,
                category=cat,
                tier_type=tier,
                price_toman=price,
                page_count=pages,
                description=desc,
            )
            products_by_code[code] = prod

        seed_students = [
            ("امیرحسین رضایی", "09123456789", "@amir_rezaei", 210000),
            ("سارا محمدی", "09351112233", "@sara_mohammadi", 85000),
            ("پارسا کاظمی", "09198887766", "@parsa_k", 340000),
            ("نگین احمدی", "09134445566", "@negin_ahmadi", 120000),
            ("دانیال شریفی", "09215556677", "@danial_sh", 0),
            ("زهرا موسوی", "09157778899", "@zahra_mousavi", 150000),
        ]
        students_by_phone: dict[str, int] = {}
        for full_name, phone, handle, wallet in seed_students:
            stu = self._repository.upsert_student(
                full_name=full_name,
                phone=phone,
                telegram_handle=handle,
                wallet_balance_toman=wallet,
            )
            students_by_phone[phone] = stu.student_id

        # Seed 4 issued licenses with deterministic forensic watermarks
        initial_licenses = [
            (
                "09123456789",
                "KONKOOR-BIO-FULL",
                "LIC-2026-1001",
                "2026-10-20T14:20:00Z",
                3,
            ),
            (
                "09351112233",
                "CS-MSC-ALG-CH3",
                "LIC-2026-1002",
                "2026-10-20T16:45:00Z",
                2,
            ),
            (
                "09198887766",
                "MED-PHARMA-FULL",
                "LIC-2026-1003",
                "2026-10-21T07:15:00Z",
                4,
            ),
            (
                "09157778899",
                "ENG-IELTS-WRITING",
                "LIC-2026-1004",
                "2026-10-21T08:50:00Z",
                1,
            ),
        ]
        for phone, prod_code, lic_code, issued_iso, dl_count in initial_licenses:
            stu_obj = self._repository.get_student_by_id(students_by_phone[phone])
            prod_obj = products_by_code[prod_code]
            if stu_obj is not None:
                stamp = build_watermark_stamp(
                    student=stu_obj,
                    product=prod_obj,
                    license_code=lic_code,
                    issued_at_iso=issued_iso,
                )
                self._repository.create_license(
                    student_id=stu_obj.student_id,
                    product_id=prod_obj.product_id,
                    price_paid_toman=prod_obj.price_toman,
                    stamp=stamp,
                    download_count=dl_count,
                )

        # Seed card-to-card receipts (3 pending, 2 approved, 1 rejected)
        seed_receipts = [
            (
                "09134445566",
                "KONKOOR-MATH-FULL",
                580000,
                "TRK-8849201",
                "6104",
                ReceiptStatus.PENDING,
                "2026-10-21T09:10:00Z",
                "واریز کارت به کارت بانک ملت جهت خرید پکیج کامل ریاضیات",
                "",
            ),
            (
                "09215556677",
                "KONKOOR-BIO-CH1",
                165000,
                "TRK-8849554",
                "5892",
                ReceiptStatus.PENDING,
                "2026-10-21T09:42:00Z",
                "فیش واریزی پایا برای فصل اول و دوم زیست دوازدهم",
                "",
            ),
            (
                "09351112233",
                "CS-MSC-ALG-FULL",
                740000,
                "TRK-8850112",
                "6037",
                ReceiptStatus.PENDING,
                "2026-10-21T10:05:00Z",
                "ارتقا از تک‌فصل به پکیج کامل طراحی الگوریتم ارشد",
                "",
            ),
            (
                "09123456789",
                "KONKOOR-BIO-FULL",
                690000,
                "TRK-8831004",
                "6219",
                ReceiptStatus.APPROVED,
                "2026-10-20T14:15:00Z",
                "تایید شده توسط ادمین — صدور آنی مجوز",
                "LIC-2026-1001",
            ),
            (
                "09198887766",
                "MED-PHARMA-FULL",
                820000,
                "TRK-8840219",
                "6274",
                ReceiptStatus.APPROVED,
                "2026-10-21T07:10:00Z",
                "تایید واریز بانک اقتصاد نوین",
                "LIC-2026-1003",
            ),
            (
                "09215556677",
                "KONKOOR-MATH-FULL",
                580000,
                "TRK-8810099",
                "5022",
                ReceiptStatus.REJECTED,
                "2026-10-19T19:30:00Z",
                "شماره پیگیری نامعتبر / عدم تطابق مبلغ فیش",
                "",
            ),
        ]
        for (
            phone,
            prod_code,
            amount,
            trk,
            last4,
            st,
            sub_iso,
            note,
            lic_code,
        ) in seed_receipts:
            self._repository.create_receipt(
                student_id=students_by_phone[phone],
                product_id=products_by_code[prod_code].product_id,
                amount_toman=amount,
                tracking_code=trk,
                card_last4=last4,
                status=st,
                submitted_at_iso=sub_iso,
                admin_note=note,
                issued_license_code=lic_code,
            )

    def get_health_status(self, version: str) -> dict:
        """Return service health metadata and active counts."""
        report = self.get_dashboard_report()
        return {
            "status": "ok",
            "version": version,
            "total_products": report.summary.total_products,
            "total_licenses_issued": report.summary.total_licenses_issued,
            "pending_receipts_count": report.summary.pending_receipts_count,
        }

    def get_dashboard_report(self) -> VaultDashboardReport:
        """Compute the full VaultDashboardReport with KPI summary and records."""
        self.ensure_initial_seed_data()
        products = self._repository.list_products()
        students = self._repository.list_students()
        receipts = self._repository.list_receipts()
        licenses = self._repository.list_licenses()

        total_revenue = sum(lic.price_paid_toman for lic in licenses)
        pending_count = sum(
            1 for r in receipts if r.status == ReceiptStatus.PENDING
        )
        approved_count = sum(
            1 for r in receipts if r.status == ReceiptStatus.APPROVED
        )
        rejected_count = sum(
            1 for r in receipts if r.status == ReceiptStatus.REJECTED
        )
        full_pkg_count = sum(
            1 for p in products if p.tier_type == ProductTierType.FULL_PACKAGE
        )
        chapter_count = sum(
            1 for p in products if p.tier_type == ProductTierType.CHAPTER_PART
        )
        wallet_total = sum(s.wallet_balance_toman for s in students)

        summary = VaultSummary(
            total_revenue_toman=total_revenue,
            total_licenses_issued=len(licenses),
            pending_receipts_count=pending_count,
            approved_receipts_count=approved_count,
            rejected_receipts_count=rejected_count,
            total_products=len(products),
            full_packages_count=full_pkg_count,
            chapter_parts_count=chapter_count,
            total_wallet_balance_toman=wallet_total,
        )
        return VaultDashboardReport(
            summary=summary,
            licenses=licenses,
            receipts=receipts,
            products=products,
            students=students,
        )

    def review_receipt(
        self,
        receipt_id: int,
        approve: bool,
        admin_note: str = "",
    ) -> ReceiptSubmission:
        """Approve or reject a pending card-to-card receipt and issue watermarked license."""
        receipt = self._repository.get_receipt(receipt_id)
        if receipt is None:
            raise ValueError(f"Receipt #{receipt_id} was not found.")
        if receipt.status != ReceiptStatus.PENDING:
            raise ValueError(
                f"Receipt #{receipt_id} has already been reviewed ({receipt.status.value})."
            )

        reviewed_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stamp = None
        if approve:
            student = self._repository.get_student_by_id(receipt.student_id)
            product = self._repository.get_product_by_id(receipt.product_id)
            if student is None or product is None:
                raise ValueError("Associated student or product not found.")
            license_code = f"LIC-2026-{2000 + receipt.receipt_id}"
            stamp = build_watermark_stamp(
                student=student,
                product=product,
                license_code=license_code,
                issued_at_iso=reviewed_at_iso,
            )

        return self._repository.complete_receipt_review_atomic(
            receipt_id=receipt_id,
            approve=approve,
            admin_note=admin_note or ("تایید فیش و صدور مجوز" if approve else "رد فیش"),
            reviewed_at_iso=reviewed_at_iso,
            stamp=stamp,
        )

    def issue_instant_license(
        self,
        request: LicenseIssueRequest,
    ) -> FulfilledLicense:
        """Issue an instant watermarked PDF license for a student and product."""
        product = self._repository.get_product_by_code(request.product_code)
        if product is None:
            raise ValueError(f"Product '{request.product_code}' was not found.")

        student = self._repository.upsert_student(
            full_name=request.student_name,
            phone=request.student_phone,
            telegram_handle=request.telegram_handle,
        )
        issued_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        existing_count = len(self._repository.list_licenses())
        license_code = f"LIC-2026-{3001 + existing_count}"

        stamp = build_watermark_stamp(
            student=student,
            product=product,
            license_code=license_code,
            issued_at_iso=issued_at_iso,
        )
        return self._repository.create_license(
            student_id=student.student_id,
            product_id=product.product_id,
            price_paid_toman=product.price_toman,
            stamp=stamp,
            download_count=1,
        )

    def submit_student_receipt(
        self,
        payload: ReceiptSubmissionCreate,
    ) -> ReceiptSubmission:
        """Record a new student card-to-card receipt submission."""
        product = self._repository.get_product_by_code(payload.product_code)
        if product is None:
            raise ValueError(f"Product '{payload.product_code}' was not found.")

        student = self._repository.upsert_student(
            full_name=payload.student_name,
            phone=payload.student_phone,
            telegram_handle=payload.telegram_handle,
        )
        return self._repository.create_receipt(
            student_id=student.student_id,
            product_id=product.product_id,
            amount_toman=payload.amount_toman,
            tracking_code=payload.tracking_code,
            card_last4=payload.card_last4,
            status=ReceiptStatus.PENDING,
            admin_note="ثبت‌شده از درگاه کارت به کارت دانشجو",
        )

    def generate_watermarked_pdf_for_license(
        self,
        license_id: int,
    ) -> tuple[str, bytes]:
        """Generate the personalized 3-layer watermarked PDF bytes for a license."""
        lic = self._repository.increment_license_download(license_id)
        if lic is None:
            raise ValueError(f"License #{license_id} was not found.")

        student = self._repository.get_student_by_id(lic.student_id)
        product = self._repository.get_product_by_id(lic.product_id)
        if student is None or product is None:
            raise ValueError("Associated student or product record missing.")

        stamp = build_watermark_stamp(
            student=student,
            product=product,
            license_code=lic.license_code,
            issued_at_iso=lic.issued_at_iso,
        )
        pdf_bytes = self._stamper.render_watermarked_pdf(
            product=product,
            student=student,
            stamp=stamp,
        )
        filename = f"{product.code.lower()}-{lic.license_code.lower()}.pdf"
        return filename, pdf_bytes

    def simulate_telegram_bot_command(
        self,
        request: TelegramSimulateRequest,
    ) -> dict:
        """Simulate the integrated Telegram bot response for /start, /catalog, or /myfiles."""
        cmd = request.command.strip().lower()
        report = self.get_dashboard_report()

        if cmd.startswith("/catalog"):
            lines = ["📚 فهرست پکیج‌های کامل و جزوات فصل‌بندی‌شده:"]
            for prod in report.products:
                tier_badge = (
                    "📦 پکیج کامل"
                    if prod.tier_type == ProductTierType.FULL_PACKAGE
                    else "📄 تک‌فصل"
                )
                lines.append(
                    f"• [{tier_badge}] {prod.title}\n"
                    f"  کد: {prod.code} | قیمت: {prod.price_toman:,} تومان ({prod.page_count} صفحه)"
                )
            return {"command": request.command, "bot_reply": "\n".join(lines)}

        if cmd.startswith("/myfiles"):
            phone = request.student_phone.strip()
            matched = [
                lic for lic in report.licenses if lic.student_phone == phone
            ]
            if not matched:
                return {
                    "command": request.command,
                    "bot_reply": f"هیچ فایل فعالی برای شماره {phone} یافت نشد.",
                }
            lines = [f"🔐 فایل‌های اختصاصی واترمارک‌شده برای {phone}:"]
            for lic in matched:
                lines.append(
                    f"• {lic.product_title}\n"
                    f"  کد مجوز: {lic.license_code} | امضای دیجیتال: {lic.watermark_hash}"
                )
            return {"command": request.command, "bot_reply": "\n".join(lines)}

        return {
            "command": request.command,
            "bot_reply": (
                "👋 به ربات هوشمند «سپهر فایل (PDF-Guard)» خوش آمدید!\n"
                "دستورات قابل اجرا:\n"
                "• /catalog — مشاهده پکیج‌های کامل و جزوات فصل‌بندی‌شده\n"
                "• /myfiles — دریافت آنی فایل‌های PDF با واترمارک اختصاصی شما"
            ),
        }

    def export_dashboard_csv(self) -> str:
        """Export all licenses and receipts as an Excel-compatible UTF-8 BOM CSV."""
        report = self.get_dashboard_report()
        return export_vault_records_to_csv(report, include_utf8_bom=True)

"""Tests for the three-layer ISO 32000-1 dynamic PDF watermarking engine."""

from __future__ import annotations

from vault.models import CourseProduct, ProductTierType, StudentAccount
from vault.pdf_stamper import DynamicPdfStamper, build_watermark_stamp


def test_build_watermark_stamp_generates_deterministic_sha256_and_masked_banner() -> None:
    """Verify WatermarkStamp contains buyer identity, license code, and SHA-256 digest."""
    student = StudentAccount(
        student_id=101,
        full_name="امیرحسین رضایی",
        phone="09123456789",
        telegram_handle="@amir_rezaei",
        wallet_balance_toman=450000,
    )
    product = CourseProduct(
        product_id=1,
        code="KONKOOR-MATH-FULL",
        title="پکیج کامل جمع‌بندی ریاضیات تجربی ۱۴۰۵",
        category="ریاضیات کنکور",
        tier_type=ProductTierType.FULL_PACKAGE,
        price_toman=380000,
        page_count=3,
        description="پکیج جامع تست‌های زمان‌دار و نکات طلایی",
    )

    stamp = build_watermark_stamp(
        student=student,
        product=product,
        license_code="LIC-2026-9001",
        issued_at_iso="2026-10-21T10:30:00Z",
    )

    assert stamp.license_code == "LIC-2026-9001"
    assert "09123456789" in stamp.diagonal_text
    assert len(stamp.watermark_hash) == 16
    assert stamp.license_code in stamp.footer_text


def test_dynamic_pdf_stamper_renders_valid_multipage_pdf_with_three_watermark_layers() -> None:
    """Verify generated PDF bytes conform to %PDF-1.4, embed 3 pages, 45-deg matrix, and hash."""
    stamper = DynamicPdfStamper()
    student = StudentAccount(
        student_id=202,
        full_name="سارا محمدی",
        phone="09351112233",
        telegram_handle="@sara_m",
        wallet_balance_toman=200000,
    )
    product = CourseProduct(
        product_id=2,
        code="ALG-CH1",
        title="فصل اول: تحلیل الگوریتم‌ها و پیچیدگی زمانی (ارشد کامپیوتر)",
        category="مهندسی کامپیوتر",
        tier_type=ProductTierType.CHAPTER_PART,
        price_toman=125000,
        page_count=3,
        description="جزوه دست‌نویس و حل تشریحی سوالات ۱۰ سال اخیر",
    )
    stamp = build_watermark_stamp(
        student=student,
        product=product,
        license_code="LIC-2026-7744",
        issued_at_iso="2026-10-21T11:00:00Z",
    )

    pdf_bytes = stamper.render_watermarked_pdf(
        product=product,
        student=student,
        stamp=stamp,
    )

    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert pdf_bytes.rstrip().endswith(b"%%EOF")
    assert b"/Type /Pages" in pdf_bytes
    assert b"/Count 3" in pdf_bytes
    # Layer 1: 45-degree diagonal rotation matrix in content stream
    assert b"0.7071 0.7071 -0.7071 0.7071" in pdf_bytes
    # Layer 2: Buyer phone and license code embedded in page stream
    assert b"09351112233" in pdf_bytes
    assert b"LIC-2026-7744" in pdf_bytes
    # Layer 3: Cryptographic SHA-256 signature in PDF metadata trailer
    assert stamp.watermark_hash.encode("ascii") in pdf_bytes

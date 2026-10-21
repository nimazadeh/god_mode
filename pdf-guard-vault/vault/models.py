"""Domain models for PDF-Guard & Course Vault.

All monetary values are represented in integer Toman (IRT) at the domain seam
so wallet balances, package prices, and receipt amounts never suffer from
floating-point drift.
"""

from __future__ import annotations

from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field


class ProductTierType(StrEnum):
    """Classification of an educational digital product."""

    FULL_PACKAGE = "full_package"
    CHAPTER_PART = "chapter_part"


class ReceiptStatus(StrEnum):
    """Verification state of a student card-to-card receipt submission."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


def normalize_toman_amount(raw_value: int | float | str) -> int:
    """Normalize numeric or formatted string amounts into integer Toman."""
    if isinstance(raw_value, (int, float)):
        return max(0, int(round(raw_value)))
    digits = "".join(ch for ch in str(raw_value) if ch.isdigit())
    return int(digits) if digits else 0


class CourseProduct(BaseModel):
    """Educational booklet, exam package, or chapter offered in the vault."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    product_id: int = Field(..., ge=1)
    code: str = Field(..., min_length=2)
    title: str = Field(..., min_length=2)
    category: str = Field(..., min_length=2)
    tier_type: ProductTierType = Field(default=ProductTierType.FULL_PACKAGE)
    price_toman: int = Field(..., ge=0)
    page_count: int = Field(default=3, ge=1, le=500)
    description: str = Field(default="")


class StudentAccount(BaseModel):
    """Learner profile and current wallet balance in Toman."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    student_id: int = Field(..., ge=1)
    full_name: str = Field(..., min_length=2)
    phone: str = Field(..., min_length=5)
    telegram_handle: str = Field(default="")
    wallet_balance_toman: int = Field(default=0, ge=0)


class WatermarkStamp(BaseModel):
    """Three-layer forensic identity imprint embedded into a personalized PDF."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    license_code: str = Field(..., min_length=4)
    student_name: str = Field(..., min_length=2)
    student_phone: str = Field(..., min_length=5)
    diagonal_text: str = Field(..., min_length=4)
    header_text: str = Field(..., min_length=4)
    footer_text: str = Field(..., min_length=4)
    watermark_hash: str = Field(..., min_length=16)
    issued_at_iso: str = Field(..., min_length=10)


class FulfilledLicense(BaseModel):
    """Issued entitlement linking a student and product with a forensic watermark."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    license_id: int = Field(..., ge=1)
    license_code: str = Field(..., min_length=4)
    student_id: int = Field(..., ge=1)
    student_name: str = Field(..., min_length=2)
    student_phone: str = Field(..., min_length=5)
    telegram_handle: str = Field(default="")
    product_id: int = Field(..., ge=1)
    product_code: str = Field(..., min_length=2)
    product_title: str = Field(..., min_length=2)
    category: str = Field(default="")
    tier_type: ProductTierType = Field(default=ProductTierType.FULL_PACKAGE)
    price_paid_toman: int = Field(..., ge=0)
    page_count: int = Field(default=3, ge=1)
    watermark_hash: str = Field(..., min_length=16)
    diagonal_text: str = Field(..., min_length=4)
    footer_text: str = Field(..., min_length=4)
    issued_at_iso: str = Field(..., min_length=10)
    download_count: int = Field(default=0, ge=0)


class ReceiptSubmission(BaseModel):
    """Card-to-card transfer receipt submitted by a student."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    receipt_id: int = Field(..., ge=1)
    tracking_code: str = Field(..., min_length=4)
    student_id: int = Field(..., ge=1)
    student_name: str = Field(..., min_length=2)
    student_phone: str = Field(..., min_length=5)
    telegram_handle: str = Field(default="")
    product_id: int = Field(..., ge=1)
    product_code: str = Field(..., min_length=2)
    product_title: str = Field(..., min_length=2)
    tier_type: ProductTierType = Field(default=ProductTierType.FULL_PACKAGE)
    amount_toman: int = Field(..., ge=0)
    card_last4: str = Field(..., min_length=4, max_length=4)
    status: ReceiptStatus = Field(default=ReceiptStatus.PENDING)
    submitted_at_iso: str = Field(..., min_length=10)
    reviewed_at_iso: str = Field(default="")
    admin_note: str = Field(default="")
    issued_license_code: str = Field(default="")


class VaultSummary(BaseModel):
    """Aggregate KPI statistics for the course vault dashboard."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    total_revenue_toman: int = 0
    total_licenses_issued: int = 0
    pending_receipts_count: int = 0
    approved_receipts_count: int = 0
    rejected_receipts_count: int = 0
    total_products: int = 0
    full_packages_count: int = 0
    chapter_parts_count: int = 0
    total_wallet_balance_toman: int = 0


class VaultDashboardReport(BaseModel):
    """Complete dashboard payload pairing KPI summary with licenses, receipts, and catalog."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    summary: VaultSummary
    licenses: list[FulfilledLicense] = Field(default_factory=list)
    receipts: list[ReceiptSubmission] = Field(default_factory=list)
    products: list[CourseProduct] = Field(default_factory=list)
    students: list[StudentAccount] = Field(default_factory=list)


class ReceiptReviewRequest(BaseModel):
    """Payload for approving or rejecting a pending card-to-card receipt."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    approve: bool
    admin_note: str = Field(default="")


class LicenseIssueRequest(BaseModel):
    """Payload for issuing an instant watermarked PDF license to a student."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    student_name: str = Field(..., min_length=2)
    student_phone: str = Field(..., min_length=5)
    telegram_handle: str = Field(default="")
    product_code: str = Field(..., min_length=2)


class ReceiptSubmissionCreate(BaseModel):
    """Payload for submitting a new student card-to-card transfer receipt."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    student_name: str = Field(..., min_length=2)
    student_phone: str = Field(..., min_length=5)
    telegram_handle: str = Field(default="")
    product_code: str = Field(..., min_length=2)
    amount_toman: int = Field(..., ge=1000)
    tracking_code: str = Field(..., min_length=4)
    card_last4: str = Field(..., min_length=4, max_length=4)


class TelegramSimulateRequest(BaseModel):
    """Payload for simulating a Telegram bot command against the live vault."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    command: str = Field(..., min_length=1)
    student_phone: str = Field(default="09123456789")

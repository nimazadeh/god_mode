"""Three-layer ISO 32000-1 (%PDF-1.4) dynamic PDF watermarking engine.

Generating standards-compliant PDF 1.4 byte streams directly in pure Python
eliminates brittle native C dependencies on Windows while embedding three
independent forensic layers on every page:
1. A 45-degree rotated translucent diagonal watermark across the page center.
2. Top and bottom forensic attribution banners with buyer phone and license ID.
3. A deterministic SHA-256 cryptographic signature in the PDF /Info dictionary.
"""

from __future__ import annotations

import hashlib

from vault.models import CourseProduct, StudentAccount, WatermarkStamp


def _sanitize_pdf_ascii(raw_text: str) -> str:
    """Convert arbitrary text into safe PDF literal string characters for Type1 fonts.

    Standard PDF Type1 Helvetica streams require ASCII printable characters;
    preserving digits, identifiers, and transliterated tokens ensures universal
    rendering across all PDF viewers without external font embedding bloat.
    """
    escaped: list[str] = []
    for ch in raw_text:
        code = ord(ch)
        if ch in ("(", ")", "\\"):
            escaped.append("\\" + ch)
        elif 32 <= code <= 126:
            escaped.append(ch)
    cleaned = "".join(escaped).strip()
    return cleaned if cleaned else "PROTECTED-ASSET"


def build_watermark_stamp(
    student: StudentAccount,
    product: CourseProduct,
    license_code: str,
    issued_at_iso: str,
) -> WatermarkStamp:
    """Create a deterministic three-layer WatermarkStamp for a student and product."""
    payload = (
        f"{license_code}|{student.phone}|{student.full_name}|"
        f"{product.code}|{product.price_toman}|{issued_at_iso}"
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16].upper()

    diagonal_text = (
        f"LICENSED TO {student.phone} | {license_code} | SHA256:{digest}"
    )
    header_text = (
        f"PDF-GUARD FORENSIC EDITION | PRODUCT: {product.code} | "
        f"BUYER: {student.phone}"
    )
    footer_text = (
        f"Exclusive License {license_code} | Buyer Phone: {student.phone} | "
        f"Sig: {digest} | Issued: {issued_at_iso}"
    )

    return WatermarkStamp(
        license_code=license_code,
        student_name=student.full_name,
        student_phone=student.phone,
        diagonal_text=diagonal_text,
        header_text=header_text,
        footer_text=footer_text,
        watermark_hash=digest,
        issued_at_iso=issued_at_iso,
    )


class DynamicPdfStamper:
    """Pure-Python ISO 32000-1 multi-page PDF generator with 3-layer forensic watermarking."""

    def render_watermarked_pdf(
        self,
        product: CourseProduct,
        student: StudentAccount,
        stamp: WatermarkStamp,
    ) -> bytes:
        """Render a complete multi-page %PDF-1.4 document stamped for the buyer."""
        total_pages = max(1, min(product.page_count, 12))
        safe_code = _sanitize_pdf_ascii(product.code)
        safe_phone = _sanitize_pdf_ascii(student.phone)
        safe_handle = _sanitize_pdf_ascii(student.telegram_handle or "N/A")
        safe_license = _sanitize_pdf_ascii(stamp.license_code)
        safe_hash = _sanitize_pdf_ascii(stamp.watermark_hash)
        safe_diagonal = _sanitize_pdf_ascii(stamp.diagonal_text)
        safe_header = _sanitize_pdf_ascii(stamp.header_text)
        safe_footer = _sanitize_pdf_ascii(stamp.footer_text)

        objects: list[bytes] = []

        # Object 1: Catalog
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

        # Object 2: Pages root (kids populated below)
        page_obj_ids = [4 + idx * 2 for idx in range(total_pages)]
        kids_refs = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        objects.append(
            f"<< /Type /Pages /Kids [ {kids_refs} ] /Count {total_pages} >>".encode(
                "ascii"
            )
        )

        # Object 3: Standard Type1 Font (Helvetica)
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        )

        # Objects 4..N: Page and Content Stream pairs
        for page_idx in range(total_pages):
            page_number = page_idx + 1
            content_obj_id = 4 + page_idx * 2 + 1

            stream_lines = [
                # Outer security frame
                "q",
                "0.86 0.88 0.91 RG",
                "1.2 w",
                "36 36 523 770 re S",
                "Q",
                # Top forensic banner bar
                "q",
                "0.95 0.96 0.98 rg",
                "36 770 523 36 re f",
                "Q",
                "BT",
                "/F1 8.5 Tf",
                "0.22 0.27 0.35 rg",
                f"48 784 Td ({safe_header} | PAGE {page_number} OF {total_pages}) Tj",
                "ET",
                # Main course booklet content block
                "BT",
                "/F1 15 Tf",
                "0.07 0.09 0.15 rg",
                f"54 725 Td (COURSE ASSET: {safe_code} - PART {page_number}/{total_pages}) Tj",
                "/F1 10.5 Tf",
                "0.25 0.30 0.38 rg",
                f"0 -26 Td (Tier Type: {product.tier_type.value.upper()} | Price: {product.price_toman:,} IRT Toman) Tj",
                f"0 -20 Td (Authorized Buyer Phone: {safe_phone} | Telegram: {safe_handle}) Tj",
                f"0 -20 Td (License Certificate ID: {safe_license} | Timestamp: {stamp.issued_at_iso}) Tj",
                f"0 -20 Td (Cryptographic Watermark SHA-256 Digest: {safe_hash}) Tj",
                "0 -32 Td (--------------------------------------------------------------------------------) Tj",
                f"0 -24 Td (Protected Educational Module Page #{page_number}) Tj",
                "0 -18 Td (This PDF document is dynamically stamped at download time with three forensic) Tj",
                "0 -16 Td (layers: diagonal coordinate transform, header/footer buyer attribution, and) Tj",
                "0 -16 Td (trailer dictionary SHA-256 metadata fingerprinting.) Tj",
                "ET",
                # Layer 1: 45-degree rotated diagonal watermark across page center
                "q",
                "BT",
                "/F1 13 Tf",
                "0.78 0.81 0.86 rg",
                f"0.7071 0.7071 -0.7071 0.7071 105 245 Tm ({safe_diagonal}) Tj",
                "ET",
                "Q",
                "q",
                "BT",
                "/F1 11 Tf",
                "0.82 0.84 0.89 rg",
                f"0.7071 0.7071 -0.7071 0.7071 135 165 Tm (DO NOT DISTRIBUTE - BUYER: {safe_phone} - {safe_license}) Tj",
                "ET",
                "Q",
                # Layer 2: Bottom forensic attribution banner
                "q",
                "0.95 0.96 0.98 rg",
                "36 36 523 32 re f",
                "Q",
                "BT",
                "/F1 8 Tf",
                "0.25 0.29 0.37 rg",
                f"48 49 Td ({safe_footer}) Tj",
                "ET",
            ]
            stream_payload = "\n".join(stream_lines).encode("ascii")

            page_dict = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 3 0 R >> >> "
                f"/Contents {content_obj_id} 0 R >>"
            ).encode("ascii")
            content_dict = (
                f"<< /Length {len(stream_payload)} >>\nstream\n".encode("ascii")
                + stream_payload
                + b"\nendstream"
            )
            objects.append(page_dict)
            objects.append(content_dict)

        # Final Object: Layer 3 Metadata /Info Dictionary with SHA-256 fingerprint
        info_obj_id = len(objects) + 1
        info_dict = (
            f"<< /Title (Protected Course {safe_code} - {safe_license}) "
            f"/Author (PDF-Guard Course Vault) "
            f"/Subject (Forensic Watermark SHA256:{safe_hash} for {safe_phone}) "
            f"/Keywords ({safe_license} {safe_phone} {safe_hash}) "
            f"/Producer (PDF-Guard ISO-32000 Engine v1.0) >>"
        ).encode("ascii")
        objects.append(info_dict)

        # Assemble complete PDF 1.4 byte stream with exact xref byte offsets
        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = [0]

        for idx, obj_body in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{idx} 0 obj\n".encode("ascii"))
            output.extend(obj_body)
            output.extend(b"\nendobj\n")

        xref_offset = len(output)
        total_obj_count = len(objects) + 1
        output.extend(f"xref\n0 {total_obj_count}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            output.extend(f"{off:010d} 00000 n \n".encode("ascii"))

        output.extend(
            (
                f"trailer\n<< /Size {total_obj_count} /Root 1 0 R /Info {info_obj_id} 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF\n"
            ).encode("ascii")
        )
        return bytes(output)

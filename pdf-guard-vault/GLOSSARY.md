# PDF-Guard & Course Vault

An educational digital asset store, student wallet ledger, card-to-card receipt verification workflow, and real-time dynamic PDF watermarking platform for instructors and academies.

## Language

**CourseProduct**:
A digital educational booklet, exam package, or lecture note offered for sale either as a complete package (`full_package`) or as an individual chapter (`chapter_part`), priced in integer Toman (`IRT`).
_Avoid_: Post, item, article, file row

**StudentAccount**:
A registered learner profile identified by a canonical student ID, full name, mobile number, Telegram handle, and current wallet balance in Toman (`wallet_balance_toman`).
_Avoid_: Client, user row, customer record

**ReceiptSubmission**:
A card-to-card bank transfer receipt submitted by a `StudentAccount` to top up their wallet or purchase a `CourseProduct`, progressing through `pending`, `approved`, or `rejected` states.
_Avoid_: Slip, payment ticket, invoice

**WatermarkStamp**:
A three-layer forensic identity imprint applied dynamically to every page of a purchased PDF: a 45-degree diagonal translucent banner, header/footer buyer attribution, and a cryptographic `SHA-256` signature in the PDF metadata dictionary.
_Avoid_: Overlay, tag, label

**FulfilledLicense**:
An immutable entitlement record linking a `StudentAccount` and a `CourseProduct` with a unique `license_code` and `watermark_hash`, authorizing on-demand generation of the personalized PDF.
_Avoid_: Download row, purchase log

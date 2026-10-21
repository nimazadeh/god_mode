# SQLite WAL Atomic Receipt Approval and License Issuance

Because many independent instructors and Telegram course bots accept card-to-card bank transfers (`کارت به کارت`) rather than automated payment gateways, administrators must review submitted transfer receipts while students concurrently browse courses and download watermarked PDFs.

We decided to persist all `CourseProduct`, `StudentAccount`, `ReceiptSubmission`, and `FulfilledLicense` records in a local SQLite database configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and partial covering indexes on pending receipts (`idx_receipts_status`). Approving a `ReceiptSubmission` executes inside an atomic transaction that updates the receipt state, credits the student's `wallet_balance_toman` (or directly issues the target `FulfilledLicense` with its `WatermarkStamp`), and prevents double-crediting if clicked twice.

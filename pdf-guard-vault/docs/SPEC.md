# PDF-Guard & Course Vault — Technical Specification

## Problem Statement

University instructors, Konkoor academies, and educational Telegram channels in Iran lose significant revenue when digital PDF booklets and exam packages are shared unauthorizedly in groups after a single purchase. At the same time, most independent educators rely on manual card-to-card (`کارت به کارت`) bank transfers, creating chaos when tracking receipts, crediting student wallets, selling either full packages or individual chapters, and manually stamping buyer details onto PDF files.

## Solution

An integrated web application, Telegram Bot webhook/simulator engine, and CLI utility (`PDF-Guard & Course Vault`) that manages hierarchical educational products (`full_package` and `chapter_part`), automates student wallet top-ups and one-click card-to-card receipt verification (`ReceiptSubmission`), dynamically stamps every page of downloaded PDFs with a three-layer forensic `WatermarkStamp` (`DynamicPdfStamper`), and provides a Persian RTL Linear Light-Mode admin dashboard responsive for both desktop and Apple iPhone (`390x844`).

## User Stories

1. As an academy administrator, I want to offer educational products both as complete discounted packages (`پکیج کامل`) and as individual chapters (`فصل‌بندی‌شده`), so that students can buy according to their budget.
2. As an academy administrator, I want to view all pending card-to-card `ReceiptSubmission` records in a dedicated queue and approve or reject them with a single click, so that student wallets are credited and PDF licenses are issued atomically without double-crediting.
3. As an academy administrator, I want every downloaded PDF to carry a 45-degree diagonal watermark, top/bottom buyer attribution banners, and a cryptographic `SHA-256` signature in the PDF metadata, so that any leaked file can be traced immediately to the buyer's name, mobile number, and `license_code`.
4. As an academy administrator, I want to issue an instant watermarked PDF license for any student and product directly from the dashboard or Telegram bot simulator, so that VIP or phone orders can be fulfilled in seconds.
5. As an academy administrator, I want to click on any license or receipt row to inspect a live visual preview of the 3-layer PDF watermark and download the actual generated `.pdf` file immediately, so that I can verify watermark legibility before sending it to the student.
6. As an academy administrator, I want to filter records by status (`همه مجوزها و فیش‌ها`, `فیش‌های در انتظار تایید`, `مجوزهای صادرشده`, `پکیج‌های کامل`, `فصل‌های تکی`, `فیش‌های ردشده`) and search by student name, mobile number, tracking code, or course title in real time.
7. As an academy administrator, I want to add new `CourseProduct` items or submit simulated student `ReceiptSubmission` requests from the UI, so that I can test and operate the entire store from a single screen.
8. As an academy administrator, I want to export all issued licenses and financial receipts to an Excel-compatible UTF-8 BOM CSV file, so that I can reconcile monthly accounting.
9. As an academy administrator managing orders from an Apple iPhone (`390x844`), I want the dashboard table to transform into touch-friendly vertical cards with zero horizontal overflow, so that I can approve receipts and issue PDFs on the go.
10. As an academy administrator, I want a built-in Telegram Bot webhook and command simulator (`/start`, `/catalog`, `/receipt`, `/myfiles`), so that the backend can connect directly to a Telegram bot or demonstrate bot interactions live to prospective clients.

## Implementation Decisions

- **Deep Module Architecture (`CourseVaultService`)**:
  - `vault/models.py`: Domain models (`CourseProduct`, `StudentAccount`, `ReceiptSubmission`, `WatermarkStamp`, `FulfilledLicense`, `VaultDashboardReport`) and Toman currency normalization.
  - `vault/pdf_stamper.py`: Pure-Python ISO 32000-1 (`%PDF-1.4`) multi-page PDF generator and 3-layer forensic watermark stamper (`DynamicPdfStamper`).
  - `vault/storage.py`: SQLite WAL repository (`VaultRepository`) with atomic receipt approval, idempotent double-approval protection, and partial covering indexes.
  - `vault/exporter.py`: RFC 4180 CSV exporter with UTF-8 BOM (`\ufeff`).
  - `vault/service.py` & `vault/api.py`: Deep orchestration module (`CourseVaultService`) and FastAPI HTTP adapter with `GZipMiddleware(minimum_size=500)`.

## Testing Decisions

- **Red-Green TDD at Public Seams**:
  - Test `DynamicPdfStamper` output to verify valid `%PDF-1.4` header, multi-page `/Count`, embedded buyer phone/license code, 45-degree rotation matrix, and `SHA-256` metadata signature.
  - Test `VaultRepository` atomic receipt approval, wallet balance updates, idempotent re-approval guard, and `EXPLAIN QUERY PLAN` index usage.
  - Test `CourseVaultService` and FastAPI endpoints (`/api/health`, `/api/dashboard`, `/api/receipts`, `/api/receipts/{id}/review`, `/api/licenses/issue`, `/api/licenses/{id}/download.pdf`, `/api/telegram/simulate`, `/api/export.csv`) and CLI one-shot export.
  - Test desktop (`1440x900`) and Apple iPhone (`390x844`) viewports in headless Playwright Chromium (`webapp-testing`).

## Out of Scope

- Third-party Shaparak redirect gatewayrequiring an e-Namad business license (the platform uses card-to-card receipt verification + wallet ledger out of the box).

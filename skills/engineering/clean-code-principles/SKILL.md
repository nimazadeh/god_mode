---
name: clean-code-principles
description: Strict enforcement of Clean Code, DRY, Single Responsibility Principle (SRP), WHY-only comments, readability-first formatting, and 100% English source code.
---

# Clean Code, DRY, SRP & 100% English Source Code Skill

Apply these rules without exception across all Python, JavaScript, HTML, CSS, and Batch files.

## 1. 100% English in Source Code (Zero Persian Characters in Codebase)

- **Chat vs. Code Separation**:
  - Explanations, reports, and conversations with the user in chat are in warm **Persian**.
  - **Every single byte of source code** (`.py`, `.js`, `.css`, `.html`, `.bat`, `.md` inside the project, UI text, comments, docstrings, variable names, log messages, and tests) MUST be **100% English**.
  - Enforce an automated test in `pytest` scanning all project source files to verify zero Persian/Arabic Unicode characters (`\u0600`–`\u06FF`) appear anywhere in the codebase.

## 2. Readability First & One Statement Per Line

- Write code for humans to read effortlessly from top to bottom.
- **Never pack multiple statements onto a single line** (no `if cond: return x`, no chained dense one-liners, no nested ternary expressions).
- Break complex expressions into named intermediate variables that explain the domain meaning.

## 3. Meaningful, Self-Documenting Identifiers

- Function names must be clear verb phrases describing their exact responsibility (`fetch_catalog_page`, `parse_product_option_prices`, `compute_price_diff_report`, `export_changes_to_csv`).
- Variable and parameter names must be complete nouns (`previous_snapshot`, `current_price_toman`, `changed_product_records`, `catalog_http_client`).
- Never use single-letter or cryptic abbreviations (`p`, `r`, `d`, `tmp`, `val`, `arr`).

## 4. WHY-Driven Comments (Never WHAT)

- Every module, class, and non-trivial function includes a concise English docstring and inline comments explaining **WHY** the engineering decision exists (e.g., why WooCommerce Store API base prices differ from HTML option add-ons, why SQLite WAL mode prevents lock contention, or why rate-limiting jitter prevents WAF blocks).
- Never write comments that merely restate the syntax (`# increment counter by 1`).

## 5. Single Responsibility Principle (SRP)

- Every module, class, and function must have **one and only one reason to change**:
  - `extractor`: Only fetches and parses product data from the source website.
  - `diff_engine`: Only compares snapshots and computes price/stock/option deltas (pure deterministic domain logic, zero I/O).
  - `storage`: Only persists and queries snapshots in SQLite.
  - `exporter`: Only formats diff reports into CSV/Excel deliverables.
  - `api`: Only maps HTTP requests to domain services.

## 6. DRY (Don't Repeat Yourself)

- Every piece of domain knowledge, validation rule, price normalization formula, or UI component renderer must have a **single canonical representation**.
- Extract shared utilities rather than duplicating parsing, formatting, or SQL queries across files.

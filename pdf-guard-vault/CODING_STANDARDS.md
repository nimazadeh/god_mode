# Coding Standards — PDF-Guard & Course Vault

This project follows the repository-wide standards in `/home/user/CODING_STANDARDS.md` and domain terms in `GLOSSARY.md`.

## 1. Deep Module Seam (`CourseVaultService`)

- HTTP routes in `vault/api.py` and CLI commands in `main.py` must call `CourseVaultService` methods exclusively and must never access `service.repository` or `service.stamper` internals directly (prevents Fowler's **Feature Envy**).
- All monetary amounts are stored and calculated in integer Toman (`IRT`).

## 2. Clean Code & Automated Guardrails (`tests/test_code_hygiene.py`)

- Python logic modules, CSS files, and Windows `.bat` scripts are 100% English; user-facing HTML and UI text in `web/` is fluent Persian RTL (`dir="rtl"`, `lang="fa"`).
- Comments explain **WHY**, never **WHAT**.
- Dynamic DOM updates use `document.createElement` and `DocumentFragment` batches.

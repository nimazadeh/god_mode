# Coding Standards

This document is read during `/code-review` (Standards axis) and `/retro`. Mechanical rules are enforced automatically by `tests/test_code_hygiene.py`; this file governs architectural and code-smell judgment calls.

## 1. Deep Modules & Seam Discipline (`codebase-design`)

- **Transport adapters must not bypass the service seam**: HTTP routes (`sentinel/api.py`) and CLI entrypoints (`main.py`) must interact exclusively with the `PriceSentinelService` public interface and must never reach into `service.repository` or `service.extractor` internals directly (avoids Fowler's **Feature Envy** and **Message Chains**).
- **The interface is the test surface**: Write tests against the public interfaces of `extractor`, `diff_engine`, `storage`, `exporter`, `service`, and `api` rather than mocking internal helper functions.

## 2. Clean Code, DRY, SRP & Readability

- **Self-Documenting Identifiers**: Every module, class, function, and variable name must reveal its domain role using the canonical terms in `GLOSSARY.md` (`CatalogProduct`, `OptionTier`, `CatalogSnapshot`, `BaselineSnapshot`, `PriceDelta`, `DiffReport`, `Watchlist`).
- **Comments Explain WHY, Never WHAT**: Write comments in standard English only where domain constraints or external quirks (such as `IRR` to `IRT` conversion, `TM Extra Product Options` `data-rules` JSON, or SQLite `WAL` concurrency) would otherwise surprise a maintainer.
- **One Statement Per Line**: Never pack multiple statements onto a single line; favor vertical legibility over horizontal compression.

## 3. UI, Accessibility & Performance Standards

- **Persian RTL User Interface + English Source Code**: User-facing labels, badges, and messages in `web/` are written in fluent Persian (`dir="rtl"`, `lang="fa"`), while all source code identifiers, comments, and technical specs remain 100% English.
- **Linear Light-Mode Visual Discipline**: Neutral surfaces (`#F7F8F9` canvas, `#FFFFFF` cards), `1px solid #EAECEF` structural borders, tabular numerals (`font-variant-numeric: tabular-nums`), and responsive card layout at `<= 760px` for Apple iPhone viewports with zero horizontal overflow.
- **Safe DOM Construction**: Construct dynamic UI rows using `document.createElement` and `DocumentFragment` batches.

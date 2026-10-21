---
name: webapp-testing
description: Toolkit for interacting with and testing local web applications using Playwright. Supports verifying frontend functionality, debugging UI behavior, capturing browser screenshots, and viewing browser logs.
---

# Web Application Testing (Anthropic Official Skill)

To test local web applications, write native Python Playwright scripts and follow the **Reconnaissance-Then-Action** pattern.

## Decision Tree & Reconnaissance-Then-Action Pattern

1. **Navigate and Wait for `networkidle`**:
   ```python
   page.goto("http://127.0.0.1:8090")
   page.wait_for_load_state("networkidle")
   ```
2. **Capture Visual Screenshot & Inspect Rendered DOM / Bounding Boxes**:
   - Always take a screenshot (`page.screenshot(path="/tmp/inspect.png", full_page=True)`) and inspect it visually + programmatically check element bounding boxes (`getBoundingClientRect()`) for overlaps, clipping, or horizontal overflow across desktop and tablet/mobile viewports.
3. **Identify Selectors & Verify Interactive Behavior**:
   - Exercise real user interactions, capture console logs (`page.on("console", ...)` and `page.on("pageerror", ...)`), and verify zero visual overlap, zero clipped text, and zero runtime errors.

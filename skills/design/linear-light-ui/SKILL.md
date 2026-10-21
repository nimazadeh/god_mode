---
name: linear-light-ui
description: Linear.app-inspired Light Mode UI/UX design system for precision software tools, dashboards, and web applications. Enforces ultra-crisp 1px hairline borders, subtle neutral surfaces, tabular typography, keyboard-first workflows, and zero visual bloat.
---

# Linear Light-Mode UI/UX Design Skill

Use this skill whenever building or refining a web application interface. It embodies the **Linear (`linear.app`) Light Mode** philosophy: surgical clarity, speed as a visual feature, high information density without clutter, and tactile precision.

## 1. Surface & Color Token Architecture (Light Mode)

Linear Light Mode relies on **subtle luminance layering** and **1px structural borders** rather than heavy drop shadows or saturated backgrounds.

```css
:root {
  /* Surfaces */
  --bg-canvas: #F7F8F9;          /* App background / sidebar shell */
  --bg-surface: #FFFFFF;         /* Primary work surface / cards / table rows */
  --bg-surface-subtle: #F3F4F6;  /* Hover states, secondary pills, filter bar */
  --bg-surface-active: #EBEEF2;  /* Active/selected row or control */

  /* Hairline Borders (1px solid) */
  --border-subtle: #EAECEF;      /* Row dividers, internal grid lines */
  --border-default: #DFE2E6;     /* Card/panel boundaries, input borders */
  --border-strong: #C8CDD4;      /* Hover input border, active separator */

  /* Typography Hierarchy (WCAG AA/AAA Verified on White) */
  --text-primary: #111315;       /* Headings, product names, primary prices (Contrast > 16:1) */
  --text-secondary: #4B5158;     /* Table metadata, SKU, categories (Contrast > 7.5:1) */
  --text-muted: #687076;         /* Timestamps, helper hints, keyboard shortcuts (Contrast > 4.8:1) */

  /* Linear Indigo Accent & Semantic Diff Signals */
  --accent-primary: #5E6AD2;     /* Linear signature indigo for primary actions & focus */
  --accent-primary-hover: #4F5BC4;
  --accent-subtle: #EEF0FF;

  /* Semantic Price Diff & Status Tokens */
  --status-up-text: #15803D;     /* Price increase / positive delta text */
  --status-up-bg: #DCFCE7;       /* Soft green pill background */
  --status-up-border: #BBF7D0;

  --status-down-text: #B91C1C;   /* Price decrease / critical alert text */
  --status-down-bg: #FEE2E2;     /* Soft red pill background */
  --status-down-border: #FECACA;

  --status-warn-text: #B45309;   /* Stock change / modified option warning */
  --status-warn-bg: #FEF3C7;
  --status-warn-border: #FDE68A;
}
```

## 2. Typography & Numeric Precision

- **Single Sans-Serif Workhorse + Monospace Data**:
  - UI & Prose: `'Inter'`, `'Geist'`, `-apple-system, BlinkMacSystemFont, sans-serif`.
  - SKUs, IDs, and Deltas: `'Geist Mono'`, `ui-monospace, SFMono-Regular, monospace`.
- **Mandatory Tabular Numerals**:
  - Every price column, percentage badge, timestamp, and counter MUST set `font-variant-numeric: tabular-nums;` so digits align vertically to the pixel across rows.
- **Restrained Type Scale**:
  - Page title: `1.125rem` (`18px`), `font-weight: 600`, `letter-spacing: -0.02em`.
  - Section / Panel header: `0.875rem` (`14px`), `font-weight: 600`.
  - Table cell / Control body: `0.8125rem` (`13px`), `line-height: 1.45`.
  - Metadata / Badge / Shortcut hint: `0.75rem` (`12px`), `font-weight: 500`.

## 3. Structural Layout & Component Rules

1. **App Shell Geometry**:
   - Compact top command bar (`height: 48px`) with breadcrumb/title on the left, live status pill in the center, and primary action button (`Scan Now`, `Export CSV/XLSX`) on the right.
   - Clean filter/view bar directly beneath (`height: 40px`) with instant segmented tabs (`Changed Only`, `Price Increased`, `Price Decreased`, `Out of Stock`, `All Tracked`) and instant search input (`/` shortcut).
2. **High-Density Scannable Data Table**:
   - No bloated card grids for tabular data. Use a crisp `<table>` with sticky header (`position: sticky; top: 0; background: var(--bg-canvas)`), `1px solid var(--border-subtle)` horizontal dividers, and subtle row hover (`var(--bg-surface-subtle)`).
3. **Micro-Elevation Only**:
   - Avoid wide blurry drop shadows. Use `box-shadow: 0 1px 2px rgba(17, 19, 21, 0.04)` only on elevated buttons, popovers, and command palettes.
4. **Snappy Micro-Interactions**:
   - Transitions stay between `100ms` and `160ms` (`cubic-bezier(0.16, 1, 0.3, 1)`).
   - Every control implements `default`, `hover`, `focus-visible` (`2px solid var(--accent-primary)`), `active`, `disabled`, and `loading` states.

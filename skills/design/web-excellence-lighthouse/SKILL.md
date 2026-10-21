---
name: web-excellence-lighthouse
description: Engineering standards for achieving 100/100 across Best Practices, Best Performance, and Best Accessibility in web applications.
---

# Web Application Excellence: Best Practices, Best Performance & Best Accessibility

Every web application surface must be engineered and tested to achieve top marks across all three pillars simultaneously.

## Pillar 1: Best Practices (Security, Modern DOM & Reliability)

1. **Zero Unsafe DOM Manipulation**:
   - Never use `eval()`, `new Function()`, or raw string HTML injection. Construct DOM nodes deterministically using `document.createElement`, `textContent`, and `DocumentFragment`.
2. **Strict Error & Promise Hygiene**:
   - Every `fetch()` and async browser operation (`navigator.clipboard.writeText`, storage APIs) must handle network/permission errors gracefully and surface actionable recovery messages in the UI.
3. **Clean CSS Architecture**:
   - Zero `!important` declarations. Use flat, predictable class specificity and CSS custom properties (`:root` design tokens).
4. **HTTP & Asset Integrity**:
   - Properly typed `Content-Type` headers, zero console errors, zero unhandled promise rejections, and valid HTML5 doctype/charset metadata.

## Pillar 2: Best Performance (Sub-16ms Frame Budget & Zero Layout Shift)

1. **Single-Reflow Batched Rendering**:
   - When rendering or filtering hundreds of rows, build off-screen inside a `DocumentFragment` and mount in a single DOM operation (`replaceChildren(fragment)`) to guarantee zero layout thrashing.
2. **Zero Cumulative Layout Shift (`CLS = 0`)**:
   - Reserve explicit dimensions for status bars, badges, and skeleton states so the layout never jumps when data arrives.
3. **Zero External Network Blocking**:
   - Self-host fonts (`woff2` with `font-display: swap`), inline critical SVG icons, and avoid heavy third-party JS bundles so First Contentful Paint (`FCP`) and Largest Contentful Paint (`LCP`) complete in under `100ms` locally.
4. **Debounced Filtering & O(1) Lookups**:
   - Keep client-side search and filter lookups indexed by product ID/SKU in `Map` structures for instant `<5ms` table filtering.

## Pillar 3: Best Accessibility (WCAG 2.2 AA/AAA & Keyboard-First Control)

1. **Semantic HTML5 Landmarks**:
   - Structure every page with `<header>`, `<nav>`, `<main>`, `<section aria-labelledby="...">`, and proper `<table>`, `<thead>`, `<th scope="col">`, `<tbody>` elements.
2. **Verified Contrast Ratios**:
   - Primary text ≥ `12:1`, secondary text ≥ `7:1`, muted text ≥ `4.5:1` against its background surface.
   - Never convey price changes by color alone: always pair semantic color with directional icons/prefixes (`+` / `▲` for increase, `-` / `▼` for decrease) and text labels.
3. **Full Keyboard Navigation & Focus Management**:
   - Every interactive element must be reachable via `Tab` using native `<button>`, `<input>`, `<select>`, and `<a>` elements (never `<div onclick>`).
   - Visible `:focus-visible` ring (`2px solid var(--accent-primary)`, `outline-offset: 2px`) on every control.
4. **Live Region Announcements (`aria-live`)**:
   - Announce scan progress, completion counts, and error alerts via `role="status"` and `aria-live="polite"` so screen readers and operators immediately perceive state changes.

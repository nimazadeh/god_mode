---
name: performance-optimization
description: Optimizes application performance across frontend, backend, queries, and databases. Use when performance requirements exist, when you suspect performance regressions, when Core Web Vitals or load times need improvement, when N+1 query patterns need fixing, or when profiling reveals bottlenecks.
---

# Performance Optimization (Addy Osmani)

## Overview

Measure before optimizing. Performance work without measurement is guessing — and guessing leads to premature optimization that adds complexity without improving what matters. Profile first, identify the actual bottleneck, fix it, measure again. Optimize only what measurements prove matters.

## Core Web Vitals Targets

| Metric | Good | Needs Improvement | Poor |
|--------|------|-------------------|------|
| **LCP** (Largest Contentful Paint) | ≤ 2.5s | ≤ 4.0s | > 4.0s |
| **INP** (Interaction to Next Paint) | ≤ 200ms | ≤ 500ms | > 500ms |
| **CLS** (Cumulative Layout Shift) | ≤ 0.1 | ≤ 0.25 | > 0.25 |

## The 5-Step Optimization Workflow

```
1. MEASURE  → Establish baseline with real data (Synthetic + RUM)
2. IDENTIFY → Find the actual bottleneck (Frontend LCP/CLS/INP or Backend N+1/Indexes/Pool)
3. FIX      → Address the specific bottleneck (one change at a time)
4. VERIFY   → Measure again under identical conditions; keep or revert ("Neutral" is a revert)
5. GUARD    → Add performance budgets and CI checks to prevent regression
```

## Performance Budgets

- JavaScript bundle: `< 200KB` gzipped
- CSS: `< 50KB` gzipped
- Fonts: `< 100KB` total (or preloaded local `woff2` with zero layout shift)
- API response time: `< 200ms` (p95)
- Lighthouse Performance score: `≥ 90` (target `100/100`)

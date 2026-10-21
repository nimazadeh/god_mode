# Domain Docs

How the engineering skills consume this repository's domain documentation when exploring or modifying a product.

## Multi-Context Repository Layout

This repository hosts multiple standalone products mapped by `GLOSSARY-MAP.md` at the repository root:

```
/
├── GLOSSARY-MAP.md
├── CODING_STANDARDS.md
├── docs/
│   └── agents/
│       ├── domain.md
│       ├── issue-tracker.md
│       └── triage-labels.md
├── .scratch/
│   ├── giyahkala-sentinel/
│   ├── aethergate-vpn/
│   └── god-mode-monitor/
└── giyahkala-sentinel/
    ├── GLOSSARY.md
    ├── CODING_STANDARDS.md
    └── docs/
        └── adr/
```

## Rules for Consuming Domain Docs

1. Before exploring or modifying a product, read `/home/user/GLOSSARY-MAP.md` and the target product's `GLOSSARY.md` and `docs/adr/*.md`.
2. Use the exact canonical terms defined in `GLOSSARY.md` in all specs, tickets, test names, and module interfaces; avoid synonyms listed under `_Avoid_`.
3. If a proposed change conflicts with an accepted ADR in `docs/adr/`, surface the conflict explicitly before writing code.

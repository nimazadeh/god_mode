# AetherGate VPN — Design System (`DESIGN.md`)

- **Aesthetic Direction**: Precision Cyber-Network Telemetry (`Operate` mode) — deep slate-obsidian surfaces (`#090d16`, `#0f172a`), electric cyan (`#06b6d4`) for active tunnel streams, emerald (`#10b981`) for verified `RFC 9421` handshakes, amber (`#f59e0b`) for `DIRECT` split-tunnel routes, and coral (`#f43f5e`) for `BLOCK` / errors.
- **Typography**: Bundled `Inter` (`--font-ui` and `--font-mono` with `font-variant-numeric: tabular-nums`) so live throughput, latency (`ms`), and packet counters never jitter.
- **Strict Craft Rules**:
  - 100% of color variables defined exclusively in `dashboard/css/variables.css`.
  - Zero `!important` in CSS; zero unsafe `innerHTML` in JS (`textContent` and DOM APIs only).
  - Every Python file ≤200 lines (≤20 lines/function) and every JS file ≤80 lines.

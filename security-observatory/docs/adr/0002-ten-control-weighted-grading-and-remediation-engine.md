# ADR 0002: Ten-Control Deterministic Grading and Secret-Safe Cookie Inspection

## Context

Security posture reports used in client consulting must be 100% reproducible, transparent in how points are earned, and must never persist sensitive session cookie values in SQLite audit logs.

## Decision

1. Separate network collection (`collector.py`) completely from pure deterministic scoring (`analyzer.py`) so all 10 weighted controls can be unit-tested offline without live sockets.
2. Parse `Set-Cookie` attributes (`Secure`, `HttpOnly`, `SameSite`) immediately at collection/analysis time while replacing raw cookie values with `<redacted>` prior to persistence or display.

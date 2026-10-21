# Sepahr Security Observatory (`v1.0.0`)

Non-destructive Web Security Posture & Configuration Observatory inspired by Mozilla Observatory and Qualys SSL Labs, built with FastAPI, SQLite WAL, and a crisp Linear Light-Mode Persian RTL interface.

## Quick Start (Windows)

Double-click `run-windows.bat` or `start_observatory.bat`. The dashboard launches automatically at `http://127.0.0.1:8094`.

## Quick Start (Linux / macOS CLI)

```bash
python3 main.py --host 0.0.0.0 --port 8094
```

### One-Shot CLI Audit

```bash
python3 main.py --scan https://github.com
```

### Automated Test Suite

```bash
pytest -v
```

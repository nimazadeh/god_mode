#!/usr/bin/env bash
set -euo pipefail
# One-Command Linux VPS Installer for AetherGate Personal VPN Server Node (:8443)
echo "=== Installing AetherGate Personal VPN Server Node (RFC 9110-9651) ==="
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
export AETHER_SECRET_KEY="${AETHER_SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}"
export AETHER_SERVER_PORT="${AETHER_SERVER_PORT:-8443}"
export AETHER_PUBLIC_HOST="${AETHER_PUBLIC_HOST:-$(hostname -I | awk '{print $1}')}"
echo "Starting AetherGate Server Node on port ${AETHER_SERVER_PORT}..."
python3 server_node.py

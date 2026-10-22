"""Standalone VPS server entrypoint (:8443) so users can deploy a self-hosted RFC 9421 camouflage node with one command."""

import os
import uvicorn
from constants import DEFAULT_SECRET_KEY, TUNNEL_SERVER_PORT
from tunnel.camouflage import create_tunnel_server_app
from tunnel.profile_uri import encode_profile_uri


def main() -> int:
    """Start the active-probe-resistant server node and emit an aethergate:// URI so clients can pair without manual JSON editing."""
    secret = os.environ.get("AETHER_SECRET_KEY", DEFAULT_SECRET_KEY)
    port = int(os.environ.get("AETHER_SERVER_PORT", str(TUNNEL_SERVER_PORT)))
    public_host = os.environ.get("AETHER_PUBLIC_HOST", "127.0.0.1")
    uri = encode_profile_uri(
        {
            "name": f"Personal-VPS-{public_host}",
            "server_url": f"http://{public_host}:{port}",
            "secret_key": secret,
            "transport": "WS_RFC8441",
            "padding_enabled": True,
            "camouflage_domain": public_host,
        }
    )
    print(f"AetherGate Server Node listening on 0.0.0.0:{port}")
    print(f"One-Click Client Import URI:\n{uri}")
    # Suppress Uvicorn's 'server: uvicorn' response header so active censorship scanners only see the decoy AetherCloud headers.
    uvicorn.run(
        create_tunnel_server_app(secret_key=secret),
        host="0.0.0.0",
        port=port,
        log_level="warning",
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

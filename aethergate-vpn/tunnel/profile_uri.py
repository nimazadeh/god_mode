"""URL-safe aethergate:// profile serializer and manager so users can share or import VPS credentials in a single string."""

import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote
from constants import DEFAULT_SECRET_KEY, PROFILES_PATH, SUPPORTED_TRANSPORTS, TUNNEL_SERVER_PORT


def encode_profile_uri(profile: dict[str, Any]) -> str:
    """Strip base64 padding and attach the profile name as a URI fragment so links stay compact and human-identifiable in chat apps."""
    core = {
        "name": profile.get("name", "Personal-Node"),
        "server_url": profile.get("server_url", f"http://127.0.0.1:{TUNNEL_SERVER_PORT}"),
        "secret_key": profile.get("secret_key", DEFAULT_SECRET_KEY),
        "transport": profile.get("transport", "WS_RFC8441"),
        "padding_enabled": bool(profile.get("padding_enabled", True)),
        "camouflage_domain": profile.get("camouflage_domain", "docs.cloud-origin.local"),
    }
    raw_json = json.dumps(core, separators=(",", ":")).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    return f"aethergate://{b64}#{quote(str(core['name']))}"


def decode_profile_uri(uri: str) -> dict[str, Any]:
    """Restore base64 padding and fall back to WS_RFC8441 if an unknown transport is specified so imported URIs never break startup."""
    clean = uri.strip()
    if not clean.startswith("aethergate://"):
        raise ValueError("URI must start with aethergate://")
    body_part, _, frag = clean[len("aethergate://") :].partition("#")
    pad = "=" * ((4 - len(body_part) % 4) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(body_part + pad).decode("utf-8"))
    if frag:
        decoded["name"] = unquote(frag)
    if decoded.get("transport") not in SUPPORTED_TRANSPORTS:
        decoded["transport"] = "WS_RFC8441"
    return decoded


class ProfileManager:
    """Seed a local loopback node when config/profiles.json is absent to guarantee at least one valid profile is always available."""

    def __init__(self, path: Path = PROFILES_PATH) -> None:
        self.path = path
        self.profiles: list[dict[str, Any]] = []
        self.active_name: str = ""
        self._load_or_seed()

    def _load_or_seed(self) -> None:
        """Auto-seed a loopback RFC node on first launch so the client works out-of-the-box without requiring an external VPS."""
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.profiles, self.active_name = data.get("profiles", []), data.get("active_name", "")
        if not self.profiles:
            prof = {
                "name": "Local-Loopback-RFC-Node", "server_url": f"http://127.0.0.1:{TUNNEL_SERVER_PORT}",
                "secret_key": DEFAULT_SECRET_KEY, "transport": "WS_RFC8441",
                "padding_enabled": True, "camouflage_domain": "docs.aether-cloud.local",
            }
            prof["uri"] = encode_profile_uri(prof)
            self.profiles, self.active_name = [prof], prof["name"]
            self.save()

    def save(self) -> None:
        """Create parent directories automatically before writing so fresh checkouts never fail on missing config/ folders."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"active_name": self.active_name, "profiles": self.profiles}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def get_active(self) -> dict[str, Any]:
        """Fall back to index 0 if active_name is missing so callers can always rely on a non-null profile dict."""
        for p in self.profiles:
            if p["name"] == self.active_name:
                return p
        return self.profiles[0]

    def import_uri(self, uri: str) -> dict[str, Any]:
        """Deduplicate by profile name on import so re-importing an updated VPS URI replaces the old entry cleanly."""
        prof = decode_profile_uri(uri)
        prof["uri"] = encode_profile_uri(prof)
        self.profiles = [p for p in self.profiles if p["name"] != prof["name"]]
        self.profiles.insert(0, prof)
        self.active_name = prof["name"]
        self.save()
        return prof

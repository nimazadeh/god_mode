"""Multi-path anti-censorship router that balances US IP cloaking to preserve direct SNI-shredded media throughput and YTM token affinity."""

import json
from pathlib import Path
import time
from typing import Any
from constants import (
    DEFAULT_BLOCKED_PATTERNS,
    DEFAULT_DOMESTIC_PATTERNS,
    GEOIP_RELAY_SUFFIXES,
)
from tunnel.doh_resolver import is_rfc1035_valid_hostname, is_youtube_video_edge_host

# Match any hostname containing IP/location/fingerprint keywords so unknown geo-checkers route through US relays with zero configuration.
_LOCATION_HEURISTIC_TOKENS = (
    "location", "myip", "ipinfo", "ipleak", "geoip", "ipapi", "ip-api",
    "whoer", "leaktest", "whatismy", "whatsmy", "whereami", "ipcheck",
    "ipdata", "ipwhois", "freegeoip", "geoloc", "ip2loc", "ipfinger",
    "fingerprint", "browserleak", "pixelscan", "iphey", "amiunique",
    "creepjs", "ja3", "ja4", "deviceinfo", "coveryourtracks", "tls.peet",
)

# Keep only exact public search, translate, and YouTube/Chrome companion endpoints direct so restricted Google subdomains (*.google.com) still get US relay.
_DIRECT_EXACT_HOSTS = {
    "google.com", "www.google.com", "translate.google.com",
    "clients1.google.com", "clients2.google.com", "clients3.google.com",
    "clients4.google.com", "clients5.google.com", "clients6.google.com",
    "waa-pa.clients6.google.com", "signaler-pa.clients6.google.com", "ogads-pa.clients6.google.com",
    "ogs.google.com", "apis.google.com", "consent.youtube.com", "consent.google.com", "accounts.youtube.com",
}

# Offload search engines, global static CDNs, and high-bandwidth media onto direct SNI-shredded links to avoid relay saturation and Incognito CAPTCHAs.
_DIRECT_JET_MEDIA_SUFFIXES = (
    "youtube.com", "youtu.be", "youtube-nocookie.com", "withyoutube.com",
    "googlevideo.com", "gvt1.com", "ytimg.com", "ggpht.com", "gstatic.com",
    "fonts.googleapis.com", "ajax.googleapis.com", "jnn-pa.googleapis.com", "youtubei.googleapis.com",
    "googleusercontent.com", "play.google.com", "widevine.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "duckduckgo.com",
    "bing.com", "msn.com", "akamaized.net", "pinterest.com", "pinimg.com", "gameloop.com",
)


def is_heuristic_location_host(host: str) -> bool:
    """Detect IP-lookup and browser-fingerprinting domains heuristically so newly created checker sites never see the domestic IP."""
    h = host.lower().strip().rstrip(".")
    return any(tok in h for tok in _LOCATION_HEURISTIC_TOKENS)


_SEARCH_IDENTITY_SUFFIXES = (
    "google.com", "bing.com", "duckduckgo.com", "startpage.com", "search.brave.com", "github.com",
)
_ZERO_CAPTCHA_EXACT_HOSTS = {
    "accounts.youtube.com", "play.google.com", "translate.google.com",
    "clients1.google.com", "clients2.google.com", "clients3.google.com",
    "clients4.google.com", "clients5.google.com", "clients6.google.com",
    "waa-pa.clients6.google.com", "signaler-pa.clients6.google.com", "ogads-pa.clients6.google.com",
    "ogs.google.com", "apis.google.com", "consent.youtube.com", "consent.google.com",
}


_GOOGLE_AI_TRIGGERS = (
    "aistudio.google.com", "alkalimakersuite", "makersuite.google.com",
    "gemini.google.com", "notebooklm.google.com",
    "colab.research.google.com", "idx.google.com", "generativelanguage.googleapis.com",
)


def is_youtube_zero_captcha_host(host: str, ytm_active: bool = False, google_ai_active: bool = False) -> bool:
    """Keep stateless static CDNs and YouTube video on direct links while routing search engines via GEOIP_RELAY to hide user location."""
    h = host.lower().strip().rstrip(".")
    if h == "music.youtube.com" or h.endswith(".music.youtube.com") or (ytm_active and (h.endswith(".googlevideo.com") or is_youtube_video_edge_host(h))):
        return False
    if google_ai_active and h != "translate.google.com" and h.endswith((".google.com", ".googleapis.com")):
        return False
    if h in _ZERO_CAPTCHA_EXACT_HOSTS:
        return True
    if any(h == s or h.endswith("." + s) for s in _SEARCH_IDENTITY_SUFFIXES):
        return False
    return is_direct_jet_media_host(h)


def is_direct_jet_media_host(host: str) -> bool:
    """Route search engines, global static CDNs, YouTube video, and GitHub assets on direct SNI-shredded links to prevent relay congestion."""
    h = host.lower().strip().rstrip(".")
    if h == "music.youtube.com" or h.endswith(".music.youtube.com"):
        return False
    return h in _DIRECT_EXACT_HOSTS or any(h == s or h.endswith("." + s) for s in _DIRECT_JET_MEDIA_SUFFIXES)


def _matches_pattern(host: str, pattern: str) -> bool:
    """Support suffix (.ir), prefix (149.154.), IPv6 (2001:), and exact domain matching so one predicate handles all routing rules."""
    clean_host = host.lower().strip().rstrip(".")
    clean_pat = pattern.lower().strip()
    if not clean_pat:
        return False
    if clean_pat.startswith("."):
        return clean_host.endswith(clean_pat) or clean_host == clean_pat.lstrip(".")
    if clean_pat.endswith((".", ":")) or clean_pat.startswith("2001:"):
        return clean_host.startswith(clean_pat)
    return clean_host == clean_pat or clean_host.endswith("." + clean_pat)


class SmartRouter:
    """Classify every outbound host into GEOIP_RELAY, TUNNEL, DIRECT, or BLOCK so media stays fast while geo-blocked apps use US IPs."""

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path
        self.location_cloak_all = False
        self.strict_privacy_partitioning = False
        self.ytm_session_active = False
        self.google_ai_session_active = False
        if self.rules_path is not None:
            self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        self.custom_rules: list[dict[str, str]] = self._load_rules()
        self.counts = {"GEOIP_RELAY": 0, "TUNNEL": 0, "DIRECT": 0, "BLOCK": 0}
        self.recent_decisions: list[dict[str, Any]] = []

    def _load_rules(self) -> list[dict[str, str]]:
        """Seed GeoIP relay rules before domestic and block patterns so critical AI/developer platforms are protected by default."""
        rules: list[dict[str, str]] = [
            {"pattern": pat, "action": "GEOIP_RELAY"} for pat in GEOIP_RELAY_SUFFIXES
        ]
        existing = {r["pattern"] for r in rules}
        for pat in DEFAULT_DOMESTIC_PATTERNS:
            if pat not in existing:
                rules.append({"pattern": pat, "action": "DIRECT"})
                existing.add(pat)
        for pat in DEFAULT_BLOCKED_PATTERNS:
            if pat not in existing:
                rules.append({"pattern": pat, "action": "BLOCK"})
                existing.add(pat)
        self._save_rules(rules)
        return rules

    def _save_rules(self, rules: list[dict[str, str]]) -> None:
        """Write routing rules to disk only when an explicit path is configured so Ghost Mode leaves zero trace files."""
        if self.rules_path is not None:
            self.rules_path.write_text(json.dumps(rules, indent=2), encoding="utf-8")

    def add_rule(self, pattern: str, action: str) -> dict[str, str]:
        """Prepend custom or auto-promoted rules at index 0 so dynamic 403/CNAME escalations override default fallbacks."""
        act = action.upper().strip()
        if act not in ("GEOIP_RELAY", "TUNNEL", "DIRECT", "BLOCK"):
            raise ValueError(f"Unsupported routing action: {action}")
        pat = pattern.lower().strip()
        if not pat:
            raise ValueError("Routing pattern cannot be empty")
        rule = {"pattern": pat, "action": act}
        self.custom_rules = [r for r in self.custom_rules if r["pattern"] != pat]
        self.custom_rules.insert(0, rule)
        self._save_rules(self.custom_rules)
        return rule

    def decide(self, host: str) -> str:
        """Route googlevideo.com through GEOIP_RELAY during active YouTube Music sessions because YTM binds stream URLs to the player exit IP."""
        h = host.lower().strip().rstrip(".")
        if h and not h.startswith(("127.", "192.168.", "10.", "149.154.", "91.108.", "2001:")) and not is_rfc1035_valid_hostname(h):
            self.counts["BLOCK"] = self.counts.get("BLOCK", 0) + 1
            return "BLOCK"
        if h == "music.youtube.com" or h.endswith(".music.youtube.com"):
            self.ytm_session_active = True
        elif h in ("www.youtube.com", "m.youtube.com", "youtube.com", "youtu.be", "accounts.youtube.com", "jnn-pa.googleapis.com", "i.ytimg.com", "s.ytimg.com"):
            self.ytm_session_active = False
            self.google_ai_session_active = False
        if any(tok in h for tok in _GOOGLE_AI_TRIGGERS):
            self.google_ai_session_active = True
        action = "TUNNEL"
        for rule in self.custom_rules:
            if _matches_pattern(host, rule["pattern"]):
                action = rule["action"]
                break
        is_local_lan = any(_matches_pattern(h, p) for p in ("localhost", "127.0.0.1", "192.168.", "10.", ".local"))
        if self.strict_privacy_partitioning and action in ("TUNNEL", "DIRECT") and not is_local_lan and not is_youtube_zero_captcha_host(h, self.ytm_session_active, self.google_ai_session_active):
            action = "GEOIP_RELAY"
        elif action == "TUNNEL":
            if (self.google_ai_session_active and h != "translate.google.com" and h.endswith((".google.com", ".googleapis.com"))) or (self.ytm_session_active and (h.endswith(".googlevideo.com") or is_youtube_video_edge_host(h))) or is_heuristic_location_host(h) or (self.location_cloak_all and not is_direct_jet_media_host(h)):
                action = "GEOIP_RELAY"
        self.counts[action] = self.counts.get(action, 0) + 1
        self.recent_decisions.insert(0, {"host": host, "action": action, "ts": int(time.time())})
        del self.recent_decisions[30:]
        return action

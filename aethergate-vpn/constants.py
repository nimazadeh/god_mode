"""Centralized protocol, network, and anti-censorship constants to prevent magic numbers and keep DPI evasion deterministic."""

from pathlib import Path

AETHERGATE_VERSION = "v11.13"
BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
PROFILES_PATH = CONFIG_DIR / "profiles.json"
ROUTING_PATH = CONFIG_DIR / "routing_rules.json"
ROUTING_RULES_PATH = ROUTING_PATH
DNS_CACHE_PATH = CONFIG_DIR / "dns_cache.json"
MINED_IPS_PATH = CONFIG_DIR / "mined_clean_ips.json"
DIAG_LOG_PATH = LOGS_DIR / "aethergate_diagnostics.log"

# Separate control plane (:9090), unified client proxy (:10808), and camouflage server (:8443) so local probes never collide.
DASHBOARD_PORT = 9090
INBOUND_PROXY_PORT = 10808
TUNNEL_SERVER_PORT = 8443
DEFAULT_SERVER_PORT = TUNNEL_SERVER_PORT

# Enforce a 300-second RFC 9421 signature window so captured tunnel frames cannot be replayed by active DPI middleboxes.
DEFAULT_SECRET_KEY = "aethergate-rfc9421-personal-master-key-2026"
DEFAULT_SHARED_SECRET = DEFAULT_SECRET_KEY
DEFAULT_PERSONAL_CF_WORKER = "frosty-bush-aethergate.nimazadeh963.workers.dev"
RFC9421_MAX_CLOCK_SKEW_SEC = 300
MAX_CLOCK_SKEW_SECONDS = RFC9421_MAX_CLOCK_SKEW_SEC
NONCE_CACHE_LIMIT = 4096

# Pad tunnel frames per RFC 9113 Section 6.1 so packet-length classifiers cannot fingerprint inner TLS handshakes.
RFC9113_DATA_FRAME_TYPE = 0x00
RFC9113_FLAG_PADDED = 0x08
RFC9113_HEADER_LEN = 4
DEFAULT_MIN_PAD_BYTES = 16
DEFAULT_MAX_PAD_BYTES = 224
MAX_FRAME_PAYLOAD_BYTES = 65000

RFC_CACHE_DEFAULT_TTL_SEC = 60
RFC_CACHE_MAX_ENTRIES = 256

SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCEEDED = 0x00

SUPPORTED_TRANSPORTS = ("DPI_DESYNC_DOH", "WS_RFC8441", "CHUNKED_RFC9112", "CONNECT_RFC9110")
TRANSPORT_MODES = SUPPORTED_TRANSPORTS

# Bypass domestic and RFC 1918 private destinations so local banking and LAN traffic never incur tunnel latency.
DEFAULT_DOMESTIC_PATTERNS = ("localhost", "127.0.0.1", "192.168.", "10.", ".ir", ".local")
DEFAULT_BYPASS_SUFFIXES = DEFAULT_DOMESTIC_PATTERNS

# Block telemetry, Wi-Fi BSSID geolocation APIs, WebRTC STUN servers, and fingerprint scripts to prevent identity/location leaks.
DEFAULT_BLOCKED_PATTERNS = (
    "doubleclick.net", "googlesyndication.com", "adservice.google.com", "googleadservices.com",
    "googletagmanager.com", "google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
    "adtrafficquality.google", "beacons.gcp.gvt2.com", "beacons.gvt2.com", "beacons2.gvt2.com", "beacons3.gvt2.com", "beacons4.gvt2.com", "beacons5.gvt2.com", "gvt2.com",
    "beacons.gvt3.com", "beacons5.gvt3.com", "gvt3.com", "optimizationguide-pa.googleapis.com", "content-autofill.googleapis.com", "mtalk.google.com",
    "csp.withgoogle.com", "sba.yandex.net", "telemetry.microsoft.com", "config.edge.skype.com", "h.trace.qq.com", "liadm.com", "d-code.liadm.com",
    "events.data.microsoft.com", "events.data.msn.com", "browser.events.data.msn.com", "otf.msn.com",
    "srtb.msn.com", "scorecardresearch.com", "sb.scorecardresearch.com",
    "turing-writingassistance.edge.microsoft.com", "editor.svc.cloud.microsoft",
    "browser-intake-us3-datadoghq.com", "amazon-adsystem.com",
    "location.services.mozilla.com", "inference.location.live.net", "gs-loc.apple.com",
    "skyhookwireless.com", "combain.com", "unwiredlabs.com", "stun.l.google.com", "stun1.l.google.com",
    "stun.cloudflare.com", "stun.services.mozilla.com", "global.stun.twilio.com",
    "fpjs.io", "openfpcdn.io", "fingerprintjs.com", "online-metrix.net", "px-cdn.net", "perimeterx.net",
    "clarity.ms", "hotjar.com", "fullstory.com", "mouseflow.com", "logrocket.io", "smartlook.com",
)
DEFAULT_BLOCK_SUFFIXES = DEFAULT_BLOCKED_PATTERNS

# Reject Iranian DNS sinkhole prefixes (10.10.34.*) and bogon answers so poisoned UDP DNS triggers Zero-SNI DoH fallback.
POISONED_IP_PREFIXES = ("10.10.34.", "0.0.0.0", "127.0.0.1")

# Exclusively use US/Canada Google Zero-SNI DoH resolvers (8.8.8.8/8.8.4.4) because 1.1.1.1 routes from Iran to Cloudflare's Astara/Baku POP.
DOH_SERVERS_NO_SNI = (
    ("8.8.8.8", "dns.google", "/resolve"),
    ("8.8.4.4", "dns.google", "/resolve"),
)

# Verified Anycast VIPs and blackholed Caucasus GGC prefixes so media streams avoid dead regional cache nodes.
GFE_ANYCAST_VIP = "216.239.38.120"
GVS_CORE_VIP = "173.194.16.198"
BLACKHOLED_GGC_PREFIXES = ("62.212.", "94.20.")
CF_ANYCAST_VIP = "104.18.14.206"
GITHUB_RAW_VIP = "185.199.108.133"

# Restrict Cloudflare miner candidates to 104.18.* because 104.16/17/19.* trigger Cloudflare Error 1034 on third-party Host headers.
CF_MINER_CANDIDATES = ("104.18.14.206", "104.18.15.206", "104.18.12.206", "104.18.13.206")
GFE_MINER_CANDIDATES = ("216.239.38.120", "216.239.32.120", "216.239.34.120", "216.239.36.120", "142.250.185.78")
PREWARM_POOL_TARGET_SIZE = 4
PREWARM_MAX_IDLE_SEC = 24.0

# Prioritize non-standard SOCKS5/HTTP ports first and exclude port 3128 Squid proxies and Asian 43.*/139.* prefixes to prevent CAPTCHAs and 5s stalls.
DEFAULT_GEOIP_RELAYS = (
    ("socks5", "67.207.92.87", 1088),
    ("http", "62.146.180.4", 3000),
    ("socks5", "107.174.30.92", 1080),
    ("socks5", "52.128.241.109", 1080),
    ("socks5", "45.149.92.160", 1080),
    ("socks5", "45.74.31.42", 7770),
    ("socks5", "45.74.31.46", 15194),
    ("http", "137.74.50.101", 15054),
    ("http", "159.89.119.49", 10000),
    ("socks5", "107.174.30.93", 1080),
)

# Enterprise CDN CNAME suffixes that enforce strict US/EU export compliance and return HTTP 403 to sanctioned exit IPs.
SANCTION_CNAME_SUFFIXES = (
    "edgekey.net", "akamaiedge.net", "edgesuite.net", "akamai.net",
    "akamaitechnologies.com", "cdn.cloudflare.net", "incapdns.net", "impervadns.net", "awswaf.com",
)

# Universal HTTP body signatures emitted by WAFs and regional blocks so unknown domains auto-promote to GEOIP_RELAY.
ACCESS_DENIED_SIGNATURES = (
    b"access denied", b"your client does not have permission", b"that's an error",
    b"that\xe2\x80\x99s an error", b"errors.edgesuite.net", b"akamaighost", b"export restrictions",
    b"country subject to", b"sorry, you have been blocked", b"block access from your country",
    b"not available in your country", b"not available in your region", b"unavailable in your region",
    b"unsupported country", b"region not supported", b"_incapsula_resource", b"451 unavailable",
    b"error 1009", b"error 1020", b"geo-restricted", b"georestricted",
    b"10.10.34.36", b"<title>ntl1</title>", b"<title>nte1</title>", b"invalidkeyword&policy=mainpolicy",
)

GEOIP_RELAY_SUFFIXES = (
    "149.154.", "91.108.", "2001:b28:f23", "2001:67c:4e8:", "arena.ai", "lmarena.ai", "arena.site", "lmsys.org",
    "startpage.com", "duckduckgo.com", "search.brave.com",
    "music.youtube.com", "remix.music.youtube.com", "mylocation.org", "iplocation.net", "iplocation.io",
    "geolocation.com", "geoiptool.com", "pixelscan.net", "iphey.com", "amiunique.org", "coveryourtracks.eff.org",
    "tls.peet.ws", "ja3er.com", "creepjs.com", "deviceinfo.me", "fv.pro",
    "whatismyip.com", "whatismyip.org", "showmyip.com", "whoismyisp.org", "ip2location.com", "ipdata.co",
    "ipgeolocation.io", "ipregistry.co", "ipwhois.io", "abstractapi.com", "bigdatacloud.com",
    "extreme-ip-lookup.com", "freegeoip.app", "geojs.io", "ipapi.com", "ipfingerprints.com", "check-host.net",
    "dnsleaktest.com", "bash.ws", "ipchicken.com", "whatsmyip.com", "whatsmyip.org", "myexternalip.com",
    "canyouseeme.org", "ipinfo.io", "ipleak.net", "whoer.net", "browserleaks.com", "whatismyipaddress.com",
    "ifconfig.me", "ifconfig.co", "ipify.org", "icanhazip.com", "ident.me", "checkip.amazonaws.com",
    "myip.com", "db-ip.com", "ipapi.co", "ip-api.com", "maxmind.com",
    "challenges.cloudflare.com", "cloudflareinsights.com", "turnstile.com",
    "r2.cloudflarestorage.com", "posthog.com", "pusher.com", "pusherapp.com",
    "vercel.live", "vercel.com", "trigger.dev", "merge.dev", "sentry.io",
    "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "claude.ai", "anthropic.com",
    "intel.com", "amd.com", "nvidia.com", "oracle.com", "java.com", "cisco.com", "dell.com",
    "delltechnologies.com", "ibm.com", "redhat.com", "openshift.com", "vmware.com", "broadcom.com",
    "hp.com", "hpe.com", "autodesk.com", "adobe.com", "mathworks.com", "ti.com", "mouser.com",
    "digikey.com", "nxp.com", "microchip.com", "analog.com", "keysight.com", "synopsys.com",
    "cadence.com", "ansys.com", "arm.com", "qualcomm.com", "xilinx.com", "crucial.com", "micron.com",
    "edgesuite.net", "edgekey.net", "akamaiedge.net", "awswaf.com",
    "android.com", "google.dev", "aistudio.google.com", "gemini.google.com", "bard.google.com",
    "notebooklm.google.com", "idx.google.com", "alkalimakersuite-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com", "makersuite-pa.clients6.google.com",
    "cloudconsole-pa.clients6.google.com",
    "accounts.google.com", "myaccount.google.com", "developers.google.com", "cloud.google.com",
    "console.cloud.google.com", "firebase.google.com", "colab.research.google.com",
    "dl.google.com", "maven.google.com", "content.googleapis.com", "generativelanguage.googleapis.com",
    "apikeys.googleapis.com", "cloudresourcemanager.googleapis.com", "serviceusage.googleapis.com",
    "iam.googleapis.com", "storage.googleapis.com", "firebase.googleapis.com", "people.googleapis.com",
    "kaggle.com", "golang.org", "pkg.go.dev", "flutter.dev", "dart.dev", "pub.dev",
    "chromium.org", "googlesource.com", "gradle.org", "jetbrains.com", "kotlinlang.org",
    "gitlab.com", "atlassian.com", "bitbucket.org", "postman.com", "figma.com", "notion.so",
    "linear.app", "supabase.com", "coursera.org", "udemy.com", "edx.org", "unity.com",
    "unrealengine.com", "epicgames.com", "zoom.us", "slack.com", "canva.com",
    "reddit.com", "redd.it", "medium.com", "spotify.com", "docker.com", "huggingface.co", "telegram.org",
)

GFE_YOUTUBE_SUFFIXES = (
    "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "withyoutube.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com",
    "android.com", "google.dev", "recaptcha.net", "redirector.googlevideo.com", "manifest.googlevideo.com",
)

CF_PROTECTED_SUFFIXES = (
    "arena.ai", "lmarena.ai", "arena.site", "challenges.cloudflare.com", "cloudflareinsights.com",
    "cdnjs.cloudflare.com", "chatgpt.com", "openai.com", "claude.ai", "discord.com", "discord.gg", "discordapp.com",
    "whoer.net", "pixelscan.net",
)

CLEAN_ANYCAST_FALLBACKS = {
    "arena.ai": CF_ANYCAST_VIP, "www.arena.ai": CF_ANYCAST_VIP, "lmarena.ai": CF_ANYCAST_VIP,
    "challenges.cloudflare.com": CF_ANYCAST_VIP, "static.cloudflareinsights.com": CF_ANYCAST_VIP,
    "cdnjs.cloudflare.com": CF_ANYCAST_VIP, "chatgpt.com": CF_ANYCAST_VIP, "claude.ai": CF_ANYCAST_VIP,
    "whoer.net": CF_ANYCAST_VIP, "www.whoer.net": CF_ANYCAST_VIP,
    "pixelscan.net": CF_ANYCAST_VIP, "www.pixelscan.net": CF_ANYCAST_VIP,
    "browserleaks.com": "104.236.69.55", "www.browserleaks.com": "104.236.69.55",
    "tls.browserleaks.com": "138.197.54.100", "quic.browserleaks.com": "138.197.54.100",
    "tls13.browserleaks.com": "104.236.69.55", "tls12.browserleaks.com": "104.236.69.55",
    "tls11.browserleaks.com": "104.236.69.55", "tls10.browserleaks.com": "104.236.69.55",
    "i.pinimg.com": "151.101.192.84",
    "www.recaptcha.net": GFE_ANYCAST_VIP, "recaptcha.net": GFE_ANYCAST_VIP,
    "translate.google.com": GFE_ANYCAST_VIP, "developer.android.com": GFE_ANYCAST_VIP,
    "aistudio.google.com": GFE_ANYCAST_VIP, "youtube.com": GFE_ANYCAST_VIP, "www.youtube.com": GFE_ANYCAST_VIP,
    "m.youtube.com": GFE_ANYCAST_VIP, "music.youtube.com": GFE_ANYCAST_VIP, "youtu.be": GFE_ANYCAST_VIP,
    "i.ytimg.com": GFE_ANYCAST_VIP, "s.ytimg.com": GFE_ANYCAST_VIP, "yt3.ggpht.com": GFE_ANYCAST_VIP,
    "youtubei.googleapis.com": GFE_ANYCAST_VIP, "jnn-pa.googleapis.com": GFE_ANYCAST_VIP,
    "waa-pa.clients6.google.com": GFE_ANYCAST_VIP, "signaler-pa.clients6.google.com": GFE_ANYCAST_VIP,
    "ogads-pa.clients6.google.com": GFE_ANYCAST_VIP, "ogs.google.com": GFE_ANYCAST_VIP,
    "apis.google.com": GFE_ANYCAST_VIP, "consent.youtube.com": GFE_ANYCAST_VIP, "consent.google.com": GFE_ANYCAST_VIP,
    "github.com": "140.82.121.4",
    "raw.githubusercontent.com": GITHUB_RAW_VIP, "x.com": "104.244.42.1", "twitter.com": "104.244.42.1",
    "telegram.org": "149.154.167.99", "web.telegram.org": "149.154.167.99",
}

TLS_FRAGMENT_CHUNK_SIZE = 5
TLS_FRAGMENT_HEADER_WINDOW = 96

# IETF RFC 10024 (August 2026) and NIST FIPS 203 post-quantum hybrid TLS 1.3 parameters so handshakes resist Harvest-Now-Decrypt-Later attacks.
RFC10024_GROUP_SECP256R1MLKEM768 = 0x11EB
RFC10024_GROUP_X25519MLKEM768 = 0x11EC
RFC10024_GROUP_SECP384R1MLKEM1024 = 0x11ED
RFC10024_OBSOLETE_KYBER768_DRAFT00 = 0x6399
FIPS203_MLKEM_Q = 3329
FIPS203_MLKEM768_EK_LEN = 1184
RFC10024_CLIENT_SHARE_LEN = 1216
RFC10024_SERVER_SHARE_LEN = 1120
RFC10024_SHARED_SECRET_LEN = 64

# FOCI 2026 Iranian border gateway DPI middlebox TTL clusters (NTL1 and NTE1) so injected RSTs and blockpages are fingerprinted immediately.
IRAN_DPI_NTL1_TTL_RANGE = (53, 55)
IRAN_DPI_NTE1_TTL_RANGE = (186, 188)


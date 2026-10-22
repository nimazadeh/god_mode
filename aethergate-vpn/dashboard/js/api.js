/* Centralize all HTTP API calls in one thin transport wrapper so UI modules never hardcode fetch URLs or headers. */
window.AetherApi = {
  lastCacheStatus: "BYPASS",

  /* Capture RFC 9211 Cache-Status headers on every response so the UI can prove in-memory HTTP cache hits without extra requests. */
  async fetchJson(url, options = {}) {
    const res = await fetch(url, options);
    const cs = res.headers.get("cache-status");
    if (cs) this.lastCacheStatus = cs;
    return res.json();
  },

  /* Poll unified tunnel, relay, and cache telemetry in one round-trip to prevent multi-request UI jitter. */
  getState() {
    return this.fetchJson("/api/live/state");
  },

  /* Synchronize the browser tunnel toggle with the OS WinINet system proxy in a single atomic POST. */
  toggleTunnel() {
    return this.fetchJson("/api/tunnel/toggle", { method: "POST" });
  },

  /* Persist transport and RFC 9113 padding changes immediately so active proxy streams switch framing without a restart. */
  selectTransport(transport, paddingEnabled) {
    return this.fetchJson("/api/tunnel/transport", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transport, padding_enabled: paddingEnabled }),
    });
  },

  /* Trigger an in-process RFC 9421 + RFC 9298 self-test so operators can verify cryptographic framing offline. */
  runBenchmark() {
    return this.fetchJson("/api/tunnel/benchmark", { method: "POST" });
  },

  /* Simulate an unauthenticated DPI scanner probe to verify the server returns a decoy HTML page instead of proxy errors. */
  probeCamouflage() {
    return this.fetchJson("/api/tunnel/probe-camouflage", { method: "POST" });
  },

  /* Hot-swap the active VPS server URI and secret key at runtime so users never edit JSON files manually. */
  importProfileUri(uri) {
    return this.fetchJson("/api/profiles/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uri }),
    });
  },

  /* Prepend custom domain routing rules at index 0 so user overrides take precedence over built-in heuristics. */
  addRoutingRule(pattern, action) {
    return this.fetchJson("/api/routing/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pattern, action }),
    });
  },

  /* Fetch the latest bounded RAM connection log ring so the live stream console updates with zero disk I/O. */
  getDiagnostics() {
    return this.fetchJson("/api/diagnostics/logs");
  },

  /* Execute on-demand 7-point DNS/TLS/ECH probes when the user explicitly requests a manual health audit. */
  runDiagnostics() {
    return this.fetchJson("/api/diagnostics/run", { method: "POST" });
  },

  /* Harvest and rank fresh US/EU SOCKS5/HTTP relays from GitHub over SNI-shredded TLS when an active relay degrades. */
  refreshRelays() {
    return this.fetchJson("/api/relays/refresh", { method: "POST" });
  },

  /* Probe Anycast candidates for genuine TLS 1.3 ServerHellos and pre-warm 0-RTT SOCKS5 sockets. */
  mineCleanIps() {
    return this.fetchJson("/api/satoshi/mine-ips", { method: "POST" });
  },

  /* Toggle RFC 1918 LAN ACLs so mobile phones on the same Wi-Fi can route through the PC tunnel. */
  toggleLanGateway() {
    return this.fetchJson("/api/satoshi/lan-gateway", { method: "POST" });
  },

  /* Toggle global US IP cloaking while keeping high-bandwidth video on direct SNI-shredded links. */
  toggleLocationCloak() {
    return this.fetchJson("/api/satoshi/location-cloak", { method: "POST" });
  },
};

/* Bind topbar stream filters, pause controls, and 2-second background polling while keeping secondary controls non-blocking. */
window.AetherApp = {
  /* Wire instant client-side log filtering and control actions with zero page reloads on the canonical http://127.0.0.1:9090/ console. */
  async init() {
    const byId = (id) => document.getElementById(id);

    /* Filter cached console lines in memory on every keystroke so searching never waits on the 2-second poll cycle. */
    byId("log-search-input")?.addEventListener("input", (e) => {
      window.AetherUI.searchQuery = String(e.target?.value || "").trim().toLowerCase();
      window.AetherUI.renderConsole();
    });

    /* Freeze DOM log updates when paused so operators can inspect and copy specific handshake lines without stream drift. */
    byId("btn-pause-log")?.addEventListener("click", () => {
      window.AetherUI.paused = !window.AetherUI.paused;
      const pbtn = byId("btn-pause-log");
      if (pbtn) {
        pbtn.textContent = window.AetherUI.paused ? "Resume Stream [PAUSED]" : "Pause Stream";
        pbtn.className = window.AetherUI.paused ? "btn btn-primary" : "btn";
      }
      window.AetherUI.setText("diag-copy-status", window.AetherUI.paused ? "Stream Paused" : "Live Stream");
    });

    document.querySelectorAll("[data-log-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("[data-log-filter]").forEach((b) => { b.className = "btn"; });
        btn.className = "btn btn-primary";
        window.AetherUI.logFilter = btn.dataset.logFilter || "ALL";
        window.AetherUI.renderConsole();
      });
    });

    byId("btn-toggle-tunnel")?.addEventListener("click", async () => { await window.AetherApi.toggleTunnel(); await this.refresh(); });
    byId("btn-run-benchmark")?.addEventListener("click", () => this.handleBenchmark());
    byId("btn-test-camouflage")?.addEventListener("click", () => this.handleCamouflageProbe());
    byId("btn-import-uri")?.addEventListener("click", () => this.handleImportUri());
    byId("btn-add-route")?.addEventListener("click", () => this.handleAddRoute());
    byId("btn-run-diag")?.addEventListener("click", () => this.handleRunDiag());
    byId("btn-mine-ips")?.addEventListener("click", () => this.handleMineIps());
    byId("btn-refresh-relays")?.addEventListener("click", () => this.handleRefreshRelays());
    byId("btn-toggle-lan")?.addEventListener("click", () => this.handleToggleLan());
    byId("btn-toggle-cloak")?.addEventListener("click", () => this.handleToggleCloak());
    byId("btn-copy-diag")?.addEventListener("click", () => this.handleCopyDiag());

    await this.refresh();
    setInterval(() => this.refresh(), 2000);
  },

  /* Fetch state and logs in parallel via Promise.all so each poll cycle completes in a single RTT. */
  async refresh() {
    try {
      const [st, diag] = await Promise.all([window.AetherApi.getState(), window.AetherApi.getDiagnostics()]);
      window.AetherUI.renderState(st, diag);
    } catch (err) {
      console.error("State poll error:", err);
    }
  },

  async handleRunDiag() {
    window.AetherUI.paused = false;
    window.AetherUI.setText("diag-copy-status", "Running probes...");
    const res = await window.AetherApi.runDiagnostics();
    window.AetherUI.renderDiagEvents([], res.report_text);
    window.AetherUI.setText("diag-copy-status", "Probes complete");
  },

  async handleRefreshRelays() {
    const res = await window.AetherApi.refreshRelays();
    window.AetherUI.setText("diag-copy-status", `Active: ${res.active_relay} (${res.pool_size})`);
    await this.refresh();
  },

  async handleMineIps() {
    window.AetherUI.setText("diag-copy-status", "Mining clean Anycast IPs...");
    const res = await window.AetherApi.mineCleanIps();
    window.AetherUI.setText("diag-copy-status", `Mined CF: ${res.best_cf_ip} (${res.best_cf_rtt_ms}ms) • GFE: ${res.best_gfe_ip} (${res.best_gfe_rtt_ms}ms)`);
    await this.refresh();
  },

  async handleToggleLan() {
    const res = await window.AetherApi.toggleLanGateway();
    window.AetherUI.setText("diag-copy-status", res.enabled ? `LAN Gateway ON (${res.endpoint})` : "LAN Gateway OFF");
    await this.refresh();
  },

  async handleToggleCloak() {
    const res = await window.AetherApi.toggleLocationCloak();
    window.AetherUI.setText("diag-copy-status", res.location_cloak_all ? "US Location Cloak: GLOBAL ON" : "US Location Cloak: Selective");
    await this.refresh();
  },

  async handleCopyDiag() {
    const box = document.getElementById("diag-report-box");
    if (box && navigator.clipboard) await navigator.clipboard.writeText(box.value);
    window.AetherUI.setText("diag-copy-status", "COPIED TO CLIPBOARD!");
  },

  async handleBenchmark() {
    const r = await window.AetherApi.runBenchmark();
    window.AetherUI.setText("benchmark-result-box", r.ok ? `RFC 9421 VERIFIED • ${r.transport} • RTT ${r.rtt_ms} ms` : "FAILED");
    await this.refresh();
  },

  async handleCamouflageProbe() {
    const r = await window.AetherApi.probeCamouflage();
    window.AetherUI.setText("camouflage-probe-status", `${r.snippet} (Cache: ${r.server_cache_status})`);
  },

  async handleImportUri() {
    const input = document.getElementById("profile-uri-input");
    if (input?.value) { await window.AetherApi.importProfileUri(input.value); await this.refresh(); }
  },

  async handleAddRoute() {
    const pattern = document.getElementById("route-pattern-input")?.value || "";
    const action = document.getElementById("route-action-select")?.value || "TUNNEL";
    if (pattern.trim()) { await window.AetherApi.addRoutingRule(pattern, action); await this.refresh(); }
  },
};

window.addEventListener("DOMContentLoaded", () => window.AetherApp.init());

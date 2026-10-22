/* Render live stream rows via textContent-only DOM nodes to eliminate XSS vectors and preserve scroll position during 2s polls. */
window.AetherUI = {
  logFilter: "ALL",
  searchQuery: "",
  paused: false,
  lastReportText: "",
  lastRenderedSignature: "",

  /* Assign textContent defensively so missing DOM IDs never throw or parse untrusted HTML strings. */
  setText(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = String(value);
    }
  },

  appendCell(tableRow, textValue) {
    const cellNode = document.createElement("td");
    cellNode.textContent = String(textValue ?? "-");
    tableRow.appendChild(cellNode);
  },

  addSpan(parentNode, className, textValue) {
    const spanNode = document.createElement("span");
    spanNode.className = className;
    spanNode.textContent = textValue;
    parentNode.appendChild(spanNode);
    return spanNode;
  },

  /*
   * Strip ASCII report banners (===/---) and static check summary lines ([OK]) so the sticky column header
   * always sits directly above chronological, live connection events with newest traffic at row 1.
   */
  matchesFilter(line) {
    if (!line || line.startsWith("===") || line.startsWith("---") || line.startsWith("[")) {
      return false;
    }
    if (this.searchQuery && !line.toLowerCase().includes(this.searchQuery)) {
      return false;
    }
    if (this.logFilter === "ALL") return true;
    if (this.logFilter === "ERR") return line.includes("ERR") || line.includes("FAIL");
    if (this.logFilter === "RELAY") return line.includes("socks5://") || line.includes("http://") || line.includes("GEOIP");
    return line.includes("SHREDDER") || line.includes("GFE_ANYCAST") || line.includes("TUNNEL") || line.includes("ENGINE_READY");
  },

  /* Colorize pipe-delimited columns semantically so errors, handshakes, and clean closures stand out at a glance. */
  classifySegment(segmentText, columnIndex, isCheckRow) {
    if (segmentText.includes("ERR") || segmentText.includes("FAIL")) return "tok-err";
    if (isCheckRow) {
      const checkPalette = ["tok-ok", "tok-info", "tok-host", "tok-warn", segmentText.includes("200 OK") ? "tok-ok" : "tok-warn"];
      return checkPalette[columnIndex] || "tok-info";
    }
    if (columnIndex === 0) return "tok-dim";
    if (columnIndex === 1) return "tok-info";
    if (columnIndex === 2) {
      if (segmentText.includes("CLOSED_OK") || segmentText.includes("ENGINE_READY")) return "tok-ok";
      return (segmentText.includes("HANDSHAKE") || segmentText.includes("CONNECT")) ? "tok-warn" : "tok-info";
    }
    if (columnIndex === 3) return "tok-host";
    if (segmentText.includes("rtt=") || segmentText.includes("REPLAYED")) return "tok-warn";
    return (segmentText.includes("SHREDDER") || segmentText.includes("VIP") || segmentText.includes("ACTIVE")) ? "tok-ok" : "tok-info";
  },

  /* Pin the column header inside the scroll container with position:sticky so column labels stay visible while scrolling deep logs. */
  buildStickyHeader() {
    const headerRow = document.createElement("div");
    headerRow.className = "console-sticky-hdr";
    headerRow.id = "console-sticky-header";
    const columnLabels = ["TIMESTAMP    ", " #ID  ", " STAGE         ", " TARGET / ENDPOINT          ", " TELEMETRY & ENGINE DETAILS"];
    columnLabels.forEach((label, index) => {
      this.addSpan(headerRow, "tok-hdr", label);
      if (index < columnLabels.length - 1) {
        this.addSpan(headerRow, "tok-dim", "│");
      }
    });
    return headerRow;
  },

  /* Make the #ID column interactive so clicking any correlation ID isolates that exact connection's full lifecycle. */
  renderLineDom(line) {
    const rowNode = document.createElement("div");
    rowNode.className = "console-line";
    const segments = line.split("│");
    const isCheckRow = line.startsWith("[");
    segments.forEach((segmentText, index) => {
      const spanNode = this.addSpan(rowNode, this.classifySegment(segmentText, index, isCheckRow), segmentText);
      if (index === 1 && segmentText.trim().startsWith("#")) {
        spanNode.style.cursor = "pointer";
        spanNode.title = "Click to isolate or unfilter this connection ID";
        spanNode.addEventListener("click", () => {
          const correlationId = segmentText.trim().toLowerCase();
          const searchInput = document.getElementById("log-search-input");
          this.searchQuery = this.searchQuery === correlationId ? "" : correlationId;
          if (searchInput) searchInput.value = this.searchQuery;
          this.renderConsole();
        });
      }
      if (index < segments.length - 1) {
        this.addSpan(rowNode, "tok-dim", "│");
      }
    });
    return rowNode;
  },

  /* Skip DOM rebuilds when the payload signature is unchanged and restore scrollTop so 2s polling never yanks the user's scroll position. */
  renderConsole(reportText) {
    if (reportText && !this.paused) this.lastReportText = reportText;
    const consoleView = document.getElementById("diag-console-view");
    if (!consoleView || !this.lastReportText) return;
    const renderSignature = `${this.logFilter}::${this.searchQuery}::${this.lastReportText}`;
    if (renderSignature === this.lastRenderedSignature && consoleView.children.length > 0) return;
    this.lastRenderedSignature = renderSignature;
    const previousScrollTop = consoleView.scrollTop;
    consoleView.textContent = "";
    consoleView.appendChild(this.buildStickyHeader());
    this.lastReportText.split("\n").filter((line) => this.matchesFilter(line)).forEach((line) => {
      consoleView.appendChild(this.renderLineDom(line));
    });
    consoleView.scrollTop = previousScrollTop;
  },

  /* Synchronize topbar badges, inline SVG country flags, and drawer metrics from the unified state snapshot. */
  renderState(state, diagData) {
    const stateBadge = document.getElementById("tunnel-state-badge");
    const powerBtn = document.getElementById("btn-toggle-tunnel");
    if (stateBadge) {
      stateBadge.textContent = state.connected ? "CONNECTED • PROTECTED" : "STANDBY (DISCONNECTED)";
      stateBadge.className = state.connected ? "badge badge-ok" : "badge badge-warn";
    }
    if (powerBtn) {
      powerBtn.textContent = state.connected ? "[DISCONNECT]" : "[CONNECT]";
      powerBtn.className = state.connected ? "btn btn-power btn-active" : "btn btn-power btn-primary";
    }
    this.setText("proxy-port-badge", `127.0.0.1:${state.inbound_port}`);
    if (state.satoshi?.lan_gateway) {
      const lanGateway = state.satoshi.lan_gateway;
      const lanBadge = document.getElementById("lan-gateway-badge");
      const lanBtn = document.getElementById("btn-toggle-lan");
      if (lanBadge) {
        lanBadge.textContent = lanGateway.enabled ? `LAN NODE: ${lanGateway.endpoint}` : "LAN NODE: OFF";
        lanBadge.className = lanGateway.enabled ? "badge badge-ok" : "badge";
      }
      if (lanBtn) {
        lanBtn.textContent = lanGateway.enabled ? `LAN Wi-Fi Node: ON (${lanGateway.lan_ip})` : "LAN Wi-Fi Node: OFF";
      }
    }
    if (state.satoshi) {
      this.setText("prewarm-pool-badge", `0-RTT POOL: ${state.satoshi.prewarm_ready || 0} READY • ${state.satoshi.prewarm_hits || 0} HITS`);
      const cloakBtn = document.getElementById("btn-toggle-cloak");
      if (cloakBtn) {
        cloakBtn.textContent = state.satoshi.location_cloak_all ? "US Cloak: GLOBAL ON" : "US Cloak: Selective";
        cloakBtn.className = state.satoshi.location_cloak_all ? "btn btn-primary" : "btn";
      }
    }
    this.setText("win-proxy-badge", state.system_proxy.enabled ? "SYS PROXY: ON" : "SYS PROXY: OFF");
    this.setText("cli-env-badge", state.system_proxy.cli_env_active ? "CLI ENV: ON" : "CLI ENV: OFF");
    this.setText("stat-rtt", `${state.telemetry.last_rtt_ms} ms`);
    this.setText("stat-packets", state.telemetry.packets_relayed);
    this.setText("stat-padding", `${state.telemetry.pad_bytes_total} B`);
    this.setText("stat-cache", `${state.rfc_cache.hits} HIT / ${state.rfc_cache.misses} MISS`);
    const countryMeta = state.routing?.country_meta;
    const flagImg = document.getElementById("active-geoip-flag");
    if (flagImg && countryMeta?.flag_svg) flagImg.src = countryMeta.flag_svg;
    if (state.routing?.active_geoip_relay) {
      this.setText("active-geoip-text", `${countryMeta?.location || "US/EU"} • ${state.routing.active_geoip_relay}`);
    }
    const rulesTbody = document.getElementById("routing-rules-tbody");
    if (rulesTbody) {
      rulesTbody.textContent = "";
      (state.routing.rules || []).slice(0, 6).forEach((rule) => {
        const tableRow = document.createElement("tr");
        [rule.pattern, rule.action, "Active"].forEach((val) => this.appendCell(tableRow, val));
        rulesTbody.appendChild(tableRow);
      });
    }
    if (diagData) this.renderDiagEvents(diagData.events || [], diagData.report_text || "");
  },

  /* Keep the hidden textarea populated with the full unclipped report so Copy Log exports every line to the clipboard. */
  renderDiagEvents(_events, reportText) {
    const reportBox = document.getElementById("diag-report-box");
    if (reportBox && reportText && !this.paused) {
      reportBox.value = reportText;
      reportBox.rows = Math.min(28, Math.max(16, reportText.split("\n").length + 1));
    }
    this.renderConsole(reportText);
  },
};

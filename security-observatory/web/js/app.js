(function () {
  "use strict";

  var appState = {
    featuredAudit: null,
    history: [],
    activeFilter: "all",
    toastTimer: null,
  };

  function byId(elementId) {
    return document.getElementById(elementId);
  }

  function clearChildren(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function makeEl(tagName, className, textValue) {
    var element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    if (textValue !== undefined && textValue !== null) {
      element.textContent = String(textValue);
    }
    return element;
  }

  function showToast(message) {
    var toast = byId("toast-banner");
    toast.textContent = message;
    toast.hidden = false;
    if (appState.toastTimer) {
      clearTimeout(appState.toastTimer);
    }
    appState.toastTimer = setTimeout(function () {
      toast.hidden = true;
    }, 2800);
  }

  function copyPlainText(textToCopy, successLabel) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(textToCopy)
        .then(function () {
          showToast(successLabel);
        })
        .catch(function () {});
    }
  }

  function setErrorMessage(message) {
    var box = byId("scan-error-box");
    if (!message) {
      box.textContent = "";
      box.hidden = true;
      return;
    }
    box.textContent = message;
    box.hidden = false;
  }

  function gradeVisualClass(grade) {
    if (grade === "A+" || grade === "A") {
      return "grade-good";
    }
    if (grade === "B" || grade === "C") {
      return "grade-mid";
    }
    return "grade-bad";
  }

  function statusBadgeMeta(status) {
    if (status === "pass") {
      return { label: "ایمن", cls: "status-pill status-pass" };
    }
    if (status === "warn") {
      return { label: "هشدار پیکربندی", cls: "status-pill status-warn" };
    }
    return { label: "نیازمند اصلاح", cls: "status-pill status-fail" };
  }

  function renderKpis(kpis) {
    byId("kpi-total-scans").textContent = String(kpis.total_scans || 0);
    byId("kpi-average-score").textContent = String(kpis.average_score || 0) + " از 100";
    byId("kpi-hardened-count").textContent = String(kpis.hardened_sites_count || 0);
    byId("kpi-critical-count").textContent = String(kpis.critical_sites_count || 0);
  }

  function renderSurfaceHygiene(surface) {
    var grid = byId("surface-hygiene-grid");
    clearChildren(grid);

    var items = [
      {
        title: "منابع ناامن Mixed Content",
        value: String(surface.mixed_content_urls || 0) + " مورد",
      },
      {
        title: "فرم‌های رمز عبور ناامن",
        value: String(surface.insecure_password_forms || 0) + " مورد",
      },
      {
        title: "لینک‌های _blank بدون noopener",
        value: String(surface.unsafe_blank_links || 0) + " مورد",
      },
      {
        title: "فایل استاندارد security.txt",
        value: surface.has_security_txt_link ? "شناسایی شد" : "مشاهده نشد",
      },
    ];

    items.forEach(function (entry) {
      var box = makeEl("div", "surface-item");
      box.appendChild(makeEl("span", "", entry.title));
      box.appendChild(makeEl("strong", "", entry.value));
      grid.appendChild(box);
    });
  }

  function renderFindingsList(audit) {
    var container = byId("findings-container");
    clearChildren(container);

    var filtered = audit.findings.filter(function (item) {
      if (appState.activeFilter === "issues") {
        return item.status !== "pass";
      }
      if (appState.activeFilter === "pass") {
        return item.status === "pass";
      }
      return true;
    });

    if (filtered.length === 0) {
      container.appendChild(
        makeEl("p", "finding-impact", "هیچ شاخصی در این فیلتر وجود ندارد.")
      );
      return;
    }

    filtered.forEach(function (item) {
      var card = makeEl("article", "finding-card");

      var topRow = makeEl("div", "finding-top");
      var leftGroup = makeEl("div", "finding-title-group");
      var badge = statusBadgeMeta(item.status);
      leftGroup.appendChild(makeEl("span", badge.cls, badge.label));
      leftGroup.appendChild(makeEl("h3", "finding-name", item.title_fa));

      var points = makeEl(
        "span",
        "points-pill",
        String(item.earned_points) + " / " + String(item.max_points) + " pts"
      );

      topRow.appendChild(leftGroup);
      topRow.appendChild(points);
      card.appendChild(topRow);

      card.appendChild(makeEl("p", "finding-impact", item.impact_fa));

      var bar = makeEl("div", "code-bar");
      bar.appendChild(makeEl("code", "observed-mono", item.observed_value));

      var copyFixBtn = makeEl("button", "btn btn-subtle", "کپی کد مقاوم‌سازی");
      copyFixBtn.type = "button";
      copyFixBtn.addEventListener("click", function () {
        copyPlainText(
          item.remediation_snippet,
          "کد مقاوم‌سازی «" + item.title_fa + "» کپی شد."
        );
      });
      bar.appendChild(copyFixBtn);
      card.appendChild(bar);

      if (item.status !== "pass") {
        card.appendChild(makeEl("pre", "snippet-pre", item.remediation_snippet));
      }

      container.appendChild(card);
    });
  }

  function renderFeaturedAudit(audit) {
    if (!audit) {
      return;
    }
    var pill = byId("active-grade-pill");
    pill.textContent = audit.grade;
    pill.className = "grade-pill " + gradeVisualClass(audit.grade);

    byId("active-hostname").textContent = audit.hostname;
    byId("active-risk-label").textContent =
      audit.risk_label_fa +
      " — " +
      String(audit.passed_count) +
      " ایمن، " +
      String(audit.warning_count) +
      " هشدار، " +
      String(audit.failed_count) +
      " نقص";

    byId("active-score-text").textContent = String(audit.score) + " از 100";
    byId("active-progress-fill").style.width = String(audit.score) + "%";

    byId("meta-tls").textContent = audit.tls_summary;
    byId("meta-email-dns").textContent =
      "SPF: " +
      (audit.spf_present ? "فعال" : "ندارد") +
      " | DMARC: " +
      (audit.dmarc_present ? "فعال" : "ندارد");
    byId("meta-stack").textContent = audit.surface.detected_stack;
    byId("meta-timing").textContent =
      "HTTP " + String(audit.status_code) + " (" + String(audit.response_time_ms) + " ms)";

    renderSurfaceHygiene(audit.surface);
    renderFindingsList(audit);
  }

  function renderHistoryTable(historyList, activeId) {
    var tbody = byId("history-tbody");
    clearChildren(tbody);

    historyList.forEach(function (row) {
      var tr = makeEl(
        "tr",
        row.audit_id === activeId ? "history-row selected-row" : "history-row"
      );

      tr.appendChild(makeEl("td", "ltr-cell", row.hostname));
      tr.appendChild(makeEl("td", "ltr-cell", row.grade));
      tr.appendChild(makeEl("td", "", String(row.score) + " از 100"));
      tr.appendChild(
        makeEl(
          "td",
          "",
          String(row.passed_count) +
            " ایمن | " +
            String(row.failed_count) +
            " نقص"
        )
      );
      tr.appendChild(makeEl("td", "", row.tls_summary));
      tr.appendChild(makeEl("td", "ltr-cell", String(row.response_time_ms) + " ms"));

      tr.addEventListener("click", function () {
        loadAuditById(row.audit_id);
      });
      tbody.appendChild(tr);
    });
  }

  function applyDashboardState(state) {
    appState.featuredAudit = state.featured_audit;
    appState.history = state.history || [];
    renderKpis(state.kpis || {});
    if (appState.featuredAudit) {
      renderFeaturedAudit(appState.featuredAudit);
      renderHistoryTable(appState.history, appState.featuredAudit.audit_id);
    }
  }

  function loadInitialDashboard() {
    fetch("/api/dashboard")
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        applyDashboardState(data);
      })
      .catch(function () {
        setErrorMessage("خطا در بارگذاری وضعیت اولیه رصدخانه.");
      });
  }

  function loadAuditById(auditId) {
    setErrorMessage("");
    fetch("/api/dashboard?audit_id=" + encodeURIComponent(String(auditId)))
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        applyDashboardState(data);
      })
      .catch(function () {
        setErrorMessage("امکان بارگذاری کارنامه انتخاب‌شده وجود نداشت.");
      });
  }

  function submitTargetScan(targetUrl) {
    var submitBtn = byId("scan-submit-btn");
    setErrorMessage("");
    submitBtn.disabled = true;
    submitBtn.textContent = "در حال ممیزی غیرمخرب...";

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl }),
    })
      .then(function (res) {
        return res.json().then(function (body) {
          return { ok: res.ok, body: body };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          setErrorMessage(result.body.detail || "خطا در بررسی دامنه هدف.");
          return;
        }
        applyDashboardState(result.body.dashboard);
        showToast("کارنامه امنیتی «" + result.body.audit.hostname + "» صادر شد.");
      })
      .catch(function () {
        setErrorMessage("ارتباط با سرور محلی برقرار نشد.");
      })
      .finally(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = "شروع ممیزی غیرمخرب";
      });
  }

  function wireEvents() {
    var form = byId("scan-form");
    var input = byId("target-url-input");

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var value = (input.value || "").trim();
      if (!value) {
        setErrorMessage("لطفاً آدرس وب‌سایت مورد نظر را وارد کنید.");
        return;
      }
      submitTargetScan(value);
    });

    var presets = document.querySelectorAll(".preset-chip");
    presets.forEach(function (chip) {
      chip.addEventListener("click", function () {
        var presetUrl = chip.getAttribute("data-preset") || "";
        input.value = presetUrl;
        submitTargetScan(presetUrl);
      });
    });

    var filterButtons = document.querySelectorAll(".tab-btn");
    filterButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        filterButtons.forEach(function (item) {
          item.classList.remove("active");
        });
        btn.classList.add("active");
        appState.activeFilter = btn.getAttribute("data-filter") || "all";
        if (appState.featuredAudit) {
          renderFindingsList(appState.featuredAudit);
        }
      });
    });

    byId("copy-report-btn").addEventListener("click", function () {
      if (!appState.featuredAudit) {
        return;
      }
      fetch(
        "/api/audits/" +
          encodeURIComponent(String(appState.featuredAudit.audit_id)) +
          "/report.md"
      )
        .then(function (res) {
          return res.text();
        })
        .then(function (markdownText) {
          copyPlainText(markdownText, "گزارش کامل مدیریتی برای ارسال به مشتری کپی شد.");
        })
        .catch(function () {});
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireEvents();
    loadInitialDashboard();
  });
})();

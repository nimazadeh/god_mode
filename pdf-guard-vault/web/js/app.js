// Frontend application controller for PDF-Guard & Course Vault
(function () {
  "use strict";

  var appState = {
    dashboard: null,
    unifiedRows: [],
    activeFilter: "all",
    searchQuery: "",
    selectedRowKey: null,
  };

  function formatToman(amount) {
    var num = Number(amount || 0);
    return num.toLocaleString("en-US");
  }

  function setStatusBanner(message, isError) {
    var msgEl = document.getElementById("status-message");
    var timeEl = document.getElementById("status-timestamp");
    var banner = document.getElementById("status-banner");
    if (msgEl) {
      msgEl.textContent = message;
    }
    if (timeEl) {
      var now = new Date();
      timeEl.textContent = now.toISOString().slice(11, 19) + " UTC";
    }
    if (banner) {
      if (isError) {
        banner.style.backgroundColor = "var(--status-danger-bg)";
        banner.style.borderColor = "var(--status-danger-border)";
        banner.style.color = "var(--status-danger-text)";
      } else {
        banner.style.backgroundColor = "var(--status-info-bg)";
        banner.style.borderColor = "var(--status-info-border)";
        banner.style.color = "var(--status-info-text)";
      }
    }
  }

  function buildUnifiedRows(dashboard) {
    var rows = [];
    var receipts = dashboard.receipts || [];
    var licenses = dashboard.licenses || [];

    // Place pending receipts at the top so the administrator can verify them immediately
    receipts.forEach(function (rec) {
      rows.push({
        rowKey: "receipt-" + String(rec.receipt_id),
        recordKind: "receipt",
        id: rec.receipt_id,
        code: rec.tracking_code,
        studentName: rec.student_name,
        studentPhone: rec.student_phone,
        telegramHandle: rec.telegram_handle || "",
        productCode: rec.product_code,
        productTitle: rec.product_title,
        tierType: rec.tier_type,
        amountToman: rec.amount_toman,
        status: rec.status,
        cardLast4: rec.card_last4,
        issuedLicenseCode: rec.issued_license_code || "",
        watermarkHash: rec.issued_license_code
          ? "ISSUED-" + rec.issued_license_code
          : "CARD-" + rec.card_last4,
        diagonalText:
          "RECEIPT " +
          rec.tracking_code +
          " | BUYER: " +
          rec.student_phone +
          " | CARD *" +
          rec.card_last4,
        footerText: rec.admin_note || "منتظر بررسی فیش واریزی کارت به کارت",
        timestampIso: rec.submitted_at_iso,
        rawRecord: rec,
      });
    });

    licenses.forEach(function (lic) {
      rows.push({
        rowKey: "license-" + String(lic.license_id),
        recordKind: "license",
        id: lic.license_id,
        code: lic.license_code,
        studentName: lic.student_name,
        studentPhone: lic.student_phone,
        telegramHandle: lic.telegram_handle || "",
        productCode: lic.product_code,
        productTitle: lic.product_title,
        tierType: lic.tier_type,
        amountToman: lic.price_paid_toman,
        status: "issued",
        cardLast4: "",
        issuedLicenseCode: lic.license_code,
        watermarkHash: lic.watermark_hash,
        diagonalText: lic.diagonal_text,
        footerText: lic.footer_text,
        timestampIso: lic.issued_at_iso,
        downloadCount: lic.download_count,
        rawRecord: lic,
      });
    });

    return rows;
  }

  function filterRows(rows) {
    var filter = appState.activeFilter;
    var query = (appState.searchQuery || "").trim().toLowerCase();

    return rows.filter(function (row) {
      var matchesTab = true;
      if (filter === "pending_receipts") {
        matchesTab = row.recordKind === "receipt" && row.status === "pending";
      } else if (filter === "licenses") {
        matchesTab = row.recordKind === "license";
      } else if (filter === "full_package") {
        matchesTab = row.tierType === "full_package";
      } else if (filter === "chapter_part") {
        matchesTab = row.tierType === "chapter_part";
      }

      if (!matchesTab) {
        return false;
      }

      if (!query) {
        return true;
      }

      var haystack = [
        row.code,
        row.studentName,
        row.studentPhone,
        row.productCode,
        row.productTitle,
        row.watermarkHash,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.indexOf(query) !== -1;
    });
  }

  function updateKpiAndCounts(dashboard, unifiedRows) {
    var summary = dashboard.summary || {};
    document.getElementById("kpi-total-revenue").textContent = formatToman(
      summary.total_revenue_toman
    );
    document.getElementById("kpi-pending-receipts").textContent = String(
      summary.pending_receipts_count || 0
    );
    document.getElementById("kpi-total-licenses").textContent = String(
      summary.total_licenses_issued || 0
    );
    document.getElementById("kpi-full-packages").textContent = String(
      summary.full_packages_count || 0
    );
    document.getElementById("kpi-chapter-parts").textContent = String(
      summary.chapter_parts_count || 0
    );
    document.getElementById("kpi-wallet-total").textContent = formatToman(
      summary.total_wallet_balance_toman
    );

    var pendingCount = unifiedRows.filter(function (r) {
      return r.recordKind === "receipt" && r.status === "pending";
    }).length;
    var licenseCount = unifiedRows.filter(function (r) {
      return r.recordKind === "license";
    }).length;
    var fullPkgCount = unifiedRows.filter(function (r) {
      return r.tierType === "full_package";
    }).length;
    var chapterCount = unifiedRows.filter(function (r) {
      return r.tierType === "chapter_part";
    }).length;

    document.getElementById("count-all").textContent = String(unifiedRows.length);
    document.getElementById("count-pending").textContent = String(pendingCount);
    document.getElementById("count-licenses").textContent = String(licenseCount);
    document.getElementById("count-full-pkg").textContent = String(fullPkgCount);
    document.getElementById("count-chapter").textContent = String(chapterCount);
  }

  function populateProductSelect(products) {
    var selectEl = document.getElementById("issue-product-select");
    if (!selectEl) {
      return;
    }
    var previousValue = selectEl.value;
    while (selectEl.firstChild) {
      selectEl.removeChild(selectEl.firstChild);
    }
    products.forEach(function (prod) {
      var opt = document.createElement("option");
      opt.value = prod.code;
      var tierLabel =
        prod.tier_type === "full_package" ? "پکیج کامل" : "تک‌فصل";
      opt.textContent =
        "[" +
        tierLabel +
        "] " +
        prod.title +
        " (" +
        formatToman(prod.price_toman) +
        " تومان)";
      selectEl.appendChild(opt);
    });
    if (previousValue) {
      selectEl.value = previousValue;
    }
  }

  function renderInspector(row) {
    var detailsEl = document.getElementById("inspector-details");
    var badgeEl = document.getElementById("inspector-badge");
    var headerLine = document.getElementById("preview-header-line");
    var diagonalLine = document.getElementById("preview-diagonal-line");
    var footerLine = document.getElementById("preview-footer-line");
    var actionsEl = document.getElementById("inspector-actions");

    while (detailsEl.firstChild) {
      detailsEl.removeChild(detailsEl.firstChild);
    }
    while (actionsEl.firstChild) {
      actionsEl.removeChild(actionsEl.firstChild);
    }

    if (!row) {
      badgeEl.textContent = "بدون انتخاب";
      return;
    }

    badgeEl.textContent =
      row.recordKind === "license" ? "مجوز PDF فعال" : "فیش کارت‌به‌کارت";
    badgeEl.className =
      "badge " +
      (row.recordKind === "license"
        ? "badge-issued"
        : row.status === "pending"
        ? "badge-pending"
        : row.status === "approved"
        ? "badge-approved"
        : "badge-rejected");

    var pairs = [
      ["کد رهگیری / مجوز", row.code],
      ["نام دانشجو", row.studentName],
      ["موبایل (واترمارک)", row.studentPhone],
      ["محصول", row.productTitle],
      [
        "نوع عرضه",
        row.tierType === "full_package" ? "پکیج کامل جامع" : "جزوه تک‌فصل",
      ],
      ["مبلغ", formatToman(row.amountToman) + " تومان"],
      ["امضای SHA-256 / کارت", row.watermarkHash],
    ];

    pairs.forEach(function (pair) {
      var item = document.createElement("div");
      item.className = "detail-item";
      var labelSpan = document.createElement("span");
      labelSpan.style.color = "var(--text-secondary)";
      labelSpan.textContent = pair[0];
      var valSpan = document.createElement("strong");
      valSpan.textContent = pair[1];
      item.appendChild(labelSpan);
      item.appendChild(valSpan);
      detailsEl.appendChild(item);
    });

    headerLine.textContent =
      "PDF-GUARD FORENSIC | PRODUCT: " +
      row.productCode +
      " | BUYER: " +
      row.studentPhone;
    diagonalLine.textContent = row.diagonalText;
    footerLine.textContent = row.footerText;

    if (row.recordKind === "license") {
      var dlLink = document.createElement("a");
      dlLink.href = "/api/licenses/" + String(row.id) + "/download.pdf";
      dlLink.className = "btn btn-primary btn-sm";
      dlLink.textContent = "دانلود فایل PDF واترمارک‌شده (" + row.code + ")";
      actionsEl.appendChild(dlLink);
    } else if (row.recordKind === "receipt" && row.status === "pending") {
      var approveBtn = document.createElement("button");
      approveBtn.type = "button";
      approveBtn.className = "btn btn-success btn-sm";
      approveBtn.textContent = "تایید فیش و صدور آنی PDF";
      approveBtn.addEventListener("click", function () {
        reviewReceipt(row.id, true);
      });

      var rejectBtn = document.createElement("button");
      rejectBtn.type = "button";
      rejectBtn.className = "btn btn-danger btn-sm";
      rejectBtn.textContent = "رد فیش";
      rejectBtn.addEventListener("click", function () {
        reviewReceipt(row.id, false);
      });

      actionsEl.appendChild(approveBtn);
      actionsEl.appendChild(rejectBtn);
    }
  }

  function renderTable() {
    var tbody = document.getElementById("vault-table-body");
    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }

    var filtered = filterRows(appState.unifiedRows);
    if (!filtered.length) {
      var emptyRow = document.createElement("tr");
      var emptyCell = document.createElement("td");
      emptyCell.colSpan = 7;
      emptyCell.style.textAlign = "center";
      emptyCell.style.padding = "24px";
      emptyCell.textContent = "هیچ رکوردی مطابق فیلتر انتخابی یافت نشد.";
      emptyRow.appendChild(emptyCell);
      tbody.appendChild(emptyRow);
      renderInspector(null);
      return;
    }

    if (
      !appState.selectedRowKey ||
      !filtered.some(function (r) {
        return r.rowKey === appState.selectedRowKey;
      })
    ) {
      appState.selectedRowKey = filtered[0].rowKey;
    }

    var fragment = document.createDocumentFragment();

    filtered.forEach(function (row) {
      var tr = document.createElement("tr");
      tr.className =
        "data-row" +
        (row.rowKey === appState.selectedRowKey ? " selected" : "");
      tr.addEventListener("click", function () {
        appState.selectedRowKey = row.rowKey;
        renderTable();
      });

      var tdCode = document.createElement("td");
      tdCode.setAttribute("data-label", "نوع و کد رهگیری");
      var codeSpan = document.createElement("span");
      codeSpan.className = "mono-num";
      codeSpan.style.fontWeight = "600";
      codeSpan.textContent = row.code;
      tdCode.appendChild(codeSpan);

      var tdStudent = document.createElement("td");
      tdStudent.setAttribute("data-label", "دانشجو / خریدار");
      var stuWrap = document.createElement("div");
      stuWrap.style.display = "flex";
      stuWrap.style.flexDirection = "column";
      stuWrap.style.gap = "2px";
      var nameStrong = document.createElement("strong");
      nameStrong.textContent = row.studentName;
      var phoneSub = document.createElement("div");
      phoneSub.className = "mono-num";
      phoneSub.style.fontSize = "0.76rem";
      phoneSub.style.color = "var(--text-secondary)";
      phoneSub.textContent = row.studentPhone;
      stuWrap.appendChild(nameStrong);
      stuWrap.appendChild(phoneSub);
      tdStudent.appendChild(stuWrap);

      var tdProduct = document.createElement("td");
      tdProduct.setAttribute("data-label", "عنوان محصول آموزشی");
      tdProduct.textContent = row.productTitle;

      var tdTier = document.createElement("td");
      tdTier.setAttribute("data-label", "نوع عرضه");
      var tierBadge = document.createElement("span");
      tierBadge.className =
        "badge " +
        (row.tierType === "full_package" ? "badge-package" : "badge-chapter");
      tierBadge.textContent =
        row.tierType === "full_package" ? "📦 پکیج کامل" : "📄 تک‌فصل";
      tdTier.appendChild(tierBadge);

      var tdAmount = document.createElement("td");
      tdAmount.setAttribute("data-label", "مبلغ (تومان)");
      var amountSpan = document.createElement("span");
      amountSpan.className = "mono-num";
      amountSpan.style.fontWeight = "600";
      amountSpan.textContent = formatToman(row.amountToman);
      tdAmount.appendChild(amountSpan);

      var tdStatus = document.createElement("td");
      tdStatus.setAttribute("data-label", "وضعیت / واترمارک");
      var stBadge = document.createElement("span");
      if (row.recordKind === "license") {
        stBadge.className = "badge badge-issued";
        stBadge.textContent = "✓ واترمارک SHA256:" + row.watermarkHash.slice(0, 8);
      } else if (row.status === "pending") {
        stBadge.className = "badge badge-pending";
        stBadge.textContent = "⏳ منتظر تایید (کارت *" + row.cardLast4 + ")";
      } else if (row.status === "approved") {
        stBadge.className = "badge badge-approved";
        stBadge.textContent = "✓ تاییدشده (" + row.issuedLicenseCode + ")";
      } else {
        stBadge.className = "badge badge-rejected";
        stBadge.textContent = "✕ ردشده";
      }
      tdStatus.appendChild(stBadge);

      var tdAction = document.createElement("td");
      tdAction.setAttribute("data-label", "عملیات سریع");
      if (row.recordKind === "license") {
        var dlAnchor = document.createElement("a");
        dlAnchor.href = "/api/licenses/" + String(row.id) + "/download.pdf";
        dlAnchor.className = "btn btn-sm";
        dlAnchor.textContent = "دانلود PDF";
        dlAnchor.addEventListener("click", function (ev) {
          ev.stopPropagation();
        });
        tdAction.appendChild(dlAnchor);
      } else if (row.status === "pending") {
        var btnApprove = document.createElement("button");
        btnApprove.type = "button";
        btnApprove.className = "btn btn-success btn-sm";
        btnApprove.textContent = "تایید فیش";
        btnApprove.addEventListener("click", function (ev) {
          ev.stopPropagation();
          reviewReceipt(row.id, true);
        });
        tdAction.appendChild(btnApprove);
      } else {
        var doneSpan = document.createElement("span");
        doneSpan.style.fontSize = "0.78rem";
        doneSpan.style.color = "var(--text-muted)";
        doneSpan.textContent = "بررسی‌شده";
        tdAction.appendChild(doneSpan);
      }

      tr.appendChild(tdCode);
      tr.appendChild(tdStudent);
      tr.appendChild(tdProduct);
      tr.appendChild(tdTier);
      tr.appendChild(tdAmount);
      tr.appendChild(tdStatus);
      tr.appendChild(tdAction);
      fragment.appendChild(tr);
    });

    tbody.appendChild(fragment);

    var selectedObj =
      filtered.find(function (r) {
        return r.rowKey === appState.selectedRowKey;
      }) || filtered[0];
    renderInspector(selectedObj);
  }

  function applyDashboardPayload(dashboard) {
    appState.dashboard = dashboard;
    appState.unifiedRows = buildUnifiedRows(dashboard);
    updateKpiAndCounts(dashboard, appState.unifiedRows);
    populateProductSelect(dashboard.products || []);
    renderTable();
  }

  function fetchDashboard() {
    fetch("/api/dashboard")
      .then(function (res) {
        if (!res.ok) {
          throw new Error("HTTP " + String(res.status));
        }
        return res.json();
      })
      .then(function (data) {
        applyDashboardPayload(data);
      })
      .catch(function (err) {
        setStatusBanner("خطا در دریافت اطلاعات داشبورد: " + err.message, true);
      });
  }

  function reviewReceipt(receiptId, approveFlag) {
    fetch("/api/receipts/" + String(receiptId) + "/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        approve: approveFlag,
        admin_note: approveFlag
          ? "تایید یک‌کلیکی فیش و صدور آنی مجوز PDF"
          : "رد شده توسط ادمین",
      }),
    })
      .then(function (res) {
        if (!res.ok) {
          throw new Error("HTTP " + String(res.status));
        }
        return res.json();
      })
      .then(function (payload) {
        applyDashboardPayload(payload.dashboard);
        var code = payload.reviewed.issued_license_code || payload.reviewed.tracking_code;
        setStatusBanner(
          approveFlag
            ? "فیش واریزی تایید شد و مجوز PDF واترمارک‌شده (" + code + ") صادر گردید."
            : "فیش واریزی (" + code + ") رد شد.",
          false
        );
      })
      .catch(function (err) {
        setStatusBanner("خطا در بررسی فیش: " + err.message, true);
      });
  }

  function bindEvents() {
    var pillButtons = document.querySelectorAll(".filter-pill");
    pillButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        pillButtons.forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");
        appState.activeFilter = btn.getAttribute("data-filter") || "all";
        renderTable();
      });
    });

    var searchInput = document.getElementById("search-input");
    if (searchInput) {
      searchInput.addEventListener("input", function () {
        appState.searchQuery = searchInput.value || "";
        renderTable();
      });
    }

    var refreshBtn = document.getElementById("btn-refresh-dashboard");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        fetchDashboard();
        setStatusBanner("اطلاعات فیش‌ها و مجوزهای PDF بروزرسانی شد.", false);
      });
    }

    var focusIssueBtn = document.getElementById("btn-focus-issue");
    if (focusIssueBtn) {
      focusIssueBtn.addEventListener("click", function () {
        var nameInput = document.getElementById("issue-student-name");
        if (nameInput) {
          nameInput.focus();
        }
      });
    }

    var issueForm = document.getElementById("form-issue-license");
    if (issueForm) {
      issueForm.addEventListener("submit", function (ev) {
        ev.preventDefault();
        var nameVal = document.getElementById("issue-student-name").value.trim();
        var phoneVal = document.getElementById("issue-student-phone").value.trim();
        var prodVal = document.getElementById("issue-product-select").value;
        if (!nameVal || !phoneVal || !prodVal) {
          return;
        }
        fetch("/api/licenses/issue", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            student_name: nameVal,
            student_phone: phoneVal,
            telegram_handle: "",
            product_code: prodVal,
          }),
        })
          .then(function (res) {
            if (!res.ok) {
              throw new Error("HTTP " + String(res.status));
            }
            return res.json();
          })
          .then(function (payload) {
            appState.selectedRowKey = "license-" + String(payload.license.license_id);
            applyDashboardPayload(payload.dashboard);
            setStatusBanner(
              "مجوز جدید (" +
                payload.license.license_code +
                ") با واترمارک اختصاصی برای " +
                nameVal +
                " صادر شد.",
              false
            );
          })
          .catch(function (err) {
            setStatusBanner("خطا در صدور مجوز: " + err.message, true);
          });
      });
    }

    var tgButtons = document.querySelectorAll(".tg-cmd-btn");
    tgButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var cmd = btn.getAttribute("data-cmd") || "/start";
        var phoneVal =
          document.getElementById("issue-student-phone").value.trim() ||
          "09123456789";
        fetch("/api/telegram/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            command: cmd,
            student_phone: phoneVal,
          }),
        })
          .then(function (res) {
            return res.json();
          })
          .then(function (data) {
            var outEl = document.getElementById("telegram-bot-output");
            if (outEl) {
              outEl.textContent = data.bot_reply || "";
            }
          });
      });
    });

    document.addEventListener("keydown", function (ev) {
      if (
        ev.target &&
        (ev.target.tagName === "INPUT" ||
          ev.target.tagName === "SELECT" ||
          ev.target.tagName === "TEXTAREA")
      ) {
        return;
      }
      if (ev.key === "/") {
        ev.preventDefault();
        var sInput = document.getElementById("search-input");
        if (sInput) {
          sInput.focus();
        }
      } else if (ev.key === "r" || ev.key === "R") {
        ev.preventDefault();
        fetchDashboard();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindEvents();
    fetchDashboard();
  });
})();

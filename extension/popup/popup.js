/**
 * popup.js — Claw Extension Controller
 *
 * Handles the full Claw /v1/analyze response shape:
 *   - Policy decisions (allow / allow_with_modifications / deny)
 *   - PII scan results
 *   - Risk analysis from Claude
 *   - Audit metadata
 *   - 403 Blocked-by-Policy state
 */

(() => {
  "use strict";

  const CLAW_URL = "http://localhost:8787";
  const ANALYZE_URL = `${CLAW_URL}/v1/analyze`;
  const HEALTH_URL  = `${CLAW_URL}/v1/health`;

  // ── DOM Refs ──────────────────────────────────────────

  const $ = (id) => document.getElementById(id);

  const dom = {
    btn:             $("btn-scan"),
    statusBar:       $("status-bar"),
    statusIcon:      $("status-icon"),
    statusText:      $("status-text"),
    statusDetail:    $("status-detail"),
    packBadge:       $("pack-badge"),
    connDot:         $("connection-dot"),
    results:         $("results"),
    denied:          $("denied"),
    error:           $("error"),
    errorText:       $("error-text"),
    // Policy
    policyBanner:    $("policy-banner"),
    policyIcon:      $("policy-icon"),
    policyText:      $("policy-decision-text"),
    policyDetail:    $("policy-detail"),
    policyRules:     $("policy-rules"),
    rulesList:       $("rules-list"),
    policyMods:      $("policy-mods"),
    modsList:        $("mods-list"),
    // PII
    piiCard:         $("pii-card"),
    piiTotal:        $("pii-total"),
    piiGrid:         $("pii-grid"),
    // Page info
    pageTitle:       $("page-title"),
    pageUrl:         $("page-url"),
    // Analysis
    summaryCard:     $("summary-card"),
    summaryBullets:  $("summary-bullets"),
    riskCard:        $("risk-card"),
    riskFill:        $("risk-fill"),
    riskScore:       $("risk-score"),
    riskRationale:   $("risk-rationale"),
    safetyCard:      $("safety-card"),
    safetyList:      $("safety-list"),
    // Audit
    auditCard:       $("audit-card"),
    auditGrid:       $("audit-grid"),
    // Denied
    deniedReason:    $("denied-reason"),
    deniedRules:     $("denied-rules"),
  };

  // ── State ─────────────────────────────────────────────

  function setStatus(state, text, detail = "") {
    dom.statusBar.className = `status-bar ${state}`;
    dom.statusText.textContent = text;
    dom.statusDetail.textContent = detail;
  }

  function resetUI() {
    dom.results.classList.add("hidden");
    dom.denied.classList.add("hidden");
    dom.error.classList.add("hidden");
    dom.summaryCard.classList.add("hidden");
    dom.riskCard.classList.add("hidden");
    dom.safetyCard.classList.add("hidden");
    dom.auditCard.classList.add("hidden");
    dom.piiCard.classList.add("hidden");
    dom.policyRules.classList.add("hidden");
    dom.policyMods.classList.add("hidden");
    dom.summaryBullets.innerHTML = "";
    dom.safetyList.innerHTML = "";
    dom.rulesList.innerHTML = "";
    dom.modsList.innerHTML = "";
    dom.piiGrid.innerHTML = "";
    dom.auditGrid.innerHTML = "";
    dom.deniedRules.innerHTML = "";
  }

  function showError(msg) {
    dom.results.classList.add("hidden");
    dom.denied.classList.add("hidden");
    dom.error.classList.remove("hidden");
    dom.errorText.textContent = msg;
    setStatus("error", "Failed");
  }

  // ── Health Check ──────────────────────────────────────

  async function checkHealth() {
    try {
      const resp = await fetch(HEALTH_URL);
      const data = await resp.json();
      dom.connDot.className = "conn-dot ok";
      if (data.components?.opa?.status === "ok") {
        dom.packBadge.textContent = "opa connected";
      }
      return true;
    } catch {
      dom.connDot.className = "conn-dot err";
      return false;
    }
  }

  // ── Content Extraction ────────────────────────────────

  async function extractContent() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab found.");
    if (tab.url?.startsWith("about:") || tab.url?.startsWith("moz-extension:")) {
      throw new Error("Cannot scan browser internal pages.");
    }

    try {
      await browser.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content/extractor.js"],
      });
    } catch { /* may already be loaded */ }

    return new Promise((resolve, reject) => {
      browser.tabs.sendMessage(tab.id, { action: "EXTRACT_CONTENT" })
        .then(r => {
          if (!r) reject(new Error("No response from content script."));
          else if (!r.success) reject(new Error(r.error));
          else resolve(r.payload);
        })
        .catch(() => reject(new Error("Content script not reachable. Reload the page.")));
    });
  }

  // ── API Call ──────────────────────────────────────────

  async function callClaw(payload) {
    const resp = await fetch(ANALYZE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: payload.url,
        title: payload.title,
        text: payload.text,
        metadata: {
          author: payload.author,
          site_name: payload.siteName,
          published_date: payload.publishedDate,
          word_count: payload.wordCount,
        },
      }),
    });

    const data = await resp.json();

    if (resp.status === 403) {
      return { denied: true, ...data };
    }
    if (!resp.ok) {
      throw new Error(data.detail || `Server error (${resp.status})`);
    }

    return { denied: false, ...data };
  }

  // ── Render: Policy Banner ─────────────────────────────

  function renderPolicy(policy, isDenied) {
    if (isDenied) {
      dom.policyBanner.className = "policy-banner denied";
      dom.policyIcon.textContent = "⛔";
      dom.policyText.textContent = "Blocked by Policy";
      dom.policyText.style.color = "var(--red)";
    } else if (policy.decision === "allow_with_modifications") {
      dom.policyBanner.className = "policy-banner modified";
      dom.policyIcon.textContent = "⚠";
      dom.policyText.textContent = "Allowed with Modifications";
      dom.policyText.style.color = "var(--amber)";
    } else {
      dom.policyBanner.className = "policy-banner allow";
      dom.policyIcon.textContent = "✓";
      dom.policyText.textContent = "Policy Passed";
      dom.policyText.style.color = "var(--green)";
    }

    dom.policyDetail.textContent =
      `Pack: ${policy.pack} · ${policy.rules_evaluated} rules · ${policy.evaluation_ms}ms`;

    // Matched rules
    if (policy.matched_rules?.length) {
      dom.policyRules.classList.remove("hidden");
      dom.rulesList.innerHTML = "";
      policy.matched_rules.forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        dom.rulesList.appendChild(li);
      });
    }

    // Modifications
    if (policy.modifications_applied?.length) {
      dom.policyMods.classList.remove("hidden");
      dom.modsList.innerHTML = "";
      policy.modifications_applied.forEach(m => {
        const li = document.createElement("li");
        li.textContent = m;
        dom.modsList.appendChild(li);
      });
    }
  }

  // ── Render: PII Scan ──────────────────────────────────

  function renderPII(pii) {
    if (!pii) return;

    dom.piiCard.classList.remove("hidden");

    const total = pii.total || 0;
    dom.piiTotal.textContent = total === 0 ? "CLEAN" : `${total} FOUND`;
    dom.piiTotal.className = `pii-total ${total === 0 ? "clean" : "detected"}`;

    const types = [
      { key: "ssn", label: "SSN" },
      { key: "credit_card", label: "CC" },
      { key: "email", label: "Email" },
      { key: "phone", label: "Phone" },
      { key: "ip_address", label: "IP" },
    ];

    dom.piiGrid.innerHTML = "";
    types.forEach(t => {
      const count = pii[t.key] || 0;
      const div = document.createElement("div");
      div.className = `pii-item ${count > 0 ? "has-pii" : "clean"}`;
      div.innerHTML = `<span class="pii-count">${count}</span><span class="pii-type">${t.label}</span>`;
      dom.piiGrid.appendChild(div);
    });
  }

  // ── Render: Analysis ──────────────────────────────────

  function renderAnalysis(analysis) {
    if (!analysis) return;

    // Summary
    if (analysis.summary?.length) {
      dom.summaryCard.classList.remove("hidden");
      dom.summaryBullets.innerHTML = "";
      analysis.summary.forEach(b => {
        const li = document.createElement("li");
        li.textContent = b;
        dom.summaryBullets.appendChild(li);
      });
    }

    // Risk
    const score = Math.max(0, Math.min(10, analysis.risk_score ?? 0));
    dom.riskCard.classList.remove("hidden");
    dom.riskFill.style.width = `${score * 10}%`;

    let riskColor;
    if (score <= 3) riskColor = "var(--green)";
    else if (score <= 6) riskColor = "var(--amber)";
    else riskColor = "var(--red)";

    dom.riskFill.style.background = riskColor;
    dom.riskScore.style.color = riskColor;
    dom.riskScore.textContent = `${score}/10`;
    dom.riskRationale.textContent = analysis.risk_rationale || "";

    // Safety flags
    if (analysis.safety_flags?.length) {
      dom.safetyCard.classList.remove("hidden");
      dom.safetyList.innerHTML = "";
      analysis.safety_flags.forEach(f => {
        const sev = (f.severity || "ok").toLowerCase();
        const icon = sev === "danger" ? "✕" : sev === "warning" ? "!" : "✓";
        const cls = sev === "danger" ? "flag-danger" : sev === "warning" ? "flag-warn" : "flag-ok";
        const div = document.createElement("div");
        div.className = `safety-flag ${cls}`;
        div.innerHTML = `<span class="flag-icon">${icon}</span><span>${f.message}</span>`;
        dom.safetyList.appendChild(div);
      });
    }
  }

  // ── Render: Audit ─────────────────────────────────────

  function renderAudit(audit) {
    if (!audit) return;
    dom.auditCard.classList.remove("hidden");
    dom.auditGrid.innerHTML = "";

    const fields = [
      ["Hash", audit.content_hash],
      ["Model", audit.model],
      ["Tokens In", audit.tokens_in?.toLocaleString()],
      ["Tokens Out", audit.tokens_out?.toLocaleString()],
      ["Latency", `${audit.latency_ms}ms`],
    ];

    fields.forEach(([key, val]) => {
      if (!val) return;
      const k = document.createElement("span");
      k.className = "audit-key";
      k.textContent = key;
      const v = document.createElement("span");
      v.className = "audit-val";
      v.textContent = val;
      dom.auditGrid.appendChild(k);
      dom.auditGrid.appendChild(v);
    });
  }

  // ── Render: Denied ────────────────────────────────────

  function renderDenied(data) {
    dom.denied.classList.remove("hidden");
    dom.deniedReason.textContent = data.reason || "Content blocked by security policy.";

    const rules = data.matched_rules || data.policy?.matched_rules || [];
    dom.deniedRules.innerHTML = "";
    rules.forEach(r => {
      const span = document.createElement("span");
      span.className = "denied-rule";
      span.textContent = r;
      dom.deniedRules.appendChild(span);
    });
  }

  // ── Main Flow ─────────────────────────────────────────

  dom.btn.addEventListener("click", async () => {
    resetUI();
    dom.btn.disabled = true;

    try {
      // Health check
      const healthy = await checkHealth();
      if (!healthy) {
        showError("Cannot reach Claw server. Run: docker compose up");
        return;
      }

      // Extract
      setStatus("working", "Extracting content", "reading DOM...");
      const payload = await extractContent();

      // Analyze
      const wordCount = payload.wordCount?.toLocaleString() || "?";
      setStatus("working", "Analyzing", `${wordCount} words → OPA → Claude`);
      const data = await callClaw(payload);

      // Page info (always shown)
      dom.pageTitle.textContent = payload.title || "Untitled";
      dom.pageUrl.textContent = payload.url;

      if (data.denied) {
        // ── DENIED ──────────────────────────────────
        dom.results.classList.remove("hidden");
        renderPolicy(data.policy, true);
        renderPII(data.pii_scan);
        renderDenied(data);
        setStatus("denied", "Blocked", data.policy?.pack || "");
      } else {
        // ── ALLOWED ─────────────────────────────────
        dom.results.classList.remove("hidden");
        renderPolicy(data.policy, false);
        renderPII(data.pii_scan);
        renderAnalysis(data.analysis);
        renderAudit(data.audit);
        setStatus("done", "Complete", `${data.audit?.latency_ms || 0}ms`);
      }

    } catch (err) {
      console.error("[Claw]", err);
      showError(err.message);
    } finally {
      dom.btn.disabled = false;
    }
  });

  // ── Init ──────────────────────────────────────────────
  checkHealth();

})();

// Claw Popup Controller — v0.2.0
(function () {
  const API = "http://localhost:8787";
  const $ = (s) => document.querySelector(s);
  const show = (id) => {
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    $(`#${id}`).classList.remove("hidden");
  };

  // --- Health check ---
  async function checkHealth() {
    try {
      const r = await fetch(`${API}/v1/health`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        const data = await r.json();
        $("#connection").classList.toggle("ok", data.status === "healthy");
      }
    } catch {
      $("#connection").classList.remove("ok");
    }
  }

  // --- Extract content from active tab ---
  async function extractContent() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab");

    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["/content/extractor.js"],
    });

    return new Promise((resolve, reject) => {
      browser.tabs.sendMessage(tab.id, { action: "extract" }).then((res) => {
        if (res?.success) resolve(res.data);
        else reject(new Error(res?.error || "Extraction failed"));
      }).catch(reject);
    });
  }

  // --- Render PII grid ---
  function renderPII(pii) {
    const grid = $("#pii-grid");
    grid.innerHTML = "";
    const types = ["ssn", "credit_card", "email", "phone", "ip_address", "keyword"];
    const labels = ["SSN", "Credit Card", "Email", "Phone", "IP Addr", "Keywords"];
    types.forEach((type, i) => {
      const count = pii?.counts?.[type] ?? 0;
      const cell = document.createElement("div");
      cell.className = `pii-cell ${count > 0 ? "detected" : "clean"}`;
      cell.innerHTML = `<div class="count">${count}</div><div class="label">${labels[i]}</div>`;
      grid.appendChild(cell);
    });
  }

  // --- Render Knowledge Hub section ---
  function renderKnowledge(knowledge) {
    const section = $("#knowledge-section");
    section.innerHTML = "";

    if (!knowledge || (!knowledge.domain_reputation && !knowledge.entries?.length)) {
      section.innerHTML = '<div class="knowledge-item"><span style="color:#64748b">No prior knowledge for this domain</span></div>';
      return;
    }

    // Domain reputation
    if (knowledge.domain_reputation) {
      const rep = knowledge.domain_reputation;
      const item = document.createElement("div");
      item.className = "knowledge-item";
      item.innerHTML = `
        <span class="domain">${rep.domain || "unknown"}</span>
        <span class="reputation ${rep.reputation || "unknown"}">${(rep.reputation || "unknown").toUpperCase()}</span>
      `;
      section.appendChild(item);
    }

    // Knowledge entries
    if (knowledge.entries?.length) {
      knowledge.entries.slice(0, 3).forEach((entry) => {
        const item = document.createElement("div");
        item.className = "knowledge-item";
        const disp = entry.disposition || "neutral";
        item.innerHTML = `
          <span style="color:#cbd5e1;font-size:10px">${entry.summary || entry.entry_type || "entry"}</span>
          <span class="reputation ${disp}">${disp.toUpperCase()}</span>
        `;
        section.appendChild(item);
      });
    }
  }

  // --- Render Argumentation section ---
  function renderArgumentation(arg) {
    const section = $("#argumentation-section");
    section.innerHTML = "";

    if (!arg || !arg.winning_arguments) {
      section.innerHTML = '<div class="arg-item">No conflicts to resolve</div>';
      return;
    }

    // Semantics label
    if (arg.semantics) {
      const sem = document.createElement("div");
      sem.className = "arg-semantics";
      sem.textContent = `Semantics: ${arg.semantics} · Decision: ${arg.final_decision || "—"}`;
      section.appendChild(sem);
    }

    // Winning arguments
    (arg.winning_arguments || []).forEach((a) => {
      const item = document.createElement("div");
      item.className = "arg-item winning";
      item.innerHTML = `<strong>✓</strong> ${a.claim || a.id} <span style="color:#64748b">(${a.source || ""}${a.strength != null ? " · " + a.strength : ""})</span>`;
      section.appendChild(item);
    });

    // Defeated arguments
    (arg.defeated_arguments || []).forEach((a) => {
      const item = document.createElement("div");
      item.className = "arg-item defeated";
      item.innerHTML = `<strong>✗</strong> ${a.claim || a.id} <span style="color:#64748b">(${a.source || ""})</span>`;
      section.appendChild(item);
    });

    // Explanation
    if (arg.explanation) {
      const expl = document.createElement("div");
      expl.className = "arg-semantics";
      expl.textContent = arg.explanation;
      section.appendChild(expl);
    }
  }

  // --- Render policy banner ---
  function renderBanner(decision) {
    const banner = $("#policy-banner");
    const d = (decision || "allow").toLowerCase();
    banner.className = "banner";
    if (d.includes("deny")) {
      banner.classList.add("deny");
      banner.textContent = "⛔ DENIED — Content blocked by policy";
    } else if (d.includes("modif")) {
      banner.classList.add("modified");
      banner.textContent = "⚠ MODIFIED — Content redacted before analysis";
    } else {
      banner.classList.add("allow");
      banner.textContent = "✅ ALLOWED — Content passed governance pipeline";
    }
  }

  // --- Render summary ---
  function renderSummary(analysis) {
    if (!analysis?.summary) return;
    const section = $("#summary-section");
    section.classList.remove("hidden");
    const list = $("#summary-list");
    list.innerHTML = "";

    const bullets = Array.isArray(analysis.summary) ? analysis.summary : [analysis.summary];
    bullets.forEach((b) => {
      const li = document.createElement("li");
      li.textContent = b;
      list.appendChild(li);
    });
  }

  // --- Render risk meter ---
  function renderRisk(analysis) {
    if (analysis?.risk_score == null) return;
    const section = $("#risk-section");
    section.classList.remove("hidden");
    const score = analysis.risk_score;
    const fill = $("#risk-fill");
    const label = $("#risk-score");

    fill.style.width = `${Math.min(score, 100)}%`;
    fill.className = "risk-fill";
    if (score <= 33) fill.classList.add("low");
    else if (score <= 66) fill.classList.add("medium");
    else fill.classList.add("high");
    label.textContent = `${score}/100`;
  }

  // --- Render safety flags ---
  function renderFlags(analysis) {
    const section = $("#flags-section");
    section.innerHTML = "";
    if (!analysis?.safety_flags?.length) return;
    section.classList.remove("hidden");

    const secLabel = document.createElement("div");
    secLabel.className = "section-label";
    secLabel.textContent = "Safety Flags";
    section.appendChild(secLabel);

    analysis.safety_flags.forEach((f) => {
      const div = document.createElement("div");
      const severity = f.severity || "info";
      div.className = `flag ${severity === "high" ? "danger" : severity === "medium" ? "warning" : "ok"}`;
      div.textContent = f.message || f;
      section.appendChild(div);
    });
  }

  // --- Render audit trail ---
  function renderAudit(data) {
    const section = $("#audit-section");
    section.innerHTML = "";
    const fields = [
      ["Request ID", data.request_id],
      ["Model", data.model],
      ["Policy Pack", data.policy_pack || "standard"],
      ["Latency", data.latency_ms ? `${data.latency_ms}ms` : "—"],
      ["Tokens", data.tokens_used || "—"],
      ["Timestamp", data.timestamp || new Date().toISOString()],
    ];
    fields.forEach(([k, v]) => {
      if (v) {
        const span = document.createElement("span");
        span.textContent = `${k}: ${v}`;
        section.appendChild(span);
      }
    });
  }

  // --- Main scan handler ---
  async function scan() {
    show("loading-view");
    try {
      const content = await extractContent();

      const res = await fetch(`${API}/v1/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: content.url,
          text: content.text,
          metadata: content.metadata,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      show("result-view");

      // Render all sections
      renderBanner(data.final_decision || data.policy?.decision);
      renderPII(data.pii);
      renderKnowledge(data.knowledge);
      renderArgumentation(data.argumentation);
      renderSummary(data.analysis);
      renderRisk(data.analysis);
      renderFlags(data.analysis);
      renderAudit(data);
    } catch (err) {
      show("idle-view");
      alert(`Scan failed: ${err.message}`);
    }
  }

  // --- Init ---
  checkHealth();
  setInterval(checkHealth, 15000);
  $("#scan-btn").addEventListener("click", scan);
})();

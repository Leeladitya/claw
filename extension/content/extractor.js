/**
 * extractor.js — Claw Content Script
 *
 * Extracts the main readable content from the active tab's DOM
 * using lightweight readability heuristics. Communicates with
 * the popup via browser.runtime messaging.
 *
 * This is the UNTRUSTED layer — all security enforcement happens
 * server-side. This script is purely a content extraction tool.
 */

(() => {
  "use strict";

  function scoreNode(node) {
    let score = 0;
    const tag = node.tagName?.toLowerCase();
    const id = (node.id || "").toLowerCase();
    const cls = (node.className || "").toLowerCase();

    if (["article", "main", "section"].includes(tag)) score += 25;
    if (/article|content|post|entry|story|body|text/i.test(id + cls)) score += 30;
    if (/sidebar|nav|footer|header|menu|comment|ad|banner|widget/i.test(id + cls)) score -= 40;
    if (["nav", "aside", "footer", "header"].includes(tag)) score -= 30;

    const text = node.innerText || "";
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    if (wordCount > 100) score += Math.min(wordCount / 10, 50);

    return score;
  }

  function extractMainContent() {
    const semantic = document.querySelector(
      "article, [role='main'], main, .post-content, .article-body, .entry-content"
    );
    if (semantic && (semantic.innerText || "").split(/\s+/).length > 50) {
      return cleanText(semantic.innerText);
    }

    const candidates = document.querySelectorAll("div, section, article, main, td");
    let bestNode = document.body;
    let bestScore = -Infinity;

    for (const node of candidates) {
      const s = scoreNode(node);
      if (s > bestScore) {
        bestScore = s;
        bestNode = node;
      }
    }

    return cleanText(bestNode.innerText || document.body.innerText);
  }

  function cleanText(raw) {
    return raw.replace(/\t/g, " ").replace(/ {2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  }

  function extractMetadata() {
    const getMeta = (name) =>
      document.querySelector(`meta[name="${name}"], meta[property="${name}"]`)?.content || "";

    return {
      title: document.title,
      url: window.location.href,
      description: getMeta("description") || getMeta("og:description"),
      author: getMeta("author") || getMeta("article:author"),
      publishedDate: getMeta("article:published_time") || getMeta("date"),
      siteName: getMeta("og:site_name"),
    };
  }

  browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.action !== "EXTRACT_CONTENT") return false;

    try {
      const text = extractMainContent();
      const metadata = extractMetadata();

      const MAX_WORDS = 12000;
      const words = text.split(/\s+/);
      const truncated = words.length > MAX_WORDS
        ? words.slice(0, MAX_WORDS).join(" ") + "\n\n[... content truncated for analysis]"
        : text;

      sendResponse({
        success: true,
        payload: { ...metadata, text: truncated, wordCount: words.length, extractedAt: new Date().toISOString() },
      });
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }

    return true;
  });
})();

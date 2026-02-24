// Claw Content Extractor — DOM heuristic extraction
(function() {
  if (window.__clawExtractorLoaded) return;
  window.__clawExtractorLoaded = true;

  // Cross-browser compat: Firefox uses browser.*, Chrome uses chrome.*
  const B = typeof browser !== "undefined" ? browser : chrome;

  function extractContent() {
    // Semantic tag scoring
    const SEMANTIC_TAGS = ['article', 'main', 'section', '[role="main"]'];
    let container = null;
    for (const sel of SEMANTIC_TAGS) {
      container = document.querySelector(sel);
      if (container && container.textContent.trim().length > 200) break;
      container = null;
    }
    if (!container) container = document.body;

    // Extract text, strip nav/footer/aside
    const clone = container.cloneNode(true);
    clone.querySelectorAll('nav, footer, aside, script, style, noscript, [role="navigation"], [role="banner"]')
      .forEach(el => el.remove());

    let text = clone.textContent
      .replace(/\s+/g, ' ')
      .replace(/\n{3,}/g, '\n\n')
      .trim();

    // Truncate for model limits
    const MAX_WORDS = 12000;
    const words = text.split(/\s+/);
    if (words.length > MAX_WORDS) {
      text = words.slice(0, MAX_WORDS).join(' ') + '\n\n[TRUNCATED]';
    }

    // Metadata
    const meta = (name) => {
      const el = document.querySelector(`meta[name="${name}"], meta[property="${name}"]`);
      return el ? el.content : '';
    };

    return {
      url: window.location.href,
      title: document.title || '',
      text: text,
      metadata: {
        author: meta('author') || meta('article:author'),
        published_date: meta('article:published_time') || meta('date'),
        site_name: meta('og:site_name'),
        description: meta('description') || meta('og:description'),
      },
      extracted_at: new Date().toISOString(),
      word_count: words.length,
    };
  }

  // Listen for extraction requests from popup
  B.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'extract') {
      try {
        sendResponse({ success: true, data: extractContent() });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    }
    return true;
  });
})();

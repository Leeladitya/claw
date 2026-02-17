# extension/ — Firefox Browser Extension

## What This Is (for everyone)

This is the part of Claw you actually see. It adds a small lobster icon (🦞) to your Firefox toolbar. When you visit a website, click the icon and hit "Scan & Analyze." Claw will:

1. Extract the page content
2. Run it through all 6 stages of the governance pipeline
3. Show you what it found: PII detected, policy decision, domain reputation, which arguments won the debate, risk assessment, and the full audit trail

You can see exactly what Claw decided and WHY — every argument, every attack, every score.

## What This Is (for developers)

**manifest.json** — WebExtension manifest v2 for Firefox.

**content/extractor.js** — Content script injected into pages. Extracts text, domain, and metadata.

**popup/popup.html + popup.js + popup.css** — Extension popup UI. Makes API calls to Claw server, renders results.

### Installation

1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select this folder's `manifest.json`

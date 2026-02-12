# Claw 🦞

### The Governance-First Browser Agent

**Secure. Auditable. OPA-Hardened.**

---

### The Context: Every Tab is an Unguarded Window

We have entered the age of browser-connected AI agents. We treat LLMs as reasoning engines, feeding them data from our browsers to get work done. But currently, that pipeline is a "wild west" of copy-pasting and blind extraction.

Every time we send a webpage to a model, we risk leaking PII, exposing internal secrets, or falling victim to prompt injection attacks hidden in the DOM.

**Claw exists to fix this.**

We are building the missing governance layer for the AI web. Claw acts as a responsible middleman—intercepting, evaluating, and sanitizing browser content *before* it ever touches an LLM.

### What is Claw?

Claw is a bridge between your browser (currently Firefox) and your AI Model (Claude). But unlike standard MCP servers or summarizers, Claw is **opinionated about security.**

It transforms an uncontrolled data firehose into an auditable, compliant, zero-trust pipeline.

* **For Developers:** It’s a "Stripe-like" API for safe browser context.
* **For Security Engineers:** It’s a Policy Enforcement Point (PEP) using OPA (Open Policy Agent).
* **For Researchers:** It’s a playground to test prompt defenses and PII masking.

### The Core Thesis

> **"OPA never sees the model, and the model never sees unfiltered content."**

Claw separates the *decision* (Policy) from the *intelligence* (LLM). This ensures that your governance logic remains lightweight, while your model receives only sanitized, policy-approved context.

### Under the Hood: The 4-Stage Pipeline

Claw doesn't just "forward" data. It processes it through a strict pipeline:

1. **Stage 1: Pre-Processing (The Cleaner)**
Raw text is extracted from the DOM. A PII scanner hunts for sensitive data (emails, SSNs, credit cards) and masks them based on your settings.
2. **Stage 2: The OPA Gate (The Judge)**
We construct a metadata object (domain, user role, content features) and send it to the Open Policy Agent. OPA returns a verdict: `allow`, `deny`, or `allow_with_modifications`.
3. **Stage 3: Context Assembly (The Builder)**
Approved content is assembled. If OPA demanded redactions, they happen here. The payload is hashed for the audit trail.
4. **Stage 4: Model Inference (The Thinker)**
Only now is the secure payload sent to the LLM. The response is captured and risk-scored.

### Getting Started

*Note: Claw is currently in **Phase 1 (Python Prototype)**. We are actively evolving this into a single-binary Go platform.*

**1. Clone the Repository**

```bash
git clone https://github.com/leeladitya/claw.git
cd claw

```

**2. Start the Server**

```bash
# Install dependencies
pip install -r requirements.txt

# Run the API bridge
uvicorn server.main:app --reload --port 8787

```

**3. Load the Extension**

1. Open Firefox and navigate to `about:debugging`.
2. Click **"This Firefox"** > **"Load Temporary Add-on"**.
3. Select the `manifest.json` file in the `/extension` folder.

**4. Analyze**
Navigate to any webpage, open the Claw extension, and hit **Analyze**. Watch your terminal to see the policy engine in action.

### The Roadmap

We are building in public. Here is where Claw is heading:

* **Phase 1 (Current):** Working Python prototype with basic OPA rules and PII scanning.
* **Phase 2 (The Rewrite):** moving to a **Single Go Binary**. No pip, no venv. Just download and run.
* **Phase 3 (Distribution):** Public availability on Mozilla Add-ons and Chrome Web Store.
* **Phase 4 (Enterprise):** SIEM integration, SOC 2 compliance mapping, and advanced "Strict" policy packs.

### Community & Philosophy

Claw is humble in its approach but ambitious in its vision. We believe that governance shouldn't require a PhD in security or days of YAML configuration.

We are looking for:

* **Rust/Go developers** to help with the binary rewrite.
* **Security researchers** to stress-test our prompt injection detection.
* **Policy geeks** to help write better Rego policy packs.

If you care about what context reaches your AI systems, you belong here.

---

**[Contribute to Claw]** • **[Read the Vision Doc]** • **[Discuss on Discord]**

*Built with 🦞 by Saatvix*

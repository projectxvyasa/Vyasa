# VYASA: Autonomous AI Penetration Testing Platform

> **VYASA** is an AI-powered autonomous penetration testing and risk-analysis platform that continuously discovers, validates, reasons about, and explains real-world attack paths across an organization's authorized attack surface.

---

## 1. Platform Philosophy

Traditional penetration testing produces thousands of fragmented tool outputs. Security engineers must manually correlate these findings to determine real business risk.

**VYASA automates that entire investigative workflow:**
* **Not just tool execution:** The AI acts as the reasoning layer that understands scan outputs and decides what to investigate next and why.
* **Attack Path Correlation:** Recognizes when multiple low/medium weaknesses combine into a critical multi-hop kill chain.
* **Executive & Technical Synthesis:** Generates prioritized remediation roadmaps and business-risk explanations.

```
Reconnaissance ──▶ Security Testing ──▶ Validation ──▶ AI Reasoning ──▶ Attack Paths ──▶ Report
```

---

## 2. Architecture & Directory Structure

```text
vyasa/
├── config/
│   └── default_config.yaml         # Configuration for LLM, Recon, Testing & Reporting
├── reports/                        # Output folder for generated Markdown and JSON reports
├── vyasa/
│   ├── __init__.py
│   ├── main.py                     # Root execution script
│   ├── cli.py                      # Command-line interface
│   ├── orchestrator.py             # Master workflow engine linking all phases
│   │
│   ├── core/                       # Core abstractions & data schemas
│   │   ├── config.py               # YA
 Subdomain, port discovery, and technology fingerprinting
│   │
│   ├── testing/                    # Phase 2: Targeted vulnerability assessment
│   │   ├── scanner_manager.py      # Probe dispatching and finding normalization
│   │   ├── web_auditor.py          # HTTP headers, cookies, sensitive endpoint audits
│   │   ├── cors_auditor.py         # Origin reflection, null origin trust, credentials checks
│   │   ├── graphql_auditor.py      # Schema introspection, GraphiQL/Playground discovery
│   │   ├── api_schema_auditor.py   # OpenAPI/Swagger discovery and interactive UI auditing
│   │   └── probe_dispatcher.py     # AI-directed targeted probe execution
│   │
│   ├── validation/                 # Phase 3: Evidence verification & false-positive triage
│   │   └── validator.py            # Reproducibility verification and confidence tagging
│   │
│   ├── reasoning/                  # Phase 4: The AI Reasoning Layer
│   │   ├── agent.py                # Reasoning agent & next-step hypothesis formulation
│   │   ├── attack_graph.py         # NetworkX directed graph for kill-chain modeling
│   │   ├── decision_engine.py      # Autonomous reasoning loop ("What to investigate next & why?")
│   │   └── prompts.py              # Diagnostic system prompts & structured JSON schemas
│   │
│   ├── reporting/                  # Phase 5: Actionable report synthesis
│   │   └── generator.py            # Markdown, JSON, and Mermaid kill-chain diagram generator
│   │
│   └── web/                        # Phase 6: Cyber Operations Command Center
│       ├── app.py                  # FastAPI background-task server & REST API
│       └── templates/index.html    # Interactive dark-mode dashboard with Mermaid.js
│
├── tests/                          # Automated unit and integration test suite
│   └── test_probes.py              # Specialized web probes verification suite
├── requirements.txt                # Python dependencies
└── README.md                       # Documentation
```

---

## 3. Quick Start & Setup

### 1. Prerequisites
* Python 3.10+
* Local LLM running via **LM Studio** / **Bionic** (e.g. `Qwen2.5-7B-Instruct-abliterated` on `http://127.0.0.1:1234/v1`) or any OpenAI-compatible API.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run a Security Engagement

#### Option A: Interactive Web Command Center (Recommended)
Launch the dark-mode cyber operations dashboard:
```bash
python main.py --web
```
Then open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. The Web UI gives you:
* Live scan execution stepper & progress tracking.
* Real-time AI Reasoning loop feed ("What to investigate next and why?").
* Interactive Mermaid.js attack path kill-chain diagrams.
* Tabular Asset inventory & categorized Vulnerability catalog.
* In-browser Markdown Report reader with one-click report switching.

#### Option B: Terminal CLI Mode (With Live Streaming & Interactive Wizard)
Run an autonomous assessment directly in your terminal:
```bash
python main.py -t authorized-target.corp
```

* **Interactive Report Customization:** Prompt for specific sections to include (Executive Summary, AI Telemetry, Attack Paths, 100+ Check Matrix, Remediation Roadmap):
```bash
python main.py -t authorized-target.corp -i
```

* **Accept All Defaults (Non-Interactive):**
```bash
python main.py -t authorized-target.corp -y
```

* **With Verbose Diagnostic Logging:**
```bash
python main.py -t authorized-target.corp -v
```

### 4. Review Generated Reports
Audit deliverables are written to `./reports/`:
* `reports/VYASA-<DATE>-<TARGET>.md` (Full customized Markdown report with Mermaid attack graphs & live probe telemetry)
* `reports/VYASA-<DATE>-<TARGET>.json` (Machine-readable JSON schema for SIEM / dashboard integration)

---

## 4. Connecting to Your Local Qwen 2.5 Model

In `config/default_config.yaml`, ensure the LLM configuration matches your local server:

```yaml
llm:
  base_url: "http://127.0.0.1:1234/v1"    # LM Studio default local port
  api_key: "lm-studio"
  model: "qwen2.5-7b-instruct-abliterated"
  temperature: 0.2
  max_tokens: 3072
```

*(Note: If the local LLM is temporarily offline, VYASA automatically engages its built-in heuristic graph correlation fallback so audits never fail).*

---

## 5. Running Automated Tests

Run the test suite covering CORS reflection, GraphQL introspection, and API schema discovery probes:

```bash
python -m unittest discover tests
```


---

## 6. Confirmation-Gated Injection Detection (SQLi / XSS / SSTI / Command)

VYASA reports an injection finding **only when it is actively confirmed** by
reproducible evidence - never on suspicion or lone reflection. Each confirmed
finding carries a `CONFIRMED VIA ...` proof marker that the validation layer
re-verifies. Input vectors covered: **query parameters, POST form fields, and
URL path segments** (e.g. `/search/<payload>/`).

* **SQL Injection** (`vyasa/testing/injection_confirm.py`): error-based,
  boolean-based blind (baseline/true/false differential, reproduced), and
  time-based blind (`SLEEP`/`WAITFOR` with a `SLEEP(0)` control, reproduced).
* **Reflected XSS**: context-aware (HTML body / attribute / JS string), confirmed
  only when a breakout payload is reflected **unencoded and verbatim** in an
  executable context; inert containers (`<textarea>`, `<title>`, comments) are
  rejected.
* **DOM / execution XSS** (`vyasa/testing/dom_scanner.py`, optional Playwright):
  loads payload URLs in a real headless Chromium and confirms **only when the
  injected JavaScript actually executes** (alert/marker hook fires). Catches
  DOM-based XSS and fragment (`#`) sinks the HTTP engine cannot see. Enable with
  `pip install playwright && playwright install chromium`; skipped gracefully if
  absent.
* **SSTI**: confirmed when `{{7*7}}`->`49` and `{{8*8}}`->`64` evaluate
  server-side (reproduced, not echoed literally).
* **OS Command Injection**: confirmed by command output (`uid=`/`gid=`) or a
  reproduced injected `sleep` delay with a `sleep 0` control.

Run the regression suite: `python -m unittest tests.test_injection_confirm`
Live diagnostic for a single URL: `python diag_injection.py "<authorized-url>"`

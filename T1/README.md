# VYASA

**Vulnerability Yield & Attack Simulation Automation** — an AI-assisted browser security copilot for pentesters and bug-bounty hunters.

VYASA is a Chrome (Manifest V3) extension that combines passive reconnaissance, technology fingerprinting, OSINT, and **authorized active confirmation** of web vulnerabilities — pinpointing issues down to the exact endpoint and parameter, so you spend less time on repetitive setup and more time on real findings.

> ⚠️ **Authorized testing only.** VYASA's active features send test traffic to the target and are gated behind an explicit per-origin authorization step. Only use them against systems you own or have written permission to test. Unauthorized scanning may be illegal.

---

## Features

**Passive audit (safe on any site)**
- Security-header analysis (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP)
- Technology fingerprinting + known-CVE matching
- Client-side secret / token detection (redacted)
- Web-storage, DOM-sink and mixed-content audit
- Cookie security review (Secure / HttpOnly / SameSite)
- Server banner & error-page information-leak detection
- DNS & email-spoofing recon (SPF / DMARC via DoH)
- **Host intelligence** — open ports & protocols, server geolocation, and host-level CVEs (passive, via public data sources)

**Active confirmation (authorized targets only)**
- Attack-surface discovery: crawl, robots/sitemap, JS endpoint extraction, subdomain enumeration (Certificate Transparency + DNS)
- **Behavior-driven route learning** — submits forms and observes the real injection point instead of guessing route names
- Per-parameter XSS testing across **query, body, and URL-path** injection points, with reflection-context classification and character-level filter fingerprinting
- Non-destructive SQLi probing (error-based + boolean-differential)
- Open-redirect checks and an expanded CORS trust map
- **Confirmation states** (Confirmed / Suspected) so only verified findings drive the risk score — keeping false positives out

**Reporting**
- JSON, Markdown (bug-bounty style) and printable PDF exports
- Cyberpunk HUD with a light / dark theme

## Install (development)

1. Clone this repository.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the `Extension v2` folder.
4. Pin VYASA and open it on any `http(s)` page.

## Usage

- **INITIATE SCAN** runs the full passive audit and attack-surface discovery — no attack traffic.
- Toggle **⚡ ACTIVE** and run again to confirm vulnerabilities down to the parameter. You'll be asked to confirm you're authorized to test the origin; state-changing forms (contact/signup/booking) are never auto-submitted unless you explicitly opt in.

## Status

🚧 In active development.

## Disclaimer

VYASA is a security-testing aid for authorized assessments and education. The authors assume no liability for misuse. Always obtain written authorization before testing any system you do not own.

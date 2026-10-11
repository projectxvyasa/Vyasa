# VYASA

**Vulnerability Yield & Attack Simulation Automation** — an AI-assisted offensive-security toolkit for pentesters and bug-bounty hunters.

This repository is a **monorepo** holding two tiers of the VYASA project:

| Folder | Tier | What it is |
|--------|------|------------|
| [`T1/`](./T1) | **T1 — Extension** | The Chrome (Manifest V3) **browser extension** — passive recon, tech fingerprinting, OSINT, and authorized active confirmation of web vulnerabilities, right inside the browser. See [`T1/README.md`](./T1/README.md). |
| [`T3/`](./T3) | **T3 — Platform** | The standalone **Python autonomous-pentest platform** — a FastAPI engine + live dashboards that crawl, probe, and run 100+ confirmation-gated vulnerability checks, with AI reasoning and attack-path correlation. See [`T3/README.md`](./T3/README.md). |

---

## ⚠️ Authorized testing only

Both tiers send test traffic to targets and are intended **only** for systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

---

## Quick start

**T1 — Extension**
```
# Load the unpacked extension
Chrome → Extensions → Developer mode → Load unpacked → select the T1/ folder
```

**T3 — Platform**
```
cd T3
pip install -r requirements.txt
python main.py            # or launch the web dashboard (see T3/README.md)
# dashboards: http://127.0.0.1:8000/  and  http://127.0.0.1:8000/live
```

---

## Repository layout

```
Vyasa/
├── T1/        # Browser extension (Manifest V3)
├── T3/        # Python autonomous-pentest platform (FastAPI + vyasa package)
├── .gitignore
└── README.md  # you are here
```

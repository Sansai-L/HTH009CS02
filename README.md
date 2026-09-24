# HTH009CS02 — Business-Risk-Ranked Vulnerability Scanner & Remediation Planner

**Event**: HACK the HORIZON 2.0 (24-Hour Hackathon)  
**Problem Statement**: HTH-CS-03 — Enterprise Security / IT Operations  
**GitHub Repository**: [https://github.com/Sansai-L/HTH009CS02](https://github.com/Sansai-L/HTH009CS02)

---

## 🎯 Executive Overview

Traditional vulnerability scanners (e.g. Nmap, OpenVAS, Nessus) produce long flat lists of findings sorted purely by raw CVSS scores, leading to **alert fatigue** for bandwidth-constrained security teams. 

**HTH009CS02** solves this by enriching technical findings with **Business Context** (Asset Criticality & Network Exposure) and **Threat Intelligence** (CISA Known Exploited Vulnerabilities + FIRST EPSS Exploit Probability), then running an exact **0/1 Knapsack Remediation Optimizer** to build the maximum risk-reduction sprint plan under fixed weekly engineering hours.

---

## 🏗️ Architecture Pipeline (Sprint 1 – 4)

```
AUTHORIZED LAB TARGET (IP / Subnet)
       ↓
TARGET AUTHORIZATION GUARDRAIL (Private Subnet Whitelist / Evaluation Mode)
       ↓
LAB SCANNER & BANNER NORMALIZER (8 Port Signatures -> Standard Finding Schema)
       ↓
THREAT INTELLIGENCE ENRICHMENT (CISA KEV Catalog + FIRST EPSS Probability API)
       ↓
BUSINESS RISK ENGINE (Base BRS = Exploitability x Criticality x Exposure)
                     (Final BRS = Base BRS x Threat Multiplier)
       ↓
0/1 KNAPSACK REMEDIATION OPTIMIZER (Maximize BRS Addressed subject to Capacity <= C)
       ↓
SQLITE DATABASE PERSISTENCE LAYER (Assets, ScanJobs, Vulnerabilities, Plans)
       ↓
INTERACTIVE WEB DASHBOARD (Survives Browser Refresh & App Restarts)
```

---

## 🧠 Business Risk & Threat Intelligence Scoring Methodology

We distinguish explicitly between technical severity, exploitation likelihood, and business context:
- **CVSS**: Technical Severity ($0.0 - 10.0$)
- **FIRST EPSS**: Exploitation Likelihood ($0.0 - 1.0$ / $0 - 100\%$)
- **CISA KEV**: Active Real-World Exploitation ($True / False$)
- **Asset Criticality**: Business Importance ($1.0 - 10.0$)
- **Exposure**: Accessibility ($0.1 - 1.0$)

### Mathematical Formula:

$$\text{Base BRS} = \text{Exploitability} \times \text{Asset Criticality} \times \text{Exposure}$$

$$\text{EPSS Contribution} = (\text{epss\_score} \times 0.5) \quad \text{if epss\_score is present else } 0.0$$

$$\text{KEV Boost} = 0.5 \quad \text{if kev\_known\_exploited is True else } 0.0$$

$$\text{Threat Multiplier} = 1.0 + \text{EPSS Contribution} + \text{KEV Boost} \in [1.0, 2.0]$$

$$\text{Final Business Risk Score (BRS)} = \text{round}(\text{Base BRS} \times \text{Threat Multiplier}, 2)$$

---

## 📡 Threat Intelligence Integration (Sprint 4)

1. **CISA KEV Catalog**:
   - Official JSON Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - Local Disk & Memory Cache: `app/threat_intel/cisa_kev_cache.json` (24h TTL).
   - Flags active exploits in the wild (`🔴 EXPLOITED`).

2. **FIRST EPSS API**:
   - Official Endpoint: `https://api.first.org/data/v1/epss`
   - Batched lookup with 3s timeout and local disk cache (`app/threat_intel/epss_cache.json`).
   - Displays EPSS score & percentile (e.g. `97.5% (P99.8%)`).

3. **Graceful Offline / Failure Fallback**:
   - If CISA or FIRST EPSS APIs are offline or unreachable, `threat_intel_multiplier = 1.0`.
   - Base BRS scoring, scanning, and 0/1 Knapsack remediation planning continue seamlessly **without crashing**.

---

## 🔌 API Route Reference

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web Dashboard Interface |
| `GET` | `/api/health` | Health Check (Returns active Sprint & Version) |
| `POST` | `/api/scan` | Scans lab target, enriches with KEV/EPSS, scores BRS, persists to SQLite |
| `POST` | `/api/plan` | Solves 0/1 Knapsack optimization, persists plan to SQLite |
| `GET` | `/api/plan/latest` | **Browser Refresh Recovery**: Retrieves latest persisted plan from SQLite |
| `GET` | `/api/threat-intel/{cve}` | Returns CISA KEV & FIRST EPSS data for a specific CVE |
| `POST` | `/api/threat-intel/refresh` | Forces refresh of the CISA KEV catalog cache |
| `POST` | `/api/findings/enrich` | Enriches findings list with threat intelligence |
| `GET` | `/api/assets` | Retrieves tracked assets from SQLite |

---

## ⚡ Quickstart & Setup Instructions

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3. Access Dashboard
# Open http://127.0.0.1:8000 in your web browser

# 4. Run Test Suite (20 Automated Tests)
python -m pytest -v
```

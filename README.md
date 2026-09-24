# 🛡️ VulnRankPro — Business-Risk Vulnerability Scanner & Remediation Planner
> **Track:** Cybersecurity (HTH-CS-03) | **Architecture:** Zero-Dependency Client-Side SPA  
> **Standards:** U.S. CISA KEV Catalog • MITRE ATT&CK® v15 • ISO 27001 / NIST CSF Aligned

---

## 📌 Executive Overview

Traditional vulnerability scanners overwhelm security teams with 200+ raw CVSS findings without business context, without awareness of active in-the-wild exploitation, and without considering real engineering capacity constraints (teams can realistically fix only 3–7 items/week).

**VulnRankPro** transforms vulnerability management from a static to-do list into a dynamic risk intelligence platform:
1. **Business-Risk Engine:** Evaluates risk via $\text{Exploitability} \times \text{Asset Criticality} \times \text{Exposure}$.
2. **Live CISA KEV Integration:** Live feed from `api.cisa.gov` — forces active exploits to maximum risk ($100/100$) and prioritizes them in Sprint 1.
3. **MITRE ATT&CK® Framework v15:** Contextual sorting and kill-chain phasing (Initial Access &rarr; Execution &rarr; Credential Access &rarr; Lateral Movement &rarr; Command and Control).
4. **Interactive ROI Simulator:** Drag-and-drop planning board with Chart.js risk forecasting under capacity constraints.
5. **Attack Path Topology Graph:** Concentric exposure zones and node scaling with real-time pivot path severing simulation.
6. **One-Click Executive PDF Brief:** Board-ready briefing with jargon translation parser and risk ROI metrics.
7. **Targeted Micro-Scan Rescan:** Closed-loop verification micro-scanner that probes only sprint endpoints and logs permanent risk drops.

---

## 🚀 Quick Start (Zero Setup Required)

VulnRankPro is an ultra-portable, zero-dependency Single Page Application (SPA). No Node.js, no Docker, and no backend servers are required.

```bash
# Clone the repository
git clone https://github.com/Sansai-L/HTH009CS02.git

# Navigate to the folder
cd HTH009CS02

# Simply open index.html in any modern web browser
# (Chrome, Edge, Firefox, Brave, Safari)
start index.html
```

---

## 🏗️ Architecture & Data Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                      EXTERNAL THREAT INTELLIGENCE                      │
│   • U.S. CISA KEV Live Catalog (api.cisa.gov / corsproxy.io)           │
│   • MITRE ATT&CK Enterprise Matrix v15 (TA0001 - TA0011)               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           CORE RISK ENGINE                             │
│   • Business-Risk Math: (Exploit/10) * (Crit/4) * (Exposure/3) * 100   │
│   • CISA KEV Override: If CVE in KEV Set -> Risk = 100, Sev = Critical │
│   • Threat Enrichment: Tactic ID, Technique ID, Kill-Chain Phase       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│  RISK REPORT    │       │   REMEDIATION    │       │  ROI SIMULATOR   │
│  • MITRE Group  │       │   • 5-Fix Sprint │       │  • Drag & Drop   │
│  • Flat Table   │       │   • Task Toggles │       │  • Chart.js Line │
│  • CSV Export   │       │   • Action Bar   │       │  • Capacity Gate │
└────────┬────────┘       └─────────┬────────┘       └────────┬─────────┘
         │                          │                         │
         ▼                          ▼                         ▼
┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│   ATTACK PATH   │       │  EXECUTIVE PDF   │       │  MICRO-RESCAN    │
│  • Concentric   │       │  • Zero-Jargon   │       │  • Target Probes │
│  • Node Sizing  │       │  • Vector Donut  │       │  • State Compare │
│  • Sever Beam   │       │  • CISO Signoff  │       │  • Trend DB Sync │
└─────────────────┘       └──────────────────┘       └──────────────────┘
```

---

## 📐 Mathematical Model & Scoring

$$\text{Business Risk Score} = \left(\frac{\text{Exploitability}}{10}\right) \times \left(\frac{\text{Asset Criticality}}{4}\right) \times \left(\frac{\text{Exposure Level}}{3}\right) \times 100$$

* **Exploitability ($1 - 10$):** Inherent ease of weaponization and exploit availability.
* **Asset Criticality ($1 - 4$):**
  * $1 =$ Low (Dev/Test Environment)
  * $2 =$ Medium (Internal Shared Host)
  * $3 =$ High (Production Application Server)
  * $4 =$ Critical (Crown-Jewel Customer / Financial Database)
* **Exposure Level ($1 - 3$):**
  * $1 =$ Restricted / Air-gapped Internal Enclave
  * $2 =$ DMZ / Semi-Public Supporting Service
  * $3 =$ Public Internet-Facing

### 🚨 CISA KEV Rule
$$\text{If } \text{CVE} \in \text{CISA KEV Catalog} \implies \text{Business Risk} = 100.0, \quad \text{Severity} = \text{"Critical"}, \quad \text{Sprint Priority} = \#1$$

---

## 🎯 7 Core Innovations

| # | Feature | Technology | Innovation |
|---|---|---|---|
| **1** | **Business-Risk Engine** | ES2022 Math | Replaces flat CVSS with real-world contextual exposure and criticality scoring. |
| **2** | **CISA KEV Override** | REST API + Fallback | Live query against 1,100+ active exploits with auto-proxy and offline fallback. |
| **3** | **MITRE ATT&CK Mapping** | Threat Intel Matrix | Contextual sorting grouping vulnerabilities into a 5-phase kill-chain. |
| **4** | **ROI Simulator** | HTML5 DnD + Chart.js | Visualizes projected risk reduction curve under strict weekly capacity limits. |
| **5** | **Attack Path Topology** | SVG + Graph Layout | Concentric perimeter layout with animated red pivot beam and path severing. |
| **6** | **Executive PDF Brief** | jsPDF + html2canvas | Jargon translation engine replacing CVE codes with business asset impacts. |
| **7** | **Verification Micro-Scan** | Socket Simulation | Narrow-scope endpoint verification that locks until sprint completion. |

---

## 📊 Presentation Deck & Materials

* **PowerPoint Presentation:** [`VulnRankPro_Hackathon_Presentation.pptx`](./VulnRankPro_Hackathon_Presentation.pptx) (15 Widescreen 16:9 Slides with Dark Cyber SOC theme)
* **Demo Lab Target:** Metasploitable 2 (`192.168.56.101`) / DVWA / Custom Labs
* **Supported Protocols:** Full IPv4, IPv6 (`[2001:db8::1]:port`), and FQDN hostname support.

---

## 🛠️ Repository File Structure

```text
HTH009CS02/
├── index.html                             # Main application SPA interface
├── style.css                              # Design system & dark SOC styling
├── app.js                                 # Core scanner engine, MITRE DB, KEV API, & micro-rescan
├── roi.js                                 # Drag-and-drop ROI simulator & Chart.js projection
├── attack-path.js                         # SVG network topology & pivot path severing
├── executive-summary.js                   # Jargon translation engine & jsPDF generation
├── VulnRankPro_Hackathon_Presentation.pptx# Hackathon staff presentation slide deck
├── README.md                              # Project documentation & technical guide
└── .gitignore                             # Git ignore configuration
```

---

## ⚖️ License & Ethical Disclosure
Built for educational, hackathon, and defensive cybersecurity posture assessment. Always obtain explicit written authorization before scanning target networks. Aligns with ISO 27001, NIST CSF, and CISA operational directives.

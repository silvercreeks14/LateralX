# LateralX — Threat Intelligence Platform

> An analyst-first forensic investigation platform. Upload raw evidence, get structured threat intelligence back in seconds — MITRE ATT&CK mapping, behavioral anomalies, attack storylines, LLM-powered narratives, and court-ready reports.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Feature Breakdown](#feature-breakdown)
  - [Evidence Ingestion](#evidence-ingestion)
  - [Authentication & Access Control](#authentication--access-control)
  - [Analysis Pipeline](#analysis-pipeline)
  - [Behavioral Analytics (Phase 2)](#behavioral-analytics-phase-2)
  - [Attack Storyline (Phase 3)](#attack-storyline-phase-3)
  - [ML Anomaly Detection](#ml-anomaly-detection)
  - [Attack Classification](#attack-classification)
  - [Threat Intelligence Enrichment](#threat-intelligence-enrichment)
  - [Case Management](#case-management)
  - [Reporting & Exports](#reporting--exports)
  - [Analyst Tools](#analyst-tools)
- [What LateralX Is Best at Analyzing](#what-lateralx-is-best-at-analyzing)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)

---

## Overview

LateralX ingests forensic evidence files (Windows event logs, Plaso timelines, PCAP captures) and runs a multi-phase analysis pipeline — from instant deterministic scanning through LLM-generated narratives — outputting structured threat intelligence that maps directly to the MITRE ATT&CK framework.

The UI is a dark-themed single-page app organized around a fixed sidebar. No page reloads. Every button maps to a real backend endpoint.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Frontend  (React + TypeScript + Vite + Tailwind CSS)     │
│  Sidebar nav → Data Ingestion / Investigations / ML Intel │
└─────────────────────┬────────────────────────────────────┘
                      │ REST (JSON)
┌─────────────────────▼────────────────────────────────────┐
│  Backend  (FastAPI + SQLAlchemy + SQLite)                 │
│                                                          │
│  Ingest → Parse → Normalize → Store                      │
│  ↓                                                       │
│  Phase 1: Quick Scan  (instant, no LLM)                  │
│    MITRE mapping · IOC extraction · Severity · ML scores │
│  ↓                                                       │
│  Phase 1+: Deep AI Analysis  (LLM-backed)                │
│    Narrative · Patient Zero · Pivot chain                │
│  ↓                                                       │
│  Phase 2: Behavioral Analytics  (deterministic)          │
│    Z-score spike · Lateral velocity · Auth burst         │
│  ↓                                                       │
│  Phase 3: Attack Storyline  (deterministic)              │
│    ATT&CK steps · Lateral paths · Blast radius           │
└──────────────────────────────────────────────────────────┘
```

---

## Feature Breakdown

### Evidence Ingestion

| Format | Description |
|--------|-------------|
| **Plaso L2T CSV** | Timelines exported from `log2timeline.py` |
| **Timesketch JSONL** | Native Timesketch export format |
| **Generic CSV** | Any CSV with timestamp, host, user, event-type columns |
| **PCAP / PCAPng** | Full packet captures parsed into protocol-labeled flow events |

- **File integrity**: SHA-256 hash computed on every upload; warns if the same filename is re-uploaded with a different hash (chain-of-custody protection)
- **Upload limit**: 100 MB per file
- **Multi-source merging**: upload multiple files into a single Case; events are merged and source-tagged in the timeline
- **Noise filtering**: high-volume background events (logoff 4634/4647, NTLM 4776, special-privileges 4672) are suppressed unless a suspicious keyword is also present
- **Hostname normalization**: strips domain suffixes (`.corp.local`, `.internal`, `.lan`, etc.), uppercases, resolves priority field order across different log schemas

---

### Authentication & Access Control

- **JWT sessions** with 4-hour sliding expiry
- **Role-based access**: `admin` vs `analyst` — admin gates ML training, synthetic baseline generation, and ground-truth verification
- **TOTP MFA** (RFC 6238) compatible with Google Authenticator, Authy, and any standard TOTP app
  - Admins enroll via QR code provisioning (`/api/admin/totp/setup`)
  - MFA is enforced on all privileged endpoints once enrolled
- **Bcrypt** password hashing

---

### Analysis Pipeline

#### Quick Scan (instant — no LLM)

Runs in milliseconds. Suitable for triage.

- **MITRE ATT&CK mapping** — keyword pattern matching across 30+ technique signatures covering execution, persistence, lateral movement, credential access, defense evasion, and impact
- **IOC extraction** — IPv4/IPv6 addresses, domain names, file hashes (MD5/SHA-1/SHA-256), suspicious filenames
- **Severity scoring** — 0–100 composite score: CRITICAL ≥ 80, HIGH ≥ 60, MEDIUM ≥ 35, LOW < 35
- **ML anomaly scores** — Isolation Forest per-user behavioral scoring (if model is trained)
- **Attack classification** — 10-category Random Forest classifier (see below)

#### Deep AI Analysis (LLM-powered)

Adds a full LLM pass over the event windows. Supports the provider configured in `.env` (only local Ollama).

- **Investigation narrative** — prose incident summary with inline event citations (`[event_id]` clickable to reveal raw log)
- **Patient Zero candidate** — first-compromised host/user identification
- **Initial access vector** — how the attacker got in
- **Pivot chain** — ordered lateral movement steps
- **Anomalous event list** — human-readable descriptions of the most significant deviations
- **Baseline comparison** — statistical comparison against the stored clean-state baseline

---

### Behavioral Analytics (Phase 2)

Four fully deterministic checks — no training data required, runs in O(n):

| Check | Trigger Condition |
|-------|------------------|
| **Hourly event spike** | Per-user event count Z-score > 2.5 over the observed hourly distribution (requires ≥ 3 distinct hours) |
| **Lateral velocity** | User accesses > 3 distinct hosts within any 30-minute window |
| **Auth failure burst** | > 10 Event ID 4625 (failed logon) failures per user within 5 minutes |
| **Off-hours privileged op** | Event ID 4672 (SeDebugPrivilege) outside 07:00–19:00 local time |

Each anomaly is returned with: `anomaly_type`, `user`, `z_score`, `threshold`, `observed`, and a `severity` rating (critical / high / medium / low).

---

### Attack Storyline (Phase 3)

Correlates events across all sources to reconstruct the attack narrative as structured data — no LLM required:

- **ATT&CK-mapped attack steps** — chronological list of `(timestamp, host, user, tactic, technique_id, technique_name, confidence)`
- **Lateral movement paths** — `from_host → to_host` with the method (SMB, WMI, RDP, etc.) and responsible technique ID
- **Blast radius**:
  - Compromised hosts and users
  - Accessed resources (file shares, databases, AD objects)
  - Persistence mechanisms installed
  - Estimated data at risk
- **Threat actor profile** — heuristic-based actor characterization
- **Entry vector** — detected initial access method
- **Tactic progression** — ordered MITRE ATT&CK kill-chain phases observed
- **Confidence rating** — high / medium / low based on evidence density

---

### ML Anomaly Detection

- **Algorithm**: scikit-learn Isolation Forest
- **Training sources**: existing DB events + optional synthetic baseline (30 synthetic users, configurable volume)
- **Per-user output**: anomaly score (0–1), risk level (`normal` / `suspicious` / `high_risk`), contributing behavioral factors
- **Analyst feedback loop**: TP / FP verification buttons on each scored user; feedback is stored as ML ground truth and used to compute precision / recall / F1 / accuracy metrics visible in the ML Stats widget
- **Minimum training threshold**: ≥ 10 users with event history
- **Admin controls**: `Seed + Train` (generate synthetic baseline then train), `Retrain` (on existing DB events only)

---

### Attack Classification

10-category supervised classifier:

| Category | Key Signals |
|----------|-------------|
| **Ransomware** | VSS deletion, bcdedit, shadow copy tampering, file encryption patterns |
| **Kerberoasting** | Event 4769 (TGS requests), RC4 encryption type, SPN enumeration |
| **Lateral Movement** | PsExec, WMI exec, admin shares, logon type 3, Event 4648 |
| **Credential Theft** | LSASS access, Mimikatz, sekurlsa, DCSync (4662), NTDS.dit |
| **Data Exfiltration** | Large outbound transfers, archive creation, staging directories |
| **C2 Communication** | Beaconing patterns, encoded payloads, unusual outbound protocols |
| **Persistence** | Scheduled tasks (4698), services (7045), registry run keys (4657) |
| **Privilege Escalation** | Token manipulation (4672), UAC bypass, named pipe impersonation |
| **Defense Evasion** | LOLBins (certutil, mshta, regsvr32, wmic), log clearing (wevtutil) |
| **Reconnaissance** | net user/group, LDAP queries, port scanning, BloodHound artifacts |

- **Model**: Random Forest, ~4,800–5,200 training samples (real labeled sessions + MITRE ATT&CK-derived synthetic data)
- **Fallback**: keyword-only scoring when scikit-learn is unavailable
- **Output**: primary category, confidence score, all-category scores, MITRE technique IDs, top evidence keywords

---

### Threat Intelligence Enrichment

- **VirusTotal** — file hash and IP reputation lookups
- **AbuseIPDB** — IP abuse confidence score
- Enrichment is applied to extracted IOCs during Deep AI Analysis (not Quick Scan — to preserve instant-response contract)
- Results are cached in-process to avoid duplicate API calls and stay within free-tier rate limits (max 4 external lookups per analysis)
- Gracefully no-ops when API keys are absent — zero impact on core analysis

---

### Case Management

- **Cases** track a named investigation across multiple evidence uploads, analyses, and notes
- **Lifecycle states**: `active` → `closed` → `archived` (with restore path)
- **Analyst notes**: create, update, delete notes attached to a case; notes are full-text searchable
- **Multi-source merging**: all uploads tagged to a case are merged in the timeline and analysis views with per-source color coding
- **Status filters**: All / Active / Closed / Archived with event counts

---

### Reporting & Exports

| Report | Format | Contents |
|--------|--------|----------|
| **Quick Scan Snapshot** | Self-contained HTML | MITRE techniques, IOCs, severity score, ML anomaly scores |
| **Deep AI Intelligence Report** | Self-contained HTML | Full narrative, patient zero, pivot chain, all findings |
| **Court-Ready Forensic Report** | Black/white HTML (print-ready) | Chain-of-custody block, SHA-256 hashes, attestation section, all evidence |
| **Case Forensic Report** | Self-contained HTML | All uploads, all analyses, all analyst notes for the case |
| **IOC Export — CSV** | CSV | Extracted indicators of compromise |
| **IOC Export — STIX 2.1** | JSON | Machine-readable threat intelligence bundle |

---

### Analyst Tools

#### Timeline
- Chronological event table with color-coded row highlighting:
  - **Amber** — suspicious LOLBin / encoded command keywords
  - **Blue** — logon events (4624, 4648, 4768, 4769)
  - **Purple** — network events from PCAP sources
- Multi-source legend with per-file color coding when multiple uploads are loaded
- Protocol badge (NET) with specific protocol label for PCAP events

#### Graph View
- Interactive attack graph built with **Cytoscape.js**
- Nodes: hosts and users; edges: observed connections and movement paths
- Per-upload source filtering

#### Filter Bar
- Dropdown filters for Host, User, and Event Type
- Filters compose (AND logic) and persist until manually cleared

#### Global Search
- Full-text search across all events and analyst notes
- Keyboard shortcut: **Ctrl+K** / **Cmd+K**
- 300 ms debounce, minimum 2 characters
- Match highlighting in results
- One-click navigation to the case containing a result

#### Analyst Chat
- LLM-powered Q&A interface against the loaded timeline
- Conversation history maintained per session
- Suggested starter questions for common investigative paths
- Supports any LLM provider configured in `.env`

---

## What LateralX Is Best at Analyzing

LateralX is purpose-built for **Windows-centric enterprise intrusion investigations**. It performs best on:

### Windows Security Event Logs

The most signal-rich input type. LateralX has first-class support for:

| Event ID | Meaning | Detection Use |
|----------|---------|---------------|
| 4624 / 4625 | Logon success / failure | Brute force, lateral movement |
| 4648 | Explicit-credential logon | Pass-the-Hash, lateral movement |
| 4662 / 4663 | AD object access | DCSync, data collection |
| 4672 | Special privileges assigned | Off-hours privilege escalation |
| 4688 | New process creation | LOLBin execution, command-line logging |
| 4698 / 4699 | Scheduled task create/delete | Persistence |
| 4768 / 4769 | Kerberos TGT / TGS request | AS-REP Roasting, Kerberoasting |
| 7045 | New service installed | Persistence |

### Active Directory Attacks

Lateral movement, privilege escalation, and credential theft patterns that span multiple hosts are exactly the scenario the pivot-chain and storyline engines are built for. The platform correlates 4624/4648 logon sequences across different systems to reconstruct attacker movement.

### Living-off-the-Land (LOLBin) Campaigns

The keyword engine and MITRE mapper cover the full LOLBin arsenal: `certutil`, `mshta`, `regsvr32`, `rundll32`, `wmic`, `wscript`/`cscript`, `msiexec`, and PowerShell encoded-command variants (`-enc`, `-EncodedCommand`).

### Plaso / Log2Timeline Exports

The L2T CSV parser handles Plaso's multi-source merged timeline format natively, including timestamp normalization, source-type extraction, and hostname deduplication across records.

### Multi-Host Incidents

When multiple log sources from different machines are uploaded into the same Case, LateralX merges them into a unified chronological timeline and correlates user/host activity across all sources. The lateral velocity check and storyline engine are specifically designed for this cross-host correlation scenario.

### Network-Level Forensics (PCAP)

PCAP captures are parsed into protocol-labeled flow events. The following protocols are recognized and labeled:

`DNS · HTTP · TLS · TCP · UDP · ICMP · SMB · SMB2 · Kerberos · LDAP · FTP · SMTP · QUIC · NBNS`

Network events appear in the timeline with a purple highlight and NET badge, and can be correlated with host-based log events within the same Case.

### What It Is Not Optimized For

- **Linux/macOS-native logs** — auditd and syslog can be ingested via generic CSV but lack the deep Event-ID mapping. Keyword-based patterns will still fire.
- **Cloud audit logs** (AWS CloudTrail, Azure Activity Log) — parseable as generic CSV/JSONL but field normalization is best-effort.
- **High-volume continuous ingestion** — LateralX is designed for focused incident scopes (up to a few hundred thousand events), not SIEM-scale streaming.

---

## Tech Stack

### Backend

| Component | Library |
|-----------|---------|
| API framework | FastAPI |
| ORM / database | SQLAlchemy + SQLite |
| Auth | python-jose (JWT), pyotp (TOTP), passlib (bcrypt) |
| ML | scikit-learn (Isolation Forest, Random Forest) |
| PCAP parsing | Scapy |
| Threat intel | requests → VirusTotal API, AbuseIPDB API |
| LLM | Configurable via `.env` (OpenAI / Anthropic / local Ollama) |

### Frontend

| Component | Library |
|-----------|---------|
| Framework | React 18 + TypeScript |
| Build tool | Vite |
| Styling | Tailwind CSS (CDN v3) |
| Graph visualization | Cytoscape.js |
| HTTP client | Fetch API (custom typed client in `src/api/client.ts`) |

### Design System

| Role | Value |
|------|-------|
| Base background | `#030712` Gray-950 |
| Surface | `#0f172a` Slate-900 |
| Elevated surface | `#1e293b` Slate-800 |
| Primary accent | `#00F0FF` Cerenkov Blue |
| Critical alert | `#FF6B00` Atomic Orange |

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- (Optional) Ollama running locally for LLM analysis without cloud API keys

### Backend

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET_KEY and ADMIN_PASSWORD

# Start the API server
uvicorn backend.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Vite dev server starts at http://localhost:5173
```

### Default Credentials

On first startup, a default admin account is created:

- **Username**: `admin`
- **Password**: value of `ADMIN_PASSWORD` in `.env` (change before production use)

MFA is optional until an admin completes TOTP setup at **Settings → MFA Setup**.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET_KEY` | Yes | Secret for JWT signing — use a long random string in production |
| `ADMIN_PASSWORD` | Yes | Initial admin account password |
| `LLM_PROVIDER` | No | `ollama` (default: `ollama`) |
| `OLLAMA_MODEL` | No | Ollama model name (default: `llama3`) |
| `VIRUSTOTAL_API_KEY` | No | Enables VirusTotal IOC enrichment |
| `ABUSEIPDB_API_KEY` | No | Enables AbuseIPDB IP reputation lookups |

---

## License

Internal research platform. All rights reserved.

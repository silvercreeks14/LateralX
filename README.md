# FIP — Forensic Investigation Platform

> An analyst-first forensic investigation platform specializing in Active Directory attack detection. Upload raw evidence, get structured threat intelligence back in seconds — MITRE ATT&CK mapping, AD-specialized lateral movement detection, behavioral anomalies, attack storylines, LLM-powered narratives, and court-ready reports.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Feature Breakdown](#feature-breakdown)
  - [Evidence Ingestion](#evidence-ingestion)
  - [Authentication & Access Control](#authentication--access-control)
  - [Analysis Pipeline](#analysis-pipeline)
  - [AD Lateral Movement Detection (LMD)](#ad-lateral-movement-detection-lmd)
  - [Behavioral Analytics](#behavioral-analytics)
  - [Attack Storyline](#attack-storyline)
  - [ML Anomaly Detection](#ml-anomaly-detection)
  - [Attack Classification](#attack-classification)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
  - [Model Quality Benchmark](#model-quality-benchmark)
  - [Threat Intelligence Enrichment](#threat-intelligence-enrichment)
  - [Case Management](#case-management)
  - [Reporting & Exports](#reporting--exports)
  - [Analyst Tools](#analyst-tools)
- [AD Attack Specialization](#ad-attack-specialization)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Sample Data](#sample-data)
- [Environment Variables](#environment-variables)

---

## Overview

FIP ingests forensic evidence files (Windows Security event logs, Sysmon telemetry, Plaso timelines, firewall flows, DNS logs, PCAP captures) and runs a multi-phase analysis pipeline — from instant deterministic scanning through LLM-generated narratives — outputting structured threat intelligence mapped to MITRE ATT&CK.

The platform is specialized for **Active Directory attack detection**, covering the full AD kill chain: initial access → credential theft → lateral movement → domain dominance. All three ML models (LMD Random Forest, Isolation Forest, Attack Classifier) have been validated against OTRF/Security-Datasets ground-truth events and MITRE ATT&CK KB v14.

The UI is a dark-themed single-page app organized around a fixed sidebar. Every button maps to a real backend endpoint.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Frontend  (React 18 + TypeScript + Vite + Tailwind CSS)      │
│                                                              │
│  Sidebar sections:                                           │
│    Data Ingestion · Timeline · Attack Graph · Analyst Chat   │
│  ─── ML Intelligence ────────────────────────────────────── │
│    AI Analysis · Attack Storyline · LMD Analysis            │
│    Model Quality · Model Settings                           │
│  ─── Management ─────────────────────────────────────────── │
│    Case Dashboard                                           │
└─────────────────────────┬────────────────────────────────────┘
                          │ REST (JSON)  /api/*
┌─────────────────────────▼────────────────────────────────────┐
│  Backend  (FastAPI + SQLAlchemy + SQLite)                     │
│                                                              │
│  Ingest → Parse → Normalize → Store (events table)          │
│                                                              │
│  Quick Scan  (/api/quick-scan)                               │
│    MITRE mapping · IOC extraction · Severity · IF scores     │
│    Attack classification                                     │
│                                                              │
│  AI Analysis  (/api/analyze)                                 │
│    Narrative · Patient Zero · Pivot chain · Baseline diff    │
│                                                              │
│  LMD Analysis  (/api/lmd-analysis)        ← AD-specialized  │
│    RF 6-class classifier · Attack graph · Feature report     │
│                                                              │
│  Behavioral  (/api/ml/behavioral)                            │
│    Z-score spike · Lateral velocity · Auth burst             │
│                                                              │
│  Attack Storyline  (/api/ml/storyline)                       │
│    ATT&CK steps · Lateral paths · Blast radius               │
│                                                              │
│  Model Benchmark  (/api/benchmark)                           │
│    OTRF/MITRE ground-truth evaluation · Grade + gaps         │
└──────────────────────────────────────────────────────────────┘
```

---

## Feature Breakdown

### Evidence Ingestion

| Format | Description |
|--------|-------------|
| **Plaso L2T CSV** | Timelines exported from `log2timeline.py` |
| **Timesketch JSONL** | Native Timesketch export / custom JSONL with `datetime`, `hostname`, `username`, `message`, `event_id` |
| **Generic CSV** | Any CSV with timestamp, host, user, event-type columns |
| **PCAP / PCAPng** | Full packet captures parsed into protocol-labeled flow events |

- **File integrity**: SHA-256 hash on every upload — warns if re-uploaded with a different hash (chain-of-custody)
- **Upload limit**: 100 MB per file
- **Multi-source merging**: multiple files in one Case are merged into a unified timeline with per-source color coding
- **Noise filtering**: high-volume background events (4634/4647 logoff, 4776 NTLM, 4672 special privileges) suppressed unless a suspicious keyword is also present
- **Hostname normalization**: strips domain suffixes (`.corp.local`, `.internal`, `.lan`), uppercases, resolves priority field order across log schemas

---

### Authentication & Access Control

- **JWT sessions** with 4-hour sliding expiry
- **Role-based access**: `admin` vs `analyst` — admin gates ML training, synthetic baseline generation, and ground-truth verification
- **TOTP MFA** (RFC 6238) compatible with Google Authenticator, Authy, and any standard TOTP app
  - Enroll via QR code at **Settings → MFA Setup**
  - MFA enforced on all privileged endpoints once enrolled
- **Bcrypt** password hashing

---

### Analysis Pipeline

#### Quick Scan (instant — no LLM)

Runs deterministically in milliseconds. Suitable for triage.

- **MITRE ATT&CK mapping** — 40+ technique signatures (see [MITRE ATT&CK Mapping](#mitre-attck-mapping))
- **IOC extraction** — IPv4/IPv6, domains, MD5/SHA-1/SHA-256, suspicious filenames
- **Severity scoring** — 0–100 composite: CRITICAL ≥ 80, HIGH ≥ 60, MEDIUM ≥ 35, LOW < 35
- **ML anomaly scores** — Isolation Forest per-user behavioral scoring (if trained)
- **Attack classification** — 10-category RF classifier

#### Deep AI Analysis (LLM-powered)

Full LLM pass over event windows. Requires a configured LLM provider (local Ollama or API key).

- **Investigation narrative** — prose incident summary with inline event citations (clickable `[event_id]` badges)
- **Patient Zero candidate** — first-compromised host/user
- **Initial access vector** — how the attacker got in
- **Pivot chain** — ordered lateral movement steps
- **Anomalous event list** — most significant deviations, human-readable
- **Baseline comparison** — statistical diff against stored clean-state baseline

> **Note**: LMD AD attack detection results are intentionally separate from AI Analysis. Run **LMD Analysis** from the sidebar for AD-specific detections and attack graph.

---

### AD Lateral Movement Detection (LMD)

Dedicated section in the sidebar — completely separate from AI Analysis.

**Model**: AD-specialized Random Forest classifier  
**Classes**: 6 attack categories + Normal  
**Benchmark**: F1 = 98%, Grade A (validated against OTRF/Security-Datasets)

| Class | Attack Type | Key Indicators |
|-------|-------------|----------------|
| 0 | Normal | Baseline Windows AD activity |
| 1 | Kerberoasting / AS-REP Roasting | EID 4769 RC4-HMAC, Rubeus, GetUserSPNs, UF_DONT_REQUIRE_PREAUTH |
| 2 | DCSync / Credential Theft | EID 4662 + 1131f6aa, lsadump::dcsync, secretsdump, procdump LSASS |
| 3 | Golden / Silver Ticket | kerberos::golden, lsadump::golden, krbtgt hash, Rubeus ptt |
| 4 | Lateral Movement | PsExec/PSEXESVC, wmic /node:, mstsc, logon type 3/9/10, sekurlsa::pth |
| 5 | AD Reconnaissance | SharpHound, BloodHound, ldapdomaindump, nltest, net group /domain |

**Features (18)**:
```
EventID  DestinationPort
Has_Kerberoast  Has_ASREPRoast  Has_PTH  Has_DCSync
Has_GoldenTicket  Has_SilverTicket  Has_PassTicket  Has_BloodHound
Has_LSASS  Has_WMI_Lateral  Has_SMB_Lateral  Has_RDP  Has_NTLMRelay
Has_DomainEnum  EID_4769  EID_4662
```

**Output**:
- Per-event detection list with attack class, severity, source/dest IP, matched indicators
- Color-coded attack breakdown chart
- Interactive Cytoscape attack graph — attacker → victim edges per technique
- Filter by attack class

---

### Behavioral Analytics

Four fully deterministic checks — no training data required, O(n) runtime:

| Check | Trigger |
|-------|---------|
| **Hourly event spike** | Per-user event count Z-score > 2.5 (requires ≥ 3 distinct hours) |
| **Lateral velocity** | User accesses > 3 distinct hosts within any 30-minute window |
| **Auth failure burst** | > 10 EID 4625 failures per user within 5 minutes |
| **Off-hours privilege** | EID 4672 (SeDebugPrivilege) outside 07:00–19:00 |

Each anomaly includes: `anomaly_type`, `entity`, `z_score`, `threshold`, `observed`, `severity`.

---

### Attack Storyline

Correlates events across all sources to reconstruct the attack as structured data — no LLM:

- **ATT&CK-mapped attack steps** — `(timestamp, host, user, tactic, technique_id, confidence)`
- **Lateral movement paths** — `from_host → to_host` with method (SMB/WMI/RDP/WinRM/PTH/PTT) and technique ID
- **Blast radius** — compromised hosts/users, accessed resources, persistence mechanisms, estimated data at risk
- **Threat actor profile** — heuristic characterization based on observed TTP combination
- **Entry vector** — detected initial access method
- **Tactic progression** — ordered ATT&CK kill-chain phases

**AD attack chains fully modeled**:
- Full Kerberoast → DCSync → Golden Ticket chain
- AS-REP Roasting → lateral movement
- NTLM relay + credential lateral across 3+ hosts
- BloodHound recon → targeted Kerberoasting
- Skeleton Key persistence
- Golden/Silver Ticket with PTT

**Supported event IDs in storyline engine**:
`4624 · 4625 · 4648 · 4662 · 4663 · 4672 · 4688 · 4698 · 4720 · 4726 · 4728 · 4732 · 4739 · 4756 · 4768 · 4769 · 4771 · 4776 · 5140 · 7045`

---

### ML Anomaly Detection (Isolation Forest)

- **Algorithm**: scikit-learn Isolation Forest (unsupervised)
- **Feature vector (15 features)**:

| Feature | Description |
|---------|-------------|
| event_rate | Events per minute |
| unique_hosts | Distinct host count |
| admin_tool_count | Known admin/attack tool invocations |
| off_hours_ratio | Fraction of events outside business hours |
| failed_logon_ratio | EID 4625 failures / total events |
| lateral_host_count | Distinct hosts accessed in 30-min windows |
| process_injection_count | Suspicious process-access patterns |
| encoded_cmd_count | Base64 / -enc PowerShell invocations |
| network_event_ratio | Network events / total events |
| privilege_event_count | EID 4672 (SeDebugPrivilege) events |
| **kerberos_ticket_rate** | Kerberos tickets / total — detects Kerberoasting burst |
| **lateral_logon_ratio** | Type 3/9/10 logons / total — detects PTH/lateral |
| **domain_recon_count** | nltest / net group / dsquery invocations |
| **priv_escalation_count** | Privilege escalation tool indicators |
| **ad_attack_tool_count** | Rubeus, BloodHound, impacket, CrackMapExec, etc. |

- **Per-entity output**: anomaly score (0–1), risk level, top contributing factors
- **Analyst feedback loop**: TP/FP verification buttons → stored ground truth → precision/recall/F1/accuracy in ML Stats
- **Admin controls**: Seed + Train (synthetic baseline) · Retrain (existing DB events)
- **Minimum**: ≥ 10 users with ≥ 5 events each

---

### Attack Classification

10-category supervised Random Forest:

| Category | Key Signals |
|----------|-------------|
| **Ransomware** | VSS deletion, bcdedit, shadow copy, encryption patterns |
| **Kerberoasting** | EID 4769, RC4 encryption, SPN enumeration |
| **Lateral Movement** | PsExec, WMI exec, admin shares, logon type 3, EID 4648 |
| **Credential Theft** | LSASS access, Mimikatz, DCSync (EID 4662), NTDS.dit |
| **Data Exfiltration** | Large transfers, archive staging, DNS tunneling |
| **C2 Communication** | Beaconing, encoded payloads, unusual outbound |
| **Persistence** | Scheduled tasks (4698), services (7045), registry run keys |
| **Privilege Escalation** | Token manipulation (4672), UAC bypass |
| **Defense Evasion** | LOLBins (certutil, mshta, regsvr32, wmic), log clearing |
| **Reconnaissance** | net user/group, LDAP queries, BloodHound |

Output: primary category · confidence score · all-category scores · MITRE technique IDs · top evidence keywords.

---

### MITRE ATT&CK Mapping

**Coverage: 100% of 25 benchmark technique pairs (Grade A)**

| Technique ID | Name | Tactic |
|---|---|---|
| T1105 | Ingress Tool Transfer | Command and Control |
| T1490 | Inhibit System Recovery | Impact |
| T1218.005 | Mshta | Defense Evasion |
| T1047 | Windows Management Instrumentation | Execution |
| T1059.001 | PowerShell (Encoded) | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1021.006 | Windows Remote Management | Lateral Movement |
| T1078 | Valid Accounts (type-3 logon) | Lateral Movement |
| T1048.003 | Exfiltration Over Unencrypted Protocol | Exfiltration |
| T1558.003 | Kerberoasting | Credential Access |
| T1558.004 | AS-REP Roasting | Credential Access |
| T1003.006 | DCSync | Credential Access |
| T1558.001 | Golden Ticket | Credential Access |
| T1558.002 | Silver Ticket | Credential Access |
| T1550.002 | Pass the Hash | Lateral Movement |
| T1550.003 | Pass the Ticket | Lateral Movement |
| T1207 | Rogue Domain Controller (Skeleton Key) | Defense Evasion |
| T1069.002 | Domain Groups Discovery (BloodHound/PowerView) | Discovery |
| T1087.002 | Domain Account Enumeration | Discovery |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access |
| T1082 | System Information Discovery | Discovery |
| T1053.005 | Scheduled Task | Persistence |
| T1547.001 | Registry Run Keys | Persistence |
| T1003.001 | LSASS Memory Dumping | Credential Access |
| T1136.001 | Local Account Creation | Persistence |
| T1543.003 | Windows Service | Persistence |
| T1098.007 | Additional Group Membership | Persistence |
| T1484.001 | Domain Policy Modification | Defense Evasion |

---

### Model Quality Benchmark

**Sidebar: ML Intelligence → Model Quality**

Evaluates all three detection models against an embedded ground-truth benchmark at any time.

**Benchmark sources**:
- **OTRF/Security-Datasets** (github.com/OTRF/Security-Datasets) — real Windows telemetry from controlled AD lab environments. Sub-datasets used: shire_empire_kerberoast, shire_empire_dcsync, shire_empire_sharphound, shire_empire_golden_ticket, shire_empire_procdump, shire_empire_pth, shire_empire_psexec, shire_empire_wmiexec, shire_empire_net_domain.
- **MITRE ATT&CK KB v14** (attack.mitre.org) — 25 technique description test pairs.

**Current benchmark results**:

| Model | Metric | Score | Grade |
|-------|--------|-------|-------|
| LMD Random Forest | F1 (macro, attack classes) | 98% | **A** |
| LMD Random Forest | Accuracy | 97% | **A** |
| MITRE ATT&CK Mapper | Technique coverage | 100% | **A** |
| Isolation Forest | AUC-ROC | requires trained model | — |

The benchmark panel shows: per-model metric bars, confusion matrix, per-class precision/recall/F1, per-dataset accuracy, identified gaps, and full dataset citations.

---

### Threat Intelligence Enrichment

- **VirusTotal** — file hash and IP reputation lookups
- **AbuseIPDB** — IP abuse confidence score
- Applied to extracted IOCs during Deep AI Analysis
- Cached in-process (max 4 external lookups per analysis) — no impact when API keys absent

---

### Case Management

- **Cases** track an investigation across multiple uploads, analyses, and notes
- **Lifecycle**: `active` → `closed` → `archived`
- **Analyst notes**: create/update/delete, pinnable, full-text searchable
- **Multi-source merging**: uploads in the same Case produce a unified timeline with per-source color coding
- **Status filters**: All / Active / Closed / Archived with event counts

---

### Reporting & Exports

| Report | Format | Contents |
|--------|--------|----------|
| **Quick Scan Snapshot** | Self-contained HTML | MITRE, IOCs, severity, ML scores |
| **Deep AI Intelligence Report** | Self-contained HTML | Full narrative, patient zero, pivot chain, all findings |
| **Court-Ready Forensic Report** | Print-ready HTML | Chain-of-custody, SHA-256 hashes, attestation section |
| **Case Forensic Report** | Self-contained HTML | All uploads, analyses, and notes for the case |
| **IOC Export — CSV** | CSV | Extracted indicators |
| **IOC Export — STIX 2.1** | JSON | Machine-readable threat intel bundle |

---

### Analyst Tools

#### Timeline
- Chronological event table with color-coded rows: amber (suspicious keyword), blue (logon/Kerberos), purple (network/PCAP)
- Multi-source legend with per-file color coding

#### Attack Graph
- Interactive Cytoscape.js graph — hosts and users as nodes, observed connections as edges
- Suspicious node/edge highlighting; per-upload source filtering

#### LMD Attack Graph
- Separate graph in the LMD Analysis section — shows attacker → victim edges per detected AD technique
- Colored by attack class (Kerberoasting, DCSync, Lateral Movement, etc.)

#### Filter Bar
- Host / User / Event Type dropdowns; AND composition; persists until cleared

#### Global Search
- Full-text across all events and analyst notes
- **Ctrl+K** / **Cmd+K** shortcut · 300 ms debounce · match highlighting

#### Analyst Chat
- LLM Q&A against the loaded timeline
- Conversation history per session; suggested starter questions

---

## AD Attack Specialization

FIP is built around the Windows Active Directory attack kill chain. All detection layers are tuned for it.

### Full kill chain coverage

| Stage | Attack | Detection Layer |
|-------|--------|----------------|
| Initial Access | Phishing / HTA delivery | MITRE T1566/T1218.005, Email gateway log parsing |
| Execution | Encoded PowerShell stager | MITRE T1059.001, Attack Classifier |
| Persistence | Registry Run key, scheduled task | MITRE T1547.001/T1053.005 |
| Reconnaissance | BloodHound / SharpHound LDAP burst | LMD class 5, IF kerberos_ticket_rate |
| Credential Access | Kerberoasting (EID 4769 RC4) | LMD class 1, MITRE T1558.003 |
| Credential Access | AS-REP Roasting | LMD class 1, MITRE T1558.004 |
| Credential Access | LSASS dump (procdump/comsvcs) | LMD class 2, MITRE T1003.001 |
| Credential Access | DCSync (EID 4662 replication GUIDs) | LMD class 2, MITRE T1003.006 |
| Lateral Movement | PsExec / SMB admin shares | LMD class 4, MITRE T1021.002 |
| Lateral Movement | WMI remote execution | LMD class 4, MITRE T1047 |
| Lateral Movement | Pass-the-Hash (logon type 9) | LMD class 4, MITRE T1550.002 |
| Lateral Movement | Pass-the-Ticket / Golden Ticket | LMD class 3/4, MITRE T1550.003/T1558.001 |
| Privilege Escalation | Golden/Silver Ticket | LMD class 3, MITRE T1558.001/T1558.002 |
| Persistence | Backdoor account (EID 4720/4728) | MITRE T1136.001/T1098.007, Storyline |
| Defense Evasion | Log clearing (EID 1102) | Storyline engine |
| Defense Evasion | Skeleton Key (lsass patch) | MITRE T1207 |

### Windows Security Event IDs with first-class support

| Event ID | Meaning | Detection |
|----------|---------|-----------|
| 4624 / 4625 | Logon success / failure | Brute force, lateral movement, PTH |
| 4648 | Explicit-credential logon | Pass-the-Hash |
| 4662 | AD object access | DCSync (1131f6aa GUID), BloodHound LDAP |
| 4668 / 4672 | Special privileges | SeDebugPrivilege, off-hours escalation |
| 4688 | Process creation | LOLBin, Rubeus, SharpHound, procdump |
| 4698 / 4699 | Scheduled task create/delete | Persistence |
| 4720 / 4726 | Account created/deleted | Backdoor account |
| 4728 / 4732 / 4756 | Security group member added | DA group persistence |
| 4739 | Domain policy changed | Domain policy modification |
| 4768 / 4769 / 4771 | Kerberos TGT/TGS/failure | Kerberoasting, AS-REP, Golden Ticket |
| 4776 | NTLM auth | Pass-the-Hash pivot |
| 5140 | Network share access | PsExec ADMIN$ staging |
| 7045 | New service installed | PsExec service, persistence |

---

## Tech Stack

### Backend

| Component | Library / Version |
|-----------|-------------------|
| API framework | FastAPI |
| ORM / database | SQLAlchemy + SQLite |
| Auth | python-jose (JWT) · pyotp (TOTP) · passlib (bcrypt) |
| ML models | scikit-learn (Isolation Forest, Random Forest) · joblib |
| Graph generation | pyvis |
| PCAP parsing | Scapy |
| Threat intel | requests → VirusTotal API, AbuseIPDB API |
| LLM | Configurable via `.env` (local Ollama) |

### Frontend

| Component | Library |
|-----------|---------|
| Framework | React 18 + TypeScript |
| Build tool | Vite |
| Styling | Tailwind CSS v3 |
| Graph (attack graph) | Cytoscape.js |
| Graph (LMD) | pyvis HTML + React iframe |
| HTTP client | Fetch API (typed client in `src/api/client.ts`) |

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
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set JWT_SECRET_KEY and ADMIN_PASSWORD at minimum
uvicorn backend.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Vite dev server: http://localhost:5173
```

### Default Credentials

- **Username**: `admin`
- **Password**: value of `ADMIN_PASSWORD` in `.env`

MFA is optional until an admin completes TOTP setup at **Settings → MFA Setup**.

---

## Sample Data

`sample_data/` contains categorized demo scenarios:

| Folder | Contents |
|--------|----------|
| `01_AD_Full_Attack_Chain/` | **Complete multi-source AD attack scenario** — 7 complementary log files (DC Security log, Sysmon telemetry, firewall flows, DNS queries, email gateway) covering a full phishing → BloodHound → Kerberoasting → DCSync → Golden Ticket chain. Import all 7 as a single Case to see cross-source correlation. |
| `02_APT_Cobalt_Strike/` | C2 beaconing and Cobalt Strike staging |
| `03_Ransomware/` | Ransomware kill chain with VSS deletion |
| `04_Insider_Threat/` | Data exfiltration by privileged insider |
| `05_Linux_Web_Attack/` | Web shell and Linux post-exploitation |
| `06_Windows_Techniques/` | LOLBAS, privilege escalation, WMI persistence |
| `07_Quick_Test/` | Small files for quick upload testing |
| `_lfs_unavailable/` | Large binary stubs (PCAP, CSV) — replace with real files |

See `sample_data/01_AD_Full_Attack_Chain/README.md` for the full attack timeline and cross-source correlation guide.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET_KEY` | Yes | Secret for JWT signing — use a long random string in production |
| `ADMIN_PASSWORD` | Yes | Initial admin account password |
| `LLM_PROVIDER` | No | `ollama` (default) |
| `OLLAMA_MODEL` | No | Ollama model name (default: `llama3`) |
| `VIRUSTOTAL_API_KEY` | No | Enables VirusTotal IOC enrichment |
| `ABUSEIPDB_API_KEY` | No | Enables AbuseIPDB IP reputation lookups |

---

## License

Internal research platform. All rights reserved.

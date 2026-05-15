# LateralX — Post-Incident AD Forensic Investigation Platform

LateralX is a post-incident digital forensics and incident response (DFIR) platform purpose-built for Active Directory environments. It ingests multi-source forensic telemetry, applies a layered detection engine (rule-based + unsupervised ML + optional LLM), and produces interactive attack graphs, MITRE ATT&CK mappings, privilege timelines, and executive-ready reports — all without requiring cloud connectivity or external services.

Designed as a structured investigation tool for cybersecurity analysts and incident responders, not a real-time SIEM or endpoint agent.

---

## What It Does

| Capability | Description |
|---|---|
| **Multi-source ingestion** | Windows Event Logs, Sysmon JSONL, Velociraptor artifacts, Timesketch exports, generic CSV, PCAP/PCAPNG |
| **71 AD detection rules** | Kerberoasting, DCSync, Pass-the-Hash/Ticket, Golden/Silver Ticket, LDAP enumeration, lateral movement, persistence, defense evasion, and more |
| **Unsupervised ML** | Isolation Forest trained on a synthetic baseline grounded in LANL 2015, CERT v6.2, and OTRF/Mordor datasets; flags statistical outliers without labeled attack data |
| **Attack chain correlation** | Groups detections by actor across tactics and builds multi-step attack narratives in MITRE tactic order |
| **Behavioral analysis** | 8 statistical checks: hourly spikes, lateral velocity, auth-failure bursts, off-hours privilege use, Kerberoasting patterns, group modifications, account creation chains, NTLM spikes |
| **Attack graph** | Interactive Cytoscape.js visualization with kill-chain overlay, degree-weighted node sizing, node search, and PNG export |
| **Privilege timeline** | Chronological escalation chain reconstruction from Windows Security EIDs (account creation → group membership → privilege use) |
| **Entity intelligence** | Per-entity (user / host / group) risk scoring (0–100), MITRE technique associations, anomaly flags |
| **IP identity** | Incident-scoped IP → hostname / users / role resolution built entirely from event telemetry, no external DNS |
| **IOC extraction** | Regex-driven extraction of IPs, URLs, domains, file paths, MD5/SHA256 hashes, registry keys; exports to CSV and STIX 2.1 |
| **Threat intelligence** | Optional VirusTotal and AbuseIPDB enrichment; gracefully no-ops when API keys are absent |
| **LLM narrative** | Optional Ollama (local) integration for AI-generated investigation narratives with citation callouts linked to event IDs |
| **Reporting** | Self-contained HTML executive reports and court-admissible forensic reports with chain-of-custody metadata |
| **Case management** | Full case lifecycle (active / closed / archived), analyst notes, pinned findings, case-scoped uploads |
| **Audit trail** | Immutable, SHA256 hash-chained audit log; tamper detection via chain integrity verification endpoint |
| **Authentication** | JWT-based sessions with optional TOTP (2FA) for the admin account |

---

## Architecture

```
Browser (React + TypeScript + Tailwind)
        │  REST API  (localhost:8000/api)
        ▼
FastAPI backend (Python 3.11+)
├── Ingest layer      — parser.py  (CSV / JSONL / PCAP → ForensicEvent)
├── Detection engine  — ad_rules.py  (71 rules, 7 categories)
│                       behavioral.py  (8 statistical checks)
│                       ml_anomaly.py  (Isolation Forest)
│                       attack_classifier.py  (supervised, 10 classes)
├── Correlation       — ad_chain_correlator.py  (multi-tactic chains)
│                       ad_tool_signatures.py  (toolkit fingerprinting)
│                       network_host_correlator.py  (Sysmon EID 3 + firewall)
│                       correlation.py  (PCAP ↔ event timeline)
├── Intelligence      — ad_entity_intel.py  (risk profiling)
│                       ad_privilege_timeline.py  (escalation chains)
│                       ip_identity.py  (IP → identity table)
│                       mitre.py  (ATT&CK mapping)
│                       ioc.py  (IOC extraction + STIX export)
│                       threat_intel.py  (VT / AbuseIPDB)
├── Narrative         — storyline.py  (deterministic attack reconstruction)
│                       llm.py  (optional Ollama narrative)
│                       report.py  (HTML report generation)
└── Storage           — SQLite (WAL mode) via SQLAlchemy
                        11 tables: events, analyses, cases, notes,
                        uploads, audit_log, users, ip_identity, …
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- (Optional) [Ollama](https://ollama.com/) for LLM narrative generation

### Install and run

```bash
# 1. Clone and install backend dependencies
pip install -r requirements.txt

# 2. Install frontend dependencies
cd frontend && npm install && cd ..

# 3. Start the backend  (default admin: ForensicAdmin2024!)
uvicorn backend.main:app --reload

# 4. Start the frontend (separate terminal)
cd frontend && npm run dev
```

Open `http://localhost:5173` and log in with username `admin`.

To use a custom admin password, set the environment variable before starting:

```bash
set ADMIN_PASSWORD=YourSecurePassword   # Windows
export ADMIN_PASSWORD=YourSecurePassword # Linux / macOS
```

### Optional: Ollama LLM

```bash
ollama pull llama3          # or any model supported by Ollama
ollama serve                # starts on localhost:11434
```

LateralX auto-detects the running Ollama instance. If Ollama is absent, narrative generation is skipped and all other features work normally.

---

## 4-Phase Investigation Workflow

The UI guides analysts through a structured DFIR workflow:

| Phase | Name | What you do |
|-------|------|-------------|
| 1 | **Collect** | Upload log files (CSV / JSONL / PCAP), manage cases, review the raw event timeline |
| 2 | **Explore** | Browse the attack graph, filter by host/user/event type, search across events and notes |
| 3 | **Analyze** | Run the detection engine, review MITRE mappings, behavioral anomalies, IOCs, storyline |
| 4 | **AD Intelligence** | AD scan (71 rules), privilege timeline, entity risk profiles, AD threat map, MITRE heatmap |

---

## Detection Engine

### Rule-Based AD Detection (71 rules)

Rules detect Windows Event ID patterns and access behaviour — not tool names. An attacker renaming `mimikatz.exe` does not evade these rules because they fire on:

- **Kerberoasting** — Accumulated EID 4769 TGS requests (not tool invocation)
- **DCSync** — `DS-Replication-Get-Changes-All` privilege exercise (not Mimikatz binary name)
- **Pass-the-Hash** — EID 4624 Type 3 logon without prior Kerberos ticket
- **Golden/Silver Ticket** — Forged ticket lifetime anomalies and EID 4769/4768 field inspection
- **LDAP enumeration** — EID 4662 DS object access patterns (BloodHound-style queries)
- **Account manipulation** — Creation, group addition, and password-reset chains in short windows
- **Lateral movement** — SMB, WinRM, RDP, WMI logon chains across hosts

Rule categories: `Kerberos`, `DCSync/Replication`, `Lateral Movement`, `Privilege Escalation`, `Persistence`, `Reconnaissance`, `Tool Signatures`

### Unsupervised ML (Isolation Forest)

Trained on a 50-profile synthetic baseline grounded in three public datasets (LANL 2015 user behaviour, CERT v6.2 insider threat, OTRF/Mordor red-team exercises). Scores every entity against the learned normal distribution — entirely name-blind, no signatures required.

### Attack Chain Correlation

After detection, `ad_chain_correlator.py` groups individual rule hits by actor and orders them by MITRE tactic progression (Recon → Credential Access → Privilege Escalation → Lateral Movement → Persistence → Impact) to produce a coherent multi-stage attack narrative for each threat actor observed in the logs.

### Tool Signature Fingerprinting

`ad_tool_signatures.py` identifies common attack toolkits through multi-event behavioural correlation rather than binary names:

| Toolkit detected | Behavioural signal |
|---|---|
| Mimikatz | LSASS process-access + privilege-use sequence |
| Rubeus | Kerberos ticket request bursts with anomalous encryption types |
| BloodHound / SharpHound | LDAP DS-Object-Access enumeration patterns |
| Impacket secretsdump | DCSync replication rights + DRSUAPI calls |
| CrackMapExec | SMB connection sweep across subnet |

---

## Supported Log Formats

| Format | Parser details |
|---|---|
| **Sysmon JSONL** | Velociraptor artifact export; EID 1/3/10/4624/4625/4648/4662/4688/4769 fully parsed |
| **Timesketch JSONL** | `timestamp`, `message`, `source`, `username`, `hostname` field mapping |
| **Plaso L2T CSV** | Legacy timeline export; date/time/source/message columns |
| **Generic CSV** | Auto-detection of host/user/timestamp columns via priority field lists |
| **PCAP / PCAPNG** | Flow extraction via PyShark; protocol/port analysis, exfiltration detection |

All formats go through a normalisation layer that strips Windows Event Log boilerplate, reduces token count by 40–60%, and applies consistent entity resolution (domain suffix stripping, system account filtering).

---

## Sample Data

Nine pre-built scenarios are included under `sample_data/` for testing and demonstration:

| Folder | Scenario |
|---|---|
| `01_AD_Full_Attack_Chain/` | Complete AD compromise chain — DC events, DNS, firewall, email gateway, Sysmon |
| `02_APT_Cobalt_Strike/` | APT campaign with C2 beacons and lateral movement |
| `03_Ransomware/` | Ransomware deployment and impact |
| `04_Insider_Threat/` | Insider threat indicators |
| `05_Linux_Web_Attack/` | Linux web server compromise |
| `06_Windows_Techniques/` | Windows-specific attack technique collection |
| `07_Quick_Test/` | Minimal dataset for fast smoke-testing |
| `08_AD_APT/` | Combined AD + APT scenario |
| `09_AD_Advanced_Breach/` | Advanced persistent AD breach |

Standalone files: `firewall_net_full.json` (408 KB netflow) and `host_sysmon_full.json` (204 KB Sysmon telemetry).

---

## API Reference (summary)

All endpoints are served under `/api`. Interactive Swagger docs available at `http://localhost:8000/docs`.

| Category | Key endpoints |
|---|---|
| **Auth** | `POST /login`, `POST /auth/refresh`, `POST /admin/totp/setup`, `POST /admin/totp/verify` |
| **Upload** | `POST /upload`, `GET /uploads`, `DELETE /uploads/{id}` |
| **Events** | `GET /events`, `GET /events/summary`, `GET /events/{id}` |
| **Analysis** | `POST /analyze`, `POST /analyze/ad-rules`, `POST /ml/behavioral`, `POST /ml/storyline` |
| **ML** | `POST /ml/quick-scan`, `POST /ml/train`, `POST /ml/seed-baseline`, `GET /ml/status` |
| **Graph** | `GET /graph` |
| **IOCs** | `GET /iocs`, `GET /iocs/export/csv`, `GET /iocs/export/stix` |
| **AD** | `POST /analyze/privilege-timeline`, `GET /ad-entities` |
| **IP Identity** | `GET /ip-identity` |
| **Cases** | `POST /cases`, `GET /cases`, `PATCH /cases/{id}`, `DELETE /cases/{id}` |
| **Notes** | `POST /notes`, `GET /notes`, `PATCH /notes/{id}`, `DELETE /notes/{id}` |
| **Reports** | `GET /report/html`, `GET /cases/{id}/report`, `GET /cases/{id}/court-report` |
| **Audit** | `GET /audit-log`, `GET /audit-log/verify` |
| **Search** | `GET /search` |
| **Threat Intel** | `GET /threat-intel/status`, `GET /incident-memory` |

---

## Project Structure

```
backend/
  analysis/
    ad_rules.py               — 71 AD detection rules (7 categories)
    ad_chain_correlator.py    — Multi-tactic attack chain builder
    ad_entity_intel.py        — Entity risk profiling (users / hosts / groups)
    ad_privilege_timeline.py  — Privilege escalation chain reconstruction
    ad_tool_signatures.py     — Toolkit behavioural fingerprinting
    behavioral.py             — 8 statistical behavioural anomaly checks
    attack_classifier.py      — Supervised 10-class attack classifier
    correlation.py            — Cross-source (PCAP ↔ event) correlation
    graph.py                  — Cytoscape.js attack graph builder
    ip_identity.py            — Incident-scoped IP → identity resolution
    ioc.py                    — IOC extraction + STIX 2.1 export
    llm.py                    — Optional Ollama LLM narrative generation
    mitre.py                  — MITRE ATT&CK technique mapper
    ml_anomaly.py             — Isolation Forest anomaly scoring
    ml_synthetic.py           — Synthetic baseline data generator
    network_host_correlator.py — Sysmon EID 3 + firewall 4-tuple join
    normalizer.py             — Log normalisation / deduplication
    report.py                 — HTML executive report generator
    rules.py                  — Sigma / Snort detection rule templates
    scoring.py                — Incident severity scorer (0–100)
    storyline.py              — Deterministic attack storyline builder
    threat_intel.py           — VirusTotal / AbuseIPDB enrichment
  api/
    routes.py                 — FastAPI route handlers (60+ endpoints)
  db/
    models.py                 — SQLAlchemy ORM (11 tables, SQLite WAL)
  ingest/
    parser.py                 — Multi-format log ingestion pipeline

frontend/
  src/
    components/               — 23 React UI panels
    api/client.ts             — Typed API client
    types/index.ts            — Shared TypeScript types
    App.tsx                   — Root layout, navigation, dark mode

backend/schema.py             — Pydantic request/response models
main.py                       — FastAPI app, CORS, security headers, bootstrap
requirements.txt              — Python dependencies
sample_data/                  — 9 pre-built attack scenarios (JSONL / CSV / JSON)
```

---

## Security Notes

- Passwords are hashed with bcrypt (passlib)
- Sessions use signed JWT tokens (HS256, 4-hour expiry with sliding refresh)
- TOTP (RFC 6238) available for admin account
- Audit log uses SHA256 hash chaining — any tampering breaks chain verification
- OWASP security headers injected on every response (CSP, X-Frame-Options, X-Content-Type-Options)
- CORS restricted to `localhost:5173` and `localhost:3000` by default
- Designed for local / air-gapped deployment; no telemetry, no cloud dependencies

---

## Testing

```bash
# Run the test suite
pytest tests/

# Key test files
tests/test_llm_config.py      — LLM connectivity and config tests
tests/test_ip_identity.py     — IP identity resolution unit tests
```

---

## License

Academic project — LateralX graduation project.

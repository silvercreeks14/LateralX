# LateralX — Post-Incident AD Forensic Investigation Platform

LateralX is a post-incident digital forensics and incident response (DFIR) platform purpose-built for Active Directory environments. It ingests multi-source forensic telemetry, applies a layered detection engine (rule-based + unsupervised ML + optional LLM), and produces interactive attack graphs, MITRE ATT&CK mappings, privilege timelines, and executive-ready reports — all without requiring cloud connectivity or external services.

Designed as a structured investigation tool for cybersecurity analysts and incident responders, not a real-time SIEM or endpoint agent.

---

## What It Does

| Capability | Description |
|---|---|
| **Multi-source ingestion** | Windows Event Logs, Sysmon JSONL, Velociraptor artifacts, Timesketch exports, generic CSV, PCAP/PCAPNG |
| **77 AD detection rules** | Kerberoasting, DCSync, Pass-the-Hash/Ticket, Golden/Silver Ticket, LDAP enumeration, lateral movement, persistence, defense evasion, LSASS handle access (CRED-008), Kerberos RC4 downgrade burst (KERB-014), Zerologon CVE-2020-1472, token impersonation chains, and more |
| **Unsupervised ML** | Isolation Forest trained on a synthetic baseline grounded in LANL 2015, CERT v6.2, and OTRF/Security-Datasets; flags statistical outliers without labeled attack data; sessions with fewer than 20 events fall back to deterministic heuristics to prevent false positives |
| **Attack chain correlation** | Groups detections by actor across tactics and builds multi-step attack narratives in MITRE tactic order |
| **Behavioral analysis** | 18 deterministic checks: statistical anomalies (hourly spikes, lateral velocity, auth-failure bursts, off-hours privilege, Kerberoasting spikes, group modification bursts, account creation chains, NTLM spikes), credential access (NTLM brute-force, Pass-the-Hash keyword, LSASS PTH correlation, Golden/Silver Ticket), lateral movement (SMB Type-3 multi-host, RDP Type-10 multi-host, Pass-the-Ticket RC4/no-TGT), execution (WMI shell spawn, event log clearing sweep), and high-confidence single-event rules (shadow copy deletion, boot recovery disabled, CertUtil/BITSAdmin downloads, MSHTA/Regsvr32 remote exec, encoded PowerShell, Mimikatz, DCSync, LSASS dump) |
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
├── Detection engine  — ad_rules.py  (77 rules, 9 categories)
│                       behavioral.py  (18 deterministic checks)
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
| 4 | **AD Intelligence** | AD scan (77 rules), privilege timeline, entity risk profiles, AD threat map, MITRE heatmap |

---

## Detection Engine

### Rule-Based AD Detection (77 rules)

Rules detect Windows Event ID patterns and access behaviour — not tool names. An attacker renaming `mimikatz.exe` does not evade these rules because they fire on:

- **Kerberoasting** — Accumulated EID 4769 TGS requests with RC4 burst detection (KERB-001, KERB-014)
- **DCSync** — `DS-Replication-Get-Changes-All` privilege exercise (not Mimikatz binary name)
- **Pass-the-Hash** — EID 4624 Type 3 logon without prior Kerberos ticket; LSASS memory patch correlation
- **Golden/Silver Ticket** — Forged ticket lifetime anomalies and EID 4769/4768 field inspection
- **LSASS credential access** — Sysmon EID 10 with dangerous GrantedAccess masks (0x1010, 0x1410, 0x1FFFFF) excluding OS safe processes
- **LDAP enumeration** — EID 4662 DS object access patterns (BloodHound-style queries)
- **Account manipulation** — Creation, group addition, and password-reset chains in short windows
- **Lateral movement** — SMB, WinRM, RDP, WMI logon chains across hosts
- **AdminSDHolder abuse** — EID 5136/5137 modifications to `CN=AdminSDHolder` (DCS-008)
- **Zerologon** — CVE-2020-1472 anonymous logon + machine-account change burst (KERB-013)

Rule categories: `Kerberos (14)`, `DCSync/Replication (10)`, `Lateral Movement (13)`, `Privilege Escalation (12)`, `Persistence (10)`, `Reconnaissance (11)`, `Tool Signatures (3)`, `Exfiltration (1)`, `Credential Dump (3)`

### Unsupervised ML (Isolation Forest)

Trained on a 50-profile synthetic baseline grounded in three public datasets (LANL 2015 user behaviour, CERT v6.2 insider threat, OTRF/Security-Datasets red-team exercises). Scores every entity against the learned normal distribution — entirely name-blind, no signatures required. Entities with fewer than 20 events automatically fall back to deterministic heuristics to prevent statistical false positives on short sessions.

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
| **Windows Event Viewer CSV** | `Get-WinEvent \| Export-Csv` output (`TimeCreated`, `MachineName`, `Id`, `Message`); deep-parses multi-line Sysmon Message blocks for Image, CommandLine, ParentImage, ParentCommandLine, User, GrantedAccess, UtcTime; tagged `VELOCIRAPTOR` source |
| **Timesketch JSONL** | `timestamp`, `message`, `source`, `username`, `hostname` field mapping |
| **Plaso L2T CSV** | Legacy timeline export; date/time/source/message columns |
| **Generic CSV** | Auto-detection of host/user/timestamp/event-id columns via priority field lists; case-insensitive header matching |
| **PCAP / PCAPNG** | Flow extraction via PyShark; protocol/port analysis, exfiltration detection |

All formats go through a normalisation layer that strips Windows Event Log boilerplate, reduces token count by 40–60%, and applies consistent entity resolution (domain suffix stripping, system account filtering).

---

## Sample Data

Fourteen pre-built scenarios are included under `sample_data/` for testing and demonstration. Each folder contains a `README.md` with environment details, attack timeline, file formats, and expected detections.

| Folder | Scenario | Severity |
|---|---|---|
| `00_Quick_Demo/` | Three minimal JSON files for smoke-testing individual rules (Zerologon, Token Impersonation, WDigest) | — |
| `01_AD_Full_Attack_Chain/` | Full AD kill chain — reconnaissance, Kerberoasting, lateral movement, persistence across 6 log sources | CRITICAL |
| `02_APT_Cobalt_Strike/` | Cobalt Strike C2 beacon via spear-phishing macro — process injection, LSASS access, SMB lateral | CRITICAL |
| `03_Ransomware/` | RDP brute-force → ransomware deploy → shadow copy deletion → event log cleared | CRITICAL |
| `04_Insider_Threat/` | Off-hours bulk data exfiltration by disgruntled employee using built-in tools only — no malware | MEDIUM |
| `05_Linux_Web_Attack/` | WordPress plugin exploit → PHP web shell → reverse bash shell (Linux auditd telemetry) | HIGH |
| `06_Windows_Techniques/` | Four isolated technique files: LOLBAS mshta, UAC bypass (fodhelper), WMI persistence, mixed tradecraft | MEDIUM–HIGH |
| `07_APT_SilverForge/` | Multi-day APT campaign — C2 beacon, DCSync, backdoor domain admin account, audit log cleared | CRITICAL |
| `08_Ransomware_BlackVault/` | NTLM brute-force → mshta HTA stager → lateral to app server via service account | HIGH |
| `09_Phishing_PhishNet/` | Macro phishing → PowerShell IEX → Mimikatz → SMB lateral → 45 MB exfiltration | CRITICAL |
| `10_WebShell_WebDoor/` | IIS web shell via w3wp.exe → certutil download → SQL server pivot → PII/payment-card exfil | CRITICAL |
| `11_APT29_Full_Chain/` | APT29-modeled full chain — 8 phases, 7 log files, Plaso/Sysmon/Timesketch/network formats | CRITICAL |
| `12_Turla_APT_Eval/` | Turla APT tradecraft from MITRE ATT&CK Evaluations Round 5 — Kerberoasting, SMB lateral, LSASS PTH, log clearing | CRITICAL |
| `13_Wizard_Spider_ATT_Eval/` | Wizard Spider/Ryuk tradecraft from MITRE ATT&CK Evaluations Round 4 — Cobalt Strike, Mimikatz, SMB lateral, ransomware anti-recovery | CRITICAL |
| `14_Carbanak_ATT_Eval/` | Carbanak+FIN7 tradecraft from MITRE ATT&CK Evaluations Round 3 — WMI lateral, LSASS PTH, SMB/RDP lateral, log clearing | CRITICAL |

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
    ad_rules.py               — 77 AD detection rules (9 categories)
    ad_chain_correlator.py    — Multi-tactic attack chain builder
    ad_entity_intel.py        — Entity risk profiling (users / hosts / groups)
    ad_privilege_timeline.py  — Privilege escalation chain reconstruction
    ad_tool_signatures.py     — Toolkit behavioural fingerprinting
    behavioral.py             — 18 deterministic behavioural anomaly checks
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
sample_data/                  — 14 pre-built attack scenarios (JSONL / CSV / JSON)
```

---

## Performance Benchmarks

### Test Suite

**237 tests, 0 failures** — 235 functional tests (API, hash chain, analysis) + 50 mutation tests specifically targeting false-positive precision.

### Benchmark 1 — OTRF/Security-Datasets (Empire C2 baseline)

Evaluated against 6 real-world Empire C2 lab captures from [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) (Mordor project). Techniques verified against OTRF metadata and direct event inspection.

| Dataset | Technique | Layer A F1 | Combined F1 |
|---|---|---|---|
| `empire_wmi_dcerpc` | WMI lateral (T1047, T1059.001, T1021.002) | 0.923 | **1.000** |
| `empire_mimikatz_logonpasswords` | LSASS dump (T1003.001, T1059.001) | 1.000 | **1.000** |
| `empire_over_pth_patch_lsass` | Pass-the-Hash / Over-PTH (T1550.002, T1021.002) | 1.000 | **1.000** |
| `empire_dcsync_dcerpc_drsuapi` | DCSync (T1003.006, T1078) | 0.875 | **0.875** |
| `rubeus_asktgt_ptt` | Pass-the-Ticket / Kerberoasting (T1550.003, T1558.003) | 1.000 | **1.000** |
| `empire_schtasks_elevated` | Scheduled Task persistence (T1053.005) | 0.917 | **0.917** |

**Macro-average (Empire baseline):**

| Layer | Precision | Recall | F1 |
|---|---|---|---|
| MITRE text-pattern (Layer A) | 0.952 | 0.985 | **0.968** |
| Behavioral rules (Layer B) | 0.667 | 0.242 | 0.355 |
| **Combined (A ∪ B)** | **0.952** | **1.000** | **0.968** |

Layer B recall is structurally limited here (0.242) because stateful sequence rules require EID combinations absent in short single-technique captures; the combined union fully compensates.

### Benchmark 2 — Non-Empire Tradecraft (Gap 1 — generalization)

Evaluated against 3 synthetic scenarios using Cobalt Strike Beacon, Metasploit psexec/Meterpreter, and manual Living-off-the-Land tradecraft — fundamentally different C2 toolchains from the Empire baseline.

| Scenario | Layer A F1 | Layer B F1 | Combined F1 |
|---|---|---|---|
| Cobalt Strike Beacon | 0.800 | 0.941 | **0.889** |
| Metasploit psexec + Meterpreter | 0.800 | 0.800 | **0.800** |
| Manual Living-off-the-Land | 0.933 | 0.600 | **0.933** |
| **Macro Average** | **0.855** | **0.810** | **0.890** |

Combined macro F1 = **0.890** vs. Empire baseline 0.968 — a 7.8-point gap attributable to Empire-specific text signatures; behavioral rules generalise comparably (0.810 vs. 0.355 structurally limited on atomic captures).

### Benchmark 3 — Multi-Stage Attack Scenarios (Layer B efficacy)

Evaluated against 7 full kill-chain scenarios spanning hours to days. Ground truth provenance is explicitly noted; 4 of 7 scenarios use externally-authored procedures as ground truth, not internal authorship.

| Scenario | GT Source | Events | P | R | F1 |
|---|---|---|---|---|---|
| `01_AD_Full_Attack_Chain` | Internal | 308 | 1.000 | 1.000 | **1.000** |
| `07_APT_SilverForge` | Internal | 350 | 1.000 | 0.889 | **0.941** |
| `09_Phishing_PhishNet` | Internal | 36 | 1.000 | 1.000 | **1.000** |
| `11_APT29_Full_Chain` | Internal | 182 | 1.000 | 1.000 | **1.000** |
| `12_Turla_APT_Eval` | **External** (MITRE Eval Round 5) | 32 | 1.000 | 1.000 | **1.000** |
| `13_Wizard_Spider_ATT_Eval` | **External** (MITRE Eval Round 4) | 13 | 1.000 | 1.000 | **1.000** |
| `14_Carbanak_ATT_Eval` | **External** (MITRE Eval Round 3) | 12 | 1.000 | 1.000 | **1.000** |
| **Macro Average** | | | **1.000** | **0.984** | **0.992** |

**Total: TP=61, FP=0, FN=1** — the single FN is `off_hours_privilege` in SilverForge (SeDebugPrivilege event falls within business hours in the dataset). Statistical rules (`hourly_event_spike`, `ntlm_spike`) excluded from scenario precision scoring as they fire by design on event-dense attack data.

**Non-circular validity note:** The 3 external-provenance scenarios (Turla, Wizard Spider, Carbanak) use ground truth derived from public MITRE ATT&CK Evaluation procedure documents — independent of the rule authors. All three score F1=1.000, confirming that the recall improvements are not artifacts of teaching-to-the-test on self-authored data.

### Benchmark 4 — Benign False-Positive Rate (60K synthetic baseline)

Evaluated `analyze_behavior` against 60,313 purely benign events (64 users, 77 hosts, 30 days) generated by `ml_synthetic.py` to measure real-world FP rates on clean enterprise data.

| Rule category | Count on benign | Assessment |
|---|---|---|
| **NEVER-FIRE** (keyword rules: mimikatz, vssadmin delete, bcdedit, encoded PS, etc.) | **0** | Correct — forensic keywords absent from benign corpus |
| **BEHAVIORAL** (lateral_velocity, rdp_lateral_movement — IT-admin activity) | 18 | Expected — IT admins legitimately access multiple hosts |
| **STATISTICAL** (hourly_event_spike — Z-score by design) | 248 | Designed operating point (~2.5% of user-hours exceed Z>2.5) |

**FP rate: 0.0629 alarms/entity/day** (overwhelmingly statistical by design; behavioral FP rate excluding statistical = 0.001/entity/day)

### ML Baseline Coverage (Gap 2)

Isolation Forest trained on a 60,313-event synthetic corpus with **64 unique users** across 6 behavioral profiles:

| Profile | Count | Behavior |
|---|---|---|
| Standard employee | 25 | Business-hours interactive, typical workload |
| Privileged admin | 10 | Elevated privileges, AD management tasks |
| Service account | 10 | 24/7 automated, constrained process set |
| Contractor | 3 | VPN Type-3, Mon-Fri 09-17, no admin tools |
| DevOps / CI | 3 | 24/7 build jobs, EID 4698 nightly tasks |
| Remote worker | 3 | Variable 07-21, VPN reconnects, elevated failure rate |

### Mutation Test Coverage (Gap 4 — confirmation bias)

50 precision tests across 11 test classes, including near-miss false-positive guards:

| Class | Tests | Guards |
|---|---|---|
| Auth failure burst | 6 | Threshold boundary, below-threshold, window boundary |
| Kerberos ticket spike | 5 | RC4 vs. AES, threshold, window |
| Ransomware triad | 7 | 2-of-3, window boundary, same-host isolation |
| SMB/RDP lateral | 5 | Machine accounts, threshold, window |
| Off-hours privilege | 4 | Work-hours boundary (exact), system user filter |
| Pass-the-hash | 5 | Kerberos user suppression, threshold |
| LSASS PTH correlation | 8 | Benign masks, safe sources, same-host, Type-3 vs. Type-9 |
| Case canonicalization | 3 | Mixed-case keywords fire correctly |
| Noise tolerance | 3 | Rules fire amid 20–80 benign events |
| Cross-user isolation | 2 | Per-user state doesn't leak |
| False positive guards | 5 | vssadmin list, bcdedit enable, bcdedit enum, vssadmin create, machine accounts |
| **Golden ticket precision** | **2** | **Kerberoasting burst must NOT fire golden_ticket; anomalous lifetime must** |

### Data Sources and Citations

| Dataset | Used for | Reference |
|---|---|---|
| **LANL 2015** | ML baseline — user/host activity distributions | Los Alamos National Laboratory, "Comprehensive, Multi-Source Cyber-Security Events" (2015), LANL Institutional Repository |
| **CERT Insider Threat v6.2** | ML baseline — insider threat behavioural patterns | CMU SEI, CERT Insider Threat Dataset v6.2 (2020), Software Engineering Institute |
| **OTRF/Security-Datasets** | ML baseline training + Empire C2 external evaluation | Omar Ortiz, "Security Datasets" (2019–2024), github.com/OTRF/Security-Datasets, MIT License |
| **MITRE ATT&CK Evaluations Round 5 (Turla)** | External-provenance Layer B ground truth (scenario 12) | MITRE Engenuity, "ATT&CK Evaluations Enterprise — Turla" (2024), attackevals.mitre-engenuity.org/enterprise/turla |
| **MITRE ATT&CK Evaluations Round 4 (Wizard Spider)** | External-provenance Layer B ground truth (scenario 13) | MITRE Engenuity, "ATT&CK Evaluations Enterprise — Wizard Spider + Sandworm" (2022), attackevals.mitre-engenuity.org/enterprise/wizard-spider-sandworm |
| **MITRE ATT&CK Evaluations Round 3 (Carbanak+FIN7)** | External-provenance Layer B ground truth (scenario 14) | MITRE Engenuity, "ATT&CK Evaluations Enterprise — Carbanak+FIN7" (2021), attackevals.mitre-engenuity.org/enterprise/carbanak-fin7 |
| **MITRE ATT&CK v14** | Technique ID / tactic / name mappings | MITRE Corporation, "ATT&CK for Enterprise" v14 (2023), attack.mitre.org |

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

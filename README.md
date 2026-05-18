# LateralX — Post-Incident AD Forensic Investigation Platform

LateralX is a post-incident digital forensics and incident response (DFIR) platform purpose-built for Active Directory environments. It ingests multi-source forensic telemetry, applies a layered detection engine (rule-based + unsupervised ML + optional LLM), and produces interactive attack graphs, MITRE ATT&CK mappings, privilege timelines, and executive-ready reports — all without requiring cloud connectivity or external services.

Designed as a structured investigation tool for cybersecurity analysts and incident responders, not a real-time SIEM or endpoint agent.

---

## What It Does

| Capability | Description |
|---|---|
| **Multi-source ingestion** | Windows Event Logs, Sysmon JSONL, Velociraptor artifacts, Timesketch exports, generic CSV, PCAP/PCAPNG; normalisation layer reduces token count 40–60% and applies consistent entity resolution |
| **77 AD detection rules** | Kerberoasting, DCSync, Pass-the-Hash/Ticket, Golden/Silver Ticket, LDAP enumeration, lateral movement, persistence, defense evasion, LSASS handle access (CRED-008), Kerberos RC4 downgrade burst (KERB-014), Zerologon CVE-2020-1472, token impersonation chains, and more |
| **Unsupervised ML** | Isolation Forest trained on a 54-user synthetic baseline grounded in LANL 2015, CERT v6.2, and OTRF/Security-Datasets across 10 behavioral profiles; flags statistical outliers without labeled attack data; sessions with fewer than 20 events fall back to deterministic heuristics to prevent false positives |
| **Supervised attack classifier** | RandomForest model trained on 4,800–5,200 labeled samples across 10 attack categories: ransomware, kerberoasting, lateral movement, credential theft, data exfiltration, C2 communication, persistence, privilege escalation, defense evasion, reconnaissance; falls back to keyword-only classification if scikit-learn is unavailable |
| **Attack chain correlation** | Groups detections by actor across tactics and builds multi-step attack narratives in MITRE tactic order |
| **Attack storyline and threat actor profiling** | Deterministic LLM-free reconstruction: session-aware attack steps, lateral movement paths (from_host → to_host with method), blast radius, and 22-tier threat actor profiling — identifies Skeleton Key, RaaS operators (Ryuk/Conti/LockBit/BlackCat/REvil), ZeroLogon, Cobalt Strike, Metasploit, APT29, FIN7/Carbanak, AD CS abuse, BloodHound-driven attacks, LotL tradecraft, insider threat indicators, and more |
| **MITRE threat group attribution** | Technique overlap matching against 12 documented threat groups (APT29, APT28, Lazarus Group, FIN7, Sandworm, Wizard Spider, Carbanak, MuddyWater, LAPSUS$, Scattered Spider, menuPass, APT41); returns top-5 matches with overlap %, coverage %, and confidence tier (low / medium / high) |
| **Behavioral analysis** | 19 deterministic checks: statistical anomalies (hourly spikes, lateral velocity, auth-failure bursts, off-hours privilege, Kerberoasting spikes, group modification bursts, account creation chains, NTLM spikes), credential access (NTLM brute-force, Pass-the-Hash keyword, LSASS PTH correlation, Golden/Silver Ticket), lateral movement (SMB Type-3 multi-host, RDP Type-10 multi-host, Pass-the-Ticket RC4/no-TGT), execution (WMI shell spawn, event log clearing sweep), ransomware triad (shadow copy + boot-recovery disable + service stop in window), and high-confidence single-event rules (shadow copy deletion, CertUtil/BITSAdmin downloads, MSHTA/Regsvr32 remote exec, encoded PowerShell, Mimikatz, DCSync, LSASS dump) |
| **Incident severity scoring** | Rule-based 0–100 severity score from MITRE technique weights, lateral movement breadth, host blast radius, and privileged account abuse; AD full-compromise chain (DCSync + Golden Ticket + Kerberoasting) forces CRITICAL; Kerberos-only sessions discounted 30% when unaccompanied by lateral movement |
| **Remediation playbooks** | 37 technique-specific playbooks (Golden Ticket, DCSync, LSASS dump, Kerberoasting, Pass-the-Hash, etc.) with immediate actions, short-term hardening steps, prevention measures, and reset requirements — surfaced automatically from detected MITRE techniques |
| **Sigma and Snort rule export** | Evidence-gated generation of Sigma (YAML) and Snort rules from detected techniques and IOCs; behavioral sequence rules (brute-force→success, lateral chain, recon→lateral) are only emitted when the pattern is actually present in the data |
| **Network correlation and DDoS detection** | Sysmon EID 3 ↔ firewall/PCAP 4-tuple join (500ms window) attributes network flows to the originating user and process; detects inbound DDoS floods (T1498.001, ≥50 distinct source IPs to same dst:port) and outbound floods from compromised hosts (T1498.002); exfiltration confirmed when scripting engine + bytes_out >50 MB via 4-tuple join |
| **Attack graph** | Interactive Cytoscape.js visualization with kill-chain overlay, degree-weighted node sizing, node search, and PNG export |
| **AD Threat Map** | Visual matrix mapping detected techniques across hosts and users in ATT&CK tactic order; highlights lateral movement paths and privilege escalation chains across the AD environment |
| **Privilege timeline** | Chronological escalation chain reconstruction from Windows Security EIDs (account creation → group membership → privilege use) |
| **Entity intelligence** | Per-entity (user / host / group) risk scoring (0–100), MITRE technique associations, anomaly flags |
| **IP identity** | Incident-scoped IP → hostname / users / role resolution built entirely from event telemetry, no external DNS |
| **IOC extraction** | Regex-driven extraction of IPs, URLs, domains, file paths, MD5/SHA256 hashes, registry keys; exports to CSV and STIX 2.1 |
| **Threat intelligence** | Optional VirusTotal and AbuseIPDB enrichment; gracefully no-ops when API keys are absent |
| **Incident memory** | Persists IOC patterns (hashes, IPs, domains, registry keys) across cases; new uploads are automatically cross-referenced against all prior incident patterns to surface recurring attacker infrastructure |
| **Global full-text search** | Real-time search across all events, analyses, cases, and notes with relevance ranking; supports fuzzy hostname/user matching and event ID filtering |
| **LMD Random Forest scan** | Upload a labelled Sysmon CSV and run a scikit-learn RandomForest classifier (`rf_model.pkl`) trained to detect Zerologon, Log4Shell, Kerberoasting, and Pass-the-Hash; returns per-event anomaly labels, a summary statistics panel, and a Cytoscape-compatible interactive attack graph with attacker / victim / normal node classification and color-coded suspicious edges |
| **LLM narrative** | Optional Ollama (local) integration for AI-generated investigation narratives with citation callouts — each AI claim links back to the specific event ID that supports it, visible inline in the UI |
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
│                       lmd_model.py  (LMD RandomForest scan + attack graph)
│                       mitre.py  (ATT&CK mapping)
│                       ioc.py  (IOC extraction + STIX export)
│                       threat_intel.py  (VT / AbuseIPDB)
│                       threat_profiling.py  (12 threat-group attribution)
│                       scoring.py  (incident severity 0–100)
│                       rules.py  (Sigma / Snort rule generation)
├── Narrative         — storyline.py  (deterministic attack reconstruction)
│                       llm.py  (optional Ollama narrative)
│                       report.py  (HTML report generation)
├── Ingest (normalise) — normalizer.py  (boilerplate stripping, entity resolution)
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
uvicorn main:app --reload

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

| Phase | Name | Nav items | What you do |
|-------|------|-----------|-------------|
| 1 | **Collect** | Data Ingestion, Cases | Upload log files (CSV / JSONL / PCAP), manage case lifecycle, review the raw event timeline |
| 2 | **Explore** | Timeline, Attack Graph | Browse the chronological event table, navigate the interactive Cytoscape.js attack graph, filter by host / user / event type |
| 3 | **Analyze** | AI Analysis, Attack Storyline | Run the full detection engine — MITRE mappings, behavioral anomalies, ML scores, IOCs, threat group attribution, remediation playbooks, report export; reconstruct deterministic attack storyline with lateral movement paths and blast radius |
| 4 | **AD Intelligence** | AD Intelligence | AD scan (77 rules), LMD RF scan, privilege timeline, entity risk profiles (0–100 per user/host/group), AD threat map, MITRE heatmap, MITRE threat group attribution |

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

Trained on a 54-user / 10-profile synthetic baseline grounded in three public datasets (LANL 2015 user behaviour, CERT v6.2 insider threat, OTRF/Security-Datasets red-team exercises). Scores every entity against the learned normal distribution — entirely name-blind, no signatures required. Entities with fewer than 20 events automatically fall back to deterministic heuristics to prevent statistical false positives on short sessions.

### Attack Chain Correlation

After detection, `ad_chain_correlator.py` groups individual rule hits by actor and orders them by MITRE tactic progression (Recon → Credential Access → Privilege Escalation → Lateral Movement → Persistence → Impact) to produce a coherent multi-stage attack narrative for each threat actor observed in the logs.

### Attack Storyline and Threat Actor Profiling

`storyline.py` is a deterministic, LLM-free attack reconstruction engine. It builds a session-aware attack timeline with three outputs:

**Attack steps** — every classified event mapped to a MITRE technique ID, tactic, host, and user. A sliding 60-minute inactivity window groups events into sessions per actor, so a 2-hour re-entry gap correctly opens a new session rather than extending the original chain.

**Lateral movement paths** — reconstructed `from_host → to_host` edges with method (SMB/PsExec, WMI, RDP, PTH, PTT, DCOM, WinRM, EternalBlue) derived from the event that caused the move.

**Threat actor profile** — a 22-tier heuristic that matches the accumulated technique set to known adversary patterns. Listed from most specific to least:

| Profile | Signals required | Adversary association |
|---|---|---|
| Skeleton Key | T1207 (`lsadump::skeleton`) | Equation Group, APT41 |
| RaaS operator | T1486 + T1490/T1561 + Cobalt Strike or Kerberoasting; family named from keywords (ryuk/conti/lockbit/blackcat/revil) | Wizard Spider, LockBit affiliates |
| Ransomware (manual) | T1486 + T1490/T1561, no C2 pre-stage | Manual ransomware deployment |
| ZeroLogon | T1068 + CVE-2020-1472 text | Any actor with unpatched DCs |
| noPac | T1068 + CVE-2021-42278/42287 text | Post-2021 opportunistic actors |
| Supply chain | T1195.002 | SolarWinds-style operators |
| Cobalt Strike + full AD compromise | Cobalt Strike + Kerberoasting + DCSync + Golden Ticket | Wizard Spider, FIN6, APT41 |
| Cobalt Strike | `msse-*` pipe / `CreateRemoteThread` / Beacon HTTP / malleable profile | Any Cobalt Strike operator |
| Metasploit / Meterpreter | `meterpreter` / `msfvenom` / `reverse_tcp` | Red teams, opportunistic actors |
| Full AD compromise chain | T1558.003 + T1003.006 + T1558.001 | APT actor with domain-persistence goal |
| AD CS abuse | T1649 + lateral or PTH | ESC1-ESC8 exploitation (Certipy/Certify) |
| BloodHound-driven attack | BloodHound text + Kerberoasting or lateral | Targeted AD attackers using graph analysis |
| APT29 / Cozy Bear | Kerberoasting + Silver Ticket + encoded PS, no Cobalt Strike | Russian SVR (NOBELIUM profile) |
| FIN7 / Carbanak | T1047 WMI lateral + T1550.002 PTH + T1053.005 sched. task | FIN7, Carbanak financial APT |
| AD credential theft | T1558.003 + T1003.006 | Any Kerberoasting + DCSync actor |
| NTLM relay + credential forwarding | T1557.001 + PTH or PTT | Responder / ntlmrelayx operators |
| Living-off-the-Land (LotL) | Lateral movement via certutil/BITS/msiexec/mshta/regsvr32 only, no malware signatures | Evasion-focused red teams, APT operators |
| PTH / PTT lateral (3+ hosts) | T1550.002 or T1550.003 to 3+ distinct hosts | Credential-forwarding lateral movement |
| Data exfiltration operator | T1567 cloud or T1048.003 DNS exfil | Espionage or financial actors |
| AS-REP Roasting + lateral | T1558.004 + lateral movement | Pre-auth disabled account exploitation |
| Golden / Silver Ticket | T1558.001 or T1558.002 | Kerberos ticket forging |
| Web shell → lateral | T1505.003 + lateral movement | Web-facing exploitation as pivot |
| Recon + Kerberoasting | BloodHound/LDAP recon + T1558.003 | Structured AD attack path execution |
| Insider threat indicators | Collection + persistence, no lateral/exploit/C2 | Malicious insider or compromised privileged account |

The profile is appended to the executive report and displayed in the Analyze tab alongside the tactic progression, entry vector, patient zero host, blast radius, and lateral movement graph.

### Supervised Attack Classifier

`attack_classifier.py` runs a RandomForest trained on 4,800–5,200 labeled samples (real scenario data + MITRE ATT&CK-derived synthetic sessions, ~20 augmented variants per scenario file) to classify every uploaded session into one of 10 categories:

| Category | MITRE techniques |
|---|---|
| Ransomware | T1486, T1490, T1489 |
| Kerberoasting | T1558.003, T1558.001 |
| Lateral Movement | T1021, T1570, T1534 |
| Credential Theft | T1003, T1555, T1552 |
| Data Exfiltration | T1048, T1567, T1071 |
| C2 Communication | T1071, T1095, T1572 |
| Persistence | T1053, T1547, T1543 |
| Privilege Escalation | T1068, T1134, T1548 |
| Defense Evasion | T1070, T1036, T1562 |
| Reconnaissance | T1087, T1069, T1046 |

Classification result (primary category + confidence score) is included in every `/analyze` response and displayed in the Analyze tab. Falls back to keyword-only classification if scikit-learn is not installed.

### MITRE Threat Group Attribution

`threat_profiling.py` compares the session's detected technique IDs against the documented technique sets for 12 threat groups sourced from the MITRE ATT&CK Groups database:

**APT29** (Cozy Bear / NOBELIUM), **APT28** (Fancy Bear), **Lazarus Group**, **FIN7**, **Sandworm**, **Wizard Spider**, **Carbanak**, **MuddyWater**, **LAPSUS$**, **Scattered Spider**, **menuPass**, **APT41**

For each group with ≥2 overlapping techniques, it returns:
- `overlap_pct` — how much of the group's documented toolkit was observed
- `coverage_pct` — what fraction of the detected techniques match that group
- `confidence` — low (<15% overlap), medium (15–30%), high (>30%)

Top-5 matches are attached to every `/analyze` response and shown in the Analyze tab alongside the storyline profile.

### Incident Severity Scoring

`scoring.py` computes a 0–100 severity score for the entire incident from four components:

| Component | Max contribution |
|---|---|
| MITRE technique weights (technique-specific point values, e.g. T1558.001 Golden Ticket = 18 pts) | 40 |
| Lateral movement breadth (distinct hosts reached) | 20 |
| Host blast radius (compromised host count) | 15 |
| Privileged account abuse + high-signal evidence (mimikatz, lsass, vssadmin, etc.) | 15 + 10 |

DCSync + Golden Ticket + Kerberoasting in the same session forces CRITICAL regardless of other weights. Kerberos-only sessions (no lateral movement or credential dump) receive a 30% discount to reduce false-positive severity on isolated recon.

### Remediation Playbooks

For every detected MITRE technique, LateralX surfaces technique-specific remediation guidance from a built-in playbook (`remediation_lookup.json`). 37 techniques covered, including:

- **Golden Ticket / DCSync**: KRBTGT double-reset procedure, AES enforcement, MDI deployment
- **LSASS dump (T1003.001)**: Credential Guard enablement, PPL protection, LSA audit hardening
- **Kerberoasting (T1558.003)**: Service account password rotation, AES-only enforcement, managed service accounts
- **Pass-the-Hash (T1550.002)**: LocalAccountTokenFilterPolicy enforcement, tiered admin model, LAPS deployment
- **Persistence mechanisms**: Scheduled task audit, service control hardening, registry run key review

Each playbook entry includes: immediate triage actions (with PowerShell commands), short-term hardening steps, long-term prevention measures, reset requirements, and which accounts are at risk.

### Network Correlation and DDoS Detection

`network_host_correlator.py` bridges the forensic gap between host telemetry and network visibility:

**4-tuple correlation** — joins Sysmon EID 3 network connection events with firewall/PCAP flows on `src_ip + dst_ip + dst_port` within a 500ms time window. A successful join enriches the network event with the originating user, process, and host — the critical attribution pivot for network-level IOCs.

**Exfiltration detection** — triggered when a scripting engine (PowerShell, cmd, wscript) is correlated with a session `bytes_out > 50 MB` (CRITICAL); volumetric threshold of 20 MB without host correlation (CRITICAL with lower confidence).

**DDoS detection** — `detect_ddos()` fires two alerts:
- *Inbound flood* (T1498.001): ≥50 distinct source IPs targeting the same `dst_ip:dst_port` within the analysis window
- *Outbound flood* (T1498.002): same `src_ip → dst_ip:dst_port` appearing ≥100 times — indicates compromised host performing DDoS

### Sigma and Snort Rule Export

`rules.py` generates machine-readable detection rules from the analysis results — importable directly into SIEM and IDS/IPS platforms:

**Sigma rules** — one rule per detected MITRE technique, with correct `logsource` (sysmon for execution/evasion, security for credential/lateral), MITRE ATT&CK tags, and detection condition derived from the technique. IOC-based rules include IP/domain/hash conditions.

**Behavioral Sigma rules** — evidence-gated: emitted only when the behavioral sequence is actually present in the uploaded data:
- Brute-force → success (T1110)
- Encoded command execution (T1059.001)
- Lateral movement chain (T1021)
- Recon → lateral move (T1087 + T1021)

**Snort rules** — one rule per IOC (IP, domain, URL), using SID range 9100000+ (IANA private).

Accessible via the `/report/html` endpoint (embedded in report) and the Analyze tab export controls.

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
| **Analysis** | `POST /analyze` (full analysis), `POST /analyze/ad-rules`, `POST /analyze/baseline-compare`, `POST /ml/behavioral`, `POST /ml/storyline`, `GET /analysis/latest` |
| **ML** | `POST /ml/quick-scan`, `POST /ml/train`, `POST /ml/seed-baseline`, `POST /ml/verify`, `GET /ml/status`, `GET /admin/ml-stats` |
| **Graph** | `GET /graph` |
| **Detection Rules** | `GET /detection-rules` (Sigma + Snort rules generated from latest analysis) |
| **Benchmark** | `GET /benchmark` (Layer A + Layer B benchmark report against OTRF datasets) |
| **IOCs** | `GET /iocs`, `GET /iocs/export/csv`, `GET /iocs/export/stix` |
| **AD** | `POST /analyze/privilege-timeline`, `GET /ad-entities` |
| **LMD RF Scan** | `POST /analyze/lmd-rf` (upload Sysmon CSV, run RandomForest, return anomalies + graph data), `GET /analyze/lmd-rf/attack-graph` (download pyvis HTML attack graph) |
| **IP Identity** | `GET /ip-identity` |
| **Cases** | `POST /cases`, `GET /cases`, `PATCH /cases/{id}`, `DELETE /cases/{id}` |
| **Notes** | `POST /notes`, `GET /notes`, `PATCH /notes/{id}`, `DELETE /notes/{id}` |
| **Reports** | `GET /report/html`, `GET /cases/{id}/report`, `GET /cases/{id}/court-report` |
| **Audit** | `GET /audit-log`, `GET /audit-log/verify` |
| **Search** | `GET /search` |
| **Threat Intel** | `GET /threat-intel/status` |
| **Incident Memory** | `GET /incident-memory` (list persisted IOC patterns), `DELETE /incident-memory` (clear cross-case pattern store) |
| **Severity** | Returned inline in every `/analyze` and `/ml/quick-scan` response as `severity_score` (0–100) |
| **Threat Groups** | Returned inline in every `/analyze` response as `threat_profiles` (top-5 MITRE group matches) |

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
    attack_classifier.py      — Supervised 10-class RandomForest classifier
    lmd_model.py              — LMD RandomForest scan (Zerologon / Log4Shell / Kerberoasting / PTH)
    behavioral.py             — 18 deterministic behavioural anomaly checks
    correlation.py            — PCAP ↔ event timestamp + IP correlation
    graph.py                  — Cytoscape.js attack graph builder
    ip_identity.py            — Incident-scoped IP → identity resolution
    ioc.py                    — IOC extraction + STIX 2.1 export
    llm.py                    — Optional Ollama LLM narrative generation
    mitre.py                  — MITRE ATT&CK technique mapper (Layer A)
    ml_anomaly.py             — Isolation Forest anomaly scoring
    ml_synthetic.py           — Synthetic baseline data generator
    network_host_correlator.py — Sysmon EID 3 ↔ firewall 4-tuple join + DDoS detection
    normalizer.py             — Log normalisation, boilerplate stripping, entity resolution
    report.py                 — HTML executive + forensic report generator
    rules.py                  — Evidence-gated Sigma / Snort rule generator
    scoring.py                — Incident severity scorer (0–100, MITRE-weighted)
    storyline.py              — Deterministic attack storyline builder
    threat_intel.py           — VirusTotal / AbuseIPDB enrichment
    threat_profiling.py       — MITRE technique overlap → 12 threat group attribution
  api/
    routes.py                 — FastAPI route handlers (60+ endpoints)
  db/
    models.py                 — SQLAlchemy ORM (11 tables, SQLite WAL)
  ingest/
    parser.py                 — Multi-format log ingestion pipeline (CSV / JSONL / Timesketch / Plaso)
    pcap_parser.py            — PCAP / PCAPng ingestion via pyshark; flow deduplication

backend/data/
  threat_groups.json          — 12 threat group technique sets (MITRE ATT&CK Groups)
  remediation_lookup.json     — 37 technique-specific remediation playbooks

rf_model.pkl                  — Trained RandomForest model for LMD scan (project root; loaded by lmd_model.py)

frontend/
  src/
    components/               — 24 React UI panels (Timeline, GraphView, BehavioralPanel,
                                StorylinePanel, MitrePanel, IOCPanel, NarrativePanel,
                                ADDetectionPanel, ADEntityPanel, ADThreatMap,
                                PrivilegeTimelinePanel, LMDRFScanPanel,
                                MLEntityBehavior, InvestigationNarrative,
                                CaseDashboard, UploadPanel, NotesPanel,
                                GlobalSearch, FilterBar, and more)
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

Evaluated `analyze_behavior` against a benign synthetic corpus (54 users, 10 profiles, 30 days) generated by `ml_synthetic.py` to measure real-world FP rates on clean enterprise data.

| Rule category | Count on benign | Assessment |
|---|---|---|
| **NEVER-FIRE** (keyword rules: mimikatz, vssadmin delete, bcdedit, encoded PS, etc.) | **0** | Correct — forensic keywords absent from benign corpus |
| **BEHAVIORAL** (lateral_velocity, rdp_lateral_movement — IT-admin activity) | 18 | Expected — IT admins legitimately access multiple hosts |
| **STATISTICAL** (hourly_event_spike — Z-score by design) | 248 | Designed operating point (~2.5% of user-hours exceed Z>2.5) |

**FP rate: 0.0629 alarms/entity/day** (overwhelmingly statistical by design; behavioral FP rate excluding statistical = 0.001/entity/day)

### ML Baseline Coverage (Gap 2)

Isolation Forest trained on a synthetic corpus with **54 unique users** across 10 behavioral profiles (generated by `ml_synthetic.py`):

| Profile | Count | Behavior |
|---|---|---|
| Standard worker | 10 | 09–17h, single host, Office/browser, no admin tools |
| IT admin | 6 | Variable hours, 8–20 hosts, legitimate admin tools, normal Kerberos |
| Service account | 6 | 22–04h, single host, scheduled/repetitive, no admin tools |
| Developer | 5 | 10–19h, 1–3 hosts, high process rate, build tooling |
| Help desk | 5 | 08–17h, 5–10 rotating hosts, remote-access tools |
| Security analyst | 7 | Legitimate security tooling, log queries, policy checks |
| DB admin | 4 | 00–06h maintenance windows, DB servers, backup tools |
| Domain controller | 4 | 24/7 Kerberos auth + replication (DC service accounts) |
| Executive | 3 | 09–16h, single host, low volume, no technical processes |
| Cloud workstation | 4 | Azure AD hybrid-joined; elevated EID 4648 + background PS noise |

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

# FIP — Forensic Intelligence Pipeline

Version 1.0.0. FastAPI backend + React frontend for digital forensics investigation. Accepts log files and PCAPs, runs a multi-stage analysis pipeline, and surfaces results through a structured investigation UI. Operates fully offline; an Ollama LLM is optional for narrative generation only.

---

## Technical Stack

| Layer | Technology | Version |
|---|---|---|
| Frontend language | TypeScript | ~6.0.2 |
| Frontend framework | React | 19.2.4 |
| Frontend build tool | Vite | 8.0.4 |
| Graph visualization | Cytoscape.js | 3.33.2 |
| Chart library | D3 | 7.9.0 |
| Styling | Tailwind CSS (utility classes) | — |
| Backend language | Python | 3.11+ |
| Backend framework | FastAPI | — |
| ASGI server | Uvicorn | — |
| ORM | SQLAlchemy | 2.x |
| Schema validation | Pydantic | 2.x |
| Database | SQLite (WAL mode) | — |
| ML library | scikit-learn | — |
| Model serialization | joblib | — |
| Graph algorithms | NetworkX | — |
| PCAP parsing | pyshark | — |
| Graph export | pyvis | — |
| Authentication | python-jose (JWT HS256), passlib (bcrypt) | — |
| MFA | pyotp (TOTP RFC 6238) | — |

---

## Project Structure

```
FIP-main/
├── main.py                        # FastAPI entry point; bootstraps admin account
├── .env                           # Runtime configuration (see Environment section)
├── forensic.db                    # SQLite database (auto-created on first run)
│
├── backend/
│   ├── schema.py                  # All Pydantic models (source of truth for API contracts)
│   ├── api/
│   │   ├── routes.py              # All API endpoints (~40+) under /api prefix
│   │   └── auth.py                # JWT issuance, TOTP verification, bcrypt helpers
│   ├── db/
│   │   └── models.py              # SQLAlchemy table definitions, FTS5 setup, WAL pragma
│   ├── ingest/
│   │   ├── parser.py              # CSV/JSON/JSONL parser for plaso/timesketch/velociraptor/generic
│   │   └── pcap_parser.py         # PCAP/PCAPNG parser via pyshark
│   ├── analysis/
│   │   ├── normalizer.py          # Event deduplication and description normalization
│   │   ├── mitre.py               # Keyword→MITRE ATT&CK technique mapper (31+ techniques)
│   │   ├── graph.py               # Cytoscape.js-compatible attack graph builder
│   │   ├── scoring.py             # Rule-based 0–100 severity scorer
│   │   ├── ioc.py                 # Regex IOC extractor + STIX 2.1 export
│   │   ├── threat_intel.py        # VirusTotal and AbuseIPDB enrichment
│   │   ├── behavioral.py          # Four deterministic behavioral anomaly checks
│   │   ├── correlation.py         # PCAP-to-logon cross-source correlator
│   │   ├── storyline.py           # Session-based ATT&CK-mapped attack storyline
│   │   ├── ml_anomaly.py          # Isolation Forest user anomaly scorer
│   │   ├── lmd_model.py           # Random Forest 6-class AD attack classifier
│   │   ├── attack_classifier.py   # Keyword-based attack-type pre-classifier
│   │   ├── rules.py               # Sigma + Snort detection rule generator
│   │   ├── llm.py                 # Narrative generation (Ollama) + deterministic fallback
│   │   └── report.py              # HTML report renderer
│   └── evaluation/
│       ├── datasets.py            # Embedded OTRF/Security-Datasets benchmark data
│       └── evaluator.py           # LMD, MITRE, and anomaly model quality evaluator
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx                # Root component; all sidebar state and routing
│   │   ├── api.ts                 # Typed fetch wrappers for every backend endpoint
│   │   └── components/
│   │       ├── UploadPanel.tsx        # File upload, source-type selection
│   │       ├── CaseDashboard.tsx      # Case list and creation
│   │       ├── Timeline.tsx           # Event timeline with FilterBar
│   │       ├── FilterBar.tsx          # Per-column filter controls
│   │       ├── GraphView.tsx          # Cytoscape.js attack graph renderer
│   │       ├── NarrativePanel.tsx     # AI Analysis section host (tabs + controls)
│   │       ├── AnalysisControls.tsx   # Run Analysis / Re-run / Export Report buttons
│   │       ├── InvestigationNarrative.tsx  # RCA result fields and narrative text
│   │       ├── IOCPanel.tsx           # IOC table with threat-intel badges
│   │       ├── MitrePanel.tsx         # MITRE ATT&CK technique cards
│   │       ├── BehavioralPanel.tsx    # Behavioral anomaly results
│   │       ├── StorylinePanel.tsx     # Attack Storyline section
│   │       ├── LMDPanel.tsx           # LMD Analysis section
│   │       ├── LMDGraphView.tsx       # LMD pyvis graph renderer
│   │       ├── MLEntityBehavior.tsx   # Per-entity Isolation Forest scores
│   │       ├── ModelQualityPanel.tsx  # Model benchmark results and grades
│   │       ├── GlobalSearch.tsx       # FTS5-backed global search overlay
│   │       ├── NotesPanel.tsx         # Analyst notes with pin support
│   │       ├── Login.tsx              # JWT login form
│   │       ├── MfaModal.tsx           # TOTP challenge modal
│   │       └── TotpSetupModal.tsx     # TOTP QR code setup for admin accounts
│   └── package.json
│
├── tests/                         # pytest suite
└── requirements.txt
```

---

## Database

SQLite file at `./forensic.db`. WAL journal mode is enabled at connection time via `PRAGMA journal_mode=WAL` in `backend/db/models.py`, enabling concurrent readers during writes.

### Tables

| Table | Purpose |
|---|---|
| `uploads` | File upload records: filename, SHA-256 hash, case_id, event_count, uploader |
| `events` | Parsed forensic events: timestamp, event_type, source_host, user, description, raw_source, event_id, extra (JSON), upload_id, case_id |
| `baseline_events` | Snapshot of events designated as a clean baseline for delta comparison |
| `analyses` | Stored `RCAResult` JSON blobs with timestamp, case_id, severity_score |
| `incident_patterns` | Persisted known-bad IOC patterns (strings) used to flag uploads at ingest time |
| `chat_messages` | Analyst chat history (stored but not exposed in the current sidebar) |
| `audit_log` | Tamper-evident log: action, actor, target, timestamp, `payload_sha256`, `prev_hash` |
| `users` | Credentials: username, `hashed_password` (bcrypt), role, TOTP secret, `totp_enabled` |
| `cases` | Investigation cases: `case_id` (UUID), title, description, status (`active`/`closed`/`archived`), creator |
| `analyst_notes` | Markdown notes attached to a case or analysis: author, content, `is_pinned` |
| `ml_ground_truth` | Analyst-labeled verdicts (true/false positive) linked to analysis_id, used to compute ML metrics |

### Full-Text Search (FTS5)

Two FTS5 virtual tables are created alongside the main tables:

- `events_fts` — mirrors `description` from `events`; searched by `GET /api/search`
- `notes_fts` — mirrors `content` from `analyst_notes`; searched by the same endpoint

Both are kept in sync via SQLite triggers on INSERT/UPDATE/DELETE.

### Audit Log Hash Chain

`AuditLogModel` stores a `payload_sha256` (SHA-256 of the JSON payload for each action) and a `prev_hash` (the `payload_sha256` of the immediately preceding log entry). This creates a forward-linked chain that allows offline tamper detection: any modification of a prior row breaks all subsequent hashes.

---

## Analysis Pipeline

`run_full_analysis()` in `backend/analysis/llm.py` executes these stages sequentially for a given set of events:

**1. Normalization** (`normalizer.py`) — Strips verbose Windows Event Log boilerplate from descriptions. Reduces token count by 40–60%. Deduplicates low-value events within a 60-second sliding window keyed on `(host, event_id, user)`; attack-relevant Event IDs and events matching attack keywords bypass deduplication. Supported Event IDs: 4624, 4625, 4657, 4662, 4663, 4672, 4688, 4698, 4768, 4769, 5140, 5145, 7045, 1102.

**2. MITRE ATT&CK Mapping** (`mitre.py`) — Keyword pattern matching across event descriptions. Maps to 31+ technique IDs. Returns `MitreTechnique` objects with `id`, `name`, `tactic`, and matched evidence string.

**3. Attack Graph** (`graph.py`) — Produces a Cytoscape.js-compatible dict. Lateral movement is flagged when a single user accesses 3+ distinct hosts within a 30-minute sliding window (`LATERAL_WINDOW_MINUTES=30`, `SUSPICIOUS_HOST_THRESHOLD=3`). For PCAP events, network flows are rendered as IP-to-IP edges; high-port non-HTTP/S destinations are flagged as C2-like. Cross-source scenario graphs link external IP → EventID 4688 → EventID 4769 within a ±10-minute temporal window (`SCENARIO_WINDOW_MINUTES=10`). Semantic event classification uses compiled regex patterns for process creation, Kerberos activity, lateral movement, authentication, impact, and defense evasion — applied when `event_id` is absent.

**4. Severity Scoring** (`scoring.py`) — Rule-based 0–100 score with five components:
- MITRE technique weights (max 40): T1490/T1486/T1485 each contribute 20 pts (ransomware/destruction), LSASS dump 15, Kerberoasting 12
- Lateral movement presence (max 20)
- Host blast radius (max 15)
- Privileged account abuse (max 15)
- High-signal keyword bonus (max 10): `certutil`, `mimikatz`, `lsass`, `vssadmin`, `psexec`, `mshta`, `-enc`, `encodedcommand`, `procdump`, `dcsync`, `sekurlsa`, `net user /add`, `schtasks /create`, `reg add`, `sc create`

**5. IOC Extraction** (`ioc.py`) — Regex extraction from event descriptions. Seven IOC types: `ip`, `url`, `sha256`, `md5`, `file_path`, `domain`, `registry_key`. Private IP ranges (RFC 1918 + loopback + broadcast) and a hardcoded benign-domain set (Microsoft infrastructure, common CDNs, certificate authorities) are excluded. Supports STIX 2.1 bundle export.

**6. Threat Intelligence Enrichment** (`threat_intel.py`) — Appends VirusTotal and AbuseIPDB reputation data to `IOC.context` strings. Capped at 4 HTTP lookups per analysis run (`_MAX_LOOKUPS=4`, `_TIMEOUT=8` seconds). Results are cached in a module-level dict for the lifetime of the server process. No-ops gracefully when API keys are absent.

**7. Behavioral Analysis** (`behavioral.py`) — Four deterministic, training-free checks run in O(n):
- `hourly_event_spike`: Z-score > 2.5 over per-user hourly event distribution (requires ≥ 3 distinct hours of data, `ZSCORE_THRESHOLD=2.5`, `MIN_HOURLY_POINTS=3`)
- `lateral_velocity`: user accesses > 3 distinct hosts within a 30-minute window (`VELOCITY_WINDOW_MIN=30`, `VELOCITY_THRESHOLD=3`)
- `auth_failure_burst`: > 10 Event ID 4625 failures from a single user within 5 minutes (`AUTH_FAIL_WINDOW_MIN=5`, `AUTH_FAIL_THRESHOLD=10`)
- `off_hours_privilege`: Event ID 4672 (SeDebugPrivilege) occurring outside 07:00–19:00 (`WORK_HOUR_START=7`, `WORK_HOUR_END=19`)

**8. Cross-Source Correlation** (`correlation.py`) — Links PCAP network flow events with logon events using IP address matching and a ±5-minute timestamp window (`CORR_WINDOW_MIN=5`). Confidence is `HIGH` when source IP matches exactly, `MEDIUM` when driven by timestamp proximity alone. Minimum confidence threshold to include a link in results: 0.30.

**9. Attack Storyline** (`storyline.py`) — Session-based ATT&CK attack chain reconstruction. An actor is identified by `(user, source_host)`. A session remains open while consecutive events from that actor arrive within 60 minutes of each other (inactivity timeout). Produces: chronological `AttackStep` list, `LateralPath` list (`from_host` → `to_host` with method and technique_id), and a `BlastRadius` summary (compromised hosts, compromised users, accessed resources, persistence mechanisms). Deterministic; requires no LLM.

**10. ML Anomaly Detection** (`ml_anomaly.py`) — Isolation Forest model (`models/isolation_forest.pkl`) loaded via joblib. Scores each user entity against 15 behavioral features derived from their event history:

| Feature | Description |
|---|---|
| `avg_login_hour` | Mean hour-of-day for all login events |
| `off_hours_ratio` | Fraction of events outside 07:00–19:00 |
| `event_velocity_per_min` | Events per minute over the observation window |
| `activity_acceleration` | Change in event velocity between first and second half of window |
| `unique_hosts` | Count of distinct source hosts touched |
| `failed_login_ratio` | Ratio of Event ID 4625 to total login events |
| `admin_tool_count` | Count of events matching admin tool keywords |
| `encoded_cmd_count` | Count of base64/encoded command events |
| `process_event_ratio` | Ratio of process-creation events to total |
| `event_type_diversity` | Shannon entropy of event type distribution |
| `kerberos_ticket_rate` | Rate of Kerberos ticket events |
| `lateral_logon_ratio` | Ratio of network logon type events |
| `domain_recon_count` | Count of domain enumeration events |
| `priv_escalation_count` | Count of privilege escalation events |
| `ad_attack_tool_count` | Count of known AD attack tool references |

Output per entity: `anomaly_score` (float), `risk_level` (`normal` / `suspicious` / `high_risk`), `contributing_factors` (list of strings), `confidence` (`insufficient_data` / `low` / `medium` / `high`), `session_event_count`.

**11. LMD Classification** (`lmd_model.py`) — Random Forest classifier (`rf_model.pkl`) for Active Directory attack detection. Six classes:

| Class ID | Label |
|---|---|
| 0 | Normal |
| 1 | Kerberoasting / AS-REP Roasting |
| 2 | DCSync / Credential Theft |
| 3 | Golden Ticket / Silver Ticket |
| 4 | Lateral Movement |
| 5 | AD Reconnaissance |

18 input features: `EventID`, `DestinationPort`, `Has_Kerberoast`, `Has_ASREPRoast`, `Has_PTH`, `Has_DCSync`, `Has_GoldenTicket`, `Has_SilverTicket`, `Has_PassTicket`, `Has_BloodHound`, `Has_LSASS`, `Has_WMI_Lateral`, `Has_SMB_Lateral`, `Has_RDP`, `Has_NTLMRelay`, `Has_DomainEnum`, `EID_4769`, `EID_4662`. No `LabelEncoder` is used; class integers are hardcoded in the module. Output: `AttackClassification` with primary class, per-class probabilities, confidence label, top matched indicator keywords, and mapped MITRE technique IDs.

**12. Detection Rule Generation** (`rules.py`) — Evidence-gated Sigma and Snort rule output. Rules are only emitted when the corresponding behavioral sequence is actually present in the ingested events (not generated from technique lists alone). Four behavioral patterns detected:
- Brute-force followed by success (T1110)
- Encoded command execution (T1059.001)
- Lateral movement chain (T1021)
- Reconnaissance followed by lateral movement (T1087 + T1021)

Snort rules use SID base 9,100,000 (IANA private range). Sigma rules include ATT&CK tactic tags.

**13. Narrative Generation** (`llm.py`) — When `LLM_PROVIDER=ollama`, posts a structured prompt to the configured Ollama endpoint and parses the response into `RCAResult.narrative`. On `requests.exceptions.RequestException`, `json.JSONDecodeError`, `ValueError`, or `RuntimeError`, falls back to `_build_deterministic_result()`. When `LLM_PROVIDER=none`, `_build_deterministic_result()` is called directly without attempting Ollama. The deterministic fallback derives `patient_zero_candidate`, `initial_access_vector`, `pivot_chain`, and `anomalous_events` from the graph analysis, MITRE techniques, and ML scores already computed in earlier stages. `narrative_citations` maps individual narrative sentences to their source `events.id` primary keys; the frontend renders these as clickable `[N]` badges.

**14. Report Generation** (`report.py`) — Renders all `RCAResult` fields into a standalone HTML file. Triggered by `GET /api/report/deep`.

The `/api/analyze` endpoint is `async def` and wraps `run_full_analysis` inside `run_in_threadpool` (Starlette) to prevent blocking the event loop during CPU-bound computation or Ollama HTTP I/O.

---

## API Endpoints

All endpoints are prefixed with `/api`. Authentication (JWT Bearer token) is required on all endpoints except `/api/auth/login` and `/api/auth/status`.

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Returns JWT token on valid credentials |
| POST | `/auth/logout` | Invalidates session (client-side token drop) |
| GET | `/auth/status` | Returns authentication state and role |
| POST | `/auth/totp/verify` | Validates TOTP code during login |
| POST | `/auth/totp/setup` | Generates TOTP secret and QR code for admin |
| POST | `/auth/totp/enable` | Enables TOTP after QR confirmation |

### Ingestion
| Method | Path | Description |
|---|---|---|
| POST | `/upload` | Accepts multipart file; returns `UploadResponse` with event count, time range, SHA-256, known-IOC matches |
| POST | `/upload/baseline` | Ingest baseline snapshot for delta comparison |
| GET | `/uploads` | List all uploads, optionally filtered by case_id |
| DELETE | `/uploads/{upload_id}` | Delete upload and its associated events |
| GET | `/events` | Paginated event list with optional filters |
| GET | `/events/summary` | Host/user/event-type counts and time range |
| DELETE | `/events` | Truncate all events |

### Analysis
| Method | Path | Description |
|---|---|---|
| POST | `/analyze` | Run full analysis pipeline; returns `RCAResult` |
| POST | `/analyze/baseline` | Compare current events against baseline snapshot; returns `BaselineComparisonResult` |
| GET | `/analyses` | List stored analyses |
| GET | `/analyses/{id}` | Retrieve stored `RCAResult` |
| DELETE | `/analyses/{id}` | Delete stored analysis |
| GET | `/storyline` | Run `build_storyline()` and return `AttackStoryline` |
| GET | `/behavioral` | Run four behavioral checks and return `BehavioralReport` |
| POST | `/lmd-analysis` | Run LMD classifier on current events; returns `AttackClassification` + pyvis graph |
| GET | `/ml-anomaly` | Run Isolation Forest scorer; returns list of `UserAnomalyScore` |
| GET | `/attack-graph` | Return Cytoscape.js-compatible graph dict |
| GET | `/report/deep` | Generate and return HTML report |

### Cases & Notes
| Method | Path | Description |
|---|---|---|
| POST | `/cases` | Create case; returns `Case` with generated UUID |
| GET | `/cases` | List all cases |
| GET | `/cases/{case_id}` | Get single case |
| PATCH | `/cases/{case_id}` | Update title, description, or status |
| DELETE | `/cases/{case_id}` | Delete case |
| POST | `/notes` | Create analyst note linked to `case_id` or `analysis_id` |
| GET | `/notes` | List notes, filtered by `case_id` or `analysis_id` |
| PATCH | `/notes/{id}` | Update note content or pin state |
| DELETE | `/notes/{id}` | Delete note |

### Model Quality & Settings
| Method | Path | Description |
|---|---|---|
| GET | `/benchmark` | Run evaluator on all three models; returns `BenchmarkReport` |
| GET | `/ml/ground-truth` | List analyst-submitted ground-truth labels |
| POST | `/ml/ground-truth` | Submit analyst verdict (true/false positive) for an analysis |
| GET | `/ml/stats` | Compute precision/recall/F1/accuracy from submitted labels |

### Search & Threat Intelligence
| Method | Path | Description |
|---|---|---|
| GET | `/search` | FTS5 full-text search across events and notes; returns `SearchResponse` |
| GET | `/ti/status` | Returns which TI providers are configured (`vt_configured`, `abuseipdb_configured`) |

### Audit & Admin
| Method | Path | Description |
|---|---|---|
| GET | `/audit-log` | Retrieve audit log entries |
| GET | `/users` | List users (admin role required) |
| POST | `/users` | Create user (admin role required) |
| DELETE | `/users/{username}` | Delete user (admin role required) |

---

## UI Sections

The sidebar is organized into four labeled groups. Section names below are the exact labels rendered in the UI.

**Evidence & Cases**
- **Data Ingestion** — Upload forensic files (`UploadPanel.tsx`). Selects source type (`plaso`, `timesketch`, `velociraptor`, `generic`, `pcap`). Lists upload history with event counts. Supports baseline snapshot ingestion and truncating all events.
- **Cases** — Create and manage investigation cases (`CaseDashboard.tsx`). Cases have status `active`, `closed`, or `archived`. Events and analyses can be scoped to a case_id.

**Investigation**
- **Timeline** — Paginated event table (`Timeline.tsx` + `FilterBar.tsx`). Filters by host, user, event type, and keyword. Events are raw records from the `events` table.
- **Attack Graph** — Cytoscape.js force-directed graph (`GraphView.tsx`). Nodes are hosts and users; edges represent authenticated sessions and lateral movement paths. Lateral movement edges are flagged when a user accesses ≥ 3 hosts in 30 minutes.

**Analysis**
- **AI Analysis** — Primary analysis section (`NarrativePanel.tsx`, `AnalysisControls.tsx`, `InvestigationNarrative.tsx`, `IOCPanel.tsx`, `MitrePanel.tsx`, `BehavioralPanel.tsx`, `MLEntityBehavior.tsx`). Single "Run Analysis" button (changes to "Re-run Analysis" when a result exists). Results displayed across five tabs. When `windows_analyzed > 0` in the result, a `+AI` badge appears indicating Ollama narrative was used. Export button triggers `GET /api/report/deep`.
- **Attack Storyline** — Session-based ATT&CK chain (`StorylinePanel.tsx`). Displays threat actor profile, lateral movement paths, and blast radius.
- **LMD Analysis** — AD attack classifier results (`LMDPanel.tsx`, `LMDGraphView.tsx`). Shows per-class probabilities, confidence label, matched indicators, and pyvis graph.

**Models**
- **Model Quality** — Benchmark runner (`ModelQualityPanel.tsx`). Displays accuracy, macro F1, per-class metrics, and confusion matrix for LMD RF; coverage/hits/partials/misses for MITRE mapper; AUC-ROC and TPR@FPR≤10% for Isolation Forest. Letter grade: A (F1 ≥ 0.90), B (≥ 0.80), C (≥ 0.65), D otherwise.
- **Model Settings** — Ground-truth labeling and ML metric summary. Analysts label analysis results as true/false positives; the backend computes precision, recall, F1, and accuracy from these labels.

---

## Authentication & Security

**JWT** — HS256, 4-hour expiry. Secret from `JWT_SECRET_KEY` env var (code default: `"change-this-in-production-please"`; must be overridden in production).

**Passwords** — bcrypt via passlib. Admin account created on first startup with credentials from `ADMIN_PASSWORD` env var (code default: `"ForensicAdmin2024!"`).

**TOTP MFA** — RFC 6238, 30-second window. `pyotp` generates secrets; `qrcode` renders the enrollment QR code. Enabled per-user via the `/auth/totp/setup` → `/auth/totp/enable` flow.

**Security headers** — Applied to every response by `SecurityHeadersMiddleware` in `main.py`:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self'`

**CORS** — Allowed origins: `http://localhost:5173`, `http://localhost:3000`, `http://127.0.0.1:5173`.

---

## Accepted File Formats

| Extension | Source Type | Parser |
|---|---|---|
| `.csv` | `plaso`, `timesketch`, `velociraptor`, `generic` | `parser.py` |
| `.json` | `generic` | `parser.py` |
| `.jsonl` | `timesketch`, `velociraptor`, `generic` | `parser.py` |
| `.pcap` | `pcap` | `pcap_parser.py` (pyshark) |
| `.pcapng` | `pcap` | `pcap_parser.py` (pyshark) |

Maximum file size: 100 MB per upload.

`parser.py` uses priority-ordered field name resolution for host entity extraction (`hostname` > `host` > `source_host` > `computername` > `workstationname` > `devicename`). Domain suffixes stripped during normalization: `.corp.local`, `.corp`, `.local`, `.internal`, `.lan`, `.ad`, `.domain`, `.home`. Hostnames are upper-cased for consistency. Timestamps are parsed against six format strings; an unrecognized format raises a `ValueError` explicitly.

---

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+
- (Optional) [Ollama](https://ollama.com) running locally for LLM narrative generation

### Backend

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt

# Create .env (see Environment Variables section)
# Then start the server:
uvicorn main:app --reload
```

The database (`forensic.db`) and default `admin` account are created automatically on first startup. The server reloads only when files under `backend/` change (`reload_dirs=["backend"]`).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dev server: `http://localhost:5173`. Backend must be running at `http://localhost:8000`.

---

## Environment Variables

All variables are read from `.env` in the project root.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | `sqlite:///./forensic.db` | SQLAlchemy connection string |
| `LLM_PROVIDER` | Yes | — | `ollama` to enable narrative generation; `none` to use deterministic fallback only |
| `OLLAMA_MODEL` | If `ollama` | `llama3.2` | Model name passed to Ollama API |
| `OLLAMA_BASE_URL` | If `ollama` | `http://localhost:11434` | Ollama HTTP base URL |
| `VT_API_KEY` | No | — | VirusTotal v3 API key; IOC enrichment skipped if absent |
| `ABUSEIPDB_KEY` | No | — | AbuseIPDB v2 API key; IP reputation skipped if absent |
| `ADMIN_PASSWORD` | No | `ForensicAdmin2024!` | Password for the bootstrapped `admin` account |
| `JWT_SECRET_KEY` | No | `change-this-in-production-please` | HS256 signing secret — override in production |

---

## Model Files

Pre-trained model binaries must be present at startup for ML features to work:

| File | Used by | Description |
|---|---|---|
| `rf_model.pkl` | `backend/analysis/lmd_model.py` | Random Forest 6-class AD attack classifier |
| `models/isolation_forest.pkl` | `backend/analysis/ml_anomaly.py` | Isolation Forest user anomaly scorer |

Both are loaded once at module import time via `joblib.load()`. A missing file raises an error at runtime when the corresponding endpoint is first called.

---

## Model Quality Benchmark

`GET /api/benchmark` runs three evaluations against embedded ground-truth data in `backend/evaluation/datasets.py` (structured after [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)):

**LMD Random Forest** — accuracy, macro precision/recall/F1, per-class `ClassMetrics`, confusion matrix.

**MITRE ATT&CK Mapper** — technique coverage: hits (exact match), partials, misses, per-technique breakdown across the benchmark set.

**Isolation Forest** — ROC curve, AUC-ROC, TPR at FPR ≤ 10%.

Grade assignment (`_grade(f1)` in `evaluator.py`): A (≥ 0.90), B (≥ 0.80), C (≥ 0.65), D otherwise. An overall grade is computed from the combined F1 of all three evaluations and returned in `BenchmarkReport.overall_grade`.

---

## Missing Context

The following items could not be fully verified from source code alone:

- **`rf_model.pkl` training** — The model binary is referenced in `lmd_model.py` but no training script exists in this repository. The 18 input features are known (hardcoded in `lmd_model.py`), but training set size, class balance, cross-validation methodology, and dataset provenance are not documented in code.
- **`models/isolation_forest.pkl` training** — `backend/analysis/ml_synthetic.py` exists and likely generates synthetic training data, but its role in producing the shipped `.pkl` is not confirmed from code alone.
- **Ollama prompt format** — The exact system prompt and message structure sent to Ollama is in `backend/analysis/llm.py` and was not included in this audit.

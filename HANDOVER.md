# LateralX — Complete Code Handover

**Date:** 2026-05-19  
**Branch:** `main`  
**Last commit:** `078d346` — Merge branch 'main' of https://github.com/silvercreeks14/FIP

> **Note for next developer:** The merge commit `078d346` was a bad merge — it concatenated both sides of merge conflicts back-to-back in 7 files, producing ~5,255 lines of dead duplicate code. All 7 files have been cleaned up and verified. See §13 for full details.

---

## 1. Project Overview

**LateralX** is a post-incident digital forensics and incident response (DFIR) platform purpose-built for Active Directory environments. It is a single-node, air-gapped-capable tool — no cloud dependency required.

**Core value:** An analyst uploads a forensic timeline (Windows Event Log CSV, Sysmon JSONL, Timesketch export, PCAP/PCAPng) and the platform runs a full detection + ML + correlation stack, producing MITRE ATT&CK mappings, attack graphs, privilege timelines, storylines, IOC enrichment, and exportable forensic reports.

---

## 2. Technology Stack

### Backend
| Layer | Technology |
|---|---|
| Runtime | Python 3.14 |
| API framework | FastAPI (REST, localhost:8000) |
| Database | SQLite via `forensic.db` |
| ML | scikit-learn (Isolation Forest, RandomForest), numpy |
| Network parsing | scapy / dpkt (PCAP ingestion) |
| LLM (optional) | Ollama local integration for AI narrative |
| Auth | JWT + TOTP (2FA) for admin account |

### Frontend
| Layer | Technology |
|---|---|
| Framework | React 19 + TypeScript 6 |
| Build tool | Vite 8 |
| Styling | Tailwind CSS via **Play CDN** (not npm package) |
| Dark mode | Class-based (`darkMode: 'class'`), `.dark` on `<html>` |
| State | React `useState`/`useEffect` — no external state library |
| Visualisation | Cytoscape.js (attack graph + LMD attack graph), inline SVG |

> **Important Tailwind note:** The project uses `https://cdn.tailwindcss.com` (Play CDN) loaded in `index.html`, NOT the Vite/PostCSS plugin. The CDN scans the live DOM and generates CSS on demand via MutationObserver. This means:
> - `dark:` variant classes work fine if `.dark` is on `<html>`
> - CSS custom properties (`var(--foo)`) used inside `style={{}}` props are **unreliable** — when a variable fails to resolve, `color` falls back to its inherited/initial value (often black). Always use Tailwind className pairs instead.

---

## 3. Project Structure

```
FIP-main/
├── main.py                    # FastAPI app entry point (uvicorn)
├── backend/
│   ├── api/                   # Route handlers (routes.py — 60+ endpoints)
│   ├── analysis/              # Detection + ML + correlation engines
│   │   ├── lmd_model.py       # LMD RandomForest scan + pyvis attack graph
│   │   └── rf_model.pkl       # Trained RandomForest model (scikit-learn)
│   ├── ingest/                # Parser (CSV / JSONL / PCAP → ForensicEvent)
│   │   └── parser.py          # parse_lmd_csv() + parse_sysmon_csv() + detect_and_parse()
│   ├── db/                    # SQLite helpers
│   ├── data/                  # Baseline data, remediation playbooks, threat group profiles
│   └── schema.py              # Pydantic models
├── frontend/
│   ├── src/
│   │   ├── App.tsx            # Root layout, theme toggle, nav routing
│   │   ├── index.css          # CSS custom properties (light + dark vars)
│   │   ├── api/client.ts      # All API calls (includes runLMDRFScan, downloadLMDAttackGraph)
│   │   ├── types/index.ts     # TypeScript interfaces (includes LMDRFScanResult, LMDGraphData)
│   │   └── components/        # All UI components (see §5)
│   └── index.html             # Tailwind CDN + darkMode config
├── tests/                     # 237 Python tests (all passing)
└── sample_data/               # Example forensic files for testing
```

---

## 4. Running the Project

```bash
# Backend
pip install -r requirements.txt
python main.py
# → FastAPI on http://localhost:8000

# Frontend (in a second terminal)
cd frontend
npm install
npm run dev
# → Vite dev server on http://localhost:5173
```

**Default credentials:**  
Username: `admin` | Password: `admin123` (change on first login)  
TOTP 2FA is optional; enable via admin settings.

**Optional AI narrative:**  
Set `OLLAMA_HOST=http://localhost:11434` in `.env` and pull a model (`ollama pull mistral`). Without this, Quick Scan still runs all rule/ML/IOC detections instantly.

---

## 5. Component Inventory

| Component | Purpose |
|---|---|
| `App.tsx` | Root layout, sidebar nav, theme toggle, ML model settings panel; passes `lmdFile` state to `ADIntelPanel` |
| `Login.tsx` | Credentials + TOTP 2FA flow |
| `UploadPanel.tsx` | Drag-and-drop upload; callback signature `onUploadSuccess(result, file)` — 2-arg, passes `File` object to caller |
| `FilterBar.tsx` | Host / user / event-type dropdowns |
| `Timeline.tsx` | Scrollable event table with source-color legend |
| `NarrativePanel.tsx` | **Main analysis output** — tabs: Overview, Investigation, Threat Intel, Behavioral |
| `InvestigationNarrative.tsx` | AI narrative with inline citation callouts |
| `AttackClassificationPanel` | Inside `NarrativePanel.tsx` — supervised attack type + confidence bar |
| `IOCPanel.tsx` | IOC table with VirusTotal / AbuseIPDB reputation badges |
| `MitrePanel.tsx` | MITRE ATT&CK tactic/technique cards |
| `BehavioralPanel.tsx` | 18-check behavioural anomaly results |
| `MLEntityBehavior.tsx` | Isolation Forest per-entity risk scores with true/false positive feedback |
| `StorylinePanel.tsx` | Attack storyline: kill chain, lateral movement paths, blast radius |
| `AnalysisControls.tsx` | Run / Re-run / Compare Baseline / Export Report buttons |
| `CaseDashboard.tsx` | Case lifecycle (active/closed/archived), evidence files, notes |
| `NotesPanel.tsx` | Analyst notes per case |
| `GlobalSearch.tsx` | Ctrl+K full-text search across events and notes |
| `ADThreatMap.tsx` | MITRE ATT&CK matrix mapped to detected hosts/users; Cytoscape.js topology graph |
| `ADEntityPanel.tsx` | Per-entity intelligence (risk score, techniques, anomalies) |
| `ADDetectionPanel.tsx` | Raw AD rule detections list |
| `ADIntelPanel.tsx` | **6-tab AD Intelligence hub**: Detection, LMD RF Scan, Timeline, Entities, Threat Map, MITRE Heatmap |
| `LMDRFScanPanel.tsx` | LMD RandomForest scan — upload Sysmon CSV, runs `rf_model.pkl`, shows anomalies + Cytoscape attack graph with attacker/victim/normal node roles |
| `GraphView.tsx` | Cytoscape.js interactive attack graph |
| `PrivilegeTimelinePanel.tsx` | Privilege escalation chain timeline from EIDs 4720/4728/4672/4719 |
| `MfaModal.tsx` / `TotpSetupModal.tsx` | MFA prompt + TOTP QR setup modals |

---

## 6. Theme System

### CSS Custom Properties (`frontend/src/index.css`)

All custom properties are declared twice — once on `:root` (light mode values) and once on `.dark` (dark mode overrides):

```css
:root {
  --brand:        #0284c7;   /* sky-600 — readable on white */
  --brand-bg:     rgba(2, 132, 199, 0.08);
  --brand-border: rgba(2, 132, 199, 0.3);
  --conf-high-c / --conf-high-bg   /* sky-600 confidence badge */
  --conf-med-c  / --conf-med-bg    /* amber-700 */
  --conf-low-c  / --conf-low-bg    /* slate-600 */
  --atk-c1 … --atk-c10 / --atk-def /* attack classification colours */
}

.dark {
  --brand: #00F0FF;          /* cyan — LateralX brand colour */
  /* all variables overridden with dark-mode equivalents */
}
```

### Dark Mode Toggle

`App.tsx` reads `localStorage.getItem('lx_theme')` on mount and adds/removes class `dark` from `document.documentElement`. The toggle button calls `document.documentElement.classList.toggle('dark')` and persists to localStorage.

### Rule for Inline Styles

**Do NOT use `var(--foo)` in `style={{ color: ... }}`** — the CSS variable approach is unreliable with Play CDN when the variable fails to resolve (browser falls back to black text on dark backgrounds).

**Use instead:**
```tsx
// Pattern A — Tailwind className pairs (preferred for all static theming)
className="text-sky-600 dark:text-[#00F0FF]"

// Pattern B — useDark() hook + direct hex (for dynamic/computed colours)
function useDark() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const obs = new MutationObserver(() => setDark(document.documentElement.classList.contains('dark')))
    obs.observe(document.documentElement, { attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return dark
}
// Then: const color = isDark ? '#ef4444' : '#dc2626'
```

`useDark()` is currently defined inline in `NarrativePanel.tsx`. If more components need it, extract it to `src/hooks/useDark.ts`.

---

## 7. UI/UX Work — Session 1 (Theming)

The first session fixed the dual light/dark mode theming across the entire codebase. The app was built dark-mode-first; almost all components had dark-only styles that were invisible or unreadable in light mode.

### Files Modified

#### `frontend/src/index.css`
- Added complete dual-mode CSS custom property system (`--brand`, `--conf-*`, `--atk-c*`) with `:root` (light) and `.dark` (dark) variants.

#### `frontend/src/App.tsx`
- Nav active state: `text-sky-600 dark:text-[#00F0FF] bg-sky-50 dark:bg-[#00F0FF]/[0.08]`
- ML seed/train buttons: added light-mode border/text variants
- ML stats cards: added `border-slate-200 dark:border-slate-700`
- IOC match banner: fixed dark-only classes
- Filter hover states: `hover:text-slate-700 dark:hover:text-slate-300`

#### `frontend/src/components/Login.tsx`
- Error banners, form labels, back button hover: all given dual light/dark pairs

#### `frontend/src/components/NarrativePanel.tsx`
- **Added `useDark()` hook** — observes `<html>` class changes reactively
- **Replaced CSS variable attack classification** — `ATK_META` now stores `{ light: '#hex', dark: '#hex' }` pairs
- Added `bg-white dark:bg-slate-900` to tab content area
- `SEVERITY_STYLES` / `CONFIDENCE_STYLES` / tab badges: all dual light/dark classes

#### `frontend/src/components/StorylinePanel.tsx`
- Replaced CSS variable confidence badges with `CONFIDENCE_CLS` Tailwind className strings
- Actor profile grid, blast radius items, borders: all dual light/dark

#### `frontend/src/components/InvestigationNarrative.tsx`
- Citation callout containers, narrative body, patient zero cards, pivot chain items: all dual light/dark

#### `frontend/src/components/IOCPanel.tsx`
- `TYPE_STYLE` map, `VtBadge`, `AbuseBadge`, TI enrichment, IOC value text, table rows: all dual light/dark

#### `frontend/src/components/MitrePanel.tsx`
- `TACTIC_COLORS` map: all 12 entries converted from single dark-mode hex strings to dual Tailwind className strings

#### `frontend/src/components/BehavioralPanel.tsx`
- `SEVERITY_BADGE.low`, progress bar track, empty state, stat card borders, error div: all dual light/dark

#### `frontend/src/components/ADEntityPanel.tsx`
- Entity type icon badges (user/host): replaced hardcoded hex `style={{ background }}` with Tailwind classes
- Upload pills (unselected): `bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400`

#### `frontend/src/components/AnalysisControls.tsx`
- Run Analysis, Compare Baseline, Divider, Export buttons: all dual light/dark

#### `frontend/src/components/MLEntityBehavior.tsx`
- `RISK_BADGE`, `SEV_BADGE`, feature tag pills, container, progress bar, buttons: all dual light/dark

#### `frontend/src/components/Timeline.tsx`
- `SOURCE_COLORS`, `SourceBadge`, container/empty-state borders, table rows: all dual light/dark

#### `frontend/src/components/UploadPanel.tsx`
- Drop zone states, container border, prompt text, warning/success/error banners: all dual light/dark

#### `frontend/src/components/GlobalSearch.tsx`
- Search trigger, dropdown overlay, section headers, result rows, case navigation, search highlight: all dual light/dark

#### `frontend/src/components/FilterBar.tsx` / `CaseDashboard.tsx`
- Hover states, status badges, expanded panel dividers, action buttons: all dual light/dark

---

## 8. UI/UX Work — Session 2 (LMD RF Scan + AD Intelligence Fixes)

### `frontend/src/components/ADIntelPanel.tsx` — full rewrite
- Removed entire duplicate old 5-tab component (~246 lines of dead code appended by bad merge)
- Fixed all 7 `MITRE_MATRIX` tactic entries from dark-only to dual light/dark Tailwind class pairs (e.g. `bg-cyan-50 dark:bg-cyan-950/30 border-cyan-200 dark:border-cyan-800/30 text-cyan-700 dark:text-cyan-400`)
- Added 6th tab **LMD RF Scan** (`id: 'lmd-rf'`) passing `ingestedFile={lmdFile}` to `LMDRFScanPanel`
- Props updated: `{ activeCaseId, uploads, lmdFile }` — `lmdFile` is the `File` object from the most recently ingested upload, threaded from `App.tsx` via `UploadPanel`'s 2-arg callback

### `frontend/src/components/ADThreatMap.tsx` — duplicate removed
- Original file was 1,509 lines (two complete component definitions back-to-back)
- Kept Version 1 (lines 1–759): `CY_STYLE: cytoscape.StylesheetJsonBlock[]`, node sizes 50/48/50/64, transparent inactive button styles
- Removed Version 2 (lines 760–1,509): smaller nodes, dark-hardcoded inactive buttons

### `frontend/src/components/PrivilegeTimelinePanel.tsx` — 2 bug fixes
- Fix 1 (timeline track divider): `dark:bg-slate-200 dark:bg-slate-800` → `bg-slate-200 dark:bg-slate-800` (removed spurious duplicate dark class)
- Fix 2 (upload filter buttons, both occurrences): `{ background: '#1e293b', color: '#94a3b8' }` (dark-hardcoded) → `{ background: 'transparent', color: '#64748b' }` (readable in both modes)

### `frontend/src/components/LMDRFScanPanel.tsx` — new component (Ahmad's work)
- Props: `{ ingestedFile?: File | null }`
- If `ingestedFile` is set, auto-populates the file input; analyst can also manually select a Sysmon CSV
- Calls `api.runLMDRFScan(file)` → displays: events_parsed, anomaly_count, graph node/edge counts, anomaly list
- Sub-component `LMDAttackGraph` renders Cytoscape.js with:
  - Attacker nodes: triangle / red (`#e11d48`)
  - Victim nodes: rectangle / orange (`#f59e0b`)
  - Normal nodes: circle / blue (`#3b82f6`)
  - Suspicious edges colored by attack type: Zerologon (`#e11d48`), Log4Shell (`#f59e0b`), Kerberoasting (`#8b5cf6`), Pass-the-Hash (`#10b981`)

---

## 9. New Backend Feature — LMD Random Forest Scan

Added by Ahmad in commit `5478c5b`. Integrated into the ADIntelPanel in this session.

### `backend/analysis/lmd_model.py`
- `run_lmd_model_and_graph(events, output_path)`:
  - Loads `rf_model.pkl` (scikit-learn RandomForest)
  - Engineers features: EventID, DestinationPort, Image_Encoded, Protocol_Encoded, Has_Kerberoast, Has_PTH, Has_Log4Shell, Has_Zerologon
  - Predicts anomalies per event; labels nodes as Attacker / Victim / Normal
  - Builds Cytoscape-compatible `graph_data` dict + pyvis HTML via `attack_graph.html`
  - Returns `(anomalies: list[str], graph_data: dict)`

### `backend/ingest/parser.py`
- Added `parse_lmd_csv()` (lines ~859–954): parses labelled Sysmon CSV for LMD model input
- Added `parse_network_csv()`: parses network flow CSVs
- `detect_and_parse()` accepts `parser_hint` parameter: pass `"lmd"` to force `parse_lmd_csv()` instead of auto-detecting format

### `backend/api/routes.py`
- `POST /analyze/lmd-rf` — `async def analyze_lmd_rf_upload()`: accepts multipart file, calls `detect_and_parse(filename, content, parser_hint="lmd")`, runs `run_lmd_model_and_graph()`, returns `LMDRFScanResult`
- `GET /analyze/lmd-rf/attack-graph` — `def download_lmd_attack_graph()`: streams the `attack_graph.html` pyvis output as a downloadable HTML file

### `frontend/src/api/client.ts`
- `runLMDRFScan(file: File): Promise<LMDRFScanResult>` — POST multipart to `/analyze/lmd-rf`
- `downloadLMDAttackGraph()` — GET `/analyze/lmd-rf/attack-graph`, triggers browser download of `attack_graph.html`

### `frontend/src/types/index.ts`
- Added interfaces: `LMDGraphNode`, `LMDGraphEdge`, `LMDGraphData`, `LMDRFScanResult`

---

## 10. Theming Conventions (for new components)

Follow these rules when writing new UI:

### Backgrounds
```
Surface:      bg-white dark:bg-slate-900
Subtle:       bg-slate-50 dark:bg-slate-800/50
Input:        bg-slate-100 dark:bg-slate-800
Page:         bg-gray-950 (App.tsx outer)
```

### Borders
```
Default:      border-slate-200 dark:border-slate-800
Subtle:       border-slate-300 dark:border-slate-700
Input:        border-slate-300 dark:border-slate-700
```

### Text
```
Primary:      text-slate-900 dark:text-white
Secondary:    text-slate-700 dark:text-slate-300
Muted:        text-slate-500 (same both modes)
Very muted:   text-slate-600 dark:text-slate-400
NEVER:        text-slate-200/300 without dark: prefix — invisible in light mode
NEVER:        text-slate-900 without dark:text-white — invisible in dark mode
```

### Brand Accent
```
Text:         text-sky-600 dark:text-[#00F0FF]
Background:   bg-sky-50 dark:bg-[#00F0FF]/[0.08]
Border:       border-sky-200 dark:border-[#00F0FF]/30
```

### Status / Severity Colours
```
Critical/Error:  text-red-700 dark:text-red-400   bg-red-50 dark:bg-red-950/20
High/Warning:    text-orange-700 dark:text-orange-400
Medium/Caution:  text-amber-700 dark:text-amber-400
Low/Success:     text-green-700 dark:text-green-400   bg-green-50 dark:bg-green-950/20
Info:            text-blue-700 dark:text-blue-400
```

---

## 11. Known Issues

All pre-existing TypeScript errors listed in the previous handover have been resolved:

| File | Previous issue | Status |
|---|---|---|
| `ADThreatMap.tsx` | `cytoscape Stylesheet` type incompatibility | **Resolved** — duplicate removed, single clean version kept |
| `GraphView.tsx` | `CollectionReturnValue` type error | **Resolved** — confirmed clean |
| `BehavioralPanel.tsx` | Missing properties on some result types | **Resolved** — confirmed clean |

TypeScript check: `cd frontend && npx tsc --noEmit` → **0 errors**.

---

## 12. Backend Bug — Sysmon CSV Parse

**Status: FIXED.**  
`parse_sysmon_csv` in `backend/ingest/parser.py` previously used `description` before it was assigned. Fixed: `description` is now built at line 725 before `user` references it at line 729. Confirmed by code review.

---

## 13. Bad Merge Fix — Critical History

### What happened

Commit `078d346` was a `git merge` of `5478c5b` (Ahmad's new LMD RF + AD features) into `79f3a4e` (frontend edits). Both branches had modified the same files. Instead of resolving merge conflicts, the merge tool concatenated both complete file versions back-to-back, producing ~5,255 lines of dead duplicate code across 7 files.

### Files that were corrupted and how they were fixed

| File | Problem | Fix |
|---|---|---|
| `frontend/src/components/ADIntelPanel.tsx` | Old 5-tab version appended after new 6-tab version (262 lines good + 246 dead) | Completely rewritten, keeping new version |
| `frontend/src/components/ADThreatMap.tsx` | Second complete component at lines 760–1,509 | Truncated to 759 lines (kept Version 1) |
| `frontend/src/components/UploadPanel.tsx` | Old 1-arg `onUploadSuccess` version appended after new 2-arg version | Truncated to 184 lines (kept new 2-arg version) |
| `frontend/src/App.tsx` | Second `export default function App()` at line 847 | Truncated to 846 lines |
| `frontend/src/api/client.ts` | Two complete `export const api` objects (OLD first, then NEW with `runLMDRFScan`) | Restored from `git show 5478c5b:frontend/src/api/client.ts` |
| `frontend/src/types/index.ts` | Two complete type files concatenated (OLD 531 lines + NEW 568 lines) | Restored from `git show 5478c5b:frontend/src/types/index.ts` |
| `backend/api/routes.py` | Two complete route files (5,522 lines total); OLD first, then NEW with LMD endpoints | Restored from `git show 5478c5b:backend/api/routes.py`; BOM stripped via `[System.IO.File]::WriteAllText` with `UTF8Encoding($false)` |

### Important: merge direction was inconsistent

- **Component files** (ADIntelPanel, ADThreatMap, UploadPanel, App.tsx): Ahmad's NEW version came first in the concatenated file. Keep the FIRST half.
- **API/type files** (routes.py, client.ts, types/index.ts): OLD version came first. Keep the SECOND half — or restore from `git show 5478c5b:path`.

### Verification

After all fixes: `git diff --stat HEAD` shows all 7 files changed (only deletions of duplicate content, no functional additions). TypeScript: 0 errors. Python AST walk: all 35 backend files clean (no duplicate top-level function/class definitions at `col_offset == 0`).

### Python BOM note

PowerShell's `Set-Content -Encoding utf8` adds a UTF-8 BOM (U+FEFF). Python's `ast.parse()` rejects files with a BOM. When writing Python files from PowerShell, always use:
```powershell
[System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
```

---

## 14. What Is NOT Done

- `TotpSetupModal.tsx` / `MfaModal.tsx` — not audited for light/dark mode theming (low priority; MFA is rarely used during investigation).
- The `useDark()` hook is defined inline in `NarrativePanel.tsx`. If other components need reactive dark mode detection, extract it to `src/hooks/useDark.ts`.
- No frontend unit tests exist. Manual testing approach: toggle light/dark mode and verify each tab of the AD Intel panel, Analyze panel, Storyline panel, and Timeline tab.
- `rf_model.pkl` training data and retraining procedure are not documented beyond `lmd_model.py` source comments. If the model needs retraining (new attack types), the training script is not included in this repo.

---

## 15. Testing

```bash
# Backend tests (237 tests, all passing)
cd /path/to/FIP-main
pytest tests/ -v

# TypeScript check (0 errors)
cd frontend
npx tsc --noEmit
```

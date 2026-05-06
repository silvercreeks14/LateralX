"""
LLM Analysis Pipeline — Air-Gapped, Ollama-Only
Supports: ollama (local) | none (offline deterministic mode)
Cloud providers (Groq, Gemini) have been removed. Set OLLAMA_BASE_URL in .env.
"""

import os
import re
import json
import string
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from backend.schema import ForensicEvent, RCAResult, NarrativeCitation
from backend.analysis import mitre as mitre_mod
from backend.analysis import ioc as ioc_mod
from backend.analysis import scoring as scoring_mod
from backend.analysis import ml_anomaly as ml_mod
from backend.analysis.graph import build_attack_graph

load_dotenv()

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower().strip()

# Ollama runs locally — keep windows small to avoid OOM and long inference waits.
# Single inference at a time; parallelism does not help a local model.
WINDOW_SIZE                = 50
WINDOW_OVERLAP             = 5
MAX_EVENTS_BEFORE_SAMPLING = 150
MAX_PARALLEL_WINDOWS       = 1

# ── PII Sanitization ─────────────────────────────────────────────────────────
# Applied before events are serialized into the LLM prompt.
# Protects privacy in audit trails even though Ollama is local.
# The original ForensicEvent objects in the database are NEVER modified.

_PRIVATE_IP_RE = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r')\b'
)


def _alpha_label(n: int) -> str:
    """0→A, 1→B, …, 25→Z, 26→AA, …"""
    result = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        result = string.ascii_uppercase[r] + result
    return result


def _sanitize_window(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """
    Return shallow-copied events with private IPs and usernames replaced by
    stable, consistent placeholders. Patterns (lateral movement between
    REDACTED_IP_1 and REDACTED_IP_2) remain intact for LLM reasoning.
    """
    ip_map: dict[str, str] = {}
    user_map: dict[str, str] = {}

    def _ip_sub(ip: str) -> str:
        if ip not in ip_map:
            ip_map[ip] = f"[REDACTED_IP_{len(ip_map) + 1}]"
        return ip_map[ip]

    def _user_sub(user: str) -> str:
        key = user.lower()
        if key not in user_map:
            user_map[key] = f"[REDACTED_USER_{_alpha_label(len(user_map))}]"
        return user_map[key]

    def _scrub(text: str) -> str:
        text = _PRIVATE_IP_RE.sub(lambda m: _ip_sub(m.group()), text)
        for key, placeholder in user_map.items():
            text = re.sub(rf'\b{re.escape(key)}\b', placeholder, text, flags=re.IGNORECASE)
        return text

    # First pass: build the complete user mapping so substitutions are stable
    for e in events:
        if e.user:
            _user_sub(e.user)

    # Second pass: apply substitutions to a copy — never mutate the originals
    sanitized = []
    for e in events:
        host = _PRIVATE_IP_RE.sub(lambda m: _ip_sub(m.group()), e.source_host)
        user = _user_sub(e.user) if e.user else None
        desc = _scrub(e.description)
        sanitized.append(e.model_copy(update={"source_host": host, "user": user, "description": desc}))

    return sanitized


# ── Prompt Templates ──────────────────────────────────────────────────────────

FORENSIC_RCA_PROMPT = """You are a senior digital forensics analyst with 15 years of incident response experience.

Analyze the following forensic event timeline segment and return a JSON object with EXACTLY these fields:
- "patient_zero_candidate": string — host or account where attack-chain activity (credential dump, LOLBin execution, persistence mechanism) FIRST originated with explicit log evidence; include timestamp and one-sentence justification; empty string if not determinable from these events
- "initial_access_vector": string — entry method EXPLICITLY evidenced in these logs only (e.g. a specific command, connection, or event proving the vector); empty string if insufficient evidence — do NOT hypothesize
- "pivot_chain": array of strings — each lateral movement step as "TIMESTAMP — USER moved from SRCHOST to DSTHOST via METHOD"; only include steps with direct log evidence; empty array if lateral movement is not confirmed
- "anomalous_events": array of strings — only events with direct log evidence of malicious or suspicious activity (LOLBins, encoded commands, shadow copy deletion, off-hours privileged execution); do NOT include events merely because they match common attack patterns if the log content does not confirm it
- "confidence": string — exactly one of "low", "medium", or "high"
- "narrative_citations": array of objects — the investigation narrative broken into individual sentences, each citing the db_id(s) that justify it. Total word count across all sentences: 120 to 140 words. Each object has:
    - "sentence": string — one plain-English sentence for an on-call engineer who has not read the logs
    - "event_ids": array of integers — the db_id values from the timeline that directly support this sentence; MUST contain at least one real db_id from the timeline; use the db_id= field shown in each log line

CRITICAL: Respond with ONLY valid JSON. No markdown fences, no explanation outside the JSON.
Every claim MUST be backed by a specific event in the timeline. If evidence is insufficient, use empty string or empty array. Never invent or assume attack behavior not present in the logs.
IMPORTANT: Escape all backslashes in file paths and registry keys with double backslashes (e.g., C:\\\\Temp\\\\agent.exe, HKLM\\\\SOFTWARE\\\\...).

Timeline segment ({event_count} events from {time_start} to {time_end}):
{timeline_text}"""

SYNTHESIS_PROMPT = """You are a senior digital forensics analyst synthesizing {window_count} partial analysis reports from the same incident.

Produce a single unified RCA. Return ONLY valid JSON with:
- "patient_zero_candidate": string — host or account with the strongest direct log evidence of being the attack origin; empty string if no window provided convincing evidence
- "initial_access_vector": string — entry method supported by explicit log evidence across the windows; empty string if not evidenced — do NOT hypothesize
- "pivot_chain": array of strings — complete merged chronological pivot chain, deduplicated; only include steps confirmed by log evidence
- "anomalous_events": array of strings — all unique anomalous events backed by log evidence, deduplicated
- "confidence": string — "low", "medium", or "high"
- "narrative_citations": array of objects — the investigation narrative broken into individual sentences citing their source events. Total word count: 120 to 140 words. Each object has:
    - "sentence": string — one plain-English sentence covering the full incident arc
    - "event_ids": array of integers — db_id values that justify this sentence (from the original timeline); must be non-empty

CRITICAL: Respond with ONLY valid JSON. No markdown fences. No preamble.
Only include claims that appear in the window reports below as evidence-based findings.
IMPORTANT: Escape all backslashes in file paths and registry keys with double backslashes (e.g., C:\\\\Temp\\\\agent.exe).

Window reports:
{window_reports}"""

# ── Shared Utilities ──────────────────────────────────────────────────────────

def _events_to_text(events: list[ForensicEvent]) -> str:
    from backend.analysis.normalizer import extract_signal  # lazy import avoids circular dep
    lines = []
    for e in sorted(events, key=lambda x: x.timestamp):
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        parts = [ts]
        # db_id is the primary key the LLM must cite in narrative_citations.event_ids
        if e.id is not None:
            parts.append(f"db_id={e.id}")
        parts.extend([f"host={e.source_host}", f"type={e.event_type}"])
        if e.user:
            parts.append(f"user={e.user}")
        if e.event_id:
            parts.append(f"EventID={e.event_id}")
        # Use signal-only extraction instead of raw description[:250].
        # Reduces average event line from ~250 to ~90 chars (~50% token savings).
        signal = extract_signal(e)
        parts.append(signal if signal else e.description[:200])
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def _fix_backslashes(text: str) -> str:
    """
    Double-escape backslashes that are not part of a valid JSON escape sequence.
    Handles Windows paths (C:\\Temp\\agent.exe) and registry keys that local
    models may emit as single-backslash strings, causing json.loads to crash.

    Uses two alternates so complete escape sequences are consumed atomically:
      1st: backslash + valid escape char  → left unchanged
      2nd: lone backslash                 → doubled to \\\\

    Valid JSON escapes left untouched: \\", \\\\, \\/, \\b, \\f, \\n, \\r, \\t, \\uXXXX
    """
    _ESC_RE = re.compile(r'\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|\\')

    def _replace(m: re.Match) -> str:
        s = m.group(0)
        if len(s) > 1:
            return s        # complete escape sequence — leave intact
        return '\\\\'       # lone backslash — double it

    return _ESC_RE.sub(_replace, text)


def _safe_parse_json(text: str) -> dict:
    """
    Parse JSON from LLM output.
    1. Strip markdown fences if the model adds them despite instructions.
    2. Attempt direct json.loads.
    3. On JSONDecodeError, fix unescaped backslashes (Windows paths, registry keys)
       and retry once — logs a warning so the analyst knows Ollama misbehaved.
    """
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        text = "\n".join(lines[start:end]).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fixed = _fix_backslashes(text)
    try:
        result = json.loads(fixed)
        log.warning(
            "Ollama output contained unescaped backslashes; applied auto-fix. "
            "Consider adding stricter escaping instructions to your model's system prompt."
        )
        return result
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM returned unparseable JSON even after backslash fix: {exc}\n"
            f"Raw output (first 500 chars): {text[:500]}"
        ) from exc


# ── Ollama Provider ───────────────────────────────────────────────────────────

def _call_ollama(prompt: str) -> dict:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model_name = os.getenv("OLLAMA_MODEL", "llama3.2")
    try:
        response = requests.post(
            f"{base_url}/api/generate",
            json={"model": model_name, "prompt": prompt, "stream": False},
            timeout=180,
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ValueError(
            f"Cannot connect to Ollama at {base_url}. "
            "Run 'ollama serve' and ensure the model is pulled: "
            f"'ollama pull {model_name}'"
        )
    except requests.exceptions.Timeout:
        raise ValueError(
            f"Ollama at {base_url} timed out after 180 s. "
            "The model may be too large for available RAM/VRAM, or inference is stalled."
        )
    return _safe_parse_json(response.json()["response"])


def _truncate_prompt(prompt: str, keep_ratio: float = 0.6) -> str:
    """Shorten event lines to fit within Ollama's context window."""
    lines = prompt.split("\n")
    truncated = []
    for line in lines:
        if len(line) > 200:
            truncated.append(line[:int(len(line) * keep_ratio)] + "…")
        else:
            truncated.append(line)
    return "\n".join(truncated)


def _call_llm(prompt: str) -> dict:
    """
    Dispatch to the configured provider.

    LLM_PROVIDER values:
      ollama  — use local Ollama inference server (air-gap safe, required for court mode)
      none    — offline mode; run_full_analysis returns deterministic result, no LLM call

    Any other value raises ValueError immediately with a remediation hint.
    """
    valid = {"ollama", "none"}
    if PROVIDER not in valid:
        raise ValueError(
            f"Unknown or disallowed LLM_PROVIDER={PROVIDER!r}. "
            f"Air-gap mode only supports: {', '.join(sorted(valid))}. "
            "Update LLM_PROVIDER in .env (groq/gemini/auto are not permitted in air-gap mode)."
        )
    if PROVIDER == "none":
        raise RuntimeError("_call_llm called in offline mode — caller must check PROVIDER first.")

    for attempt, current_prompt in enumerate([prompt, _truncate_prompt(prompt)]):
        try:
            return _call_ollama(current_prompt)
        except ValueError:
            raise  # connection / timeout errors — no point retrying with same server
        except Exception as exc:
            msg = str(exc).lower()
            if "context" in msg or "token" in msg or "too long" in msg or "too large" in msg:
                if attempt == 0:
                    log.info("Ollama context-limit hit; retrying with truncated prompt.")
                    continue
            log.warning("Ollama attempt %d failed: %s", attempt + 1, exc)
            raise

    raise RuntimeError("Ollama failed on both full and truncated prompt.")


# ── Analysis Pipeline ─────────────────────────────────────────────────────────

def analyze_window(events: list[ForensicEvent]) -> dict:
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    sanitized = _sanitize_window(sorted_events)
    prompt = FORENSIC_RCA_PROMPT.format(
        event_count=len(sanitized),
        time_start=sorted_events[0].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        time_end=sorted_events[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        timeline_text=_events_to_text(sanitized),
    )
    return _call_llm(prompt)


def synthesize_windows(window_results: list[dict]) -> dict:
    reports_text = "\n\n---WINDOW BOUNDARY---\n\n".join(
        f"Window {i + 1}:\n{json.dumps(r, indent=2)}"
        for i, r in enumerate(window_results)
    )
    prompt = SYNTHESIS_PROMPT.format(
        window_count=len(window_results),
        window_reports=reports_text,
    )
    return _call_llm(prompt)


_SUSPICIOUS_KEYWORDS = {
    "certutil", "vssadmin", "wmic", "mshta", "regsvr32", "rundll32",
    "powershell", "psexec", "mimikatz", "lsass", "shadow", "encoded",
    "bypass", "invoke", "download", "bitsadmin", "schtasks", "net user",
    "net localgroup", "whoami", "nltest", "tasklist", "procdump",
    "4624", "4648", "4698", "4720", "7045",
}


def _sample_events(events: list[ForensicEvent]) -> list[ForensicEvent]:
    """
    For large logs: keep all suspicious events + a temporal sample of the rest,
    capped at MAX_EVENTS_BEFORE_SAMPLING. Protects Ollama from OOM.
    """
    if len(events) <= MAX_EVENTS_BEFORE_SAMPLING:
        return events

    suspicious, benign = [], []
    for e in events:
        text = f"{e.description} {e.event_type} {e.event_id or ''}".lower()
        if any(kw in text for kw in _SUSPICIOUS_KEYWORDS):
            suspicious.append(e)
        else:
            benign.append(e)

    budget = MAX_EVENTS_BEFORE_SAMPLING - len(suspicious)
    if budget > 0 and benign:
        step = max(1, len(benign) // budget)
        sampled_benign = benign[::step][:budget]
    else:
        sampled_benign = []

    return sorted(suspicious + sampled_benign, key=lambda e: e.timestamp)


def _analyze_window_indexed(args: tuple[int, list[ForensicEvent]]) -> tuple[int, dict]:
    idx, window = args
    try:
        return idx, analyze_window(window)
    except Exception as e:
        return idx, {
            "patient_zero_candidate": "",
            "initial_access_vector": "",
            "pivot_chain": [],
            "anomalous_events": [f"Window {idx + 1} analysis error: {str(e)}"],
            "confidence": "low",
            "narrative": f"Analysis failed for window {idx + 1}.",
        }


def _build_deterministic_narrative(
    techniques: list,
    iocs: list,
    suspicious_users: list[str],
    severity: int,
    event_count: int,
) -> str:
    """
    Plain-English summary from deterministic analysis only.
    Used when LLM_PROVIDER=none (fully offline / air-gapped mode).
    """
    sev_label = (
        "CRITICAL" if severity >= 80
        else "HIGH" if severity >= 60
        else "MEDIUM" if severity >= 35
        else "LOW"
    )
    parts = [f"Offline deterministic analysis of {event_count} events (LLM_PROVIDER=none)."]
    if suspicious_users:
        names = ", ".join(suspicious_users[:4])
        suffix = f" and {len(suspicious_users) - 4} more" if len(suspicious_users) > 4 else ""
        parts.append(
            f"Lateral movement detected: {len(suspicious_users)} account(s) "
            f"accessed 3 or more hosts within 30 minutes ({names}{suffix})."
        )
    if techniques:
        tactics = list(dict.fromkeys(t.tactic for t in techniques))
        tech_names = ", ".join(t.name for t in techniques[:5])
        suffix = f" (+{len(techniques) - 5} more)" if len(techniques) > 5 else ""
        parts.append(
            f"{len(techniques)} MITRE ATT&CK technique(s) identified across "
            f"{len(tactics)} tactic(s): {tech_names}{suffix}."
        )
    if iocs:
        type_counts: dict[str, int] = {}
        for ioc in iocs:
            type_counts[ioc.type] = type_counts.get(ioc.type, 0) + 1
        ioc_summary = ", ".join(f"{v} {k}" for k, v in list(type_counts.items())[:4])
        parts.append(f"Extracted {len(iocs)} IOC(s): {ioc_summary}.")
    parts.append(
        f"Computed severity: {sev_label} ({severity}/100). "
        "Set LLM_PROVIDER=ollama in .env and run 'ollama serve' to enable AI narrative analysis."
    )
    return " ".join(parts)


def run_full_analysis(events: list[ForensicEvent]) -> RCAResult:
    """
    Main entry point. Accepts list[ForensicEvent], returns RCAResult.

    LLM_PROVIDER=none  — skip all LLM calls; return deterministic-only result
                         (safe for fully offline environments).
    LLM_PROVIDER=ollama — run windowed Ollama inference on sampled events.
    """
    if not events:
        raise ValueError("Cannot analyze an empty event list.")

    events = sorted(events, key=lambda e: e.timestamp)

    # Deterministic enrichment — always runs, zero network cost
    techniques = mitre_mod.map_techniques(events)
    iocs = ioc_mod.extract_iocs(events)
    graph = build_attack_graph(events)
    suspicious_users = graph.get("suspicious_users", [])
    severity = scoring_mod.calculate_severity(events, techniques, suspicious_users)
    ml_scores = ml_mod.score_all_users(events)

    # ── Offline mode ──────────────────────────────────────────────────────────
    if PROVIDER == "none":
        return RCAResult(
            patient_zero_candidate="",
            initial_access_vector="Offline mode — set LLM_PROVIDER=ollama in .env for AI narrative",
            pivot_chain=[],
            anomalous_events=[f"{t.id} {t.name} ({t.tactic})" for t in techniques],
            confidence="low",
            narrative=_build_deterministic_narrative(
                techniques, iocs, suspicious_users, severity, len(events)
            ),
            analyzed_event_count=len(events),
            windows_analyzed=0,
            mitre_techniques=techniques,
            severity_score=severity,
            iocs=iocs,
            ml_anomaly_scores=ml_scores,
        )

    # ── Ollama-assisted analysis ──────────────────────────────────────────────
    sampled = _sample_events(events)

    step = WINDOW_SIZE - WINDOW_OVERLAP
    windows = [
        sampled[i: i + WINDOW_SIZE]
        for i in range(0, len(sampled), step)
        if len(sampled[i: i + WINDOW_SIZE]) >= 5
    ]
    if not windows:
        windows = [sampled]

    indexed = list(enumerate(windows))
    results_map: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_WINDOWS, len(windows))) as pool:
        futures = {pool.submit(_analyze_window_indexed, item): item[0] for item in indexed}
        for future in as_completed(futures):
            idx, result = future.result()
            results_map[idx] = result

    window_results = [results_map[i] for i in range(len(windows))]
    final = synthesize_windows(window_results) if len(window_results) > 1 else window_results[0]

    # Parse narrative_citations; derive the narrative string from them for backward compat.
    raw_citations = final.get("narrative_citations", [])
    narrative_citations: list[NarrativeCitation] = []
    if isinstance(raw_citations, list):
        for item in raw_citations:
            if isinstance(item, dict) and "sentence" in item:
                ids = item.get("event_ids", [])
                narrative_citations.append(NarrativeCitation(
                    sentence=str(item["sentence"]),
                    event_ids=[int(i) for i in ids if isinstance(i, (int, float))],
                ))

    # Derive flat narrative string — fall back to legacy "narrative" key if model skips citations
    if narrative_citations:
        narrative = " ".join(c.sentence for c in narrative_citations)
    else:
        narrative = final.get("narrative", "")

    return RCAResult(
        patient_zero_candidate=final.get("patient_zero_candidate", ""),
        initial_access_vector=final.get("initial_access_vector", ""),
        pivot_chain=final.get("pivot_chain", []),
        anomalous_events=final.get("anomalous_events", []),
        confidence=final.get("confidence", "low"),
        narrative=narrative,
        analyzed_event_count=len(events),
        windows_analyzed=len(windows),
        mitre_techniques=techniques,
        severity_score=severity,
        iocs=iocs,
        ml_anomaly_scores=ml_scores,
        narrative_citations=narrative_citations,
    )

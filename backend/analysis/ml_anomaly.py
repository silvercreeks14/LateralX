"""
ML-based behavioral anomaly detection using Isolation Forest.

Scores each user's event session against a learned baseline of normal behaviour.
No labeled attack data required — purely unsupervised. The model learns what
normal activity looks like and surfaces statistical outliers.

Workflow:
  1. Admin calls train() after uploading representative baseline/investigation logs.
  2. run_full_analysis() calls score_all_entities() on every analysis run.
  3. Scores and contributing factors are included in RCAResult.
"""

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.schema import ForensicEvent, UserAnomalyScore

logger = logging.getLogger(__name__)

MODEL_PATH = Path("models/isolation_forest.pkl")

# Minimum distinct users needed for a statistically meaningful model.
# Below this threshold, the model would overfit to too few samples.
MIN_TRAINING_USERS = 10
MIN_SESSION_EVENTS = 5   # users with fewer events are skipped

# Accounts with these name patterns have predictable, repetitive behaviour by design.
# Scoring them as anomalous produces noise rather than signal.
_SERVICE_ACCOUNT_TERMS = frozenset({
    "svc_", "_svc", "svc-", "-svc",
    "backup", "system", "svchost", "localsystem",
    "network service", "local service", "nt authority",
})


def _is_service_account(username: str) -> bool:
    """Return True when the username matches known service-account naming patterns."""
    u = username.lower().strip()
    if u.endswith("$"):   # machine accounts (DOMAIN\COMPUTERNAME$)
        return True
    return any(term in u for term in _SERVICE_ACCOUNT_TERMS)


_ADMIN_TOOLS = frozenset({
    "certutil", "vssadmin", "wmic", "mshta", "psexec", "mimikatz",
    "procdump", "regsvr32", "rundll32", "schtasks", "bitsadmin",
    "nltest", "whoami", "tasklist", "net.exe", "net1.exe",
    # AD attack tooling
    "rubeus", "bloodhound", "sharphound", "impacket", "crackmapexec",
    "wmiexec", "smbexec", "secretsdump", "getuserspns", "kerbrute",
    "ntlmrelayx", "responder",
})

# AD-specific credential / lateral-movement event IDs
_KERBEROS_EIDS   = frozenset({"4768", "4769", "4770", "4771"})
_LATERAL_LOGON_TYPES = frozenset({"3", "9", "10"})  # Network, NewCreds, RemoteInteractive

FEATURE_NAMES = [
    "avg_login_hour",
    "off_hours_ratio",
    "event_velocity_per_min",
    "activity_acceleration",
    "unique_hosts",
    "failed_login_ratio",
    "admin_tool_count",
    "encoded_cmd_count",
    "process_event_ratio",
    "event_type_diversity",
    # AD-specific features
    "kerberos_ticket_rate",      # Kerberos ticket requests per event
    "lateral_logon_ratio",       # Network/RDP logons as ratio of all logons
    "domain_recon_count",        # BloodHound / LDAP / nltest / net commands
    "priv_escalation_count",     # Token manipulation / UAC bypass / exploitation events
    "ad_attack_tool_count",      # Rubeus / mimikatz / impacket / secretsdump hits
]


# ── Feature extraction ────────────────────────────────────────────────────────

import re as _re

_DOMAIN_RECON_RE = _re.compile(
    r'bloodhound|sharphound|ldapdomaindump|adrecon|nltest|get-domain|powerview'
    r'|get-netgroupmember|find-localadminaccess|net\s+group\s+.*/domain'
    r'|net\s+user\s+.*/domain|dsquery',
    _re.I,
)
_PRIV_ESC_RE = _re.compile(
    r'fodhelper|uac.*bypass|bypass.*uac|juicypotato|rottenpotato|sweetpotato'
    r'|seimpersonatepriv|printnightmare|zerologon|ms17-010|eternalblue',
    _re.I,
)
_AD_TOOL_RE = _re.compile(
    r'rubeus|bloodhound|impacket|crackmapexec|secretsdump|kerbrute'
    r'|ntlmrelayx|responder|mimikatz|lsadump|dcsync',
    _re.I,
)


def _extract_features(events: list[ForensicEvent]) -> np.ndarray:
    """
    Return a (1, 15) feature vector for one user's session.
    All features are defensive — gracefully degrade when specific EventIDs
    are absent from the dataset.
    """
    sorted_ev = sorted(events, key=lambda e: e.timestamp)
    total = len(sorted_ev)

    # ── Temporal ──────────────────────────────────────────────────────────────
    hours = [e.timestamp.hour for e in sorted_ev]
    avg_hour = float(np.mean(hours))
    off_hours_ratio = sum(1 for h in hours if h < 7 or h > 19) / total

    span_min = max(
        (sorted_ev[-1].timestamp - sorted_ev[0].timestamp).total_seconds() / 60,
        1.0,
    )
    event_velocity = total / span_min

    # Escalation signal: rate in 2nd half of session vs 1st half.
    mid = max(total // 2, 1)
    first_half, second_half = sorted_ev[:mid], sorted_ev[mid:]
    if len(first_half) > 1 and len(second_half) > 1:
        fs = max((first_half[-1].timestamp - first_half[0].timestamp).total_seconds() / 60, 1.0)
        ss = max((second_half[-1].timestamp - second_half[0].timestamp).total_seconds() / 60, 1.0)
        acceleration = (len(second_half) / ss) / (len(first_half) / fs)
    else:
        acceleration = 1.0

    # ── Host diversity ────────────────────────────────────────────────────────
    unique_hosts = float(len({e.source_host for e in sorted_ev}))

    # ── Authentication features ────────────────────────────────────────────────
    logon_ids = {"4624", "4648", "4625"}
    logon_events = [e for e in sorted_ev if e.event_id in logon_ids]
    if logon_events:
        failed = sum(1 for e in sorted_ev if e.event_id == "4625")
        failed_ratio = failed / len(logon_events)
    else:
        failed_ratio = 0.0

    # ── Process / command features ────────────────────────────────────────────
    process_events = [e for e in sorted_ev if e.event_id == "4688"]
    proc_ratio = len(process_events) / total

    desc_lower = [e.description.lower() for e in sorted_ev]
    admin_count = float(sum(
        1 for d in desc_lower if any(t in d for t in _ADMIN_TOOLS)
    ))
    encoded_count = float(sum(
        1 for d in desc_lower
        if "-enc" in d or "encodedcommand" in d or "base64" in d
    ))

    # ── Event type entropy ─────────────────────────────────────────────────────
    type_diversity = len({e.event_type for e in sorted_ev}) / total

    # ── AD-specific features ──────────────────────────────────────────────────

    # Kerberos ticket request rate (4768/4769/4770/4771 per total events)
    kerb_events = [e for e in sorted_ev if e.event_id in _KERBEROS_EIDS]
    kerberos_rate = len(kerb_events) / total

    # Lateral logon ratio: network (type 3), new-creds (type 9), RDP (type 10)
    lateral_logons = 0
    for e in sorted_ev:
        if e.event_id in ("4624", "4648"):
            desc = e.description or ""
            m = _re.search(r'Logon Type:\s*(\d+)', desc, _re.I)
            if m and m.group(1) in _LATERAL_LOGON_TYPES:
                lateral_logons += 1
    lat_logon_ratio = lateral_logons / max(len(logon_events), 1)

    # Domain recon command count
    domain_recon = float(sum(
        1 for d in desc_lower if _DOMAIN_RECON_RE.search(d)
    ))

    # Privilege escalation indicator count
    priv_esc = float(sum(
        1 for d in desc_lower if _PRIV_ESC_RE.search(d)
    ))

    # AD attack tool count (Rubeus, BloodHound, impacket, etc.)
    ad_tools = float(sum(
        1 for d in desc_lower if _AD_TOOL_RE.search(d)
    ))

    return np.array([[
        avg_hour,
        off_hours_ratio,
        event_velocity,
        acceleration,
        unique_hosts,
        failed_ratio,
        admin_count,
        encoded_count,
        proc_ratio,
        type_diversity,
        kerberos_rate,
        lat_logon_ratio,
        domain_recon,
        priv_esc,
        ad_tools,
    ]])


def _top_contributing_factors(
    vec: np.ndarray,
    baseline_mean: np.ndarray,
    baseline_std: np.ndarray,
) -> list[str]:
    """Return up to 3 human-readable factors driving the anomaly score."""
    std_safe = np.where(baseline_std < 1e-6, 1.0, baseline_std)
    z = np.abs((vec[0] - baseline_mean) / std_safe)
    top = np.argsort(z)[::-1][:3]

    labels = {
        "avg_login_hour":         "unusual activity hour",
        "off_hours_ratio":        "high off-hours activity",
        "event_velocity_per_min": "high event rate",
        "activity_acceleration":  "escalating activity pattern",
        "unique_hosts":           "accessed many hosts",
        "failed_login_ratio":     "high failed login rate",
        "admin_tool_count":       "admin/LOLBin tool usage",
        "encoded_cmd_count":      "encoded or obfuscated commands",
        "process_event_ratio":    "high process creation rate",
        "event_type_diversity":   "unusual event type mix",
        "kerberos_ticket_rate":   "abnormal Kerberos ticket request rate (possible Kerberoasting)",
        "lateral_logon_ratio":    "high ratio of network/RDP logons (lateral movement pattern)",
        "domain_recon_count":     "AD/domain reconnaissance activity (BloodHound/LDAP/nltest)",
        "priv_escalation_count":  "privilege escalation attempt detected",
        "ad_attack_tool_count":   "AD attack tooling detected (Rubeus/mimikatz/impacket)",
    }
    return [labels[FEATURE_NAMES[i]] for i in top if z[i] > 0.5]


def _risk_level(score: float) -> str:
    if score >= 0.70:
        return "high_risk"
    if score >= 0.45:
        return "suspicious"
    return "normal"


def _heuristic_score(events: list[ForensicEvent]) -> UserAnomalyScore:
    """
    Rule-based fallback when the Isolation Forest model is absent or the user
    session is too small to score statistically. Each fired rule contributes a
    fixed weight; the total is capped at 1.0. Returned confidence is always
    'insufficient_data' so the UI can distinguish heuristic from model output.
    """
    total = len(events)
    if total == 0:
        return UserAnomalyScore(
            entity="unknown",
            anomaly_score=0.0,
            risk_level="normal",
            contributing_factors=[],
            session_event_count=0,
            confidence="insufficient_data",
        )

    desc_lower = [e.description.lower() for e in events]
    hours = [e.timestamp.hour for e in events]

    off_hours_ratio = sum(1 for h in hours if h < 7 or h > 19) / total
    encoded_count = sum(
        1 for d in desc_lower if "-enc" in d or "encodedcommand" in d or "base64" in d
    )
    admin_count = sum(1 for d in desc_lower if any(t in d for t in _ADMIN_TOOLS))
    unique_hosts = len({e.source_host for e in events})
    failed = sum(1 for e in events if e.event_id == "4625")
    logon_ev = [e for e in events if e.event_id in {"4624", "4648", "4625"}]
    failed_ratio = failed / len(logon_ev) if logon_ev else 0.0

    sorted_evs = sorted(events, key=lambda e: e.timestamp)
    span_min = max(
        (sorted_evs[-1].timestamp - sorted_evs[0].timestamp).total_seconds() / 60,
        1.0,
    )
    event_velocity = total / span_min

    # AD-specific counts
    domain_recon  = sum(1 for d in desc_lower if _DOMAIN_RECON_RE.search(d))
    priv_esc      = sum(1 for d in desc_lower if _PRIV_ESC_RE.search(d))
    ad_tools      = sum(1 for d in desc_lower if _AD_TOOL_RE.search(d))
    kerb_events   = [e for e in events if e.event_id in _KERBEROS_EIDS]

    raw_score = 0.0
    factors: list[str] = []

    # ── AD attack tool detection (immediate high-risk indicator) ──────────────
    if ad_tools > 0:
        raw_score += 0.60
        factors.append("AD attack tooling detected (Rubeus/mimikatz/impacket)")
    if priv_esc > 0:
        raw_score += 0.45
        factors.append("privilege escalation attempt detected")
    if domain_recon > 2:
        raw_score += 0.35
        factors.append("AD/domain reconnaissance activity (BloodHound/LDAP/nltest)")
    if kerb_events:
        krate = len(kerb_events) / total
        if krate > 0.15:   # >15% of events are Kerberos ticket requests
            raw_score += 0.35
            factors.append("abnormal Kerberos ticket request rate (possible Kerberoasting)")

    # ── Standard behavioral signals ───────────────────────────────────────────
    if off_hours_ratio > 0.8:
        raw_score += 0.30
        factors.append("high off-hours activity")
    if encoded_count > 0:
        raw_score += 0.40
        factors.append("encoded or obfuscated commands")
    if admin_count > 2:
        raw_score += 0.25
        factors.append("admin/LOLBin tool usage")
    if unique_hosts > 2:
        raw_score += 0.20
        factors.append("accessed many hosts")
    if failed_ratio > 0.3:
        raw_score += 0.30
        factors.append("high failed login rate")
    if event_velocity > 10:
        raw_score += 0.20
        factors.append("high event velocity spike")

    score = round(min(raw_score, 1.0), 3)
    entity_name = events[0].user or "unknown"
    return UserAnomalyScore(
        entity=entity_name,
        anomaly_score=score,
        risk_level=_risk_level(score),
        contributing_factors=factors,
        session_event_count=total,
        confidence="insufficient_data",
    )


# ── Training ──────────────────────────────────────────────────────────────────

def train(all_events: list[ForensicEvent]) -> dict:
    """
    Train an Isolation Forest on per-user feature vectors extracted from
    all_events. Uses both current investigation events and any baseline events
    passed in. Returns training statistics dict on success.
    Raises ValueError if there is not enough data.
    """
    user_events: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in all_events:
        if e.user:
            user_events[e.user].append(e)

    # Drop users with too few events — they produce unreliable vectors
    qualified = {u: evs for u, evs in user_events.items() if len(evs) >= MIN_SESSION_EVENTS}

    if len(qualified) < MIN_TRAINING_USERS:
        raise ValueError(
            f"Insufficient training data: {len(qualified)} user(s) with "
            f"≥{MIN_SESSION_EVENTS} events found, minimum {MIN_TRAINING_USERS} required. "
            f"Upload more logs (investigation + baseline) to build a meaningful model."
        )

    vectors = np.vstack([_extract_features(evs) for evs in qualified.values()])

    scaler = StandardScaler()
    scaled = scaler.fit_transform(vectors)

    # contamination=0.05 tells the model to treat ~5% of training sessions
    # as potential anomalies. Adjust upward if your environment is noisier.
    model = IsolationForest(contamination=0.05, random_state=42, n_estimators=150)
    model.fit(scaled)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "scaler": scaler,
        "baseline_mean": vectors.mean(axis=0),
        "baseline_std": vectors.std(axis=0),
        "trained_on_users": len(qualified),
        "trained_on_events": len(all_events),
        "trained_at": datetime.utcnow().isoformat(),
        "feature_names": FEATURE_NAMES,
    }, MODEL_PATH)

    logger.info(
        "ML anomaly model trained: %d users, %d events",
        len(qualified), len(all_events),
    )
    return {
        "trained_on_users": len(qualified),
        "trained_on_events": len(all_events),
        "trained_at": datetime.utcnow().isoformat(),
    }


# ── Status ────────────────────────────────────────────────────────────────────

def get_model_status() -> dict:
    """Return a status dict safe to send to the frontend."""
    if not MODEL_PATH.exists():
        return {"trained": False, "trained_on_users": 0, "trained_on_events": 0, "trained_at": None}
    try:
        pkg = joblib.load(MODEL_PATH)
        return {
            "trained": True,
            "trained_on_users": pkg.get("trained_on_users", 0),
            "trained_on_events": pkg.get("trained_on_events", 0),
            "trained_at": pkg.get("trained_at"),
        }
    except Exception:
        return {"trained": False, "trained_on_users": 0, "trained_on_events": 0, "trained_at": None}


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_all_entities(events: list[ForensicEvent]) -> list[UserAnomalyScore]:
    """
    Score each entity's (user/account) session against the trained baseline.
    Returns an empty list if no model has been trained yet — never raises.
    Results are sorted highest anomaly score first.
    """
    pkg = None
    if MODEL_PATH.exists():
        try:
            pkg = joblib.load(MODEL_PATH)
        except Exception as exc:
            logger.warning("Could not load ML model: %s", exc)

    user_events: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in events:
        if e.user:
            user_events[e.user].append(e)

    if not user_events:
        return []

    # No trained model → heuristic fallback for every non-service user
    if pkg is None:
        return sorted(
            [
                _heuristic_score(evs)
                for user, evs in user_events.items()
                if not _is_service_account(user)
            ],
            key=lambda s: s.anomaly_score,
            reverse=True,
        )

    # Reject models trained on a different feature set — fall back to heuristic
    saved_features = pkg.get("feature_names", [])
    if saved_features and len(saved_features) != len(FEATURE_NAMES):
        logger.warning(
            "Isolation Forest trained on %d features but current extractor produces %d — "
            "using heuristic fallback until model is retrained.",
            len(saved_features), len(FEATURE_NAMES),
        )
        pkg = None

    if pkg is None:
        return sorted(
            [_heuristic_score(evs) for user, evs in user_events.items()
             if not _is_service_account(user)],
            key=lambda s: s.anomaly_score, reverse=True,
        )

    model: IsolationForest = pkg["model"]
    scaler: StandardScaler = pkg["scaler"]
    baseline_mean: np.ndarray = pkg["baseline_mean"]
    baseline_std: np.ndarray = pkg["baseline_std"]
    trained_on: int = pkg.get("trained_on_users", 0)

    if trained_on >= 30:
        confidence = "high"
    elif trained_on >= MIN_TRAINING_USERS:
        confidence = "medium"
    else:
        confidence = "low"

    scores: list[UserAnomalyScore] = []
    for user, evs in user_events.items():
        # Service accounts have predictable repetitive patterns by design — skip them
        if _is_service_account(user):
            continue
        # Too few events for the statistical model — use heuristic fallback
        if len(evs) < MIN_SESSION_EVENTS:
            scores.append(_heuristic_score(evs))
            continue

        vec = _extract_features(evs)
        try:
            scaled = scaler.transform(vec)
            raw = float(model.decision_function(scaled)[0])
            normalized = float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
        except Exception as exc:
            logger.warning("Scoring failed for user %s: %s", user, exc)
            scores.append(_heuristic_score(evs))
            continue

        factors = _top_contributing_factors(vec, baseline_mean, baseline_std)
        scores.append(UserAnomalyScore(
            entity=user,
            anomaly_score=round(normalized, 3),
            risk_level=_risk_level(normalized),
            contributing_factors=factors,
            session_event_count=len(evs),
            confidence=confidence,
        ))

    return sorted(scores, key=lambda s: s.anomaly_score, reverse=True)

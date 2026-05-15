"""
LateralX AD Attack Chain Correlator.

Groups ADRuleDetection dicts by actor/entity and chains them into
multi-tactic attack narratives using MITRE tactic progression ordering.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta

_TACTIC_ORDER = {
    "Reconnaissance":       0,
    "Discovery":            0,
    "Credential Access":    1,
    "Privilege Escalation": 2,
    "Lateral Movement":     3,
    "Execution":            4,
    "Persistence":          5,
    "Defense Evasion":      6,
    "Exfiltration":         7,
    "Impact":               8,
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_SESSION_WINDOW = timedelta(minutes=30)


def _highest_sev(sevs: list[str]) -> str:
    return min(sevs, key=lambda s: _SEV_ORDER.get(s, 4)) if sevs else "low"


def _parse_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def _looks_like_host(name: str) -> bool:
    """Heuristic: hostnames are UPPERCASE by convention in LateralX; users are mixed-case."""
    return bool(name) and name == name.upper() and not name.endswith("$")


def correlate_attack_chains(detections: list[dict]) -> list[dict]:
    """
    Group detections by actor into attack chains.
    A chain requires ≥2 detections spanning ≥2 distinct MITRE tactics.

    Host-to-user session linking: when a rule fires on a host entity (e.g.
    RECON-005 LDAP burst from HOST-X) and another rule fires on a user entity
    (e.g. DCS-001 DCSync by jsmith) whose source_host is HOST-X within a
    30-minute window, the host detections are merged into the user chain.
    This avoids splitting a single attacker's activity across two chains just
    because some rules key on hostname and others key on username.
    """
    if not detections:
        return []

    # ── Step 1: build host → candidate users map from source_host field ───────
    # source_host is populated by run_ad_rules using the triggering event IDs.
    # When entity is a username and source_host differs, the user was active on
    # that host — link them for potential chain merging.
    host_to_users: dict[str, set[str]] = defaultdict(set)
    for d in detections:
        host   = d.get("source_host", "")
        entity = d.get("entity", "")
        if (host and host != entity
                and entity not in ("__unknown__", "unknown")
                and not entity.endswith("$")):
            host_to_users[host].add(entity)

    # ── Step 2: group detections by entity ────────────────────────────────────
    by_entity: dict[str, list[dict]] = defaultdict(list)
    for d in detections:
        entity = d.get("entity", "")
        if entity and entity not in ("__unknown__", "unknown"):
            by_entity[entity].append(d)

    # ── Step 3: merge host-entity groups into overlapping user-entity groups ──
    for host, users in host_to_users.items():
        if host not in by_entity or not users:
            continue
        host_dets = by_entity[host]
        host_ts   = [t for t in (_parse_ts(d.get("timestamp", "")) for d in host_dets) if t]
        if not host_ts:
            continue
        h_min, h_max = min(host_ts), max(host_ts)

        best_user  = None
        best_count = 0
        for user in users:
            if user not in by_entity:
                continue
            user_ts = [t for t in (_parse_ts(d.get("timestamp", "")) for d in by_entity[user]) if t]
            if not user_ts:
                continue
            u_min, u_max = min(user_ts), max(user_ts)
            # Windows overlap: either range extends within 30 min of the other
            overlaps = not (h_max + _SESSION_WINDOW < u_min or u_max + _SESSION_WINDOW < h_min)
            if overlaps and len(by_entity[user]) > best_count:
                best_count = len(by_entity[user])
                best_user  = user

        if best_user:
            by_entity[best_user].extend(by_entity.pop(host))

    # ── Step 4: build chains ───────────────────────────────────────────────────
    chains = []
    for actor, dets in by_entity.items():
        if len(dets) < 2:
            continue

        tactics = list({d.get("mitre_tactic", "") for d in dets if d.get("mitre_tactic")})
        if len(tactics) < 2:
            continue

        sorted_dets = sorted(
            dets,
            key=lambda d: _TACTIC_ORDER.get(d.get("mitre_tactic", ""), 9),
        )

        valid_ts = [t for t in (_parse_ts(d.get("timestamp", "")) for d in sorted_dets) if t]
        first_seen = min(valid_ts).isoformat() if valid_ts else ""
        last_seen  = max(valid_ts).isoformat() if valid_ts else ""

        ordered_tactics = sorted(tactics, key=lambda t: _TACTIC_ORDER.get(t, 9))
        mitre_ids = sorted({d.get("mitre_id", "") for d in dets if d.get("mitre_id")})
        severity  = _highest_sev([d.get("severity", "low") for d in dets])
        rule_names = [d.get("rule_name", "") for d in sorted_dets[:3]]
        summary = (
            f"{actor} — attack path: {' → '.join(ordered_tactics)}. "
            f"Techniques: {', '.join(mitre_ids[:4])}{'…' if len(mitre_ids) > 4 else ''}. "
            f"Rules triggered: {', '.join(r for r in rule_names if r)[:80]}."
        )

        chains.append({
            "chain_id":        f"CHAIN-{len(chains)+1:03d}",
            "actor":           actor,
            "tactics":         ordered_tactics,
            "mitre_ids":       mitre_ids,
            "severity":        severity,
            "detection_count": len(dets),
            "first_seen":      first_seen,
            "last_seen":       last_seen,
            "summary":         summary,
            "detection_ids":   [d.get("rule_id", "") for d in sorted_dets],
        })

    chains.sort(key=lambda c: (_SEV_ORDER.get(c["severity"], 4), -c["detection_count"]))
    return chains

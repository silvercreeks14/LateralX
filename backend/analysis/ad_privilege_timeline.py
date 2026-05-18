"""
LateralX AD Privilege Escalation Timeline.

Extracts privilege-relevant events, orders them chronologically, and links
multi-step escalation chains (e.g. account creation → group add → sensitive
privilege use within a configurable time window).
"""

from __future__ import annotations
from collections import defaultdict
from datetime import timedelta
from backend.schema import ForensicEvent

# EID → (action label, MITRE ID, base severity)
_PRIVILEGE_EID_MAP: dict[str, tuple[str, str, str]] = {
    "4720": ("Account Created",              "T1136.001", "medium"),
    "4722": ("Account Enabled",              "T1098",     "low"),
    "4723": ("Password Changed",             "T1098",     "low"),
    "4724": ("Password Reset",               "T1098",     "medium"),
    "4725": ("Account Disabled",             "T1098",     "low"),
    "4726": ("Account Deleted",              "T1098",     "medium"),
    "4728": ("Added to Global Group",        "T1098",     "medium"),
    "4729": ("Removed from Global Group",    "T1098",     "low"),
    "4732": ("Added to Local Group",         "T1098",     "medium"),
    "4733": ("Removed from Local Group",     "T1098",     "low"),
    "4735": ("Local Group Modified",         "T1098",     "medium"),
    "4737": ("Global Group Modified",        "T1098",     "medium"),
    "4741": ("Computer Account Created",     "T1207",     "medium"),
    "4756": ("Added to Universal Group",     "T1098",     "medium"),
    "4764": ("Group Type Changed",           "T1484.001", "medium"),
    "4765": ("SID History Added",            "T1134.005", "high"),
    "4766": ("SID History Add Failed",       "T1134.005", "medium"),
    "4672": ("Special Privileges Assigned",  "T1134",     "medium"),
    "4673": ("Sensitive Privilege Used",     "T1134",     "high"),
    "4674": ("Operation Attempt on Object",  "T1134",     "medium"),
    "4719": ("Audit Policy Changed",         "T1562.002", "high"),
    "4886": ("Certificate Issued",           "T1649",     "medium"),
    "4887": ("Certificate Approved",         "T1649",     "medium"),
    "5136": ("Directory Object Modified",    "T1484.001", "medium"),
    "5137": ("Directory Object Created",     "T1484.001", "medium"),
    "1102": ("Audit Log Cleared",            "T1070.001", "high"),
    "104":  ("System Log Cleared",           "T1070.001", "high"),
}

# Groups that warrant "high" severity when added to
_PRIV_GROUPS = frozenset({
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "group policy creator owners",
})

# Chain window: events within this many minutes of the first step count as
# a single escalation chain for the same actor.
_CHAIN_WINDOW_MIN = 30

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _escalate_severity(base: str, event: ForensicEvent) -> str:
    """Bump severity to 'high' or 'critical' based on description keywords."""
    desc = (event.description or "").lower()
    if any(g in desc for g in _PRIV_GROUPS):
        return "high" if base == "medium" else base
    if any(kw in desc for kw in ("sedebugprivilege", "setcbprivilege", "seloaddriverprivilege",
                                  "mimikatz", "sekurlsa", "lsass")):
        return "critical"
    return base


def _build_privilege_events(events: list[ForensicEvent]) -> list[dict]:
    priv_events = []
    for e in events:
        spec = _PRIVILEGE_EID_MAP.get(e.event_id or "")
        if spec is None:
            continue
        action, mitre_id, base_sev = spec
        severity = _escalate_severity(base_sev, e)

        # Build a human-readable detail string
        desc = (e.description or "")
        detail = desc[:200] if len(desc) > 200 else desc

        priv_events.append({
            "timestamp":   e.timestamp.isoformat(),
            "event_id":    e.event_id,
            "actor":       e.user or e.source_host or "unknown",
            "target":      None,
            "action":      action,
            "detail":      detail,
            "severity":    severity,
            "mitre_id":    mitre_id,
            "db_event_id": e.id,
        })

    # Sort chronologically
    priv_events.sort(key=lambda x: x["timestamp"])
    return priv_events


def _build_escalation_chains(priv_events: list[dict]) -> list[dict]:
    """
    Group privilege events by actor within a rolling time window.
    A chain requires ≥2 distinct event types from the same actor.
    """
    if not priv_events:
        return []

    actor_events: dict[str, list[dict]] = defaultdict(list)
    for ev in priv_events:
        actor_events[ev["actor"]].append(ev)

    chains = []
    chain_id = 0

    for actor, actor_evs in actor_events.items():
        actor_evs.sort(key=lambda x: x["timestamp"])
        window = timedelta(minutes=_CHAIN_WINDOW_MIN)

        # Sliding window grouping
        i = 0
        while i < len(actor_evs):
            group = [actor_evs[i]]
            from datetime import datetime
            anchor_ts = datetime.fromisoformat(actor_evs[i]["timestamp"])

            j = i + 1
            while j < len(actor_evs):
                cur_ts = datetime.fromisoformat(actor_evs[j]["timestamp"])
                if cur_ts - anchor_ts <= window:
                    group.append(actor_evs[j])
                    j += 1
                else:
                    break

            # Only emit chain if ≥2 distinct event types
            distinct_eids = {ev["event_id"] for ev in group}
            if len(distinct_eids) >= 2 or any(
                _SEV_ORDER.get(ev["severity"], 3) <= 1 for ev in group
            ):
                last_ts = datetime.fromisoformat(group[-1]["timestamp"])
                duration_min = (last_ts - anchor_ts).total_seconds() / 60

                highest = "low"
                for ev in group:
                    if _SEV_ORDER.get(ev["severity"], 3) < _SEV_ORDER.get(highest, 3):
                        highest = ev["severity"]

                mitre_ids = sorted({ev["mitre_id"] for ev in group})

                # Build readable summary
                actions = [ev["action"] for ev in group]
                unique_actions = list(dict.fromkeys(actions))  # preserve order, deduplicate
                summary = (
                    f"{actor!r} performed {len(group)} privilege operations "
                    f"({', '.join(unique_actions[:4])}{'...' if len(unique_actions) > 4 else ''}) "
                    f"over {duration_min:.0f} min"
                )

                chains.append({
                    "chain_id":              f"CHAIN-{chain_id:03d}",
                    "actor":                 actor,
                    "steps":                 group,
                    "total_duration_minutes": round(duration_min, 1),
                    "highest_severity":      highest,
                    "mitre_ids":             mitre_ids,
                    "summary":               summary,
                })
                chain_id += 1

            i = j if j > i else i + 1

    chains.sort(key=lambda c: (_SEV_ORDER.get(c["highest_severity"], 3), c["chain_id"]))
    return chains


def build_privilege_timeline(events: list[ForensicEvent]) -> dict:
    """
    Main entry point. Returns a dict matching PrivilegeTimelineResult schema.
    """
    if not events:
        return {
            "privilege_events":       [],
            "escalation_chains":      [],
            "total_privilege_events": 0,
            "unique_actors":          0,
            "highest_severity":       "none",
        }

    priv_events = _build_privilege_events(events)
    chains      = _build_escalation_chains(priv_events)

    unique_actors = len({ev["actor"] for ev in priv_events})
    highest = "none"
    for ev in priv_events:
        if _SEV_ORDER.get(ev["severity"], 3) < _SEV_ORDER.get(highest, 4):
            highest = ev["severity"]
    if not priv_events:
        highest = "none"

    return {
        "privilege_events":       priv_events,
        "escalation_chains":      chains,
        "total_privilege_events": len(priv_events),
        "unique_actors":          unique_actors,
        "highest_severity":       highest,
    }

"""
LateralX AD Entity Intelligence.

Profiles users, hosts, and groups observed in forensic events and assigns
risk scores (0-100) with MITRE technique associations, lateral movement
target lists, and anomaly flags.
"""

from __future__ import annotations
from collections import defaultdict
from datetime import timedelta
from backend.schema import ForensicEvent

# EID sets used for risk signal detection
_CRED_EIDS      = {"4769", "4768", "4771", "4662", "4648", "10"}
_LATERAL_EIDS   = {"4624", "5140", "4648", "7045", "4697"}
_PRIV_EIDS      = {"4728", "4732", "4756", "4672", "4673", "4720", "4741"}
_DESTRUCT_EIDS  = {"1102", "104", "4719"}
_RECON_EIDS     = {"4661", "5156", "4625"}

# MITRE IDs associated with specific EIDs
_EID_MITRE: dict[str, str] = {
    "4769": "T1558.003", "4768": "T1558.004", "4771": "T1558.004",
    "4662": "T1003.006", "4648": "T1550.002", "10":   "T1003.001",
    "4624": "T1550.002", "5140": "T1021.002", "7045": "T1543.003",
    "4697": "T1543.003", "4728": "T1098",     "4732": "T1098",
    "4756": "T1098",     "4672": "T1134",     "4673": "T1134",
    "4720": "T1136.001", "4741": "T1207",     "1102": "T1070.001",
    "104":  "T1070.001", "4719": "T1562.002", "4661": "T1087.001",
    "5156": "T1069.002", "4625": "T1110",
}

# Privileged group names (lowercase)
_PRIV_GROUPS = frozenset({
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "group policy creator owners",
})


def _desc_contains(event: ForensicEvent, *keywords: str) -> bool:
    d = (event.description or "").lower()
    return any(kw.lower() in d for kw in keywords)


def _risk_label(score: int) -> str:
    if score >= 60:
        return "compromised"
    if score >= 30:
        return "suspicious"
    return "clean"


def build_entity_intel(events: list[ForensicEvent]) -> dict:
    """
    Main entry point. Returns a dict matching ADEntityIntelResult schema.
    """
    if not events:
        return {
            "entities":          [],
            "total_entities":    0,
            "compromised_count": 0,
            "suspicious_count":  0,
            "top_risk_entity":   None,
        }

    # ── Build per-entity data ─────────────────────────────────────────────────

    # Users
    user_data: dict[str, dict] = defaultdict(lambda: {
        "event_count": 0, "eids": [], "techniques": set(),
        "hosts_touched": set(), "anomaly_flags": [],
        "first_seen": None, "last_seen": None,
        "group_memberships": set(),
    })

    # Hosts
    host_data: dict[str, dict] = defaultdict(lambda: {
        "event_count": 0, "eids": [], "techniques": set(),
        "users_seen": set(), "anomaly_flags": [],
        "first_seen": None, "last_seen": None,
    })

    for e in events:
        ts = e.timestamp

        # ── User profile ──────────────────────────────────────────────────────
        user = e.user
        if user and not user.endswith("$"):
            u = user_data[user]
            u["event_count"] += 1
            if e.event_id:
                u["eids"].append(e.event_id)
            mitre = _EID_MITRE.get(e.event_id or "")
            if mitre:
                u["techniques"].add(mitre)
            u["hosts_touched"].add(e.source_host)
            if u["first_seen"] is None or ts < u["first_seen"]:
                u["first_seen"] = ts
            if u["last_seen"] is None or ts > u["last_seen"]:
                u["last_seen"] = ts
            # group membership from EID 4728/4732/4756 descriptions
            if e.event_id in {"4728", "4732", "4756"}:
                desc_l = (e.description or "").lower()
                for grp in _PRIV_GROUPS:
                    if grp in desc_l:
                        u["group_memberships"].add(grp.title())

        # ── Host profile ──────────────────────────────────────────────────────
        host = e.source_host
        if host:
            h = host_data[host]
            h["event_count"] += 1
            if e.event_id:
                h["eids"].append(e.event_id)
            mitre = _EID_MITRE.get(e.event_id or "")
            if mitre:
                h["techniques"].add(mitre)
            if user and not user.endswith("$"):
                h["users_seen"].add(user)
            if h["first_seen"] is None or ts < h["first_seen"]:
                h["first_seen"] = ts
            if h["last_seen"] is None or ts > h["last_seen"]:
                h["last_seen"] = ts

    # ── Anomaly flag + risk scoring for users ─────────────────────────────────

    entities = []

    for user, u in user_data.items():
        risk = 0
        flags: list[str] = []
        eids = set(u["eids"])

        # Credential-access signals
        cred_count = sum(u["eids"].count(e) for e in _CRED_EIDS)
        if cred_count > 5:
            risk += 20
            flags.append("High credential-access event count")
        if "4662" in eids:
            risk += 25
            flags.append("DS-Replication access (DCSync indicator)")
        if "4769" in eids:
            ticket_count = u["eids"].count("4769")
            if ticket_count > 15:
                risk += 20
                flags.append(f"Kerberos ticket spike ({ticket_count} EID 4769)")
        if "4648" in eids:
            risk += 10
            flags.append("Explicit credential use (EID 4648)")

        # Lateral movement signals
        if len(u["hosts_touched"]) >= 4:
            risk += 15
            flags.append(f"Touched {len(u['hosts_touched'])} distinct hosts")
        if "5140" in eids:
            risk += 10
            flags.append("Admin share access (EID 5140)")

        # Privilege signals
        priv_count = sum(u["eids"].count(e) for e in _PRIV_EIDS)
        if priv_count > 0:
            risk += min(priv_count * 5, 20)
            flags.append(f"Privilege-related events ({priv_count})")
        if u["group_memberships"]:
            risk += 15
            flags.append(f"Member of: {', '.join(sorted(u['group_memberships']))}")

        risk = min(risk, 100)

        entities.append({
            "name":                   user,
            "entity_type":            "user",
            "risk_score":             risk,
            "risk_label":             _risk_label(risk),
            "first_seen":             u["first_seen"].isoformat() if u["first_seen"] else "",
            "last_seen":              u["last_seen"].isoformat()  if u["last_seen"]  else "",
            "event_count":            u["event_count"],
            "associated_techniques":  sorted(u["techniques"]),
            "group_memberships":      sorted(u["group_memberships"]),
            "lateral_targets":        sorted(u["hosts_touched"]),
            "anomaly_flags":          flags,
        })

    # ── Anomaly flag + risk scoring for hosts ─────────────────────────────────

    for host, h in host_data.items():
        risk = 0
        flags: list[str] = []
        eids = set(h["eids"])

        if "7045" in eids or "4697" in eids:
            risk += 20
            flags.append("Service installation detected")
        if len(h["users_seen"]) >= 5:
            risk += 15
            flags.append(f"{len(h['users_seen'])} distinct users logged in")
        if "1102" in eids or "104" in eids:
            risk += 25
            flags.append("Audit log cleared from this host")
        if "4719" in eids:
            risk += 15
            flags.append("Audit policy modified")
        if h["eids"].count("4625") > 10:
            risk += 10
            flags.append("High authentication failure count")

        risk = min(risk, 100)

        entities.append({
            "name":                   host,
            "entity_type":            "host",
            "risk_score":             risk,
            "risk_label":             _risk_label(risk),
            "first_seen":             h["first_seen"].isoformat() if h["first_seen"] else "",
            "last_seen":              h["last_seen"].isoformat()  if h["last_seen"]  else "",
            "event_count":            h["event_count"],
            "associated_techniques":  sorted(h["techniques"]),
            "group_memberships":      [],
            "lateral_targets":        sorted(h["users_seen"]),
            "anomaly_flags":          flags,
        })

    # Sort by risk score descending
    entities.sort(key=lambda e: -e["risk_score"])

    compromised_count = sum(1 for e in entities if e["risk_label"] == "compromised")
    suspicious_count  = sum(1 for e in entities if e["risk_label"] == "suspicious")
    top_risk_entity   = entities[0]["name"] if entities and entities[0]["risk_score"] > 0 else None

    return {
        "entities":          entities,
        "total_entities":    len(entities),
        "compromised_count": compromised_count,
        "suspicious_count":  suspicious_count,
        "top_risk_entity":   top_risk_entity,
    }

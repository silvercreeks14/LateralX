"""
LateralX AD Tool Signature Detection.

Behavioral fingerprinting for common AD attack toolkits.
Complements the rule-based detections with deeper multi-event correlation.
"""
from __future__ import annotations
from collections import defaultdict
from backend.schema import ForensicEvent


def _eid(events: list[ForensicEvent], *eids: str) -> list[ForensicEvent]:
    return [e for e in events if e.event_id in eids]


def _has(ev: ForensicEvent, *kw: str) -> bool:
    d = (ev.description or "").lower()
    return any(k.lower() in d for k in kw)


def detect_tool_signatures(events: list[ForensicEvent]) -> list[dict]:
    """
    Detect behavioral fingerprints of common AD attack toolkits.
    Returns list of ToolSignatureHit dicts sorted by confidence.
    """
    hits: list[dict] = []
    hits.extend(_rubeus(events))
    hits.extend(_mimikatz(events))
    hits.extend(_bloodhound(events))
    hits.extend(_impacket(events))
    hits.extend(_crackmapexec(events))

    _conf_order = {"high": 0, "medium": 1, "low": 2}
    hits.sort(key=lambda h: _conf_order.get(h["confidence"], 3))
    return hits


def _rubeus(events: list[ForensicEvent]) -> list[dict]:
    hits = []
    seen: set[str] = set()

    for e in _eid(events, "1", "4688"):
        if not _has(e, "rubeus", "rubeus.exe"):
            continue
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "Rubeus",
            "confidence": "high",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [f"Rubeus process image in command line (EID {e.event_id}, {e.timestamp.strftime('%H:%M:%S')})"],
            "mitre_ids":  ["T1558.003", "T1558.004", "T1550.003"],
        })

    rc4_users = {e.user for e in _eid(events, "4769") if _has(e, "0x17", "rc4") and e.user}
    tgt_users  = {e.user for e in _eid(events, "4768") if e.user}
    pre_users  = {e.user for e in _eid(events, "4771") if e.user}
    for user in (rc4_users & tgt_users & pre_users) - seen:
        if not user:
            continue
        seen.add(user)
        evs = [e for e in events if e.user == user and e.event_id in ("4769", "4768", "4771")]
        hits.append({
            "tool_name":  "Rubeus",
            "confidence": "medium",
            "entity":     user,
            "timestamp":  evs[0].timestamp.isoformat() if evs else "",
            "indicators": [
                f"RC4-downgrade TGS requests (EID 4769) combined with TGT requests (EID 4768)",
                "Pre-auth failures (EID 4771) from same account",
                "Sequence matches Rubeus kerberoast + asreproast workflow",
            ],
            "mitre_ids": ["T1558.003", "T1558.004"],
        })
    return hits


def _mimikatz(events: list[ForensicEvent]) -> list[dict]:
    hits = []
    seen: set[str] = set()

    for e in _eid(events, "1", "4688"):
        if not _has(e, "mimikatz", "mimi.dll", "mimilib", "sekurlsa", "lsadump", "kerberos::ptt"):
            continue
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "Mimikatz",
            "confidence": "high",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [f"Mimikatz signature in process creation event (EID {e.event_id})"],
            "mitre_ids":  ["T1003.001", "T1550.002", "T1558.001"],
        })

    lsass_ents = {e.source_host or e.user for e in _eid(events, "10") if _has(e, "lsass")}
    setcb_ents  = {e.source_host or e.user for e in _eid(events, "4673") if _has(e, "setcbprivilege")}
    for entity in (lsass_ents & setcb_ents) - seen:
        if not entity:
            continue
        seen.add(entity)
        evs = [e for e in events
               if (e.source_host or e.user or "") == entity and e.event_id in ("10", "4673")]
        hits.append({
            "tool_name":  "Mimikatz",
            "confidence": "medium",
            "entity":     entity,
            "timestamp":  evs[0].timestamp.isoformat() if evs else "",
            "indicators": [
                "LSASS process access with credential-read rights (Sysmon EID 10)",
                "SeTcbPrivilege elevation from same entity (EID 4673)",
                "Combined pattern consistent with mimikatz sekurlsa::logonpasswords",
            ],
            "mitre_ids": ["T1003.001"],
        })
    return hits


def _bloodhound(events: list[ForensicEvent]) -> list[dict]:
    hits = []
    seen: set[str] = set()

    for e in _eid(events, "1", "4688"):
        if not _has(e, "bloodhound", "sharphound", "invoke-bloodhound", "sharphound.exe"):
            continue
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "BloodHound/SharpHound",
            "confidence": "high",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [f"SharpHound collector binary in process arguments (EID {e.event_id})"],
            "mitre_ids":  ["T1482", "T1069.002", "T1087.002"],
        })

    ldap_evs = [e for e in _eid(events, "5156") if _has(e, ":389", ":636", "ldap")]
    by_host: dict[str, list[ForensicEvent]] = defaultdict(list)
    for e in ldap_evs:
        by_host[e.source_host or "unknown"].append(e)
    for host, evs in by_host.items():
        if len(evs) >= 50 and host not in seen:
            seen.add(host)
            hits.append({
                "tool_name":  "BloodHound/SharpHound",
                "confidence": "medium",
                "entity":     host,
                "timestamp":  evs[0].timestamp.isoformat(),
                "indicators": [
                    f"{len(evs)} outbound LDAP connections in short window (EID 5156 port 389/636)",
                    "Connection density consistent with SharpHound ACL/session/trust collection",
                ],
                "mitre_ids": ["T1482", "T1069.002"],
            })
    return hits


def _impacket(events: list[ForensicEvent]) -> list[dict]:
    hits = []
    seen: set[str] = set()

    for e in _eid(events, "1", "4688"):
        if not _has(e, "impacket", "secretsdump", "smbexec.py", "wmiexec.py",
                    "psexec.py", "getuserspns", "getnpusers", "lookupsid"):
            continue
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "Impacket",
            "confidence": "high",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [f"Impacket script name in process command line (EID {e.event_id})"],
            "mitre_ids":  ["T1003.006", "T1557.001", "T1021.002"],
        })

    dcsync = [e for e in _eid(events, "4662")
              if _has(e, "DS-Replication-Get-Changes") and "dc" not in (e.source_host or "").lower()]
    for e in dcsync:
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "Impacket",
            "confidence": "medium",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [
                "DCSync replication request from non-DC host (EID 4662)",
                "Pattern consistent with impacket secretsdump.py -just-dc",
            ],
            "mitre_ids": ["T1003.006"],
        })
    return hits


def _crackmapexec(events: list[ForensicEvent]) -> list[dict]:
    hits = []
    seen: set[str] = set()

    for e in _eid(events, "1", "4688"):
        if not _has(e, "crackmapexec", "cme.exe"):
            continue
        entity = e.user or e.source_host or "unknown"
        if entity in seen:
            continue
        seen.add(entity)
        hits.append({
            "tool_name":  "CrackMapExec",
            "confidence": "high",
            "entity":     entity,
            "timestamp":  e.timestamp.isoformat(),
            "indicators": [f"CrackMapExec binary detected (EID {e.event_id})"],
            "mitre_ids":  ["T1110.003", "T1021.002"],
        })

    ntlm_by_src: dict[str, int] = defaultdict(int)
    for e in _eid(events, "4776"):
        ntlm_by_src[e.source_host or ""] += 1
    smb_by_src: dict[str, int] = defaultdict(int)
    for e in _eid(events, "5140"):
        if _has(e, "admin$", "c$", "ipc$"):
            smb_by_src[e.source_host or e.user or ""] += 1

    for src in set(ntlm_by_src) & set(smb_by_src):
        if not src or src in seen:
            continue
        if ntlm_by_src[src] >= 10 and smb_by_src[src] >= 5:
            seen.add(src)
            hits.append({
                "tool_name":  "CrackMapExec",
                "confidence": "medium",
                "entity":     src,
                "timestamp":  "",
                "indicators": [
                    f"{ntlm_by_src[src]} NTLM credential validations (EID 4776)",
                    f"{smb_by_src[src]} admin share accesses (EID 5140)",
                    "Combined pattern consistent with CME smb module lateral movement",
                ],
                "mitre_ids": ["T1110.003", "T1021.002"],
            })
    return hits

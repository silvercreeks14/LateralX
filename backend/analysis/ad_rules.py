"""
LateralX AD Detection Engine — rule-based Active Directory attack detection.

71 rules across 7 categories, evaluated against ForensicEvent lists.
Rules are plain Python dataclasses — add new rules by appending to AD_RULES.
Each rule is fully transparent: no black-box scoring, no ML weights.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import timedelta
from typing import Callable
from backend.schema import ForensicEvent

# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

@dataclass
class ADRule:
    rule_id: str
    rule_name: str
    category: str           # human-readable category label
    severity: str           # "low" | "medium" | "high" | "critical"
    mitre_id: str
    mitre_tactic: str
    confidence: str         # "low" | "medium" | "high"
    # Evaluator: receives the full event list, returns list of
    # {"entity", "event_ids", "evidence", "timestamp"} dicts (one per hit).
    evaluate: Callable[[list[ForensicEvent]], list[dict]] = field(repr=False)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _events_by_eid(events: list[ForensicEvent], *eids: str) -> list[ForensicEvent]:
    return [e for e in events if e.event_id in eids]


def _desc_contains(event: ForensicEvent, *keywords: str) -> bool:
    d = (event.description or "").lower()
    return any(kw.lower() in d for kw in keywords)


def _sliding_burst(
    events: list[ForensicEvent],
    window_min: int,
    threshold: int,
    key_fn: Callable[[ForensicEvent], str],
) -> list[tuple[str, int, "datetime"]]:
    """Return (key, burst_count, peak_ts) for any key exceeding threshold in window."""
    from collections import deque
    bucket: dict[str, list] = defaultdict(list)
    for e in events:
        bucket[key_fn(e)].append(e.timestamp)

    window = timedelta(minutes=window_min)
    results = []
    for key, times in bucket.items():
        times.sort()
        q: deque = deque()
        best = 0
        best_ts = times[0]
        for ts in times:
            q.append(ts)
            while q and (ts - q[0]) > window:
                q.popleft()
            if len(q) > best:
                best = len(q)
                best_ts = ts
        if best >= threshold:
            results.append((key, best, best_ts))
    return results


# ---------------------------------------------------------------------------
# Category 1 — Kerberoasting / Kerberos abuse
# ---------------------------------------------------------------------------

def _kerb001(events):
    """EID 4769 spike >20 Kerberos service tickets in 10 min."""
    hits = _sliding_burst(
        _events_by_eid(events, "4769"), 10, 20,
        lambda e: e.user or e.source_host or "__unknown__",
    )
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in events if e.event_id == "4769" and (e.user or e.source_host) == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} Kerberos service ticket requests (EID 4769) in 10 min"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


def _kerb002(events):
    """EID 4768 + RC4 encryption type — weak cipher indicates ticket forgery attempt."""
    matches = [
        e for e in _events_by_eid(events, "4768")
        if _desc_contains(e, "0x17", "RC4", "arcfour")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["AS-REQ with RC4 downgrade cipher (EID 4768) — possible ticket forging"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb003(events):
    """EID 4771 — Kerberos pre-auth failure, repeated (>5 in 5 min)."""
    hits = _sliding_burst(
        _events_by_eid(events, "4771"), 5, 5,
        lambda e: e.user or e.source_host or "__unknown__",
    )
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in events if e.event_id == "4771" and (e.user or e.source_host) == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} Kerberos pre-auth failures (EID 4771) in 5 min"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


def _kerb004(events):
    """EID 4769 + non-standard SPN pattern — possible Kerberoasting target selection."""
    suspicious_spns = ("MSSQLSvc", "HTTP", "cifs", "host", "ldap", "exchangeMDB")
    matches = [
        e for e in _events_by_eid(events, "4769")
        if any(_desc_contains(e, spn) for spn in suspicious_spns)
        and _desc_contains(e, "0x17", "RC4")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Service ticket with RC4 for high-value SPN (EID 4769) — Kerberoasting target"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb005(events):
    """EID 4768 for non-existent account (pre-auth not required) — AS-REP Roasting."""
    matches = [
        e for e in _events_by_eid(events, "4768")
        if _desc_contains(e, "0x10", "Don't require Kerberos preauthentication",
                          "DONT_REQUIRE_PREAUTH", "pre-auth not required")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["AS-REQ for account with pre-auth disabled (EID 4768) — AS-REP Roasting"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb006(events):
    """EID 4769 from non-domain-joined host (source IP not matching known DCs)."""
    matches = [
        e for e in _events_by_eid(events, "4769")
        if _desc_contains(e, "ClientAddress") and not _desc_contains(e, "::1", "127.0.0.1")
    ]
    seen: set[str] = set()
    out = []
    for e in matches[:20]:  # cap to 20 to avoid noise
        entity = e.source_host or e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Kerberos service ticket requested from external client address (EID 4769)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb007(events):
    """EID 4769 with ticket options 0x40810010 (forwardable renewable) — Golden Ticket indicator."""
    matches = [
        e for e in _events_by_eid(events, "4769")
        if _desc_contains(e, "0x40810010", "forwardable", "renewable")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["TGS with forwardable+renewable flags (EID 4769) — possible Golden Ticket use"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb008(events):
    """EID 4624 type 3 with Kerberos + no preceding 4768 — pass-the-ticket."""
    tgt_users = {
        e.user for e in _events_by_eid(events, "4768")
        if e.user and not (e.user or "").endswith("$")
    }
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "Kerberos", "LogonType: 3", "LogonType:3")
        and e.user and e.user not in tgt_users
        and not (e.user or "").endswith("$")
    ]
    seen: set[str] = set()
    out = []
    for e in matches[:10]:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Kerberos network logon with no preceding TGT request — possible Pass-the-Ticket"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 2 — DCSync / Credential Dump
# ---------------------------------------------------------------------------

def _dcs001(events):
    """EID 4662 DS-Replication-Get-Changes — DCSync core indicator."""
    matches = [
        e for e in _events_by_eid(events, "4662")
        if _desc_contains(e,
            "DS-Replication-Get-Changes",
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
        )
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["DS-Replication-Get-Changes access right (EID 4662) — DCSync credential dump"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs002(events):
    """EID 4662 from non-DC host — replication request from workstation."""
    matches = [
        e for e in _events_by_eid(events, "4662")
        if _desc_contains(e, "DS-Replication")
        and "dc" not in (e.source_host or "").lower()
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["DS-Replication from non-DC host (EID 4662) — credential dump from workstation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs003(events):
    """EID 4673 SeTcbPrivilege from mimikatz-associated process."""
    matches = [
        e for e in _events_by_eid(events, "4673")
        if _desc_contains(e, "SeTcbPrivilege", "SeTakeOwnershipPrivilege")
        and _desc_contains(e, "mimikatz", "sekurlsa", "lsass")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["SeTcbPrivilege elevation with mimikatz/LSASS context (EID 4673)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs004(events):
    """EID 4624 type 9 (NewCredentials) — mimikatz sekurlsa::pth or pass-the-hash."""
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "LogonType: 9", "LogonType:9", "NewCredentials")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["NewCredentials logon type (EID 4624 type 9) — possible Pass-the-Hash"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs005(events):
    """EID 4648 explicit credential logon + LSASS/Mimikatz description."""
    matches = [
        e for e in _events_by_eid(events, "4648")
        if _desc_contains(e, "mimikatz", "sekurlsa", "lsass", "wce", "fgdump")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Explicit credentials logon with credential-dump tool reference (EID 4648)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs006(events):
    """LSASS handle open attempt — Sysmon EID 10 with lsass.exe target."""
    matches = [
        e for e in _events_by_eid(events, "10")
        if _desc_contains(e, "lsass.exe", "lsass")
        and _desc_contains(e, "GrantedAccess", "0x1010", "0x1410", "0x1038")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["LSASS process access with credential-read rights (Sysmon EID 10)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs007(events):
    """Sysmon EID 1 — comsvcs.dll MiniDump (living-off-the-land LSASS dump)."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "comsvcs", "MiniDump", "rundll32")
        and _desc_contains(e, "lsass", "full")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["comsvcs.dll MiniDump called with lsass target — living-off-the-land LSASS dump"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 3 — Lateral Movement
# ---------------------------------------------------------------------------

def _lat001(events):
    """EID 4648 explicit credentials + remote host — over-pass-the-hash."""
    matches = [
        e for e in _events_by_eid(events, "4648")
        if _desc_contains(e, "Target Server", "network", "remote")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Explicit credential use to remote host (EID 4648) — possible lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat002(events):
    """EID 5140 admin share access (ADMIN$/C$/IPC$) — PsExec/SMB lateral movement."""
    matches = [
        e for e in _events_by_eid(events, "5140")
        if _desc_contains(e, "ADMIN$", "C$", "IPC$")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Admin share access (EID 5140 ADMIN$/C$/IPC$) — PsExec/SMB lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat003(events):
    """EID 4624 type 10 (RemoteInteractive) — RDP login."""
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "LogonType: 10", "LogonType:10", "RemoteInteractive")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["RDP RemoteInteractive logon (EID 4624 type 10) — remote desktop lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat004(events):
    """Sysmon EID 1 — wmic.exe /node: or Invoke-WmiMethod (WMI lateral)."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "wmic", "WmiMethod", "Win32_Process")
        and _desc_contains(e, "/node:", "Create", "CommandLineEventConsumer")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["WMI remote process creation (wmic /node: or Win32_Process) — WMI lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat005(events):
    """Sysmon EID 1 — psexec or smbexec in command line."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "psexec", "smbexec", "paexec", "remcom")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["PsExec/SMBExec execution detected — remote code execution lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat006(events):
    """EID 4624 type 3 from unusual source + admin group — net-use/WinRM pivot."""
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "LogonType: 3", "LogonType:3")
        and _desc_contains(e, "admin", "Administrators")
        and not (e.user or "").endswith("$")
    ]
    seen: set[str] = set()
    out = []
    for e in matches[:15]:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Network logon (type 3) with admin context (EID 4624) — possible WinRM/net-use pivot"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat007(events):
    """EID 7045 — new service installed on remote host (PsExec pattern)."""
    matches = [
        e for e in _events_by_eid(events, "7045")
        if _desc_contains(e, "PSEXESVC", "REMCOMSVC", "cmd.exe", "powershell")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.source_host or e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Suspicious service installed (EID 7045) — PsExec/remote execution pattern"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat008(events):
    """EID 4697 — service installation from temp/user-writable path."""
    matches = [
        e for e in _events_by_eid(events, "4697")
        if _desc_contains(e, "\\Temp\\", "\\AppData\\", "\\Users\\", "%TEMP%")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Service installed from writable user path (EID 4697) — persistence/lateral technique"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 4 — Privilege Escalation
# ---------------------------------------------------------------------------

def _priv001(events):
    """EID 4728/4732/4756 — user added to domain/local admin group."""
    priv_groups = ("Domain Admins", "Enterprise Admins", "Administrators",
                   "Schema Admins", "Account Operators", "Backup Operators")
    matches = [
        e for e in _events_by_eid(events, "4728", "4732", "4756")
        if any(_desc_contains(e, g) for g in priv_groups)
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Account added to privileged group (EID 4728/4732/4756) — privilege escalation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv002(events):
    """EID 4720 + EID 4728 within 10 min — backdoor account creation."""
    from collections import deque
    create_evs = sorted(_events_by_eid(events, "4720"), key=lambda e: e.timestamp)
    add_evs    = sorted(_events_by_eid(events, "4728"), key=lambda e: e.timestamp)
    window     = timedelta(minutes=10)
    seen: set[str] = set()
    out = []
    for ce in create_evs:
        key = ce.user or ce.source_host or "__unknown__"
        if key in seen:
            continue
        for ae in add_evs:
            if ae.timestamp < ce.timestamp:
                continue
            if ae.timestamp - ce.timestamp > window:
                break
            seen.add(key)
            out.append({
                "entity": key,
                "event_ids": [x for x in [ce.id, ae.id] if x],
                "evidence": ["Account created then immediately added to group within 10 min — backdoor account"],
                "timestamp": ce.timestamp.isoformat(),
            })
            break
    return out


def _priv003(events):
    """EID 4672 SeDebugPrivilege to non-system account."""
    matches = [
        e for e in _events_by_eid(events, "4672")
        if _desc_contains(e, "SeDebugPrivilege")
        and e.user
        and not (e.user or "").endswith("$")
        and (e.user or "").lower() not in ("system", "local service", "network service")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["SeDebugPrivilege granted to non-system account (EID 4672) — privilege abuse"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv004(events):
    """EID 4674 — sensitive privilege use (SeTcbPrivilege, SeLoadDriver)."""
    matches = [
        e for e in _events_by_eid(events, "4673", "4674")
        if _desc_contains(e, "SeTcbPrivilege", "SeLoadDriverPrivilege",
                          "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Critical privilege used (SeTcbPrivilege/SeLoadDriverPrivilege) (EID 4673/4674)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv005(events):
    """EID 4103/4104 PowerShell — Invoke-TokenManipulation or token impersonation."""
    matches = [
        e for e in _events_by_eid(events, "4103", "4104")
        if _desc_contains(e, "Invoke-TokenManipulation", "ImpersonateNamedPipeClient",
                          "DuplicateToken", "SeImpersonatePrivilege", "Token")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["PowerShell token manipulation/impersonation (EID 4103/4104) — privilege escalation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv006(events):
    """EID 4984/4985 — domain policy modified (GPO change for persistence)."""
    matches = _events_by_eid(events, "5136", "5137")
    domain_policy = [
        e for e in matches
        if _desc_contains(e, "Group Policy", "GPC", "gpLink", "gPOptions", "cn=Policies")
    ]
    seen: set[str] = set()
    out = []
    for e in domain_policy:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Group Policy Object modified (EID 5136/5137) — domain policy manipulation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv007(events):
    """EID 4741 — computer account created (possible DC clone or rogue DC prep)."""
    matches = _events_by_eid(events, "4741")
    out = []
    for e in matches:
        out.append({
            "entity": e.user or e.source_host or "__unknown__",
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Computer account created (EID 4741) — possible rogue DC or Skeleton Key prep"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv008(events):
    """EID 4776 NTLM spike from non-DC (NTLM relay indicator)."""
    hits = _sliding_burst(
        [e for e in _events_by_eid(events, "4776")
         if "dc" not in (e.source_host or "").lower()],
        5, 15,
        lambda e: e.source_host or "__unknown__",
    )
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in events if e.event_id == "4776"
               and (e.source_host or "") == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} NTLM credential validations from non-DC {entity!r} in 5 min — possible NTLM relay"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 5 — Persistence & Backdoor
# ---------------------------------------------------------------------------

def _pers001(events):
    """EID 4720 — account created outside business hours."""
    matches = [
        e for e in _events_by_eid(events, "4720")
        if not (7 <= e.timestamp.hour < 19)
    ]
    out = []
    for e in matches:
        out.append({
            "entity": e.user or e.source_host or "__unknown__",
            "event_ids": [e.id] if e.id else [],
            "evidence": [f"Account created outside business hours at {e.timestamp.strftime('%H:%M')} (EID 4720)"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers002(events):
    """EID 4698 — scheduled task created with suspicious command."""
    matches = [
        e for e in _events_by_eid(events, "4698")
        if _desc_contains(e, "powershell", "cmd", "wscript", "cscript",
                          "mshta", "regsvr32", "rundll32", "-enc", "-encodedcommand")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Scheduled task with suspicious command interpreter (EID 4698) — persistence"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers003(events):
    """Sysmon EID 12/13 — Registry Run/RunOnce key modification."""
    matches = [
        e for e in _events_by_eid(events, "12", "13")
        if _desc_contains(e, "\\Run\\", "\\RunOnce\\", "CurrentVersion\\Run",
                          "Winlogon\\Userinit", "Winlogon\\Shell")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Registry Run key modified (Sysmon EID 12/13) — persistence via autorun"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers004(events):
    """EID 4719 — system audit policy changed (disabling logging = anti-forensics)."""
    matches = _events_by_eid(events, "4719")
    out = []
    for e in matches:
        out.append({
            "entity": e.user or e.source_host or "__unknown__",
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Audit policy changed (EID 4719) — possible log tampering or anti-forensics"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers005(events):
    """EID 1102 — security audit log cleared."""
    matches = _events_by_eid(events, "1102", "104")
    out = []
    for e in matches:
        out.append({
            "entity": e.user or e.source_host or "__unknown__",
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Security event log cleared (EID 1102/104) — evidence destruction"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers006(events):
    """EID 4657 — registry value modification in HKLM SAM/SECURITY (hash extraction prep)."""
    matches = [
        e for e in _events_by_eid(events, "4657")
        if _desc_contains(e, "HKLM\\SAM", "HKLM\\SECURITY", "LSA Secrets",
                          "\\CurrentControlSet\\Control\\Lsa")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["SAM/SECURITY registry key modified (EID 4657) — credential/hash extraction prep"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers007(events):
    """Sysmon EID 11 — file created in startup folder."""
    matches = [
        e for e in _events_by_eid(events, "11")
        if _desc_contains(e, "\\Startup\\", "\\Start Menu\\Programs\\Startup",
                          "shell:startup", "All Users\\Startup")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["File written to Startup folder (Sysmon EID 11) — persistence via startup"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers008(events):
    """EID 4886/4887 — AD CS certificate issued (ADCS abuse / persistence)."""
    matches = _events_by_eid(events, "4886", "4887")
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Certificate issued via AD CS (EID 4886/4887) — possible ADCS abuse for persistence"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 6 — Reconnaissance & Discovery
# ---------------------------------------------------------------------------

def _recon001(events):
    """Sysmon EID 1 — BloodHound/SharpHound LDAP reconnaissance."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "bloodhound", "sharphound", "SharpView",
                          "powerview", "Get-NetUser", "Get-NetGroup",
                          "Invoke-BloodHound")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["BloodHound/SharpHound/PowerView execution detected — AD domain enumeration"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _recon002(events):
    """EID 4661 — handle request on SAM object (local account enumeration)."""
    matches = [
        e for e in _events_by_eid(events, "4661")
        if _desc_contains(e, "SAM_USER", "SAM_DOMAIN", "S-1-5-21")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["SAM object handle request (EID 4661) — local account enumeration"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _recon003(events):
    """Sysmon EID 1 — nltest, net group 'domain', dsquery commands."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "nltest", "dsquery", "ldapsearch",
                          "net group \"domain", "net user /domain",
                          "gpresult", "whoami /groups")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Domain reconnaissance command executed (nltest/dsquery/net group) — AD discovery"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _recon004(events):
    """EID 4662 on CN=Schema — schema reconnaissance."""
    matches = [
        e for e in _events_by_eid(events, "4662")
        if _desc_contains(e, "CN=Schema", "schemaIDGUID", "attributeSchema")
        and not _desc_contains(e, "DS-Replication")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["AD schema read access (EID 4662 CN=Schema) — reconnaissance for ADCS/Skeleton Key"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _recon005(events):
    """EID 5156 / Sysmon EID 3 — outbound LDAP/LDAPS connection burst (bulk AD querying).

    EID 5156 fires only when 'Audit Filtering Platform Connection' is enabled.
    Sysmon EID 3 captures all network connections and is far more common in practice.
    Both are checked so neither telemetry source is missed.
    """
    def _is_ldap(e) -> bool:
        if _desc_contains(e, ":389", ":636", "LDAP", "ldap"):
            return True
        # Sysmon EID 3: DestinationPort lives in the extra dict (populated by parser)
        if e.extra:
            dport = str(e.extra.get("DestinationPort") or "")
            return dport in ("389", "636")
        return False

    ldap_events = [
        e for e in _events_by_eid(events, "5156", "3")
        if _is_ldap(e)
    ]
    hits = _sliding_burst(ldap_events, 5, 30, lambda e: e.source_host or "__unknown__")
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in ldap_events if (e.source_host or "") == entity]
        eid_label = "EID 5156/Sysmon EID 3"
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} outbound LDAP connections in 5 min from {entity!r} ({eid_label}) — bulk AD enumeration"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


def _recon006(events):
    """EID 4625 + username enumeration pattern (incremental names or many distinct users)."""
    fail_evs = _events_by_eid(events, "4625")
    distinct_users_per_host: dict[str, set[str]] = defaultdict(set)
    host_times: dict[str, list] = defaultdict(list)
    for e in fail_evs:
        host = e.source_host or "__unknown__"
        distinct_users_per_host[host].add(e.user or "__unknown__")
        host_times[host].append(e.timestamp)

    out = []
    seen: set[str] = set()
    for host, users in distinct_users_per_host.items():
        if len(users) >= 10 and host not in seen:
            seen.add(host)
            out.append({
                "entity": host,
                "event_ids": [],
                "evidence": [
                    f"{len(users)} distinct failed usernames from {host!r} — "
                    "possible username enumeration attack"
                ],
                "timestamp": min(host_times[host]).isoformat(),
            })
    return out


def _recon007(events):
    """Sysmon EID 1 — ping sweep or nmap/masscan discovery."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "nmap", "masscan", "ping -n 1", "arp-scan",
                          "Invoke-PortScan", "Test-NetConnection")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Network scan tool executed (nmap/masscan/arp-scan) — network discovery"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _recon008(events):
    """EID 4688 — net.exe commands querying domain trust/forest info."""
    matches = [
        e for e in _events_by_eid(events, "4688", "1")
        if _desc_contains(e, "nltest /domain_trusts", "net view /domain",
                          "netdom query trust", "Get-ADTrust")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Domain trust enumeration command (EID 4688) — inter-domain reconnaissance"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 1 additions — Kerberoasting (KERB-009..012)
# ---------------------------------------------------------------------------

def _kerb009(events):
    """EID 4624 Kerberos network logon preceded by NTLM auth from same user — Overpass-the-Hash."""
    ntlm_users = {
        e.user for e in _events_by_eid(events, "4776")
        if e.user and not (e.user or "").endswith("$")
    }
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "Kerberos", "LogonType: 3", "LogonType:3")
        and e.user in ntlm_users
        and not (e.user or "").endswith("$")
    ]
    seen: set[str] = set()
    out = []
    for e in matches[:10]:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Kerberos network logon following NTLM credential validation (EID 4776+4624) — Overpass-the-Hash"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb010(events):
    """EID 4769 — ≥10 distinct TGS requests from one user in 10 min (SPN enumeration)."""
    tgs_evs = _events_by_eid(events, "4769")
    spn_by_user: dict[str, list] = defaultdict(list)
    for e in tgs_evs:
        user = e.user or "__unknown__"
        spn_by_user[user].append(e.timestamp)
    out = []
    seen: set[str] = set()
    for user, times in spn_by_user.items():
        if len(times) < 10 or user in seen:
            continue
        times_sorted = sorted(times)
        window_hits = sum(
            1 for t in times_sorted
            if (t - times_sorted[0]).total_seconds() <= 600
        )
        if window_hits >= 10:
            seen.add(user)
            out.append({
                "entity": user,
                "event_ids": [],
                "evidence": [f"{window_hits} Kerberos TGS requests from {user!r} in 10 min — SPN enumeration for Kerberoasting target selection"],
                "timestamp": times_sorted[0].isoformat(),
            })
    return out


def _kerb011(events):
    """EID 4769 for krbtgt service — Silver Ticket / Golden Ticket use indicator."""
    matches = [
        e for e in _events_by_eid(events, "4769")
        if _desc_contains(e, "krbtgt", "KRBTGT")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["TGS requested for krbtgt service (EID 4769) — possible Golden Ticket or Silver Ticket use"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _kerb012(events):
    """EID 4768/4769 with mixed RC4+AES encryption from same user — encryption downgrade fingerprint."""
    enc_by_user: dict[str, set[str]] = defaultdict(set)
    evs_by_user: dict[str, list] = defaultdict(list)
    for e in _events_by_eid(events, "4768", "4769"):
        user = e.user or "__unknown__"
        desc = (e.description or "").lower()
        for enc in ("0x1", "0x3", "0x11", "0x12", "0x17", "0x18"):
            if enc in desc:
                enc_by_user[user].add(enc)
        evs_by_user[user].append(e)
    out = []
    for user, encs in enc_by_user.items():
        if "0x17" in encs and len(encs) >= 3:
            evs = evs_by_user[user]
            out.append({
                "entity": user,
                "event_ids": [e.id for e in evs[:5] if e.id],
                "evidence": [f"Mixed Kerberos encryption types ({', '.join(sorted(encs))}) from {user!r} — downgrade fingerprint indicates ticket manipulation"],
                "timestamp": evs[0].timestamp.isoformat() if evs else "",
            })
    return out


# ---------------------------------------------------------------------------
# Category 2 additions — DCSync / Credential Dump (DCS-008..010)
# ---------------------------------------------------------------------------

def _dcs008(events):
    """EID 5136/5137 on CN=AdminSDHolder — ACL backdoor on privileged container."""
    matches = [
        e for e in _events_by_eid(events, "5136", "5137")
        if _desc_contains(e, "AdminSDHolder", "CN=AdminSDHolder")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["AdminSDHolder object modified (EID 5136/5137) — ACL backdoor granting persistent control of privileged accounts"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs009(events):
    """EID 4765/4766 — SID History added to account (privilege inheritance)."""
    matches = _events_by_eid(events, "4765", "4766")
    out = []
    for e in matches:
        out.append({
            "entity": e.user or e.source_host or "__unknown__",
            "event_ids": [e.id] if e.id else [],
            "evidence": ["SID History attribute added to account (EID 4765/4766) — attacker inheriting domain admin privileges via SID injection"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _dcs010(events):
    """Sysmon EID 1/11 — NTDS.dit access or VSS shadow copy of AD database."""
    matches = [
        e for e in _events_by_eid(events, "1", "11")
        if _desc_contains(e, "ntds.dit", "ntds\\ntds.dit", "NTDS.DIT")
        or (_desc_contains(e, "vssadmin", "wmic shadowcopy", "diskshadow")
            and _desc_contains(e, "ntds", "active directory", "NTDS"))
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["NTDS.dit file access or VSS shadow copy containing AD database (Sysmon EID 1/11) — offline credential extraction from Domain Controller"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 3 additions — Lateral Movement (LAT-009..012)
# ---------------------------------------------------------------------------

def _lat009(events):
    """EID 4624 with NTLMv1 authentication — weak protocol relay risk."""
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "NTLMv1", "NTLM V1", "LM_and_NTLM", "LmCompatibilityLevel")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["NTLMv1 authentication observed (EID 4624) — weak protocol susceptible to NTLM relay and cracking"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat010(events):
    """Sysmon EID 19/20/21 — WMI event subscription with suspicious consumer."""
    matches = [
        e for e in _events_by_eid(events, "19", "20", "21")
        if _desc_contains(e, "powershell", "cmd", "wscript", "cscript",
                           "rundll32", "regsvr32", "-enc", "-nop",
                           "CommandLineEventConsumer", "ActiveScriptEventConsumer")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["WMI event subscription with suspicious consumer (Sysmon EID 19/20/21) — WMI persistence or lateral movement channel"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat011(events):
    """EID 4624 type 3 with DCOM/CLSID reference — DCOM lateral movement."""
    matches = [
        e for e in _events_by_eid(events, "4624")
        if _desc_contains(e, "LogonType: 3", "LogonType:3")
        and _desc_contains(e, "DCOM", "CLSID", "MMC20.Application",
                            "ShellWindows", "ShellBrowserWindow", "dcomcnfg")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["DCOM network logon type 3 with COM class reference (EID 4624) — DCOM lateral movement"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _lat012(events):
    """EID 4625 RemoteInteractive burst from same source — RDP brute force."""
    rdp_fails = [
        e for e in _events_by_eid(events, "4625")
        if _desc_contains(e, "LogonType: 10", "LogonType:10", "RemoteInteractive")
    ]
    hits = _sliding_burst(rdp_fails, 5, 10, lambda e: e.source_host or "__unknown__")
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in rdp_fails if (e.source_host or "") == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs[:10] if e.id],
            "evidence": [f"{count} failed RDP logon attempts from {entity!r} in 5 min — RDP brute force"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 4 additions — Privilege Escalation (PRIV-009..011)
# ---------------------------------------------------------------------------

def _priv009(events):
    """EID 4625 — >20 failures against ≥5 distinct accounts from same host (password spraying)."""
    fail_evs = _events_by_eid(events, "4625")
    hits = _sliding_burst(fail_evs, 30, 20, lambda e: e.source_host or "__unknown__")
    out = []
    seen: set[str] = set()
    for entity, count, peak_ts in hits:
        if entity in seen:
            continue
        evs = [e for e in fail_evs if (e.source_host or "") == entity]
        distinct_users = len({e.user for e in evs if e.user})
        if distinct_users >= 5:
            seen.add(entity)
            out.append({
                "entity": entity,
                "event_ids": [e.id for e in evs[:10] if e.id],
                "evidence": [
                    f"{count} failed logons against {distinct_users} distinct accounts from {entity!r} in 30 min — password spraying"
                ],
                "timestamp": peak_ts.isoformat(),
            })
    return out


def _priv010(events):
    """EID 4741 — computer account created by non-privileged user (MachineAccountQuota abuse)."""
    matches = [
        e for e in _events_by_eid(events, "4741")
        if e.user
        and not (e.user or "").endswith("$")
        and (e.user or "").upper() not in ("NT AUTHORITY\\SYSTEM", "SYSTEM", "ADMINISTRATOR")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Computer account created by non-privileged user (EID 4741) — MachineAccountQuota abuse for Kerberos relay attack prep"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _priv011(events):
    """Sysmon EID 1 — PrintSpooler/Potato exploit for SeImpersonatePrivilege abuse."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "PrintSpooler", "spoolsv", "JuicyPotato", "RoguePotato",
                           "SweetPotato", "GodPotato", "PrintNotify", "EfsPotato",
                           "SeImpersonatePrivilege", "ImpersonatePrivilege",
                           "SpoolSample", "PrintDemon")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["PrintSpooler/Potato exploit pattern (Sysmon EID 1) — SeImpersonatePrivilege abuse for SYSTEM escalation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 5 additions — Persistence (PERS-009..010)
# ---------------------------------------------------------------------------

def _pers009(events):
    """EID 4720 — account with machine-naming convention ($) created by human user."""
    matches = [
        e for e in _events_by_eid(events, "4720")
        if e.user
        and not (e.user or "").endswith("$")
        and "$" in (e.description or "")
        and "SYSTEM" not in (e.user or "").upper()
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Account with machine-account naming created by non-system user (EID 4720) — hidden backdoor service account"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


def _pers010(events):
    """Sysmon EID 1 — shadow copy deletion (ransomware / anti-forensics)."""
    matches = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "vssadmin", "wmic shadowcopy", "wbadmin", "diskshadow", "bcdedit")
        and _desc_contains(e, "delete", "resize", "shadowstorage", "recoveryenabled no",
                            "ignorefailures", "bootstatuspolicy")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Shadow copy / recovery deletion command (Sysmon EID 1) — anti-forensics or ransomware preparation"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 6 additions — Reconnaissance (RECON-009..011)
# ---------------------------------------------------------------------------

def _recon009(events):
    """EID 1644 burst — LDAP expensive search operations (bulk AD enumeration)."""
    hits = _sliding_burst(
        _events_by_eid(events, "1644"), 5, 10,
        lambda e: e.source_host or "__unknown__",
    )
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in events if e.event_id == "1644" and (e.source_host or "") == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} LDAP expensive search operations from {entity!r} in 5 min — bulk AD enumeration"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


def _recon010(events):
    """EID 4661 burst from same host — SAMR-based user enumeration."""
    hits = _sliding_burst(
        _events_by_eid(events, "4661"), 5, 15,
        lambda e: e.source_host or "__unknown__",
    )
    out = []
    for entity, count, peak_ts in hits:
        evs = [e for e in events if e.event_id == "4661" and (e.source_host or "") == entity]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs if e.id],
            "evidence": [f"{count} SAM object handle requests from {entity!r} in 5 min — SAMR user enumeration burst"],
            "timestamp": peak_ts.isoformat(),
        })
    return out


def _recon011(events):
    """EID 1/4688 — Domain Controller enumeration commands."""
    matches = [
        e for e in _events_by_eid(events, "1", "4688")
        if _desc_contains(e, "nltest /dclist", "nltest /dsgetdc",
                           "Get-ADDomain", "Get-ADForest", "netdom query dc",
                           "net group \"domain controllers\"")
    ]
    seen: set[str] = set()
    out = []
    for e in matches:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Domain Controller enumeration command (EID 1/4688) — pre-attack DC identification"],
            "timestamp": e.timestamp.isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Category 7 — Tool Detection (TOOL-001..003)
# ---------------------------------------------------------------------------

def _tool001(events):
    """Rubeus tool behavioral fingerprint — process name or combined Kerberos abuse pattern."""
    proc_hits = [e for e in _events_by_eid(events, "1") if _desc_contains(e, "Rubeus", "rubeus.exe")]
    seen: set[str] = set()
    out = []
    for e in proc_hits:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Rubeus.exe process image detected (Sysmon EID 1) — Kerberos attack toolkit"],
            "timestamp": e.timestamp.isoformat(),
        })
    # Behavioral: RC4 TGS burst + TGT requests from same user
    rc4_tgs_users = {
        e.user for e in _events_by_eid(events, "4769")
        if _desc_contains(e, "0x17", "RC4") and e.user
    }
    tgt_users = {e.user for e in _events_by_eid(events, "4768") if e.user}
    preauth_users = {e.user for e in _events_by_eid(events, "4771") if e.user}
    for entity in (rc4_tgs_users & tgt_users & preauth_users) - seen:
        if not entity:
            continue
        seen.add(entity)
        evs = [e for e in events if (e.user or "") == entity and e.event_id in ("4769", "4768", "4771")]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs[:5] if e.id],
            "evidence": [
                "Rubeus behavioral fingerprint: RC4 TGS + TGT + pre-auth failures from same user",
                "Pattern matches Rubeus kerberoast/asreproast combined workflow",
            ],
            "timestamp": evs[0].timestamp.isoformat() if evs else "",
        })
    return out


def _tool002(events):
    """Mimikatz tool behavioral fingerprint — process name or LSASS+SeTcbPrivilege combo."""
    direct = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "mimikatz", "mimilib", "sekurlsa", "lsadump", "kerberos::ptt")
    ]
    seen: set[str] = set()
    out = []
    for e in direct:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Mimikatz command or module name in process arguments (Sysmon EID 1)"],
            "timestamp": e.timestamp.isoformat(),
        })
    lsass_entities = {
        e.source_host or e.user
        for e in _events_by_eid(events, "10")
        if _desc_contains(e, "lsass")
    }
    setcb_entities = {
        e.source_host or e.user
        for e in _events_by_eid(events, "4673")
        if _desc_contains(e, "SeTcbPrivilege")
    }
    for entity in (lsass_entities & setcb_entities) - seen:
        if not entity:
            continue
        seen.add(entity)
        evs = [e for e in events
               if (e.source_host or e.user or "") == entity and e.event_id in ("10", "4673")]
        out.append({
            "entity": entity,
            "event_ids": [e.id for e in evs[:5] if e.id],
            "evidence": [
                "LSASS process access with credential-read rights (Sysmon EID 10)",
                "SeTcbPrivilege elevation from same entity (EID 4673)",
                "Combined pattern consistent with mimikatz sekurlsa::logonpasswords",
            ],
            "timestamp": evs[0].timestamp.isoformat() if evs else "",
        })
    return out


def _tool003(events):
    """Impacket / CrackMapExec behavioral fingerprint — process names or NTLM+SMB burst."""
    direct = [
        e for e in _events_by_eid(events, "1")
        if _desc_contains(e, "impacket", "secretsdump", "smbexec.py", "wmiexec.py",
                           "psexec.py", "getuserspns", "getnpusers", "lookupsid",
                           "crackmapexec", "cme.exe")
    ]
    seen: set[str] = set()
    out = []
    for e in direct:
        entity = e.user or e.source_host or "__unknown__"
        if entity in seen:
            continue
        seen.add(entity)
        out.append({
            "entity": entity,
            "event_ids": [e.id] if e.id else [],
            "evidence": ["Impacket/CrackMapExec script or binary name detected in process arguments (Sysmon EID 1)"],
            "timestamp": e.timestamp.isoformat(),
        })
    # Behavioral: high NTLM auth + admin share burst from same host
    ntlm_count: dict[str, int] = defaultdict(int)
    for e in _events_by_eid(events, "4776"):
        ntlm_count[e.source_host or "__unknown__"] += 1
    smb_count: dict[str, int] = defaultdict(int)
    for e in _events_by_eid(events, "5140"):
        if _desc_contains(e, "ADMIN$", "C$", "IPC$"):
            smb_count[e.source_host or e.user or "__unknown__"] += 1
    for src in set(ntlm_count) & set(smb_count) - seen:
        if not src or ntlm_count[src] < 10 or smb_count[src] < 5:
            continue
        seen.add(src)
        out.append({
            "entity": src,
            "event_ids": [],
            "evidence": [
                f"{ntlm_count[src]} NTLM credential validations (EID 4776)",
                f"{smb_count[src]} admin share accesses (EID 5140)",
                "Combined pattern consistent with CrackMapExec SMB module credential spray",
            ],
            "timestamp": "",
        })
    return out


# ---------------------------------------------------------------------------
# Category 8 — Exfiltration (network-flow based)
# ---------------------------------------------------------------------------

def _net001(events):
    """Large bytes_out to non-RFC1918 IP from any host (firewall / PCAP events).

    Reads bytes_out from the extra dict populated by parse_network_csv /
    parse_timesketch_jsonl.  Aggregates per source_host; flags hosts that
    send ≥50 MB outbound to external IPs across all observed flows.
    """
    import ipaddress

    def _is_external(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback
                        or addr.is_link_local or addr.is_multicast)
        except ValueError:
            return False

    bytes_by_host: dict[str, int] = defaultdict(int)
    evs_by_host:   dict[str, list] = defaultdict(list)

    for e in events:
        if not e.extra:
            continue
        bytes_out = e.extra.get("bytes_out")
        dst_ip    = str(e.extra.get("dst_ip") or "")
        if not bytes_out or not dst_ip or not _is_external(dst_ip):
            continue
        host = e.source_host or "__unknown__"
        try:
            bytes_by_host[host] += int(bytes_out)
            evs_by_host[host].append(e)
        except (ValueError, TypeError):
            continue

    THRESHOLD = 50_000_000  # 50 MB
    out = []
    for host, total in bytes_by_host.items():
        if total < THRESHOLD:
            continue
        evs = evs_by_host[host]
        mb  = total // 1_000_000
        out.append({
            "entity":    host,
            "event_ids": [e.id for e in evs[:10] if e.id],
            "evidence":  [f"{mb} MB outbound to external IP(s) from {host!r} — potential data exfiltration"],
            "timestamp": min(e.timestamp for e in evs).isoformat(),
        })
    return out


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

AD_RULES: list[ADRule] = [
    # ── Kerberoasting ─────────────────────────────────────────────────────────
    ADRule("KERB-001", "Kerberoasting Ticket Spike",      "Kerberoasting",   "high",     "T1558.003", "Credential Access", "high",   _kerb001),
    ADRule("KERB-002", "RC4 TGT Downgrade",               "Kerberoasting",   "high",     "T1558.003", "Credential Access", "medium", _kerb002),
    ADRule("KERB-003", "AS-REP Pre-Auth Failure Burst",   "Kerberoasting",   "medium",   "T1558.004", "Credential Access", "medium", _kerb003),
    ADRule("KERB-004", "Kerberoasting Target Selection",  "Kerberoasting",   "high",     "T1558.003", "Credential Access", "high",   _kerb004),
    ADRule("KERB-005", "AS-REP Roasting",                 "Kerberoasting",   "high",     "T1558.004", "Credential Access", "high",   _kerb005),
    ADRule("KERB-006", "External Kerberos Request",       "Kerberoasting",   "medium",   "T1558.003", "Credential Access", "low",    _kerb006),
    ADRule("KERB-007", "Golden Ticket Flag Pattern",      "Kerberoasting",   "critical", "T1558.001", "Credential Access", "medium", _kerb007),
    ADRule("KERB-008", "Pass-the-Ticket",                 "Kerberoasting",   "high",     "T1550.003", "Lateral Movement",  "medium", _kerb008),
    # ── DCSync / Credential Dump ───────────────────────────────────────────────
    ADRule("DCS-001",  "DCSync Replication Request",      "DCSync",          "critical", "T1003.006", "Credential Access", "high",   _dcs001),
    ADRule("DCS-002",  "DCSync From Workstation",         "DCSync",          "critical", "T1003.006", "Credential Access", "high",   _dcs002),
    ADRule("DCS-003",  "Mimikatz SeTcb Privilege",        "DCSync",          "critical", "T1003.001", "Credential Access", "high",   _dcs003),
    ADRule("DCS-004",  "Pass-the-Hash NewCredentials",    "DCSync",          "high",     "T1550.002", "Lateral Movement",  "medium", _dcs004),
    ADRule("DCS-005",  "Explicit Cred Dump Tool",         "DCSync",          "high",     "T1003.001", "Credential Access", "high",   _dcs005),
    ADRule("DCS-006",  "LSASS Process Access",            "DCSync",          "critical", "T1003.001", "Credential Access", "high",   _dcs006),
    ADRule("DCS-007",  "comsvcs MiniDump LSASS",          "DCSync",          "critical", "T1003.001", "Credential Access", "high",   _dcs007),
    # ── Lateral Movement ──────────────────────────────────────────────────────
    ADRule("LAT-001",  "Explicit Cred Remote Access",     "Lateral Movement","high",     "T1550.002", "Lateral Movement",  "medium", _lat001),
    ADRule("LAT-002",  "Admin Share SMB Access",          "Lateral Movement","high",     "T1021.002", "Lateral Movement",  "high",   _lat002),
    ADRule("LAT-003",  "RDP Remote Login",                "Lateral Movement","medium",   "T1021.001", "Lateral Movement",  "medium", _lat003),
    ADRule("LAT-004",  "WMI Remote Execution",            "Lateral Movement","high",     "T1047",     "Execution",         "high",   _lat004),
    ADRule("LAT-005",  "PsExec/SMBExec Execution",        "Lateral Movement","high",     "T1021.002", "Lateral Movement",  "high",   _lat005),
    ADRule("LAT-006",  "Admin Network Logon",             "Lateral Movement","medium",   "T1021.002", "Lateral Movement",  "low",    _lat006),
    ADRule("LAT-007",  "Remote Service Installation",     "Lateral Movement","high",     "T1021.002", "Lateral Movement",  "high",   _lat007),
    ADRule("LAT-008",  "Service From Writable Path",      "Lateral Movement","medium",   "T1543.003", "Persistence",       "medium", _lat008),
    # ── Privilege Escalation ──────────────────────────────────────────────────
    ADRule("PRIV-001", "Add to Privileged Group",         "Privilege Escalation","high", "T1098",     "Persistence",       "high",   _priv001),
    ADRule("PRIV-002", "Backdoor Account Creation",       "Privilege Escalation","critical","T1136.001","Persistence",    "high",   _priv002),
    ADRule("PRIV-003", "SeDebugPrivilege Grant",          "Privilege Escalation","high", "T1134",     "Privilege Escalation","high", _priv003),
    ADRule("PRIV-004", "Critical Privilege Invocation",   "Privilege Escalation","critical","T1134",  "Privilege Escalation","high", _priv004),
    ADRule("PRIV-005", "Token Manipulation via PS",       "Privilege Escalation","high", "T1134.001", "Privilege Escalation","high", _priv005),
    ADRule("PRIV-006", "GPO Domain Policy Modified",      "Privilege Escalation","high", "T1484.001", "Defense Evasion",   "high",   _priv006),
    ADRule("PRIV-007", "Rogue Computer Account Created",  "Privilege Escalation","high", "T1207",     "Defense Evasion",   "medium", _priv007),
    ADRule("PRIV-008", "NTLM Relay Spike",                "Privilege Escalation","high", "T1557.001", "Credential Access", "high",   _priv008),
    # ── Persistence / Backdoor ────────────────────────────────────────────────
    ADRule("PERS-001", "Off-Hours Account Creation",      "Persistence",     "medium",   "T1136.001", "Persistence",       "medium", _pers001),
    ADRule("PERS-002", "Suspicious Scheduled Task",       "Persistence",     "high",     "T1053.005", "Persistence",       "high",   _pers002),
    ADRule("PERS-003", "Registry Autorun Modification",   "Persistence",     "medium",   "T1547.001", "Persistence",       "medium", _pers003),
    ADRule("PERS-004", "Audit Policy Disabled",           "Persistence",     "high",     "T1562.002", "Defense Evasion",   "high",   _pers004),
    ADRule("PERS-005", "Event Log Cleared",               "Persistence",     "high",     "T1070.001", "Defense Evasion",   "high",   _pers005),
    ADRule("PERS-006", "SAM/SECURITY Registry Access",    "Persistence",     "critical", "T1003.002", "Credential Access", "high",   _pers006),
    ADRule("PERS-007", "Startup Folder File Drop",        "Persistence",     "high",     "T1547.001", "Persistence",       "medium", _pers007),
    ADRule("PERS-008", "AD CS Certificate Abuse",         "Persistence",     "high",     "T1649",     "Credential Access", "medium", _pers008),
    # ── Reconnaissance ────────────────────────────────────────────────────────
    ADRule("RECON-001","BloodHound/SharpHound Exec",      "Reconnaissance",  "high",     "T1482",     "Discovery",         "high",   _recon001),
    ADRule("RECON-002","SAM Object Enumeration",          "Reconnaissance",  "medium",   "T1087.001", "Discovery",         "medium", _recon002),
    ADRule("RECON-003","Domain Recon Commands",           "Reconnaissance",  "medium",   "T1482",     "Discovery",         "high",   _recon003),
    ADRule("RECON-004","AD Schema Read",                  "Reconnaissance",  "low",      "T1482",     "Discovery",         "medium", _recon004),
    ADRule("RECON-005","Bulk LDAP Enumeration",           "Reconnaissance",  "medium",   "T1069.002", "Discovery",         "medium", _recon005),
    ADRule("RECON-006","Username Enumeration",            "Reconnaissance",  "medium",   "T1087.002", "Discovery",         "medium", _recon006),
    ADRule("RECON-007","Network Scan Tool",               "Reconnaissance",  "medium",   "T1046",     "Discovery",         "high",   _recon007),
    ADRule("RECON-008","Domain Trust Enumeration",        "Reconnaissance",  "low",      "T1482",     "Discovery",         "medium", _recon008),
    # ── Kerberoasting additions ───────────────────────────────────────────────
    ADRule("KERB-009", "Overpass-the-Hash",               "Kerberoasting",   "high",     "T1550.003", "Lateral Movement",  "high",   _kerb009),
    ADRule("KERB-010", "SPN Enumeration Burst",           "Kerberoasting",   "medium",   "T1558.003", "Credential Access", "medium", _kerb010),
    ADRule("KERB-011", "krbtgt TGS Request",              "Kerberoasting",   "critical", "T1558.001", "Credential Access", "high",   _kerb011),
    ADRule("KERB-012", "Mixed Kerberos Encryption",       "Kerberoasting",   "medium",   "T1558.003", "Credential Access", "medium", _kerb012),
    # ── DCSync additions ──────────────────────────────────────────────────────
    ADRule("DCS-008",  "AdminSDHolder Modification",      "DCSync",          "critical", "T1222.001", "Defense Evasion",   "high",   _dcs008),
    ADRule("DCS-009",  "SID History Injection",           "DCSync",          "critical", "T1134.005", "Privilege Escalation","high", _dcs009),
    ADRule("DCS-010",  "NTDS.dit Extraction",             "DCSync",          "critical", "T1003.003", "Credential Access", "high",   _dcs010),
    # ── Lateral Movement additions ────────────────────────────────────────────
    ADRule("LAT-009",  "NTLMv1 Authentication",           "Lateral Movement","high",     "T1557.001", "Credential Access", "medium", _lat009),
    ADRule("LAT-010",  "WMI Event Subscription",          "Lateral Movement","high",     "T1546.003", "Privilege Escalation","high", _lat010),
    ADRule("LAT-011",  "DCOM Lateral Movement",           "Lateral Movement","high",     "T1021.003", "Lateral Movement",  "medium", _lat011),
    ADRule("LAT-012",  "RDP Brute Force",                 "Lateral Movement","high",     "T1110.003", "Credential Access", "high",   _lat012),
    # ── Privilege Escalation additions ───────────────────────────────────────
    ADRule("PRIV-009", "Password Spraying",               "Privilege Escalation","high", "T1110.003", "Credential Access", "high",   _priv009),
    ADRule("PRIV-010", "MachineAccountQuota Abuse",       "Privilege Escalation","high", "T1136.002", "Persistence",       "medium", _priv010),
    ADRule("PRIV-011", "SeImpersonatePrivilege Abuse",    "Privilege Escalation","critical","T1134.001","Privilege Escalation","high",_priv011),
    # ── Persistence additions ─────────────────────────────────────────────────
    ADRule("PERS-009", "Hidden Machine Account",          "Persistence",     "high",     "T1136.001", "Persistence",       "medium", _pers009),
    ADRule("PERS-010", "Shadow Copy Deletion",            "Persistence",     "critical", "T1490",     "Impact",            "high",   _pers010),
    # ── Reconnaissance additions ──────────────────────────────────────────────
    ADRule("RECON-009","LDAP Expensive Query Burst",      "Reconnaissance",  "medium",   "T1069.002", "Discovery",         "medium", _recon009),
    ADRule("RECON-010","SAMR Enumeration Burst",          "Reconnaissance",  "medium",   "T1087.001", "Discovery",         "medium", _recon010),
    ADRule("RECON-011","Domain Controller Enumeration",   "Reconnaissance",  "low",      "T1018",     "Discovery",         "medium", _recon011),
    # ── Tool Detection ────────────────────────────────────────────────────────
    ADRule("TOOL-001", "Rubeus Tool Signature",           "Tool Detection",  "critical", "T1558.003", "Credential Access", "high",   _tool001),
    ADRule("TOOL-002", "Mimikatz Tool Signature",         "Tool Detection",  "critical", "T1003.001", "Credential Access", "high",   _tool002),
    ADRule("TOOL-003", "Impacket/CME Tool Signature",     "Tool Detection",  "high",     "T1557.001", "Credential Access", "medium", _tool003),
    # ── Exfiltration ──────────────────────────────────────────────────────────
    ADRule("NET-001",  "Large Outbound Data Transfer",    "Exfiltration",    "high",     "T1041",     "Exfiltration",      "medium", _net001),
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------

def run_ad_rules(events: list[ForensicEvent]) -> dict:
    """
    Evaluate all AD_RULES against the event list.
    Returns a dict matching the ADRulesResult schema.
    """
    # Build event-id → source_host index so chain correlator can link host entities
    # (e.g. RECON-005 fires on a hostname) to user entities (e.g. DCS-001 fires on a
    # username) when both were active on the same machine in the same time window.
    event_host_map: dict[int, str] = {
        e.id: e.source_host
        for e in events
        if e.id is not None and e.source_host and e.source_host != "UNKNOWN-HOST"
    }

    detections = []
    for rule in AD_RULES:
        try:
            hits = rule.evaluate(events)
        except Exception:
            continue
        for hit in hits:
            # Resolve source_host from the triggering event IDs when available
            source_host = next(
                (event_host_map[eid] for eid in (hit.get("event_ids") or [])
                 if eid in event_host_map),
                None,
            )
            detections.append({
                "rule_id":      rule.rule_id,
                "rule_name":    rule.rule_name,
                "category":     rule.category,
                "severity":     rule.severity,
                "mitre_id":     rule.mitre_id,
                "mitre_tactic": rule.mitre_tactic,
                "confidence":   rule.confidence,
                "entity":       hit.get("entity", "unknown"),
                "event_ids":    hit.get("event_ids", []),
                "evidence":     hit.get("evidence", []),
                "timestamp":    hit.get("timestamp", events[0].timestamp.isoformat() if events else ""),
                "source_host":  source_host or "",
            })

    detections.sort(key=lambda d: (_SEV_ORDER.get(d["severity"], 4), d["timestamp"]))

    categories_hit = sorted({d["category"] for d in detections})
    mitre_ids      = sorted({d["mitre_id"] for d in detections})
    highest = detections[0]["severity"] if detections else "none"

    return {
        "total_events_analyzed": len(events),
        "detections":            detections,
        "detection_count":       len(detections),
        "categories_hit":        categories_hit,
        "highest_severity":      highest,
        "mitre_ids":             mitre_ids,
    }

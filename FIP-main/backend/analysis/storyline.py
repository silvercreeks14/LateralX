"""
Attack Storyline Generation — Phase 3.

Correlates events across all log sources to produce a structured attack storyline:
  - ATT&CK-mapped attack steps in chronological order
  - Lateral movement path reconstruction (from_host → to_host with method)
  - Blast radius: compromised hosts/users, accessed resources, persistence mechanisms
  - Threat actor profile heuristics

The build_storyline() function is deterministic and requires no LLM — it operates
entirely on structured ForensicEvent fields and pattern matching.

Session model
─────────────
Each actor is identified by (user, source_host).  A session stays "open" for an
actor as long as consecutive events from that actor arrive within
INACTIVITY_TIMEOUT_SECONDS of each other.  Once the gap exceeds the timeout, a
new session is opened for the same actor.

This single-linkage temporal clustering correctly handles "low and slow" attacks:
  - A 13-minute pause between lateral movement and execution → same session ✓
  - A 59-minute pause mid-chain → same session ✓
  - A 2-hour gap (attacker re-enters separately) → new session, new chain ✓

Deduplication applies per (actor, session) pair, not globally, so the same
technique can appear in multiple distinct sessions of the same actor.
"""

import re
from collections import defaultdict
from datetime import timedelta
from backend.schema import ForensicEvent

# ── Sliding inactivity timeout ─────────────────────────────────────────────────
#
# If an actor (user, host) is silent for longer than this, any subsequent event
# from that actor opens a new session rather than extending the existing one.
# 60 minutes is chosen to accommodate "hands-on-keyboard" dwell times observed in
# real-world intrusions while still separating distinct re-entry episodes.

INACTIVITY_TIMEOUT_SECONDS: int = 3600  # 60 minutes

# ── MITRE ATT&CK tactic progression ───────────────────────────────────────────

TACTIC_ORDER = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

# ── Event ID → ATT&CK (highest-signal mapping; patterns take priority) ────────

_EID_TECHNIQUE: dict[str, tuple[str, str, str]] = {
    # (technique_id, name, tactic)
    # 4688/4624/4663 are handled conditionally in _classify() — not here.
    '4698': ('T1053.005', 'Scheduled Task',               'Persistence'),
    '7045': ('T1543.003', 'Windows Service',               'Persistence'),
    '4657': ('T1547.001', 'Registry Run Keys',             'Persistence'),
    '4662': ('T1003.006', 'DCSync',                        'Credential Access'),
    '4625': ('T1110',     'Brute Force',                   'Credential Access'),
    '4672': ('T1134',     'Access Token Manipulation',     'Privilege Escalation'),
    '4769': ('T1558.003', 'Kerberoasting',                 'Credential Access'),
    '4768': ('T1558.004', 'AS-REP Roasting',               'Credential Access'),
    '5140': ('T1021.002', 'SMB/Windows Admin Shares',      'Lateral Movement'),
    '5145': ('T1021.002', 'SMB/Windows Admin Shares',      'Lateral Movement'),
    '1102': ('T1070.001', 'Clear Windows Event Logs',      'Defense Evasion'),
}

# Pattern-based classification (checked first; more specific than EID mapping)
_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r'\bwinword\b.*cmd|word.*spawns|macro.*delivery|\.docm\b', re.I),
        'T1566.001', 'Spearphishing Attachment', 'Initial Access'),
    (re.compile(r'\bmimikatz\b|\bsekurlsa\b|\blsadump::(?:sam|dcsync|lsa)\b', re.I),
        'T1003', 'OS Credential Dumping', 'Credential Access'),
    (re.compile(r'\bdcsync\b|DS-Replication|1131f6aa|1131f6ab', re.I),
        'T1003.006', 'DCSync', 'Credential Access'),
    (re.compile(r'\bprocdump\b|comsvcs.*minidump|lsass.*dump|ntds\.dit', re.I),
        'T1003', 'OS Credential Dumping', 'Credential Access'),
    (re.compile(r'\bgolden.*ticket\b|\bkrbtgt\b.*hash|lsadump::golden|\bptt\b', re.I),
        'T1558.001', 'Golden Ticket', 'Credential Access'),
    (re.compile(r'\bkerberoast\b|etype.*0x17|rc4.*kerberoast|GetUserSPNs', re.I),
        'T1558.003', 'Kerberoasting', 'Credential Access'),
    (re.compile(r'\bpowershell\b.*-e(?:nc\b|ncodedcommand)|iex.*downloadstring|invoke-expression', re.I),
        'T1059.001', 'PowerShell', 'Execution'),
    (re.compile(r'\bpowerview\b|Get-DomainUser|Get-DomainGroupMember|Find-LocalAdminAccess', re.I),
        'T1069.002', 'Domain Groups Discovery', 'Discovery'),
    (re.compile(r'\bbloodhound\b|\bsharphound\b|Invoke-BloodHound|CollectionMethod', re.I),
        'T1069.002', 'Domain Groups Discovery', 'Discovery'),
    (re.compile(r'\bnmap\b|\bport.*scan\b|\bnetwork.*scan', re.I),
        'T1046', 'Network Service Discovery', 'Discovery'),
    (re.compile(r'\bldapdomaindump\b|\badrecon\b|ldap.*dump', re.I),
        'T1087.002', 'Domain Account Enumeration', 'Discovery'),
    (re.compile(r'\bnet\s+user\b.*domain|net\s+group.*domain admins|nltest.*dclist', re.I),
        'T1087.002', 'Domain Account', 'Discovery'),
    (re.compile(r'\bpsexec\b|\bpsexesvc\b|\bwmiexec\b|\bsmbexec\b|\batexec\b|\bdcomexec\b', re.I),
        'T1021.002', 'SMB/Windows Admin Shares', 'Lateral Movement'),
    (re.compile(r'\brdp\b.*lateral|mstsc.*lateral|logon type.*10\b|type\s+10\b', re.I),
        'T1021.001', 'Remote Desktop Protocol', 'Lateral Movement'),
    (re.compile(r'\bfodhelper\b|ms-settings.*shell.*open.*command|uac.*bypass|bypass.*uac', re.I),
        'T1548.002', 'Bypass User Account Control', 'Privilege Escalation'),
    (re.compile(r'\bprintnightmare\b|cve-2021-34527|spoolsv.*cmd|print spooler', re.I),
        'T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation'),
    (re.compile(r'\bjuicypotato\b|\brottenpotato\b|\bsweetpotato\b|seimpersonatepriv', re.I),
        'T1134.002', 'Create Process with Token', 'Privilege Escalation'),
    (re.compile(r'\balwaysinstallelevated\b|malicious.*msi|msi.*elevated', re.I),
        'T1548.002', 'Bypass User Account Control', 'Privilege Escalation'),
    (re.compile(r'\bunquoted.*service\b|service.*path.*unquoted', re.I),
        'T1574.009', 'Unquoted Service Path', 'Privilege Escalation'),
    (re.compile(r'\bwmi.*(?:event)?filter\b|\b__eventfilter\b|commandlineeventconsumer', re.I),
        'T1546.003', 'WMI Event Subscription', 'Persistence'),
    (re.compile(r'\bbitsadmin\b|bits.*job', re.I),
        'T1197', 'BITS Jobs', 'Persistence'),
    (re.compile(r'\bsethc\b|image file execution options|accessibility.*debug', re.I),
        'T1546.008', 'Accessibility Features', 'Persistence'),
    (re.compile(r'inprocserver32|com.*hijack|clsid.*dll', re.I),
        'T1546.015', 'COM Hijacking', 'Persistence'),
    (re.compile(r'\bauthorized_keys\b|ssh.*backdoor|rsa.*pub.*key', re.I),
        'T1098.004', 'SSH Authorized Keys', 'Persistence'),
    (re.compile(r'winlogon.*userinitmpr|logon.*script|logon\.bat', re.I),
        'T1037.001', 'Logon Script', 'Persistence'),
    (re.compile(r'\bmsse-\d+|createremotethread|reflective.*inject|pipe.*created', re.I),
        'T1055', 'Process Injection', 'Defense Evasion'),
    (re.compile(r'\bamsi\b|amsiutils|invoke-obfuscat|etw.*bypass|amsi\.dll', re.I),
        'T1562.001', 'Disable or Modify Tools', 'Defense Evasion'),
    (re.compile(r'\bwevtutil\s+cl\b|event.*log.*cleared|clearev', re.I),
        'T1070.001', 'Clear Windows Event Logs', 'Defense Evasion'),
    (re.compile(r'\brobocopy\b|staging.*directory|data.*staging', re.I),
        'T1074', 'Data Staged', 'Collection'),
    (re.compile(r'\bvssadmin\b.*delete|delete.*shadow|net\s+stop\s+vss', re.I),
        'T1490', 'Inhibit System Recovery', 'Impact'),
    (re.compile(r'\biam\s+create.user\b|createuser.*svc|attachuserpolicy.*administrator', re.I),
        'T1136.003', 'Cloud Account', 'Persistence'),
]

# ── Conditional guards for high-noise Event IDs ────────────────────────────────
#
# These regexes gate the three Event IDs that produce the most false positives
# when mapped unconditionally:
#
#   4688 (Process Creation) → T1059 only when a real shell or LOLBin is present.
#        chrome.exe / excel.exe / outlook.exe launching normally must be ignored.
#
#   4624 (Logon Success)    → T1078 only for Network (type 3) or NewCredentials
#        (type 9) logons.  Interactive (2) and Service (5) logons are local ops.
#
#   4663 (Object Access)    → T1005 only when the accessing process is not a
#        known Office app, OR the path leads to a staging/temp directory.

_SHELL_LOLBIN_RE = re.compile(
    r'\b(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|'
    r'certutil|msiexec|bitsadmin|wmic|forfiles|pcalua|installutil|cmstp|'
    r'msbuild|regasm|regsvcs|bash|sh|zsh|python|python3|ruby|perl|node)\b',
    re.IGNORECASE,
)

_STAGING_PATH_RE = re.compile(
    r'\\(?:temp|tmp|staging|exfil|transfer)\\', re.IGNORECASE,
)

_OFFICE_PROC_RE = re.compile(
    r'\b(?:excel|winword|powerpnt|outlook|onenote|access|publisher|visio)\.exe\b',
    re.IGNORECASE,
)


def _classify(e: ForensicEvent) -> tuple[str, str, str] | None:
    """Return (technique_id, name, tactic) — pattern check first, conditional EID fallback."""
    desc = (e.description or '').lower()

    for pat, tid, name, tactic in _PATTERNS:
        if pat.search(desc):
            return tid, name, tactic

    eid = e.event_id or ''

    if eid == '4688':
        # T1059 only when the process name or command line contains a shell or LOLBin.
        # Standard GUI apps (Chrome, Office, Explorer) return None.
        if _SHELL_LOLBIN_RE.search(desc):
            return ('T1059', 'Command and Scripting Interpreter', 'Execution')
        return None

    if eid == '4624':
        # T1078 lateral movement only on Network (3) or NewCredentials (9) logons.
        # Interactive (2), Service (5), Unlock (7) etc. are normal local operations.
        m = re.search(r'logon type:\s*(\d+)', desc)
        if m and m.group(1) in ('3', '9'):
            return ('T1078', 'Valid Accounts', 'Lateral Movement')
        return None

    if eid == '4663':
        # T1005 is skipped when an Office app reads its own files outside staging dirs.
        if _OFFICE_PROC_RE.search(desc) and not _STAGING_PATH_RE.search(desc):
            return None
        return ('T1005', 'Data from Local System', 'Collection')

    return _EID_TECHNIQUE.get(eid)


def _actor_key(e: ForensicEvent) -> tuple[str, str]:
    """
    Stable identity for an attack actor: (normalized_user, source_host).

    Using both user and host means a different user on the same host,
    or the same user pivoting to a new host, are tracked as distinct actors.
    This correctly models credential-based lateral movement where the attacker
    may use different accounts at different stages.
    """
    return ((e.user or 'unknown').lower(), e.source_host or 'unknown')


def _is_lateral(e: ForensicEvent) -> bool:
    """Return True when this event represents lateral movement."""
    desc = (e.description or '').lower()
    if e.event_id in ('5140', '5145'):
        return True
    if e.event_id == '4624':
        # Only network logons (type 3) and remote interactive (type 10) count
        if re.search(r'logon type:\s*(?:3|10)\b|type\s+(?:3|10)\b|network logon', desc, re.I):
            return True
    if re.search(r'\bpsexec\b|\bpsexesvc\b|\bwmiexec\b|\bsmbexec\b|\batexec\b|\bdcomexec\b', desc, re.I):
        return True
    return False


def _extract_src(e: ForensicEvent) -> str | None:
    m = re.search(
        r'Source(?:\s+Network)?\s+Address:\s*([^\s\r\n\-]+)',
        e.description or '', re.IGNORECASE,
    )
    if m and m.group(1) not in ('-', '', '::1', '127.0.0.1'):
        return m.group(1)
    return None


def _extract_resource(desc: str) -> str | None:
    m = re.search(
        r'(?:Object Name|Share Name):\s*([^\r\n]+?)(?=\s*(?:Process Name:|Accesses:|Access:|$))',
        desc, re.IGNORECASE,
    )
    if m:
        resource = m.group(1).strip().rstrip('.').strip()[:100]
        if resource and resource not in ('', '-'):
            return resource
    return None


# ── Main builder ───────────────────────────────────────────────────────────────

def build_storyline(events: list[ForensicEvent]) -> dict:
    """
    Build a structured attack storyline from a list of ForensicEvents.

    Uses a sliding inactivity timeout (INACTIVITY_TIMEOUT_SECONDS) to group
    events from the same actor into coherent sessions.  Deduplication of
    attack steps is scoped to each (actor, session) pair rather than being
    global, so:

      - Repeated technique use by the same actor within one session is
        collapsed (prevents noise from repeated logons, etc.).
      - The same technique appearing in a distinct later session (after a long
        pause) is recorded as a new step, correctly surfacing re-entry.

    Returns a plain dict matching AttackStoryline schema.
    """
    if not events:
        return _empty()

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    t0   = sorted_events[0].timestamp
    tend = sorted_events[-1].timestamp
    duration_minutes = (tend - t0).total_seconds() / 60

    # ── Session-aware attack step collection ───────────────────────────────────
    #
    # State per actor:
    #   step_actor_last[actor]  → timestamp of the most recent classified event
    #   step_actor_sid[actor]   → current session index (increments on timeout)
    # State per (actor, session):
    #   step_seen[(actor, sid)] → set of (technique_id, host) already recorded
    #
    # Algorithm (O(n) single pass):
    #   For each classified event e:
    #     1. Compute gap = e.timestamp - step_actor_last[actor]
    #     2. If gap > INACTIVITY_TIMEOUT_SECONDS → new session (sid += 1)
    #     3. Dedup check: if (tid, host) already in step_seen[(actor, sid)] → skip
    #     4. Otherwise → record step, add to step_seen

    step_actor_last: dict[tuple, object] = {}
    step_actor_sid:  dict[tuple, int]    = {}
    step_seen:       dict[tuple, set]    = defaultdict(set)

    attack_steps: list[dict] = []
    step_num = 0

    for e in sorted_events:
        cls = _classify(e)
        if cls is None:
            continue
        tid, tname, tactic = cls

        actor  = _actor_key(e)
        last_t = step_actor_last.get(actor)
        gap_sec = (
            (e.timestamp - last_t).total_seconds()
            if last_t is not None else float('inf')
        )

        if gap_sec > INACTIVITY_TIMEOUT_SECONDS:
            step_actor_sid[actor] = step_actor_sid.get(actor, -1) + 1

        sid = step_actor_sid.get(actor, 0)
        step_actor_last[actor] = e.timestamp

        session_key = (actor, sid)
        step_sig    = (tid, e.source_host)
        if step_sig in step_seen[session_key]:
            continue
        step_seen[session_key].add(step_sig)

        step_num += 1
        attack_steps.append({
            'step_number':    step_num,
            'timestamp':      e.timestamp.isoformat(),
            'host':           e.source_host,
            'user':           e.user,
            'tactic':         tactic,
            'technique_id':   tid,
            'technique_name': tname,
            'description':    (e.description or '')[:200],
            'event_ids':      [e.id] if e.id else [],
            'confidence':     'high' if e.event_id else 'medium',
        })

    # ── Session-aware lateral movement paths ───────────────────────────────────
    #
    # Lateral paths use the same sliding-window session model.
    # The dedup key is (src, dst, user, session_id): the same src→dst move by
    # the same user within one session is collapsed, but a return path in a
    # later session (after a long gap) is recorded as a distinct entry.

    lat_actor_last: dict[tuple, object] = {}
    lat_actor_sid:  dict[tuple, int]    = {}
    lateral_paths:  list[dict]          = []
    seen_lateral:   set[tuple]          = set()

    for e in sorted_events:
        if not _is_lateral(e):
            continue
        src = _extract_src(e)
        if not src:
            continue
        dst  = e.source_host
        user = e.user or 'unknown'
        actor = (user.lower(), dst)

        last_t  = lat_actor_last.get(actor)
        gap_sec = (
            (e.timestamp - last_t).total_seconds()
            if last_t is not None else float('inf')
        )
        if gap_sec > INACTIVITY_TIMEOUT_SECONDS:
            lat_actor_sid[actor] = lat_actor_sid.get(actor, -1) + 1
        lat_actor_last[actor] = e.timestamp
        sid = lat_actor_sid.get(actor, 0)

        lat_key = (src, dst, user, sid)
        if lat_key in seen_lateral:
            continue
        seen_lateral.add(lat_key)

        if e.event_id in ('5140', '5145'):
            method = 'SMB Share Access'
        elif re.search(r'psexec|wmiexec|smbexec', e.description or '', re.I):
            method = 'PsExec/WMI Remote Exec'
        elif e.event_id == '4624':
            lt = re.search(r'Logon Type:\s*(\d+)', e.description or '', re.I)
            if lt and lt.group(1) == '10':
                method = 'RDP (Remote Interactive)'
            else:
                method = 'Network Logon (Type 3)'
        else:
            method = 'Remote Execution'

        lateral_paths.append({
            'from_host':    src,
            'to_host':      dst,
            'user':         user,
            'method':       method,
            'timestamp':    e.timestamp.isoformat(),
            'technique_id': 'T1021.001' if 'RDP' in method else 'T1021.002',
        })

    # ── Blast radius ───────────────────────────────────────────────────────────
    compromised_hosts = sorted({e.source_host for e in sorted_events if e.source_host})
    compromised_users = sorted({
        e.user for e in sorted_events
        if e.user and not (e.user or '').endswith('$')
    })

    accessed_resources: list[str] = []
    for e in sorted_events:
        if e.event_id in ('4663', '5140', '5145'):
            res = _extract_resource(e.description or '')
            if res and res not in accessed_resources:
                accessed_resources.append(res)

    persistence_steps = [s for s in attack_steps if s['tactic'] == 'Persistence']
    persistence_mechanisms = list(dict.fromkeys(s['technique_name'] for s in persistence_steps))

    # ── Tactic progression ─────────────────────────────────────────────────────
    tactics_seen = dict.fromkeys(s['tactic'] for s in attack_steps)
    tactic_progression = [t for t in TACTIC_ORDER if t in tactics_seen]

    # ── Entry vector ───────────────────────────────────────────────────────────
    entry_vector = 'Unknown'
    for s in attack_steps:
        if s['tactic'] == 'Initial Access':
            entry_vector = f"{s['technique_name']} on {s['host']} at {s['timestamp'][:16]}"
            break
    if entry_vector == 'Unknown' and attack_steps:
        first = attack_steps[0]
        entry_vector = f"{first['technique_name']} on {first['host']} at {first['timestamp'][:16]}"

    # ── Threat actor profile ───────────────────────────────────────────────────
    tids_seen  = {s['technique_id'] for s in attack_steps}
    names_seen = {s['technique_name'] for s in attack_steps}

    has_cobalt     = any(
        re.search(r'\bmsse-\d+|createremotethread', e.description or '', re.I)
        for e in sorted_events
    )
    has_kerberoast = 'T1558.003' in tids_seen
    has_dcsync     = 'T1003.006' in tids_seen
    has_golden     = 'T1558.001' in tids_seen
    n_persist      = len(persistence_mechanisms)

    if has_cobalt:
        actor_profile = 'APT — Cobalt Strike C2 (MSSE named pipe / CreateRemoteThread injection confirmed)'
    elif has_kerberoast and has_dcsync and has_golden:
        actor_profile = 'APT — Full AD compromise chain: Kerberoasting → DCSync → Golden Ticket'
    elif has_kerberoast and has_dcsync:
        actor_profile = 'APT — AD credential theft: Kerberoasting + DCSync'
    elif n_persist >= 4:
        actor_profile = f'Persistent threat actor — {n_persist} distinct persistence mechanisms deployed'
    elif 'Exploitation for Privilege Escalation' in names_seen:
        actor_profile = 'Threat actor exploiting unpatched vulnerability for privilege escalation'
    elif 'Bypass User Account Control' in names_seen and n_persist >= 2:
        actor_profile = 'Insider or post-initial-access actor — UAC bypass + persistence'
    else:
        actor_profile = 'Threat actor profile requires additional corroborating evidence'

    confidence = 'high' if len(attack_steps) >= 5 else ('medium' if len(attack_steps) >= 2 else 'low')

    return {
        'threat_actor_profile':  actor_profile,
        'entry_vector':          entry_vector,
        'tactic_progression':    tactic_progression,
        'attack_steps':          attack_steps,
        'lateral_paths':         lateral_paths,
        'blast_radius': {
            'compromised_hosts':       compromised_hosts,
            'compromised_users':       compromised_users,
            'accessed_resources':      accessed_resources,
            'estimated_data_at_risk':  (
                f"{len(accessed_resources)} resource(s) accessed across "
                f"{len(compromised_hosts)} host(s)"
            ),
            'persistence_mechanisms':  persistence_mechanisms,
        },
        'total_duration_minutes': round(duration_minutes, 1),
        'confidence':             confidence,
        'total_attack_steps':     len(attack_steps),
        'total_lateral_paths':    len(lateral_paths),
    }


def _empty() -> dict:
    return {
        'threat_actor_profile':   '',
        'entry_vector':           '',
        'tactic_progression':     [],
        'attack_steps':           [],
        'lateral_paths':          [],
        'blast_radius': {
            'compromised_hosts':      [],
            'compromised_users':      [],
            'accessed_resources':     [],
            'estimated_data_at_risk': '',
            'persistence_mechanisms': [],
        },
        'total_duration_minutes': 0.0,
        'confidence':             'low',
        'total_attack_steps':     0,
        'total_lateral_paths':    0,
    }

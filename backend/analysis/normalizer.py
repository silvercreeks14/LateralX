"""
Log normalization preprocessing layer — Phase 2.

Strips Windows Event Log boilerplate from verbose descriptions, keeping only
high-signal fields. Reduces average description token count by 40-60%.

Supports: Event IDs 4624/4625/4657/4662/4663/4672/4688/4698/4768/4769/5140/5145/7045/1102.
Falls back to stripped-and-capped text for unknown event types.

Deduplication uses a priority-bypass system:
  - High-value events (attack-relevant EIDs or attack keyword in description)
    are NEVER deduplicated regardless of surrounding background noise rate.
  - Low-value events are deduplicated within a sliding window (default 60 s)
    keyed on (host, event_id, user).
"""

import re
from datetime import datetime
from backend.schema import ForensicEvent

# ── Field-level extraction patterns ───────────────────────────────────────────

_NEW_PROC_NAME = re.compile(
    r'New Process Name:\s*([^\r\n]+?)(?=\s*Token Elevation|\s*Creator Process|\s*$)',
    re.IGNORECASE,
)
_CREATOR_PROC_NAME = re.compile(
    r'Creator Process Name:\s*([^\r\n]+?)(?=\s*Process Command Line:|\s*$)',
    re.IGNORECASE,
)
_CMD_LINE = re.compile(r'Process Command Line:\s*([^\r\n]+)', re.IGNORECASE)

_LOGON_TYPE = re.compile(r'Logon Type:\s*(\d+)', re.IGNORECASE)
_LOGON_TYPE_MAP = {
    "2": "Interactive", "3": "Network", "4": "Batch",
    "5": "Service",     "7": "Unlock",  "9": "NewCredentials",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}
_SOURCE_ADDR = re.compile(r'Source(?:\s+Network)?\s+Address:\s*([^\s\r\n]+)', re.IGNORECASE)
_AUTH_PACKAGE = re.compile(r'Authentication Package:\s*(\w+)', re.IGNORECASE)
_GOLDEN_GUID  = re.compile(r'00000000-0000-0000-0000-000000000000', re.IGNORECASE)

_OBJ_NAME  = re.compile(
    r'Object\s+Name:\s*([^\r\n]+?)(?=\s*Object Value Name:|\s*Type:|\s*Process Name:|\s*$)',
    re.IGNORECASE,
)
_OBJ_VALUE = re.compile(
    r'Object Value Name:\s*([^\r\n]+?)(?=\s*Type:|\s*New Value:|\s*$)',
    re.IGNORECASE,
)
_NEW_VALUE = re.compile(r'New Value:\s*([^\r\n]+)', re.IGNORECASE)

_PRIV_LIST = re.compile(
    r'Privileges:\s*((?:[A-Z][a-zA-Z]+(?:\.[a-zA-Z]+)*\s*)+)',
    re.IGNORECASE,
)
_HIGH_PRIVS = {
    'SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege',
    'SeAssignPrimaryTokenPrivilege', 'SeBackupPrivilege',
    'SeRestorePrivilege', 'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege',
}

_TASK_NAME    = re.compile(r'Task Name:\s*([^\r\n]+?)(?=\s*Task Actions:|\s*$)', re.IGNORECASE)
_TASK_ACTIONS = re.compile(r'Task Actions:\s*([^\r\n]+)', re.IGNORECASE)

_SVC_NAME = re.compile(r'Service Name:\s*([^\r\n]+)', re.IGNORECASE)
_SVC_FILE = re.compile(r'Service File Name:\s*([^\r\n]+)', re.IGNORECASE)

_KRB_SVC   = re.compile(r'Service Name:\s*([^\r\n]+)', re.IGNORECASE)
_KRB_ETYPE = re.compile(r'(?:Ticket )?Encryption Type:\s*(0x[0-9a-fA-F]+|\d+)', re.IGNORECASE)

_SHARE_NAME = re.compile(r'Share Name:\s*([^\r\n]+)', re.IGNORECASE)

_BOILERPLATE = re.compile(
    r'(?:Creator |New )?Subject:\s*(?:Security ID:[^.]*\.?\s*)?'
    r'(?:Account Name:[^.]+)?(?:Account Domain:[^.]+)?(?:Logon ID:[^.]+)?\.?\s*'
    r'|Process Information:\s*New Process ID:\s*0x[0-9a-fA-F]+\s*'
    r'|Token Elevation Type:\s*\w+\s*\(\d+\)\s*'
    r'|(?:A new process has been created|An operation was performed on an object'
    r'|A registry value was modified|An attempt was made to access an object'
    r'|Special privileges assigned to new logon'
    r'|An account was (?:successfully )?logged on'
    r'|An account failed to log on'
    r'|A new service was installed in the system'
    r'|A scheduled task was created)\.\s*',
    re.IGNORECASE,
)

# ── Noise detection ────────────────────────────────────────────────────────────

_SVC_ACCOUNT_TERMS = frozenset({
    'svc_', '_svc', 'svc-', '-svc', 'system', 'network service',
    'nt authority', 'local service', 'iis apppool',
})
_BENIGN_KEYWORDS = frozenset({
    'mimikatz', 'sekurlsa', 'certutil', 'encoded', 'mshta', 'psexec',
    'vssadmin', 'shadow', '-enc', 'ransom', 'kerberoast', 'dcsync',
})
_NOISE_EVENT_IDS = frozenset({'4634', '4647'})


def is_noise(event: ForensicEvent) -> bool:
    """Return True for machine accounts, benign service logons, and rapid background EIDs."""
    user = (event.user or '').lower()
    if user.endswith('$'):
        return True
    if any(t in user for t in _SVC_ACCOUNT_TERMS):
        desc_lower = (event.description or '').lower()
        if not any(kw in desc_lower for kw in _BENIGN_KEYWORDS):
            return True
    if event.event_id in _NOISE_EVENT_IDS:
        return True
    return False


# ── Priority bypass: high-value signal detection ───────────────────────────────
#
# Events that match either check are NEVER deduplicated in normalize_events().
# This prevents a "low and slow" attacker's critical events from being silenced
# by high-frequency background traffic that happens to share the same
# (host, EID, user) dedup key.
#
# Two complementary checks:
#   1. Structural: event ID belongs to a set that carries inherent ATT&CK signal.
#   2. Lexical:    description contains a known attack tool, LOLBin, or technique term.

_HIGH_VALUE_EVENT_IDS: frozenset[str] = frozenset({
    '4648',          # Explicit-credentials logon (pass-the-hash pivot)
    '4657',          # Registry value modified
    '4662', '4663',  # AD object / file access (DCSync indicator)
    '4698', '4699',  # Scheduled task created / deleted
    '4768', '4769',  # Kerberos TGT / TGS (AS-REP Roasting, Kerberoasting)
    '5140', '5145',  # SMB share / file access
    '7045',          # New Windows service installed
    '1102',          # Audit log cleared (defense evasion)
})

_HIGH_VALUE_KEYWORDS: frozenset[str] = frozenset({
    # Credential access / dumping
    'mimikatz', 'sekurlsa', 'lsadump', 'lsass', 'ntds.dit', 'procdump',
    'dcsync', 'kerberoast', 'rubeus', 'pass-the-hash', 'overpass-the-hash',
    'asreproast', 'golden ticket', 'krbtgt', 'silver ticket',
    # Lateral movement tools
    'psexec', 'psexesvc', 'wmiexec', 'smbexec', 'atexec', 'dcomexec',
    'admin$', 'ipc$', 'c$',
    # LOLBin execution
    'certutil', 'mshta', 'regsvr32', 'rundll32', 'wscript', 'cscript',
    'msiexec', 'bitsadmin', 'wmic',
    # PowerShell / obfuscation
    '-encodedcommand', '-enc ', 'invoke-expression', 'iex ', 'iex(',
    'downloadstring', 'downloadfile', 'frombase64string', 'invoke-obfuscat',
    'base64',
    # Defense evasion
    'vssadmin', 'shadowcopy', 'wevtutil', 'bcdedit', 'clear-eventlog',
    'clearev', 'amsiutils', 'amsi.dll', 'etw',
    # Persistence backdoors
    'sethc', 'utilman', 'image file execution options', 'inprocserver32',
    'authorized_keys', 'userinitmpr', 'commandlineeventconsumer',
    # Reconnaissance / AD tools
    'bloodhound', 'sharphound', 'powerview', 'adrecon', 'ldapdump',
    'get-domainuser', 'find-localadminaccess',
    # Exploitation
    'printnightmare', 'juicypotato', 'rottenpotato', 'sweetpotato',
    'cobalt', 'beacon', 'msse-', 'createremotethread', 'reflective',
    # Staging / exfil
    'robocopy', 'data.*staging', 'ransom',
})


def _is_high_value(event: ForensicEvent) -> bool:
    """
    Return True when an event carries high-value attack signal.

    Used by normalize_events() to determine whether an event may be
    deduplicated.  High-value events are always preserved.
    """
    if event.event_id in _HIGH_VALUE_EVENT_IDS:
        return True
    desc_lower = (event.description or '').lower()
    return any(kw in desc_lower for kw in _HIGH_VALUE_KEYWORDS)


# ── Signal extractors per Event ID ────────────────────────────────────────────

def _parse_process_creation(desc: str) -> str:
    parts = []
    m = _NEW_PROC_NAME.search(desc)
    if m:
        proc = m.group(1).strip().rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
        parts.append(f"proc={proc}")
    m = _CREATOR_PROC_NAME.search(desc)
    if m:
        parent = m.group(1).strip().rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
        parts.append(f"parent={parent}")
    m = _CMD_LINE.search(desc)
    if m:
        parts.append(f"cmd={m.group(1).strip()[:160]}")
    if 'TokenElevationTypeFull' in desc:
        parts.append('elevated=FULL')
    return ' | '.join(parts) if parts else desc[:200]


def _parse_logon(desc: str, eid: str) -> str:
    parts = ['LOGON_FAIL' if eid == '4625' else 'LOGON_OK']
    m = _LOGON_TYPE.search(desc)
    if m:
        parts.append(f"type={_LOGON_TYPE_MAP.get(m.group(1), m.group(1))}")
    m = _SOURCE_ADDR.search(desc)
    if m:
        parts.append(f"src={m.group(1)}")
    m = _AUTH_PACKAGE.search(desc)
    if m:
        parts.append(f"auth={m.group(1)}")
    if _GOLDEN_GUID.search(desc):
        parts.append('GOLDEN_TICKET_INDICATOR')
    return ' | '.join(parts)


def _parse_registry_mod(desc: str) -> str:
    parts = ['REG_MOD']
    m = _OBJ_NAME.search(desc)
    if m:
        parts.append(f"key={m.group(1).strip()[:100]}")
    m = _OBJ_VALUE.search(desc)
    if m:
        parts.append(f"val={m.group(1).strip()[:50]}")
    m = _NEW_VALUE.search(desc)
    if m:
        parts.append(f"data={m.group(1).strip()[:90]}")
    return ' | '.join(parts)


def _parse_object_access(desc: str) -> str:
    is_dcsync = '1131f6aa' in desc or '1131f6ab' in desc
    parts = ['DCSYNC_ACCESS' if is_dcsync else 'OBJ_ACCESS']
    m = re.search(r'Object Type:\s*(\w+)', desc, re.IGNORECASE)
    if m:
        parts.append(f"type={m.group(1)}")
    m = re.search(
        r'Object Name:\s*([^\r\n]+?)(?=\s*(?:Process Name:|Accesses:|Access:|\.\s+\w|\s*$))',
        desc, re.IGNORECASE,
    )
    if m:
        parts.append(f"obj={m.group(1).strip()[:80]}")
    if is_dcsync:
        parts.append('DS-Replication-Get-Changes-All')
    return ' | '.join(parts)


def _parse_special_privs(desc: str) -> str:
    m = _PRIV_LIST.search(desc)
    if not m:
        return 'SPECIAL_PRIVS'
    tokens = [t.strip('.') for t in m.group(1).split()]
    high = [t for t in tokens if t in _HIGH_PRIVS]
    return f"SPECIAL_PRIVS | {','.join(high)}" if high else 'SPECIAL_PRIVS'


def _parse_scheduled_task(desc: str) -> str:
    parts = ['SCHTASK_CREATE']
    m = _TASK_NAME.search(desc)
    if m:
        parts.append(f"name={m.group(1).strip()[:70]}")
    m = _TASK_ACTIONS.search(desc)
    if m:
        parts.append(f"action={m.group(1).strip()[:90]}")
    return ' | '.join(parts)


def _parse_service_install(desc: str) -> str:
    parts = ['SVC_INSTALL']
    m = _SVC_NAME.search(desc)
    if m:
        parts.append(f"name={m.group(1).strip()[:60]}")
    m = _SVC_FILE.search(desc)
    if m:
        parts.append(f"bin={m.group(1).strip()[:80]}")
    return ' | '.join(parts)


def _parse_kerberos_ticket(desc: str, eid: str) -> str:
    parts = ['KRB_TGS' if eid == '4769' else 'KRB_TGT']
    m = _KRB_SVC.search(desc)
    if m:
        parts.append(f"svc={m.group(1).strip()[:70]}")
    m = _KRB_ETYPE.search(desc)
    if m:
        raw = m.group(1).lower()
        label = 'RC4_KERBEROAST_RISK' if raw == '0x17' else raw
        parts.append(f"etype={label}")
    return ' | '.join(parts)


def _parse_share_access(desc: str) -> str:
    parts = ['SHARE_ACCESS']
    m = _SHARE_NAME.search(desc)
    if m:
        parts.append(f"share={m.group(1).strip()[:40]}")
    m = _SOURCE_ADDR.search(desc)
    if m:
        parts.append(f"src={m.group(1).strip()}")
    return ' | '.join(parts)


# ── Main extraction entry point ────────────────────────────────────────────────

def extract_signal(event: ForensicEvent) -> str:
    """
    Extract signal-only text from a verbose Windows/Linux event description.
    Returns a compact string suitable for LLM prompts (typically 60-120 chars).
    """
    desc = event.description or ''
    eid  = event.event_id or ''

    if   eid == '4688':              return _parse_process_creation(desc)
    elif eid in ('4624', '4625'):    return _parse_logon(desc, eid)
    elif eid == '4657':              return _parse_registry_mod(desc)
    elif eid in ('4662', '4663'):    return _parse_object_access(desc)
    elif eid == '4672':              return _parse_special_privs(desc)
    elif eid == '4698':              return _parse_scheduled_task(desc)
    elif eid == '7045':              return _parse_service_install(desc)
    elif eid in ('4769', '4768'):    return _parse_kerberos_ticket(desc, eid)
    elif eid in ('5140', '5145'):    return _parse_share_access(desc)
    elif eid == '1102':              return 'AUDIT_LOG_CLEARED'
    else:
        return _BOILERPLATE.sub('', desc).strip()[:200]


# ── Batch normalization ────────────────────────────────────────────────────────

class NormalizedEvent:
    """Compact in-memory form of a ForensicEvent with signal-only description."""
    __slots__ = ('timestamp', 'host', 'user', 'event_id', 'signal', 'db_id', 'raw_type', 'high_value')

    def __init__(self, e: ForensicEvent, signal: str, high_value: bool = False) -> None:
        self.timestamp  = e.timestamp
        self.host       = e.source_host
        self.user       = e.user
        self.event_id   = e.event_id
        self.signal     = signal
        self.db_id      = e.id
        self.raw_type   = e.event_type
        self.high_value = high_value


def normalize_events(
    events: list[ForensicEvent],
    filter_noise: bool = True,
    dedup_window_seconds: int = 60,
) -> list[NormalizedEvent]:
    """
    Normalize a list of ForensicEvents into compact NormalizedEvent objects.

    Steps:
    1. Noise filter — drops machine-account logons and pure background EIDs (optional).
    2. Priority bypass — events classified as high-value by _is_high_value() are
       appended unconditionally, bypassing the dedup window entirely.
       last_seen IS updated for bypassed events so that subsequent low-signal events
       sharing the same (host, EID, user) key remain suppressed.
    3. Deduplication — low-signal events with the same (host, EID, user) key within
       dedup_window_seconds of the previous pass-through are dropped.
    4. Signal extraction — extract_signal() reduces verbose boilerplate to
       a compact, LLM-friendly string.

    WHY this prevents false negatives on slow attackers
    ────────────────────────────────────────────────────
    Without the bypass, a frequent background process (e.g. EID 4688 cmd.exe every
    30 s from automated tooling) keeps refreshing last_seen[key].  An attacker's
    malicious cmd.exe that arrives 45 s after the last background one shares the
    same key and falls within the 60 s window → silently dropped.

    With the bypass, the attacker's cmd.exe containing 'certutil' or '-enc' is
    identified as high-value and appended before the dedup check is even evaluated.
    The surrounding background noise is still deduplicated normally.

    Returns NormalizedEvent list sorted by timestamp.
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    result: list[NormalizedEvent] = []
    last_seen: dict[str, datetime] = {}

    for e in sorted_events:
        if filter_noise and is_noise(e):
            continue

        key = f"{e.source_host}|{e.event_id or ''}|{(e.user or '').lower()}"

        if _is_high_value(e):
            # Always preserve attack-relevant events.
            # Refresh last_seen so low-signal noise immediately following this
            # event (same key) is still subject to the dedup window.
            last_seen[key] = e.timestamp
            result.append(NormalizedEvent(e, extract_signal(e), high_value=True))
            continue

        last = last_seen.get(key)
        if last and (e.timestamp - last).total_seconds() < dedup_window_seconds:
            continue

        last_seen[key] = e.timestamp
        result.append(NormalizedEvent(e, extract_signal(e), high_value=False))

    return result


def normalized_to_llm_text(events: list[NormalizedEvent]) -> str:
    """Format normalized events as compact LLM prompt text."""
    lines = []
    for e in events:
        ts    = e.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        parts = [ts]
        if e.db_id is not None:
            parts.append(f'db_id={e.db_id}')
        parts.append(f'host={e.host}')
        if e.user:
            parts.append(f'user={e.user}')
        if e.event_id:
            parts.append(f'EID={e.event_id}')
        parts.append(e.signal)
        lines.append(' | '.join(parts))
    return '\n'.join(lines)

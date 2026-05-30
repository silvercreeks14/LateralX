"""
Multi-format forensic timeline parser.
Supports: Plaso L2T CSV, Timesketch JSONL, generic CSV, Sysmon CSV, and LMD CSV.
"""

import csv
import json
import logging
import re
from datetime import datetime as _dt, timezone as _tz
from io import StringIO

from backend.schema import ForensicEvent, RawSource

log = logging.getLogger(__name__)


def _extract_event_id(message: str) -> str | None:
    """Extract a Windows Event ID from a message string using regex."""
    match = re.search(r"[Ee]vent\s*[Ii][Dd][:=\s]+(\d{3,5})", message)
    return match.group(1) if match else None


# ── Sysmon Message deep-parse helpers ─────────────────────────────────────────

# Canonical key names for fields extracted from Sysmon Message blocks.
# Keyed by lowercase so the IGNORECASE regex match can normalize to PascalCase.
_SYSMON_MSG_CANONICAL_KEYS: dict[str, str] = {
    "image":             "Image",
    "commandline":       "CommandLine",
    "parentimage":       "ParentImage",
    "parentcommandline": "ParentCommandLine",
    "user":              "User",
    "targetimage":       "TargetImage",
    "grantedaccess":     "GrantedAccess",
    "utctime":           "UtcTime",
}

# Compiled multiline pattern – one scan extracts all targeted fields.
# IGNORECASE so Message blocks written by different Sysmon versions still match.
_SYSMON_MSG_RE = re.compile(
    r"^\s*(?P<key>Image|CommandLine|ParentImage|ParentCommandLine"
    r"|User|TargetImage|GrantedAccess|UtcTime)\s*:\s*(?P<value>.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _deep_parse_sysmon_message(message_text: str) -> dict:
    """
    Extract high-signal forensic key-value pairs from a Sysmon Message block.

    Targeted fields: Image, CommandLine, ParentImage, ParentCommandLine,
    User, TargetImage, GrantedAccess.

    Uses a single compiled multiline regex pass; first occurrence of each key
    wins (Sysmon always lists the most specific value first).  Returns an empty
    dict on empty/None input rather than raising.
    """
    if not message_text:
        return {}
    result: dict = {}
    for m in _SYSMON_MSG_RE.finditer(message_text):
        key = _SYSMON_MSG_CANONICAL_KEYS.get(m.group("key").lower(), m.group("key"))
        if key in result:          # first match wins
            continue
        value = m.group("value").strip()
        if value and value.lower() not in ("-", "null", "none", ""):
            result[key] = value
    return result


# Compiled separator pattern for single-line "Key: Value. Key: Value." descriptions.
# Matches the ". FieldName:" boundary so it can be replaced with a newline, making
# the text parseable by _deep_parse_sysmon_message (which expects multiline format).
_SYSMON_INLINE_SPLIT_RE = re.compile(
    r"\.\s+(?=(?:Image|CommandLine|ParentImage|ParentCommandLine"
    r"|TargetImage|GrantedAccess|UtcTime)\s*:)",
    re.IGNORECASE,
)


def _extract_sysmon_inline(text: str) -> dict:
    """
    Extract Sysmon key-value pairs from a single-line period-separated description.

    Handles the format produced by some SIEM exports and custom CSV scenarios:
      "New process. Image: C:\\cmd.exe. Parent: w3wp.exe. CommandLine: cmd.exe /c whoami."

    Strategy:
      1. Normalise the "Parent:" shorthand to "ParentImage:" so the canonical
         Sysmon key mapping in _deep_parse_sysmon_message recognises it.
      2. Insert newlines before known Sysmon field names.
      3. Delegate to _deep_parse_sysmon_message which handles multiline format.

    Returns an empty dict when no Sysmon field patterns are found.
    """
    if not text or ":" not in text:
        return {}
    # "Parent:" is a shorthand used by some SIEM exports for "ParentImage:".
    # Only normalise the bare word — leave "ParentImage:" and "ParentCommandLine:" intact.
    text = re.sub(r"\bParent(?!Image|CommandLine)\b", "ParentImage", text, flags=re.IGNORECASE)
    converted = _SYSMON_INLINE_SPLIT_RE.sub("\n", text)
    if "\n" not in converted:
        return {}
    return _deep_parse_sysmon_message(converted)


def _find_column(headers: list[str], candidates: list[str]) -> str | None:
    """Return the first candidate column name that exists in headers, else None."""
    for c in candidates:
        if c in headers:
            return c
    return None


# Domain suffixes stripped from hostnames to produce a clean entity ID.
_DOMAIN_SUFFIXES = (
    ".corp.local", ".corp", ".local", ".internal", ".lan",
    ".ad", ".domain", ".home",
)

# Priority-ordered field names for host entity resolution.
# Earlier entries win when multiple fields are present in the same record.
_HOST_FIELD_PRIORITY = [
    "hostname", "host", "source_host", "sourcehost",
    "computername", "computer_name", "computer",
    "workstationname", "workstation_name", "workstation",
    "sourceworkstationname", "source_workstation",
    "devicename", "device_name",
]

# Priority-ordered field names for user/actor resolution across log formats.
# Covers Plaso, Timesketch, Velociraptor, Sysmon, generic SIEM exports, and
# verbose Windows Event Log key-value pairs inside description/message text.
_USER_FIELD_PRIORITY = [
    # Primary structured user fields (most reliable)
    "username", "user",
    "account_name", "accountname", "account",
    "subjectusername", "subject_username",
    "sourceusername", "source_user", "sourceuser",
    "targetusername", "target_username", "targetuser", "target_user",
    "initiatorname", "actor",
    # Windows security audit: "subject" is the acting account when username=SYSTEM
    # Safe because _normalize_username rejects values containing spaces,
    # so email "subject" lines ("Q1 Budget Review — ...") are automatically excluded.
    "subject",
    # Network/SIEM log formats
    "src_user", "srcuser", "dst_user", "dstuser",
    # Audit trail / change-management logs
    "created_by", "modified_by", "operator", "owner",
    # Email gateway logs (lowest priority — "sender" could be external)
    "sender", "recipient",
]

# Values that represent "no meaningful actor" in Windows Event Logs.
# NOTE: "system" is intentionally NOT listed here.  SYSTEM is a valid Windows
# principal (NT AUTHORITY\SYSTEM) and its presence in security events — especially
# audit log clearing, privilege use, or process creation — is forensically
# significant.  Filtering it would hide real attack evidence.
_SYSTEM_ACCOUNTS = frozenset({
    "local service", "localservice",
    "network service", "networkservice",
    "anonymous logon", "anonymouslogon",
    "nt authority", "-", "n/a", "unknown", "null", "",
})

# Description-text patterns used when no structured user field is populated.
# Ordered from most specific (least false-positive risk) to least specific.
_USER_DESC_PATTERNS = [
    re.compile(r'Account\s+Name:\s*([\w][\w\-\.]{0,48})', re.IGNORECASE),
    re.compile(r'SubjectUserName:\s*([\w][\w\-\.]{0,48})', re.IGNORECASE),
    re.compile(r'TargetUserName:\s*([\w][\w\-\.]{0,48})', re.IGNORECASE),
    re.compile(r'User(?:Name)?:\s*([\w][\w\-\.]{0,48})', re.IGNORECASE),
]


def _normalize_username(raw: str | None) -> str | None:
    """
    Normalise a raw username string for consistent cross-source identity.

    Transformations applied (in order):
      1. Strip whitespace
      2. Strip domain prefix  (CORP\\jsmith  → jsmith)
      3. Strip UPN suffix     (jsmith@corp   → jsmith)
      4. Return None for machine accounts ($), SIDs, system/service accounts,
         and placeholder values ('-', 'n/a', etc.)
    """
    if not raw:
        return None
    name = raw.strip()
    # Strip domain prefix: CORP\jsmith or CORP/jsmith
    if '\\' in name:
        name = name.rsplit('\\', 1)[-1].strip()
    elif '/' in name and not name.lower().startswith('http'):
        name = name.rsplit('/', 1)[-1].strip()
    # Strip UPN suffix: jsmith@corp.local → jsmith
    if '@' in name:
        name = name.split('@', 1)[0].strip()
    if not name:
        return None
    # Names with spaces are descriptions/labels, not usernames
    if ' ' in name:
        return None
    # Machine account (ends with $)
    if name.endswith('$'):
        return None
    # Windows SID (S-1-5-…)
    if re.match(r'^S-\d+-\d', name):
        return None
    # Built-in service / placeholder accounts
    if name.lower() in _SYSTEM_ACCOUNTS:
        return None
    return name


def _extract_user_from_description(description: str) -> str | None:
    """
    Extract an actor username from a Windows Event Log or syslog description
    when no structured user field is available.

    Uses finditer so that descriptions with multiple Account Name: entries
    (e.g. EID 4624 with Subject + Target blocks) try every match per pattern,
    not just the first (which is often the machine account).
    """
    for pattern in _USER_DESC_PATTERNS:
        for m in pattern.finditer(description):
            name = _normalize_username(m.group(1))
            if name:
                return name
    return None


def _resolve_user(obj: dict, description: str = "") -> str | None:
    """
    Resolve the acting user from a structured log dict (CSV row or JSON object).

    Strategy:
      1. Build a case-insensitive key map to handle title-case Windows fields
         like "User", "TargetUser", "Computer" without needing exact-case matches.
      2. Try each field in _USER_FIELD_PRIORITY through the lowercase map.
      3. Normalise via _normalize_username (strips domain prefix, UPN, SIDs, etc.).
      4. Fall back to description-text extraction if all structured fields yield None.
    """
    lower_obj = {k.lower(): v for k, v in obj.items()}
    for field in _USER_FIELD_PRIORITY:
        val = lower_obj.get(field)
        if val and str(val).strip():
            name = _normalize_username(str(val))
            if name:
                return name
    if description:
        return _extract_user_from_description(description)
    return None


def _normalize_hostname(raw: str | None) -> str:
    """
    Normalize a raw hostname/IP to a clean, consistent entity ID.

    Transformations applied:
      - Strip leading/trailing whitespace
      - Strip common AD domain suffixes (e.g. '.corp.local')
      - Upper-case for consistency (Windows hostnames are case-insensitive)
      - Return 'UNKNOWN-HOST' when nothing usable is found
    """
    if not raw or raw.strip().lower() in ("", "unknown-host", "unknown", "-", "n/a"):
        return "UNKNOWN-HOST"
    host = raw.strip().rstrip('.')  # strip trailing dots (DNS FQDN / Windows Event Viewer export)
    for suffix in _DOMAIN_SUFFIXES:
        if host.lower().endswith(suffix):
            host = host[: len(host) - len(suffix)]
            break
    return host.upper() if host else "UNKNOWN-HOST"


def _resolve_host(obj: dict) -> str:
    """
    Try each field in _HOST_FIELD_PRIORITY in order; return the first non-empty value
    normalized via _normalize_hostname. Falls back to 'UNKNOWN-HOST'.
    Uses a case-insensitive key map to handle title-case Windows fields like "Computer".
    """
    lower_obj = {k.lower(): v for k, v in obj.items()}
    for field in _HOST_FIELD_PRIORITY:
        val = lower_obj.get(field)
        if val and str(val).strip():
            return _normalize_hostname(str(val))
    return "UNKNOWN-HOST"


def parse_plaso_csv(content: str) -> list[ForensicEvent]:
    """
    Parse a Plaso psort.py L2T CSV export into ForensicEvent objects.

    Expected columns: datetime, timestamp_desc, source, source_long,
    message, parser, display_name, tag, hostname, username.
    Malformed rows are skipped silently.
    """
    events: list[ForensicEvent] = []
    reader = csv.DictReader(StringIO(content))

    for row in reader:
        try:
            # Strip whitespace from all values
            row = {k.strip(): (v.strip() if v else v) for k, v in row.items()}

            timestamp_raw = row.get("datetime", "")
            if not timestamp_raw:
                continue

            message = row.get("message", "") or ""
            event_id = _extract_event_id(message)

            events.append(
                ForensicEvent(
                    timestamp=timestamp_raw,
                    event_type=row.get("timestamp_desc", "Unknown") or "Unknown",
                    source_host=_normalize_hostname(row.get("hostname")),
                    user=_resolve_user(row, message),
                    description=message[:1000],
                    raw_source=RawSource.PLASO,
                    event_id=event_id,
                    extra={
                        "source": row.get("source"),
                        "source_long": row.get("source_long"),
                        "parser": row.get("parser"),
                        "display_name": row.get("display_name"),
                        "tag": row.get("tag"),
                    },
                )
            )
        except Exception:
            # Skip malformed rows silently
            continue

    return events


def _build_windows_description(obj: dict) -> str:
    """
    Build a `Key: Value` description string from Windows Event Log JSON fields
    so that downstream regex patterns (Share Name:, Service Name:, Account Name:,
    Source Network Address:, Object Name:) match correctly even when the event
    lacks a free-text "message" or "description" key.
    """
    lower = {k.lower(): v for k, v in obj.items()}
    parts: list[str] = []

    if v := lower.get("eventname"):
        parts.append(f"EventName: {v}")
    if v := lower.get("process"):
        parts.append(f"Process: {v}")
    if v := lower.get("processname"):
        parts.append(f"Process Name: {v}")
    if v := lower.get("commandline"):
        parts.append(f"CommandLine: {v}")
    if v := lower.get("scriptblocktext"):
        parts.append(f"ScriptBlockText: {str(v)[:300]}")
    # User fields: include as "Account Name:" so downstream regex patterns match
    for user_key in ("targetuser", "user", "subject", "created_by", "operator"):
        if v := lower.get(user_key):
            v_str = str(v)
            if ' ' not in v_str and len(v_str) <= 64:
                parts.append(f"Account Name: {v_str}")
                break
    if v := lower.get("ipaddress") or lower.get("clientaddress"):
        parts.append(f"Source Network Address: {v}")
    if v := lower.get("sharename"):
        parts.append(f"Share Name: {v}")
    if v := lower.get("objectname"):
        parts.append(f"Object Name: {v}")
    if v := lower.get("servicename"):
        parts.append(f"Service Name: {v}")
    if v := lower.get("taskname"):
        parts.append(f"Task Name: {v}")
    if v := lower.get("content"):
        parts.append(f"Content: {str(v)[:200]}")
    if v := lower.get("privilegelist"):
        parts.append(f"Privilege List: {v}")
    if v := lower.get("ticketencryptiontype"):
        parts.append(f"Ticket Encryption Type: {v}")
    if v := lower.get("accessmask"):
        parts.append(f"Access Mask: {v}")

    return " | ".join(parts)


_NETWORK_SRC_KEYS = frozenset({"src_ip", "source_ip", "src_addr", "client_ip"})
_NETWORK_DST_KEYS = frozenset({"dst_ip", "dest_ip", "destination_ip", "dst_addr"})
_SYSMON_EID3_FIELDS = ("SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Image")


def _is_network_record(obj: dict) -> bool:
    lower_keys = {k.lower() for k in obj}
    return bool(lower_keys & _NETWORK_SRC_KEYS) and bool(lower_keys & _NETWORK_DST_KEYS)


def _promote_nested(obj: dict) -> dict:
    """
    Recursively flatten all nested dictionaries into the top-level dict.
    This ensures that fields like winlog.event_data.SubjectUserName are
    found by the resolution helpers (_resolve_host, _resolve_user).
    """
    merged = dict(obj)

    def _recurse(d: dict):
        for k, v in d.items():
            # Promote the key if it's not already at the top level
            if k not in merged or merged[k] is None:
                merged[k] = v
            if isinstance(v, dict):
                _recurse(v)

    # First pass: promote direct children (preserves existing logic)
    for v in obj.values():
        if isinstance(v, dict):
            _recurse(v)

    # Special case mappings for common ECS/Logstash patterns
    event_sub = obj.get("event")
    if isinstance(event_sub, dict) and "id" in event_sub:
        merged.setdefault("event_id", str(event_sub["id"]))

    log_sub = obj.get("log")
    if isinstance(log_sub, dict):
        src = log_sub.get("source")
        if src:
            merged.setdefault("hostname", src)
            merged.setdefault("timestamp_desc", src)

    # Normalize address field variants
    _alt_src = merged.get("source_address") or merged.get("sourceaddress") or merged.get("saddr")
    if _alt_src:
        merged.setdefault("src_ip", _alt_src)
    _alt_dst = merged.get("destination_address") or merged.get("destinationaddress") or merged.get("daddr")
    if _alt_dst:
        merged.setdefault("dst_ip", _alt_dst)
    
    _alt_dport = merged.get("destination_port") or merged.get("destinationport") or merged.get("dport")
    if _alt_dport is not None:
        merged.setdefault("dst_port", _alt_dport)
    _alt_sport = merged.get("source_port") or merged.get("sourceport") or merged.get("sport")
    if _alt_sport is not None:
        merged.setdefault("src_port", _alt_sport)

    return merged


def parse_timesketch_jsonl(content: str) -> list[ForensicEvent]:
    """
    Parse Timesketch / simulation JSON exports in either format:
      - Standard JSON array  (pretty-printed or compact)
      - Single JSON object
      - JSONL (one compact object per line)

    Detection order:
      1. Attempt json.loads(content) on the full string.
         - list  → processed as a batch of event objects
         - dict  → wrapped in a list and processed as a single event
      2. On JSONDecodeError, fall back to line-by-line JSONL parsing.

    Primary field mappings:
      datetime / @timestamp / timestamp / time / EventTime  -> timestamp
      timestamp_desc -> event_type
      hostname       -> source_host  (falls back to host priority list)
      username / user -> user
      message / description / EventDescription -> description
    All unmapped fields are stored in `extra`.
    Epoch integers (seconds or milliseconds) are converted to ISO 8601.
    Rows with no timestamp field receive the current UTC time.
    """
    _TS_KEYS = ("datetime", "@timestamp", "timestamp", "time", "EventTime")
    _DESC_KEYS = ("message", "Message", "description", "EventDescription")
    KNOWN_FIELDS = {
        "datetime", "@timestamp", "timestamp", "time", "EventTime",
        "timestamp_desc",
        "hostname", "host", "source_host", "sourcehost",
        "computername", "computer_name", "computer",
        "workstationname", "workstation_name", "workstation",
        "sourceworkstationname", "source_workstation",
        "devicename", "device_name",
        "username", "user",
        "account_name", "accountname", "account",
        "subjectusername", "subject_username", "SubjectUserName",
        "sourceusername", "source_user", "sourceuser",
        "targetusername", "target_username", "TargetUserName",
        "initiatorname", "actor",
        "message", "description", "EventDescription",
        "event_id", "EventID", "eventid",
    }

    # ── Phase 1: collect raw objects ─────────────────────────────────────────
    objects: list[dict] = []

    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            objects = [o for o in parsed if isinstance(o, dict)]
        elif isinstance(parsed, dict):
            objects = [parsed]
        # scalar values (int, str, …) produce an empty list → no events
    except json.JSONDecodeError:
        # JSONL fallback: parse one object per non-empty line
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    objects.append(obj)
            except json.JSONDecodeError:
                log.warning("parse_timesketch_jsonl: skipped unparseable line: %s", line[:50])

    # ── Phase 2: map objects to ForensicEvents ────────────────────────────────
    events: list[ForensicEvent] = []

    for obj in objects:
        try:
            obj = _promote_nested(obj)
            # Timestamp resolution: first matching key wins
            timestamp_raw: str = ""
            for key in _TS_KEYS:
                v = obj.get(key)
                if v is not None:
                    if isinstance(v, (int, float)):
                        # Epoch ms when value > year-2001 boundary; else epoch s
                        epoch_s = v / 1000.0 if v > 1_000_000_000_000 else float(v)
                        timestamp_raw = _dt.utcfromtimestamp(epoch_s).strftime("%Y-%m-%dT%H:%M:%SZ")
                    else:
                        timestamp_raw = str(v)
                    break
            if not timestamp_raw:
                timestamp_raw = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Description resolution must come first so _resolve_user can use it
            message: str = ""
            for key in _DESC_KEYS:
                v = obj.get(key)
                if v:
                    message = str(v)
                    break
            if not message:
                message = _build_windows_description(obj)
            if not message:
                message = json.dumps(obj)

            is_net = _is_network_record(obj)
            if is_net:
                low = {k.lower(): v for k, v in obj.items()}
                source_host = str(
                    low.get("src_ip") or low.get("source_ip") or low.get("src_addr") or "UNKNOWN-HOST"
                )
                user = None
                _raw_source = RawSource.PCAP
            else:
                source_host = _resolve_host(obj)
                user = _resolve_user(obj, message)
                _raw_source = RawSource.TIMESKETCH

            # Prefer direct event_id field; fall back to regex from message text
            raw_eid = obj.get("event_id") or obj.get("EventID") or obj.get("eventid")
            event_id = str(raw_eid).strip() if raw_eid else _extract_event_id(message)

            # Extra: all keys not consumed by the known field set
            extra = {k: v for k, v in obj.items() if k not in KNOWN_FIELDS}

            # EID 3 (Sysmon Network Connection) from JSON: the network fields live in
            # the message string rather than as structured keys — extract them so
            # network_host_correlator can find SourceIp, DestinationIp, etc. in extra.
            if event_id == "3" and not is_net and message:
                for _f in _SYSMON_EID3_FIELDS:
                    m = re.search(rf'{_f}:\s*(\S+)', message)
                    if m:
                        extra.setdefault(_f, m.group(1))

            events.append(
                ForensicEvent(
                    timestamp=timestamp_raw,
                    event_type=obj.get("timestamp_desc", "Unknown") or "Unknown",
                    source_host=source_host,
                    user=user,
                    description=message[:1000],
                    raw_source=_raw_source,
                    event_id=event_id,
                    extra=extra if extra else None,
                )
            )
        except Exception as exc:
            log.warning("parse_timesketch_jsonl: skipped row (%s): %s",
                        type(exc).__name__, str(obj)[:50])

    return events


def parse_generic_csv(content: str) -> list[ForensicEvent]:
    """
    Fallback CSV parser using fuzzy column-name matching.

    Required columns (by candidate names):
      timestamp  — timestamp / datetime / time / date
      description — description / message / msg / details

    Optional columns:
      host       — hostname / host / source_host / computer
      user       — username / user / account
      event_type — event_type / type / category
      event_id   — event_id / eventid
    """
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file has no headers.")

    headers = [h.strip().lower() for h in reader.fieldnames]

    ts_col   = _find_column(headers, ["timestamp", "datetime", "time", "date", "eventtime", "@timestamp", "timecreated"])
    desc_col = _find_column(headers, ["description", "message", "msg", "details"])
    msg_col  = _find_column(headers, ["message"])  # Sysmon/Windows Event Viewer Message column

    host_col = _find_column(headers, [
        "hostname", "host", "source_host", "computer",
        "computername", "computer_name", "workstationname", "workstation_name",
        "workstation", "devicename", "device_name", "machinename",
    ])
    user_col = _find_column(headers, [
        "username", "user", "account", "accountname", "account_name",
        "subjectusername", "subject_username",
        "sourceusername", "source_user",
        "targetusername", "target_username",
    ])
    type_col = _find_column(headers, ["event_type", "type", "category"])
    eid_col  = _find_column(headers, ["event_id", "eventid", "id"])

    raw_source = RawSource.VELOCIRAPTOR if msg_col else RawSource.GENERIC

    events: list[ForensicEvent] = []
    # Re-read with normalised keys
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            norm_row = {k.strip().lower(): (v.strip() if v else v) for k, v in row.items()}

            if ts_col:
                timestamp_raw = norm_row.get(ts_col, "") or ""
            else:
                timestamp_raw = ""
            if not timestamp_raw:
                timestamp_raw = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            if desc_col:
                description = norm_row.get(desc_col, "") or ""
            else:
                description = json.dumps(norm_row)

            raw_user = norm_row.get(user_col) if user_col else None
            user = _normalize_username(raw_user) or _extract_user_from_description(description)

            # Extract structured fields from the message column when present, or fall
            # back to inline extraction for CSV files that embed Image/CommandLine
            # directly in the description field ("Key: Value. Key: Value." format).
            sysmon_extra: dict = {}
            if msg_col:
                sysmon_extra = _deep_parse_sysmon_message(norm_row.get(msg_col, "") or "")
            elif description:
                sysmon_extra = _extract_sysmon_inline(description)

            events.append(
                ForensicEvent(
                    timestamp=timestamp_raw,
                    event_type=norm_row.get(type_col, "Generic") if type_col else "Generic",
                    source_host=_normalize_hostname(norm_row.get(host_col) if host_col else None),
                    user=user,
                    description=description[:1000],
                    raw_source=raw_source,
                    event_id=norm_row.get(eid_col) if eid_col else None,
                    extra=sysmon_extra if sysmon_extra else None,
                )
            )
        except Exception:
            continue

    return events


def parse_sysmon_csv(content: str) -> list[ForensicEvent]:
    """
    Parse a Sysmon-style CSV export (e.g. from the LMD dataset / test_set.csv).

    Key column mappings:
      SystemTime / timestamp -> timestamp  (SystemTime preferred; truncated 'timestamp' fallback)
      Computer               -> source_host
      User / SourceUser      -> user
      EventID                -> event_id
      EventType / RuleName   -> event_type
      CommandLine / Image / RuleName / Details -> description (first non-zero value wins)
    All rows are kept; malformed rows are skipped silently.
    """
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file has no headers.")

    headers = [h.strip().lower() for h in reader.fieldnames]

    # Build a mapping from lowercased column name -> original column name
    orig_map = {h.strip().lower(): h for h in reader.fieldnames}

    def _get(row: dict, *keys: str) -> str:
        """Return first non-empty, non-'0' value among the given keys (case-insensitive)."""
        for k in keys:
            v = row.get(orig_map.get(k.lower(), k), "") or ""
            v = v.strip()
            if v and v != "0" and v.lower() not in ("nan", "none", "-", "null"):
                return v
        return ""

    # Detect Sysmon Message column for deep-parse pipeline
    msg_col_sysmon = _find_column(headers, ["message"])

    events: list[ForensicEvent] = []
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            # Prefer full SystemTime over the truncated 'timestamp' field
            ts = _get(row, "SystemTime", "timestamp", "datetime", "time", "CreationUtcTime", "timecreated")
            if not ts:
                ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            host = _normalize_hostname(_get(row, "Computer", "SourceHostname", "hostname", "host", "machinename"))

            # EventID may have a trailing '.0' (float-exported) — strip it
            raw_eid = _get(row, "EventID")
            event_id = raw_eid.split(".")[0] if raw_eid else None

            # Event type: prefer EventType column, fall back to RuleName
            event_type = _get(row, "EventType", "RuleName") or "Sysmon"

            # Build a human-readable description from the richest available fields
            desc_parts = []
            rule = _get(row, "RuleName")
            if rule:
                desc_parts.append(f"Rule: {rule}")
            image = _get(row, "Image")
            if image:
                desc_parts.append(f"Image: {image}")
            cmdline = _get(row, "CommandLine")
            if cmdline:
                desc_parts.append(f"CmdLine: {cmdline}")
            target = _get(row, "TargetImage", "TargetFilename", "TargetObject")
            if target:
                desc_parts.append(f"Target: {target}")
            details = _get(row, "Details")
            if details:
                desc_parts.append(f"Details: {details}")
            src_ip = _get(row, "SourceIp")
            dst_ip = _get(row, "DestinationIp")
            dst_port = _get(row, "DestinationPort")
            if src_ip or dst_ip:
                net = f"Net: {src_ip} -> {dst_ip}"
                if dst_port and dst_port != "0":
                    net += f":{dst_port.split('.')[0]}"
                desc_parts.append(net)
            proto = _get(row, "Protocol")
            if proto:
                desc_parts.append(f"Proto: {proto}")

            description = " | ".join(desc_parts) if desc_parts else json.dumps(
                {k: v for k, v in row.items() if v and v.strip() not in ("", "0", "-")}
            )

            user = (
                _normalize_username(_get(row, "User", "SourceUser", "SubjectUserName", "TargetUserName", "username"))
                or _extract_user_from_description(description)
            )

            extra: dict = {}
            for field in ("Image", "CommandLine", "ParentImage", "ParentCommandLine",
                           "Hashes", "SourceIp", "SourcePort", "DestinationIp",
                           "DestinationPort", "Protocol", "RuleName", "TargetImage",
                           "TargetObject", "GrantedAccess"):
                val = _get(row, field)
                if val:
                    extra[field] = val

            # Deep-parse Sysmon Message block when present; structured fields
            # extracted here win over the coarser desc_parts-based description.
            if msg_col_sysmon:
                msg_text = _get(row, "Message")
                if msg_text:
                    extra.update(_deep_parse_sysmon_message(msg_text))

            events.append(
                ForensicEvent(
                    timestamp=ts,
                    event_type=event_type,
                    source_host=host,
                    user=user,
                    description=description[:1000],
                    raw_source=RawSource.VELOCIRAPTOR if msg_col_sysmon else RawSource.GENERIC,
                    event_id=event_id,
                    extra=extra if extra else None,
                )
            )
        except Exception:
            continue

    return events


def parse_network_csv(content: str) -> list[ForensicEvent]:
    """
    Parse a WAF / firewall / netflow CSV into ForensicEvent objects.

    Detected when the CSV header contains 'src_ip', 'source_ip', or 'src_addr'.
    Events are assigned raw_source=RawSource.PCAP so the attack-graph builder
    treats them as network traffic and links them to host-log events via the
    cross-source scenario graph (external IP → EventID 4688 → 4769 chain).

    Expected columns (by candidate names):
      timestamp  — timestamp / datetime / time / date
      src_ip     — src_ip / source_ip / src_addr / client_ip
      dst_ip     — dst_ip / dest_ip / destination_ip / dst_addr / server_ip
      dst_port   — dst_port / dest_port / dport / port
      protocol   — protocol / proto / transport
      action     — action / verdict / disposition
    """
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file has no headers.")

    headers = [h.strip().lower() for h in reader.fieldnames]

    ts_col       = _find_column(headers, ["timestamp", "datetime", "time", "date"])
    src_col      = _find_column(headers, ["src_ip", "source_ip", "src_addr", "client_ip"])
    dst_col      = _find_column(headers, ["dst_ip", "dest_ip", "destination_ip", "dst_addr", "server_ip"])
    sport_col    = _find_column(headers, ["src_port", "source_port", "sport"])
    port_col     = _find_column(headers, ["dst_port", "dest_port", "dport", "port"])
    proto_col    = _find_column(headers, ["protocol", "proto", "transport"])
    action_col   = _find_column(headers, ["action", "verdict", "disposition"])
    bytes_out_col = _find_column(headers, ["bytes_out", "bytes_sent", "bytes_transferred",
                                           "out_bytes", "sent_bytes", "octets_out"])

    events: list[ForensicEvent] = []
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            norm = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items()}

            src_ip = norm.get(src_col, "") if src_col else ""
            if not src_ip:
                continue

            ts_raw = (norm.get(ts_col, "") if ts_col else "") or _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            dst_ip   = norm.get(dst_col, "")   if dst_col   else ""
            protocol = (norm.get(proto_col, "TCP") if proto_col else "TCP").upper()
            action   = norm.get(action_col, "") if action_col else ""

            try:
                src_port: int | None = int(norm.get(sport_col, "0") if sport_col else "0") or None
            except ValueError:
                src_port = None
            try:
                dst_port: int | None = int(norm.get(port_col, "0") if port_col else "0") or None
            except ValueError:
                dst_port = None
            try:
                bytes_out: int | None = int(float(norm.get(bytes_out_col, "0") if bytes_out_col else "0")) or None
            except ValueError:
                bytes_out = None

            dst_str = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else (dst_ip or "")
            desc = f"{protocol} {src_ip} → {dst_str}" + (f" [{action}]" if action else "")

            extra: dict = {
                "dst_ip":    dst_ip or "",
                "dst_port":  dst_port,
                "src_ip":    src_ip,
                "protocol":  protocol,
                "action":    action,
                "client_ip": src_ip,   # WAF fallback: link attacker IP even when timestamps differ
            }
            if src_port:
                extra["src_port"] = src_port
            if bytes_out:
                extra["bytes_out"] = bytes_out

            events.append(ForensicEvent(
                timestamp=ts_raw,
                event_type=protocol or "TCP",
                source_host=src_ip,
                description=desc[:1000],
                raw_source=RawSource.PCAP,
                extra=extra,
            ))
        except Exception:
            continue

    return events


def parse_lmd_csv(content: str) -> list[ForensicEvent]:
    """
    Parse an LMD-labelled Sysmon CSV into ForensicEvent objects.

    The LMD dataset adds a Label column to Sysmon-like telemetry. Label 0 is
    treated as normal; any non-zero label is preserved as an LMD attack signal
    and later consumed by the Random Forest scanner.
    """
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file has no headers.")

    orig_map = {h.strip().lower(): h for h in reader.fieldnames if h}

    def _get(row: dict, *keys: str, keep_zero: bool = False) -> str:
        for key in keys:
            val = row.get(orig_map.get(key.lower(), key), "") or ""
            val = str(val).strip()
            if not val or val.lower() in ("nan", "none", "-", "null"):
                continue
            if val == "0" and not keep_zero:
                continue
            return val
        return ""

    events: list[ForensicEvent] = []
    for row in reader:
        try:
            timestamp = _get(row, "SystemTime", "timestamp", "datetime", "time", "CreationUtcTime")
            if not timestamp:
                timestamp = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            raw_eid = _get(row, "EventID")
            event_id = raw_eid.split(".")[0] if raw_eid else None

            label_raw = _get(row, "Label", keep_zero=True).split(".")[0] or "0"
            is_attack = label_raw not in ("", "0")

            host = _normalize_hostname(_get(row, "Computer", "SourceHostname", "hostname", "host"))
            user = _get(row, "User", "SourceUser", "username") or None

            desc_parts: list[str] = []
            if is_attack:
                desc_parts.append(f"[LMD ATTACK label={label_raw}]")
            for label, keys in (
                ("Rule", ("RuleName",)),
                ("Image", ("Image",)),
                ("CmdLine", ("CommandLine",)),
                ("Target", ("TargetImage", "TargetFilename", "TargetObject")),
                ("Details", ("Details",)),
                ("Category", ("Category",)),
            ):
                value = _get(row, *keys)
                if value:
                    desc_parts.append(f"{label}: {value}")

            src_ip = _get(row, "SourceIp")
            dst_ip = _get(row, "DestinationIp")
            dst_port = _get(row, "DestinationPort")
            if src_ip or dst_ip:
                net = f"Net: {src_ip} -> {dst_ip}"
                if dst_port:
                    net += f":{dst_port.split('.')[0]}"
                desc_parts.append(net)

            description = " | ".join(desc_parts)
            if not description:
                description = json.dumps({
                    k: v for k, v in row.items()
                    if v and str(v).strip() not in ("", "0", "-")
                })

            extra: dict = {"lmd_label": label_raw, "lmd_is_attack": is_attack}
            for field in (
                "Image", "CommandLine", "ParentImage", "ParentCommandLine",
                "Hashes", "SourceIp", "DestinationIp", "DestinationPort",
                "Protocol", "RuleName", "TargetObject", "GrantedAccess",
            ):
                value = _get(row, field)
                if value:
                    extra[field] = value

            events.append(ForensicEvent(
                timestamp=timestamp,
                event_type="LMD:Attack" if is_attack else (_get(row, "EventType", "RuleName") or "LMD:Normal"),
                source_host=host,
                user=user,
                description=description[:1000],
                raw_source=RawSource.GENERIC,
                event_id=event_id,
                extra=extra,
            ))
        except Exception:
            continue

    return events


def detect_and_parse(filename: str, content: str, parser_hint: str | None = None) -> list[ForensicEvent]:
    """
    Auto-detect the file format by extension and first-line content,
    then dispatch to the appropriate parser.

    Rules:
      parser_hint="lmd" -> parse_lmd_csv
      .jsonl / .json   -> parse_timesketch_jsonl
      .csv with "timestamp_desc" AND "parser" in first line -> parse_plaso_csv
      .csv with LMD "label" column -> parse_lmd_csv
      .csv with Sysmon columns ("computer" + "rulename" OR "eventid" + "image") -> parse_sysmon_csv
      .csv with network columns (src_ip / source_ip / src_addr) -> parse_network_csv
      any other .csv   -> parse_generic_csv
      anything else    -> ValueError
    """
    if parser_hint:
        hint = parser_hint.strip().lower()
        if hint == "lmd":
            return parse_lmd_csv(content)
        if hint == "sysmon":
            return parse_sysmon_csv(content)
        if hint == "plaso":
            return parse_plaso_csv(content)
        if hint in ("timesketch", "jsonl"):
            return parse_timesketch_jsonl(content)
        if hint == "network":
            return parse_network_csv(content)
        if hint == "generic":
            return parse_generic_csv(content)

    name_lower = filename.lower()

    if name_lower.endswith(".jsonl") or name_lower.endswith(".json"):
        return parse_timesketch_jsonl(content)

    if name_lower.endswith(".csv"):
        first_line = content.split("\n")[0].lower()
        header_cols = {c.strip() for c in first_line.split(",")}
        if "timestamp_desc" in header_cols and "parser" in header_cols:
            return parse_plaso_csv(content)
        if "label" in header_cols and ("computer" in header_cols or "image" in header_cols):
            return parse_lmd_csv(content)
        # Sysmon CSV: has 'computer' + 'rulename', or 'eventid' + 'image'
        if ("computer" in header_cols and "rulename" in header_cols) or \
           ("eventid" in header_cols and "image" in header_cols):
            return parse_sysmon_csv(content)
        # Network flow / WAF / firewall log: header contains src_ip or similar
        if header_cols & {"src_ip", "source_ip", "src_addr"}:
            return parse_network_csv(content)
        return parse_generic_csv(content)

    raise ValueError(
        f"Unsupported file extension for '{filename}'. "
        "Supported formats: .csv (Plaso L2T, Sysmon, LMD, network, or generic), .jsonl / .json (Timesketch)."
    )

"""
Multi-format forensic timeline parser.
Supports: Plaso L2T CSV, Timesketch JSONL, generic CSV, Sysmon CSV, and LMD CSV.
"""

import csv
import json
import re
from datetime import datetime as _dt, timezone as _tz
from io import StringIO

from backend.schema import ForensicEvent, RawSource


def _extract_event_id(message: str) -> str | None:
    """Extract a Windows Event ID from a message string using regex."""
    match = re.search(r"[Ee]vent\s*[Ii][Dd][:=\s]+(\d{3,5})", message)
    return match.group(1) if match else None


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
    host = raw.strip()
    for suffix in _DOMAIN_SUFFIXES:
        if host.lower().endswith(suffix):
            host = host[: len(host) - len(suffix)]
            break
    return host.upper() if host else "UNKNOWN-HOST"


def _resolve_host(obj: dict) -> str:
    """
    Try each field in _HOST_FIELD_PRIORITY in order; return the first non-empty value
    normalized via _normalize_hostname. Falls back to 'UNKNOWN-HOST'.
    """
    for field in _HOST_FIELD_PRIORITY:
        val = obj.get(field) or obj.get(field.lower()) or obj.get(field.upper())
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
                    user=row.get("username") or None,
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


def parse_timesketch_jsonl(content: str) -> list[ForensicEvent]:
    """
    Parse a Timesketch JSONL export (one JSON object per line).

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
    _DESC_KEYS = ("message", "description", "EventDescription")
    KNOWN_FIELDS = {
        "datetime", "@timestamp", "timestamp", "time", "EventTime",
        "timestamp_desc",
        "hostname", "host", "source_host", "sourcehost",
        "computername", "computer_name", "computer",
        "workstationname", "workstation_name", "workstation",
        "sourceworkstationname", "source_workstation",
        "devicename", "device_name",
        "username", "user",
        "message", "description", "EventDescription",
        "event_id", "EventID", "eventid",
    }
    events: list[ForensicEvent] = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)

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

            source_host = _resolve_host(obj)
            user = obj.get("username") or obj.get("user") or None

            # Description resolution: first matching key wins; fallback to full row
            message: str = ""
            for key in _DESC_KEYS:
                v = obj.get(key)
                if v:
                    message = str(v)
                    break
            if not message:
                message = json.dumps(obj)

            # Prefer direct event_id field; fall back to regex from message text
            raw_eid = obj.get("event_id") or obj.get("EventID") or obj.get("eventid")
            event_id = str(raw_eid).strip() if raw_eid else _extract_event_id(message)

            # Extra: all keys not consumed by the known field set
            extra = {k: v for k, v in obj.items() if k not in KNOWN_FIELDS}

            events.append(
                ForensicEvent(
                    timestamp=timestamp_raw,
                    event_type=obj.get("timestamp_desc", "Unknown") or "Unknown",
                    source_host=source_host,
                    user=user,
                    description=message[:1000],
                    raw_source=RawSource.TIMESKETCH,
                    event_id=event_id,
                    extra=extra if extra else None,
                )
            )
        except Exception:
            continue

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

    ts_col = _find_column(headers, ["timestamp", "datetime", "time", "date", "eventtime", "@timestamp", "date and time"])
    desc_col = _find_column(headers, ["description", "message", "msg", "details", "info"])

    host_col = _find_column(headers, [
        "hostname", "host", "source_host", "computer",
        "computername", "computer_name", "workstationname", "workstation_name",
        "workstation", "devicename", "device_name",
    ])
    user_col = _find_column(headers, ["username", "user", "account", "accountname"])
    type_col = _find_column(headers, ["event_type", "type", "category", "task category"])
    eid_col = _find_column(headers, ["event_id", "eventid"])

    events: list[ForensicEvent] = []
    # Re-read with normalised keys
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            # Filter out None keys (extra columns without headers) to avoid crash
            norm_row = {k.strip().lower(): (v.strip() if v else v) for k, v in row.items() if k}

            if ts_col:
                timestamp_raw = norm_row.get(ts_col, "") or ""
            else:
                timestamp_raw = ""
            if not timestamp_raw:
                timestamp_raw = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            if desc_col:
                description = norm_row.get(desc_col, "") or ""
            else:
                # If no description col found, check for unnamed column data (common in Windows exports)
                extra_msg = row.get(None)
                if extra_msg:
                    description = " ".join(extra_msg) if isinstance(extra_msg, list) else str(extra_msg)
                else:
                    description = json.dumps(norm_row)

            events.append(
                ForensicEvent(
                    timestamp=timestamp_raw,
                    event_type=norm_row.get(type_col, "Generic") if type_col else "Generic",
                    source_host=_normalize_hostname(norm_row.get(host_col) if host_col else None),
                    user=norm_row.get(user_col) if user_col else None,
                    description=description[:1000],
                    raw_source=RawSource.GENERIC,
                    event_id=norm_row.get(eid_col) if eid_col else None,
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

    events: list[ForensicEvent] = []
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            # Prefer full SystemTime over the truncated 'timestamp' field
            ts = _get(row, "SystemTime", "timestamp", "datetime", "time", "CreationUtcTime")
            if not ts:
                ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            host = _normalize_hostname(_get(row, "Computer", "SourceHostname", "hostname", "host"))

            user = _get(row, "User", "SourceUser", "username") or None

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

            extra: dict = {}
            for field in ("Image", "CommandLine", "ParentImage", "ParentCommandLine",
                           "Hashes", "SourceIp", "DestinationIp", "DestinationPort",
                           "Protocol", "RuleName", "TargetObject", "GrantedAccess"):
                val = _get(row, field)
                if val:
                    extra[field] = val

            events.append(
                ForensicEvent(
                    timestamp=ts,
                    event_type=event_type,
                    source_host=host,
                    user=user,
                    description=description[:1000],
                    raw_source=RawSource.GENERIC,
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

    ts_col    = _find_column(headers, ["timestamp", "datetime", "time", "date"])
    src_col   = _find_column(headers, ["src_ip", "source_ip", "src_addr", "client_ip"])
    dst_col   = _find_column(headers, ["dst_ip", "dest_ip", "destination_ip", "dst_addr", "server_ip"])
    port_col  = _find_column(headers, ["dst_port", "dest_port", "dport", "port"])
    proto_col = _find_column(headers, ["protocol", "proto", "transport"])
    action_col= _find_column(headers, ["action", "verdict", "disposition"])

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
                dst_port: int | None = int(norm.get(port_col, "0") if port_col else "0") or None
            except ValueError:
                dst_port = None

            dst_str = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else (dst_ip or "")
            desc = f"{protocol} {src_ip} → {dst_str}" + (f" [{action}]" if action else "")

            events.append(ForensicEvent(
                timestamp=ts_raw,
                event_type=protocol or "TCP",
                source_host=src_ip,
                description=desc[:1000],
                raw_source=RawSource.PCAP,
                extra={
                    "dst_ip":    dst_ip or "",
                    "dst_port":  dst_port,
                    "src_ip":    src_ip,
                    "protocol":  protocol,
                    "action":    action,
                    "client_ip": src_ip,   # WAF fallback: link attacker IP even when timestamps differ
                },
            ))
        except Exception:
            continue

    return events


def parse_lmd_csv(content: str) -> list[ForensicEvent]:
    """
    Parse a Sysmon CSV that was labelled with the LMD (Lateral Movement Detection)
    model schema.  The file is expected to contain a 'Label' column where:
      0  = normal / benign event
      1  = attack event (lateral movement)
      2  = attack event (second attack class)

    All events are stored.  Attack events (Label != 0) are annotated with
    event_type = "LMD:Attack" and a severity tag in the description so the
    rest of the pipeline (graphs, reports, MITRE mapping) treats them as
    high-signal indicators.

    Column mappings are identical to parse_sysmon_csv; the only additions are:
      Label    -> stored in extra["lmd_label"] and reflected in event_type
      Category -> used to enrich the description when present
    """
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file has no headers.")

    # Build a lowercased -> original-case column map
    orig_map = {h.strip().lower(): h for h in reader.fieldnames}

    def _get(row: dict, *keys: str) -> str:
        for k in keys:
            v = row.get(orig_map.get(k.lower(), k), "") or ""
            v = v.strip()
            if v and v != "0" and v.lower() not in ("nan", "none", "-", "null"):
                return v
        return ""

    def _get_raw(row: dict, *keys: str) -> str:
        """Like _get but also returns '0' (needed for Label field)."""
        for k in keys:
            v = row.get(orig_map.get(k.lower(), k), "") or ""
            v = v.strip()
            if v and v.lower() not in ("nan", "none", "-", "null"):
                return v
        return ""

    # Label -> human-readable tag
    _LABEL_MAP = {
        "0": ("Normal", False),
        "1": ("Attack", True),
        "2": ("Attack", True),
    }

    events: list[ForensicEvent] = []
    reader2 = csv.DictReader(StringIO(content))
    for row in reader2:
        try:
            ts = _get(row, "SystemTime", "timestamp", "datetime", "time", "CreationUtcTime")
            if not ts:
                ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            host = _normalize_hostname(_get(row, "Computer", "SourceHostname", "hostname", "host"))
            user = _get(row, "User", "SourceUser", "username") or None

            raw_eid = _get(row, "EventID")
            event_id = raw_eid.split(".")[0] if raw_eid else None

            # Read the LMD label (0/1/2).  Fall back to "0" (normal) if absent.
            label_raw = _get_raw(row, "Label").split(".")[0]  # strip .0 suffix from floats
            label_text, is_attack = _LABEL_MAP.get(label_raw, ("Normal", False))

            event_type = "LMD:Attack" if is_attack else (_get(row, "EventType", "RuleName") or "LMD:Normal")

            # Build description
            desc_parts = []
            if is_attack:
                desc_parts.append(f"[LMD ATTACK \u2014 label={label_raw}]")
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
            category = _get(row, "Category")
            if category:
                desc_parts.append(f"Category: {category}")

            description = " | ".join(desc_parts) if desc_parts else json.dumps(
                {k: v for k, v in row.items() if v and str(v).strip() not in ("", "0", "-")}
            )

            extra: dict = {"lmd_label": label_raw, "lmd_is_attack": is_attack}
            for field in ("Image", "CommandLine", "ParentImage", "ParentCommandLine",
                          "Hashes", "SourceIp", "DestinationIp", "DestinationPort",
                          "Protocol", "RuleName", "TargetObject", "GrantedAccess"):
                val = _get(row, field)
                if val:
                    extra[field] = val

            events.append(
                ForensicEvent(
                    timestamp=ts,
                    event_type=event_type,
                    source_host=host,
                    user=user,
                    description=description[:1000],
                    raw_source=RawSource.GENERIC,
                    event_id=event_id,
                    extra=extra,
                )
            )
        except Exception:
            continue

    return events


def detect_and_parse(
    filename: str,
    content: str,
    parser_hint: str | None = None,
) -> list[ForensicEvent]:
    """
    Auto-detect the file format by extension and first-line content,
    then dispatch to the appropriate parser.

    Parameters
    ----------
    filename     : original filename (used for extension-based detection)
    content      : decoded text content of the uploaded file
    parser_hint  : optional explicit parser choice supplied by the user.
                   Accepted values:
                     "lmd"       -> parse_lmd_csv  (LMD labelled Sysmon CSV)
                     "sysmon"    -> parse_sysmon_csv
                     "plaso"     -> parse_plaso_csv
                     "timesketch"-> parse_timesketch_jsonl
                     "network"   -> parse_network_csv
                     "generic"   -> parse_generic_csv
                   If None or unrecognised the format is auto-detected.

    Auto-detection rules (when parser_hint is None):
      .jsonl / .json  -> parse_timesketch_jsonl
      .csv with "timestamp_desc" AND "parser" -> parse_plaso_csv
      .csv with LMD "label" column -> parse_lmd_csv
      .csv with Sysmon columns    -> parse_sysmon_csv
      .csv with network columns   -> parse_network_csv
      any other .csv              -> parse_generic_csv
      anything else               -> ValueError
    """
    # ── Explicit parser override ───────────────────────────────────────────────
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
        # Unknown hint — fall through to auto-detection

    # ── Auto-detection ────────────────────────────────────────────────────────
    name_lower = filename.lower()

    if name_lower.endswith(".jsonl") or name_lower.endswith(".json"):
        return parse_timesketch_jsonl(content)

    if name_lower.endswith(".csv"):
        first_line = content.split("\n")[0].lower()
        header_cols = {c.strip() for c in first_line.split(",")}
        if "timestamp_desc" in header_cols and "parser" in header_cols:
            return parse_plaso_csv(content)
        # LMD-labelled CSV: contains a 'label' column alongside Sysmon fields
        if "label" in header_cols and (
            ("computer" in header_cols or "image" in header_cols)
        ):
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
        "Supported formats: .csv (Plaso L2T, Sysmon, LMD, or generic), .jsonl / .json (Timesketch)."
    )

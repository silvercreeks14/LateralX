"""
Cross-source event correlation engine.

Links PCAP network flow events with JSONL/CSV user logon events using
timestamp proximity and IP address matching. This surfaces the identity
behind a network beacon — the most critical pivot in an investigation.

Algorithm:
  1. Build an IP-to-hostname map from log events (log source_host may be an IP).
  2. For each suspicious PCAP flow, find logon events within ±CORR_WINDOW_MIN
     from the same host (matched by IP equality or reverse-hostname lookup).
  3. Score confidence: HIGH when IP matches exactly, MEDIUM when timestamp
     proximity alone drives the match.
  4. Return CorrelationLink objects that can be attached to RCAResult.

Usage:
    from backend.analysis.correlation import correlate_sources
    links = correlate_sources(all_events)
"""

import re
from dataclasses import dataclass, field
from datetime import timedelta

from backend.schema import ForensicEvent

# Correlation window: a PCAP beacon within this many minutes of a logon event
# is considered potentially the same host/user activity.
CORR_WINDOW_MIN = 5

# Minimum confidence score to include a link in the results.
_MIN_CONFIDENCE = 0.30

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class CorrelationLink:
    pcap_timestamp: str
    pcap_src_ip: str
    pcap_dst_ip: str
    pcap_protocol: str
    log_timestamp: str
    log_host: str
    log_user: str | None
    log_event_id: str | None
    confidence: float          # 0.0–1.0
    confidence_label: str      # "HIGH" | "MEDIUM" | "LOW"
    reason: str


def _is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s.strip()))


def _ip_to_host_map(log_events: list[ForensicEvent]) -> dict[str, str]:
    """
    Build IP → hostname mapping from log events whose source_host is an IP.
    Also includes cases where the description contains an IP mapped to a hostname.
    Returns {ip: hostname}.
    """
    ip_host: dict[str, str] = {}
    for e in log_events:
        host = e.source_host
        if _is_ip(host):
            # source_host IS an IP — record the reverse
            ip_host[host] = host
        # Look for "ip=X.X.X.X hostname=HOSTNAME" style fields in description
        desc = e.description.lower()
        ip_match = re.search(r"\bip[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})\b", desc)
        host_match = re.search(r"\bhostname[=:\s]+([\w\-\.]+)\b", desc)
        if ip_match and host_match:
            ip_host[ip_match.group(1)] = host_match.group(1).upper()
        # Extra fields (e.g. Timesketch JSONL may carry ip_address field)
        if e.extra:
            ip_val = e.extra.get("ip_address") or e.extra.get("ip") or e.extra.get("src_ip")
            if ip_val and _is_ip(str(ip_val)):
                ip_host[str(ip_val)] = e.source_host
    return ip_host


def _host_matches_ip(host: str, ip: str, ip_host_map: dict[str, str]) -> bool:
    """Return True when host is the same entity as ip."""
    if host == ip:
        return True
    # host may be a hostname that resolves to ip
    mapped = ip_host_map.get(ip, "")
    if mapped and mapped.upper() == host.upper():
        return True
    # ip may be a hostname that is actually an IP (fallback: exact string)
    return False


def correlate_sources(events: list[ForensicEvent]) -> list[CorrelationLink]:
    """
    Find correlations between PCAP network events and log-based user events.

    Returns a list of CorrelationLink objects, ordered by descending confidence.
    Returns an empty list when there are no PCAP events or no log events to correlate.
    """
    pcap_events = [e for e in events if e.raw_source.value == "pcap"]
    log_events  = [e for e in events if e.raw_source.value != "pcap"]

    if not pcap_events or not log_events:
        return []

    ip_host_map = _ip_to_host_map(log_events)
    window = timedelta(minutes=CORR_WINDOW_MIN)
    links: list[CorrelationLink] = []
    seen: set[str] = set()  # deduplicate (pcap_ts, log_ts, src_ip, log_host)

    for pcap_ev in pcap_events:
        src_ip = pcap_ev.source_host
        extra = pcap_ev.extra or {}
        dst_ip = extra.get("dst_ip", "")
        protocol = pcap_ev.event_type.upper()
        suspicious = extra.get("suspicious", False)

        # Only correlate suspicious PCAP flows to reduce noise
        if not suspicious:
            try:
                dst_port = int(extra.get("dst_port", 0)) or None
            except (ValueError, TypeError):
                dst_port = None
            # Still correlate if the flow targets a known high-risk port
            _HIGH_RISK_PORTS = {4444, 8080, 8443, 1337, 31337, 6666, 9999, 53}
            if dst_port not in _HIGH_RISK_PORTS:
                continue

        t_pcap = pcap_ev.timestamp

        for log_ev in log_events:
            t_log = log_ev.timestamp
            if abs((t_pcap - t_log).total_seconds()) > window.total_seconds():
                continue

            log_host = log_ev.source_host
            ip_match = _host_matches_ip(log_host, src_ip, ip_host_map)
            time_delta_s = abs((t_pcap - t_log).total_seconds())

            # Confidence model:
            # IP match + close timestamp → HIGH
            # IP match alone           → MEDIUM
            # Timestamp only           → LOW (only if both are on same subnet)
            if ip_match and time_delta_s <= 60:
                confidence = 0.90
                label = "HIGH"
                reason = f"IP match ({src_ip} == {log_host}) within {time_delta_s:.0f}s"
            elif ip_match:
                confidence = 0.70
                label = "MEDIUM"
                reason = f"IP match ({src_ip} == {log_host}), Δt={time_delta_s:.0f}s"
            else:
                # Temporal proximity only — lower confidence
                confidence = 0.35
                label = "LOW"
                reason = f"Temporal proximity Δt={time_delta_s:.0f}s, {src_ip} ↔ {log_host}"

            if confidence < _MIN_CONFIDENCE:
                continue

            dedup_key = f"{pcap_ev.timestamp.isoformat()}|{log_ev.timestamp.isoformat()}|{src_ip}|{log_host}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            links.append(CorrelationLink(
                pcap_timestamp=pcap_ev.timestamp.isoformat(),
                pcap_src_ip=src_ip,
                pcap_dst_ip=dst_ip,
                pcap_protocol=protocol,
                log_timestamp=log_ev.timestamp.isoformat(),
                log_host=log_host,
                log_user=log_ev.user,
                log_event_id=log_ev.event_id,
                confidence=round(confidence, 2),
                confidence_label=label,
                reason=reason,
            ))

    links.sort(key=lambda lk: lk.confidence, reverse=True)
    return links

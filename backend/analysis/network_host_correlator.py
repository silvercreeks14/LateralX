"""
Host-to-Perimeter 4-Tuple Network Correlation Engine.

Bridges the forensic gap between:
  - Sysmon EID 3 (Network Connection): records the process, user, src_ip:src_port,
    dst_ip:dst_port at the moment the TCP SYN is issued on the host.
  - Firewall / WAF / netflow logs (PCAP raw_source): see the same 4-tuple at the
    perimeter but have no host context — user and process are invisible at Layer 4.

The join uses two predicates simultaneously:
  1. 4-Tuple match: src_ip + dst_ip + dst_port (+ src_port when available in both).
  2. Time-window match: |fw_timestamp − eid3_timestamp| ≤ JOIN_WINDOW_MS (default 500ms).
     The OS records EID 3 at SYN-send time; the firewall logs the session on SYN-ACK
     or first data packet. 500ms covers all realistic LAN/WAN RTTs without spanning
     separate TCP sessions on the same 4-tuple.

On a successful join the PCAP event's extra dict is enriched in-place with:
  correlated_host, correlated_user, correlated_process, bytes_out_bytes,
  correlation_delta_ms — consumed by build_attack_graph() and calculate_severity().

Three detection capabilities:

  T1048 Exfiltration:
    • Joined: scripting engine + bytes_out > 50 MB confirmed via 4-tuple join -> CRITICAL
    • Volumetric: any single session bytes_out > 20 MB without host join -> CRITICAL
      (lower bar because we lack process context to confirm the tool)

  T1498 / T1499 DDoS:
    • Outbound flood (T1498.002): same src_ip -> same dst_ip:dst_port appearing
      >= DDOS_OUTBOUND_CONN_THRESHOLD times — compromised host performing DDoS
    • Inbound flood (T1498.001): >= DDOS_INBOUND_SRC_THRESHOLD distinct source IPs
      all hitting the same dst_ip:dst_port — monitored network under attack

Usage:
    from backend.analysis.network_host_correlator import (
        correlate_network_to_host, detect_ddos
    )
    exfil_alerts = correlate_network_to_host(events)   # mutates PCAP extras in-place
    ddos_alerts  = detect_ddos(events)
"""

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from backend.schema import ForensicEvent

log = logging.getLogger(__name__)

# ── Tuneable constants ─────────────────────────────────────────────────────────

JOIN_WINDOW_MS: int = 500

# Joined exfil: scripting engine confirmed via 4-tuple join
EXFIL_BYTES_THRESHOLD: int = 50 * 1024 * 1024    # 50 MB

# Unjoined exfil: large outbound transfer with no host context
EXFIL_BYTES_UNJOINED: int = 20 * 1024 * 1024     # 20 MB

# DDoS: outbound flood from a single src to same dst:port
DDOS_OUTBOUND_CONN_THRESHOLD: int = 100

# DDoS: inbound flood — many distinct sources hitting same dst:port
DDOS_INBOUND_SRC_THRESHOLD: int = 50

# ── Scripting/shell process detection ─────────────────────────────────────────

_SHELL_RE = re.compile(
    r'(?:^|[/\\])'
    r'(?:powershell|pwsh|cmd|wscript|cscript|mshta|msbuild|'
    r'rundll32|regsvr32|python3?|bash|sh|zsh|perl|ruby|node)'
    r'(?:\.exe)?$',
    re.IGNORECASE,
)


def _is_shell_process(image: str) -> bool:
    return bool(_SHELL_RE.search(image.strip()))


def _parse_port(val) -> int | None:
    try:
        p = int(val)
        return p if 0 < p <= 65535 else None
    except (TypeError, ValueError):
        return None


def _parse_bytes(val) -> int:
    try:
        return max(0, int(float(str(val).replace(",", "").strip())))
    except (TypeError, ValueError):
        return 0


# ── Public output types ───────────────────────────────────────────────────────

@dataclass
class ExfilAlert:
    """
    Exfiltration session — confirmed via 4-tuple join (correlated=True)
    or detected purely from firewall bytes_out (correlated=False).
    """
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    host: str           # empty when correlated=False
    user: str | None
    process_image: str  # empty when correlated=False
    bytes_out: int
    time_delta_ms: float
    mitre_technique: str = "T1048"
    severity: str = "CRITICAL"
    correlated: bool = True

    @property
    def bytes_out_human(self) -> str:
        gb = self.bytes_out / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.1f} GB"
        return f"{self.bytes_out / (1024 ** 2):.1f} MB"

    def summary(self) -> str:
        if self.correlated:
            return (
                f"[T1048 EXFIL] {self.process_image} ({self.user or '?'}@{self.host}) "
                f"-> {self.dst_ip}:{self.dst_port}  {self.bytes_out_human} out"
            )
        return (
            f"[T1048 EXFIL] {self.src_ip} -> {self.dst_ip}:{self.dst_port}  "
            f"{self.bytes_out_human} out (no host context — firewall only)"
        )


@dataclass
class DDoSAlert:
    """Volumetric denial-of-service pattern detected in firewall/PCAP logs."""
    direction: str       # "outbound" | "inbound"
    src_ip: str          # attacker IP; "multiple" for inbound flood
    dst_ip: str
    dst_port: int
    connection_count: int
    distinct_sources: int
    mitre_technique: str  # T1498.001 (inbound) | T1498.002 (outbound)
    severity: str = "HIGH"

    def summary(self) -> str:
        if self.direction == "outbound":
            return (
                f"[T1498 DDoS] Outbound flood: {self.src_ip} -> "
                f"{self.dst_ip}:{self.dst_port}  "
                f"{self.connection_count} connections (compromised host performing DDoS)"
            )
        return (
            f"[T1498 DDoS] Inbound flood: {self.distinct_sources} sources -> "
            f"{self.dst_ip}:{self.dst_port}  {self.connection_count} total connections"
        )


# ── Core functions ────────────────────────────────────────────────────────────

def correlate_network_to_host(events: list[ForensicEvent]) -> list[ExfilAlert]:
    """
    4-tuple + time-window join between Sysmon EID 3 and PCAP/firewall events.
    Mutates matched PCAP events in-place to carry host identity.

    Also performs standalone volumetric exfil detection on unjoined PCAP events:
    any single session with bytes_out > EXFIL_BYTES_UNJOINED is flagged T1048.

    Returns ExfilAlert objects for all detected exfiltration sessions.
    Safe to call when no EID 3 or no PCAP events exist.
    """
    eid3_events = [
        e for e in events
        if e.raw_source.value != "pcap" and e.event_id == "3"
    ]
    pcap_events = [
        e for e in events
        if e.raw_source.value == "pcap"
    ]

    alerts: list[ExfilAlert] = []
    matched_pcap_oids: set[int] = set()

    # ── Phase 1: 4-tuple join ─────────────────────────────────────────────────
    if eid3_events and pcap_events:
        for eid3 in eid3_events:
            extra3 = eid3.extra or {}

            src_ip   = extra3.get("SourceIp")      or extra3.get("sourceip")      or ""
            src_port = _parse_port(extra3.get("SourcePort")      or extra3.get("sourceport"))
            dst_ip   = extra3.get("DestinationIp") or extra3.get("destinationip") or ""
            dst_port = _parse_port(extra3.get("DestinationPort") or extra3.get("destinationport"))
            image    = extra3.get("Image")          or extra3.get("image")          or ""

            if not src_ip or not dst_ip or dst_port is None:
                continue

            for pcap_ev in pcap_events:
                if id(pcap_ev) in matched_pcap_oids:
                    continue

                extra_fw    = pcap_ev.extra or {}
                fw_src_ip   = extra_fw.get("src_ip") or pcap_ev.source_host or ""
                fw_src_port = _parse_port(extra_fw.get("src_port") or extra_fw.get("source_port"))
                fw_dst_ip   = extra_fw.get("dst_ip", "")
                fw_dst_port = _parse_port(extra_fw.get("dst_port"))

                if fw_src_ip != src_ip or fw_dst_ip != dst_ip or fw_dst_port != dst_port:
                    continue
                if src_port and fw_src_port and src_port != fw_src_port:
                    continue

                delta_ms = (pcap_ev.timestamp - eid3.timestamp).total_seconds() * 1000
                if not (-JOIN_WINDOW_MS <= delta_ms <= JOIN_WINDOW_MS):
                    continue

                # ── Join confirmed ────────────────────────────────────────────
                matched_pcap_oids.add(id(pcap_ev))
                bytes_out = _parse_bytes(
                    extra_fw.get("bytes_out") or extra_fw.get("bytes_sent") or 0
                )

                if pcap_ev.extra is None:
                    pcap_ev.extra = {}
                pcap_ev.extra.update({
                    "correlated_host":      eid3.source_host,
                    "correlated_user":      eid3.user,
                    "correlated_process":   image,
                    "bytes_out_bytes":      bytes_out,
                    "correlation_delta_ms": round(delta_ms, 1),
                })

                log.info(
                    "4-tuple join: %s:%s -> %s:%d  Δt=%.0fms  "
                    "host=%s process=%s bytes_out=%d",
                    src_ip, src_port or "?", dst_ip, dst_port, delta_ms,
                    eid3.source_host, image or "?", bytes_out,
                )

                if _is_shell_process(image) and bytes_out >= EXFIL_BYTES_THRESHOLD:
                    pcap_ev.extra["t1048_exfil"] = True
                    pcap_ev.extra["severity_override"] = "CRITICAL"
                    alert = ExfilAlert(
                        src_ip=src_ip,
                        src_port=src_port or 0,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        host=eid3.source_host,
                        user=eid3.user,
                        process_image=image,
                        bytes_out=bytes_out,
                        time_delta_ms=round(delta_ms, 1),
                        correlated=True,
                    )
                    alerts.append(alert)
                    log.warning("T1048 EXFIL (joined): %s", alert.summary())

    # ── Phase 2: volumetric exfil on unjoined firewall events ─────────────────
    for pcap_ev in pcap_events:
        if id(pcap_ev) in matched_pcap_oids:
            continue
        extra_fw = pcap_ev.extra or {}
        bytes_out = _parse_bytes(
            extra_fw.get("bytes_out") or extra_fw.get("bytes_sent") or 0
        )
        if bytes_out < EXFIL_BYTES_UNJOINED:
            continue

        src_ip   = extra_fw.get("src_ip") or pcap_ev.source_host or ""
        dst_ip   = extra_fw.get("dst_ip", "")
        dst_port = _parse_port(extra_fw.get("dst_port")) or 0

        if pcap_ev.extra is None:
            pcap_ev.extra = {}
        pcap_ev.extra["t1048_exfil"] = True
        pcap_ev.extra["severity_override"] = "CRITICAL"

        alert = ExfilAlert(
            src_ip=src_ip,
            src_port=_parse_port(extra_fw.get("src_port")) or 0,
            dst_ip=dst_ip,
            dst_port=dst_port,
            host="",
            user=None,
            process_image="",
            bytes_out=bytes_out,
            time_delta_ms=0.0,
            correlated=False,
        )
        alerts.append(alert)
        log.warning("T1048 EXFIL (unjoined): %s", alert.summary())

    return alerts


def detect_ddos(events: list[ForensicEvent]) -> list[DDoSAlert]:
    """
    Detect volumetric DDoS patterns from PCAP/firewall events.

    Outbound flood (T1498.002): same src_ip making >= DDOS_OUTBOUND_CONN_THRESHOLD
    connections to the same dst_ip:dst_port across the capture window. Indicates a
    compromised internal host performing DDoS against an external target.

    Inbound flood (T1498.001): >= DDOS_INBOUND_SRC_THRESHOLD distinct source IPs
    all connecting to the same dst_ip:dst_port. Indicates the monitored network is
    under inbound DDoS attack (reflected in firewall allow/deny records).
    """
    pcap_events = [e for e in events if e.raw_source.value == "pcap"]
    if not pcap_events:
        return []

    # Count (src_ip, dst_ip, dst_port) occurrences for outbound flood detection
    outbound_counts: dict[tuple, int] = defaultdict(int)
    # Map (dst_ip, dst_port) -> set of distinct src_ips for inbound flood detection
    inbound_sources: dict[tuple, set] = defaultdict(set)

    for e in pcap_events:
        extra = e.extra or {}
        src_ip   = extra.get("src_ip") or e.source_host or ""
        dst_ip   = extra.get("dst_ip", "")
        dst_port_raw = extra.get("dst_port")
        if not src_ip or not dst_ip or dst_port_raw is None:
            continue
        try:
            dst_port = int(dst_port_raw)
        except (TypeError, ValueError):
            continue

        outbound_counts[(src_ip, dst_ip, dst_port)] += 1
        inbound_sources[(dst_ip, dst_port)].add(src_ip)

    alerts: list[DDoSAlert] = []

    for (src_ip, dst_ip, dst_port), count in outbound_counts.items():
        if count >= DDOS_OUTBOUND_CONN_THRESHOLD:
            alert = DDoSAlert(
                direction="outbound",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                connection_count=count,
                distinct_sources=1,
                mitre_technique="T1498.002",
                severity="HIGH",
            )
            alerts.append(alert)
            log.warning("T1498 DDoS outbound: %s", alert.summary())

    for (dst_ip, dst_port), src_set in inbound_sources.items():
        if len(src_set) >= DDOS_INBOUND_SRC_THRESHOLD:
            total_conn = sum(
                outbound_counts.get((s, dst_ip, dst_port), 0) for s in src_set
            )
            alert = DDoSAlert(
                direction="inbound",
                src_ip="multiple",
                dst_ip=dst_ip,
                dst_port=dst_port,
                connection_count=total_conn,
                distinct_sources=len(src_set),
                mitre_technique="T1498.001",
                severity="HIGH",
            )
            alerts.append(alert)
            log.warning("T1498 DDoS inbound: %s", alert.summary())

    return alerts

"""
Incident-scoped IP-to-Identity table for LateralX.

Builds a mapping of  IP address → (hostname, users, role)  purely from the
ingested event telemetry — no external DNS or DHCP required.

Evidence sources, ranked by confidence weight:
  4 — PCAP event enriched by network_host_correlator (confirmed 4-tuple join)
  3 — Sysmon EID 3 (Network Connection): src_ip seen leaving a known host
  2 — EID 4624 (Successful Logon): IpAddress / WorkstationName fields
  1 — Generic: any IP field in extra when source_host is a real hostname

Role classification (dc beats server beats workstation beats unknown):
  dc          — EID 4768/4769 source, or destination port in {88,389,636,3268,3269}
  server      — destination port in the well-known server set
  workstation — default for host-originated connections

Usage:
    from backend.analysis.ip_identity import IpIdentityTable
    table = IpIdentityTable.build(events)
    identity = table.resolve("192.168.1.50")
    if identity:
        print(identity.hostname, identity.users, identity.role)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from backend.schema import ForensicEvent

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

_DC_PORTS: frozenset[int] = frozenset({88, 389, 636, 3268, 3269})
_SERVER_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 3306, 5432,
    8080, 8443, 9200, 27017,
})

_ROLE_RANK = {"dc": 3, "server": 2, "workstation": 1, "unknown": 0}


def _is_ip(v: object) -> bool:
    return bool(isinstance(v, str) and _IP_RE.match(v.strip()))


def _parse_port(v: object) -> Optional[int]:
    try:
        p = int(v)
        return p if 0 < p <= 65535 else None
    except (TypeError, ValueError):
        return None


def _strip_ipv6_prefix(addr: str) -> str:
    """Normalize ::ffff:192.168.1.1  →  192.168.1.1 (Windows logs IPv4-mapped IPv6)."""
    if addr.startswith("::ffff:") or addr.startswith("::FFFF:"):
        return addr[7:]
    return addr


@dataclass
class HostIdentity:
    ip: str
    hostname: str = ""
    users: set[str] = field(default_factory=set)
    role: str = "unknown"       # "dc" | "server" | "workstation" | "unknown"
    confidence: int = 0         # weight of the best source that set hostname
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_eids: set[str] = field(default_factory=set)

    def _update_time(self, ts: Optional[datetime]) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def merge_hostname(self, hostname: str, weight: int) -> None:
        """Accept a hostname candidate; keep the highest-weight value."""
        if hostname and weight > self.confidence:
            self.hostname = hostname
            self.confidence = weight

    def add_user(self, user: Optional[str]) -> None:
        if user and user.strip() and not user.strip().endswith("$"):
            self.users.add(user.strip())

    def promote_role(self, role: str) -> None:
        """Monotonically advance role toward dc (highest)."""
        if _ROLE_RANK.get(role, 0) > _ROLE_RANK.get(self.role, 0):
            self.role = role


class IpIdentityTable:
    """
    Incident-scoped IP → identity map.

    Build once per analysis request via IpIdentityTable.build(events).
    Then call resolve(ip) to enrich graph nodes, alerts, or storylines.
    """

    def __init__(self) -> None:
        self._table: dict[str, HostIdentity] = {}

    # ── Public interface ──────────────────────────────────────────────────────

    @classmethod
    def build(cls, events: list[ForensicEvent]) -> "IpIdentityTable":
        """Scan all events once and return a fully populated table."""
        tbl = cls()
        for e in events:
            tbl._ingest(e)
        return tbl

    def resolve(self, ip: str) -> Optional[HostIdentity]:
        """Return the best identity for *ip*, or None if not seen."""
        if not ip:
            return None
        return self._table.get(_strip_ipv6_prefix(ip.strip()))

    def all_entries(self) -> list[HostIdentity]:
        return list(self._table.values())

    def __len__(self) -> int:
        return len(self._table)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _entry(self, ip: str) -> HostIdentity:
        ip = _strip_ipv6_prefix(ip.strip())
        if ip not in self._table:
            self._table[ip] = HostIdentity(ip=ip)
        return self._table[ip]

    def _ingest(self, e: ForensicEvent) -> None:
        eid = str(e.event_id or "").strip()
        extra = e.extra or {}

        if eid == "3":
            self._from_eid3(e, extra)
        elif eid == "4624":
            self._from_eid4624(e, extra)
        elif eid in ("4768", "4769"):
            self._from_kerberos(e, extra, eid)
        else:
            self._from_generic(e, extra)

        if e.raw_source.value == "pcap" and extra.get("correlated_host"):
            self._from_pcap_enriched(e, extra)

    def _from_eid3(self, e: ForensicEvent, extra: dict) -> None:
        """Sysmon EID 3: the emitting host's src_ip → known hostname + user."""
        src_ip = (
            extra.get("SourceIp") or extra.get("sourceip") or
            extra.get("SourceAddress") or extra.get("sourceaddress") or ""
        ).strip()
        dst_ip = (
            extra.get("DestinationIp") or extra.get("destinationip") or
            extra.get("DestinationAddress") or extra.get("destinationaddress") or ""
        ).strip()
        dst_port = _parse_port(
            extra.get("DestinationPort") or extra.get("destinationport")
        )

        if _is_ip(src_ip) and e.source_host and e.source_host not in ("UNKNOWN-HOST", ""):
            entry = self._entry(src_ip)
            entry.merge_hostname(e.source_host, weight=3)
            entry.add_user(e.user)
            entry.promote_role("workstation")
            entry._update_time(e.timestamp)
            entry.source_eids.add("3")

        if _is_ip(dst_ip) and dst_port is not None:
            entry = self._entry(dst_ip)
            if dst_port in _DC_PORTS:
                entry.promote_role("dc")
            elif dst_port in _SERVER_PORTS:
                entry.promote_role("server")
            entry._update_time(e.timestamp)
            entry.source_eids.add("3-dst")

    def _from_eid4624(self, e: ForensicEvent, extra: dict) -> None:
        """
        EID 4624 (Successful Logon):
          IpAddress      = the connecting client's IP
          WorkstationName = the client's NetBIOS hostname
          TargetUserName  = the account being logged in as
        """
        client_ip = (
            extra.get("IpAddress") or extra.get("ipaddress") or
            extra.get("SourceNetworkAddress") or extra.get("sourcenetworkaddress") or ""
        ).strip()
        client_ip = _strip_ipv6_prefix(client_ip)

        workstation = (
            extra.get("WorkstationName") or extra.get("workstationname") or ""
        ).strip()
        target_user = (
            extra.get("TargetUserName") or extra.get("targetusername") or ""
        ).strip()

        if not _is_ip(client_ip) or client_ip in ("-", "127.0.0.1", "::1"):
            return

        entry = self._entry(client_ip)
        if workstation and workstation not in ("-", ""):
            entry.merge_hostname(workstation.upper(), weight=2)
        entry.add_user(target_user or e.user)
        entry.promote_role("workstation")
        entry._update_time(e.timestamp)
        entry.source_eids.add("4624")

    def _from_kerberos(self, e: ForensicEvent, extra: dict, eid: str) -> None:
        """
        EID 4768/4769 (Kerberos AS-REQ / TGS-REQ):
          ClientAddress = the requesting client's IP (often IPv4-mapped IPv6)
          TargetUserName = the requesting principal
        The host that logged this event is always the KDC → mark it DC.
        """
        client_ip = (
            extra.get("ClientAddress") or extra.get("clientaddress") or
            extra.get("IpAddress") or extra.get("ipaddress") or ""
        ).strip()
        client_ip = _strip_ipv6_prefix(client_ip)

        req_user = (
            extra.get("TargetUserName") or extra.get("targetusername") or ""
        ).strip()

        if _is_ip(client_ip) and client_ip not in ("127.0.0.1", "::1"):
            entry = self._entry(client_ip)
            entry.add_user(req_user or e.user)
            entry._update_time(e.timestamp)
            entry.source_eids.add(eid)

        # The logging host is the KDC — if stored as an IP, mark it DC
        if _is_ip(e.source_host):
            kdc = self._entry(e.source_host)
            kdc.promote_role("dc")
            kdc._update_time(e.timestamp)
            kdc.source_eids.add(eid + "-kdc")

    def _from_generic(self, e: ForensicEvent, extra: dict) -> None:
        """
        Fallback: harvest an IP from any known extra field when the event
        already has a resolved (non-IP) hostname in source_host.
        """
        if not extra or not e.source_host:
            return
        if e.source_host in ("UNKNOWN-HOST", "") or _is_ip(e.source_host):
            return

        for key in ("src_ip", "source_ip", "SourceIp", "sourceip", "SourceAddress"):
            val = str(extra.get(key) or "").strip()
            if _is_ip(val):
                entry = self._entry(val)
                entry.merge_hostname(e.source_host, weight=1)
                entry.add_user(e.user)
                entry._update_time(e.timestamp)
                break

    def _from_pcap_enriched(self, e: ForensicEvent, extra: dict) -> None:
        """
        PCAP events enriched by network_host_correlator carry correlated_host /
        correlated_user.  Weight 4 — highest confidence because the 4-tuple join
        is confirmed.
        """
        src_ip = (extra.get("src_ip") or e.source_host or "").strip()
        corr_host: str = extra.get("correlated_host") or ""
        corr_user: Optional[str] = extra.get("correlated_user")

        if _is_ip(src_ip) and corr_host:
            entry = self._entry(src_ip)
            entry.merge_hostname(corr_host, weight=4)
            entry.add_user(corr_user)
            entry.promote_role("workstation")
            entry._update_time(e.timestamp)
            entry.source_eids.add("pcap-correlated")

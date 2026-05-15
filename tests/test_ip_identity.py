"""
Tests for backend/analysis/ip_identity.py

Covers every evidence source, role classification, confidence priority,
edge cases (IPv6-mapped addresses, machine accounts, empty input).
No network calls, no DB connections.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from backend.analysis.ip_identity import (
    IpIdentityTable,
    HostIdentity,
    _strip_ipv6_prefix,
    _is_ip,
    _parse_port,
    _DC_PORTS,
    _SERVER_PORTS,
)
from backend.schema import ForensicEvent, RawSource


# ── Helpers ───────────────────────────────────────────────────────────────────

_TS = datetime(2024, 6, 1, 12, 0, 0)


def _ev(
    event_id: Optional[str] = None,
    source_host: str = "WORKSTATION-01",
    user: Optional[str] = None,
    raw_source: RawSource = RawSource.GENERIC,
    extra: Optional[dict] = None,
    ts: datetime = _TS,
) -> ForensicEvent:
    return ForensicEvent(
        timestamp=ts,
        event_type="test",
        source_host=source_host,
        user=user,
        description="",
        raw_source=raw_source,
        event_id=event_id,
        extra=extra or {},
    )


# ── Unit tests: utility functions ─────────────────────────────────────────────

def test_strip_ipv6_prefix_lower():
    assert _strip_ipv6_prefix("::ffff:192.168.1.5") == "192.168.1.5"


def test_strip_ipv6_prefix_upper():
    assert _strip_ipv6_prefix("::FFFF:10.0.0.1") == "10.0.0.1"


def test_strip_ipv6_prefix_plain():
    assert _strip_ipv6_prefix("192.168.1.5") == "192.168.1.5"


def test_is_ip_valid():
    assert _is_ip("192.168.1.1")
    assert _is_ip("10.0.0.1")
    assert _is_ip("255.255.255.0")


def test_is_ip_rejects_non_ip():
    assert not _is_ip("WORKSTATION-01")
    assert not _is_ip("")
    assert not _is_ip(None)
    assert not _is_ip("not.an.ip.address.here")


def test_parse_port_valid():
    assert _parse_port(88) == 88
    assert _parse_port("443") == 443
    assert _parse_port(65535) == 65535


def test_parse_port_out_of_range():
    assert _parse_port(0) is None
    assert _parse_port(70000) is None
    assert _parse_port("abc") is None


# ── Unit tests: HostIdentity ───────────────────────────────────────────────────

def test_merge_hostname_higher_weight_wins():
    h = HostIdentity(ip="1.2.3.4")
    h.merge_hostname("LOW", weight=1)
    h.merge_hostname("HIGH", weight=3)
    h.merge_hostname("MEDIUM", weight=2)
    assert h.hostname == "HIGH"
    assert h.confidence == 3


def test_merge_hostname_same_weight_no_overwrite():
    h = HostIdentity(ip="1.2.3.4")
    h.merge_hostname("FIRST", weight=2)
    h.merge_hostname("SECOND", weight=2)
    assert h.hostname == "FIRST"   # lower-or-equal weight does not overwrite


def test_add_user_strips_machine_accounts():
    h = HostIdentity(ip="1.2.3.4")
    h.add_user("MACHINE$")
    h.add_user("WORKSTATION$")
    assert h.users == set()


def test_add_user_strips_whitespace():
    h = HostIdentity(ip="1.2.3.4")
    h.add_user("  jsmith  ")
    assert "jsmith" in h.users


def test_add_user_ignores_none_and_empty():
    h = HostIdentity(ip="1.2.3.4")
    h.add_user(None)
    h.add_user("")
    assert h.users == set()


def test_promote_role_hierarchy():
    h = HostIdentity(ip="1.2.3.4")
    assert h.role == "unknown"
    h.promote_role("workstation")
    assert h.role == "workstation"
    h.promote_role("server")
    assert h.role == "server"
    h.promote_role("dc")
    assert h.role == "dc"
    h.promote_role("workstation")   # dc is not demoted
    assert h.role == "dc"


# ── IpIdentityTable: build from EID 3 ─────────────────────────────────────────

def test_eid3_maps_source_ip_to_hostname_and_user():
    events = [_ev(
        event_id="3",
        source_host="WORKSTATION-01",
        user="jsmith",
        extra={"SourceIp": "192.168.1.50", "DestinationIp": "10.0.0.5", "DestinationPort": "80"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.1.50")
    assert entry is not None
    assert entry.hostname == "WORKSTATION-01"
    assert "jsmith" in entry.users
    assert entry.role == "workstation"
    assert entry.confidence == 3
    assert "3" in entry.source_eids


def test_eid3_destination_port_88_marks_dc():
    events = [_ev(
        event_id="3",
        source_host="WORKSTATION-01",
        extra={"SourceIp": "192.168.1.50", "DestinationIp": "10.0.0.1", "DestinationPort": "88"},
    )]
    tbl = IpIdentityTable.build(events)
    dc_entry = tbl.resolve("10.0.0.1")
    assert dc_entry is not None
    assert dc_entry.role == "dc"


def test_eid3_destination_port_389_marks_dc():
    events = [_ev(
        event_id="3",
        source_host="HOST",
        extra={"SourceIp": "192.168.1.2", "DestinationIp": "10.0.0.2", "DestinationPort": "389"},
    )]
    tbl = IpIdentityTable.build(events)
    assert tbl.resolve("10.0.0.2").role == "dc"


def test_eid3_destination_port_443_marks_server():
    events = [_ev(
        event_id="3",
        source_host="HOST",
        extra={"SourceIp": "192.168.1.2", "DestinationIp": "10.0.1.1", "DestinationPort": "443"},
    )]
    tbl = IpIdentityTable.build(events)
    assert tbl.resolve("10.0.1.1").role == "server"


def test_eid3_unknown_host_not_indexed():
    events = [_ev(
        event_id="3",
        source_host="UNKNOWN-HOST",
        extra={"SourceIp": "192.168.1.50", "DestinationIp": "10.0.0.5", "DestinationPort": "80"},
    )]
    tbl = IpIdentityTable.build(events)
    # Destination gets role=server (port 80), but source should not get a hostname
    src_entry = tbl.resolve("192.168.1.50")
    assert src_entry is None or src_entry.hostname == ""


def test_eid3_case_insensitive_field_names():
    """Lower-case field names (e.g. Sysmon in some parsers) must be accepted."""
    events = [_ev(
        event_id="3",
        source_host="HOST-A",
        user="alice",
        extra={"sourceip": "10.1.1.10", "destinationip": "10.2.2.20", "destinationport": "445"},
    )]
    tbl = IpIdentityTable.build(events)
    assert tbl.resolve("10.1.1.10") is not None
    assert tbl.resolve("10.1.1.10").hostname == "HOST-A"


# ── IpIdentityTable: build from EID 4624 ──────────────────────────────────────

def test_eid4624_maps_client_ip_to_workstation_and_user():
    events = [_ev(
        event_id="4624",
        source_host="DC-01",
        extra={
            "IpAddress": "192.168.1.75",
            "WorkstationName": "LAPTOP-77",
            "TargetUserName": "bobsmith",
        },
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.1.75")
    assert entry is not None
    assert entry.hostname == "LAPTOP-77"
    assert "bobsmith" in entry.users
    assert entry.role == "workstation"
    assert entry.confidence == 2
    assert "4624" in entry.source_eids


def test_eid4624_ipv6_mapped_address_normalized():
    events = [_ev(
        event_id="4624",
        extra={
            "IpAddress": "::ffff:192.168.1.99",
            "WorkstationName": "WORKSTATION-99",
            "TargetUserName": "carol",
        },
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.1.99")
    assert entry is not None
    assert entry.hostname == "WORKSTATION-99"


def test_eid4624_loopback_ignored():
    events = [_ev(
        event_id="4624",
        extra={"IpAddress": "127.0.0.1", "WorkstationName": "LOCAL", "TargetUserName": "admin"},
    )]
    tbl = IpIdentityTable.build(events)
    assert tbl.resolve("127.0.0.1") is None


def test_eid4624_machine_account_not_added_as_user():
    events = [_ev(
        event_id="4624",
        extra={
            "IpAddress": "10.0.0.55",
            "WorkstationName": "SERV",
            "TargetUserName": "SERV$",
        },
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.0.0.55")
    assert entry is not None
    assert entry.users == set()


def test_eid4624_dash_workstation_name_ignored():
    events = [_ev(
        event_id="4624",
        extra={"IpAddress": "10.0.0.22", "WorkstationName": "-", "TargetUserName": "dave"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.0.0.22")
    assert entry is not None
    assert entry.hostname == ""


# ── IpIdentityTable: build from EID 4768/4769 ─────────────────────────────────

def test_kerberos_4769_maps_client_ip_to_user():
    events = [_ev(
        event_id="4769",
        source_host="DC-01",
        extra={"ClientAddress": "192.168.5.10", "TargetUserName": "eve"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.5.10")
    assert entry is not None
    assert "eve" in entry.users
    assert "4769" in entry.source_eids


def test_kerberos_4768_ipv6_mapped_normalized():
    events = [_ev(
        event_id="4768",
        source_host="DC-02",
        extra={"ClientAddress": "::ffff:10.10.10.5", "TargetUserName": "frank"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.10.10.5")
    assert entry is not None
    assert "frank" in entry.users


def test_kerberos_source_host_is_ip_gets_dc_role():
    """When the KDC's source_host field is an IP (unusual but valid), mark it DC."""
    events = [_ev(
        event_id="4768",
        source_host="10.0.0.1",    # KDC stored as IP, not hostname
        extra={"ClientAddress": "192.168.1.20", "TargetUserName": "grace"},
    )]
    tbl = IpIdentityTable.build(events)
    kdc_entry = tbl.resolve("10.0.0.1")
    assert kdc_entry is not None
    assert kdc_entry.role == "dc"


def test_kerberos_machine_account_not_added():
    events = [_ev(
        event_id="4769",
        extra={"ClientAddress": "192.168.1.30", "TargetUserName": "HOST$"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.1.30")
    assert entry is not None
    assert entry.users == set()


# ── IpIdentityTable: PCAP-correlated enrichment ───────────────────────────────

def test_pcap_correlated_highest_confidence():
    events = [
        # Low-confidence source first
        _ev(
            event_id="4624",
            extra={"IpAddress": "10.0.0.50", "WorkstationName": "OLD-NAME"},
        ),
        # Correlated PCAP overrides with weight=4
        _ev(
            event_id=None,
            source_host="10.0.0.50",
            raw_source=RawSource.PCAP,
            extra={
                "src_ip": "10.0.0.50",
                "correlated_host": "REAL-HOSTNAME",
                "correlated_user": "henry",
            },
        ),
    ]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.0.0.50")
    assert entry is not None
    assert entry.hostname == "REAL-HOSTNAME"
    assert "henry" in entry.users
    assert "pcap-correlated" in entry.source_eids


def test_pcap_without_correlated_host_not_enriched():
    events = [_ev(
        event_id=None,
        source_host="10.0.0.60",
        raw_source=RawSource.PCAP,
        extra={"src_ip": "10.0.0.60"},    # no correlated_host
    )]
    tbl = IpIdentityTable.build(events)
    # PCAP event with no correlated_host produces no entry (no useful attribution)
    entry = tbl.resolve("10.0.0.60")
    assert entry is None or "pcap-correlated" not in (entry.source_eids or set())


# ── IpIdentityTable: generic fallback ─────────────────────────────────────────

def test_generic_fallback_maps_src_ip_to_hostname():
    events = [_ev(
        event_id="7045",
        source_host="FILE-SERVER-01",
        user="svc_backup",
        extra={"src_ip": "10.5.5.5"},
    )]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.5.5.5")
    assert entry is not None
    assert entry.hostname == "FILE-SERVER-01"


def test_generic_fallback_skips_when_source_host_is_ip():
    """Don't record source_host as a hostname when it is itself an IP."""
    events = [_ev(
        event_id="7045",
        source_host="10.0.0.1",   # source_host is an IP — useless as a hostname
        extra={"src_ip": "10.0.0.1"},
    )]
    tbl = IpIdentityTable.build(events)
    # Should not index — no useful hostname to record
    entry = tbl.resolve("10.0.0.1")
    assert entry is None or entry.hostname == ""


# ── Confidence and user accumulation across sources ───────────────────────────

def test_users_accumulated_across_events():
    events = [
        _ev(event_id="4769", extra={"ClientAddress": "10.1.1.1", "TargetUserName": "alice"}),
        _ev(event_id="4769", extra={"ClientAddress": "10.1.1.1", "TargetUserName": "bob"}),
        _ev(event_id="4769", extra={"ClientAddress": "10.1.1.1", "TargetUserName": "alice"}),
    ]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.1.1.1")
    assert entry.users == {"alice", "bob"}


def test_higher_confidence_source_wins_over_lower():
    """EID 3 (weight=3) must overwrite EID 4624 (weight=2) hostname."""
    events = [
        _ev(
            event_id="4624",
            extra={"IpAddress": "192.168.2.1", "WorkstationName": "OLD-NAME"},
        ),
        _ev(
            event_id="3",
            source_host="CORRECT-NAME",
            extra={"SourceIp": "192.168.2.1", "DestinationIp": "10.0.0.1", "DestinationPort": "80"},
        ),
    ]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("192.168.2.1")
    assert entry.hostname == "CORRECT-NAME"
    assert entry.confidence == 3


# ── Timestamps ────────────────────────────────────────────────────────────────

def test_first_and_last_seen_tracked():
    t1 = datetime(2024, 1, 1, 8, 0)
    t2 = datetime(2024, 1, 1, 9, 0)
    t3 = datetime(2024, 1, 1, 10, 0)
    events = [
        _ev(event_id="4769", extra={"ClientAddress": "10.0.0.7", "TargetUserName": "x"}, ts=t2),
        _ev(event_id="4769", extra={"ClientAddress": "10.0.0.7", "TargetUserName": "x"}, ts=t1),
        _ev(event_id="4769", extra={"ClientAddress": "10.0.0.7", "TargetUserName": "x"}, ts=t3),
    ]
    tbl = IpIdentityTable.build(events)
    entry = tbl.resolve("10.0.0.7")
    assert entry.first_seen == t1
    assert entry.last_seen == t3


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_event_list():
    tbl = IpIdentityTable.build([])
    assert len(tbl) == 0
    assert tbl.resolve("10.0.0.1") is None


def test_resolve_unknown_ip_returns_none():
    tbl = IpIdentityTable.build([])
    assert tbl.resolve("1.2.3.4") is None
    assert tbl.resolve("") is None
    assert tbl.resolve("  ") is None


def test_all_entries_returns_all():
    events = [
        _ev(event_id="3", source_host="H1", extra={"SourceIp": "10.0.0.1", "DestinationIp": "10.0.0.2", "DestinationPort": "80"}),
        _ev(event_id="4624", extra={"IpAddress": "10.0.0.3", "WorkstationName": "W3"}),
    ]
    tbl = IpIdentityTable.build(events)
    ips = {e.ip for e in tbl.all_entries()}
    assert "10.0.0.1" in ips
    assert "10.0.0.3" in ips


def test_resolve_normalizes_ipv6_prefix():
    events = [_ev(
        event_id="4624",
        extra={"IpAddress": "::ffff:192.168.10.10", "WorkstationName": "LAPTOP-X"},
    )]
    tbl = IpIdentityTable.build(events)
    # Both the raw form and the normalized form should resolve
    assert tbl.resolve("192.168.10.10") is not None
    assert tbl.resolve("::ffff:192.168.10.10") is not None


def test_all_dc_ports_trigger_dc_role():
    for port in [88, 389, 636, 3268, 3269]:
        events = [_ev(
            event_id="3",
            source_host="WORKSTATION",
            extra={"SourceIp": "192.168.1.5", "DestinationIp": "10.0.0.1", "DestinationPort": str(port)},
        )]
        tbl = IpIdentityTable.build(events)
        entry = tbl.resolve("10.0.0.1")
        assert entry is not None and entry.role == "dc", f"port {port} should produce dc role"


def test_events_without_extra_do_not_crash():
    events = [_ev(event_id="4624", extra=None)]
    tbl = IpIdentityTable.build(events)
    assert len(tbl) == 0

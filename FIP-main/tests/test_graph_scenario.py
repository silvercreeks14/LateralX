"""
Phase 3 — Cross-Source Scenario Graph Tests.

All tests use in-memory ForensicEvent objects (no DB required).

Invariants verified:
  1. _is_ip_address correctly identifies bare IPv4 addresses.
  2. When source_host is a raw IP, the node type is external_ip.
  3. WAF/PCAP event + EventID 4688 within ±10 min → initial_access scenario edge.
  4. WAF/PCAP event + EventID 4688 outside ±10 min → no scenario edge created.
  5. EventID 4688 + EventID 4769 within ±10 min → execution scenario edge.
  6. Full chain WAF→4688→4769 → all three attack stages present.
  7. PCAP-only upload → network graph (existing path preserved).
  8. Host-log-only upload → logon/generic graph (no scenario graph invoked).
  9. Mixed PCAP + host logs → graph_mode == "scenario".
 10. Scenario edges carry attack_stage and scenario_link fields.
 11. External IP nodes are marked suspicious by default.
 12. Missing hostname falls back to 'unknown_host' node id.
"""

from datetime import datetime, timedelta
import pytest
from backend.analysis.graph import (
    _is_ip_address,
    _build_cross_source_scenario_graph,
    build_attack_graph,
)
from backend.schema import ForensicEvent, RawSource

# ── Fixtures & helpers ────────────────────────────────────────────────────────

T0 = datetime(2024, 1, 15, 10, 0, 0)


def _pcap(src_ip: str, dst_ip: str = "10.0.0.1",
          t_offset_min: float = 0, dst_port: int = 4444) -> ForensicEvent:
    return ForensicEvent(
        timestamp=T0 + timedelta(minutes=t_offset_min),
        event_type="tcp",
        source_host=src_ip,
        description=f"{src_ip} -> {dst_ip}:{dst_port}",
        raw_source=RawSource.PCAP,
        extra={"dst_ip": dst_ip, "dst_port": dst_port},
    )


def _host(host: str, event_id: str, user: str | None = None,
          t_offset_min: float = 0,
          raw_source: RawSource = RawSource.GENERIC) -> ForensicEvent:
    return ForensicEvent(
        timestamp=T0 + timedelta(minutes=t_offset_min),
        event_type="windows_event",
        source_host=host,
        user=user,
        description=f"Event {event_id} on {host}",
        raw_source=raw_source,
        event_id=event_id,
    )


def _logon(host: str, user: str, t_offset_min: float = 0) -> ForensicEvent:
    return ForensicEvent(
        timestamp=T0 + timedelta(minutes=t_offset_min),
        event_type="logon",
        source_host=host,
        user=user,
        description=f"Logon by {user} on {host}",
        raw_source=RawSource.GENERIC,
        event_id="4624",
    )


# ── Unit tests for _is_ip_address ────────────────────────────────────────────

def test_is_ip_address_valid():
    assert _is_ip_address("192.168.1.100") is True
    assert _is_ip_address("10.0.0.1") is True
    assert _is_ip_address("203.0.113.42") is True


def test_is_ip_address_invalid():
    assert _is_ip_address("WORKSTATION-01") is False
    assert _is_ip_address("dc01.corp.local") is False
    assert _is_ip_address("") is False
    assert _is_ip_address("not-an-ip") is False


# ── IP-as-node fallback ───────────────────────────────────────────────────────

def test_ip_source_host_becomes_external_ip_node():
    """When source_host is a bare IP, the node type must be external_ip."""
    pcap = [_pcap("203.0.113.1", "10.0.0.50")]
    proc = [_host("10.0.0.50", "4688")]
    result = _build_cross_source_scenario_graph(pcap, proc)

    nodes_by_id = {n["data"]["id"]: n for n in result["elements"]["nodes"]}
    assert "203.0.113.1" in nodes_by_id
    assert nodes_by_id["203.0.113.1"]["data"]["type"] == "external_ip"


def test_external_ip_node_suspicious_by_default():
    """external_ip nodes start suspicious (they are untrusted external sources)."""
    pcap = [_pcap("1.2.3.4", "10.0.0.5")]
    proc = [_host("10.0.0.5", "4688")]
    result = _build_cross_source_scenario_graph(pcap, proc)

    nodes_by_id = {n["data"]["id"]: n for n in result["elements"]["nodes"]}
    assert nodes_by_id["1.2.3.4"]["data"]["suspicious"] is True


# ── Scenario A: initial_access ────────────────────────────────────────────────

def test_initial_access_edge_within_window():
    """WAF IP + EventID 4688 within 10 min → initial_access scenario edge."""
    pcap = [_pcap("203.0.113.1", "10.0.0.50", t_offset_min=0)]
    proc = [_host("WORKSTATION-01", "4688", t_offset_min=5)]   # 5 min later — inside window
    result = _build_cross_source_scenario_graph(pcap, proc)

    scenario_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "initial_access"
    ]
    assert len(scenario_edges) == 1
    edge = scenario_edges[0]
    assert edge["data"]["source"] == "203.0.113.1"
    assert edge["data"]["target"] == "WORKSTATION-01"
    assert edge["data"]["scenario_link"] is True
    assert edge["data"]["suspicious"] is True


def test_initial_access_edge_outside_window():
    """WAF IP + EventID 4688 outside ±10 min → no scenario edge."""
    pcap = [_pcap("203.0.113.1", "10.0.0.50", t_offset_min=0)]
    proc = [_host("WORKSTATION-01", "4688", t_offset_min=15)]  # 15 min — outside window
    result = _build_cross_source_scenario_graph(pcap, proc)

    scenario_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "initial_access"
    ]
    assert len(scenario_edges) == 0


def test_initial_access_boundary_exactly_10_min():
    """WAF IP + EventID 4688 at exactly ±10 min → edge IS created (inclusive boundary)."""
    pcap = [_pcap("5.5.5.5", "10.0.0.1", t_offset_min=0)]
    proc = [_host("HOST-A", "4688", t_offset_min=10)]  # exactly 10 min
    result = _build_cross_source_scenario_graph(pcap, proc)

    scenario_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "initial_access"
    ]
    assert len(scenario_edges) == 1


# ── Scenario B: execution (4688 → 4769) ──────────────────────────────────────

def test_execution_edge_4688_to_4769_within_window():
    """EventID 4688 + EventID 4769 within 10 min → execution scenario edge."""
    pcap = [_pcap("8.8.8.8", "10.0.0.1", t_offset_min=-5)]  # before, unrelated timing
    proc = [_host("HOST-A", "4688", t_offset_min=0)]
    kerb = [_host("DC-01", "4769", t_offset_min=7)]   # 7 min after 4688 — inside window
    result = _build_cross_source_scenario_graph(pcap, proc + kerb)

    exec_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "execution"
    ]
    assert len(exec_edges) == 1
    assert exec_edges[0]["data"]["source"] == "HOST-A"
    assert exec_edges[0]["data"]["target"] == "DC-01"


def test_execution_edge_4688_to_4769_outside_window():
    """EventID 4688 + EventID 4769 > 10 min apart → no execution edge."""
    pcap = [_pcap("1.1.1.1", "10.0.0.1")]
    proc = [_host("HOST-A", "4688", t_offset_min=0)]
    kerb = [_host("DC-01", "4769", t_offset_min=20)]  # 20 min — outside window
    result = _build_cross_source_scenario_graph(pcap, proc + kerb)

    exec_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "execution"
    ]
    assert len(exec_edges) == 0


# ── Scenario C: privilege_escalation (4769 → logon) ──────────────────────────

def test_privilege_escalation_edge_after_4769():
    """4769 host + subsequent logon to different host within 10 min → priv_esc edge."""
    pcap = [_pcap("2.2.2.2", "10.0.0.1")]
    kerb = [_host("DC-01", "4769", t_offset_min=0)]
    logon_ev = [_logon("FILE-SERVER", user="jdoe", t_offset_min=5)]  # 5 min after kerb
    result = _build_cross_source_scenario_graph(pcap, kerb + logon_ev)

    priv_edges = [
        e for e in result["elements"]["edges"]
        if e["data"].get("attack_stage") == "privilege_escalation"
    ]
    assert len(priv_edges) == 1
    assert priv_edges[0]["data"]["source"] == "DC-01"
    assert priv_edges[0]["data"]["target"] == "FILE-SERVER"


# ── Full attack chain ─────────────────────────────────────────────────────────

def test_full_chain_all_three_stages():
    """
    Complete attack chain:
      203.0.113.1 (WAF) → WORKSTATION-01 (4688) → DC-01 (4769) → FILE-SERVER (4624)
    All three attack_stage values must be present in the edge set.
    """
    pcap = [_pcap("203.0.113.1", "10.0.0.10", t_offset_min=0)]
    proc = [_host("WORKSTATION-01", "4688", t_offset_min=3)]
    kerb = [_host("DC-01", "4769", t_offset_min=8)]
    logon_ev = [_logon("FILE-SERVER", user="jdoe", t_offset_min=13)]

    result = _build_cross_source_scenario_graph(pcap, proc + kerb + logon_ev)

    stages = {e["data"]["attack_stage"] for e in result["elements"]["edges"]
              if e["data"].get("scenario_link")}
    assert "initial_access" in stages
    assert "execution" in stages
    assert "privilege_escalation" in stages
    assert result["scenario_links"] == 3


# ── build_attack_graph dispatcher ────────────────────────────────────────────

def test_build_graph_pcap_only_returns_network_graph():
    """PCAP-only events → network graph (no scenario mode)."""
    events = [_pcap("1.1.1.1", "2.2.2.2")]
    result = build_attack_graph(events)
    assert result.get("graph_mode") != "scenario"
    assert "network_connections" in result


def test_build_graph_host_only_no_scenario():
    """Host-log-only events → logon or generic graph, not scenario."""
    events = [_host("HOST-A", "4624", user="alice")]
    result = build_attack_graph(events)
    assert result.get("graph_mode") != "scenario"


def test_build_graph_mixed_returns_scenario_mode():
    """PCAP + host log events together → graph_mode == 'scenario'."""
    events = [
        _pcap("203.0.113.1", "10.0.0.1", t_offset_min=0),
        _host("WORKSTATION-01", "4688", t_offset_min=5),
    ]
    result = build_attack_graph(events)
    assert result["graph_mode"] == "scenario"


def test_scenario_graph_scenario_links_count():
    """scenario_links key reflects actual number of cross-source edges."""
    pcap = [_pcap("5.5.5.5", "10.0.0.1", t_offset_min=0)]
    proc = [_host("HOST-B", "4688", t_offset_min=4)]
    kerb = [_host("DC-01", "4769", t_offset_min=9)]
    result = build_attack_graph(pcap + proc + kerb)
    # initial_access (WAF→HOST-B) + execution (HOST-B→DC-01) = 2 scenario edges
    assert result["scenario_links"] == 2


def test_missing_hostname_uses_unknown_host():
    """Events with empty source_host fall back to 'unknown_host' node id."""
    proc = [ForensicEvent(
        timestamp=T0,
        event_type="windows_event",
        source_host="",      # empty hostname
        description="4688 no host",
        raw_source=RawSource.GENERIC,
        event_id="4688",
    )]
    pcap = [_pcap("9.9.9.9", "10.0.0.1", t_offset_min=2)]
    result = _build_cross_source_scenario_graph(pcap, proc)

    node_ids = {n["data"]["id"] for n in result["elements"]["nodes"]}
    assert "unknown_host" in node_ids

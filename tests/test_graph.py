from datetime import datetime
from backend.schema import ForensicEvent, RawSource
from backend.analysis.graph import build_attack_graph


def _make_pcap(ts: str, src: str, dst: str, proto: str, port: int) -> ForensicEvent:
    return ForensicEvent(
        timestamp=datetime.fromisoformat(ts),
        event_type=proto,
        source_host=src,
        user=None,
        description=f"{proto} flow",
        raw_source=RawSource.PCAP,
        event_id=None,
        extra={"dst_ip": dst, "dst_port": port, "transport": "TCP"},
    )


def _make_logon(ts: str, host: str, user: str) -> ForensicEvent:
    return ForensicEvent(
        timestamp=datetime.fromisoformat(ts),
        event_type="Logon",
        source_host=host,
        user=user,
        description="Event ID 4624 logon",
        raw_source=RawSource.GENERIC,
        event_id="4624",
    )


def test_graph_nodes_created():
    events = [
        _make_logon("2024-01-01 08:00:00", "HOST-A", "alice"),
        _make_logon("2024-01-01 08:05:00", "HOST-B", "alice"),
    ]
    result = build_attack_graph(events)
    node_ids = [n["data"]["id"] for n in result["elements"]["nodes"]]
    assert "HOST-A" in node_ids
    assert "HOST-B" in node_ids
    assert "alice" in node_ids


def test_lateral_movement_flagged():
    events = [
        _make_logon("2024-01-01 08:00:00", "HOST-A", "jdoe"),
        _make_logon("2024-01-01 08:05:00", "HOST-B", "jdoe"),
        _make_logon("2024-01-01 08:10:00", "HOST-C", "jdoe"),
    ]
    result = build_attack_graph(events)
    assert "jdoe" in result["suspicious_users"]


def test_no_false_positive_single_host():
    events = [
        _make_logon("2024-01-01 08:00:00", "HOST-A", "normal_user"),
        _make_logon("2024-01-01 09:00:00", "HOST-A", "normal_user"),
    ]
    result = build_attack_graph(events)
    assert "normal_user" not in result["suspicious_users"]


# ── PCAP network graph tests ──────────────────────────────────────────────────

def test_pcap_only_routes_to_network_graph():
    events = [
        _make_pcap("2024-01-01 10:00:00", "192.168.1.5", "10.0.0.1", "TCP", 443),
        _make_pcap("2024-01-01 10:00:01", "192.168.1.5", "8.8.8.8", "DNS", 53),
    ]
    result = build_attack_graph(events)
    node_ids = {n["data"]["id"] for n in result["elements"]["nodes"]}
    assert "192.168.1.5" in node_ids
    assert "10.0.0.1" in node_ids
    assert "8.8.8.8" in node_ids
    assert result["total_logon_events"] == 0
    assert result["network_connections"] == 2


def test_pcap_high_port_flagged_suspicious():
    # Port 4444 is a classic C2/meterpreter port — should be flagged
    events = [
        _make_pcap("2024-01-01 10:00:00", "192.168.1.10", "1.2.3.4", "TCP", 4444),
    ]
    result = build_attack_graph(events)
    assert "192.168.1.10" in result["suspicious_users"]
    edge = result["elements"]["edges"][0]
    assert edge["data"]["suspicious"] is True


def test_pcap_standard_https_not_flagged():
    events = [
        _make_pcap("2024-01-01 10:00:00", "192.168.1.20", "93.184.216.34", "TCP", 443),
    ]
    result = build_attack_graph(events)
    assert "192.168.1.20" not in result["suspicious_users"]
    edge = result["elements"]["edges"][0]
    assert edge["data"]["suspicious"] is False


def test_pcap_smb_always_flagged():
    # SMB is in _SENSITIVE_PROTOCOLS — flag regardless of port
    events = [
        _make_pcap("2024-01-01 10:00:00", "192.168.1.30", "192.168.1.2", "SMB", 445),
    ]
    result = build_attack_graph(events)
    assert "192.168.1.30" in result["suspicious_users"]


def test_mixed_logon_and_pcap_uses_scenario_graph():
    # Phase 3: when both PCAP and host log events are present, the cross-source
    # scenario graph is returned — both IP nodes AND logon nodes appear.
    events = [
        _make_logon("2024-01-01 08:00:00", "HOST-A", "alice"),
        _make_pcap("2024-01-01 10:00:00", "192.168.1.5", "10.0.0.1", "TCP", 443),
    ]
    result = build_attack_graph(events)
    node_ids = {n["data"]["id"] for n in result["elements"]["nodes"]}
    assert "alice" in node_ids
    assert "HOST-A" in node_ids
    # PCAP IP nodes ARE present in the scenario graph
    assert "192.168.1.5" in node_ids
    assert result["graph_mode"] == "scenario"

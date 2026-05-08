"""Tests for evidence-gated behavioral Sigma rule generation."""
from datetime import datetime, timedelta
from backend.schema import ForensicEvent, RawSource
from backend.analysis.rules import generate_behavioral_sigma_rules


def _ev(
    user: str,
    ts: datetime,
    event_id: str | None = None,
    host: str = "HOST-A",
    desc: str = "normal activity",
    etype: str = "Security",
) -> ForensicEvent:
    return ForensicEvent(
        timestamp=ts,
        event_type=etype,
        source_host=host,
        user=user,
        description=desc,
        raw_source=RawSource.GENERIC,
        event_id=event_id,
    )


BASE = datetime(2024, 6, 1, 14, 0, 0)


def test_no_events_returns_no_rules():
    assert generate_behavioral_sigma_rules([]) == []


def test_clean_events_return_no_behavioral_rules():
    events = [_ev("alice", BASE + timedelta(minutes=i), event_id="4624") for i in range(3)]
    rules = generate_behavioral_sigma_rules(events)
    # 3 logins to the same host, no failures — no rule should fire
    assert all(r["id"] != "brute_force_success" for r in rules)


# ── Brute-force pattern ───────────────────────────────────────────────────────

def test_brute_force_success_pattern_detected():
    # 3 failures within 10 min, then success within 5 min
    events = [
        _ev("bob", BASE + timedelta(minutes=i), event_id="4625") for i in range(3)
    ] + [
        _ev("bob", BASE + timedelta(minutes=4), event_id="4624"),
    ]
    rules = generate_behavioral_sigma_rules(events)
    titles = [r["title"] for r in rules]
    assert any("Brute-Force" in t for t in titles)
    rule = next(r for r in rules if "Brute-Force" in r["title"])
    assert "bob" in rule["description"]
    assert "attack.credential_access" in rule["tags"]


def test_brute_force_without_success_no_rule():
    # Failures only, no subsequent success
    events = [
        _ev("charlie", BASE + timedelta(minutes=i), event_id="4625") for i in range(5)
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert not any("Brute-Force" in r["title"] for r in rules)


# ── Encoded command pattern ───────────────────────────────────────────────────

def test_encoded_command_detected():
    events = [
        _ev("dave", BASE, event_id="4688",
            desc="powershell.exe -EncodedCommand SGVsbG8gV29ybGQ="),
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert any("Encoded" in r["title"] for r in rules)
    rule = next(r for r in rules if "Encoded" in r["title"])
    assert "attack.execution" in rule["tags"]
    assert rule["level"] == "high"


def test_no_encoded_command_no_rule():
    events = [_ev("eve", BASE, event_id="4688", desc="notepad.exe opened")]
    rules = generate_behavioral_sigma_rules(events)
    assert not any("Encoded" in r["title"] for r in rules)


# ── Lateral movement pattern ─────────────────────────────────────────────────

def test_lateral_movement_detected():
    # Same user logs onto 3 different hosts within 30 min
    events = [
        _ev("frank", BASE + timedelta(minutes=i * 5), event_id="4624",
            host=f"HOST-{i}")
        for i in range(3)
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert any("Lateral Movement" in r["title"] for r in rules)
    rule = next(r for r in rules if "Lateral Movement" in r["title"])
    assert "frank" in rule["description"]
    assert "attack.lateral_movement" in rule["tags"]


def test_lateral_movement_outside_window_no_rule():
    # Same user on 3 hosts but spread over 2 hours — no rule
    events = [
        _ev("grace", BASE + timedelta(hours=i), event_id="4624", host=f"HOST-{i}")
        for i in range(3)
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert not any("Lateral Movement" in r["title"] for r in rules)


# ── Recon then pivot pattern ──────────────────────────────────────────────────

def test_recon_then_lateral_move_detected():
    events = [
        _ev("mallory", BASE, desc="whoami /all", host="HOST-A"),
        _ev("mallory", BASE + timedelta(minutes=10), event_id="4624", host="HOST-B"),
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert any("Reconnaissance" in r["title"] for r in rules)
    rule = next(r for r in rules if "Reconnaissance" in r["title"])
    assert "attack.discovery" in rule["tags"]
    assert rule["level"] == "medium"


def test_recon_without_subsequent_logon_no_rule():
    events = [
        _ev("norm", BASE, desc="whoami /all", host="HOST-A"),
    ]
    rules = generate_behavioral_sigma_rules(events)
    assert not any("Reconnaissance" in r["title"] for r in rules)


# ── UUID stability ────────────────────────────────────────────────────────────

def test_rule_ids_are_stable():
    events = [
        _ev("ivan", BASE + timedelta(minutes=i), event_id="4625") for i in range(3)
    ] + [_ev("ivan", BASE + timedelta(minutes=4), event_id="4624")]

    rules1 = generate_behavioral_sigma_rules(events)
    rules2 = generate_behavioral_sigma_rules(events)
    ids1 = {r["id"] for r in rules1}
    ids2 = {r["id"] for r in rules2}
    assert ids1 == ids2

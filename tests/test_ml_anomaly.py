"""Tests for ML anomaly detection — heuristic fallback path."""
from datetime import datetime, timedelta
from backend.schema import ForensicEvent, RawSource
from backend.analysis.ml_anomaly import score_all_users, _heuristic_score


def _ev(user: str, hour: int = 10, event_id: str | None = None, desc: str = "normal") -> ForensicEvent:
    ts = datetime(2024, 1, 1, hour, 0, 0)
    return ForensicEvent(
        timestamp=ts,
        event_type="Process",
        source_host="HOST-A",
        user=user,
        description=desc,
        raw_source=RawSource.GENERIC,
        event_id=event_id,
    )


# ── _heuristic_score unit tests ───────────────────────────────────────────────

def test_heuristic_clean_session_is_normal():
    events = [_ev("alice", hour=9) for _ in range(3)]
    result = _heuristic_score(events)
    assert result.risk_level == "normal"
    assert result.anomaly_score == 0.0
    assert result.confidence == "insufficient_data"


def test_heuristic_encoded_command_flagged():
    events = [_ev("bob", desc="powershell -encodedcommand AAAA")]
    result = _heuristic_score(events)
    assert result.anomaly_score >= 0.4
    assert "encoded or obfuscated commands" in result.contributing_factors


def test_heuristic_single_admin_tool_not_flagged():
    # Single certutil doesn't cross the >2 admin-tool threshold (reduces whoami FPs)
    events = [_ev("carol", desc="certutil -decode payload")]
    result = _heuristic_score(events)
    assert "admin/LOLBin tool usage" not in result.contributing_factors


def test_heuristic_multiple_admin_tools_flagged():
    # 3+ distinct admin/LOLBin events DO trigger the flag
    events = [
        _ev("carol", desc="certutil -decode payload"),
        _ev("carol", desc="psexec \\\\target cmd"),
        _ev("carol", desc="vssadmin list shadows"),
    ]
    result = _heuristic_score(events)
    assert result.anomaly_score >= 0.25
    assert "admin/LOLBin tool usage" in result.contributing_factors


def test_heuristic_off_hours_flagged():
    events = [_ev("dave", hour=2) for _ in range(5)]
    result = _heuristic_score(events)
    assert "high off-hours activity" in result.contributing_factors


def test_heuristic_multiple_red_flags_caps_at_one():
    events = [
        _ev("mallory", hour=3, desc="certutil -encodedcommand base64stuff"),
        _ev("mallory", hour=3, desc="certutil -encodedcommand base64stuff"),
    ]
    result = _heuristic_score(events)
    assert result.anomaly_score <= 1.0


def test_heuristic_failed_logins_flagged():
    events = [_ev("eve", event_id="4625") for _ in range(4)] + \
             [_ev("eve", event_id="4624")]
    result = _heuristic_score(events)
    assert "high failed login rate" in result.contributing_factors


def test_heuristic_multiple_hosts():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [
        ForensicEvent(
            timestamp=base + timedelta(minutes=i),
            event_type="Logon",
            source_host=f"HOST-{i}",
            user="mallory",
            description="logon",
            raw_source=RawSource.GENERIC,
        )
        for i in range(4)
    ]
    result = _heuristic_score(events)
    assert "accessed many hosts" in result.contributing_factors


# ── score_all_users fallback integration tests ────────────────────────────────

def test_score_all_users_no_model_returns_heuristic(tmp_path, monkeypatch):
    """Without a trained model, score_all_users must still return results."""
    import backend.analysis.ml_anomaly as ml_mod
    monkeypatch.setattr(ml_mod, "MODEL_PATH", tmp_path / "nonexistent.pkl")

    events = [_ev("alice", hour=9) for _ in range(3)]
    results = score_all_users(events)
    assert len(results) == 1
    assert results[0].confidence == "insufficient_data"
    assert results[0].entity == "alice"


def test_score_all_users_sparse_user_uses_heuristic(tmp_path, monkeypatch):
    """A user with <5 events must get a heuristic score even when a model exists."""
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from backend.analysis.ml_anomaly import FEATURE_NAMES, MIN_SESSION_EVENTS
    import backend.analysis.ml_anomaly as ml_mod

    # Build a minimal valid model package
    dummy_vecs = np.random.default_rng(0).random((15, len(FEATURE_NAMES)))
    scaler = StandardScaler().fit(dummy_vecs)
    model = IsolationForest(n_estimators=10, random_state=0).fit(scaler.transform(dummy_vecs))
    pkg = {
        "model": model,
        "scaler": scaler,
        "baseline_mean": dummy_vecs.mean(axis=0),
        "baseline_std": dummy_vecs.std(axis=0),
        "trained_on_users": 15,
        "trained_on_events": 100,
        "trained_at": "2024-01-01T00:00:00",
        "feature_names": FEATURE_NAMES,
    }
    model_path = tmp_path / "test_model.pkl"
    joblib.dump(pkg, model_path)
    monkeypatch.setattr(ml_mod, "MODEL_PATH", model_path)

    # User with only 2 events — below MIN_SESSION_EVENTS=5
    events = [_ev("sparse_user", hour=9) for _ in range(MIN_SESSION_EVENTS - 1)]
    results = score_all_users(events)
    assert len(results) == 1
    assert results[0].confidence == "insufficient_data"
    assert results[0].entity == "sparse_user"

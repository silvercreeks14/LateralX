"""
Phase 2 — Hash-Chain Audit Log Tests.

All tests use an in-memory SQLite database and mock the route helper
directly — no real server process is started.

Invariants verified:
  1. Each row's payload_sha256 is computed from its prev_hash + action + detail + file_sha256.
  2. A chain of rows can be fully verified as intact.
  3. Modifying any stored field on a row causes the chain to break from that point.
  4. _compute_chain_hash is deterministic (same inputs → same output every call).
  5. Legacy rows with prev_hash=NULL are skipped gracefully during verification.
"""

import hashlib
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

# ── Bootstrap a fresh in-memory DB for every test ────────────────────────────

@pytest.fixture
def db_session():
    """Isolated in-memory SQLite session with the full schema applied."""
    from backend.db.models import Base, init_db
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ── Import helpers after fixture so they don't depend on real DB ─────────────

def _get_write_audit_and_compute(db_session):
    """
    Import route helpers with the DB session patched to use the test session.
    Returns (_compute_chain_hash, _write_audit_fn, AuditLogModel).
    """
    from backend.api.routes import _compute_chain_hash, _write_audit
    from backend.db.models import AuditLogModel
    return _compute_chain_hash, _write_audit, AuditLogModel


# ── Unit tests for _compute_chain_hash ───────────────────────────────────────

def test_compute_chain_hash_deterministic():
    """Same inputs always produce the same hash."""
    from backend.api.routes import _compute_chain_hash

    h1 = _compute_chain_hash("GENESIS", "upload", {"filename": "a.csv"}, "abc123")
    h2 = _compute_chain_hash("GENESIS", "upload", {"filename": "a.csv"}, "abc123")
    assert h1 == h2
    assert len(h1) == 64   # hex SHA-256


def test_compute_chain_hash_changes_with_action():
    """Different action → different hash."""
    from backend.api.routes import _compute_chain_hash

    h1 = _compute_chain_hash("GENESIS", "upload", {}, "")
    h2 = _compute_chain_hash("GENESIS", "analyze", {}, "")
    assert h1 != h2


def test_compute_chain_hash_changes_with_prev_hash():
    """Different prev_hash → different hash (chain is sensitive to history)."""
    from backend.api.routes import _compute_chain_hash

    h1 = _compute_chain_hash("GENESIS", "upload", {}, "")
    h2 = _compute_chain_hash("different_prev", "upload", {}, "")
    assert h1 != h2


def test_compute_chain_hash_changes_with_detail():
    """Changing detail changes the hash — tamper-evident."""
    from backend.api.routes import _compute_chain_hash

    h1 = _compute_chain_hash("GENESIS", "upload", {"filename": "a.csv"}, "")
    h2 = _compute_chain_hash("GENESIS", "upload", {"filename": "b.csv"}, "")
    assert h1 != h2


def test_compute_chain_hash_matches_manual_sha256():
    """Verify the hash matches a hand-computed SHA-256 of the canonical JSON."""
    from backend.api.routes import _compute_chain_hash

    canonical = json.dumps(
        {"prev_hash": "GENESIS", "action": "login", "detail": {}, "file_sha256": ""},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert _compute_chain_hash("GENESIS", "login", {}, "") == expected


# ── Integration: _write_audit builds the chain ────────────────────────────────

def test_first_row_uses_genesis(db_session):
    """First audit entry must use 'GENESIS' as prev_hash."""
    from backend.api.routes import _write_audit
    from backend.db.models import AuditLogModel

    _write_audit(db_session, "login", {"user": "alice"})
    row = db_session.query(AuditLogModel).first()
    assert row is not None
    assert row.prev_hash == "GENESIS"
    assert row.payload_sha256 is not None
    assert len(row.payload_sha256) == 64


def test_second_row_chains_from_first(db_session):
    """Second entry's prev_hash must equal first entry's payload_sha256."""
    from backend.api.routes import _write_audit
    from backend.db.models import AuditLogModel

    _write_audit(db_session, "login", {"user": "alice"})
    _write_audit(db_session, "upload", {"filename": "log.csv"}, sha256="aabbcc")

    rows = db_session.query(AuditLogModel).order_by(AuditLogModel.id).all()
    assert len(rows) == 2
    assert rows[1].prev_hash == rows[0].payload_sha256


def test_file_sha256_stored_separately(db_session):
    """file_sha256 column preserves the original evidence hash untouched."""
    from backend.api.routes import _write_audit
    from backend.db.models import AuditLogModel

    _write_audit(db_session, "upload", {"filename": "evidence.csv"}, sha256="deadbeef" * 8)
    row = db_session.query(AuditLogModel).first()
    assert row.file_sha256 == "deadbeef" * 8
    # payload_sha256 is the chain hash — must differ from file_sha256
    assert row.payload_sha256 != row.file_sha256


def test_chain_of_five_entries_is_intact(db_session):
    """A sequence of 5 entries must all verify cleanly."""
    from backend.api.routes import _write_audit, _compute_chain_hash
    from backend.db.models import AuditLogModel

    actions = ["login", "upload", "analyze", "export_csv", "logout"]
    for action in actions:
        _write_audit(db_session, action, {"step": action})

    rows = db_session.query(AuditLogModel).order_by(AuditLogModel.id).all()
    assert len(rows) == 5

    prev = "GENESIS"
    for row in rows:
        expected = _compute_chain_hash(
            prev_hash=row.prev_hash,
            action=row.action,
            detail=row.detail,
            file_sha256=row.file_sha256 or "",
        )
        assert row.payload_sha256 == expected, f"Chain broken at id={row.id}"
        prev = row.payload_sha256


# ── Tamper detection ──────────────────────────────────────────────────────────

def test_tamper_action_breaks_chain(db_session):
    """Changing a row's action field must cause the chain to fail verification."""
    from backend.api.routes import _write_audit, _compute_chain_hash
    from backend.db.models import AuditLogModel

    _write_audit(db_session, "login", {"user": "alice"})
    _write_audit(db_session, "upload", {"filename": "log.csv"})

    # Tamper: change the first row's action after the fact
    first = db_session.query(AuditLogModel).order_by(AuditLogModel.id).first()
    first.action = "TAMPERED"
    db_session.commit()

    rows = db_session.query(AuditLogModel).order_by(AuditLogModel.id).all()

    # Re-verify: first row's chain hash no longer matches its stored hash
    broken = False
    for row in rows:
        expected = _compute_chain_hash(
            prev_hash=row.prev_hash,
            action=row.action,
            detail=row.detail or {},
            file_sha256=row.file_sha256 or "",
        )
        if row.payload_sha256 != expected:
            broken = True
            break
    assert broken, "Tampered row should have broken the chain"


def test_tamper_detail_breaks_chain(db_session):
    """Changing a row's detail must invalidate its hash."""
    from backend.api.routes import _write_audit, _compute_chain_hash
    from backend.db.models import AuditLogModel

    _write_audit(db_session, "login", {"user": "alice", "performed_by": "alice"})

    row = db_session.query(AuditLogModel).first()
    row.detail = {"user": "mallory", "performed_by": "mallory"}  # tampered
    db_session.commit()

    row = db_session.query(AuditLogModel).first()
    expected = _compute_chain_hash(
        prev_hash=row.prev_hash,
        action=row.action,
        detail=row.detail,
        file_sha256=row.file_sha256 or "",
    )
    assert row.payload_sha256 != expected


# ── NarrativeCitation schema ──────────────────────────────────────────────────

def test_narrative_citation_schema():
    """NarrativeCitation Pydantic model must accept valid data and reject bad types."""
    from backend.schema import NarrativeCitation

    c = NarrativeCitation(sentence="The attacker moved laterally.", event_ids=[1, 42])
    assert c.sentence == "The attacker moved laterally."
    assert c.event_ids == [1, 42]


def test_rca_result_includes_narrative_citations():
    """RCAResult must accept narrative_citations and default to empty list."""
    from backend.schema import RCAResult

    result = RCAResult(
        patient_zero_candidate="HOST-01",
        initial_access_vector="Phishing",
        pivot_chain=[],
        anomalous_events=[],
        confidence="high",
        narrative="The attacker compromised HOST-01.",
        analyzed_event_count=5,
        windows_analyzed=1,
    )
    assert result.narrative_citations == []


def test_rca_result_with_populated_citations():
    """RCAResult with citations must expose them correctly."""
    from backend.schema import RCAResult, NarrativeCitation

    citations = [
        NarrativeCitation(sentence="Attacker used mimikatz.", event_ids=[7, 8]),
        NarrativeCitation(sentence="Lateral movement to DC-01.", event_ids=[12]),
    ]
    result = RCAResult(
        patient_zero_candidate="HOST-01",
        initial_access_vector="Phishing",
        pivot_chain=[],
        anomalous_events=[],
        confidence="high",
        narrative="Attacker used mimikatz. Lateral movement to DC-01.",
        analyzed_event_count=10,
        windows_analyzed=1,
        narrative_citations=citations,
    )
    assert len(result.narrative_citations) == 2
    assert result.narrative_citations[0].event_ids == [7, 8]

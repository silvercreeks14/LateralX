from sqlalchemy import (
    Column, Integer, String, DateTime, JSON, Float, Boolean, Text,
    create_engine, text, inspect, event as sa_event,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from datetime import datetime
from uuid import uuid4
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./forensic.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        # Queue writers for up to 30 s before raising OperationalError.
        # The default 5 s is too short when an analysis commit and a bulk-delete
        # upload arrive simultaneously under WAL mode.
        "timeout": 30,
    },
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@sa_event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _connection_record):
    """
    WAL mode: allows concurrent reads during a write and survives crashes
    without data corruption. synchronous=NORMAL is safe with WAL.
    foreign_keys enforces referential integrity at the SQLite layer.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Base(DeclarativeBase):
    pass


class UploadModel(Base):
    """Tracks every file uploaded to the platform, enabling multi-source case views."""
    __tablename__ = "uploads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), nullable=True, index=True)
    filename = Column(Text, nullable=False)
    file_hash = Column(String(64), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    uploaded_by = Column(String(100), nullable=True)
    event_count = Column(Integer, default=0)


class EventModel(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(255), nullable=False, index=True)
    source_host = Column(String(255), nullable=False, index=True)
    user = Column(String(255), nullable=True, index=True)
    description = Column(String(1000), nullable=False)
    raw_source = Column(String(50), nullable=False)
    event_id = Column(String(20), nullable=True, index=True)
    extra = Column(JSON, nullable=True)
    # v3: case management — nullable so legacy rows remain valid
    case_id = Column(String(36), nullable=True, index=True)
    # v4: multi-source — which upload this event came from
    upload_id = Column(Integer, nullable=True, index=True)


class BaselineEventModel(Base):
    """Stores a 'normal' baseline upload for anomaly comparison."""
    __tablename__ = "baseline_events"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(255), nullable=False)
    source_host = Column(String(255), nullable=False)
    user = Column(String(255), nullable=True)
    description = Column(String(1000), nullable=False)
    raw_source = Column(String(50), nullable=False)
    event_id = Column(String(20), nullable=True)


class AnalysisModel(Base):
    __tablename__ = "analyses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    patient_zero_candidate = Column(String(1000))
    initial_access_vector = Column(String(1000))
    pivot_chain = Column(JSON)
    anomalous_events = Column(JSON)
    confidence = Column(String(20))
    narrative = Column(String(2000))
    analyzed_event_count = Column(Integer)
    windows_analyzed = Column(Integer)
    # v2 enrichment columns
    mitre_techniques = Column(JSON, nullable=True)
    severity_score = Column(Integer, nullable=True, default=0)
    iocs = Column(JSON, nullable=True)
    consensus_agreement = Column(Float, nullable=True)
    # v3: case management + ML ground truth
    case_id = Column(String(36), nullable=True, index=True)
    ml_scores = Column(JSON, nullable=True)   # persisted list[UserAnomalyScore] dicts


class IncidentPatternModel(Base):
    """Tracks IOCs seen across analyses for cross-incident memory."""
    __tablename__ = "incident_patterns"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ioc_type = Column(String(50), nullable=False, index=True)
    ioc_value = Column(String(500), nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    incident_count = Column(Integer, default=1)
    context = Column(String(500), nullable=True)


class ChatMessageModel(Base):
    """Persists analyst chat history across sessions."""
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    role = Column(String(20), nullable=False)     # "user" | "assistant"
    content = Column(String(10000), nullable=False)


class AuditLogModel(Base):
    """
    Immutable, tamper-evident investigation audit trail.
    Rows are NEVER updated or deleted — enforced at the route layer.

    Hash-chain layout (v5):
      payload_sha256 — SHA-256 of the canonical JSON of this row's data PLUS prev_hash.
                       Verifying the full chain: re-compute each row's hash from its stored
                       fields and prev_hash; a mismatch indicates tampering.
      prev_hash      — payload_sha256 of the immediately preceding row ("GENESIS" for row 1).
      file_sha256    — original SHA-256 of an evidence file (upload events only); preserved
                       separately so payload_sha256 can serve exclusively as the chain hash.
    """
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    detail = Column(JSON, nullable=True)
    payload_sha256 = Column(String(64), nullable=True)   # chain hash (v5+)
    prev_hash = Column(String(64), nullable=True)        # previous row's chain hash (v5+)
    file_sha256 = Column(String(64), nullable=True)      # raw evidence file hash (v5+)


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(200), nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # admin | analyst
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    # v3: legacy console-MFA (6-digit ephemeral code)
    mfa_secret = Column(String(6), nullable=True)
    # v4: TOTP (Google Authenticator)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=True)


# ── v3 New Tables ──────────────────────────────────────────────────────────────

class CaseModel(Base):
    """Groups multiple log uploads into a named investigation case."""
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    title = Column(String(200), nullable=False)
    description = Column(String(1000), nullable=True)
    status = Column(String(20), default="active")   # active | closed | archived
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class NoteModel(Base):
    """Timestamped analyst notes attached to a case or analysis."""
    __tablename__ = "analyst_notes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), nullable=True, index=True)
    analysis_id = Column(Integer, nullable=True, index=True)
    author = Column(String(100), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    is_pinned = Column(Boolean, default=False)


class MLGroundTruthModel(Base):
    """
    Admin-verified ML predictions used to calculate precision/recall/F1.

    is_true_positive = True  → analyst confirmed this user was a real threat
    is_true_positive = False → analyst marked this as a false alarm
    """
    __tablename__ = "ml_ground_truth"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, nullable=True, index=True)
    user = Column(String(100), nullable=False)
    predicted_risk = Column(String(20), nullable=False)    # normal|suspicious|high_risk
    predicted_score = Column(Float, nullable=False)
    verified_by = Column(String(100), nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow)
    is_true_positive = Column(Boolean, nullable=False)
    notes = Column(String(500), nullable=True)


# ── Migration ──────────────────────────────────────────────────────────────────

def _migrate_schema():
    """
    Idempotent forward-only migration.
    Adds new columns and tables to an existing database without touching
    existing rows or dropping anything. Safe to call on every startup.
    """
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())

    def _add_columns(table: str, additions: dict[str, str]) -> None:
        if table not in existing_tables:
            return  # create_all will create the full table
        existing_cols = {col["name"] for col in insp.get_columns(table)}
        with engine.connect() as conn:
            for col, col_type in additions.items():
                if col not in existing_cols:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
            conn.commit()

    # audit_log — v5 hash-chain columns
    _add_columns("audit_log", {
        "prev_hash":   "VARCHAR(64)",
        "file_sha256": "VARCHAR(64)",
    })

    # analyses — v2 enrichment + v3 case/ML columns
    _add_columns("analyses", {
        "mitre_techniques":   "JSON",
        "severity_score":     "INTEGER DEFAULT 0",
        "iocs":               "JSON",
        "consensus_agreement": "FLOAT",
        "case_id":            "VARCHAR(36)",
        "ml_scores":          "JSON",
    })

    # events — v3 case tagging, v4 multi-source
    _add_columns("events", {
        "case_id":   "VARCHAR(36)",
        "upload_id": "INTEGER",
    })

    # users — v3 console MFA, v4 TOTP
    _add_columns("users", {
        "mfa_secret":    "VARCHAR(6)",
        "totp_secret":   "VARCHAR(64)",
        "totp_enabled":  "BOOLEAN DEFAULT 0",
    })

    # ── FTS5 virtual tables for global full-text search ────────────────────────
    with engine.connect() as conn:
        try:
            conn.execute(text("""
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    description, source_host, user, event_type,
                    content='events', content_rowid='id'
                )
            """))
            conn.execute(text("""
                CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
                    content,
                    content='analyst_notes', content_rowid='id'
                )
            """))
            # Sync triggers for events_fts
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS events_fts_insert
                AFTER INSERT ON events BEGIN
                    INSERT INTO events_fts(rowid, description, source_host, user, event_type)
                    VALUES (
                        new.id,
                        COALESCE(new.description,''),
                        COALESCE(new.source_host,''),
                        COALESCE(new.user,''),
                        COALESCE(new.event_type,'')
                    );
                END
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS events_fts_delete
                AFTER DELETE ON events BEGIN
                    INSERT INTO events_fts(events_fts, rowid, description, source_host, user, event_type)
                    VALUES (
                        'delete', old.id,
                        COALESCE(old.description,''),
                        COALESCE(old.source_host,''),
                        COALESCE(old.user,''),
                        COALESCE(old.event_type,'')
                    );
                END
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS events_fts_update
                AFTER UPDATE ON events BEGIN
                    INSERT INTO events_fts(events_fts, rowid, description, source_host, user, event_type)
                    VALUES (
                        'delete', old.id,
                        COALESCE(old.description,''),
                        COALESCE(old.source_host,''),
                        COALESCE(old.user,''),
                        COALESCE(old.event_type,'')
                    );
                    INSERT INTO events_fts(rowid, description, source_host, user, event_type)
                    VALUES (
                        new.id,
                        COALESCE(new.description,''),
                        COALESCE(new.source_host,''),
                        COALESCE(new.user,''),
                        COALESCE(new.event_type,'')
                    );
                END
            """))
            # Sync triggers for notes_fts
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS notes_fts_insert
                AFTER INSERT ON analyst_notes BEGIN
                    INSERT INTO notes_fts(rowid, content)
                    VALUES (new.id, COALESCE(new.content,''));
                END
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS notes_fts_delete
                AFTER DELETE ON analyst_notes BEGIN
                    INSERT INTO notes_fts(notes_fts, rowid, content)
                    VALUES ('delete', old.id, COALESCE(old.content,''));
                END
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS notes_fts_update
                AFTER UPDATE ON analyst_notes BEGIN
                    INSERT INTO notes_fts(notes_fts, rowid, content)
                    VALUES ('delete', old.id, COALESCE(old.content,''));
                    INSERT INTO notes_fts(rowid, content)
                    VALUES (new.id, COALESCE(new.content,''));
                END
            """))
            conn.commit()
            # Populate FTS index from existing data (safe to re-run)
            conn.execute(text("INSERT INTO events_fts(events_fts) VALUES('rebuild')"))
            conn.execute(text("INSERT INTO notes_fts(notes_fts) VALUES('rebuild')"))
            conn.commit()
        except Exception as exc:
            conn.rollback()
            print(f"[FTS5 migration] warning: {exc}")


def init_db():
    _migrate_schema()
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

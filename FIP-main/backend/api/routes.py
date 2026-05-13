"""
FastAPI route handlers — v4
Added: case management, analyst notes, ML ground truth, detection rules,
       threat intel enrichment, MFA guards, token refresh.
"""

import asyncio
import json
import os
import shutil
import hashlib
from pathlib import Path
from sqlalchemy import text as sa_text
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response, FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from datetime import datetime

from backend.schema import (
    ForensicEvent, RCAResult, UploadResponse, EventSummary,
    ChatRequest, ChatResponse, BaselineComparisonResult, MitreTechnique, IOC,
    Case, CaseCreate, CaseUpdate, Note, NoteCreate, NoteUpdate,
    MLStats, GroundTruthCreate, UserAnomalyScore,
    Upload, SearchResponse, SearchEventResult, SearchNoteResult,
    AttackClassification,
)
from backend.ingest.parser import detect_and_parse
from backend.ingest.pcap_parser import parse_pcap
from backend.db.models import (
    get_db, EventModel, AnalysisModel, BaselineEventModel,
    IncidentPatternModel, ChatMessageModel, AuditLogModel, UserModel, init_db,
    CaseModel, NoteModel, MLGroundTruthModel, UploadModel,
)
import re as _re
from backend.api.auth import (
    verify_password, create_access_token, get_current_user, get_password_hash,
    require_admin, require_mfa,
    generate_totp_secret, get_totp_qr_png_b64, get_totp_uri, verify_totp,
)

_ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".pcap", ".pcapng"}
_PCAP_EXTENSIONS = {".pcap", ".pcapng"}
_MAX_UPLOAD_BYTES = 100 * 1024 * 1024   # 100 MB
_CHUNK_SIZE = 1024 * 1024               # 1 MB read chunks

import threading

# Caps simultaneous LLM analyses so inner per-window thread pools (up to 5
# threads each) cannot exhaust the process-wide asyncio executor under load.
_analysis_semaphore = threading.Semaphore(2)

from backend.analysis.llm import run_full_analysis
from backend.analysis.graph import build_attack_graph
from backend.analysis import mitre as mitre_mod
from backend.analysis import ioc as ioc_mod
from backend.analysis import scoring as scoring_mod
from backend.analysis import ml_anomaly as ml_mod
from backend.analysis import ml_synthetic as ml_synth
from backend.analysis import threat_intel as ti_mod
from backend.analysis import rules as rules_mod
from backend.analysis.chat import run_chat
from backend.analysis.report import generate_report
from backend.analysis.ioc import iocs_to_csv, iocs_to_stix
from backend.analysis import attack_classifier as atk_clf
from backend.analysis.behavioral import analyze_behavior
from backend.analysis.storyline import build_storyline
from backend.analysis.lmd_model import run_lmd_model_and_graph

router = APIRouter()

# ── Noise-reduction filter constants ──────────────────────────────────────────

# Event IDs that are inherently high-volume background noise.
# 4634/4647 = Logoff; 4776 = NTLM auth; 4672 = Special privileges assigned.
# These are suppressed UNLESS a suspicious keyword also appears in description.
_NOISE_EVENT_IDS: frozenset[str] = frozenset({"4634", "4647", "4776", "4672"})

# Any of these keywords in the description overrides the noise filter.
_NOISE_SIGNAL_KW: frozenset[str] = frozenset({
    "mimikatz", "sekurlsa", "certutil", "encoded", "mshta",
    "psexec", "vssadmin", "shadow", "-enc", "ransom",
})

_NOISE_SVC_TERMS: frozenset[str] = frozenset({
    "svc_", "_svc", "svc-", "-svc", "backup", "system",
    "svchost", "localsystem", "network service", "nt authority",
})


def _is_noise_event(row: EventModel) -> bool:
    user = (row.user or "").lower()
    if user.endswith("$"):
        return True
    if any(t in user for t in _NOISE_SVC_TERMS):
        return True
    if row.event_id in _NOISE_EVENT_IDS:
        desc = (row.description or "").lower()
        if not any(kw in desc for kw in _NOISE_SIGNAL_KW):
            return True
    return False


def _apply_noise_filter(rows: list[EventModel]) -> list[EventModel]:
    """
    Remove routine background events to surface high-signal detections.
    Filters machine/service accounts and benign high-frequency event IDs.
    Also deduplicates rapid identical events (same host+eid+user within 60 s).
    """
    from datetime import timedelta as _td
    result: list[EventModel] = []
    last_seen: dict[str, datetime] = {}
    for row in rows:
        if _is_noise_event(row):
            continue
        key = f"{row.source_host}|{row.event_id or ''}|{row.user or ''}"
        last = last_seen.get(key)
        if last and (row.timestamp - last).total_seconds() < 60:
            continue
        last_seen[key] = row.timestamp
        result.append(row)
    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _row_to_event(r: EventModel) -> ForensicEvent:
    return ForensicEvent(
        id=r.id, timestamp=r.timestamp, event_type=r.event_type,
        source_host=r.source_host, user=r.user, description=r.description,
        raw_source=r.raw_source, event_id=r.event_id, extra=r.extra,
    )


def _compute_chain_hash(
    prev_hash: str,
    action: str,
    detail: dict,
    file_sha256: str,
) -> str:
    """
    Compute the tamper-evident chain hash for one audit row.

    The canonical input is a deterministic JSON string (sorted keys, no spaces)
    of the four fields that must never change.  Any post-write modification to
    action, detail, or file_sha256 will produce a different hash, breaking
    verification from that row onward.
    """
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "action": action,
            "detail": detail,
            "file_sha256": file_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_audit(
    db: Session,
    action: str,
    detail: dict | None = None,
    sha256: str | None = None,
    username: str | None = None,
) -> None:
    """
    Append one immutable, hash-chained audit entry.

    Each row's payload_sha256 is SHA-256(prev_hash || action || detail || file_sha256),
    creating an unbreakable chain: tampering with any stored field invalidates all
    subsequent hashes and is detectable via GET /api/audit-log/verify.
    """
    try:
        d = {**(detail or {}), **({"performed_by": username} if username else {})}

        # Fetch the most recent hash to chain from (serialises writes in SQLite WAL)
        last_row = db.query(AuditLogModel).order_by(AuditLogModel.id.desc()).first()
        prev_hash = (last_row.payload_sha256 or "GENESIS") if last_row else "GENESIS"

        chain_hash = _compute_chain_hash(
            prev_hash=prev_hash,
            action=action,
            detail=d,
            file_sha256=sha256 or "",
        )

        db.add(AuditLogModel(
            action=action,
            detail=d,
            payload_sha256=chain_hash,   # chain hash (not the raw file hash)
            prev_hash=prev_hash,
            file_sha256=sha256,          # preserve original evidence file hash
        ))
        db.commit()
    except Exception:
        db.rollback()


def _scan_incident_memory(iocs: list[IOC], db: Session) -> list[str]:
    matches = []
    for ioc in iocs:
        pattern = db.query(IncidentPatternModel).filter(
            IncidentPatternModel.ioc_value == ioc.value
        ).first()
        if pattern:
            matches.append(
                f"{ioc.type} '{ioc.value}' seen in "
                f"{pattern.incident_count} previous incident(s) "
                f"(first: {pattern.first_seen.strftime('%Y-%m-%d')})"
            )
    return matches


def _save_iocs_to_memory(iocs: list[IOC], db: Session) -> None:
    for ioc in iocs:
        existing = db.query(IncidentPatternModel).filter(
            IncidentPatternModel.ioc_value == ioc.value
        ).first()
        if existing:
            existing.incident_count += 1
            existing.last_seen = datetime.utcnow()
        else:
            db.add(IncidentPatternModel(
                ioc_type=ioc.type,
                ioc_value=ioc.value,
                context=ioc.context[:500],
            ))
    db.commit()


# ── Auth ───────────────────────────────────────────────────────────────────────

@router.post("/login")
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter(UserModel.username == form.username).first()
    if not user or not user.is_active or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Admin accounts with TOTP configured require it at login
    if user.role == "admin" and user.totp_enabled and user.totp_secret:
        submitted = request.headers.get("X-MFA-Code")
        if not submitted:
            return JSONResponse(
                status_code=202,
                content={
                    "mfa_required": True,
                    "totp": True,
                    "username": user.username,
                    "message": "Enter the 6-digit code from your authenticator app.",
                },
            )
        if not verify_totp(user.totp_secret, submitted):
            raise HTTPException(status_code=403, detail="Invalid TOTP code.")

    token = create_access_token({"sub": user.username, "role": user.role})
    _write_audit(db, "login", {"username": user.username, "mfa": user.role == "admin"})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
    }


@router.post("/auth/refresh")
def refresh_token(current_user: UserModel = Depends(get_current_user)):
    """
    Sliding-session token refresh.
    Client calls this when the current token has < 20 minutes remaining.
    Returns a fresh 4-hour token without requiring re-authentication.
    The call goes through a raw fetch() in client.ts — NOT through the
    request() helper — to avoid an infinite refresh-check loop.
    """
    new_token = create_access_token({"sub": current_user.username, "role": current_user.role})
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "username": current_user.username,
        "role": current_user.role,
    }


# ── TOTP Setup (admin only) ────────────────────────────────────────────────────

@router.post("/admin/totp/setup")
def totp_setup(
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_admin),
):
    """
    Generate a new TOTP secret for the admin account and return the QR code.
    The secret is saved immediately but totp_enabled stays False until /verify.
    Call again to rotate the secret (requires re-scan in authenticator app).
    """
    secret = generate_totp_secret()
    user = db.query(UserModel).filter(UserModel.username == admin_user.username).first()
    user.totp_secret = secret
    user.totp_enabled = False   # not active until verified
    db.commit()
    qr_b64 = get_totp_qr_png_b64(admin_user.username, secret)
    uri = get_totp_uri(admin_user.username, secret)
    return {
        "secret": secret,
        "uri": uri,
        "qr_code_png_b64": qr_b64,
        "instructions": (
            "Scan the QR code in Google Authenticator (or compatible app), "
            "then call POST /api/admin/totp/verify with your first code to activate."
        ),
    }


@router.post("/admin/totp/verify")
def totp_verify(
    code: str = Query(..., description="6-digit TOTP code from your authenticator app"),
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_admin),
):
    """Verify the first TOTP code after setup and activate TOTP for this account."""
    user = db.query(UserModel).filter(UserModel.username == admin_user.username).first()
    if not user.totp_secret:
        raise HTTPException(400, "No TOTP secret set up. Call POST /api/admin/totp/setup first.")
    if not verify_totp(user.totp_secret, code):
        raise HTTPException(403, "Invalid TOTP code. Scan the QR code again and retry.")
    user.totp_enabled = True
    db.commit()
    _write_audit(db, "totp_enabled", {"username": admin_user.username}, username=admin_user.username)
    return {"status": "ok", "message": "TOTP activated. Future logins will require your authenticator app."}


@router.delete("/admin/totp/disable")
def totp_disable(
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_admin),
):
    """Disable TOTP for the admin account."""
    user = db.query(UserModel).filter(UserModel.username == admin_user.username).first()
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    _write_audit(db, "totp_disabled", {"username": admin_user.username}, username=admin_user.username)
    return {"status": "ok", "message": "TOTP disabled. Login will use console MFA."}


@router.get("/admin/totp/status")
def totp_status(
    admin_user: UserModel = Depends(require_admin),
):
    """Return current TOTP configuration status for the admin account."""
    return {
        "totp_enabled": bool(admin_user.totp_enabled),
        "totp_configured": bool(admin_user.totp_secret),
    }


# ── Global Full-Text Search ────────────────────────────────────────────────────

@router.get("/search", response_model=SearchResponse)
def global_search(
    q: str = Query(..., min_length=2, max_length=200, description="Search query"),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Full-text search across events and analyst notes using SQLite FTS5.
    Results include highlighted snippets. Requires the FTS5 migration to have run.
    """
    # Sanitize: remove FTS5 operators, build prefix-match query
    safe = _re.sub(r'[^\w\s]', ' ', q).strip()
    if not safe:
        return SearchResponse(events=[], notes=[], total=0)
    fts_q = ' '.join(f'{w}*' for w in safe.split()[:8] if w)

    events_out: list[SearchEventResult] = []
    notes_out: list[SearchNoteResult] = []

    try:
        rows = db.execute(
            sa_text("""
                SELECT e.id, e.timestamp, e.source_host, e.user, e.event_type,
                       e.case_id, e.upload_id,
                       snippet(events_fts, 0, '<mark>', '</mark>', '…', 20) AS snip
                FROM events_fts
                JOIN events e ON e.id = events_fts.rowid
                WHERE events_fts MATCH :q
                LIMIT :lim
            """),
            {"q": fts_q, "lim": limit},
        ).fetchall()
        for r in rows:
            events_out.append(SearchEventResult(
                id=r[0],
                timestamp=r[1].isoformat() if hasattr(r[1], "isoformat") else str(r[1]),
                source_host=r[2] or "",
                user=r[3],
                event_type=r[4] or "",
                case_id=r[5],
                upload_id=r[6],
                snippet=r[7] or "",
            ))
    except Exception:
        pass  # FTS table may not exist on very old DBs

    try:
        nrows = db.execute(
            sa_text("""
                SELECT n.id, n.case_id, n.author, n.created_at,
                       snippet(notes_fts, 0, '<mark>', '</mark>', '…', 20) AS snip
                FROM notes_fts
                JOIN analyst_notes n ON n.id = notes_fts.rowid
                WHERE notes_fts MATCH :q
                LIMIT :lim
            """),
            {"q": fts_q, "lim": limit},
        ).fetchall()
        for r in nrows:
            notes_out.append(SearchNoteResult(
                id=r[0],
                case_id=r[1],
                author=r[2] or "",
                created_at=r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
                snippet=r[4] or "",
            ))
    except Exception:
        pass

    return SearchResponse(
        events=events_out,
        notes=notes_out,
        total=len(events_out) + len(notes_out),
    )


# ── Upload ─────────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=UploadResponse)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str | None = Query(default=None, description="Optional case UUID to tag events with"),
    parser_hint: str | None = Query(default=None, description="Force a specific parser: lmd | sysmon | plaso | timesketch | network | generic"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(400, "No filename provided.")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            f"Unsupported file type '{ext}'. Accepted formats: .csv, .json, .jsonl, .pcap, .pcapng",
        )

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File too large. Maximum upload size is 100 MB.")
        chunks.append(chunk)
    raw_original = b"".join(chunks)

    # For text files, normalise line endings (CRLF → LF, bare CR → LF) and strip
    # trailing blank lines before hashing. This ensures identical content produces
    # the same SHA-256 hash regardless of OS line-ending convention, eliminating
    # false-positive "file integrity changed" alerts caused by Windows vs Unix uploads.
    _TEXT_EXTS = {".csv", ".json", ".jsonl", ".txt"}
    raw = raw_original
    if ext in _TEXT_EXTS:
        try:
            text = raw_original.decode("utf-8", errors="replace")
            text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
            raw = text.encode("utf-8")
        except Exception:
            pass  # fallback: use original bytes unchanged

    # Canonical (normalised) hash — stored in the audit log going forward.
    # raw_hash kept separately for backward-compat comparison against older DB
    # entries that were written before line-ending normalisation was introduced.
    hex_hash = hashlib.sha256(raw).hexdigest()
    raw_hash = hashlib.sha256(raw_original).hexdigest()

    try:
        if ext in _PCAP_EXTENSIONS:
            try:
                events = await asyncio.to_thread(parse_pcap, raw, file.filename)
            except ValueError as exc:
                raise HTTPException(400, str(exc))
        else:
            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                raise HTTPException(400, "Could not decode file as UTF-8.")
            try:
                events = detect_and_parse(file.filename, content, parser_hint=parser_hint)
            except ValueError as exc:
                raise HTTPException(400, str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Parsing failed: {exc}")

    if not events:
        raise HTTPException(400, "No events parsed. Check file format.")

    try:
        if case_id:
            # Multi-source: accumulate — never delete existing case events
            pass
        else:
            # Global workspace: replace (clear previous global uploads + events).
            db.query(EventModel).filter(EventModel.case_id == None).delete(synchronize_session=False)  # noqa: E711
            db.query(UploadModel).filter(UploadModel.case_id == None).delete(synchronize_session=False)  # noqa: E711

        # Create the upload manifest row first, then insert events with upload_id
        upload_row = UploadModel(
            case_id=case_id,
            filename=file.filename,
            file_hash=hex_hash,
            uploaded_by=current_user.username,
            event_count=len(events),
        )
        db.add(upload_row)
        db.flush()  # populate upload_row.id without committing

        for e in events:
            db.add(EventModel(
                timestamp=e.timestamp, event_type=e.event_type,
                source_host=e.source_host, user=e.user,
                description=e.description, raw_source=e.raw_source.value,
                event_id=e.event_id,
                extra=e.extra if isinstance(e.extra, dict) else None,
                case_id=case_id,
                upload_id=upload_row.id,
            ))
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"Database write failed: {exc}. Try restarting the server if this persists.")

    recent_uploads = (
        db.query(AuditLogModel)
        .filter(AuditLogModel.action == "upload")
        .order_by(AuditLogModel.id.desc())
        .limit(100)
        .all()
    )

    # Integrity check: find the most recent previous upload of this exact filename.
    # Compare its stored file_sha256 against BOTH the normalised hash and the
    # original raw hash — this handles old DB entries written before line-ending
    # normalisation was introduced.  hash_changed = True only when a prior upload
    # exists AND its stored hash matches NEITHER form of the current file.
    # (row.payload_sha256 is the tamper-evident chain hash, not the file hash —
    # the real file hash lives in row.file_sha256.)
    hash_changed = False
    for row in recent_uploads:
        if isinstance(row.detail, dict) and row.detail.get("filename") == file.filename:
            stored = row.file_sha256  # actual evidence file hash
            if stored and stored not in (hex_hash, raw_hash):
                hash_changed = True
            break  # only compare against the most recent entry for this filename

    iocs = ioc_mod.extract_iocs(events)
    matches = _scan_incident_memory(iocs, db)

    timestamps = [e.timestamp for e in events]
    _write_audit(db, "upload", {
        "filename": file.filename,
        "events_loaded": len(events),
        "hash_changed": hash_changed,
        "known_ioc_matches": len(matches),
    }, sha256=hex_hash, username=current_user.username)

    return UploadResponse(
        status="ok", events_loaded=len(events), filename=file.filename,
        time_range={"start": min(timestamps).isoformat(), "end": max(timestamps).isoformat()},
        known_ioc_matches=matches,
        file_hash=hex_hash,
        hash_changed=hash_changed,
    )


@router.post("/clear")
def clear_workspace(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    try:
        chat_deleted = db.query(ChatMessageModel).delete(synchronize_session=False)
        # Only clear global workspace — preserve case-tagged events and uploads
        analyses_deleted = db.query(AnalysisModel).filter(AnalysisModel.case_id == None).delete(synchronize_session=False)  # noqa: E711
        events_deleted = db.query(EventModel).filter(EventModel.case_id == None).delete(synchronize_session=False)  # noqa: E711
        uploads_deleted = db.query(UploadModel).filter(UploadModel.case_id == None).delete(synchronize_session=False)  # noqa: E711
        db.commit()
        _write_audit(db, "clear", {
            "events_deleted": events_deleted,
            "analyses_deleted": analyses_deleted,
            "chat_messages_deleted": chat_deleted,
            "uploads_deleted": uploads_deleted,
        }, username=current_user.username)
        return {"status": "cleared"}
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"Clear failed: {exc}")


@router.post("/upload/baseline", response_model=dict)
async def upload_baseline(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(400, "No filename provided.")
    raw = await file.read()
    content = raw.decode("utf-8", errors="replace")
    try:
        events = detect_and_parse(file.filename, content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not events:
        raise HTTPException(400, "No events parsed from baseline file.")

    db.query(BaselineEventModel).delete(synchronize_session=False)
    for e in events:
        db.add(BaselineEventModel(
            timestamp=e.timestamp, event_type=e.event_type,
            source_host=e.source_host, user=e.user,
            description=e.description, raw_source=e.raw_source.value,
            event_id=e.event_id,
        ))
    db.commit()
    _write_audit(db, "baseline_upload", {
        "filename": file.filename,
        "baseline_events": len(events),
    }, username=current_user.username)
    return {"status": "ok", "baseline_events": len(events), "filename": file.filename}


# ── Events ─────────────────────────────────────────────────────────────────────

@router.get("/events/summary", response_model=EventSummary)
def get_summary(
    case_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    case_id=<uuid>  → events for that case only
    case_id absent  → global workspace only (case_id IS NULL)

    This scoping prevents case-tagged events from inflating the global
    workspace count when the analyst is working without an active case.
    """
    q = db.query(EventModel)
    if case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        return EventSummary(total=0, hosts=[], users=[], event_types=[])
    return EventSummary(
        total=len(rows),
        hosts=sorted(set(r.source_host for r in rows)),
        users=sorted(set(r.user for r in rows if r.user)),
        event_types=sorted(set(r.event_type for r in rows)),
        time_range={
            "start": min(r.timestamp for r in rows).isoformat(),
            "end": max(r.timestamp for r in rows).isoformat(),
        },
    )


@router.get("/events")
def get_events(
    host: str | None = None, user: str | None = None,
    event_type: str | None = None, event_id: str | None = None,
    start: str | None = None, end: str | None = None,
    case_id: str | None = Query(default=None),
    noise_filter: bool = False,
    limit: int = 1000,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    case_id=<uuid>    → events for that case
    case_id absent    → global workspace (case_id IS NULL)
    noise_filter=true → suppress machine/service accounts, benign high-freq EIDs,
                        and rapid duplicate events (same host+eid+user within 60 s)
    """
    q = db.query(EventModel)
    if case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    if host:       q = q.filter(EventModel.source_host == host)
    if user:       q = q.filter(EventModel.user == user)
    if event_type: q = q.filter(EventModel.event_type == event_type)
    if event_id:   q = q.filter(EventModel.event_id == event_id)
    if start:
        try:    q = q.filter(EventModel.timestamp >= datetime.fromisoformat(start))
        except ValueError: raise HTTPException(400, f"Invalid start: {start}")
    if end:
        try:    q = q.filter(EventModel.timestamp <= datetime.fromisoformat(end))
        except ValueError: raise HTTPException(400, f"Invalid end: {end}")
    rows = q.order_by(EventModel.timestamp).limit(limit).all()
    if noise_filter:
        rows = _apply_noise_filter(rows)
    return [{"id": r.id, "timestamp": r.timestamp.isoformat(), "event_type": r.event_type,
             "source_host": r.source_host, "user": r.user, "description": r.description,
             "raw_source": r.raw_source, "event_id": r.event_id,
             "upload_id": r.upload_id} for r in rows]


# ── Analysis ───────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=RCAResult)
def run_analysis(
    case_id: str | None = Query(default=None),
    upload_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(EventModel).order_by(EventModel.timestamp)
    if upload_id is not None:
        q = q.filter(EventModel.upload_id == upload_id)
    elif case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded. Upload a file first.")
    events = [_row_to_event(r) for r in rows]
    try:
        with _analysis_semaphore:
            result = run_full_analysis(events)
    except Exception as exc:
        raise HTTPException(500, f"LLM analysis failed: {exc}")

    # Supervised attack-type classification
    clf_result = atk_clf.classify_session(events)
    if clf_result.confidence_label != "none":
        attack_clf = AttackClassification(
            primary_attack=clf_result.primary_attack,
            confidence=clf_result.confidence,
            confidence_label=clf_result.confidence_label,
            all_scores=clf_result.all_scores,
            top_evidence=clf_result.top_evidence,
            mitre_techniques=clf_result.mitre_techniques,
        )
        result = result.model_copy(update={"attack_classification": attack_clf})

    # Enrich IOCs with VirusTotal / AbuseIPDB reputation (no-op if keys absent)
    enriched_iocs = ti_mod.enrich_iocs(result.iocs)
    result = result.model_copy(update={"iocs": enriched_iocs})

    # Run the trained LMD classifier and keep its graph in the AI Analysis response.
    lmd_anomalies = []
    lmd_graph = None
    try:
        lmd_anomalies, lmd_graph = run_lmd_model_and_graph(events)
    except Exception as exc:
        print(f"Error running LMD model: {exc}")

    if lmd_anomalies:
        result = result.model_copy(update={
            "anomalous_events": lmd_anomalies + result.anomalous_events,
            "lmd_graph": lmd_graph,
        })
    elif lmd_graph:
        result = result.model_copy(update={"lmd_graph": lmd_graph})

    _save_iocs_to_memory(result.iocs, db)
    db.add(AnalysisModel(
        patient_zero_candidate=result.patient_zero_candidate,
        initial_access_vector=result.initial_access_vector,
        pivot_chain=result.pivot_chain, anomalous_events=result.anomalous_events,
        confidence=result.confidence, narrative=result.narrative,
        analyzed_event_count=result.analyzed_event_count,
        windows_analyzed=result.windows_analyzed,
        mitre_techniques=[t.model_dump() for t in result.mitre_techniques],
        severity_score=result.severity_score,
        iocs=[i.model_dump() for i in result.iocs],
        consensus_agreement=result.consensus_agreement,
        ml_scores=[s.model_dump() for s in result.ml_anomaly_scores],
        case_id=case_id,
    ))
    db.commit()
    _write_audit(db, "analyze", {
        "events": result.analyzed_event_count,
        "windows": result.windows_analyzed,
        "confidence": result.confidence,
        "severity": result.severity_score,
        "mitre_count": len(result.mitre_techniques),
        "ioc_count": len(result.iocs),
        "case_id": case_id,
    }, username=current_user.username)
    return result


@router.get("/attack-graph-html", summary="Serve LMD attack graph HTML")
async def get_attack_graph_html():
    project_root = Path(__file__).resolve().parent.parent.parent
    graph_path = project_root / "attack_graph.html"
    if not graph_path.exists():
        raise HTTPException(
            status_code=404,
            detail="attack_graph.html not found. Run a Quick Scan or AI Analysis first to generate it.",
        )
    return FileResponse(str(graph_path), media_type="text/html", filename="attack_graph.html")


@router.post("/analyze/baseline-compare", response_model=BaselineComparisonResult)
def compare_with_baseline(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    current_rows = (
        db.query(EventModel)
        .filter(EventModel.case_id == None)  # noqa: E711 — global workspace only
        .all()
    )
    baseline_rows = db.query(BaselineEventModel).all()
    if not current_rows:
        raise HTTPException(400, "No events loaded.")
    if not baseline_rows:
        raise HTTPException(400, "No baseline uploaded. Use POST /api/upload/baseline first.")

    current_hosts = {r.source_host for r in current_rows}
    baseline_hosts = {r.source_host for r in baseline_rows}
    current_users = {r.user for r in current_rows if r.user}
    baseline_users = {r.user for r in baseline_rows if r.user}
    current_types = {r.event_type for r in current_rows}
    baseline_types = {r.event_type for r in baseline_rows}

    new_hosts = sorted(current_hosts - baseline_hosts)
    new_users = sorted(current_users - baseline_users)
    anomalous_types = sorted(current_types - baseline_types)
    delta = len(current_rows) - len(baseline_rows)

    parts = []
    if new_hosts:
        parts.append(f"New hosts not seen in baseline: {', '.join(new_hosts)}.")
    if new_users:
        parts.append(f"New user accounts: {', '.join(new_users)}.")
    if anomalous_types:
        parts.append(f"New event types: {', '.join(anomalous_types)}.")
    if delta > 0:
        parts.append(f"Event volume increased by {delta} ({len(baseline_rows)} → {len(current_rows)}).")
    summary = " ".join(parts) if parts else "No significant deviations detected from baseline."

    events = [_row_to_event(r) for r in current_rows]
    techniques = mitre_mod.map_techniques(events)
    graph = build_attack_graph(events)
    current_score = scoring_mod.calculate_severity(events, techniques, graph.get("suspicious_users", []))

    baseline_events = [ForensicEvent(
        timestamp=r.timestamp, event_type=r.event_type, source_host=r.source_host,
        user=r.user, description=r.description, raw_source=r.raw_source,
        event_id=r.event_id, extra=None,
    ) for r in baseline_rows]
    baseline_techniques = mitre_mod.map_techniques(baseline_events)
    baseline_graph = build_attack_graph(baseline_events)
    baseline_score = scoring_mod.calculate_severity(
        baseline_events, baseline_techniques, baseline_graph.get("suspicious_users", [])
    )

    result = BaselineComparisonResult(
        new_hosts=new_hosts, new_users=new_users,
        anomalous_event_types=anomalous_types,
        event_count_delta=delta, summary=summary,
        severity_delta=current_score - baseline_score,
    )
    _write_audit(db, "baseline_compare", {
        "new_hosts": len(new_hosts), "new_users": len(new_users),
        "severity_delta": result.severity_delta,
    }, username=current_user.username)
    return result


@router.post("/ml/quick-scan", response_model=RCAResult)
def ml_quick_scan(
    case_id: str | None = Query(default=None),
    upload_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Instant deterministic scan — no LLM calls, sub-second on any dataset.
    Runs MITRE mapping, IOC extraction, severity scoring, and ML anomaly detection.
    Returns an RCAResult with windows_analyzed=0 to signal a quick-scan result.
    """
    q = db.query(EventModel).order_by(EventModel.timestamp)
    if upload_id is not None:
        q = q.filter(EventModel.upload_id == upload_id)
    elif case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded. Upload a file first.")
    events = [_row_to_event(r) for r in rows]

    techniques = mitre_mod.map_techniques(events)
    iocs = ioc_mod.extract_iocs(events)
    # Enrich IOCs with VirusTotal / AbuseIPDB reputation (no-op if keys absent)
    iocs = ti_mod.enrich_iocs(iocs)

    graph = build_attack_graph(events)
    suspicious_users = graph.get("suspicious_users", [])
    severity = scoring_mod.calculate_severity(events, techniques, suspicious_users)
    ml_scores = ml_mod.score_all_users(events)
    lmd_anomalies = []
    lmd_graph = None
    try:
        lmd_anomalies, lmd_graph = run_lmd_model_and_graph(events)
    except Exception as exc:
        print(f"Error running LMD model: {exc}")

    clf_result = atk_clf.classify_session(events)
    attack_clf = AttackClassification(
        primary_attack=clf_result.primary_attack,
        confidence=clf_result.confidence,
        confidence_label=clf_result.confidence_label,
        all_scores=clf_result.all_scores,
        top_evidence=clf_result.top_evidence,
        mitre_techniques=clf_result.mitre_techniques,
    ) if clf_result.confidence_label != "none" else None

    result = RCAResult(
        patient_zero_candidate="",
        initial_access_vector="",
        pivot_chain=[],
        anomalous_events=lmd_anomalies + [f"{t.id} {t.name} ({t.tactic})" for t in techniques],
        confidence="high" if lmd_anomalies else "low",
        narrative=(
            "Quick scan complete — MITRE detections, IOCs, severity, ML behavioral "
            f"{len(lmd_anomalies)} LMD attacks detected via Random Forest. "
            "MITRE detections, IOCs, severity, ML behavioral anomaly scores, and attack-type classification are ready. "
            "Run AI Analysis for the full investigation narrative."
        ),
        analyzed_event_count=len(events),
        windows_analyzed=0,
        mitre_techniques=techniques,
        severity_score=severity,
        iocs=iocs,
        ml_anomaly_scores=ml_scores,
        attack_classification=attack_clf,
        lmd_graph=lmd_graph,
    )

    # Save to DB so Export Report works immediately after quick scan
    db.add(AnalysisModel(
        patient_zero_candidate="",
        initial_access_vector="",
        pivot_chain=[], anomalous_events=result.anomalous_events,
        confidence=result.confidence, narrative=result.narrative,
        analyzed_event_count=len(events),
        windows_analyzed=0,
        mitre_techniques=[t.model_dump() for t in techniques],
        severity_score=severity,
        iocs=[i.model_dump() for i in iocs],
        ml_scores=[s.model_dump() for s in ml_scores],
        case_id=case_id,
    ))
    db.commit()

    _write_audit(db, "quick_scan", {
        "events": len(events),
        "severity": severity,
        "mitre_count": len(techniques),
        "ioc_count": len(iocs),
        "case_id": case_id,
    }, username=current_user.username)

    return result


@router.get("/analysis/latest")
def get_latest_analysis(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(AnalysisModel).order_by(AnalysisModel.id.desc()).first()
    if not row:
        raise HTTPException(404, "No analysis has been run yet.")

    def _parse_json_col(col):
        if col is None:
            return []
        if isinstance(col, str):
            try:
                return json.loads(col)
            except Exception:
                return []
        return col

    return {
        "patient_zero_candidate": row.patient_zero_candidate,
        "initial_access_vector": row.initial_access_vector,
        "pivot_chain": _parse_json_col(row.pivot_chain),
        "anomalous_events": _parse_json_col(row.anomalous_events),
        "confidence": row.confidence,
        "narrative": row.narrative,
        "analyzed_event_count": row.analyzed_event_count,
        "windows_analyzed": row.windows_analyzed,
        "mitre_techniques": _parse_json_col(row.mitre_techniques),
        "severity_score": row.severity_score or 0,
        "iocs": _parse_json_col(row.iocs),
        "consensus_agreement": row.consensus_agreement,
        "created_at": row.created_at.isoformat(),
    }


# ── Graph ──────────────────────────────────────────────────────────────────────

@router.get("/graph")
def get_graph(
    raw_source: str | None = Query(default=None, description="Filter to a specific raw_source (e.g. 'pcap')"),
    case_id: str | None = Query(default=None),
    upload_id: int | None = Query(default=None, description="Filter to a single upload's events"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    query = db.query(EventModel).order_by(EventModel.timestamp)
    if upload_id is not None:
        # A specific upload already uniquely identifies the scope — skip case/global filter
        query = query.filter(EventModel.upload_id == upload_id)
    elif case_id:
        query = query.filter(EventModel.case_id == case_id)
    else:
        query = query.filter(EventModel.case_id == None)  # noqa: E711
    if raw_source:
        query = query.filter(EventModel.raw_source == raw_source)
    rows = query.all()
    if not rows:
        raise HTTPException(400, "No events loaded.")
    return build_attack_graph([_row_to_event(r) for r in rows])


# ── Chat ───────────────────────────────────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rows = (
        db.query(EventModel)
        .filter(EventModel.case_id == None)  # noqa: E711
        .order_by(EventModel.timestamp)
        .all()
    )
    if not rows:
        raise HTTPException(400, "No events loaded. Upload a file before chatting.")
    events = [_row_to_event(r) for r in rows]
    try:
        response = run_chat(req.message, req.history, events)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Chat failed: {exc}")
    _write_audit(db, "chat", {
        "message_length": len(req.message),
        "history_turns": len(req.history),
    }, username=current_user.username)
    return ChatResponse(response=response)


# ── IOC Endpoints ─────────────────────────────────────────────────────────────

@router.get("/iocs")
def get_iocs(
    case_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(EventModel)
    if case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded.")
    iocs = ioc_mod.extract_iocs([_row_to_event(r) for r in rows])
    return {"iocs": [i.model_dump() for i in iocs], "total": len(iocs)}


@router.get("/iocs/export/csv")
def export_iocs_csv(
    case_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(EventModel)
    if case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded.")
    iocs = ioc_mod.extract_iocs([_row_to_event(r) for r in rows])
    _write_audit(db, "export_csv", {"ioc_count": len(iocs)}, username=current_user.username)
    return PlainTextResponse(
        content=iocs_to_csv(iocs),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iocs.csv"},
    )


@router.get("/iocs/export/stix")
def export_iocs_stix(
    case_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(EventModel)
    if case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded.")
    iocs = ioc_mod.extract_iocs([_row_to_event(r) for r in rows])
    _write_audit(db, "export_stix", {"ioc_count": len(iocs)}, username=current_user.username)
    return JSONResponse(
        content=iocs_to_stix(iocs),
        headers={"Content-Disposition": "attachment; filename=iocs_stix.json"},
    )


# ── Report ─────────────────────────────────────────────────────────────────────

@router.get("/report/html", response_class=HTMLResponse)
def get_report_html(
    type: str = Query(default="auto", description="Report type: auto | quick | deep | court"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Generate a self-contained HTML report for the latest analysis.
    type=quick  → lightweight Quick Scan Snapshot (fastest, MITRE + IOC + ML)
    type=deep   → full Deep AI Intelligence Report (narrative, event timeline, charts)
    type=auto   → auto-detect: deep if windows_analyzed>0 else quick
    type=court  → court-ready exhibit: black/white, chain-of-custody, attestation block
    """
    from backend.analysis.report import generate_report, generate_quick_scan_report, generate_court_report

    def _pjc(col):
        if col is None: return []
        if isinstance(col, str):
            try: return json.loads(col)
            except: return []
        return col

    # Resolve which analysis row to use
    if type == "quick":
        analysis_row = (
            db.query(AnalysisModel)
            .filter(AnalysisModel.windows_analyzed == 0)
            .order_by(AnalysisModel.id.desc())
            .first()
        )
        if not analysis_row:
            analysis_row = db.query(AnalysisModel).order_by(AnalysisModel.id.desc()).first()
    elif type == "deep":
        analysis_row = (
            db.query(AnalysisModel)
            .filter(AnalysisModel.windows_analyzed > 0)
            .order_by(AnalysisModel.id.desc())
            .first()
        )
        if not analysis_row:
            analysis_row = db.query(AnalysisModel).order_by(AnalysisModel.id.desc()).first()
    else:
        analysis_row = db.query(AnalysisModel).order_by(AnalysisModel.id.desc()).first()

    if not analysis_row:
        raise HTTPException(400, "Run an analysis first before generating a report.")

    event_q = db.query(EventModel).order_by(EventModel.timestamp)
    if analysis_row.case_id:
        event_q = event_q.filter(EventModel.case_id == analysis_row.case_id)
    else:
        event_q = event_q.filter(EventModel.case_id == None)  # noqa: E711
    event_rows = event_q.all()
    events = [_row_to_event(r) for r in event_rows]

    result = RCAResult(
        patient_zero_candidate=analysis_row.patient_zero_candidate or "",
        initial_access_vector=analysis_row.initial_access_vector or "",
        pivot_chain=_pjc(analysis_row.pivot_chain),
        anomalous_events=_pjc(analysis_row.anomalous_events),
        confidence=analysis_row.confidence or "low",
        narrative=analysis_row.narrative or "",
        analyzed_event_count=analysis_row.analyzed_event_count or 0,
        windows_analyzed=analysis_row.windows_analyzed or 0,
        mitre_techniques=[MitreTechnique(**t) for t in _pjc(analysis_row.mitre_techniques)],
        severity_score=analysis_row.severity_score or 0,
        iocs=[IOC(**i) for i in _pjc(analysis_row.iocs)],
        consensus_agreement=analysis_row.consensus_agreement,
        ml_anomaly_scores=[UserAnomalyScore(**s) for s in _pjc(analysis_row.ml_scores)],
    )

    # Choose report generator
    is_quick = (type == "quick") or (type == "auto" and result.windows_analyzed == 0)
    if type == "court":
        # Gather chain-of-custody data for the court report
        audit_rows = db.query(AuditLogModel).order_by(AuditLogModel.id).all()
        chained = [r for r in audit_rows if r.prev_hash is not None]
        broken_at: int | None = None
        for row in chained:
            expected = _compute_chain_hash(
                prev_hash=row.prev_hash,
                action=row.action,
                detail=row.detail or {},
                file_sha256=row.file_sha256 or "",
            )
            if row.payload_sha256 != expected:
                broken_at = row.id
                break
        audit_status = {
            "valid": broken_at is None,
            "total": len(audit_rows),
            "chained": len(chained),
            "legacy_pre_chain": len(audit_rows) - len(chained),
            "broken_at": broken_at,
            "message": (
                "Chain intact."
                if broken_at is None
                else f"Chain BROKEN at entry #{broken_at} — tamper detected."
            ),
        }
        # Evidence file manifest scoped to the same case/workspace as the analysis
        upload_q = db.query(UploadModel)
        if analysis_row.case_id:
            upload_q = upload_q.filter(UploadModel.case_id == analysis_row.case_id)
        else:
            upload_q = upload_q.filter(UploadModel.case_id == None)  # noqa: E711
        uploads = upload_q.order_by(UploadModel.id).all()
        # Case metadata (if analysis is tied to a case)
        case_row = None
        if analysis_row.case_id:
            case_row = db.query(CaseModel).filter(
                CaseModel.case_id == analysis_row.case_id
            ).first()
        html = generate_court_report(
            result, events,
            audit_status=audit_status,
            uploads=uploads,
            case=case_row,
        )
        filename = "court_ready_report.html"
        audit_type = "export_court_report"
    elif is_quick:
        html = generate_quick_scan_report(result)
        filename = "quick_scan_snapshot.html"
        audit_type = "export_quick_scan"
    else:
        html = generate_report(result, events)
        filename = "deep_analysis_report.html"
        audit_type = "export_deep_report"

    _write_audit(db, audit_type, {
        "severity": result.severity_score,
        "confidence": result.confidence,
        "event_count": result.analyzed_event_count,
        "type": type,
    }, username=current_user.username)
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Incident Memory ────────────────────────────────────────────────────────────

@router.get("/incident-memory")
def get_incident_memory(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rows = db.query(IncidentPatternModel).order_by(
        IncidentPatternModel.incident_count.desc()
    ).limit(200).all()
    return {
        "patterns": [
            {
                "ioc_type": r.ioc_type, "ioc_value": r.ioc_value,
                "incident_count": r.incident_count,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.delete("/incident-memory")
def clear_incident_memory(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    db.query(IncidentPatternModel).delete(synchronize_session=False)
    db.commit()
    _write_audit(db, "clear_incident_memory", {}, username=current_user.username)
    return {"status": "cleared"}


# ── Single Event Lookup ────────────────────────────────────────────────────────

@router.get("/events/{event_id}")
def get_event_by_id(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Fetch a single forensic event by its database ID (used by citation links)."""
    row = db.query(EventModel).filter(EventModel.id == event_id).first()
    if not row:
        raise HTTPException(404, f"Event {event_id} not found.")
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat(),
        "event_type": row.event_type,
        "source_host": row.source_host,
        "user": row.user,
        "description": row.description,
        "raw_source": row.raw_source,
        "event_id": row.event_id,
        "upload_id": row.upload_id,
    }


# ── Audit Log (read-only) ──────────────────────────────────────────────────────

@router.get("/audit-log")
def get_audit_log(
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rows = (
        db.query(AuditLogModel)
        .order_by(AuditLogModel.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return {
        "entries": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "action": r.action,
                "detail": r.detail or {},
                "payload_sha256": r.payload_sha256,
                "prev_hash": r.prev_hash,
                "file_sha256": r.file_sha256,
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.get("/audit-log/verify")
def verify_audit_chain(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Verify the cryptographic hash chain across all audit log entries.

    Reads every row in insertion order, re-computes the expected chain hash from
    its stored fields, and checks it against the stored payload_sha256.  Any
    mismatch indicates post-write tampering.

    Rows with prev_hash=NULL were written before the v5 hash-chain upgrade and
    are skipped (they cannot be verified retroactively).
    """
    rows = db.query(AuditLogModel).order_by(AuditLogModel.id).all()
    if not rows:
        return {"valid": True, "total": 0, "chained": 0, "broken_at": None,
                "message": "Audit log is empty."}

    chained = [r for r in rows if r.prev_hash is not None]
    broken_at: int | None = None

    for row in chained:
        expected = _compute_chain_hash(
            prev_hash=row.prev_hash,
            action=row.action,
            detail=row.detail or {},
            file_sha256=row.file_sha256 or "",
        )
        if row.payload_sha256 != expected:
            broken_at = row.id
            break

    legacy = len(rows) - len(chained)
    return {
        "valid": broken_at is None,
        "total": len(rows),
        "chained": len(chained),
        "legacy_pre_chain": legacy,
        "broken_at": broken_at,
        "message": (
            "Chain intact." if broken_at is None
            else f"Chain BROKEN at entry #{broken_at} — tamper detected."
        ),
    }


# ── ML Anomaly Detection ───────────────────────────────────────────────────────

@router.post("/ml/train")
def train_ml_model(
    request: Request,
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_mfa),
):
    """
    Train (or retrain) the Isolation Forest anomaly model on all events
    currently in the DB — both investigation events and baseline events.
    Admin only. Requires at least 10 users with ≥5 events each.
    """
    current_rows = db.query(EventModel).all()
    baseline_rows = db.query(BaselineEventModel).all()

    current_events = [_row_to_event(r) for r in current_rows]
    baseline_events = [
        ForensicEvent(
            timestamp=r.timestamp, event_type=r.event_type,
            source_host=r.source_host, user=r.user,
            description=r.description, raw_source=r.raw_source,
            event_id=r.event_id, extra=None,
        )
        for r in baseline_rows
    ]
    all_events = current_events + baseline_events

    if not all_events:
        raise HTTPException(400, "No events in the database. Upload investigation or baseline logs first.")

    try:
        stats = ml_mod.train(all_events)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"ML training failed: {exc}")

    _write_audit(db, "ml_train", stats, username=admin_user.username)
    return {"status": "ok", **stats}


@router.get("/ml/status")
def get_ml_status(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return whether the anomaly model has been trained and basic stats."""
    status = ml_mod.get_model_status()
    try:
        synthetic_count = db.query(BaselineEventModel).filter(
            BaselineEventModel.user.like("user%")
            | BaselineEventModel.user.like("itadmin%")
            | BaselineEventModel.user.like("svc_backup%")
            | BaselineEventModel.user.like("dev%")
            | BaselineEventModel.user.like("helpdesk%")
            | BaselineEventModel.user.like("dbadmin%")
            | BaselineEventModel.user.like("exec%")
        ).count()
    except Exception:
        synthetic_count = 0
    status["synthetic_baseline_events"] = synthetic_count
    return status


@router.post("/ml/seed-baseline")
def seed_ml_baseline(
    request: Request,
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_mfa),
):
    """
    Generate synthetic baseline events covering 7 user profile types
    (standard_worker ×8, it_admin ×4, service_account ×5, developer ×4,
    help_desk ×4, db_admin ×3, executive ×2 = 30 users) and store them
    as BaselineEventModel rows.

    Safe to call multiple times — clears previous synthetic rows first
    (identified by known synthetic hostnames) so real baseline uploads
    are not affected.
    Admin only.
    """
    events = ml_synth.generate_baseline_events(days=30)

    # Remove previously seeded synthetic rows to avoid duplicates on re-seed.
    # Real baseline uploads use different host naming so they are unaffected.
    _SYNTHETIC_HOSTS = (
        "WORKSTATION-", "DB-SERVER-", "DEV-WS-", "EXEC-WS-",
    )
    _SYNTHETIC_EXACT = {
        "DC-01", "DC-02", "FILE-SERVER-01", "FILE-SERVER-02",
        "WEB-SERVER-01", "APP-SERVER-01", "PRINT-SERVER-01",
        "MGMT-SERVER-01", "BUILD-SERVER-01", "DEV-SERVER-01",
        "DB-SERVER-03", "BACKUP-01",
    }

    existing = db.query(BaselineEventModel).all()
    synthetic_ids = [
        r.id for r in existing
        if any(r.source_host.startswith(p) for p in _SYNTHETIC_HOSTS)
        or r.source_host in _SYNTHETIC_EXACT
    ]
    if synthetic_ids:
        db.query(BaselineEventModel).filter(
            BaselineEventModel.id.in_(synthetic_ids)
        ).delete(synchronize_session=False)
        db.commit()

    for e in events:
        db.add(BaselineEventModel(
            timestamp=e.timestamp,
            event_type=e.event_type,
            source_host=e.source_host,
            user=e.user,
            description=e.description,
            raw_source=e.raw_source.value,
            event_id=e.event_id,
        ))
    db.commit()

    _write_audit(db, "ml_seed_baseline", {
        "synthetic_events": len(events),
        "user_profiles": 7,
        "synthetic_users": 30,
    }, username=admin_user.username)

    return {
        "status": "ok",
        "synthetic_events_stored": len(events),
        "user_profiles": 7,
        "synthetic_users": 30,
        "message": (
            "Synthetic baseline stored. Now call POST /api/ml/train to build "
            "the model using this data combined with any real baseline/investigation events."
        ),
    }


# ── Maintenance (admin only) ───────────────────────────────────────────────────

def _purge_pycache(root: str) -> int:
    """
    Recursively delete all __pycache__ directories and .pyc files under root.
    Returns the count of items removed.
    """
    removed = 0
    for item in Path(root).rglob("__pycache__"):
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
            removed += 1
    for item in Path(root).rglob("*.pyc"):
        try:
            item.unlink()
            removed += 1
        except OSError:
            pass
    return removed


@router.post("/maintenance/cleanup")
def deep_clean(
    request: Request,
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_mfa),
):
    """
    Admin-only deep clean:
      1. Delete all events, analyses, chat messages, baseline events,
         and incident memory rows (audit log is preserved).
      2. Run VACUUM to reclaim disk space from the SQLite file.
      3. Remove all __pycache__ directories and .pyc files from the project root.
      4. Append a DEEP_CLEAN entry to the immutable audit log.
    """
    from backend.db.models import BaselineEventModel as BEM

    try:
        stats: dict = {}
        stats["events_deleted"] = db.query(EventModel).delete(synchronize_session=False)
        stats["analyses_deleted"] = db.query(AnalysisModel).delete(synchronize_session=False)
        stats["chat_deleted"] = db.query(ChatMessageModel).delete(synchronize_session=False)
        stats["baseline_deleted"] = db.query(BEM).delete(synchronize_session=False)
        stats["incident_memory_deleted"] = db.query(IncidentPatternModel).delete(synchronize_session=False)
        db.commit()

        # VACUUM must run outside a transaction
        with db.bind.connect() as conn:
            conn.execute(sa_text("VACUUM"))

        # Filesystem hygiene
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        stats["pycache_removed"] = _purge_pycache(project_root)

        _write_audit(db, "DEEP_CLEAN", stats, username=admin_user.username)
        return {"status": "ok", **stats}

    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"Deep clean failed: {exc}")


# ── Case Management ────────────────────────────────────────────────────────────

@router.post("/cases", response_model=Case)
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    from uuid import uuid4
    now = datetime.utcnow()
    row = CaseModel(
        case_id=str(uuid4()),
        title=payload.title,
        description=payload.description,
        status="active",
        created_at=now,
        updated_at=now,
        created_by=current_user.username,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    _write_audit(db, "case_create", {"case_id": row.case_id, "title": payload.title},
                 username=current_user.username)
    event_count = db.query(EventModel).filter(EventModel.case_id == row.case_id).count()
    analysis_count = db.query(AnalysisModel).filter(AnalysisModel.case_id == row.case_id).count()
    return Case(
        case_id=row.case_id, title=row.title, description=row.description,
        status=row.status, created_at=row.created_at, created_by=row.created_by,
        updated_at=row.updated_at, event_count=event_count, analysis_count=analysis_count,
    )


@router.get("/cases", response_model=list[Case])
def list_cases(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    rows = db.query(CaseModel).order_by(CaseModel.created_at.desc()).all()
    result = []
    for row in rows:
        event_count = db.query(EventModel).filter(EventModel.case_id == row.case_id).count()
        analysis_count = db.query(AnalysisModel).filter(AnalysisModel.case_id == row.case_id).count()
        result.append(Case(
            case_id=row.case_id, title=row.title, description=row.description,
            status=row.status, created_at=row.created_at, created_by=row.created_by,
            updated_at=row.updated_at, event_count=event_count, analysis_count=analysis_count,
        ))
    return result


@router.get("/cases/{case_id}", response_model=Case)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not row:
        raise HTTPException(404, f"Case {case_id!r} not found.")
    event_count = db.query(EventModel).filter(EventModel.case_id == case_id).count()
    analysis_count = db.query(AnalysisModel).filter(AnalysisModel.case_id == case_id).count()
    return Case(
        case_id=row.case_id, title=row.title, description=row.description,
        status=row.status, created_at=row.created_at, created_by=row.created_by,
        updated_at=row.updated_at, event_count=event_count, analysis_count=analysis_count,
    )


@router.patch("/cases/{case_id}", response_model=Case)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not row:
        raise HTTPException(404, f"Case {case_id!r} not found.")
    if payload.title is not None:
        row.title = payload.title
    if payload.description is not None:
        row.description = payload.description
    if payload.status is not None:
        allowed = {"active", "closed", "archived"}
        if payload.status not in allowed:
            raise HTTPException(400, f"status must be one of: {allowed}")
        row.status = payload.status
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    event_count = db.query(EventModel).filter(EventModel.case_id == case_id).count()
    analysis_count = db.query(AnalysisModel).filter(AnalysisModel.case_id == case_id).count()
    return Case(
        case_id=row.case_id, title=row.title, description=row.description,
        status=row.status, created_at=row.created_at, created_by=row.created_by,
        updated_at=row.updated_at, event_count=event_count, analysis_count=analysis_count,
    )


@router.delete("/cases/{case_id}")
def delete_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_admin),
):
    row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not row:
        raise HTTPException(404, f"Case {case_id!r} not found.")
    db.delete(row)
    db.query(NoteModel).filter(NoteModel.case_id == case_id).delete(synchronize_session=False)
    db.commit()
    _write_audit(db, "case_delete", {"case_id": case_id}, username=current_user.username)
    return {"status": "deleted", "case_id": case_id}


@router.get("/cases/{case_id}/report", response_class=HTMLResponse)
def get_case_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Generate a comprehensive forensic HTML report for all data in a case."""
    from backend.analysis.report import generate_case_report
    from backend.analysis import ml_anomaly as _ml_mod

    case_row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not case_row:
        raise HTTPException(404, f"Case {case_id!r} not found.")

    event_rows = (
        db.query(EventModel)
        .filter(EventModel.case_id == case_id)
        .order_by(EventModel.timestamp)
        .all()
    )
    events = [_row_to_event(r) for r in event_rows]

    analysis_rows = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.case_id == case_id)
        .order_by(AnalysisModel.id.desc())
        .all()
    )

    note_rows = (
        db.query(NoteModel)
        .filter(NoteModel.case_id == case_id)
        .order_by(NoteModel.is_pinned.desc(), NoteModel.created_at.asc())
        .all()
    )

    def _pjc(col):
        if col is None: return []
        if isinstance(col, str):
            try: return json.loads(col)
            except: return []
        return col

    # If no events at all, error early
    if not events and not analysis_rows:
        raise HTTPException(400, "No data in this case yet. Upload evidence first.")

    # If no analyses, run a quick deterministic scan on the fly
    if not analysis_rows:
        from backend.analysis import mitre as _mit, ioc as _ioc, scoring as _sc
        from backend.analysis.graph import build_attack_graph as _bag
        techniques = _mit.map_techniques(events)
        iocs = _ioc.extract_iocs(events)
        graph = _bag(events)
        severity = _sc.calculate_severity(events, techniques, graph.get("suspicious_users", []))
        ml_scores = _ml_mod.score_all_users(events)
        # Build a synthetic analysis record (not persisted)
        agg_techniques = techniques
        agg_iocs = iocs
        agg_ml_scores = ml_scores
        agg_severity = severity
        agg_narrative = "Quick scan performed on-the-fly — no AI analysis has been run for this case yet."
        agg_confidence = "low"
        agg_event_count = len(events)
        agg_patient_zero = ""
        agg_access_vector = ""
        agg_pivot_chain: list[str] = []
        agg_anomalous: list[str] = [f"{t.id} {t.name} ({t.tactic})" for t in techniques]
        agg_consensus: float | None = None
    else:
        # Aggregate across all analyses for this case
        seen_t: dict[str, MitreTechnique] = {}
        seen_i: dict[str, IOC] = {}
        seen_ml: dict[str, UserAnomalyScore] = {}
        agg_severity = 0
        agg_narrative = ""
        agg_confidence = "low"
        agg_event_count = len(events)
        agg_patient_zero = ""
        agg_access_vector = ""
        agg_pivot_chain = []
        agg_anomalous = []
        agg_consensus = None

        conf_rank = {"low": 0, "medium": 1, "high": 2}
        for row in reversed(analysis_rows):  # oldest first so latest wins
            for t in [MitreTechnique(**x) for x in _pjc(row.mitre_techniques)]:
                seen_t[t.id] = t
            for i in [IOC(**x) for x in _pjc(row.iocs)]:
                seen_i[i.value] = i
            for s in [UserAnomalyScore(**x) for x in _pjc(row.ml_scores)]:
                seen_ml[s.user] = s
            if (row.severity_score or 0) > agg_severity:
                agg_severity = row.severity_score or 0
            if row.narrative and len(row.narrative) > len(agg_narrative):
                agg_narrative = row.narrative
            if conf_rank.get(row.confidence or "low", 0) >= conf_rank.get(agg_confidence, 0):
                agg_confidence = row.confidence or "low"
            if row.patient_zero_candidate:
                agg_patient_zero = row.patient_zero_candidate
            if row.initial_access_vector:
                agg_access_vector = row.initial_access_vector
            if row.pivot_chain:
                agg_pivot_chain = _pjc(row.pivot_chain)
            if row.anomalous_events:
                agg_anomalous = _pjc(row.anomalous_events)
            if row.consensus_agreement is not None:
                agg_consensus = row.consensus_agreement

        agg_techniques = list(seen_t.values())
        agg_iocs = list(seen_i.values())
        agg_ml_scores = list(seen_ml.values())

    result = RCAResult(
        patient_zero_candidate=agg_patient_zero,
        initial_access_vector=agg_access_vector,
        pivot_chain=agg_pivot_chain,
        anomalous_events=agg_anomalous,
        confidence=agg_confidence,
        narrative=agg_narrative,
        analyzed_event_count=agg_event_count,
        windows_analyzed=len(analysis_rows),
        mitre_techniques=agg_techniques,
        severity_score=agg_severity,
        iocs=agg_iocs,
        consensus_agreement=agg_consensus,
        ml_anomaly_scores=agg_ml_scores,
    )

    upload_rows = (
        db.query(UploadModel)
        .filter(UploadModel.case_id == case_id)
        .order_by(UploadModel.uploaded_at.asc())
        .all()
    )

    notes = [Note.model_validate(n) for n in note_rows]
    uploads = [Upload.model_validate(u) for u in upload_rows]
    case_obj = Case(
        case_id=case_row.case_id, title=case_row.title, description=case_row.description,
        status=case_row.status, created_at=case_row.created_at, created_by=case_row.created_by,
        updated_at=case_row.updated_at, event_count=len(events), analysis_count=len(analysis_rows),
    )

    html = generate_case_report(case_obj, result, events, notes, uploads)
    safe_title = case_row.title.replace(" ", "_")[:40]
    _write_audit(db, "case_report", {
        "case_id": case_id, "events": len(events), "analyses": len(analysis_rows),
    }, username=current_user.username)
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename=case_report_{safe_title}.html"},
    )


@router.get("/cases/{case_id}/court-report", response_class=HTMLResponse)
def get_case_court_report(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Generate a court-ready forensic exhibit for all data in a specific case."""
    from backend.analysis.report import generate_court_report
    from backend.analysis import ml_anomaly as _ml_mod

    case_row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not case_row:
        raise HTTPException(404, f"Case {case_id!r} not found.")

    event_rows = (
        db.query(EventModel)
        .filter(EventModel.case_id == case_id)
        .order_by(EventModel.timestamp)
        .all()
    )
    events = [_row_to_event(r) for r in event_rows]

    analysis_rows = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.case_id == case_id)
        .order_by(AnalysisModel.id.desc())
        .all()
    )

    if not events and not analysis_rows:
        raise HTTPException(400, "No data in this case yet. Upload evidence first.")

    def _pjc(col):
        if col is None: return []
        if isinstance(col, str):
            try: return json.loads(col)
            except: return []
        return col

    # Aggregate all analyses for this case
    if not analysis_rows:
        from backend.analysis import mitre as _mit, ioc as _ioc, scoring as _sc
        from backend.analysis.graph import build_attack_graph as _bag
        techniques = _mit.map_techniques(events)
        iocs       = _ioc.extract_iocs(events)
        graph      = _bag(events)
        severity   = _sc.calculate_severity(events, techniques, graph.get("suspicious_users", []))
        ml_scores  = _ml_mod.score_all_users(events)
        result = RCAResult(
            patient_zero_candidate="", initial_access_vector="",
            pivot_chain=[], anomalous_events=[],
            confidence="low",
            narrative="Quick scan performed on-the-fly — no AI analysis has been run for this case yet.",
            analyzed_event_count=len(events), windows_analyzed=0,
            mitre_techniques=techniques, severity_score=severity,
            iocs=iocs, ml_anomaly_scores=ml_scores,
        )
    else:
        seen_t: dict[str, MitreTechnique] = {}
        seen_i: dict[str, IOC] = {}
        seen_ml: dict[str, UserAnomalyScore] = {}
        agg_severity, agg_narrative, agg_confidence = 0, "", "low"
        agg_event_count = len(events)
        agg_patient_zero, agg_access_vector = "", ""
        agg_pivot_chain, agg_anomalous, agg_consensus = [], [], None
        conf_rank = {"low": 0, "medium": 1, "high": 2}
        for row in reversed(analysis_rows):
            for t in [MitreTechnique(**x) for x in _pjc(row.mitre_techniques)]:
                seen_t[t.id] = t
            for i in [IOC(**x) for x in _pjc(row.iocs)]:
                seen_i[i.value] = i
            for s in [UserAnomalyScore(**x) for x in _pjc(row.ml_scores)]:
                seen_ml[s.user] = s
            if (row.severity_score or 0) > agg_severity:
                agg_severity = row.severity_score or 0
            if row.narrative and len(row.narrative) > len(agg_narrative):
                agg_narrative = row.narrative
            if conf_rank.get(row.confidence or "low", 0) >= conf_rank.get(agg_confidence, 0):
                agg_confidence = row.confidence or "low"
            if row.patient_zero_candidate:
                agg_patient_zero = row.patient_zero_candidate
            if row.initial_access_vector:
                agg_access_vector = row.initial_access_vector
            if row.pivot_chain:
                agg_pivot_chain = _pjc(row.pivot_chain)
            if row.anomalous_events:
                agg_anomalous = _pjc(row.anomalous_events)
            if row.consensus_agreement is not None:
                agg_consensus = row.consensus_agreement
        result = RCAResult(
            patient_zero_candidate=agg_patient_zero,
            initial_access_vector=agg_access_vector,
            pivot_chain=agg_pivot_chain, anomalous_events=agg_anomalous,
            confidence=agg_confidence, narrative=agg_narrative,
            analyzed_event_count=agg_event_count, windows_analyzed=len(analysis_rows),
            mitre_techniques=list(seen_t.values()), severity_score=agg_severity,
            iocs=list(seen_i.values()), consensus_agreement=agg_consensus,
            ml_anomaly_scores=list(seen_ml.values()),
        )

    # Chain-of-custody audit data
    audit_rows = db.query(AuditLogModel).order_by(AuditLogModel.id).all()
    chained = [r for r in audit_rows if r.prev_hash is not None]
    broken_at: int | None = None
    for row in chained:
        expected = _compute_chain_hash(
            prev_hash=row.prev_hash,
            action=row.action,
            detail=row.detail or {},
            file_sha256=row.file_sha256 or "",
        )
        if row.payload_sha256 != expected:
            broken_at = row.id
            break
    audit_status = {
        "valid": broken_at is None,
        "total": len(audit_rows),
        "chained": len(chained),
        "legacy_pre_chain": len(audit_rows) - len(chained),
        "broken_at": broken_at,
        "message": (
            "Chain intact."
            if broken_at is None
            else f"Chain BROKEN at entry #{broken_at} — tamper detected."
        ),
    }

    upload_rows = (
        db.query(UploadModel)
        .filter(UploadModel.case_id == case_id)
        .order_by(UploadModel.uploaded_at.asc())
        .all()
    )

    html = generate_court_report(
        result, events,
        audit_status=audit_status,
        uploads=upload_rows,
        case=case_row,
    )
    safe_title = case_row.title.replace(" ", "_")[:40]
    _write_audit(db, "case_court_report", {
        "case_id": case_id, "events": len(events), "analyses": len(analysis_rows),
    }, username=current_user.username)
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename=court_report_{safe_title}.html"},
    )


# ── Case Uploads Manifest ──────────────────────────────────────────────────────

@router.get("/cases/{case_id}/uploads", response_model=list[Upload])
def list_case_uploads(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return all files uploaded to a specific case, ordered newest first."""
    case_row = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not case_row:
        raise HTTPException(404, f"Case {case_id!r} not found.")
    rows = (
        db.query(UploadModel)
        .filter(UploadModel.case_id == case_id)
        .order_by(UploadModel.uploaded_at.desc())
        .all()
    )
    return [Upload.model_validate(r) for r in rows]


@router.get("/uploads", response_model=list[Upload])
def list_global_uploads(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Return uploads in the global workspace (no case), ordered newest first."""
    rows = (
        db.query(UploadModel)
        .filter(UploadModel.case_id == None)  # noqa: E711
        .order_by(UploadModel.uploaded_at.desc())
        .all()
    )
    return [Upload.model_validate(r) for r in rows]


@router.delete("/uploads/{upload_id}")
def delete_upload(
    upload_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a single upload and all its associated events."""
    row = db.query(UploadModel).filter(UploadModel.id == upload_id).first()
    if not row:
        raise HTTPException(404, f"Upload {upload_id} not found.")
    db.query(EventModel).filter(EventModel.upload_id == upload_id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    return {"status": "deleted", "upload_id": upload_id}


# ── Analyst Notes ──────────────────────────────────────────────────────────────

@router.post("/notes", response_model=Note)
def create_note(
    payload: NoteCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    now = datetime.utcnow()
    row = NoteModel(
        case_id=payload.case_id,
        analysis_id=payload.analysis_id,
        author=current_user.username,
        content=payload.content,
        created_at=now,
        updated_at=now,
        is_pinned=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return Note.model_validate(row)


@router.get("/notes", response_model=list[Note])
def list_notes(
    case_id: str | None = Query(default=None),
    analysis_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    q = db.query(NoteModel)
    if case_id:
        q = q.filter(NoteModel.case_id == case_id)
    if analysis_id is not None:
        q = q.filter(NoteModel.analysis_id == analysis_id)
    rows = q.order_by(NoteModel.is_pinned.desc(), NoteModel.created_at.desc()).all()
    return [Note.model_validate(r) for r in rows]


@router.patch("/notes/{note_id}", response_model=Note)
def update_note(
    note_id: int,
    payload: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(NoteModel).filter(NoteModel.id == note_id).first()
    if not row:
        raise HTTPException(404, f"Note {note_id} not found.")
    if payload.content is not None:
        row.content = payload.content
    if payload.is_pinned is not None:
        row.is_pinned = payload.is_pinned
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return Note.model_validate(row)


@router.delete("/notes/{note_id}")
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    row = db.query(NoteModel).filter(NoteModel.id == note_id).first()
    if not row:
        raise HTTPException(404, f"Note {note_id} not found.")
    db.delete(row)
    db.commit()
    return {"status": "deleted", "note_id": note_id}


# ── ML Ground Truth & Stats ────────────────────────────────────────────────────

@router.post("/ml/verify")
def verify_ml_prediction(
    payload: GroundTruthCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_admin),
):
    """
    Record analyst ground truth for a specific user's ML prediction.
    Looks up the latest anomaly score for the user from the most recent analysis,
    then stores the verification.
    """
    # Find the most recent analysis that has ml_scores
    analysis_row = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.ml_scores.isnot(None))
        .order_by(AnalysisModel.id.desc())
        .first()
    )
    if analysis_row is None:
        raise HTTPException(400, "No ML scores on record. Run a full analysis first.")

    raw = analysis_row.ml_scores
    if isinstance(raw, str):
        try:
            scores_list = json.loads(raw)
        except Exception:
            scores_list = []
    else:
        scores_list = raw or []

    user_score = next((s for s in scores_list if s.get("user") == payload.user), None)
    if user_score is None:
        raise HTTPException(404, f"No ML score found for user {payload.user!r} in latest analysis.")

    row = MLGroundTruthModel(
        analysis_id=payload.analysis_id or analysis_row.id,
        user=payload.user,
        predicted_risk=user_score.get("risk_level", "unknown"),
        predicted_score=float(user_score.get("anomaly_score", 0.0)),
        verified_by=current_user.username,
        is_true_positive=payload.is_true_positive,
        notes=payload.notes,
    )
    db.add(row)
    db.commit()
    _write_audit(db, "ml_verify", {
        "user": payload.user,
        "is_true_positive": payload.is_true_positive,
        "predicted_risk": row.predicted_risk,
    }, username=current_user.username)
    return {
        "status": "recorded",
        "user": payload.user,
        "predicted_risk": row.predicted_risk,
        "predicted_score": row.predicted_score,
        "is_true_positive": payload.is_true_positive,
    }


@router.get("/admin/ml-stats", response_model=MLStats)
def get_ml_stats(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_admin),
):
    """
    Compute precision / recall / F1 from analyst ground truth verifications.
    Positive class = anomalous / suspicious / high_risk predictions.
    """
    rows = db.query(MLGroundTruthModel).all()
    if not rows:
        return MLStats(
            total_verifications=0, true_positives=0, true_negatives=0,
            false_positives=0, false_negatives=0, note="No verifications recorded yet.",
        )

    tp = tn = fp = fn = 0
    for r in rows:
        predicted_positive = r.predicted_risk in ("suspicious", "high_risk")
        if r.is_true_positive and predicted_positive:
            tp += 1
        elif (not r.is_true_positive) and (not predicted_positive):
            tn += 1
        elif (not r.is_true_positive) and predicted_positive:
            fp += 1
        elif r.is_true_positive and (not predicted_positive):
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall    = tp / (tp + fn) if (tp + fn) > 0 else None
    f1        = (2 * precision * recall / (precision + recall)
                 if precision is not None and recall is not None
                 and (precision + recall) > 0 else None)
    accuracy  = (tp + tn) / len(rows) if rows else None

    return MLStats(
        total_verifications=len(rows),
        true_positives=tp, true_negatives=tn,
        false_positives=fp, false_negatives=fn,
        precision=round(precision, 4) if precision is not None else None,
        recall=round(recall, 4) if recall is not None else None,
        f1_score=round(f1, 4) if f1 is not None else None,
        accuracy=round(accuracy, 4) if accuracy is not None else None,
        note=f"Based on {len(rows)} analyst verification(s).",
    )


# ── Behavioral Analysis ────────────────────────────────────────────────────────

@router.post("/ml/behavioral")
def behavioral_analysis(
    case_id: str | None = Query(default=None),
    upload_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Run four behavioral anomaly checks against the loaded events:
      1. Per-user hourly event spike (Z-score > 2.5)
      2. Cross-host lateral velocity (> 3 distinct hosts in 30 min)
      3. Authentication failure burst (> 10 Event 4625 in 5 min)
      4. Off-hours SeDebugPrivilege assignment (outside 07:00-19:00)
    Returns a BehavioralReport with all detected anomalies sorted by severity.
    """
    q = db.query(EventModel).order_by(EventModel.timestamp)
    if upload_id is not None:
        q = q.filter(EventModel.upload_id == upload_id)
    elif case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded. Upload a file first.")
    events = [_row_to_event(r) for r in rows]
    report = analyze_behavior(events)
    _write_audit(db, "behavioral_analysis", {
        "event_count": len(events),
        "anomalies_found": len(report.get("anomalies", [])),
        "highest_severity": report.get("highest_severity", "none"),
        "case_id": case_id,
    }, username=current_user.username)
    return report


# ── Attack Storyline ───────────────────────────────────────────────────────────

@router.post("/ml/storyline")
def attack_storyline(
    case_id: str | None = Query(default=None),
    upload_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Build a structured attack storyline from loaded events.

    Outputs:
      - threat_actor_profile: heuristic threat actor classification
      - entry_vector: identified initial access method
      - tactic_progression: ordered list of observed ATT&CK tactics
      - attack_steps: chronological list of technique-mapped events
      - lateral_paths: host-to-host movement with method and technique
      - blast_radius: compromised hosts/users, accessed resources, persistence mechanisms
    Deterministic — no LLM call required. Sub-second for datasets up to 10k events.
    """
    q = db.query(EventModel).order_by(EventModel.timestamp)
    if upload_id is not None:
        q = q.filter(EventModel.upload_id == upload_id)
    elif case_id:
        q = q.filter(EventModel.case_id == case_id)
    else:
        q = q.filter(EventModel.case_id == None)  # noqa: E711
    rows = q.all()
    if not rows:
        raise HTTPException(400, "No events loaded. Upload a file first.")
    events = [_row_to_event(r) for r in rows]
    storyline = build_storyline(events)
    _write_audit(db, "storyline", {
        "event_count": len(events),
        "attack_steps": storyline.get("total_attack_steps", 0),
        "lateral_paths": storyline.get("total_lateral_paths", 0),
        "confidence": storyline.get("confidence", "low"),
        "case_id": case_id,
    }, username=current_user.username)
    return storyline


# ── Threat Intel Status ────────────────────────────────────────────────────────

@router.get("/threat-intel/status")
def get_threat_intel_status(
    current_user: UserModel = Depends(get_current_user),
):
    """Return which external threat intel providers have API keys configured."""
    return ti_mod.get_status()


# ── Detection Rules ────────────────────────────────────────────────────────────

@router.get("/detection-rules")
def get_detection_rules(
    fmt: str = Query(default="json", description="Output format: json | text"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Generate Sigma + Snort/Suricata detection rules from the latest analysis.
    fmt=json  → { sigma: [...], snort: [...] }
    fmt=text  → plain-text combined block (for copy-paste into SIEM/IDS)
    """
    analysis_row = (
        db.query(AnalysisModel)
        .filter(AnalysisModel.case_id == None)  # noqa: E711 — global workspace only
        .order_by(AnalysisModel.id.desc())
        .first()
    )
    if not analysis_row:
        raise HTTPException(400, "Run an analysis first before generating detection rules.")

    def _pjc(col):
        if col is None: return []
        if isinstance(col, str):
            try: return json.loads(col)
            except: return []
        return col

    techniques = [MitreTechnique(**t) for t in _pjc(analysis_row.mitre_techniques)]
    iocs = [IOC(**i) for i in _pjc(analysis_row.iocs)]

    sigma_rules  = rules_mod.generate_sigma_rules(iocs, techniques)
    snort_rules  = rules_mod.generate_snort_rules(iocs)

    # Behavioral rules — query the events scoped to this analysis's case (if any)
    event_query = db.query(EventModel)
    if analysis_row.case_id:
        event_query = event_query.filter(EventModel.case_id == analysis_row.case_id)
    raw_events = event_query.order_by(EventModel.timestamp).limit(5000).all()
    fe_events = [_row_to_event(r) for r in raw_events]
    behavioral_rules = rules_mod.generate_behavioral_sigma_rules(fe_events)
    sigma_rules = sigma_rules + behavioral_rules

    if fmt == "text":
        return PlainTextResponse(
            content=rules_mod.rules_to_text(sigma_rules, snort_rules),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=detection_rules.txt"},
        )

    return {
        "sigma": sigma_rules,
        "snort": snort_rules,
        "sigma_count": len(sigma_rules),
        "snort_count": len(snort_rules),
    }

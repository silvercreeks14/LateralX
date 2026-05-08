from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Optional
from enum import Enum


class RawSource(str, Enum):
    PLASO = "plaso"
    TIMESKETCH = "timesketch"
    VELOCIRAPTOR = "velociraptor"
    GENERIC = "generic"
    PCAP = "pcap"


class ForensicEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    event_type: str
    source_host: str
    user: Optional[str] = None
    description: str
    raw_source: RawSource
    event_id: Optional[str] = None
    extra: Optional[dict] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, datetime):
            return v
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(str(v).strip(), fmt)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse timestamp: {v}")


class MitreTechnique(BaseModel):
    id: str        # e.g. "T1059.001"
    name: str      # e.g. "PowerShell"
    tactic: str    # e.g. "Execution"
    evidence: Optional[str] = None


class IOC(BaseModel):
    type: str    # ip | url | file_path | md5 | sha256 | domain | registry_key
    value: str
    context: str


class UserAnomalyScore(BaseModel):
    entity: str
    anomaly_score: float
    risk_level: str                  # "normal" | "suspicious" | "high_risk"
    contributing_factors: list[str]
    session_event_count: int
    confidence: str                  # "insufficient_data" | "low" | "medium" | "high"


class NarrativeCitation(BaseModel):
    """
    Maps one sentence of the AI narrative to the specific database event IDs that
    support it.  Used to render clickable [N] citation badges in the frontend.
    event_ids are integer primary keys from the `events` table.
    """
    sentence: str
    event_ids: list[int] = []


class AttackClassification(BaseModel):
    primary_attack: str
    confidence: float
    confidence_label: str          # "none" | "low" | "medium" | "high"
    all_scores: dict[str, float]   # category -> probability, sorted descending
    top_evidence: list[str]        # matched indicator keywords
    mitre_techniques: list[str]    # MITRE ATT&CK IDs for primary category


class RCAResult(BaseModel):
    patient_zero_candidate: str
    initial_access_vector: str
    pivot_chain: list[str]
    anomalous_events: list[str]
    confidence: str
    narrative: str
    analyzed_event_count: int
    windows_analyzed: int
    mitre_techniques: list[MitreTechnique] = []
    severity_score: int = 0
    iocs: list[IOC] = []
    consensus_agreement: Optional[float] = None
    ml_anomaly_scores: list[UserAnomalyScore] = []
    # v5: explainable AI — every narrative sentence mapped to its source event IDs
    narrative_citations: list[NarrativeCitation] = []
    # v6: supervised attack-type classification
    attack_classification: Optional[AttackClassification] = None
    # LMD Random Forest attack graph rendered inside AI Analysis
    lmd_graph: Optional[dict] = None


class UploadResponse(BaseModel):
    status: str
    events_loaded: int
    filename: str
    time_range: dict
    known_ioc_matches: list[str] = []
    file_hash: str = ""
    hash_changed: bool = False


class EventSummary(BaseModel):
    total: int
    hosts: list[str]
    users: list[str]
    event_types: list[str]
    time_range: Optional[dict] = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []


class ChatResponse(BaseModel):
    response: str


class BaselineComparisonResult(BaseModel):
    new_hosts: list[str]
    new_users: list[str]
    anomalous_event_types: list[str]
    event_count_delta: int
    summary: str
    severity_delta: int = 0


# ── v3 Case Management ────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None   # "active" | "closed" | "archived"


class Case(BaseModel):
    case_id: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: datetime
    created_by: Optional[str] = None
    updated_at: datetime
    event_count: int = 0
    analysis_count: int = 0

    model_config = {"from_attributes": True}


class NoteCreate(BaseModel):
    case_id: Optional[str] = None
    analysis_id: Optional[int] = None
    content: str


class NoteUpdate(BaseModel):
    content: Optional[str] = None
    is_pinned: Optional[bool] = None


class Note(BaseModel):
    id: int
    case_id: Optional[str] = None
    analysis_id: Optional[int] = None
    author: str
    content: str
    created_at: datetime
    updated_at: datetime
    is_pinned: bool

    model_config = {"from_attributes": True}


# ── v3 ML Ground Truth & Metrics ──────────────────────────────────────────────

class GroundTruthCreate(BaseModel):
    analysis_id: Optional[int] = None
    user: str
    is_true_positive: bool
    notes: Optional[str] = None


class MLStats(BaseModel):
    total_verifications: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    accuracy: Optional[float] = None
    note: str


# ── v4 Multi-source & Search ──────────────────────────────────────────────────

class Upload(BaseModel):
    id: int
    case_id: Optional[str] = None
    filename: str
    file_hash: Optional[str] = None
    uploaded_at: datetime
    uploaded_by: Optional[str] = None
    event_count: int

    model_config = {"from_attributes": True}


class SearchEventResult(BaseModel):
    id: int
    timestamp: str
    source_host: str
    user: Optional[str] = None
    event_type: str
    case_id: Optional[str] = None
    upload_id: Optional[int] = None
    snippet: str


class SearchNoteResult(BaseModel):
    id: int
    case_id: Optional[str] = None
    author: str
    created_at: str
    snippet: str


class SearchResponse(BaseModel):
    events: list[SearchEventResult]
    notes: list[SearchNoteResult]
    total: int


# ── Phase 2: Behavioral Analysis ──────────────────────────────────────────────

class BehavioralAnomaly(BaseModel):
    anomaly_type: str   # "hourly_event_spike" | "lateral_velocity" | "auth_failure_burst" | "off_hours_privilege"
    entity: str
    description: str
    z_score: Optional[float] = None
    threshold: float
    observed: float
    severity: str       # "low" | "medium" | "high"


class BehavioralReport(BaseModel):
    anomalies: list[BehavioralAnomaly]
    profiled_entities: int
    analysis_window_hours: float
    highest_severity: str   # "none" | "low" | "medium" | "high"


# ── Phase 3: Attack Storyline ──────────────────────────────────────────────────

class AttackStep(BaseModel):
    step_number: int
    timestamp: str
    host: str
    user: Optional[str] = None
    tactic: str
    technique_id: str
    technique_name: str
    description: str
    event_ids: list[int] = []
    confidence: str     # "low" | "medium" | "high"


class LateralPath(BaseModel):
    from_host: str
    to_host: str
    user: str
    method: str
    timestamp: str
    technique_id: str


class BlastRadius(BaseModel):
    compromised_hosts: list[str]
    compromised_users: list[str]
    accessed_resources: list[str]
    estimated_data_at_risk: str
    persistence_mechanisms: list[str]


class AttackStoryline(BaseModel):
    threat_actor_profile: str
    entry_vector: str
    tactic_progression: list[str]
    attack_steps: list[AttackStep]
    lateral_paths: list[LateralPath]
    blast_radius: BlastRadius
    total_duration_minutes: float
    confidence: str
    total_attack_steps: int
    total_lateral_paths: int


# ── Model Quality / Benchmark ──────────────────────────────────────────────────

class ClassMetrics(BaseModel):
    class_id: int
    class_name: str
    precision: float
    recall: float
    f1: float
    support: int


class ModelBenchmarkResult(BaseModel):
    model_name: str
    dataset_source: str
    dataset_url: Optional[str] = None
    dataset_citation: str
    n_samples: int
    grade: str                              # "A" | "B" | "C" | "D" | "N/A"
    gaps: list[str] = []
    # LMD-specific
    accuracy: Optional[float] = None
    precision_macro: Optional[float] = None
    recall_macro: Optional[float] = None
    f1_macro: Optional[float] = None
    class_metrics: list[ClassMetrics] = []
    confusion_matrix: list[list[int]] = []
    class_labels: list[str] = []
    per_dataset: Optional[dict] = None
    # MITRE-specific
    coverage: Optional[float] = None
    hits: Optional[int] = None
    partials: Optional[int] = None
    misses: Optional[int] = None
    per_technique: Optional[list] = None
    # Anomaly-specific
    auc_roc: Optional[float] = None
    tpr_at_fpr10: Optional[float] = None
    roc_curve: Optional[list] = None
    note: Optional[str] = None


class BenchmarkReport(BaseModel):
    run_at: str
    overall_grade: str
    recommendations: list[str]
    lmd: ModelBenchmarkResult
    mitre: ModelBenchmarkResult
    anomaly: ModelBenchmarkResult
    benchmark_datasets: dict[str, str] = {}

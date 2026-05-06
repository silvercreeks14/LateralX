export interface LoginResponse {
  access_token: string
  token_type: string
  username: string
  role: string
}

export interface ForensicEvent {
  id: number
  timestamp: string
  event_type: string
  source_host: string
  user: string | null
  description: string
  raw_source: string
  event_id: string | null
  upload_id?: number | null
}

export interface EventSummary {
  total: number
  hosts: string[]
  users: string[]
  event_types: string[]
  time_range?: { start: string; end: string }
}

export interface UploadResponse {
  status: string
  events_loaded: number
  filename: string
  time_range: { start: string; end: string }
  known_ioc_matches: string[]
  file_hash: string
  hash_changed: boolean
}

export interface AuditEntry {
  id: number
  timestamp: string
  action: string
  detail: Record<string, unknown>
  payload_sha256: string | null
  prev_hash: string | null
  file_sha256: string | null
}

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  evidence?: string | null
}

export interface IOC {
  type: string
  value: string
  context: string
}

export interface UserAnomalyScore {
  user: string
  anomaly_score: number
  risk_level: 'normal' | 'suspicious' | 'high_risk'
  contributing_factors: string[]
  session_event_count: number
  confidence: 'insufficient_data' | 'low' | 'medium' | 'high'
}

export interface MLModelStatus {
  trained: boolean
  trained_on_users: number
  trained_on_events: number
  trained_at: string | null
  synthetic_baseline_events: number
}

export interface NarrativeCitation {
  sentence: string
  event_ids: number[]
}

export interface AttackClassification {
  primary_attack: string
  confidence: number
  confidence_label: 'none' | 'low' | 'medium' | 'high'
  all_scores: Record<string, number>
  top_evidence: string[]
  mitre_techniques: string[]
}

export interface RCAResult {
  patient_zero_candidate: string
  initial_access_vector: string
  pivot_chain: string[]
  anomalous_events: string[]
  confidence: 'low' | 'medium' | 'high'
  narrative: string
  analyzed_event_count: number
  windows_analyzed: number
  mitre_techniques: MitreTechnique[]
  severity_score: number
  iocs: IOC[]
  consensus_agreement: number | null
  ml_anomaly_scores?: UserAnomalyScore[]
  // v5: explainable AI — narrative sentences mapped to source event IDs
  narrative_citations?: NarrativeCitation[]
  // v6: supervised attack-type classification
  attack_classification?: AttackClassification | null
  lmd_graph?: { nodes: any[]; edges: any[] } | null
}

export interface ScenarioStep {
  step: number
  attack_stage: string
  source: string
  target: string
  timestamp: string
  event_id: string
  description: string
}

export interface GraphData {
  elements: { nodes: CyNode[]; edges: CyEdge[] }
  suspicious_users: string[]
  total_logon_events: number
  unique_hosts: number
  scenario_links?: number
  graph_mode?: string
  scenario_story?: ScenarioStep[]
}

export interface CyNode {
  data: {
    id: string
    label: string
    type: 'host' | 'user' | 'external_ip'
    subtype?: 'server' | 'workstation'
    suspicious: boolean
  }
  classes: string
}

export interface CyEdge {
  data: {
    id: string
    source: string
    target: string
    timestamp: string
    suspicious: boolean
    count?: number
    seq?: number
    attack_stage?: string
    scenario_link?: boolean
    label?: string
  }
}

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export interface BaselineComparisonResult {
  new_hosts: string[]
  new_users: string[]
  anomalous_event_types: string[]
  event_count_delta: number
  summary: string
  severity_delta: number
}

export interface IncidentPattern {
  ioc_type: string
  ioc_value: string
  incident_count: number
  first_seen: string
  last_seen: string
}

export interface Case {
  case_id: string
  title: string
  description: string | null
  status: string
  created_at: string
  created_by: string | null
  updated_at: string
  event_count: number
  analysis_count: number
}

export interface CaseUpdate {
  title?: string
  description?: string
  status?: 'active' | 'closed' | 'archived'
}

export interface Note {
  id: number
  case_id: string | null
  analysis_id: number | null
  author: string
  content: string
  created_at: string
  updated_at: string
  is_pinned: boolean
}

export interface MLStats {
  total_verifications: number
  true_positives: number
  true_negatives: number
  false_positives: number
  false_negatives: number
  precision: number | null
  recall: number | null
  f1_score: number | null
  accuracy: number | null
  note: string
}

export interface SigmaRule {
  title: string
  id: string
  status: string
  description: string
  tags: string[]
  detection: { keywords: string[]; condition: string }
  level: string
}

export interface ThreatIntelStatus {
  vt_configured: boolean
  abuseipdb_configured: boolean
}

export interface DetectionRulesResponse {
  sigma: SigmaRule[]
  snort: string[]
  sigma_count: number
  snort_count: number
}

export interface Upload {
  id: number
  case_id: string | null
  filename: string
  file_hash: string | null
  uploaded_at: string
  uploaded_by: string | null
  event_count: number
}

export interface SearchEventResult {
  id: number
  timestamp: string
  source_host: string
  user: string | null
  event_type: string
  case_id: string | null
  upload_id: number | null
  snippet: string
}

export interface SearchNoteResult {
  id: number
  case_id: string | null
  author: string
  created_at: string
  snippet: string
}

export interface SearchResponse {
  events: SearchEventResult[]
  notes: SearchNoteResult[]
  total: number
}

export interface TotpStatus {
  totp_enabled: boolean
  totp_configured: boolean
}

export interface TotpSetupResult {
  secret: string
  uri: string
  qr_code_png_b64: string
  instructions: string
}

// ── Phase 2: Behavioral Analysis ─────────────────────────────────────────────

export interface BehavioralAnomaly {
  anomaly_type: string
  user: string
  description: string
  z_score: number | null
  threshold: number
  observed: number
  severity: string
}

export interface BehavioralReport {
  anomalies: BehavioralAnomaly[]
  profiled_users: number
  analysis_window_hours: number
  highest_severity: string
}

// ── Phase 3: Attack Storyline ─────────────────────────────────────────────────

export interface AttackStep {
  step_number: number
  timestamp: string
  host: string
  user: string | null
  tactic: string
  technique_id: string
  technique_name: string
  description: string
  event_ids: number[]
  confidence: string
}

export interface LateralPath {
  from_host: string
  to_host: string
  user: string
  method: string
  timestamp: string
  technique_id: string
}

export interface BlastRadius {
  compromised_hosts: string[]
  compromised_users: string[]
  accessed_resources: string[]
  estimated_data_at_risk: string
  persistence_mechanisms: string[]
}

export interface AttackStoryline {
  threat_actor_profile: string
  entry_vector: string
  tactic_progression: string[]
  attack_steps: AttackStep[]
  lateral_paths: LateralPath[]
  blast_radius: BlastRadius
  total_duration_minutes: number
  confidence: string
  total_attack_steps: number
  total_lateral_paths: number
}

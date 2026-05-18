import type {
  ForensicEvent, EventSummary, UploadResponse, RCAResult,
  GraphData, BaselineComparisonResult, IncidentPattern, AuditEntry,
  LoginResponse, MLModelStatus, Case, CaseUpdate, Note, MLStats, DetectionRulesResponse,
  ThreatIntelStatus, Upload, SearchResponse, TotpStatus, TotpSetupResult, NarrativeCitation,
  BehavioralReport, BehavioralAnomaly, AttackStoryline, AttackStep, LateralPath, BlastRadius,
  EntityAnomalyScore,
  ADRulesResult, PrivilegeTimelineResult, ADEntityIntelResult,
} from '../types'

// Re-export so components don't need a second import path
export type { NarrativeCitation, BehavioralReport, BehavioralAnomaly, AttackStoryline, AttackStep, LateralPath, BlastRadius, EntityAnomalyScore }

const BASE = '/api'
const TOKEN_KEY = 'lx_token'
const USER_KEY = 'lx_user'

// ── Token helpers ──────────────────────────────────────────────────────────────

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string, username: string, role: string): void {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify({ username, role }))
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function isAuthenticated(): boolean {
  const token = getToken()
  if (!token) return false
  try {
    // JWT payload is base64url-encoded; check exp claim
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.exp * 1000 > Date.now()
  } catch {
    return false
  }
}

export function getStoredUser(): { username: string; role: string } | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

// ── Token refresh (raw fetch — bypasses request() to prevent recursion) ────────

// Single in-flight promise shared across concurrent callers so a burst of requests
// near token expiry only fires one /auth/refresh round-trip.
let _refreshInFlight: Promise<void> | null = null

export async function silentRefresh(): Promise<void> {
  if (_refreshInFlight) return _refreshInFlight
  const token = getToken()
  if (!token) return
  _refreshInFlight = (async () => {
    try {
      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.ok) {
        const data = await res.json()
        setToken(data.access_token, data.username, data.role)
      }
    } catch { /* silent */ } finally {
      _refreshInFlight = null
    }
  })()
  return _refreshInFlight
}

// ── Request core ───────────────────────────────────────────────────────────────

async function request<T>(path: string, options: RequestInit = {}, mfaCode?: string): Promise<T> {
  const token = getToken()
  const headers = new Headers(options.headers as HeadersInit | undefined)

  if (token) {
    // Sliding session: refresh if < 20 minutes remaining (raw fetch, not recursive)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      if (payload.exp * 1000 - Date.now() < 20 * 60 * 1000) {
        await silentRefresh()
      }
    } catch { /* ignore */ }
    headers.set('Authorization', `Bearer ${getToken() ?? token}`)
  }

  if (mfaCode) headers.set('X-MFA-Code', mfaCode)

  const res = await fetch(`${BASE}${path}`, { ...options, headers })

  // MFA challenge: server printed a 6-digit code to the console
  if (res.status === 202) {
    const body = await res.json().catch(() => ({}))
    if (body.detail?.mfa_required) {
      window.dispatchEvent(new CustomEvent('auth:mfa-required', { detail: { path, options } }))
      throw new Error('MFA_REQUIRED')
    }
  }

  if (res.status === 401) {
    clearToken()
    window.dispatchEvent(new CustomEvent('auth:expired'))
    throw new Error('Session expired. Please log in again.')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `Request failed: ${res.status}`)
  }
  return res.json()
}

async function _downloadBlob(path: string, filename: string, mime: string): Promise<void> {
  const token = getToken()
  const headers = new Headers()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const res = await fetch(`${BASE}${path}`, { headers })
  if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('auth:expired')); return }
  if (!res.ok) throw new Error(`Download failed: ${res.status}`)
  const blob = new Blob([await res.blob()], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ── API surface ────────────────────────────────────────────────────────────────

export const api = {
  // ── Auth
  // Step 1: submit credentials.
  //   Non-admin → returns LoginResponse immediately.
  //   Admin     → returns { mfa_required: true, username } — server printed code to console.
  loginInit: async (
    username: string,
    password: string,
  ): Promise<LoginResponse | { mfa_required: true; username: string }> => {
    const body = new URLSearchParams({ username, password })
    const res = await fetch(`${BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (res.status === 202) return res.json()
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Login failed')
    }
    return res.json()
  },

  // Step 2 (admin only): re-submit credentials with the MFA code.
  loginConfirm: async (
    username: string,
    password: string,
    mfaCode: string,
  ): Promise<LoginResponse> => {
    const body = new URLSearchParams({ username, password })
    const res = await fetch(`${BASE}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-MFA-Code': mfaCode,
      },
      body: body.toString(),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Invalid MFA code')
    }
    return res.json()
  },

  // ── Upload
  uploadFile: (file: File): Promise<UploadResponse> => {
    const form = new FormData()
    form.append('file', file)
    return request('/upload', { method: 'POST', body: form })
  },
  uploadBaseline: (file: File): Promise<{ status: string; baseline_events: number }> => {
    const form = new FormData()
    form.append('file', file)
    return request('/upload/baseline', { method: 'POST', body: form })
  },

  // ── Events
  getSummary: (caseId?: string | null): Promise<EventSummary> => {
    const qs = caseId ? `?case_id=${encodeURIComponent(caseId)}` : ''
    return request(`/events/summary${qs}`)
  },
  getEvents: (params: Record<string, string> = {}, caseId?: string | null): Promise<ForensicEvent[]> => {
    const p = new URLSearchParams(params)
    if (caseId) p.set('case_id', caseId)
    const qs = p.toString()
    return request(`/events${qs ? '?' + qs : ''}`)
  },

  // ── Analysis
  runAnalysis: (caseId?: string | null, uploadId?: number | null): Promise<RCAResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze${qs ? '?' + qs : ''}`, { method: 'POST' })
  },
  compareBaseline: (): Promise<BaselineComparisonResult> =>
    request('/analyze/baseline-compare', { method: 'POST' }),
  getLatestAnalysis: (): Promise<RCAResult> => request('/analysis/latest'),

  // ── Graph
  getGraph: (rawSource?: string, caseId?: string | null, uploadId?: number | null): Promise<GraphData> => {
    const p = new URLSearchParams()
    if (rawSource) p.set('raw_source', rawSource)
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/graph${qs ? '?' + qs : ''}`)
  },

  // ── IOCs
  getIocs: (): Promise<{ iocs: import('../types').IOC[]; total: number }> => request('/iocs'),
  exportIocsCsv: () => _downloadBlob('/iocs/export/csv', 'iocs.csv', 'text/csv'),
  exportIocsStix: () => _downloadBlob('/iocs/export/stix', 'iocs_stix.json', 'application/json'),

  // ── Report
  downloadReport: (type: 'auto' | 'quick' | 'deep' | 'court' = 'auto') =>
    _downloadBlob(
      `/report/html?type=${type}`,
      type === 'quick'  ? 'quick_scan_snapshot.html'
      : type === 'court' ? 'court_ready_report.html'
      : 'deep_analysis_report.html',
      'text/html',
    ),
  downloadCaseReport: (caseId: string) =>
    _downloadBlob(`/cases/${caseId}/report`, `case_report_${caseId.slice(0, 8)}.html`, 'text/html'),
  downloadCaseCourtReport: (caseId: string) =>
    _downloadBlob(`/cases/${caseId}/court-report`, `court_report_${caseId.slice(0, 8)}.html`, 'text/html'),

  // ── Incident Memory
  getIncidentMemory: (): Promise<{ patterns: IncidentPattern[]; total: number }> =>
    request('/incident-memory'),
  clearIncidentMemory: (): Promise<{ status: string }> =>
    request('/incident-memory', { method: 'DELETE' }),

  // ── Workspace
  clearWorkspace: (): Promise<{ status: string }> =>
    request('/clear', { method: 'POST' }),

  // ── Events (single lookup — used by citation badges)
  getEventById: (id: number): Promise<ForensicEvent> =>
    request(`/events/${id}`),

  // ── Audit Log
  getAuditLog: (limit = 200): Promise<{ entries: AuditEntry[]; total: number }> =>
    request(`/audit-log?limit=${limit}`),
  verifyAuditChain: (): Promise<{
    valid: boolean
    total: number
    chained: number
    legacy_pre_chain: number
    broken_at: number | null
    message: string
  }> => request('/audit-log/verify'),

  // ── Upload with optional case tag
  uploadFileToCase: (file: File, caseId: string): Promise<UploadResponse> => {
    const form = new FormData()
    form.append('file', file)
    return request(`/upload?case_id=${encodeURIComponent(caseId)}`, { method: 'POST', body: form })
  },

  // ── ML Anomaly Detection
  getMlStatus: (): Promise<MLModelStatus> =>
    request('/ml/status'),
  // Initial call (no MFA code) — throws 'MFA_REQUIRED'; follow up with trainMlModelMfa
  trainMlModel: (): Promise<{ status: string; trained_on_users: number; trained_on_events: number; trained_at: string }> =>
    request('/ml/train', { method: 'POST' }),
  trainMlModelMfa: (code: string): Promise<{ status: string; trained_on_users: number; trained_on_events: number; trained_at: string }> =>
    request('/ml/train', { method: 'POST' }, code),
  // Initial call (no MFA code) — throws 'MFA_REQUIRED'; follow up with seedMlBaselineMfa
  seedMlBaseline: (): Promise<{ status: string; synthetic_events_stored: number; synthetic_users: number }> =>
    request('/ml/seed-baseline', { method: 'POST' }),
  seedMlBaselineMfa: (code: string): Promise<{ status: string; synthetic_events_stored: number; synthetic_users: number }> =>
    request('/ml/seed-baseline', { method: 'POST' }, code),
  mlQuickScan: (caseId?: string | null, uploadId?: number | null): Promise<RCAResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/quick-scan${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── ML Ground Truth & Stats
  verifyMlPrediction: (entity: string, isPositive: boolean, notes?: string): Promise<object> =>
    request('/ml/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: entity, is_true_positive: isPositive, notes }),
    }),
  getMlStats: (): Promise<MLStats> => request('/admin/ml-stats'),

  // ── Case Management
  createCase: (title: string, description?: string): Promise<Case> =>
    request('/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description }),
    }),
  listCases: (): Promise<Case[]> => request('/cases'),
  getCase: (caseId: string): Promise<Case> => request(`/cases/${caseId}`),
  updateCase: (caseId: string, patch: CaseUpdate): Promise<Case> =>
    request(`/cases/${caseId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
  deleteCase: (caseId: string): Promise<{ status: string }> =>
    request(`/cases/${caseId}`, { method: 'DELETE' }),

  // ── Analyst Notes
  createNote: (content: string, caseId?: string, analysisId?: number): Promise<Note> =>
    request('/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, case_id: caseId, analysis_id: analysisId }),
    }),
  listNotes: (caseId?: string, analysisId?: number): Promise<Note[]> => {
    const params = new URLSearchParams()
    if (caseId) params.set('case_id', caseId)
    if (analysisId !== undefined) params.set('analysis_id', String(analysisId))
    const qs = params.toString()
    return request(`/notes${qs ? '?' + qs : ''}`)
  },
  updateNote: (id: number, patch: { content?: string; is_pinned?: boolean }): Promise<Note> =>
    request(`/notes/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
  deleteNote: (id: number): Promise<{ status: string }> =>
    request(`/notes/${id}`, { method: 'DELETE' }),

  // ── Threat Intel
  getTiStatus: (): Promise<ThreatIntelStatus> => request('/threat-intel/status'),

  // ── Detection Rules
  getDetectionRules: (): Promise<DetectionRulesResponse> =>
    request('/detection-rules?fmt=json'),
  downloadDetectionRules: () =>
    _downloadBlob('/detection-rules?fmt=text', 'detection_rules.txt', 'text/plain'),
  downloadSigmaRules: () =>
    _downloadBlob('/detection-rules?fmt=sigma', 'sigma_rules.yml', 'text/plain'),
  downloadYaraRules: () =>
    _downloadBlob('/detection-rules?fmt=yara', 'lateralx_rules.yar', 'text/plain'),
  downloadSnortRules: () =>
    _downloadBlob('/detection-rules?fmt=snort', 'snort_rules.rules', 'text/plain'),

  // ── Multi-source uploads (per case or global workspace)
  getCaseUploads: (caseId: string): Promise<Upload[]> =>
    request(`/cases/${caseId}/uploads`),
  getUploads: (): Promise<Upload[]> => request('/uploads'),
  deleteUpload: (uploadId: number): Promise<{ status: string; upload_id: number }> =>
    request(`/uploads/${uploadId}`, { method: 'DELETE' }),

  // ── Global full-text search
  search: (q: string, limit = 20): Promise<SearchResponse> =>
    request(`/search?q=${encodeURIComponent(q)}&limit=${limit}`),

  // ── Phase 2: Behavioral Analysis
  mlBehavioral: (caseId?: string | null, uploadId?: number | null): Promise<BehavioralReport> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/behavioral${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── Phase 3: Attack Storyline
  mlStoryline: (caseId?: string | null, uploadId?: number | null): Promise<AttackStoryline> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/storyline${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Detection Engine
  runADRules: (caseId?: string | null, uploadId?: number | null): Promise<ADRulesResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze/ad-rules${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Privilege Timeline
  runPrivilegeTimeline: (caseId?: string | null, uploadId?: number | null): Promise<PrivilegeTimelineResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze/privilege-timeline${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Entity Intelligence
  getADEntities: (caseId?: string | null, uploadId?: number | null): Promise<ADEntityIntelResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ad-entities${qs ? '?' + qs : ''}`)
  },

  // ── TOTP setup (admin only)
  getTotpStatus: (): Promise<TotpStatus> => request('/admin/totp/status'),
  setupTotp: (): Promise<TotpSetupResult> =>
    request('/admin/totp/setup', { method: 'POST' }),
  verifyTotp: (code: string): Promise<{ status: string; message: string }> =>
    request(`/admin/totp/verify?code=${encodeURIComponent(code)}`, { method: 'POST' }),
  disableTotp: (): Promise<{ status: string; message: string }> =>
    request('/admin/totp/disable', { method: 'DELETE' }),
}
import type {
  ForensicEvent, EventSummary, UploadResponse, RCAResult,
  GraphData, BaselineComparisonResult, IncidentPattern, AuditEntry,
  LoginResponse, MLModelStatus, Case, CaseUpdate, Note, MLStats, DetectionRulesResponse,
  ThreatIntelStatus, Upload, SearchResponse, TotpStatus, TotpSetupResult, NarrativeCitation,
  BehavioralReport, BehavioralAnomaly, AttackStoryline, AttackStep, LateralPath, BlastRadius,
  EntityAnomalyScore, LMDRFScanResult,
  ADRulesResult, PrivilegeTimelineResult, ADEntityIntelResult,
} from '../types'

// Re-export so components don't need a second import path
export type { NarrativeCitation, BehavioralReport, BehavioralAnomaly, AttackStoryline, AttackStep, LateralPath, BlastRadius, EntityAnomalyScore }

const BASE = '/api'
const TOKEN_KEY = 'lx_token'
const USER_KEY = 'lx_user'

// ── Token helpers ──────────────────────────────────────────────────────────────

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string, username: string, role: string): void {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify({ username, role }))
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function isAuthenticated(): boolean {
  const token = getToken()
  if (!token) return false
  try {
    // JWT payload is base64url-encoded; check exp claim
    const payload = JSON.parse(atob(token.split('.')[1]))
    return payload.exp * 1000 > Date.now()
  } catch {
    return false
  }
}

export function getStoredUser(): { username: string; role: string } | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

// ── Token refresh (raw fetch — bypasses request() to prevent recursion) ────────

// Single in-flight promise shared across concurrent callers so a burst of requests
// near token expiry only fires one /auth/refresh round-trip.
let _refreshInFlight: Promise<void> | null = null

export async function silentRefresh(): Promise<void> {
  if (_refreshInFlight) return _refreshInFlight
  const token = getToken()
  if (!token) return
  _refreshInFlight = (async () => {
    try {
      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.ok) {
        const data = await res.json()
        setToken(data.access_token, data.username, data.role)
      }
    } catch { /* silent */ } finally {
      _refreshInFlight = null
    }
  })()
  return _refreshInFlight
}

// ── Request core ───────────────────────────────────────────────────────────────

async function request<T>(path: string, options: RequestInit = {}, mfaCode?: string): Promise<T> {
  const token = getToken()
  const headers = new Headers(options.headers as HeadersInit | undefined)

  if (token) {
    // Sliding session: refresh if < 20 minutes remaining (raw fetch, not recursive)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      if (payload.exp * 1000 - Date.now() < 20 * 60 * 1000) {
        await silentRefresh()
      }
    } catch { /* ignore */ }
    headers.set('Authorization', `Bearer ${getToken() ?? token}`)
  }

  if (mfaCode) headers.set('X-MFA-Code', mfaCode)

  const res = await fetch(`${BASE}${path}`, { ...options, headers })

  // MFA challenge: server printed a 6-digit code to the console
  if (res.status === 202) {
    const body = await res.json().catch(() => ({}))
    if (body.detail?.mfa_required) {
      window.dispatchEvent(new CustomEvent('auth:mfa-required', { detail: { path, options } }))
      throw new Error('MFA_REQUIRED')
    }
  }

  if (res.status === 401) {
    clearToken()
    window.dispatchEvent(new CustomEvent('auth:expired'))
    throw new Error('Session expired. Please log in again.')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `Request failed: ${res.status}`)
  }
  return res.json()
}

async function _downloadBlob(path: string, filename: string, mime: string): Promise<void> {
  const token = getToken()
  const headers = new Headers()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const res = await fetch(`${BASE}${path}`, { headers })
  if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('auth:expired')); return }
  if (!res.ok) throw new Error(`Download failed: ${res.status}`)
  const blob = new Blob([await res.blob()], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ── API surface ────────────────────────────────────────────────────────────────

export const api = {
  // ── Auth
  // Step 1: submit credentials.
  //   Non-admin → returns LoginResponse immediately.
  //   Admin     → returns { mfa_required: true, username } — server printed code to console.
  loginInit: async (
    username: string,
    password: string,
  ): Promise<LoginResponse | { mfa_required: true; username: string }> => {
    const body = new URLSearchParams({ username, password })
    const res = await fetch(`${BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (res.status === 202) return res.json()
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Login failed')
    }
    return res.json()
  },

  // Step 2 (admin only): re-submit credentials with the MFA code.
  loginConfirm: async (
    username: string,
    password: string,
    mfaCode: string,
  ): Promise<LoginResponse> => {
    const body = new URLSearchParams({ username, password })
    const res = await fetch(`${BASE}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-MFA-Code': mfaCode,
      },
      body: body.toString(),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Invalid MFA code')
    }
    return res.json()
  },

  // ── Upload
  uploadFile: (file: File): Promise<UploadResponse> => {
    const form = new FormData()
    form.append('file', file)
    return request('/upload', { method: 'POST', body: form })
  },
  uploadBaseline: (file: File): Promise<{ status: string; baseline_events: number }> => {
    const form = new FormData()
    form.append('file', file)
    return request('/upload/baseline', { method: 'POST', body: form })
  },

  // ── Events
  getSummary: (caseId?: string | null): Promise<EventSummary> => {
    const qs = caseId ? `?case_id=${encodeURIComponent(caseId)}` : ''
    return request(`/events/summary${qs}`)
  },
  getEvents: (params: Record<string, string> = {}, caseId?: string | null): Promise<ForensicEvent[]> => {
    const p = new URLSearchParams(params)
    if (caseId) p.set('case_id', caseId)
    const qs = p.toString()
    return request(`/events${qs ? '?' + qs : ''}`)
  },

  // ── Analysis
  runAnalysis: (caseId?: string | null, uploadId?: number | null): Promise<RCAResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze${qs ? '?' + qs : ''}`, { method: 'POST' })
  },
  compareBaseline: (): Promise<BaselineComparisonResult> =>
    request('/analyze/baseline-compare', { method: 'POST' }),
  getLatestAnalysis: (): Promise<RCAResult> => request('/analysis/latest'),

  // ── Graph
  getGraph: (rawSource?: string, caseId?: string | null, uploadId?: number | null): Promise<GraphData> => {
    const p = new URLSearchParams()
    if (rawSource) p.set('raw_source', rawSource)
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/graph${qs ? '?' + qs : ''}`)
  },

  // ── IOCs
  getIocs: (): Promise<{ iocs: import('../types').IOC[]; total: number }> => request('/iocs'),
  exportIocsCsv: () => _downloadBlob('/iocs/export/csv', 'iocs.csv', 'text/csv'),
  exportIocsStix: () => _downloadBlob('/iocs/export/stix', 'iocs_stix.json', 'application/json'),

  // ── Report
  downloadReport: (type: 'auto' | 'quick' | 'deep' | 'court' = 'auto') =>
    _downloadBlob(
      `/report/html?type=${type}`,
      type === 'quick'  ? 'quick_scan_snapshot.html'
      : type === 'court' ? 'court_ready_report.html'
      : 'deep_analysis_report.html',
      'text/html',
    ),
  downloadCaseReport: (caseId: string) =>
    _downloadBlob(`/cases/${caseId}/report`, `case_report_${caseId.slice(0, 8)}.html`, 'text/html'),
  downloadCaseCourtReport: (caseId: string) =>
    _downloadBlob(`/cases/${caseId}/court-report`, `court_report_${caseId.slice(0, 8)}.html`, 'text/html'),

  // ── Incident Memory
  getIncidentMemory: (): Promise<{ patterns: IncidentPattern[]; total: number }> =>
    request('/incident-memory'),
  clearIncidentMemory: (): Promise<{ status: string }> =>
    request('/incident-memory', { method: 'DELETE' }),

  // ── Workspace
  clearWorkspace: (): Promise<{ status: string }> =>
    request('/clear', { method: 'POST' }),

  // ── Events (single lookup — used by citation badges)
  getEventById: (id: number): Promise<ForensicEvent> =>
    request(`/events/${id}`),

  // ── Audit Log
  getAuditLog: (limit = 200): Promise<{ entries: AuditEntry[]; total: number }> =>
    request(`/audit-log?limit=${limit}`),
  verifyAuditChain: (): Promise<{
    valid: boolean
    total: number
    chained: number
    legacy_pre_chain: number
    broken_at: number | null
    message: string
  }> => request('/audit-log/verify'),

  // ── Upload with optional case tag
  uploadFileToCase: (file: File, caseId: string): Promise<UploadResponse> => {
    const form = new FormData()
    form.append('file', file)
    return request(`/upload?case_id=${encodeURIComponent(caseId)}`, { method: 'POST', body: form })
  },

  // ── ML Anomaly Detection
  getMlStatus: (): Promise<MLModelStatus> =>
    request('/ml/status'),
  // Initial call (no MFA code) — throws 'MFA_REQUIRED'; follow up with trainMlModelMfa
  trainMlModel: (): Promise<{ status: string; trained_on_users: number; trained_on_events: number; trained_at: string }> =>
    request('/ml/train', { method: 'POST' }),
  trainMlModelMfa: (code: string): Promise<{ status: string; trained_on_users: number; trained_on_events: number; trained_at: string }> =>
    request('/ml/train', { method: 'POST' }, code),
  // Initial call (no MFA code) — throws 'MFA_REQUIRED'; follow up with seedMlBaselineMfa
  seedMlBaseline: (): Promise<{ status: string; synthetic_events_stored: number; synthetic_users: number }> =>
    request('/ml/seed-baseline', { method: 'POST' }),
  seedMlBaselineMfa: (code: string): Promise<{ status: string; synthetic_events_stored: number; synthetic_users: number }> =>
    request('/ml/seed-baseline', { method: 'POST' }, code),
  mlQuickScan: (caseId?: string | null, uploadId?: number | null): Promise<RCAResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/quick-scan${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── ML Ground Truth & Stats
  verifyMlPrediction: (entity: string, isPositive: boolean, notes?: string): Promise<object> =>
    request('/ml/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: entity, is_true_positive: isPositive, notes }),
    }),
  getMlStats: (): Promise<MLStats> => request('/admin/ml-stats'),

  // ── Case Management
  createCase: (title: string, description?: string): Promise<Case> =>
    request('/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description }),
    }),
  listCases: (): Promise<Case[]> => request('/cases'),
  getCase: (caseId: string): Promise<Case> => request(`/cases/${caseId}`),
  updateCase: (caseId: string, patch: CaseUpdate): Promise<Case> =>
    request(`/cases/${caseId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
  deleteCase: (caseId: string): Promise<{ status: string }> =>
    request(`/cases/${caseId}`, { method: 'DELETE' }),

  // ── Analyst Notes
  createNote: (content: string, caseId?: string, analysisId?: number): Promise<Note> =>
    request('/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, case_id: caseId, analysis_id: analysisId }),
    }),
  listNotes: (caseId?: string, analysisId?: number): Promise<Note[]> => {
    const params = new URLSearchParams()
    if (caseId) params.set('case_id', caseId)
    if (analysisId !== undefined) params.set('analysis_id', String(analysisId))
    const qs = params.toString()
    return request(`/notes${qs ? '?' + qs : ''}`)
  },
  updateNote: (id: number, patch: { content?: string; is_pinned?: boolean }): Promise<Note> =>
    request(`/notes/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
  deleteNote: (id: number): Promise<{ status: string }> =>
    request(`/notes/${id}`, { method: 'DELETE' }),

  // ── Threat Intel
  getTiStatus: (): Promise<ThreatIntelStatus> => request('/threat-intel/status'),

  // ── Detection Rules
  getDetectionRules: (): Promise<DetectionRulesResponse> =>
    request('/detection-rules?fmt=json'),
  downloadDetectionRules: () =>
    _downloadBlob('/detection-rules?fmt=text', 'detection_rules.txt', 'text/plain'),
  downloadSigmaRules: () =>
    _downloadBlob('/detection-rules?fmt=sigma', 'sigma_rules.yml', 'text/plain'),
  downloadYaraRules: () =>
    _downloadBlob('/detection-rules?fmt=yara', 'lateralx_rules.yar', 'text/plain'),
  downloadSnortRules: () =>
    _downloadBlob('/detection-rules?fmt=snort', 'snort_rules.rules', 'text/plain'),

  // ── Multi-source uploads (per case or global workspace)
  getCaseUploads: (caseId: string): Promise<Upload[]> =>
    request(`/cases/${caseId}/uploads`),
  getUploads: (): Promise<Upload[]> => request('/uploads'),
  deleteUpload: (uploadId: number): Promise<{ status: string; upload_id: number }> =>
    request(`/uploads/${uploadId}`, { method: 'DELETE' }),

  // ── Global full-text search
  search: (q: string, limit = 20): Promise<SearchResponse> =>
    request(`/search?q=${encodeURIComponent(q)}&limit=${limit}`),

  // ── Phase 2: Behavioral Analysis
  mlBehavioral: (caseId?: string | null, uploadId?: number | null): Promise<BehavioralReport> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/behavioral${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── Phase 3: Attack Storyline
  mlStoryline: (caseId?: string | null, uploadId?: number | null): Promise<AttackStoryline> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ml/storyline${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Detection Engine
  runADRules: (caseId?: string | null, uploadId?: number | null): Promise<ADRulesResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze/ad-rules${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Privilege Timeline
  runLMDRFScan: (file: File): Promise<LMDRFScanResult> => {
    const form = new FormData()
    form.append('file', file)
    return request('/analyze/lmd-rf', { method: 'POST', body: form })
  },
  downloadLMDAttackGraph: () =>
    _downloadBlob('/analyze/lmd-rf/attack-graph', 'attack_graph.html', 'text/html'),

  runPrivilegeTimeline: (caseId?: string | null, uploadId?: number | null): Promise<PrivilegeTimelineResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/analyze/privilege-timeline${qs ? '?' + qs : ''}`, { method: 'POST' })
  },

  // ── AD Entity Intelligence
  getADEntities: (caseId?: string | null, uploadId?: number | null): Promise<ADEntityIntelResult> => {
    const p = new URLSearchParams()
    if (caseId) p.set('case_id', caseId)
    if (uploadId != null) p.set('upload_id', String(uploadId))
    const qs = p.toString()
    return request(`/ad-entities${qs ? '?' + qs : ''}`)
  },

  // ── TOTP setup (admin only)
  getTotpStatus: (): Promise<TotpStatus> => request('/admin/totp/status'),
  setupTotp: (): Promise<TotpSetupResult> =>
    request('/admin/totp/setup', { method: 'POST' }),
  verifyTotp: (code: string): Promise<{ status: string; message: string }> =>
    request(`/admin/totp/verify?code=${encodeURIComponent(code)}`, { method: 'POST' }),
  disableTotp: (): Promise<{ status: string; message: string }> =>
    request('/admin/totp/disable', { method: 'DELETE' }),
}

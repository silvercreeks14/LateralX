import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/client'
import type { Case, Upload } from '../types'
import NotesPanel from './NotesPanel'

interface Props {
  onSelectCase?: (caseId: string | null) => void
  uploadKey?: number
}

type StatusFilter = 'all' | 'active' | 'closed' | 'archived'

export default function CaseDashboard({ onSelectCase, uploadKey }: Props) {
  const [cases, setCases] = useState<Case[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [updatingId, setUpdatingId] = useState<string | null>(null)

  // Evidence management state
  const [caseUploads, setCaseUploads] = useState<Upload[]>([])
  const [uploadsLoading, setUploadsLoading] = useState(false)
  const [deletingUploadId, setDeletingUploadId] = useState<number | null>(null)

  const loadCases = useCallback(async () => {
    try {
      const data = await api.listCases()
      setCases(data)
    } catch { /* silent */ }
  }, [])

  useEffect(() => { loadCases() }, [loadCases, uploadKey])

  const loadUploads = useCallback(async (caseId: string) => {
    setUploadsLoading(true)
    try {
      const data = await api.getCaseUploads(caseId)
      setCaseUploads(data)
    } catch { /* silent */ } finally {
      setUploadsLoading(false)
    }
  }, [])

  // Load uploads when a case is selected
  useEffect(() => {
    if (selectedId) loadUploads(selectedId)
    else setCaseUploads([])
  }, [selectedId, loadUploads])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const title = newTitle.trim()
    if (!title) return
    setSaving(true)
    setError(null)
    try {
      const c = await api.createCase(title, newDesc.trim() || undefined)
      setCases(prev => [c, ...prev])
      setNewTitle('')
      setNewDesc('')
      setCreating(false)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create case')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (caseId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!window.confirm('Delete this case and all its notes?')) return
    try {
      await api.deleteCase(caseId)
      setCases(prev => prev.filter(c => c.case_id !== caseId))
      if (selectedId === caseId) {
        setSelectedId(null)
        onSelectCase?.(null)
      }
    } catch { /* silent */ }
  }

  const handleSelect = (caseId: string) => {
    const next = selectedId === caseId ? null : caseId
    setSelectedId(next)
    onSelectCase?.(next)
  }

  const handleSetStatus = async (caseId: string, status: 'active' | 'closed' | 'archived', e: React.MouseEvent) => {
    e.stopPropagation()
    setUpdatingId(caseId)
    try {
      const updated = await api.updateCase(caseId, { status })
      setCases(prev => prev.map(c => c.case_id === caseId ? updated : c))
    } catch { /* silent */ } finally {
      setUpdatingId(null)
    }
  }

  const handleExportCourtReport = async (caseId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await api.downloadCaseCourtReport(caseId)
    } catch { /* silent */ }
  }

  const handleDeleteUpload = async (uploadId: number, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!window.confirm('Remove this evidence file and all its events from the investigation?')) return
    setDeletingUploadId(uploadId)
    try {
      await api.deleteUpload(uploadId)
      setCaseUploads(prev => prev.filter(u => u.id !== uploadId))
      loadCases()
    } catch { /* silent */ } finally {
      setDeletingUploadId(null)
    }
  }

  const selected = cases.find(c => c.case_id === selectedId)
  const filteredCases = statusFilter === 'all' ? cases : cases.filter(c => c.status === statusFilter)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white">Case Management</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            {cases.filter(c => c.status === 'active').length} active · {cases.length} total
          </p>
        </div>
        <button
          onClick={() => setCreating(v => !v)}
          className="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
        >
          + New Case
        </button>
      </div>

      {/* Status filter tabs */}
      {cases.length > 0 && (
        <div className="flex gap-1 bg-slate-800 rounded-lg p-1 w-fit">
          {(['all', 'active', 'closed', 'archived'] as StatusFilter[]).map(f => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={`text-xs px-3 py-1 rounded-md capitalize transition-colors ${
                statusFilter === f
                  ? 'bg-slate-700 text-white font-medium'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {f === 'all' ? `All (${cases.length})` : `${f} (${cases.filter(c => c.status === f).length})`}
            </button>
          ))}
        </div>
      )}

      {/* Create form */}
      {creating && (
        <form onSubmit={handleCreate} className="bg-blue-950/20 border border-blue-800/40 rounded-lg p-4 space-y-3">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Case Title *</label>
            <input
              type="text"
              value={newTitle}
              onChange={e => setNewTitle(e.target.value)}
              placeholder="e.g. Ransomware Incident April 2026"
              autoFocus
              className="w-full bg-slate-800 border border-slate-700 text-white rounded-md px-3 py-2 text-sm focus:outline-none placeholder-slate-600"
              onFocus={e => { e.currentTarget.style.borderColor = '#00F0FF60' }}
              onBlur={e => { e.currentTarget.style.borderColor = '' }}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Description (optional)</label>
            <textarea
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              placeholder="Brief description of this case…"
              rows={2}
              className="w-full bg-slate-800 border border-slate-700 text-white rounded-md px-3 py-2 text-sm resize-none focus:outline-none placeholder-slate-600"
              onFocus={e => { e.currentTarget.style.borderColor = '#00F0FF60' }}
              onBlur={e => { e.currentTarget.style.borderColor = '' }}
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={!newTitle.trim() || saving}
              className="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-md"
            >
              {saving ? 'Creating…' : 'Create Case'}
            </button>
            <button
              type="button"
              onClick={() => setCreating(false)}
              className="text-xs px-3 py-1.5 border border-slate-700 text-slate-400 rounded-md hover:bg-slate-800"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Case list */}
      {cases.length === 0 ? (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-8 text-center">
          <p className="text-sm text-slate-500">No cases yet.</p>
          <p className="text-xs text-slate-600 mt-1">Create a case to organise evidence uploads and analyst notes.</p>
        </div>
      ) : filteredCases.length === 0 ? (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-6 text-center">
          <p className="text-sm text-slate-500">No {statusFilter} cases.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredCases.map(c => (
            <div
              key={c.case_id}
              onClick={() => handleSelect(c.case_id)}
              className={`rounded-lg border cursor-pointer transition-all ${
                selectedId === c.case_id
                  ? 'border-cyan-500/40 bg-cyan-950/10'
                  : 'border-slate-800 bg-slate-900 hover:border-slate-700'
              }`}
            >
              <div className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-semibold text-white truncate">{c.title}</h3>
                      <span className={`flex-shrink-0 text-xs px-2 py-0.5 rounded-full font-medium ${
                        c.status === 'active'   ? 'bg-green-900/30 text-green-400' :
                        c.status === 'closed'   ? 'bg-slate-800 text-slate-500' :
                                                  'bg-amber-900/30 text-amber-400'
                      }`}>
                        {c.status}
                      </span>
                    </div>
                    {c.description && (
                      <p className="text-xs text-slate-500 mt-0.5 truncate">{c.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2 text-xs text-slate-600">
                      <span>{c.event_count} events</span>
                      <span>{c.analysis_count} analyses</span>
                      <span>by {c.created_by ?? 'unknown'}</span>
                      <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>

                  {/* Action buttons */}
                  <div className="flex items-center gap-1.5 flex-shrink-0" onClick={e => e.stopPropagation()}>
                    {/* Lifecycle */}
                    {c.status === 'active' && (
                      <button
                        onClick={e => handleSetStatus(c.case_id, 'closed', e)}
                        disabled={updatingId === c.case_id}
                        className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-400 hover:bg-slate-800 disabled:opacity-40"
                        title="Close case"
                      >
                        Close
                      </button>
                    )}
                    {c.status === 'closed' && (
                      <>
                        <button
                          onClick={e => handleSetStatus(c.case_id, 'active', e)}
                          disabled={updatingId === c.case_id}
                          className="text-xs px-2 py-1 rounded border border-green-800/40 text-green-400 hover:bg-green-950/20 disabled:opacity-40"
                          title="Reopen case"
                        >
                          Reopen
                        </button>
                        <button
                          onClick={e => handleSetStatus(c.case_id, 'archived', e)}
                          disabled={updatingId === c.case_id}
                          className="text-xs px-2 py-1 rounded border border-amber-800/40 text-amber-400 hover:bg-amber-950/20 disabled:opacity-40"
                          title="Archive case"
                        >
                          Archive
                        </button>
                      </>
                    )}
                    {c.status === 'archived' && (
                      <button
                        onClick={e => handleSetStatus(c.case_id, 'active', e)}
                        disabled={updatingId === c.case_id}
                        className="text-xs px-2 py-1 rounded border border-green-800/40 text-green-400 hover:bg-green-950/20 disabled:opacity-40"
                        title="Restore to active"
                      >
                        Restore
                      </button>
                    )}
                    {/* Export court-ready report */}
                    <button
                      onClick={e => handleExportCourtReport(c.case_id, e)}
                      className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-400 hover:bg-slate-800"
                      title="Export court-ready forensic report — black/white, chain-of-custody, attestation block"
                    >
                      Export Report
                    </button>
                    {/* Delete */}
                    <button
                      onClick={e => handleDelete(c.case_id, e)}
                      className="text-slate-700 hover:text-red-400 transition-colors text-sm p-1"
                      title="Delete case"
                    >
                      ✕
                    </button>
                  </div>
                </div>
              </div>

              {/* Expanded: evidence + notes */}
              {selectedId === c.case_id && (
                <div className="border-t border-slate-800 p-4 space-y-4" onClick={e => e.stopPropagation()}>

                  {/* Evidence files */}
                  <div>
                    <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Evidence Files</p>
                    {uploadsLoading ? (
                      <p className="text-xs text-slate-600 py-1">Loading evidence…</p>
                    ) : caseUploads.length === 0 ? (
                      <p className="text-xs text-slate-600 italic">No files uploaded to this case yet.</p>
                    ) : (
                      <div className="space-y-1">
                        {caseUploads.map(u => (
                          <div
                            key={u.id}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-md bg-slate-800 border border-slate-700"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <svg className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                              </svg>
                              <span className="text-xs text-slate-300 font-mono truncate" title={u.filename}>{u.filename}</span>
                              <span className="text-xs text-slate-600 flex-shrink-0">{u.event_count.toLocaleString()} events</span>
                              <span className="text-xs text-slate-700 flex-shrink-0">
                                {new Date(u.uploaded_at).toLocaleDateString()}
                              </span>
                            </div>
                            <button
                              onClick={e => handleDeleteUpload(u.id, e)}
                              disabled={deletingUploadId === u.id}
                              className="text-slate-600 hover:text-red-400 transition-colors disabled:opacity-40 flex-shrink-0 p-1"
                              title="Remove this evidence file and all its events from the investigation"
                            >
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                              </svg>
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Analyst notes */}
                  <NotesPanel caseId={c.case_id} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Selected case summary bar */}
      {selected && (
        <div className="rounded-lg px-4 py-2.5 text-xs flex items-center justify-between border"
          style={{ background: '#00F0FF12', borderColor: '#00F0FF30', color: '#00F0FF' }}>
          <span>Active case: <strong>{selected.title}</strong></span>
          <button
            onClick={() => { setSelectedId(null); onSelectCase?.(null) }}
            className="opacity-60 hover:opacity-100 transition-opacity"
          >
            Deselect
          </button>
        </div>
      )}
    </div>
  )
}

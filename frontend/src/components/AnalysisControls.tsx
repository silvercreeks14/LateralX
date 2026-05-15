import { useState } from 'react'
import { api } from '../api/client'
import type { Upload } from '../types'

interface Props {
  loading:           boolean
  baselineLoading:   boolean
  uploads:           Upload[]
  isAdmin:           boolean
  activeCaseId?:     string | null
  hasResult:         boolean
  onRunAnalysis:     (uploadId?: number | null) => void
  onCompareBaseline: () => void
}

export default function AnalysisControls({
  loading, baselineLoading, uploads, isAdmin, activeCaseId, hasResult,
  onRunAnalysis, onCompareBaseline,
}: Props) {
  const [selectedUploadId, setSelectedUploadId] = useState<number | null>(null)
  const [exporting, setExporting] = useState(false)

  const effectiveUploadId = uploads.length > 1 ? selectedUploadId : null

  const handleExport = async () => {
    setExporting(true)
    try {
      if (activeCaseId) {
        await api.downloadCaseReport(activeCaseId)
      } else {
        await api.downloadReport('deep')
      }
    } catch { /* silent — browser will show error */ } finally {
      setExporting(false)
    }
  }

  return (
    <div className="space-y-3">
      {/* ── Upload source picker (multi-upload contexts) ───────────────────── */}
      {uploads.length > 1 && (
        <div className="bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3">
          <p className="text-xs font-medium text-slate-500 mb-2">Analysis source:</p>
          <div className="flex flex-wrap gap-2">
            {uploads.map(u => (
              <button
                key={u.id}
                onClick={() => setSelectedUploadId(u.id)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors max-w-[220px] truncate ${
                  selectedUploadId === u.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-cyan-500/40 hover:text-cyan-400'
                }`}
                title={`${u.filename} — ${u.event_count.toLocaleString()} events`}
              >
                {u.filename.length > 28 ? u.filename.slice(0, 25) + '…' : u.filename}
                <span className={`ml-1 ${selectedUploadId === u.id ? 'text-blue-200' : 'text-slate-600'}`}>
                  ({u.event_count.toLocaleString()})
                </span>
              </button>
            ))}
            {isAdmin && (
              <button
                onClick={() => setSelectedUploadId(null)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors border ${
                  selectedUploadId === null
                    ? 'bg-amber-500 text-white border-amber-500'
                    : 'bg-white dark:bg-slate-900 border-amber-700/40 text-amber-400 hover:bg-amber-950/20'
                }`}
                title="Analyse all uploads merged (admin only)"
              >
                All merged
              </button>
            )}
          </div>
          {selectedUploadId === null && isAdmin && uploads.length > 1 && (
            <p className="text-xs text-amber-400 mt-1.5">
              Analysing all {uploads.length} sources merged — may increase false positives across unrelated incidents.
            </p>
          )}
        </div>
      )}

      {/* ── Control row ────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => onRunAnalysis(effectiveUploadId)}
          disabled={loading}
          className="text-xs px-3 py-1.5 rounded-md font-medium disabled:opacity-40 transition-colors"
          style={loading ? {} : { background: '#00F0FF18', color: '#00F0FF', border: '1px solid #00F0FF40' }}
        >
          {loading ? 'Analyzing…' : hasResult ? 'Re-run Analysis' : 'Run Analysis'}
        </button>

        <button
          onClick={onCompareBaseline}
          disabled={baselineLoading}
          className="text-xs text-teal-400 hover:text-teal-300 border border-teal-800/40 px-3 py-1.5 rounded-md disabled:opacity-40"
        >
          {baselineLoading ? 'Comparing…' : 'Compare Baseline'}
        </button>

        {/* ── Export ─────────────────────────────────────────────────────── */}
        {hasResult && (
          <div className="border-l border-slate-700 pl-2 ml-1">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="text-xs border px-3 py-1.5 rounded-md text-slate-300 border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 flex items-center gap-1.5"
              title={
                activeCaseId
                  ? 'Export full case forensic report as HTML'
                  : 'Export this analysis as a standalone HTML report'
              }
            >
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              {exporting ? 'Exporting…' : 'Export Report'}
            </button>
            {!activeCaseId && (
              <p className="text-xs text-slate-600 mt-0.5 pl-0.5">Link a case for full forensic report</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

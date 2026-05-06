import { useState, useCallback, useEffect } from 'react'
import { api } from '../api/client'
import type { RCAResult, MLModelStatus, UserAnomalyScore, ThreatIntelStatus, Upload, ForensicEvent, AttackClassification } from '../types'
import MitrePanel from './MitrePanel'
import IOCPanel from './IOCPanel'
import LMDGraphView from './LMDGraphView'

interface Props {
  result: RCAResult | null
  loading: boolean
  onRunAnalysis: (uploadId?: number | null) => void
  onCompareBaseline: () => void
  onQuickScan: (uploadId?: number | null) => void
  baselineLoading: boolean
  quickScanLoading: boolean
  mlStatus: MLModelStatus | null
  isAdmin: boolean
  uploads: Upload[]
  activeCaseId?: string | null
}

const CONFIDENCE_STYLES: Record<string, string> = {
  high:   'bg-green-900/30 text-green-400 border-green-700/40',
  medium: 'bg-amber-900/30 text-amber-400 border-amber-700/40',
  low:    'bg-red-900/30 text-red-400 border-red-700/40',
}

// ── Attack Classification Panel ───────────────────────────────────────────────

const ATK_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  ransomware:           { label: 'Ransomware',           color: '#ef4444', bg: 'bg-red-950/20',     border: 'border-red-800/40' },
  kerberoasting:        { label: 'Kerberoasting',        color: '#a78bfa', bg: 'bg-violet-950/20',  border: 'border-violet-800/40' },
  lateral_movement:     { label: 'Lateral Movement',     color: '#fbbf24', bg: 'bg-amber-950/20',   border: 'border-amber-800/40' },
  credential_theft:     { label: 'Credential Theft',     color: '#fb7185', bg: 'bg-rose-950/20',    border: 'border-rose-800/40' },
  data_exfiltration:    { label: 'Data Exfiltration',    color: '#38bdf8', bg: 'bg-sky-950/20',     border: 'border-sky-800/40' },
  c2_communication:     { label: 'C2 Communication',     color: '#34d399', bg: 'bg-emerald-950/20', border: 'border-emerald-800/40' },
  persistence:          { label: 'Persistence',          color: '#fb923c', bg: 'bg-orange-950/20',  border: 'border-orange-800/40' },
  privilege_escalation: { label: 'Privilege Escalation', color: '#f472b6', bg: 'bg-pink-950/20',    border: 'border-pink-800/40' },
  defense_evasion:      { label: 'Defense Evasion',      color: '#60a5fa', bg: 'bg-blue-950/20',    border: 'border-blue-800/40' },
  reconnaissance:       { label: 'Reconnaissance',       color: '#a3e635', bg: 'bg-lime-950/20',    border: 'border-lime-800/40' },
}

const CONF_BAR: Record<string, string> = {
  high:   'bg-green-500',
  medium: 'bg-amber-400',
  low:    'bg-red-400',
  none:   'bg-slate-600',
}

function AttackClassificationPanel({ clf }: { clf: AttackClassification }) {
  const [expanded, setExpanded] = useState(false)
  const meta = ATK_META[clf.primary_attack] ?? { label: clf.primary_attack, color: '#94a3b8', bg: 'bg-slate-800', border: 'border-slate-700' }
  const pct  = Math.round(clf.confidence * 100)

  const secondary = Object.entries(clf.all_scores)
    .filter(([k]) => k !== clf.primary_attack)
    .slice(0, 5)

  return (
    <div className={`rounded-lg border ${meta.border} ${meta.bg} p-4`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Attack Classification</h3>
            <span
              className="text-xs px-1.5 py-0.5 rounded font-medium border"
              style={{ color: meta.color, borderColor: meta.color + '44', background: meta.color + '11' }}
            >
              {clf.confidence_label.toUpperCase()}
            </span>
          </div>
          <p className="text-lg font-bold" style={{ color: meta.color }}>{meta.label}</p>

          <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 bg-slate-700 rounded-full h-2 overflow-hidden">
              <div
                className={`h-2 rounded-full ${CONF_BAR[clf.confidence_label]}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="text-xs font-mono text-slate-500 w-8 text-right">{pct}%</span>
          </div>

          {clf.mitre_techniques.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {clf.mitre_techniques.map(id => (
                <span key={id} className="text-xs px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 font-mono">
                  {id}
                </span>
              ))}
            </div>
          )}

          {clf.top_evidence.length > 0 && (
            <div className="mt-2">
              <p className="text-xs text-slate-500 mb-1">Key indicators detected:</p>
              <div className="flex flex-wrap gap-1">
                {clf.top_evidence.map((kw, i) => (
                  <span key={i} className="text-xs px-1.5 py-0.5 rounded bg-slate-900 border font-mono" style={{ borderColor: meta.color + '55', color: meta.color }}>
                    {kw}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <button
          onClick={() => setExpanded(e => !e)}
          className="text-xs text-slate-500 hover:text-slate-300 flex-shrink-0 mt-1"
          title="Show all category scores"
        >
          {expanded ? '▲ less' : '▼ all scores'}
        </button>
      </div>

      {expanded && secondary.length > 0 && (
        <div className="mt-3 pt-3 border-t border-slate-700 space-y-1.5">
          <p className="text-xs font-medium text-slate-500 mb-2">All category scores</p>
          {Object.entries(clf.all_scores).map(([cat, score]) => {
            const m = ATK_META[cat] ?? { label: cat, color: '#94a3b8' }
            const w = Math.round(score * 100)
            return (
              <div key={cat} className="flex items-center gap-2">
                <span className="text-xs w-40 truncate" style={{ color: m.color }}>{m.label}</span>
                <div className="flex-1 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-1.5 rounded-full opacity-70"
                    style={{ width: `${w}%`, background: m.color }}
                  />
                </div>
                <span className="text-xs font-mono text-slate-500 w-8 text-right">{w}%</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

const SEVERITY_BAR: Record<string, { bar: string; label: string; text: string }> = {
  CRITICAL: { bar: 'bg-red-600',    label: 'CRITICAL', text: 'text-red-400' },
  HIGH:     { bar: 'bg-orange-500', label: 'HIGH',     text: 'text-orange-400' },
  MEDIUM:   { bar: 'bg-amber-400',  label: 'MEDIUM',   text: 'text-amber-400' },
  LOW:      { bar: 'bg-green-400',  label: 'LOW',      text: 'text-green-400' },
}

function severityLabel(score: number): string {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 35) return 'MEDIUM'
  return 'LOW'
}

export default function NarrativePanel({
  result, loading, onRunAnalysis, onCompareBaseline, onQuickScan,
  baselineLoading, quickScanLoading, mlStatus,
  isAdmin, uploads, activeCaseId,
}: Props) {
  const [selectedUploadId, setSelectedUploadId] = useState<number | null>(null)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [verifyDone, setVerifyDone] = useState<Record<string, boolean>>({})
  const [tiStatus, setTiStatus] = useState<ThreatIntelStatus | null>(null)
  const [citedEvent, setCitedEvent] = useState<ForensicEvent | null>(null)
  const [citedEventId, setCitedEventId] = useState<number | null>(null)
  const [citedEventLoading, setCitedEventLoading] = useState(false)

  useEffect(() => {
    api.getTiStatus().then(setTiStatus).catch(() => {})
  }, [])

  const handleVerify = useCallback(async (user: string, isPositive: boolean) => {
    setVerifying(user)
    try {
      await api.verifyMlPrediction(user, isPositive)
      setVerifyDone(prev => ({ ...prev, [user]: true }))
    } catch { /* silent */ } finally {
      setVerifying(null)
    }
  }, [])

  const handleCitationClick = useCallback(async (eventId: number) => {
    if (citedEventId === eventId) {
      setCitedEvent(null)
      setCitedEventId(null)
      return
    }
    setCitedEventId(eventId)
    setCitedEvent(null)
    setCitedEventLoading(true)
    try {
      const ev = await api.getEventById(eventId)
      setCitedEvent(ev)
    } catch {
      setCitedEvent(null)
    } finally {
      setCitedEventLoading(false)
    }
  }, [citedEventId])

  if (loading) {
    return (
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-16 flex flex-col items-center gap-4 text-slate-500">
        <svg className="animate-spin h-10 w-10" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
        </svg>
        <p className="text-sm">Running AI analysis… may take 1–5 minutes with a local Ollama model</p>
      </div>
    )
  }

  const effectiveUploadId = uploads.length > 1 ? selectedUploadId : null

  if (!result) {
    return (
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-10 flex flex-col items-center gap-6">
        <div className="text-center">
          <svg className="mx-auto h-12 w-12 text-slate-700 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <p className="text-slate-400 text-sm mb-1">No analysis has been run yet.</p>
          <p className="text-slate-500 text-xs">Upload evidence and choose a source below to start analysis.</p>
        </div>

        {/* Per-upload source picker */}
        {uploads.length > 1 && (
          <div className="w-full max-w-lg bg-slate-800 border border-slate-700 rounded-lg px-4 py-3">
            <p className="text-xs font-medium text-slate-500 mb-2">Analyse which source?</p>
            <div className="flex flex-wrap gap-2">
              {uploads.map(u => (
                <button
                  key={u.id}
                  onClick={() => setSelectedUploadId(u.id)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors max-w-[220px] truncate ${
                    selectedUploadId === u.id
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 border border-slate-700 text-slate-400 hover:border-cyan-500/40 hover:text-cyan-400'
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
                      : 'bg-slate-900 border-amber-700/40 text-amber-400 hover:bg-amber-950/20'
                  }`}
                  title="Analyse all uploads merged together (admin only)"
                >
                  All merged
                </button>
              )}
            </div>
            {selectedUploadId === null && isAdmin && uploads.length > 1 && (
              <p className="text-xs text-amber-400 mt-1.5">Analysing all {uploads.length} sources merged — may increase false positives across unrelated incidents.</p>
            )}
          </div>
        )}

        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={() => onQuickScan(effectiveUploadId)}
            disabled={quickScanLoading}
            className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-medium text-sm px-6 py-3 rounded-lg transition-colors"
            title="Instant scan — MITRE, IOCs, ML scores. No LLM wait."
          >
            {quickScanLoading ? 'Scanning…' : 'Quick Scan'}
          </button>
          <button
            onClick={() => onRunAnalysis(effectiveUploadId)}
            className="bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm px-6 py-3 rounded-lg transition-colors"
          >
            Run AI Analysis
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          Quick Scan is instant (no LLM). AI Analysis uses the provider in <code className="bg-slate-800 px-1 rounded">.env</code>.
          ML model training is available in <span className="text-slate-300">Model Settings</span>.
        </p>
      </div>
    )
  }

  const confidenceStyle = CONFIDENCE_STYLES[result.confidence] ?? CONFIDENCE_STYLES.low
  const sLabel = severityLabel(result.severity_score)
  const sStyle = SEVERITY_BAR[sLabel]

  const isQuickScan = result.windows_analyzed === 0

  return (
    <div className="space-y-5">
      {/* Quick-scan banner */}
      {isQuickScan && (
        <div className="rounded-lg border border-emerald-800/40 bg-emerald-950/20 px-4 py-3 flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-emerald-300">Quick scan complete</p>
            <p className="text-xs text-emerald-500 mt-0.5">
              Deterministic analysis only — MITRE, IOCs, severity, and ML scores are ready instantly.
              Run AI Analysis to generate the investigation narrative.
            </p>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <button
              onClick={() => onRunAnalysis(effectiveUploadId)}
              className="text-xs font-medium text-blue-400 border border-blue-700/40 px-3 py-1.5 rounded-md hover:bg-blue-950/20 whitespace-nowrap"
            >
              AI Analysis
            </button>
          </div>
        </div>
      )}

      {/* Header row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          {!isQuickScan && (
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${confidenceStyle}`}>
              {result.confidence.toUpperCase()} CONFIDENCE
            </span>
          )}
          <span className="text-xs text-slate-500">
            {result.analyzed_event_count} events
            {!isQuickScan && ` · ${result.windows_analyzed} window${result.windows_analyzed !== 1 ? 's' : ''}`}
          </span>
        </div>

        {/* Analysis controls */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onQuickScan(effectiveUploadId)}
            disabled={quickScanLoading}
            className="text-xs text-emerald-400 hover:text-emerald-300 border border-emerald-800/40 px-3 py-1.5 rounded-md disabled:opacity-40"
          >
            {quickScanLoading ? 'Scanning…' : 'Quick Scan'}
          </button>
          {!isQuickScan && (
            <button
              onClick={() => onRunAnalysis(effectiveUploadId)}
              className="text-xs text-blue-400 hover:text-blue-300 border border-blue-700/40 px-3 py-1.5 rounded-md"
            >
              Re-run
            </button>
          )}
          <button
            onClick={onCompareBaseline}
            disabled={baselineLoading}
            className="text-xs text-teal-400 hover:text-teal-300 border border-teal-800/40 px-3 py-1.5 rounded-md disabled:opacity-40"
          >
            {baselineLoading ? 'Comparing…' : 'Compare Baseline'}
          </button>

          {/* Export group — 2 options */}
          <div className="flex flex-wrap gap-2 border-l border-slate-700 pl-2 ml-1">
            <button
              onClick={() => api.downloadReport(isQuickScan ? 'quick' : 'deep')}
              className="text-xs border px-3 py-1.5 rounded-md text-slate-400 hover:text-slate-300 border-slate-700 hover:bg-slate-800"
              title="Export this analysis as a self-contained HTML report"
            >
              Analysis Report
            </button>
            <button
              onClick={() => activeCaseId && api.downloadCaseReport(activeCaseId)}
              disabled={!activeCaseId}
              className="text-xs border px-3 py-1.5 rounded-md border-slate-700 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-slate-400 hover:text-slate-300"
              title={activeCaseId ? 'Export comprehensive case report as HTML' : 'Select a case to export its full report'}
            >
              Case Report
            </button>
          </div>
        </div>
      </div>

      {/* Severity bar */}
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Severity Score</h3>
          <span className={`text-sm font-bold ${sStyle.text}`}>{sLabel} — {result.severity_score}/100</span>
        </div>
        <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
          <div
            className={`h-3 rounded-full transition-all ${sStyle.bar}`}
            style={{ width: `${result.severity_score}%` }}
          />
        </div>
      </div>

      {/* Attack Classification */}
      {result.attack_classification && (
        <AttackClassificationPanel clf={result.attack_classification} />
      )}

      {/* Narrative */}
      {!isQuickScan && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Analyst Narrative</h3>
            {result.narrative_citations && result.narrative_citations.length > 0 && (
              <span className="text-xs text-blue-400 font-medium">
                {result.narrative_citations.length} cited sentences · click [id] to reveal evidence
              </span>
            )}
          </div>

          {result.narrative_citations && result.narrative_citations.length > 0 ? (
            <div className="space-y-2">
              {result.narrative_citations.map((citation, i) => (
                <p key={i} className="text-sm text-slate-200 leading-relaxed">
                  <span className="italic">{citation.sentence}</span>
                  {citation.event_ids.map(id => (
                    <button
                      key={id}
                      onClick={() => handleCitationClick(id)}
                      className={`ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono border transition-colors ${
                        citedEventId === id
                          ? 'bg-blue-600 text-white border-blue-600'
                          : 'bg-blue-900/30 text-blue-400 border-blue-700/40 hover:bg-blue-900/50'
                      }`}
                      title={`Show raw log for event #${id}`}
                    >
                      [{id}]
                    </button>
                  ))}
                </p>
              ))}

              {/* Inline evidence callout */}
              {(citedEventLoading || citedEvent) && (
                <div className="mt-3 bg-slate-800 border border-blue-700/40 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-blue-400">
                      Cited Evidence — Event #{citedEventId}
                    </span>
                    <button
                      onClick={() => { setCitedEvent(null); setCitedEventId(null) }}
                      className="text-xs text-slate-500 hover:text-slate-300"
                    >
                      ✕
                    </button>
                  </div>
                  {citedEventLoading ? (
                    <p className="text-xs text-blue-400">Loading raw log…</p>
                  ) : citedEvent && (
                    <div className="space-y-1 text-xs font-mono text-slate-300">
                      <div><span className="text-slate-500">time:</span> {new Date(citedEvent.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</div>
                      <div><span className="text-slate-500">host:</span> {citedEvent.source_host}</div>
                      {citedEvent.user && <div><span className="text-slate-500">user:</span> {citedEvent.user}</div>}
                      {citedEvent.event_id && <div><span className="text-slate-500">EventID:</span> {citedEvent.event_id}</div>}
                      <div><span className="text-slate-500">type:</span> {citedEvent.event_type}</div>
                      <div className="mt-1.5 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300 break-all whitespace-pre-wrap leading-relaxed">
                        {citedEvent.description}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <blockquote className="text-sm text-slate-200 leading-relaxed border-l-4 border-blue-500 pl-4 italic">
              {result.narrative}
            </blockquote>
          )}
        </div>
      )}

      {/* Patient zero + initial access */}
      {!isQuickScan && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Patient Zero Candidate</h3>
            <p className="text-sm text-slate-200">
              {result.patient_zero_candidate || <span className="text-slate-600 italic">No candidate identified</span>}
            </p>
          </div>
          <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Initial Access Vector</h3>
            <p className="text-sm text-slate-200">
              {result.initial_access_vector || <span className="text-slate-600 italic">Unknown</span>}
            </p>
          </div>
        </div>
      )}

      {/* Pivot chain */}
      {result.pivot_chain.length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Pivot Chain (Lateral Movement)</h3>
          <ol className="space-y-2">
            {result.pivot_chain.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-blue-400 font-bold flex-shrink-0">{i + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Anomalous events */}
      {result.anomalous_events.length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Anomalous Events Detected</h3>
          <ul className="space-y-1.5">
            {result.anomalous_events.map((ev, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-amber-400 flex-shrink-0">⚠</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.lmd_graph?.nodes?.length ? (
        <LMDGraphView graphData={result.lmd_graph} />
      ) : null}

      {/* MITRE ATT&CK */}
      {result.mitre_techniques?.length > 0 && (
        <MitrePanel techniques={result.mitre_techniques} />
      )}

      {/* IOCs */}
      {result.iocs?.length > 0 && (
        <IOCPanel iocs={result.iocs} isQuickScan={isQuickScan} tiStatus={tiStatus} />
      )}

      {/* ML Behavioral Anomaly Scores */}
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
            ML Behavioral Anomaly Scores
          </h3>
          {mlStatus?.trained && (
            <span className="text-xs text-slate-500">
              trained on {mlStatus.trained_on_users} users
              {mlStatus.synthetic_baseline_events > 0 &&
                ` · ${mlStatus.synthetic_baseline_events} synthetic events in baseline`}
            </span>
          )}
        </div>

        {!mlStatus?.trained ? (
          <p className="text-xs text-slate-500 italic">
            No model trained yet. Go to <span className="text-slate-300">Model Settings</span> to train the anomaly detector.
          </p>
        ) : result.ml_anomaly_scores && result.ml_anomaly_scores.length > 0 ? (
          <div className="space-y-3">
            {result.ml_anomaly_scores.map((s: UserAnomalyScore) => (
              <div key={s.user}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-sm font-mono text-slate-300 truncate">{s.user}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold flex-shrink-0 ${
                      s.risk_level === 'high_risk'  ? 'bg-red-900/30 text-red-400' :
                      s.risk_level === 'suspicious' ? 'bg-amber-900/30 text-amber-400' :
                                                      'bg-green-900/30 text-green-400'
                    }`}>
                      {s.risk_level === 'high_risk' ? 'HIGH RISK' :
                       s.risk_level === 'suspicious' ? 'SUSPICIOUS' : 'NORMAL'}
                    </span>
                    {s.confidence === 'insufficient_data' && (
                      <span className="text-xs text-slate-500 flex-shrink-0">insufficient data</span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
                    <span className="text-xs text-slate-500">
                      {Math.round(s.anomaly_score * 100)}% · {s.session_event_count} events
                    </span>
                    {isAdmin && !verifyDone[s.user] && (
                      <>
                        <button
                          onClick={() => handleVerify(s.user, true)}
                          disabled={verifying === s.user}
                          className="text-xs px-2 py-0.5 rounded border border-green-800/40 text-green-400 hover:bg-green-950/20 disabled:opacity-40"
                          title="Confirm this is a real threat (True Positive)"
                        >
                          TP
                        </button>
                        <button
                          onClick={() => handleVerify(s.user, false)}
                          disabled={verifying === s.user}
                          className="text-xs px-2 py-0.5 rounded border border-slate-700 text-slate-400 hover:bg-slate-800 disabled:opacity-40"
                          title="Mark as false alarm (True Negative / False Positive)"
                        >
                          FP
                        </button>
                      </>
                    )}
                    {verifyDone[s.user] && (
                      <span className="text-xs text-green-400">✓ verified</span>
                    )}
                  </div>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-1.5 mb-1">
                  <div
                    className={`h-1.5 rounded-full transition-all ${
                      s.risk_level === 'high_risk'  ? 'bg-red-500' :
                      s.risk_level === 'suspicious' ? 'bg-amber-400' :
                                                      'bg-green-400'
                    }`}
                    style={{ width: `${s.anomaly_score * 100}%` }}
                  />
                </div>
                {s.contributing_factors.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {s.contributing_factors.map((f) => (
                      <span key={f} className="text-xs text-slate-500 bg-slate-800 rounded px-1.5 py-0.5">{f}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500 italic">
            No users with sufficient event history to score in this dataset.
          </p>
        )}
      </div>
    </div>
  )
}

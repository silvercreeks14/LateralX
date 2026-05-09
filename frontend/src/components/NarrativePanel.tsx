import { useState, useCallback, useEffect, useRef } from 'react'
import { api } from '../api/client'
import type { RCAResult, MLModelStatus, ThreatIntelStatus, Upload, AttackClassification } from '../types'
import MitrePanel from './MitrePanel'
import IOCPanel from './IOCPanel'
import InvestigationNarrative from './InvestigationNarrative'
import MLEntityBehavior from './MLEntityBehavior'
import AnalysisControls from './AnalysisControls'

interface Props {
  result:            RCAResult | null
  loading:           boolean
  baselineLoading:   boolean
  mlStatus:          MLModelStatus | null
  isAdmin:           boolean
  uploads:           Upload[]
  activeCaseId?:     string | null
  onRunAnalysis:     (uploadId?: number | null) => void
  onCompareBaseline: () => void
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, { bar: string; text: string; ring: string; bg: string }> = {
  CRITICAL: { bar: 'bg-red-600',    text: 'text-red-400',    ring: 'border-red-700/60',    bg: 'bg-red-950/20'    },
  HIGH:     { bar: 'bg-orange-500', text: 'text-orange-400', ring: 'border-orange-700/60', bg: 'bg-orange-950/20' },
  MEDIUM:   { bar: 'bg-amber-400',  text: 'text-amber-400',  ring: 'border-amber-700/60',  bg: 'bg-amber-950/20'  },
  LOW:      { bar: 'bg-green-400',  text: 'text-green-400',  ring: 'border-green-700/60',  bg: 'bg-green-950/20'  },
}

const CONFIDENCE_STYLES: Record<string, string> = {
  high:   'bg-green-900/30 text-green-400 border-green-700/40',
  medium: 'bg-amber-900/30 text-amber-400 border-amber-700/40',
  low:    'bg-red-900/30 text-red-400 border-red-700/40',
}

function severityLabel(score: number): string {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 35) return 'MEDIUM'
  return 'LOW'
}

function fmtElapsed(sec: number): string {
  if (sec < 60) return `${sec}s`
  return `${Math.floor(sec / 60)}m ${sec % 60}s`
}

// ── Loading screen with elapsed timer ────────────────────────────────────────

function LoadingScreen() {
  const [elapsed, setElapsed] = useState(0)
  const ref = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    ref.current = setInterval(() => setElapsed(s => s + 1), 1000)
    return () => { if (ref.current) clearInterval(ref.current) }
  }, [])

  const phase =
    elapsed < 15  ? 'Sampling events and preparing analysis windows…' :
    elapsed < 60  ? 'Running window analysis with Ollama — window 1 of 2…' :
    elapsed < 120 ? 'Running window analysis with Ollama — window 2 of 2…' :
    elapsed < 180 ? 'Synthesising results across windows…' :
                    'Still working — large dataset or slow hardware detected…'

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-14 flex flex-col items-center gap-5 text-center">
      <div className="relative">
        <svg className="animate-spin h-12 w-12" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
          <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
          <path className="opacity-80" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
        </svg>
        <div
          className="absolute inset-0 flex items-center justify-center text-xs font-mono font-bold"
          style={{ color: '#00F0FF' }}
        >
          {fmtElapsed(elapsed)}
        </div>
      </div>

      <div className="space-y-1.5">
        <p className="text-sm font-semibold text-slate-200">AI Analysis running</p>
        <p className="text-xs text-slate-400 max-w-xs">{phase}</p>
      </div>

      <div className="w-full max-w-xs bg-slate-800 rounded-full h-1 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-1000"
          style={{
            width: `${Math.min(95, (elapsed / 240) * 100)}%`,
            background: 'linear-gradient(90deg, #00F0FF, #3b82f6)',
          }}
        />
      </div>

      <p className="text-xs text-slate-600 max-w-xs">
        You can navigate to other sections — analysis continues in the background
        and results will appear here when complete.
      </p>

      {elapsed > 30 && (
        <div className="text-xs text-slate-500 bg-slate-800 rounded-lg px-3 py-2 max-w-xs">
          Tip: <span className="text-slate-300">Quick Scan</span> takes &lt;5 seconds and
          provides MITRE, IOCs, and ML scores without waiting for Ollama.
        </div>
      )}
    </div>
  )
}

// ── Attack Classification ─────────────────────────────────────────────────────

const ATK_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  ransomware:           { label: 'Ransomware',           color: '#ef4444', bg: 'bg-red-950/20',     border: 'border-red-800/40'     },
  kerberoasting:        { label: 'Kerberoasting',        color: '#a78bfa', bg: 'bg-violet-950/20',  border: 'border-violet-800/40'  },
  lateral_movement:     { label: 'Lateral Movement',     color: '#fbbf24', bg: 'bg-amber-950/20',   border: 'border-amber-800/40'   },
  credential_theft:     { label: 'Credential Theft',     color: '#fb7185', bg: 'bg-rose-950/20',    border: 'border-rose-800/40'    },
  data_exfiltration:    { label: 'Data Exfiltration',    color: '#38bdf8', bg: 'bg-sky-950/20',     border: 'border-sky-800/40'     },
  c2_communication:     { label: 'C2 Communication',     color: '#34d399', bg: 'bg-emerald-950/20', border: 'border-emerald-800/40' },
  persistence:          { label: 'Persistence',          color: '#fb923c', bg: 'bg-orange-950/20',  border: 'border-orange-800/40'  },
  privilege_escalation: { label: 'Privilege Escalation', color: '#f472b6', bg: 'bg-pink-950/20',    border: 'border-pink-800/40'    },
  defense_evasion:      { label: 'Defense Evasion',      color: '#60a5fa', bg: 'bg-blue-950/20',    border: 'border-blue-800/40'    },
  reconnaissance:       { label: 'Reconnaissance',       color: '#a3e635', bg: 'bg-lime-950/20',    border: 'border-lime-800/40'    },
}

const CONF_BAR: Record<string, string> = {
  high: 'bg-green-500', medium: 'bg-amber-400', low: 'bg-red-400', none: 'bg-slate-600',
}

function AttackClassificationPanel({ clf }: { clf: AttackClassification }) {
  const [expanded, setExpanded] = useState(false)
  const meta = ATK_META[clf.primary_attack] ?? { label: clf.primary_attack, color: '#94a3b8', bg: 'bg-slate-800', border: 'border-slate-700' }
  const pct  = Math.round(clf.confidence * 100)

  return (
    <div className={`rounded-lg border ${meta.border} ${meta.bg} p-4`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-widest">Attack Classification</span>
            <span className="text-xs px-1.5 py-0.5 rounded font-medium border"
              style={{ color: meta.color, borderColor: meta.color + '44', background: meta.color + '11' }}>
              {clf.confidence_label.toUpperCase()}
            </span>
          </div>
          <p className="text-lg font-bold" style={{ color: meta.color }}>{meta.label}</p>
          <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 bg-slate-700 rounded-full h-2 overflow-hidden">
              <div className={`h-2 rounded-full ${CONF_BAR[clf.confidence_label]}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-xs font-mono text-slate-500 w-8 text-right">{pct}%</span>
          </div>
          {clf.mitre_techniques.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {clf.mitre_techniques.map(id => (
                <span key={id} className="text-xs px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 font-mono">{id}</span>
              ))}
            </div>
          )}
          {clf.top_evidence.length > 0 && (
            <div className="mt-2">
              <p className="text-xs text-slate-500 mb-1">Key indicators:</p>
              <div className="flex flex-wrap gap-1">
                {clf.top_evidence.map((kw, i) => (
                  <span key={i} className="text-xs px-1.5 py-0.5 rounded bg-slate-900 border font-mono"
                    style={{ borderColor: meta.color + '55', color: meta.color }}>{kw}</span>
                ))}
              </div>
            </div>
          )}
        </div>
        <button onClick={() => setExpanded(e => !e)} className="text-xs text-slate-500 hover:text-slate-300 flex-shrink-0 mt-1">
          {expanded ? '▲ less' : '▼ all'}
        </button>
      </div>
      {expanded && (
        <div className="mt-3 pt-3 border-t border-slate-700 space-y-1.5">
          <p className="text-xs font-medium text-slate-500 mb-2">All scores</p>
          {Object.entries(clf.all_scores).map(([cat, score]) => {
            const m = ATK_META[cat] ?? { label: cat, color: '#94a3b8' }
            const w = Math.round(score * 100)
            return (
              <div key={cat} className="flex items-center gap-2">
                <span className="text-xs w-40 truncate" style={{ color: m.color }}>{m.label}</span>
                <div className="flex-1 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                  <div className="h-1.5 rounded-full opacity-70" style={{ width: `${w}%`, background: m.color }} />
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

// ── Tab bar ───────────────────────────────────────────────────────────────────

type TabId = 'overview' | 'investigation' | 'intel' | 'behavioral'

interface TabDef {
  id:      TabId
  label:   string
  accent:  string
  badge?:  React.ReactNode
}

function TabBar({
  tabs, active, onChange,
}: {
  tabs:     TabDef[]
  active:   TabId
  onChange: (id: TabId) => void
}) {
  return (
    <div className="flex border-b border-slate-800 bg-slate-900 rounded-t-xl overflow-hidden">
      {tabs.map(t => {
        const isActive = t.id === active
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className="relative flex items-center gap-2 px-4 py-3 text-xs font-semibold transition-colors flex-1 justify-center"
            style={isActive
              ? { color: t.accent, borderBottom: `2px solid ${t.accent}`, marginBottom: '-1px' }
              : { color: '#64748b', borderBottom: '2px solid transparent', marginBottom: '-1px' }
            }
            onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = '#94a3b8' }}
            onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = '#64748b' }}
          >
            <span className="uppercase tracking-wide">{t.label}</span>
            {t.badge}
          </button>
        )
      })}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function NarrativePanel({
  result, loading, baselineLoading,
  mlStatus, isAdmin, uploads, activeCaseId,
  onRunAnalysis, onCompareBaseline,
}: Props) {
  const [activeTab,  setActiveTab]  = useState<TabId>('overview')
  const [tiStatus,   setTiStatus]   = useState<ThreatIntelStatus | null>(null)
  const [verifying,  setVerifying]  = useState<string | null>(null)
  const [verifyDone, setVerifyDone] = useState<Record<string, boolean>>({})

  useEffect(() => {
    let live = true
    api.getTiStatus().then(s => { if (live) setTiStatus(s) }).catch(() => {})
    return () => { live = false }
  }, [])

  const handleVerify = useCallback(async (entity: string, isPositive: boolean) => {
    setVerifying(entity)
    try {
      await api.verifyMlPrediction(entity, isPositive)
      setVerifyDone(prev => ({ ...prev, [entity]: true }))
    } catch { /* silent */ } finally { setVerifying(null) }
  }, [])

  // Jump to investigation tab automatically when results arrive
  useEffect(() => {
    if (result) setActiveTab('investigation')
  }, [result])

  // ── Loading ─────────────────────────────────────────────────────────────────
  if (loading) return <LoadingScreen />

  // ── Empty state ─────────────────────────────────────────────────────────────
  if (!result) {
    return (
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-10 flex flex-col items-center gap-6">
        <div className="text-center">
          <svg className="mx-auto h-12 w-12 text-slate-700 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <p className="text-slate-400 text-sm mb-1">No analysis run yet.</p>
          <p className="text-slate-500 text-xs">Upload evidence then click Run Analysis to start.</p>
        </div>
        <AnalysisControls
          loading={loading} baselineLoading={baselineLoading}
          uploads={uploads} isAdmin={isAdmin} hasResult={false}
          activeCaseId={activeCaseId} onRunAnalysis={onRunAnalysis}
          onCompareBaseline={onCompareBaseline}
        />
        <p className="text-xs text-slate-500">
          Analysis runs all detections — MITRE, IOCs, ML, correlation — and
          adds an AI narrative if Ollama is configured in{' '}
          <code className="bg-slate-800 px-1 rounded">.env</code>.
          ML training is in <span className="text-slate-300">Model Settings</span>.
        </p>
      </div>
    )
  }

  // ── Result helpers ──────────────────────────────────────────────────────────
  const withLLM       = result.windows_analyzed > 0
  const sLabel        = severityLabel(result.severity_score)
  const sStyle        = SEVERITY_STYLES[sLabel]
  const confidenceCls = CONFIDENCE_STYLES[result.confidence] ?? CONFIDENCE_STYLES.low
  const mitreCount    = result.mitre_techniques?.length ?? 0
  const iocCount      = result.iocs?.length ?? 0
  const { highRiskCount, suspCount } = (result.ml_anomaly_scores ?? []).reduce(
    (acc, s) => {
      if (s.risk_level === 'high_risk') acc.highRiskCount++
      else if (s.risk_level === 'suspicious') acc.suspCount++
      return acc
    },
    { highRiskCount: 0, suspCount: 0 },
  )

  const tabs: TabDef[] = [
    {
      id: 'overview',
      label: 'Overview',
      accent: '#ef4444',
      badge: (
        <span className={`text-xs px-1.5 py-0.5 rounded font-bold border ${sStyle.ring} ${sStyle.text} ${sStyle.bg}`}>
          {sLabel}
        </span>
      ),
    },
    {
      id: 'investigation',
      label: 'Investigation',
      accent: '#3b82f6',
      badge: withLLM
        ? <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 border border-blue-700/30">+AI</span>
        : undefined,
    },
    {
      id: 'intel',
      label: 'Threat Intel',
      accent: '#8b5cf6',
      badge: (mitreCount + iocCount) > 0
        ? <span className="text-xs text-slate-500">{mitreCount}T · {iocCount}I</span>
        : undefined,
    },
    {
      id: 'behavioral',
      label: 'Behavioral',
      accent: '#00F0FF',
      badge: (highRiskCount + suspCount) > 0
        ? <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/30 text-red-400 border border-red-700/30 font-bold">
            {highRiskCount + suspCount} flagged
          </span>
        : undefined,
    },
  ]

  return (
    <div className="space-y-3">

      {/* ── Controls card (always visible above tabs) ────────────────────── */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 px-4 py-3 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border ${confidenceCls}`}>
            {result.confidence.toUpperCase()} CONFIDENCE
          </span>
          <span className="text-xs text-slate-500">
            {result.analyzed_event_count.toLocaleString()} events
            {withLLM && ` · ${result.windows_analyzed} AI window${result.windows_analyzed !== 1 ? 's' : ''}`}
            {result.consensus_agreement != null && ` · ${Math.round(result.consensus_agreement * 100)}% consensus`}
          </span>
        </div>
        <AnalysisControls
          loading={loading} baselineLoading={baselineLoading}
          uploads={uploads} isAdmin={isAdmin} hasResult={true}
          activeCaseId={activeCaseId} onRunAnalysis={onRunAnalysis}
          onCompareBaseline={onCompareBaseline}
        />
      </div>

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      <div className="rounded-xl border border-slate-800 overflow-hidden">
        <TabBar tabs={tabs} active={activeTab} onChange={setActiveTab} />

        <div className="p-4 space-y-4 min-h-[200px]">

          {/* Overview tab ─────────────────────────────────────────────────── */}
          {activeTab === 'overview' && (
            <>
              {/* Severity */}
              <div className="bg-slate-900 rounded-lg border border-slate-800 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-500 uppercase tracking-widest">Severity Score</span>
                  <span className={`text-sm font-bold ${sStyle.text}`}>{sLabel} — {result.severity_score}/100</span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2.5 overflow-hidden">
                  <div className={`h-2.5 rounded-full transition-all ${sStyle.bar}`} style={{ width: `${result.severity_score}%` }} />
                </div>
                <div className="flex justify-between mt-1.5 text-xs text-slate-700 font-mono select-none">
                  <span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
                </div>
              </div>

              {/* Attack classification */}
              {result.attack_classification && <AttackClassificationPanel clf={result.attack_classification} />}
            </>
          )}

          {/* Investigation tab ─────────────────────────────────────────────── */}
          {activeTab === 'investigation' && (
            <InvestigationNarrative result={result} />
          )}

          {/* Threat Intel tab ──────────────────────────────────────────────── */}
          {activeTab === 'intel' && (
            <>
              {mitreCount === 0 && iocCount === 0 ? (
                <div className="py-12 text-center">
                  <p className="text-slate-600 text-sm">No threat intelligence data available for this result.</p>
                </div>
              ) : (
                <>
                  {mitreCount > 0 && <MitrePanel techniques={result.mitre_techniques} />}
                  {iocCount > 0 && <IOCPanel iocs={result.iocs} tiStatus={tiStatus} />}
                </>
              )}
            </>
          )}

          {/* Behavioral tab ────────────────────────────────────────────────── */}
          {activeTab === 'behavioral' && (
            <MLEntityBehavior
              mlScores={result.ml_anomaly_scores ?? []}
              mlStatus={mlStatus}
              isAdmin={isAdmin}
              activeCaseId={activeCaseId}
              uploadId={uploads.length > 1 ? (uploads[0]?.id ?? null) : null}
              verifyDone={verifyDone}
              verifying={verifying}
              onVerify={handleVerify}
            />
          )}

        </div>
      </div>
    </div>
  )
}

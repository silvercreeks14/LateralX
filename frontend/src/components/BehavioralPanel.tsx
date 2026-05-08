import { useState } from 'react'
import { api } from '../api/client'
import type { BehavioralReport, BehavioralAnomaly } from '../types'

interface Props {
  activeCaseId: string | null
  selectedUploadId: number | null
}

const ANOMALY_LABELS: Record<string, string> = {
  hourly_spike: 'Z-Score Spike',
  lateral_velocity: 'Lateral Velocity',
  auth_failure_burst: 'Auth Burst',
  off_hours_privilege: 'Off-Hours Privilege',
}

const SEVERITY_BORDER: Record<string, string> = {
  critical: '#FF6B00',
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#475569',
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  high: 'bg-red-500/15 text-red-400 border border-red-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  low: 'bg-slate-700/50 text-slate-400 border border-slate-600/30',
}

function AnomalyCard({ a }: { a: BehavioralAnomaly }) {
  const sev = a.severity.toLowerCase()
  const borderColor = SEVERITY_BORDER[sev] ?? SEVERITY_BORDER.low
  const badgeClass = SEVERITY_BADGE[sev] ?? SEVERITY_BADGE.low

  return (
    <div
      className="bg-slate-800/60 rounded-xl p-4 border-l-4"
      style={{ borderLeftColor: borderColor }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            {ANOMALY_LABELS[a.anomaly_type] ?? a.anomaly_type}
          </span>
          <span className="text-white text-sm font-mono">{a.user}</span>
        </div>
        <span className={`px-2 py-0.5 rounded-full text-xs font-semibold uppercase flex-shrink-0 ${badgeClass}`}>
          {a.severity}
        </span>
      </div>

      <p className="text-slate-300 text-sm mb-3">{a.description}</p>

      <div className="flex items-center gap-4 text-xs text-slate-500">
        <span>Observed: <span className="text-slate-300 font-mono">{a.observed.toFixed(1)}</span></span>
        <span>Threshold: <span className="text-slate-300 font-mono">{a.threshold.toFixed(1)}</span></span>
        {a.z_score != null && (
          <span>Z-score: <span className="text-slate-300 font-mono">{a.z_score.toFixed(2)}σ</span></span>
        )}
      </div>

      <div className="mt-2.5 h-1 bg-slate-700 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: `${Math.min(100, (a.observed / Math.max(a.threshold * 2, a.observed)) * 100)}%`,
            background: borderColor,
          }}
        />
      </div>
    </div>
  )
}

export default function BehavioralPanel({ activeCaseId, selectedUploadId }: Props) {
  const [report, setReport] = useState<BehavioralReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await api.mlBehavioral(activeCaseId, selectedUploadId)
      setReport(r)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Behavioral analysis failed')
    } finally {
      setLoading(false)
    }
  }

  const sevStatColor: Record<string, string> = {
    critical: '#FF6B00', high: '#ef4444', medium: '#f59e0b', low: '#64748b', none: '#64748b',
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-white font-semibold text-lg">Behavioral Anomaly Detection</h2>
          <p className="text-slate-500 text-sm mt-0.5">
            Z-score spike · lateral velocity · auth burst · off-hours privilege
          </p>
        </div>
        <button
          onClick={run}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all disabled:opacity-50 text-slate-900"
          style={{ background: '#00F0FF' }}
          onMouseEnter={e => { if (!loading) (e.currentTarget as HTMLButtonElement).style.background = '#00D8E8' }}
          onMouseLeave={e => { if (!loading) (e.currentTarget as HTMLButtonElement).style.background = '#00F0FF' }}
        >
          {loading ? (
            <>
              <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
              </svg>
              Analyzing…
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Run Analysis
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="bg-red-950/50 border border-red-800/50 text-red-300 rounded-xl px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {!report && !loading && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <div className="w-14 h-14 rounded-full bg-slate-800 flex items-center justify-center mb-2">
            <svg className="w-7 h-7 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <p className="text-slate-400 text-sm font-medium">No behavioral analysis run yet</p>
          <p className="text-slate-600 text-xs max-w-xs">
            Upload events and click Run Analysis to detect Z-score spikes, lateral
            movement velocity, auth failure bursts, and off-hours privilege escalation.
          </p>
        </div>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Anomalies', value: String(report.anomalies.length), color: report.anomalies.length > 0 ? '#FF6B00' : '#00F0FF' },
              { label: 'Users Profiled', value: String(report.profiled_users), color: '#00F0FF' },
              { label: 'Window', value: `${report.analysis_window_hours.toFixed(1)}h`, color: '#00F0FF' },
              { label: 'Highest Severity', value: report.highest_severity.toUpperCase(), color: sevStatColor[report.highest_severity] ?? '#64748b' },
            ].map(s => (
              <div key={s.label} className="bg-slate-900 rounded-xl p-4 border border-slate-800">
                <p className="text-xs text-slate-500 mb-1 uppercase tracking-wide">{s.label}</p>
                <p className="text-lg font-bold" style={{ color: s.color }}>{s.value}</p>
              </div>
            ))}
          </div>

          {report.anomalies.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 flex flex-col items-center gap-2">
              <div
                className="w-10 h-10 rounded-full flex items-center justify-center mb-1 border"
                style={{ background: '#00F0FF15', borderColor: '#00F0FF30' }}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-slate-300 font-medium text-sm">No anomalies detected</p>
              <p className="text-slate-600 text-xs">
                {report.profiled_users} user(s) profiled — all within normal behavioral bounds
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-slate-500 uppercase tracking-wide font-semibold">
                {report.anomalies.length} anomal{report.anomalies.length === 1 ? 'y' : 'ies'} detected
              </p>
              {report.anomalies.map((a, i) => (
                <AnomalyCard key={i} a={a} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

import { useState, useCallback } from 'react'
import { api } from '../api/client'
import type {
  EntityAnomalyScore, MLModelStatus, BehavioralReport, BehavioralAnomaly,
} from '../types'

// ── Anomaly score helpers ─────────────────────────────────────────────────────

const RISK_BADGE: Record<string, string> = {
  high_risk:  'bg-red-900/30 text-red-400',
  suspicious: 'bg-amber-900/30 text-amber-400',
  normal:     'bg-green-900/30 text-green-400',
}

const RISK_BAR: Record<string, string> = {
  high_risk:  'bg-red-500',
  suspicious: 'bg-amber-400',
  normal:     'bg-green-400',
}

const RISK_LABEL: Record<string, string> = {
  high_risk:  'HIGH RISK',
  suspicious: 'SUSPICIOUS',
  normal:     'NORMAL',
}

// ── Behavioral anomaly helpers ────────────────────────────────────────────────

const BEHAV_TYPE_LABEL: Record<string, string> = {
  hourly_spike:       'Z-Score Spike',
  lateral_velocity:   'Lateral Velocity',
  auth_failure_burst: 'Auth Burst',
  off_hours_privilege:'Off-Hours Privilege',
}

const SEV_BORDER: Record<string, string> = {
  critical: '#FF6B00',
  high:     '#ef4444',
  medium:   '#f59e0b',
  low:      '#475569',
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  high:     'bg-red-500/15 text-red-400 border border-red-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  low:      'bg-slate-700/50 text-slate-400 border border-slate-600/30',
}

function BehavioralAnomalyCard({ a }: { a: BehavioralAnomaly }) {
  const sev        = a.severity.toLowerCase()
  const borderClr  = SEV_BORDER[sev] ?? SEV_BORDER.low
  const badgeCls   = SEV_BADGE[sev]  ?? SEV_BADGE.low

  return (
    <div
      className="bg-slate-800/60 rounded-lg p-3.5 border-l-4"
      style={{ borderLeftColor: borderClr }}
    >
      <div className="flex items-start justify-between gap-3 mb-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 flex-shrink-0">
            {BEHAV_TYPE_LABEL[a.anomaly_type] ?? a.anomaly_type}
          </span>
          <span className="text-white text-xs font-mono truncate">{a.entity}</span>
        </div>
        <span className={`px-2 py-0.5 rounded-full text-xs font-semibold uppercase flex-shrink-0 ${badgeCls}`}>
          {a.severity}
        </span>
      </div>
      <p className="text-slate-300 text-xs mb-2">{a.description}</p>
      <div className="flex items-center gap-4 text-xs text-slate-500">
        <span>Observed: <span className="text-slate-300 font-mono">{a.observed.toFixed(1)}</span></span>
        <span>Threshold: <span className="text-slate-300 font-mono">{a.threshold.toFixed(1)}</span></span>
        {a.z_score != null && (
          <span>Z: <span className="text-slate-300 font-mono">{a.z_score.toFixed(2)}σ</span></span>
        )}
      </div>
      <div className="mt-2 h-1 bg-slate-700 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{
            width: `${Math.min(100, (a.observed / Math.max(a.threshold * 2, a.observed)) * 100)}%`,
            background: borderClr,
          }}
        />
      </div>
    </div>
  )
}

// ── Props ─────────────────────────────────────────────────────────────────────

interface Props {
  mlScores:      EntityAnomalyScore[]
  mlStatus:      MLModelStatus | null
  isAdmin:       boolean
  activeCaseId?: string | null
  uploadId?:     number | null
  verifyDone:    Record<string, boolean>
  verifying:     string | null
  onVerify:      (entity: string, isPositive: boolean) => void
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function MLEntityBehavior({
  mlScores, mlStatus, isAdmin, activeCaseId, uploadId,
  verifyDone, verifying, onVerify,
}: Props) {
  const [behavReport,    setBehavReport]    = useState<BehavioralReport | null>(null)
  const [behavLoading,   setBehavLoading]   = useState(false)
  const [behavError,     setBehavError]     = useState<string | null>(null)

  const runBehavioral = useCallback(async () => {
    setBehavLoading(true)
    setBehavError(null)
    try {
      const r = await api.mlBehavioral(activeCaseId, uploadId)
      setBehavReport(r)
    } catch (e) {
      setBehavError(e instanceof Error ? e.message : 'Behavioral analysis failed')
    } finally {
      setBehavLoading(false)
    }
  }, [activeCaseId, uploadId])

  const sevStatColor: Record<string, string> = {
    critical: '#FF6B00', high: '#ef4444', medium: '#f59e0b', low: '#64748b', none: '#64748b',
  }

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 p-4 space-y-5">

      {/* ── Section header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-0.5">
            ML Entity Behavior Analysis
          </h3>
          {mlStatus?.trained && (
            <p className="text-xs text-slate-600">
              Isolation Forest trained on {mlStatus.trained_on_users} entities
              {mlStatus.synthetic_baseline_events > 0 &&
                ` · ${mlStatus.synthetic_baseline_events} synthetic baseline events`}
            </p>
          )}
        </div>
        <button
          onClick={runBehavioral}
          disabled={behavLoading}
          className="text-xs px-3 py-1.5 rounded border border-cyan-800/40 text-cyan-400 hover:bg-cyan-950/20 disabled:opacity-40 whitespace-nowrap"
          title="Run deterministic behavioral checks: Z-score spikes, lateral velocity, auth bursts, off-hours privilege"
        >
          {behavLoading ? 'Analyzing…' : 'Run Behavioral Checks'}
        </button>
      </div>

      {/* ── ML Isolation Forest scores ────────────────────────────────────── */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
          Isolation Forest — Per-Entity Anomaly Scores
        </p>

        {!mlStatus?.trained ? (
          <p className="text-xs text-slate-500 italic">
            No model trained. Go to <span className="text-slate-300">Model Settings</span> to train the anomaly detector.
          </p>
        ) : mlScores.length > 0 ? (
          <div className="space-y-3">
            {mlScores.map((s: EntityAnomalyScore) => (
              <div key={s.entity}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-sm font-mono text-slate-300 truncate">{s.entity}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold flex-shrink-0 ${RISK_BADGE[s.risk_level] ?? RISK_BADGE.normal}`}>
                      {RISK_LABEL[s.risk_level] ?? s.risk_level.toUpperCase()}
                    </span>
                    {s.confidence === 'insufficient_data' && (
                      <span className="text-xs text-slate-500 flex-shrink-0">heuristic</span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
                    <span className="text-xs text-slate-500">
                      {Math.round(s.anomaly_score * 100)}% · {s.session_event_count} events
                    </span>
                    {isAdmin && !verifyDone[s.entity] && (
                      <>
                        <button
                          onClick={() => onVerify(s.entity, true)}
                          disabled={verifying === s.entity}
                          className="text-xs px-2 py-0.5 rounded border border-green-800/40 text-green-400 hover:bg-green-950/20 disabled:opacity-40"
                          title="Confirm real threat (True Positive)"
                        >
                          TP
                        </button>
                        <button
                          onClick={() => onVerify(s.entity, false)}
                          disabled={verifying === s.entity}
                          className="text-xs px-2 py-0.5 rounded border border-slate-700 text-slate-400 hover:bg-slate-800 disabled:opacity-40"
                          title="Mark as false alarm (False Positive)"
                        >
                          FP
                        </button>
                      </>
                    )}
                    {verifyDone[s.entity] && (
                      <span className="text-xs text-green-400">✓ verified</span>
                    )}
                  </div>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-1.5 mb-1">
                  <div
                    className={`h-1.5 rounded-full transition-all ${RISK_BAR[s.risk_level] ?? RISK_BAR.normal}`}
                    style={{ width: `${s.anomaly_score * 100}%` }}
                  />
                </div>
                {s.contributing_factors.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {s.contributing_factors.map(f => (
                      <span key={f} className="text-xs text-slate-500 bg-slate-800 rounded px-1.5 py-0.5">{f}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500 italic">
            No entities with sufficient event history to score in this dataset.
          </p>
        )}
      </div>

      {/* ── Behavioral anomaly detection results ──────────────────────────── */}
      <div className="border-t border-slate-800 pt-4">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
          Deterministic Behavioral Checks
          <span className="ml-2 font-normal normal-case text-slate-600">
            Z-score spike · lateral velocity · auth burst · off-hours privilege
          </span>
        </p>

        {behavError && (
          <div className="bg-red-950/50 border border-red-800/50 text-red-300 rounded px-3 py-2 text-xs mb-3">
            {behavError}
          </div>
        )}

        {!behavReport && !behavLoading && (
          <p className="text-xs text-slate-600 italic">
            Click "Run Behavioral Checks" above to detect statistical anomalies.
          </p>
        )}

        {behavLoading && (
          <div className="flex items-center gap-2 text-xs text-slate-500 py-2">
            <svg className="animate-spin h-3.5 w-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            Running behavioral analysis…
          </div>
        )}

        {behavReport && (
          <div className="space-y-3">
            {/* Stats row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {[
                { label: 'Anomalies',        value: String(behavReport.anomalies.length),                            color: behavReport.anomalies.length > 0 ? '#FF6B00' : '#00F0FF' },
                { label: 'Entities Profiled', value: String(behavReport.profiled_entities),                          color: '#00F0FF' },
                { label: 'Window',            value: `${behavReport.analysis_window_hours.toFixed(1)}h`,             color: '#00F0FF' },
                { label: 'Highest Severity',  value: behavReport.highest_severity.toUpperCase(),                     color: sevStatColor[behavReport.highest_severity] ?? '#64748b' },
              ].map(s => (
                <div key={s.label} className="bg-slate-800 rounded-lg p-3 border border-slate-700">
                  <p className="text-xs text-slate-500 mb-1 uppercase tracking-wide">{s.label}</p>
                  <p className="text-sm font-bold" style={{ color: s.color }}>{s.value}</p>
                </div>
              ))}
            </div>

            {/* Anomaly cards */}
            {behavReport.anomalies.length === 0 ? (
              <div className="text-center py-6">
                <p className="text-slate-400 text-sm font-medium">No behavioral anomalies detected</p>
                <p className="text-slate-600 text-xs mt-1">
                  {behavReport.profiled_entities} entit{behavReport.profiled_entities === 1 ? 'y' : 'ies'} profiled — all within normal behavioural bounds
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {behavReport.anomalies.map((a, i) => (
                  <BehavioralAnomalyCard key={i} a={a} />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

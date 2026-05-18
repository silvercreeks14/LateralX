import { useState } from 'react'
import { api } from '../api/client'
import type { PrivilegeTimelineResult, PrivilegeEvent, EscalationChain, Upload } from '../types'

const SEV_COLOR: Record<string, string> = {
  critical: 'border-red-400 dark:border-red-600 bg-red-50 dark:bg-red-950/20',
  high:     'border-orange-400 dark:border-orange-600 bg-orange-50 dark:bg-orange-950/20',
  medium:   'border-amber-400 dark:border-amber-600 bg-amber-50 dark:bg-amber-950/20',
  low:      'border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-800/30',
}
const SEV_TEXT: Record<string, string> = {
  critical: 'text-red-700 dark:text-red-400',
  high:     'text-orange-700 dark:text-orange-400',
  medium:   'text-amber-700 dark:text-amber-400',
  low:      'text-slate-600 dark:text-slate-400',
}
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-amber-500',
  low:      'bg-slate-500',
}

function TimelineEvent({ ev }: { ev: PrivilegeEvent }) {
  return (
    <div className="flex gap-3 group">
      {/* Timeline track */}
      <div className="flex flex-col items-center flex-shrink-0">
        <div className={`w-3 h-3 rounded-full mt-1 flex-shrink-0 ${SEV_DOT[ev.severity] ?? 'bg-slate-500'}`} />
        <div className="w-px flex-1 bg-slate-200 dark:bg-slate-800 mt-1" />
      </div>
      {/* Event card */}
      <div className={`flex-1 rounded-lg border px-3 py-2 mb-2 text-xs ${SEV_COLOR[ev.severity] ?? SEV_COLOR.low}`}>
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className={`font-semibold ${SEV_TEXT[ev.severity] ?? 'text-slate-500'}`}>{ev.action}</span>
          <span className="font-mono bg-slate-200 dark:bg-slate-800/60 px-1.5 py-0.5 rounded text-slate-600 dark:text-slate-400">{ev.mitre_id}</span>
          <span className="text-slate-500 ml-auto font-mono">{ev.timestamp.slice(0, 19).replace('T', ' ')}</span>
        </div>
        <div className="flex items-center gap-2 text-slate-500">
          <span>EID <span className="font-mono text-slate-700 dark:text-slate-300">{ev.event_id}</span></span>
          <span className="text-slate-400">·</span>
          <span>actor: <span className="font-mono text-slate-700 dark:text-slate-300">{ev.actor}</span></span>
          {ev.target && (
            <>
              <span className="text-slate-400">→</span>
              <span className="font-mono text-slate-700 dark:text-slate-300">{ev.target}</span>
            </>
          )}
        </div>
        {ev.detail && (
          <p className="text-slate-500 mt-1 leading-relaxed line-clamp-2">{ev.detail}</p>
        )}
      </div>
    </div>
  )
}

function ChainCard({ chain }: { chain: EscalationChain }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={`rounded-xl border-2 ${SEV_COLOR[chain.highest_severity] ?? SEV_COLOR.low}`}>
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className={`font-mono text-xs font-bold ${SEV_TEXT[chain.highest_severity] ?? 'text-slate-500'}`}>
              {chain.chain_id}
            </span>
            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[chain.highest_severity] ?? 'bg-slate-500'}`} />
            <span className="text-slate-900 dark:text-white font-semibold text-sm">{chain.actor}</span>
          </div>
          <p className="text-slate-600 dark:text-slate-400 text-xs leading-relaxed">{chain.summary}</p>
          <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500">
            <span>{chain.steps.length} steps</span>
            <span>·</span>
            <span>{chain.total_duration_minutes.toFixed(0)} min</span>
            <span>·</span>
            <div className="flex gap-1 flex-wrap">
              {chain.mitre_ids.map(id => (
                <span key={id} className="font-mono px-1.5 py-0 bg-slate-200 dark:bg-slate-800 text-purple-700 dark:text-purple-400 rounded text-xs">{id}</span>
              ))}
            </div>
          </div>
        </div>
        <span className="text-slate-500 text-sm flex-shrink-0">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-black/10 dark:border-white/10">
          <div className="mt-3">
            {chain.steps.map((step, i) => (
              <TimelineEvent key={i} ev={step} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

interface Props {
  activeCaseId?: string | null
  selectedUploadId?: number | null
  uploads?: Upload[]
}

export default function PrivilegeTimelinePanel({ activeCaseId, selectedUploadId: propUploadId, uploads }: Props) {
  const [result, setResult] = useState<PrivilegeTimelineResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [uploadId, setUploadId] = useState<number | null>(propUploadId ?? null)
  const [view, setView] = useState<'chains' | 'timeline'>('chains')

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const res = await api.runPrivilegeTimeline(activeCaseId, uploadId)
      setResult(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Privilege timeline failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-slate-900 dark:text-white font-semibold text-lg">AD Privilege Escalation Timeline</h2>
            <p className="text-slate-500 text-sm mt-0.5">
              Reconstructs privilege-event chains from EID 4720/4728/4672/4719 and related events.
              Detects multi-step escalation sequences within configurable time windows.
            </p>
          </div>
          <button
            onClick={run}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-50 transition-colors flex-shrink-0"
            style={{ background: loading ? '#334155' : '#00F0FF', color: loading ? '#94a3b8' : '#0f172a' }}
          >
            {loading ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Building…
              </>
            ) : 'Build Timeline'}
          </button>
        </div>

        {/* Upload selector */}
        {(uploads ?? []).length > 1 && (
          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <span className="text-xs text-slate-500">Source:</span>
            <button
              onClick={() => setUploadId(null)}
              className="px-2.5 py-1 rounded-full text-xs font-medium transition-colors"
              style={uploadId === null ? { background: '#00F0FF', color: '#0f172a' } : { background: 'transparent', color: '#64748b' }}
            >All</button>
            {(uploads ?? []).map(u => (
              <button
                key={u.id}
                onClick={() => setUploadId(u.id)}
                className="px-2.5 py-1 rounded-full text-xs font-medium transition-colors truncate max-w-[180px]"
                style={uploadId === u.id ? { background: '#00F0FF', color: '#0f172a' } : { background: '#1e293b', color: '#94a3b8' }}
                title={u.filename}
              >{u.filename.length > 22 ? u.filename.slice(0, 19) + '…' : u.filename}</button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 rounded-xl px-4 py-3 text-sm">{error}</div>
      )}

      {result && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Privilege Events', value: result.total_privilege_events, color: 'text-orange-600 dark:text-orange-400' },
              { label: 'Escalation Chains', value: result.escalation_chains.length, color: result.escalation_chains.length > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' },
              { label: 'Unique Actors', value: result.unique_actors, color: 'text-blue-600 dark:text-blue-400' },
              { label: 'Highest Severity', value: result.highest_severity.toUpperCase(), color: SEV_TEXT[result.highest_severity] ?? 'text-slate-500' },
            ].map(s => (
              <div key={s.label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* View toggle */}
          {result.total_privilege_events > 0 && (
            <div className="flex gap-2">
              {(['chains', 'timeline'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors border ${
                    view === v
                      ? 'bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white border-slate-300 dark:border-slate-600'
                      : 'bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  {v === 'chains' ? `Escalation Chains (${result.escalation_chains.length})` : `Full Timeline (${result.total_privilege_events})`}
                </button>
              ))}
            </div>
          )}

          {/* Chains view */}
          {view === 'chains' && (
            result.escalation_chains.length === 0 ? (
              <div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800/30 rounded-xl p-8 text-center">
                <p className="text-green-700 dark:text-green-400 font-semibold mb-1">No escalation chains detected</p>
                <p className="text-slate-500 text-sm">No multi-step privilege escalation sequences found in the time window.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {result.escalation_chains.map(c => <ChainCard key={c.chain_id} chain={c} />)}
              </div>
            )
          )}

          {/* Full timeline view */}
          {view === 'timeline' && (
            result.privilege_events.length === 0 ? (
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center">
                <p className="text-slate-500 text-sm">No privilege-related events found. Upload Windows event logs containing EID 4720/4728/4672.</p>
              </div>
            ) : (
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4">
                <div className="max-h-[600px] overflow-y-auto pr-1">
                  {result.privilege_events.map((ev, i) => (
                    <TimelineEvent key={i} ev={ev} />
                  ))}
                </div>
              </div>
            )
          )}
        </>
      )}

      {!result && !loading && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <svg className="h-12 w-12 text-slate-300 dark:text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <p className="text-sm text-slate-500">Click "Build Timeline" to reconstruct the privilege escalation sequence.</p>
        </div>
      )}
    </div>
  )
}

import { useState, useCallback } from 'react'
import { api } from '../api/client'
import type { LMDResult, LMDDetection, Upload } from '../types'
import LMDGraphView from './LMDGraphView'

interface Props {
  activeCaseId?: string | null
  uploads:        Upload[]
}

// ── Severity / colour helpers ─────────────────────────────────────────────────

const SEVERITY_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: 'text-red-400',    bg: 'bg-red-950/30',    border: 'border-red-800/50'    },
  high:     { text: 'text-orange-400', bg: 'bg-orange-950/30', border: 'border-orange-800/50' },
  medium:   { text: 'text-amber-400',  bg: 'bg-amber-950/30',  border: 'border-amber-800/50'  },
  none:     { text: 'text-slate-500',  bg: 'bg-slate-800/30',  border: 'border-slate-700/50'  },
}

const CLASS_DOT: Record<string, string> = {
  'Kerberoasting/AS-REP':   '#8b5cf6',
  'DCSync/Credential Theft':'#ef4444',
  'Golden/Silver Ticket':   '#f59e0b',
  'Lateral Movement':       '#fbbf24',
  'AD Reconnaissance':      '#38bdf8',
  'Normal Traffic':         '#64748b',
}

// ── Small stat card ────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 px-4 py-3 flex flex-col gap-0.5 min-w-[110px]">
      <span className="text-xs text-slate-500 uppercase tracking-wide">{label}</span>
      <span className="text-xl font-bold font-mono" style={{ color: color ?? '#e2e8f0' }}>{value}</span>
      {sub && <span className="text-xs text-slate-600">{sub}</span>}
    </div>
  )
}

// ── Detection row ─────────────────────────────────────────────────────────────

function DetectionRow({ det, idx }: { det: LMDDetection; idx: number }) {
  const [open, setOpen] = useState(false)
  const sev = SEVERITY_STYLE[det.severity] ?? SEVERITY_STYLE.none
  const dot = CLASS_DOT[det.attack_label] ?? '#94a3b8'

  return (
    <>
      <tr
        className="cursor-pointer hover:bg-slate-800/40 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2 pl-4 pr-2 text-xs font-mono text-slate-500">{idx + 1}</td>
        <td className="py-2 pr-3">
          <span
            className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full border ${sev.text} ${sev.bg} ${sev.border}`}
          >
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: dot }} />
            {det.attack_label}
          </span>
        </td>
        <td className="py-2 pr-3 text-xs font-mono text-slate-400">{det.source_ip || '—'}</td>
        <td className="py-2 pr-3 text-xs font-mono text-slate-400">{det.dest_ip || '—'}</td>
        <td className="py-2 pr-3 text-xs text-slate-500">{det.event_id || '—'}</td>
        <td className="py-2 pr-4 text-xs font-mono text-slate-500 max-w-[160px] truncate">
          {det.image || '—'}
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-900/60">
          <td colSpan={6} className="px-6 py-3">
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Command Line</p>
                <code className="text-slate-300 break-all">{det.command_line || '(none)'}</code>
              </div>
              <div>
                <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Matched AD Indicators</p>
                {det.matched_features.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {det.matched_features.map(f => (
                      <span key={f} className="text-xs px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-purple-400 font-mono">
                        {f.replace('Has_', '').replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-600">None</span>
                )}
              </div>
              <div>
                <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Destination Port</p>
                <span className="font-mono text-slate-300">{det.destination_port || '—'}</span>
              </div>
              <div>
                <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Severity</p>
                <span className={`font-semibold uppercase ${sev.text}`}>{det.severity}</span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Attack breakdown bar ───────────────────────────────────────────────────────

function AttackBreakdown({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (total === 0) return null
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1])

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-4">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Attack Breakdown</h3>
      <div className="space-y-2.5">
        {entries.map(([label, count]) => {
          const pct = Math.round((count / total) * 100)
          const dot = CLASS_DOT[label] ?? '#94a3b8'
          return (
            <div key={label} className="flex items-center gap-3">
              <span className="text-xs text-slate-400 w-44 truncate flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: dot }} />
                {label}
              </span>
              <div className="flex-1 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                <div className="h-1.5 rounded-full" style={{ width: `${pct}%`, background: dot }} />
              </div>
              <span className="text-xs font-mono text-slate-500 w-10 text-right">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function LMDPanel({ activeCaseId, uploads }: Props) {
  const [loading,       setLoading]       = useState(false)
  const [result,        setResult]        = useState<LMDResult | null>(null)
  const [error,         setError]         = useState<string | null>(null)
  const [selectedUpload, setSelectedUpload] = useState<number | null>(null)
  const [activeTab,     setActiveTab]     = useState<'detections' | 'graph'>('detections')
  const [filterClass,   setFilterClass]   = useState<string>('all')

  const handleRun = useCallback(async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.runLmdAnalysis(activeCaseId, selectedUpload)
      setResult(r)
      setActiveTab(r.detections.length > 0 ? 'detections' : 'graph')
    } catch (e: any) {
      setError(e.message ?? 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }, [activeCaseId, selectedUpload])

  const totalDetections = result?.detections.length ?? 0
  const attackClasses   = result ? Object.keys(result.attack_counts) : []
  const filteredDets    = result
    ? (filterClass === 'all' ? result.detections : result.detections.filter(d => d.attack_label === filterClass))
    : []

  const criticalCount = result?.detections.filter(d => d.severity === 'critical').length ?? 0
  const highCount     = result?.detections.filter(d => d.severity === 'high').length ?? 0

  return (
    <div className="space-y-4">
      {/* ── Header card ──────────────────────────────────────────────────── */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 px-5 py-4 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold text-slate-200">AD Lateral Movement Detection</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Random Forest classifier trained on 6 AD attack classes: Kerberoasting, DCSync,
              Golden/Silver Ticket, Lateral Movement, Reconnaissance, and Normal traffic.
            </p>
          </div>
          <div className="flex-shrink-0 flex items-center gap-1.5">
            <span className="text-xs px-2 py-0.5 rounded-full bg-purple-900/30 border border-purple-700/30 text-purple-400 font-semibold">
              RF Model
            </span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-400">
              AD Specialized
            </span>
          </div>
        </div>

        {/* Upload selector */}
        {uploads.length > 1 && (
          <div className="flex items-center gap-3">
            <label className="text-xs text-slate-500 flex-shrink-0">Source:</label>
            <select
              className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-slate-500"
              value={selectedUpload ?? ''}
              onChange={e => setSelectedUpload(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">All uploads (case scope)</option>
              {uploads.map(u => (
                <option key={u.id} value={u.id}>{u.filename}</option>
              ))}
            </select>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleRun}
            disabled={loading}
            className="px-4 py-2 rounded-lg text-xs font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              background: loading ? '#1e293b' : 'linear-gradient(135deg,#7c3aed,#4f46e5)',
              color: '#fff',
              border: '1px solid #6d28d9',
            }}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                  <path className="opacity-80" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                Running LMD…
              </span>
            ) : 'Run LMD Analysis'}
          </button>
          {result && (
            <span className="text-xs text-slate-500">
              Analyzed {result.total_events.toLocaleString()} events
            </span>
          )}
        </div>

        {error && (
          <div className="rounded-lg border border-red-800/40 bg-red-950/20 px-3 py-2 text-xs text-red-400">
            {error}
          </div>
        )}
      </div>

      {/* ── Results ──────────────────────────────────────────────────────── */}
      {result && (
        <>
          {/* Stat row */}
          <div className="flex flex-wrap gap-3">
            <StatCard label="Total Events" value={result.total_events.toLocaleString()} />
            <StatCard label="Detections" value={totalDetections}
              sub={totalDetections === 0 ? 'clean' : 'attacks found'}
              color={totalDetections > 0 ? '#f97316' : '#22c55e'} />
            {criticalCount > 0 && (
              <StatCard label="Critical" value={criticalCount} color="#ef4444" />
            )}
            {highCount > 0 && (
              <StatCard label="High" value={highCount} color="#f97316" />
            )}
            <StatCard label="Attack Classes" value={attackClasses.length}
              sub={attackClasses.length > 0 ? attackClasses.slice(0, 2).join(', ') : 'none'} />
          </div>

          {totalDetections === 0 ? (
            <div className="bg-slate-900 rounded-xl border border-emerald-800/30 p-10 text-center">
              <svg className="mx-auto h-10 w-10 text-emerald-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <p className="text-emerald-400 text-sm font-semibold">No AD attacks detected</p>
              <p className="text-slate-600 text-xs mt-1">All {result.total_events.toLocaleString()} events classified as normal traffic.</p>
            </div>
          ) : (
            <>
              <AttackBreakdown counts={result.attack_counts} />

              {/* Tab bar */}
              <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
                <div className="flex border-b border-slate-800">
                  {([['detections', 'Detections', `${totalDetections}`], ['graph', 'Attack Graph', '']] as const).map(([id, label, badge]) => (
                    <button
                      key={id}
                      onClick={() => setActiveTab(id)}
                      className="flex items-center gap-2 px-5 py-3 text-xs font-semibold transition-colors"
                      style={activeTab === id
                        ? { color: '#a78bfa', borderBottom: '2px solid #a78bfa', marginBottom: '-1px' }
                        : { color: '#64748b', borderBottom: '2px solid transparent', marginBottom: '-1px' }
                      }
                    >
                      {label}
                      {badge && (
                        <span className="text-xs px-1.5 py-0.5 rounded-full bg-purple-900/30 text-purple-400 border border-purple-700/30 font-bold">
                          {badge}
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                {/* Detections tab */}
                {activeTab === 'detections' && (
                  <div className="p-4 space-y-3">
                    {/* Filter bar */}
                    {attackClasses.length > 1 && (
                      <div className="flex flex-wrap gap-2">
                        <button
                          onClick={() => setFilterClass('all')}
                          className="text-xs px-2.5 py-1 rounded-full border transition-colors"
                          style={filterClass === 'all'
                            ? { background: '#4f46e5', color: '#fff', borderColor: '#4338ca' }
                            : { color: '#64748b', borderColor: '#334155' }
                          }
                        >
                          All ({totalDetections})
                        </button>
                        {attackClasses.map(cls => (
                          <button
                            key={cls}
                            onClick={() => setFilterClass(cls)}
                            className="text-xs px-2.5 py-1 rounded-full border transition-colors"
                            style={filterClass === cls
                              ? { background: CLASS_DOT[cls] + '33', color: CLASS_DOT[cls], borderColor: CLASS_DOT[cls] + '66' }
                              : { color: '#64748b', borderColor: '#334155' }
                            }
                          >
                            {cls} ({result.attack_counts[cls]})
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Table */}
                    <div className="overflow-x-auto rounded-lg border border-slate-800">
                      <table className="w-full text-left">
                        <thead className="bg-slate-800/60">
                          <tr>
                            <th className="py-2 pl-4 pr-2 text-xs font-semibold text-slate-500 w-8">#</th>
                            <th className="py-2 pr-3 text-xs font-semibold text-slate-500">Attack Type</th>
                            <th className="py-2 pr-3 text-xs font-semibold text-slate-500">Source IP</th>
                            <th className="py-2 pr-3 text-xs font-semibold text-slate-500">Dest IP</th>
                            <th className="py-2 pr-3 text-xs font-semibold text-slate-500">EventID</th>
                            <th className="py-2 pr-4 text-xs font-semibold text-slate-500">Image</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {filteredDets.map((det, i) => (
                            <DetectionRow key={det.event_index} det={det} idx={i} />
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className="text-xs text-slate-600">Click a row to expand command line and matched AD indicators.</p>
                  </div>
                )}

                {/* Graph tab */}
                {activeTab === 'graph' && result.graph && (
                  result.graph.nodes.length > 0 ? (
                    <div className="p-4">
                      <LMDGraphView graphData={result.graph} />
                    </div>
                  ) : (
                    <div className="p-10 text-center text-slate-600 text-sm">
                      No IP-level graph data available — events lacked source/destination IP fields.
                    </div>
                  )
                )}
              </div>
            </>
          )}
        </>
      )}

      {!result && !loading && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-10 text-center space-y-3">
          <svg className="mx-auto h-12 w-12 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
          </svg>
          <p className="text-slate-400 text-sm">Run the LMD model to detect AD attacks in uploaded logs.</p>
          <p className="text-slate-600 text-xs max-w-sm mx-auto">
            Detects: Kerberoasting · DCSync · Golden/Silver Ticket · Lateral Movement ·
            BloodHound / LDAP Reconnaissance
          </p>
        </div>
      )}
    </div>
  )
}

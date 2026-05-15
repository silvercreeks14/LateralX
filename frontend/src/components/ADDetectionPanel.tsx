import { useState } from 'react'
import { api } from '../api/client'
import type { ADRulesResult, ADRuleDetection, AttackChain, ToolSignatureHit, Upload } from '../types'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/30 border-red-300 dark:border-red-800/40',
  high:     'text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30 border-orange-300 dark:border-orange-800/40',
  medium:   'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-800/40',
  low:      'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800/30 border-slate-300 dark:border-slate-700/40',
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-amber-500',
  low:      'bg-slate-500',
}

const CATEGORY_COLOR: Record<string, string> = {
  'Kerberoasting':        'text-purple-700 dark:text-purple-400 bg-purple-50 dark:bg-purple-950/30 border-purple-300 dark:border-purple-800/40',
  'DCSync':               'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/30 border-red-300 dark:border-red-800/40',
  'Lateral Movement':     'text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-950/30 border-blue-300 dark:border-blue-800/40',
  'Privilege Escalation': 'text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30 border-orange-300 dark:border-orange-800/40',
  'Persistence':          'text-yellow-700 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-950/30 border-yellow-300 dark:border-yellow-800/40',
  'Reconnaissance':       'text-cyan-700 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/30 border-cyan-300 dark:border-cyan-800/40',
  'Tool Detection':       'text-pink-700 dark:text-pink-400 bg-pink-50 dark:bg-pink-950/30 border-pink-300 dark:border-pink-800/40',
}

const CONF_COLOR: Record<string, string> = {
  high:   'text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/30',
  medium: 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30',
  low:    'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800/40',
}

const SEV_CHAIN: Record<string, string> = {
  critical: 'border-l-red-500',
  high:     'border-l-orange-500',
  medium:   'border-l-amber-500',
  low:      'border-l-slate-400',
}

function SeverityBadge({ sev }: { sev: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${SEV_COLOR[sev] ?? SEV_COLOR.low}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${SEV_DOT[sev] ?? 'bg-slate-500'}`} />
      {sev}
    </span>
  )
}

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${CATEGORY_COLOR[cat] ?? 'text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700'}`}>
      {cat}
    </span>
  )
}

function DetectionCard({ d }: { d: ADRuleDetection }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={`rounded-xl border transition-colors ${SEV_COLOR[d.severity] ?? SEV_COLOR.low}`}>
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex flex-col gap-1 flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge sev={d.severity} />
            <CategoryBadge cat={d.category} />
            <span className="font-mono text-xs text-slate-500">{d.rule_id}</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap mt-1">
            <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">{d.rule_name}</span>
            <span className="text-xs text-slate-500">entity: <span className="font-mono text-slate-700 dark:text-slate-300">{d.entity}</span></span>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 mt-0.5 flex-wrap">
            <span>{d.mitre_tactic}</span>
            <span className="font-mono bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded text-slate-600 dark:text-slate-400">{d.mitre_id}</span>
            <span>confidence: <span className="text-slate-700 dark:text-slate-300">{d.confidence}</span></span>
            <span className="ml-auto font-mono">{d.timestamp.slice(0, 19).replace('T', ' ')}</span>
          </div>
        </div>
        <span className="text-slate-500 text-sm flex-shrink-0 mt-1">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-current/20 space-y-3 mt-0">
          {d.evidence.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5 mt-3">Evidence</p>
              <ul className="space-y-1">
                {d.evidence.map((ev, i) => (
                  <li key={i} className="text-xs text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-900/60 rounded px-3 py-1.5 flex items-start gap-2">
                    <span className="text-slate-400 flex-shrink-0">•</span>
                    {ev}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {d.event_ids.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">Source Event IDs</p>
              <div className="flex flex-wrap gap-1">
                {d.event_ids.map(id => (
                  <span key={id} className="font-mono text-xs px-2 py-0.5 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded border border-slate-300 dark:border-slate-700">#{id}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function AttackChainCard({ chain }: { chain: AttackChain }) {
  const [open, setOpen] = useState(false)
  const duration = (() => {
    if (!chain.first_seen || !chain.last_seen) return null
    const diffMs = new Date(chain.last_seen).getTime() - new Date(chain.first_seen).getTime()
    const mins = Math.round(diffMs / 60000)
    if (mins < 60) return `${mins}m`
    return `${Math.floor(mins / 60)}h ${mins % 60}m`
  })()
  return (
    <div className={`rounded-xl border-l-4 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 ${SEV_CHAIN[chain.severity] ?? 'border-l-slate-400'}`}>
      <button className="w-full flex items-start gap-3 px-4 py-3 text-left" onClick={() => setOpen(v => !v)}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <SeverityBadge sev={chain.severity} />
            <span className="font-mono text-xs text-slate-500">{chain.chain_id}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              {chain.detection_count} detections
            </span>
            {duration && <span className="text-xs text-slate-500">{duration}</span>}
          </div>
          <p className="font-semibold text-sm text-slate-900 dark:text-slate-100">{chain.actor}</p>
          <p className="text-xs text-slate-500 mt-0.5">{chain.summary}</p>
          <div className="flex items-center gap-1 mt-1.5 flex-wrap">
            {chain.tactics.map((t, i) => (
              <span key={t} className="flex items-center gap-1 text-xs">
                <span className="text-slate-700 dark:text-slate-300">{t}</span>
                {i < chain.tactics.length - 1 && <span className="text-slate-400">→</span>}
              </span>
            ))}
          </div>
        </div>
        <span className="text-slate-500 text-sm flex-shrink-0 mt-1">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-slate-200 dark:border-slate-700/40 space-y-3">
          <div className="mt-3">
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">MITRE ATT&amp;CK IDs</p>
            <div className="flex flex-wrap gap-1.5">
              {chain.mitre_ids.map(id => (
                <span key={id} className="font-mono text-xs px-2 py-0.5 bg-purple-50 dark:bg-purple-950/30 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-800/40 rounded">{id}</span>
              ))}
            </div>
          </div>
          {chain.first_seen && chain.last_seen && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">Timeline</p>
              <div className="flex items-center gap-3 text-xs font-mono text-slate-500">
                <span>{chain.first_seen.slice(0, 19).replace('T', ' ')}</span>
                <span>→</span>
                <span>{chain.last_seen.slice(0, 19).replace('T', ' ')}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ToolSignatureCard({ hit }: { hit: ToolSignatureHit }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
      <button className="w-full flex items-start gap-3 px-4 py-3 text-left" onClick={() => setOpen(v => !v)}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="font-semibold text-sm text-pink-700 dark:text-pink-400">{hit.tool_name}</span>
            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${CONF_COLOR[hit.confidence] ?? CONF_COLOR.low}`}>
              {hit.confidence} confidence
            </span>
          </div>
          <div className="text-xs text-slate-500">
            entity: <span className="font-mono text-slate-700 dark:text-slate-300">{hit.entity}</span>
            {hit.timestamp && (
              <span className="ml-3 font-mono">{hit.timestamp.slice(0, 19).replace('T', ' ')}</span>
            )}
          </div>
        </div>
        <span className="text-slate-500 text-sm flex-shrink-0 mt-1">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-slate-200 dark:border-slate-700/40 space-y-3">
          {hit.indicators.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">Behavioral Indicators</p>
              <ul className="space-y-1">
                {hit.indicators.map((ind, i) => (
                  <li key={i} className="text-xs text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-900/60 rounded px-3 py-1.5 flex items-start gap-2">
                    <span className="text-pink-400 flex-shrink-0">•</span>
                    {ind}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {hit.mitre_ids.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">MITRE ATT&amp;CK IDs</p>
              <div className="flex flex-wrap gap-1.5">
                {hit.mitre_ids.map(id => (
                  <span key={id} className="font-mono text-xs px-2 py-0.5 bg-pink-50 dark:bg-pink-950/30 text-pink-700 dark:text-pink-400 border border-pink-200 dark:border-pink-800/40 rounded">{id}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

interface Props {
  activeCaseId?: string | null
  uploads?: Upload[]
  onResult?: (result: ADRulesResult) => void
}

export default function ADDetectionPanel({ activeCaseId, uploads, onResult }: Props) {
  const [result, setResult] = useState<ADRulesResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedUploadId, setSelectedUploadId] = useState<number | null>(null)
  const [filterCat, setFilterCat] = useState<string>('all')
  const [filterSev, setFilterSev] = useState<string>('all')

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const res = await api.runADRules(activeCaseId, selectedUploadId)
      setResult(res)
      onResult?.(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'AD detection failed')
    } finally {
      setLoading(false)
    }
  }

  const detections = result?.detections ?? []
  const filtered = detections.filter(d => {
    if (filterCat !== 'all' && d.category !== filterCat) return false
    if (filterSev !== 'all' && d.severity !== filterSev) return false
    return true
  })

  const categories = Array.from(new Set(detections.map(d => d.category))).sort()
  const severities = Array.from(new Set(detections.map(d => d.severity))).sort()

  const countBySev = (sev: string) => detections.filter(d => d.severity === sev).length

  const filterBtn = (active: boolean) =>
    `px-2 py-0.5 rounded text-xs font-medium transition-colors ${
      active
        ? 'bg-slate-600 dark:bg-slate-600 text-white'
        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
    }`

  return (
    <div className="space-y-5">

      {/* Header + controls */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-slate-900 dark:text-white font-semibold text-lg">AD Detection Engine</h2>
            <p className="text-slate-500 text-sm mt-0.5">
              71 rule-based Active Directory attack detections across 7 categories.
              No ML model — fully transparent rule evaluation.
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
                Scanning…
              </>
            ) : 'Run AD Scan'}
          </button>
        </div>

        {/* Upload selector */}
        {(uploads ?? []).length > 1 && (
          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <span className="text-xs text-slate-500">Source:</span>
            <button
              onClick={() => setSelectedUploadId(null)}
              className="px-2.5 py-1 rounded-full text-xs font-medium transition-colors"
              style={selectedUploadId === null ? { background: '#00F0FF', color: '#0f172a' } : { background: '#1e293b', color: '#94a3b8' }}
            >All uploads</button>
            {(uploads ?? []).map(u => (
              <button
                key={u.id}
                onClick={() => setSelectedUploadId(u.id)}
                className="px-2.5 py-1 rounded-full text-xs font-medium transition-colors truncate max-w-[180px]"
                style={selectedUploadId === u.id ? { background: '#00F0FF', color: '#0f172a' } : { background: '#1e293b', color: '#94a3b8' }}
                title={u.filename}
              >{u.filename.length > 22 ? u.filename.slice(0, 19) + '…' : u.filename}</button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 rounded-xl px-4 py-3 text-sm">{error}</div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Stats grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { label: 'Total Events',    value: result.total_events_analyzed.toLocaleString(), color: 'text-slate-700 dark:text-slate-200' },
              { label: 'Detections',      value: result.detection_count,        color: result.detection_count > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' },
              { label: 'Categories Hit',  value: result.categories_hit.length,  color: 'text-orange-600 dark:text-orange-400' },
              { label: 'MITRE IDs',       value: result.mitre_ids.length,       color: 'text-purple-600 dark:text-purple-400' },
              { label: 'Attack Chains',   value: result.attack_chains.length,   color: result.attack_chains.length > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-500' },
              { label: 'Tool Signatures', value: result.tool_signatures.length, color: result.tool_signatures.length > 0 ? 'text-pink-600 dark:text-pink-400' : 'text-slate-500' },
            ].map(s => (
              <div key={s.label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Severity breakdown */}
          {detections.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                const count = countBySev(sev)
                if (!count) return null
                return (
                  <div key={sev} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${SEV_COLOR[sev]}`}>
                    <span className={`w-2 h-2 rounded-full ${SEV_DOT[sev]}`} />
                    {count} {sev}
                  </div>
                )
              })}
            </div>
          )}

          {/* Filters */}
          {detections.length > 0 && (
            <div className="flex flex-wrap gap-3 items-center">
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-500">Category:</span>
                {['all', ...categories].map(c => (
                  <button key={c} onClick={() => setFilterCat(c)} className={filterBtn(filterCat === c)}>
                    {c === 'all' ? 'All' : c}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-500">Severity:</span>
                {['all', ...severities].map(s => (
                  <button key={s} onClick={() => setFilterSev(s)} className={filterBtn(filterSev === s)}>
                    {s === 'all' ? 'All' : s}
                  </button>
                ))}
              </div>
              <span className="text-xs text-slate-400 ml-auto">{filtered.length} of {detections.length} detections</span>
            </div>
          )}

          {/* Detection list */}
          {detections.length === 0 ? (
            <div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800/30 rounded-xl p-8 text-center">
              <p className="text-green-700 dark:text-green-400 font-semibold mb-1">No AD attacks detected</p>
              <p className="text-slate-500 text-sm">{result.total_events_analyzed.toLocaleString()} events analyzed — all 71 rules returned clean.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((d, i) => <DetectionCard key={`${d.rule_id}-${d.entity}-${i}`} d={d} />)}
              {filtered.length === 0 && (
                <p className="text-slate-500 text-sm text-center py-6">No detections match current filters.</p>
              )}
            </div>
          )}

          {/* MITRE IDs summary */}
          {result.mitre_ids.length > 0 && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 uppercase tracking-wide">MITRE ATT&amp;CK Techniques Detected</p>
              <div className="flex flex-wrap gap-1.5">
                {result.mitre_ids.map(id => (
                  <span key={id} className="font-mono text-xs px-2 py-1 bg-purple-50 dark:bg-purple-950/30 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-800/40 rounded">{id}</span>
                ))}
              </div>
            </div>
          )}

          {/* Attack Chains */}
          {result.attack_chains.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide">
                Attack Chains — {result.attack_chains.length} correlated sequence{result.attack_chains.length !== 1 ? 's' : ''}
              </p>
              {result.attack_chains.map(chain => (
                <AttackChainCard key={chain.chain_id} chain={chain} />
              ))}
            </div>
          )}

          {/* Tool Signatures */}
          {result.tool_signatures.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide">
                Tool Signatures — {result.tool_signatures.length} adversary toolkit{result.tool_signatures.length !== 1 ? 's' : ''} identified
              </p>
              {result.tool_signatures.map((hit, i) => (
                <ToolSignatureCard key={`${hit.tool_name}-${hit.entity}-${i}`} hit={hit} />
              ))}
            </div>
          )}
        </>
      )}

      {!result && !loading && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <svg className="h-12 w-12 text-slate-300 dark:text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <p className="text-sm text-slate-500">Click "Run AD Scan" to detect Active Directory attack patterns.</p>
        </div>
      )}
    </div>
  )
}

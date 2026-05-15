import { useState } from 'react'
import { api } from '../api/client'
import type { ADEntityIntelResult, ADEntity, Upload } from '../types'

const RISK_COLOR: Record<string, string> = {
  compromised: 'border-red-300 dark:border-red-600/50 bg-red-50 dark:bg-red-950/10',
  suspicious:  'border-orange-300 dark:border-orange-600/50 bg-orange-50 dark:bg-orange-950/10',
  clean:       'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900',
}
const RISK_TEXT: Record<string, string> = {
  compromised: 'text-red-600 dark:text-red-400',
  suspicious:  'text-orange-600 dark:text-orange-400',
  clean:       'text-green-600 dark:text-green-400',
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 60
    ? 'bg-red-500'
    : score >= 30
    ? 'bg-orange-500'
    : 'bg-green-500'
  return (
    <div className="w-full h-1.5 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all ${color}`}
        style={{ width: `${score}%` }}
      />
    </div>
  )
}

function EntityCard({ entity }: { entity: ADEntity }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={`rounded-xl border transition-all ${RISK_COLOR[entity.risk_label]}`}>
      <button
        className="w-full flex items-center gap-4 px-4 py-3 text-left"
        onClick={() => setOpen(v => !v)}
      >
        {/* Entity type icon */}
        <div className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center text-sm font-bold"
          style={{
            background: entity.entity_type === 'user'  ? '#0f3460' :
                        entity.entity_type === 'host'  ? '#1e3a8a' : '#1e293b',
            color: entity.entity_type === 'user'  ? '#60a5fa' :
                   entity.entity_type === 'host'  ? '#93c5fd' : '#94a3b8',
          }}>
          {entity.entity_type === 'user' ? 'U' : entity.entity_type === 'host' ? 'H' : 'G'}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 truncate">{entity.name}</span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${RISK_TEXT[entity.risk_label]}`}>
              {entity.risk_label}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-1.5">
            <span className={`text-sm font-bold ${RISK_TEXT[entity.risk_label]}`}>{entity.risk_score}</span>
            <div className="flex-1">
              <RiskBar score={entity.risk_score} />
            </div>
            <span className="text-xs text-slate-500 flex-shrink-0">{entity.event_count} events</span>
          </div>
        </div>
        <span className="text-slate-400 text-sm flex-shrink-0 ml-2">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-black/10 dark:border-white/5 space-y-3">
          <div className="grid grid-cols-2 gap-3 mt-3 text-xs">
            <div>
              <p className="text-slate-500 mb-0.5">First seen</p>
              <p className="font-mono text-slate-700 dark:text-slate-300">{entity.first_seen.slice(0, 19).replace('T', ' ')}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Last seen</p>
              <p className="font-mono text-slate-700 dark:text-slate-300">{entity.last_seen.slice(0, 19).replace('T', ' ')}</p>
            </div>
          </div>

          {entity.anomaly_flags.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">Risk Indicators</p>
              <ul className="space-y-1">
                {entity.anomaly_flags.map((flag, i) => (
                  <li key={i} className="text-xs text-slate-700 dark:text-slate-300 flex items-start gap-2 bg-slate-100 dark:bg-slate-800/50 rounded px-2 py-1">
                    <span className="text-orange-500 flex-shrink-0">⚠</span>{flag}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {entity.associated_techniques.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">MITRE Techniques</p>
              <div className="flex flex-wrap gap-1.5">
                {entity.associated_techniques.map(t => (
                  <span key={t} className="font-mono text-xs px-2 py-0.5 bg-purple-50 dark:bg-purple-950/30 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-800/40 rounded">{t}</span>
                ))}
              </div>
            </div>
          )}

          {entity.group_memberships.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">Group Memberships</p>
              <div className="flex flex-wrap gap-1.5">
                {entity.group_memberships.map(g => (
                  <span key={g} className="text-xs px-2 py-0.5 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800/40 rounded">{g}</span>
                ))}
              </div>
            </div>
          )}

          {entity.lateral_targets.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1.5">
                {entity.entity_type === 'host' ? 'Users Logged In' : 'Hosts Accessed'}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {entity.lateral_targets.map(t => (
                  <span key={t} className="font-mono text-xs px-2 py-0.5 bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-800/40 rounded">{t}</span>
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
}

export default function ADEntityPanel({ activeCaseId, uploads }: Props) {
  const [result, setResult] = useState<ADEntityIntelResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [uploadId, setUploadId] = useState<number | null>(null)
  const [filterType, setFilterType] = useState<'all' | 'user' | 'host' | 'group'>('all')
  const [filterRisk, setFilterRisk] = useState<'all' | 'compromised' | 'suspicious' | 'clean'>('all')
  const [sortBy, setSortBy] = useState<'risk' | 'events'>('risk')

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const res = await api.getADEntities(activeCaseId, uploadId)
      setResult(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Entity profiling failed')
    } finally {
      setLoading(false)
    }
  }

  const entities = result?.entities ?? []
  const filtered = entities
    .filter(e => filterType === 'all' || e.entity_type === filterType)
    .filter(e => filterRisk === 'all' || e.risk_label === filterRisk)
    .sort((a, b) => sortBy === 'risk' ? b.risk_score - a.risk_score : b.event_count - a.event_count)

  const filterBtn = (active: boolean) =>
    `px-2 py-0.5 rounded text-xs font-medium transition-colors ${
      active
        ? 'bg-slate-600 dark:bg-slate-600 text-white'
        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
    }`

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-slate-900 dark:text-white font-semibold text-lg">AD Entity Intelligence</h2>
            <p className="text-slate-500 text-sm mt-0.5">
              Profiles users, hosts, and groups — risk scoring, MITRE technique associations,
              lateral movement targets, and anomaly flags per entity.
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
                Profiling…
              </>
            ) : 'Profile Entities'}
          </button>
        </div>

        {(uploads ?? []).length > 1 && (
          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <span className="text-xs text-slate-500">Source:</span>
            <button
              onClick={() => setUploadId(null)}
              className="px-2.5 py-1 rounded-full text-xs font-medium transition-colors"
              style={uploadId === null ? { background: '#00F0FF', color: '#0f172a' } : { background: '#1e293b', color: '#94a3b8' }}
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
              { label: 'Total Entities', value: result.total_entities, color: 'text-slate-700 dark:text-slate-200' },
              { label: 'Compromised', value: result.compromised_count, color: result.compromised_count > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' },
              { label: 'Suspicious', value: result.suspicious_count, color: result.suspicious_count > 0 ? 'text-orange-600 dark:text-orange-400' : 'text-green-600 dark:text-green-400' },
              { label: 'Top Risk', value: result.top_risk_entity ?? '—', color: 'text-amber-600 dark:text-amber-400' },
            ].map(s => (
              <div key={s.label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                <p className={`text-xl font-bold truncate ${s.color}`} title={String(s.value)}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Filters */}
          {entities.length > 0 && (
            <div className="flex flex-wrap gap-3 items-center">
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-500">Type:</span>
                {(['all', 'user', 'host', 'group'] as const).map(t => (
                  <button key={t} onClick={() => setFilterType(t)} className={filterBtn(filterType === t)}>{t}</button>
                ))}
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-500">Risk:</span>
                {(['all', 'compromised', 'suspicious', 'clean'] as const).map(r => (
                  <button key={r} onClick={() => setFilterRisk(r)} className={filterBtn(filterRisk === r)}>{r}</button>
                ))}
              </div>
              <div className="flex items-center gap-1.5 ml-auto">
                <span className="text-xs text-slate-500">Sort:</span>
                {(['risk', 'events'] as const).map(s => (
                  <button key={s} onClick={() => setSortBy(s)} className={filterBtn(sortBy === s)}>{s}</button>
                ))}
              </div>
              <span className="text-xs text-slate-400">{filtered.length} entities</span>
            </div>
          )}

          {/* Entity list */}
          {entities.length === 0 ? (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center">
              <p className="text-slate-500 text-sm">No entities found in the selected events.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map(e => <EntityCard key={`${e.entity_type}-${e.name}`} entity={e} />)}
              {filtered.length === 0 && (
                <p className="text-slate-500 text-sm text-center py-6">No entities match current filters.</p>
              )}
            </div>
          )}
        </>
      )}

      {!result && !loading && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <svg className="h-12 w-12 text-slate-300 dark:text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
          <p className="text-sm text-slate-500">Click "Profile Entities" to analyze users and hosts.</p>
        </div>
      )}
    </div>
  )
}

import { useState } from 'react'
import { api } from '../api/client'
import type { AttackStoryline, AttackStep, LateralPath } from '../types'

interface Props {
  activeCaseId: string | null
  selectedUploadId: number | null
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':        '#ef4444',
  'Execution':             '#f97316',
  'Persistence':           '#f59e0b',
  'Privilege Escalation':  '#eab308',
  'Defense Evasion':       '#84cc16',
  'Credential Access':     '#22c55e',
  'Discovery':             '#06b6d4',
  'Lateral Movement':      '#3b82f6',
  'Collection':            '#8b5cf6',
  'Command and Control':   '#ec4899',
  'Exfiltration':          '#f43f5e',
  'Impact':                '#FF6B00',
}

const CONFIDENCE_CLS: Record<string, string> = {
  high:   'bg-sky-50 dark:bg-[#00F0FF]/[0.08] text-sky-600 dark:text-[#00F0FF] border border-sky-200 dark:border-[#00F0FF]/30',
  medium: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-500/30',
  low:    'bg-slate-100 dark:bg-slate-700/30 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-600/30',
}

function StepCard({ step, isLast }: { step: AttackStep; isLast: boolean }) {
  const tacticColor = TACTIC_COLORS[step.tactic] ?? '#64748b'
  const confCls = CONFIDENCE_CLS[step.confidence] ?? CONFIDENCE_CLS.low

  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center flex-shrink-0">
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-slate-900 flex-shrink-0 z-10"
          style={{ background: tacticColor }}
        >
          {step.step_number}
        </div>
        {!isLast && <div className="w-px flex-1 bg-slate-200 dark:bg-slate-800 mt-1" />}
      </div>

      <div className="flex-1 pb-5">
        <div className="bg-slate-100/60 dark:bg-slate-800/60 rounded-xl p-4 border border-slate-200 dark:border-slate-700/40">
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="px-2 py-0.5 rounded text-xs font-semibold"
                style={{ background: tacticColor + '25', color: tacticColor }}
              >
                {step.tactic}
              </span>
              <span className="text-xs font-mono text-slate-500">{step.technique_id}</span>
            </div>
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium flex-shrink-0 ${confCls}`}>
              {step.confidence}
            </span>
          </div>

          <p className="text-sm font-medium mb-1 text-slate-900 dark:text-white">{step.technique_name}</p>
          <p className="text-slate-600 dark:text-slate-400 text-xs mb-2">{step.description}</p>

          <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
            <span className="font-mono text-slate-500 dark:text-slate-400">{step.host}</span>
            {step.user && <span className="font-mono text-slate-500 dark:text-slate-400">→ {step.user}</span>}
            <span>{step.timestamp.slice(0, 19).replace('T', ' ')}</span>
          </div>

          {step.event_ids.length > 0 && (
            <div className="flex gap-1 mt-2 flex-wrap">
              {step.event_ids.map(id => (
                <span key={id} className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 rounded text-xs font-mono">
                  EID:{id}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function LateralCard({ path }: { path: LateralPath }) {
  return (
    <div className="flex items-center gap-3 bg-slate-100/60 dark:bg-slate-800/60 rounded-lg px-4 py-3 border border-slate-200 dark:border-slate-700/40">
      <span className="font-mono text-sm text-slate-700 dark:text-slate-300 truncate">{path.from_host}</span>
      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"
        style={{ color: 'var(--brand)' }}>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
      </svg>
      <span className="font-mono text-sm text-slate-700 dark:text-slate-300 truncate">{path.to_host}</span>
      <span className="text-xs text-slate-500 flex-shrink-0">via {path.user}</span>
      <span className="ml-auto text-xs px-2 py-0.5 bg-blue-50 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 rounded font-mono flex-shrink-0">
        {path.method}
      </span>
    </div>
  )
}

export default function StorylinePanel({ activeCaseId, selectedUploadId }: Props) {
  const [storyline, setStoryline] = useState<AttackStoryline | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setLoading(true)
    setError(null)
    try {
      const s = await api.mlStoryline(activeCaseId, selectedUploadId)
      setStoryline(s)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Storyline generation failed')
    } finally {
      setLoading(false)
    }
  }

  const confCls = storyline
    ? (CONFIDENCE_CLS[storyline.confidence] ?? CONFIDENCE_CLS.low)
    : CONFIDENCE_CLS.low

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-slate-900 dark:text-white font-semibold text-lg">Attack Storyline</h2>
          <p className="text-slate-500 text-sm mt-0.5">
            Deterministic ATT&amp;CK mapping · lateral path reconstruction · blast radius
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
              Building…
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
              </svg>
              Build Storyline
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800/50 text-red-700 dark:text-red-300 rounded-xl px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {!storyline && !loading && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <div className="w-14 h-14 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-2">
            <svg className="w-7 h-7 text-slate-400 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
            </svg>
          </div>
          <p className="text-slate-700 dark:text-slate-400 text-sm font-medium">No storyline generated yet</p>
          <p className="text-slate-500 dark:text-slate-600 text-xs max-w-xs">
            Click Build Storyline to reconstruct the attack narrative with MITRE ATT&amp;CK
            technique mapping, lateral movement paths, and blast radius assessment.
          </p>
        </div>
      )}

      {storyline && (
        <>
          {/* Actor profile banner */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Threat Actor Profile</p>
                <p className="text-slate-900 dark:text-white font-bold text-xl">{storyline.threat_actor_profile}</p>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold flex-shrink-0 ${confCls}`}>
                {storyline.confidence.toUpperCase()} CONFIDENCE
              </span>
            </div>
            <div className="grid grid-cols-3 gap-4 text-sm border-t border-slate-200 dark:border-slate-800 pt-4">
              <div>
                <p className="text-xs text-slate-500 mb-1">Entry Vector</p>
                <p className="text-slate-700 dark:text-slate-300 text-xs">{storyline.entry_vector}</p>
              </div>
              <div>
                <p className="text-xs text-slate-500 mb-1">Total Duration</p>
                <p className="text-slate-700 dark:text-slate-300">{Math.round(storyline.total_duration_minutes)} min</p>
              </div>
              <div>
                <p className="text-xs text-slate-500 mb-1">Scope</p>
                <p className="text-slate-700 dark:text-slate-300">
                  {storyline.total_attack_steps} steps &middot; {storyline.total_lateral_paths} lateral paths
                </p>
              </div>
            </div>
          </div>

          {/* Tactic progression */}
          {storyline.tactic_progression.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-2">Kill Chain</p>
              <div className="flex items-center gap-1 flex-wrap">
                {storyline.tactic_progression.map((t, i) => {
                  const color = TACTIC_COLORS[t] ?? '#64748b'
                  return (
                    <div key={t} className="flex items-center gap-1">
                      <span
                        className="px-2.5 py-1 rounded text-xs font-medium"
                        style={{ background: color + '22', color }}
                      >
                        {t}
                      </span>
                      {i < storyline.tactic_progression.length - 1 && (
                        <svg className="w-3 h-3 text-slate-400 dark:text-slate-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Attack steps */}
          {storyline.attack_steps.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-3">
                Attack Timeline ({storyline.attack_steps.length} steps)
              </p>
              {storyline.attack_steps.map((step, i) => (
                <StepCard
                  key={step.step_number}
                  step={step}
                  isLast={i === storyline.attack_steps.length - 1}
                />
              ))}
            </div>
          )}

          {/* Lateral paths */}
          {storyline.lateral_paths.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-2">
                Lateral Movement ({storyline.lateral_paths.length} paths)
              </p>
              <div className="space-y-2">
                {storyline.lateral_paths.map((p, i) => <LateralCard key={i} path={p} />)}
              </div>
            </div>
          )}

          {/* Blast radius */}
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-3">Blast Radius</p>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Compromised Hosts',      items: storyline.blast_radius.compromised_hosts,      color: '#FF6B00' },
                { label: 'Compromised Users',       items: storyline.blast_radius.compromised_users,      color: '#ef4444' },
                { label: 'Accessed Resources',      items: storyline.blast_radius.accessed_resources,     color: '#f59e0b' },
                { label: 'Persistence Mechanisms',  items: storyline.blast_radius.persistence_mechanisms, color: '#8b5cf6' },
              ].map(section => (
                <div key={section.label} className="bg-white dark:bg-slate-900 rounded-xl p-4 border border-slate-200 dark:border-slate-800">
                  <p className="text-xs font-semibold mb-2" style={{ color: section.color }}>
                    {section.label}
                  </p>
                  {section.items.length === 0 ? (
                    <p className="text-slate-500 dark:text-slate-600 text-xs">None identified</p>
                  ) : (
                    <ul className="space-y-1">
                      {section.items.slice(0, 8).map((item, i) => (
                        <li key={i} className="text-slate-700 dark:text-slate-300 text-xs font-mono truncate">{item}</li>
                      ))}
                      {section.items.length > 8 && (
                        <li className="text-slate-500 dark:text-slate-600 text-xs">+{section.items.length - 8} more</li>
                      )}
                    </ul>
                  )}
                </div>
              ))}
            </div>
            <div className="mt-3 bg-white dark:bg-slate-900 rounded-xl px-4 py-3 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <span className="text-xs text-slate-500">Estimated Data at Risk</span>
              <span className="text-sm font-semibold text-orange-600 dark:text-orange-400">
                {storyline.blast_radius.estimated_data_at_risk}
              </span>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

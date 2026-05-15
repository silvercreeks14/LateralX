import type { MitreTechnique } from '../types'

interface Props {
  techniques: MitreTechnique[]
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':       'bg-red-950/20 border-red-800/40 text-red-400',
  'Execution':            'bg-orange-950/20 border-orange-800/40 text-orange-400',
  'Persistence':          'bg-amber-950/20 border-amber-800/40 text-amber-400',
  'Privilege Escalation': 'bg-yellow-950/20 border-yellow-800/40 text-yellow-400',
  'Defense Evasion':      'bg-lime-950/20 border-lime-800/40 text-lime-400',
  'Credential Access':    'bg-emerald-950/20 border-emerald-800/40 text-emerald-400',
  'Discovery':            'bg-teal-950/20 border-teal-800/40 text-teal-400',
  'Lateral Movement':     'bg-cyan-950/20 border-cyan-800/40 text-cyan-400',
  'Collection':           'bg-sky-950/20 border-sky-800/40 text-sky-400',
  'Command and Control':  'bg-blue-950/20 border-blue-800/40 text-blue-400',
  'Exfiltration':         'bg-violet-950/20 border-violet-800/40 text-violet-400',
  'Impact':               'bg-rose-950/20 border-rose-800/40 text-rose-400',
}

export default function MitrePanel({ techniques }: Props) {
  if (techniques.length === 0) return null

  const grouped = techniques.reduce<Record<string, MitreTechnique[]>>((acc, t) => {
    ;(acc[t.tactic] ??= []).push(t)
    return acc
  }, {})

  return (
    <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-4">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
        MITRE ATT&amp;CK Techniques Identified ({techniques.length})
      </h3>
      <div className="space-y-3">
        {Object.entries(grouped).map(([tactic, techs]) => (
          <div key={tactic}>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5">
              {tactic}
            </p>
            <div className="flex flex-wrap gap-2">
              {techs.map((t) => {
                const style = TACTIC_COLORS[t.tactic] ?? 'bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400'
                return (
                  <div
                    key={t.id}
                    className={`border rounded-lg px-3 py-2 ${style} cursor-default`}
                    title={t.evidence ?? ''}
                  >
                    <p className="font-mono text-xs font-bold">{t.id}</p>
                    <p className="text-xs mt-0.5">{t.name}</p>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500 mt-3">
        Hover a technique card to see the triggering evidence. Mapped from{' '}
        <span className="font-medium">MITRE ATT&amp;CK® v14</span>.
      </p>
    </div>
  )
}

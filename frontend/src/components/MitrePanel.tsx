import type { MitreTechnique } from '../types'

interface Props {
  techniques: MitreTechnique[]
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':       'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800/40 text-red-700 dark:text-red-400',
  'Execution':            'bg-orange-50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-800/40 text-orange-700 dark:text-orange-400',
  'Persistence':          'bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/40 text-amber-700 dark:text-amber-400',
  'Privilege Escalation': 'bg-yellow-50 dark:bg-yellow-950/20 border-yellow-200 dark:border-yellow-800/40 text-yellow-700 dark:text-yellow-400',
  'Defense Evasion':      'bg-lime-50 dark:bg-lime-950/20 border-lime-200 dark:border-lime-800/40 text-lime-700 dark:text-lime-400',
  'Credential Access':    'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-400',
  'Discovery':            'bg-teal-50 dark:bg-teal-950/20 border-teal-200 dark:border-teal-800/40 text-teal-700 dark:text-teal-400',
  'Lateral Movement':     'bg-cyan-50 dark:bg-cyan-950/20 border-cyan-200 dark:border-cyan-800/40 text-cyan-700 dark:text-cyan-400',
  'Collection':           'bg-sky-50 dark:bg-sky-950/20 border-sky-200 dark:border-sky-800/40 text-sky-700 dark:text-sky-400',
  'Command and Control':  'bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800/40 text-blue-700 dark:text-blue-400',
  'Exfiltration':         'bg-violet-50 dark:bg-violet-950/20 border-violet-200 dark:border-violet-800/40 text-violet-700 dark:text-violet-400',
  'Impact':               'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/40 text-rose-700 dark:text-rose-400',
}

export default function MitrePanel({ techniques }: Props) {
  if (techniques.length === 0) return null

  const grouped = techniques.reduce<Record<string, MitreTechnique[]>>((acc, t) => {
    ;(acc[t.tactic] ??= []).push(t)
    return acc
  }, {})

  return (
    <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 p-4">
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
                const style = TACTIC_COLORS[t.tactic] ?? 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
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

import { useState } from 'react'
import { api } from '../api/client'
import type {
  BenchmarkReport, ModelBenchmarkResult, ClassMetrics, TechniqueResult,
} from '../types'

// ── Grade badge ────────────────────────────────────────────────────────────────
const GRADE_COLOR: Record<string, string> = {
  A: 'bg-emerald-500 text-white',
  B: 'bg-blue-500 text-white',
  C: 'bg-yellow-500 text-white',
  D: 'bg-red-600 text-white',
  'N/A': 'bg-slate-600 text-slate-300',
}

function GradeBadge({ grade }: { grade: string }) {
  return (
    <span className={`inline-flex items-center justify-center w-8 h-8 rounded-full text-sm font-bold ${GRADE_COLOR[grade] ?? GRADE_COLOR['N/A']}`}>
      {grade}
    </span>
  )
}

// ── Metric bar ─────────────────────────────────────────────────────────────────
function MetricBar({ label, value }: { label: string; value: number }) {
  const pct = Math.round(value * 100)
  const color = value >= 0.9 ? 'bg-emerald-500' : value >= 0.8 ? 'bg-blue-500' : value >= 0.65 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="mb-2">
      <div className="flex justify-between text-xs text-slate-400 mb-1">
        <span>{label}</span>
        <span className="font-mono font-semibold text-white">{pct}%</span>
      </div>
      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

// ── Confusion matrix ───────────────────────────────────────────────────────────
function ConfusionMatrix({ matrix, labels }: { matrix: number[][]; labels: string[] }) {
  if (!matrix.length) return null
  const maxVal = Math.max(...matrix.flat())
  return (
    <div className="overflow-x-auto">
      <div className="text-xs text-slate-400 mb-2">
        Rows = actual class · Columns = predicted class
      </div>
      <table className="text-xs border-collapse">
        <thead>
          <tr>
            <th className="w-6" />
            {labels.map((l, i) => (
              <th key={i} className="text-slate-400 font-normal p-1 max-w-16 truncate text-center"
                  title={l}>
                {l.split(/[\s/]/)[0]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, ri) => (
            <tr key={ri}>
              <td className="text-slate-400 pr-2 text-right text-xs max-w-20 truncate"
                  title={labels[ri]}>
                {labels[ri].split(/[\s/]/)[0]}
              </td>
              {row.map((val, ci) => {
                const intensity = maxVal ? val / maxVal : 0
                const bg = ri === ci
                  ? `rgba(16,185,129,${0.2 + intensity * 0.7})`
                  : val > 0 ? `rgba(239,68,68,${0.2 + intensity * 0.7})` : 'transparent'
                return (
                  <td key={ci} className="text-center font-mono p-1 rounded"
                      style={{ backgroundColor: bg, minWidth: '2rem' }}>
                    <span className={val > 0 ? 'text-white' : 'text-slate-600'}>{val}</span>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Per-class table ────────────────────────────────────────────────────────────
function ClassTable({ metrics }: { metrics: ClassMetrics[] }) {
  return (
    <table className="w-full text-xs text-slate-300 mt-2">
      <thead>
        <tr className="text-slate-500 border-b border-slate-700">
          <th className="text-left py-1">Class</th>
          <th className="text-right py-1">Prec</th>
          <th className="text-right py-1">Rec</th>
          <th className="text-right py-1">F1</th>
          <th className="text-right py-1">N</th>
        </tr>
      </thead>
      <tbody>
        {metrics.map(m => {
          const warn = m.class_id !== 0 && (m.recall < 0.8 || m.precision < 0.8)
          return (
            <tr key={m.class_id} className={`border-b border-slate-800 ${warn ? 'text-yellow-400' : ''}`}>
              <td className="py-1 pr-2">{m.class_name}</td>
              <td className="text-right font-mono">{(m.precision * 100).toFixed(0)}%</td>
              <td className="text-right font-mono">{(m.recall * 100).toFixed(0)}%</td>
              <td className="text-right font-mono">{(m.f1 * 100).toFixed(0)}%</td>
              <td className="text-right font-mono text-slate-500">{m.support}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

// ── MITRE coverage table ───────────────────────────────────────────────────────
function MitreCoverageTable({ results }: { results: TechniqueResult[] }) {
  const [showMissed, setShowMissed] = useState(false)
  const visible = showMissed ? results.filter(r => r.status !== 'hit') : results.slice(0, 15)
  return (
    <div>
      <div className="flex gap-2 mb-2">
        <button
          onClick={() => setShowMissed(false)}
          className={`px-2 py-1 rounded text-xs ${!showMissed ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300'}`}>
          All ({results.length})
        </button>
        <button
          onClick={() => setShowMissed(true)}
          className={`px-2 py-1 rounded text-xs ${showMissed ? 'bg-red-700 text-white' : 'bg-slate-700 text-slate-300'}`}>
          Gaps ({results.filter(r => r.status !== 'hit').length})
        </button>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-slate-500 border-b border-slate-700">
            <th className="text-left py-1 w-12">Status</th>
            <th className="text-left py-1">Description</th>
            <th className="text-left py-1 w-28">Expected</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((r, i) => (
            <tr key={i} className="border-b border-slate-800">
              <td className="py-1">
                <span className={`px-1 rounded text-xs font-mono ${
                  r.status === 'hit' ? 'bg-emerald-900 text-emerald-300' :
                  r.status === 'partial' ? 'bg-yellow-900 text-yellow-300' :
                  'bg-red-900 text-red-300'}`}>
                  {r.status}
                </span>
              </td>
              <td className="py-1 text-slate-300 pr-2 truncate max-w-xs">{r.description}</td>
              <td className="py-1 text-slate-500 font-mono text-xs">{r.expected.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!showMissed && results.length > 15 && (
        <div className="text-xs text-slate-500 mt-1">Showing 15 of {results.length} — click Gaps to see only issues</div>
      )}
    </div>
  )
}

// ── ROC mini-chart ─────────────────────────────────────────────────────────────
function RocChart({ points }: { points: { fpr: number; tpr: number }[] }) {
  if (!points.length) return null
  const W = 160, H = 100, pad = 16
  const sx = (v: number) => pad + v * (W - 2 * pad)
  const sy = (v: number) => (H - pad) - v * (H - 2 * pad)
  const pathD = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${sx(p.fpr)} ${sy(p.tpr)}`)
    .join(' ')
  return (
    <svg width={W} height={H} className="text-blue-400">
      {/* Diagonal reference */}
      <line x1={pad} y1={H - pad} x2={W - pad} y2={pad} stroke="#475569" strokeWidth={1} strokeDasharray="3,3" />
      {/* FPR=0.1 vertical guide */}
      <line x1={sx(0.1)} y1={pad} x2={sx(0.1)} y2={H - pad} stroke="#f59e0b" strokeWidth={1} strokeDasharray="2,2" />
      {/* Curve */}
      <path d={pathD} fill="none" stroke="currentColor" strokeWidth={2} />
      {/* Axes */}
      <line x1={pad} y1={H - pad} x2={W - pad} y2={H - pad} stroke="#475569" strokeWidth={1} />
      <line x1={pad} y1={pad} x2={pad} y2={H - pad} stroke="#475569" strokeWidth={1} />
      {/* Labels */}
      <text x={W / 2} y={H - 1} textAnchor="middle" fontSize={8} fill="#64748b">FPR</text>
      <text x={4} y={H / 2} textAnchor="middle" fontSize={8} fill="#64748b" transform={`rotate(-90,4,${H / 2})`}>TPR</text>
    </svg>
  )
}

// ── Single model card ──────────────────────────────────────────────────────────
function ModelCard({ result, defaultOpen }: { result: ModelBenchmarkResult; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  const [tab, setTab] = useState<'metrics' | 'matrix' | 'classes' | 'gaps' | 'dataset'>('metrics')

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-slate-750">
        <div className="flex items-center gap-3">
          <GradeBadge grade={result.grade} />
          <div>
            <div className="text-white text-sm font-medium">{result.model_name}</div>
            <div className="text-slate-400 text-xs">{result.dataset_source}</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {result.f1_macro != null && (
            <span className="text-xs text-slate-400">
              F1 <span className="font-mono text-white">{(result.f1_macro * 100).toFixed(0)}%</span>
            </span>
          )}
          {result.coverage != null && (
            <span className="text-xs text-slate-400">
              Coverage <span className="font-mono text-white">{(result.coverage * 100).toFixed(0)}%</span>
            </span>
          )}
          {result.auc_roc != null && (
            <span className="text-xs text-slate-400">
              AUC <span className="font-mono text-white">{result.auc_roc.toFixed(3)}</span>
            </span>
          )}
          <svg className={`w-4 h-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`}
               fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {open && (
        <div className="border-t border-slate-700 p-4">
          {/* Tab bar */}
          <div className="flex gap-1 mb-4 flex-wrap">
            {(['metrics', 'matrix', 'classes', 'gaps', 'dataset'] as const).map(t => {
              const hidden = (
                (t === 'matrix' && !result.confusion_matrix?.length) ||
                (t === 'classes' && !result.class_metrics?.length)
              )
              if (hidden) return null
              return (
                <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-1 text-xs rounded ${tab === t ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}>
                  {t === 'matrix' ? 'Confusion Matrix' : t === 'classes' ? 'Per Class' :
                   t === 'gaps' ? `Gaps (${result.gaps.length})` :
                   t === 'dataset' ? 'Dataset' : 'Metrics'}
                </button>
              )
            })}
          </div>

          {tab === 'metrics' && (
            <div className="space-y-1">
              {result.accuracy != null && <MetricBar label="Accuracy" value={result.accuracy} />}
              {result.precision_macro != null && <MetricBar label="Precision (macro, attack classes)" value={result.precision_macro} />}
              {result.recall_macro != null && <MetricBar label="Recall (macro, attack classes)" value={result.recall_macro} />}
              {result.f1_macro != null && <MetricBar label="F1 Score (macro)" value={result.f1_macro} />}
              {result.coverage != null && <MetricBar label="Technique Coverage" value={result.coverage} />}
              {result.auc_roc != null && <MetricBar label="ROC AUC" value={result.auc_roc} />}
              {result.tpr_at_fpr10 != null && (
                <div>
                  <MetricBar label="TPR @ FPR ≤ 10%" value={result.tpr_at_fpr10} />
                  {result.roc_curve && (
                    <div className="mt-2">
                      <RocChart points={result.roc_curve} />
                      <div className="text-xs text-slate-500 mt-1">
                        Yellow line = FPR 10% operating point
                      </div>
                    </div>
                  )}
                </div>
              )}
              {result.hits != null && (
                <div className="grid grid-cols-3 gap-2 mt-3">
                  <div className="bg-emerald-900/40 rounded p-2 text-center">
                    <div className="text-emerald-400 text-lg font-bold">{result.hits}</div>
                    <div className="text-xs text-slate-400">Full hits</div>
                  </div>
                  <div className="bg-yellow-900/40 rounded p-2 text-center">
                    <div className="text-yellow-400 text-lg font-bold">{result.partials}</div>
                    <div className="text-xs text-slate-400">Partial</div>
                  </div>
                  <div className="bg-red-900/40 rounded p-2 text-center">
                    <div className="text-red-400 text-lg font-bold">{result.misses}</div>
                    <div className="text-xs text-slate-400">Misses</div>
                  </div>
                </div>
              )}
              {result.note && (
                <div className="mt-2 text-xs text-slate-400 bg-slate-700 rounded p-2">{result.note}</div>
              )}
            </div>
          )}

          {tab === 'matrix' && result.confusion_matrix && result.class_labels && (
            <ConfusionMatrix matrix={result.confusion_matrix} labels={result.class_labels} />
          )}

          {tab === 'classes' && result.class_metrics && (
            <ClassTable metrics={result.class_metrics} />
          )}

          {tab === 'gaps' && (
            <div>
              {result.gaps.length === 0 ? (
                <div className="text-emerald-400 text-sm">No gaps detected — all thresholds met.</div>
              ) : (
                <ul className="space-y-2">
                  {result.gaps.map((g, i) => (
                    <li key={i} className="flex gap-2 text-xs text-slate-300">
                      <span className="text-yellow-400 mt-0.5 shrink-0">▶</span>
                      <span>{g}</span>
                    </li>
                  ))}
                </ul>
              )}
              {result.per_technique && (
                <div className="mt-4">
                  <div className="text-xs text-slate-400 mb-2 font-semibold">Technique-level coverage</div>
                  <MitreCoverageTable results={result.per_technique} />
                </div>
              )}
            </div>
          )}

          {tab === 'dataset' && (
            <div className="space-y-3 text-xs text-slate-300">
              <div>
                <div className="text-slate-500 mb-1">Source</div>
                <div>{result.dataset_source}</div>
              </div>
              {result.dataset_url && (
                <div>
                  <div className="text-slate-500 mb-1">URL</div>
                  <span className="font-mono text-blue-400">{result.dataset_url}</span>
                </div>
              )}
              <div>
                <div className="text-slate-500 mb-1">Citation</div>
                <div className="text-slate-400 italic">{result.dataset_citation}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Samples</div>
                <span className="font-mono">{result.n_samples} events</span>
              </div>
              {result.per_dataset && (
                <div>
                  <div className="text-slate-500 mb-2">Per sub-dataset accuracy</div>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-500 border-b border-slate-700">
                        <th className="text-left py-1">Dataset</th>
                        <th className="text-right py-1">Acc</th>
                        <th className="text-right py-1">Correct</th>
                        <th className="text-right py-1">Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(result.per_dataset).map(([ds, v]) => (
                        <tr key={ds} className="border-b border-slate-800">
                          <td className="py-1 pr-2">
                            <div>{ds}</div>
                            <div className="text-slate-600 text-xs truncate max-w-xs">{v.citation}</div>
                          </td>
                          <td className="text-right font-mono">{(v.accuracy * 100).toFixed(0)}%</td>
                          <td className="text-right font-mono">{v.correct}</td>
                          <td className="text-right font-mono">{v.total}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main panel ─────────────────────────────────────────────────────────────────
export default function ModelQualityPanel() {
  const [report, setReport] = useState<BenchmarkReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await api.runBenchmark()
      setReport(r)
    } catch (e: any) {
      setError(e.message ?? 'Benchmark failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-400 mt-1">
            Evaluates LMD, MITRE mapper, and Isolation Forest against ground-truth
            events structured after{' '}
            <span className="text-blue-400 font-mono">OTRF/Security-Datasets</span>
            {' '}and{' '}
            <span className="text-blue-400 font-mono">MITRE ATT&CK KB v14</span>.
          </p>
        </div>
        <button
          onClick={run}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white rounded text-sm font-medium transition-colors shrink-0">
          {loading ? (
            <>
              <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Running…
            </>
          ) : 'Run Benchmark'}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded p-3 text-sm">{error}</div>
      )}

      {!report && !loading && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-8 text-center">
          <div className="text-4xl mb-3">🔬</div>
          <div className="text-slate-300 font-medium mb-1">No benchmark results yet</div>
          <div className="text-slate-500 text-sm">
            Click "Run Benchmark" to evaluate all models against the ground-truth dataset.
            This takes 5–15 seconds.
          </div>
        </div>
      )}

      {report && (
        <>
          {/* Overall summary bar */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 flex items-center gap-6 flex-wrap">
            <div className="flex items-center gap-3">
              <GradeBadge grade={report.overall_grade} />
              <div>
                <div className="text-white font-semibold">Overall Grade</div>
                <div className="text-slate-400 text-xs">
                  Run at {new Date(report.run_at).toLocaleString()}
                </div>
              </div>
            </div>
            <div className="flex-1 min-w-48">
              <div className="text-xs text-slate-400 mb-1">Recommendations</div>
              <ul className="space-y-1">
                {report.recommendations.slice(0, 3).map((r, i) => (
                  <li key={i} className="flex gap-2 text-xs text-slate-300">
                    <span className="text-blue-400 shrink-0">▶</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Three model cards */}
          <ModelCard result={report.lmd} defaultOpen />
          <ModelCard result={report.mitre} />
          <ModelCard result={report.anomaly} />

          {/* Dataset provenance footer */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <div className="text-xs font-semibold text-slate-400 mb-3 uppercase tracking-wide">
              Benchmark Dataset Provenance
            </div>
            <div className="grid grid-cols-1 gap-1">
              {Object.entries(report.benchmark_datasets).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <span className="text-blue-400 font-mono shrink-0">{k}</span>
                  <span className="text-slate-500">—</span>
                  <span className="text-slate-400">{v}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

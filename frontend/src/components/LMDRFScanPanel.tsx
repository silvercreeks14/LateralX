import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api } from '../api/client'
import type { LMDGraphData, LMDRFScanResult } from '../types'

const ATTACK_LEGEND = [
  { label: 'Zerologon', color: '#e11d48' },
  { label: 'Log4Shell', color: '#f59e0b' },
  { label: 'Kerberoasting', color: '#8b5cf6' },
  { label: 'Pass-the-Hash', color: '#10b981' },
]

function LMDAttackGraph({
  graph,
  suspiciousEdges,
  downloading,
  onDownload,
}: {
  graph: LMDGraphData
  suspiciousEdges: number
  downloading: boolean
  onDownload: () => void
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    const elements = [
      ...graph.nodes.map(node => ({
        group: 'nodes' as const,
        data: {
          ...node.data,
          role: node.data.role ?? 'Normal',
        },
        classes: (node.data.role ?? 'Normal').toLowerCase(),
      })),
      ...graph.edges.map(edge => ({
        group: 'edges' as const,
        data: {
          ...edge.data,
          suspicious: Boolean(edge.data.suspicious),
        },
        classes: edge.data.suspicious ? 'suspicious' : 'normal',
      })),
    ]

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            width: 28,
            height: 28,
            'background-color': '#7dd3fc',
            'border-width': 2,
            'border-color': '#e0f2fe',
            color: '#dbeafe',
            'font-size': 9,
            'font-family': 'system-ui, sans-serif',
            'text-outline-color': '#111827',
            'text-outline-width': 2,
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 5,
          },
        },
        {
          selector: 'node.attacker',
          style: {
            shape: 'triangle',
            'background-color': '#991b1b',
            'border-color': '#fecaca',
            width: 38,
            height: 38,
          },
        },
        {
          selector: 'node.victim',
          style: {
            shape: 'round-rectangle',
            'background-color': '#f97316',
            'border-color': '#fed7aa',
            width: 36,
            height: 30,
          },
        },
        {
          selector: 'edge',
          style: {
            label: 'data(label)',
            width: 1.4,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            color: '#cbd5e1',
            'font-size': 8,
            'text-outline-color': '#111827',
            'text-outline-width': 2,
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: 'edge.suspicious',
          style: {
            width: 2.5,
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
          },
        },
      ],
      layout: {
        name: graph.nodes.length > 120 ? 'concentric' : 'cose',
        animate: false,
        padding: 70,
        nodeRepulsion: 9000,
        idealEdgeLength: 130,
        edgeElasticity: 80,
        gravity: 0.18,
        numIter: 900,
      } as cytoscape.LayoutOptions,
      minZoom: 0.08,
      maxZoom: 3,
      wheelSensitivity: 0.12,
    })

    cy.ready(() => {
      cy.fit(undefined, 60)
      if (graph.nodes.length > 80) cy.zoom(Math.max(cy.zoom() * 0.8, 0.08))
    })

    return () => cy.destroy()
  }, [graph])

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
      <div className="flex items-center justify-between gap-4 px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 flex-wrap">
        <h3 className="font-semibold text-slate-700 dark:text-slate-100">LMD Model result</h3>
        <div className="flex items-center gap-4 text-sm text-slate-500 flex-wrap">
          <button
            onClick={onDownload}
            disabled={downloading}
            className="px-4 py-1.5 rounded-lg border border-blue-200 dark:border-blue-800/60 bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 font-semibold disabled:opacity-50"
          >
            {downloading ? 'Downloading...' : 'Download Graph'}
          </button>
          <span className="hidden sm:block h-6 w-px bg-slate-200 dark:bg-slate-800" />
          <span>Attacker</span>
          <span>Victim</span>
          <span>Normal</span>
        </div>
      </div>

      <div className="flex items-center justify-between gap-4 px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 flex-wrap">
        <div className="flex items-center gap-3 text-sm text-slate-600 dark:text-slate-300 flex-wrap">
          <span className="font-semibold text-slate-700 dark:text-slate-200">Detected Attacks:</span>
          {ATTACK_LEGEND.map(item => (
            <span key={item.label} className="inline-flex items-center gap-1.5">
              <span className="h-3.5 w-3.5 rounded-full" style={{ background: item.color }} />
              {item.label}
            </span>
          ))}
        </div>
        <span className="text-xs text-slate-500">{suspiciousEdges} suspicious edges</span>
      </div>

      <div className="relative h-[560px] bg-slate-950">
        <div ref={containerRef} className="absolute inset-0" />
      </div>
    </div>
  )
}

interface Props {
  ingestedFile?: File | null
}

export default function LMDRFScanPanel({ ingestedFile }: Props) {
  const [file, setFile] = useState<File | null>(ingestedFile ?? null)
  const [result, setResult] = useState<LMDRFScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  const graphSummary = useMemo(() => {
    const graph = result?.graph_data
    if (!graph) return { nodes: 0, edges: 0, suspiciousEdges: 0 }
    return {
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      suspiciousEdges: graph.edges.filter(e => e.data.suspicious).length,
    }
  }, [result])

  useEffect(() => {
    if (ingestedFile) {
      setFile(ingestedFile)
      setResult(null)
      setError(null)
    }
  }, [ingestedFile])

  const runScan = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await api.runLMDRFScan(file))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'LMD RF scan failed')
    } finally {
      setLoading(false)
    }
  }

  const downloadGraph = async () => {
    setDownloading(true)
    setError(null)
    try {
      await api.downloadLMDAttackGraph()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Attack graph download failed')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h3 className="text-slate-900 dark:text-white font-semibold">LMD Random Forest Scan</h3>
            <p className="text-slate-500 text-sm mt-0.5">
              Uses the latest CSV from Data Ingestion. The LMD parser and RF model only run when this scan is started.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <label className="cursor-pointer inline-flex items-center justify-center px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800">
              Choose Different CSV
              <input
                type="file"
                accept=".csv,text/csv"
                className="hidden"
                onChange={e => {
                  setFile(e.target.files?.[0] ?? null)
                  setResult(null)
                  setError(null)
                }}
              />
            </label>
            <button
              onClick={runScan}
              disabled={!file || loading}
              className="px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ background: '#00F0FF', color: '#0f172a' }}
            >
              {loading ? 'Scanning...' : 'Run Scan'}
            </button>
          </div>
        </div>

        {file && (
          <div className="mt-4 text-xs text-slate-500">
            Ready for LMD RF scan: <span className="font-mono text-slate-700 dark:text-slate-300">{file.name}</span>
            {ingestedFile && file === ingestedFile && (
              <span className="ml-2 rounded bg-sky-50 dark:bg-sky-950/30 px-2 py-0.5 text-sky-700 dark:text-sky-300">
                from Data Ingestion
              </span>
            )}
          </div>
        )}

        {!file && (
          <div className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800/40 bg-amber-50 dark:bg-amber-950/20 px-3 py-2 text-sm text-amber-700 dark:text-amber-300">
            Upload or choose an LMD-labelled Sysmon CSV in Data Ingestion first, then run this scan here.
          </div>
        )}

        {error && (
          <div className="mt-4 rounded-lg border border-red-200 dark:border-red-800/40 bg-red-50 dark:bg-red-950/20 px-3 py-2 text-sm text-red-700 dark:text-red-300">
            {error}
          </div>
        )}
      </div>

      {result && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {[
              { label: 'Parsed events', value: result.events_parsed },
              { label: 'Anomalies', value: result.anomaly_count },
              { label: 'Graph nodes', value: graphSummary.nodes },
              { label: 'Graph edges', value: graphSummary.edges },
            ].map(item => (
              <div key={item.label} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
                <div className="text-2xl font-bold text-slate-900 dark:text-white">{item.value}</div>
                <div className="text-xs text-slate-500 mt-1">{item.label}</div>
              </div>
            ))}
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h3 className="text-slate-900 dark:text-white font-semibold">Detected LMD Anomalies</h3>
                <p className="text-xs text-slate-500 mt-0.5">{result.filename}</p>
              </div>
            </div>

            {result.anomalies.length === 0 ? (
              <div className="rounded-lg bg-slate-50 dark:bg-slate-800/50 px-3 py-3 text-sm text-slate-600 dark:text-slate-300">
                No LMD anomalies detected.
              </div>
            ) : (
              <ul className="space-y-2">
                {result.anomalies.map((anomaly, i) => (
                  <li key={`${anomaly}-${i}`} className="rounded-lg border border-red-200 dark:border-red-800/40 bg-red-50 dark:bg-red-950/20 px-3 py-2 text-sm text-red-800 dark:text-red-200">
                    {anomaly}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <LMDAttackGraph
            graph={result.graph_data}
            suspiciousEdges={graphSummary.suspiciousEdges}
            downloading={downloading}
            onDownload={downloadGraph}
          />
        </>
      )}
    </div>
  )
}

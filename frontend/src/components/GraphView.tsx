import { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import type { GraphData, ForensicEvent, ScenarioStep } from '../types'
import { api } from '../api/client'

interface Props {
  graphData: GraphData | null
  activeCaseId?: string | null
  selectedUploadId?: number | null
}

interface NodeDetail {
  id: string
  type: 'host' | 'user'
  subtype?: string
  suspicious: boolean
  connections: string[]
  eventCount: number
  firstSeen: string | null
  activity: ForensicEvent[]
  activityLoading: boolean
}

const LAYOUTS = [
  { id: 'breadthfirst',  label: 'Attack Path' },
  { id: 'cose',          label: 'Force' },
  { id: 'grid',          label: 'Grid' },
  { id: 'circle',        label: 'Circle' },
] as const

type LayoutId = typeof LAYOUTS[number]['id']

const STAGE_META: Record<string, { label: string; border: string; bg: string; text: string; order: number }> = {
  initial_access:       { label: 'Initial Access',       border: '#D97706', bg: '#D9770610', text: '#fcd34d', order: 0 },
  execution:            { label: 'Execution',             border: '#7C3AED', bg: '#7C3AED10', text: '#c4b5fd', order: 1 },
  privilege_escalation: { label: 'Privilege Escalation',  border: '#BE185D', bg: '#BE185D10', text: '#f9a8d4', order: 2 },
  compromise:           { label: 'Compromise',            border: '#DC2626', bg: '#DC262610', text: '#fca5a5', order: 3 },
}

function KillChainPanel({
  story,
  onHighlight,
  onClear,
  activeStage,
}: {
  story: ScenarioStep[]
  onHighlight: (stage: string, nodes: string[]) => void
  onClear: () => void
  activeStage: string | null
}) {
  const byStage: Record<string, ScenarioStep[]> = {}
  for (const step of story) {
    if (!byStage[step.attack_stage]) byStage[step.attack_stage] = []
    byStage[step.attack_stage].push(step)
  }

  const stages = Object.keys(byStage).sort(
    (a, b) => (STAGE_META[a]?.order ?? 9) - (STAGE_META[b]?.order ?? 9),
  )

  return (
    <div className="w-72 border-l border-slate-200 dark:border-slate-800 flex flex-col bg-white dark:bg-slate-900 text-xs overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between shrink-0">
        <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide text-xs">Kill Chain</span>
        {activeStage && (
          <button onClick={onClear} className="text-slate-500 hover:text-slate-300 text-xs">
            Clear
          </button>
        )}
      </div>

      <div className="overflow-y-auto flex-1 flex flex-col gap-3 p-3">
        {stages.map(stage => {
          const meta  = STAGE_META[stage] ?? { label: stage, border: '#64748b', bg: '#64748b10', text: '#94a3b8', order: 9 }
          const steps = byStage[stage]
          const nodes = Array.from(new Set(steps.flatMap(s => [s.source, s.target])))
          const active = activeStage === stage

          return (
            <div
              key={stage}
              className="rounded-lg overflow-hidden cursor-pointer transition-opacity"
              style={{
                border: `1px solid ${meta.border}${active ? 'ff' : '50'}`,
                background: active ? meta.bg : 'transparent',
                opacity: activeStage && !active ? 0.45 : 1,
              }}
              onClick={() => active ? onClear() : onHighlight(stage, nodes)}
            >
              {/* Stage header */}
              <div
                className="px-3 py-1.5 flex items-center justify-between"
                style={{ borderBottom: `1px solid ${meta.border}30` }}
              >
                <span className="font-bold uppercase tracking-wide text-xs" style={{ color: meta.text }}>
                  {meta.label}
                </span>
                <span className="text-slate-500 text-xs">{steps.length} step{steps.length !== 1 ? 's' : ''}</span>
              </div>

              {/* Step list */}
              <div className="flex flex-col gap-1.5 p-2">
                {steps.map(step => (
                  <div key={step.step} className="flex flex-col gap-0.5 rounded bg-slate-100 dark:bg-slate-800/60 px-2 py-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-slate-500 dark:text-slate-500 font-mono">#{step.step}</span>
                      {step.event_id && (
                        <span className="px-1 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-400 font-mono">{step.event_id}</span>
                      )}
                      <span className="text-slate-500 font-mono ml-auto">{step.timestamp.slice(11, 19)}</span>
                    </div>
                    <div className="flex items-center gap-1 font-mono text-xs">
                      <span className="text-blue-400 truncate max-w-[80px]" title={step.source}>{step.source}</span>
                      <span className="text-slate-600">→</span>
                      <span className="text-red-400 truncate max-w-[80px]" title={step.target}>{step.target}</span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-500 leading-snug line-clamp-2">{step.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </div>

      <div className="px-3 py-2 border-t border-slate-200 dark:border-slate-800 text-slate-500 text-xs shrink-0 text-center">
        Click a stage to highlight nodes on graph
      </div>
    </div>
  )
}

export default function GraphView({ graphData, activeCaseId, selectedUploadId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null)
  const [layout, setLayout] = useState<LayoutId>('breadthfirst')
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [showKillChain, setShowKillChain] = useState(false)
  const [activeStage, setActiveStage] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [searchHits, setSearchHits] = useState(0)

  const panelOpen = selectedNode !== null
  useEffect(() => {
    requestAnimationFrame(() => { cyRef.current?.resize() })
  }, [panelOpen, showKillChain])

  const buildCy = useCallback(() => {
    if (!containerRef.current || !graphData) return

    cyRef.current?.destroy()
    cyRef.current = null

    const allNodes = graphData.elements.nodes
    const allEdges = graphData.elements.edges

    const nodes = showSuspiciousOnly
      ? allNodes.filter(n => n.data.suspicious || graphData.suspicious_users.includes(n.data.id))
      : allNodes
    const nodeIds = new Set(nodes.map(n => n.data.id))
    const edges = showSuspiciousOnly
      ? allEdges.filter(e => e.data.suspicious && nodeIds.has(e.data.source) && nodeIds.has(e.data.target))
      : allEdges.filter(e => nodeIds.has(e.data.source) && nodeIds.has(e.data.target))

    setNodeCount(nodes.length)
    setEdgeCount(edges.length)

    const layoutConfig: Record<LayoutId, cytoscape.LayoutOptions> = {
      breadthfirst:  { name: 'breadthfirst', directed: true, padding: 40, spacingFactor: 1.4, animate: false },
      cose:          { name: 'cose', animate: false, nodeRepulsion: () => 10000, idealEdgeLength: () => 140, padding: 40 },
      grid:          { name: 'grid', padding: 40, animate: false },
      circle:        { name: 'circle', padding: 40, animate: false },
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        {
          selector: 'node.host',
          style: {
            shape: 'round-rectangle',
            'background-color': '#1D4ED8',
            label: 'data(label)',
            color: '#ffffff',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            width: 130,
            height: 38,
            'text-wrap': 'ellipsis',
            'text-max-width': '118px',
            'border-width': 2,
            'border-color': '#1E40AF',
          },
        },
        {
          selector: 'node.server',
          style: {
            shape: 'rectangle',
            'background-color': '#92400E',
            'border-color': '#78350F',
          },
        },
        {
          selector: 'node.user',
          style: {
            shape: 'ellipse',
            'background-color': '#059669',
            label: 'data(label)',
            color: '#ffffff',
            'font-size': '11px',
            'text-valign': 'center',
            'text-halign': 'center',
            width: 110,
            height: 38,
            'text-wrap': 'ellipsis',
            'text-max-width': '98px',
            'border-width': 2,
            'border-color': '#047857',
          },
        },
        {
          selector: 'node.external_ip',
          style: {
            shape: 'hexagon',
            'background-color': '#D97706',
            'border-color': '#92400E',
            'border-width': 2,
            label: 'data(label)',
            color: '#ffffff',
            'font-size': '10px',
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            width: 120,
            height: 42,
            'text-wrap': 'ellipsis',
            'text-max-width': '108px',
          },
        },
        {
          selector: 'node.suspicious',
          style: {
            'background-color': '#DC2626',
            'border-color': '#991B1B',
            'border-width': 3,
          },
        },
        {
          selector: 'node:selected',
          style: { 'border-color': '#FBBF24', 'border-width': 4 },
        },
        {
          selector: 'edge',
          style: {
            'line-color': '#94A3B8',
            'target-arrow-color': '#94A3B8',
            'target-arrow-shape': 'triangle',
            'source-arrow-shape': 'none',
            'arrow-scale': 1.6,
            'curve-style': 'bezier',
            width: 2,
            label: 'data(seq)',
            'font-size': '10px',
            'font-weight': 'bold',
            color: '#475569',
            'text-background-color': '#f8fafc',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-border-width': 1,
            'text-border-color': '#cbd5e1',
            'text-border-opacity': 1,
          },
        },
        {
          selector: 'edge[?suspicious]',
          style: {
            'line-color': '#DC2626',
            'target-arrow-color': '#DC2626',
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4],
            width: 3,
            color: '#DC2626',
            'text-background-color': '#450a0a',
            'text-border-color': '#991B1B',
          },
        },
        {
          selector: 'edge:selected',
          style: { 'line-color': '#FBBF24', 'target-arrow-color': '#FBBF24', width: 4 },
        },
        {
          selector: 'edge[attack_stage="initial_access"]',
          style: {
            'line-color': '#D97706', 'target-arrow-color': '#D97706',
            'line-style': 'dashed', 'line-dash-pattern': [10, 4], width: 3,
            label: 'Initial Access', 'font-size': '9px', color: '#F59E0B',
            'text-background-color': '#451a03', 'text-background-opacity': 0.95,
            'text-background-padding': '2px', 'text-border-width': 1,
            'text-border-color': '#92400E', 'text-border-opacity': 1,
          },
        },
        {
          selector: 'edge[attack_stage="execution"]',
          style: {
            'line-color': '#7C3AED', 'target-arrow-color': '#7C3AED',
            'line-style': 'dashed', 'line-dash-pattern': [10, 4], width: 3,
            label: 'Execution', 'font-size': '9px', color: '#A78BFA',
            'text-background-color': '#2e1065', 'text-background-opacity': 0.95,
            'text-background-padding': '2px', 'text-border-width': 1,
            'text-border-color': '#5B21B6', 'text-border-opacity': 1,
          },
        },
        {
          selector: 'edge[attack_stage="privilege_escalation"]',
          style: {
            'line-color': '#BE185D', 'target-arrow-color': '#BE185D',
            'line-style': 'dashed', 'line-dash-pattern': [10, 4], width: 4,
            label: 'Priv Esc', 'font-size': '9px', color: '#F472B6',
            'text-background-color': '#4a044e', 'text-background-opacity': 0.95,
            'text-background-padding': '2px', 'text-border-width': 1,
            'text-border-color': '#9D174D', 'text-border-opacity': 1,
          },
        },
        {
          selector: 'edge[attack_stage="compromise"]',
          style: {
            'line-color': '#7F1D1D', 'target-arrow-color': '#7F1D1D',
            'line-style': 'dashed', 'line-dash-pattern': [6, 3], width: 4,
            label: 'Compromise', 'font-size': '9px', color: '#FCA5A5',
            'text-background-color': '#450a0a', 'text-background-opacity': 0.95,
            'text-background-padding': '2px', 'text-border-width': 1,
            'text-border-color': '#7F1D1D', 'text-border-opacity': 1,
          },
        },
        {
          selector: 'node.target',
          style: { 'background-color': '#7F1D1D', 'border-color': '#450A0A', 'border-width': 4 },
        },
        {
          selector: '.faded',
          style: { opacity: 0.15 },
        },
        {
          selector: 'node.search-hit',
          style: { 'border-color': '#FBBF24', 'border-width': 4, 'border-opacity': 1 },
        },
      ],
      layout: layoutConfig[layout],
    })

    cyRef.current = cy

    cy.nodes().forEach(node => {
      const deg = Math.max(node.degree(false), 1)
      const isHost = node.hasClass('host') || node.hasClass('server')
      const baseW = isHost ? 130 : node.hasClass('user') ? 110 : 120
      const scale = 1 + Math.min((deg - 1) * 0.07, 0.45)
      node.style({ width: Math.round(baseW * scale), height: Math.round(38 * scale) })
    })

    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      cy.elements().addClass('faded')
      node.removeClass('faded')
      node.connectedEdges().removeClass('faded')
      node.neighborhood().removeClass('faded')

      const connectedEdges = node.connectedEdges()
      const neighbours = node.neighborhood().nodes()
      const edgeCountSum = connectedEdges.reduce(
        (sum: number, e: cytoscape.EdgeSingular) => sum + (Number(e.data('count')) || 1), 0,
      )
      const timestamps = connectedEdges
        .map((e: cytoscape.EdgeSingular) => e.data('timestamp') as string)
        .filter(Boolean).sort()

      const nodeId   = node.data('id')   as string
      const nodeType = node.data('type') as 'host' | 'user'

      setSelectedNode({
        id: nodeId, type: nodeType, subtype: node.data('subtype'),
        suspicious: node.data('suspicious'),
        connections: neighbours.map((n: cytoscape.NodeSingular) => n.data('label')),
        eventCount: edgeCountSum,
        firstSeen: timestamps[0] ? timestamps[0].slice(0, 19).replace('T', ' ') : null,
        activity: [], activityLoading: true,
      })

      if (nodeId === 'unknown_user') {
        setSelectedNode(prev => prev && prev.id === nodeId ? { ...prev, activityLoading: false } : prev)
        return
      }

      const params: Record<string, string> = nodeType === 'host'
        ? { host: nodeId, limit: '100' }
        : { user: nodeId, limit: '100' }
      if (selectedUploadId != null) params.upload_id = String(selectedUploadId)
      api.getEvents(params, activeCaseId ?? null)
        .then(events => {
          setSelectedNode(prev => prev && prev.id === nodeId
            ? { ...prev, activity: events, activityLoading: false } : prev)
        })
        .catch(() => {
          setSelectedNode(prev => prev && prev.id === nodeId
            ? { ...prev, activityLoading: false } : prev)
        })
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) { cy.elements().removeClass('faded'); setSelectedNode(null) }
    })
  }, [graphData, layout, showSuspiciousOnly, activeCaseId, selectedUploadId])

  useEffect(() => {
    buildCy()
    return () => { cyRef.current?.destroy(); cyRef.current = null }
  }, [buildCy])

  const fitGraph        = () => cyRef.current?.fit(undefined, 40)
  const zoomIn          = () => cyRef.current?.zoom({ level: (cyRef.current.zoom() || 1) * 1.3, renderedPosition: { x: containerRef.current!.clientWidth / 2, y: containerRef.current!.clientHeight / 2 } })
  const zoomOut         = () => cyRef.current?.zoom({ level: (cyRef.current.zoom() || 1) * 0.75, renderedPosition: { x: containerRef.current!.clientWidth / 2, y: containerRef.current!.clientHeight / 2 } })
  const focusSuspicious = () => {
    if (!cyRef.current) return
    const sus = cyRef.current.nodes('.suspicious')
    if (sus.length === 0) return
    cyRef.current.elements().addClass('faded')
    sus.removeClass('faded'); sus.connectedEdges().removeClass('faded')
    sus.neighborhood().removeClass('faded')
    cyRef.current.fit(sus.closedNeighborhood(), 60)
  }

  const handleHighlight = useCallback((stage: string, nodeIds: string[]) => {
    setActiveStage(stage)
    setSelectedNode(null)
    const cy = cyRef.current
    if (!cy) return
    cy.elements().addClass('faded')
    nodeIds.forEach(id => {
      const el = cy.getElementById(id)
      el.removeClass('faded')
      el.connectedEdges().filter(`[attack_stage="${stage}"]`).removeClass('faded')
    })
    const targets = cy.collection(nodeIds.map(id => cy.getElementById(id)).filter(el => el.length > 0))
    if (targets.length > 0) cy.fit(targets, 60)
  }, [])

  const handleClear = useCallback(() => {
    setActiveStage(null)
    cyRef.current?.elements().removeClass('faded')
  }, [])

  const handleSearch = useCallback((term: string) => {
    setSearchTerm(term)
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().removeClass('search-hit')
    cy.elements().removeClass('faded')
    setActiveStage(null)
    if (!term.trim()) { setSearchHits(0); return }
    const lower = term.toLowerCase()
    const hits = cy.nodes().filter(n =>
      ((n.data('label') as string) ?? '').toLowerCase().includes(lower) ||
      ((n.data('id') as string) ?? '').toLowerCase().includes(lower),
    )
    setSearchHits(hits.length)
    if (hits.length > 0) {
      cy.elements().addClass('faded')
      hits.forEach(n => {
        n.removeClass('faded')
        n.addClass('search-hit')
        n.connectedEdges().removeClass('faded')
        n.neighborhood().removeClass('faded')
      })
      cy.fit(hits.closedNeighborhood(), 60)
    }
  }, [])

  const exportPng = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const png = cy.png({ full: true, scale: 2 })
    const a = document.createElement('a')
    a.href = png
    a.download = `attack-graph-${activeCaseId ?? 'export'}.png`
    a.click()
  }, [activeCaseId])

  if (!graphData) {
    return (
      <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-16 flex flex-col items-center gap-3 text-center">
        <svg className="h-12 w-12 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
        <p className="text-sm text-slate-500">No events loaded — upload a log file or PCAP to generate the attack graph.</p>
      </div>
    )
  }

  const hasSuspicious = graphData.suspicious_users.length > 0
  const hasScenario   = (graphData.scenario_story?.length ?? 0) > 0

  return (
    <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden">

      {/* Toolbar */}
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-3">

        {/* Stats */}
        <div className="flex items-center gap-3 text-xs text-slate-500">
          <span className="font-medium text-slate-700 dark:text-slate-300">{nodeCount} nodes</span>
          <span>{edgeCount} edges</span>
          <span>{graphData.total_logon_events} events</span>
          {(graphData.scenario_links ?? 0) > 0 && (
            <span className="text-amber-500 dark:text-amber-400 font-semibold">
              {graphData.scenario_links} scenario link{graphData.scenario_links !== 1 ? 's' : ''}
            </span>
          )}
          {hasSuspicious && (
            <span className="text-red-500 dark:text-red-400 font-semibold">
              {graphData.suspicious_users.length} suspicious
            </span>
          )}
        </div>

        {/* Node search */}
        <div className="relative">
          <input
            type="text"
            value={searchTerm}
            onChange={e => handleSearch(e.target.value)}
            placeholder="Search nodes…"
            className="h-7 pl-7 pr-6 text-xs rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500 w-36"
          />
          <svg className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {searchTerm && (
            <span className={`absolute right-1.5 top-1/2 -translate-y-1/2 text-xs font-bold ${searchHits > 0 ? 'text-amber-500' : 'text-slate-400'}`}>
              {searchHits}
            </span>
          )}
        </div>

        <div className="flex-1" />

        {/* Layout selector */}
        <div className="flex items-center gap-1 text-xs">
          <span className="text-slate-500 mr-1">Layout:</span>
          {LAYOUTS.map(l => (
            <button
              key={l.id}
              onClick={() => setLayout(l.id)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                layout === l.id ? 'bg-blue-600 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
              }`}
            >
              {l.label}
            </button>
          ))}
        </div>

        {/* Kill Chain toggle — only visible when scenario data exists */}
        {hasScenario && (
          <button
            onClick={() => {
              setShowKillChain(v => !v)
              if (showKillChain) handleClear()
            }}
            className={`text-xs px-3 py-1 rounded font-medium border transition-colors ${
              showKillChain
                ? 'bg-amber-700 text-white border-amber-700'
                : 'border-amber-700/40 text-amber-400 hover:bg-amber-950/20'
            }`}
          >
            Kill Chain
          </button>
        )}

        {hasSuspicious && (
          <button
            onClick={() => setShowSuspiciousOnly(v => !v)}
            className={`text-xs px-3 py-1 rounded font-medium border transition-colors ${
              showSuspiciousOnly
                ? 'bg-red-600 text-white border-red-600'
                : 'border-red-800/40 text-red-400 hover:bg-red-950/20'
            }`}
          >
            {showSuspiciousOnly ? 'All paths' : 'Suspicious only'}
          </button>
        )}

        {/* Labels toggle */}
        <div className="flex items-center gap-1">
          <button onClick={zoomIn}   className="w-7 h-7 flex items-center justify-center rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 text-sm font-bold">+</button>
          <button onClick={zoomOut}  className="w-7 h-7 flex items-center justify-center rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 text-sm font-bold">&#8722;</button>
          <button onClick={fitGraph} className="px-2.5 h-7 flex items-center justify-center rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 text-xs">Fit</button>
          {hasSuspicious && (
            <button onClick={focusSuspicious} className="px-2.5 h-7 flex items-center justify-center rounded bg-orange-950/20 hover:bg-orange-950/30 text-orange-400 text-xs font-medium">Focus</button>
          )}
          <button
            onClick={exportPng}
            className="w-7 h-7 flex items-center justify-center rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 text-sm"
            title="Export graph as PNG"
          >
            ↓
          </button>
        </div>
      </div>

      {/* Complexity banner */}
      {nodeCount > 25 && !showSuspiciousOnly && hasSuspicious && (
        <div className="px-4 py-2 bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800/40 flex items-center gap-2 text-xs text-amber-700 dark:text-amber-400">
          <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>
            Large graph ({nodeCount} nodes) — use{' '}
            <button className="underline font-semibold" onClick={() => setShowSuspiciousOnly(true)}>Suspicious only</button>
            {' '}or search to focus on specific nodes.
          </span>
        </div>
      )}

      {/* Graph canvas + panels */}
      <div className="flex" style={{ height: 560 }}>
        <div ref={containerRef} className="flex-1" />

        {/* Kill Chain side panel — sits alongside the graph, does not replace it */}
        {showKillChain && hasScenario && (
          <KillChainPanel
            story={graphData.scenario_story!}
            onHighlight={handleHighlight}
            onClear={handleClear}
            activeStage={activeStage}
          />
        )}

        {/* Node detail side panel */}
        {!showKillChain && selectedNode && (
          <div className="w-72 border-l border-slate-200 dark:border-slate-800 flex flex-col text-xs bg-white dark:bg-slate-900">
            <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between shrink-0">
              <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide text-xs">Node Detail</span>
              <button
                onClick={() => { cyRef.current?.elements().removeClass('faded'); setSelectedNode(null) }}
                className="text-slate-500 hover:text-slate-700 dark:text-slate-300 text-sm"
              >
                &#10005;
              </button>
            </div>

            <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex flex-col gap-2 shrink-0">
              <div>
                <p className="text-slate-500 mb-0.5">Name</p>
                <p className="font-mono text-slate-800 dark:text-slate-200 break-all">{selectedNode.id}</p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                  selectedNode.type === 'host' ? 'bg-blue-900/30 text-blue-400' : 'bg-emerald-900/30 text-emerald-400'
                }`}>{selectedNode.type}</span>
                {selectedNode.subtype && (
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                    selectedNode.subtype === 'server' ? 'bg-amber-900/30 text-amber-400' : 'bg-slate-800 text-slate-500'
                  }`}>{selectedNode.subtype}</span>
                )}
                {selectedNode.suspicious && (
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-900/30 text-red-400">suspicious</span>
                )}
              </div>
              <div className="flex gap-4">
                <div>
                  <p className="text-slate-500 mb-0.5">Events</p>
                  <p className="font-semibold text-slate-800 dark:text-slate-200">{selectedNode.eventCount}</p>
                </div>
                {selectedNode.firstSeen && (
                  <div>
                    <p className="text-slate-500 mb-0.5">First seen</p>
                    <p className="font-mono text-slate-400">{selectedNode.firstSeen}</p>
                  </div>
                )}
              </div>
              {selectedNode.connections.length > 0 && (
                <div>
                  <p className="text-slate-500 mb-1">Connected to</p>
                  <ul className="space-y-0.5">
                    {selectedNode.connections.map(c => (
                      <li key={c} className="font-mono text-slate-400 truncate" title={c}>{c}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="flex flex-col flex-1 min-h-0">
              <div className="px-4 py-2 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between shrink-0">
                <span className="font-semibold text-slate-500 uppercase tracking-wide text-xs">Activity Log</span>
                {!selectedNode.activityLoading && (
                  <span className="text-slate-600">{selectedNode.activity.length} events</span>
                )}
              </div>
              <div className="overflow-y-auto flex-1 px-2 py-1">
                {selectedNode.activityLoading ? (
                  <p className="text-slate-500 text-center py-4">Loading&#8230;</p>
                ) : selectedNode.activity.length === 0 ? (
                  <div className="px-2 py-4 text-center">
                    {selectedNode.id === 'unknown_user' ? (
                      <p className="text-slate-500 text-xs">Events in this group had no user field recorded.</p>
                    ) : selectedNode.type === 'host' ? (
                      <p className="text-slate-500 text-xs">No events from this host in the current dataset.</p>
                    ) : (
                      <p className="text-slate-500 text-xs">No events found for this user.</p>
                    )}
                  </div>
                ) : (
                  <ul className="space-y-1">
                    {selectedNode.activity.map(ev => {
                      const isProcess    = ev.event_id === '4688' || ev.event_type?.toLowerCase().includes('process')
                      const isLogon      = ev.event_id === '4624'  || ev.event_id === '4648'
                      const isSuspicious = /certutil|vssadmin|mshta|wmic|regsvr32|rundll32|mimikatz|lsass|shadow|encoded|bypass|invoke|psexec|procdump/i.test(ev.description)
                      return (
                        <li key={ev.id} className={`rounded px-2 py-1.5 border ${
                          isSuspicious ? 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800/40' :
                          isProcess    ? 'bg-purple-50 dark:bg-purple-950/20 border-purple-200 dark:border-purple-800/40' :
                          isLogon      ? 'bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800/40' :
                                         'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700'
                        }`}>
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span className={`px-1.5 py-0 rounded text-xs font-bold ${
                              isSuspicious ? 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300' :
                              isProcess    ? 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' :
                              isLogon      ? 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300' :
                                             'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
                            }`}>
                              {ev.event_id ?? ev.event_type?.slice(0, 8) ?? '&#8212;'}
                            </span>
                            <span className="text-slate-500 font-mono">{ev.timestamp.slice(11, 19)}</span>
                            {isSuspicious && <span className="text-red-400 font-bold ml-auto">!</span>}
                          </div>
                          <p className="text-slate-700 dark:text-slate-300 break-words leading-tight" style={{ wordBreak: 'break-all' }}>
                            {ev.description.slice(0, 180)}{ev.description.length > 180 ? '&#8230;' : ''}
                          </p>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
              <p className="text-slate-500 text-center py-2 border-t border-slate-200 dark:border-slate-800 shrink-0">Click canvas to deselect</p>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="px-4 py-2.5 border-t border-slate-200 dark:border-slate-800 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-slate-500">
        <span className="flex items-center gap-2"><span className="inline-block w-5 h-3.5 rounded-sm bg-blue-700" /> Workstation</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 h-3.5 bg-amber-800" /> Server</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 h-3.5 rounded-full bg-emerald-600" /> User</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 h-3.5 rounded-full bg-red-600" /> Lateral mvmt</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 h-3.5 bg-amber-600" style={{ clipPath: 'polygon(25% 0%,75% 0%,100% 50%,75% 100%,25% 100%,0% 50%)' }} /> External IP</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 border-t-2 border-dashed border-amber-500" /> Initial Access</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 border-t-2 border-dashed border-violet-600" /> Execution</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 border-t-2 border-dashed border-pink-600" /> Priv Esc</span>
        <span className="flex items-center gap-2"><span className="inline-block w-5 border-t-2 border-dashed border-red-900" style={{ borderColor: '#7F1D1D' }} /> Compromise</span>
      </div>
    </div>
  )
}

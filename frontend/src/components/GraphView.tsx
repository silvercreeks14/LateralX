import { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import type { GraphData, ForensicEvent } from '../types'
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
  { id: 'breadthfirst', label: 'Attack Path' },
  { id: 'cose',         label: 'Force' },
  { id: 'grid',         label: 'Grid' },
  { id: 'circle',       label: 'Circle' },
] as const

type LayoutId = typeof LAYOUTS[number]['id']

export default function GraphView({ graphData, activeCaseId, selectedUploadId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null)
  const [layout, setLayout] = useState<LayoutId>('breadthfirst')
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)

  const panelOpen = selectedNode !== null
  useEffect(() => {
    requestAnimationFrame(() => { cyRef.current?.resize() })
  }, [panelOpen])

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
      breadthfirst: { name: 'breadthfirst', directed: true, padding: 40, spacingFactor: 1.4, animate: false },
      cose:         { name: 'cose', animate: false, nodeRepulsion: () => 10000, idealEdgeLength: () => 140, padding: 40 },
      grid:         { name: 'grid', padding: 40, animate: false },
      circle:       { name: 'circle', padding: 40, animate: false },
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
            color: '#334155',
            'text-background-color': '#1e293b',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-border-width': 1,
            'text-border-color': '#475569',
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
      ],
      layout: layoutConfig[layout],
    })

    cyRef.current = cy

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

  if (!graphData) {
    return (
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-16 flex flex-col items-center gap-3 text-center">
        <svg className="h-12 w-12 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
        <p className="text-sm text-slate-500">No events loaded — upload a log file or PCAP to generate the attack graph.</p>
      </div>
    )
  }

  const hasSuspicious = graphData.suspicious_users.length > 0

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">

      {/* Toolbar */}
      <div className="px-4 py-2.5 border-b border-slate-800 flex flex-wrap items-center gap-3">

        {/* Stats */}
        <div className="flex items-center gap-3 text-xs text-slate-500">
          <span className="font-medium text-slate-300">{nodeCount} nodes</span>
          <span>{edgeCount} edges</span>
          <span>{graphData.total_logon_events} events</span>
          {(graphData.scenario_links ?? 0) > 0 && (
            <span className="text-amber-400 font-semibold">
              {graphData.scenario_links} scenario link{graphData.scenario_links !== 1 ? 's' : ''}
            </span>
          )}
          {hasSuspicious && (
            <span className="text-red-400 font-semibold">
              {graphData.suspicious_users.length} suspicious
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
                layout === l.id ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              {l.label}
            </button>
          ))}
        </div>

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

        <div className="flex items-center gap-1">
          <button onClick={zoomIn}   className="w-7 h-7 flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-sm font-bold">+</button>
          <button onClick={zoomOut}  className="w-7 h-7 flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-sm font-bold">&#8722;</button>
          <button onClick={fitGraph} className="px-2.5 h-7 flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs">Fit</button>
          {hasSuspicious && (
            <button onClick={focusSuspicious} className="px-2.5 h-7 flex items-center justify-center rounded bg-orange-950/20 hover:bg-orange-950/30 text-orange-400 text-xs font-medium">Focus</button>
          )}
        </div>
      </div>

      {/* Graph canvas + node detail panel */}
      <div className="flex" style={{ height: 560 }}>
        <div ref={containerRef} className="flex-1" />

        {/* Node detail side panel */}
        {selectedNode && (
          <div className="w-72 border-l border-slate-800 flex flex-col text-xs bg-slate-900">
            <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between shrink-0">
              <span className="font-semibold text-slate-400 uppercase tracking-wide text-xs">Node Detail</span>
              <button
                onClick={() => { cyRef.current?.elements().removeClass('faded'); setSelectedNode(null) }}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                &#10005;
              </button>
            </div>

            <div className="px-4 py-3 border-b border-slate-800 flex flex-col gap-2 shrink-0">
              <div>
                <p className="text-slate-500 mb-0.5">Name</p>
                <p className="font-mono text-slate-200 break-all">{selectedNode.id}</p>
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
                  <p className="font-semibold text-slate-200">{selectedNode.eventCount}</p>
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
              <div className="px-4 py-2 border-b border-slate-800 flex items-center justify-between shrink-0">
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
                      const isProcess   = ev.event_id === '4688' || ev.event_type?.toLowerCase().includes('process')
                      const isLogon     = ev.event_id === '4624'  || ev.event_id === '4648'
                      const isSuspicious = /certutil|vssadmin|mshta|wmic|regsvr32|rundll32|mimikatz|lsass|shadow|encoded|bypass|invoke|psexec|procdump/i.test(ev.description)
                      return (
                        <li key={ev.id} className={`rounded px-2 py-1.5 border ${
                          isSuspicious ? 'bg-red-950/20 border-red-800/40' :
                          isProcess    ? 'bg-purple-950/20 border-purple-800/40' :
                          isLogon      ? 'bg-blue-950/20 border-blue-800/40' :
                                         'bg-slate-800 border-slate-700'
                        }`}>
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span className={`px-1.5 py-0 rounded text-xs font-bold ${
                              isSuspicious ? 'bg-red-900/40 text-red-300' :
                              isProcess    ? 'bg-purple-900/40 text-purple-300' :
                              isLogon      ? 'bg-blue-900/40 text-blue-300' :
                                             'bg-slate-700 text-slate-400'
                            }`}>
                              {ev.event_id ?? ev.event_type?.slice(0, 8) ?? '&#8212;'}
                            </span>
                            <span className="text-slate-500 font-mono">{ev.timestamp.slice(11, 19)}</span>
                            {isSuspicious && <span className="text-red-400 font-bold ml-auto">!</span>}
                          </div>
                          <p className="text-slate-300 break-words leading-tight" style={{ wordBreak: 'break-all' }}>
                            {ev.description.slice(0, 180)}{ev.description.length > 180 ? '&#8230;' : ''}
                          </p>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
              <p className="text-slate-500 text-center py-2 border-t border-slate-800 shrink-0">Click canvas to deselect</p>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="px-4 py-2.5 border-t border-slate-800 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-slate-500">
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

import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api } from '../api/client'
import type { ADEntityIntelResult, ADEntity, Upload } from '../types'

// ── IOC list ──────────────────────────────────────────────────────────────────
const KNOWN_IOCS = new Set([
  '185.220.101.47', '194.165.16.158', '23.19.227.147', '91.108.56.167',
])

const IP_RE      = /^(\d{1,3}\.){3}\d{1,3}$/
const PRIVATE_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/
const isIoc        = (n: string) => KNOWN_IOCS.has(n)
const isExternalIp = (n: string) => IP_RE.test(n) && !PRIVATE_RE.test(n)
const isInternalIp = (n: string) => IP_RE.test(n) && PRIVATE_RE.test(n)

// ── MITRE technique label map ─────────────────────────────────────────────────
const TECHNIQUE_LABEL: Record<string, string> = {
  'T1558.003': 'Kerberoasting',    'T1558.004': 'AS-REP Roasting',
  'T1558.001': 'Golden Ticket',    'T1558.002': 'Silver Ticket',
  'T1003.001': 'LSASS Dump',       'T1003.006': 'DCSync',
  'T1550.002': 'Pass-the-Hash',    'T1550.003': 'Pass-the-Ticket',
  'T1098':     'Acct Manipulation','T1543.003': 'Persistence/Svc',
  'T1134':     'Privilege Esc',    'T1134.001': 'Token Impersonation',
  'T1070.001': 'Log Tampering',    'T1021.002': 'Lateral (SMB)',
  'T1110':     'Password Spraying','T1069.002': 'Domain Recon',
  'T1087.001': 'Acct Enumeration', 'T1562.002': 'Defense Evasion',
  'T1207':     'Rogue DC',         'T1136.001': 'New Account',
}

function threatLabel(techniques: string[], flags: string[]): string {
  for (const t of techniques) {
    if (TECHNIQUE_LABEL[t]) return TECHNIQUE_LABEL[t]
  }
  const f = (flags[0] ?? '').toLowerCase()
  if (f.includes('dcsync') || f.includes('ds-replication')) return 'DCSync'
  if (f.includes('kerberos'))   return 'Kerberoasting'
  if (f.includes('credential')) return 'Credential Access'
  if (f.includes('host'))       return 'Lateral Movement'
  if (f.includes('service'))    return 'Persistence'
  if (f.includes('audit') || f.includes('log')) return 'Log Tampering'
  return 'Suspicious Activity'
}

// ── SVG icon data URIs — white stroke on solid node background ────────────────
const enc = (s: string) => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s)
const SL  = 'stroke-linecap="round" stroke-linejoin="round"'

const ICON_HOST = enc(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" ${SL}>` +
  `<rect x="2" y="3" width="20" height="14" rx="2"/>` +
  `<line x1="8" y1="21" x2="16" y2="21"/>` +
  `<line x1="12" y1="17" x2="12" y2="21"/></svg>`
)

const ICON_USER = enc(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" ${SL}>` +
  `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>` +
  `<circle cx="12" cy="7" r="4"/></svg>`
)

const ICON_THREAT = enc(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" ${SL}>` +
  `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>` +
  `<line x1="12" y1="9" x2="12" y2="13"/>` +
  `<line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
)

const ICON_IOC = enc(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" ${SL}>` +
  `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>` +
  `<line x1="12" y1="8" x2="12" y2="12"/>` +
  `<line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
)

const ICON_EXT = enc(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" ${SL}>` +
  `<circle cx="12" cy="12" r="10"/>` +
  `<line x1="2" y1="12" x2="22" y2="12"/>` +
  `<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`
)

// ── Cytoscape stylesheet ──────────────────────────────────────────────────────
// background-fit:'none' + explicit 55% dimensions = icon padded inside ring border
const CY_STYLE: cytoscape.StylesheetJsonBlock[] = [
  {
    selector: 'node',
    style: {
      shape:                      'ellipse',
      width:                      50,
      height:                     50,
      'background-color':         '#3b82f6',
      'border-width':             2.5,
      'border-color':             '#1d4ed8',
      'background-image':         ICON_HOST,
      'background-fit':           'none' as const,
      'background-width':         '55%' as unknown as number,
      'background-height':        '55%' as unknown as number,
      'background-image-opacity': 1,
      label:                      'data(label)',
      'text-valign':              'bottom' as const,
      'text-halign':              'center' as const,
      'text-margin-y':            6,
      'font-size':                12,
      'font-family':              'system-ui, sans-serif',
      'font-weight':              'bold' as const,
      color:                      '#1e293b',
      'text-outline-color':       '#f8fafc',
      'text-outline-width':       3,
      'text-max-width':           '130px',
    },
  },
  {
    selector: 'node[nodeType = "host"]',
    style: {
      'background-color': '#3b82f6',
      'border-color':     '#1d4ed8',
      'background-image': ICON_HOST,
    },
  },
  {
    selector: 'node[nodeType = "host_ip"]',
    style: {
      'background-color': '#22c55e',
      'border-color':     '#15803d',
      'background-image': ICON_HOST,
    },
  },
  {
    selector: 'node[nodeType = "user"]',
    style: {
      'background-color': '#6366f1',
      'border-color':     '#4338ca',
      'background-image': ICON_USER,
    },
  },
  {
    selector: 'node[nodeType = "group"]',
    style: {
      shape:              'diamond' as const,
      'background-color': '#a855f7',
      'border-color':     '#7c3aed',
      'background-image': ICON_USER,
    },
  },
  {
    selector: 'node[nodeType = "threat"]',
    style: {
      width:              48,
      height:             48,
      'background-color': '#f97316',
      'border-color':     '#c2410c',
      'border-width':     2,
      'background-image': ICON_THREAT,
      color:              '#7c2d12',
      'font-size':        11,
      'font-weight':      'bold' as const,
    },
  },
  {
    selector: 'node[nodeType = "ioc"]',
    style: {
      width:              50,
      height:             50,
      'background-color': '#ef4444',
      'border-color':     '#991b1b',
      'border-width':     2,
      'background-image': ICON_IOC,
      color:              '#991b1b',
      'font-weight':      'bold' as const,
    },
  },
  {
    selector: 'node[nodeType = "external_ip"]',
    style: {
      'background-color': '#64748b',
      'border-color':     '#475569',
      'background-image': ICON_EXT,
      color:              '#475569',
    },
  },
  // Pivot — largest node, darkest blue
  {
    selector: 'node[?isPivot][nodeType = "host"]',
    style: {
      width:              64,
      height:             64,
      'background-color': '#1d4ed8',
      'border-color':     '#1e3a8a',
      'border-width':     3,
      'background-image': ICON_HOST,
      color:              '#1e3a8a',
      'font-weight':      'bold' as const,
      'font-size':        13,
    },
  },
  {
    selector: 'node[?isPivot][nodeType = "user"]',
    style: {
      width:              64,
      height:             64,
      'background-color': '#1d4ed8',
      'border-color':     '#1e3a8a',
      'border-width':     3,
      'background-image': ICON_USER,
      color:              '#1e3a8a',
      'font-weight':      'bold' as const,
      'font-size':        13,
    },
  },
  {
    selector: 'node.highlighted',
    style: { 'border-width': 4, 'border-color': '#0ea5e9' },
  },
  {
    selector: 'edge',
    style: {
      width:                2,
      'line-color':         '#94a3b8',
      'target-arrow-shape': 'triangle' as const,
      'target-arrow-color': '#94a3b8',
      'curve-style':        'bezier' as const,
      'arrow-scale':        0.8,
      'line-style':         'solid' as const,
    },
  },
  {
    selector: 'edge[edgeStyle = "dashed"]',
    style: { 'line-style': 'dashed' as const, 'line-dash-pattern': [6, 3] },
  },
  {
    selector: 'edge[edgeType = "threat"]',
    style: { 'line-color': '#fb923c', 'target-arrow-color': '#fb923c' },
  },
  {
    selector: 'edge[edgeType = "ioc"]',
    style: {
      'line-color':         '#f87171',
      'target-arrow-color': '#f87171',
      'line-style':         'dashed' as const,
    },
  },
  {
    selector: 'edge[edgeType = "inferred"]',
    style: {
      'line-color':         '#cbd5e1',
      'target-arrow-color': '#cbd5e1',
      'line-style':         'dashed' as const,
      'line-dash-pattern':  [4, 4],
    },
  },
]

// ── Node label ────────────────────────────────────────────────────────────────
function nodeLabel(name: string, entityType: string): string {
  if (isIoc(name) || isExternalIp(name)) return name
  if (isInternalIp(name)) return `⌂ ${name}`
  if (entityType === 'host') return name
  return name
}

// ── Data mapping: ADEntityIntelResult → Cytoscape elements ───────────────────
function buildElements(result: ADEntityIntelResult): {
  elements: cytoscape.ElementDefinition[]
  directEdgeCount: number
  inferredEdgeCount: number
} {
  const entityIds = new Set(result.entities.map(e => e.name))
  const elements: cytoscape.ElementDefinition[] = []

  // Degree map for pivot detection
  const degreeMap = new Map<string, number>()
  for (const e of result.entities) {
    degreeMap.set(e.name, (degreeMap.get(e.name) ?? 0) + e.lateral_targets.length)
    for (const t of e.lateral_targets) {
      degreeMap.set(t, (degreeMap.get(t) ?? 0) + 1)
    }
  }
  const pivotName = [...degreeMap.entries()].reduce(
    (max, cur) => (cur[1] > max[1] ? cur : max),
    ['', 0]
  )[0]

  // Entity nodes
  for (const e of result.entities) {
    const nodeType: string = isIoc(e.name) ? 'ioc'
      : isExternalIp(e.name) ? 'external_ip'
      : isInternalIp(e.name) ? 'host_ip'
      : e.entity_type
    elements.push({
      data: {
        id:        e.name,
        label:     nodeLabel(e.name, e.entity_type),
        nodeType,
        entity:    e,
        isPivot:   e.name === pivotName && (degreeMap.get(e.name) ?? 0) >= 3,
        riskScore: e.risk_score,
      },
    })
  }

  // Extra nodes for lateral targets not in entity list
  const extraSeen = new Set<string>()
  for (const e of result.entities) {
    for (const t of e.lateral_targets) {
      if (!entityIds.has(t) && !extraSeen.has(t)) {
        extraSeen.add(t)
        elements.push({
          data: {
            id:        t,
            label:     nodeLabel(t, 'host'),
            nodeType:  isIoc(t) ? 'ioc' : isExternalIp(t) ? 'external_ip' : 'host',
            entity:    null,
            isPivot:   false,
            riskScore: 0,
          },
        })
      }
    }
  }

  // Threat nodes (synthesised for risk_score >= 70)
  const threatNodeIds = new Set<string>()
  for (const e of result.entities) {
    if (e.risk_score < 70) continue
    const tid = `__threat__${e.name}`
    threatNodeIds.add(tid)
    elements.push({
      data: {
        id:        tid,
        label:     threatLabel(e.associated_techniques, e.anomaly_flags),
        nodeType:  'threat',
        entity:    e,
        isPivot:   false,
        riskScore: e.risk_score,
        sourceId:  e.name,
      },
    })
  }

  // Direct edges from lateral movement
  const edgeSeen = new Set<string>()
  let directEdgeCount = 0

  const addEdge = (src: string, tgt: string, edgeType: string, edgeStyle: string) => {
    const key = `${src}→${tgt}`
    if (edgeSeen.has(key)) return
    edgeSeen.add(key)
    elements.push({ data: { id: key, source: src, target: tgt, edgeType, edgeStyle } })
  }

  for (const e of result.entities) {
    const highRisk  = e.risk_score >= 70
    const edgeStyle = e.risk_score >= 85 ? 'solid' : 'dashed'
    const tid       = `__threat__${e.name}`

    for (const target of e.lateral_targets) {
      const tgtExists = entityIds.has(target) || extraSeen.has(target)
      if (!tgtExists) continue

      if (highRisk && threatNodeIds.has(tid)) {
        addEdge(e.name, tid,    'threat', edgeStyle)
        addEdge(tid,    target, 'threat', edgeStyle)
      } else {
        addEdge(e.name, target, (isIoc(target) || isExternalIp(target)) ? 'ioc' : 'normal', edgeStyle)
      }
      directEdgeCount++
    }
  }

  // Inferred correlation edges when no direct lateral movement found
  let inferredEdgeCount = 0
  if (directEdgeCount === 0 && result.entities.length > 1) {
    const techMap = new Map<string, string[]>()
    for (const e of result.entities) {
      for (const t of e.associated_techniques) {
        const list = techMap.get(t) ?? []
        list.push(e.name)
        techMap.set(t, list)
      }
    }
    for (const [, names] of techMap) {
      for (let i = 0; i < names.length - 1; i++) {
        const key = `${names[i]}→${names[i + 1]}`
        if (!edgeSeen.has(key)) {
          edgeSeen.add(key)
          elements.push({
            data: { id: key, source: names[i], target: names[i + 1], edgeType: 'inferred', edgeStyle: 'dashed' },
          })
          inferredEdgeCount++
        }
      }
    }
  }

  return { elements, directEdgeCount, inferredEdgeCount }
}

// ── Hover state ───────────────────────────────────────────────────────────────
type HoverKind = 'entity' | 'threat' | 'ioc' | 'external'
interface HoverInfo {
  kind:    HoverKind
  name:    string
  entity?: ADEntity | null
  label?:  string
  score?:  number
  x: number
  y: number
}

// ── Component ─────────────────────────────────────────────────────────────────
interface Props {
  activeCaseId?: string | null
  uploads?: Upload[]
}

export default function ADThreatMap({ activeCaseId, uploads }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef        = useRef<cytoscape.Core | null>(null)
  const [result,           setResult]           = useState<ADEntityIntelResult | null>(null)
  const [loading,          setLoading]          = useState(false)
  const [error,            setError]            = useState<string | null>(null)
  const [selectedUploadId, setSelectedUploadId] = useState<number | null>(null)
  const [hover,            setHover]            = useState<HoverInfo | null>(null)
  const [edgeInfo,         setEdgeInfo]         = useState<{ direct: number; inferred: number } | null>(null)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      setResult(await api.getADEntities(activeCaseId, selectedUploadId))
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Threat map fetch failed')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!result || !containerRef.current) return

    cyRef.current?.destroy()

    const { elements, directEdgeCount, inferredEdgeCount } = buildElements(result)
    setEdgeInfo({ direct: directEdgeCount, inferred: inferredEdgeCount })

    const totalEdges = directEdgeCount + inferredEdgeCount
    const nodeCount  = result.entities.length

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: CY_STYLE,
      minZoom: 0.2,
      maxZoom: 2.5,
    })

    // Layout: cose for connected graphs, circle/grid for isolated nodes
    const layoutOptions: cytoscape.LayoutOptions =
      totalEdges > 0
        ? {
            name:            'cose',
            animate:         false,
            padding:         60,
            nodeRepulsion:   () => 8000,
            idealEdgeLength: () => 110,
            gravity:         0.25,
          } as cytoscape.LayoutOptions
        : (nodeCount <= 6
            ? { name: 'circle', animate: false, padding: 80 } as cytoscape.LayoutOptions
            : { name: 'grid',   animate: false, padding: 60 } as cytoscape.LayoutOptions
          )

    const layout = cy.layout(layoutOptions)
    layout.on('layoutstop', () => {
      // Cap auto-fit zoom — cose can zoom too tight on sparse graphs
      if (cy.zoom() > 1.4) {
        cy.zoom(1.4)
        cy.center()
      }
    })
    layout.run()

    // Hover tooltip
    cy.on('mouseover', 'node', evt => {
      const n      = evt.target
      const pos    = n.renderedPosition()
      const nt     = n.data('nodeType') as string
      const entity = n.data('entity') as ADEntity | null

      if (nt === 'threat') {
        setHover({ kind: 'threat', name: n.data('id'), label: n.data('label'), score: n.data('riskScore'), entity, x: pos.x, y: pos.y })
      } else if (nt === 'ioc') {
        setHover({ kind: 'ioc', name: n.data('id'), label: 'Blacklisted IOC', entity, x: pos.x, y: pos.y })
      } else if (nt === 'external_ip') {
        setHover({ kind: 'external', name: n.data('id'), label: 'External IP', entity, x: pos.x, y: pos.y })
      } else {
        setHover({ kind: 'entity', name: n.data('id'), entity, score: n.data('riskScore'), x: pos.x, y: pos.y })
      }
      n.addClass('highlighted')
    })
    cy.on('mouseout', 'node', evt => {
      evt.target.removeClass('highlighted')
      setHover(null)
    })

    // Click: fit neighbourhood
    cy.on('tap', 'node', evt => {
      cy.animate({ fit: { eles: evt.target.closedNeighborhood(), padding: 60 }, duration: 400 })
    })

    // Double-click canvas: reset view
    cy.on('dblclick', () => cy.animate({ fit: { eles: cy.elements(), padding: 40 }, duration: 300 }))

    cyRef.current = cy
    return () => { cy.destroy(); cyRef.current = null }
  }, [result])

  const riskColor = (score: number) =>
    score >= 70 ? 'text-red-600'
    : score >= 30 ? 'text-orange-500'
    : 'text-emerald-600'

  return (
    <div className="space-y-5">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
        <div className="flex items-start justify-between flex-wrap gap-5">
          <div className="max-w-3xl">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-slate-900 dark:text-white font-semibold text-xl">AD Threat Map</h2>
              {edgeInfo && (
                <span className="text-xs font-medium text-slate-500 bg-slate-100 dark:bg-slate-800 rounded-full px-2.5 py-1">
                  {edgeInfo.direct} confirmed / {edgeInfo.inferred} inferred links
                </span>
              )}
            </div>
            <p className="text-slate-600 dark:text-slate-400 text-sm mt-2 leading-relaxed">
              Force-directed threat intelligence graph — host/user topology with synthesized attack nodes
              and IOC correlation. Nodes with risk&nbsp;≥&nbsp;70 route through orange threat nodes.
            </p>
          </div>
          <button
            onClick={run}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold disabled:opacity-50 flex-shrink-0 shadow-sm"
            style={{ background: loading ? '#334155' : '#00F0FF', color: loading ? '#94a3b8' : '#0f172a' }}
          >
            {loading ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Loading…
              </>
            ) : 'Build Threat Map'}
          </button>
        </div>

        {(uploads ?? []).length > 1 && (
          <div className="flex items-center gap-2 mt-5 flex-wrap border-t border-slate-200 dark:border-slate-800 pt-4">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide mr-1">Evidence source</span>
            <button
              onClick={() => setSelectedUploadId(null)}
              className="px-3 py-1.5 rounded-full text-xs font-semibold border"
              style={selectedUploadId === null ? { background: '#00F0FF', color: '#0f172a', borderColor: '#00F0FF' } : { background: 'transparent', color: '#64748b', borderColor: '#cbd5e1' }}
            >All uploads</button>
            {(uploads ?? []).map(u => (
              <button key={u.id} onClick={() => setSelectedUploadId(u.id)}
                className="px-3 py-1.5 rounded-full text-xs font-semibold truncate max-w-[220px] border"
                style={selectedUploadId === u.id ? { background: '#00F0FF', color: '#0f172a', borderColor: '#00F0FF' } : { background: 'transparent', color: '#64748b', borderColor: '#cbd5e1' }}
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
          {/* Summary stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { label: 'Total Entities', value: result.total_entities,    color: 'text-slate-700 dark:text-slate-200' },
              { label: 'Compromised',    value: result.compromised_count, color: 'text-red-600 dark:text-red-400' },
              { label: 'Suspicious',     value: result.suspicious_count,  color: 'text-orange-500' },
            ].map(s => (
              <div key={s.label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">{s.label}</p>
                <p className={`text-3xl font-bold tabular-nums ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Sparse graph banner */}
          {edgeInfo && edgeInfo.direct === 0 && (
            <div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800/30 rounded-xl px-4 py-3 flex items-start gap-3">
              <svg className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <p className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed">
                {edgeInfo.inferred > 0
                  ? `No direct lateral movement detected. Showing ${edgeInfo.inferred} inferred correlation edge${edgeInfo.inferred !== 1 ? 's' : ''} between entities sharing MITRE techniques (dashed). Upload Sysmon or Windows Security event logs for direct host-to-host paths.`
                  : 'No lateral movement links found in this log sample. Entities appear isolated — this typically means events are from a single host, or no cross-host logon/network events were parsed. Try uploading Sysmon network or Windows Security logon logs.'
                }
              </p>
            </div>
          )}

          {/* Cytoscape canvas */}
          <div className="rounded-2xl overflow-hidden relative border border-slate-200 dark:border-slate-700 shadow-sm" style={{ background: '#f8fafc' }}>

            {/* Legend */}
            <div className="absolute top-4 left-4 z-10 bg-white/95 backdrop-blur rounded-xl shadow-md px-4 py-3 text-xs space-y-2" style={{ border: '1px solid #e2e8f0' }}>
              <p className="font-bold text-slate-600 uppercase tracking-wide text-[11px] mb-2">Node Types</p>
              <LegendRow color="#3b82f6" border="#1d4ed8" label="Host / Hostname" />
              <LegendRow color="#6366f1" border="#4338ca" label="User Account" />
              <LegendRow color="#1d4ed8" border="#1e3a8a" label="Pivot (most connected)" />
              <LegendRow color="#f97316" border="#c2410c" label="Threat / Attack (risk ≥ 70)" />
              <LegendRow color="#ef4444" border="#991b1b" label="IOC / Blacklisted IP" />
              <LegendRow color="#64748b" border="#475569" label="External IP" />
              <div className="border-t border-slate-200 mt-1 pt-1.5 space-y-1">
                <div className="flex items-center gap-2 text-slate-500">
                  <div className="w-6 h-px bg-slate-400" />
                  <span>Solid — confirmed (risk ≥ 85)</span>
                </div>
                <div className="flex items-center gap-2 text-slate-500">
                  <div className="w-6 h-px border-t border-dashed border-slate-400" />
                  <span>Dashed — inferred / lower risk</span>
                </div>
              </div>
            </div>

            {/* Controls hint */}
            <div className="absolute bottom-4 right-4 z-10 bg-white/90 rounded-lg px-3 py-1.5 text-[11px] text-slate-500 pointer-events-none shadow-sm">
              Click a node to focus · double-click canvas to reset
            </div>

            {/* Hover tooltip */}
            {hover && (
              <div
                className="absolute z-20 bg-white rounded-lg shadow-lg px-3 py-2.5 text-xs pointer-events-none max-w-[220px]"
                style={{ left: Math.min(hover.x + 16, 580), top: hover.y + 16, border: '1px solid #e2e8f0' }}
              >
                {hover.kind === 'threat' ? (
                  <>
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className="text-orange-500 text-base">⚠</span>
                      <p className="font-bold text-orange-700">{hover.label}</p>
                    </div>
                    {hover.entity && (
                      <p className="text-slate-500">Entity: <span className="font-mono text-slate-700">{hover.entity.name}</span></p>
                    )}
                    <p className={`font-semibold mt-0.5 ${riskColor(hover.score ?? 0)}`}>
                      Risk score: {hover.score}/100
                    </p>
                    {hover.entity?.anomaly_flags && hover.entity.anomaly_flags.length > 0 && (
                      <p className="text-slate-500 mt-1 text-[10px] leading-snug">{hover.entity.anomaly_flags[0]}</p>
                    )}
                  </>
                ) : hover.kind === 'ioc' ? (
                  <>
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className="text-red-500">🛡</span>
                      <p className="font-bold text-red-700">Blacklisted IOC</p>
                    </div>
                    <p className="font-mono text-slate-700">{hover.name}</p>
                    <p className="text-red-500 text-[10px] mt-0.5">Matches known-bad indicator list</p>
                  </>
                ) : hover.kind === 'external' ? (
                  <>
                    <p className="font-semibold text-slate-700 mb-0.5">External IP</p>
                    <p className="font-mono text-slate-600">{hover.name}</p>
                    {hover.entity && <p className="text-slate-500 mt-0.5">{hover.entity.event_count} events</p>}
                  </>
                ) : (
                  <>
                    <p className="font-semibold text-slate-800 mb-1">{hover.name}</p>
                    {hover.entity && (
                      <>
                        <p className={`font-semibold capitalize text-xs mb-0.5 ${riskColor(hover.entity.risk_score)}`}>
                          {hover.entity.risk_label} — {hover.entity.risk_score}/100
                        </p>
                        <p className="text-slate-500">{hover.entity.event_count} events · {hover.entity.entity_type}</p>
                        {hover.entity.anomaly_flags.length > 0 && (
                          <p className="text-slate-500 mt-1 text-[10px] leading-snug">{hover.entity.anomaly_flags[0]}</p>
                        )}
                        {hover.entity.associated_techniques.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {hover.entity.associated_techniques.slice(0, 3).map(t => (
                              <span key={t} className="font-mono text-[9px] px-1 py-0.5 bg-purple-50 text-purple-700 rounded border border-purple-200">{t}</span>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </>
                )}
              </div>
            )}

            <div ref={containerRef} style={{ height: '660px', width: '100%' }} />
          </div>

          {/* High-risk entity list */}
          {result.entities.filter(e => e.risk_label !== 'clean').length > 0 && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-3 uppercase tracking-wide">High-Risk Entities</p>
              <div className="space-y-2">
                {result.entities
                  .filter(e => e.risk_label !== 'clean')
                  .sort((a, b) => b.risk_score - a.risk_score)
                  .slice(0, 10)
                  .map(e => (
                    <div key={e.name} className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${e.risk_label === 'compromised' ? 'bg-red-500' : 'bg-orange-500'}`} />
                      <span className="font-mono text-xs text-slate-700 dark:text-slate-300 flex-1 truncate">{e.name}</span>
                      <span className="text-xs text-slate-500 capitalize">{e.entity_type}</span>
                      {e.associated_techniques.length > 0 && (
                        <span className="text-xs font-medium text-purple-600 dark:text-purple-400 truncate max-w-[120px]">
                          {TECHNIQUE_LABEL[e.associated_techniques[0]] ?? e.associated_techniques[0]}
                        </span>
                      )}
                      <span className={`text-xs font-bold tabular-nums ${riskColor(e.risk_score)}`}>{e.risk_score}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </>
      )}

      {!result && !loading && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
          <svg className="h-12 w-12 text-slate-300 dark:text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2" />
          </svg>
          <p className="text-sm text-slate-500">Click "Build Threat Map" to visualize the AD threat topology.</p>
        </div>
      )}
    </div>
  )
}

// ── Legend row ────────────────────────────────────────────────────────────────
function LegendRow({ color, border, label }: { color: string; border: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-5 h-5 rounded-full flex-shrink-0" style={{ background: color, border: `1.5px solid ${border}` }} />
      <span className="text-slate-600 whitespace-nowrap">{label}</span>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'

interface Props {
  graphData: {
    nodes: any[]
    edges: any[]
  }
}

export default function LMDGraphView({ graphData }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [selectedDetails, setSelectedDetails] = useState<string | null>(null)

  useEffect(() => {
    if (!containerRef.current || !graphData) return

    cyRef.current?.destroy()

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...graphData.nodes, ...graphData.edges],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            label: 'data(label)',
            color: '#ffffff',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            width: 140,
            height: 40,
            shape: (ele) => ele.data('shape') || 'ellipse',
            'border-width': 2,
            'border-color': '#000000',
            'text-wrap': 'wrap',
          },
        },
        {
          selector: 'edge',
          style: {
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            width: 3,
            label: 'data(label)',
            'font-size': '12px',
            'font-weight': 'bold',
            color: 'data(color)',
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.2,
        animate: true,
        animationDuration: 500
      },
    })

    cy.on('tap', 'node, edge', (evt) => {
      const ele = evt.target
      setSelectedDetails(ele.data('title') || 'No additional details available.')
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedDetails(null)
      }
    })

    cyRef.current = cy

    return () => {
      cyRef.current?.destroy()
      cyRef.current = null
    }
  }, [graphData])

  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden mt-4 shadow-sm">
      <div className="px-4 py-3 border-b border-gray-100 flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-700">LMD Model result</h3>
          <div className="flex gap-4 items-center">
            <a 
              href="http://localhost:8000/api/attack-graph-html" 
              target="_blank" 
              rel="noopener noreferrer"
              download="attack_graph.html"
              className="px-3 py-1 bg-blue-50 text-blue-600 rounded-md text-xs font-semibold hover:bg-blue-100 transition-colors border border-blue-200 shadow-sm flex items-center gap-1"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
              Download Graph
            </a>
            <div className="text-xs text-gray-500 flex gap-4 border-l border-gray-200 pl-4">
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-darkred rounded-sm"></span> Attacker</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-orange rounded-sm"></span> Victim</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-lightblue rounded-sm"></span> Normal</span>
            </div>
          </div>
        </div>
        <div className="text-xs text-gray-500 flex gap-4 border-t border-gray-100 pt-2">
          <span className="font-semibold text-gray-600">Detected Attacks:</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full" style={{backgroundColor: '#e11d48'}}></span> Zerologon</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full" style={{backgroundColor: '#f59e0b'}}></span> Log4Shell</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full" style={{backgroundColor: '#8b5cf6'}}></span> Kerberoasting</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full" style={{backgroundColor: '#10b981'}}></span> Pass-the-Hash</span>
        </div>
      </div>
      <div className="flex" style={{ height: 500 }}>
        <div ref={containerRef} className="flex-1 bg-slate-900 relative" />
        
        {/* Details Sidebar */}
        {selectedDetails && (
          <div className="w-80 bg-white border-l border-gray-200 p-4 overflow-y-auto shadow-inner">
            <div className="flex items-center justify-between mb-3 border-b border-gray-100 pb-2">
              <h4 className="font-semibold text-gray-700 text-sm">Selection Details</h4>
              <button 
                onClick={() => setSelectedDetails(null)}
                className="text-gray-400 hover:text-gray-600 text-xs"
              >
                ✕ Close
              </button>
            </div>
            <div className="text-xs text-gray-600 font-mono whitespace-pre-wrap leading-relaxed">
              {selectedDetails}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

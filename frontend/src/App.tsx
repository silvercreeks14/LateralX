import { useState, useEffect, useCallback, useRef } from 'react'
import { api, isAuthenticated, clearToken, getStoredUser } from './api/client'
import Login from './components/Login'
import UploadPanel from './components/UploadPanel'
import FilterBar from './components/FilterBar'
import Timeline from './components/Timeline'
import GraphView from './components/GraphView'
import NarrativePanel from './components/NarrativePanel'
import MfaModal from './components/MfaModal'
import CaseDashboard from './components/CaseDashboard'
import GlobalSearch from './components/GlobalSearch'
import TotpSetupModal from './components/TotpSetupModal'
import StorylinePanel from './components/StorylinePanel'
import LMDPanel from './components/LMDPanel'
import ModelQualityPanel from './components/ModelQualityPanel'
import type {
  ForensicEvent, EventSummary, RCAResult, GraphData, UploadResponse,
  BaselineComparisonResult, MLModelStatus, MLStats, Upload,
} from './types'

type Section =
  | 'ingest' | 'cases' | 'timeline' | 'graph'
  | 'analysis' | 'storyline' | 'lmd'
  | 'benchmark' | 'ml-settings'

type MfaPendingAction = 'train' | 'seed-and-train' | null

// ── Sidebar nav item ───────────────────────────────────────────────────────────

function NavItem({
  id, label, active, badge, onClick, icon,
}: {
  id: Section; label: string; active: boolean; badge?: string
  onClick: (s: Section) => void; icon: React.ReactNode
}) {
  return (
    <button
      onClick={() => onClick(id)}
      className="w-full flex items-center gap-3 py-2 pr-3 rounded-lg text-sm font-medium transition-all text-left"
      style={active ? {
        background: '#00F0FF12',
        color: '#00F0FF',
        borderLeft: '2px solid #00F0FF',
        paddingLeft: '10px',
      } : {
        color: '#94a3b8',
        paddingLeft: '12px',
      }}
      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLButtonElement).style.color = '#e2e8f0' }}
      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLButtonElement).style.color = '#94a3b8' }}
    >
      <span className="flex-shrink-0 w-4 h-4">{icon}</span>
      <span className="flex-1 truncate">{label}</span>
      {badge && (
        <span className="text-xs px-1.5 py-0.5 rounded bg-slate-700 text-slate-400 font-mono flex-shrink-0">
          {badge}
        </span>
      )}
    </button>
  )
}

// ── Icon helpers ───────────────────────────────────────────────────────────────

const Icon = ({ d, d2 }: { d: string; d2?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
    {d2 && <path d={d2} />}
  </svg>
)

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const [authed, setAuthed]           = useState(() => isAuthenticated())
  const [currentUser, setCurrentUser] = useState(() => getStoredUser())

  const [summary,          setSummary]          = useState<EventSummary | null>(null)
  const [events,           setEvents]           = useState<ForensicEvent[]>([])
  const [filters,          setFilters]          = useState<Record<string, string>>({})
  const [noiseFilter,      setNoiseFilter]      = useState(false)
  const [graphData,        setGraphData]        = useState<GraphData | null>(null)
  const [rca,              setRca]              = useState<RCAResult | null>(null)
  const [rcaLoading,       setRcaLoading]       = useState(false)
  const [baselineLoading,  setBaselineLoading]  = useState(false)
  const [baselineResult,   setBaselineResult]   = useState<BaselineComparisonResult | null>(null)
  const [activeSection,    setActiveSectionRaw] = useState<Section>(() =>
    (sessionStorage.getItem('fip_section') as Section | null) ?? 'ingest'
  )
  const [error,            setError]            = useState<string | null>(null)
  const [knownIocMatches,  setKnownIocMatches]  = useState<string[]>([])
  const [relevanceWarning, setRelevanceWarning] = useState<string | null>(null)
  const [mlStatus,         setMlStatus]         = useState<MLModelStatus | null>(null)
  const [mlTrainLoading,   setMlTrainLoading]   = useState(false)
  const [mlSeedLoading,    setMlSeedLoading]    = useState(false)

  const [mfaPending,       setMfaPending]       = useState<MfaPendingAction>(null)
  const [mlStats,          setMlStats]          = useState<MLStats | null>(null)
  const [mlStatsLoading,   setMlStatsLoading]   = useState(false)
  const [activeCaseId,     setActiveCaseIdRaw]  = useState<string | null>(() =>
    sessionStorage.getItem('fip_case') || null
  )
  const [uploadKey,            setUploadKey]            = useState(0)
  const [caseUploads,          setCaseUploads]          = useState<Upload[]>([])
  const [graphUploads,         setGraphUploads]         = useState<Upload[]>([])
  const [selectedGraphUploadId, setSelectedGraphUploadId] = useState<number | null>(null)
  const [showTotpSetup,        setShowTotpSetup]        = useState(false)

  const uploadVersionRef = useRef(0)
  const activeCaseIdRef  = useRef(activeCaseId)
  activeCaseIdRef.current = activeCaseId
  const filtersRef       = useRef(filters)
  filtersRef.current = filters
  const noiseFilterRef   = useRef(false)
  noiseFilterRef.current = noiseFilter

  const switchSection = useCallback((s: Section) => {
    sessionStorage.setItem('fip_section', s)
    setActiveSectionRaw(s)
  }, [])

  const setActiveCaseId = useCallback((id: string | null) => {
    if (id) sessionStorage.setItem('fip_case', id)
    else sessionStorage.removeItem('fip_case')
    setActiveCaseIdRaw(id)
  }, [])

  useEffect(() => {
    const onExpired = () => { setAuthed(false); setCurrentUser(null) }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  const handleLogin  = () => { setAuthed(true); setCurrentUser(getStoredUser()) }
  const handleLogout = () => { clearToken(); setAuthed(false); setCurrentUser(null) }

  const refreshSummary = useCallback(async () => {
    try { setSummary(await api.getSummary(activeCaseIdRef.current)) } catch { /* no events yet */ }
  }, [])

  const refreshEvents = useCallback(async (f?: Record<string, string>) => {
    try {
      const source  = f ?? filtersRef.current
      const cleaned = Object.fromEntries(Object.entries(source).filter(([, v]) => v))
      if (noiseFilterRef.current) cleaned.noise_filter = 'true'
      setEvents(await api.getEvents(cleaned, activeCaseIdRef.current))
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load events')
    }
  }, [])

  const handleUploadSuccess = async (result: UploadResponse) => {
    const myVersion = ++uploadVersionRef.current
    const prevSummary = summary
    setError(null); setBaselineResult(null); setRelevanceWarning(null)
    setUploadKey(k => k + 1)
    if (result.known_ioc_matches?.length) setKnownIocMatches(result.known_ioc_matches)

    await refreshSummary()
    if (uploadVersionRef.current !== myVersion) return

    if (prevSummary?.time_range && result.time_range) {
      const [ps, pe, ns, ne] = [
        new Date(prevSummary.time_range.start).getTime(),
        new Date(prevSummary.time_range.end).getTime(),
        new Date(result.time_range.start).getTime(),
        new Date(result.time_range.end).getTime(),
      ]
      if (ne < ps || ns > pe) {
        setRelevanceWarning(
          `No temporal overlap between "${result.filename}" ` +
          `(${result.time_range.start.slice(0, 10)} – ${result.time_range.end.slice(0, 10)}) ` +
          `and existing workspace ` +
          `(${prevSummary.time_range.start.slice(0, 10)} – ${prevSummary.time_range.end.slice(0, 10)}). ` +
          `Files may be from different incidents.`
        )
      }
    }
    await refreshEvents({})
    if (uploadVersionRef.current !== myVersion) return
    setSelectedGraphUploadId(null)
    const isPcap = /\.pcap(ng)?$/i.test(result.filename)
    try {
      const g = await api.getGraph(isPcap ? 'pcap' : undefined, activeCaseIdRef.current)
      if (uploadVersionRef.current !== myVersion) return
      setGraphData(g)
    } catch { /* no graph events */ }
    try {
      const latest = await api.getLatestAnalysis()
      if (uploadVersionRef.current !== myVersion) return
      setRca(latest)
    } catch { /* no previous analysis */ }
  }

  const handleFilterChange = (f: Record<string, string>) => {
    setFilters(f)
    refreshEvents({ ...f, ...(noiseFilterRef.current ? { noise_filter: 'true' } : {}) })
  }

  const handleNoiseFilterToggle = () => {
    const next = !noiseFilter
    setNoiseFilter(next)
    noiseFilterRef.current = next
    refreshEvents()
  }

  const handleRunAnalysis = async (uploadId?: number | null) => {
    setRcaLoading(true); setError(null)
    try {
      const result = await api.runAnalysis(activeCaseId, uploadId ?? null)
      setRca(result)
      switchSection('analysis')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally { setRcaLoading(false) }
  }

  const handleCompareBaseline = async () => {
    setBaselineLoading(true); setError(null)
    try { setBaselineResult(await api.compareBaseline()) }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Baseline comparison failed — upload a baseline first') }
    finally { setBaselineLoading(false) }
  }

  const handleTrainMl = async () => {
    setMlTrainLoading(true); setError(null)
    try {
      await api.trainMlModel()
      setMlStatus(await api.getMlStatus())
    } catch (e: unknown) {
      if (e instanceof Error && e.message === 'MFA_REQUIRED') { setMfaPending('train'); setMlTrainLoading(false); return }
      setError(e instanceof Error ? e.message : 'ML training failed')
    } finally { setMlTrainLoading(false) }
  }

  const handleSeedAndTrain = async () => {
    setMlSeedLoading(true); setError(null)
    try {
      await api.seedMlBaseline()
      setMlStatus(await api.getMlStatus())
      await handleTrainMlMfa(undefined)
    } catch (e: unknown) {
      if (e instanceof Error && e.message === 'MFA_REQUIRED') { setMfaPending('seed-and-train'); setMlSeedLoading(false); return }
      setError(e instanceof Error ? e.message : 'Seed and train failed')
    } finally { setMlSeedLoading(false) }
  }

  const handleTrainMlMfa = async (code: string | undefined) => {
    setMlTrainLoading(true); setError(null)
    try {
      if (code) await api.trainMlModelMfa(code); else await api.trainMlModel()
      setMlStatus(await api.getMlStatus())
      setMfaPending(null)
    } catch (e: unknown) {
      if (e instanceof Error && e.message === 'MFA_REQUIRED') { setMfaPending('train'); return }
      setError(e instanceof Error ? e.message : 'ML training failed')
      setMfaPending(null)
    } finally { setMlTrainLoading(false) }
  }

  const handleMfaConfirm = async (code: string) => {
    if (mfaPending === 'train') {
      await handleTrainMlMfa(code)
    } else if (mfaPending === 'seed-and-train') {
      setMlSeedLoading(true); setMfaPending(null)
      try { await api.seedMlBaselineMfa(code) }
      catch (e: unknown) { setError(e instanceof Error ? e.message : 'Seed baseline failed'); setMlSeedLoading(false); return }
      setMlSeedLoading(false)
      await handleTrainMl()
    }
  }

  const handleLoadMlStats = async () => {
    setMlStatsLoading(true)
    try {
      setMlStats(await api.getMlStats())
    } catch { /* silent */ } finally {
      setMlStatsLoading(false)
    }
  }

useEffect(() => {
    setSelectedGraphUploadId(null)
    if (activeCaseId) {
      api.getCaseUploads(activeCaseId)
        .then(u => { setCaseUploads(u); setGraphUploads(u) })
        .catch(() => { setCaseUploads([]); setGraphUploads([]) })
    } else {
      setCaseUploads([])
      api.getUploads().then(setGraphUploads).catch(() => setGraphUploads([]))
    }
  }, [activeCaseId, uploadKey])

  const refreshGraph = useCallback(async (uploadId: number | null) => {
    const isPcap = uploadId != null
      ? (graphUploads.find(u => u.id === uploadId)?.filename ?? '').match(/\.pcap(ng)?$/i) !== null
      : false
    try {
      setGraphData(await api.getGraph(isPcap ? 'pcap' : undefined, activeCaseIdRef.current, uploadId))
    } catch { setGraphData(null) }
  }, [graphUploads])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!authed) return
    refreshSummary()
    refreshEvents()
    api.getMlStatus().then(setMlStatus).catch(() => {})
    // Reload graph from existing events so navigating back always works
    api.getGraph(undefined, activeCaseIdRef.current)
      .then(setGraphData)
      .catch(() => {})
  }, [authed, activeCaseId])

  if (!authed) return <Login onLogin={handleLogin} />

  // ── Sidebar nav definitions ─────────────────────────────────────────────────

  const nav = {
    ingest: <Icon d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />,
    timeline: <Icon d="M4 6h16M4 10h16M4 14h16M4 18h16" />,
    graph: <Icon d="M13 10V3L4 14h7v7l9-11h-7z" />,
    analysis: <Icon d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />,
    cases: <Icon d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />,
    storyline: <Icon d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />,
    lmd:      <Icon d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />,
    benchmark: <Icon d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />,
    'ml-settings': <Icon d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z" />,
  }

  const evtCount = summary?.total ?? 0

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden">
      {/* ── Overlay modals ──────────────────────────────────────────────────── */}
      {showTotpSetup && <TotpSetupModal onClose={() => setShowTotpSetup(false)} />}
      {mfaPending && (
        <MfaModal
          actionLabel={mfaPending === 'train' ? 'Train ML Model' : 'Seed Baseline + Train'}
          onConfirm={handleMfaConfirm}
          onCancel={() => setMfaPending(null)}
        />
      )}

      {/* ── Sidebar ─────────────────────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 flex flex-col bg-slate-900 border-r border-slate-800">
        {/* Logo */}
        <div className="px-4 py-5 border-b border-slate-800 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-7 rounded-md flex items-center justify-center font-black text-slate-900 text-xs flex-shrink-0"
              style={{ background: '#00F0FF' }}
            >
              FIP
            </div>
            <span className="text-white font-bold tracking-tight">FIP Platform</span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto">
          <p className="px-3 pb-1 text-xs font-semibold text-slate-600 uppercase tracking-wider">
            Evidence &amp; Cases
          </p>
          <NavItem id="ingest" label="Data Ingestion" active={activeSection === 'ingest'} onClick={switchSection} icon={nav.ingest} />
          <NavItem id="cases"  label="Cases"          active={activeSection === 'cases'}  onClick={switchSection} icon={nav.cases} />

          <p className="px-3 pt-4 pb-1 text-xs font-semibold text-slate-600 uppercase tracking-wider">
            Investigation
          </p>
          <NavItem id="timeline" label="Timeline"     active={activeSection === 'timeline'} onClick={switchSection} icon={nav.timeline} badge={evtCount > 0 ? String(evtCount) : undefined} />
          <NavItem id="graph"    label="Attack Graph" active={activeSection === 'graph'}    onClick={switchSection} icon={nav.graph} />

          <p className="px-3 pt-4 pb-1 text-xs font-semibold text-slate-600 uppercase tracking-wider">
            Analysis
          </p>
          <NavItem id="analysis"  label="AI Analysis"      active={activeSection === 'analysis'}  onClick={switchSection} icon={nav.analysis} />
          <NavItem id="storyline" label="Attack Storyline" active={activeSection === 'storyline'} onClick={switchSection} icon={nav.storyline} />
          <NavItem id="lmd"       label="LMD Analysis"     active={activeSection === 'lmd'}       onClick={switchSection} icon={nav.lmd} />

          <p className="px-3 pt-4 pb-1 text-xs font-semibold text-slate-600 uppercase tracking-wider">
            Models
          </p>
          <NavItem id="benchmark"   label="Model Quality"  active={activeSection === 'benchmark'}   onClick={switchSection} icon={nav.benchmark} />
          <NavItem id="ml-settings" label="Model Settings" active={activeSection === 'ml-settings'} onClick={switchSection} icon={nav['ml-settings']} />
        </nav>

        {/* User footer */}
        <div className="px-3 py-3 border-t border-slate-800 flex-shrink-0 space-y-1">
          {activeCaseId && (
            <div className="flex items-center justify-between px-1 py-1 mb-1">
              <span className="text-xs text-slate-500 truncate">Case active</span>
              <button
                onClick={() => setActiveCaseId(null)}
                className="text-xs text-slate-600 hover:text-slate-400 ml-2 flex-shrink-0"
              >
                ✕
              </button>
            </div>
          )}
          <div className="flex items-center gap-2 px-1">
            <div className="flex-1 min-w-0">
              <p className="text-white text-xs font-medium truncate">{currentUser?.username ?? 'analyst'}</p>
              <p className="text-slate-600 text-xs capitalize">{currentUser?.role ?? 'analyst'}</p>
            </div>
            {currentUser?.role === 'admin' && (
              <button
                onClick={() => setShowTotpSetup(true)}
                className="text-xs px-1.5 py-1 rounded border border-slate-700 text-slate-500 hover:border-slate-500 hover:text-slate-300 transition-colors"
                title="TOTP Setup"
              >
                TOTP
              </button>
            )}
            <button
              onClick={handleLogout}
              className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-500 hover:border-slate-500 hover:text-slate-300 transition-colors"
            >
              Out
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main area ───────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="h-14 flex items-center px-5 gap-4 bg-slate-900/60 border-b border-slate-800 flex-shrink-0">
          <GlobalSearch
            onNavigateCase={(caseId) => { setActiveCaseId(caseId); switchSection('cases') }}
          />
          {evtCount > 0 && (
            <div className="text-right text-xs text-slate-500 hidden md:block flex-shrink-0">
              <span className="font-medium" style={{ color: '#00F0FF' }}>{evtCount.toLocaleString()} events</span>
              {summary?.time_range && (
                <span className="ml-2 text-slate-600">
                  {summary.time_range.start.slice(0, 10)} &rarr; {summary.time_range.end.slice(0, 10)}
                </span>
              )}
            </div>
          )}
        </header>

        {/* Notification banners */}
        {(error || knownIocMatches.length > 0 || relevanceWarning) && (
          <div className="flex-shrink-0 space-y-2 px-6 pt-4">
            {knownIocMatches.length > 0 && (
              <div
                className="rounded-xl px-4 py-3 text-sm flex items-start justify-between gap-3 border"
                style={{ background: '#FF6B0010', borderColor: '#FF6B0030', color: '#fca5a5' }}
              >
                <span><span className="font-semibold" style={{ color: '#FF6B00' }}>IOC match:</span> {knownIocMatches.join(', ')}</span>
                <button onClick={() => setKnownIocMatches([])} className="text-xs opacity-60 hover:opacity-100 flex-shrink-0">Dismiss</button>
              </div>
            )}
            {relevanceWarning && (
              <div className="bg-amber-950/40 border border-amber-800/40 text-amber-300 rounded-xl px-4 py-3 text-xs flex items-start gap-2 justify-between">
                <span><span className="font-semibold">Relevance warning:</span> {relevanceWarning}</span>
                <button onClick={() => setRelevanceWarning(null)} className="opacity-60 hover:opacity-100 flex-shrink-0">✕</button>
              </div>
            )}
            {error && (
              <div className="bg-red-950/50 border border-red-800/50 text-red-300 rounded-xl px-4 py-3 text-sm flex items-start justify-between gap-3">
                <span>{error}</span>
                <button onClick={() => setError(null)} className="opacity-60 hover:opacity-100 flex-shrink-0">✕</button>
              </div>
            )}
          </div>
        )}

        {/* Section content */}
        <main className="flex-1 overflow-auto">
          <div className="p-6 max-w-6xl">

            {/* Data Ingestion ─────────────────────────────────────────────── */}
            {activeSection === 'ingest' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-white font-semibold text-lg mb-1">Data Ingestion</h2>
                  <p className="text-slate-500 text-sm">Upload Windows Event Logs, Sysmon XML, or PCAP files for analysis.</p>
                </div>
                <UploadPanel onUploadSuccess={handleUploadSuccess} activeCaseId={activeCaseId} currentSummary={summary} />
                {baselineResult && (
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-white font-semibold text-sm">Baseline Comparison</h3>
                      <button onClick={() => setBaselineResult(null)} className="text-xs text-slate-600 hover:text-slate-400">Dismiss</button>
                    </div>
                    <p className="text-slate-300 text-sm mb-3">{baselineResult.summary}</p>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                      {baselineResult.new_hosts.length > 0 && (
                        <div>
                          <p className="font-semibold text-slate-500 mb-1">New Hosts</p>
                          {baselineResult.new_hosts.map(h => <p key={h} className="text-slate-300 font-mono">{h}</p>)}
                        </div>
                      )}
                      {baselineResult.new_users.length > 0 && (
                        <div>
                          <p className="font-semibold text-slate-500 mb-1">New Users</p>
                          {baselineResult.new_users.map(u => <p key={u} className="text-slate-300 font-mono">{u}</p>)}
                        </div>
                      )}
                      {baselineResult.anomalous_event_types.length > 0 && (
                        <div>
                          <p className="font-semibold text-slate-500 mb-1">New Event Types</p>
                          {baselineResult.anomalous_event_types.map(t => <p key={t} className="text-slate-300 font-mono">{t}</p>)}
                        </div>
                      )}
                      <div>
                        <p className="font-semibold text-slate-500 mb-1">Event Delta</p>
                        <p className={`font-mono ${baselineResult.event_count_delta > 0 ? 'text-orange-400' : 'text-green-400'}`}>
                          {baselineResult.event_count_delta > 0 ? '+' : ''}{baselineResult.event_count_delta}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Timeline ───────────────────────────────────────────────────── */}
            {activeSection === 'timeline' && (
              evtCount > 0 ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="flex-1 min-w-0">
                      <FilterBar summary={summary!} onFilterChange={handleFilterChange} />
                    </div>
                    <button
                      onClick={handleNoiseFilterToggle}
                      className={`shrink-0 text-xs px-3 py-1.5 rounded-lg border font-medium transition-colors ${
                        noiseFilter
                          ? 'text-slate-900 border-transparent'
                          : 'border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-300'
                      }`}
                      style={noiseFilter ? { background: '#00F0FF', borderColor: '#00F0FF' } : {}}
                    >
                      {noiseFilter ? 'Noise filter ON' : 'Noise filter OFF'}
                    </button>
                  </div>
                  <Timeline events={events} uploads={caseUploads} />
                </div>
              ) : (
                <EmptyState
                  icon="M4 6h16M4 10h16M4 14h16M4 18h16"
                  message={activeCaseId ? 'Upload a file above to add events to this case.' : 'Upload a log file or PCAP to begin.'}
                  action={() => switchSection('ingest')}
                  actionLabel="Go to Data Ingestion"
                />
              )
            )}

            {/* Attack Graph ───────────────────────────────────────────────── */}
            {activeSection === 'graph' && (
              <div className="space-y-3">
                <div className="bg-slate-900 rounded-xl border border-slate-800 px-4 py-3 flex flex-wrap items-center gap-2">
                  {graphUploads.length > 1 && (
                    <>
                      <span className="text-xs font-medium text-slate-500 mr-1">Graph source:</span>
                      <button
                        onClick={() => { setSelectedGraphUploadId(null); refreshGraph(null) }}
                        className="px-3 py-1 rounded-full text-xs font-medium transition-colors"
                        style={selectedGraphUploadId === null
                          ? { background: '#00F0FF', color: '#0f172a' }
                          : { background: '#1e293b', color: '#94a3b8' }}
                      >
                        All uploads
                      </button>
                      {graphUploads.map(u => (
                        <button
                          key={u.id}
                          onClick={() => { setSelectedGraphUploadId(u.id); refreshGraph(u.id) }}
                          className="px-3 py-1 rounded-full text-xs font-medium transition-colors max-w-[200px] truncate"
                          style={selectedGraphUploadId === u.id
                            ? { background: '#00F0FF', color: '#0f172a' }
                            : { background: '#1e293b', color: '#94a3b8' }}
                          title={`${u.filename} — ${u.event_count.toLocaleString()} events`}
                        >
                          {u.filename.length > 26 ? u.filename.slice(0, 23) + '…' : u.filename}
                        </button>
                      ))}
                    </>
                  )}
                  <div className="ml-auto">
                    <button
                      onClick={() => refreshGraph(selectedGraphUploadId)}
                      className="text-xs px-3 py-1 rounded border border-slate-700 text-slate-400 hover:bg-slate-800 transition-colors"
                      title="Reload the attack graph from current events"
                    >
                      ↺ Reload Graph
                    </button>
                  </div>
                </div>
                <GraphView
                  graphData={graphData}
                  activeCaseId={activeCaseId}
                  selectedUploadId={selectedGraphUploadId}
                />
              </div>
            )}

            {/* AI Analysis ────────────────────────────────────────────────── */}
            {activeSection === 'analysis' && (
              <NarrativePanel
                result={rca}
                loading={rcaLoading}
                baselineLoading={baselineLoading}
                onRunAnalysis={handleRunAnalysis}
                onCompareBaseline={handleCompareBaseline}
                mlStatus={mlStatus}
                isAdmin={currentUser?.role === 'admin'}
                uploads={graphUploads}
                activeCaseId={activeCaseId}
              />
            )}

            {/* Cases ──────────────────────────────────────────────────────── */}
            {activeSection === 'cases' && (
              <CaseDashboard onSelectCase={setActiveCaseId} uploadKey={uploadKey} />
            )}

            {/* Attack Storyline ───────────────────────────────────────────── */}
            {activeSection === 'storyline' && (
              <StorylinePanel
                activeCaseId={activeCaseId}
                selectedUploadId={selectedGraphUploadId}
              />
            )}

            {/* LMD Analysis ──────────────────────────────────────────────── */}
            {activeSection === 'lmd' && (
              <div className="space-y-4">
                <div>
                  <h2 className="text-white font-semibold text-lg mb-1">LMD Analysis</h2>
                  <p className="text-slate-500 text-sm">
                    AD-specialized Random Forest lateral movement detection — run independently of AI Analysis.
                  </p>
                </div>
                <LMDPanel activeCaseId={activeCaseId} uploads={caseUploads} />
              </div>
            )}

            {/* Model Quality Benchmark ───────────────────────────────────── */}
            {activeSection === 'benchmark' && (
              <div className="space-y-4">
                <div>
                  <h2 className="text-white font-semibold text-lg mb-1">Model Quality</h2>
                  <p className="text-slate-500 text-sm">
                    Benchmark all detection models against OTRF/Security-Datasets and MITRE ATT&CK KB v14 ground truth.
                  </p>
                </div>
                <ModelQualityPanel />
              </div>
            )}

            {/* ML Model Settings ──────────────────────────────────────────── */}
            {activeSection === 'ml-settings' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-white font-semibold text-lg mb-1">Model Settings</h2>
                  <p className="text-slate-500 text-sm">Isolation Forest anomaly detector — training controls and performance metrics.</p>
                </div>

                {mlStatus ? (
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-5">
                    {/* Status + training controls */}
                    <div className="flex items-center justify-between flex-wrap gap-3">
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 rounded-full flex-shrink-0"
                          style={{ background: mlStatus.trained ? '#00F0FF' : '#475569' }} />
                        <p className="text-white font-semibold">
                          {mlStatus.trained ? 'Model trained and active' : 'Model not trained'}
                        </p>
                      </div>
                      {currentUser?.role === 'admin' && (
                        <div className="flex gap-2 flex-wrap">
                          <button
                            onClick={handleSeedAndTrain}
                            disabled={mlSeedLoading || mlTrainLoading}
                            className="text-xs px-3 py-1.5 rounded border border-violet-800/40 text-violet-400 hover:bg-violet-950/20 disabled:opacity-40 whitespace-nowrap"
                            title="Generate 30-user synthetic baseline then train the model"
                          >
                            {mlSeedLoading ? 'Seeding…' : 'Seed + Train'}
                          </button>
                          <button
                            onClick={handleTrainMl}
                            disabled={mlTrainLoading || mlSeedLoading}
                            className="text-xs px-3 py-1.5 rounded border border-blue-800/40 text-blue-400 hover:bg-blue-950/20 disabled:opacity-40 whitespace-nowrap"
                            title="Train on existing DB events only (requires ≥10 users)"
                          >
                            {mlTrainLoading ? 'Training…' : mlStatus.trained ? 'Retrain' : 'Train'}
                          </button>
                          <button
                            onClick={handleLoadMlStats}
                            disabled={mlStatsLoading}
                            className="text-xs px-3 py-1.5 rounded border border-slate-700 text-slate-400 hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap"
                            title="Load precision/recall/F1 from analyst verifications"
                          >
                            {mlStatsLoading ? 'Loading…' : 'View Stats'}
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Training metadata */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { label: 'Training Users',   value: mlStatus.trained_on_users ?? '—' },
                        { label: 'Training Events',  value: mlStatus.trained_on_events ?? '—' },
                        { label: 'Synthetic Events', value: mlStatus.synthetic_baseline_events ?? '—' },
                        { label: 'Trained At',       value: mlStatus.trained_at ? mlStatus.trained_at.slice(0, 10) : '—' },
                      ].map(s => (
                        <div key={s.label} className="bg-slate-800 rounded-xl p-3">
                          <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                          <p className="text-white font-semibold text-sm">{String(s.value)}</p>
                        </div>
                      ))}
                    </div>

                    {/* ML Stats widget */}
                    {mlStats && (
                      <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-semibold text-slate-400">Model Performance Metrics</span>
                          <button onClick={() => setMlStats(null)} className="text-xs text-slate-500 hover:text-slate-300">✕</button>
                        </div>
                        <div className="grid grid-cols-4 gap-2 text-center text-xs mb-3">
                          {[
                            { label: 'Precision', val: mlStats.precision },
                            { label: 'Recall',    val: mlStats.recall },
                            { label: 'F1 Score',  val: mlStats.f1_score },
                            { label: 'Accuracy',  val: mlStats.accuracy },
                          ].map(({ label, val }) => (
                            <div key={label} className="bg-slate-900 rounded border border-slate-700 p-2">
                              <div className="text-slate-500 text-xs mb-1">{label}</div>
                              <div className="font-semibold text-slate-200">
                                {val !== null && val !== undefined ? `${Math.round(val * 100)}%` : '—'}
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="grid grid-cols-4 gap-2 text-center text-xs">
                          {[
                            { label: 'TP', val: mlStats.true_positives,  color: 'text-green-400' },
                            { label: 'TN', val: mlStats.true_negatives,  color: 'text-green-400' },
                            { label: 'FP', val: mlStats.false_positives, color: 'text-red-400'   },
                            { label: 'FN', val: mlStats.false_negatives, color: 'text-red-400'   },
                          ].map(({ label, val, color }) => (
                            <div key={label} className="bg-slate-900 rounded border border-slate-700 p-2">
                              <div className="text-slate-500 text-xs mb-1">{label}</div>
                              <div className={`font-semibold ${color}`}>{val}</div>
                            </div>
                          ))}
                        </div>
                        <p className="text-xs text-slate-500 mt-2">{mlStats.note}</p>
                      </div>
                    )}

                    {!mlStatus.trained && (
                      <p className="text-xs text-slate-600">
                        Click <span className="text-violet-400">Seed + Train</span> to generate a synthetic baseline and train,
                        or <span className="text-blue-400">Train</span> to train on existing DB events only (requires ≥ 10 users).
                        Analyst TP/FP feedback in AI Analysis feeds into model performance metrics here.
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 flex items-center justify-center">
                    <p className="text-slate-600 text-sm">Loading model status…</p>
                  </div>
                )}
              </div>
            )}

          </div>
        </main>
      </div>
    </div>
  )
}

// ── Shared empty state ─────────────────────────────────────────────────────────

function EmptyState({
  icon, message, action, actionLabel,
}: { icon: string; message: string; action?: () => void; actionLabel?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-16 flex flex-col items-center gap-3 text-center">
      <svg className="h-12 w-12 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={icon} />
      </svg>
      <p className="text-sm text-slate-500">{message}</p>
      {action && actionLabel && (
        <button
          onClick={action}
          className="mt-1 text-xs px-3 py-1.5 rounded-lg font-medium text-slate-900 transition-colors"
          style={{ background: '#00F0FF' }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  )
}

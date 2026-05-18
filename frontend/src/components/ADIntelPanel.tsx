import { useState } from 'react'
import ADDetectionPanel from './ADDetectionPanel'
import PrivilegeTimelinePanel from './PrivilegeTimelinePanel'
import ADEntityPanel from './ADEntityPanel'
import ADThreatMap from './ADThreatMap'
import LMDRFScanPanel from './LMDRFScanPanel'
import type { ADRulesResult, Upload } from '../types'

// AD-relevant MITRE techniques organized by tactic
const MITRE_MATRIX = [
  {
    tactic: 'Recon',
    bg: 'bg-cyan-50 dark:bg-cyan-950/30', border: 'border-cyan-200 dark:border-cyan-800/30', text: 'text-cyan-700 dark:text-cyan-400',
    hitBg: 'bg-cyan-600 dark:bg-cyan-700/60', hitText: 'text-white dark:text-cyan-100',
    techniques: [
      { id: 'T1018',     name: 'Remote System Discovery' },
      { id: 'T1069.002', name: 'Domain Groups' },
      { id: 'T1087.002', name: 'Domain Accounts' },
      { id: 'T1482',     name: 'Domain Trust Discovery' },
      { id: 'T1016',     name: 'System Network Config' },
      { id: 'T1049',     name: 'Network Connections' },
    ],
  },
  {
    tactic: 'Credential Access',
    bg: 'bg-purple-50 dark:bg-purple-950/30', border: 'border-purple-200 dark:border-purple-800/30', text: 'text-purple-700 dark:text-purple-400',
    hitBg: 'bg-purple-600 dark:bg-purple-700/60', hitText: 'text-white dark:text-purple-100',
    techniques: [
      { id: 'T1558.003', name: 'Kerberoasting' },
      { id: 'T1558.004', name: 'AS-REP Roasting' },
      { id: 'T1558.001', name: 'Golden Ticket' },
      { id: 'T1558.002', name: 'Silver Ticket' },
      { id: 'T1003.001', name: 'LSASS Memory' },
      { id: 'T1003.006', name: 'DCSync' },
      { id: 'T1110.001', name: 'Password Guessing' },
      { id: 'T1110.003', name: 'Password Spraying' },
      { id: 'T1557.001', name: 'LLMNR Poisoning' },
    ],
  },
  {
    tactic: 'Privilege Escalation',
    bg: 'bg-orange-50 dark:bg-orange-950/30', border: 'border-orange-200 dark:border-orange-800/30', text: 'text-orange-700 dark:text-orange-400',
    hitBg: 'bg-orange-600 dark:bg-orange-700/60', hitText: 'text-white dark:text-orange-100',
    techniques: [
      { id: 'T1134.001', name: 'Token Impersonation' },
      { id: 'T1134.002', name: 'Create Process w/Token' },
      { id: 'T1484.001', name: 'Group Policy Modification' },
      { id: 'T1484.002', name: 'Domain Trust Modification' },
      { id: 'T1068',     name: 'Exploit Privilege Esc' },
      { id: 'T1078',     name: 'Valid Accounts' },
      { id: 'T1098',     name: 'Account Manipulation' },
    ],
  },
  {
    tactic: 'Lateral Movement',
    bg: 'bg-blue-50 dark:bg-blue-950/30', border: 'border-blue-200 dark:border-blue-800/30', text: 'text-blue-700 dark:text-blue-400',
    hitBg: 'bg-blue-600 dark:bg-blue-700/60', hitText: 'text-white dark:text-blue-100',
    techniques: [
      { id: 'T1021.001', name: 'Remote Desktop Protocol' },
      { id: 'T1021.002', name: 'SMB/Admin Shares' },
      { id: 'T1021.006', name: 'Windows Remote Mgmt' },
      { id: 'T1550.002', name: 'Pass the Hash' },
      { id: 'T1550.003', name: 'Pass the Ticket' },
      { id: 'T1563.002', name: 'RDP Hijacking' },
    ],
  },
  {
    tactic: 'Persistence',
    bg: 'bg-yellow-50 dark:bg-yellow-950/30', border: 'border-yellow-200 dark:border-yellow-800/30', text: 'text-yellow-700 dark:text-yellow-400',
    hitBg: 'bg-yellow-600 dark:bg-yellow-700/60', hitText: 'text-white dark:text-yellow-100',
    techniques: [
      { id: 'T1053.005', name: 'Scheduled Task' },
      { id: 'T1547.001', name: 'Registry Run Keys' },
      { id: 'T1543.003', name: 'Windows Service' },
      { id: 'T1136.002', name: 'Domain Account' },
      { id: 'T1197',     name: 'BITS Jobs' },
      { id: 'T1546.013', name: 'PowerShell Profile' },
    ],
  },
  {
    tactic: 'Defense Evasion',
    bg: 'bg-slate-100 dark:bg-slate-800/40', border: 'border-slate-300 dark:border-slate-700/40', text: 'text-slate-600 dark:text-slate-400',
    hitBg: 'bg-slate-500 dark:bg-slate-600/60', hitText: 'text-white dark:text-slate-100',
    techniques: [
      { id: 'T1070.001', name: 'Clear Event Logs' },
      { id: 'T1562.001', name: 'Disable Security Tools' },
      { id: 'T1036',     name: 'Masquerading' },
      { id: 'T1218',     name: 'LOLBin Execution' },
      { id: 'T1112',     name: 'Modify Registry' },
    ],
  },
  {
    tactic: 'Impact',
    bg: 'bg-red-50 dark:bg-red-950/30', border: 'border-red-200 dark:border-red-800/30', text: 'text-red-700 dark:text-red-400',
    hitBg: 'bg-red-600 dark:bg-red-700/60', hitText: 'text-white dark:text-red-100',
    techniques: [
      { id: 'T1490', name: 'Inhibit System Recovery' },
      { id: 'T1486', name: 'Data Encrypted for Impact' },
      { id: 'T1489', name: 'Service Stop' },
    ],
  },
] as const

type TabId = 'detection' | 'lmd-rf' | 'timeline' | 'entities' | 'threat-map' | 'mitre-heatmap'

const TABS: { id: TabId; label: string }[] = [
  { id: 'detection',     label: 'Detection' },
  { id: 'lmd-rf',        label: 'LMD RF Scan' },
  { id: 'timeline',      label: 'Timeline' },
  { id: 'entities',      label: 'Entities' },
  { id: 'threat-map',    label: 'Threat Map' },
  { id: 'mitre-heatmap', label: 'MITRE Heatmap' },
]

interface Props {
  activeCaseId?: string | null
  uploads?: Upload[]
  lmdFile?: File | null
}

export default function ADIntelPanel({ activeCaseId, uploads, lmdFile }: Props) {
  const [activeTab,      setActiveTab]      = useState<TabId>('detection')
  const [adRulesResult,  setAdRulesResult]  = useState<ADRulesResult | null>(null)

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-slate-900 dark:text-white font-semibold text-xl">AD Intelligence</h2>
          <p className="text-slate-500 text-sm mt-1">
            Active Directory attack detection, privilege escalation, entity risk, topology, and MITRE coverage.
          </p>
        </div>
        {(uploads ?? []).length > 0 && (
          <span className="text-xs font-medium text-slate-500 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2">
            {(uploads ?? []).length} evidence source{(uploads ?? []).length === 1 ? '' : 's'} available
          </span>
        )}
      </div>

      {/* Tab strip */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-2 shadow-sm">
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="min-h-10 px-3 rounded-xl text-sm font-semibold transition-all whitespace-nowrap border"
              style={activeTab === tab.id
                ? { background: '#00F0FF', color: '#0f172a', borderColor: '#00F0FF' }
                : { color: '#64748b', borderColor: 'transparent' }}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Detection — display:none preserves scan state when switching tabs */}
      <div style={{ display: activeTab === 'detection' ? undefined : 'none' }}>
        <ADDetectionPanel
          activeCaseId={activeCaseId}
          uploads={uploads}
          onResult={setAdRulesResult}
        />
      </div>

      <div style={{ display: activeTab === 'lmd-rf' ? undefined : 'none' }}>
        <LMDRFScanPanel ingestedFile={lmdFile ?? null} />
      </div>

      {/* Timeline — display:none preserves timeline state */}
      <div style={{ display: activeTab === 'timeline' ? undefined : 'none' }}>
        <PrivilegeTimelinePanel activeCaseId={activeCaseId} uploads={uploads} />
      </div>

      {/* Entities — display:none preserves entity data */}
      <div style={{ display: activeTab === 'entities' ? undefined : 'none' }}>
        <ADEntityPanel activeCaseId={activeCaseId} uploads={uploads} />
      </div>

      {/* Threat Map — display:none preserves Cytoscape instance */}
      <div style={{ display: activeTab === 'threat-map' ? undefined : 'none' }}>
        <ADThreatMap activeCaseId={activeCaseId} uploads={uploads} />
      </div>

      {/* MITRE Heatmap — stateless read of adRulesResult, re-render on tab switch is fine */}
      {activeTab === 'mitre-heatmap' && (
        <div className="space-y-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <h3 className="text-slate-900 dark:text-white font-semibold">MITRE ATT&amp;CK Coverage</h3>
                <p className="text-slate-500 text-sm mt-0.5">
                  Highlighted cells indicate techniques detected by the AD scan.
                </p>
              </div>
              {!adRulesResult ? (
                <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/30 rounded-lg px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
                  Run the AD Scan in the Detection tab to populate coverage.
                </div>
              ) : (
                <span className="text-xs text-slate-500">
                  {adRulesResult.mitre_ids.length} techniques detected
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {MITRE_MATRIX.map(col => {
              const hitIds  = new Set(adRulesResult?.mitre_ids ?? [])
              const colHits = col.techniques.filter(t => hitIds.has(t.id)).length
              return (
                <div key={col.tactic} className={`rounded-xl border p-3 space-y-1.5 ${col.bg} ${col.border}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-bold uppercase tracking-wide ${col.text}`}>{col.tactic}</span>
                    {colHits > 0 && (
                      <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${col.hitBg} ${col.hitText}`}>
                        {colHits}/{col.techniques.length}
                      </span>
                    )}
                  </div>
                  {col.techniques.map(t => {
                    const hit = hitIds.has(t.id)
                    return (
                      <div
                        key={t.id}
                        className={`rounded px-2 py-1.5 flex items-center gap-2 ${
                          hit
                            ? `${col.hitBg} ${col.hitText}`
                            : 'bg-white dark:bg-slate-800/50 text-slate-500 dark:text-slate-600'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${hit ? 'bg-current' : 'bg-slate-400 dark:bg-slate-600'}`} />
                        <div className="min-w-0">
                          <span className="font-mono text-xs font-semibold block leading-tight">{t.id}</span>
                          <span className="text-xs leading-tight block truncate">{t.name}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )
            })}
          </div>

          <div className="flex items-center gap-6 text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded bg-purple-600 dark:bg-purple-700/60" />
              <span>Detected by AD scan</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded bg-slate-200 dark:bg-slate-800" />
              <span>Not detected</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

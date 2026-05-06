import { api } from '../api/client'
import type { IOC, ThreatIntelStatus } from '../types'

interface Props {
  iocs: IOC[]
  isQuickScan?: boolean
  tiStatus?: ThreatIntelStatus | null
}

const TYPE_STYLE: Record<string, string> = {
  ip:           'bg-red-950/20 text-red-400',
  url:          'bg-orange-950/20 text-orange-400',
  domain:       'bg-amber-950/20 text-amber-400',
  file_path:    'bg-blue-950/20 text-blue-400',
  md5:          'bg-purple-950/20 text-purple-400',
  sha256:       'bg-violet-950/20 text-violet-400',
  registry_key: 'bg-slate-800 text-slate-400',
}

interface TiTags {
  vtMalicious: number | null
  vtTotal: number | null
  abuseScore: number | null
  cleanContext: string
}

function parseTiTags(context: string): TiTags {
  let cleanContext = context
  let vtMalicious: number | null = null
  let vtTotal: number | null = null
  let abuseScore: number | null = null

  const vtMatch = context.match(/\[VT:\s*(\d+)\/(\d+)\s*malicious\]/i)
  if (vtMatch) {
    vtMalicious = parseInt(vtMatch[1], 10)
    vtTotal     = parseInt(vtMatch[2], 10)
    cleanContext = cleanContext.replace(vtMatch[0], '').trim()
  }

  const abMatch = context.match(/\[AbuseIPDB:\s*(\d+)%\s*confidence\]/i)
  if (abMatch) {
    abuseScore = parseInt(abMatch[1], 10)
    cleanContext = cleanContext.replace(abMatch[0], '').trim()
  }

  return { vtMalicious, vtTotal, abuseScore, cleanContext }
}

function VtBadge({ malicious, total }: { malicious: number; total: number }) {
  const isClean = malicious === 0
  return (
    <span
      title={`VirusTotal: ${malicious}/${total} engines flagged as malicious`}
      className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-xs font-bold whitespace-nowrap ${
        isClean ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
      }`}
    >
      <span className="font-mono">VT</span>
      <span className="font-normal">{malicious}/{total}</span>
    </span>
  )
}

function AbuseBadge({ score }: { score: number }) {
  const color =
    score >= 75 ? 'bg-red-900/30 text-red-400' :
    score >= 30 ? 'bg-amber-900/30 text-amber-400' :
                  'bg-green-900/30 text-green-400'
  return (
    <span
      title={`AbuseIPDB: ${score}% abuse confidence score`}
      className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-xs font-bold whitespace-nowrap ${color}`}
    >
      <span className="font-mono">IPDB</span>
      <span className="font-normal">{score}%</span>
    </span>
  )
}

export default function IOCPanel({ iocs, isQuickScan = false, tiStatus = null }: Props) {
  if (iocs.length === 0) return null

  const parsed = iocs.map(ioc => ({ ioc, ti: parseTiTags(ioc.context) }))

  const enriched = parsed.filter(
    ({ ti }) => ti.vtMalicious !== null || ti.abuseScore !== null
  )
  const flagged = enriched.filter(
    ({ ti }) => (ti.vtMalicious ?? 0) > 0 || (ti.abuseScore ?? 0) >= 30
  )
  const hasEnrichment = enriched.length > 0

  const counts = iocs.reduce<Record<string, number>>((acc, i) => {
    acc[i.type] = (acc[i.type] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
          Indicators of Compromise ({iocs.length})
        </h3>
        <div className="flex gap-2">
          <button
            onClick={() => api.exportIocsCsv()}
            className="text-xs px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-md font-medium"
          >
            Export CSV
          </button>
          <button
            onClick={() => api.exportIocsStix()}
            className="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-medium"
          >
            Export STIX 2.1
          </button>
        </div>
      </div>

      {/* Type summary badges */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(counts).map(([type, count]) => (
          <span
            key={type}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${TYPE_STYLE[type] ?? 'bg-slate-800 text-slate-400'}`}
          >
            {type} <span className="font-bold">{count}</span>
          </span>
        ))}
      </div>

      {/* Threat Intelligence summary */}
      {hasEnrichment ? (
        <div className={`rounded-lg border p-3 ${
          flagged.length > 0
            ? 'bg-red-950/20 border-red-800/40'
            : 'bg-green-950/20 border-green-800/40'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            <svg className={`w-4 h-4 flex-shrink-0 ${flagged.length > 0 ? 'text-red-400' : 'text-green-400'}`}
              fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span className={`text-xs font-semibold ${flagged.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
              Threat Intelligence Enrichment
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              flagged.length > 0 ? 'bg-red-900/30 text-red-400' : 'bg-green-900/30 text-green-400'
            }`}>
              {enriched.length} IOC{enriched.length !== 1 ? 's' : ''} checked
              {flagged.length > 0 ? ` · ${flagged.length} flagged` : ' · all clean'}
            </span>
          </div>

          {flagged.length > 0 && (
            <div className="space-y-1">
              {flagged.map(({ ioc, ti }, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs bg-slate-800 border border-red-900/30 rounded px-2.5 py-1.5">
                  <span className={`px-1.5 py-0.5 rounded font-medium text-xs ${TYPE_STYLE[ioc.type] ?? 'bg-slate-700 text-slate-400'}`}>
                    {ioc.type}
                  </span>
                  <span className="font-mono text-slate-300 truncate flex-1" title={ioc.value}>{ioc.value}</span>
                  <div className="flex gap-1 flex-shrink-0">
                    {ti.vtMalicious !== null && ti.vtTotal !== null && (
                      <VtBadge malicious={ti.vtMalicious} total={ti.vtTotal} />
                    )}
                    {ti.abuseScore !== null && (
                      <AbuseBadge score={ti.abuseScore} />
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {flagged.length === 0 && (
            <p className="text-xs text-green-400">
              All {enriched.length} checked IOC{enriched.length !== 1 ? 's' : ''} returned clean results from VirusTotal / AbuseIPDB.
            </p>
          )}
        </div>
      ) : (
        <div className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 flex items-start gap-2">
          <svg className="w-3.5 h-3.5 text-slate-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-xs text-slate-500">
            {isQuickScan ? (
              <>Threat intel enrichment is not run during Quick Scan. Run <span className="text-slate-300 font-medium">AI Analysis</span> to trigger VirusTotal / AbuseIPDB reputation lookups on IPs and domains.</>
            ) : tiStatus && !tiStatus.vt_configured && !tiStatus.abuseipdb_configured ? (
              <>No API keys configured — add <code className="bg-slate-900 px-1 rounded border border-slate-700">VT_API_KEY</code> and <code className="bg-slate-900 px-1 rounded border border-slate-700">ABUSEIPDB_KEY</code> to <code className="bg-slate-900 px-1 rounded border border-slate-700">.env</code> and restart the server.</>
            ) : tiStatus && (!tiStatus.vt_configured || !tiStatus.abuseipdb_configured) ? (
              <>Partial configuration — {!tiStatus.vt_configured && <><code className="bg-slate-900 px-1 rounded border border-slate-700">VT_API_KEY</code> missing</>}{!tiStatus.vt_configured && !tiStatus.abuseipdb_configured && ' and '}{!tiStatus.abuseipdb_configured && <><code className="bg-slate-900 px-1 rounded border border-slate-700">ABUSEIPDB_KEY</code> missing</>}. No IP or domain IOCs were found in this dataset, or the API returned no results.</>
            ) : (
              <>API keys are configured. No IP or domain IOCs were found in this dataset, or the external lookup returned no results for these values.</>
            )}
          </p>
        </div>
      )}

      {/* IOC table */}
      <div className="overflow-x-auto max-h-64 overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-800">
            <tr>
              <th className="text-left px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide w-24">Type</th>
              <th className="text-left px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide">Value</th>
              <th className="text-left px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide">Context</th>
              <th className="text-left px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide w-32">Reputation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {parsed.map(({ ioc, ti }, idx) => {
              const isFlagged = (ti.vtMalicious ?? 0) > 0 || (ti.abuseScore ?? 0) >= 30
              return (
                <tr key={idx} className={isFlagged ? 'bg-red-950/20' : 'hover:bg-slate-800/50'}>
                  <td className="px-2 py-1.5">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${TYPE_STYLE[ioc.type] ?? 'bg-slate-800 text-slate-400'}`}>
                      {ioc.type}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 font-mono text-slate-300 max-w-[200px] truncate" title={ioc.value}>
                    {ioc.value}
                  </td>
                  <td className="px-2 py-1.5 text-slate-500 max-w-[200px] truncate" title={ti.cleanContext}>
                    {ti.cleanContext}
                  </td>
                  <td className="px-2 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      {ti.vtMalicious !== null && ti.vtTotal !== null && (
                        <VtBadge malicious={ti.vtMalicious} total={ti.vtTotal} />
                      )}
                      {ti.abuseScore !== null && (
                        <AbuseBadge score={ti.abuseScore} />
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

import type { ForensicEvent, Upload } from '../types'

interface Props {
  events: ForensicEvent[]
  uploads?: Upload[]
}

const SUSPICIOUS_KEYWORDS = ['certutil', 'vssadmin', 'mshta', 'wmic', 'powershell -enc', 'powershell.exe -enc']
const LOGON_EVENT_IDS     = new Set(['4624', '4648', '4768', '4769'])
const NETWORK_PROTOCOLS   = new Set(['DNS', 'HTTP', 'TLS', 'TCP', 'UDP', 'ICMP', 'SMB', 'SMB2', 'KERBEROS', 'FTP', 'SMTP', 'QUIC', 'NBNS', 'LDAP'])

const SOURCE_COLORS = [
  'bg-sky-900/40 text-sky-400',
  'bg-lime-900/40 text-lime-400',
  'bg-fuchsia-900/40 text-fuchsia-400',
  'bg-orange-900/40 text-orange-400',
  'bg-teal-900/40 text-teal-400',
  'bg-rose-900/40 text-rose-400',
  'bg-indigo-900/40 text-indigo-400',
  'bg-yellow-900/40 text-yellow-400',
]

function rowHighlight(event: ForensicEvent): string {
  const desc = event.description.toLowerCase()
  if (SUSPICIOUS_KEYWORDS.some(kw => desc.includes(kw))) return 'border-l-4 border-amber-500 bg-amber-950/20'
  if (event.event_id && LOGON_EVENT_IDS.has(event.event_id))  return 'border-l-4 border-blue-500 bg-blue-950/20'
  if (event.raw_source === 'pcap')                             return 'border-l-4 border-purple-500 bg-purple-950/20'
  return 'border-l-4 border-transparent'
}

function SourceBadge({ event }: { event: ForensicEvent }) {
  if (event.raw_source !== 'pcap') return null
  const proto   = event.event_type.toUpperCase()
  const isKnown = NETWORK_PROTOCOLS.has(proto)
  return (
    <span className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-semibold
      ${isKnown ? 'bg-purple-900/40 text-purple-400' : 'bg-slate-800 text-slate-500'}`}>
      <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
          d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
      </svg>
      NET
    </span>
  )
}

export default function Timeline({ events, uploads = [] }: Props) {
  const uploadMap = new Map<number, { label: string; color: string }>()
  uploads.forEach((u, idx) => {
    const label = u.filename.length > 20 ? u.filename.slice(0, 18) + '…' : u.filename
    uploadMap.set(u.id, { label, color: SOURCE_COLORS[idx % SOURCE_COLORS.length] })
  })
  const multiSource = uploads.length > 1

  if (events.length === 0) {
    return (
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-800 p-12 text-center">
        <svg className="mx-auto h-10 w-10 mb-3 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p className="text-sm text-slate-500">No events match the current filters.</p>
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden">
      {/* Header / legend */}
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
        <span className="text-sm font-medium text-slate-300">{events.length} events</span>
        <div className="flex flex-wrap gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-3 border-l-4 border-blue-500 bg-blue-950/30 rounded-sm" />
            Logon
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-3 border-l-4 border-amber-500 bg-amber-950/30 rounded-sm" />
            Suspicious tool
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-3 border-l-4 border-purple-500 bg-purple-950/30 rounded-sm" />
            Network (PCAP)
          </span>
          {multiSource && (
            <span className="font-medium" style={{ color: '#00F0FF' }}>
              {uploads.length} sources merged
            </span>
          )}
        </div>
      </div>

      {/* Source legend */}
      {multiSource && (
        <div className="px-4 py-2 border-b border-slate-800 bg-slate-100/50 dark:bg-slate-800/50 flex flex-wrap gap-2">
          {uploads.map((u, idx) => {
            const info = uploadMap.get(u.id)
            return info ? (
              <span key={u.id} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${info.color}`}>
                <span className="font-bold">#{idx + 1}</span>
                {info.label}
                <span className="opacity-60">({u.event_count} events)</span>
              </span>
            ) : null
          })}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800">
              {['Timestamp', 'Host', 'User', 'Type', 'Event ID'].map(h => (
                <th key={h} className="px-3 py-2 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
              ))}
              {multiSource && (
                <th className="px-3 py-2 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">Source</th>
              )}
              <th className="px-3 py-2 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {events.map(event => {
              const srcInfo = event.upload_id != null ? uploadMap.get(event.upload_id) : undefined
              return (
                <tr key={event.id} className={`${rowHighlight(event)} hover:bg-slate-800/40 transition-colors`}>
                  <td className="px-3 py-2 font-mono text-xs text-slate-500 whitespace-nowrap">
                    {event.timestamp.replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-300 whitespace-nowrap font-medium">
                    {event.source_host}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400 whitespace-nowrap">
                    {event.user ?? <span className="text-slate-700">—</span>}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400 whitespace-nowrap max-w-[160px]">
                    <div className="flex items-center gap-1">
                      <SourceBadge event={event} />
                      <span className="truncate">{event.event_type}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs font-mono text-slate-500 whitespace-nowrap">
                    {event.event_id ?? <span className="text-slate-700">—</span>}
                  </td>
                  {multiSource && (
                    <td className="px-3 py-2 text-xs whitespace-nowrap">
                      {srcInfo
                        ? <span className={`px-1.5 py-0.5 rounded font-medium text-[10px] ${srcInfo.color}`}>{srcInfo.label}</span>
                        : <span className="text-slate-700">—</span>
                      }
                    </td>
                  )}
                  <td className="px-3 py-2 text-xs text-slate-400 max-w-xs truncate" title={event.description}>
                    {event.description.slice(0, 120)}{event.description.length > 120 ? '…' : ''}
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

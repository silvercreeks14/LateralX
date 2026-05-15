import { useState } from 'react'
import type { EventSummary } from '../types'

interface Props {
  summary: EventSummary
  onFilterChange: (filters: Record<string, string>) => void
}

const selectClass = `bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white rounded-lg text-sm px-3 py-1.5
  focus:outline-none focus:border-cyan-500/60 min-w-[160px] cursor-pointer`

export default function FilterBar({ summary, onFilterChange }: Props) {
  const [host,      setHost]      = useState('')
  const [user,      setUser]      = useState('')
  const [eventType, setEventType] = useState('')

  const handleChange = (field: 'host' | 'user' | 'event_type', value: string) => {
    const next = {
      host:       field === 'host'       ? value : host,
      user:       field === 'user'       ? value : user,
      event_type: field === 'event_type' ? value : eventType,
    }
    if (field === 'host')       setHost(value)
    if (field === 'user')       setUser(value)
    if (field === 'event_type') setEventType(value)
    onFilterChange(Object.fromEntries(Object.entries(next).filter(([, v]) => v)))
  }

  return (
    <div className="flex gap-4 flex-wrap items-center">
      <div className="flex flex-col gap-1">
        <label className="text-xs font-medium text-slate-500 uppercase tracking-wide">Host</label>
        <select value={host} onChange={e => handleChange('host', e.target.value)} className={selectClass}>
          <option value="">All hosts</option>
          {summary.hosts.map(h => <option key={h} value={h}>{h}</option>)}
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label className="text-xs font-medium text-slate-500 uppercase tracking-wide">User</label>
        <select value={user} onChange={e => handleChange('user', e.target.value)} className={selectClass}>
          <option value="">All users</option>
          {summary.users.map(u => <option key={u} value={u}>{u}</option>)}
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label className="text-xs font-medium text-slate-500 uppercase tracking-wide">Event Type</label>
        <select value={eventType} onChange={e => handleChange('event_type', e.target.value)}
          className={`${selectClass} min-w-[200px]`}>
          <option value="">All types</option>
          {summary.event_types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {(host || user || eventType) && (
        <div className="flex flex-col gap-1 mt-auto">
          <label className="text-xs text-transparent">clear</label>
          <button
            onClick={() => { setHost(''); setUser(''); setEventType(''); onFilterChange({}) }}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-500 hover:text-slate-200 transition-colors"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  )
}

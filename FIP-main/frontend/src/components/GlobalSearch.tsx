import { useState, useRef, useEffect, useCallback } from 'react'
import { api } from '../api/client'
import type { SearchResponse } from '../types'

interface Props {
  onNavigateCase?: (caseId: string) => void
}

export default function GlobalSearch({ onNavigateCase }: Props) {
  const [open,    setOpen]    = useState(false)
  const [query,   setQuery]   = useState('')
  const [results, setResults] = useState<SearchResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const inputRef     = useRef<HTMLInputElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); setOpen(true); setTimeout(() => inputRef.current?.focus(), 50) }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false)
    }
    if (open) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const runSearch = useCallback(async (q: string) => {
    if (q.trim().length < 2) { setResults(null); return }
    setLoading(true)
    try { setResults(await api.search(q.trim())) }
    catch { setResults(null) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    const t = setTimeout(() => runSearch(query), 300)
    return () => clearTimeout(t)
  }, [query, runSearch])

  const handleOpen = () => { setOpen(true); setTimeout(() => inputRef.current?.focus(), 50) }

  return (
    <div className="relative flex-1 max-w-xs" ref={containerRef}>
      <button
        onClick={handleOpen}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-500 hover:border-slate-600 hover:text-slate-300 text-xs transition-colors w-full"
        title="Global search (Ctrl+K)"
      >
        <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <span className="flex-1 text-left">Search</span>
        <kbd className="hidden sm:inline-block px-1 py-0.5 bg-slate-800 rounded text-[10px] text-slate-600">Ctrl+K</kbd>
      </button>

      {open && (
        <div className="absolute left-0 top-full mt-2 w-[480px] bg-slate-900 rounded-xl shadow-2xl border border-slate-800 z-50 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
            <svg className="w-4 h-4 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search events and notes…"
              className="flex-1 text-sm outline-none bg-transparent text-white placeholder-slate-600"
            />
            {loading && (
              <svg className="animate-spin w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
            )}
            <button onClick={() => setOpen(false)} className="text-slate-600 hover:text-slate-400 text-lg leading-none ml-1">×</button>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {results && results.total === 0 && query.trim().length >= 2 && (
              <p className="px-4 py-6 text-center text-sm text-slate-500">No results for "{query}"</p>
            )}

            {results && results.events.length > 0 && (
              <div>
                <div className="px-4 py-1.5 bg-slate-800 text-[10px] font-semibold text-slate-500 uppercase tracking-wide">
                  Events ({results.events.length})
                </div>
                {results.events.map(ev => (
                  <div key={ev.id} className="px-4 py-2.5 border-b border-slate-800/60 hover:bg-slate-800/50 cursor-default">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-[10px] font-mono text-slate-500">{ev.timestamp.slice(0, 19)}</span>
                      <span className="text-[10px] font-medium" style={{ color: '#00F0FF' }}>{ev.source_host}</span>
                      {ev.user && <span className="text-[10px] text-slate-500">{ev.user}</span>}
                      {ev.case_id && (
                        <button
                          className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 hover:bg-blue-900/50"
                          onClick={() => { onNavigateCase?.(ev.case_id!); setOpen(false) }}
                        >
                          case
                        </button>
                      )}
                    </div>
                    <p
                      className="text-xs text-slate-400"
                      dangerouslySetInnerHTML={{ __html: ev.snippet.replace(/<mark>/g, '<mark class="bg-yellow-500/30 rounded px-0.5 text-yellow-200">') }}
                    />
                  </div>
                ))}
              </div>
            )}

            {results && results.notes.length > 0 && (
              <div>
                <div className="px-4 py-1.5 bg-slate-800 text-[10px] font-semibold text-slate-500 uppercase tracking-wide">
                  Analyst Notes ({results.notes.length})
                </div>
                {results.notes.map(note => (
                  <div key={note.id} className="px-4 py-2.5 border-b border-slate-800/60 hover:bg-slate-800/50 cursor-default">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-[10px] font-medium text-amber-400">{note.author}</span>
                      <span className="text-[10px] text-slate-500">{note.created_at.slice(0, 10)}</span>
                      {note.case_id && (
                        <button
                          className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 hover:bg-blue-900/50"
                          onClick={() => { onNavigateCase?.(note.case_id!); setOpen(false) }}
                        >
                          case
                        </button>
                      )}
                    </div>
                    <p
                      className="text-xs text-slate-400"
                      dangerouslySetInnerHTML={{ __html: note.snippet.replace(/<mark>/g, '<mark class="bg-yellow-500/30 rounded px-0.5 text-yellow-200">') }}
                    />
                  </div>
                ))}
              </div>
            )}

            {!results && !loading && query.trim().length < 2 && (
              <p className="px-4 py-6 text-center text-xs text-slate-600">
                Type at least 2 characters to search across all events and notes
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

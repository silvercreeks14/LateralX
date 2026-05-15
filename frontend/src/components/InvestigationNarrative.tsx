import { useState, useCallback } from 'react'
import { api } from '../api/client'
import type { RCAResult, ForensicEvent, NarrativeCitation } from '../types'

interface Props {
  result: RCAResult
}

// ── Citation evidence callout ─────────────────────────────────────────────────

function CitationCallout({
  eventId,
  loading,
  event,
  onClose,
}: {
  eventId: number
  loading: boolean
  event: ForensicEvent | null
  onClose: () => void
}) {
  return (
    <div className="mt-3 bg-slate-800 border border-blue-700/40 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold text-blue-400">
          Cited Evidence — Event #{eventId}
        </span>
        <button onClick={onClose} className="text-xs text-slate-500 hover:text-slate-300">✕</button>
      </div>
      {loading ? (
        <p className="text-xs text-blue-400">Loading raw log…</p>
      ) : event ? (
        <div className="space-y-1 text-xs font-mono text-slate-300">
          <div><span className="text-slate-500">time:</span> {new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</div>
          <div><span className="text-slate-500">host:</span> {event.source_host}</div>
          {event.user     && <div><span className="text-slate-500">user:</span>    {event.user}</div>}
          {event.event_id && <div><span className="text-slate-500">EventID:</span> {event.event_id}</div>}
          <div><span className="text-slate-500">type:</span> {event.event_type}</div>
          <div className="mt-1.5 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 text-xs text-slate-700 dark:text-slate-300 break-all whitespace-pre-wrap leading-relaxed">
            {event.description}
          </div>
        </div>
      ) : null}
    </div>
  )
}

// ── Narrative body with clickable citation badges ─────────────────────────────

function NarrativeBody({
  citations,
  plainNarrative,
}: {
  citations: NarrativeCitation[]
  plainNarrative: string
}) {
  const [citedEventId,      setCitedEventId]      = useState<number | null>(null)
  const [citedEvent,        setCitedEvent]        = useState<ForensicEvent | null>(null)
  const [citedEventLoading, setCitedEventLoading] = useState(false)

  const handleCitationClick = useCallback(async (eventId: number) => {
    if (citedEventId === eventId) {
      setCitedEvent(null)
      setCitedEventId(null)
      return
    }
    setCitedEventId(eventId)
    setCitedEvent(null)
    setCitedEventLoading(true)
    try {
      setCitedEvent(await api.getEventById(eventId))
    } catch {
      setCitedEvent(null)
    } finally {
      setCitedEventLoading(false)
    }
  }, [citedEventId])

  if (!citations.length) {
    return (
      <blockquote className="text-sm text-slate-200 leading-relaxed border-l-4 border-blue-500 pl-4 italic">
        {plainNarrative}
      </blockquote>
    )
  }

  return (
    <div className="space-y-2">
      {citations.map((c, i) => (
        <p key={i} className="text-sm text-slate-200 leading-relaxed">
          <span className="italic">{c.sentence}</span>
          {c.event_ids.map(id => (
            <button
              key={id}
              onClick={() => handleCitationClick(id)}
              className={`ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono border transition-colors ${
                citedEventId === id
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-blue-900/30 text-blue-400 border-blue-700/40 hover:bg-blue-900/50'
              }`}
              title={`Show raw log for event #${id}`}
            >
              [{id}]
            </button>
          ))}
        </p>
      ))}

      {(citedEventLoading || citedEvent) && citedEventId != null && (
        <CitationCallout
          eventId={citedEventId}
          loading={citedEventLoading}
          event={citedEvent}
          onClose={() => { setCitedEvent(null); setCitedEventId(null) }}
        />
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function InvestigationNarrative({ result }: Props) {
  return (
    <div className="space-y-4">

      {/* ── Analyst narrative ──────────────────────────────────────────────── */}
      {result.narrative && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-800 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest">
              {result.windows_analyzed > 0 ? 'AI Investigation Narrative' : 'Investigation Summary'}
            </h3>
            {result.narrative_citations && result.narrative_citations.length > 0 && (
              <span className="text-xs text-blue-400 font-medium">
                {result.narrative_citations.length} cited sentences · click [id] to reveal evidence
              </span>
            )}
          </div>
          <NarrativeBody
            citations={result.narrative_citations ?? []}
            plainNarrative={result.narrative}
          />
        </div>
      )}

      {/* ── Patient zero + initial access ──────────────────────────────────── */}
      {(result.patient_zero_candidate || result.initial_access_vector) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-2">
              Patient Zero Candidate
            </h3>
            <p className="text-sm text-slate-200">
              {result.patient_zero_candidate || <span className="text-slate-600 italic">No candidate identified</span>}
            </p>
          </div>
          <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-2">
              Initial Access Vector
            </h3>
            <p className="text-sm text-slate-200">
              {result.initial_access_vector || <span className="text-slate-600 italic">Unknown</span>}
            </p>
          </div>
        </div>
      )}

      {/* ── Pivot chain ────────────────────────────────────────────────────── */}
      {result.pivot_chain.length > 0 && (
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3">
            Pivot Chain — Lateral Movement
          </h3>
          <ol className="space-y-2">
            {result.pivot_chain.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-blue-400 font-bold flex-shrink-0">{i + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* ── Anomalous events ───────────────────────────────────────────────── */}
      {result.anomalous_events.length > 0 && (
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-slate-800 p-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3">
            Anomalous Events Detected
          </h3>
          <ul className="space-y-1.5">
            {result.anomalous_events.map((ev, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-amber-400 flex-shrink-0">⚠</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

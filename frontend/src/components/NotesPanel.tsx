import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/client'
import type { Note } from '../types'

interface Props {
  caseId?: string
  analysisId?: number
}

export default function NotesPanel({ caseId, analysisId }: Props) {
  const [notes, setNotes] = useState<Note[]>([])
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadNotes = useCallback(async () => {
    try {
      const data = await api.listNotes(caseId, analysisId)
      setNotes(data)
    } catch {
      // silent — panel may appear before any notes exist
    }
  }, [caseId, analysisId])

  useEffect(() => {
    loadNotes()
  }, [loadNotes])

  const handleCreate = async () => {
    const content = draft.trim()
    if (!content) return
    setSaving(true)
    setError(null)
    try {
      await api.createNote(content, caseId, analysisId)
      setDraft('')
      await loadNotes()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save note')
    } finally {
      setSaving(false)
    }
  }

  const handlePin = async (note: Note) => {
    try {
      await api.updateNote(note.id, { is_pinned: !note.is_pinned })
      await loadNotes()
    } catch { /* silent */ }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteNote(id)
      setNotes(prev => prev.filter(n => n.id !== id))
    } catch { /* silent */ }
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-3">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Analyst Notes</h3>

      {/* Note composer */}
      <div className="space-y-2">
        <textarea
          value={draft}
          onChange={e => setDraft(e.target.value)}
          placeholder="Add a note about this case or finding…"
          rows={3}
          className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-blue-300"
        />
        {error && <p className="text-xs text-red-600">{error}</p>}
        <button
          onClick={handleCreate}
          disabled={!draft.trim() || saving}
          className="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-md transition-colors"
        >
          {saving ? 'Saving…' : 'Add Note'}
        </button>
      </div>

      {/* Notes list */}
      {notes.length === 0 ? (
        <p className="text-xs text-gray-400 italic">No notes yet.</p>
      ) : (
        <ul className="space-y-2">
          {notes.map(note => (
            <li
              key={note.id}
              className={`rounded-lg border px-3 py-2.5 text-sm ${
                note.is_pinned
                  ? 'bg-amber-50 border-amber-200'
                  : 'bg-gray-50 border-gray-100'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <p className="text-gray-800 leading-relaxed flex-1">{note.content}</p>
                <div className="flex gap-1 flex-shrink-0 mt-0.5">
                  <button
                    onClick={() => handlePin(note)}
                    title={note.is_pinned ? 'Unpin' : 'Pin'}
                    className={`text-xs px-1.5 py-0.5 rounded transition-colors ${
                      note.is_pinned
                        ? 'text-amber-600 hover:text-amber-800'
                        : 'text-gray-400 hover:text-amber-500'
                    }`}
                  >
                    ★
                  </button>
                  <button
                    onClick={() => handleDelete(note.id)}
                    title="Delete"
                    className="text-xs px-1.5 py-0.5 rounded text-gray-300 hover:text-red-500 transition-colors"
                  >
                    ✕
                  </button>
                </div>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {note.author} · {new Date(note.created_at).toLocaleString()}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

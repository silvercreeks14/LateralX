import { useState, useRef, useEffect } from 'react'
import { api } from '../api/client'
import type { ChatMessage } from '../types'

const SUGGESTIONS = [
  'Were any new accounts created during the incident?',
  'What was the first suspicious event in the timeline?',
  'Which hosts were accessed by the attacker?',
  'Was any persistence mechanism established?',
  'Summarise all certutil or vssadmin usage.',
]

export default function ChatPanel() {
  const [history, setHistory] = useState<ChatMessage[]>([])
  const [input,   setInput]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [history, loading])

  const send = async (message: string) => {
    if (!message.trim()) return
    const userMsg: ChatMessage = { role: 'user', content: message }
    setHistory(h => [...h, userMsg])
    setInput('')
    setLoading(true)
    setError(null)
    try {
      const res = await api.chat(message, [...history, userMsg])
      setHistory(h => [...h, { role: 'assistant', content: res.response }])
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Chat failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-slate-900 rounded-2xl border border-slate-800 flex flex-col" style={{ height: 560 }}>
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-shrink-0">
        <div>
          <h2 className="text-sm font-semibold text-white">Analyst Chat</h2>
          <p className="text-xs text-slate-500">Ask questions about the loaded timeline</p>
        </div>
        {history.length > 0 && (
          <button
            onClick={() => { setHistory([]); setError(null) }}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
        {history.length === 0 && (
          <div className="py-6">
            <p className="text-xs text-slate-600 mb-3 text-center">Suggested questions</p>
            <div className="flex flex-col gap-2">
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  className="text-left text-xs px-3 py-2 border border-slate-700 rounded-lg text-slate-400 hover:bg-slate-800 hover:border-slate-600 hover:text-slate-200 transition-colors"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {history.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-[80%] px-3 py-2 rounded-lg text-sm leading-relaxed whitespace-pre-wrap ${
                msg.role === 'user'
                  ? 'text-slate-900 rounded-br-sm'
                  : 'bg-slate-800 text-slate-200 rounded-bl-sm'
              }`}
              style={msg.role === 'user' ? { background: '#00F0FF' } : {}}
            >
              {msg.content}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-800 px-3 py-2 rounded-lg rounded-bl-sm flex gap-1">
              {[0, 1, 2].map(i => (
                <span
                  key={i}
                  className="w-1.5 h-1.5 rounded-full bg-slate-500 animate-bounce"
                  style={{ animationDelay: `${i * 0.15}s` }}
                />
              ))}
            </div>
          </div>
        )}

        {error && (
          <div className="text-xs text-red-400 bg-red-950/30 border border-red-800/40 rounded-lg px-3 py-2">
            {error}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <div className="border-t border-slate-800 px-3 py-2 flex gap-2 flex-shrink-0">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send(input)}
          placeholder="Ask about the timeline…"
          className="flex-1 text-sm px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg focus:outline-none placeholder-slate-600"
          onFocus={e => { e.currentTarget.style.borderColor = '#00F0FF60' }}
          onBlur={e => { e.currentTarget.style.borderColor = '' }}
          disabled={loading}
        />
        <button
          onClick={() => send(input)}
          disabled={loading || !input.trim()}
          className="px-4 py-2 text-slate-900 text-sm font-medium rounded-lg disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          style={{ background: '#00F0FF' }}
          onMouseEnter={e => { if (!loading && input.trim()) (e.currentTarget as HTMLButtonElement).style.background = '#00D8E8' }}
          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = '#00F0FF' }}
        >
          Send
        </button>
      </div>
    </div>
  )
}

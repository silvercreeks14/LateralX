import { useState } from 'react'

interface Props {
  actionLabel: string
  onConfirm: (code: string) => void
  onCancel: () => void
}

export default function MfaModal({ actionLabel, onConfirm, onCancel }: Props) {
  const [code, setCode] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = code.trim()
    if (!/^\d{6}$/.test(trimmed)) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
    setError('')
    onConfirm(trimmed)
  }

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl w-full max-w-sm p-6">
        <div className="flex items-start gap-3 mb-4">
          <div className="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center"
            style={{ background: '#f59e0b20', border: '1px solid #f59e0b40' }}>
            <svg className="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">Admin MFA Required</h2>
            <p className="text-sm text-slate-500 mt-0.5">
              Action: <span className="font-medium text-slate-300">{actionLabel}</span>
            </p>
          </div>
        </div>

        <div className="bg-amber-950/30 border border-amber-700/40 rounded-xl px-3 py-2.5 mb-4">
          <p className="text-xs text-amber-300 leading-relaxed">
            Open <strong>Google Authenticator</strong> (or any TOTP app) and enter the current
            6-digit code for the <strong>LateralX</strong> account.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1 uppercase tracking-wide">
              Authenticator Code
            </label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              autoFocus
              className="w-full bg-slate-800 border border-slate-700 text-white rounded-lg px-3 py-2.5 text-center font-mono text-xl tracking-widest focus:outline-none placeholder-slate-600"
              onFocus={e => { e.currentTarget.style.boxShadow = '0 0 0 2px #f59e0b40'; e.currentTarget.style.borderColor = '#f59e0b60' }}
              onBlur={e => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = '' }}
            />
            <p className="text-xs text-slate-600 mt-1">The code refreshes every 30 seconds.</p>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={onCancel}
              className="flex-1 border border-slate-700 text-slate-300 rounded-lg py-2 text-sm font-medium hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={code.length !== 6}
              className="flex-1 bg-amber-500 hover:bg-amber-600 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg py-2 text-sm font-medium transition-colors"
            >
              Verify &amp; Proceed
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

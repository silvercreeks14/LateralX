import { useState, useRef, useEffect } from 'react'
import { api, setToken } from '../api/client'

interface Props {
  onLogin: () => void
}

type Step = 'credentials' | 'mfa'

export default function Login({ onLogin }: Props) {
  const [step, setStep] = useState<Step>('credentials')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [pendingUsername, setPendingUsername] = useState('')
  const [pendingPassword, setPendingPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const codeInputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (step === 'mfa') codeInputRef.current?.focus()
  }, [step])

  const handleCredentials = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const res = await api.loginInit(username, password)
      if ('mfa_required' in res && res.mfa_required) {
        setPendingUsername(username)
        setPendingPassword(password)
        setStep('mfa')
      } else {
        const lr = res as import('../types').LoginResponse
        setToken(lr.access_token, lr.username, lr.role)
        onLogin()
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleMfa = async (e: React.FormEvent) => {
    e.preventDefault()
    if (mfaCode.length !== 6) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
    setError(null)
    setLoading(true)
    try {
      const res = await api.loginConfirm(pendingUsername, pendingPassword, mfaCode)
      setToken(res.access_token, res.username, res.role)
      onLogin()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid MFA code')
      setMfaCode('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      {/* Background grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(0,240,255,0.5) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0,240,255,0.5) 1px, transparent 1px)`,
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center gap-3 mb-4">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center font-black text-slate-900 text-lg"
              style={{ background: '#00F0FF' }}
            >
              LX
            </div>
            <span className="text-3xl font-black text-white dark:text-white tracking-tight">LateralX</span>
          </div>
          <p className="text-slate-500 text-sm">Threat Intelligence Platform</p>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 shadow-2xl">

          {/* ── Step 1: Credentials ── */}
          {step === 'credentials' && (
            <form onSubmit={handleCredentials} className="space-y-5">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                  Username
                </label>
                <input
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  className="w-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white rounded-lg px-4 py-2.5 text-sm
                             focus:outline-none focus:ring-2 focus:border-transparent placeholder-slate-400 dark:placeholder-slate-600"
                  style={{ '--tw-ring-color': '#00F0FF40' } as React.CSSProperties}
                  onFocus={e => { e.currentTarget.style.boxShadow = '0 0 0 2px #00F0FF40'; e.currentTarget.style.borderColor = '#00F0FF60' }}
                  onBlur={e => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = '' }}
                  placeholder="analyst"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                  Password
                </label>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  className="w-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white rounded-lg px-4 py-2.5 text-sm
                             focus:outline-none placeholder-slate-400 dark:placeholder-slate-600"
                  onFocus={e => { e.currentTarget.style.boxShadow = '0 0 0 2px #00F0FF40'; e.currentTarget.style.borderColor = '#00F0FF60' }}
                  onBlur={e => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = '' }}
                  placeholder="••••••••"
                />
              </div>

              {error && (
                <div className="bg-red-950 border border-red-800 text-red-300 text-sm rounded-lg px-4 py-3">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full font-semibold py-2.5 rounded-lg text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed text-slate-900"
                style={{ background: loading ? '#00C8D4' : '#00F0FF' }}
                onMouseEnter={e => { if (!loading) e.currentTarget.style.background = '#00D8E8' }}
                onMouseLeave={e => { if (!loading) e.currentTarget.style.background = '#00F0FF' }}
              >
                {loading ? 'Authenticating…' : 'Sign in'}
              </button>
            </form>
          )}

          {/* ── Step 2: MFA ── */}
          {step === 'mfa' && (
            <form onSubmit={handleMfa} className="space-y-5">
              <button
                type="button"
                onClick={() => { setStep('credentials'); setError(null); setMfaCode('') }}
                className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors mb-2"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Back
              </button>

              <div className="flex flex-col items-center gap-3 py-2">
                <div className="w-12 h-12 rounded-full border flex items-center justify-center"
                  style={{ background: '#00F0FF15', borderColor: '#00F0FF40' }}>
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"
                    style={{ color: '#00F0FF' }}>
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                </div>
                <div className="text-center">
                  <p className="text-white font-semibold text-sm">Authenticator Verification</p>
                  <p className="text-slate-400 text-xs mt-1">
                    Enter the code for <span className="font-mono" style={{ color: '#00F0FF' }}>{pendingUsername}</span>
                  </p>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                  6-Digit Code
                </label>
                <input
                  ref={codeInputRef}
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={e => {
                    const v = e.target.value.replace(/\D/g, '').slice(0, 6)
                    setMfaCode(v)
                    setError(null)
                  }}
                  placeholder="000000"
                  className="w-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white rounded-lg px-4 py-3 text-xl
                             tracking-[0.5em] text-center font-mono focus:outline-none placeholder-slate-400 dark:placeholder-slate-600"
                  onFocus={e => { e.currentTarget.style.boxShadow = '0 0 0 2px #00F0FF40'; e.currentTarget.style.borderColor = '#00F0FF60' }}
                  onBlur={e => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = '' }}
                />
                <p className="text-xs text-slate-600 mt-1.5">Code refreshes every 30 seconds.</p>
              </div>

              {error && (
                <div className="bg-red-950 border border-red-800 text-red-300 text-sm rounded-lg px-4 py-3">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="w-full font-semibold py-2.5 rounded-lg text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed text-slate-900"
                style={{ background: '#00F0FF' }}
              >
                {loading ? 'Verifying…' : 'Verify & Sign in'}
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-xs text-slate-700 mt-6">
          Contact your system administrator for access.
        </p>
      </div>
    </div>
  )
}

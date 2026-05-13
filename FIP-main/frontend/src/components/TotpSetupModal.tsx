import { useState } from 'react'
import { api } from '../api/client'
import type { TotpSetupResult } from '../types'

interface Props {
  onClose: () => void
}

export default function TotpSetupModal({ onClose }: Props) {
  const [step, setStep] = useState<'idle' | 'scanning' | 'verifying' | 'done' | 'error'>('idle')
  const [setup, setSetup] = useState<TotpSetupResult | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)

  const handleSetup = async () => {
    setStep('scanning')
    setError(null)
    try {
      const result = await api.setupTotp()
      setSetup(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Setup failed')
      setStep('error')
    }
  }

  const handleVerify = async () => {
    if (!code || code.length !== 6) return
    setStep('verifying')
    setError(null)
    try {
      await api.verifyTotp(code)
      setStep('done')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Verification failed')
      setStep('scanning')
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md">
        <div className="px-6 pt-6 pb-4 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-gray-900">Setup TOTP Authentication</h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none">×</button>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Link your admin account to Google Authenticator or a compatible TOTP app.
          </p>
        </div>

        <div className="px-6 py-5 space-y-4">
          {step === 'done' ? (
            <div className="text-center py-4">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-gray-800">TOTP Activated</p>
              <p className="text-xs text-gray-500 mt-1">Future logins will require your authenticator code.</p>
              <button onClick={onClose} className="mt-4 px-4 py-2 bg-green-600 text-white text-sm rounded-lg hover:bg-green-700">
                Done
              </button>
            </div>
          ) : step === 'idle' ? (
            <>
              <p className="text-sm text-gray-600">
                Click below to generate a QR code. Scan it in Google Authenticator, Authy, or any TOTP-compatible app.
              </p>
              <button
                onClick={handleSetup}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg"
              >
                Generate QR Code
              </button>
            </>
          ) : (
            <>
              {setup && (
                <>
                  <div className="flex justify-center">
                    <img
                      src={`data:image/png;base64,${setup.qr_code_png_b64}`}
                      alt="TOTP QR Code"
                      className="w-48 h-48 border border-gray-200 rounded-lg"
                    />
                  </div>
                  <p className="text-xs text-gray-500 text-center">{setup.instructions}</p>
                  <div className="bg-gray-50 rounded-lg p-3 text-xs font-mono text-gray-600 break-all select-all">
                    Manual key: {setup.secret}
                  </div>
                  <div className="space-y-2">
                    <label className="block text-xs font-medium text-gray-700">
                      Enter the 6-digit code from your app to activate
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={6}
                      value={code}
                      onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono tracking-[0.4em] text-center focus:outline-none focus:ring-2 focus:ring-blue-500"
                      onKeyDown={e => e.key === 'Enter' && handleVerify()}
                    />
                    {error && <p className="text-xs text-red-600">{error}</p>}
                    <button
                      onClick={handleVerify}
                      disabled={code.length !== 6 || step === 'verifying'}
                      className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg"
                    >
                      {step === 'verifying' ? 'Verifying…' : 'Activate TOTP'}
                    </button>
                  </div>
                </>
              )}
            </>
          )}
          {step === 'error' && (
            <p className="text-sm text-red-600">{error}</p>
          )}
        </div>
      </div>
    </div>
  )
}

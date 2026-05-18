import { useState, useCallback } from 'react'
import { api } from '../api/client'
import type { EventSummary, UploadResponse } from '../types'

interface Props {
  onUploadSuccess: (result: UploadResponse, file: File) => void
  activeCaseId?: string | null
  currentSummary?: EventSummary | null
}

export default function UploadPanel({ onUploadSuccess, activeCaseId, currentSummary }: Props) {
  const [uploading,   setUploading]   = useState(false)
  const [result,      setResult]      = useState<UploadResponse | null>(null)
  const [error,       setError]       = useState<string | null>(null)
  const [dragging,    setDragging]    = useState(false)
  const [pendingFile, setPendingFile] = useState<File | null>(null)

  const doUpload = useCallback(async (file: File, clearFirst: boolean) => {
    setUploading(true); setError(null); setResult(null); setPendingFile(null)
    try {
      if (clearFirst) await api.clearWorkspace()
      const res = activeCaseId
        ? await api.uploadFileToCase(file, activeCaseId)
        : await api.uploadFile(file)
      setResult(res)
      onUploadSuccess(res, file)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }, [onUploadSuccess, activeCaseId])

  const handleFile = useCallback((file: File) => {
    if (!activeCaseId && (currentSummary?.total ?? 0) > 0) { setPendingFile(file); return }
    doUpload(file, false)
  }, [activeCaseId, currentSummary, doUpload])

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault(); setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    e.target.value = ''
  }

  const dropZoneClass = dragging
    ? 'border-cyan-500 bg-cyan-50 dark:bg-cyan-950/20'
    : pendingFile
    ? 'border-amber-500 bg-amber-50 dark:bg-amber-950/20'
    : 'border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500'

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Upload Evidence File</h2>
        {activeCaseId && (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border"
            style={{ background: '#00F0FF10', borderColor: '#00F0FF30', color: '#00F0FF' }}>
            <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M2 6a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1H2V6zm-1 3a1 1 0 011-1h14a1 1 0 011 1v6a2 2 0 01-2 2H4a2 2 0 01-2-2V9z" clipRule="evenodd" />
            </svg>
            Tagged to active case
          </span>
        )}
      </div>

      <div
        onDrop={onDrop}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        className={`border-2 border-dashed rounded-xl p-10 text-center transition-colors ${dropZoneClass}`}
      >
        {uploading ? (
          <div className="flex flex-col items-center gap-2 text-slate-500">
            <svg className="animate-spin h-8 w-8" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <span className="text-sm">Uploading and parsing…</span>
          </div>
        ) : pendingFile ? (
          <div className="space-y-3">
            <div className="flex items-center justify-center gap-2 text-amber-300">
              <svg className="h-5 w-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <span className="text-sm font-semibold">
                Workspace has {currentSummary!.total.toLocaleString()} events loaded
              </span>
            </div>
            <p className="text-xs text-amber-400/80">
              Uploading will <strong>replace</strong> existing events.
              Use a <strong>Case</strong> for multi-source analysis.
            </p>
            <div className="flex items-center justify-center gap-3 pt-1">
              <button
                onClick={() => doUpload(pendingFile, false)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
              >
                Upload &amp; replace workspace
              </button>
              <button
                onClick={() => doUpload(pendingFile, true)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors"
              >
                Clear all &amp; upload fresh
              </button>
              <button
                onClick={() => setPendingFile(null)}
                className="px-3 py-2 text-sm text-slate-500 hover:text-slate-300 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <>
            <svg className="mx-auto h-10 w-10 mb-3 text-slate-600" stroke="currentColor" fill="none" viewBox="0 0 48 48">
              <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
              <span className="font-medium text-slate-700 dark:text-slate-300">Drag and drop</span> your timeline file here
            </p>
            <p className="text-xs text-slate-600 mb-4">Plaso L2T CSV · Timesketch JSONL · generic CSV · PCAP/PCAPng</p>
            <label
              className="cursor-pointer inline-block text-slate-900 text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
              style={{ background: '#00F0FF' }}
              onMouseEnter={e => (e.currentTarget.style.background = '#00D8E8')}
              onMouseLeave={e => (e.currentTarget.style.background = '#00F0FF')}
            >
              Browse file
              <input type="file" accept=".csv,.jsonl,.json,.pcap,.pcapng" className="hidden" onChange={onFileInput} />
            </label>
          </>
        )}
      </div>

      {result?.hash_changed && (
        <div className="mt-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-700/40 rounded-xl px-4 py-3 flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300">
          <span className="flex-shrink-0 font-bold">⚠</span>
          <span>
            <span className="font-semibold">File integrity warning:</span>{' '}
            <span className="font-mono">{result.filename}</span> was previously loaded with a different SHA-256 hash.
          </span>
        </div>
      )}

      {result && (
        <div className="mt-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800/40 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <svg className="h-5 w-5 text-green-600 dark:text-green-400 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <div className="flex-1">
              <p className="text-sm font-semibold text-green-700 dark:text-green-300">
                {result.events_loaded} events loaded from <span className="font-mono">{result.filename}</span>
              </p>
              <p className="text-xs text-green-600 dark:text-green-500 mt-1">
                {result.time_range.start.slice(0, 19).replace('T', ' ')} &rarr;{' '}
                {result.time_range.end.slice(0, 19).replace('T', ' ')}
              </p>
              {result.file_hash && (
                <p className="text-xs text-green-700 dark:text-green-600 mt-1 font-mono">
                  SHA-256: {result.file_hash.slice(0, 16)}…{result.file_hash.slice(-8)}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/40 rounded-xl p-4 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}
    </div>
  )
}
import { useState, useCallback } from 'react'
import { api } from '../api/client'
import type { EventSummary, UploadResponse } from '../types'

interface Props {
  onUploadSuccess: (result: UploadResponse) => void
  activeCaseId?: string | null
  currentSummary?: EventSummary | null
}

export default function UploadPanel({ onUploadSuccess, activeCaseId, currentSummary }: Props) {
  const [uploading,   setUploading]   = useState(false)
  const [result,      setResult]      = useState<UploadResponse | null>(null)
  const [error,       setError]       = useState<string | null>(null)
  const [dragging,    setDragging]    = useState(false)
  const [pendingFile, setPendingFile] = useState<File | null>(null)

  const doUpload = useCallback(async (file: File, clearFirst: boolean) => {
    setUploading(true); setError(null); setResult(null); setPendingFile(null)
    try {
      if (clearFirst) await api.clearWorkspace()
      const res = activeCaseId
        ? await api.uploadFileToCase(file, activeCaseId)
        : await api.uploadFile(file)
      setResult(res)
      onUploadSuccess(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }, [onUploadSuccess, activeCaseId])

  const handleFile = useCallback((file: File) => {
    if (!activeCaseId && (currentSummary?.total ?? 0) > 0) { setPendingFile(file); return }
    doUpload(file, false)
  }, [activeCaseId, currentSummary, doUpload])

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault(); setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    e.target.value = ''
  }

  const dropZoneClass = dragging
    ? 'border-cyan-500 bg-cyan-50 dark:bg-cyan-950/20'
    : pendingFile
    ? 'border-amber-500 bg-amber-50 dark:bg-amber-950/20'
    : 'border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500'

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Upload Evidence File</h2>
        {activeCaseId && (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border"
            style={{ background: '#00F0FF10', borderColor: '#00F0FF30', color: '#00F0FF' }}>
            <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M2 6a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1H2V6zm-1 3a1 1 0 011-1h14a1 1 0 011 1v6a2 2 0 01-2 2H4a2 2 0 01-2-2V9z" clipRule="evenodd" />
            </svg>
            Tagged to active case
          </span>
        )}
      </div>

      <div
        onDrop={onDrop}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        className={`border-2 border-dashed rounded-xl p-10 text-center transition-colors ${dropZoneClass}`}
      >
        {uploading ? (
          <div className="flex flex-col items-center gap-2 text-slate-500">
            <svg className="animate-spin h-8 w-8" fill="none" viewBox="0 0 24 24" style={{ color: '#00F0FF' }}>
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            <span className="text-sm">Uploading and parsing…</span>
          </div>
        ) : pendingFile ? (
          <div className="space-y-3">
            <div className="flex items-center justify-center gap-2 text-amber-300">
              <svg className="h-5 w-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <span className="text-sm font-semibold">
                Workspace has {currentSummary!.total.toLocaleString()} events loaded
              </span>
            </div>
            <p className="text-xs text-amber-400/80">
              Uploading will <strong>replace</strong> existing events.
              Use a <strong>Case</strong> for multi-source analysis.
            </p>
            <div className="flex items-center justify-center gap-3 pt-1">
              <button
                onClick={() => doUpload(pendingFile, false)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
              >
                Upload &amp; replace workspace
              </button>
              <button
                onClick={() => doUpload(pendingFile, true)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors"
              >
                Clear all &amp; upload fresh
              </button>
              <button
                onClick={() => setPendingFile(null)}
                className="px-3 py-2 text-sm text-slate-500 hover:text-slate-300 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <>
            <svg className="mx-auto h-10 w-10 mb-3 text-slate-600" stroke="currentColor" fill="none" viewBox="0 0 48 48">
              <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
              <span className="font-medium text-slate-700 dark:text-slate-300">Drag and drop</span> your timeline file here
            </p>
            <p className="text-xs text-slate-600 mb-4">Plaso L2T CSV · Timesketch JSONL · generic CSV · PCAP/PCAPng</p>
            <label
              className="cursor-pointer inline-block text-slate-900 text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
              style={{ background: '#00F0FF' }}
              onMouseEnter={e => (e.currentTarget.style.background = '#00D8E8')}
              onMouseLeave={e => (e.currentTarget.style.background = '#00F0FF')}
            >
              Browse file
              <input type="file" accept=".csv,.jsonl,.json,.pcap,.pcapng" className="hidden" onChange={onFileInput} />
            </label>
          </>
        )}
      </div>

      {result?.hash_changed && (
        <div className="mt-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-700/40 rounded-xl px-4 py-3 flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300">
          <span className="flex-shrink-0 font-bold">⚠</span>
          <span>
            <span className="font-semibold">File integrity warning:</span>{' '}
            <span className="font-mono">{result.filename}</span> was previously loaded with a different SHA-256 hash.
          </span>
        </div>
      )}

      {result && (
        <div className="mt-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800/40 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <svg className="h-5 w-5 text-green-600 dark:text-green-400 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <div className="flex-1">
              <p className="text-sm font-semibold text-green-700 dark:text-green-300">
                {result.events_loaded} events loaded from <span className="font-mono">{result.filename}</span>
              </p>
              <p className="text-xs text-green-600 dark:text-green-500 mt-1">
                {result.time_range.start.slice(0, 19).replace('T', ' ')} &rarr;{' '}
                {result.time_range.end.slice(0, 19).replace('T', ' ')}
              </p>
              {result.file_hash && (
                <p className="text-xs text-green-700 dark:text-green-600 mt-1 font-mono">
                  SHA-256: {result.file_hash.slice(0, 16)}…{result.file_hash.slice(-8)}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/40 rounded-xl p-4 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}
    </div>
  )
}

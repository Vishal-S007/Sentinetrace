import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { api, ApiError, type LogFormat, type LogSource, type SourceFormat } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Button, Empty, ErrorBanner, Field, Loading, PageHeader, Select, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'loaded'; sources: LogSource[]; formats: LogFormat[] }

const COMMON_ZONES = ['UTC', 'Asia/Kolkata', 'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles', 'Asia/Singapore', 'Australia/Sydney']

function message(err: unknown): string {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

async function fetchAll(): Promise<LoadState> {
  try {
    const [sources, formats] = await Promise.all([api.sources(), api.formats()])
    return { kind: 'loaded', sources, formats }
  } catch (err) {
    return { kind: 'error', message: message(err) }
  }
}

function formatLabel(formats: LogFormat[], id: SourceFormat): string {
  if (id === 'auto') return 'Auto-detect'
  return formats.find((f) => f.id === id)?.label ?? id
}

function CreateSourceForm({ formats, onCreated }: { formats: LogFormat[]; onCreated: (s: LogSource) => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [format, setFormat] = useState<SourceFormat>('auto')
  const [pattern, setPattern] = useState('')
  const [timezone, setTimezone] = useState('UTC')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const example = formats.find((f) => f.id === format)?.example

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const created = await api.createSource({
        name,
        description,
        format,
        timezone,
        custom_pattern: format === 'nginx_custom' ? pattern : null,
      })
      setName('')
      setDescription('')
      setPattern('')
      onCreated(created)
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} aria-label="Add log source" className="mb-6 space-y-3 rounded-md border border-line bg-panel p-4" noValidate>
      <h2 className="text-sm font-semibold">Add log source</h2>
      {error && <ErrorBanner message={error} />}
      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
        <Field label="Name">
          <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. web-prod-nginx" />
        </Field>
        <Field label="Format">
          <Select value={format} onChange={(e) => setFormat(e.target.value as SourceFormat)}>
            <option value="auto">Auto-detect per file</option>
            {formats.map((f) => (
              <option key={f.id} value={f.id}>
                {f.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Time zone" hint="Used when log timestamps have no UTC offset">
          <TextInput list="tz-list" value={timezone} onChange={(e) => setTimezone(e.target.value)} />
        </Field>
        <Field label="Description (optional)">
          <TextInput value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </div>
      <datalist id="tz-list">
        {COMMON_ZONES.map((z) => (
          <option key={z} value={z} />
        ))}
      </datalist>
      {format === 'nginx_custom' && (
        <Field label="Nginx log_format" hint="Paste the log_format string from nginx.conf; it must include $time_local, $time_iso8601 or $msec.">
          <textarea
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            rows={3}
            className="w-full rounded-md border border-line bg-base px-3 py-2 font-mono text-xs text-ink focus:border-accent focus:outline-none"
            placeholder='$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent'
          />
        </Field>
      )}
      {example && format !== 'nginx_custom' && (
        <p className="break-all font-mono text-xs text-ink-dim">
          <span className="font-sans">Example: </span>
          {example}
        </p>
      )}
      <Button type="submit" variant="primary" disabled={busy || !name.trim() || (format === 'nginx_custom' && !pattern.trim())}>
        {busy ? 'Creating…' : 'Create source'}
      </Button>
    </form>
  )
}

function UploadControl({ source, formats }: { source: LogSource; formats: LogFormat[] }) {
  const [file, setFile] = useState<File | null>(null)
  const [override, setOverride] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ ok: true; jobId: number } | { ok: false; text: string } | null>(null)
  const [inputKey, setInputKey] = useState(0)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!file) return
    setBusy(true)
    setResult(null)
    try {
      const { job } = await api.upload(source.id, file, override || undefined)
      setResult({ ok: true, jobId: job.id })
      setFile(null)
      setInputKey((k) => k + 1)
    } catch (err) {
      setResult({ ok: false, text: message(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} aria-label={`Upload to ${source.name}`} className="mt-3 space-y-2 border-t border-line pt-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <span className="sr-only">Log file for {source.name}</span>
          <input
            key={inputKey}
            type="file"
            accept=".log,.txt,.json,.jsonl,.ndjson,text/plain,application/json"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="block text-xs text-ink-dim file:mr-2 file:rounded-md file:border file:border-line file:bg-panel-2 file:px-2 file:py-1 file:text-ink"
            disabled={!source.enabled}
          />
        </label>
        <div className="w-60">
          <Select aria-label={`Format override for ${source.name}`} value={override} onChange={(e) => setOverride(e.target.value)} disabled={!source.enabled}>
            <option value="">Use source format</option>
            {formats
              .filter((f) => f.id !== 'nginx_custom' || source.custom_pattern)
              .map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
          </Select>
        </div>
        <Button type="submit" disabled={!file || busy || !source.enabled}>
          {busy ? 'Uploading…' : 'Upload'}
        </Button>
      </div>
      {!source.enabled && <p className="text-xs text-ink-dim">Enable this source to upload files.</p>}
      {result?.ok && (
        <p role="status" className="text-sm text-ok">
          Uploaded. Processing as{' '}
          <Link className="underline" to={`/jobs/${result.jobId}`}>
            job #{result.jobId}
          </Link>
          .
        </p>
      )}
      {result && !result.ok && <ErrorBanner message={result.text} />}
    </form>
  )
}

function SourceCard({ source, formats, canImport, onChanged }: {
  source: LogSource
  formats: LogFormat[]
  canImport: boolean
  onChanged: (s: LogSource) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function toggle() {
    setBusy(true)
    setError(null)
    try {
      onChanged(await api.updateSource(source.id, { enabled: !source.enabled }))
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="rounded-md border border-line bg-panel p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-medium">
            {source.name}
            {!source.enabled && <span className="ml-2 rounded border border-line px-1.5 text-xs text-ink-dim">Disabled</span>}
          </p>
          {source.description && <p className="text-sm text-ink-dim">{source.description}</p>}
        </div>
        {canImport && (
          <Button onClick={() => void toggle()} disabled={busy} variant={source.enabled ? 'secondary' : 'primary'}>
            {source.enabled ? 'Disable' : 'Enable'}
          </Button>
        )}
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-5">
        <div>
          <dt className="text-xs text-ink-dim">Format</dt>
          <dd>{formatLabel(formats, source.format)}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-dim">Time zone</dt>
          <dd className="font-mono text-xs">{source.timezone}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-dim">Files</dt>
          <dd>
            <Link className="hover:text-accent" to={`/jobs?source_id=${source.id}`}>
              {formatCount(source.file_count)}
            </Link>
          </dd>
        </div>
        <div>
          <dt className="text-xs text-ink-dim">Events</dt>
          <dd>{formatCount(source.event_count)}</dd>
        </div>
        <div>
          <dt className="text-xs text-ink-dim">Last upload</dt>
          <dd className="text-ink-dim">{formatDateTime(source.last_upload_at)}</dd>
        </div>
      </dl>
      {source.custom_pattern && <p className="mt-2 break-all font-mono text-xs text-ink-dim">{source.custom_pattern}</p>}
      {error && <div className="mt-2"><ErrorBanner message={error} /></div>}
      {canImport && <UploadControl source={source} formats={formats} />}
    </li>
  )
}

export function SourcesPage() {
  const { can } = useAuth()
  const canImport = can('logs:import')
  const [state, setState] = useState<LoadState>({ kind: 'loading' })

  useEffect(() => {
    let active = true
    void fetchAll().then((s) => active && setState(s))
    return () => {
      active = false
    }
  }, [])

  function upsert(source: LogSource) {
    setState((s) => {
      if (s.kind !== 'loaded') return s
      const exists = s.sources.some((x) => x.id === source.id)
      const sources = exists ? s.sources.map((x) => (x.id === source.id ? source : x)) : [...s.sources, source]
      return { ...s, sources: sources.sort((a, b) => a.name.localeCompare(b.name)) }
    })
  }

  return (
    <section>
      <PageHeader title="Log sources" subtitle="Where logs come from, how they are parsed, and file imports." />
      {state.kind === 'loading' && <Loading label="Loading log sources…" />}
      {state.kind === 'error' && <ErrorBanner message={`Could not load log sources: ${state.message}`} />}
      {state.kind === 'loaded' && (
        <>
          {canImport && <CreateSourceForm formats={state.formats} onCreated={upsert} />}
          {state.sources.length === 0 ? (
            <Empty>{canImport ? 'No log sources yet. Add one above, then upload a log file.' : 'No log sources have been configured.'}</Empty>
          ) : (
            <ul className="space-y-3">
              {state.sources.map((s) => (
                <SourceCard key={s.id} source={s} formats={state.formats} canImport={canImport} onChanged={upsert} />
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  )
}

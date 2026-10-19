import { Fragment, useCallback, useEffect, useState } from 'react'

import { api, ApiError, type HealthResponse, type ReadinessResponse, type SystemInfo } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ErrorBanner, Loading } from '../components/ui'
import { errorMessage } from '../lib/errors'
import { formatBytes, formatCount, formatDateTime } from '../lib/format'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'loaded'; health: HealthResponse; ready: ReadinessResponse; checkedAt: Date }

async function fetchStatus(): Promise<State> {
  try {
    const [health, ready] = await Promise.all([api.health(), api.ready()])
    return { kind: 'loaded', health, ready, checkedAt: new Date() }
  } catch (err) {
    const message = err instanceof ApiError ? err.message : 'Unexpected error'
    return { kind: 'error', message }
  }
}

function Indicator({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span
        aria-hidden
        className={`h-2.5 w-2.5 rounded-full ${ok ? 'bg-ok' : 'bg-crit'}`}
      />
      <span className={ok ? 'text-ok' : 'text-crit'}>{label}</span>
    </span>
  )
}

function show(value: unknown): string {
  if (value === null || value === undefined) return 'not set'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'none'
  if (typeof value === 'number') return value.toLocaleString()
  return String(value)
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-panel p-3">
      <dt className="text-xs text-ink-dim">{label}</dt>
      <dd className="mt-1 text-sm tabular-nums">{value}</dd>
    </div>
  )
}

function AdminSystem() {
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .system()
      .then((i) => active && setInfo(i))
      .catch((err: unknown) => active && setError(errorMessage(err)))
    return () => {
      active = false
    }
  }, [])

  if (error) return <div className="mt-6"><ErrorBanner message={`Could not load settings: ${error}`} /></div>
  if (!info) return <div className="mt-6"><Loading label="Loading settings…" /></div>
  const groups = [...new Set(info.settings.map((s) => s.group))]
  const usedPct = info.storage.total_bytes ? Math.round(100 - (100 * info.storage.free_bytes) / info.storage.total_bytes) : 0

  return (
    <>
      <section aria-label="Database, queue and storage" className="mt-6">
        <h2 className="mb-2 text-sm font-semibold">Database, queue and storage</h2>
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4">
          <Stat label="Database" value={`${info.database.name} on ${info.database.host}`} />
          <Stat label="PostgreSQL" value={info.database.server_version} />
          <Stat label="Database size" value={formatBytes(info.database.size_bytes)} />
          <Stat label="Events (approx.)" value={formatCount(info.database.rows.events ?? 0)} />
          <Stat label="Imports queued / running" value={`${info.queue.jobs_queued} / ${info.queue.jobs_running}`} />
          <Stat label="Failed imports" value={formatCount(info.queue.jobs_failed)} />
          <Stat label="Detection runs queued" value={`${info.queue.runs_queued} (+${info.queue.runs_running} running)`} />
          <Stat label="Last detection finished" value={formatDateTime(info.queue.last_detection_finished_at)} />
          <Stat label="Stored uploads" value={`${formatCount(info.storage.files)} files, ${formatBytes(info.storage.bytes)}`} />
          <Stat label="Disk free" value={`${formatBytes(info.storage.free_bytes)} (${usedPct}% used)`} />
          <Stat label="Alerts (approx.)" value={formatCount(info.database.rows.alerts ?? 0)} />
          <Stat label="Audit entries (approx.)" value={formatCount(info.database.rows.audit_log ?? 0)} />
        </dl>
      </section>

      <section aria-label="Application settings" className="mt-6">
        <h2 className="text-sm font-semibold">Application settings</h2>
        <p className="mb-2 text-xs text-ink-dim">
          Effective values. They are set with environment variables (see <code className="font-mono">.env.example</code>) and apply after a restart.
          Detection thresholds are changed under Detection rules, and retention under Data retention. Secrets are never shown.
        </p>
        <div className="overflow-x-auto rounded-md border border-line" tabIndex={0} role="region" aria-label="Settings table">
          <table className="w-full min-w-[640px] text-left text-sm">
            <tbody>
              {groups.map((g) => (
                <Fragment key={g}>
                  <tr className="bg-panel">
                    <th colSpan={3} scope="colgroup" className="px-3 py-2 text-xs uppercase tracking-wide text-ink-dim">
                      {g}
                    </th>
                  </tr>
                  {info.settings
                    .filter((s) => s.group === g)
                    .map((s) => (
                      <tr key={s.key} className="border-t border-line align-top">
                        <th scope="row" className="px-3 py-2 font-normal">
                          {s.description}
                        </th>
                        <td className="px-3 py-2 tabular-nums">{show(s.value)}</td>
                        <td className="px-3 py-2 font-mono text-xs text-ink-dim">{s.env}</td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

export function StatusPage() {
  const { can } = useAuth()
  const [state, setState] = useState<State>({ kind: 'loading' })

  const load = useCallback(() => {
    setState({ kind: 'loading' })
    void fetchStatus().then(setState)
  }, [])

  useEffect(() => {
    let active = true
    void fetchStatus().then((next) => {
      if (active) setState(next)
    })
    return () => {
      active = false
    }
  }, [])

  return (
    <section aria-labelledby="status-heading" className="max-w-5xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 id="status-heading" className="text-xl font-semibold">
            Settings &amp; status
          </h1>
          <p className="text-sm text-ink-dim">Live health of the API and database{can('settings:manage') ? ', and the effective application settings' : ''}.</p>
        </div>
        <button
          type="button"
          onClick={load}
          disabled={state.kind === 'loading'}
          className="rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm hover:border-accent disabled:opacity-50"
        >
          {state.kind === 'loading' ? 'Checking…' : 'Re-check'}
        </button>
      </div>

      {state.kind === 'loading' && (
        <p role="status" className="text-ink-dim">
          Checking API health…
        </p>
      )}

      {state.kind === 'error' && (
        <div role="alert" className="rounded-md border border-crit/40 bg-crit/10 p-4 text-sm">
          <p className="font-medium text-crit">API unreachable</p>
          <p className="mt-1 text-ink-dim">{state.message}</p>
        </div>
      )}

      {state.kind === 'loaded' && (
        <dl className="grid grid-cols-1 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-3">
          <div className="bg-panel p-4">
            <dt className="text-xs uppercase tracking-wide text-ink-dim">API</dt>
            <dd className="mt-2">
              <Indicator ok={state.health.status === 'ok'} label={state.health.status === 'ok' ? 'Online' : 'Degraded'} />
            </dd>
          </div>
          <div className="bg-panel p-4">
            <dt className="text-xs uppercase tracking-wide text-ink-dim">Database</dt>
            <dd className="mt-2">
              <Indicator
                ok={state.ready.database === 'ok'}
                label={state.ready.database === 'ok' ? 'Connected' : 'Unavailable'}
              />
            </dd>
          </div>
          <div className="bg-panel p-4">
            <dt className="text-xs uppercase tracking-wide text-ink-dim">Version</dt>
            <dd className="mt-2 font-mono text-sm">{state.health.version}</dd>
          </div>
          <div className="col-span-full flex gap-1 bg-panel px-4 py-2 text-xs text-ink-dim">
            <dt>Last checked</dt>
            <dd>{state.checkedAt.toLocaleTimeString()}</dd>
          </div>
        </dl>
      )}
      {can('settings:manage') && <AdminSystem />}
    </section>
  )
}

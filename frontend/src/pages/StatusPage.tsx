import { useCallback, useEffect, useState } from 'react'

import { api, ApiError, type HealthResponse, type ReadinessResponse } from '../api/client'

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

export function StatusPage() {
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
    <section aria-labelledby="status-heading" className="max-w-3xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 id="status-heading" className="text-xl font-semibold">
            System status
          </h1>
          <p className="text-sm text-ink-dim">Live health and readiness of the SentinelTrace API.</p>
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
          <p className="col-span-full bg-panel px-4 py-2 text-xs text-ink-dim">
            Last checked {state.checkedAt.toLocaleTimeString()}
          </p>
        </dl>
      )}
    </section>
  )
}

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { api, type DetectionRun, type Rule } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge } from '../components/badges'
import { errorMessage } from '../lib/errors'
import { Button, ErrorBanner, Loading, PageHeader, SuccessBanner } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'

function RunDetection() {
  const [runs, setRuns] = useState<DetectionRun[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .detectionRuns()
      .then((r) => active && setRuns(r))
      .catch(() => active && setRuns([]))
    return () => {
      active = false
    }
  }, [])

  async function run() {
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const r = await api.runDetection()
      setMessage(`Detection run #${r.id} queued. The worker re-evaluates all events with the current rule settings.`)
      setRuns(await api.detectionRuns())
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const last = runs?.[0]
  return (
    <section aria-label="Detection runs" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-panel p-4 text-sm">
      <div>
        <p>Rule changes apply to new imports. Re-run detection to apply them to events already imported.</p>
        {last && (
          <p className="text-xs text-ink-dim">
            Last run #{last.id}: {last.status}
            {last.status === 'completed' && ` · ${last.alerts_created} created, ${last.alerts_updated} updated`} · {formatDateTime(last.finished_at ?? last.created_at)}
          </p>
        )}
        {message && <div className="mt-2"><SuccessBanner message={message} /></div>}
        {error && <div className="mt-2"><ErrorBanner message={error} /></div>}
      </div>
      <Button onClick={() => void run()} disabled={busy}>
        {busy ? 'Queuing…' : 'Re-run detection'}
      </Button>
    </section>
  )
}

export function RulesPage() {
  const { can } = useAuth()
  const [rules, setRules] = useState<Rule[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .rules()
      .then((r) => active && setRules(r))
      .catch((err: unknown) => active && setError(errorMessage(err)))
    return () => {
      active = false
    }
  }, [])

  return (
    <section>
      <PageHeader title="Detection rules" subtitle="Deterministic rules run over imported events. Thresholds and severity are versioned; every change is audited." />
      {can('rules:manage') && <RunDetection />}
      {error && <ErrorBanner message={`Could not load rules: ${error}`} />}
      {!rules && !error && <Loading label="Loading rules…" />}
      {rules && (
        <div className="overflow-x-auto rounded-md border border-line" tabIndex={0} role="region" aria-label="Rules table">
          <table className="w-full min-w-[860px] text-left text-sm">
            <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
              <tr>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2 text-right">Version</th>
                <th className="px-3 py-2 text-right">Open alerts</th>
                <th className="px-3 py-2">Last changed</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id} className="border-t border-line align-top">
                  <td className="max-w-md px-3 py-2">
                    <Link to={`/rules/${r.rule_id}`} className="block text-ink hover:text-accent">
                      {r.name}
                    </Link>
                    <span className="font-mono text-xs text-ink-dim">{r.rule_id}</span>
                  </td>
                  <td className="px-3 py-2 capitalize text-ink-dim">{r.category}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="px-3 py-2">
                    {r.enabled ? <span className="text-ok">Enabled</span> : <span className="text-ink-dim">Disabled</span>}
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">v{r.version}</td>
                  <td className="px-3 py-2 text-right tabular-nums">
                    {r.open_alerts > 0 ? (
                      <Link to={`/alerts?rule_id=${r.rule_id}&status=new`} className="text-accent hover:underline">
                        {formatCount(r.open_alerts)}
                      </Link>
                    ) : (
                      0
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-dim">
                    {formatDateTime(r.updated_at)}
                    {r.updated_by && ` · ${r.updated_by}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

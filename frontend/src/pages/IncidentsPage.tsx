import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { api, type Incident, type IncidentFilters } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { IncidentStatusBadge, SeverityBadge } from '../components/badges'
import { errorMessage } from '../lib/errors'
import { Button, Empty, ErrorBanner, Field, Loading, PageHeader, Select, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'
import { INCIDENT_STATUSES, INCIDENT_STATUS_LABEL, SEVERITIES, SEVERITY_LABEL } from '../lib/severity'

const KEYS = ['status', 'severity', 'assigned_to', 'q', 'open_only'] as const

/** Incident list. Remounted (keyed by the query string) whenever the filters change. */
export function IncidentsPage() {
  const { can } = useAuth()
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => {
    const f: IncidentFilters = {}
    for (const k of KEYS) {
      const v = params.get(k)
      if (v) f[k] = v
    }
    return f
  }, [params])
  const [draft, setDraft] = useState<IncidentFilters>(filters)
  const [items, setItems] = useState<Incident[]>([])
  const [next, setNext] = useState<number | null>(null)
  const [phase, setPhase] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)

  useEffect(() => {
    let active = true
    api
      .incidents(filters)
      .then((p) => {
        if (!active) return
        setItems(p.items)
        setNext(p.next_before_id)
        setPhase('loaded')
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(errorMessage(err))
        setPhase('error')
      })
    return () => {
      active = false
    }
  }, [filters])

  async function more() {
    if (next === null) return
    setLoadingMore(true)
    try {
      const p = await api.incidents(filters, next)
      setItems((prev) => [...prev, ...p.items])
      setNext(p.next_before_id)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoadingMore(false)
    }
  }

  function apply(e: FormEvent) {
    e.preventDefault()
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(draft)) if (v) p.set(k, v)
    setParams(p)
  }
  const set = (k: keyof IncidentFilters, v: string) => setDraft((d) => ({ ...d, [k]: v || undefined }))

  return (
    <section>
      <PageHeader
        title="Incidents"
        subtitle="Related alerts grouped for investigation, with owner, status, notes and a timeline."
        actions={
          can('incidents:manage') ? (
            <Link to="/incidents/new" className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-on-accent hover:brightness-110">
              New incident
            </Link>
          ) : undefined
        }
      />
      <form onSubmit={apply} aria-label="Incident filters" className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-line bg-panel p-4">
        <div className="w-40">
          <Field label="Status">
            <Select value={draft.status ?? ''} onChange={(e) => set('status', e.target.value)}>
              <option value="">Any status</option>
              {INCIDENT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {INCIDENT_STATUS_LABEL[s]}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <div className="w-36">
          <Field label="Severity">
            <Select value={draft.severity ?? ''} onChange={(e) => set('severity', e.target.value)}>
              <option value="">Any severity</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <div className="w-40">
          <Field label="Owner">
            <Select value={draft.assigned_to ?? ''} onChange={(e) => set('assigned_to', e.target.value)}>
              <option value="">Anyone</option>
              <option value="me">Assigned to me</option>
              <option value="none">Unassigned</option>
            </Select>
          </Field>
        </div>
        <div className="w-56">
          <Field label="Title contains">
            <TextInput value={draft.q ?? ''} onChange={(e) => set('q', e.target.value)} />
          </Field>
        </div>
        <label className="flex items-center gap-2 pb-2 text-sm">
          <input type="checkbox" checked={draft.open_only === 'true'} onChange={(e) => set('open_only', e.target.checked ? 'true' : '')} />
          Hide resolved and closed
        </label>
        <Button type="submit" variant="primary">
          Apply
        </Button>
        <Button onClick={() => setParams(new URLSearchParams())}>Reset</Button>
      </form>

      {phase === 'loading' && <Loading label="Loading incidents…" />}
      {phase === 'error' && <ErrorBanner message={`Could not load incidents: ${error}`} />}
      {phase === 'loaded' && items.length === 0 && (
        <Empty>No incidents match. Create one from the alert queue by selecting related alerts, or from an alert's page.</Empty>
      )}
      {phase === 'loaded' && items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Incident</th>
                  <th className="px-3 py-2 text-right">Alerts</th>
                  <th className="px-3 py-2">Owner</th>
                  <th className="px-3 py-2">Updated</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id} className="border-t border-line align-top">
                    <td className="px-3 py-2">
                      <SeverityBadge severity={i.severity} />
                    </td>
                    <td className="w-full max-w-0 px-3 py-2">
                      <Link to={`/incidents/${i.id}`} className="block truncate text-ink hover:text-accent" title={i.title}>
                        {i.title}
                      </Link>
                      <span className="text-xs text-ink-dim">
                        #{i.id} · opened by {i.created_by}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">{formatCount(i.alert_count)}</td>
                    <td className="px-3 py-2 text-xs">{i.assignee ?? <span className="text-ink-dim">—</span>}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">{formatDateTime(i.updated_at)}</td>
                    <td className="px-3 py-2">
                      <IncidentStatusBadge status={i.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {next !== null && (
            <div className="mt-3 text-right">
              <Button onClick={() => void more()} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load older incidents'}
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

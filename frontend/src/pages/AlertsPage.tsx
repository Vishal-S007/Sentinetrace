import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { api, ApiError, type Alert, type AlertFilters, type RuleSummary } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AlertStatusBadge, ConfidenceLabel, SeverityBadge } from '../components/badges'
import { ExportLinks } from '../components/investigation'
import { Button, Empty, ErrorBanner, Field, Loading, PageHeader, Select, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'
import { ALERT_STATUSES, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL } from '../lib/severity'

const FILTER_KEYS = ['status', 'severity', 'rule_id', 'source_ip', 'assigned_to', 'q', 'since', 'until'] as const
const MAX_SELECTED = 200
const PAGE = 50

function msg(err: unknown) {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

/** The alert queue. Remounted (keyed by the query string) whenever the filters change. */
export function AlertsPage() {
  const { can } = useAuth()
  const navigate = useNavigate()
  const canGroup = can('incidents:manage')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => {
    const f: AlertFilters = {}
    for (const k of FILTER_KEYS) {
      const v = params.get(k)
      if (v) f[k] = v
    }
    return f
  }, [params])

  const [draft, setDraft] = useState<AlertFilters>(filters)
  const [rules, setRules] = useState<RuleSummary[]>([])
  const [items, setItems] = useState<Alert[]>([])
  const [next, setNext] = useState<number | null>(null)
  const [phase, setPhase] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)

  useEffect(() => {
    let active = true
    api
      .alerts(filters, undefined, PAGE)
      .then((page) => {
        if (!active) return
        setItems(page.items)
        setNext(page.next_before_id)
        setPhase('loaded')
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(msg(err))
        setPhase('error')
      })
    api
      .rules()
      .then((r) => active && setRules(r))
      .catch(() => {
        /* the rule filter falls back to free text if rules can't be loaded */
      })
    return () => {
      active = false
    }
  }, [filters])

  async function more() {
    if (next === null) return
    setLoadingMore(true)
    try {
      const page = await api.alerts(filters, next, PAGE)
      setItems((prev) => [...prev, ...page.items])
      setNext(page.next_before_id)
    } catch (err) {
      setError(msg(err))
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

  function toggle(id: number) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else if (next.size < MAX_SELECTED) next.add(id)
      return next
    })
  }

  const allShownSelected = items.length > 0 && items.every((a) => selected.has(a.id))
  function toggleAll() {
    setSelected((prev) => {
      const next = new Set(prev)
      for (const a of items) {
        if (allShownSelected) next.delete(a.id)
        else if (next.size < MAX_SELECTED) next.add(a.id)
      }
      return next
    })
  }

  const set = (k: keyof AlertFilters, v: string) => setDraft((d) => ({ ...d, [k]: v || undefined }))
  const timeFiltered = filters.since || filters.until

  return (
    <section>
      <PageHeader
        title="Alert queue"
        subtitle="Grouped detections, newest first. Each alert is an indicator to investigate, not confirmed compromise."
        actions={can('reports:export') ? <ExportLinks kind="alerts" filters={filters} /> : undefined}
      />

      <form onSubmit={apply} aria-label="Alert filters" className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-line bg-panel p-4">
        <div className="w-40">
          <Field label="Status">
            <Select value={draft.status ?? ''} onChange={(e) => set('status', e.target.value)}>
              <option value="">Any status</option>
              {ALERT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABEL[s]}
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
        <div className="w-72">
          <Field label="Rule">
            <Select value={draft.rule_id ?? ''} onChange={(e) => set('rule_id', e.target.value)}>
              <option value="">Any rule</option>
              {rules.map((r) => (
                <option key={r.rule_id} value={r.rule_id}>
                  {r.rule_id} · {r.name}
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
        <div className="w-44">
          <Field label="Source IP">
            <TextInput value={draft.source_ip ?? ''} onChange={(e) => set('source_ip', e.target.value)} />
          </Field>
        </div>
        <div className="w-52">
          <Field label="Title contains">
            <TextInput value={draft.q ?? ''} onChange={(e) => set('q', e.target.value)} />
          </Field>
        </div>
        <Button type="submit" variant="primary">
          Apply
        </Button>
        <Button onClick={() => setParams(new URLSearchParams())}>Reset</Button>
      </form>
      {timeFiltered && (
        <p className="mb-3 text-xs text-ink-dim">
          Active between {formatDateTime(filters.since ?? null)} and {formatDateTime(filters.until ?? null)} ·{' '}
          <button
            type="button"
            className="text-accent underline"
            onClick={() => {
              const p = new URLSearchParams(params)
              p.delete('since')
              p.delete('until')
              setParams(p)
            }}
          >
            clear time window
          </button>
        </p>
      )}

      {phase === 'loading' && <Loading label="Loading alerts…" />}
      {phase === 'error' && <ErrorBanner message={`Could not load alerts: ${error}`} />}
      {phase === 'loaded' && items.length === 0 && (
        <Empty>No alerts match these filters. Alerts appear here after imported logs are analysed.</Empty>
      )}
      {canGroup && selected.size > 0 && (
        <div role="region" aria-label="Selection" className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-accent/40 bg-accent/5 px-4 py-2 text-sm">
          <span>
            {selected.size} alert{selected.size === 1 ? '' : 's'} selected
            {selected.size >= MAX_SELECTED && ` (maximum ${MAX_SELECTED})`}
          </span>
          <Button variant="primary" onClick={() => navigate(`/incidents/new?alerts=${[...selected].join(',')}`)}>
            Create incident
          </Button>
          <Button onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      )}
      {phase === 'loaded' && items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-md border border-line" tabIndex={0} role="region" aria-label="Alerts table">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                <tr>
                  {canGroup && (
                    <th className="w-8 px-3 py-2">
                      <input type="checkbox" aria-label="Select all shown alerts" checked={allShownSelected} onChange={toggleAll} />
                    </th>
                  )}
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Alert</th>
                  <th className="px-3 py-2">Source IP</th>
                  <th className="px-3 py-2 text-right">Events</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Last seen</th>
                  <th className="px-3 py-2">Owner</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className={`border-t border-line align-top ${selected.has(a.id) ? 'bg-accent/5' : ''}`}>
                    {canGroup && (
                      <td className="px-3 py-2">
                        <input type="checkbox" aria-label={`Select alert ${a.id}`} checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                      </td>
                    )}
                    <td className="px-3 py-2">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="w-full max-w-0 px-3 py-2">
                      <Link to={`/alerts/${a.id}`} className="block truncate text-ink hover:text-accent" title={a.title}>
                        {a.title}
                      </Link>
                      <span className="font-mono text-xs text-ink-dim">
                        #{a.id} · {a.rule_id}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{a.source_ip ?? '—'}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{formatCount(a.event_count)}</td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <ConfidenceLabel confidence={a.confidence} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">{formatDateTime(a.last_seen)}</td>
                    <td className="px-3 py-2 text-xs">{a.assignee ?? <span className="text-ink-dim">—</span>}</td>
                    <td className="px-3 py-2">
                      <AlertStatusBadge status={a.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {next !== null && (
            <div className="mt-3 text-right">
              <Button onClick={() => void more()} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load older alerts'}
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

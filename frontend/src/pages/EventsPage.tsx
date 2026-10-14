import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { api, ApiError, type EventDetail, type EventFilters, type EventItem } from '../api/client'
import { SeverityBadge } from '../components/badges'
import { useAuth } from '../auth/AuthContext'
import { ExportLinks } from '../components/investigation'
import { Button, Empty, ErrorBanner, Field, Loading, PageHeader, Select, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'

const FILTER_KEYS = ['q', 'since', 'until', 'source_ip', 'event_type', 'http_status', 'method', 'username', 'source_id', 'flagged', 'alert_severity', 'alert_id'] as const
const EVENT_TYPES = ['http_request', 'auth_failure', 'auth_success', 'auth_other', 'app_log']
const PAGE = 50

function msg(err: unknown) {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

/** datetime-local (local time) <-> ISO UTC */
function toLocalInput(iso?: string) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}
function fromLocalInput(v: string) {
  return v ? new Date(v).toISOString() : ''
}

function EventDetailPanel({ id, onClose }: { id: number; onClose: () => void }) {
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .event(id)
      .then((d) => active && setDetail(d))
      .catch((err: unknown) => active && setError(msg(err)))
    return () => {
      active = false
    }
  }, [id])

  const fields: [string, string | number | null][] = detail
    ? [
        ['Event time', formatDateTime(detail.event_time)],
        ['Ingested', formatDateTime(detail.ingested_at)],
        ['Type', detail.event_type],
        ['Source IP', detail.source_ip],
        ['User', detail.username],
        ['Method', detail.http_method],
        ['Path', detail.path],
        ['Query', detail.query],
        ['Status', detail.http_status],
        ['Bytes', detail.bytes_sent],
        ['User agent', detail.user_agent],
        ['Referrer', detail.referrer],
        ['Host', detail.host],
        ['Level', detail.severity],
        ['Message', detail.message],
        ['Log source', detail.source_name],
        ['File / line', `${detail.filename} : ${detail.line_number}`],
      ]
    : []

  return (
    <aside aria-label={`Event ${id}`} className="rounded-md border border-line bg-panel p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Event #{id}</h2>
        <Button onClick={onClose}>Close</Button>
      </div>
      {error && <ErrorBanner message={error} />}
      {!detail && !error && <Loading label="Loading event…" />}
      {detail && (
        <div className="space-y-4 text-sm">
          <div>
            <p className="mb-1 text-xs uppercase tracking-wide text-ink-dim">Original log line</p>
            {/* Untrusted content: rendered as text only. */}
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-base p-2 font-mono text-xs">{detail.raw_line}</pre>
          </div>
          <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1">
            {fields
              .filter(([, v]) => v !== null && v !== '')
              .map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-ink-dim">{k}</dt>
                  <dd className="break-all">{v}</dd>
                </div>
              ))}
          </dl>
          {Object.keys(detail.attributes).length > 0 && (
            <div>
              <p className="mb-1 text-xs uppercase tracking-wide text-ink-dim">Attributes</p>
              <pre className="overflow-auto whitespace-pre-wrap break-all rounded bg-base p-2 font-mono text-xs">{JSON.stringify(detail.attributes, null, 2)}</pre>
            </div>
          )}
          <div>
            <p className="mb-1 text-xs uppercase tracking-wide text-ink-dim">Linked alerts</p>
            {detail.alerts.length === 0 ? (
              <p className="text-ink-dim">Not part of any alert.</p>
            ) : (
              <ul className="space-y-1">
                {detail.alerts.map((a) => (
                  <li key={a.id} className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <Link to={`/alerts/${a.id}`} className="text-accent hover:underline">
                      {a.title}
                    </Link>
                    {a.indicator && <span className="font-mono text-xs text-ink-dim">{a.indicator}</span>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </aside>
  )
}

export function EventsPage() {
  const { can } = useAuth()
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => {
    const f: EventFilters = {}
    for (const k of FILTER_KEYS) {
      const v = params.get(k)
      if (v) f[k] = v
    }
    return f
  }, [params])
  const filterKey = JSON.stringify(filters)

  const [draft, setDraft] = useState<EventFilters>(filters)
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [items, setItems] = useState<EventItem[]>([])
  const [next, setNext] = useState<string | null>(null)
  const [count, setCount] = useState<{ n: number; capped: boolean } | null>(null)
  const [phase, setPhase] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const cursor = cursors[cursors.length - 1]

  useEffect(() => {
    let active = true
    api
      .events(JSON.parse(filterKey) as EventFilters, cursor, PAGE)
      .then((page) => {
        if (!active) return
        setItems(page.items)
        setNext(page.next_cursor)
        if (page.count !== null) setCount({ n: page.count, capped: page.count_capped })
        setPhase('loaded')
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(msg(err))
        setPhase('error')
      })
    return () => {
      active = false
    }
  }, [filterKey, cursor])

  function apply(e: FormEvent) {
    e.preventDefault()
    const nextParams = new URLSearchParams()
    for (const [k, v] of Object.entries(draft)) if (v) nextParams.set(k, v)
    setPhase('loading')
    setCursors([undefined])
    setSelected(null)
    setParams(nextParams)
  }

  function reset() {
    setDraft({})
    setPhase('loading')
    setCursors([undefined])
    setParams(new URLSearchParams())
  }

  function set<K extends keyof EventFilters>(k: K, v: string) {
    setDraft((d) => ({ ...d, [k]: v || undefined }))
  }

  const pageNo = cursors.length

  return (
    <section>
      <PageHeader
        title="Event explorer"
        subtitle="Search and filter normalized events. Filtering and paging run on the server."
        actions={can('reports:export') ? <ExportLinks kind="events" filters={filters} /> : undefined}
      />

      <form onSubmit={apply} aria-label="Event filters" className="mb-4 rounded-md border border-line bg-panel p-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Search raw log line">
            <TextInput value={draft.q ?? ''} onChange={(e) => set('q', e.target.value)} placeholder="e.g. union%20select, sqlmap" />
          </Field>
          <Field label="Source IP or CIDR">
            <TextInput value={draft.source_ip ?? ''} onChange={(e) => set('source_ip', e.target.value)} placeholder="203.0.113.0/24" />
          </Field>
          <Field label="From">
            <TextInput type="datetime-local" value={toLocalInput(draft.since)} onChange={(e) => set('since', fromLocalInput(e.target.value))} />
          </Field>
          <Field label="To">
            <TextInput type="datetime-local" value={toLocalInput(draft.until)} onChange={(e) => set('until', fromLocalInput(e.target.value))} />
          </Field>
          <Field label="Event type">
            <Select value={draft.event_type ?? ''} onChange={(e) => set('event_type', e.target.value)}>
              <option value="">Any</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="HTTP status" hint="Code (404) or class (4xx)">
            <TextInput value={draft.http_status ?? ''} onChange={(e) => set('http_status', e.target.value)} maxLength={3} />
          </Field>
          <Field label="Detection status">
            <Select value={draft.flagged ?? ''} onChange={(e) => set('flagged', e.target.value)}>
              <option value="">Any</option>
              <option value="true">Linked to an alert</option>
              <option value="false">Not linked to an alert</option>
            </Select>
          </Field>
          <Field label="Alert severity">
            <Select value={draft.alert_severity ?? ''} onChange={(e) => set('alert_severity', e.target.value)}>
              <option value="">Any</option>
              {['low', 'medium', 'high', 'critical'].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary">
            Apply filters
          </Button>
          <Button onClick={reset}>Reset</Button>
          {filters.alert_id && (
            <span className="text-xs text-ink-dim">
              Showing evidence of{' '}
              <Link className="text-accent underline" to={`/alerts/${filters.alert_id}`}>
                alert #{filters.alert_id}
              </Link>
            </span>
          )}
        </div>
      </form>

      {phase === 'error' && <ErrorBanner message={`Could not load events: ${error}`} />}
      {phase === 'loading' && <Loading label="Loading events…" />}
      {phase === 'loaded' && items.length === 0 && <Empty>No events match these filters.</Empty>}
      {phase === 'loaded' && items.length > 0 && (
        <div className={`grid gap-4 ${selected ? 'xl:grid-cols-[1fr_28rem]' : ''}`}>
          <div className="min-w-0">
            <p className="mb-2 text-sm text-ink-dim">
              {count ? `${formatCount(count.n)}${count.capped ? '+' : ''} matching events` : ''} · page {pageNo}
            </p>
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                  <tr>
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Source IP</th>
                    <th className="px-3 py-2">Request / user</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr
                      key={e.id}
                      className={`cursor-pointer border-t border-line align-top hover:bg-panel-2 ${selected === e.id ? 'bg-panel-2' : ''}`}
                      onClick={() => setSelected(e.id)}
                    >
                      <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                        <button type="button" className="text-left hover:text-ink" aria-label={`Open event ${e.id}`} onClick={() => setSelected(e.id)}>
                          {formatDateTime(e.event_time)}
                        </button>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{e.event_type}</td>
                      <td className="px-3 py-2 font-mono text-xs">{e.source_ip ?? '—'}</td>
                      <td className="max-w-md px-3 py-2">
                        <span className="block truncate font-mono text-xs" title={e.raw_line}>
                          {e.http_method ? `${e.http_method} ${e.path ?? ''}${e.query ? `?${e.query}` : ''}` : e.message ?? e.username ?? e.raw_line}
                        </span>
                        {e.username && e.http_method && <span className="text-xs text-ink-dim">{e.username}</span>}
                      </td>
                      <td className="px-3 py-2 tabular-nums">{e.http_status ?? '—'}</td>
                      <td className="px-3 py-2">{e.max_alert_severity ? <SeverityBadge severity={e.max_alert_severity} /> : <span className="text-ink-dim">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between">
              <Button
                disabled={cursors.length === 1}
                onClick={() => {
                  setPhase('loading')
                  setCursors((c) => c.slice(0, -1))
                }}
              >
                ← Newer
              </Button>
              <Button
                disabled={!next}
                onClick={() => {
                  setPhase('loading')
                  setCursors((c) => [...c, next ?? undefined])
                }}
              >
                Older →
              </Button>
            </div>
          </div>
          {selected && <EventDetailPanel key={selected} id={selected} onClose={() => setSelected(null)} />}
        </div>
      )}
    </section>
  )
}

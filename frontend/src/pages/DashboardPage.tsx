import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { api, ApiError, type Dashboard, type DashboardRange } from '../api/client'
import { AlertStatusBadge, SeverityBadge } from '../components/badges'
import { JobStatusBadge } from '../components/JobStatusBadge'
import { Empty, ErrorBanner, Loading, PageHeader } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'
import { SERIES_BLUE, SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL } from '../lib/severity'

const RANGES: { value: DashboardRange; label: string }[] = [
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: 'all', label: 'All time' },
]
const STEP_MS = { hour: 3_600_000, day: 86_400_000, week: 604_800_000 }
const AXIS = { stroke: '#8b9bab', fontSize: 11 }
const compact = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 })
const GRID = '#233040'

type State = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'loaded'; data: Dashboard }

function tickLabel(iso: string, bucket: Dashboard['bucket']) {
  const d = new Date(iso)
  return bucket === 'hour'
    ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' })
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function bucketRange(iso: string, bucket: Dashboard['bucket']) {
  const start = new Date(iso)
  return { since: start.toISOString(), until: new Date(start.getTime() + STEP_MS[bucket]).toISOString() }
}

/** Recharts passes the clicked bar; its data row is on `payload`. */
function bucketOf(item: unknown): string | undefined {
  return (item as { payload?: { bucket_start?: string } } | undefined)?.payload?.bucket_start
}

/** Fixed low -> critical order; text stays in ink colours, the swatch carries identity. */
function SeverityLegend() {
  return (
    <ul className="flex flex-wrap justify-center gap-4 pt-2 text-xs text-ink-dim">
      {SEVERITIES.map((s) => (
        <li key={s} className="inline-flex items-center gap-1.5">
          <span aria-hidden className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLOR[s] }} />
          {SEVERITY_LABEL[s]}
        </li>
      ))}
    </ul>
  )
}

function Tile({ label, value, to, tone, sub }: { label: string; value: number; to?: string; tone?: string; sub?: string }) {
  const body = (
    <>
      <p className="text-xs uppercase tracking-wide text-ink-dim">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${tone ?? ''}`}>{formatCount(value)}</p>
      {sub && <p className="text-xs text-ink-dim">{sub}</p>}
    </>
  )
  return to ? (
    <Link to={to} className="block rounded-md border border-line bg-panel p-4 hover:border-accent">
      {body}
    </Link>
  ) : (
    <div className="rounded-md border border-line bg-panel p-4">{body}</div>
  )
}

function Card({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="min-w-0 rounded-md border border-line bg-panel p-4" aria-label={title}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function ChartTooltip({ active, payload, label, bucket }: {
  active?: boolean
  payload?: { name: string; value: number; color: string }[]
  label?: string
  bucket: Dashboard['bucket']
}) {
  if (!active || !payload?.length || !label) return null
  return (
    <div className="rounded-md border border-line bg-panel-2 px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 text-ink-dim">{tickLabel(label, bucket)}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 tabular-nums">
          <span aria-hidden className="h-2 w-2 rounded-sm" style={{ backgroundColor: p.color }} />
          <span className="text-ink-dim">{p.name}</span>
          <span className="ml-auto text-ink">{formatCount(p.value)}</span>
        </p>
      ))}
      <p className="mt-1 text-[11px] text-ink-dim">Click to drill down</p>
    </div>
  )
}

function DashboardBody({ data }: { data: Dashboard }) {
  const navigate = useNavigate()
  const { totals, bucket } = data
  const maxSev = Math.max(1, ...data.alerts_by_severity.map((s) => s.count))
  const anyAlertsOverTime = data.alerts_over_time.some((p) => SEVERITIES.some((s) => p[s] > 0))

  return (
    <>
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label="Events in range" value={totals.events} to="/events" sub={`${formatCount(totals.alerts)} alerts in range`} />
        <Tile label="Open alerts" value={totals.open_alerts} to="/alerts?status=new" tone={totals.open_alerts ? 'text-warn' : ''} />
        <Tile label="High / critical open" value={totals.high_open_alerts} to="/alerts?severity=high&status=new" tone={totals.high_open_alerts ? 'text-crit' : ''} />
        <Tile label="Log sources" value={totals.sources} to="/sources" sub={`${formatCount(totals.files)} imported files`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Events over time">
          {data.events_over_time.length === 0 ? (
            <Empty>No events in this range.</Empty>
          ) : (
            <>
              <div className="h-56" role="img" aria-label={`Events per ${bucket}`}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.events_over_time} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
                    <CartesianGrid vertical={false} stroke={GRID} />
                    <XAxis dataKey="bucket_start" tickFormatter={(v) => tickLabel(v, bucket)} tick={AXIS} stroke={GRID} minTickGap={24} />
                    <YAxis tick={AXIS} stroke={GRID} width={44} allowDecimals={false} tickFormatter={(v: number) => compact.format(v)} />
                    <Tooltip content={<ChartTooltip bucket={bucket} />} cursor={{ fill: '#16202b' }} />
                    <Bar
                      dataKey="count"
                      name="Events"
                      fill={SERIES_BLUE}
                      radius={[4, 4, 0, 0]}
                      cursor="pointer"
                      onClick={(item) => {
                        const start = bucketOf(item)
                        if (!start) return
                        const r = bucketRange(start, bucket)
                        navigate(`/events?since=${encodeURIComponent(r.since)}&until=${encodeURIComponent(r.until)}`)
                      }}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <details className="mt-2 text-xs text-ink-dim">
                <summary className="cursor-pointer">View as table</summary>
                <table className="mt-2 w-full">
                  <tbody>
                    {data.events_over_time.filter((p) => p.count > 0).map((p) => {
                      const r = bucketRange(p.bucket_start, bucket)
                      return (
                        <tr key={p.bucket_start}>
                          <td className="py-0.5">{tickLabel(p.bucket_start, bucket)}</td>
                          <td className="text-right tabular-nums">
                            <Link
                              className="text-accent hover:underline"
                              to={`/events?since=${encodeURIComponent(r.since)}&until=${encodeURIComponent(r.until)}`}
                            >
                              {formatCount(p.count)}
                            </Link>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </details>
            </>
          )}
        </Card>

        <Card title="Alerts by first seen, per severity">
          {!anyAlertsOverTime ? (
            <Empty>No alerts started in this range.</Empty>
          ) : (
            <div className="h-56" role="img" aria-label="Alerts over time by severity">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.alerts_over_time} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
                  <CartesianGrid vertical={false} stroke={GRID} />
                  <XAxis dataKey="bucket_start" tickFormatter={(v) => tickLabel(v, bucket)} tick={AXIS} stroke={GRID} minTickGap={24} />
                  <YAxis tick={AXIS} stroke={GRID} width={36} allowDecimals={false} tickFormatter={(v: number) => compact.format(v)} />
                  <Tooltip content={<ChartTooltip bucket={bucket} />} cursor={{ fill: '#16202b' }} />
                  <Legend content={<SeverityLegend />} />
                  {SEVERITIES.map((s) => (
                    <Bar
                      key={s}
                      dataKey={s}
                      name={SEVERITY_LABEL[s]}
                      stackId="sev"
                      fill={SEVERITY_COLOR[s]}
                      stroke="#111821"
                      strokeWidth={1}
                      cursor="pointer"
                      onClick={(item) => {
                        const start = bucketOf(item)
                        if (!start) return
                        const r = bucketRange(start, bucket)
                        navigate(`/alerts?severity=${s}&since=${encodeURIComponent(r.since)}&until=${encodeURIComponent(r.until)}`)
                      }}
                    />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          {anyAlertsOverTime && (
            <details className="mt-2 text-xs text-ink-dim">
              <summary className="cursor-pointer">View as table</summary>
              <table className="mt-2 w-full">
                <thead>
                  <tr>
                    <th className="py-0.5 text-left font-normal">Period</th>
                    {SEVERITIES.map((s) => (
                      <th key={s} className="text-right font-normal">
                        {SEVERITY_LABEL[s]}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.alerts_over_time
                    .filter((p) => SEVERITIES.some((s) => p[s] > 0))
                    .map((p) => {
                      const r = bucketRange(p.bucket_start, bucket)
                      return (
                        <tr key={p.bucket_start}>
                          <td className="py-0.5">{tickLabel(p.bucket_start, bucket)}</td>
                          {SEVERITIES.map((s) => (
                            <td key={s} className="text-right tabular-nums">
                              {p[s] > 0 ? (
                                <Link
                                  className="text-accent hover:underline"
                                  to={`/alerts?severity=${s}&since=${encodeURIComponent(r.since)}&until=${encodeURIComponent(r.until)}`}
                                >
                                  {formatCount(p[s])}
                                </Link>
                              ) : (
                                '0'
                              )}
                            </td>
                          ))}
                        </tr>
                      )
                    })}
                </tbody>
              </table>
            </details>
          )}
        </Card>

        <Card title="Alerts by severity" action={<Link to="/alerts" className="text-xs text-accent hover:underline">All alerts →</Link>}>
          <ul className="space-y-2">
            {[...data.alerts_by_severity].reverse().map((s) => (
              <li key={s.key}>
                <Link to={`/alerts?severity=${s.key}`} className="group grid grid-cols-[6rem_1fr_3.5rem] items-center gap-3 text-sm">
                  <SeverityBadge severity={s.key} />
                  <span className="h-2.5 rounded-sm bg-panel-2">
                    <span className="block h-full rounded-sm" style={{ width: `${(s.count / maxSev) * 100}%`, backgroundColor: SEVERITY_COLOR[s.key] }} />
                  </span>
                  <span className="text-right tabular-nums group-hover:text-accent">{formatCount(s.count)}</span>
                </Link>
              </li>
            ))}
          </ul>
          <div className="mt-4 flex flex-wrap gap-3 text-xs text-ink-dim">
            {data.alerts_by_status.map((s) => (
              <Link key={s.key} to={`/alerts?status=${s.key}`} className="inline-flex items-center gap-1.5 hover:text-ink">
                <AlertStatusBadge status={s.key} /> <span className="tabular-nums">{s.count}</span>
              </Link>
            ))}
          </div>
        </Card>

        <Card title="Top source IPs by alerts">
          {data.top_source_ips.length === 0 ? (
            <Empty>No alerts with a source IP in this range.</Empty>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-ink-dim">
                <tr>
                  <th className="pb-2 font-normal">Source IP</th>
                  <th className="pb-2 font-normal">Highest severity</th>
                  <th className="pb-2 text-right font-normal">Alerts</th>
                  <th className="pb-2 text-right font-normal">Events</th>
                </tr>
              </thead>
              <tbody>
                {data.top_source_ips.map((r) => (
                  <tr key={r.source_ip} className="border-t border-line">
                    <td className="py-1.5 font-mono text-xs">
                      <Link to={`/alerts?source_ip=${encodeURIComponent(r.source_ip)}`} className="text-accent hover:underline">
                        {r.source_ip}
                      </Link>
                    </td>
                    <td>
                      <SeverityBadge severity={r.max_severity} />
                    </td>
                    <td className="text-right tabular-nums">{r.alert_count}</td>
                    <td className="text-right tabular-nums">
                      <Link to={`/events?source_ip=${encodeURIComponent(r.source_ip)}`} className="hover:text-accent">
                        {formatCount(r.event_count)}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Most frequently triggered rules">
          {data.top_rules.length === 0 ? (
            <Empty>No rules fired in this range.</Empty>
          ) : (
            <ul className="divide-y divide-line text-sm">
              {data.top_rules.map((r) => (
                <li key={r.rule_id}>
                  <Link to={`/alerts?rule_id=${r.rule_id}`} className="flex items-center justify-between gap-3 py-1.5 hover:text-accent">
                    <span>
                      <span className="mr-2 font-mono text-xs text-ink-dim">{r.rule_id}</span>
                      {r.name}
                    </span>
                    <span className="tabular-nums">{r.alert_count}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recent high-severity alerts">
          {data.recent_high_alerts.length === 0 ? (
            <Empty>No high or critical alerts in this range.</Empty>
          ) : (
            <ul className="divide-y divide-line text-sm">
              {data.recent_high_alerts.map((a) => (
                <li key={a.id} className="py-1.5">
                  <Link to={`/alerts/${a.id}`} className="flex items-start justify-between gap-3 hover:text-accent">
                    <span className="min-w-0">
                      <span className="block truncate">{a.title}</span>
                      <span className="text-xs text-ink-dim">{formatDateTime(a.last_seen)}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={a.severity} />
                      <AlertStatusBadge status={a.status} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Recent ingestion jobs" action={<Link to="/jobs" className="text-xs text-accent hover:underline">All jobs →</Link>}>
          {data.recent_jobs.length === 0 ? (
            <Empty>
              No imports yet. <Link className="underline" to="/sources">Upload a log file</Link>.
            </Empty>
          ) : (
            <ul className="divide-y divide-line text-sm">
              {data.recent_jobs.map((j) => (
                <li key={j.id}>
                  <Link to={`/jobs/${j.id}`} className="flex items-center justify-between gap-3 py-1.5 hover:text-accent">
                    <span className="min-w-0 truncate">
                      <span className="mr-2 font-mono text-xs text-ink-dim">#{j.id}</span>
                      {j.filename} <span className="text-ink-dim">→ {j.source_name}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-3">
                      <span className="text-xs tabular-nums text-ink-dim">{formatCount(j.parsed_count)} events</span>
                      <JobStatusBadge status={j.status} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  )
}

export function DashboardPage() {
  const [params, setParams] = useSearchParams()
  const range = (RANGES.some((r) => r.value === params.get('range')) ? params.get('range') : '7d') as DashboardRange
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    let active = true
    api
      .dashboard(range)
      .then((data) => active && setState({ kind: 'loaded', data }))
      .catch((err: unknown) => active && setState({ kind: 'error', message: err instanceof ApiError ? err.message : 'Unexpected error' }))
    return () => {
      active = false
    }
  }, [range])

  function choose(r: DashboardRange) {
    setState({ kind: 'loading' })
    setParams({ range: r })
  }

  const loaded = state.kind === 'loaded' ? state.data : null
  const emptyRange = loaded && loaded.totals.events === 0 && loaded.data_range.last_event && range !== 'all'

  return (
    <section>
      <PageHeader
        title="Security overview"
        subtitle={loaded?.start ? `${formatDateTime(loaded.start)} – ${formatDateTime(loaded.end)}` : 'Figures are computed live from stored events and alerts.'}
        actions={
          <div role="group" aria-label="Time range" className="flex overflow-hidden rounded-md border border-line text-sm">
            {RANGES.map((r) => (
              <button
                key={r.value}
                type="button"
                aria-pressed={r.value === range}
                onClick={() => choose(r.value)}
                className={`px-3 py-1.5 ${r.value === range ? 'bg-panel-2 text-ink' : 'text-ink-dim hover:text-ink'}`}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      />
      {state.kind === 'loading' && <Loading label="Loading overview…" />}
      {state.kind === 'error' && <ErrorBanner message={`Could not load the overview: ${state.message}`} />}
      {emptyRange && loaded && (
        <div role="status" className="mb-4 rounded-md border border-line bg-panel p-3 text-sm text-ink-dim">
          No events in the last {RANGES.find((r) => r.value === range)?.label}. Stored data spans{' '}
          {formatDateTime(loaded.data_range.first_event)} – {formatDateTime(loaded.data_range.last_event)}.{' '}
          <button type="button" className="text-accent underline" onClick={() => choose('all')}>
            Show all time
          </button>
        </div>
      )}
      {loaded && <DashboardBody data={loaded} />}
    </section>
  )
}

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import {
  api,
  ApiError,
  type AlertActivity,
  type AlertDetail,
  type AlertStatus,
  type EvidenceItem,
  type EvidencePage,
  type HistoryEntry,
  type Incident,
} from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AlertStatusBadge, ConfidenceLabel, IncidentStatusBadge, SeverityBadge } from '../components/badges'
import { AssigneeSelect, NoteComposer, NoteList } from '../components/investigation'
import { errorMessage } from '../lib/errors'
import { useAssignees } from '../lib/useAssignees'
import { Button, ErrorBanner, Loading, Select, SuccessBanner, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'
import { ALERT_STATUSES, STATUS_LABEL } from '../lib/severity'

function msg(err: unknown) {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

function humanDuration(seconds: number) {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}

function DetailValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-ink-dim">none</span>
    return (
      <ul className="flex flex-wrap gap-1">
        {value.map((v, i) => (
          <li key={i} className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-xs">
            {String(v)}
          </li>
        ))}
      </ul>
    )
  }
  if (typeof value === 'boolean') return <span>{value ? 'yes' : 'no'}</span>
  return <span className="font-mono text-xs">{String(value)}</span>
}

function StatusControl({ alert, onChanged }: { alert: AlertDetail; onChanged: (a: AlertDetail) => void }) {
  const assignees = useAssignees(true)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState<AlertStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  async function change(status: AlertStatus) {
    setBusy(status)
    setError(null)
    setDone(null)
    try {
      onChanged(await api.setAlertStatus(alert.id, status, note))
      setDone(`Status changed to ${STATUS_LABEL[status]}.`)
      setNote('')
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(null)
    }
  }

  async function assign(id: number | null) {
    setError(null)
    setDone(null)
    try {
      const updated = await api.assignAlert(alert.id, id)
      onChanged(updated)
      setDone(updated.assignee ? `Assigned to ${updated.assignee}.` : 'Owner cleared.')
    } catch (err) {
      setError(msg(err))
    }
  }

  return (
    <section aria-label="Triage" className="rounded-md border border-line bg-panel p-4">
      <h2 className="mb-2 text-sm font-semibold">Triage</h2>
      <div className="mb-3">
        <span className="mb-1 block text-xs text-ink-dim">Owner</span>
        <AssigneeSelect
          value={alert.assigned_to}
          currentName={alert.assignee}
          assignees={assignees}
          onChange={(id) => void assign(id)}
          label="Alert owner"
        />
      </div>
      <div className="mb-2 flex flex-wrap gap-2">
        {ALERT_STATUSES.filter((s) => s !== alert.status).map((s) => (
          <Button key={s} onClick={() => void change(s)} disabled={busy !== null} variant={s === 'resolved' ? 'primary' : 'secondary'}>
            {busy === s ? 'Saving…' : `Mark ${STATUS_LABEL[s].toLowerCase()}`}
          </Button>
        ))}
      </div>
      <label className="block text-xs text-ink-dim">
        Note for the audit trail (optional)
        <TextInput value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} placeholder="Why this status?" />
      </label>
      {error && <div className="mt-2"><ErrorBanner message={error} /></div>}
      {done && <div className="mt-2"><SuccessBanner message={done} /></div>}
    </section>
  )
}

function Evidence({ alert }: { alert: AlertDetail }) {
  const [page, setPage] = useState<EvidencePage | null>(null)
  const [rows, setRows] = useState<EvidenceItem[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    api
      .alertEvidence(alert.id)
      .then((p) => {
        if (!active) return
        setPage(p)
        setRows(p.items)
      })
      .catch((err: unknown) => active && setError(msg(err)))
    return () => {
      active = false
    }
  }, [alert.id])

  async function more() {
    if (!page?.next_after_id) return
    setBusy(true)
    try {
      const p = await api.alertEvidence(alert.id, page.next_after_id)
      setPage(p)
      setRows((r) => [...r, ...p.items])
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-label="Evidence">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Evidence</h2>
        <Link to={`/events?alert_id=${alert.id}`} className="text-xs text-accent hover:underline">
          Open in event explorer →
        </Link>
      </div>
      {error && <ErrorBanner message={`Could not load evidence: ${error}`} />}
      {!page && !error && <Loading label="Loading evidence…" />}
      {page && (
        <>
          <p className="mb-2 text-xs text-ink-dim">
            Showing {formatCount(rows.length)} of {formatCount(page.total_linked)} linked events
            {page.truncated && ` (the alert covers ${formatCount(page.total_events)} events; evidence links are capped)`}.
          </p>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[800px] text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Indicator</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Original log line</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.event_id} className="border-t border-line align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">{formatDateTime(e.event_time)}</td>
                    <td className="px-3 py-2 font-mono text-xs">{e.indicator ?? '—'}</td>
                    <td className="px-3 py-2 tabular-nums">{e.http_status ?? '—'}</td>
                    <td className="px-3 py-2">
                      {/* Untrusted log content: plain text only. */}
                      <code className="block max-h-20 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-ink-dim">{e.raw_line}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {page.next_after_id && (
            <div className="mt-3 text-right">
              <Button onClick={() => void more()} disabled={busy}>
                {busy ? 'Loading…' : 'Show more evidence'}
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

const ACTION_LABEL: Record<string, string> = {
  'alert.status_change': 'Status changed',
  'alert.assign': 'Owner changed',
  'alert.note': 'Added a note',
}

function describe(h: HistoryEntry): string {
  const d = h.details as { from?: string | null; to?: string | null; kind?: string }
  if (h.action === 'alert.status_change') {
    const label = (v?: string | null) => (v ? (STATUS_LABEL[v as AlertStatus] ?? v) : 'none')
    return `${label(d.from)} → ${label(d.to)}`
  }
  if (h.action === 'alert.assign') return `${d.from ?? 'unassigned'} → ${d.to ?? 'unassigned'}`
  if (h.action === 'alert.note') return d.kind === 'action' ? 'action taken' : d.kind === 'evidence' ? 'evidence reference' : 'note'
  return ''
}

function AddToIncident({ alert }: { alert: AlertDetail }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState<Incident[] | null>(null)
  const [choice, setChoice] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .incidents({ open_only: 'true' }, undefined, 100)
      .then((p) => active && setOpen(p.items))
      .catch(() => active && setOpen([]))
    return () => {
      active = false
    }
  }, [])

  async function add() {
    setBusy(true)
    setError(null)
    try {
      if (choice === 'new') {
        const inc = await api.createIncident({ title: alert.title, alert_ids: [alert.id] })
        navigate(`/incidents/${inc.id}`)
      } else if (choice) {
        await api.linkAlerts(Number(choice), [alert.id])
        navigate(`/incidents/${choice}`)
      }
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <div className="mt-3 space-y-2">
      <div className="flex gap-2">
        <Select aria-label="Add to incident" value={choice} onChange={(e) => setChoice(e.target.value)} disabled={open === null}>
          <option value="">Add to incident…</option>
          <option value="new">New incident from this alert</option>
          {(open ?? []).map((i) => (
            <option key={i.id} value={i.id}>
              #{i.id} {i.title}
            </option>
          ))}
        </Select>
        <Button onClick={() => void add()} disabled={!choice || busy}>
          {busy ? 'Adding…' : 'Add'}
        </Button>
      </div>
      {error && <ErrorBanner message={error} />}
    </div>
  )
}

function Activity({ alert, refreshKey }: { alert: AlertDetail; refreshKey: string }) {
  const { can } = useAuth()
  const [activity, setActivity] = useState<AlertActivity | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    return api
      .alertActivity(alert.id)
      .then(setActivity)
      .catch((err: unknown) => setError(msg(err)))
  }, [alert.id])

  useEffect(() => {
    void load()
  }, [load, refreshKey])

  return (
    <>
      <section aria-label="Investigation notes" className="rounded-md border border-line bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold">Investigation notes</h2>
        {error && <ErrorBanner message={`Could not load activity: ${error}`} />}
        {!activity && !error && <Loading label="Loading notes…" />}
        {activity && <NoteList notes={activity.notes} />}
        {can('alerts:triage') && (
          <div className="mt-4 border-t border-line pt-4">
            <NoteComposer
              onSubmit={async (body) => {
                await api.addAlertNote(alert.id, body)
                await load()
              }}
            />
          </div>
        )}
      </section>
      {activity && (
        <section aria-label="Incidents" className="rounded-md border border-line bg-panel p-4">
          <h2 className="mb-2 text-sm font-semibold">Incidents</h2>
          {activity.incidents.length === 0 ? (
            <p className="text-sm text-ink-dim">Not part of an incident.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {activity.incidents.map((i) => (
                <li key={i.id} className="flex items-center justify-between gap-2">
                  <Link to={`/incidents/${i.id}`} className="truncate text-accent hover:underline">
                    #{i.id} {i.title}
                  </Link>
                  <IncidentStatusBadge status={i.status} />
                </li>
              ))}
            </ul>
          )}
          {can('incidents:manage') && <AddToIncident alert={alert} />}
        </section>
      )}
      {activity && (
        <section aria-label="History" className="rounded-md border border-line bg-panel p-4">
          <h2 className="mb-2 text-sm font-semibold">History</h2>
          {activity.history.length === 0 ? (
            <p className="text-sm text-ink-dim">No changes yet.</p>
          ) : (
            <ol className="space-y-2 text-sm">
              {activity.history.map((h) => (
                <li key={h.id}>
                  <p>
                    <span className="font-medium">{ACTION_LABEL[h.action] ?? h.action}</span>{' '}
                    <span className="text-ink-dim">{describe(h)}</span>
                  </p>
                  <p className="text-xs text-ink-dim">
                    {h.actor ?? 'system'} · {formatDateTime(h.occurred_at)}
                    {typeof h.details.note === 'string' && h.details.note ? ` · “${h.details.note}”` : ''}
                  </p>
                </li>
              ))}
            </ol>
          )}
        </section>
      )}
    </>
  )
}

export function AlertDetailPage() {
  const { id } = useParams()
  const alertId = Number(id)
  const { can } = useAuth()
  const [alert, setAlert] = useState<AlertDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .alert(alertId)
      .then((a) => active && setAlert(a))
      .catch((err: unknown) => active && setError(msg(err)))
    return () => {
      active = false
    }
  }, [alertId])

  if (!Number.isInteger(alertId) || alertId <= 0) return <ErrorBanner message="Invalid alert id." />
  if (error) return <ErrorBanner message={`Could not load alert #${alertId}: ${error}`} />
  if (!alert) return <Loading label="Loading alert…" />

  const memberIds = Array.isArray(alert.details.member_alert_ids) ? (alert.details.member_alert_ids as number[]) : []
  const details = Object.entries(alert.details).filter(([k]) => k !== 'member_alert_ids')

  return (
    <section className="max-w-6xl">
      <p className="mb-2 text-sm">
        <Link to="/alerts" className="text-ink-dim hover:text-ink">
          ← Alert queue
        </Link>
      </p>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold">{alert.title}</h1>
          <p className="font-mono text-xs text-ink-dim">
            Alert #{alert.id} ·{' '}
            <Link to={`/rules/${alert.rule_id}`} className="hover:text-accent">
              {alert.rule_id} v{alert.rule_version}
            </Link>{' '}
            · {alert.rule_name}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={alert.severity} />
          <ConfidenceLabel confidence={alert.confidence} />
          <AlertStatusBadge status={alert.status} />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-4">
          <section aria-label="What was observed" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-2 text-sm font-semibold">What was observed</h2>
            <p className="text-sm leading-relaxed">{alert.reason}</p>
            <h3 className="mb-1 mt-4 text-xs uppercase tracking-wide text-ink-dim">Why this confidence</h3>
            <p className="text-sm text-ink-dim">{alert.confidence_reason}</p>
          </section>

          <section aria-label="Recommended investigation" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-2 text-sm font-semibold">Recommended investigation</h2>
            <ol className="list-decimal space-y-1 pl-5 text-sm">
              {alert.recommended_steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          </section>

          <Evidence alert={alert} />
        </div>

        <div className="min-w-0 space-y-4">
          {can('alerts:triage') && <StatusControl alert={alert} onChanged={setAlert} />}
          <Activity alert={alert} refreshKey={`${alert.status}|${alert.assigned_to}`} />
          <section aria-label="Facts" className="rounded-md border border-line bg-panel p-4">
            <dl className="grid grid-cols-[6.5rem_1fr] gap-x-2 gap-y-1.5 text-sm">
              <dt className="text-ink-dim">First seen</dt>
              <dd>{formatDateTime(alert.first_seen)}</dd>
              <dt className="text-ink-dim">Last seen</dt>
              <dd>{formatDateTime(alert.last_seen)}</dd>
              <dt className="text-ink-dim">Events</dt>
              <dd className="tabular-nums">{formatCount(alert.event_count)}</dd>
              <dt className="text-ink-dim">Owner</dt>
              <dd>{alert.assignee ?? <span className="text-ink-dim">unassigned</span>}</dd>
              <dt className="text-ink-dim">Rule window</dt>
              <dd>{humanDuration(alert.window_seconds)}</dd>
              {alert.source_ip && (
                <>
                  <dt className="text-ink-dim">Source IP</dt>
                  <dd className="font-mono text-xs">
                    <Link to={`/events?source_ip=${encodeURIComponent(alert.source_ip)}`} className="text-accent hover:underline">
                      {alert.source_ip}
                    </Link>{' '}
                    <Link to={`/alerts?source_ip=${encodeURIComponent(alert.source_ip)}`} className="font-sans text-ink-dim hover:text-ink">
                      (all alerts)
                    </Link>
                  </dd>
                </>
              )}
              {alert.username && (
                <>
                  <dt className="text-ink-dim">Account</dt>
                  <dd className="break-all">{alert.username}</dd>
                </>
              )}
              {alert.endpoint && (
                <>
                  <dt className="text-ink-dim">Top endpoint</dt>
                  <dd className="break-all font-mono text-xs">{alert.endpoint}</dd>
                </>
              )}
            </dl>
          </section>
          {details.length > 0 && (
            <section aria-label="Rule details" className="rounded-md border border-line bg-panel p-4">
              <h2 className="mb-2 text-sm font-semibold">Rule details</h2>
              <dl className="space-y-2 text-sm">
                {details.map(([k, v]) => (
                  <div key={k}>
                    <dt className="text-xs text-ink-dim">{k.replaceAll('_', ' ')}</dt>
                    <dd>
                      <DetailValue value={v} />
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          )}
          {memberIds.length > 0 && (
            <section aria-label="Member alerts" className="rounded-md border border-line bg-panel p-4">
              <h2 className="mb-2 text-sm font-semibold">Correlated alerts</h2>
              <ul className="space-y-1 text-sm">
                {memberIds.map((m) => (
                  <li key={m}>
                    <Link to={`/alerts/${m}`} className="text-accent hover:underline">
                      Alert #{m}
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>
    </section>
  )
}

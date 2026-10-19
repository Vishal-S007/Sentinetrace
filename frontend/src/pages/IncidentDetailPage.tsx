import { useEffect, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api, type IncidentDetail, type IncidentStatus, type Severity, type TimelineItem } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AlertStatusBadge, IncidentStatusBadge, SeverityBadge } from '../components/badges'
import { AssigneeSelect, NoteComposer, TextArea } from '../components/investigation'
import { errorMessage } from '../lib/errors'
import { useAssignees } from '../lib/useAssignees'
import { Button, ErrorBanner, Field, Loading, Select, SuccessBanner, TextInput } from '../components/ui'
import { formatCount, formatDateTime } from '../lib/format'
import { INCIDENT_STATUSES, INCIDENT_STATUS_LABEL, SEVERITIES, SEVERITY_LABEL } from '../lib/severity'

const KIND_LABEL: Record<TimelineItem['kind'], string> = { observed: 'Observed', change: 'Change', note: 'Note' }
const KIND_MARK: Record<TimelineItem['kind'], string> = {
  observed: 'border-ink-dim bg-base',
  change: 'border-accent bg-accent',
  note: 'border-warn bg-warn',
}

function Timeline({ items }: { items: TimelineItem[] }) {
  if (items.length === 0) return <p className="text-sm text-ink-dim">Nothing recorded yet.</p>
  return (
    <ol className="relative space-y-4 border-l border-line pl-5">
      {items.map((t, i) => (
        <li key={i} className="relative">
          <span aria-hidden className={`absolute -left-[26px] top-1 h-2.5 w-2.5 rounded-full border-2 ${KIND_MARK[t.kind]}`} />
          <p className="text-xs text-ink-dim">
            <span className="mr-2 uppercase tracking-wide">{KIND_LABEL[t.kind]}</span>
            {formatDateTime(t.at)}
            {t.actor && <> · {t.actor}</>}
          </p>
          <p className="text-sm">
            {t.alert_id !== null ? (
              <Link to={`/alerts/${t.alert_id}`} className="hover:text-accent">
                {t.title}
              </Link>
            ) : (
              t.title
            )}
          </p>
          {t.detail && <p className="mt-0.5 whitespace-pre-wrap break-words text-sm text-ink-dim">{t.detail}</p>}
          {t.event_id !== null && <p className="text-xs text-ink-dim">References event #{t.event_id}</p>}
        </li>
      ))}
    </ol>
  )
}

function ManagePanel({ incident, onChange }: { incident: IncidentDetail; onChange: (i: IncidentDetail) => void }) {
  const assignees = useAssignees(true)
  const [status, setStatus] = useState<IncidentStatus>(incident.status)
  const [severity, setSeverity] = useState<Severity>(incident.severity)
  const [owner, setOwner] = useState<number | null>(incident.assigned_to)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const dirty = status !== incident.status || severity !== incident.severity || owner !== incident.assigned_to

  async function save(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setDone(null)
    try {
      const body: Parameters<typeof api.updateIncident>[1] = { note }
      if (status !== incident.status) body.status = status
      if (severity !== incident.severity) body.severity = severity
      if (owner !== incident.assigned_to) body.assigned_to = owner
      onChange(await api.updateIncident(incident.id, body))
      setNote('')
      setDone('Saved.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={save} aria-label="Manage incident" className="space-y-3 rounded-md border border-line bg-panel p-4">
      <h2 className="text-sm font-semibold">Manage</h2>
      <Field label="Status">
        <Select value={status} onChange={(e) => setStatus(e.target.value as IncidentStatus)}>
          {INCIDENT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {INCIDENT_STATUS_LABEL[s]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Severity">
        <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </Select>
      </Field>
      <div className="text-sm">
        <span className="mb-1 block text-ink-dim">Owner</span>
        <AssigneeSelect value={owner} currentName={incident.assignee} assignees={assignees} onChange={setOwner} label="Incident owner" />
      </div>
      <Field label="Reason (optional, kept in the timeline)">
        <TextInput value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} />
      </Field>
      {error && <ErrorBanner message={error} />}
      {done && <SuccessBanner message={done} />}
      <Button type="submit" variant="primary" disabled={!dirty || busy} className="w-full">
        {busy ? 'Saving…' : 'Save changes'}
      </Button>
    </form>
  )
}

function EditSummary({ incident, onChange, onDone }: { incident: IncidentDetail; onChange: (i: IncidentDetail) => void; onDone: () => void }) {
  const [title, setTitle] = useState(incident.title)
  const [summary, setSummary] = useState(incident.summary)
  const [error, setError] = useState<string | null>(null)

  async function save(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      const body: Parameters<typeof api.updateIncident>[1] = {}
      if (title.trim() !== incident.title) body.title = title.trim()
      if (summary !== incident.summary) body.summary = summary
      if (Object.keys(body).length) onChange(await api.updateIncident(incident.id, body))
      onDone()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <form onSubmit={save} aria-label="Edit summary" className="space-y-3">
      <Field label="Title">
        <TextInput required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
      </Field>
      <Field label="Summary">
        <TextArea rows={5} maxLength={10000} value={summary} onChange={(e) => setSummary(e.target.value)} />
      </Field>
      {error && <ErrorBanner message={error} />}
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!title.trim()}>
          Save
        </Button>
      </div>
    </form>
  )
}

function LinkAlertsForm({ incident, onChange }: { incident: IncidentDetail; onChange: (i: IncidentDetail) => void }) {
  const [raw, setRaw] = useState('')
  const [error, setError] = useState<string | null>(null)
  const ids = [...new Set(raw.split(/[\s,]+/).filter(Boolean).map(Number))].filter((n) => Number.isInteger(n) && n > 0)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      onChange(await api.linkAlerts(incident.id, ids))
      setRaw('')
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <form onSubmit={submit} aria-label="Link alerts" className="mt-3 flex flex-wrap items-start gap-2">
      <div className="w-64">
        <TextInput aria-label="Alert IDs to link" placeholder="Alert IDs, e.g. 12, 15" value={raw} onChange={(e) => setRaw(e.target.value)} />
      </div>
      <Button type="submit" disabled={ids.length === 0}>
        Link alerts
      </Button>
      {error && (
        <div className="w-full">
          <ErrorBanner message={error} />
        </div>
      )}
    </form>
  )
}

export function IncidentDetailPage() {
  const { id } = useParams()
  const incidentId = Number(id)
  const { can } = useAuth()
  const canManage = can('incidents:manage')
  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api
      .incident(incidentId)
      .then((i) => active && setIncident(i))
      .catch((err: unknown) => active && setError(errorMessage(err)))
    return () => {
      active = false
    }
  }, [incidentId])

  if (!Number.isInteger(incidentId) || incidentId <= 0) return <ErrorBanner message="Invalid incident id." />
  if (error) return <ErrorBanner message={`Could not load incident #${incidentId}: ${error}`} />
  if (!incident) return <Loading label="Loading incident…" />

  async function unlink(alertId: number) {
    setActionError(null)
    try {
      setIncident(await api.unlinkAlert(incidentId, alertId))
    } catch (err) {
      setActionError(errorMessage(err))
    }
  }

  return (
    <section className="max-w-6xl">
      <p className="mb-2 text-sm">
        <Link to="/incidents" className="text-ink-dim hover:text-ink">
          ← Incidents
        </Link>
      </p>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold break-words">{incident.title}</h1>
          <p className="text-xs text-ink-dim">
            Incident #{incident.id} · opened by {incident.created_by} {formatDateTime(incident.created_at)}
            {incident.closed_at && <> · closed {formatDateTime(incident.closed_at)}</>}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={incident.severity} />
          <IncidentStatusBadge status={incident.status} />
          <span className="text-xs text-ink-dim">Owner: {incident.assignee ?? 'unassigned'}</span>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-4">
          <section aria-label="Summary" className="rounded-md border border-line bg-panel p-4">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-semibold">Summary</h2>
              {canManage && !editing && (
                <button type="button" className="text-xs text-accent hover:underline" onClick={() => setEditing(true)}>
                  Edit
                </button>
              )}
            </div>
            {editing ? (
              <EditSummary incident={incident} onChange={setIncident} onDone={() => setEditing(false)} />
            ) : incident.summary ? (
              <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{incident.summary}</p>
            ) : (
              <p className="text-sm text-ink-dim">No summary yet.</p>
            )}
          </section>

          <section aria-label="Linked alerts" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-2 text-sm font-semibold">Linked alerts ({formatCount(incident.alert_count)})</h2>
            {actionError && <ErrorBanner message={actionError} />}
            {incident.alerts.length === 0 ? (
              <p className="text-sm text-ink-dim">No alerts linked.</p>
            ) : (
              <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Linked alert list">
                <table className="w-full min-w-[560px] text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-ink-dim">
                    <tr>
                      <th className="py-1.5 pr-3">Severity</th>
                      <th className="py-1.5 pr-3">Alert</th>
                      <th className="py-1.5 pr-3">First seen</th>
                      <th className="py-1.5 pr-3">Status</th>
                      {canManage && <th className="py-1.5" />}
                    </tr>
                  </thead>
                  <tbody>
                    {incident.alerts.map((a) => (
                      <tr key={a.id} className="border-t border-line align-top">
                        <td className="py-2 pr-3">
                          <SeverityBadge severity={a.severity} />
                        </td>
                        <td className="w-full max-w-0 py-2 pr-3">
                          <Link to={`/alerts/${a.id}`} className="block truncate hover:text-accent" title={a.title}>
                            {a.title}
                          </Link>
                          <span className="font-mono text-xs text-ink-dim">
                            #{a.id} · {a.rule_id} · {formatCount(a.event_count)} events
                          </span>
                        </td>
                        <td className="whitespace-nowrap py-2 pr-3 text-ink-dim">{formatDateTime(a.first_seen)}</td>
                        <td className="py-2 pr-3">
                          <AlertStatusBadge status={a.status} />
                        </td>
                        {canManage && (
                          <td className="py-2 text-right">
                            <button type="button" className="text-xs text-ink-dim hover:text-crit" onClick={() => void unlink(a.id)} aria-label={`Remove alert ${a.id}`}>
                              Remove
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {canManage && <LinkAlertsForm incident={incident} onChange={setIncident} />}
          </section>

          <section aria-label="Timeline" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-3 text-sm font-semibold">Timeline</h2>
            <Timeline items={incident.timeline} />
            {canManage && (
              <div className="mt-5 border-t border-line pt-4">
                <h3 className="mb-2 text-xs uppercase tracking-wide text-ink-dim">Record a note, action or evidence reference</h3>
                <NoteComposer
                  onSubmit={async (body) => {
                    await api.addIncidentNote(incidentId, body)
                    setIncident(await api.incident(incidentId))
                  }}
                />
              </div>
            )}
          </section>
        </div>

        <div className="min-w-0 space-y-4">
          {canManage && <ManagePanel key={`${incident.status}|${incident.severity}|${incident.assigned_to}`} incident={incident} onChange={setIncident} />}
          {can('reports:export') && (
            <section aria-label="Report" className="rounded-md border border-line bg-panel p-4">
              <h2 className="mb-1 text-sm font-semibold">Incident report</h2>
              <p className="mb-3 text-xs text-ink-dim">Details, linked alerts with evidence samples, and the full timeline.</p>
              <div className="flex gap-2">
                <a href={api.incidentReportUrl(incident.id, 'markdown')} download className="rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm hover:border-accent">
                  Download Markdown
                </a>
                <a href={api.incidentReportUrl(incident.id, 'json')} download className="rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm hover:border-accent">
                  JSON
                </a>
              </div>
            </section>
          )}
        </div>
      </div>
    </section>
  )
}

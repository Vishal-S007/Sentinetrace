import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { api, type Alert, type Severity } from '../api/client'
import { SeverityBadge } from '../components/badges'
import { AssigneeSelect, TextArea } from '../components/investigation'
import { errorMessage } from '../lib/errors'
import { useAssignees } from '../lib/useAssignees'
import { Button, ErrorBanner, Field, PageHeader, Select, TextInput } from '../components/ui'
import { SEVERITIES, SEVERITY_LABEL } from '../lib/severity'

function parseIds(raw: string | null): number[] {
  if (!raw) return []
  const ids = raw
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0)
  return [...new Set(ids)].slice(0, 200)
}

export function IncidentNewPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const alertIds = useMemo(() => parseIds(params.get('alerts')), [params])
  const assignees = useAssignees(true)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [title, setTitle] = useState('')
  const [summary, setSummary] = useState('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [owner, setOwner] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    // Show the selected alerts (up to 20) so the analyst can confirm what is being grouped.
    Promise.all(alertIds.slice(0, 20).map((id) => api.alert(id).catch(() => null)))
      .then((list) => {
        if (!active) return
        const found = list.filter((a): a is NonNullable<typeof a> => a !== null)
        setAlerts(found)
        if (found.length > 0) setTitle((t) => t || (found.length === 1 ? found[0].title : `${found[0].title} and related activity`))
      })
      .catch(() => {})
    return () => {
      active = false
    }
  }, [alertIds])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const inc = await api.createIncident({
        title: title.trim(),
        summary,
        severity: severity || null,
        assigned_to: owner,
        alert_ids: alertIds,
      })
      navigate(`/incidents/${inc.id}`, { replace: true })
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <section className="max-w-3xl">
      <p className="mb-2 text-sm">
        <Link to="/incidents" className="text-ink-dim hover:text-ink">
          ← Incidents
        </Link>
      </p>
      <PageHeader title="New incident" subtitle="Group related alerts to investigate them together." />
      <form onSubmit={submit} aria-label="Create incident" className="space-y-4 rounded-md border border-line bg-panel p-4">
        <Field label="Title">
          <TextInput required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label="Summary (optional)">
          <TextArea rows={4} maxLength={10000} value={summary} onChange={(e) => setSummary(e.target.value)} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Severity" hint="Defaults to the highest severity among the linked alerts.">
            <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')}>
              <option value="">Automatic</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </Select>
          </Field>
          <div className="text-sm">
            <span className="mb-1 block text-ink-dim">Owner</span>
            <AssigneeSelect value={owner} currentName={null} assignees={assignees} onChange={setOwner} label="Incident owner" />
          </div>
        </div>
        <div>
          <h2 className="mb-1 text-sm text-ink-dim">Linked alerts ({alertIds.length})</h2>
          {alertIds.length === 0 ? (
            <p className="text-sm text-ink-dim">None yet. You can link alerts after creating the incident.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {alerts.map((a) => (
                <li key={a.id} className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="truncate">
                    #{a.id} {a.title}
                  </span>
                </li>
              ))}
              {alertIds.length > alerts.length && <li className="text-ink-dim">and {alertIds.length - alerts.length} more</li>}
            </ul>
          )}
        </div>
        {error && <ErrorBanner message={error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={() => navigate(-1)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !title.trim()}>
            {busy ? 'Creating…' : 'Create incident'}
          </Button>
        </div>
      </form>
    </section>
  )
}

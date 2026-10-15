import { useEffect, useState, type FormEvent } from 'react'

import { api, type RetentionCounts } from '../api/client'
import { Button, ErrorBanner, Field, Loading, PageHeader, SuccessBanner, TextInput } from '../components/ui'
import { errorMessage } from '../lib/errors'
import { formatBytes, formatCount, formatDateTime } from '../lib/format'

const ROWS: { key: keyof RetentionCounts; label: string; rule: string }[] = [
  { key: 'alerts', label: 'Alerts', rule: 'Resolved or false positive, last seen before the cutoff, not in an incident, no notes' },
  { key: 'evidence_links', label: 'Evidence links', rule: 'Belonging to those alerts' },
  { key: 'events', label: 'Events', rule: 'Before the cutoff, not evidence for a kept alert, not referenced by a note' },
  { key: 'ingestion_errors', label: 'Rejected-line records', rule: 'From imports that finished before the cutoff' },
  { key: 'stored_files', label: 'Stored uploads', rule: 'Uploaded before the cutoff, imports finished, content not shared with a newer upload' },
]

export function RetentionPage() {
  const [days, setDays] = useState('90')
  const [preview, setPreview] = useState<RetentionCounts | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [confirm, setConfirm] = useState('')
  const [purging, setPurging] = useState(false)
  const [done, setDone] = useState<RetentionCounts | null>(null)

  async function load(d: number) {
    setLoading(true)
    setError(null)
    try {
      setPreview(await api.retentionPreview(d))
    } catch (err) {
      setPreview(null)
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let active = true
    api
      .retentionPreview(90)
      .then((p) => active && setPreview(p))
      .catch((err: unknown) => active && setError(errorMessage(err)))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [])

  function onPreview(e: FormEvent) {
    e.preventDefault()
    setDone(null)
    setConfirm('')
    void load(Number(days))
  }

  async function purge() {
    if (!preview) return
    setPurging(true)
    setError(null)
    try {
      setDone(await api.retentionPurge(preview.older_than_days))
      setConfirm('')
      await load(preview.older_than_days)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setPurging(false)
    }
  }

  const total = preview ? preview.alerts + preview.events + preview.ingestion_errors + preview.stored_files : 0

  return (
    <section className="max-w-4xl">
      <PageHeader
        title="Data retention"
        subtitle="Remove old data that is no longer needed. Open alerts, incidents, notes, users, settings and the audit log are never removed."
      />
      <form onSubmit={onPreview} aria-label="Retention period" className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-line bg-panel p-4">
        <div className="w-48">
          <Field label="Keep data newer than (days)" hint={preview ? `Minimum ${preview.min_days} days` : undefined}>
            <TextInput type="number" min={1} max={36500} required value={days} onChange={(e) => setDays(e.target.value)} />
          </Field>
        </div>
        <Button type="submit">Preview</Button>
        <p className="pb-2 text-xs text-ink-dim">
          {preview?.auto_days
            ? `Automatic purge is on: the worker removes data older than ${preview.auto_days} days once a day.`
            : 'Automatic purge is off (set ST_RETENTION_AUTO_DAYS to enable it).'}
        </p>
      </form>

      {error && <ErrorBanner message={error} />}
      {done && (
        <div className="mb-4">
          <SuccessBanner
            message={`Removed ${formatCount(done.alerts)} alerts, ${formatCount(done.events)} events, ${formatCount(done.ingestion_errors)} rejected-line records and ${formatCount(done.stored_files)} stored uploads. Recorded in the audit log.`}
          />
        </div>
      )}
      {loading && <Loading label="Calculating…" />}
      {preview && !loading && (
        <div className="space-y-4">
          <section aria-label="Preview" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-1 text-sm font-semibold">Would be removed</h2>
            <p className="mb-3 text-xs text-ink-dim">Everything older than {formatDateTime(preview.cutoff)} that matches these rules.</p>
            <table className="w-full text-left text-sm">
              <tbody>
                {ROWS.map((r) => (
                  <tr key={r.key} className="border-t border-line align-top">
                    <th scope="row" className="py-2 pr-3 font-medium">
                      {r.label}
                    </th>
                    <td className="py-2 pr-3 text-right tabular-nums">
                      {formatCount(preview[r.key] as number)}
                      {r.key === 'stored_files' && preview.stored_bytes > 0 && <span className="text-ink-dim"> ({formatBytes(preview.stored_bytes)})</span>}
                    </td>
                    <td className="py-2 text-xs text-ink-dim">{r.rule}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section aria-label="Purge" className="rounded-md border border-crit/40 bg-panel p-4">
            <h2 className="mb-1 text-sm font-semibold">Purge</h2>
            {total === 0 ? (
              <p className="text-sm text-ink-dim">Nothing is eligible with this retention period.</p>
            ) : (
              <>
                <p className="mb-3 text-sm text-ink-dim">This cannot be undone. Type PURGE to confirm.</p>
                <div className="flex flex-wrap items-center gap-3">
                  <div className="w-40">
                    <TextInput aria-label="Type PURGE to confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
                  </div>
                  <Button variant="danger" disabled={confirm !== 'PURGE' || purging} onClick={() => void purge()}>
                    {purging ? 'Purging…' : `Purge data older than ${preview.older_than_days} days`}
                  </Button>
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </section>
  )
}

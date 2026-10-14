import { useState, type FormEvent, type TextareaHTMLAttributes } from 'react'

import { api, type Assignee, type Note, type NoteCreate, type NoteKind } from '../api/client'
import { errorMessage } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { NOTE_KIND_LABEL } from '../lib/severity'
import { Button, ErrorBanner, Select } from './ui'

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className="w-full rounded-md border border-line bg-base px-3 py-2 text-sm text-ink placeholder:text-ink-dim/60 focus:border-accent focus:outline-none"
      {...props}
    />
  )
}

export function AssigneeSelect({
  value,
  currentName,
  assignees,
  onChange,
  disabled,
  label = 'Owner',
}: {
  value: number | null
  currentName: string | null
  assignees: Assignee[]
  onChange: (id: number | null) => void
  disabled?: boolean
  label?: string
}) {
  const known = assignees.some((a) => a.id === value)
  return (
    <Select
      aria-label={label}
      value={value === null ? '' : String(value)}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
    >
      <option value="">Unassigned</option>
      {value !== null && !known && <option value={value}>{currentName ?? `User #${value}`}</option>}
      {assignees.map((a) => (
        <option key={a.id} value={a.id}>
          {a.username} ({a.role})
        </option>
      ))}
    </Select>
  )
}

const KIND_MARK: Record<NoteKind, string> = { note: '•', action: '✓', evidence: '§' }

export function NoteList({ notes, empty = 'No notes yet.' }: { notes: Note[]; empty?: string }) {
  if (notes.length === 0) return <p className="text-sm text-ink-dim">{empty}</p>
  return (
    <ol className="space-y-3">
      {notes.map((n) => (
        <li key={n.id} className="rounded-md border border-line bg-base/40 p-3">
          <p className="mb-1 flex flex-wrap items-center gap-x-2 text-xs text-ink-dim">
            <span aria-hidden>{KIND_MARK[n.kind]}</span>
            <span className="font-medium text-ink">{NOTE_KIND_LABEL[n.kind]}</span>
            <span>{n.author}</span>
            <span>{formatDateTime(n.created_at)}</span>
          </p>
          {/* User-entered text: rendered as text, line breaks kept. */}
          <p className="whitespace-pre-wrap break-words text-sm">{n.body}</p>
          {n.event_id !== null && <EventRef id={n.event_id} />}
        </li>
      ))}
    </ol>
  )
}

function EventRef({ id }: { id: number }) {
  return (
    <p className="mt-1 text-xs text-ink-dim">
      References event <span className="font-mono text-ink">#{id}</span>
    </p>
  )
}

export function NoteComposer({ onSubmit }: { onSubmit: (body: NoteCreate) => Promise<void> }) {
  const [kind, setKind] = useState<NoteKind>('note')
  const [body, setBody] = useState('')
  const [eventId, setEventId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!body.trim()) return
    setBusy(true)
    setError(null)
    try {
      await onSubmit({ kind, body: body.trim(), event_id: eventId ? Number(eventId) : null })
      setBody('')
      setEventId('')
      setKind('note')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} aria-label="Add note" className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <div className="w-48">
          <Select aria-label="Entry type" value={kind} onChange={(e) => setKind(e.target.value as NoteKind)}>
            {(Object.keys(NOTE_KIND_LABEL) as NoteKind[]).map((k) => (
              <option key={k} value={k}>
                {NOTE_KIND_LABEL[k]}
              </option>
            ))}
          </Select>
        </div>
        {kind === 'evidence' && (
          <input
            aria-label="Event ID (optional)"
            inputMode="numeric"
            pattern="[0-9]*"
            placeholder="Event ID (optional)"
            value={eventId}
            onChange={(e) => setEventId(e.target.value.replace(/\D/g, ''))}
            className="w-44 rounded-md border border-line bg-base px-3 py-2 text-sm"
          />
        )}
      </div>
      <TextArea
        aria-label="Note text"
        rows={3}
        maxLength={5000}
        placeholder={kind === 'action' ? 'What was done, e.g. "Blocked 203.0.113.60 at the firewall"' : 'Findings, reasoning, next steps…'}
        value={body}
        onChange={(e) => setBody(e.target.value)}
      />
      {error && <ErrorBanner message={error} />}
      <div className="flex items-center justify-between gap-2 text-xs text-ink-dim">
        <span>Notes are permanent; add a new note to correct one.</span>
        <Button type="submit" variant="primary" className="whitespace-nowrap" disabled={busy || !body.trim()}>
          {busy ? 'Saving…' : 'Add to record'}
        </Button>
      </div>
    </form>
  )
}

export function ExportLinks({
  kind,
  filters,
  label = 'Export',
}: {
  kind: 'alerts' | 'events' | 'audit'
  filters: Record<string, string | undefined>
  label?: string
}) {
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span className="text-ink-dim">{label}:</span>
      {(['csv', 'json'] as const).map((f) => (
        <a
          key={f}
          href={api.exportUrl(kind, filters, f)}
          download
          className="rounded-md border border-line bg-panel-2 px-2.5 py-1 text-xs hover:border-accent"
        >
          {f.toUpperCase()}
        </a>
      ))}
    </span>
  )
}

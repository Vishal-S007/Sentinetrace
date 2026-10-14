import { useEffect, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api, type JsonSchemaProp, type RuleDetail, type Severity } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge } from '../components/badges'
import { errorMessage } from '../lib/errors'
import { Button, ErrorBanner, Field, Loading, Select, SuccessBanner, TextInput } from '../components/ui'
import { formatDateTime } from '../lib/format'
import { SEVERITIES, SEVERITY_LABEL } from '../lib/severity'

type Draft = Record<string, string | boolean>

function toDraft(config: Record<string, unknown>, props: Record<string, JsonSchemaProp>): Draft {
  const d: Draft = {}
  for (const [k, p] of Object.entries(props)) {
    const v = config[k]
    d[k] = p.type === 'boolean' ? Boolean(v) : Array.isArray(v) ? v.join(', ') : v === undefined || v === null ? '' : String(v)
  }
  return d
}

function fromDraft(draft: Draft, props: Record<string, JsonSchemaProp>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, p] of Object.entries(props)) {
    const v = draft[k]
    if (p.type === 'boolean') out[k] = Boolean(v)
    else if (p.type === 'integer' || p.type === 'number') out[k] = v === '' ? null : Number(v)
    else if (p.type === 'array') out[k] = String(v).split(',').map((s) => s.trim()).filter(Boolean)
    else out[k] = v
  }
  return out
}

function label(key: string, p: JsonSchemaProp) {
  return p.title ?? key.replaceAll('_', ' ')
}

function ConfigValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) return <span className="font-mono text-xs">{value.join(', ')}</span>
  if (typeof value === 'boolean') return <span>{value ? 'yes' : 'no'}</span>
  return <span className="font-mono text-xs">{String(value)}</span>
}

function changedKeys(a: Record<string, unknown>, b: Record<string, unknown>): Set<string> {
  return new Set(Object.keys({ ...a, ...b }).filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k])))
}

export function RuleDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const canManage = can('rules:manage')
  const [rule, setRule] = useState<RuleDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft>({})
  const [enabled, setEnabled] = useState(true)
  const [severity, setSeverity] = useState<Severity>('medium')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)

  function load(r: RuleDetail) {
    setRule(r)
    setDraft(toDraft(r.config, r.config_schema.properties ?? {}))
    setEnabled(r.enabled)
    setSeverity(r.severity)
  }

  useEffect(() => {
    let active = true
    api
      .rule(id)
      .then((r) => active && load(r))
      .catch((err: unknown) => active && setError(errorMessage(err)))
    return () => {
      active = false
    }
  }, [id])

  if (error) return <ErrorBanner message={`Could not load rule ${id}: ${error}`} />
  if (!rule) return <Loading label="Loading rule…" />
  const props = rule.config_schema.properties ?? {}
  const newConfig = fromDraft(draft, props)
  const dirty = enabled !== rule.enabled || severity !== rule.severity || changedKeys(newConfig, rule.config).size > 0

  async function save(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setSaveError(null)
    setSaved(null)
    try {
      const updated = await api.updateRule(rule!.rule_id, { enabled, severity, config: newConfig, note })
      load(updated)
      setNote('')
      setSaved(`Saved as version ${updated.version}.`)
    } catch (err) {
      setSaveError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="max-w-5xl">
      <p className="mb-2 text-sm">
        <Link to="/rules" className="text-ink-dim hover:text-ink">
          ← Detection rules
        </Link>
      </p>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{rule.name}</h1>
          <p className="font-mono text-xs text-ink-dim">
            {rule.rule_id} · v{rule.version} · {rule.category}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={rule.severity} />
          <span className={rule.enabled ? 'text-sm text-ok' : 'text-sm text-ink-dim'}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <section aria-label="About this rule" className="rounded-md border border-line bg-panel p-4">
            <p className="text-sm leading-relaxed">{rule.description}</p>
            <h2 className="mb-1 mt-4 text-xs uppercase tracking-wide text-ink-dim">Recommended investigation</h2>
            <ol className="list-decimal space-y-1 pl-5 text-sm">
              {rule.recommended_steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
            {rule.open_alerts > 0 && (
              <p className="mt-4 text-sm">
                <Link to={`/alerts?rule_id=${rule.rule_id}`} className="text-accent hover:underline">
                  View this rule's alerts ({rule.open_alerts} open) →
                </Link>
              </p>
            )}
          </section>

          <section aria-label="Version history" className="rounded-md border border-line bg-panel p-4">
            <h2 className="mb-3 text-sm font-semibold">Version history</h2>
            <ol className="space-y-3">
              {rule.versions.map((v, i) => {
                const prev = rule.versions[i + 1]
                const diff = prev ? changedKeys(v.config, prev.config) : new Set<string>()
                return (
                  <li key={v.version} className="border-l-2 border-line pl-3 text-sm">
                    <p>
                      <span className="font-medium">v{v.version}</span>{' '}
                      <span className="text-xs text-ink-dim">
                        {formatDateTime(v.changed_at)} · {v.changed_by ?? 'initial configuration'}
                      </span>
                    </p>
                    {prev && (
                      <ul className="mt-1 space-y-0.5 text-xs text-ink-dim">
                        {v.enabled !== prev.enabled && <li>State: {prev.enabled ? 'enabled' : 'disabled'} → {v.enabled ? 'enabled' : 'disabled'}</li>}
                        {v.severity !== prev.severity && <li>Severity: {prev.severity} → {v.severity}</li>}
                        {[...diff].map((k) => (
                          <li key={k}>
                            {props[k] ? label(k, props[k]) : k}: <ConfigValue value={prev.config[k]} /> → <ConfigValue value={v.config[k]} />
                          </li>
                        ))}
                      </ul>
                    )}
                    {v.note && <p className="mt-1 text-xs">“{v.note}”</p>}
                  </li>
                )
              })}
            </ol>
          </section>
        </div>

        <form onSubmit={save} aria-label="Rule settings" className="space-y-3 self-start rounded-md border border-line bg-panel p-4">
          <h2 className="text-sm font-semibold">Settings</h2>
          {!canManage && <p className="text-xs text-ink-dim">Only administrators can change rule settings.</p>}
          <fieldset disabled={!canManage} className="space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              Rule enabled
            </label>
            <Field label="Severity" hint={`Default: ${SEVERITY_LABEL[rule.default_severity]}`}>
              <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY_LABEL[s]}
                  </option>
                ))}
              </Select>
            </Field>
            {Object.entries(props).map(([k, p]) => {
              const hint = [p.description, `default ${Array.isArray(rule.default_config[k]) ? (rule.default_config[k] as unknown[]).join(', ') : String(rule.default_config[k])}`]
                .filter(Boolean)
                .join(' · ')
              if (p.type === 'boolean')
                return (
                  <label key={k} className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1" checked={Boolean(draft[k])} onChange={(e) => setDraft((d) => ({ ...d, [k]: e.target.checked }))} />
                    <span>
                      {label(k, p)}
                      <span className="block text-xs text-ink-dim">{hint}</span>
                    </span>
                  </label>
                )
              return (
                <Field key={k} label={label(k, p)} hint={hint}>
                  <TextInput
                    type={p.type === 'integer' || p.type === 'number' ? 'number' : 'text'}
                    min={p.minimum}
                    max={p.maximum}
                    step={p.type === 'integer' ? 1 : undefined}
                    value={String(draft[k] ?? '')}
                    onChange={(e) => setDraft((d) => ({ ...d, [k]: e.target.value }))}
                  />
                </Field>
              )
            })}
            <Field label="Change note (optional)">
              <TextInput value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder="Why this change?" />
            </Field>
          </fieldset>
          {saveError && <ErrorBanner message={saveError} />}
          {saved && <SuccessBanner message={saved} />}
          {canManage && (
            <Button type="submit" variant="primary" className="w-full" disabled={!dirty || saving}>
              {saving ? 'Saving…' : 'Save new version'}
            </Button>
          )}
        </form>
      </div>
    </section>
  )
}

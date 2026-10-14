/** Typed API client. Same-origin, cookie-authenticated, CSRF-protected. */

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// ---- Types (mirror backend schemas) ----

export type RoleName = 'admin' | 'analyst' | 'viewer'

export interface HealthResponse {
  status: string
  version: string
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready'
  database: 'ok' | 'unavailable'
}

export interface User {
  id: number
  username: string
  email: string | null
  role: RoleName
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export interface Me {
  user: User
  permissions: string[]
}

export interface Role {
  name: RoleName
  description: string
  permissions: string[]
}

export interface AuditEntry {
  id: number
  occurred_at: string
  actor_user_id: number | null
  actor_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  ip: string | null
  request_id: string | null
  details: Record<string, unknown>
}

export interface AuditPage {
  items: AuditEntry[]
  next_before_id: number | null
}

export interface UserCreate {
  username: string
  email?: string | null
  password: string
  role: RoleName
}

export type UserUpdate = Partial<{ email: string | null; role: RoleName; is_active: boolean; password: string }>

export type SourceFormat =
  | 'auto'
  | 'apache_combined'
  | 'nginx_combined'
  | 'nginx_common'
  | 'nginx_custom'
  | 'json'
  | 'auth_log'
export type JobStatus = 'queued' | 'running' | 'completed' | 'completed_with_errors' | 'failed'

export interface LogFormat {
  id: Exclude<SourceFormat, 'auto'>
  label: string
  example: string
  detectable: boolean
}

export interface LogSource {
  id: number
  name: string
  description: string
  format: SourceFormat
  custom_pattern: string | null
  timezone: string
  enabled: boolean
  created_at: string
  file_count: number
  event_count: number
  last_upload_at: string | null
}

export interface SourceCreate {
  name: string
  description?: string
  format: SourceFormat
  custom_pattern?: string | null
  timezone: string
}

export type SourceUpdate = Partial<SourceCreate & { enabled: boolean }>

export interface ImportedFile {
  id: number
  source_id: number
  original_filename: string
  sha256: string
  size_bytes: number
  encoding: string
  uploaded_at: string
}

export interface Job {
  id: number
  status: JobStatus
  source_id: number
  source_name: string
  file_id: number
  filename: string
  size_bytes: number
  encoding: string
  requested_format: string | null
  format: string | null
  total_lines: number
  parsed_count: number
  rejected_count: number
  duplicate_count: number
  errors_truncated: boolean
  error_message: string | null
  attempts: number
  created_by: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface JobPage {
  items: Job[]
  next_before_id: number | null
}

export interface IngestionErrorRow {
  id: number
  line_number: number
  reason: string
  raw_line: string
}

export interface ErrorPage {
  items: IngestionErrorRow[]
  next_after_id: number | null
  total_rejected: number
  stored: number
  truncated: boolean
}

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'false_positive'
export type Confidence = 'low' | 'medium' | 'high'
export type DashboardRange = '24h' | '7d' | '30d' | '90d' | 'all'

export interface Alert {
  id: number
  rule_id: string
  rule_name: string
  rule_version: number
  title: string
  severity: Severity
  status: AlertStatus
  confidence: Confidence
  source_ip: string | null
  username: string | null
  endpoint: string | null
  first_seen: string
  last_seen: string
  event_count: number
  assigned_to: number | null
  assignee: string | null
  created_at: string
  updated_at: string
}

export interface AlertDetail extends Alert {
  reason: string
  confidence_reason: string
  recommended_action: string
  recommended_steps: string[]
  window_seconds: number
  bucket_start: string
  evidence_truncated: boolean
  evidence_count: number
  details: Record<string, unknown>
}

export interface AlertPage {
  items: Alert[]
  next_before_id: number | null
}

export interface EvidenceItem {
  event_id: number
  indicator: string | null
  event_time: string
  event_type: string
  source_ip: string | null
  username: string | null
  http_method: string | null
  path: string | null
  query: string | null
  http_status: number | null
  user_agent: string | null
  source_id: number
  file_id: number
  line_number: number
  raw_line: string
}

export interface EvidencePage {
  items: EvidenceItem[]
  next_after_id: number | null
  total_linked: number
  total_events: number
  truncated: boolean
}

export interface RuleSummary {
  rule_id: string
  name: string
  category: string
  severity: Severity
  enabled: boolean
}

export interface JsonSchemaProp {
  type?: string
  title?: string
  description?: string
  minimum?: number
  maximum?: number
  exclusiveMinimum?: number
  items?: { type?: string }
  default?: unknown
}

export interface Rule extends RuleSummary {
  description: string
  default_severity: Severity
  version: number
  config: Record<string, unknown>
  default_config: Record<string, unknown>
  config_schema: { properties?: Record<string, JsonSchemaProp>; required?: string[] }
  recommended_steps: string[]
  updated_at: string
  updated_by: string | null
  open_alerts: number
}

export interface RuleVersion {
  version: number
  enabled: boolean
  severity: Severity
  config: Record<string, unknown>
  note: string
  changed_by: string | null
  changed_at: string
}

export interface RuleDetail extends Rule {
  versions: RuleVersion[]
}

export type RuleUpdate = Partial<{ enabled: boolean; severity: Severity; config: Record<string, unknown>; note: string }>

export interface DetectionRun {
  id: number
  trigger: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  alerts_created: number
  alerts_updated: number
  error_message: string | null
  created_at: string
  finished_at: string | null
}

export type NoteKind = 'note' | 'action' | 'evidence'

export interface Note {
  id: number
  kind: NoteKind
  body: string
  event_id: number | null
  author: string
  created_at: string
}

export interface NoteCreate {
  kind: NoteKind
  body: string
  event_id?: number | null
}

export interface HistoryEntry {
  id: number
  occurred_at: string
  actor: string | null
  action: string
  details: Record<string, unknown>
}

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'

export interface IncidentRef {
  id: number
  title: string
  status: IncidentStatus
  severity: Severity
}

export interface AlertActivity {
  notes: Note[]
  history: HistoryEntry[]
  incidents: IncidentRef[]
}

export interface Assignee {
  id: number
  username: string
  role: RoleName
}

export interface Incident {
  id: number
  title: string
  summary: string
  status: IncidentStatus
  severity: Severity
  assigned_to: number | null
  assignee: string | null
  created_by: string
  created_at: string
  updated_at: string
  closed_at: string | null
  alert_count: number
}

export interface TimelineItem {
  at: string
  kind: 'observed' | 'change' | 'note'
  title: string
  detail: string | null
  actor: string | null
  alert_id: number | null
  event_id: number | null
}

export interface IncidentDetail extends Incident {
  alerts: Alert[]
  notes: Note[]
  timeline: TimelineItem[]
}

export interface IncidentPage {
  items: Incident[]
  next_before_id: number | null
}

export interface IncidentCreate {
  title: string
  summary?: string
  severity?: Severity | null
  assigned_to?: number | null
  alert_ids?: number[]
}

export type IncidentUpdate = Partial<{
  title: string
  summary: string
  status: IncidentStatus
  severity: Severity
  assigned_to: number | null
  note: string
}>

export type IncidentFilters = Partial<{ status: string; severity: string; assigned_to: string; q: string; open_only: string }>

export interface EventItem {
  id: number
  event_time: string
  ingested_at: string
  event_type: string
  source_ip: string | null
  username: string | null
  http_method: string | null
  path: string | null
  query: string | null
  http_status: number | null
  bytes_sent: number | null
  user_agent: string | null
  host: string | null
  severity: string | null
  message: string | null
  source_id: number
  source_name: string
  raw_line: string
  alert_count: number
  max_alert_severity: Severity | null
}

export interface EventPage {
  items: EventItem[]
  next_cursor: string | null
  count: number | null
  count_capped: boolean
}

export interface EventDetail extends EventItem {
  referrer: string | null
  http_version: string | null
  attributes: Record<string, unknown>
  file_id: number
  filename: string
  line_number: number
  job_id: number
  alerts: { id: number; rule_id: string; title: string; severity: Severity; status: AlertStatus; indicator: string | null }[]
}

export interface Dashboard {
  range: DashboardRange
  start: string | null
  end: string
  bucket: 'hour' | 'day' | 'week'
  totals: { events: number; alerts: number; open_alerts: number; high_open_alerts: number; sources: number; files: number }
  alerts_by_severity: { key: Severity; count: number }[]
  alerts_by_status: { key: AlertStatus; count: number }[]
  events_over_time: { bucket_start: string; count: number }[]
  alerts_over_time: ({ bucket_start: string } & Record<Severity, number>)[]
  top_source_ips: { source_ip: string; alert_count: number; event_count: number; max_severity: Severity }[]
  top_rules: { rule_id: string; name: string; alert_count: number }[]
  recent_jobs: { id: number; status: JobStatus; filename: string; source_name: string; parsed_count: number; rejected_count: number; created_at: string }[]
  recent_high_alerts: Alert[]
  data_range: { first_event: string | null; last_event: string | null }
}

export type EventFilters = Partial<{
  q: string
  since: string
  until: string
  source_ip: string
  event_type: string
  http_status: string
  method: string
  username: string
  source_id: string
  flagged: string
  alert_severity: string
  alert_id: string
}>

export type AlertFilters = Partial<{
  status: string
  severity: string
  rule_id: string
  source_ip: string
  assigned_to: string
  q: string
  since: string
  until: string
}>

// ---- Transport ----

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const CSRF_COOKIE = 'st_csrf'

export function readCookie(name: string): string | null {
  for (const part of document.cookie.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return decodeURIComponent(v.join('='))
  }
  return null
}

type UnauthorizedListener = () => void
let onUnauthorized: UnauthorizedListener | null = null

/** The auth provider registers here so any 401 (expired session) logs the UI out. */
export function setUnauthorizedListener(fn: UnauthorizedListener | null) {
  onUnauthorized = fn
}

function describeValidation(detail: unknown): string | null {
  if (!Array.isArray(detail)) return null
  const msgs = detail
    .map((d: { loc?: unknown[]; msg?: string }) => {
      const field = Array.isArray(d.loc) ? d.loc[d.loc.length - 1] : undefined
      return field && d.msg ? `${String(field)}: ${d.msg}` : d.msg
    })
    .filter(Boolean)
  return msgs.length ? msgs.join('; ') : null
}

interface RequestOptions {
  method?: string
  body?: unknown
  /** Multipart body; the browser sets the Content-Type boundary. */
  form?: FormData
  acceptStatuses?: number[]
  /** Don't trigger the global logout on 401 (used by login and the initial /me probe). */
  quiet401?: boolean
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = {}
  if (opts.body !== undefined && !opts.form) headers['Content-Type'] = 'application/json'
  if (UNSAFE.has(method)) {
    const csrf = readCookie(CSRF_COOKIE)
    if (csrf) headers['X-CSRF-Token'] = csrf
  }

  let resp: Response
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.form ?? (opts.body !== undefined ? JSON.stringify(opts.body) : undefined),
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the SentinelTrace API')
  }

  if (!resp.ok && !(opts.acceptStatuses ?? []).includes(resp.status)) {
    let message = `Request failed (${resp.status})`
    try {
      const body = (await resp.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') message = body.detail
      else message = describeValidation(body.detail) ?? message
    } catch {
      /* non-JSON error body: keep the generic message */
    }
    if (resp.status === 401 && !opts.quiet401) onUnauthorized?.()
    throw new ApiError(resp.status, message)
  }
  if (resp.status === 204) return undefined as T
  return (await resp.json()) as T
}

export function toQuery(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, String(v))
  const qs = q.toString()
  return qs ? `?${qs}` : ''
}

// ---- Endpoints ----

export const api = {
  health: () => request<HealthResponse>('/api/health'),
  // 503 is a meaningful readiness answer, not a transport failure.
  ready: () => request<ReadinessResponse>('/api/ready', { acceptStatuses: [503] }),

  me: () => request<Me>('/api/auth/me', { quiet401: true }),
  login: (username: string, password: string) =>
    request<Me>('/api/auth/login', { method: 'POST', body: { username, password }, quiet401: true }),
  logout: () => request<void>('/api/auth/logout', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('/api/auth/password', { method: 'POST', body: { current_password, new_password } }),

  roles: () => request<Role[]>('/api/roles'),
  users: () => request<User[]>('/api/users'),
  createUser: (body: UserCreate) => request<User>('/api/users', { method: 'POST', body }),
  updateUser: (id: number, body: UserUpdate) => request<User>(`/api/users/${id}`, { method: 'PATCH', body }),

  formats: () => request<LogFormat[]>('/api/formats'),
  sources: () => request<LogSource[]>('/api/sources'),
  createSource: (body: SourceCreate) => request<LogSource>('/api/sources', { method: 'POST', body }),
  updateSource: (id: number, body: SourceUpdate) =>
    request<LogSource>(`/api/sources/${id}`, { method: 'PATCH', body }),
  upload: (sourceId: number, file: File, format?: string) => {
    const form = new FormData()
    form.append('file', file)
    if (format) form.append('format', format)
    return request<{ file: ImportedFile; job: Job }>(`/api/sources/${sourceId}/files`, { method: 'POST', form })
  },
  jobs: (params: { status?: string; source_id?: number; before_id?: number; limit?: number }) =>
    request<JobPage>(`/api/jobs${toQuery(params)}`),
  job: (id: number) => request<Job>(`/api/jobs/${id}`),
  jobErrors: (id: number, after_id?: number) => request<ErrorPage>(`/api/jobs/${id}/errors${toQuery({ after_id })}`),
  retryJob: (id: number) => request<Job>(`/api/jobs/${id}/retry`, { method: 'POST' }),
  jobErrorsCsvUrl: (id: number) => `/api/jobs/${id}/errors.csv`,

  dashboard: (range: DashboardRange) => request<Dashboard>(`/api/dashboard${toQuery({ range })}`),
  events: (filters: EventFilters, cursor?: string, limit = 50) =>
    request<EventPage>(`/api/events${toQuery({ ...filters, cursor, limit, with_count: 'true' })}`),
  event: (id: number) => request<EventDetail>(`/api/events/${id}`),
  alerts: (filters: AlertFilters, before_id?: number, limit = 50) =>
    request<AlertPage>(`/api/alerts${toQuery({ ...filters, before_id, limit })}`),
  alert: (id: number) => request<AlertDetail>(`/api/alerts/${id}`),
  alertEvidence: (id: number, after_id?: number, limit = 50) =>
    request<EvidencePage>(`/api/alerts/${id}/evidence${toQuery({ after_id, limit })}`),
  setAlertStatus: (id: number, status: AlertStatus, note = '') =>
    request<AlertDetail>(`/api/alerts/${id}`, { method: 'PATCH', body: { status, note } }),
  assignAlert: (id: number, assigned_to: number | null) =>
    request<AlertDetail>(`/api/alerts/${id}`, { method: 'PATCH', body: { assigned_to } }),
  alertActivity: (id: number) => request<AlertActivity>(`/api/alerts/${id}/activity`),
  addAlertNote: (id: number, body: NoteCreate) =>
    request<Note>(`/api/alerts/${id}/notes`, { method: 'POST', body }),
  assignees: () => request<Assignee[]>('/api/assignees'),

  rules: () => request<Rule[]>('/api/rules'),
  rule: (id: string) => request<RuleDetail>(`/api/rules/${encodeURIComponent(id)}`),
  updateRule: (id: string, body: RuleUpdate) =>
    request<RuleDetail>(`/api/rules/${encodeURIComponent(id)}`, { method: 'PATCH', body }),
  runDetection: () => request<DetectionRun>('/api/detection/runs', { method: 'POST', body: {} }),
  detectionRuns: () => request<DetectionRun[]>('/api/detection/runs?limit=5'),

  incidents: (filters: IncidentFilters, before_id?: number, limit = 50) =>
    request<IncidentPage>(`/api/incidents${toQuery({ ...filters, before_id, limit })}`),
  incident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
  createIncident: (body: IncidentCreate) => request<IncidentDetail>('/api/incidents', { method: 'POST', body }),
  updateIncident: (id: number, body: IncidentUpdate) =>
    request<IncidentDetail>(`/api/incidents/${id}`, { method: 'PATCH', body }),
  linkAlerts: (id: number, alert_ids: number[]) =>
    request<IncidentDetail>(`/api/incidents/${id}/alerts`, { method: 'POST', body: { alert_ids } }),
  unlinkAlert: (id: number, alertId: number) =>
    request<IncidentDetail>(`/api/incidents/${id}/alerts/${alertId}`, { method: 'DELETE' }),
  addIncidentNote: (id: number, body: NoteCreate) =>
    request<Note>(`/api/incidents/${id}/notes`, { method: 'POST', body }),
  incidentReportUrl: (id: number, format: 'markdown' | 'json') => `/api/incidents/${id}/report${toQuery({ format })}`,

  /** Download links: plain GETs, authenticated by the session cookie. */
  exportUrl: (kind: 'alerts' | 'events' | 'audit', filters: Record<string, string | undefined>, format: 'csv' | 'json') =>
    `/api/${kind}/export${toQuery({ ...filters, format })}`,

  audit: (params: { action?: string; actor?: string; target_type?: string; target_id?: string; before_id?: number; limit?: number }) =>
    request<AuditPage>(`/api/audit${toQuery(params)}`),
}

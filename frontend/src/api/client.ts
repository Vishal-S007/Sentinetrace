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

function toQuery(params: Record<string, string | number | undefined>): string {
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

  audit: (params: { action?: string; actor?: string; before_id?: number; limit?: number }) =>
    request<AuditPage>(`/api/audit${toQuery(params)}`),
}

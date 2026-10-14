import type { Job, LogFormat, LogSource } from '../api/client'

export const formats: LogFormat[] = [
  { id: 'apache_combined', label: 'Apache combined', example: '1.2.3.4 - - [..] "GET / HTTP/1.1" 200 1 "-" "UA"', detectable: true },
  { id: 'nginx_custom', label: 'Nginx custom log_format', example: 'pattern', detectable: false },
  { id: 'json', label: 'JSON lines', example: '{"timestamp":"..."}', detectable: true },
]

export function makeSource(over: Partial<LogSource> = {}): LogSource {
  return {
    id: 1,
    name: 'web-prod',
    description: 'Production nginx',
    format: 'apache_combined',
    custom_pattern: null,
    timezone: 'UTC',
    enabled: true,
    created_at: '2026-10-10T00:00:00Z',
    file_count: 2,
    event_count: 1234,
    last_upload_at: '2026-10-11T00:00:00Z',
    ...over,
  }
}

export function makeJob(over: Partial<Job> = {}): Job {
  return {
    id: 7,
    status: 'completed',
    source_id: 1,
    source_name: 'web-prod',
    file_id: 3,
    filename: 'access.log',
    size_bytes: 2048,
    encoding: 'utf-8',
    requested_format: null,
    format: 'apache_combined',
    total_lines: 10,
    parsed_count: 8,
    rejected_count: 2,
    duplicate_count: 0,
    errors_truncated: false,
    error_message: null,
    attempts: 1,
    created_by: 'analyst1',
    created_at: '2026-10-12T10:00:00Z',
    started_at: '2026-10-12T10:00:01Z',
    finished_at: '2026-10-12T10:00:02Z',
    ...over,
  }
}

import type { Alert, AlertDetail, Dashboard, EventItem } from '../api/client'

export function makeAlert(over: Partial<Alert> = {}): Alert {
  return {
    id: 11,
    rule_id: 'ST-WEB-001',
    rule_name: 'SQL injection indicators in request data',
    rule_version: 1,
    title: 'SQL injection indicators from 203.0.113.10',
    severity: 'high',
    status: 'new',
    confidence: 'high',
    source_ip: '203.0.113.10',
    username: null,
    endpoint: '/products',
    first_seen: '2026-10-01T01:14:00Z',
    last_seen: '2026-10-01T01:14:25Z',
    event_count: 6,
    assigned_to: null,
    assignee: null,
    created_at: '2026-10-13T10:00:00Z',
    updated_at: '2026-10-13T10:00:00Z',
    ...over,
  }
}

export function makeAlertDetail(over: Partial<AlertDetail> = {}): AlertDetail {
  return {
    ...makeAlert(),
    reason: '6 request(s) from 203.0.113.10 contained SQL injection patterns. Indicator only: a matching request does not show the attack succeeded.',
    confidence_reason: 'The User-Agent identifies a known attack tool.',
    recommended_action: 'Review the matching requests.',
    recommended_steps: ['Review the matching requests.', 'Check database logs.', 'Block the IP.'],
    window_seconds: 3600,
    bucket_start: '2026-10-01T01:00:00Z',
    evidence_truncated: false,
    evidence_count: 1,
    details: { indicator_types: ['union_select', 'tautology'], attack_tool_user_agent: true },
    assigned_to: null,
    ...over,
  }
}

export function makeEvent(over: Partial<EventItem> = {}): EventItem {
  return {
    id: 501,
    event_time: '2026-10-01T01:14:10Z',
    ingested_at: '2026-10-13T10:00:00Z',
    event_type: 'http_request',
    source_ip: '203.0.113.10',
    username: null,
    http_method: 'GET',
    path: '/products',
    query: 'id=1%20union%20select%201',
    http_status: 500,
    bytes_sent: 512,
    user_agent: 'sqlmap/1.7',
    host: null,
    severity: null,
    message: null,
    source_id: 1,
    source_name: 'web-prod',
    raw_line: '203.0.113.10 - - [01/Oct/2026:01:14:10 +0000] "GET /products?id=1%20union%20select%201 HTTP/1.1" 500 512 "-" "sqlmap/1.7"',
    alert_count: 2,
    max_alert_severity: 'high',
    ...over,
  }
}

export function makeDashboard(over: Partial<Dashboard> = {}): Dashboard {
  const b = (h: number) => `2026-10-01T0${h}:00:00Z`
  return {
    range: '7d',
    start: '2026-10-01T00:00:00Z',
    end: '2026-10-01T05:00:00Z',
    bucket: 'hour',
    totals: { events: 6620, alerts: 13, open_alerts: 12, high_open_alerts: 4, sources: 3, files: 3 },
    alerts_by_severity: [
      { key: 'low', count: 1 },
      { key: 'medium', count: 8 },
      { key: 'high', count: 4 },
      { key: 'critical', count: 0 },
    ],
    alerts_by_status: [
      { key: 'new', count: 12 },
      { key: 'investigating', count: 1 },
      { key: 'resolved', count: 0 },
      { key: 'false_positive', count: 0 },
    ],
    events_over_time: [0, 1, 2, 3].map((h) => ({ bucket_start: b(h), count: 1000 + h })),
    alerts_over_time: [0, 1, 2, 3].map((h) => ({ bucket_start: b(h), low: 0, medium: h, high: 1, critical: 0 })),
    top_source_ips: [{ source_ip: '203.0.113.60', alert_count: 4, event_count: 67, max_severity: 'high' }],
    top_rules: [{ rule_id: 'ST-AUTH-001', name: 'Repeated authentication failures', alert_count: 4 }],
    recent_jobs: [{ id: 3, status: 'completed', filename: 'web_access.log', source_name: 'web', parsed_count: 6331, rejected_count: 0, created_at: '2026-10-13T10:00:00Z' }],
    recent_high_alerts: [makeAlert({ id: 38, title: 'Potential brute force from 203.0.113.60 (8 accounts)' })],
    data_range: { first_event: '2026-10-01T00:00:00Z', last_event: '2026-10-01T05:00:00Z' },
    ...over,
  }
}

import type { IncidentDetail, RuleDetail } from '../api/client'

export function makeIncident(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: 5,
    title: 'SQL injection campaign from 203.0.113.10',
    summary: 'Scanner followed by injection attempts.',
    status: 'open',
    severity: 'high',
    assigned_to: null,
    assignee: null,
    created_by: 'analystuser',
    created_at: '2026-10-13T10:00:00Z',
    updated_at: '2026-10-13T10:05:00Z',
    closed_at: null,
    alert_count: 1,
    alerts: [makeAlert()],
    notes: [],
    timeline: [
      { at: '2026-10-01T01:14:00Z', kind: 'observed', title: 'First observed: SQL injection indicators from 203.0.113.10', detail: null, actor: null, alert_id: 11, event_id: null },
      { at: '2026-10-13T10:00:00Z', kind: 'change', title: 'Incident created', detail: null, actor: 'analystuser', alert_id: null, event_id: null },
      { at: '2026-10-13T10:05:00Z', kind: 'note', title: 'Action taken', detail: 'Blocked <b>IP</b> at WAF', actor: 'analystuser', alert_id: null, event_id: 501 },
    ],
    ...over,
  }
}

export const assignees = [
  { id: 2, username: 'ana', role: 'analyst' as const },
  { id: 3, username: 'root', role: 'admin' as const },
]

export function makeRule(over: Partial<RuleDetail> = {}): RuleDetail {
  return {
    rule_id: 'ST-AUTH-001',
    name: 'Repeated authentication failures',
    category: 'auth',
    description: 'Many failed logins for one account from one IP.',
    severity: 'medium',
    default_severity: 'medium',
    enabled: true,
    version: 2,
    config: { threshold: 5, window_seconds: 300 },
    default_config: { threshold: 5, window_seconds: 300 },
    config_schema: {
      properties: {
        threshold: { type: 'integer', title: 'Threshold', description: 'Failures within the window', minimum: 2, maximum: 10000 },
        window_seconds: { type: 'integer', title: 'Window Seconds', minimum: 10, maximum: 86400 },
      },
    },
    recommended_steps: ['Check whether any login succeeded.'],
    updated_at: '2026-10-13T09:00:00Z',
    updated_by: 'root',
    open_alerts: 3,
    versions: [
      { version: 2, enabled: true, severity: 'medium', config: { threshold: 5, window_seconds: 300 }, note: 'tuned', changed_by: 'root', changed_at: '2026-10-13T09:00:00Z' },
      { version: 1, enabled: true, severity: 'medium', config: { threshold: 8, window_seconds: 300 }, note: '', changed_by: null, changed_at: '2026-10-12T09:00:00Z' },
    ],
    ...over,
  }
}

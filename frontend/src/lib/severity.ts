import type { AlertStatus, Severity } from '../api/client'

export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']

/**
 * Severity is ordinal, so it uses one hue stepped light -> dark (validated with the dataviz
 * palette validator in --ordinal mode against the dark panel surface #111821). Colour is
 * never the only cue: severity is always shown with its text label.
 */
export const SEVERITY_COLOR: Record<Severity, string> = {
  low: '#f4b4b4',
  medium: '#ec8a8a',
  high: '#e05b5b',
  critical: '#c62f2f',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export const ALERT_STATUSES: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive']

/** Single-series charts (event volume) use the first categorical slot, dark-mode step. */
export const SERIES_BLUE = '#3987e5'

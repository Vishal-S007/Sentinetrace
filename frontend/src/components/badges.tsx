import type { AlertStatus, Confidence, Severity } from '../api/client'
import { SEVERITY_COLOR, SEVERITY_LABEL, STATUS_LABEL } from '../lib/severity'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium">
      <span aria-hidden className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLOR[severity] }} />
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

const STATUS_STYLE: Record<AlertStatus, string> = {
  new: 'border-accent/50 text-accent',
  investigating: 'border-warn/50 text-warn',
  resolved: 'border-ok/50 text-ok',
  false_positive: 'border-line text-ink-dim',
}

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span className={`inline-block whitespace-nowrap rounded-full border px-2 py-0.5 text-xs ${STATUS_STYLE[status]}`}>
      {STATUS_LABEL[status]}
    </span>
  )
}

export function ConfidenceLabel({ confidence }: { confidence: Confidence }) {
  const bars = { low: 1, medium: 2, high: 3 }[confidence]
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink-dim" title={`${confidence} confidence`}>
      <span aria-hidden className="inline-flex items-end gap-0.5">
        {[1, 2, 3].map((i) => (
          <span key={i} className={`w-1 rounded-sm ${i <= bars ? 'bg-ink' : 'bg-line'}`} style={{ height: 4 + i * 3 }} />
        ))}
      </span>
      <span className="capitalize">{confidence} confidence</span>
    </span>
  )
}

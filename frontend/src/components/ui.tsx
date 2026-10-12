import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react'

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="text-sm text-ink-dim">{subtitle}</p>}
      </div>
      {actions}
    </div>
  )
}

export function Button({
  variant = 'secondary',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' }) {
  const styles = {
    primary: 'bg-accent text-on-accent font-medium hover:brightness-110',
    secondary: 'border border-line bg-panel-2 hover:border-accent',
    danger: 'border border-crit/50 text-crit hover:bg-crit/10',
  }[variant]
  return (
    <button
      type="button"
      className={`rounded-md px-3 py-1.5 text-sm disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}
      {...props}
    />
  )
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-ink-dim">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-dim">{hint}</span>}
    </label>
  )
}

const inputCls =
  'w-full rounded-md border border-line bg-base px-3 py-2 text-sm text-ink placeholder:text-ink-dim/60 focus:border-accent focus:outline-none'

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={inputCls} {...props} />
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={inputCls} {...props} />
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-md border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
      {message}
    </div>
  )
}

export function SuccessBanner({ message }: { message: string }) {
  return (
    <div role="status" className="rounded-md border border-ok/40 bg-ok/10 p-3 text-sm text-ok">
      {message}
    </div>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <p role="status" className="text-sm text-ink-dim">
      {label}
    </p>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-md border border-dashed border-line p-6 text-center text-sm text-ink-dim">{children}</p>
}

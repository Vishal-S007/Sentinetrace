import { useEffect, useState, type ReactNode } from 'react'
import { Link, NavLink, useParams } from 'react-router-dom'

import { api, ApiError, type LegalFacts } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ErrorBanner, Loading } from '../components/ui'
import { LEGAL_DOCS, type LegalSlug as Slug } from '../lib/legal'


/** Links to the three legal pages, for page footers. */
export function LegalLinks({ className = '' }: { className?: string }) {
  return (
    <nav aria-label="Legal" className={`flex flex-wrap gap-x-3 gap-y-1 text-xs text-ink-dim ${className}`}>
      {LEGAL_DOCS.map((d) => (
        <Link key={d.slug} to={`/legal/${d.slug}`} className="underline-offset-2 hover:text-ink hover:underline">
          {d.title}
        </Link>
      ))}
    </nav>
  )
}

function H2({ children }: { children: ReactNode }) {
  return <h2 className="mb-2 mt-8 text-base font-semibold text-ink">{children}</h2>
}

function P({ children }: { children: ReactNode }) {
  return <p className="mb-3">{children}</p>
}

function List({ items }: { items: ReactNode[] }) {
  return (
    <ul className="mb-3 list-disc space-y-1 pl-5">
      {items.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  )
}

function operatorName(f: LegalFacts) {
  return f.operator.name || 'the organisation that runs this SentinelTrace instance'
}

function Contact({ facts }: { facts: LegalFacts }) {
  const { name, contact, address } = facts.operator
  if (!name && !contact && !address) {
    return (
      <p role="note" className="mb-3 rounded-md border border-warn/40 bg-warn/10 p-3 text-warn">
        The operator of this instance has not published their details yet. Ask your administrator. Administrators set them
        with ST_OPERATOR_NAME, ST_OPERATOR_CONTACT and ST_OPERATOR_ADDRESS.
      </p>
    )
  }
  return (
    <dl className="mb-3 grid grid-cols-[6rem_1fr] gap-y-1">
      {name && (
        <>
          <dt className="text-ink-dim">Operator</dt>
          <dd>{name}</dd>
        </>
      )}
      {address && (
        <>
          <dt className="text-ink-dim">Address</dt>
          <dd className="whitespace-pre-line">{address}</dd>
        </>
      )}
      {contact && (
        <>
          <dt className="text-ink-dim">Contact</dt>
          <dd>{contact.includes('@') ? <a className="text-accent underline" href={`mailto:${contact}`}>{contact}</a> : contact}</dd>
        </>
      )}
    </dl>
  )
}

function hours(h: number) {
  return h % 24 === 0 ? `${h / 24} day${h === 24 ? '' : 's'}` : `${h} hours`
}

function Privacy({ facts }: { facts: LegalFacts }) {
  const r = facts.retention
  return (
    <>
      <P>
        This policy explains what personal data this SentinelTrace instance holds, why, for how long, and what you can do
        about it. SentinelTrace is a log analysis and threat detection tool used by authorised staff.
      </P>

      <H2>1. Who is responsible</H2>
      <P>The data controller is {operatorName(facts)} (the &ldquo;operator&rdquo;).</P>
      <Contact facts={facts} />

      <H2>2. Data about people who use SentinelTrace</H2>
      <List
        items={[
          <><strong>Account:</strong> username, role, and an email address only if your administrator adds one. Your password is stored only as an Argon2id hash. Nobody can read it.</>,
          <><strong>Sign-in records:</strong> the time, your IP address and your browser&rsquo;s user agent for each session, and the username, IP address and outcome of each sign-in attempt.</>,
          <><strong>Audit log:</strong> security-relevant actions you take (for example triage, exports, rule or user changes), with time and IP address.</>,
          <><strong>Your work:</strong> alert status changes, notes and incidents you create.</>,
        ]}
      />

      <H2>3. Data in imported logs</H2>
      <P>
        Staff import server logs to look for attacks. These logs can contain IP addresses, usernames, web addresses and
        browser user agents of people who used the monitored systems. Only staff authorised by the operator import logs, and
        only logs the operator is entitled to process.
      </P>

      <H2>4. Why the data is used</H2>
      <List
        items={[
          'To provide your account, keep it secure, and limit password-guessing attacks.',
          'To detect and investigate attacks on the operator’s systems (security monitoring).',
          'To keep an accountable record of who changed what.',
        ]}
      />
      <P>
        The legal basis is the operator&rsquo;s legitimate interest in protecting its networks and information, and, for
        staff accounts, the employment or service relationship.
      </P>

      <H2>5. What SentinelTrace does not do</H2>
      <List
        items={[
          'No analytics, advertising or tracking. No third-party scripts, fonts or services are loaded.',
          'No data is sold or shared with third parties by the software. Everything stays on the operator’s own servers.',
          'No marketing emails. The software does not send email at all.',
          'Only two strictly necessary cookies (see the cookie policy).',
        ]}
      />

      <H2>6. How long data is kept</H2>
      <div className="mb-3 overflow-x-auto" tabIndex={0} role="region" aria-label="Retention periods">
        <table className="w-full min-w-[420px] text-left">
          <thead className="text-xs uppercase tracking-wide text-ink-dim">
            <tr>
              <th className="py-1.5 pr-3">Data</th>
              <th className="py-1.5">Kept for</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-t border-line">
              <td className="py-1.5 pr-3">Sign-in attempts</td>
              <td>{r.login_attempt_days} days, then deleted automatically</td>
            </tr>
            <tr className="border-t border-line">
              <td className="py-1.5 pr-3">Sessions</td>
              <td>
                Up to {hours(r.session_absolute_hours)} while active (ended after {r.session_idle_minutes} minutes idle), then
                deleted {r.session_retention_days} days after they end
              </td>
            </tr>
            <tr className="border-t border-line">
              <td className="py-1.5 pr-3">Imported logs and closed alerts</td>
              <td>
                {r.data_retention_days
                  ? `${r.data_retention_days} days, then purged automatically`
                  : `Until an administrator purges them (never less than ${r.data_retention_min_days} days)`}
                . Open alerts, incidents and notes are kept while needed for investigations.
              </td>
            </tr>
            <tr className="border-t border-line">
              <td className="py-1.5 pr-3">Account</td>
              <td>Until the account is erased</td>
            </tr>
            <tr className="border-t border-line">
              <td className="py-1.5 pr-3">Audit log</td>
              <td>Kept permanently as a tamper-resistant security record</td>
            </tr>
          </tbody>
        </table>
      </div>

      <H2>7. Security</H2>
      <P>
        Data is protected with hashed passwords, server-side sessions, CSRF protection, role-based access, rate-limited
        sign-in, a strict content security policy and an append-only audit log.
      </P>

      <H2>8. Your rights</H2>
      <P>
        Depending on where you live, you can ask to access, correct or delete your personal data, or object to its use. You
        can also complain to your data protection authority.
      </P>
      <List
        items={[
          <><strong>Deletion:</strong> signed-in users can choose <em>Request deletion of my data</em> on the <Link className="text-accent underline" to="/account">My account</Link> page. An administrator then erases the account: the username and email are replaced, the account is disabled, and its sessions and sign-in records are deleted.</>,
          <><strong>What is kept after deletion:</strong> past audit log entries, because they are a legally useful security record that cannot be edited, and alerts, notes and incidents, which then show the anonymised account.</>,
          <><strong>Other requests,</strong> including from people whose data appears in imported logs: contact the operator using the details above.</>,
        ]}
      />

      <H2>9. Children</H2>
      <P>
        SentinelTrace is a workplace tool for adults. It is not intended for anyone under 18, and accounts are only created
        by administrators for authorised staff. It does not knowingly collect data from children.
      </P>

      <H2>10. Changes</H2>
      <P>If this policy changes, the effective date below changes too.</P>
    </>
  )
}

function Terms({ facts }: { facts: LegalFacts }) {
  return (
    <>
      <P>
        These terms apply to this SentinelTrace instance, run by {operatorName(facts)} (the &ldquo;operator&rdquo;). By
        signing in you agree to them.
      </P>
      <Contact facts={facts} />

      <H2>1. Who may use it</H2>
      <List
        items={[
          'Staff and contractors authorised by the operator, aged 18 or over.',
          'Accounts are created by an administrator. Keep your password secret and do not share your account.',
        ]}
      />

      <H2>2. Acceptable use</H2>
      <List
        items={[
          'Import only logs you are authorised to process, for security purposes.',
          'Do not try to bypass access controls, attack the service, or upload files that are not log files.',
          'Treat the data you see as confidential and follow the law and the operator’s policies.',
        ]}
      />

      <H2>3. Alerts are indicators, not proof</H2>
      <P>
        Detection rules flag patterns that may indicate an attack. An alert does not prove that an attack happened or
        succeeded, and no tool detects every attack. Decisions remain with the people investigating.
      </P>

      <H2>4. Fees and refunds</H2>
      <P>
        SentinelTrace is free software. It has no prices, subscriptions, in-app purchases or paid features, so there are no
        fees and nothing to refund. If the operator charges for a service built on it, the operator&rsquo;s own agreement
        and refund policy apply.
      </P>

      <H2>5. The software</H2>
      <P>
        The software is provided &ldquo;as is&rdquo;, without warranties of any kind, to the extent the law allows. It
        includes open-source components under their own licences, listed in the project&rsquo;s THIRD_PARTY_NOTICES file.
      </P>

      <H2>6. Suspension</H2>
      <P>Administrators may disable an account that breaks these terms or is no longer needed.</P>

      <H2>7. Privacy</H2>
      <P>
        How personal data is handled is described in the <Link className="text-accent underline" to="/legal/privacy">privacy policy</Link>.
      </P>

      <H2>8. Changes</H2>
      <P>If these terms change, the effective date below changes too.</P>
    </>
  )
}

function Cookies({ facts }: { facts: LegalFacts }) {
  return (
    <>
      <P>
        SentinelTrace uses only the two cookies below. Both are <strong>strictly necessary</strong>: without them you cannot
        sign in safely. Cookies like these do not need consent, so there is nothing to accept or reject.
      </P>
      <div className="mb-3 overflow-x-auto" tabIndex={0} role="region" aria-label="Cookies used">
        <table className="w-full min-w-[560px] text-left">
          <thead className="text-xs uppercase tracking-wide text-ink-dim">
            <tr>
              <th className="py-1.5 pr-3">Name</th>
              <th className="py-1.5 pr-3">Purpose</th>
              <th className="py-1.5 pr-3">Expires after</th>
              <th className="py-1.5">Details</th>
            </tr>
          </thead>
          <tbody>
            {facts.cookies.map((c) => (
              <tr key={c.name} className="border-t border-line align-top">
                <td className="py-1.5 pr-3 font-mono">{c.name}</td>
                <td className="py-1.5 pr-3">{c.purpose}</td>
                <td className="py-1.5 pr-3">{hours(c.duration_hours)}, or when you sign out</td>
                <td className="py-1.5">
                  First-party, SameSite={c.same_site}
                  {c.http_only ? ', not readable by scripts' : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <H2>What is not used</H2>
      <List
        items={[
          'No analytics, advertising, social media or other third-party cookies.',
          'No tracking pixels, fingerprinting, or tracking data in browser storage.',
        ]}
      />

      <H2>Controlling cookies</H2>
      <P>
        You can delete or block cookies in your browser settings. If you block these two, signing in will not work. Signing
        out deletes them.
      </P>

      <H2>Contact</H2>
      <Contact facts={facts} />
    </>
  )
}

export function LegalPage() {
  const { slug } = useParams<{ slug: string }>()
  const { state } = useAuth()
  const [facts, setFacts] = useState<LegalFacts | null>(null)
  const [error, setError] = useState<string | null>(null)
  const doc = LEGAL_DOCS.find((d) => d.slug === slug)

  useEffect(() => {
    api.legal().then(setFacts, (err) => setError(err instanceof ApiError ? err.message : 'Could not load this page.'))
  }, [])

  useEffect(() => {
    if (doc) document.title = `${doc.title} · SentinelTrace`
    return () => {
      document.title = 'SentinelTrace'
    }
  }, [doc])

  const back = state.status === 'authenticated' ? { to: '/', label: 'Back to SentinelTrace' } : { to: '/login', label: 'Back to sign in' }

  return (
    <div className="min-h-full">
      <header className="border-b border-line bg-panel">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <Link to={back.to} className="flex items-center gap-2 font-semibold tracking-tight">
            <span aria-hidden className="h-2 w-2 rounded-full bg-accent" />
            SentinelTrace
          </Link>
          <nav aria-label="Legal documents" className="flex gap-1 text-sm">
            {LEGAL_DOCS.map((d) => (
              <NavLink
                key={d.slug}
                to={`/legal/${d.slug}`}
                className={({ isActive }) => `rounded-md px-2 py-1 ${isActive ? 'bg-panel-2 text-ink' : 'text-ink-dim hover:text-ink'}`}
              >
                {d.title}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-3xl px-4 py-8 text-sm leading-relaxed text-ink-dim">
        {!doc ? (
          <>
            <h1 className="mb-2 text-xl font-semibold text-ink">Page not found</h1>
            <Link className="text-accent underline" to="/legal/privacy">
              Privacy policy
            </Link>
          </>
        ) : (
          <article>
            <h1 className="mb-1 text-xl font-semibold text-ink">{doc.title}</h1>
            {facts && <p className="mb-6 text-xs">Effective {facts.effective_date}</p>}
            {error && <ErrorBanner message={error} />}
            {!facts && !error && <Loading />}
            {facts && (doc.slug as Slug) === 'privacy' && <Privacy facts={facts} />}
            {facts && (doc.slug as Slug) === 'terms' && <Terms facts={facts} />}
            {facts && (doc.slug as Slug) === 'cookies' && <Cookies facts={facts} />}
          </article>
        )}
        <p className="mt-10">
          <Link className="text-accent underline" to={back.to}>
            {back.label}
          </Link>
        </p>
      </main>
    </div>
  )
}

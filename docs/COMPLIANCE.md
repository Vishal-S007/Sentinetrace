# Compliance checklist

A review of SentinelTrace against 20 common website and app compliance checks.

**Context:** SentinelTrace is free, self-hosted software for authorised security staff. It has no payments, no marketing, no reviews, no public sign-up and sends no email. Some checks therefore do not apply. Each one is still recorded below, with the reason.

**Status key:**
- **Done:** implemented and tested.
- **N/A:** does not apply, with the reason, and with a safeguard where one is useful.
- **Operator:** the person running an instance must do something.

> The legal texts are a sound starting point, not legal advice. An operator should have them reviewed for their jurisdiction and fill in their own details before real users sign in.

| # | Check | Status | What was done / why | Evidence |
|---|---|---|---|---|
| 1 | Privacy policy | Done + Operator | `/legal/privacy`: controller, data held about users and in imported logs, purposes and legal basis, what is never done, retention periods (filled in from live settings), security, rights, children, changes. The operator sets their name, contact and address. | `frontend/src/pages/LegalPage.tsx`, `GET /api/legal`, `LegalPage.test.tsx` |
| 2 | Terms of service | Done + Operator | `/legal/terms`: who may use it, acceptable use, alerts are indicators only, fees and refunds, as-is software, suspension, changes. Linked from the sign-in form. | `LegalPage.tsx`, `LoginPage.tsx` |
| 3 | Refund policy | N/A (covered) | Nothing is sold, so nothing can be refunded. Terms §4 says so plainly, and says that an operator who charges must apply their own refund policy. | Terms §4 |
| 4 | Cookie policy | Done | `/legal/cookies` lists both cookies with purpose, lifetime and flags. The list comes from the server, and a test checks that it matches the cookies actually set at sign-in. | `test_legal_cookie_list_matches_cookies_actually_set` |
| 5 | Cookie consent banner | Done (notice) | Both cookies are strictly necessary (session and CSRF), so consent is not required, and an "Accept / Reject" banner would offer a fake choice. Instead, the sign-in page shows a plain notice saying which cookies are used and why, linking to the cookie policy. There are no analytics, advertising or third-party cookies, and nothing in browser storage. If a non-essential cookie is ever added, a real opt-in banner must come with it. | `LoginPage.tsx`; no `localStorage`/`sessionStorage` use in the code |
| 6 | Check form consents | Done | No form asks for consent to anything optional, and no checkbox is pre-ticked (all checkboxes are filters or settings). The sign-in form states that signing in accepts the terms and links both policies. Deletion requests and erasure need an explicit confirmation step. | `LoginPage.tsx`, `AccountPage.tsx`, `UsersPage.tsx` |
| 7 | No unnecessary data | Done | Email is optional. User agents are truncated to 512 characters. Passwords are stored only as Argon2id hashes. **New:** the worker deletes login attempts after 30 days and ended sessions after 7 days (both configurable, and never inside the login rate-limit window). Imported log data is covered by the existing retention purge. The deletion-request audit entry deliberately stores no free text. | `app/services/privacy.py`, `test_prune_*` |
| 8 | Audit third-party SDKs | Done | No analytics, advertising, crash-reporting or tracking SDKs. The browser loads nothing from other origins, which the strict CSP (`default-src 'self'`) enforces and an E2E test checks. All 115 runtime dependencies and their licences are listed. Dependency vulnerability audits run in CI. | `THIRD_PARTY_NOTICES.md`, `e2e/security.spec.ts`, CI `security` job |
| 9 | Remove dark patterns | Done | Reviewed every flow: no pre-ticked boxes, no confirm-shaming, no hidden cancel, no forced continuity. Requesting deletion is as easy as any other action (two clicks), and its consequences are stated first. Destructive admin actions (purge, erase) state their effects and need typed confirmation. The cookie notice is informative, not a nag. | `AccountPage.tsx`, `UsersPage.tsx`, `RetentionPage.tsx` |
| 10 | Remove hidden fees | N/A | The software has no prices, fees or paid features. Terms §4 states this. | Terms §4 |
| 11 | Remove fake reviews | N/A (checked) | There are no reviews, ratings, testimonials or endorsements anywhere in the app, README or docs. | `README.md`, `docs/` |
| 12 | Remove unsupported claims | Done | Every figure in the README is backed by a test or report (test counts, coverage, ground-truth results), and detection results are stated as synthetic-data results only. "Live dashboard" was changed to "a dashboard computed from the stored events and alerts", because there is no live log streaming. Alerts are worded as indicators, never as proof. | `README.md`, `docs/reports/phase-8.md` |
| 13 | Accessibility: alt text | Done | Images in the README have descriptive alt text. Charts carry `role="img"` with a label and a "View as table" alternative. Decorative dots are `aria-hidden`. The axe-core scan reports no missing text alternatives on any screen. | `DashboardPage.tsx`, `e2e/accessibility.spec.ts` |
| 14 | Fix colour contrast | Done | All text colour pairs meet WCAG 2.1 AA (4.5:1 for body text). The axe-core contrast check passes on every screen and on the public pages. | `e2e/accessibility.spec.ts` |
| 15 | Keyboard navigation | Done | **New:** a "Skip to main content" link; a visible focus ring on every interactive element; scrollable tables are focusable and labelled so they can be scrolled with the keyboard; chart drill-downs are also offered as links in "View as table". A keyboard-only E2E test signs in, uses the skip link and navigates the sidebar. | `App.tsx`, `index.css`, `e2e/accessibility.spec.ts` |
| 16 | Add business details | Done + Operator | Operator name, contact and address are settings (`ST_OPERATOR_NAME`, `ST_OPERATOR_CONTACT`, `ST_OPERATOR_ADDRESS`), shown on all three legal pages. Until they are set, the pages show a visible warning saying the details are missing. | `.env.example`, `docker-compose.yml`, `LegalPage.tsx` |
| 17 | Age consent for kids' data | N/A (covered) | Accounts are created only by administrators, for staff, and the terms require users to be 18 or over. The privacy policy says the tool is not intended for children and does not knowingly collect their data. No age or birth date is collected. | Privacy §9, Terms §1 |
| 18 | Unsubscribe link in emails | N/A | The software sends no email of any kind (no SMTP or mail code). If email is ever added, any non-essential message needs an unsubscribe link. | Code search: no mail sending |
| 19 | License fonts/images | Done | No font files are bundled or fetched (system fonts only). **New:** the default Vite logo favicon was replaced with original artwork. Screenshots show this app with synthetic data. Third-party code licences are listed, with notes on LGPL-3.0 (psycopg) and MPL-2.0 (certifi), both used unmodified. | `frontend/public/favicon.svg`, `THIRD_PARTY_NOTICES.md` |
| 20 | Data deletion request | Done | **New:** any user can choose "Request deletion of my data" on My account; the request is recorded in the audit log and shown to admins on Users & roles. An admin then chooses "Erase data" and retypes the username to confirm. The account is anonymised (`erased-user-<id>`), its email is removed, it is disabled and cannot be revived, and its sessions and login attempts are deleted. Alerts, notes and incidents keep pointing at the anonymised account. The append-only audit log is kept as a security record, which the privacy policy explains. People whose data appears in imported logs are directed to the operator's contact. | `POST /api/auth/deletion-request`, `POST /api/users/{id}/erase`, `test_privacy.py`, `AccountPage.test.tsx`, `UsersPage.test.tsx` |

## Before real users sign in (operator checklist)

1. Set `ST_OPERATOR_NAME`, `ST_OPERATOR_CONTACT` and `ST_OPERATOR_ADDRESS`, and `ST_LEGAL_EFFECTIVE_DATE` when the texts change.
2. Have the privacy policy and terms reviewed for your jurisdiction, and adjust `frontend/src/pages/LegalPage.tsx` if needed.
3. Choose a retention period for imported logs (`ST_RETENTION_AUTO_DAYS`) that matches your policy.
4. Import only logs you are entitled to process, and decide how you will handle requests from people whose data appears in them.
5. Serve the app over HTTPS (see `docs/deployment.md`).

## Known limits

- Erasure covers user accounts. Data about third parties inside imported logs is removed by the retention purge, not per person.
- Past audit log entries keep the username the person had at the time. They cannot be edited, by design.
- Automated accessibility tools find only part of all issues. The keyboard test and manual review cover more, but a screen-reader review by a specialist has not been done.

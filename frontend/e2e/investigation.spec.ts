import { expect, test, type Page } from '@playwright/test'

// Needs the backend API and the worker (ingestion + detection) on the same database.
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'admin'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? ''

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function apacheTime(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`
}

/** A unique IP per run, so the alert this run creates is always a new one. */
function runIp(n: number): string {
  return `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${(n & 254) + 1}`
}

function attackLog(ip: string, runId: string, start: Date): string {
  const lines: string[] = []
  const at = (s: number) => apacheTime(new Date(start.getTime() + s * 1000))
  for (let i = 0; i < 5; i++) {
    lines.push(`198.51.100.20 - - [${at(i)}] "GET /shop/${runId}/item/${i} HTTP/1.1" 200 900 "-" "Mozilla/5.0"`)
  }
  lines.push(
    `${ip} - - [${at(10)}] "GET /products/${runId}?id=1%20union%20select%20username,password%20from%20users HTTP/1.1" 500 312 "-" "sqlmap/1.7.2"`,
    `${ip} - - [${at(12)}] "GET /products/${runId}?id=1'%20or%20'1'='1 HTTP/1.1" 200 4100 "-" "sqlmap/1.7.2"`,
  )
  return lines.join('\n') + '\n'
}

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(ADMIN_USER)
  await page.getByLabel('Password').fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible()
}

test.beforeAll(() => {
  if (!ADMIN_PASSWORD) throw new Error('Set E2E_ADMIN_PASSWORD (and E2E_ADMIN_USER) for the E2E run')
})

test('investigate an alert: import, overview, queue, evidence, triage, event explorer', async ({ page }) => {
  const now = Date.now()
  const runId = now.toString(36)
  const ip = runIp(Math.floor(now / 1000))
  const sourceName = `e2e-inv-${runId}`
  await signIn(page)

  // Import a small web log containing SQL injection attempts from one IP.
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Log sources' }).click()
  const create = page.getByRole('form', { name: 'Add log source' })
  await create.getByLabel('Name').fill(sourceName)
  await create.getByLabel('Format').selectOption('apache_combined')
  await create.getByRole('button', { name: 'Create source' }).click()
  const upload = page.getByRole('form', { name: `Upload to ${sourceName}` })
  await upload.getByLabel(`Log file for ${sourceName}`).setInputFiles({
    name: `inv-${runId}.log`,
    mimeType: 'text/plain',
    buffer: Buffer.from(attackLog(ip, runId, new Date(now - 10 * 60_000))),
  })
  await upload.getByRole('button', { name: 'Upload' }).click()
  await upload.getByRole('link', { name: /job #\d+/ }).click()
  await expect(page.getByText('Completed', { exact: true })).toBeVisible({ timeout: 30_000 })

  // Detection runs after the import; wait until the alert for this IP is in the queue.
  await expect(async () => {
    await page.goto(`/alerts?source_ip=${ip}`)
    await expect(page.getByRole('link', { name: `SQL injection indicators from ${ip}` })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 45_000 })

  // The overview counts it and links to it.
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Overview' }).click()
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible()
  const ips = page.getByRole('region', { name: 'Top source IPs by alerts' })
  await expect(ips.getByRole('link', { name: ip })).toBeVisible()
  await ips.getByRole('link', { name: ip }).click()
  await expect(page).toHaveURL(new RegExp(`/alerts\\?source_ip=${ip.replaceAll('.', '\\.')}$`))

  // Open the alert: explanation, confidence reason and raw evidence lines.
  await page.getByRole('link', { name: `SQL injection indicators from ${ip}` }).click()
  await expect(page.getByRole('heading', { name: `SQL injection indicators from ${ip}` })).toBeVisible()
  await expect(page.getByRole('region', { name: 'What was observed' })).toContainText('does not show the attack succeeded')
  const evidence = page.getByRole('region', { name: 'Evidence' })
  await expect(evidence.getByText(/union%20select%20username/)).toBeVisible()
  await expect(evidence.getByText('union_select')).toBeVisible()

  // Triage: move it to investigating with a note; the badge updates.
  const triage = page.getByRole('region', { name: 'Triage' })
  await triage.getByLabel(/Note for the audit trail/).fill(`e2e ${runId}`)
  await triage.getByRole('button', { name: 'Mark investigating' }).click()
  await expect(triage.getByText('Status changed to Investigating.')).toBeVisible()
  await expect(triage.getByRole('button', { name: 'Mark investigating' })).toHaveCount(0)

  // The status change is audited with the note.
  const audit = await page.evaluate(async () => (await fetch('/api/audit?action=alert.status_change')).json())
  expect(JSON.stringify(audit)).toContain(`e2e ${runId}`)

  // Pivot to the event explorer for this IP: both attack requests, none of the benign ones.
  await page.getByRole('region', { name: 'Facts' }).getByRole('link', { name: ip }).click()
  await expect(page.getByRole('heading', { name: 'Event explorer' })).toBeVisible()
  await expect(page.getByText(/^2 matching events/)).toBeVisible()
  await page.getByRole('button', { name: /^Open event \d+$/ }).first().click()
  const panel = page.getByRole('complementary', { name: /^Event \d+$/ })
  await expect(panel.getByText(`inv-${runId}.log`, { exact: false })).toBeVisible()
  await expect(panel.getByRole('link', { name: new RegExp(`SQL injection indicators from ${ip.replaceAll('.', '\\.')}`) })).toBeVisible()
})

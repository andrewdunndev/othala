/**
 * audit-capture.mjs — visual + a11y audit capture for the Othala portal.
 *
 * Runs INSIDE the e2e-tester container on the compose network so
 * auth.othala.test resolves (Caddy alias). Reuses the e2e auth approach:
 * seed identities via the Kratos admin API, login via the JSON-API flow,
 * carry the session cookie in a fresh BrowserContext.
 *
 * For each target page:
 *   - screenshot at 1280px (desktop) and 390px (mobile), full-page
 *   - inject axe-core (the `axe-core` npm dependency, baked into the
 *     e2e-tester image's node_modules) and collect violations
 *
 * Output: /out/audit/*.png + /out/audit/axe-results.json
 */

import { chromium } from 'playwright';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const BASE = process.env.BASE ?? 'http://auth.othala.test';
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
const OUT = '/out/audit';
const AXE_SRC = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const TEST_PASSWORD = 'othala-testpass-2026';

// ─── identity seed (mirror e2e/playwright/actions/identity.ts) ───────────────
async function seed({ email, username, displayName, groups }) {
  const body = {
    schema_id: 'family',
    state: 'active',
    traits: { username, email, displayName },
    metadata_admin: { groups },
    credentials: { password: { config: { password: TEST_PASSWORD } } },
  };
  const resp = await fetch(`${KRATOS_ADMIN_URL}/admin/identities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (resp.ok) { const d = await resp.json(); return { id: d.id, email }; }
  if (resp.status === 409) {
    const l = await fetch(`${KRATOS_ADMIN_URL}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`);
    if (l.ok) { const arr = await l.json(); if (arr.length) return { id: arr[0].id, email }; }
  }
  throw new Error(`seed ${email} failed: ${resp.status} ${await resp.text().catch(() => '')}`);
}

// ─── login via JSON API (mirror actions/login.ts) ────────────────────────────
function findCsrf(nodes) {
  for (const n of nodes ?? []) {
    if (n?.type === 'input' && n?.attributes?.name === 'csrf_token' && n?.attributes?.type === 'hidden')
      return n.attributes.value ?? '';
  }
  return '';
}
async function login(ctx, identifier, password) {
  const flowResp = await ctx.request.get(`${BASE}/self-service/login/browser`, {
    headers: { Accept: 'application/json' }, maxRedirects: 5,
  });
  if (!flowResp.ok()) throw new Error(`login flow init: ${flowResp.status()}`);
  const flow = await flowResp.json();
  const action = flow?.ui?.action ?? '';
  const csrf = findCsrf(flow?.ui?.nodes ?? []);
  if (!action) throw new Error('login flow missing action');
  const sub = await ctx.request.post(action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { identifier, password, method: 'password', csrf_token: csrf },
    maxRedirects: 5,
  });
  if (!sub.ok()) throw new Error(`login submit: ${sub.status()} ${(await sub.text()).slice(0, 200)}`);
}

const VIEWPORTS = {
  desktop: { width: 1280, height: 900 },
  mobile: { width: 390, height: 844 },
};

const axeResults = {};
const captureLog = [];

async function capture(ctx, name, url, { waitClick } = {}) {
  for (const [vpName, vp] of Object.entries(VIEWPORTS)) {
    const page = await ctx.newPage();
    await page.setViewportSize(vp);
    const file = `${OUT}/${name}-${vpName}.png`;
    try {
      const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => null);
      // optional interaction (e.g. click email-code option) — desktop+mobile both
      if (waitClick) {
        await waitClick(page).catch((e) => captureLog.push(`[${name}/${vpName}] waitClick: ${e.message}`));
        await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
      }
      await page.screenshot({ path: file, fullPage: true });
      captureLog.push(`[ok] ${name}-${vpName} -> ${page.url()} (status ${resp?.status() ?? '?'})`);
      // run axe ONCE per page (desktop pass only — DOM is identical, layout differs)
      if (vpName === 'desktop') {
        try {
          await page.evaluate(AXE_SRC);
          const results = await page.evaluate(async () => await window.axe.run(document, {
            resultTypes: ['violations'],
          }));
          axeResults[name] = {
            url: page.url(),
            violations: results.violations.map((v) => ({
              id: v.id, impact: v.impact, help: v.help, helpUrl: v.helpUrl,
              nodes: v.nodes.map((n) => ({ target: n.target, html: n.html.slice(0, 200), failureSummary: n.failureSummary })),
            })),
          };
        } catch (e) {
          axeResults[name] = { url: page.url(), error: `axe failed: ${e.message}` };
          captureLog.push(`[axe-err] ${name}: ${e.message}`);
        }
      }
    } catch (e) {
      captureLog.push(`[FAIL] ${name}-${vpName}: ${e.message}`);
    } finally {
      await page.close();
    }
  }
}

(async () => {
  const browser = await chromium.launch();

  // Seed identities.
  const member = await seed({ email: 'audit.member@othala.test', username: 'audit.member', displayName: 'Audit Member', groups: ['family', 'access-grafana'] });
  const admin = await seed({ email: 'admin@othala.test', username: 'admin', displayName: 'Othala Admin', groups: ['family', 'access-grafana', 'admin'] });
  captureLog.push(`seeded member=${member.id} admin=${admin.id}`);

  // ── UNAUTH ──────────────────────────────────────────────────────────────
  {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    await capture(ctx, 'index-unauth', `${BASE}/`);
    await capture(ctx, 'login-default', `${BASE}/auth/login`);
    // email-code step: on the default login page, the email input + "Send
    // sign-in code" already render in the code block (TIER 2). To reach the
    // CODE ENTRY state we'd need to submit; capture the identifier state as
    // "email-code" and additionally try submitting to reach code entry.
    await capture(ctx, 'login-emailcode', `${BASE}/auth/login`, {
      waitClick: async (page) => {
        // Fill the email + click "Send sign-in code" to advance to code entry.
        const email = page.locator('#code-identifier');
        if (await email.count()) {
          await email.fill('audit.member@othala.test');
          await page.locator('.code-submit').first().click();
        }
      },
    });
    // password/legacy state: expand the <details> disclosure.
    await capture(ctx, 'login-password', `${BASE}/auth/login`, {
      waitClick: async (page) => {
        const sum = page.locator('.password-summary');
        if (await sum.count()) await sum.click();
      },
    });
    await capture(ctx, 'recovery', `${BASE}/auth/recovery`);
    await capture(ctx, 'error-not-admin', `${BASE}/auth/error?reason=not-admin`);
    await capture(ctx, 'notfound-404', `${BASE}/this-page-does-not-exist-xyz`);
    await ctx.close();
  }

  // ── MEMBER ──────────────────────────────────────────────────────────────
  {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    await login(ctx, member.email, TEST_PASSWORD);
    await capture(ctx, 'member-index', `${BASE}/`);
    await capture(ctx, 'member-settings', `${BASE}/auth/settings`);
    await ctx.close();
  }

  // ── ADMIN ───────────────────────────────────────────────────────────────
  // NOTE: admin@othala.test triggers AAL2 step-up at /admin (password is AAL1).
  // The JSON-API login only establishes AAL1, so /admin will redirect to a
  // step-up login. We capture what we land on and report honestly.
  {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    await login(ctx, admin.email, TEST_PASSWORD);
    await capture(ctx, 'admin-index', `${BASE}/admin`);
    await capture(ctx, 'admin-users', `${BASE}/admin/users`);
    await capture(ctx, 'admin-user-detail', `${BASE}/admin/users/${member.id}`);
    await capture(ctx, 'admin-user-detail-edit', `${BASE}/admin/users/${member.id}?mode=edit`);
    await capture(ctx, 'admin-groups', `${BASE}/admin/groups`);
    await capture(ctx, 'admin-oauth2', `${BASE}/admin/oauth2`);
    await ctx.close();
  }

  await browser.close();
  writeFileSync(`${OUT}/axe-results.json`, JSON.stringify(axeResults, null, 2));
  writeFileSync(`${OUT}/capture-log.txt`, captureLog.join('\n') + '\n');
  console.log(captureLog.join('\n'));
  console.log('\n=== axe summary ===');
  for (const [name, r] of Object.entries(axeResults)) {
    if (r.error) { console.log(`${name}: ${r.error}`); continue; }
    const byImpact = {};
    for (const v of r.violations) byImpact[v.impact] = (byImpact[v.impact] ?? 0) + 1;
    console.log(`${name}: ${r.violations.length} violations ${JSON.stringify(byImpact)}`);
  }
})().catch((e) => { console.error('CAPTURE FATAL:', e); process.exit(1); });

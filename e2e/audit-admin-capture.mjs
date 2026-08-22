/**
 * audit-admin-capture.mjs — reach AAL2 and capture the admin surfaces.
 *
 * The admin gate (requireAdminSession) step-ups AAL1 admins to an AAL2 login.
 * A plain password login is AAL1, so the prior pass only captured the step-up
 * login screen. This script:
 *   1. seeds admin@othala.test (carrying the metadata_admin.admin marker),
 *   2. logs in (AAL1) and enrolls a TOTP credential via the settings flow,
 *   3. performs an aal=aal2 login submitting the computed TOTP code → AAL2,
 *   4. screenshots /admin/* at desktop+mobile + runs axe.
 *
 * TOTP (RFC 6238) is implemented with node crypto (SHA1/6-digit/30s — Kratos
 * pquerna/otp defaults). No external dependency.
 */

import { chromium } from 'playwright';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const BASE = process.env.BASE ?? 'http://auth.othala.test';
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
const OUT = '/out/audit';
const AXE_SRC = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const TEST_PASSWORD = 'othala-testpass-2026';

// ─── base32 decode (RFC 4648, no padding) ────────────────────────────────────
function base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.replace(/=+$/, '').toUpperCase().replace(/\s+/g, '');
  let bits = 0, value = 0; const out = [];
  for (const c of s) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secretB32, t = Date.now()) {
  const key = base32Decode(secretB32);
  let counter = Math.floor(t / 1000 / 30);
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  const hmac = createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

async function seed({ email, username, displayName, groups, admin = false }) {
  // Admin authority is the strict metadata_admin.admin === true marker
  // (portal isAdminMarker) — group membership alone confers nothing.
  const body = { schema_id: 'family', state: 'active', traits: { username, email, displayName },
    metadata_admin: admin ? { groups, admin: true } : { groups },
    credentials: { password: { config: { password: TEST_PASSWORD } } } };
  const resp = await fetch(`${KRATOS_ADMIN_URL}/admin/identities`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (resp.ok) { const d = await resp.json(); return { id: d.id, email }; }
  // 409 (documented) OR 500 (Kratos v26 returns 500 on duplicate identifier) —
  // fall back to lookup either way.
  if (resp.status === 409 || resp.status === 500) {
    const l = await fetch(`${KRATOS_ADMIN_URL}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`);
    if (l.ok) { const arr = await l.json(); if (arr.length) return { id: arr[0].id, email }; }
  }
  throw new Error(`seed ${email} failed: ${resp.status}`);
}

function findCsrf(nodes) {
  for (const n of nodes ?? [])
    if (n?.attributes?.name === 'csrf_token' && n?.attributes?.type === 'hidden') return n.attributes.value ?? '';
  return '';
}
function nodeByName(nodes, name) {
  for (const n of nodes ?? []) if (n?.attributes?.name === name) return n;
  return null;
}

async function passwordLogin(ctx, identifier, aal) {
  const url = `${BASE}/self-service/login/browser` + (aal ? `?aal=${aal}` : '');
  const fr = await ctx.request.get(url, { headers: { Accept: 'application/json' }, maxRedirects: 5 });
  const flow = await fr.json();
  return flow;
}

const captureLog = [];
const axeResults = {};
const VIEWPORTS = { desktop: { width: 1280, height: 900 }, mobile: { width: 390, height: 844 } };

async function capture(ctx, name, url) {
  for (const [vpName, vp] of Object.entries(VIEWPORTS)) {
    const page = await ctx.newPage();
    await page.setViewportSize(vp);
    try {
      const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => null);
      await page.screenshot({ path: `${OUT}/${name}-${vpName}.png`, fullPage: true });
      captureLog.push(`[ok] ${name}-${vpName} -> ${page.url()} (status ${resp?.status() ?? '?'})`);
      if (vpName === 'desktop') {
        try {
          await page.evaluate(AXE_SRC);
          const results = await page.evaluate(async () => await window.axe.run(document, { resultTypes: ['violations'] }));
          axeResults[name] = { url: page.url(), violations: results.violations.map((v) => ({
            id: v.id, impact: v.impact, help: v.help, helpUrl: v.helpUrl,
            nodes: v.nodes.map((n) => ({ target: n.target, html: n.html.slice(0, 200), failureSummary: n.failureSummary })) })) };
        } catch (e) { axeResults[name] = { url: page.url(), error: e.message }; }
      }
    } catch (e) { captureLog.push(`[FAIL] ${name}-${vpName}: ${e.message}`); }
    finally { await page.close(); }
  }
}

(async () => {
  const browser = await chromium.launch();
  const admin = await seed({ email: 'admin@othala.test', username: 'admin', displayName: 'Othala Admin', groups: ['family', 'access-grafana', 'admin'], admin: true });
  const member = await seed({ email: 'audit.member@othala.test', username: 'audit.member', displayName: 'Audit Member', groups: ['family', 'access-grafana'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });

  // 1) AAL1 password login.
  {
    const flow = await passwordLogin(ctx);
    const csrf = findCsrf(flow.ui.nodes);
    const sub = await ctx.request.post(flow.ui.action, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      data: { identifier: admin.email, password: TEST_PASSWORD, method: 'password', csrf_token: csrf }, maxRedirects: 5 });
    captureLog.push(`[admin] AAL1 login status=${sub.status()}`);
  }

  // 2) Enroll TOTP via settings flow.
  let totpSecret = null;
  {
    let fr = await ctx.request.get(`${BASE}/self-service/settings/browser`, { headers: { Accept: 'application/json' }, maxRedirects: 5 });
    let flow = await fr.json();
    let csrf = findCsrf(flow.ui.nodes);

    // If a TOTP credential is already enrolled (leftover from a prior run),
    // the secret node is absent and only totp_unlink shows. Unlink first so a
    // fresh secret is issued that we can read + compute codes against.
    if (nodeByName(flow.ui.nodes, 'totp_unlink')) {
      const un = await ctx.request.post(flow.ui.action, {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        data: { method: 'totp', totp_unlink: 'true', csrf_token: csrf }, maxRedirects: 5 });
      captureLog.push(`[admin] TOTP unlink status=${un.status()}`);
      fr = await ctx.request.get(`${BASE}/self-service/settings/browser`, { headers: { Accept: 'application/json' }, maxRedirects: 5 });
      flow = await fr.json();
      csrf = findCsrf(flow.ui.nodes);
    }
    // The totp secret is in a text node (attributes.text.text) or in
    // attributes with id totp_secret_key. Search nodes for the base32 secret.
    for (const n of flow.ui.nodes) {
      const a = n.attributes ?? {};
      if (a.id === 'totp_secret_key' && a.text?.text) { totpSecret = a.text.text; break; }
      if (a.node_type === 'text' && a.text?.context?.secret) { totpSecret = a.text.context.secret; break; }
      if (a.node_type === 'text' && /^[A-Z2-7]{16,}$/.test(String(a.text?.text ?? '').replace(/\s/g, ''))) {
        totpSecret = String(a.text.text).replace(/\s/g, ''); break;
      }
    }
    captureLog.push(`[admin] totp secret found=${!!totpSecret}${totpSecret ? ' (' + totpSecret.length + ' chars)' : ''}`);
    if (totpSecret) {
      const code = totp(totpSecret);
      const sub = await ctx.request.post(flow.ui.action, {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        data: { method: 'totp', totp_code: code, csrf_token: csrf }, maxRedirects: 5 });
      captureLog.push(`[admin] TOTP enroll status=${sub.status()} body=${(await sub.text()).slice(0, 120)}`);
    }
  }

  // Check current AAL — enrolling TOTP in a privileged session may already
  // elevate it; if so we skip the explicit step-up.
  {
    const who = await ctx.request.get(`${BASE}/sessions/whoami`, { headers: { Accept: 'application/json' } });
    const wb = await who.json().catch(() => ({}));
    captureLog.push(`[admin] post-enroll whoami aal=${wb.authenticator_assurance_level}`);
  }

  // 3) AAL2 step-up login with the TOTP code.
  if (totpSecret) {
    const flow = await passwordLogin(ctx, 'aal2');
    if (!flow?.ui) {
      captureLog.push(`[admin] aal2 flow init returned no ui: ${JSON.stringify(flow).slice(0, 200)}`);
    } else {
      const csrf = findCsrf(flow.ui.nodes);
      // The aal2 login flow may carry a fresh totp window; recompute.
      const code = totp(totpSecret);
      const sub = await ctx.request.post(flow.ui.action, {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        data: { method: 'totp', totp_code: code, csrf_token: csrf }, maxRedirects: 5 });
      captureLog.push(`[admin] AAL2 login status=${sub.status()} body=${(await sub.text()).slice(0, 120)}`);
    }
    const who = await ctx.request.get(`${BASE}/sessions/whoami`, { headers: { Accept: 'application/json' } });
    const wb = await who.json().catch(() => ({}));
    captureLog.push(`[admin] final whoami aal=${wb.authenticator_assurance_level}`);
  }

  // 4) Capture admin surfaces.
  await capture(ctx, 'admin-index', `${BASE}/admin`);
  await capture(ctx, 'admin-users', `${BASE}/admin/users`);
  await capture(ctx, 'admin-user-new', `${BASE}/admin/users/new`);
  await capture(ctx, 'admin-user-detail', `${BASE}/admin/users/${member.id}`);
  await capture(ctx, 'admin-user-detail-edit', `${BASE}/admin/users/${member.id}?mode=edit`);
  await capture(ctx, 'admin-groups', `${BASE}/admin/groups`);
  await capture(ctx, 'admin-oauth2', `${BASE}/admin/oauth2`);
  await capture(ctx, 'admin-activity', `${BASE}/admin/activity`);

  await ctx.close();
  await browser.close();
  writeFileSync(`${OUT}/axe-results-admin.json`, JSON.stringify(axeResults, null, 2));
  writeFileSync(`${OUT}/capture-log-admin.txt`, captureLog.join('\n') + '\n');
  console.log(captureLog.join('\n'));
  console.log('\n=== admin axe summary ===');
  for (const [name, r] of Object.entries(axeResults)) {
    if (r.error) { console.log(`${name}: ${r.error}`); continue; }
    const byImpact = {};
    for (const v of r.violations) byImpact[v.impact] = (byImpact[v.impact] ?? 0) + 1;
    console.log(`${name}: ${r.violations.length} violations ${JSON.stringify(byImpact)}`);
  }
})().catch((e) => { console.error('ADMIN CAPTURE FATAL:', e); process.exit(1); });

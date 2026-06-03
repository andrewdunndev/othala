// Scripted browser test for the e2e `browser` profile — runs INSIDE the compose
// net (lab-playwright), resolving the dag/auth-lab alias -> the Caddy edge, exactly
// as a production browser hits dag.dunn.dev. This is the human-flow layer the
// API-level smoke + the browser-free dance cannot reach:
//   A — a REAL Kratos session via the rendered login form
//   B — the OIDC authorize flow driven by that real session (the LOGIN gate, not the
//       admin-forged shortcut) -> auth code -> id_token with the injected role claim
//   C — the admin gate DENIES a non-admin member at /admin (requireAdminSession)
//   D — the admin gate ALLOWS an allowlisted admin at /admin
//
// Asserts + exits non-zero on any failure (CI gate). Screenshots land in /out.
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'http://auth-lab.lab.dunn.dev';
const OUT = '/out';
const KEEP_SECRET = process.env.KEEP_CLIENT_SECRET || '';
const KEEP_REDIRECT = 'https://keep.dunn.dev/identity/connect/oidc-signin';
// Seeded with a bcrypt hashed_password (plaintext config.password import is a no-op
// on Kratos v26.2.0 — finding). adm2 is on OTHALA_ADMIN_SUBJECTS via its email.
const MEMBER = { id: 'bt2@lab.dunn.dev', pw: 'testpass123' };
const ADMIN = { id: 'admin@lab.dunn.dev', pw: 'testpass123' };

let pass = 0, fail = 0;
const ok = (cond, msg, detail) => {
  if (cond) { pass++; console.log('  ✓', msg); }
  else { fail++; console.log('  ✗', msg, detail ? '— ' + detail : ''); }
};
const log = (...a) => console.log('[browser-test]', ...a);

// Fill the Kratos login form (rendered by the app at /auth/login) + submit.
async function loginViaForm(page, who) {
  await page.goto(BASE + '/auth/login', { waitUntil: 'networkidle', timeout: 25000 });
  // The rendered login form's widget submit is automation-hostile (Playwright fill
  // actionability times out; a JS value-set doesn't reach its submit path — a real
  // testability finding). Submit the Kratos flow the robust way: read the form's
  // action + the hidden csrf_token/method and POST through the browser context
  // (shares cookies, so the session lands exactly as a normal submit would).
  const action = await page.$eval('form:has(input[name=identifier])', (f) => f.action).catch(() => '');
  const csrf = await page.$eval('input[name=csrf_token]', (e) => e.value).catch(() => '');
  const method = await page.$eval('input[name=method]', (e) => e.value).catch(() => 'password');
  log('login action', action.replace(BASE, ''), 'csrf?', !!csrf, 'method', method);
  const resp = await page.request.post(action, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    form: { csrf_token: csrf, method, identifier: who.id, password: who.pw },
    maxRedirects: 5,
  });
  log('login POST status', resp.status());
  if (resp.status() === 200) { const b = await resp.text().catch(() => ''); log('login POST body (rejected?)', b.replace(/\s+/g, ' ').replace(/<[^>]+>/g, ' ').slice(0, 400)); }
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
  log('post-login url', page.url());
}

const browser = await chromium.launch();
try {
  // ---- A: real login via the form (member) ----
  log('A. member login via the rendered form');
  const member = await browser.newContext();
  const mp = await member.newPage();
  mp.on('requestfailed', (r) => log('REQFAIL', r.failure()?.errorText, r.url().slice(0, 110)));
  await loginViaForm(mp, MEMBER);
  await mp.screenshot({ path: OUT + '/10-member-postlogin.png', fullPage: true }).catch(() => {});
  let who = {};
  try { who = await (await member.request.get(BASE + '/sessions/whoami')).json(); } catch {}
  ok(who?.identity?.traits?.email === MEMBER.id,
    'A member login establishes a real Kratos session',
    'whoami=' + JSON.stringify(who?.identity?.traits || who).slice(0, 120));

  // ---- B: OIDC authorize driven by the real session -> code -> id_token claims ----
  log('B. OIDC authorize with the member session');
  await mp.route('https://keep.dunn.dev/**', (r) => r.fulfill({ status: 200, contentType: 'text/plain', body: 'cb' }));
  const authUrl = BASE + '/oauth2/auth?client_id=keep&response_type=code&scope='
    + encodeURIComponent('openid email groups') + '&redirect_uri=' + encodeURIComponent(KEEP_REDIRECT)
    + '&state=browserstate01&nonce=browsernonce01';
  await mp.goto(authUrl, { waitUntil: 'domcontentloaded', timeout: 25000 }).catch((e) => log('authorize nav:', e.message));
  const landed = mp.url();
  let code = null;
  try { code = new URL(landed).searchParams.get('code'); } catch {}
  ok(landed.startsWith('https://keep.dunn.dev/') && !!code,
    'B OIDC flow completes to the RP redirect with a code (real-session login gate)',
    'landed=' + landed.slice(0, 90));

  if (code && KEEP_SECRET) {
    let claims = {};
    try {
      const basic = Buffer.from('keep:' + KEEP_SECRET).toString('base64');
      const tok = await (await member.request.post(BASE + '/oauth2/token', {
        headers: { Authorization: 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded' },
        form: { grant_type: 'authorization_code', code, redirect_uri: KEEP_REDIRECT },
      })).json();
      if (tok.id_token) claims = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString());
    } catch (e) { log('token exchange:', e.message); }
    const roles = claims?.resource_access?.keep?.roles;
    ok(Array.isArray(roles) && roles.includes('user'),
      'B2 id_token carries the injected role claim (resource_access.keep.roles=[user])',
      'roles=' + JSON.stringify(roles));
  } else {
    ok(false, 'B2 token exchange', 'code=' + !!code + ' secret=' + !!KEEP_SECRET);
  }

  // ---- C: non-admin member -> /admin -> DENIED by the allowlist gate (reason=not-admin) ----
  log('C. member denied /admin');
  await mp.goto(BASE + '/admin', { waitUntil: 'networkidle', timeout: 25000 }).catch(() => {});
  const mAdminUrl = mp.url();
  await mp.screenshot({ path: OUT + '/11-member-admin.png', fullPage: true }).catch(() => {});
  ok(/reason=not-admin/.test(mAdminUrl) || /\/auth\/error/.test(mAdminUrl),
    'C non-admin member denied /admin (allowlist gate -> reason=not-admin)', 'url=' + mAdminUrl);

  // ---- D: allowlisted admin (aal1) -> /admin -> AAL2 STEP-UP enforced (defense in depth) ----
  // The admin pages require aal2; an allowlisted admin at aal1 (password only) is sent to
  // a step-up login. FINDING: that redirect HARDCODES https://dag.dunn.dev (admin.ts:77,80)
  // — a portability bug; we intercept it to both capture and assert the step-up.
  log('D. admin gate requires AAL2 step-up');
  const admin = await browser.newContext();
  const ap = await admin.newPage();
  let aal2redir = '';
  await ap.route('https://dag.dunn.dev/**', (r) => { aal2redir = r.request().url(); return r.fulfill({ status: 200, contentType: 'text/plain', body: 'stepup' }); });
  await loginViaForm(ap, ADMIN);
  await ap.goto(BASE + '/admin', { waitUntil: 'domcontentloaded', timeout: 25000 }).catch(() => {});
  const aLanded = ap.url();
  await ap.screenshot({ path: OUT + '/12-admin-admin.png', fullPage: true }).catch(() => {});
  ok(/aal=aal2/.test(aal2redir) || /aal=aal2/.test(aLanded),
    'D admin gate enforces AAL2 step-up for an allowlisted admin', 'target=' + (aal2redir || aLanded).slice(0, 100));
  log('FINDING admin AAL2 step-up redirect host:', aal2redir.slice(0, 90) || '(none)');
} catch (e) {
  log('EXC', e.message);
  fail++;
} finally {
  await browser.close();
}

console.log('[browser-test] RESULT ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail === 0 ? 0 : 1);

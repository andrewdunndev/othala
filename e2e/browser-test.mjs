// Scripted browser test for the e2e `browser` profile — runs INSIDE the compose
// net (lab-playwright), so it resolves the service names + the `dag.test` alias
// (which points at the Caddy edge) just like a production browser hits dag.dunn.dev.
//
// This is the human-flow layer the API-level smoke + the browser-free dance can't
// reach: a REAL Kratos session (login form), the rendered UI, and the admin gate.
// It is the CI artifact; the agent-browser pass (next) explores on the same plumbing.
//
// Iterated like the OIDC dance: each step proves out against the live substrate.
// This first iteration just renders the login page and reports the form shape so we
// learn the selectors; assertions get layered on next.
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'http://dag.test';
const OUT = '/out';

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
const errors = [];
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', (e) => errors.push('PAGEERROR ' + e.message));
let nresp = 0;
page.on('response', (r) => { if (nresp++ < 20) console.log('[browser-test] RESP', r.status(), r.url()); });

const log = (...a) => console.log('[browser-test]', ...a);

try {
  log('goto', BASE + '/auth/login');
  const resp = await page.goto(BASE + '/auth/login', { waitUntil: 'networkidle', timeout: 20000 });
  log('status', resp && resp.status(), 'final-url', page.url(), 'title', await page.title());
  await page.screenshot({ path: OUT + '/01-login.png', fullPage: true });

  const inputs = await page.$$eval('input', (els) =>
    els.map((e) => ({ name: e.name, type: e.type, id: e.id, placeholder: e.placeholder })));
  log('INPUTS', JSON.stringify(inputs));
  const buttons = await page.$$eval('button, input[type=submit]', (els) =>
    els.map((e) => ({ text: (e.innerText || e.value || '').trim(), name: e.name, type: e.type })));
  log('BUTTONS', JSON.stringify(buttons));
  const h1 = await page.$$eval('h1, h2, legend', (els) => els.map((e) => e.innerText.trim()).filter(Boolean));
  log('HEADINGS', JSON.stringify(h1));
  log('CONSOLE-ERRORS', JSON.stringify(errors));
} catch (e) {
  log('EXC', e.message);
  try { await page.screenshot({ path: OUT + '/01-error.png', fullPage: true }); } catch {}
} finally {
  await browser.close();
}

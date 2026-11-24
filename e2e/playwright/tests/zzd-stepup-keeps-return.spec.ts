// ZZD — a login POST Kratos does not run keeps the app sign-in. Kratos answers a POST to a flow the session already
// satisfies with a bare 303 to default_browser_return_url, dropping the flow's return_to. In production the passkey POST
// signed in, its 303 to /oauth2/login was not followed, and a second POST of the same first-factor flow sent the sheet
// home, where the landing asked for TOTP although the app is skip_step_up. The sign-in must reach the app callback.
import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey } from '../actions/passkey';
import { getSession } from '../actions/session';

const APP_ORIGIN = 'https://grafana.othala.test';
const OPT_OUT_CLIENT = 'audiobookshelf';
const OPT_OUT_ORIGIN = 'https://audiobookshelf.othala.test';
const OPT_OUT_REDIRECT = `${OPT_OUT_ORIGIN}/auth/openid/callback`;

const authorizeUrl = (baseURL: string, client: string, redirect: string) =>
  `${baseURL}/oauth2/auth?client_id=${client}&response_type=code` +
  `&scope=${encodeURIComponent('openid email')}` +
  `&redirect_uri=${encodeURIComponent(redirect)}&state=zzd-state&nonce=zzd-nonce`;

/** A member holding a passkey and TOTP, signed out; returns the TOTP secret. */
async function seed(page: Page, slug: string, baseURL: string, kratosAdminURL: string): Promise<string> {
  const ctx = page.context();
  const username = `${slug}.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: `ZZD ${slug}`, groups: ['grafana-access', 'audiobookshelf-access'], kratosAdminURL });
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
  await registerPasskey(page, baseURL);
  const secret = await enrollTotpSecret(ctx, baseURL);
  await ctx.clearCookies();
  return secret;
}

/** Start the authorize and sign in with the passkey; returns the first-factor flow's action. */
async function passkeyFirst(page: Page, url: string): Promise<string> {
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/auth\/login\?flow=/, { timeout: 15_000 });
  await page.waitForLoadState('networkidle');
  const form = page.locator('form.passkey-block');
  await expect(form, 'ZZD: the first factor offers the passkey').toBeVisible({ timeout: 10_000 });
  const action = (await form.getAttribute('action')) ?? '';
  expect(action, 'ZZD: the passkey form posts to a login flow').toMatch(/\/self-service\/login\?flow=/);
  await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function');
  await form.locator('button[name="passkey_login_trigger"]').click();
  return action;
}

/** Requests to an app host, which does not resolve in the browser: answered locally and recorded. */
async function recordApp(page: Page, origin: string): Promise<string[]> {
  const hits: string[] = [];
  await page.route(`${origin}/**`, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: 'app' }));
  page.on('request', (r) => {
    if (r.url().startsWith(origin)) hits.push(r.url());
  });
  return hits;
}

const callbackOf = (hits: string[]) => hits.map((u) => new URL(u)).find((u) => u.searchParams.has('code'));

async function expectCallback(hits: string[], redirect: string, label: string): Promise<void> {
  await expect
    .poll(() => callbackOf(hits)?.searchParams.get('code') ?? '', { message: `${label}: the sign-in ends at the app callback with a code`, timeout: 30_000 })
    .not.toBe('');
  const cb = callbackOf(hits)!;
  expect(`${cb.origin}${cb.pathname}`, `${label}: the callback is the registered redirect_uri`).toBe(redirect);
  expect(cb.searchParams.get('state'), `${label}: the callback carries the authorize state`).toBe('zzd-state');
}

/**
 * The first passkey POST signs in, but its 303 to /oauth2/login is answered here with a 204, so the page stays on the
 * spent first-factor flow, as the sheet did. Resolves to the 303's Location.
 */
async function holdFirstPasskeyPost(page: Page): Promise<() => string | undefined> {
  let location: string | undefined;
  let held = false;
  await page.route(/\/self-service\/login\?flow=/, async (route) => {
    if (route.request().method() !== 'POST' || held) return route.continue();
    held = true;
    const response = await route.fetch({ maxRedirects: 0 });
    location = response.headers()['location'] ?? `status ${response.status()}`;
    await route.fulfill({ response, status: 204, body: '' });
  });
  return () => location;
}

async function passkeyAgain(page: Page): Promise<void> {
  const button = page.locator('form.passkey-block button[name="passkey_login_trigger"]');
  await expect(button, 'ZZD: the spent first-factor flow is still offered').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function');
  await button.click();
}

function recordAsks(page: Page): string[] {
  const asks: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes('aal=aal2')) asks.push(r.url());
  });
  return asks;
}

test('ZZD1 — skip_step_up client: a second POST of the spent passkey flow still reaches the app with no second step', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD1: virtual authenticator is attached').toBeTruthy();
  await seed(page, 'zzd1.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, OPT_OUT_ORIGIN);
  const asks = recordAsks(page);
  const firstLocation = await holdFirstPasskeyPost(page);

  await passkeyFirst(page, authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT));
  await expect.poll(firstLocation, { message: 'ZZD1: the first passkey POST signs in and points at /oauth2/login', timeout: 15_000 }).toContain('/oauth2/login');

  // The production second POST: Kratos runs nothing and answers 303 to the site root.
  await passkeyAgain(page);
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD1');
  expect(asks, 'ZZD1: no request asks for aal2').toEqual([]);
  await expect(page.locator('#totp-code'), 'ZZD1: the TOTP form never renders').toHaveCount(0);
});

test('ZZD2 — skip_step_up client: the spent passkey flow page, loaded again, continues to the app', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD2: virtual authenticator is attached').toBeTruthy();
  await seed(page, 'zzd2.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, OPT_OUT_ORIGIN);
  const asks = recordAsks(page);
  const firstLocation = await holdFirstPasskeyPost(page);

  await passkeyFirst(page, authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT));
  await expect.poll(firstLocation, { message: 'ZZD2: the first passkey POST signs in and points at /oauth2/login', timeout: 15_000 }).toContain('/oauth2/login');

  // Loaded again, the spent flow is not offered: the login page redirects to the flow's return, and nothing is clicked.
  const reloaded = page.waitForResponse((r) => r.request().method() === 'GET' && /\/auth\/login\?flow=/.test(r.url()));
  await page.reload().catch(() => {});
  expect((await reloaded).status(), 'ZZD2: the spent flow is not rendered; the page redirects to its return').toBe(302);
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD2');
  await expect(page.locator('form.passkey-block'), 'ZZD2: the spent passkey form is not offered').toHaveCount(0);
  expect(asks, 'ZZD2: no request asks for aal2').toEqual([]);
});

test('ZZD3 — a step-up POST answered after another one already signed in still reaches the app', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD3: virtual authenticator is attached').toBeTruthy();
  const secret = await seed(page, 'zzd3.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, APP_ORIGIN);

  await passkeyFirst(page, authorizeUrl(baseURL!, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI));
  const code = page.locator('#totp-code');
  await expect(code, 'ZZD3: the client steps the passkey session up').toBeVisible({ timeout: 15_000 });

  // One submit signs in out of the page's sight, as a doubled submit whose response the browser drops; the page's own
  // submit then meets a session already at aal2 and Kratos answers 303 to the site root.
  const form = page.locator('form:has(#totp-code)');
  const action = (await form.getAttribute('action')) ?? '';
  const csrf = (await form.locator('input[name="csrf_token"]').getAttribute('value')) ?? '';
  const totp = await computeTotp(secret);
  const out = await page.context().request.post(action, {
    form: { csrf_token: csrf, method: 'totp', totp_code: totp },
    maxRedirects: 0,
  });
  expect(out.status(), 'ZZD3: the out-of-sight submit signs in').toBe(303);
  expect(out.headers()['location'] ?? '', 'ZZD3: and would have returned to the login challenge').toContain('/oauth2/login');

  await code.fill(totp);
  await form.locator('button[type="submit"]').click();
  await expectCallback(hits, GRAFANA_REDIRECT_URI, 'ZZD3');
});

/** An app sign-in started and abandoned at its bounce: the kept return is set, and the page sits on the login page. */
async function abandonAt(page: Page, baseURL: string): Promise<string[]> {
  const resumes: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes('/oauth2/login?')) resumes.push(r.url());
  });
  await page.goto(authorizeUrl(baseURL, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI), { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/auth\/login\?flow=/, { timeout: 15_000 });
  return resumes;
}

test('ZZD4 — a front-door sign-in after an abandoned app sign-in lands home, not in the app', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD4: virtual authenticator is attached').toBeTruthy();
  const ctx = page.context();
  const username = `zzd4.member.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: 'ZZD zzd4', groups: ['grafana-access'], kratosAdminURL });
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await registerPasskey(page, baseURL!);
  await ctx.clearCookies();
  const hits = await recordApp(page, APP_ORIGIN);

  const resumes = await abandonAt(page, baseURL!);
  const before = resumes.length;
  // The front door: a fresh sign-in with no app return.
  await passkeyFirst(page, `${baseURL}/auth/login`);
  await page.waitForURL((u) => u.pathname === '/', { timeout: 15_000 });
  await expect(page.locator('#greeting'), 'ZZD4: lands on the dashboard').toBeVisible();
  expect(resumes.slice(before), 'ZZD4: the abandoned app sign-in is not resumed').toEqual([]);
  expect(hits, 'ZZD4: the app is never reached').toEqual([]);
});

test('ZZD5 — after an abandoned app step-up, Home resumes it once, then stays home', async ({ baseURL, kratosAdminURL, page }) => {
  test.setTimeout(90_000);
  const ctx = page.context();
  const username = `zzd5.admin.${Date.now()}`;
  const email = `${username}@othala.test`;
  // Admin-marked with no second factor: the app steps up, the landing does not.
  await createIdentityWithPassword({ email, username, displayName: 'ZZD zzd5', groups: ['grafana-access'], isAdmin: true, kratosAdminURL });
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'ZZD5: aal1').toBe('aal1');

  const resumes = await abandonAt(page, baseURL!);
  expect(new URL(page.url()).searchParams.get('flow'), 'ZZD5: the app asked for the second step').toBeTruthy();

  const first = resumes.length;
  await page.goto(`${baseURL}/`, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/auth\/login\?flow=/, { timeout: 15_000 });
  expect(resumes.slice(first).some((u) => u.includes('resume=1')), 'ZZD5: the first Home resumes the app sign-in').toBe(true);

  const second = resumes.length;
  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  expect(new URL(page.url()).pathname, 'ZZD5: the second Home stays home').toBe('/');
  await expect(page.locator('#greeting'), 'ZZD5: lands on the dashboard').toBeVisible();
  expect(resumes.slice(second), 'ZZD5: nothing is resumed twice').toEqual([]);
});


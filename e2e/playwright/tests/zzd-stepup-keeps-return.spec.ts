// ZZD — a step-up POST that Kratos does not run keeps the app sign-in. Kratos answers a login POST whose flow asks for no
// more than the session holds with a bare 303 to default_browser_return_url, dropping the flow's return_to; the portal keeps
// the return in a cookie, so the landing sends the sign-in back to /oauth2/login. A passkey alone on a skip_step_up client
// never sees the second step.
import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey } from '../actions/passkey';

const APP_ORIGIN = 'https://grafana.othala.test';
const OPT_OUT_CLIENT = 'audiobookshelf';
const OPT_OUT_REDIRECT = 'https://audiobookshelf.othala.test/auth/openid/callback';

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

test('ZZD1 — passkey, a wrong code, a step-up POST Kratos does not run, then the right code: the sign-in reaches the app', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD1: virtual authenticator is attached').toBeTruthy();
  const secret = await seed(page, 'zzd1.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, APP_ORIGIN);

  const firstFactor = await passkeyFirst(page, authorizeUrl(baseURL!, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI));
  const code = page.locator('#totp-code');
  await expect(code, 'ZZD1: the client steps the passkey session up').toBeVisible({ timeout: 15_000 });
  const stepUpFlow = new URL(page.url()).searchParams.get('flow');

  // A wrong code is refused on the same flow, so the return rides on.
  await code.fill(await computeTotp(secret, Date.now() / 1000 - 600));
  await page.locator('form:has(#totp-code) button[type="submit"]').click();
  await expect(page.locator('#totp-code-error, #flow-error').first(), 'ZZD1: the wrong code is refused in place').toBeVisible({ timeout: 15_000 });
  expect(new URL(page.url()).searchParams.get('flow'), 'ZZD1: the refusal keeps the step-up flow').toBe(stepUpFlow);

  // The production POST: Kratos found the session already at the posted flow's AAL, ran nothing and answered 303 to the
  // site root. Posting the code to the spent first-factor flow (aal1, as the session is) takes that same branch.
  await page.evaluate((action) => {
    document.querySelector<HTMLFormElement>('form:has(#totp-code)')!.action = action;
  }, firstFactor);
  await code.fill(await computeTotp(secret));
  await page.locator('form:has(#totp-code) button[type="submit"]').click();

  // The landing sends the sign-in back to a step-up bound to the same login challenge.
  await page.waitForURL((u) => u.pathname === '/auth/login' && !!u.searchParams.get('flow') && u.searchParams.get('flow') !== stepUpFlow, { timeout: 15_000 });
  await expect(code, 'ZZD1: the second step is asked again').toBeVisible({ timeout: 15_000 });
  await code.fill(await computeTotp(secret));
  await page.locator('form:has(#totp-code) button[type="submit"]').click();
  await expectCallback(hits, GRAFANA_REDIRECT_URI, 'ZZD1');
});

test('ZZD2 — a step-up POST answered after another one already signed in still reaches the app', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD2: virtual authenticator is attached').toBeTruthy();
  const secret = await seed(page, 'zzd2.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, APP_ORIGIN);

  await passkeyFirst(page, authorizeUrl(baseURL!, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI));
  const code = page.locator('#totp-code');
  await expect(code, 'ZZD2: the client steps the passkey session up').toBeVisible({ timeout: 15_000 });

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
  expect(out.status(), 'ZZD2: the out-of-sight submit signs in').toBe(303);
  expect(out.headers()['location'] ?? '', 'ZZD2: and would have returned to the login challenge').toContain('/oauth2/login');

  await code.fill(totp);
  await form.locator('button[type="submit"]').click();
  await expectCallback(hits, GRAFANA_REDIRECT_URI, 'ZZD2');
});

test('ZZD3 — a passkey alone on a skip_step_up client reaches the callback with no second step', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD3: virtual authenticator is attached').toBeTruthy();
  await seed(page, 'zzd3.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, 'https://audiobookshelf.othala.test');
  const asks: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes('aal=aal2')) asks.push(r.url());
  });

  await passkeyFirst(page, authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT));
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD3');
  expect(asks, 'ZZD3: no request asks for aal2').toEqual([]);
  await expect(page.locator('#totp-code'), 'ZZD3: the TOTP form never renders').toHaveCount(0);
});

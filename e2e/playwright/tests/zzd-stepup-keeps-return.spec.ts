// ZZD — a login POST Kratos does not run keeps the app sign-in. Kratos answers a POST to a flow the session already
// satisfies with a bare 303 to default_browser_return_url, dropping the flow's return_to. In production the passkey POST
// signed in, its 303 to /oauth2/login was not followed, and a second POST of the same first-factor flow sent the sheet
// home, where the landing asked for TOTP although the app is skip_step_up. The sign-in must reach the app callback.
import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey } from '../actions/passkey';

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

  // Loaded again, the spent flow must not be offered: the page continues to the flow's return. If it is offered, use
  // it as a person would, which sends the second POST of ZZD1.
  await page.reload().catch(() => {});
  const offered = await page
    .locator('form.passkey-block button[name="passkey_login_trigger"]')
    .isVisible({ timeout: 3_000 })
    .catch(() => false);
  if (offered) await passkeyAgain(page);
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD2');
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

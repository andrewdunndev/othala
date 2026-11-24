// ZZD — a spent first-factor flow on a skip_step_up client. Kratos answers a POST to a flow the session already satisfies
// with a bare 303 to default_browser_return_url, before any strategy and without the flow's return_to. The login page never
// offers such a flow again (ZZD2); a repeat POST that still reaches Kratos lands on the dag home, and a fresh app sign-in
// from there reaches the app with no second step (ZZD1).
import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey } from '../actions/passkey';

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

test('ZZD1 — skip_step_up client: a repeat POST of the spent passkey flow lands on the dag home; a fresh app sign-in then reaches the app with no second step', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZZD1: virtual authenticator is attached').toBeTruthy();
  await seed(page, 'zzd1.member', baseURL!, kratosAdminURL);
  const hits = await recordApp(page, OPT_OUT_ORIGIN);
  const firstLocation = await holdFirstPasskeyPost(page);

  await passkeyFirst(page, authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT));
  await expect.poll(firstLocation, { message: 'ZZD1: the first passkey POST signs in and points at /oauth2/login', timeout: 15_000 }).toContain('/oauth2/login');
  const spent = new URL(page.url()).searchParams.get('flow');

  // The residual: Kratos answers the repeat POST with the site root, so the sign-in lands on the dag home, whose
  // landing asks this second-factor holder for it. No error page, no loop.
  const landed: string[] = [];
  page.on('request', (r) => {
    if (r.isNavigationRequest()) landed.push(r.url());
  });
  await passkeyAgain(page);
  await page.waitForURL((u) => u.pathname === '/auth/login' && !!u.searchParams.get('flow') && u.searchParams.get('flow') !== spent, { timeout: 15_000 });
  await page.waitForLoadState('networkidle');
  expect(landed, 'ZZD1: the repeat POST lands on the dag home').toContain(`${baseURL}/`);
  expect(landed.filter((u) => u === `${baseURL}/`), 'ZZD1: the home is reached once, not in a loop').toHaveLength(1);
  await expect(page.locator('#totp-code'), 'ZZD1: the landing renders its step-up form').toBeVisible();
  expect(hits, 'ZZD1: the app is not reached on this path').toEqual([]);

  // A fresh sign-in from the app: the passkey session goes straight through on the skip_step_up client.
  const asks = recordAsks(page);
  await page.goto(authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT), { waitUntil: 'commit' }).catch(() => {});
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD1');
  expect(asks, 'ZZD1: the fresh app sign-in asks for no aal2').toEqual([]);
  await expect(page.locator('#totp-code'), 'ZZD1: the fresh app sign-in renders no TOTP form').toHaveCount(0);
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
  const answer = await reloaded;
  expect(answer.status(), 'ZZD2: the spent flow is not rendered; the page redirects to its return').toBe(302);
  expect(answer.headers()['location'] ?? '', 'ZZD2: the redirect is the flow\'s /oauth2/login return').toMatch(/^\/oauth2\/login\?login_challenge=./);
  await expectCallback(hits, OPT_OUT_REDIRECT, 'ZZD2');
  await expect(page.locator('form.passkey-block'), 'ZZD2: the spent passkey form is not offered').toHaveCount(0);
  expect(asks, 'ZZD2: no request asks for aal2').toEqual([]);
});

// VB — the second step is asked at the dag sign-in: a TOTP holder answers once there and no app asks again; a
// member with no second factor is never asked; the "lost your second step" contact link stays reachable.

import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey, passkeySignIn } from '../actions/passkey';
import { getSession } from '../actions/session';

const APP_ORIGIN = 'https://grafana.othala.test';

const hasWindowFn = (n: string) => typeof (window as unknown as Record<string, unknown>)[n] === 'function';

function authorizeUrl(baseURL: string): string {
  return (
    `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=vb-state&nonce=vb-nonce`
  );
}

/** Requests that ask for a login flow or a second factor, recorded while the callback runs. */
function recordAsks(page: Page): string[] {
  const asks: string[] = [];
  page.on('request', (r) => {
    if (/aal=aal2|\/auth\/login/.test(r.url())) asks.push(r.url());
  });
  return asks;
}

async function seed(slug: string, kratosAdminURL: string, isAdmin: boolean): Promise<{ email: string }> {
  const username = `${slug}.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: `VB ${slug}`, groups: ['grafana-access'], isAdmin, kratosAdminURL });
  return { email };
}

test('VB1 — an admin with a passkey and TOTP is asked once at the dag sign-in, then no app asks', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(90_000);
  expect(virtualAuthenticator.authenticatorId, 'VB1: virtual authenticator is attached').toBeTruthy();
  const ctx = page.context();
  const { email } = await seed('vb1.admin', kratosAdminURL, true);
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await registerPasskey(page, baseURL!);
  const secret = await enrollTotpSecret(ctx, baseURL!);
  await ctx.clearCookies();

  await page.goto(`${baseURL}/auth/login`, { waitUntil: 'networkidle' });
  const loginBtn = page.locator('button[name="passkey_login_trigger"]').first();
  await expect(loginBtn, 'VB1: passkey sign-in button').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeyLogin');
  await loginBtn.click();
  const code = page.locator('#totp-code');
  await expect(code, 'VB1: the dag sign-in asks for the second step').toBeVisible({ timeout: 15_000 });
  await expect(page).toHaveURL(/\/auth\/login\?flow=/);
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'VB1: aal1 until answered').toBe('aal1');

  await code.fill(await computeTotp(secret));
  await page.locator('form:has(#totp-code) button[type="submit"]').click();
  await page.waitForURL((u) => u.pathname === '/', { timeout: 15_000 });
  await expect(page.locator('#greeting'), 'VB1: lands on the dashboard').toBeVisible();
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'VB1: aal2 after the step').toBe('aal2');

  await ctx.route(`${APP_ORIGIN}/**`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'app' }));
  const asks = recordAsks(page);
  await page.goto(authorizeUrl(baseURL!));
  await page.waitForURL((u) => u.origin === APP_ORIGIN, { timeout: 15_000 });
  expect(new URL(page.url()).searchParams.get('code'), 'VB1: the app receives a code').toBeTruthy();
  expect(asks, 'VB1: the app sign-in never asks again').toEqual([]);
  const fa = await ctx.request.get(`${baseURL}/api/forward-auth?group=grafana-access`, { maxRedirects: 0 });
  expect(fa.status(), 'VB1: forward-auth admits the aal2 session').toBe(200);
});

test('VB2 — a passkey-only member is never asked for a second step', async ({ baseURL, kratosAdminURL, page, virtualAuthenticator }) => {
  test.setTimeout(90_000);
  expect(virtualAuthenticator.authenticatorId, 'VB2: virtual authenticator is attached').toBeTruthy();
  const ctx = page.context();
  const { email } = await seed('vb2.member', kratosAdminURL, false);
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await registerPasskey(page, baseURL!);
  await ctx.clearCookies();

  const asks = recordAsks(page);
  await passkeySignIn(page, `${baseURL}/auth/login`);
  await page.waitForURL((u) => u.pathname === '/', { timeout: 15_000 });
  await expect(page.locator('.tile[data-slug="grafana"]'), 'VB2: the dashboard shows the Grafana tile').toBeVisible();
  expect(asks.filter((u) => u.includes('aal=aal2')), 'VB2: no second-step request').toEqual([]);
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'VB2: aal1').toBe('aal1');

  await ctx.route(`${APP_ORIGIN}/**`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'app' }));
  await page.goto(authorizeUrl(baseURL!));
  await page.waitForURL((u) => u.origin === APP_ORIGIN, { timeout: 15_000 });
  expect(new URL(page.url()).searchParams.get('code'), 'VB2: the app receives a code').toBeTruthy();
  expect(asks.filter((u) => u.includes('aal=aal2')), 'VB2: the app sign-in did not ask either').toEqual([]);
});

test('VB3 — a TOTP holder at aal1 reaches the contact form through ?ask=', async ({ baseURL, kratosAdminURL, page }) => {
  const ctx = page.context();
  const { email } = await seed('vb3.member', kratosAdminURL, false);
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await enrollTotpSecret(ctx, baseURL!);

  const res = await page.goto(`${baseURL}/?ask=problem#get-in-touch`, { waitUntil: 'networkidle' });
  expect(res?.status(), 'VB3: the landing renders').toBe(200);
  await expect(page, 'VB3: no step-up redirect').toHaveURL(`${baseURL}/?ask=problem#get-in-touch`);
  await expect(page.locator('#request-form'), 'VB3: the contact form is present').toBeAttached();
});

// ZI — the household journey, entirely through the UI: an admin adds a person and grants app access, the
// person redeems the link and code, enrols a passkey and an authenticator app, then signs in to an OIDC app
// and a forward_auth app. Only the e2e admin's own sign-in is seeded through the API.

import type { Page } from '@playwright/test';
import { test, expect, adminAal2Context, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';
const APP_ORIGIN = 'https://grafana.othala.test';

const hasWindowFn = (n: string) => typeof (window as unknown as Record<string, unknown>)[n] === 'function';

test('ZI1 — admin adds a person; they redeem, enrol a passkey and TOTP, and sign in to an OIDC app and a forward_auth app', async ({
  browser,
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'ZI1: virtual authenticator is attached to the person\'s page').toBeTruthy();

  const suffix = Date.now();
  const adminSeed = await createIdentityWithPassword({
    email: `zi1.admin.${suffix}@othala.test`,
    username: `zi1.admin.${suffix}`,
    displayName: 'ZI1 Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const person = { username: `zi1.person.${suffix}`, email: `zi1.person.${suffix}@othala.test` };

  // (a) The admin creates the user, captures the link and code, and grants the two apps.
  const adminCtx = await adminAal2Context({ browser, email: adminSeed.email, password: TEST_PASSWORD, baseURL: baseURL! });
  let link = '';
  let code = '';
  try {
    const admin = await adminCtx.newPage();
    const formUrl = `${baseURL}/admin/users/new`;
    await admin.goto(formUrl, { waitUntil: 'networkidle' });
    await admin.locator('#username').fill(person.username);
    await admin.locator('#email').fill(person.email);
    await admin.getByRole('button', { name: /Create identity/ }).click();
    await expect(admin.getByText(`Identity created for ${person.username}.`), 'ZI1: creation notice').toBeVisible();
    link = await admin.locator('#recoveryUrl').inputValue();
    code = await admin.locator('#recoveryCode').inputValue();
    expect(link, 'ZI1: an enrollment link is shown').toMatch(/^https?:\/\//);
    expect(code, 'ZI1: a recovery code is shown').toMatch(/^\d{6}$/);

    await admin.goto(`${baseURL}/admin/users?q=${encodeURIComponent(person.username)}`, { waitUntil: 'networkidle' });
    await admin.locator('a.users-username-link', { hasText: person.username }).click();
    await admin.getByRole('link', { name: 'Edit', exact: true }).first().click();
    await admin.locator('input[name="accessGroups"][value="grafana-access"]').check();
    await admin.locator('input[name="accessGroups"][value="proxywatch-access"]').check();
    await admin.getByRole('button', { name: 'Save' }).click();
    await expect(admin.getByText('Identity updated.'), 'ZI1: access grant saved').toBeVisible();
  } finally {
    await adminCtx.close();
  }

  // (b) The person, in a fresh context (the page fixture's), redeems the link and code.
  const ctx = page.context();
  await page.goto(link, { waitUntil: 'networkidle' });
  await page.locator('input[name="code"]').fill(code);
  await page.getByRole('button', { name: /Verify code/ }).click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/recovery'), { timeout: 15_000 });

  // (c) A passkey, then an authenticator app whose secret is read from the settings page.
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  const registerBtn = page.locator(PASSKEY_REGISTER_BUTTON).first();
  await expect(registerBtn, 'ZI1: passkey register button').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeySettingsRegistration');
  await registerBtn.click();
  await page.waitForLoadState('networkidle');

  const totpForm = page.locator('form:has(.totp-secret-value)');
  const secret = (await totpForm.locator('.totp-secret-value').textContent())?.trim() ?? '';
  expect(secret, 'ZI1: the setup key is a base32 secret').toMatch(/^[A-Z2-7]{16,}$/i);
  await totpForm.locator('input[name="totp_code"]').fill(await computeTotp(secret));
  await totpForm.locator('button[type="submit"]').click();
  await page.waitForLoadState('networkidle');
  await expect(page.locator('.totp-secret-value'), 'ZI1: enrolled, so the setup key is no longer offered').toHaveCount(0);

  // (d) A returning visit: usernameless passkey sign-in, then an OIDC app and a forward_auth app.
  await ctx.clearCookies();
  await page.goto(`${baseURL}/auth/login`, { waitUntil: 'networkidle' });
  const loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
  await expect(loginBtn, 'ZI1: passkey sign-in button').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeyLogin');
  await loginBtn.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 });

  await ctx.route(`${APP_ORIGIN}/**`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'app' }));
  const authorize =
    `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=zi-household-state&nonce=zi-household-nonce`;
  await page.goto(authorize);
  await stepUpIfAsked(page, secret);
  await page.waitForURL((u) => u.origin === APP_ORIGIN, { timeout: 15_000 });
  expect(new URL(page.url()).searchParams.get('code'), `ZI1: the OIDC app receives a code, landed at ${page.url()}`).toBeTruthy();

  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  await expect(page.getByText('Proxywatch').first(), 'ZI1: the forward_auth app is on the person\'s portal').toBeVisible();
  const forward = await ctx.request.get(`${baseURL}/api/forward-auth?group=proxywatch-access`, { maxRedirects: 0 });
  expect(forward.status(), 'ZI1: forward_auth admits the person').toBe(200);
});

/** The second factor the person enrolled is asked for when the session is below aal2; answer it in the page. */
async function stepUpIfAsked(page: Page, secret: string): Promise<void> {
  await page.waitForURL((u) => u.origin === APP_ORIGIN || u.pathname.startsWith('/auth/login'), { timeout: 15_000 });
  if (!new URL(page.url()).pathname.startsWith('/auth/login')) return;
  const form = page.locator('form:has(#totp-code)');
  await expect(form, 'ZI1: step-up offers the authenticator code').toBeVisible({ timeout: 10_000 });
  await form.locator('#totp-code').fill(await computeTotp(secret));
  await form.locator('button[type="submit"]').click();
}

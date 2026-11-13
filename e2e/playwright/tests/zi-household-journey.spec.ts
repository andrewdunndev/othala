// ZI — the household journey, entirely through the UI: an admin adds a person and grants app access, the
// person redeems the link and code, enrols a passkey and an authenticator app, then signs in to an OIDC app
// and a forward_auth app. Only the e2e admin's own sign-in is seeded through the API.

import type { Page } from '@playwright/test';
import { test, expect, adminAal2Context, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { requireEnv, walk } from '../actions/oidc';
import { getSession } from '../actions/session';
import { clickAndSettle } from '../actions/passkey';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';
const APP_ORIGIN = 'https://grafana.othala.test';
const PROXYWATCH_ORIGIN = 'https://proxywatch.othala.test';

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
    await admin.locator('#displayName').fill('ZI1 Person');
    await admin.locator('#email').fill(person.email);
    await admin.locator('summary', { hasText: 'More options' }).click();
    await admin.locator('#username').fill(person.username);
    await admin.getByRole('button', { name: 'Add person' }).click();
    await expect(admin.getByRole('heading', { name: 'ZI1 is ready' }), 'ZI1: creation card').toBeVisible();
    link = await admin.locator('#recoveryUrl').inputValue();
    code = await admin.locator('#recoveryCode').inputValue();
    expect(link, 'ZI1: an enrollment link is shown').toMatch(/^https?:\/\//);
    expect(code, 'ZI1: a recovery code is shown').toMatch(/^\d{6}$/);

    await admin.getByRole('link', { name: 'View ZI1' }).click();
    await admin.locator('input[name="level:grafana"][value="viewer"]').check();
    await admin.locator('input[name="level:proxywatch"][value="use"]').check();
    await admin.getByRole('button', { name: 'Save access' }).click();
    await expect(admin.getByText('Access saved.'), 'ZI1: access grant saved').toBeVisible();
  } finally {
    await adminCtx.close();
  }

  // (b) The person, in a fresh context (the page fixture's), redeems the link and code.
  const ctx = page.context();
  await page.goto(link, { waitUntil: 'networkidle' });
  await page.locator('input[name="code"]').fill(code);
  await page.locator('form:has(input[name="code"]) button[name="method"]').click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/recovery'), { timeout: 15_000 });

  // (c) A passkey, then an authenticator app whose secret is read from the settings page.
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  const registerBtn = page.locator(PASSKEY_REGISTER_BUTTON).first();
  await expect(registerBtn, 'ZI1: passkey register button').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeySettingsRegistration');
  await clickAndSettle(page, registerBtn);
  // The save replaced the settings flow, so open a fresh one: its setup key is the one the form will verify.
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });

  await page.locator('.lbl-setup', { hasText: 'Set up authenticator app' }).click();
  const totpForm = page.locator('form:has(.totp-secret-value)');
  const secret = ((await totpForm.locator('.totp-secret-value').textContent()) ?? '').replace(/\s+/g, '');
  expect(secret, 'ZI1: the setup key is a base32 secret').toMatch(/^[A-Z2-7]{16,}$/i);
  await totpForm.locator('input[name="totp_code"]').fill(await computeTotp(secret));
  await totpForm.locator('button[type="submit"]').click();
  await page.waitForLoadState('networkidle');
  await expect(page.locator('.totp-secret-value'), 'ZI1: enrolled, so the setup key is no longer offered').toHaveCount(0, { timeout: 15_000 });

  // (d) A returning visit: usernameless passkey sign-in, then an OIDC app and a forward_auth app.
  await ctx.clearCookies();
  await page.goto(`${baseURL}/auth/login`, { waitUntil: 'networkidle' });
  const loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
  await expect(loginBtn, 'ZI1: passkey sign-in button').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeyLogin');
  await loginBtn.click();
  await answerSecondStepAtDag(page, secret);

  const authorize =
    `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=zi-household-state&nonce=zi-household-nonce`;
  // Hand-walked: the app host does not resolve in the browser, and the second step was answered at the dag.
  const chain = await walk(ctx, baseURL!, authorize, (loc) => loc.origin === APP_ORIGIN);
  const code2 = chain.at(-1)?.searchParams.get('code');
  expect(code2, `ZI1: the OIDC app receives a code, hops ${chain.join(' > ')}`).toBeTruthy();
  expect(chain.map(String).filter((u) => /aal=aal2|\/auth\/login/.test(u)), 'ZI1: the app sign-in never asks').toEqual([]);

  // The code redeems at the token endpoint for an id_token carrying the person.
  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${requireEnv('GRAFANA_CLIENT_SECRET')}`).toString('base64');
  const token = await ctx.request.post(`${baseURL}/oauth2/token`, {
    headers: { Authorization: `Basic ${basic}` },
    form: { grant_type: 'authorization_code', code: code2!, redirect_uri: GRAFANA_REDIRECT_URI },
  });
  expect(token.status(), `ZI1: the token endpoint redeems the code: ${await token.text()}`).toBe(200);
  const idToken = (await token.json()).id_token as string;
  const claims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString('utf8'));
  expect(claims.sub, 'ZI1: id_token names the person').toBeTruthy();
  expect(claims.email, 'ZI1: id_token carries the person\'s email').toBe(person.email);
  expect(claims.email_verified, 'ZI1: the admin vouched for the address, so the id_token says verified').toBe(true);
  expect(claims.groups, 'ZI1: id_token carries the granted app group').toContain('grafana-access');

  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  await expect(page.getByText('Proxywatch').first(), 'ZI1: the forward_auth app is on the person\'s portal').toBeVisible();
  // The forward_auth app sits behind the edge route: the person reaches the stub through the portal's gate.
  const appResponse = await page.goto(PROXYWATCH_ORIGIN, { waitUntil: 'networkidle' });
  expect(appResponse?.status(), 'ZI1: forward_auth admits the person to the app').toBe(200);
  await expect(page.getByText('proxywatch-stub'), 'ZI1: the person reaches the app behind the edge').toBeVisible();

  // Forged identity headers are stripped before the gate copies its own id in, and no cookie reaches the app.
  const session = await getSession(ctx, baseURL!);
  const forged = await ctx.request.get(PROXYWATCH_ORIGIN, {
    headers: {
      'X-Kratos-Authenticated-Identity-Id': '00000000-0000-0000-0000-000000000000',
      'X-Remote-User': 'admin',
      'Remote-User': 'admin',
    },
    maxRedirects: 0,
  });
  expect(forged.status(), 'ZI1: the gate admits the person despite the forged headers').toBe(200);
  expect(await forged.text(), 'ZI1: the app sees only the gate\'s identity id, no spoofed user and no cookie').toBe(
    `proxywatch-stub id=${session!.identity.id} spoof= cookie=`,
  );
});

/** The dag sign-in asks the enrolled second factor; answer it in the page and land on the dashboard. */
async function answerSecondStepAtDag(page: Page, secret: string): Promise<void> {
  const form = page.locator('form:has(#totp-code)');
  await expect(form, 'ZI1: the dag sign-in offers the authenticator code').toBeVisible({ timeout: 15_000 });
  await form.locator('#totp-code').fill(await computeTotp(secret));
  await form.locator('button[type="submit"]').click();
  await page.waitForURL((u) => u.pathname === '/', { timeout: 15_000 });
}

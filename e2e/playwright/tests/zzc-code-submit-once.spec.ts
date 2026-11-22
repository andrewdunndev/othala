// ZZC — a code form leaves the page once: a second submit during the first (iOS code AutoFill plus a tap) must not
// send a second POST, or the browser follows the later response and the app sign-in never returns to the app.

import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

const APP_ORIGIN = 'https://grafana.othala.test';

test('ZZC1 — a doubled TOTP submit during app sign-in posts once and lands on the app callback', async ({ browser, baseURL, kratosAdminURL }) => {
  test.setTimeout(90_000);
  const username = `zzc1.member.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: 'ZZC zzc1', groups: ['grafana-access'], kratosAdminURL });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
    const secret = await enrollTotpSecret(ctx, baseURL);
    await ctx.clearCookies();
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);

    const page = await ctx.newPage();
    // The app host does not resolve in the browser: answer its callback locally.
    await page.route(`${APP_ORIGIN}/**`, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: 'app' }));
    const authorize =
      `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
      `&scope=${encodeURIComponent('openid email')}` +
      `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}&state=zzc-state&nonce=zzc-nonce`;
    await page.goto(authorize, { waitUntil: 'networkidle' });
    const code = page.locator('#totp-code');
    await expect(code, 'ZZC1: authorize asks for the second step').toBeVisible({ timeout: 15_000 });

    // Hold the first POST so the second submit lands while it is in flight, as it does on a phone.
    await page.route(/\/self-service\/login\?flow=/, async (r) => {
      if (r.request().method() === 'POST') await new Promise((res) => setTimeout(res, 3000));
      await r.continue();
    });
    const posts: string[] = [];
    const appHits: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/self-service/login')) posts.push(r.url());
      if (r.url().startsWith(APP_ORIGIN)) appHits.push(r.url());
    });

    await code.fill(await computeTotp(secret));
    await page.evaluate(async () => {
      const form = document.querySelector<HTMLFormElement>('form:has(#totp-code)')!;
      form.requestSubmit();
      await new Promise((res) => setTimeout(res, 1000));
      form.requestSubmit();
    });
    // The app host does not resolve, so the callback is read from the requests the page made, not from page.url().
    const callback = () => appHits.map((u) => new URL(u)).find((u) => u.searchParams.has('code'));
    await expect
      .poll(() => callback()?.searchParams.get('code') ?? '', { message: `ZZC1: the authorize ends at the app callback with a code; posts=${posts.length}, app requests=${appHits.length}`, timeout: 30_000 })
      .not.toBe('');
    await page.waitForTimeout(3000);
    expect(`${callback()?.origin}${callback()?.pathname}`, 'ZZC1: the callback is the registered redirect_uri').toBe(GRAFANA_REDIRECT_URI);
    expect(callback()?.searchParams.get('state'), 'ZZC1: the callback carries the authorize state').toBe('zzc-state');
    expect(posts, 'ZZC1: one POST left the page').toHaveLength(1);
  } finally {
    await ctx.close();
  }
});

test('ZZC2 — a doubled TOTP enrol submit on settings posts once, through the router too', async ({ browser, baseURL, kratosAdminURL }) => {
  test.setTimeout(90_000);
  const username = `zzc2.member.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: 'ZZC zzc2', groups: [], kratosAdminURL });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
    await page.locator('.lbl-setup', { hasText: 'Set up authenticator app' }).click();
    const form = page.locator('form:has(.totp-secret-value)');
    const secret = ((await form.locator('.totp-secret-value').textContent()) ?? '').replace(/\s+/g, '');
    expect(secret, 'ZZC2: the setup key is a base32 secret').toMatch(/^[A-Z2-7]{16,}$/i);

    // Hold the first POST so the second submit lands while it is in flight. Requests are counted at the page, so a
    // fetch made by the router counts as well as a native form post.
    await page.route(/\/self-service\/settings\?flow=/, async (r) => {
      if (r.request().method() === 'POST') await new Promise((res) => setTimeout(res, 3000));
      await r.continue();
    });
    const posts: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/self-service/settings')) posts.push(r.url());
    });

    await form.locator('input[name="totp_code"]').fill(await computeTotp(secret));
    await page.evaluate(async () => {
      const f = document.querySelector<HTMLFormElement>('form:has(#totp-code)')!;
      f.requestSubmit();
      await new Promise((res) => setTimeout(res, 1000));
      f.requestSubmit();
    });
    await expect(page.locator('.totp-secret-value'), 'ZZC2: enrolled, so the setup key is no longer offered').toHaveCount(0, { timeout: 20_000 });
    await page.waitForTimeout(3000);
    expect(posts, 'ZZC2: one settings POST left the page').toHaveLength(1);
  } finally {
    await ctx.close();
  }
});

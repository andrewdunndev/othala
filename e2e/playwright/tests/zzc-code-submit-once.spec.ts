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
      if (r.request().method() === 'POST') await new Promise((res) => setTimeout(res, 1500));
      await r.continue();
    });
    const posts: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/self-service/login')) posts.push(r.url());
    });

    await code.fill(await computeTotp(secret));
    await page.evaluate(async () => {
      const form = document.querySelector<HTMLFormElement>('form:has(#totp-code)')!;
      form.requestSubmit();
      await new Promise((res) => setTimeout(res, 1000));
      form.requestSubmit();
    });
    await page.waitForURL((u) => u.origin === APP_ORIGIN, { timeout: 20_000 });
    await page.waitForTimeout(1500);
    const end = new URL(page.url());
    expect(end.origin, `ZZC1: ends at the app, got ${end}`).toBe(APP_ORIGIN);
    expect(end.searchParams.get('code'), 'ZZC1: the app receives a code').toBeTruthy();
    expect(posts, 'ZZC1: one POST left the page').toHaveLength(1);
  } finally {
    await ctx.close();
  }
});

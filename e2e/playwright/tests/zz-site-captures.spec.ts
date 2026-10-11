// ZZ — the two frames othala.dunn.dev's hero shows: the passkey sign-in page, then the app dashboard it leads to.
// Written to /out/captures; site/public/captures holds the copies the site serves.

import { mkdirSync } from 'node:fs';
import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

const OUT = '/out/captures';
const hasWindowFn = (n: string) => typeof (window as unknown as Record<string, unknown>)[n] === 'function';

test('ZZ1 — capture passkey sign-in and the dashboard it opens', async ({ baseURL, kratosAdminURL, page, virtualAuthenticator }) => {
  expect(virtualAuthenticator.authenticatorId).toBeTruthy();
  mkdirSync(OUT, { recursive: true });
  await page.setViewportSize({ width: 1120, height: 760 });

  const identity = await createIdentityWithPassword({
    email: 'avery@othala.test',
    username: 'avery',
    displayName: 'Avery',
    groups: ['grafana-access', 'audiobookshelf-access', 'proxywatch-access', 'prompt-access', 'stepca-access'],
    kratosAdminURL,
  });

  const ctx = page.context();
  await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  await page.waitForFunction(hasWindowFn, 'oryPasskeySettingsRegistration');
  await page.locator('button[name="passkey_register_trigger"]').first().click();
  await page.waitForLoadState('networkidle');

  await ctx.clearCookies();
  expect(await getSession(ctx, baseURL)).toBeNull();

  await page.goto(`${baseURL}/auth/login`, { waitUntil: 'networkidle' });
  const passkey = page.locator('button[name="passkey_login_trigger"]').first();
  await expect(passkey).toBeVisible({ timeout: 15_000 });
  await page.waitForFunction(hasWindowFn, 'oryPasskeyLogin');
  await page.screenshot({ path: `${OUT}/sign-in.png` });

  await passkey.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 });
  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  await expect(page.locator('article.tile').first()).toBeVisible();
  await page.screenshot({ path: `${OUT}/dashboard.png` });
});

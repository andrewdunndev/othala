/**
 * ZC — signing out takes a POST carrying the page's sign-out token.
 *
 *   ZC1 — a GET of /auth/logout (a link followed from anywhere) renders the
 *         confirm form, and a token-less POST re-renders it; the session
 *         stays alive through both.
 *   ZC2 — pressing Sign out on the home page ends the session.
 *
 * Each attempt seeds its own member so no run depends on another.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { hasSession } from '../actions/session';

async function seedMember(tag: string, kratosAdminURL: string) {
  const suffix = `${tag}.${Date.now()}`;
  return createIdentityWithPassword({
    email: `sign.out.${suffix}@othala.test`,
    username: `sign.out.${suffix}`,
    displayName: 'Sign Out',
    groups: [],
    kratosAdminURL,
  });
}

test('ZC1 — a GET or a token-less POST leaves the session alive', async ({ browser, baseURL, kratosAdminURL }) => {
  const member = await seedMember('zc1', kratosAdminURL);
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    expect(await hasSession(ctx, baseURL!), 'session after login').toBe(true);

    const page = await ctx.newPage();
    const resp = await page.goto(`${baseURL}/auth/logout`, { waitUntil: 'networkidle' });
    expect(resp?.status(), 'GET renders the confirm page').toBe(200);
    expect(new URL(page.url()).pathname).toBe('/auth/logout');
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    expect(await hasSession(ctx, baseURL!), 'session after GET').toBe(true);

    const post = await ctx.request.post(`${baseURL}/auth/logout`, {
      form: { csrf_token: '' },
      headers: { Origin: new URL(baseURL!).origin },
      maxRedirects: 0,
    });
    expect(post.status(), 'token-less POST re-renders the form').toBe(200);
    expect(await hasSession(ctx, baseURL!), 'session after token-less POST').toBe(true);
  } finally {
    await ctx.close();
  }
});

test('ZC2 — the home page Sign out button ends the session', async ({ browser, baseURL, kratosAdminURL }) => {
  const member = await seedMember('zc2', kratosAdminURL);
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
    await Promise.all([
      page.waitForResponse(
        (r) => r.url().startsWith(`${baseURL}/auth/logout`) && r.request().method() === 'POST',
      ),
      page.getByRole('button', { name: 'Sign out', exact: true }).click(),
    ]);
    // Kratos returns the browser home signed out.
    await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 15_000 });
    expect(await hasSession(ctx, baseURL!), 'session after Sign out').toBe(false);
  } finally {
    await ctx.close();
  }
});

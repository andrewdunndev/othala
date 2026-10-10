// U — a manifest's <stem>.svg renders as its tile logo for a viewer who can see the tile, and 404s for everyone else.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';

test('U1 — a member sees the sidecar logo load; the route is sandboxed', async ({ ctx, baseURL, member }) => {
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const page = await ctx.newPage();
  await page.goto(`${baseURL}/`);
  const img = page.locator('.tile[data-slug="grafana"] img.app-icon-img');
  await expect(img).toBeVisible();
  expect(await img.evaluate((el: HTMLImageElement) => el.naturalWidth)).toBeGreaterThan(0);

  const res = await ctx.request.get(`${baseURL}/icons/grafana.svg`);
  expect(res.status()).toBe(200);
  expect(res.headers()['content-security-policy']).toContain('sandbox');
});

test('U2 — a non-member and an anonymous caller get 404 on the icon URL', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  await createIdentityWithPassword({
    email: 'u2.outsider@othala.test',
    username: 'u2.outsider',
    displayName: 'U2 Outsider',
    groups: [],
    kratosAdminURL,
  });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: 'u2.outsider@othala.test', password: TEST_PASSWORD }, baseURL);
    expect((await ctx.request.get(`${baseURL}/icons/grafana.svg`)).status()).toBe(404);
  } finally {
    await ctx.close();
  }
  const anon = await browser.newContext();
  try {
    expect((await anon.request.get(`${baseURL}/icons/grafana.svg`)).status()).toBe(404);
  } finally {
    await anon.close();
  }
});

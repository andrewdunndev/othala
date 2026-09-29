/**
 * W — admin changes end a subject's refresh tokens.
 *
 * A member signs in to grafana with offline_access and holds a refresh token.
 * The refresh grant works once (control), then an admin acts on the member
 * through /admin/users/<id>:
 *
 *   W1  Delete permanently  — the portal revokes sessions and Hydra grants
 *                             before deleting the identity.
 *   W2  Save without the app's access group — the portal revokes the
 *                             subject's Hydra consent sessions after the write.
 *
 * Either way the next refresh grant must fail at Hydra's token endpoint.
 */

import type { BrowserContext, Page } from 'playwright-core';
import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

const GRAFANA_CLIENT_ID = 'grafana';
const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';

function clientSecret(): string {
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');
  return secret;
}

/** Walk the authorize chain (spec B's walk) with offline_access and return the code. */
async function authorizeOffline(ctx: BrowserContext, baseURL: string): Promise<string> {
  let url =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups offline_access')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=w-grant-revocation-state` +
    `&nonce=w-grant-revocation-nonce`;
  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) throw new Error(`authorize chain stalled at hop ${hop} (${url}): status ${resp.status()}`);
    const parsed = new URL(loc, baseURL);
    if (parsed.searchParams.get('error')) throw new Error(`authorize denied: ${loc}`);
    if (loc.startsWith('https://grafana.othala.test')) {
      const code = parsed.searchParams.get('code');
      if (!code) throw new Error(`no code at terminus: ${loc}`);
      return code;
    }
    url = parsed.toString();
  }
  throw new Error(`authorize chain did not terminate in 10 hops (last: ${url})`);
}

/** POST a grant to Hydra's token endpoint with client_secret_basic. */
async function tokenGrant(ctx: BrowserContext, hydraPublicURL: string, form: Record<string, string>) {
  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${clientSecret()}`).toString('base64');
  return ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    form,
  });
}

/** Sign the member in, obtain a refresh token, and prove one refresh works. Returns the rotated token. */
async function liveRefreshToken(opts: {
  browser: import('playwright-core').Browser;
  baseURL: string;
  hydraPublicURL: string;
  email: string;
}): Promise<string> {
  const ctx = await opts.browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: opts.email, password: TEST_PASSWORD }, opts.baseURL);
    const code = await authorizeOffline(ctx, opts.baseURL);
    const exchange = await tokenGrant(ctx, opts.hydraPublicURL, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: GRAFANA_REDIRECT_URI,
    });
    expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
    const first = (await exchange.json()).refresh_token as string | undefined;
    expect(first, 'offline_access must yield a refresh_token').toBeTruthy();

    const control = await tokenGrant(ctx, opts.hydraPublicURL, { grant_type: 'refresh_token', refresh_token: first! });
    expect(control.ok(), `control refresh must succeed before the admin change: ${control.status()}`).toBe(true);
    const rotated = (await control.json()).refresh_token as string | undefined;
    expect(rotated, 'the refresh grant must rotate the refresh_token').toBeTruthy();
    return rotated!;
  } finally {
    await ctx.close();
  }
}

async function expectRefreshRefused(browser: import('playwright-core').Browser, hydraPublicURL: string, refreshToken: string) {
  const ctx = await browser.newContext();
  try {
    const resp = await tokenGrant(ctx, hydraPublicURL, { grant_type: 'refresh_token', refresh_token: refreshToken });
    expect([400, 401], `refresh after the admin change must be refused; got ${resp.status()}`).toContain(resp.status());
  } finally {
    await ctx.close();
  }
}

async function seedPair(tag: string) {
  const suffix = Date.now();
  const admin = await createIdentityWithPassword({
    email: `${tag}.admin.${suffix}@othala.test`,
    username: `${tag}.admin.${suffix}`,
    displayName: `${tag.toUpperCase()} Admin`,
    groups: [],
    isAdmin: true,
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const username = `${tag}.member.${suffix}`;
  const member = await createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: `${tag.toUpperCase()} Member`,
    groups: ['family', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  return { admin, member: { ...member, username } };
}

async function submitAndExpectStatus(page: Page, targetUrl: string, click: () => Promise<void>, expected: number[]) {
  const [resp] = await Promise.all([
    page.waitForResponse((r) => r.url().startsWith(targetUrl) && r.request().method() === 'POST'),
    click(),
  ]);
  expect(expected, `admin POST status ${resp.status()}`).toContain(resp.status());
}

test('W1 — deleting an identity ends its refresh tokens', async ({ browser, baseURL, hydraPublicURL }) => {
  const { admin, member } = await seedPair('w1');
  const refreshToken = await liveRefreshToken({ browser, baseURL: baseURL!, hydraPublicURL, email: member.email });

  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${member.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await page.locator('summary', { hasText: 'Delete identity' }).click();
    await page.locator('input[name="confirm"]').fill(member.username);
    // The delete action answers 303 to /admin/users?deleted=1.
    await submitAndExpectStatus(page, targetUrl, () => page.getByRole('button', { name: 'Delete permanently' }).click(), [303]);
    await page.waitForURL(/\/admin\/users\?deleted=1/);
  } finally {
    await ctx.close();
  }

  await expectRefreshRefused(browser, hydraPublicURL, refreshToken);
});

test('W2 — removing the app access group ends the refresh tokens', async ({ browser, baseURL, hydraPublicURL }) => {
  const { admin, member } = await seedPair('w2');
  const refreshToken = await liveRefreshToken({ browser, baseURL: baseURL!, hydraPublicURL, email: member.email });

  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${member.id}`;
    await page.goto(`${targetUrl}?mode=edit`, { waitUntil: 'networkidle' });
    await page.locator('input[name="accessGroups"][value="grafana-access"]').uncheck();
    await submitAndExpectStatus(page, targetUrl, () => page.getByRole('button', { name: 'Save', exact: true }).click(), [200]);
    await expect(page.getByText('Identity updated.'), 'W2: the save and the grant revocation must both succeed').toBeVisible();
  } finally {
    await ctx.close();
  }

  await expectRefreshRefused(browser, hydraPublicURL, refreshToken);
});

// ZG — ending a member's app sign-ins posts a back-channel logout token for their login session.

import { createServer } from 'node:http';
import type { BrowserContext, Page } from '@playwright/test';
import { decodeJwt } from 'jose';
import { test, expect, adminAal2Context, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { hasSession } from '../actions/session';
import { requireEnv, walk } from '../actions/oidc';

function seed(tag: string, isAdmin = false) {
  const name = `${tag}.${isAdmin ? 'admin' : 'member'}.${Date.now()}`;
  return createIdentityWithPassword({
    email: `${name}@othala.test`,
    username: name,
    displayName: isAdmin ? 'ZG Admin' : 'ZG Member',
    groups: isAdmin ? [] : ['everyone', 'grafana-access'],
    isAdmin,
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
}

async function listenForLogoutTokens() {
  const tokens: string[] = [];
  const sink = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const t = new URLSearchParams(body).get('logout_token');
      if (t) tokens.push(t);
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => sink.listen(4500, '0.0.0.0', resolve));
  return { tokens, close: () => new Promise((resolve) => sink.close(resolve)) };
}

async function authorizeGrafana(ctx: BrowserContext, baseURL: string, hydraPublicURL: string): Promise<string> {
  const secret = requireEnv('GRAFANA_CLIENT_SECRET');
  const authorize =
    `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=zg-state&nonce=zg-nonce`;
  const chain = await walk(ctx, baseURL, authorize, (loc) => loc.href.startsWith('https://grafana.othala.test'));
  const code = chain.at(-1)?.searchParams.get('code');
  expect(code, `authorize must end in a code; chain: ${chain.map(String).join(' -> ')}`).toBeTruthy();
  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${secret}`).toString('base64');
  const exchange = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    form: { grant_type: 'authorization_code', code: code!, redirect_uri: GRAFANA_REDIRECT_URI },
  });
  expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
  const sid = decodeJwt((await exchange.json()).id_token as string).sid;
  expect(sid, 'id_token must carry sid').toBeTruthy();
  return sid as string;
}

async function expectLogoutToken(tokens: string[], sid: string) {
  await expect.poll(() => tokens.length, { timeout: 10_000 }).toBeGreaterThan(0);
  const logout = decodeJwt(tokens[0]);
  expect(logout.sid).toBe(sid);
  expect(logout.aud).toEqual([GRAFANA_CLIENT_ID]);
  expect(Object.keys(logout.events as object)).toContain('http://schemas.openid.net/event/backchannel-logout');
}

async function submitStatus(page: Page, url: string, click: () => Promise<void>): Promise<number> {
  const [resp] = await Promise.all([
    page.waitForResponse((r) => r.url().startsWith(url) && r.request().method() === 'POST'),
    click(),
  ]);
  return resp.status();
}

test('ZG — force re-login delivers a logout token carrying the session sid', async ({ browser, baseURL, hydraPublicURL }) => {
  const admin = await seed('zg', true);
  const member = await seed('zg');
  const sink = await listenForLogoutTokens();
  const memberCtx = await browser.newContext();
  const adminCtx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    await loginViaJsonApi(memberCtx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const sid = await authorizeGrafana(memberCtx, baseURL!, hydraPublicURL);

    const page = await adminCtx.newPage();
    const targetUrl = `${baseURL}/admin/users/${member.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await page.locator('summary', { hasText: 'Sign out everywhere' }).click();
    const status = await submitStatus(page, targetUrl, () =>
      page.locator('form.confirm').getByRole('button', { name: 'Sign out everywhere' }).click(),
    );
    expect([200, 303], `force re-login status ${status}`).toContain(status);

    await expectLogoutToken(sink.tokens, sid);
  } finally {
    await memberCtx.close();
    await adminCtx.close();
    await sink.close();
  }
});

test('ZG2 — portal sign-out delivers a logout token for the app session', async ({ browser, baseURL, hydraPublicURL }) => {
  const member = await seed('zg2');
  const sink = await listenForLogoutTokens();
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const sid = await authorizeGrafana(ctx, baseURL!, hydraPublicURL);

    const page = await ctx.newPage();
    await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
    await submitStatus(page, `${baseURL}/auth/logout`, () => page.getByRole('button', { name: 'Sign out', exact: true }).click());

    await expectLogoutToken(sink.tokens, sid);
    await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 15_000 });
    expect(await hasSession(ctx, baseURL!), 'session after Sign out').toBe(false);
  } finally {
    await ctx.close();
    await sink.close();
  }
});

test('ZG3 — removing app access delivers a logout token for the app session', async ({ browser, baseURL, hydraPublicURL }) => {
  const admin = await seed('zg3', true);
  const member = await seed('zg3');
  const sink = await listenForLogoutTokens();
  const memberCtx = await browser.newContext();
  const adminCtx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    await loginViaJsonApi(memberCtx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const sid = await authorizeGrafana(memberCtx, baseURL!, hydraPublicURL);

    const page = await adminCtx.newPage();
    const targetUrl = `${baseURL}/admin/users/${member.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await page.locator('input[name="level:grafana"][value="none"]').check();
    const status = await submitStatus(page, targetUrl, () => page.getByRole('button', { name: 'Save access' }).click());
    expect(status, 'save access status').toBe(200);
    await expect(page.getByText('Access saved.')).toBeVisible();

    await expectLogoutToken(sink.tokens, sid);
  } finally {
    await memberCtx.close();
    await adminCtx.close();
    await sink.close();
  }
});

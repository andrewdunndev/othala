// ZM — an app that asks for a fresh sign-in (prompt=login or max_age) sends an older portal session through a refresh.

import { test, expect, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { walk } from '../actions/oidc';

async function expectRefreshedSignIn(
  browser: import('playwright-core').Browser,
  baseURL: string,
  tag: string,
  freshness: string,
) {
  const name = `${tag}.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${name}@othala.test`,
    username: name,
    displayName: 'ZM Member',
    groups: ['everyone', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const creds = { identifier: member.email, password: TEST_PASSWORD };
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, creds, baseURL);
    const before = Date.parse((await getSession(ctx, baseURL))?.authenticated_at as string);
    await new Promise((r) => setTimeout(r, 31_000));

    const authorize =
      `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
      `&scope=${encodeURIComponent('openid email groups')}&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
      `&state=zm-state&nonce=zm-nonce&${freshness}`;
    const toLogin = await walk(ctx, baseURL, authorize, (loc) => loc.pathname === '/auth/login');
    const bounce = toLogin.at(-1)!;
    expect(bounce.pathname, `chain: ${toLogin.map(String).join(' -> ')}`).toBe('/auth/login');
    expect(bounce.searchParams.get('refresh')).toBe('true');
    const returnTo = bounce.searchParams.get('return_to')!;
    expect(returnTo).toMatch(/^\/oauth2\/login\?login_challenge=/);

    await loginViaJsonApi(ctx, creds, baseURL, `?refresh=true&return_to=${encodeURIComponent(returnTo)}`);
    const toApp = await walk(ctx, baseURL, `${baseURL}${returnTo}`, (loc) => loc.href.startsWith('https://grafana.othala.test'));
    expect(toApp.at(-1)?.searchParams.get('code'), `chain: ${toApp.map(String).join(' -> ')}`).toBeTruthy();

    const after = Date.parse((await getSession(ctx, baseURL))?.authenticated_at as string);
    expect(after - before).toBeGreaterThan(30_000);
  } finally {
    await ctx.close();
  }
}

test('ZM1 — prompt=login refreshes a 31s-old session before the code is issued', async ({ browser, baseURL }) => {
  test.setTimeout(90_000);
  await expectRefreshedSignIn(browser, baseURL!, 'zm1', 'prompt=login');
});

test('ZM2 — max_age under the 30s floor refreshes a 31s-old session before the code is issued', async ({ browser, baseURL }) => {
  test.setTimeout(90_000);
  await expectRefreshedSignIn(browser, baseURL!, 'zm2', 'max_age=5');
});

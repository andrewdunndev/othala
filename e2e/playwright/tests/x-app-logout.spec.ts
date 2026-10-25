// X — signing out of an app ends the SSO session.

import { test, expect, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { requireEnv, walk } from '../actions/oidc';

function clientSecret(): string {
  return requireEnv('GRAFANA_CLIENT_SECRET');
}

function authorizeURL(baseURL: string): string {
  return (
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=x-app-logout-state` +
    `&nonce=x-app-logout-nonce`
  );
}

test('X — RP-initiated logout ends the Kratos session and the next authorize requires login', async ({
  browser,
  baseURL,
  hydraPublicURL,
}) => {
  const suffix = Date.now();
  const username = `x.member.${suffix}`;
  const member = await createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: 'X Member',
    groups: ['family', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });

  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);

    const signIn = await walk(ctx, baseURL!, authorizeURL(baseURL!), (loc) => loc.href.startsWith('https://grafana.othala.test'));
    const terminus = signIn.at(-1);
    const code = terminus?.searchParams.get('code');
    expect(code, `authorize must end in a code; chain: ${signIn.map(String).join(' -> ')}`).toBeTruthy();
    const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${clientSecret()}`).toString('base64');
    const exchange = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
      headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      form: { grant_type: 'authorization_code', code: code!, redirect_uri: GRAFANA_REDIRECT_URI },
    });
    expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
    const idToken = (await exchange.json()).id_token as string | undefined;
    expect(idToken, 'openid scope must yield an id_token').toBeTruthy();

    const before = await ctx.cookies();
    expect(before.find((c) => c.name === 'ory_kratos_session')?.secure, 'Kratos session cookie present and Secure').toBe(true);

    const logout = await walk(
      ctx,
      baseURL!,
      `${baseURL}/oauth2/sessions/logout?id_token_hint=${encodeURIComponent(idToken!)}`,
      (loc) => loc.pathname === '/' || loc.pathname.startsWith('/auth/error'),
    );
    const chain = logout.map(String).join(' -> ');
    expect(logout.some((loc) => loc.pathname === '/oauth2/logout'), `logout must reach the portal; chain: ${chain}`).toBe(true);
    expect(logout.at(-1)?.pathname, `logout must finish at the post-logout page; chain: ${chain}`).toBe('/');

    const replay = await browser.newContext();
    try {
      await replay.addCookies(before);
      const whoami = await replay.request.get(`${baseURL}/sessions/whoami`, { headers: { Accept: 'application/json' } });
      expect(whoami.status(), 'whoami with the pre-logout cookie must be 401').toBe(401);

      const again = await walk(
        replay,
        baseURL!,
        authorizeURL(baseURL!),
        (loc) => loc.href.startsWith('https://grafana.othala.test') || loc.pathname.startsWith('/auth/login'),
      );
      const againChain = again.map(String).join(' -> ');
      expect(again.at(-1)?.pathname, `authorize after logout must bounce to login; chain: ${againChain}`).toMatch(/^\/auth\/login/);
      expect(again.some((loc) => loc.searchParams.has('code')), `no code after logout; chain: ${againChain}`).toBe(false);
    } finally {
      await replay.close();
    }
  } finally {
    await ctx.close();
  }
});

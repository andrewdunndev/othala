/**
 * X — signing out of an app ends the SSO session.
 *
 * A member signs in to grafana, then grafana starts an RP-initiated logout at
 * Hydra's end-session endpoint with the id_token as id_token_hint. Hydra hands
 * the logout challenge to the portal, which revokes the member's Kratos session
 * before accepting. Afterwards:
 *
 *   - /sessions/whoami with the pre-logout cookies answers 401, and
 *   - a fresh authorize bounces to the login UI instead of issuing a code.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { walk } from '../actions/oidc';

const GRAFANA_CLIENT_ID = 'grafana';
const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';

function clientSecret(): string {
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');
  return secret;
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

    // Sign in to grafana and exchange the code for an id_token.
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

    // Keep the pre-logout cookies (Kratos session + Hydra login session).
    const before = await ctx.cookies();
    expect(before.some((c) => c.name === 'ory_kratos_session'), 'Kratos session cookie present').toBe(true);

    // RP-initiated logout through the edge, as grafana's browser would do it.
    const logout = await walk(
      ctx,
      baseURL!,
      `${baseURL}/oauth2/sessions/logout?id_token_hint=${encodeURIComponent(idToken!)}`,
      (loc) => loc.pathname === '/' || loc.pathname.startsWith('/auth/error'),
    );
    const chain = logout.map(String).join(' -> ');
    expect(logout.some((loc) => loc.pathname === '/oauth2/logout'), `logout must reach the portal; chain: ${chain}`).toBe(true);
    expect(logout.at(-1)?.pathname, `logout must finish at the post-logout page; chain: ${chain}`).toBe('/');

    // The pre-logout Kratos cookie no longer authenticates.
    const replay = await browser.newContext();
    try {
      await replay.addCookies(before);
      const whoami = await replay.request.get(`${baseURL}/sessions/whoami`, { headers: { Accept: 'application/json' } });
      expect(whoami.status(), 'whoami with the pre-logout cookie must be 401').toBe(401);

      // A new authorize with the same cookies must ask for login, not issue a code.
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

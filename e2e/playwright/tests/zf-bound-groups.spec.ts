// ZF — an app's groups claim carries only the groups its manifest binds plus its role's claim_emit.

import { decodeJwt } from 'jose';
import { test, expect, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { walk } from '../actions/oidc';

test('ZF — groups claim omits identity groups and groups no grafana binding names', async ({ browser, baseURL, hydraPublicURL }) => {
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');
  const username = `zf.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: 'ZF Member',
    groups: ['everyone', 'family', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });

  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const authorize =
      `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
      `&scope=${encodeURIComponent('openid email groups')}&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
      `&state=zf-state&nonce=zf-nonce`;
    const chain = await walk(ctx, baseURL!, authorize, (loc) => loc.href.startsWith('https://grafana.othala.test'));
    const code = chain.at(-1)?.searchParams.get('code');
    expect(code, `authorize must end in a code; chain: ${chain.map(String).join(' -> ')}`).toBeTruthy();

    const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${secret}`).toString('base64');
    const exchange = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
      headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      form: { grant_type: 'authorization_code', code: code!, redirect_uri: GRAFANA_REDIRECT_URI },
    });
    expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
    const claims = decodeJwt((await exchange.json()).id_token as string);
    expect([...(claims.groups as string[])].sort()).toEqual(['grafana-access', 'viewer']);
  } finally {
    await ctx.close();
  }
});

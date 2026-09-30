// B — the authorization-code flow with a real member session yields an id_token carrying the grafana_role claim.

import { test, expect, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { decodeJwt } from 'jose';

test('B — OIDC authorize flow issues id_token with grafana_role=[Viewer]', async ({
  ctx,
  baseURL,
  hydraPublicURL,
  member,
}) => {
  const GRAFANA_CLIENT_SECRET = process.env.GRAFANA_CLIENT_SECRET;
  if (!GRAFANA_CLIENT_SECRET) {
    throw new Error('GRAFANA_CLIENT_SECRET env var not set — inject from compose environment');
  }

  await loginViaJsonApi(
    ctx,
    { identifier: member.email, password: member.password },
    baseURL,
  );

  const authURL =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=pwtest-state-01` +
    `&nonce=pwtest-nonce-01`;

  let url = authURL;
  let code: string | null = null;
  for (let hop = 0; hop < 8 && !code; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) {
      throw new Error(
        `OIDC chain stalled at hop ${hop} (${url}): status ${resp.status()}, no Location`,
      );
    }
    if (loc.startsWith('https://grafana.othala.test')) {
      code = new URL(loc).searchParams.get('code');
      break;
    }
    url = loc.startsWith('http') ? loc : new URL(loc, baseURL).toString();
  }
  expect(code, 'OIDC flow must complete to the grafana redirect_uri with a ?code').not.toBeNull();
  expect(code!.length, 'auth code must be non-empty').toBeGreaterThan(0);

  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${GRAFANA_CLIENT_SECRET}`).toString('base64');
  const tokenResp = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    form: {
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: GRAFANA_REDIRECT_URI,
    },
  });

  expect(tokenResp.ok(), `token exchange failed: ${tokenResp.status()}`).toBe(true);

  const tokenBody = await tokenResp.json();
  expect(tokenBody.id_token, 'id_token must be present in token response').toBeTruthy();

  const claims = decodeJwt(tokenBody.id_token as string);

  console.log('[B] id_token claims:', JSON.stringify({
    sub: claims.sub,
    email: claims['email'],
    groups: claims['groups'],
    grafana_role: claims['grafana_role'],
  }));

  const grafanaRole: string[] = (claims['grafana_role'] as string[]) ?? [];

  expect(
    Array.isArray(grafanaRole),
    'grafana_role must be an array',
  ).toBe(true);
  expect(
    grafanaRole.includes('Viewer'),
    `grafana_role must include 'Viewer'; got ${JSON.stringify(grafanaRole)}`,
  ).toBe(true);
});

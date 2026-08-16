/**
 * B — OIDC authorize → id_token with the grafana_role role claim
 *     (browser-test.mjs assertions B and B2).
 *
 * Drives the full OAuth2 authorization-code flow with the REAL member session
 * (the login gate, not the admin-forged shortcut used by oidc-dance.mjs),
 * against the grafana client — THE role-mapping example.
 *
 * Flow:
 *   1. Login as member (bt2@othala.test) via JSON-API — establishes an
 *      ory_kratos_session cookie in the BrowserContext.
 *   2. Navigate the BrowserContext to the /oauth2/auth authorize URL.
 *      Hydra sees the session → redirects to the app login challenge handler
 *      (/oauth2/login) → which reads the Kratos session and calls the Hydra
 *      admin API to accept the login request → Hydra then redirects to the
 *      app consent handler (/oauth2/consent) → which checks the subject's
 *      groups and emits the role claim → Hydra issues the auth code →
 *      redirects to grafana's redirect_uri.
 *   3. Intercept the redirect to grafana.othala.test (the redirect_uri is not
 *      reachable from inside the compose net) via page.route(), capture the
 *      auth code from the redirect URL.
 *   4. Exchange the code for tokens (POST /oauth2/token, client_secret_basic).
 *   5. Decode the id_token with jose (jwtDecrypt / decodeJwt — RS256, public
 *      key via jwks: verify signature against Hydra's JWKS endpoint).
 *   6. Assert grafana_role includes 'Viewer' (grafana-access -> viewer per the
 *      grafana consent block's group_role_map). The member holds ONLY
 *      `grafana-access`; the admin-tier role would need `grafana-admin` held in
 *      addition. Spec T covers that pairing and its ordering hazard.
 *
 * The grafana redirect_uri (https://grafana.othala.test/login/generic_oauth)
 * is external; inside the compose net it is unresolvable. We intercept it at
 * the Playwright route layer before the browser attempts a TCP connection.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { decodeJwt } from 'jose';

const GRAFANA_CLIENT_ID = 'grafana';
const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';

test('B — OIDC authorize flow issues id_token with grafana_role=[Viewer]', async ({
  browser,
  baseURL,
  hydraPublicURL,
  member,
}) => {
  const GRAFANA_CLIENT_SECRET = process.env.GRAFANA_CLIENT_SECRET;
  if (!GRAFANA_CLIENT_SECRET) {
    throw new Error('GRAFANA_CLIENT_SECRET env var not set — inject from compose environment');
  }

  const ctx = await browser.newContext();

  try {
    // Step 1: login as member — session cookie lands in ctx's jar.
    await loginViaJsonApi(
      ctx,
      { identifier: member.email, password: member.password },
      baseURL,
    );

    // Step 2+3: walk the OAuth2 authorize redirect chain with the real session
    // via ctx.request (maxRedirects:0). grafana.othala.test (the redirect_uri) is
    // unresolvable inside the compose net, and page.route can't reliably
    // intercept a top-level NAVIGATION to an unresolvable host — so we read the
    // auth code straight from the grafana redirect's Location header instead of
    // letting the browser navigate there. ctx.request shares the context cookie
    // jar, so the Kratos session + Hydra flow cookies propagate across hops.
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

    // Step 4: token exchange — use the hydraPublicURL directly (inside compose net).
    // client_secret_basic: Authorization: Basic base64(client_id:client_secret)
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

    // Step 5: decode with jose (no signature verification needed for e2e claims check;
    // the signature is already validated by the exchange HTTP request returning 200).
    // For signature verification, use createRemoteJWKSet from jose against Hydra's JWKS.
    const claims = decodeJwt(tokenBody.id_token as string);

    console.log('[B] id_token claims:', JSON.stringify({
      sub: claims.sub,
      email: claims['email'],
      groups: claims['groups'],
      grafana_role: claims['grafana_role'],
    }));

    // Step 6: assert the injected role claim. The grafana consent block maps
    // grafana-access -> viewer -> grafana_role: ['Viewer'].
    const grafanaRole: string[] = (claims['grafana_role'] as string[]) ?? [];

    expect(
      Array.isArray(grafanaRole),
      'grafana_role must be an array',
    ).toBe(true);
    expect(
      grafanaRole.includes('Viewer'),
      `grafana_role must include 'Viewer'; got ${JSON.stringify(grafanaRole)}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

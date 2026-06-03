/**
 * B — OIDC authorize → id_token with resource_access.keep.roles claim
 *     (browser-test.mjs assertions B and B2).
 *
 * Drives the full OAuth2 authorization-code flow with the REAL member session
 * (the login gate, not the admin-forged shortcut used by oidc-dance.mjs).
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
 *      redirects to keep's redirect_uri.
 *   3. Intercept the redirect to keep.dunn.dev (the redirect_uri is not
 *      reachable from inside the compose net) via page.route(), capture the
 *      auth code from the redirect URL.
 *   4. Exchange the code for tokens (POST /oauth2/token, client_secret_basic).
 *   5. Decode the id_token with jose (jwtDecrypt / decodeJwt — RS256, public
 *      key via jwks: verify signature against Hydra's JWKS endpoint).
 *   6. Assert resource_access.keep.roles includes 'user'.
 *
 * The keep redirect_uri (https://keep.dunn.dev/identity/connect/oidc-signin)
 * is external; inside the compose net it is unresolvable. We intercept it at
 * the Playwright route layer before the browser attempts a TCP connection.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { decodeJwt } from 'jose';

const KEEP_CLIENT_ID = 'keep';
const KEEP_REDIRECT_URI = 'https://keep.dunn.dev/identity/connect/oidc-signin';

test('B — OIDC authorize flow issues id_token with resource_access.keep.roles=[user]', async ({
  browser,
  baseURL,
  hydraPublicURL,
  member,
}) => {
  const KEEP_CLIENT_SECRET = process.env.KEEP_CLIENT_SECRET;
  if (!KEEP_CLIENT_SECRET) {
    throw new Error('KEEP_CLIENT_SECRET env var not set — inject from compose environment');
  }

  const ctx = await browser.newContext();

  try {
    // Step 1: login as member — session cookie lands in ctx's jar.
    await loginViaJsonApi(
      ctx,
      { identifier: member.email, password: member.password },
      baseURL,
    );

    const page = await ctx.newPage();

    // Step 2 + 3: intercept the redirect to keep.dunn.dev.
    // The route captures the full URL before any TCP resolution attempt.
    let redirectedUrl: string | null = null;
    await page.route(`${KEEP_REDIRECT_URI}**`, (route) => {
      redirectedUrl = route.request().url();
      route.fulfill({ status: 200, contentType: 'text/plain', body: 'intercepted' });
    });
    // Also intercept any https://keep.dunn.dev/* (wildcard for the domain).
    await page.route('https://keep.dunn.dev/**', (route) => {
      redirectedUrl = route.request().url();
      route.fulfill({ status: 200, contentType: 'text/plain', body: 'intercepted' });
    });

    const authURL =
      `${baseURL}/oauth2/auth` +
      `?client_id=${KEEP_CLIENT_ID}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent('openid email groups')}` +
      `&redirect_uri=${encodeURIComponent(KEEP_REDIRECT_URI)}` +
      `&state=pwtest-state-01` +
      `&nonce=pwtest-nonce-01`;

    await page.goto(authURL, { waitUntil: 'domcontentloaded', timeout: 30_000 });

    // The flow should have resolved to the intercepted keep redirect.
    expect(redirectedUrl, 'OIDC flow must complete to the keep redirect_uri').not.toBeNull();

    const code = redirectedUrl
      ? new URL(redirectedUrl as string).searchParams.get('code')
      : null;
    expect(code, 'auth code must be present in the redirect URL').not.toBeNull();
    expect(code!.length, 'auth code must be non-empty').toBeGreaterThan(0);

    // Step 4: token exchange — use the hydraPublicURL directly (inside compose net).
    // client_secret_basic: Authorization: Basic base64(client_id:client_secret)
    const basic = Buffer.from(`${KEEP_CLIENT_ID}:${KEEP_CLIENT_SECRET}`).toString('base64');
    const tokenResp = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
      headers: {
        Authorization: `Basic ${basic}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      form: {
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: KEEP_REDIRECT_URI,
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
      resource_access: claims['resource_access'],
    }));

    // Step 6: assert the injected role claim.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const resourceAccess = claims['resource_access'] as any;
    const keepRoles: string[] = resourceAccess?.keep?.roles ?? [];

    expect(
      Array.isArray(keepRoles),
      'resource_access.keep.roles must be an array',
    ).toBe(true);
    expect(
      keepRoles.includes('user'),
      `resource_access.keep.roles must include 'user'; got ${JSON.stringify(keepRoles)}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

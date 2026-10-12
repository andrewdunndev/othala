// T — the converged access model, asserted end to end.

import { test, expect, adminAal2Context, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { requireEnv } from '../actions/oidc';
import { decodeJwt } from 'jose';
import type { BrowserContext } from 'playwright-core';

interface AuthorizeOutcome {
  code?: string;
  error?: string;
  terminus: string;
}

async function walkAuthorize(
  ctx: BrowserContext,
  baseURL: string,
): Promise<AuthorizeOutcome> {
  let url =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=t-access-model-state` +
    `&nonce=t-access-model-nonce`;

  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) {
      throw new Error(
        `authorize chain stalled at hop ${hop} (${url}): status ${resp.status()}, no Location`,
      );
    }
    const parsed = new URL(loc, baseURL);
    const error = parsed.searchParams.get('error');
    if (error) return { error, terminus: loc };
    if (loc.startsWith('https://grafana.othala.test')) {
      const code = parsed.searchParams.get('code');
      return { code: code ?? undefined, terminus: loc };
    }
    url = loc.startsWith('http') ? loc : new URL(loc, baseURL).toString();
  }
  throw new Error(`authorize chain did not terminate in 10 hops (last: ${url})`);
}

async function idTokenClaims(
  ctx: BrowserContext,
  hydraPublicURL: string,
  code: string,
  clientSecret: string,
): Promise<Record<string, unknown>> {
  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${clientSecret}`).toString('base64');
  const tokenResp = await ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    form: {
      grant_type: 'authorization_code',
      code,
      redirect_uri: GRAFANA_REDIRECT_URI,
    },
  });
  expect(tokenResp.ok(), `token exchange failed: ${tokenResp.status()}`).toBe(true);
  const body = await tokenResp.json();
  expect(body.id_token, 'id_token must be present in the token response').toBeTruthy();
  return decodeJwt(body.id_token as string) as Record<string, unknown>;
}

async function seedAndLogin(opts: {
  browser: import('playwright-core').Browser;
  kratosAdminURL: string;
  baseURL: string;
  slug: string;
  groups: string[];
  /** Enrol TOTP and step up: an identity holding `<svc>-admin` signs in at aal2. */
  aal2?: boolean;
}): Promise<BrowserContext> {
  const { browser, kratosAdminURL, baseURL, slug, groups, aal2 } = opts;
  const email = `${slug}@othala.test`;
  await createIdentityWithPassword({
    email,
    username: slug,
    displayName: `T ${slug}`,
    groups,
    kratosAdminURL,
  });
  if (aal2) return adminAal2Context({ browser, email, password: TEST_PASSWORD, baseURL });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
    return ctx;
  } catch (err) {
    await ctx.close();
    throw err;
  }
}

test('T1 — `grafana-access` alone grants entry and the user-tier role', async ({
  browser,
  baseURL,
  hydraPublicURL,
  kratosAdminURL,
}) => {
  const secret = requireEnv('GRAFANA_CLIENT_SECRET');

  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't1.access-only',
    groups: ['grafana-access'],
  });
  try {
    const outcome = await walkAuthorize(ctx, baseURL);
    expect(
      outcome.code,
      'T1: holding `grafana-access` MUST grant entry — it is the only group the ' +
        'grafana manifest binds under presentation.access, and it is what every ' +
        `member holds. Flow terminated at: ${outcome.terminus}`,
    ).toBeTruthy();

    const claims = await idTokenClaims(ctx, hydraPublicURL, outcome.code!, secret);
    const role = (claims['grafana_role'] as string[]) ?? [];
    console.log('[T1] grafana_role:', JSON.stringify(role), 'groups:', JSON.stringify(claims['groups']));

    expect(
      role,
      'T1: `grafana-access` maps to the viewer role (grafana.yaml group_role_map), ' +
        `so grafana_role must be exactly ["Viewer"]; got ${JSON.stringify(role)}`,
    ).toEqual(['Viewer']);
  } finally {
    await ctx.close();
  }
});

test('T2 — both groups, access FIRST: entry, and the role resolves to ADMIN', async ({
  browser,
  baseURL,
  hydraPublicURL,
  kratosAdminURL,
}) => {
  const secret = requireEnv('GRAFANA_CLIENT_SECRET');

  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't2.access-then-admin',
    groups: ['grafana-access', 'grafana-admin'],
    aal2: true,
  });
  try {
    const outcome = await walkAuthorize(ctx, baseURL);
    expect(
      outcome.code,
      'T2: an admin holds `grafana-access` explicitly and is admitted by it like ' +
        `anyone else. Flow terminated at: ${outcome.terminus}`,
    ).toBeTruthy();

    const claims = await idTokenClaims(ctx, hydraPublicURL, outcome.code!, secret);
    const role = (claims['grafana_role'] as string[]) ?? [];
    console.log('[T2] grafana_role:', JSON.stringify(role), 'groups:', JSON.stringify(claims['groups']));

    expect(
      role,
      'T2 (ORDERING HAZARD): groups were stored ["grafana-access","grafana-admin"] — ' +
        'the alphabetical order every real admin ends up with. Role resolution must ' +
        'be a pure function of the group SET, keeping the HIGHEST-ranked role ' +
        '(lookupRole, portal/src/lib/claims.ts), so grafana_role must be ' +
        `["GrafanaAdmin"]; got ${JSON.stringify(role)}. Getting ["Viewer"] here means ` +
        'the resolver reverted to first-match-wins on stored order and every admin ' +
        'has been silently downgraded.',
    ).toEqual(['GrafanaAdmin']);
  } finally {
    await ctx.close();
  }
});

test('T3 — both groups, admin FIRST: same entry, same ADMIN role (order-independent)', async ({
  browser,
  baseURL,
  hydraPublicURL,
  kratosAdminURL,
}) => {
  const secret = requireEnv('GRAFANA_CLIENT_SECRET');

  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't3.admin-then-access',
    groups: ['grafana-admin', 'grafana-access'],
    aal2: true,
  });
  try {
    const outcome = await walkAuthorize(ctx, baseURL);
    expect(
      outcome.code,
      'T3: entry still comes from `grafana-access`; array order is not an input to ' +
        `the gate. Flow terminated at: ${outcome.terminus}`,
    ).toBeTruthy();

    const claims = await idTokenClaims(ctx, hydraPublicURL, outcome.code!, secret);
    const role = (claims['grafana_role'] as string[]) ?? [];
    console.log('[T3] grafana_role:', JSON.stringify(role), 'groups:', JSON.stringify(claims['groups']));

    expect(
      role,
      'T3 (ORDERING HAZARD, mirror of T2): groups were stored ' +
        '["grafana-admin","grafana-access"] — the same SET as T2, reversed. The ' +
        'resolved role must be identical to T2\'s ["GrafanaAdmin"]; got ' +
        `${JSON.stringify(role)}. A T2/T3 DISAGREEMENT means role resolution depends ` +
        'on stored group order, which nothing guarantees.',
    ).toEqual(['GrafanaAdmin']);
  } finally {
    await ctx.close();
  }
});

test('T4 — `grafana-admin` ALONE is DENIED (admin-implies-access is abolished)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't4.admin-only',
    groups: ['grafana-admin'],
  });
  try {
    const outcome = await walkAuthorize(ctx, baseURL);
    console.log('[T4] terminus:', outcome.terminus);

    expect(
      outcome.code,
      'T4 (ABOLITION): this identity holds ONLY `grafana-admin` and it was ADMITTED. ' +
        'Admin-implies-access has been reintroduced. Entry must come from ' +
        '`grafana-access` and NOTHING else — an identity with only `<svc>-admin` is a ' +
        'MISCONFIGURED identity, not a supported shortcut. Look for `grafana-admin` ' +
        'added back to `presentation.access:` in e2e/content/apps/grafana.yaml (that list ' +
        'is the mechanism), or for a derivation added to enforceAccessGate in ' +
        `portal/src/lib/gate.ts. Flow terminated at: ${outcome.terminus}`,
    ).toBeFalsy();

    expect(
      outcome.error,
      'T4 (ABOLITION): the denial must be an OAuth2 access_denied from the access ' +
        `gate; got error=${outcome.error} at ${outcome.terminus}. The precise reason ` +
        'is opaque by design (logged server-side only) — the guard is that entry is ' +
        'refused.',
    ).toBe('access_denied');
  } finally {
    await ctx.close();
  }
});

test('T5 — NEITHER group is DENIED', async ({ browser, baseURL, kratosAdminURL }) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't5.no-groups',
    groups: [],
  });
  try {
    const outcome = await walkAuthorize(ctx, baseURL);
    console.log('[T5] terminus:', outcome.terminus);

    expect(
      outcome.code,
      'T5: an identity holding no group at all must never be admitted — absence of a ' +
        `binding is absence, never a default grant. Flow terminated at: ${outcome.terminus}`,
    ).toBeFalsy();
    expect(
      outcome.error,
      `T5: denial must be access_denied; got error=${outcome.error} at ${outcome.terminus}`,
    ).toBe('access_denied');
  } finally {
    await ctx.close();
  }
});

const FA = (baseURL: string, group: string) =>
  `${baseURL}/api/forward-auth?group=${encodeURIComponent(group)}`;

test('T6 — forward_auth: `proxywatch-access` alone → 200', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't6.fa-access-only',
    groups: ['proxywatch-access'],
  });
  try {
    const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
    expect(
      resp.status(),
      'T6: holding the access group the edge passes must ALLOW; got ' +
        `${resp.status()} (200=allow, 401=no session, 403=denied)`,
    ).toBe(200);
  } finally {
    await ctx.close();
  }
});

test('T7 — forward_auth: an admin holding BOTH still enters via `<svc>-access` → 200', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't7.fa-both',
    groups: ['proxywatch-access', 'proxywatch-admin'],
  });
  try {
    const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
    expect(
      resp.status(),
      'T7: an admin holds `proxywatch-access` explicitly, so the edge keeps passing ' +
        'that ONE group and admins are admitted by it like everyone else. A 403 here ' +
        'means admins have stopped holding the access group and edge Caddyfiles now ' +
        `need per-app admin knowledge; got ${resp.status()}`,
    ).toBe(200);
  } finally {
    await ctx.close();
  }
});

test('T8 — forward_auth: `proxywatch-admin` ALONE → 403 (abolition, at the edge)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't8.fa-admin-only',
    groups: ['proxywatch-admin'],
  });
  try {
    const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
    expect(
      resp.status(),
      'T8 (ABOLITION, edge path): this identity holds ONLY `proxywatch-admin` and the ' +
        `edge gate returned ${resp.status()} instead of 403. If it returned 200, ` +
        'admin-implies-access has been reintroduced in enforceGroupGate ' +
        '(portal/src/lib/gate.ts) or in /api/forward-auth — an admin group must never ' +
        'satisfy a gate for the access group. If it returned 401, the denial is being ' +
        'reported as "please log in", which loops an authenticated user through login.',
    ).toBe(403);
  } finally {
    await ctx.close();
  }
});

test('T9 — forward_auth: NEITHER group → 403', async ({ browser, baseURL, kratosAdminURL }) => {
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't9.fa-no-groups',
    groups: [],
  });
  try {
    const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
    expect(
      resp.status(),
      'T9: a logged-in identity with no groups must get a flat 403, NOT a 401 — 401 is ' +
        'the only status Caddy turns into a login redirect, so a 403-worthy denial ' +
        `returned as 401 is a redirect loop through login; got ${resp.status()}`,
    ).toBe(403);
  } finally {
    await ctx.close();
  }
});

test('T10 — forward_auth: no session at all → 401', async ({ ctx, baseURL }) => {
  const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
  expect(
    resp.status(),
    'T10: with no Kratos session the gate must 401 so the edge sends the user to ' +
      `login; got ${resp.status()}`,
  ).toBe(401);
});

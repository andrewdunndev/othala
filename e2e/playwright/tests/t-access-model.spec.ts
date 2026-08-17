/**
 * T — The converged access model, asserted end to end.
 *
 * THE MODEL
 * ---------
 * Exactly two groups exist per service:
 *
 *   `<svc>-access`  ENTRY. Everyone who may use the service holds it —
 *                   ordinary members and admins alike.
 *   `<svc>-admin`   ROLE. Held IN ADDITION to `<svc>-access` by admins.
 *
 * Nothing is derived from anything else. "Can this person get in?" is answered
 * by looking at ONE group, with no rule to remember. In particular
 * admin-implies-access is ABOLISHED: an identity holding only `<svc>-admin` is
 * NOT admitted. That is a misconfigured identity, not a supported shortcut.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Before it, the suite encoded the retired cohort model (family/friends/kids)
 * and no fixture bound two groups at all, so every invariant below could be
 * deleted from the product and the suite would stay green. These cases are the
 * ones that fail when the model is walked back:
 *
 *   T4  fails if anyone reintroduces admin-implies-access.
 *   T8  fails if anyone reintroduces it at the forward_auth edge.
 *   T2  fails if role resolution reverts to first-match-wins on stored order
 *       (the alphabetical order an admin actually gets: access before admin).
 *   T3  fails if it reverts to LAST-match-wins, the mirror bug.
 *
 * WHAT ENFORCES WHAT (no folklore — each claim names its enforcer)
 * ---------------------------------------------------------------
 *   ENTRY, OIDC apps  enforceAccessGate  portal/src/lib/gate.ts, over
 *                     manifest.accessGroups, which parseAccessGroups
 *                     (portal/src/lib/access-groups.ts) reads from
 *                     `presentation.access:`. e2e/manifests/grafana.yaml lists
 *                     ONLY `grafana-access` there. That one-entry list IS the
 *                     abolition — a second entry would restore the old grant.
 *   ENTRY, edge apps  enforceGroupGate (gate.ts) via /api/forward-auth, over
 *                     the single group the edge passes as ?group=. The edge
 *                     passes `<svc>-access` for everyone, admins included.
 *   ROLE              lookupRole  portal/src/lib/claims.ts, over
 *                     consent.group_role_map, ranked by declaration index in
 *                     consent.roles (highest rank wins across the whole group
 *                     SET, so stored order cannot change the answer).
 *
 * NOT ASSERTED HERE, DELIBERATELY: that admin implies access. That behaviour is
 * gone. A test for it would be a test for the bug.
 *
 * ORTHOGONAL, DO NOT CONFLATE: metadata_admin.admin is PORTAL admin
 * authority and gates /admin. It is a marker, not a group. No group grants it
 * and it grants no group. Specs C, Q and R cover it; none of these identities
 * carry it.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { decodeJwt } from 'jose';
import type { BrowserContext } from 'playwright-core';

const GRAFANA_CLIENT_ID = 'grafana';
const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';

/** Result of walking the OAuth2 authorize chain to its terminus. */
interface AuthorizeOutcome {
  /** Set when the flow completed: the authorization code. */
  code?: string;
  /** Set when the flow was denied: the OAuth2 `error` param. */
  error?: string;
  /** The Location the walk terminated on, for failure messages. */
  terminus: string;
}

/**
 * Walk the authorize redirect chain with the session already in `ctx`'s jar and
 * report the terminus. Mirrors spec B's walk (grafana.othala.test is
 * unresolvable inside the compose net, so we read the code/error out of the
 * Location header rather than letting the browser navigate there), with one
 * addition: a denial can surface as an `error` param on any hop, so we check
 * every hop instead of only the final one.
 */
async function walkAuthorize(
  ctx: BrowserContext,
  baseURL: string,
): Promise<AuthorizeOutcome> {
  // `groups` is requested so the groups claim survives the OIDC Core §5.4
  // scope-gate in composeIDTokenClaims; grafana_role is manifest-injected and
  // is not scope-gated. Matches spec B's request.
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

/** Exchange an authorization code and return the decoded id_token claims. */
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

/**
 * Seed an identity holding EXACTLY `groups` and return a logged-in context.
 * The caller closes the context.
 *
 * Groups are written straight through the Kratos admin API, so the array lands
 * in metadata_admin.groups in exactly the order given — which is what makes the
 * T2/T3 ordering pair meaningful. (normalizeGroupOrder in
 * portal/src/lib/access.ts only runs on the admin FORM write path; it is
 * cosmetic and is not what makes role resolution deterministic.)
 */
async function seedAndLogin(opts: {
  browser: import('playwright-core').Browser;
  kratosAdminURL: string;
  baseURL: string;
  slug: string;
  groups: string[];
}): Promise<BrowserContext> {
  const { browser, kratosAdminURL, baseURL, slug, groups } = opts;
  const email = `${slug}@othala.test`;
  await createIdentityWithPassword({
    email,
    username: slug,
    displayName: `T ${slug}`,
    groups,
    kratosAdminURL,
  });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
    return ctx;
  } catch (err) {
    await ctx.close();
    throw err;
  }
}

// ══ Part 1: OIDC apps — entry from the manifest access binding ═══════════════

test('T1 — `grafana-access` alone grants entry and the user-tier role', async ({
  browser,
  baseURL,
  hydraPublicURL,
  kratosAdminURL,
}) => {
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');

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
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');

  // ['grafana-access', 'grafana-admin'] — alphabetical, i.e. the order a real
  // admin's groups actually sit in after normalizeGroupOrder. A first-match-wins
  // resolver silently hands this identity the VIEWER role.
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't2.access-then-admin',
    groups: ['grafana-access', 'grafana-admin'],
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
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');

  // The SAME set as T2, stored in the opposite order. T2 and T3 must agree;
  // that agreement is the whole assertion. metadata_admin.groups is written
  // through the Kratos admin API, which makes no ordering promise at all.
  const ctx = await seedAndLogin({
    browser, kratosAdminURL, baseURL,
    slug: 't3.admin-then-access',
    groups: ['grafana-admin', 'grafana-access'],
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
        'added back to `presentation.access:` in e2e/manifests/grafana.yaml (that list ' +
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

// ══ Part 2: edge apps — the same model through forward_auth ══════════════════
//
// Apps with no OIDC support are gated at the reverse proxy: Caddy subrequests
// /api/forward-auth?group=<svc>-access and keys on the STATUS. The e2e fixture
// for this shape is proxywatch (e2e/manifests/proxywatch.yaml).
//
// The edge passes ONE group and it is always `<svc>-access` — that is the whole
// point of the converged model: it works for everyone including admins, so no
// Caddyfile needs to know about admin groups. T7 is what proves the edge config
// does not need a second group; T8 is what stops the derivation coming back.
//
// Status contract (portal/src/pages/api/forward-auth.ts):
//   200 in the group · 401 no session · 403 every authorization failure

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

test('T10 — forward_auth: no session at all → 401', async ({ browser, baseURL }) => {
  const ctx = await browser.newContext();
  try {
    const resp = await ctx.request.get(FA(baseURL, 'proxywatch-access'), { maxRedirects: 0 });
    expect(
      resp.status(),
      'T10: with no Kratos session the gate must 401 so the edge sends the user to ' +
        `login; got ${resp.status()}`,
    ).toBe(401);
  } finally {
    await ctx.close();
  }
});

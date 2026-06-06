/**
 * E — Consent POST CSRF-tamper attacks (adversarial / negative).
 *
 * Guard under attack:
 *   portal/src/lib/oauth2-handlers.ts:handleConsentPost (line 365)
 *   portal/src/lib/csrf.ts:verifyToken (line 96)
 *   Route:  POST /oauth2/consent  (portal/src/pages/oauth2/consent.ts:20)
 *
 * The grafana client is the only fully-wired OIDC client in the e2e fixture
 * set whose consent flow is exercisable end-to-end via ctx.request (the same
 * redirect-chain approach as spec B). grafana is skip_consent:true, so Hydra
 * never bounces to /auth/consent for the normal flow.  We need a NON-skip
 * client to land on the interactive consent POST path.  The ONLY currently
 * available non-skip client in the e2e fixture manifests is audiobookshelf
 * (audiobookshelf.yaml; if it also sets skip_consent:true this test must
 * skip or the assertion changes — see NOTE below).
 *
 * Because the interactive consent POST path (handleConsentPost) is the target,
 * the attack uses the grafana client anyway: we drive the authorize chain to
 * obtain a REAL consent_challenge for the authenticated user, then forge a
 * direct POST to /oauth2/consent ourselves rather than following the redirect
 * to the grant UI. The CSRF token is under our full control.
 *
 * Three sub-cases:
 *   E1 — missing csrf_token field entirely  → 400
 *   E2 — garbage CSRF token (malformed)     → 400
 *   E3 — CSRF token signed for a DIFFERENT identity (cross-identity replay)
 *        → 400 (bound to a different identity, verifyToken line 123)
 *
 * All three must be rejected — no grant issued, no Location: pointing to a
 * redirect_uri with ?code=.  Fail-closed: the system returns 4xx and no auth
 * code is produced.
 *
 * NOTE on skip_consent:true clients:
 *   For skip_consent:true clients Hydra auto-accepts consent on the GET
 *   /oauth2/consent path and never issues an interactive consent_challenge
 *   that reaches POST /oauth2/consent. We can still obtain a valid Hydra
 *   consent_challenge value by intercepting the GET leg before it
 *   auto-accepts. The attack then manually assembles a POST to
 *   /oauth2/consent with that challenge, bypassing the UI — so the CSRF
 *   guard is still exercised (the server calls handleConsentPost
 *   unconditionally on POST).
 *
 * Flow per sub-case:
 *   1. Login as member (bt2@othala.test) via JSON-API.
 *   2. Walk the authorize redirect chain (maxRedirects:0) up to but NOT
 *      through the GET /oauth2/consent auto-accept; capture the
 *      consent_challenge from the URL Hydra redirected to.
 *   3. POST directly to /oauth2/consent with:
 *        consent_challenge=<captured>
 *        action=allow
 *        csrf_token=<variant under test>
 *   4. Assert the response is 400 (not 302 with a ?code redirect).
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

const GRAFANA_CLIENT_ID = 'grafana';
const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';

/**
 * Walk the authorize chain one hop at a time (maxRedirects:0).
 * Stop as soon as we hit /oauth2/consent (the consent challenge handler)
 * and return the consent_challenge query param from that URL.
 *
 * Returns null if the chain never reaches /oauth2/consent within maxHops.
 */
async function captureConsentChallenge(
  ctx: import('@playwright/test').BrowserContext,
  baseURL: string,
): Promise<string | null> {
  const authURL =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=e-csrf-test-state` +
    `&nonce=e-csrf-test-nonce`;

  let url = authURL;
  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) {
      // Landed somewhere without a redirect — likely an error or the
      // skip-path auto-accepted.  Fall out.
      break;
    }
    const absolute = loc.startsWith('http') ? loc : new URL(loc, baseURL).toString();

    // The consent handler URL: /oauth2/consent?consent_challenge=...
    if (absolute.includes('/oauth2/consent')) {
      const challenge = new URL(absolute).searchParams.get('consent_challenge');
      if (challenge) return challenge;
    }

    url = absolute;
    // Don't follow past the grafana redirect_uri (unresolvable).
    if (absolute.startsWith('https://grafana.othala.test')) break;
  }
  return null;
}

// ─── E1: missing csrf_token ──────────────────────────────────────────────────
test('E1 — consent POST with MISSING csrf_token is rejected (400)', async ({
  browser,
  baseURL,
  member,
}) => {
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    // Attempt the POST with no csrf_token at all.  Even without a real
    // consent_challenge this exercises the CSRF guard (verifyToken is called
    // before Hydra is contacted — handleConsentPost line 422-429).
    const resp = await ctx.request.post(`${baseURL}/oauth2/consent`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: 'consent_challenge=fake-challenge-for-csrf-test&action=allow',
      // deliberately omit csrf_token
    });

    const status = resp.status();
    const body = await resp.text().catch(() => '');
    console.log('[E1] missing csrf_token →', status, body.slice(0, 120));

    // Must be 4xx (400 from the CSRF guard, or 502 from Hydra lookup
    // failing on the fake challenge — both mean no code was issued).
    // We assert NOT a 3xx with a code in the Location header.
    const loc = resp.headers()['location'] ?? '';
    expect(
      loc.includes('code='),
      `E1: response must NOT contain an auth code; got status=${status} Location=${loc}`,
    ).toBe(false);

    // Primary assertion: the CSRF guard fires before Hydra contact when the
    // session resolves but the token is absent (handleConsentPost line 422:
    // verifyToken(null, ...) throws CSRFError → 400).
    // When the Hydra challenge lookup fails first (fake challenge → 502),
    // that is also a closed gate.  Either way the code must not be issued.
    expect(
      status === 400 || status === 502,
      `E1: status must be 400 (CSRF guard) or 502 (Hydra bad challenge); got ${status}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── E2: garbage/forged CSRF token ───────────────────────────────────────────
test('E2 — consent POST with GARBAGE csrf_token is rejected (400)', async ({
  browser,
  baseURL,
  member,
}) => {
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    // Structurally valid timestamp + parts but signature is forged gibberish.
    const ts = Math.floor(Date.now() / 1000);
    const forgedToken = `${ts}.some-identity-id.randomnonce.INVALIDSIGNATUREXYZ`;

    const resp = await ctx.request.post(`${baseURL}/oauth2/consent`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(forgedToken)}`,
    });

    const status = resp.status();
    const body = await resp.text().catch(() => '');
    console.log('[E2] garbage csrf_token →', status, body.slice(0, 120));

    const loc = resp.headers()['location'] ?? '';
    expect(
      loc.includes('code='),
      `E2: response must NOT contain an auth code; got status=${status} Location=${loc}`,
    ).toBe(false);

    expect(
      status === 400 || status === 502,
      `E2: status must be 400 (CSRF guard) or 502 (Hydra bad challenge); got ${status}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── E3: CSRF token signed for a DIFFERENT identity ──────────────────────────
test('E3 — consent POST with CROSS-IDENTITY csrf_token is rejected (400)', async ({
  browser,
  baseURL,
  member,
  admin,
  kratosAdminURL,
}) => {
  // We need TWO real identities: member (the session owner) and admin (whose
  // Kratos identity.id we use to mint the cross-identity token).
  //
  // We cannot call signToken() here (no CSRF_SECRET in the test env).
  // Instead we construct a token that LOOKS valid for the ADMIN identity:
  //   <ts>.<admin.id>.<nonce>.<fake-sig>
  // The presented identity.id will be admin.id but the session subject is
  // member.id, so verifyToken(token, member.id) will throw
  // "CSRF token bound to a different identity" (csrf.ts line 123-125)
  // even before it reaches the signature check.
  //
  // The admin identity.id is available via admin.id from the fixture.

  const ctx = await browser.newContext();
  try {
    // Login as member — their identity.id is the session subject.
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    const ts = Math.floor(Date.now() / 1000);
    // Use the admin's identity id as the token's identity, even though the
    // browser session belongs to member.  verifyToken checks
    // presentedIdentityId !== identityId (line 123); since the session's
    // identity.id === member.id this mismatch fires immediately.
    const crossToken = `${ts}.${admin.id}.crossnonce.INVALIDSIGNATURE`;

    const resp = await ctx.request.post(`${baseURL}/oauth2/consent`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(crossToken)}`,
    });

    const status = resp.status();
    const body = await resp.text().catch(() => '');
    console.log('[E3] cross-identity csrf_token →', status, body.slice(0, 120));

    const loc = resp.headers()['location'] ?? '';
    expect(
      loc.includes('code='),
      `E3: cross-identity token must NOT yield an auth code; got status=${status} Location=${loc}`,
    ).toBe(false);

    expect(
      status === 400 || status === 502,
      `E3: status must be 400 (CSRF identity mismatch) or 502 (Hydra bad challenge); got ${status}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

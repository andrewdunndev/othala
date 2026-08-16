/**
 * S — AAL2 step-up renders from Kratos's NATURAL redirect (regression for
 * work item #4).
 *
 * Bug: login.astro derived its AAL2 step-up rendering solely from the
 * `?aal=aal2` QUERY PARAM. Kratos's own redirect from the login-browser
 * AAL2 initiator (a real top-level navigation to
 * `/self-service/login/browser?aal=aal2&refresh=true`, as opposed to the
 * `Accept: application/json` shortcut other specs use) lands back on
 * `/auth/login?flow=<id>` WITHOUT re-appending `aal=aal2` — so the TOTP
 * step-up form never rendered via the natural flow, even though the landed
 * flow was correctly primed for AAL2 server-side (requested_aal:'aal2',
 * second-factor nodes present).
 *
 * Why the existing suite missed this: d-admin-aal2-stepup.spec.ts and the
 * adminAal2Context fixture helper both drive the step-up via the JSON-API
 * path (`Accept: application/json`), which Kratos answers with the flow
 * body directly — no browser redirect involved at all, so the param-drop
 * this bug depends on never happens in those tests. This is the first spec
 * to drive an ACTUAL browser navigation through the AAL2 initiator.
 *
 * S1 confirms both halves:
 *   (a) the natural redirect really does land without aal=aal2 in the URL
 *       (the premise — if Kratos ever starts preserving the param this
 *       spec should be revisited, not silently pass or fail); and
 *   (b) the TOTP step-up form renders anyway, and completing it produces a
 *       genuine AAL2 session — proving detection is flow-object-driven
 *       (login.astro's isAal2: requested_aal / second-factor node
 *       presence), not query-param-driven.
 */

import { test, expect } from '../fixtures';
import { enrollTotpSecret, computeTotp } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

test('S1 — AAL2 TOTP step-up form renders after the natural (param-dropping) Kratos redirect', async ({
  page,
  baseURL,
  kratosAdminURL,
}) => {
  // Dedicated throwaway identity — TOTP enrollment is per-identity state,
  // kept isolated from the shared worker-scoped `admin`/`member` fixtures.
  const identity = await createIdentityWithPassword({
    email: 's1.aal2-natural@othala.test',
    username: 's1.aal2.natural',
    displayName: 'S1 AAL2 Natural Redirect',
    groups: [],
    kratosAdminURL,
  });
  console.log('[S1] seeded identity:', identity.id, identity.email);

  const ctx = page.context();
  await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL!);

  const totpSecret = await enrollTotpSecret(ctx, baseURL!);
  console.log('[S1] TOTP enrolled, secret captured (first 6 chars):', totpSecret.slice(0, 6) + '…');

  // The natural step-up entrypoint: a REAL top-level navigation (default
  // Accept header — not Accept: application/json), so Kratos performs its
  // actual browser redirect back to the portal's rendered login page —
  // exactly the path work item #4 found broken.
  await page.goto(`${baseURL}/self-service/login/browser?aal=aal2&refresh=true`, {
    waitUntil: 'networkidle',
  });

  const landedUrl = page.url();
  console.log('[S1] landed on:', landedUrl);

  // Premise check: Kratos's redirect must land on the rendered login page
  // carrying a flow id, and must NOT carry aal=aal2 — this is the exact
  // natural-flow behaviour the bug report traced hop-by-hop. If Kratos ever
  // starts preserving the param, THIS assertion is the one to revisit, not
  // the render assertion below.
  expect(landedUrl, 'S1 premise: must land on the portal login page').toMatch(/\/auth\/login\?/);
  expect(landedUrl, 'S1 premise: must carry a flow id').toMatch(/[?&]flow=/);
  expect(
    landedUrl.includes('aal=aal2'),
    `S1 premise: Kratos's natural redirect must NOT preserve aal=aal2 (if this now fails, ` +
    `Kratos's redirect behaviour changed upstream — revisit this spec, not login.astro); got ${landedUrl}`,
  ).toBe(false);

  // The regression assertion: even without aal=aal2 in the URL, the TOTP
  // step-up form must render — login.astro derives isAal2 from the flow
  // object (requested_aal / second-factor nodes), not the query param.
  const totpForm = page.locator('form.aal2-form').filter({ has: page.locator('#totp-code') });
  const totpInput = totpForm.locator('#totp-code');
  await expect(
    totpInput,
    'S1 (regression for #4): TOTP step-up input must render from the natural (param-dropping) ' +
    'redirect — pre-fix, login.astro trusted only the query param and rendered the primary ' +
    '(passkey/code/password) tiers instead',
  ).toBeVisible({ timeout: 10_000 });

  // Close the loop: complete the step-up and confirm the resulting session
  // is genuinely at AAL2 — proof this isn't just a form that renders but
  // can't be submitted.
  const code = await computeTotp(totpSecret);
  await totpInput.fill(code);
  await totpForm.locator('button[type="submit"]').click();
  await page.waitForLoadState('networkidle');

  const session = await getSession(ctx, baseURL!);
  expect(session?.active, 'S1: session must be active after step-up').toBe(true);
  expect(
    session?.authenticator_assurance_level,
    `S1: session must be at AAL2 after completing the step-up; got ${session?.authenticator_assurance_level}`,
  ).toBe('aal2');

  console.log('[S1] PASS — AAL2 step-up form rendered from the natural redirect and completed to a real AAL2 session');
});

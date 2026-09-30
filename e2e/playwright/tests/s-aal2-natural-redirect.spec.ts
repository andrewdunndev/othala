// S — the AAL2 step-up renders from Kratos's natural redirect.

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

  await page.goto(`${baseURL}/self-service/login/browser?aal=aal2&refresh=true`, {
    waitUntil: 'networkidle',
  });

  const landedUrl = page.url();
  console.log('[S1] landed on:', landedUrl);

  expect(landedUrl, 'S1 premise: must land on the portal login page').toMatch(/\/auth\/login\?/);
  expect(landedUrl, 'S1 premise: must carry a flow id').toMatch(/[?&]flow=/);
  expect(
    landedUrl.includes('aal=aal2'),
    `S1 premise: Kratos's natural redirect must NOT preserve aal=aal2 (if this now fails, ` +
    `Kratos's redirect behaviour changed upstream — revisit this spec, not login.astro); got ${landedUrl}`,
  ).toBe(false);

  const totpForm = page.locator('form.aal2-form').filter({ has: page.locator('#totp-code') });
  const totpInput = totpForm.locator('#totp-code');
  await expect(
    totpInput,
    'S1 (regression for #4): TOTP step-up input must render from the natural (param-dropping) ' +
    'redirect — pre-fix, login.astro trusted only the query param and rendered the primary ' +
    '(passkey/code/password) tiers instead',
  ).toBeVisible({ timeout: 10_000 });

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

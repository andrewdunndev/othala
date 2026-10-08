// ZO — device-code phishing: a link carrying someone else's code, opened in a browser with an older aal2 session, must
// ask for a fresh sign-in before anything is approved, and even then the code is confirmed despite skip_consent.

import { test, expect, enrollTotpSecret, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { startDeviceFlow, pollDeviceToken, recordNavigations, totpStepUp, answerSignIns } from '../actions/device';

test('ZO1 — a prefilled link on a 31s-old session refreshes the sign-in and still asks to confirm the code', async ({ ctx, request, baseURL }) => {
  test.setTimeout(120_000);
  const name = `zo1.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${name}@othala.test`, username: name, displayName: 'ZO Member', groups: ['stepca-access'], kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const creds = { identifier: member.email, password: TEST_PASSWORD };
  await loginViaJsonApi(ctx, creds, baseURL);
  const secret = await enrollTotpSecret(ctx, baseURL);
  await totpStepUp(ctx, baseURL, secret, '', true);
  expect((await getSession(ctx, baseURL))?.authenticator_assurance_level, 'ZO1: the victim holds an aal2 session').toBe('aal2');
  await new Promise((r) => setTimeout(r, 31_000));

  const attacker = await startDeviceFlow(request, baseURL);
  const page = await ctx.newPage();
  const hops = recordNavigations(page);
  await page.goto(attacker.verification_uri_complete);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForURL((u) => ['/auth/login', '/auth/consent', '/device/done', '/auth/error'].includes(u.pathname));

  const chain = hops.map(String).join(' -> ');
  const bounce = hops.find((u) => u.pathname === '/auth/login' && u.searchParams.has('return_to'));
  expect(bounce?.searchParams.get('refresh'), `ZO1: a fresh sign-in is asked for: ${chain}`).toBe('true');
  expect(bounce?.searchParams.get('aal'), `ZO1: and it proves the second factor again: ${chain}`).toBe('aal2');
  expect(hops.some((u) => u.pathname === '/auth/consent' || u.pathname === '/device/done'), `ZO1: nothing approved: ${chain}`).toBe(false);
  const pending = await pollDeviceToken(request, baseURL, attacker.device_code);
  expect(pending.body.error, 'ZO1: the attacker\'s device is still waiting').toBe('authorization_pending');

  const settled = await answerSignIns(page, hops, baseURL, creds, secret);
  expect(settled.pathname, `ZO1: skip_consent does not skip the confirm, got ${settled}`).toBe('/auth/consent');
  await expect(page.locator('.device-code'), 'ZO1: the confirm screen shows the code').toHaveText(attacker.user_code);

  await page.getByRole('button', { name: 'Deny' }).click();
  await page.waitForURL((u) => u.pathname === '/auth/error');
  expect(new URL(page.url()).searchParams.get('reason')).toBe('sign-in-cancelled');
  expect((await pollDeviceToken(request, baseURL, attacker.device_code)).status, 'ZO1: a denied device gets no token').not.toBe(200);
});

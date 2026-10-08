// ZN — a device grant approved in the browser: the code arrives prefilled, a second factor is asked for, the confirm
// screen shows the code and the app, and the device's poll then gets an aal2 token.

import { test, expect, enrollTotpSecret, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { startDeviceFlow, pollDeviceToken, recordNavigations, answerSignIns } from '../actions/device';

test('ZN1 — a member with a second factor approves a device and the device gets an aal2 token', async ({ ctx, request, baseURL }) => {
  const name = `zn1.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${name}@othala.test`, username: name, displayName: 'ZN Member', groups: ['stepca-access'], kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const creds = { identifier: member.email, password: TEST_PASSWORD };
  await loginViaJsonApi(ctx, creds, baseURL);
  const secret = await enrollTotpSecret(ctx, baseURL);

  const device = await startDeviceFlow(request, baseURL);
  const page = await ctx.newPage();
  const hops = recordNavigations(page);
  await page.goto(device.verification_uri_complete);
  await expect(page.locator('#user-code'), 'ZN1: the link prefills the code').toHaveValue(device.user_code);
  await page.getByRole('button', { name: 'Continue' }).click();

  const settled = await answerSignIns(page, hops, baseURL, creds, secret);
  expect(settled.pathname, `ZN1: the confirm screen, got ${settled}`).toBe('/auth/consent');
  await expect(page.locator('.device-code'), 'ZN1: the confirm screen shows the code').toHaveText(device.user_code);
  await expect(page.locator('.consent-app-name'), 'ZN1: and names the app').toHaveText('Certificates');

  await page.getByRole('button', { name: 'Allow' }).click();
  await page.waitForURL((u) => u.pathname === '/device/done');
  await expect(page.getByText('Certificates is signed in'), 'ZN1: the success page names the app').toBeVisible();

  const token = await pollDeviceToken(request, baseURL, device.device_code);
  expect(token.status, `ZN1: the poll redeems: ${JSON.stringify(token.body)}`).toBe(200);
  const claims = JSON.parse(Buffer.from(token.body.id_token.split('.')[1], 'base64url').toString('utf8'));
  expect(claims.acr, 'ZN1: the token records the second factor').toBe('aal2');
  expect(claims.email).toBe(member.email);
});

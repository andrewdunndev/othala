// ZP — an identity with no second factor cannot approve a device: the browser ends on the portal's error page, never
// Hydra's raw JSON, and the device never gets a token.

import { test, expect, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { startDeviceFlow, pollDeviceToken } from '../actions/device';

test('ZP1 — a password-only member is refused on the portal error page and no token issues', async ({ ctx, request, baseURL }) => {
  const name = `zp1.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${name}@othala.test`, username: name, displayName: 'ZP Member', groups: ['stepca-access'], kratosAdminURL: KRATOS_ADMIN_URL,
  });
  await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL);

  const device = await startDeviceFlow(request, baseURL);
  const page = await ctx.newPage();
  await page.goto(device.verification_uri_complete);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForURL((u) => u.pathname === '/auth/error');
  expect(new URL(page.url()).searchParams.get('reason')).toBe('second-factor-required');
  await expect(page.getByRole('heading', { name: 'This needs a second step' })).toBeVisible();

  const token = await pollDeviceToken(request, baseURL, device.device_code);
  expect(token.status, `ZP1: no token: ${JSON.stringify(token.body)}`).not.toBe(200);
});

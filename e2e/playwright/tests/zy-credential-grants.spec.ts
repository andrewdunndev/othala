// ZY — every credential change ends the refresh tokens issued before it: the revoke-grants hook runs after a passkey,
// a security key, an authenticator app and a backup-code set are saved, not only after a password change.

import type { Browser, BrowserContext } from 'playwright-core';
import { test, expect, enrollTotpSecret, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken, loginViaJsonApi } from '../actions/login';
import { expectRefreshRefused, liveRefreshToken } from '../actions/grants';
import { addPlatformAuthenticator, registerPasskey } from '../actions/passkey';

// A member with the household group and a password, holding a live refresh token, and a signed-in browser context.
async function memberWithGrant(
  browser: Browser,
  baseURL: string,
  hydraPublicURL: string,
  tag: string,
): Promise<{ id: string; ctx: BrowserContext; refreshToken: string }> {
  const suffix = Date.now();
  const username = `${tag}.member.${suffix}`;
  const member = await createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: `${tag.toUpperCase()} Member`,
    groups: ['everyone', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const refreshToken = await liveRefreshToken({ browser, baseURL, hydraPublicURL, email: member.email });
  const ctx = await browser.newContext();
  await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL);
  return { id: member.id, ctx, refreshToken };
}

const stored = async (id: string, type: string): Promise<unknown> =>
  (await readIdentity(KRATOS_ADMIN_URL, id, [type])).credentials?.[type];

test.describe('ZY — a credential change ends earlier refresh tokens', () => {
  test('ZY1 — a new passkey', async ({ browser, baseURL, hydraPublicURL }) => {
    const { id, ctx, refreshToken } = await memberWithGrant(browser, baseURL!, hydraPublicURL, 'zy1');
    try {
      const page = await ctx.newPage();
      await addPlatformAuthenticator(ctx, page);
      await registerPasskey(page, baseURL!);
      await expect.poll(async () => Boolean(await stored(id, 'passkey')), { timeout: 10_000, message: 'ZY1: the passkey is stored' }).toBe(true);
    } finally {
      await ctx.close();
    }
    await expectRefreshRefused(browser, hydraPublicURL, refreshToken, 'ZY1: after a passkey is added');
  });

  test('ZY2 — a new security key', async ({ browser, baseURL, hydraPublicURL }) => {
    const { id, ctx, refreshToken } = await memberWithGrant(browser, baseURL!, hydraPublicURL, 'zy2');
    try {
      const page = await ctx.newPage();
      const cdp = await ctx.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
      });
      await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
      await page.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).click();
      const displayName = page.locator('input[name="webauthn_register_displayname"]');
      if (await displayName.count()) await displayName.fill('ZY2 key');
      const trigger = page.locator('button[name="webauthn_register_trigger"]').first();
      await expect(trigger, 'ZY2: the security key register button is offered').toBeVisible({ timeout: 10_000 });
      await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryWebAuthnRegistration === 'function');
      await trigger.click();
      await expect.poll(async () => Boolean(await stored(id, 'webauthn')), { timeout: 15_000, message: 'ZY2: the security key is stored' }).toBe(true);
    } finally {
      await ctx.close();
    }
    await expectRefreshRefused(browser, hydraPublicURL, refreshToken, 'ZY2: after a security key is added');
  });

  test('ZY3 — a new authenticator app', async ({ browser, baseURL, hydraPublicURL }) => {
    const { id, ctx, refreshToken } = await memberWithGrant(browser, baseURL!, hydraPublicURL, 'zy3');
    try {
      await enrollTotpSecret(ctx, baseURL!);
      expect(Boolean(await stored(id, 'totp')), 'ZY3: the app is stored').toBe(true);
    } finally {
      await ctx.close();
    }
    await expectRefreshRefused(browser, hydraPublicURL, refreshToken, 'ZY3: after an authenticator app is added');
  });

  test('ZY4 — a new set of backup codes', async ({ browser, baseURL, hydraPublicURL }) => {
    const { id, ctx, refreshToken } = await memberWithGrant(browser, baseURL!, hydraPublicURL, 'zy4');
    try {
      const flowResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, { headers: { Accept: 'application/json' }, maxRedirects: 5 });
      expect(flowResp.ok(), 'ZY4: settings flow init').toBe(true);
      const flow = await flowResp.json();
      const csrf = findCsrfToken(flow.ui.nodes);
      const post = (data: Record<string, unknown>) =>
        ctx.request.post(flow.ui.action, {
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          data: { csrf_token: csrf, method: 'lookup_secret', ...data },
          maxRedirects: 0,
        });
      // The codes are shown first and saved only when confirmed; the hook runs on the save.
      const generated = await post({ lookup_secret_regenerate: true });
      expect([200, 400], `ZY4: generating the codes answered ${generated.status()}`).toContain(generated.status());
      const confirmed = await post({ lookup_secret_confirm: true });
      expect(confirmed.status(), `ZY4: confirming the codes answered ${confirmed.status()}`).toBe(200);
      expect(Boolean(await stored(id, 'lookup_secret')), 'ZY4: the codes are stored').toBe(true);
    } finally {
      await ctx.close();
    }
    await expectRefreshRefused(browser, hydraPublicURL, refreshToken, 'ZY4: after backup codes are saved');
  });
});

// ZT — admin recovery Step B: the authenticator app cannot be unlinked while it is the last app or key, so a lost
// phone is replaced key first, then the swap (docs/runbooks/admin-recovery.md).

import type { BrowserContext } from 'playwright-core';
import { test, expect, adminAal2Context, enrollTotpSecret } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken } from '../actions/login';

const SECOND_FACTOR_KEEP = 'Admin accounts keep at least one authenticator app or security key.';

interface StoredCredentials {
  totp?: { config?: { totp_url?: string } };
  webauthn?: { config?: { credentials?: Array<{ is_passwordless?: boolean }> } };
}

async function storedCredentials(kratosAdminURL: string, id: string): Promise<StoredCredentials> {
  return ((await readIdentity(kratosAdminURL, id, ['totp', 'webauthn'])) as { credentials?: StoredCredentials }).credentials ?? {};
}

const totpUrl = (c: StoredCredentials) => c.totp?.config?.totp_url ?? '';
const securityKeys = (c: StoredCredentials) => (c.webauthn?.config?.credentials ?? []).filter((k) => k.is_passwordless !== true);

async function submitSettings(ctx: BrowserContext, baseURL: string, data: Record<string, unknown>) {
  const flowResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  expect(flowResp.ok(), 'settings flow init').toBe(true);
  const flow = await flowResp.json();
  const resp = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { csrf_token: findCsrfToken(flow.ui.nodes), ...data },
    maxRedirects: 0,
  });
  return { status: resp.status(), body: await resp.json().catch(() => null) };
}

test('ZT1 — unlink is refused until a security key is added, then the app is swapped for a new one', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const suffix = Date.now();
  const seeded = await createIdentityWithPassword({
    email: `zt1.admin.${suffix}@othala.test`,
    username: `zt1.admin.${suffix}`,
    displayName: 'ZT1 Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const ctx = await adminAal2Context({ browser, email: seeded.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const before = await storedCredentials(kratosAdminURL, seeded.id);
    expect(totpUrl(before), 'ZT1: the app is enrolled').not.toBe('');

    // The app is the last second factor, so the unlink is refused and the app stays.
    const refused = await submitSettings(ctx, baseURL!, { method: 'totp', totp_unlink: true });
    expect(refused.status, 'ZT1: the unlink is refused with the flow').toBe(400);
    const messages = ((refused.body?.ui?.messages ?? []) as Array<{ text?: string }>).map((m) => String(m.text));
    expect(messages, 'ZT1: the refusal names the rule').toContain(SECOND_FACTOR_KEEP);
    expect(totpUrl(await storedCredentials(kratosAdminURL, seeded.id)), 'ZT1: the app is still enrolled').toBe(totpUrl(before));

    // Key first: a security key, added inside the privileged window.
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
    });
    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');
    await page.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).click();
    const displayName = page.locator('input[name="webauthn_register_displayname"]');
    if (await displayName.count()) await displayName.fill('ZT1 key');
    const trigger = page.locator('button[name="webauthn_register_trigger"]').first();
    await expect(trigger, 'ZT1: security key register button').toBeVisible({ timeout: 10_000 });
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryWebAuthnRegistration === 'function');
    await trigger.click();
    await expect
      .poll(async () => securityKeys(await storedCredentials(kratosAdminURL, seeded.id)).length, {
        timeout: 15_000,
        message: 'ZT1: the security key is stored',
      })
      .toBe(1);

    // Now the app can be unlinked, and a new one set up in its place.
    const unlinked = await submitSettings(ctx, baseURL!, { method: 'totp', totp_unlink: true });
    expect(unlinked.status, 'ZT1: the unlink is accepted once a key remains').toBe(200);
    const mid = await storedCredentials(kratosAdminURL, seeded.id);
    expect(totpUrl(mid), 'ZT1: the old app is gone').toBe('');
    expect(securityKeys(mid), 'ZT1: the key remains').toHaveLength(1);

    await enrollTotpSecret(ctx, baseURL!);
    const after = await storedCredentials(kratosAdminURL, seeded.id);
    expect(totpUrl(after), 'ZT1: a new app is enrolled').not.toBe('');
    expect(totpUrl(after), 'ZT1: and it is not the old one').not.toBe(totpUrl(before));
    expect(securityKeys(after), 'ZT1: the stand-in key is still there to remove').toHaveLength(1);
  } finally {
    await ctx.close();
  }
});

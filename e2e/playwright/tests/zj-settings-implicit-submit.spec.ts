// ZJ — Enter in a settings text field must never submit a removal.

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

test('ZJ2 — Enter in the new key name never removes an enrolled key', async ({ browser, baseURL, kratosAdminURL }) => {
  const identity = await createIdentityWithPassword({
    email: 'implicit.enter@othala.test',
    username: 'implicit.enter',
    displayName: 'Implicit Enter Tester',
    groups: [],
    kratosAdminURL,
  });
  const ctx = await browser.newContext();
  const keyCount = async () => {
    const c = ((await readIdentity(kratosAdminURL, identity.id, ['webauthn'])) as { credentials?: { webauthn?: { config?: { credentials?: unknown[] } } } }).credentials;
    return c?.webauthn?.config?.credentials?.length ?? 0;
  };
  try {
    await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
    });
    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');
    await page.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).first().click();
    await page.locator('input[name="webauthn_register_displayname"]').fill('ZJ2 first');
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryWebAuthnRegistration === 'function');
    await page.locator('button[name="webauthn_register_trigger"]').first().click();
    await expect.poll(keyCount, { timeout: 15_000, message: 'the first key is stored' }).toBe(1);

    // A fresh page, so the redirect that follows enrolment cannot interrupt the next navigation. It has the
    // virtual WebAuthn environment but no authenticator: a ceremony started by Enter cannot add a key, and a
    // removal would drop the count to 0.
    await page.close();
    const page2 = await ctx.newPage();
    await (await ctx.newCDPSession(page2)).send('WebAuthn.enable', { enableUI: false });
    await page2.goto(`${baseURL}/auth/settings`);
    await page2.waitForLoadState('networkidle');
    await page2.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).first().click();
    const posts: string[] = [];
    page2.on('request', (r) => { if (r.method() === 'POST') posts.push(r.url()); });
    const name = page2.locator('input[name="webauthn_register_displayname"]');
    await name.fill('ZJ2 second');
    await name.press('Enter');
    await page2.waitForTimeout(1500);
    expect(posts, 'Enter posted nothing').toEqual([]);
    expect(await keyCount(), 'the enrolled key is still there').toBe(1);
  } finally {
    await ctx.close();
  }
});

/**
 * passkey.ts — a CDP virtual authenticator, passkey enrolment from settings, and usernameless passkey sign-in.
 */

import type { BrowserContext, Locator, Page } from '@playwright/test';
import { expect } from '@playwright/test';

const REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

type Win = Record<string, unknown>;

/** A platform authenticator on the page: it holds resident, user-verified credentials, like a phone or laptop. */
export async function addPlatformAuthenticator(ctx: BrowserContext, page: Page): Promise<string> {
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  return authenticatorId;
}

/** Enrol a passkey from the settings page; the session must be privileged. */
export async function registerPasskey(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  const button = page.locator(REGISTER_BUTTON).first();
  await expect(button, 'the passkey register button is offered').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(() => typeof (window as unknown as Win).oryPasskeySettingsRegistration === 'function');
  await clickAndSettle(page, button);
}

// The save posts, then redirects through a fresh settings flow to /auth/settings?flow=. The previous document stays current, and
// networkidle, until the new one commits, so neither a response event nor a load state marks the end. The saved passkey listed
// on the settled flow URL does; a caller that navigates earlier has its goto interrupted.
export async function clickAndSettle(page: Page, button: Locator): Promise<void> {
  const listed = page.locator('[data-credential="passkey"]');
  const before = await listed.count();
  await button.click();
  await expect(listed, 'the saved passkey is listed').toHaveCount(before + 1, { timeout: 15_000 });
  await expect(page, 'the save lands on a settings flow').toHaveURL(/\/auth\/settings\?flow=/);
  await page.waitForLoadState('networkidle');
}

/** Sign in with a passkey from whatever sign-in flow `startUrl` opens (a refresh, or a fresh login). */
export async function passkeySignIn(page: Page, startUrl: string): Promise<void> {
  await page.goto(startUrl, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/auth\/login\?flow=/, { timeout: 10_000 });
  await page.waitForLoadState('networkidle');
  let button = page.locator(LOGIN_BUTTON).first();
  if (!(await button.isVisible().catch(() => false))) {
    await page.reload();
    await page.waitForLoadState('networkidle');
    button = page.locator(LOGIN_BUTTON).first();
  }
  await expect(button, 'the passkey sign-in button is offered').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(() => typeof (window as unknown as Win).oryPasskeyLogin === 'function');
  await button.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 });
}

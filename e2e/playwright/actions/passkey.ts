/**
 * passkey.ts — a CDP virtual authenticator, passkey enrolment from settings, and usernameless passkey sign-in.
 */

import type { BrowserContext, Page } from '@playwright/test';
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
  // The save answers with a redirect back to settings; a caller that navigates before that page lands loses the passkey or the goto.
  const settled = page.waitForResponse((r) => r.request().isNavigationRequest() && r.request().method() === 'GET' && new URL(r.url()).pathname === '/auth/settings');
  await button.click();
  await settled;
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

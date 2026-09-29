/**
 * ZA — an admin account keeps a second factor through self-service settings.
 *
 *   ZA1 — an admin whose only second factor is an authenticator app submits
 *         totp_unlink; the change is refused with the neutral message and the
 *         admin API still reports the app enrolled.
 *   ZA2 — an admin with an authenticator app and a security key removes the
 *         key; the change is saved and the app stays enrolled.
 *
 * Each test seeds its own admin (unique per run) so enrolment state never
 * carries across runs.
 */

import type { BrowserContext } from 'playwright-core';
import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken } from '../actions/login';

const SECOND_FACTOR_KEEP = 'Admin accounts keep at least one authenticator app or security key.';

interface StoredCredentials {
  totp?: { config?: { totp_url?: string } };
  webauthn?: { config?: { credentials?: Array<{ is_passwordless?: boolean }> } };
}

async function storedCredentials(kratosAdminURL: string, id: string): Promise<StoredCredentials> {
  const resp = await fetch(`${kratosAdminURL}/admin/identities/${id}?include_credential=totp&include_credential=webauthn`);
  expect(resp.ok, 'admin API identity read').toBe(true);
  return ((await resp.json()) as { credentials?: StoredCredentials }).credentials ?? {};
}

const totpEnrolled = (c: StoredCredentials) => Boolean(c.totp?.config?.totp_url);
const securityKeys = (c: StoredCredentials) => (c.webauthn?.config?.credentials ?? []).filter((k) => k.is_passwordless !== true);

async function seedAdmin(browser: import('playwright-core').Browser, baseURL: string, kratosAdminURL: string, label: string) {
  const suffix = `${label}.${Date.now()}`;
  const seeded = await createIdentityWithPassword({
    email: `keep.factor.${suffix}@othala.test`,
    username: `keep.factor.${suffix}`,
    displayName: 'Keep Factor',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  // Password sign-in, authenticator-app enrolment through settings, aal2 step-up.
  const ctx = await adminAal2Context({ browser, email: seeded.email, password: TEST_PASSWORD, baseURL });
  return { seeded, ctx };
}

/** Submit one settings method of a fresh flow as JSON; returns status + body. */
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
  return { status: resp.status(), body: await resp.json().catch(() => null), flow };
}

function flowMessages(body: any): string[] {
  return (body?.ui?.messages ?? []).map((m: any) => String(m.text));
}

test.describe('ZA — admin keeps a second factor', () => {
  test('ZA1 — unlinking the only authenticator app is refused', async ({ browser, baseURL, kratosAdminURL }) => {
    const { seeded, ctx } = await seedAdmin(browser, baseURL, kratosAdminURL, 'totp');
    try {
      expect(totpEnrolled(await storedCredentials(kratosAdminURL, seeded.id)), 'app enrolled before').toBe(true);

      const { status, body } = await submitSettings(ctx, baseURL, { method: 'totp', totp_unlink: true });
      expect(status, 'refused totp change answers 400 with the flow').toBe(400);
      expect(flowMessages(body)).toContain(SECOND_FACTOR_KEEP);

      expect(totpEnrolled(await storedCredentials(kratosAdminURL, seeded.id)), 'app still enrolled').toBe(true);
    } finally {
      await ctx.close();
    }
  });

  test('ZA2 — with an app and a key, removing the key is saved', async ({ browser, baseURL, kratosAdminURL }) => {
    const { seeded, ctx } = await seedAdmin(browser, baseURL, kratosAdminURL, 'key');
    try {
      // Register a security key through the settings page with a CDP virtual authenticator.
      const page = await ctx.newPage();
      const cdp = await ctx.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
      });
      await page.goto(`${baseURL}/auth/settings`);
      await page.waitForLoadState('networkidle');
      const displayName = page.locator('input[name="webauthn_register_displayname"]');
      if (await displayName.count()) await displayName.fill('ZA2 key');
      const trigger = page.locator('button[name="webauthn_register_trigger"]').first();
      await expect(trigger, 'security key register button').toBeVisible({ timeout: 10_000 });
      await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryWebAuthnRegistration === 'function');
      await trigger.click();
      await expect
        .poll(async () => securityKeys(await storedCredentials(kratosAdminURL, seeded.id)).length, {
          timeout: 15_000,
          message: 'the security key is stored',
        })
        .toBe(1);

      const flowResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, {
        headers: { Accept: 'application/json' },
        maxRedirects: 5,
      });
      const flow = await flowResp.json();
      const removeNode = (flow.ui.nodes as any[]).find((n) => n?.attributes?.name === 'webauthn_remove');
      expect(removeNode, 'settings flow offers the key for removal').toBeTruthy();

      const { status } = await submitSettings(ctx, baseURL, {
        method: 'webauthn',
        webauthn_remove: String(removeNode.attributes.value),
      });
      expect(status, 'key removal accepted').toBe(200);

      const after = await storedCredentials(kratosAdminURL, seeded.id);
      expect(securityKeys(after)).toHaveLength(0);
      expect(totpEnrolled(after), 'app still enrolled').toBe(true);
    } finally {
      await ctx.close();
    }
  });
});

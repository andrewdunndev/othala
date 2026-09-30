/**
 * Y — username is admin-controlled; email stays self-service.
 *
 *   Y1 — the settings page shows the username read-only.
 *   Y2 — a profile-settings submission that changes the username is refused
 *        with the neutral message, and the admin API still reports the old
 *        username.
 *   Y3 — an email change through the same form is saved; the post-save
 *        profile-sessions webhook ends the member's other sessions and keeps
 *        the one that saved; the new address is unverified and gets a
 *        verification mail.
 *   Y4 — after an email change, a refresh login by code mails the new address
 *        and nothing goes to the old one.
 */

import type { BrowserContext } from 'playwright-core';
import { test, expect } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken, loginViaJsonApi } from '../actions/login';
import { forRecipient, waitForMessage } from '../actions/mail';

const USERNAME_CHANGE_REFUSAL = 'Your username can only be changed by an administrator.';

async function storedTraits(kratosAdminURL: string, id: string) {
  return (await readIdentity(kratosAdminURL, id)).traits as { username: string; email: string; displayName?: string };
}

/** Submit the profile method of a fresh settings flow as JSON; returns status + body. */
async function submitProfile(ctx: BrowserContext, baseURL: string, traits: Record<string, string>) {
  const flowResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  expect(flowResp.ok(), 'settings flow init').toBe(true);
  const flow = await flowResp.json();
  const resp = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { method: 'profile', csrf_token: findCsrfToken(flow.ui.nodes), traits },
    maxRedirects: 0,
  });
  return { status: resp.status(), body: await resp.json().catch(() => null) };
}

function usernameNodeMessages(body: any): string[] {
  const node = (body?.ui?.nodes ?? []).find((n: any) => n?.attributes?.name === 'traits.username');
  return (node?.messages ?? []).map((m: any) => String(m.text));
}

test.describe('Y — username is admin-only', () => {
  test('Y1/Y2 — a username change is refused and the stored username is unchanged', async ({
    browser,
    baseURL,
    kratosAdminURL,
  }) => {
    const username = `rename.refused.${Date.now()}`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Rename Refused',
      groups: [],
      kratosAdminURL,
    });
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);

      const page = await ctx.request.get(`${baseURL}/auth/settings`, { maxRedirects: 5 });
      expect(page.status()).toBe(200);
      const html = await page.text();
      expect(html).toMatch(/id="username-readonly"[^>]*readonly/);
      expect(html).toContain('Only an administrator can change your username.');

      const before = await storedTraits(kratosAdminURL, seeded.id);
      const { status, body } = await submitProfile(ctx, baseURL, { ...before, username: `rename.accepted.${Date.now()}` });
      expect(status, 'refused profile submission answers 400 with the flow').toBe(400);
      expect(usernameNodeMessages(body)).toContain(USERNAME_CHANGE_REFUSAL);

      const after = await storedTraits(kratosAdminURL, seeded.id);
      expect(after.username).toBe(username);
    } finally {
      await ctx.close();
    }
  });

  test('Y3 — an email change is saved and ends the other sessions', async ({ browser, baseURL, kratosAdminURL }) => {
    const username = `address.change.${Date.now()}`;
    const changed = `${username}.new@othala.test`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Address Change',
      groups: [],
      kratosAdminURL,
    });
    const other = await browser.newContext();
    const ctx = await browser.newContext();
    try {
      const since = Date.now();
      await loginViaJsonApi(other, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);

      const before = await storedTraits(kratosAdminURL, seeded.id);
      const { status } = await submitProfile(ctx, baseURL, { ...before, email: changed });
      expect(status, 'email change accepted').toBe(200);

      const after = await storedTraits(kratosAdminURL, seeded.id);
      expect(after.email).toBe(changed);
      expect(after.username).toBe(username);
      const addresses = (await readIdentity(kratosAdminURL, seeded.id)).verifiable_addresses as Array<{ value: string; verified: boolean }>;
      expect(addresses.find((a) => a.value === changed)?.verified, 'new address unverified').toBe(false);
      await waitForMessage(forRecipient(changed, since));

      const whoOther = await other.request.get(`${baseURL}/sessions/whoami`, { headers: { Accept: 'application/json' } });
      expect(whoOther.status(), 'the other session ended').toBe(401);
      const whoSelf = await ctx.request.get(`${baseURL}/sessions/whoami`, { headers: { Accept: 'application/json' } });
      expect(whoSelf.status(), 'the submitting session survives').toBe(200);
    } finally {
      await ctx.close();
      await other.close();
    }
  });

  test('Y4 — a refresh login by code mails the new address, not the old one', async ({ browser, baseURL, kratosAdminURL }) => {
    const username = `refresh.code.${Date.now()}`;
    const changed = `${username}.new@othala.test`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Refresh Code',
      groups: [],
      kratosAdminURL,
    });
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);
      const before = await storedTraits(kratosAdminURL, seeded.id);
      expect((await submitProfile(ctx, baseURL, { ...before, email: changed })).status).toBe(200);

      const refreshByCode = async (identifier: string) => {
        const flowResp = await ctx.request.get(`${baseURL}/self-service/login/browser?refresh=true`, {
          headers: { Accept: 'application/json' },
          maxRedirects: 5,
        });
        expect(flowResp.ok(), 'refresh login flow init').toBe(true);
        const flow = await flowResp.json();
        await ctx.request.post(flow.ui.action, {
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          data: { method: 'code', identifier, csrf_token: findCsrfToken(flow.ui.nodes) },
          maxRedirects: 0,
        });
      };

      const since = Date.now();
      await refreshByCode(changed);
      await waitForMessage(forRecipient(changed, since));

      const sinceOld = Date.now();
      await refreshByCode(seeded.email);
      await expect(waitForMessage(forRecipient(seeded.email, sinceOld), 5_000)).rejects.toThrow(/Timed out/);
    } finally {
      await ctx.close();
    }
  });
});

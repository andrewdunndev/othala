// ZE — an account with a password or passkey changes its email addresses only from a session whose newest
// sign-in used one; an account with neither keeps the code-only path.

import type { BrowserContext } from 'playwright-core';
import { test, expect } from '../fixtures';
import { createIdentityCodeOnly, createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken, loginViaJsonApi } from '../actions/login';
import { forRecipient, waitForMessage } from '../actions/mail';

const EMAIL_CHANGE_REFUSAL = 'To change an email address, sign in again with your passkey or password.';

async function storedTraits(kratosAdminURL: string, id: string) {
  return (await readIdentity(kratosAdminURL, id)).traits as { username: string; email: string; displayName?: string };
}

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

/** Sign in by emailed code: on the browser context's existing session this is a refresh login. */
async function codeLogin(ctx: BrowserContext, baseURL: string, identifier: string, refresh: boolean) {
  const flowResp = await ctx.request.get(`${baseURL}/self-service/login/browser${refresh ? '?refresh=true' : ''}`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  expect(flowResp.ok(), 'login flow init').toBe(true);
  const flow = await flowResp.json();
  const since = Date.now();
  const sent = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { method: 'code', identifier, csrf_token: findCsrfToken(flow.ui.nodes) },
    maxRedirects: 0,
  });
  const step2 = await sent.json();
  const { code } = await waitForMessage(forRecipient(identifier, since, /to log in/i));
  expect(code, 'code in the mail body').not.toBe('');
  const done = await ctx.request.post(step2.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { method: 'code', identifier, code, csrf_token: findCsrfToken(step2.ui.nodes) },
    maxRedirects: 5,
  });
  expect(done.status(), 'code accepted').toBeLessThan(400);
}

function emailNodeMessages(body: any): string[] {
  const node = (body?.ui?.nodes ?? []).find((n: any) => n?.attributes?.name === 'traits.email');
  return (node?.messages ?? []).map((m: any) => String(m.text));
}

function seedOpts(prefix: string, kratosAdminURL: string) {
  const username = `${prefix}.${Date.now()}`;
  return { email: `${username}@othala.test`, username, displayName: 'Email Change', groups: [], kratosAdminURL };
}

test.describe('ZE — email changes need a first-factor sign-in', () => {
  test('ZE1 — a password account refreshed by code cannot change its email', async ({ browser, baseURL, kratosAdminURL }) => {
    const seeded = await createIdentityWithPassword(seedOpts('ze.code', kratosAdminURL));
    const target = `ze.code.${Date.now()}.new@othala.test`;
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);
      await codeLogin(ctx, baseURL, seeded.email, true);

      const before = await storedTraits(kratosAdminURL, seeded.id);
      const since = Date.now();
      const { status, body } = await submitProfile(ctx, baseURL, { ...before, email: target });
      expect(status, 'refused profile submission answers 400 with the flow').toBe(400);
      expect(emailNodeMessages(body)).toContain(EMAIL_CHANGE_REFUSAL);

      expect((await storedTraits(kratosAdminURL, seeded.id)).email).toBe(seeded.email);
      await expect(waitForMessage(forRecipient(target, since, /verif/i), 5_000)).rejects.toThrow(/Timed out/);
    } finally {
      await ctx.close();
    }
  });

  test('ZE2 — a password account signed in with its password can change its email', async ({ browser, baseURL, kratosAdminURL }) => {
    const seeded = await createIdentityWithPassword(seedOpts('ze.owner', kratosAdminURL));
    const target = `ze.owner.${Date.now()}.new@othala.test`;
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);
      const before = await storedTraits(kratosAdminURL, seeded.id);
      expect((await submitProfile(ctx, baseURL, { ...before, email: target })).status).toBe(200);
      expect((await storedTraits(kratosAdminURL, seeded.id)).email).toBe(target);
    } finally {
      await ctx.close();
    }
  });

  test('ZE3 — an account with no password or passkey changes its email after a code sign-in', async ({ browser, baseURL, kratosAdminURL }) => {
    const seeded = await createIdentityCodeOnly(seedOpts('ze.keyless', kratosAdminURL));
    const target = `ze.keyless.${Date.now()}.new@othala.test`;
    const ctx = await browser.newContext();
    try {
      await codeLogin(ctx, baseURL, seeded.email, false);
      const before = await storedTraits(kratosAdminURL, seeded.id);
      expect((await submitProfile(ctx, baseURL, { ...before, email: target })).status).toBe(200);
      expect((await storedTraits(kratosAdminURL, seeded.id)).email).toBe(target);
    } finally {
      await ctx.close();
    }
  });
});

// ZS — a code request answers the same for an address with an account and one without.

import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';
import { findCsrfToken } from '../actions/login';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Flow = { ui: { action: string; nodes: any[]; messages?: Array<{ id: number }> }; state?: string };

async function requestCode(request: APIRequestContext, baseURL: string, flowKind: 'login' | 'recovery', email: string) {
  const init = await request.get(`${baseURL}/self-service/${flowKind}/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  expect(init.ok(), `${flowKind} flow init`).toBe(true);
  const flow = (await init.json()) as Flow;
  const data =
    flowKind === 'login'
      ? { method: 'code', identifier: email, csrf_token: findCsrfToken(flow.ui.nodes) }
      : { method: 'code', email, csrf_token: findCsrfToken(flow.ui.nodes) };
  const resp = await request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data,
    maxRedirects: 0,
  });
  const body = (await resp.json()) as Flow;
  return {
    status: resp.status(),
    state: body.state,
    messages: (body.ui?.messages ?? []).map((m) => m.id),
    fields: body.ui.nodes.map((n) => `${n.group}:${n.attributes?.name ?? n.type}`),
  };
}

for (const flowKind of ['login', 'recovery'] as const) {
  test(`ZS-${flowKind} — a known and an unknown address get the same status and response shape`, async ({ browser, baseURL, kratosAdminURL }) => {
    const username = `enum.${flowKind}.${Date.now()}`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Enumeration Probe',
      groups: [],
      kratosAdminURL,
    });
    const ctx = await browser.newContext();
    try {
      const known = await requestCode(ctx.request, baseURL!, flowKind, seeded.email);
      const unknown = await requestCode(ctx.request, baseURL!, flowKind, `nobody.${username}@othala.test`);
      expect(unknown, `ZS-${flowKind}: the answer must not tell whether the address has an account`).toEqual(known);
    } finally {
      await ctx.close();
    }
  });
}

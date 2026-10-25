// ZR — what a signed-in person can read and write about their own admin-managed access.

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { findCsrfToken, loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

test.describe('ZR — admin-managed access is not self-service', () => {
  test('ZR1 — the public session read omits metadata_admin, admin marker included', async ({ browser, baseURL, kratosAdminURL }) => {
    const username = `whoami.hidden.${Date.now()}`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Whoami Hidden',
      groups: ['family'],
      isAdmin: true,
      kratosAdminURL,
    });
    expect((await readIdentity(kratosAdminURL, seeded.id)).metadata_admin, 'the seed carries the marker').toBeTruthy();
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL!);
      const session = await getSession(ctx, baseURL!);
      expect(session?.active).toBe(true);
      expect(session?.identity, 'ZR1: whoami must not expose metadata_admin').not.toHaveProperty('metadata_admin');
    } finally {
      await ctx.close();
    }
  });

  test('ZR2 — a profile submission carrying metadata_admin leaves the stored groups unchanged', async ({ browser, baseURL, kratosAdminURL }) => {
    const username = `groups.fixed.${Date.now()}`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Groups Fixed',
      groups: ['family'],
      kratosAdminURL,
    });
    const before = await readIdentity(kratosAdminURL, seeded.id);
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL!);
      const flowResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, {
        headers: { Accept: 'application/json' },
        maxRedirects: 5,
      });
      expect(flowResp.ok(), 'settings flow init').toBe(true);
      const flow = await flowResp.json();
      const resp = await ctx.request.post(flow.ui.action, {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        data: {
          method: 'profile',
          csrf_token: findCsrfToken(flow.ui.nodes),
          traits: before.traits,
          metadata_admin: { groups: ['family', 'grafana-admin'], admin: true },
          'metadata_admin.groups': ['grafana-admin'],
        },
        maxRedirects: 0,
      });
      expect(resp.status(), 'ZR2: the self-service submission is accepted').toBe(200);
      const after = await readIdentity(kratosAdminURL, seeded.id);
      expect(after.metadata_admin, 'ZR2: admin-managed metadata is untouched by a self-service submission').toEqual(before.metadata_admin);
    } finally {
      await ctx.close();
    }
  });
});

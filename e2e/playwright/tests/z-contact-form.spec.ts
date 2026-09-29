/**
 * Z — the contact form is for signed-in members; the error page shows only known reasons.
 *
 *   Z1 — a POST without a session answers 401 and no mail is sent.
 *   Z2 — a signed-in POST answers 200 and the mail names the account
 *        (username and identity id).
 *   Z3 — an invalid submission from a signed-in member answers 400.
 *   Z4 — /auth/error does not echo an arbitrary reason value.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { searchMailBodies as mailBodies } from '../actions/mail';

test.describe('Z — contact form requires a session', () => {
  test('Z1 — no session: 401 and nothing sent', async ({ playwright, baseURL }) => {
    const marker = `z1-${Date.now()}`;
    const anon = await playwright.request.newContext();
    try {
      const resp = await anon.post(`${baseURL}/api/request`, {
        data: { name: 'Anon', type: 'access', message: `${marker} please grant access` },
      });
      expect(resp.status()).toBe(401);
    } finally {
      await anon.dispose();
    }
    expect(await mailBodies(marker)).toHaveLength(0);
  });

  test('Z2/Z3 — signed in: 200 with the account in the mail, 400 on bad input', async ({
    browser,
    baseURL,
    kratosAdminURL,
  }) => {
    const username = `contact.member.${Date.now()}`;
    const seeded = await createIdentityWithPassword({
      email: `${username}@othala.test`,
      username,
      displayName: 'Contact Member',
      groups: [],
      kratosAdminURL,
    });
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: seeded.email, password: TEST_PASSWORD }, baseURL);

      const bad = await ctx.request.post(`${baseURL}/api/request`, {
        data: { name: '', type: 'access', message: '' },
      });
      expect(bad.status()).toBe(400);

      const marker = `z2-${Date.now()}`;
      const ok = await ctx.request.post(`${baseURL}/api/request`, {
        data: { name: 'Contact Member', type: 'access', message: `${marker} please grant access` },
      });
      expect(ok.status()).toBe(200);

      const bodies = await mailBodies(marker);
      expect(bodies).toHaveLength(1);
      expect(bodies[0]).toContain(username);
      expect(bodies[0]).toContain(seeded.id);
    } finally {
      await ctx.close();
    }
  });
});

test('Z4 — /auth/error shows a known reason and drops an unknown one', async ({ playwright, baseURL }) => {
  const anon = await playwright.request.newContext();
  try {
    const known = await anon.get(`${baseURL}/auth/error?reason=not-admin`);
    expect(known.status()).toBe(403);
    expect(await known.text()).toContain('not-admin');

    const unknown = await anon.get(`${baseURL}/auth/error?reason=zz-arbitrary-text-91`);
    expect(unknown.status()).toBe(400);
    expect(await unknown.text()).not.toContain('zz-arbitrary-text-91');
  } finally {
    await anon.dispose();
  }
});

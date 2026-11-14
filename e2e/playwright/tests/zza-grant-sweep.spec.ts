// ZZA — the portal's grant sweep. A credential change made through the Kratos admin API fires no hook, so the sweep alone
// ends the person's app grants: they survive at first, and are gone within a sweep period with the marker moved on. A
// sign-in writes no credential field the fingerprint reads, so signing in by password or passkey ends nothing, across
// two sweep periods. The e2e overlay runs the sweep every 10 seconds (OTHALA_REVOKE_SWEEP_SECONDS in othala.env).

import type { Browser } from 'playwright-core';
import { test, expect, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { adminApi } from '../actions/kratos-admin';
import { loginViaJsonApi } from '../actions/login';
import { expectRefreshRefusedSoon, liveRefreshToken, refreshOnce } from '../actions/grants';
import { addPlatformAuthenticator, passkeySignIn, registerPasskey } from '../actions/passkey';

const SWEEP_MS = 10_000;
// A bcrypt hash of a password other than TEST_PASSWORD, as the seeds are written.
const OTHER_PASSWORD_HASH = '$2b$10$nR8fIEYD8ApzyZhaRYrYQOaAAbWbSLdci/oan7ExY1OLi2u4/jl0q';

type Marker = { fp: string; at: string };

async function marker(id: string): Promise<Marker | undefined> {
  return (await readIdentity(KRATOS_ADMIN_URL, id)).metadata_admin?.grants_revoked;
}

async function seedMember(tag: string) {
  const username = `${tag}.member.${Date.now()}`;
  return createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: `${tag.toUpperCase()} Member`,
    groups: ['everyone', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
}

/**
 * Waits until the identity carries a marker and one more sweep has passed over it. The seeds hold a bcrypt hash that Kratos
 * rewrites at the first password sign-in, and a passkey save is followed by a detached hook, so a mark taken before
 * either lands is replaced by the next pass; grants minted after this returns are not caught by that.
 */
async function settled(id: string): Promise<Marker> {
  await expect.poll(() => marker(id), { timeout: 3 * SWEEP_MS, message: 'the sweep stamps an identity that has no marker' }).toBeDefined();
  await new Promise((r) => setTimeout(r, SWEEP_MS + 2_000));
  return (await marker(id))!;
}

async function memberWithSignIn(browser: Browser, baseURL: string, tag: string) {
  const member = await seedMember(tag);
  const first = await browser.newContext();
  try {
    await loginViaJsonApi(first, { identifier: member.email, password: TEST_PASSWORD }, baseURL);
  } finally {
    await first.close();
  }
  return member;
}

test.describe('ZZA — the grant sweep', () => {
  test.setTimeout(180_000);

  test('ZZA1 — an admin-API password change ends the grants within a sweep period and moves the marker', async ({ browser, baseURL, hydraPublicURL }) => {
    const member = await memberWithSignIn(browser, baseURL!, 'zza1');
    await settled(member.id);
    const refreshToken = await liveRefreshToken({ browser, baseURL: baseURL!, hydraPublicURL, email: member.email });
    const stamped = (await marker(member.id))!;

    // No hook fires for an admin write. Metadata is carried over so the marker stays.
    const current = await readIdentity(KRATOS_ADMIN_URL, member.id);
    const put = await adminApi(KRATOS_ADMIN_URL, 'PUT', `identities/${member.id}`, {
      schema_id: current.schema_id,
      state: current.state,
      traits: current.traits,
      metadata_admin: current.metadata_admin,
      credentials: { password: { config: { hashed_password: OTHER_PASSWORD_HASH } } },
    });
    expect(put.ok, `admin credential write answered ${put.status}`).toBe(true);

    const rotated = await refreshOnce(browser, hydraPublicURL, refreshToken);
    expect(rotated, 'ZZA1: the grant survives the change until a sweep runs').not.toBeNull();

    await expect
      .poll(async () => (await marker(member.id))?.fp, { timeout: 3 * SWEEP_MS, message: 'ZZA1: the sweep moves the marker to the new fingerprint' })
      .not.toBe(stamped.fp);
    expect(Date.parse((await marker(member.id))!.at), 'ZZA1: the marker is newer').toBeGreaterThan(Date.parse(stamped.at));
    await expectRefreshRefusedSoon(browser, hydraPublicURL, rotated!, 'ZZA1: after the sweep', 3 * SWEEP_MS);
  });

  test('ZZA2 — signing in by password and by passkey ends nothing across two sweep periods', async ({ browser, baseURL, hydraPublicURL }) => {
    const member = await memberWithSignIn(browser, baseURL!, 'zza2');
    const ctx = await browser.newContext();
    try {
      await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
      const page = await ctx.newPage();
      await addPlatformAuthenticator(ctx, page);
      await registerPasskey(page, baseURL!);
      const stamped = await settled(member.id);
      const refreshToken = await liveRefreshToken({ browser, baseURL: baseURL!, hydraPublicURL, email: member.email });

      const again = await browser.newContext();
      try {
        await loginViaJsonApi(again, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
      } finally {
        await again.close();
      }
      await passkeySignIn(page, `${baseURL}/self-service/login/browser?refresh=true&return_to=${encodeURIComponent(`${baseURL}/auth/settings`)}`);

      await new Promise((r) => setTimeout(r, 2 * SWEEP_MS + 5_000));
      const kept = await refreshOnce(browser, hydraPublicURL, refreshToken);
      expect(kept, 'ZZA2: the grant survives two sweep periods after the sign-ins').not.toBeNull();
      expect((await marker(member.id))?.fp, 'ZZA2: the marker did not move').toBe(stamped.fp);
    } finally {
      await ctx.close();
    }
  });
});

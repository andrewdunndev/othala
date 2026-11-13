// ZU — admin recovery Step D: a recovered session is first-factor only, so settings asks for the second factor the
// admin still holds until the console deletes it (docs/runbooks/admin-recovery.md).

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { getSession } from '../actions/session';

async function adminApi(kratosAdminURL: string, method: string, path: string, body?: unknown): Promise<Response> {
  return fetch(`${kratosAdminURL}/admin/${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test('ZU1 — recovery lands at the first factor; settings opens only after the second factor is deleted', async ({
  browser,
  baseURL,
  kratosAdminURL,
  page,
}) => {
  const suffix = Date.now();
  const seeded = await createIdentityWithPassword({
    email: `zu1.admin.${suffix}@othala.test`,
    username: `zu1.admin.${suffix}`,
    displayName: 'ZU1 Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  // The admin holds an authenticator app; the phone is then "lost".
  const enrol = await adminAal2Context({ browser, email: seeded.email, password: TEST_PASSWORD, baseURL: baseURL! });
  await enrol.close();
  const stored = await readIdentity(kratosAdminURL, seeded.id, ['totp']);
  expect(stored.credentials?.totp, 'ZU1: the app is enrolled before recovery').toBeTruthy();

  // Step 1: clear the marker, so the recovery gate lets the flow through.
  const cleared = await adminApi(kratosAdminURL, 'PATCH', `identities/${seeded.id}`, [{ op: 'remove', path: '/metadata_admin/admin' }]);
  expect(cleared.ok, 'ZU1: the marker is cleared').toBe(true);

  // Step 3: issue the code and redeem link and code in a fresh browser.
  const issued = await adminApi(kratosAdminURL, 'POST', 'recovery/code', { identity_id: seeded.id, expires_in: '1h' });
  expect(issued.ok, 'ZU1: the recovery code is issued').toBe(true);
  const { recovery_link: link, recovery_code: code } = (await issued.json()) as { recovery_link: string; recovery_code: string };
  await page.goto(link, { waitUntil: 'networkidle' });
  await page.locator('input[name="code"]').fill(code);
  await page.locator('form:has(input[name="code"]) button[name="method"]').click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/recovery'), { timeout: 15_000 });

  const ctx = page.context();
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'ZU1: the recovered session is first factor only').toBe('aal1');

  // While the app exists, settings sends the admin to the second-factor sign-in.
  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  expect(new URL(page.url()).pathname, 'ZU1: settings redirects to sign-in while the app exists').toBe('/auth/login');
  const flowId = new URL(page.url()).searchParams.get('flow');
  expect(flowId, 'ZU1: the sign-in flow id').toBeTruthy();
  const flow = await (await ctx.request.get(`${baseURL}/self-service/login/flows?id=${flowId}`, { headers: { Accept: 'application/json' } })).json();
  expect(flow.requested_aal, 'ZU1: the sign-in asks for the second factor').toBe('aal2');

  // Step 2: delete the second factor the admin can no longer answer (the backup-code credential is absent here).
  const deleted = await adminApi(kratosAdminURL, 'DELETE', `identities/${seeded.id}/credentials/totp`);
  expect(deleted.status, 'ZU1: the app credential is deleted').toBe(204);
  const noCodes = await adminApi(kratosAdminURL, 'DELETE', `identities/${seeded.id}/credentials/lookup_secret`);
  expect([204, 404], 'ZU1: an absent backup-code credential is not an error that matters').toContain(noCodes.status);

  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  expect(new URL(page.url()).pathname, 'ZU1: settings opens at the first factor').toBe('/auth/settings');
  await expect(page.locator('button[name="passkey_register_trigger"]').first(), 'ZU1: passkey enrolment is offered').toBeVisible({ timeout: 10_000 });

  // Step 5: restore the marker, and the identity matches what was read first.
  const restored = await adminApi(kratosAdminURL, 'PATCH', `identities/${seeded.id}`, [{ op: 'add', path: '/metadata_admin/admin', value: true }]);
  expect(restored.ok, 'ZU1: the marker is restored').toBe(true);
  const after = await readIdentity(kratosAdminURL, seeded.id);
  expect(after.metadata_admin, 'ZU1: the metadata matches what was read before').toEqual(stored.metadata_admin);
});

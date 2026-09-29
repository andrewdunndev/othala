/**
 * U — D1: admin-triggered invite email delivers a code via the Kratos
 * courier, and the two-channel contract holds (code only, no embedded link).
 *
 * D1 (the standing mechanism is recorded as the "D1 addendum" under "No
 * password ever transits a channel" in DECISIONS.md) adds a second delivery
 * path alongside the existing "Issue enrollment link + code" hand-off: an
 * admin can click
 * "Send invite email" on /admin/users/<id> and Kratos's OWN courier — not
 * the portal — sends the invitee a recovery CODE. `sendInviteRecoveryEmail`
 * (portal/src/lib/kratos.ts) drives Kratos's self-service recovery flow
 * server-side for the identity's on-file address.
 *
 * U1 asserts the FULL path a real operator exercises: a real AAL2 admin
 * browser session opens the rendered user page (so Referrer-Policy and the
 * rest of middleware.ts's actual headers are in play — see
 * r-admin-post-origin.spec.ts, work item #5), clicks the real button, and
 * the resulting mailpit message:
 *   (a) is addressed to the invitee,
 *   (b) carries a 6-digit recovery code,
 *   (c) does NOT carry the code embedded in a URL — the "no password ever
 *       transits a channel" two-channel invariant requires that this
 *       message alone can never be the complete credential (link + code).
 *
 * U2 and U3 cover the two refusal branches added by the D1 addendum's
 * best-practice bundle (adversarial review; DECISIONS.md):
 *   - U2: the target carries the admin marker. shouldRefuseRecovery
 *     (src/lib/access.ts) refuses before Kratos is ever asked — same
 *     HIGH-3 gate as issue-recovery — and mailpit must receive nothing.
 *   - U3: the confirm-address field does not byte-equal the target's
 *     on-file email. confirmsInviteAddress (src/lib/access.ts) refuses
 *     server-side before Kratos is ever asked, and mailpit must receive
 *     nothing.
 *
 * Cookie-jar / mailpit conventions mirrored from j-recovery-flow.spec.ts and
 * r-admin-post-origin.spec.ts: a per-run unique invitee email (so retries and
 * prior runs never collide on a stale mailpit message), and an `afterMs`
 * guard on the mailpit poll (waitForInviteEmail for the positive case,
 * assertNoInviteEmail for U2/U3's negative case).
 *
 * Live-stack requirements:
 *   - Kratos recovery flow enabled with `use: code` (kratos.yml).
 *   - Mailpit reachable at mailpit:8025 on the compose net.
 *   - The Othala portal running with the send-invite-email action wired.
 */

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { listMail, waitForMessage, forRecipient } from '../actions/mail';

// Negative assertion: the refusal branches short-circuit before Kratos, so a
// short window suffices; U1 proves delivery within the longer timeout.
async function assertNoInviteEmail(toAddress: string, afterMs: number): Promise<void> {
  const deadline = Date.now() + 4_000;
  while (Date.now() < deadline) {
    const hit = (await listMail()).find(forRecipient(toAddress, afterMs, /recover/i));
    if (hit) throw new Error(`unexpected recovery message for ${toAddress} (subject: "${hit.subject}")`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

test('U1 — admin "Send invite email" delivers a code-only message via the Kratos courier', async ({
  browser,
  baseURL,
}) => {
  const uniqueSuffix = Date.now();
  const actingAdmin = await createIdentityWithPassword({
    email: `u1.acting-admin.${uniqueSuffix}@othala.test`,
    username: `u1.acting.admin.${uniqueSuffix}`,
    displayName: 'U1 Acting Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  const invitee = await createIdentityWithPassword({
    email: `u1.invitee.${uniqueSuffix}@othala.test`,
    username: `u1.invitee.${uniqueSuffix}`,
    displayName: 'U1 Invitee',
    groups: [],
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  console.log('[U1] acting admin:', actingAdmin.id, '| invitee:', invitee.id, invitee.email);

  const ctx = await adminAal2Context({
    browser,
    email: actingAdmin.email,
    password: TEST_PASSWORD,
    baseURL: baseURL!,
  });

  try {
    const startTime = Date.now();
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${invitee.id}`;

    // Real GET navigation — response carries the actual middleware.ts
    // security headers, exactly like r-admin-post-origin.spec.ts (R1).
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'U1: admin page must render the invitee identity').toContainText('u1.invitee');

    // Click the real button — a REAL <form method="post"> submit, Chromium
    // computing Origin from the page's actual response headers.
    const sendBtn = page.getByRole('button', { name: 'Send invite email' });
    await expect(sendBtn, 'U1: "Send invite email" button must be visible').toBeVisible({ timeout: 10_000 });

    // D-addendum best-practice bundle: send-time address confirmation is a
    // required, server-checked field on this same form now — re-type the
    // invitee's own address so U1 continues to exercise the happy path.
    await page.locator('input[name="confirmEmail"]').fill(invitee.email);

    const [postResp] = await Promise.all([
      page.waitForResponse((r) => r.url() === targetUrl && r.request().method() === 'POST'),
      sendBtn.click(),
    ]);
    console.log('[U1] send-invite-email POST →', postResp.status());

    expect(postResp.status(), 'U1: invite-email POST must not 403 (CSRF/origin gate)').not.toBe(403);
    expect(postResp.status(), 'U1: invite-email POST must succeed (200, same-page re-render)').toBe(200);

    await expect(
      page.getByText(/invite email sent/i),
      'U1: page must show the "Invite email sent" success notice',
    ).toBeVisible();

    // Ground truth: the message actually landed in the courier's relay.
    const { code, body, id: messageId } = await waitForMessage(forRecipient(invitee.email, startTime, /recover/i));
    console.log('[U1] invite email received, message id:', messageId, 'code:', code);

    expect(code, 'U1: the delivered message must carry a 6-digit recovery code').toMatch(/^\d{6}$/);

    // The two-channel invariant (DECISIONS.md "No password ever transits a
    // channel"): this message alone must never be the complete credential.
    // A magic-link recovery template would embed the code in the URL as
    // `?code=<code>` (or similar) — assert that shape is absent here.
    expect(
      body.includes(`code=${code}`),
      `U1: the invite email must carry the code WITHOUT it also being embedded in a link ` +
        `(code=${code} found in body) — that would collapse the two required channels into one`,
    ).toBe(false);

    console.log('[U1] PASS — invite email delivered a code-only message for', invitee.email);
  } finally {
    await ctx.close();
  }
});

test('U2 — "Send invite email" against an admin-marked target is refused console-only, and mailpit receives nothing', async ({
  browser,
  baseURL,
}) => {
  // Same HIGH-3 gate as issue-recovery (shouldRefuseRecovery, src/lib/access.ts):
  // the target carries metadata_admin.admin===true, so the action handler
  // refuses BEFORE the confirm-address check and BEFORE sendInviteRecoveryEmail
  // is ever called. The confirm field is still filled with the CORRECT address
  // so the only thing under test is the admin-marked refusal, not a mismatch.
  const uniqueSuffix = Date.now();
  const actingAdmin = await createIdentityWithPassword({
    email: `u2.acting-admin.${uniqueSuffix}@othala.test`,
    username: `u2.acting.admin.${uniqueSuffix}`,
    displayName: 'U2 Acting Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  const adminTarget = await createIdentityWithPassword({
    email: `u2.admin-target.${uniqueSuffix}@othala.test`,
    username: `u2.admin.target.${uniqueSuffix}`,
    displayName: 'U2 Admin Target',
    groups: [],
    isAdmin: true,
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  console.log('[U2] acting admin:', actingAdmin.id, '| admin target:', adminTarget.id, adminTarget.email);

  const ctx = await adminAal2Context({
    browser,
    email: actingAdmin.email,
    password: TEST_PASSWORD,
    baseURL: baseURL!,
  });

  try {
    const startTime = Date.now();
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${adminTarget.id}`;

    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'U2: admin page must render the admin-target identity').toContainText('u2.admin.target');

    const sendBtn = page.getByRole('button', { name: 'Send invite email' });
    await expect(sendBtn, 'U2: "Send invite email" button must be visible').toBeVisible({ timeout: 10_000 });
    await page.locator('input[name="confirmEmail"]').fill(adminTarget.email);

    const [postResp] = await Promise.all([
      page.waitForResponse((r) => r.url() === targetUrl && r.request().method() === 'POST'),
      sendBtn.click(),
    ]);
    console.log('[U2] send-invite-email POST →', postResp.status());

    expect(postResp.status(), 'U2: refusal is a normal same-page re-render, not a 403').toBe(200);

    await expect(
      page.getByText(/admin recovery is console-only/i),
      'U2: page must show the console-only refusal notice',
    ).toBeVisible();

    // Ground truth: the refusal happened before Kratos was ever asked.
    await assertNoInviteEmail(adminTarget.email, startTime);

    console.log('[U2] PASS — admin-marked target refused console-only; mailpit received nothing');
  } finally {
    await ctx.close();
  }
});

test('U3 — "Send invite email" with a mismatched confirm-address is refused, and mailpit receives nothing', async ({
  browser,
  baseURL,
}) => {
  // Best-practice bundle (D1 addendum, DECISIONS.md): send-time address
  // confirmation, server-enforced. A non-admin target so the ONLY thing
  // under test is confirmsInviteAddress rejecting the mismatch — the
  // admin-marked gate never enters into it.
  const uniqueSuffix = Date.now();
  const actingAdmin = await createIdentityWithPassword({
    email: `u3.acting-admin.${uniqueSuffix}@othala.test`,
    username: `u3.acting.admin.${uniqueSuffix}`,
    displayName: 'U3 Acting Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  const invitee = await createIdentityWithPassword({
    email: `u3.invitee.${uniqueSuffix}@othala.test`,
    username: `u3.invitee.${uniqueSuffix}`,
    displayName: 'U3 Invitee',
    groups: [],
    kratosAdminURL: process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434',
  });
  console.log('[U3] acting admin:', actingAdmin.id, '| invitee:', invitee.id, invitee.email);

  const ctx = await adminAal2Context({
    browser,
    email: actingAdmin.email,
    password: TEST_PASSWORD,
    baseURL: baseURL!,
  });

  try {
    const startTime = Date.now();
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${invitee.id}`;

    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'U3: admin page must render the invitee identity').toContainText('u3.invitee');

    const sendBtn = page.getByRole('button', { name: 'Send invite email' });
    await expect(sendBtn, 'U3: "Send invite email" button must be visible').toBeVisible({ timeout: 10_000 });
    // Deliberately wrong — one character off from the invitee's real address.
    await page.locator('input[name="confirmEmail"]').fill(`wrong.${invitee.email}`);

    const [postResp] = await Promise.all([
      page.waitForResponse((r) => r.url() === targetUrl && r.request().method() === 'POST'),
      sendBtn.click(),
    ]);
    console.log('[U3] send-invite-email POST →', postResp.status());

    expect(postResp.status(), 'U3: refusal is a normal same-page re-render, not a 403').toBe(200);

    await expect(
      page.getByText(/confirmation address does not match/i),
      'U3: page must show the confirm-address mismatch notice',
    ).toBeVisible();

    // Ground truth: the mismatch was refused before Kratos was ever asked.
    await assertNoInviteEmail(invitee.email, startTime);

    console.log('[U3] PASS — mismatched confirm-address refused; mailpit received nothing');
  } finally {
    await ctx.close();
  }
});

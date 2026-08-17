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
 * Cookie-jar / mailpit conventions mirrored from j-recovery-flow.spec.ts and
 * r-admin-post-origin.spec.ts: a per-run unique invitee email (so retries and
 * prior runs never collide on a stale mailpit message), and an `afterMs`
 * guard on the mailpit poll.
 *
 * Live-stack requirements:
 *   - Kratos recovery flow enabled with `use: code` (kratos.yml).
 *   - Mailpit reachable at mailpit:8025 on the compose net.
 *   - The Othala portal running with the send-invite-email action wired.
 */

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';

const MAILPIT_API = process.env.MAILPIT_API ?? 'http://mailpit:8025';
const MAIL_TIMEOUT_MS = 15_000;
const MAIL_POLL_INTERVAL_MS = 500;

/**
 * Poll mailpit for the invite-email message sent to `toAddress`.
 * Returns { messageId, code, body } once it arrives, throws on timeout.
 * Mirrors waitForRecoveryCode in j-recovery-flow.spec.ts.
 */
async function waitForInviteEmail(
  toAddress: string,
  afterMs: number,
): Promise<{ messageId: string; code: string; body: string }> {
  const deadline = Date.now() + MAIL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const resp = await fetch(`${MAILPIT_API}/api/v1/messages`);
    if (!resp.ok) throw new Error(`mailpit /api/v1/messages returned ${resp.status}`);
    const data = (await resp.json()) as {
      messages?: Array<{
        ID: string;
        Subject: string;
        To: Array<{ Address: string }>;
        Created: string; // mailpit v1 API field name (not `Date`)
      }>;
    };
    const candidates = (data.messages ?? [])
      .filter(
        (m) =>
          m.To.some((t) => t.Address.toLowerCase() === toAddress.toLowerCase()) &&
          /recover/i.test(m.Subject) &&
          new Date(m.Created).getTime() >= afterMs - 5_000,
      )
      .sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());

    const match = candidates[0];
    if (match) {
      const msgResp = await fetch(`${MAILPIT_API}/api/v1/message/${match.ID}`);
      if (!msgResp.ok) throw new Error(`mailpit message fetch returned ${msgResp.status}`);
      const msgData = (await msgResp.json()) as { Text?: string; HTML?: string };
      const body = msgData.Text ?? msgData.HTML ?? '';
      const codeMatch = body.match(/\b(\d{6})\b/);
      if (codeMatch) {
        return { messageId: match.ID, code: codeMatch[1], body };
      }
    }
    await new Promise((r) => setTimeout(r, MAIL_POLL_INTERVAL_MS));
  }
  throw new Error(`Timed out waiting for invite email to ${toAddress} after ${MAIL_TIMEOUT_MS}ms`);
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
    const { code, body, messageId } = await waitForInviteEmail(invitee.email, startTime);
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

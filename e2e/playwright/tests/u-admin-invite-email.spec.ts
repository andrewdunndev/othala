// U — an admin invite delivers a code-only email through the Kratos courier (no embedded link).

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { HOUSEHOLD, listMail, waitForMessage, forRecipient } from '../actions/mail';
import { csrfTokenFor, postAdminAction } from '../actions/admin-post';

const INVITE_SUBJECT = /invited|recover/i;

async function assertNoInviteEmail(toAddress: string, afterMs: number): Promise<void> {
  const deadline = Date.now() + 4_000;
  while (Date.now() < deadline) {
    const hit = (await listMail()).find(forRecipient(toAddress, afterMs, INVITE_SUBJECT));
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

    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'U1: admin page must render the invitee identity').toContainText('U1 Invitee');

    await page.locator('summary', { hasText: 'Email a code instead' }).click();
    const sendBtn = page.getByRole('button', { name: 'Send invite email' });
    await expect(sendBtn, 'U1: "Send invite email" button must be visible').toBeVisible({ timeout: 10_000 });

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

    const { code, subject, body, id: messageId } = await waitForMessage(forRecipient(invitee.email, startTime, INVITE_SUBJECT));
    console.log('[U1] invite email received, message id:', messageId, 'code:', code);

    expect(code, 'U1: the delivered message must carry a 6-digit recovery code').toMatch(/^\d{6}$/);
    expect(subject, 'U1: the subject says it is an invite to the household').toContain(`invited to ${HOUSEHOLD}`);
    expect(body, 'U1: the body says how to set up the account').toContain(`invited to ${HOUSEHOLD}. To set up your account`);

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

test('U2 — an admin-marked target is offered no invite email or setup link, a hand-made POST is refused server-side, and mailpit receives nothing', async ({
  browser,
  baseURL,
}) => {
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
  const bystander = await createIdentityWithPassword({
    email: `u2.bystander.${uniqueSuffix}@othala.test`,
    username: `u2.bystander.${uniqueSuffix}`,
    displayName: 'U2 Bystander',
    groups: [],
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
    await expect(page.locator('h1'), 'U2: admin page must render the admin-target identity').toContainText('U2 Admin Target');

    // The page withholds email and setup-link actions from an admin-marked target and says so.
    await expect(page.getByText(/A household admin cannot be sent a setup link here/i), 'U2: the no-setup-link note is shown').toBeVisible();
    await expect(page.getByRole('button', { name: 'Send invite email' }), 'U2: no invite email action is offered').toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Get setup link' }), 'U2: no setup link action is offered').toHaveCount(0);

    // The server guard stands on its own: a token from a non-admin's page, posted at the admin target by hand.
    await page.goto(`${baseURL}/admin/users/${bystander.id}`, { waitUntil: 'networkidle' });
    const token = await csrfTokenFor(page, 'send-invite-email');
    expect(token, 'U2: the bystander page carries an invite-email token').not.toBe('');
    const resp = await postAdminAction(ctx, baseURL!, adminTarget.id, {
      csrf_token: token,
      action: 'send-invite-email',
      confirmEmail: adminTarget.email,
    });
    expect(resp.status(), 'U2: the refusal is a normal re-render, not a 403').toBe(200);
    expect(await resp.text(), 'U2: the server refuses admin recovery by email').toMatch(/setup link for an admin cannot be made here/);

    await assertNoInviteEmail(adminTarget.email, startTime);

    console.log('[U2] PASS — admin-marked target offered no setup link; mailpit received nothing');
  } finally {
    await ctx.close();
  }
});

test('U3 — "Send invite email" with a mismatched confirm-address is refused, and mailpit receives nothing', async ({
  browser,
  baseURL,
}) => {
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
    await expect(page.locator('h1'), 'U3: admin page must render the invitee identity').toContainText('U3 Invitee');

    await page.locator('summary', { hasText: 'Email a code instead' }).click();
    const sendBtn = page.getByRole('button', { name: 'Send invite email' });
    await expect(sendBtn, 'U3: "Send invite email" button must be visible').toBeVisible({ timeout: 10_000 });
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

    await assertNoInviteEmail(invitee.email, startTime);

    console.log('[U3] PASS — mismatched confirm-address refused; mailpit received nothing');
  } finally {
    await ctx.close();
  }
});

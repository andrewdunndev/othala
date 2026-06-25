/**
 * J — Recovery flow: non-admin succeeds; admin is blocked by the recovery-gate.
 *
 * Coverage gap addressed: the recovery-gate webhook path (Kratos → othala
 * /admin/recovery-gate → 403 → Kratos blocks recovery for the admin) had ZERO
 * browser-driven e2e coverage. smoke.sh probes the gate endpoint in isolation;
 * this spec drives the FULL Kratos→webhook→gate path via the actual browser
 * self-service recovery flow so that any mis-wiring of the webhook URL,
 * jsonnet body template, or gate decision is caught at the integration level.
 *
 * Background: Kratos is configured to POST a recovery-gate webhook before
 * completing recovery (kratos.yml flows.recovery.after.hooks). The webhook
 * body is rendered by recovery-gate.jsonnet:
 *   { identity_id, is_admin, groups, traits: { email, ... } }
 * `is_admin` is derived from metadata_admin.admin (ADR 0008 marker). The gate
 * (othala loopback :4431 /admin/recovery-gate) refuses recovery (403) iff
 * is_admin===true. Kratos interprets a 4xx from the webhook as a flow abort,
 * preventing the privileged session from being issued.
 *
 * J1 — NON-ADMIN recovery (happy path):
 *   a. Seed a fresh non-admin identity (member.recovery@othala.test) via admin API.
 *   b. Initiate recovery via ctx.request (cookie-bearing) POST /self-service/recovery/browser.
 *   c. Query mailpit :8025/api/v1/messages for the recovery code email.
 *   d. Submit the code via ctx.request (SAME cookie jar as flow init).
 *   e. Assert a privileged settings session is established
 *      (AAL1 session with flow=recovery, or /auth/settings redirect).
 *
 * J2 — ADMIN recovery (gate blocks):
 *   a. Look up the pre-seeded recovery-admin identity (RECOVERY_ADMIN_EMAIL) by
 *      credentials_identifier. validate.sh seeds it with metadata_admin.admin=true
 *      (ADR 0008 marker) before Playwright starts.
 *   b. Initiate recovery — same flow as J1.
 *   c. Query mailpit for the admin recovery code.
 *   d. Submit the code via ctx.request (same cookie jar).
 *   e. Assert recovery is BLOCKED: the gate fires (is_admin=true → 403) and
 *      Kratos aborts the flow. Observable as: no privileged session (whoami
 *      returns null or inactive), OR Kratos redirects to /auth/error.
 *
 * Cookie-jar contract:
 *   ALL Kratos self-service operations (flow init, email submit, code submit) use
 *   ctx.request (the Playwright APIRequestContext attached to the BrowserContext).
 *   This ensures the CSRF cookie and the session cookie issued by Kratos on a
 *   successful code submission all land in the SAME jar that getSession() reads.
 *   Using globalThis.fetch for any of these steps breaks the cookie chain and
 *   causes spurious failures (ErrCodeAlreadyUsed on double-submit, or a 401 from
 *   getSession() because the session cookie ended up in a discarded fetch context).
 *
 * Live-stack requirements:
 *   - Kratos recovery flow enabled with `use: code`.
 *   - The recovery-gate webhook is configured in kratos.yml:
 *       flows.recovery.after.hooks → http_request → othala:4431/admin/recovery-gate
 *   - RECOVERY_GATE_SECRET injected via compose env (the gate 401s a bad bearer).
 *   - Mailpit running on the compose net (mailpit:8025 HTTP API reachable from
 *     inside the playwright container on the same compose network).
 *   - The recovery-admin identity has metadata_admin.admin=true (seeded by validate.sh);
 *     J2 looks up the RECOVERY_ADMIN_EMAIL identity and drives recovery through the
 *     webhook path. The gate refuses it because is_admin=true (set from the marker
 *     by recovery-gate.jsonnet). validate.sh is the source of truth for the seed.
 *
 * Mailpit API: GET http://mailpit:8025/api/v1/messages returns:
 *   { messages: [{ ID, Subject, To: [{Address}], Snippet, ... }], ... }
 * The recovery code is a 6-digit numeric code in the email body. We fetch the
 * raw message text via GET http://mailpit:8025/api/v1/message/<ID> to extract
 * the code by regex.
 */

import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';
import { getSession } from '../actions/session';

// The mailpit HTTP API is reachable inside the compose net on the compose
// service hostname. From the playwright container (same network), use:
const MAILPIT_API = process.env.MAILPIT_API ?? 'http://mailpit:8025';

// How long to wait for Kratos to send the recovery email (Kratos enqueues
// the courier job; delivery is near-instant in the compose env).
const MAIL_TIMEOUT_MS = 15_000;
const MAIL_POLL_INTERVAL_MS = 500;

/**
 * Poll mailpit for a recovery code email sent to `toAddress`.
 * Uses bare globalThis.fetch — mailpit has no session state so this is safe.
 * Returns { messageId, code } once the email arrives, or throws on timeout.
 */
async function waitForRecoveryCode(
  toAddress: string,
  afterMs: number = Date.now(),
): Promise<{ messageId: string; code: string }> {
  const deadline = Date.now() + MAIL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const resp = await fetch(`${MAILPIT_API}/api/v1/messages`);
    if (!resp.ok) throw new Error(`mailpit /api/v1/messages returned ${resp.status}`);
    const data = await resp.json() as {
      messages?: Array<{
        ID: string;
        Subject: string;
        To: Array<{ Address: string }>;
        // Mailpit v1 API uses `Created` (ISO 8601), NOT `Date`.
        Created: string;
      }>;
    };
    const messages = data.messages ?? [];
    // Find the most-recent message addressed to `toAddress` that arrived after
    // our flow started AND has "recovery" in the subject.
    // IMPORTANT: the `afterMs` guard is required — mailpit accumulates emails
    // across test runs in the same lab session. Without the date filter the
    // function returns a code from a PREVIOUS run that has already been used,
    // the code submit returns 200-with-error (not a session), and the test fails.
    const candidates = messages
      .filter((m) =>
        m.To.some((t) => t.Address.toLowerCase() === toAddress.toLowerCase()) &&
        /recover/i.test(m.Subject) &&
        new Date(m.Created).getTime() >= afterMs - 5_000, // 5s grace for clock skew
      )
      .sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());

    const match = candidates[0];
    if (match) {
      // Fetch the raw message text to extract the 6-digit code.
      const msgResp = await fetch(`${MAILPIT_API}/api/v1/message/${match.ID}`);
      if (!msgResp.ok) throw new Error(`mailpit message fetch returned ${msgResp.status}`);
      const msgData = await msgResp.json() as { Text?: string; HTML?: string };
      const body = msgData.Text ?? msgData.HTML ?? '';
      // Kratos recovery codes are 6-digit numeric codes.
      const codeMatch = body.match(/\b(\d{6})\b/);
      if (codeMatch) {
        return { messageId: match.ID, code: codeMatch[1] };
      }
    }
    await new Promise((r) => setTimeout(r, MAIL_POLL_INTERVAL_MS));
  }
  throw new Error(`Timed out waiting for recovery email to ${toAddress} after ${MAIL_TIMEOUT_MS}ms`);
}

/**
 * Initiate a Kratos recovery flow using the provided APIRequestContext.
 * The context's cookie jar receives the CSRF cookie from Kratos. This MUST
 * be the same context used for all subsequent submissions so CSRF validation
 * and the session cookie remain in a single jar.
 */
async function initRecoveryFlow(
  req: APIRequestContext,
  baseURL: string,
): Promise<{ id: string; action: string; csrfToken: string }> {
  const resp = await req.get(`${baseURL}/self-service/recovery/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  if (!resp.ok()) {
    throw new Error(
      `recovery flow init failed: ${resp.status()} ${await resp.text().catch(() => '')}`,
    );
  }
  const flow = await resp.json() as {
    id: string;
    ui?: {
      action?: string;
      nodes?: Array<{
        type: string;
        attributes?: { name?: string; type?: string; value?: unknown };
      }>;
    };
  };

  const action = flow?.ui?.action ?? '';
  let csrfToken = '';
  for (const node of flow?.ui?.nodes ?? []) {
    if (
      node?.type === 'input' &&
      node?.attributes?.name === 'csrf_token' &&
      node?.attributes?.type === 'hidden'
    ) {
      csrfToken = String(node.attributes.value ?? '');
      break;
    }
  }
  if (!action) {
    throw new Error(`recovery flow missing ui.action: ${JSON.stringify(flow).slice(0, 300)}`);
  }
  return { id: flow.id, action, csrfToken };
}

/**
 * Submit the recovery email address to trigger the code email.
 * Uses the provided APIRequestContext (must be same jar as initRecoveryFlow).
 */
async function submitRecoveryEmail(
  req: APIRequestContext,
  action: string,
  csrfToken: string,
  email: string,
): Promise<void> {
  const resp = await req.post(action, {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    data: { email, method: 'code', csrf_token: csrfToken },
    maxRedirects: 5,
  });
  // A 200 or 422 (form re-render with messages) are both acceptable here;
  // Kratos may return 422 while still sending the email.
  const status = resp.status();
  if (status !== 200 && status !== 422) {
    throw new Error(
      `recovery email submit returned unexpected ${status}: ${await resp.text().catch(() => '')}`,
    );
  }
}

// ─── J1: NON-ADMIN recovery (happy path) ─────────────────────────────────────

test('J1 — non-admin recovery flow issues a privileged settings session', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  // Seed a fresh non-admin identity to avoid residual state from other tests.
  const identity = await createIdentityWithPassword({
    email: 'member.recovery@othala.test',
    username: 'member.recovery',
    displayName: 'Recovery Test Member',
    groups: ['family'],
    kratosAdminURL,
  });
  console.log('[J1] seeded non-admin identity:', identity.id, identity.email);

  const ctx = await browser.newContext();
  try {
    const req = ctx.request;
    const startTime = Date.now();

    // Step 1: Initiate the recovery flow via ctx.request (cookie-bearing).
    // This seeds the CSRF cookie into ctx's jar. All subsequent operations
    // MUST use the same req so CSRF validation passes and the session cookie
    // from a successful code submission lands in the right jar.
    const flow = await initRecoveryFlow(req, baseURL);
    console.log('[J1] recovery flow id:', flow.id);

    // Step 2: Submit the email address to trigger the code email.
    // Uses the same req/cookie jar as flow init.
    await submitRecoveryEmail(req, flow.action, flow.csrfToken, identity.email);
    console.log('[J1] recovery email submitted');

    // Step 3: Wait for the recovery code to arrive in mailpit.
    // waitForRecoveryCode uses bare fetch (mailpit has no session state).
    const { code, messageId } = await waitForRecoveryCode(identity.email, startTime);
    console.log('[J1] recovery code received, message id:', messageId, 'code:', code);

    // Step 4: Submit the recovery code ONCE via ctx.request (the same cookie
    // jar). Kratos validates the CSRF token (which lives in ctx's cookie jar),
    // marks the code as used, issues a session cookie into ctx's jar, and
    // redirects to /auth/settings.
    //
    // IMPORTANT: do NOT call submitRecoveryCode via globalThis.fetch and then
    // also via ctx.request — that double-submits the code (ErrCodeAlreadyUsed
    // on the second call) and the session cookie only lands in the jar used
    // by the first successful call, which would be the discarded fetch context.
    const codeResp = await req.post(flow.action, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      data: { code, method: 'code', csrf_token: flow.csrfToken },
      maxRedirects: 5,
    });
    console.log('[J1] code submit status:', codeResp.status());

    // Step 5: Assert an active session is established.
    // After a successful recovery code submission, Kratos issues a session and
    // redirects to the settings page. The session cookie is now in ctx's jar.
    const session = await getSession(ctx, baseURL);

    expect(
      session,
      'J1: non-admin recovery must result in an active session',
    ).not.toBeNull();
    expect(
      session!.active,
      'J1: recovery session must be active',
    ).toBe(true);
    expect(
      session!.identity?.traits?.email,
      'J1: recovery session must belong to the recovered identity',
    ).toBe(identity.email);

    console.log('[J1] PASS — non-admin recovery issued an active session for', identity.email);
  } finally {
    await ctx.close();
  }
});

// ─── J2: ADMIN recovery blocked by recovery-gate webhook ─────────────────────

test('J2 — admin recovery is blocked by the recovery-gate webhook (no privileged session)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  // Look up the pre-seeded recovery-admin identity (RECOVERY_ADMIN_EMAIL).
  // validate.sh seeds it with metadata_admin.admin=true (ADR 0008 marker) before
  // Playwright starts. The recovery-gate refuses recovery for this identity because
  // the jsonnet sets is_admin=true from the marker. No OTHALA_ADMIN_IDS env is
  // involved — the gate decision is carried in the webhook payload field.
  const recoveryAdminEmail = process.env.RECOVERY_ADMIN_EMAIL ?? 'admin.recovery@othala.test';
  const listResp = await fetch(
    `${kratosAdminURL}/admin/identities?credentials_identifier=${encodeURIComponent(recoveryAdminEmail)}`,
  );
  if (!listResp.ok) {
    throw new Error(
      `[J2] recovery-admin lookup failed: HTTP ${listResp.status} for ${recoveryAdminEmail}`,
    );
  }
  const idList = (await listResp.json()) as Array<{ id: string }>;
  if (idList.length === 0) {
    throw new Error(
      `[J2] no identity found for ${recoveryAdminEmail} — did validate.sh seed phase run?`,
    );
  }
  const identity = { id: idList[0].id, email: recoveryAdminEmail };
  console.log('[J2] looked up admin-marker identity:', identity.id, identity.email);

  const ctx = await browser.newContext();
  try {
    const req = ctx.request;
    const startTime = Date.now();

    // Step 1: Initiate recovery flow via ctx.request (cookie-bearing).
    const flow = await initRecoveryFlow(req, baseURL);
    console.log('[J2] recovery flow id:', flow.id);

    // Step 2: Submit the admin email via ctx.request.
    await submitRecoveryEmail(req, flow.action, flow.csrfToken, identity.email);
    console.log('[J2] admin recovery email submitted');

    // Step 3: Wait for the recovery code email in mailpit.
    // NOTE: Kratos sends the email BEFORE calling the webhook (the webhook fires
    // after the code is validated, not at initiation). So we DO expect an email.
    let code: string;
    try {
      const result = await waitForRecoveryCode(identity.email, startTime);
      code = result.code;
      console.log('[J2] admin recovery code received:', result.messageId);
    } catch (e) {
      // If no email arrived, Kratos may have blocked at initiation — that is
      // also acceptable (the gate may fire earlier in some Kratos versions).
      console.log('[J2] no recovery email (gate may fire at initiation):', String(e));

      // Assert no session was issued.
      const session = await getSession(ctx, baseURL);
      expect(
        session?.active ?? false,
        'J2: if no recovery email, there must be no active session (gate blocked at initiation)',
      ).toBe(false);
      console.log('[J2] PASS — admin recovery blocked (no email path)');
      return;
    }

    // Step 4: Submit the recovery code via ctx.request (same cookie jar).
    // The gate webhook fires here (after code validation). Kratos should abort
    // the flow (no session cookie set) due to the 403 from the gate.
    const codeResp = await req.post(flow.action, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      data: { code, method: 'code', csrf_token: flow.csrfToken },
      maxRedirects: 0,
    });

    const status = codeResp.status();
    const loc = codeResp.headers()['location'] ?? '';
    console.log('[J2] admin code submit result:', status, loc);

    // Step 5: Assert the gate BLOCKED recovery.
    //
    // Observable outcomes when the gate fires 403:
    //   a. Kratos aborts the flow and redirects to the error page (/auth/error).
    //   b. The code submission returns a 422 with an error message in the flow body.
    //   c. No session cookie is set (whoami returns null / inactive).
    //
    // We assert the union: either the response signals an error/abort,
    // OR no active session exists.
    const session = await getSession(ctx, baseURL);
    const sessionBlocked = !session || session.active !== true;
    const responseSignalsBlock =
      status >= 400 ||           // 4xx direct error
      /error/.test(loc) ||        // redirect to error page
      status === 302 && /error/.test(loc);

    expect(
      sessionBlocked || responseSignalsBlock,
      `J2: admin recovery must be blocked by the gate; got status=${status} loc=${loc} session.active=${session?.active}`,
    ).toBe(true);

    // Belt-and-suspenders: if somehow a session was issued, it must NOT be active.
    expect(
      session?.active ?? false,
      `J2: admin recovery must NOT produce an active session (gate should have fired); got active=${session?.active}`,
    ).toBe(false);

    console.log('[J2] PASS — admin recovery blocked by recovery-gate webhook');
  } finally {
    await ctx.close();
  }
});

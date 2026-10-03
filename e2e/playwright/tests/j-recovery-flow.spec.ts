// J — recovery succeeds for a non-admin and is blocked by the recovery-gate for an admin.

import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';
import { getSession } from '../actions/session';
import { waitForMessage, forRecipient } from '../actions/mail';

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

async function submitRecoveryEmail(
  req: APIRequestContext,
  action: string,
  csrfToken: string,
  email: string,
): Promise<{
  csrfToken: string;
  action: string;
  nodes: Array<{
    type: string;
    group: string;
    attributes?: { name?: string; type?: string; value?: unknown };
  }>;
}> {
  const resp = await req.post(action, {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    data: { email, method: 'code', csrf_token: csrfToken },
    maxRedirects: 5,
  });
  const status = resp.status();
  if (status !== 200 && status !== 400 && status !== 422) {
    throw new Error(
      `recovery email submit returned unexpected ${status}: ${await resp.text().catch(() => '')}`,
    );
  }

  let updatedCsrf = csrfToken;
  let updatedAction = action;
  let updatedNodes: Array<{
    type: string;
    group: string;
    attributes?: { name?: string; type?: string; value?: unknown };
  }> = [];
  try {
    const body = await resp.json().catch(() => null) as {
      ui?: {
        action?: string;
        nodes?: Array<{
          type: string;
          group: string;
          attributes?: { name?: string; type?: string; value?: unknown };
        }>;
      };
    } | null;
    updatedNodes = body?.ui?.nodes ?? [];
    updatedAction = body?.ui?.action ?? action;
    for (const node of updatedNodes) {
      if (
        node?.type === 'input' &&
        node?.attributes?.name === 'csrf_token' &&
        node?.attributes?.type === 'hidden'
      ) {
        const v = String(node.attributes.value ?? '');
        if (v) { updatedCsrf = v; break; }
      }
    }
  } catch {
  }
  return { csrfToken: updatedCsrf, action: updatedAction, nodes: updatedNodes };
}

test('J1 — non-admin recovery flow issues a privileged settings session', async ({
  ctx,
  baseURL,
  kratosAdminURL,
}) => {
  const uniqueSuffix = Date.now();
  const identity = await createIdentityWithPassword({
    email: `member.recovery.${uniqueSuffix}@othala.test`,
    username: `member.recovery.${uniqueSuffix}`,
    displayName: 'Recovery Test Member',
    groups: [],
    kratosAdminURL,
  });
  console.log('[J1] seeded non-admin identity:', identity.id, identity.email);

  const req = ctx.request;
  const startTime = Date.now();

  const flow = await initRecoveryFlow(req, baseURL);
  console.log('[J1] recovery flow id:', flow.id);

  const step2 = await submitRecoveryEmail(req, flow.action, flow.csrfToken, identity.email);
  console.log('[J1] recovery email submitted; csrf for code submit:', step2.csrfToken !== flow.csrfToken ? 'rotated' : 'unchanged');

  const emailHidden = step2.nodes.find(
    (n) =>
      n.group === 'default' &&
      n.type === 'input' &&
      n.attributes?.name === 'email' &&
      n.attributes?.type === 'hidden',
  );
  expect(
    emailHidden,
    'J1: the Kratos recovery step-2 (code-entry) form must NOT carry an email ' +
    'hidden node — sending email on code submit re-triggers step-1 (resend) ' +
    'and prevents code verification',
  ).toBeUndefined();

  const codePage = await req.get(`${baseURL}/auth/recovery?flow=${flow.id}`);
  expect(await codePage.text(), 'J1: the code step tells people to check spam or junk').toMatch(/spam or junk/i);

  const { code, id: messageId } = await waitForMessage(forRecipient(identity.email, startTime, /recover/i));
  console.log('[J1] recovery code received, message id:', messageId, 'code:', code);

  const codeResp = await req.post(step2.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { code, method: 'code', csrf_token: step2.csrfToken },
    maxRedirects: 5,
  });
  console.log('[J1] code submit status:', codeResp.status());

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
});

test('J2 — admin recovery is blocked by the recovery-gate webhook (no privileged session)', async ({
  ctx,
  baseURL,
  kratosAdminURL,
}) => {
  const uniqueSuffix = Date.now();
  const identity = await createIdentityWithPassword({
    email: `admin.recovery.${uniqueSuffix}@othala.test`,
    username: `admin.recovery.${uniqueSuffix}`,
    displayName: 'Recovery Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  console.log('[J2] seeded admin-marker identity:', identity.id, identity.email);

  const req = ctx.request;
  const startTime = Date.now();

  const flow = await initRecoveryFlow(req, baseURL);
  console.log('[J2] recovery flow id:', flow.id);

  const step2 = await submitRecoveryEmail(req, flow.action, flow.csrfToken, identity.email);
  const codeSubmitCsrf = step2.csrfToken;
  console.log('[J2] admin recovery email submitted; csrf rotated:', codeSubmitCsrf !== flow.csrfToken);

  let code: string;
  try {
    const result = await waitForMessage(forRecipient(identity.email, startTime, /recover/i));
    code = result.code;
    console.log('[J2] admin recovery code received:', result.id);
  } catch (e) {
    console.log('[J2] no recovery email (gate may fire at initiation):', String(e));

    const session = await getSession(ctx, baseURL);
    expect(
      session?.active ?? false,
      'J2: if no recovery email, there must be no active session (gate blocked at initiation)',
    ).toBe(false);
    console.log('[J2] PASS — admin recovery blocked (no email path)');
    return;
  }

  const codeResp = await req.post(step2.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { code, method: 'code', csrf_token: codeSubmitCsrf },
    maxRedirects: 0,
  });

  const status = codeResp.status();
  const loc = codeResp.headers()['location'] ?? '';
  console.log('[J2] admin code submit result:', status, loc);

  const gateBase = process.env.OTHALA_ADMIN_URL ?? 'http://othala:4431';
  const probeBody = JSON.stringify({
    identity_id: identity.id,
    is_admin: false, // deliberately false — proves gate ignores payload, uses admin API
    groups: ['grafana-admin'],
    traits: { email: identity.email },
  });
  const probeResp = await fetch(`${gateBase}/admin/recovery-gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${process.env.RECOVERY_GATE_SECRET ?? ''}`,
    },
    body: probeBody,
  });
  expect(
    probeResp.status,
    'J2: recovery-gate must return 403 for admin identity (gate fetches metadata_admin via admin API, ignoring payload is_admin)',
  ).toBe(403);
  console.log('[J2] gate direct probe:', probeResp.status, '(403 = gate correctly blocks admin via admin API lookup)');

  const session = await getSession(ctx, baseURL);
  const sessionBlocked = !session || session.active !== true;
  expect(
    sessionBlocked,
    'J2: no privileged session must be issued after admin recovery — gate blocks end-to-end',
  ).toBe(true);
  console.log('[J2] PASS — admin recovery blocked end-to-end; no session issued');
});

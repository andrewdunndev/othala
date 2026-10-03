// K — the email-code login completes end to end.

import { test, expect } from '../fixtures';
import type { APIRequestContext } from '@playwright/test';
import { createIdentityWithPassword } from '../actions/identity';
import { getSession } from '../actions/session';
import { HOUSEHOLD, waitForMessage, forRecipient } from '../actions/mail';

async function initLoginFlow(
  request: APIRequestContext,
  baseURL: string,
): Promise<{
  id: string;
  action: string;
  csrfToken: string;
  nodes: Array<{
    type: string;
    group: string;
    attributes?: { name?: string; type?: string; value?: unknown };
  }>;
}> {
  const resp = await request.get(`${baseURL}/self-service/login/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  if (!resp.ok()) {
    throw new Error(
      `login flow init failed: ${resp.status()} ${await resp.text().catch(() => '')}`,
    );
  }
  const flow = (await resp.json()) as {
    id: string;
    ui?: {
      action?: string;
      nodes?: Array<{
        type: string;
        group: string;
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
    throw new Error(
      `login flow missing ui.action: ${JSON.stringify(flow).slice(0, 300)}`,
    );
  }
  return { id: flow.id, action, csrfToken, nodes: flow?.ui?.nodes ?? [] };
}

async function submitIdentifierForCode(
  request: APIRequestContext,
  action: string,
  csrfToken: string,
  email: string,
): Promise<{
  action: string;
  csrfToken: string;
  nodes: Array<{
    type: string;
    group: string;
    attributes?: { name?: string; type?: string; value?: unknown };
  }>;
}> {
  const resp = await request.post(action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { identifier: email, method: 'code', csrf_token: csrfToken },
    maxRedirects: 5,
  });

  const s = resp.status();
  if (s !== 200 && s !== 400 && s !== 422) {
    throw new Error(
      `identifier submit returned unexpected ${s}: ${await resp.text().catch(() => '')}`,
    );
  }

  const flow = (await resp.json()) as {
    ui?: {
      action?: string;
      nodes?: Array<{
        type: string;
        group: string;
        attributes?: { name?: string; type?: string; value?: unknown };
      }>;
    };
  };

  const updatedAction = flow?.ui?.action ?? action;
  let updatedCsrf = csrfToken;
  for (const node of flow?.ui?.nodes ?? []) {
    if (
      node?.type === 'input' &&
      node?.attributes?.name === 'csrf_token' &&
      node?.attributes?.type === 'hidden'
    ) {
      updatedCsrf = String(node.attributes.value ?? csrfToken);
      break;
    }
  }

  return {
    action: updatedAction,
    csrfToken: updatedCsrf,
    nodes: flow?.ui?.nodes ?? [],
  };
}

test('K1 — email-code login delivers a code and establishes an active session', async ({
  ctx,
  baseURL,
  kratosAdminURL,
}) => {
  const identity = await createIdentityWithPassword({
    email: 'email-code-login@othala.test',
    username: 'email.code.login',
    displayName: 'Email Code Test',
    groups: [],
    kratosAdminURL,
  });
  console.log('[K1] seeded identity:', identity.id, identity.email);

  const startTime = Date.now();

  const flow = await initLoginFlow(ctx.request, baseURL);
  console.log('[K1] login flow id:', flow.id);

  const step2 = await submitIdentifierForCode(ctx.request, flow.action, flow.csrfToken, identity.email);
  console.log('[K1] identifier submitted; step-2 action:', step2.action);

  const { code, subject, body, id: messageId } = await waitForMessage(forRecipient(identity.email, startTime));
  expect(subject, 'K1: the subject names the household').toContain(HOUSEHOLD);
  expect(body, 'K1: the body names the household').toContain(HOUSEHOLD);
  console.log('[K1] received sign-in code:', code, 'message id:', messageId);

  const codeSubmitResp = await ctx.request.post(step2.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: {
      csrf_token: step2.csrfToken,
      identifier: identity.email,
      code,
      method: 'code',
    },
    maxRedirects: 5,
  });
  console.log('[K1] code submit status:', codeSubmitResp.status());

  const session = await getSession(ctx, baseURL);

  expect(
    session,
    'K1: email-code login must result in an active session',
  ).not.toBeNull();

  expect(
    session!.active,
    'K1: session must be active after successful code submission',
  ).toBe(true);

  expect(
    session!.identity?.traits?.email,
    'K1: session must belong to the email-code identity',
  ).toBe(identity.email);

  console.log('[K1] PASS — email-code login established an active session for', identity.email);
});

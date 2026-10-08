/**
 * Kratos JSON-API login (application/json accept path): skips the widget's CSS transition
 * while still routing through Caddy, so the session cookie is bound to the edge host.
 */

import type { BrowserContext, APIRequestContext } from '@playwright/test';
import { computeTotp } from '../fixtures';

export interface Credentials {
  identifier: string;
  password: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findCsrfToken(nodes: any[]): string {
  for (const node of nodes ?? []) {
    if (
      node?.type === 'input' &&
      node?.attributes?.name === 'csrf_token' &&
      node?.attributes?.type === 'hidden'
    ) {
      return node.attributes.value ?? '';
    }
  }
  return '';
}

export async function loginViaJsonApi(
  ctx: BrowserContext,
  creds: Credentials,
  base: string,
  flowQuery = '',
): Promise<string> {
  const req: APIRequestContext = ctx.request;

  const flowResp = await req.get(`${base}/self-service/login/browser${flowQuery}`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });

  if (!flowResp.ok()) {
    throw new Error(
      `login flow init failed: ${flowResp.status()} ${await flowResp.text().catch(() => '')}`,
    );
  }

  const flow = await flowResp.json();
  const action: string = flow?.ui?.action ?? '';
  const csrfToken = findCsrfToken(flow?.ui?.nodes ?? []);

  if (!action) {
    throw new Error(`login flow missing ui.action; flow=${JSON.stringify(flow).slice(0, 400)}`);
  }

  const submitResp = await req.post(action, {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    data: {
      identifier: creds.identifier,
      password: creds.password,
      method: 'password',
      csrf_token: csrfToken,
    },
    maxRedirects: 5,
  });

  if (!submitResp.ok()) {
    const body = await submitResp.text().catch(() => '');
    throw new Error(
      `login submit failed: ${submitResp.status()} — ${body.slice(0, 400)}`,
    );
  }

  const cookies = await ctx.cookies();
  const session = cookies.find((c) => c.name === 'ory_kratos_session');
  return session?.value ?? '(no session cookie found)';
}

/** Completes an aal2 TOTP step-up over the Kratos JSON API; `refresh` re-asks even a fresh aal2 session. */
export async function totpStepUp(ctx: BrowserContext, baseURL: string, secret: string, returnTo = '', refresh = false): Promise<void> {
  const query = `${refresh ? '&refresh=true' : ''}${returnTo ? `&return_to=${encodeURIComponent(returnTo)}` : ''}`;
  const flowResp = await ctx.request.get(`${baseURL}/self-service/login/browser?aal=aal2${query}`, {
    headers: { Accept: 'application/json' },
  });
  if (!flowResp.ok()) throw new Error(`aal2 flow init answered ${flowResp.status()}`);
  const flow = await flowResp.json();
  const resp = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { csrf_token: findCsrfToken(flow.ui.nodes), method: 'totp', totp_code: await computeTotp(secret) },
  });
  if (!resp.ok()) throw new Error(`totp step-up answered ${resp.status()}: ${(await resp.text()).slice(0, 300)}`);
}

/**
 * login.ts — Ory Kratos JSON-API login action.
 *
 * Uses the Kratos self-service login flow via the APPLICATION/JSON accept path
 * (Kratos "Browser flow with API-compatible client" pattern) rather than DOM
 * form scraping. This bypasses the rendered widget's CSS transition (the
 * automation-hostility: transition:0.6s finding from browser-test.mjs) while
 * still routing through Caddy → Kratos → othala on the same network host, so
 * the resulting session cookie is bound to auth.othala.test exactly as a human
 * browser submit would produce.
 *
 * Flow:
 *   1. GET {BASE}/self-service/login/browser with Accept: application/json
 *      → Kratos returns a LoginFlow JSON body (no redirect, because Accept says
 *        application/json and this is a "native / API-compatible" browser client)
 *   2. Extract csrf_token from flow.ui.nodes (the hidden input node)
 *   3. POST credentials to flow.ui.action
 *      body: { identifier, password, method:'password', csrf_token }
 *      → Kratos accepts → 200 with Set-Cookie: ory_kratos_session
 *
 * The APIRequestContext is attached to the BrowserContext so the session
 * cookie is automatically shared with page navigations.
 */

import type { BrowserContext, APIRequestContext } from '@playwright/test';

export interface Credentials {
  identifier: string;
  password: string;
}

/**
 * Find the csrf_token value inside a Kratos LoginFlow's ui.nodes array.
 * The CSRF node is a hidden input with name='csrf_token'.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findCsrfToken(nodes: any[]): string {
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

/**
 * loginViaJsonApi — obtain a Kratos session for `creds` inside `ctx`.
 *
 * After this call the BrowserContext cookie jar contains ory_kratos_session,
 * so any subsequent page.goto() or ctx.request call carries the session.
 *
 * @param ctx   The Playwright BrowserContext (manages the cookie jar).
 * @param creds Identity credentials { identifier, password }.
 * @param base  The public base URL of the Othala edge (default from env).
 * @returns     The session cookie value (for logging/assertions only).
 */
export async function loginViaJsonApi(
  ctx: BrowserContext,
  creds: Credentials,
  base: string,
): Promise<string> {
  const req: APIRequestContext = ctx.request;

  // Step 1: initiate the browser login flow; Accept: application/json tells
  // Kratos to return the flow as JSON instead of redirecting to the UI URL.
  const flowResp = await req.get(`${base}/self-service/login/browser`, {
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

  // Step 2: submit credentials to the flow action endpoint.
  // The action URL is already the fully-qualified Kratos submit endpoint;
  // Caddy routes /self-service/* → kratos:4433.
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

  // Extract the session cookie value for diagnostic logging.
  // The actual cookie is stored in the BrowserContext jar automatically.
  const cookies = await ctx.cookies();
  const session = cookies.find((c) => c.name === 'ory_kratos_session');
  return session?.value ?? '(no session cookie found)';
}

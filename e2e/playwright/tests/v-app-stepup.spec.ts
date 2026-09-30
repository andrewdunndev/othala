// V — second-factor step-up at app sign-in and forward-auth, and the code-login gate for admins.

import { test, expect, enrollTotpSecret, computeTotp, GRAFANA_REDIRECT_URI } from '../fixtures';
import type { APIRequestContext } from '@playwright/test';
import type { BrowserContext } from 'playwright-core';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { waitForMessage, forRecipient } from '../actions/mail';

const ADMIN_CODE_REFUSAL = 'Admin accounts sign in with a passkey or password.';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Flow = { id: string; ui: { action: string; nodes: any[]; messages?: Array<{ text: string }> } };

function csrfOf(flow: Flow): string {
  const n = flow.ui.nodes.find((x) => x?.attributes?.name === 'csrf_token');
  return String(n?.attributes?.value ?? '');
}

async function initFlow(request: APIRequestContext, url: string): Promise<Flow> {
  const resp = await request.get(url, { headers: { Accept: 'application/json' }, maxRedirects: 5 });
  expect(resp.ok(), `login flow init ${url}: ${resp.status()}`).toBe(true);
  return (await resp.json()) as Flow;
}

async function codeLogin(ctx: BrowserContext, baseURL: string, email: string) {
  const since = Date.now();
  const flow = await initFlow(ctx.request, `${baseURL}/self-service/login/browser`);
  const step1 = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { identifier: email, method: 'code', csrf_token: csrfOf(flow) },
    maxRedirects: 5,
  });
  const step2 = (await step1.json()) as Flow;
  const { code } = await waitForMessage(forRecipient(email, since));
  const resp = await ctx.request.post(step2.ui?.action ?? flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { identifier: email, code, method: 'code', csrf_token: csrfOf(step2) || csrfOf(flow) },
    maxRedirects: 5,
  });
  return { status: resp.status(), body: await resp.text() };
}

async function walkAuthorize(ctx: BrowserContext, baseURL: string): Promise<URL> {
  let url =
    `${baseURL}/oauth2/auth?client_id=grafana&response_type=code` +
    `&scope=${encodeURIComponent('openid email')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=v-app-stepup-state&nonce=v-app-stepup-nonce`;
  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) throw new Error(`authorize stalled at ${url}: ${resp.status()}`);
    const parsed = new URL(loc, baseURL);
    if (loc.startsWith('https://grafana.othala.test') || parsed.pathname === '/auth/login') return parsed;
    url = parsed.toString();
  }
  throw new Error('authorize did not terminate in 10 hops');
}

const forwardAuth = (ctx: BrowserContext, baseURL: string) =>
  ctx.request.get(`${baseURL}/api/forward-auth?group=grafana-access`, { maxRedirects: 0 });

async function seedWithTotp(
  browser: import('playwright-core').Browser,
  kratosAdminURL: string,
  baseURL: string,
  slug: string,
  isAdmin: boolean,
): Promise<{ email: string; secret: string }> {
  const username = `${slug}.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({
    email, username, displayName: `V ${slug}`, groups: ['grafana-access'], isAdmin, kratosAdminURL,
  });
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL);
    return { email, secret: await enrollTotpSecret(ctx, baseURL) };
  } finally {
    await ctx.close();
  }
}

test('V1 — admin email-code login is refused with the neutral message', async ({ browser, baseURL, kratosAdminURL, ctx }) => {
  const { email } = await seedWithTotp(browser, kratosAdminURL, baseURL, 'v1.admin', true);
  const res = await codeLogin(ctx, baseURL, email);
  expect(res.status, `V1: refusal must not be a success; body ${res.body.slice(0, 300)}`).toBeGreaterThanOrEqual(400);
  expect(res.body, 'V1: the hook message reaches the flow').toContain(ADMIN_CODE_REFUSAL);
  expect(await getSession(ctx, baseURL), 'V1: no session cookie may be issued').toBeNull();
});

test('V2 — a TOTP member signed in by code steps up before app sign-in and forward-auth', async ({ browser, baseURL, kratosAdminURL, ctx }) => {
  const { email, secret } = await seedWithTotp(browser, kratosAdminURL, baseURL, 'v2.member', false);
  const login = await codeLogin(ctx, baseURL, email);
  expect(login.status, `V2: code login; body ${login.body.slice(0, 300)}`).toBe(200);
  const session = await getSession(ctx, baseURL);
  expect(session?.authenticator_assurance_level, 'V2: code login yields aal1').toBe('aal1');

  const stepped = await walkAuthorize(ctx, baseURL);
  expect(stepped.pathname, `V2: must land on the login page, got ${stepped}`).toBe('/auth/login');
  expect(stepped.searchParams.get('aal')).toBe('aal2');
  expect((await forwardAuth(ctx, baseURL)).status(), 'V2: aal1 forward-auth').toBe(401);

  const plain = await ctx.request.get(`${baseURL}/auth/login?return_to=${encodeURIComponent(`${baseURL}/`)}`, { maxRedirects: 0 });
  const promoted = new URL(plain.headers()['location'] ?? '', baseURL);
  expect(promoted.pathname, `V2: login page redirect, got ${promoted}`).toBe('/self-service/login/browser');
  expect(promoted.searchParams.get('aal'), 'V2: aal1 session without aal param is promoted').toBe('aal2');
  expect(promoted.searchParams.get('return_to')).toBe(`${baseURL}/`);

  const flow = await initFlow(ctx.request, `${baseURL}/self-service/login/browser?aal=aal2`);
  const totp = await ctx.request.post(flow.ui.action, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { csrf_token: csrfOf(flow), method: 'totp', totp_code: await computeTotp(secret) },
    maxRedirects: 5,
  });
  expect(totp.ok(), `V2: TOTP step: ${totp.status()}`).toBe(true);
  expect((await getSession(ctx, baseURL))?.authenticator_assurance_level).toBe('aal2');

  const done = await walkAuthorize(ctx, baseURL);
  expect(done.origin, `V2: aal2 must reach the callback, got ${done}`).toBe('https://grafana.othala.test');
  expect(done.searchParams.get('code')).toBeTruthy();
  expect((await forwardAuth(ctx, baseURL)).status(), 'V2: aal2 forward-auth').toBe(200);
});

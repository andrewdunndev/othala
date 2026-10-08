/**
 * The device grant from both ends: the device's half (Hydra's device endpoint and token poll, as a CLI on another
 * machine would call them) and the browser's half (answering the portal's sign-in bounces over the Kratos JSON API).
 */

import type { APIRequestContext, BrowserContext, Page } from '@playwright/test';
import { computeTotp } from '../fixtures';
import { loginViaJsonApi, findCsrfToken, type Credentials } from './login';

export const DEVICE_CLIENT_ID = 'stepca';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export interface DeviceAuthorization {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export async function startDeviceFlow(request: APIRequestContext, baseURL: string): Promise<DeviceAuthorization> {
  const resp = await request.post(`${baseURL}/oauth2/device/auth`, {
    form: { client_id: DEVICE_CLIENT_ID, scope: 'openid email' },
  });
  if (!resp.ok()) throw new Error(`device/auth answered ${resp.status()}: ${await resp.text()}`);
  return (await resp.json()) as DeviceAuthorization;
}

/** One poll; an unapproved grant answers 400 authorization_pending. */
export async function pollDeviceToken(
  request: APIRequestContext,
  baseURL: string,
  deviceCode: string,
): Promise<{ status: number; body: Record<string, string> }> {
  const resp = await request.post(`${baseURL}/oauth2/token`, {
    form: { grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: DEVICE_CLIENT_ID },
  });
  return { status: resp.status(), body: (await resp.json()) as Record<string, string> };
}

/** Every URL the page requests as a navigation, redirect hops included. */
export function recordNavigations(page: Page): URL[] {
  const seen: URL[] = [];
  page.on('request', (r) => {
    if (r.isNavigationRequest()) seen.push(new URL(r.url()));
  });
  return seen;
}

export async function totpStepUp(ctx: BrowserContext, baseURL: string, secret: string, returnTo = ''): Promise<void> {
  const query = returnTo ? `&return_to=${encodeURIComponent(returnTo)}` : '';
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

const SETTLED = ['/auth/login', '/auth/consent', '/auth/error', '/device/done'];

/** Wait for the page to settle, answering each portal sign-in bounce; returns where it settled otherwise. */
export async function answerSignIns(
  page: Page,
  hops: URL[],
  baseURL: string,
  creds: Credentials,
  totpSecret?: string,
): Promise<URL> {
  for (let round = 0; round < 3; round++) {
    await page.waitForURL((u) => SETTLED.includes(u.pathname));
    const bounce = [...hops].reverse().find((u) => u.pathname === '/auth/login' && u.searchParams.has('return_to'));
    if (new URL(page.url()).pathname !== '/auth/login' || !bounce) return new URL(page.url());
    const returnTo = bounce.searchParams.get('return_to')!;
    if (bounce.searchParams.get('aal') === 'aal2' && totpSecret) await totpStepUp(page.context(), baseURL, totpSecret, returnTo);
    else await loginViaJsonApi(page.context(), creds, baseURL, `?refresh=true&return_to=${encodeURIComponent(returnTo)}`);
    hops.length = 0;
    await page.goto(`${baseURL}${returnTo}`);
  }
  throw new Error(`sign-in did not settle in 3 rounds (at ${page.url()})`);
}

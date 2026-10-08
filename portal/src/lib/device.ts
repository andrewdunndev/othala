// The device grant's code entry (/device/verify) and success page (/device/done). Entering a code needs no session:
// Hydra sends the browser through the ordinary login and consent challenges next, where the device branch holds it to
// a fresh aal2 sign-in and a confirm screen that shows this code.

import { createHash } from 'node:crypto';
import { ResponseError, type OAuth2Api } from '@ory/client-fetch';
import { hydraAdmin } from './ory-fetch';
import { signToken, csrfRefusal } from './csrf';
import { publicUrl } from './config';

/** The path of every device-grant login and consent request_url; Hydra's login request has no device field. */
export const DEVICE_VERIFY_PATH = '/oauth2/device/verify';
export const DEVICE_CODE_COOKIE = 'othala_device_code';
const USER_CODE_RE = /^[A-Za-z0-9-]{6,32}$/;
const CODE_COOKIE_MAX_AGE_S = 600; // ttl.device_user_code

export function isDeviceRequest(requestUrl: string | undefined): boolean {
  try {
    return new URL(requestUrl ?? '').pathname === DEVICE_VERIFY_PATH;
  } catch {
    return false;
  }
}

/** The code this browser entered, for display on the confirm screen only. */
export function readDeviceCode(cookieHeader: string | null | undefined): string | null {
  for (const part of (cookieHeader ?? '').split(';')) {
    const [name, value] = part.trim().split('=');
    if (name === DEVICE_CODE_COOKIE && USER_CODE_RE.test(value ?? '')) return value;
  }
  return null;
}

function codeCookie(value: string, maxAge: number): string {
  const secure = publicUrl.startsWith('https:') ? '; Secure' : '';
  return `${DEVICE_CODE_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure}`;
}

export const clearDeviceCode = (): string => codeCookie('', 0);

/** No session exists yet, so the token binds to the challenge. */
const csrfSubject = (challenge: string) => createHash('sha256').update(challenge).digest('hex');

export interface VerifyView {
  challenge: string;
  userCode: string;
  csrfToken: string;
  error?: 'missing' | 'not-found';
}

export interface DeviceDeps {
  oauth2?: Pick<OAuth2Api, 'acceptUserCodeRequest'>;
}

function view(challenge: string, userCode: string, error?: VerifyView['error']): VerifyView {
  return { challenge, userCode, csrfToken: challenge ? signToken(csrfSubject(challenge), 'device') : '', error };
}

/** GET renders the form (a user_code on the link prefills it); POST accepts the code and sends the browser on. */
export async function handleDeviceVerify(req: Request, deps: DeviceDeps = {}): Promise<Response | VerifyView> {
  if (req.method !== 'POST') {
    const q = new URL(req.url).searchParams;
    const challenge = q.get('device_challenge') ?? '';
    return view(challenge, q.get('user_code') ?? '', challenge ? undefined : 'missing');
  }

  const body = new URLSearchParams(await req.text());
  const challenge = body.get('device_challenge') ?? '';
  const userCode = (body.get('user_code') ?? '').trim();
  if (!challenge) return view('', userCode, 'missing');
  if (csrfRefusal(body.get('csrf_token'), csrfSubject(challenge), 'device') !== null) {
    return new Response('CSRF token invalid', { status: 400 });
  }
  if (!USER_CODE_RE.test(userCode)) return view(challenge, userCode, 'not-found');

  try {
    const { redirect_to } = await (deps.oauth2 ?? hydraAdmin()).acceptUserCodeRequest({
      deviceChallenge: challenge,
      acceptDeviceUserCodeRequest: { user_code: userCode },
    });
    return new Response(null, {
      status: 302,
      headers: { Location: redirect_to, 'Set-Cookie': codeCookie(userCode, CODE_COOKIE_MAX_AGE_S) },
    });
  } catch (err) {
    const status = err instanceof ResponseError ? err.response.status : 0;
    if (status >= 400 && status < 500) return view(challenge, userCode, 'not-found');
    console.error('[portal] upstream failure', { step: 'acceptUserCodeRequest', error: String(err) });
    return new Response('upstream error', { status: 502 });
  }
}

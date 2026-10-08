// Invariant: a code reaches Hydra only with a CSRF token minted for its own challenge; only an accepted code is stored,
// in an httpOnly Lax cookie; Hydra's 4xx re-renders the form, anything else is an upstream error.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ResponseError } from '@ory/client-fetch';
import { handleDeviceVerify, isDeviceRequest, readDeviceCode, DEVICE_CODE_COOKIE, type VerifyView } from './device.js';
import { _resetForTests } from './csrf.js';

beforeEach(() => {
  _resetForTests();
  process.env['CSRF_SECRET'] = 'a-test-secret-that-is-at-least-32-chars!!';
});

const URL_BASE = 'https://sso.othala.test/device/verify';

async function formFor(challenge: string): Promise<VerifyView> {
  return (await handleDeviceVerify(new Request(`${URL_BASE}?device_challenge=${challenge}`))) as VerifyView;
}

function post(fields: Record<string, string>): Request {
  return new Request(URL_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
}

function hydra(result: () => Promise<{ redirect_to: string }>) {
  return { acceptUserCodeRequest: vi.fn(result) };
}

const accepted = () => hydra(async () => ({ redirect_to: 'https://sso.othala.test/oauth2/device/verify?device_verifier=v' }));

describe('isDeviceRequest', () => {
  it.each([
    ['https://sso.othala.test/oauth2/device/verify?client_id=stepca', true],
    ['https://sso.othala.test/oauth2/auth?client_id=grafana', false],
    ['https://sso.othala.test/oauth2/device/verify/x', false],
    ['not a url', false],
    [undefined, false],
  ])('%s -> %s', (url, expected) => expect(isDeviceRequest(url)).toBe(expected));
});

describe('readDeviceCode', () => {
  it('reads the code among other cookies', () => {
    expect(readDeviceCode(`a=1; ${DEVICE_CODE_COOKIE}=ABCD-EFGH; b=2`)).toBe('ABCD-EFGH');
  });
  it.each([null, '', `${DEVICE_CODE_COOKIE}=`, `${DEVICE_CODE_COOKIE}=<script>`, `x${DEVICE_CODE_COOKIE}=ABCDEFGH`])(
    'refuses %s',
    (header) => expect(readDeviceCode(header)).toBeNull(),
  );
});

describe('handleDeviceVerify GET', () => {
  it('prefills the code from the link and mints a token', async () => {
    const v = (await handleDeviceVerify(new Request(`${URL_BASE}?device_challenge=dc&user_code=ABCDEFGH`))) as VerifyView;
    expect(v).toMatchObject({ challenge: 'dc', userCode: 'ABCDEFGH', error: undefined });
    expect(v.csrfToken).not.toBe('');
  });
  it('without a challenge renders the start-on-your-device notice', async () => {
    expect(await handleDeviceVerify(new Request(URL_BASE))).toMatchObject({ error: 'missing', csrfToken: '' });
  });
});

describe('handleDeviceVerify POST', () => {
  it('accepts the code, stores it for display and follows Hydra', async () => {
    const { csrfToken } = await formFor('dc');
    const oauth2 = accepted();
    const res = (await handleDeviceVerify(post({ device_challenge: 'dc', user_code: ' ABCDEFGH ', csrf_token: csrfToken }), { oauth2 })) as Response;
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://sso.othala.test/oauth2/device/verify?device_verifier=v');
    expect(oauth2.acceptUserCodeRequest).toHaveBeenCalledWith({ deviceChallenge: 'dc', acceptDeviceUserCodeRequest: { user_code: 'ABCDEFGH' } });
    const cookie = res.headers.get('set-cookie') ?? '';
    expect(cookie).toMatch(new RegExp(`^${DEVICE_CODE_COOKIE}=ABCDEFGH; Path=/; Max-Age=600; HttpOnly; SameSite=Lax`));
  });

  it('re-renders "not found" with a fresh token when Hydra refuses the code', async () => {
    const { csrfToken } = await formFor('dc');
    const oauth2 = hydra(async () => {
      throw new ResponseError(new Response(null, { status: 400 }), 'invalid_request');
    });
    const v = (await handleDeviceVerify(post({ device_challenge: 'dc', user_code: 'ABCDEFGH', csrf_token: csrfToken }), { oauth2 })) as VerifyView;
    expect(v).toMatchObject({ challenge: 'dc', userCode: 'ABCDEFGH', error: 'not-found' });
    expect(v.csrfToken).not.toBe(csrfToken);
  });

  it('answers 502 when Hydra fails', async () => {
    const { csrfToken } = await formFor('dc');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const oauth2 = hydra(async () => {
      throw new Error('boom');
    });
    const res = (await handleDeviceVerify(post({ device_challenge: 'dc', user_code: 'ABCDEFGH', csrf_token: csrfToken }), { oauth2 })) as Response;
    expect(res.status).toBe(502);
    spy.mockRestore();
  });

  it.each([
    ['no token', async () => ''],
    ['a token minted for another challenge', async () => (await formFor('other')).csrfToken],
  ])('refuses %s without calling Hydra', async (_name, token) => {
    const oauth2 = accepted();
    const res = (await handleDeviceVerify(post({ device_challenge: 'dc', user_code: 'ABCDEFGH', csrf_token: await token() }), { oauth2 })) as Response;
    expect(res.status).toBe(400);
    expect(oauth2.acceptUserCodeRequest).not.toHaveBeenCalled();
  });

  it('refuses a malformed code without calling Hydra', async () => {
    const { csrfToken } = await formFor('dc');
    const oauth2 = accepted();
    const v = await handleDeviceVerify(post({ device_challenge: 'dc', user_code: 'AB;CD=EF', csrf_token: csrfToken }), { oauth2 });
    expect(v).toMatchObject({ error: 'not-found' });
    expect(oauth2.acceptUserCodeRequest).not.toHaveBeenCalled();
  });
});

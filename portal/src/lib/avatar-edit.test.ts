// Invariant: both picture editors go through one handler, so the member and the admin get the same refusals and a
// refusal writes nothing.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { patchAvatarMock, getSessionMock } = vi.hoisted(() => ({ patchAvatarMock: vi.fn(), getSessionMock: vi.fn() }));
vi.mock('./admin-api', () => ({ patchAvatar: patchAvatarMock }));
vi.mock('./kratos', () => ({ getSession: getSessionMock, browserFlows: { settings: (u: string) => u } }));

import { applyAvatarForm } from './avatar-edit';
import { AVATAR_MAX_BYTES } from './avatar';
import { POST } from '../pages/auth/avatar.js';
import { signToken, _resetForTests } from './csrf';
import { avatarOf, imageBytes, session } from './test-builders';

process.env.CSRF_SECRET ||= 'test-secret-must-be-at-least-32-chars-long!!';

const file = (bytes: Uint8Array, name = 'p.png') => new File([bytes as BlobPart], name);
const form = (entries: Record<string, string | File>) => {
  const f = new FormData();
  for (const [k, v] of Object.entries(entries)) f.set(k, v);
  return f;
};

beforeEach(() => {
  patchAvatarMock.mockReset().mockResolvedValue(undefined);
  getSessionMock.mockReset();
  _resetForTests();
});

describe('applyAvatarForm', () => {
  it('stores a valid upload under the identity', async () => {
    const r = await applyAvatarForm(form({ avatar: file(imageBytes('png')) }), 'id-1');
    expect(r).toEqual({ ok: true, change: 'set' });
    expect(patchAvatarMock).toHaveBeenCalledWith('id-1', avatarOf('png'));
  });

  it('removes on remove=1', async () => {
    expect(await applyAvatarForm(form({ remove: '1' }), 'id-1')).toEqual({ ok: true, change: 'removed' });
    expect(patchAvatarMock).toHaveBeenCalledWith('id-1', null);
  });

  it('refuses a missing file, an oversized one and a wrong type without writing', async () => {
    expect(await applyAvatarForm(form({}), 'id-1')).toEqual({ ok: false, code: 'empty' });
    expect(await applyAvatarForm(form({ avatar: file(new Uint8Array(AVATAR_MAX_BYTES + 1)) }), 'id-1')).toEqual({ ok: false, code: 'too-large' });
    expect(await applyAvatarForm(form({ avatar: file(new TextEncoder().encode('<svg/>'), 'p.svg') }), 'id-1')).toEqual({ ok: false, code: 'type' });
    expect(patchAvatarMock).not.toHaveBeenCalled();
  });
});

describe('POST /auth/avatar', () => {
  const run = async (fields: Record<string, string | File>, opts: { token?: string | null; active?: boolean; raw?: Request } = {}) => {
    getSessionMock.mockResolvedValue(opts.active === false ? { active: false } : session('aal1'));
    const sess = session('aal1');
    const token = opts.token === undefined ? signToken(sess.identity!.id, 'avatar') : opts.token;
    const body = form({ ...(token === null ? {} : { csrf_token: token }), ...fields });
    const cookies = { set: vi.fn() };
    const res = (await POST({ request: opts.raw ?? new Request('http://portal.test/auth/avatar', { method: 'POST', body }), redirect: (u: string, s: number) => new Response(null, { status: s, headers: { Location: u } }), cookies } as never)) as Response;
    return { res, flash: cookies.set.mock.calls[0]?.[1] };
  };

  it('saves for the signed-in identity only, then redirects with a saved flash', async () => {
    const { res, flash } = await run({ avatar: file(imageBytes('png')) });
    expect(res.status).toBe(303);
    expect(flash).toBe('set');
    expect(patchAvatarMock).toHaveBeenCalledWith(session('aal1').identity!.id, avatarOf('png'));
  });

  it('refuses a missing or wrong-action CSRF token and writes nothing', async () => {
    expect((await run({ avatar: file(imageBytes('png')) }, { token: null })).flash).toBe('csrf');
    const sess = session('aal1');
    expect((await run({ avatar: file(imageBytes('png')) }, { token: signToken(sess.identity!.id, 'passkey-name') })).flash).toBe('csrf');
    expect(patchAvatarMock).not.toHaveBeenCalled();
  });

  it('sends a signed-out caller to login without reading the form', async () => {
    const { res } = await run({ avatar: file(imageBytes('png')) }, { active: false });
    expect(res.headers.get('Location')).toBe('/auth/login');
    expect(patchAvatarMock).not.toHaveBeenCalled();
  });

  it('refuses a body over the ceiling before parsing it', async () => {
    // A source that stops when cancelled, so nothing is pushed into a closed stream.
    let sent = 0;
    const stream = new ReadableStream({
      pull(c) {
        c.enqueue(new Uint8Array(16 * 1024));
        sent += 16 * 1024;
        if (sent >= 1024 * 1024) c.close();
      },
    });
    const raw = new Request('http://portal.test/auth/avatar', { method: 'POST', body: stream, headers: { 'content-type': 'multipart/form-data; boundary=x' }, duplex: 'half' } as RequestInit);
    const { flash } = await run({}, { raw });
    expect(sent).toBeLessThan(1024 * 1024);
    expect(flash).toBe('too-large');
    expect(patchAvatarMock).not.toHaveBeenCalled();
  });
});

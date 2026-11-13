// Invariant: both picture editors go through one handler, so the member and the admin get the same refusals and a
// refusal writes nothing.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { patchAvatarMock, getSessionMock } = vi.hoisted(() => ({ patchAvatarMock: vi.fn(), getSessionMock: vi.fn() }));
vi.mock('./admin-api', () => ({ patchAvatar: patchAvatarMock }));
vi.mock('./kratos', () => ({ getSession: getSessionMock, browserFlows: { settings: (u: string) => u } }));

import { applyAvatarForm } from './avatar-edit';
import { AVATAR_MAX_BYTES } from './avatar-limits';
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

  // The adapter's bodySizeLimit (astro.config.mjs) wraps the Node request in astro core's limitAsyncIterable and builds
  // `new Request({ body, duplex: 'half' })`. The limit lives in the server, not the handler, so this replays that exact
  // shape with a copy of limitAsyncIterable and drives the real handler through it.
  async function* limited(source: AsyncIterable<Uint8Array>, limit: number) {
    let received = 0;
    for await (const chunk of source) {
      received += chunk.byteLength;
      if (received > limit) throw new Error(`Body size limit exceeded: received more than ${limit} bytes`);
      yield chunk;
    }
  }
  // `finished` resolves when the source generator has stopped, so a test never leaves a pull pending on a body the handler
  // has already abandoned: undici enqueues into a stream that is closed by then and the rejection lands in a later test.
  const adapterRequest = (chunk: number, count: number, contentType = 'multipart/form-data; boundary=x', onPull?: () => void) => {
    let stop!: () => void;
    const finished = new Promise<void>((r) => (stop = r));
    async function* source() {
      try {
        for (let i = 0; i < count; i++) {
          await new Promise((r) => setTimeout(r, 1));
          onPull?.();
          yield new Uint8Array(chunk);
        }
      } finally {
        stop();
      }
    }
    const request = new Request('http://portal.test/auth/avatar', {
      method: 'POST',
      body: limited(source(), 262144) as unknown as BodyInit,
      duplex: 'half',
      headers: { 'content-type': contentType },
    } as RequestInit);
    return { request, finished };
  };

  it('answers too-large for a body past the adapter limit, with no unhandled rejection or exception', async () => {
    const events: unknown[] = [];
    const onEvent = (e: unknown) => events.push(e);
    process.on('unhandledRejection', onEvent);
    process.on('uncaughtException', onEvent);
    try {
      let pulled = 0;
      const { request, finished } = adapterRequest(16 * 1024, 80, undefined, () => pulled++);
      const { flash } = await run({}, { raw: request });
      await finished;
      expect(flash).toBe('too-large');
      expect(pulled).toBeLessThan(80);
      expect(patchAvatarMock).not.toHaveBeenCalled();
      await new Promise((r) => setTimeout(r, 150));
      expect(events).toEqual([]);
    } finally {
      process.off('unhandledRejection', onEvent);
      process.off('uncaughtException', onEvent);
    }
  });

  it('answers a body that is not a form as a refused type, not too-large', async () => {
    const { request, finished } = adapterRequest(100, 2, 'multipart/form-data; boundary=x');
    const { flash } = await run({}, { raw: request });
    await finished;
    expect(flash).toBe('type');
  });
});

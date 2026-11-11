import { describe, it, expect, vi, beforeEach } from 'vitest';

const { getIdentityMock } = vi.hoisted(() => ({ getIdentityMock: vi.fn() }));
vi.mock('../../lib/admin-api', () => ({ getIdentityWithoutCredentials: getIdentityMock }));

import { GET } from './[id]/[hash].js';
import { identity, avatarOf } from '../../lib/test-builders.js';

const ID = '3f2b8c1e-5d4a-4b7e-9a10-6c2d8e4f1a77';
const a = avatarOf('webp');
const hash = a.sha256.slice(0, 16);

const call = (id: string, h: string) => GET({ params: { id, hash: h }, request: new Request(`http://portal.test/avatar/${id}/${h}`) } as never) as Promise<Response>;
const snapshot = async (r: Response) => ({ status: r.status, body: await r.text(), headers: [...r.headers].sort() });

beforeEach(() => {
  getIdentityMock.mockReset().mockResolvedValue(identity({ id: ID, metadataAdmin: { avatar: a } }));
});

describe('GET /avatar/<id>/<hash>', () => {
  it('serves the stored bytes with the hardened headers', async () => {
    const res = await call(ID, hash);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/webp');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
    expect(res.headers.get('cache-control')).toBe('public, max-age=31536000, immutable');
    expect(res.headers.get('etag')).toBe(`"${a.sha256}"`);
    expect(Buffer.from(await res.arrayBuffer()).toString('base64')).toBe(a.data);
  });

  it('answers every miss with the same 404', async () => {
    const miss = await snapshot(await call(ID, 'f'.repeat(16)));
    expect(miss.status).toBe(404);
    getIdentityMock.mockResolvedValue(identity({ id: ID }));
    const absent = await snapshot(await call(ID, hash));
    getIdentityMock.mockRejectedValue(new Error('404'));
    const unknown = await snapshot(await call(ID, hash));
    const malformed = await snapshot(await call('not-a-uuid', hash));
    const badHash = await snapshot(await call(ID, 'zz'));
    for (const m of [absent, unknown, malformed, badHash]) expect(m).toEqual(miss);
  });

  it('checks the id and hash shape before any Kratos call', async () => {
    getIdentityMock.mockClear();
    await call('../etc', hash);
    await call(ID, 'short');
    expect(getIdentityMock).not.toHaveBeenCalled();
  });

  it('never serves a stored type outside the three', async () => {
    getIdentityMock.mockResolvedValue(identity({ id: ID, metadataAdmin: { avatar: { ...a, type: 'image/svg+xml' } as never } }));
    expect((await call(ID, hash)).status).toBe(404);
  });
});

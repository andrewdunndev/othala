import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const { getSessionMock, getIdentityMock } = vi.hoisted(() => ({ getSessionMock: vi.fn(), getIdentityMock: vi.fn() }));

vi.mock('../../lib/kratos', () => ({ getSession: getSessionMock }));
vi.mock('astro:middleware', () => ({ defineMiddleware: (fn: unknown) => fn }));
vi.mock('../../lib/admin-api', () => ({ getIdentity: getIdentityMock }));

import { GET } from './[slug].svg.js';
import { setContentDir } from '../../lib/manifests.js';
import { identity, session } from '../../lib/test-builders.js';
import { onRequest } from '../../middleware.js';

const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>';
const manifest = (group: string) =>
  `presentation:\n  name: App\n  description: d\n  url: https://app.example.test\n  icon: AP\n  auth_kind: external\n  access:\n    - ${group}\n`;

let root: string;
let dir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'icon-route-'));
  dir = join(root, 'apps');
  mkdirSync(dir);
  writeFileSync(join(dir, 'app.yaml'), manifest('app-access'));
  writeFileSync(join(dir, 'app.svg'), SVG);
  writeFileSync(join(dir, 'big.yaml'), manifest('app-access'));
  writeFileSync(join(dir, 'big.svg'), SVG + ' '.repeat(33 * 1024));
  for (const [stem, bytes] of [['edge', 32 * 1024], ['over', 32 * 1024 + 1]] as const) {
    writeFileSync(join(dir, `${stem}.yaml`), manifest('app-access'));
    writeFileSync(join(dir, `${stem}.svg`), SVG + ' '.repeat(bytes - SVG.length));
  }
  writeFileSync(join(dir, 'text.yaml'), manifest('app-access'));
  writeFileSync(join(dir, 'text.svg'), '<html><script>alert(1)</script></html>');
  setContentDir(root);
  getSessionMock.mockResolvedValue(session('aal1'));
  getIdentityMock.mockResolvedValue(identity({ metadataAdmin: { groups: ['app-access'] } }));
});

afterEach(() => {
  setContentDir(undefined);
  rmSync(root, { recursive: true, force: true });
});

function call(slug: string, cookie: string | null = 'c=1') {
  const url = new URL(`http://portal.test/icons/${slug}.svg`);
  const headers = cookie ? { cookie } : undefined;
  return GET({ params: { slug }, request: new Request(url, { headers }), url } as never) as Promise<Response>;
}

describe('GET /icons/<stem>.svg', () => {
  it('serves the sidecar sandboxed to a viewer who can see the tile', async () => {
    const res = await call('app');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/svg+xml');
    expect(res.headers.get('content-security-policy')).toContain('sandbox');
    expect(res.headers.get('cache-control')).toContain('private');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await res.text()).toBe(SVG);
  });

  it('keeps the route CSP through the middleware', async () => {
    const res = (await onRequest({ request: new Request('http://portal.test/icons/app.svg'), url: new URL('http://portal.test/icons/app.svg') } as never, async () => call('app'))) as Response;
    expect(res.headers.get('content-security-policy')).toMatch(/^sandbox/);
  });

  it('serves a logo of exactly 32 KiB and refuses one byte more', async () => {
    expect((await call('edge')).status).toBe(200);
    expect((await call('over')).status).toBe(404);
  });

  it('is 404 without a session cookie', async () => {
    expect((await call('app', null)).status).toBe(404);
  });

  it('is 404 for an inactive session', async () => {
    getSessionMock.mockResolvedValue(null);
    expect((await call('app')).status).toBe(404);
  });

  it('is 404 for a viewer outside the tile group', async () => {
    getIdentityMock.mockResolvedValue(identity({ metadataAdmin: { groups: ['other'] } }));
    expect((await call('app')).status).toBe(404);
  });

  it('is 404 when the identity lookup fails', async () => {
    getIdentityMock.mockRejectedValue(new Error('down'));
    expect((await call('app')).status).toBe(404);
  });

  it.each([['unknown'], ['../app'], ['..%2Fapp'], ['big'], ['text']])('is 404 for %s', async (slug) => {
    expect((await call(slug)).status).toBe(404);
  });
});

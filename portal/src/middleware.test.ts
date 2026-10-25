import { describe, expect, it, vi } from 'vitest';

vi.mock('astro:middleware', () => ({ defineMiddleware: (fn: unknown) => fn }));

import { onRequest } from './middleware';

type Next = () => Promise<Response>;

function run(path: string, accept: string, next: Next) {
  const url = new URL(`http://portal.test${path}`);
  const rewrite = vi.fn(async () => new Response('<html>branded</html>', { headers: { 'content-type': 'text/html' } }));
  const request = new Request(url, { headers: { accept } });
  const res = (onRequest as unknown as (c: unknown, n: Next) => Promise<Response>)({ request, url, rewrite }, next);
  return { res, rewrite };
}

const json = (status: number) => async () =>
  new Response('{"error":"x"}', { status, headers: { 'content-type': 'application/json' } });

const BASELINE = [
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'strict-transport-security',
  'content-security-policy',
];

describe('middleware', () => {
  it('rebrands an HTML navigation error and keeps the original status', async () => {
    const { res, rewrite } = run('/nope', 'text/html', json(404));
    const out = await res;
    expect(out.status).toBe(404);
    expect(rewrite).toHaveBeenCalledWith('/auth/error?reason=not-found');
    expect(await out.text()).toContain('branded');
  });

  it('rewrites an unmapped status to the forbidden copy', async () => {
    const { res, rewrite } = run('/x', 'text/html', json(418));
    expect((await res).status).toBe(418);
    expect(rewrite).toHaveBeenCalledWith('/auth/error?reason=forbidden');
  });

  it('leaves a JSON caller\'s error body untouched', async () => {
    const { res, rewrite } = run('/api/x', 'application/json', json(403));
    const out = await res;
    expect(rewrite).not.toHaveBeenCalled();
    expect(await out.text()).toBe('{"error":"x"}');
  });

  it('does not rewrite the error routes themselves', async () => {
    const { res, rewrite } = run('/auth/error', 'text/html', json(500));
    await res;
    expect(rewrite).not.toHaveBeenCalled();
  });

  it.each([
    ['a 200', '/', 'text/html', 200],
    ['a rebranded 404', '/nope', 'text/html', 404],
    ['a JSON 500', '/api/x', 'application/json', 500],
  ])('sets the full header baseline on %s', async (_n, path, accept, status) => {
    const { res } = run(path, accept, json(status));
    const out = await res;
    for (const h of BASELINE) expect(out.headers.get(h), h).toBeTruthy();
    expect(out.headers.get('strict-transport-security')).toBe('max-age=63072000; includeSubDomains; preload');
    expect(out.headers.get('cross-origin-opener-policy')).toBe('same-origin');
  });

  it('keeps a CSP the route set', async () => {
    const { res } = run('/icons/a.svg', 'image/svg+xml', async () =>
      new Response('', { headers: { 'content-security-policy': 'sandbox' } }));
    expect((await res).headers.get('content-security-policy')).toBe('sandbox');
  });
});

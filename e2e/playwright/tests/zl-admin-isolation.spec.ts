// ZL — the admin surfaces are not reachable from the public edge.

import { test, expect } from '../fixtures';

test('ZL2 — admin-only routes are not served through the edge', async ({ ctx, baseURL }) => {
  for (const path of ['/healthz', '/readyz', '/admin/identities', '/admin/clients', '/admin/health/ready']) {
    const resp = await ctx.request.get(`${baseURL}${path}`, { maxRedirects: 0 });
    const json = (resp.headers()['content-type'] ?? '').includes('json');
    expect(json, `${path}: got ${resp.status()} JSON from the edge`).toBe(false);
  }
});

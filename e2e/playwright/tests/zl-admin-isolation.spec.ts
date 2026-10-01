// ZL — the admin surfaces are not reachable from the public edge.

import net from 'node:net';
import { test, expect } from '../fixtures';

/** Resolve true when a TCP connection to host:port succeeds, false when refused or silent. */
const reachable = (host: string, port: number) =>
  new Promise<boolean>((resolve) => {
    const s = net.connect({ host, port, timeout: 2000 });
    s.once('connect', () => (s.destroy(), resolve(true)));
    s.once('error', () => resolve(false));
    s.once('timeout', () => (s.destroy(), resolve(false)));
  });

test('ZL1 — the edge listens on the public port only: Kratos, Hydra and portal admin ports are closed', async ({ baseURL }) => {
  const host = new URL(baseURL!).hostname;
  expect(await reachable(host, 80), 'control: the public port answers').toBe(true);
  for (const port of [4434, 4445, 4431]) {
    expect(await reachable(host, port), `${host}:${port} must not accept connections`).toBe(false);
  }
});

test('ZL2 — admin-only routes are not served through the edge', async ({ ctx, baseURL }) => {
  for (const path of ['/healthz', '/readyz', '/admin/identities', '/admin/clients', '/admin/health/ready']) {
    const resp = await ctx.request.get(`${baseURL}${path}`, { maxRedirects: 0 });
    const json = (resp.headers()['content-type'] ?? '').includes('json');
    expect(resp.status() === 200 && json, `${path}: got ${resp.status()} JSON from the edge`).toBe(false);
  }
});

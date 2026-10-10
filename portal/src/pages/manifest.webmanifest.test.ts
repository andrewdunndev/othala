import { it, expect, vi } from 'vitest';

it('names the app for the deployment and carries no estate wording', async () => {
  vi.stubEnv('OTHALA_INSTANCE_NAME', 'Acme');
  vi.resetModules();
  const { GET } = await import('./manifest.webmanifest.js');
  const res = await (GET as () => Response | Promise<Response>)();
  expect(res.headers.get('content-type')).toBe('application/manifest+json');
  expect(await res.json()).toMatchObject({ name: 'Acme', short_name: 'Acme', description: 'Single sign-on portal.' });
  vi.unstubAllEnvs();
});

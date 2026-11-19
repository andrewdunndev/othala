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

it('lists the 192 and 512 PNG icons', async () => {
  vi.resetModules();
  const { GET } = await import('./manifest.webmanifest.js');
  const res = await (GET as () => Response | Promise<Response>)();
  const { icons } = (await res.json()) as { icons: Array<{ src: string; sizes: string; type: string }> };
  expect(icons.map((i) => [i.src, i.sizes, i.type])).toEqual([
    ['/icon-192.png', '192x192', 'image/png'],
    ['/icon-512.png', '512x512', 'image/png'],
  ]);
});

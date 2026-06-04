/**
 * fixtures/index.ts — Othala test fixtures, mirroring Ory Kratos's
 * test/e2e/playwright/fixtures pattern.
 *
 * Exposes via test.extend:
 *   baseURL         — http://auth.othala.test (the Caddy edge inside compose)
 *   kratosAdminURL  — http://kratos:4434 (admin API, reachable inside compose net)
 *   hydraPublicURL  — http://hydra:4444 (Hydra public, inside compose net)
 *   hydraAdminURL   — http://hydra:4445 (Hydra admin, inside compose net)
 *   member          — { id, email, password } seeded identity (bt2@othala.test),
 *                     access-grafana group, NOT on OTHALA_ADMIN_SUBJECTS
 *   admin           — { id, email, password } seeded identity (admin@othala.test),
 *                     ON OTHALA_ADMIN_SUBJECTS (triggers AAL2 step-up at /admin)
 *
 * Both identities are seeded ONCE per worker (scope: 'worker') so the cost is
 * paid at most once across the serial test run.
 */

import { test as base } from '@playwright/test';
import { createIdentityWithPassword, TEST_PASSWORD, type SeedResult } from '../actions/identity';

export interface OthalaFixtures {
  baseURL: string;
  kratosAdminURL: string;
  hydraPublicURL: string;
  hydraAdminURL: string;
  member: SeedResult & { password: string };
  admin: SeedResult & { password: string };
}

export const test = base.extend<OthalaFixtures>({
  // URLs: read from env (injected by compose playwright service) or fall back
  // to the compose-net defaults. Tests inside the compose net can reach these
  // directly; the Playwright container is on the same compose network.
  baseURL: async ({}, use) => {
    await use(process.env.BASE ?? 'http://auth.othala.test');
  },

  // Worker-scoped: the worker-scoped `member`/`admin` fixtures depend on
  // kratosAdminURL, and a worker fixture cannot depend on a test-scoped one.
  // (Matches Ory upstream, where these URLs are worker-scoped options.)
  kratosAdminURL: [async ({}, use) => {
    await use(process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434');
  }, { scope: 'worker' }],

  hydraPublicURL: [async ({}, use) => {
    await use(process.env.HYDRA_PUBLIC_URL ?? 'http://hydra:4444');
  }, { scope: 'worker' }],

  hydraAdminURL: [async ({}, use) => {
    await use(process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445');
  }, { scope: 'worker' }],

  // member: bt2@othala.test, access-grafana + family groups.
  // NOT on OTHALA_ADMIN_SUBJECTS (admin@othala.test is).
  member: [
    async ({ kratosAdminURL }, use) => {
      const result = await createIdentityWithPassword({
        email: 'bt2@othala.test',
        username: 'bt2',
        displayName: 'Browser Test 2',
        groups: ['family', 'access-grafana'],
        kratosAdminURL,
      });
      await use({ ...result, password: TEST_PASSWORD });
    },
    { scope: 'worker' },
  ],

  // admin: admin@othala.test — must match OTHALA_ADMIN_SUBJECTS in gen-secrets.sh.
  // The admin gate (requireAdminSession in the othala app) checks this list.
  // At AAL1 (password only), visiting /admin triggers the AAL2 step-up redirect.
  admin: [
    async ({ kratosAdminURL }, use) => {
      const result = await createIdentityWithPassword({
        email: 'admin@othala.test',
        username: 'admin',
        displayName: 'Othala Admin',
        groups: ['family', 'access-grafana', 'admin'],
        kratosAdminURL,
      });
      await use({ ...result, password: TEST_PASSWORD });
    },
    { scope: 'worker' },
  ],
});

export { expect } from '@playwright/test';

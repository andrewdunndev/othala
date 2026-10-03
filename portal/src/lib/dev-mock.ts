// Dev-only mock identity for `astro dev` pages that cannot reach Kratos (index.astro, apps/[slug].astro,
// requirements/[name].astro). Every entry point returns null outside dev, so production never reads a query param.

import type { Identity } from './types';

/**
 * Groups for the mock person. They must intersect the `presentation.access:` groups of the manifests in MANIFEST_DIR or
 * zero tiles render. OTHALA_DEV_MOCK_GROUPS sets the list, and `?dev-groups=a,b` overrides it for one request.
 */
function mockGroups(url: URL): string[] {
  const fromQuery = url.searchParams.get('dev-groups');
  const raw: string | undefined = fromQuery ?? import.meta.env.OTHALA_DEV_MOCK_GROUPS;
  if (raw) return raw.split(',').map((g) => g.trim()).filter(Boolean);
  return ['everyone', 'grafana-access', 'audiobookshelf-access', 'proxywatch-access', 'prompt-access'];
}

/** The mock person for a dev request, or null outside dev. `?dev-prereqs=tailscale,vpn` sets the prerequisites the
 *  admin has marked for them; absent means none are marked. */
export function devMockIdentity(url: URL): Identity | null {
  if (!import.meta.env.DEV) return null;
  const prereqs = (url.searchParams.get('dev-prereqs') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  return {
    id: 'dev-mock',
    traits: { username: 'dev.user', email: 'dev@example.local', displayName: 'Dev User' },
    metadata_admin: { groups: mockGroups(url), prerequisites: prereqs },
  } as unknown as Identity;
}

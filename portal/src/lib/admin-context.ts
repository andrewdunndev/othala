// What every /admin page starts from: the admin gate (AAL2, freshness and the admin marker, via requireAdminSession) and
// the served app catalog. In `astro dev`, `?dev-state=` swaps both for a fixture household so the pages iterate without
// Kratos; production never reads that parameter.

import { requireAdminSession } from './admin';
import { joinApps, type AdminApp } from './admin-view';
import { devAdmin, isDevAdminState, type DevAdmin } from './admin-fixtures';
import { manifestHealth, servingManifests, type ManifestHealth } from './manifest-store';
import { loadTiles } from './tiles';

export interface AdminContext {
  /** The signed-in admin's identity id. */
  adminId: string;
  apps: AdminApp[];
  health: ManifestHealth;
  /** Set only for a dev fixture request; the page reads people from it instead of Kratos and refuses to write. */
  dev: DevAdmin | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function adminContext(astro: any): Promise<AdminContext | Response> {
  const devParam: string | null = import.meta.env.DEV ? astro.url.searchParams.get('dev-state') : null;
  if (isDevAdminState(devParam)) {
    const dev = devAdmin(devParam);
    const health: ManifestHealth = dev.broken
      ? { status: 'stale', error: 'grafana.yaml: presentation.access names an unknown group', failingSinceMs: Date.now() - 600_000, serving: dev.apps.length }
      : { status: 'ok', error: null, failingSinceMs: null, serving: dev.apps.length };
    return { adminId: dev.adminId, apps: dev.apps, health, dev };
  }

  const guard = await requireAdminSession(astro);
  if (guard instanceof Response) return guard;

  // Serving store, not the strict loader: operators grant and revoke access here, so these pages must survive a broken manifest.
  let tiles: ReturnType<typeof loadTiles> = [];
  try {
    tiles = loadTiles();
  } catch (err) {
    console.error('[othala/admin] loadTiles failed:', err);
  }
  return { adminId: guard.identity?.id ?? '', apps: joinApps(servingManifests(), tiles), health: manifestHealth(), dev: null };
}

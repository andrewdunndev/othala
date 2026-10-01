// What the Apps page reads beyond the manifests: which OIDC clients Hydra already has (so an app whose client was never
// registered shows a problem), and who holds which level on an app. A failed Hydra read is "unknown", never "synced".

import { HYDRA_ADMIN_URL } from './constants';
import type { AdminApp } from './admin-view';
import { currentLevel, isOpenToEveryone, levelsFor, NO_ACCESS } from './access-rows';
import type { Identity } from './types';

/** Client ids Hydra holds, or null when Hydra cannot be read (so nothing is claimed about sync). */
export async function hydraClientIds(fetcher: typeof fetch = fetch): Promise<Set<string> | null> {
  try {
    const res = await fetcher(`${HYDRA_ADMIN_URL}/admin/clients?page_size=500`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (!Array.isArray(body)) return null;
    return new Set(body.map((c) => (c as { client_id?: unknown }).client_id).filter((v): v is string => typeof v === 'string'));
  } catch {
    return null;
  }
}

export interface Holder {
  id: string;
  name: string;
  /** Their level's label when it is above the app's base level; empty at the base level. */
  level: string;
  /** Their sign-in is off, so the app is listed but they cannot use it. */
  off: boolean;
}

/** People who hold the app (any level above No access), with their level shown only above the base level. Open apps have no holders list. */
export function holdersOf(app: AdminApp, people: readonly { identity: Identity; name: string }[]): Holder[] {
  const m = app.manifest;
  if (isOpenToEveryone(m)) return [];
  const levels = levelsFor(m);
  const out: Holder[] = [];
  for (const p of people) {
    const level = currentLevel(m, p.identity.metadata_admin);
    if (level === NO_ACCESS) continue;
    const label = levels.find((l) => l.value === level)?.label ?? level;
    out.push({ id: p.identity.id, name: p.name, level: level === levels[0].value ? '' : label, off: p.identity.state === 'inactive' });
  }
  return out;
}

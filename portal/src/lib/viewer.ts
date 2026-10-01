// Who is looking at a focused page, for the top bar (Account, Sign out) and for choosing error actions. Cosmetic only:
// any failure or slow answer reads as signed out, and no decision about access hangs on it. In `astro dev`,
// `?dev-viewer=member|admin` stands in for a session so signed-in states render without Kratos.

import { getSession } from './kratos';
import { getIdentity } from './admin-api';
import { parseIdentity } from './identity-facts';

export interface Viewer {
  identityId: string;
  isAdmin: boolean;
}

const LOOKUP_MS = 1500;

/** The dev stand-in for a viewer, or null: only ever non-null in dev, only for the two known values. */
export function devViewer(dev: boolean, param: string | null): Viewer | null {
  if (!dev || (param !== 'member' && param !== 'admin')) return null;
  return { identityId: 'dev-mock', isAdmin: param === 'admin' };
}

export async function currentViewer(request: Request, url: URL): Promise<Viewer | null> {
  const mock = devViewer(import.meta.env.DEV, url.searchParams.get('dev-viewer'));
  if (mock) return mock;
  const cookie = request.headers.get('cookie') ?? undefined;
  if (!cookie) return null;
  const lookup = (async (): Promise<Viewer | null> => {
    const session = await getSession(cookie);
    const id = session?.active ? session.identity?.id : undefined;
    if (!id) return null;
    const isAdmin = await getIdentity(id).then((i) => parseIdentity(i).isAdmin, () => false);
    return { identityId: id, isAdmin };
  })();
  const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), LOOKUP_MS));
  return Promise.race([lookup.catch(() => null), timeout]);
}

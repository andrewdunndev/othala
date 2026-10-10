// An app's logo, from its `<slug>.svg` sidecar. Served only to a signed-in viewer who can see the tile; every other
// case (no session, no access, unknown or rejected sidecar) is the same 404, so a stem cannot be probed.

import type { APIRoute } from 'astro';
import { getTile, userCanSeeTile } from '../../lib/tiles';
import { getSession } from '../../lib/kratos';
import { getIdentity } from '../../lib/admin-api';
import { parseIdentity } from '../../lib/identity-facts';
import { devMockIdentity } from '../../lib/dev-mock';
import type { Identity } from '../../lib/types';

export const prerender = false;

const notFound = () => new Response('Not found', { status: 404 });

async function viewerGroups(request: Request, url: URL): Promise<string[] | null> {
  let identity: Identity | null = url.searchParams.get('dev-state') === 'post-auth' ? devMockIdentity(url) : null;
  if (!identity) {
    const cookie = request.headers.get('cookie') ?? undefined;
    if (!cookie) return null;
    const session = await getSession(cookie).catch(() => null);
    if (!session?.active || !session.identity) return null;
    identity = await getIdentity(session.identity.id).catch(() => null);
  }
  return identity ? parseIdentity(identity).groups : null;
}

export const GET: APIRoute = async ({ params, request, url }) => {
  const groups = await viewerGroups(request, url);
  const tile = params.slug ? getTile(params.slug) : undefined;
  if (!groups || !tile?.iconSvg || !userCanSeeTile(tile, groups)) return notFound();
  return new Response(tile.iconSvg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Content-Security-Policy': "sandbox; default-src 'none'; style-src 'unsafe-inline'",
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, max-age=300',
    },
  });
};

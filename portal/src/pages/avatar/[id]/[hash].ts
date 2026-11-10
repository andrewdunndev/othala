// A member's picture, at a URL that names the identity and the first 16 hex digits of the image hash. Relying-party
// servers fetch it with no cookie, so it is unauthenticated; the UUID plus the hash is the capability, and a new picture
// is a new URL. A malformed id, unknown identity, absent picture and stale hash are the same 404.

import type { APIRoute } from 'astro';
import { getIdentity } from '../../../lib/admin-api';
import { AVATAR_HASH_RE, AVATAR_ID_RE, readAvatar } from '../../../lib/avatar';

export const prerender = false;

const notFound = () =>
  new Response('Not found', {
    status: 404,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });

export const GET: APIRoute = async ({ params }) => {
  const { id, hash } = params;
  if (!id || !hash || !AVATAR_ID_RE.test(id) || !AVATAR_HASH_RE.test(hash)) return notFound();
  const identity = await getIdentity(id).catch(() => null);
  const avatar = readAvatar(identity?.metadata_admin);
  if (!avatar || avatar.sha256.slice(0, 16) !== hash) return notFound();
  return new Response(Buffer.from(avatar.data, 'base64'), {
    headers: {
      'Content-Type': avatar.type,
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'public, max-age=31536000, immutable',
      ETag: `"${avatar.sha256}"`,
    },
  });
};

// POST /auth/passkey-name: rename one of the signed-in person's passkeys. Kratos v26.2.0 holds no passkey name, so the
// name is stored in metadata_admin.passkeyNames by a targeted admin patch. Needs the Kratos session (so the identity is
// the caller's own), a CSRF token minted for that identity, and a credential id that identity owns.

import type { APIRoute } from 'astro';
import { browserFlows, getSession } from '../../lib/kratos';
import { getIdentity, patchPasskeyName } from '../../lib/admin-api';
import { verifyToken, CSRFError } from '../../lib/csrf';
import { applyRename } from '../../lib/passkey-names';
import { publicUrl } from '../../lib/config';

export const prerender = false;

const text = (status: number, body: string) =>
  new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });

export const POST: APIRoute = async ({ request, redirect }) => {
  let session;
  try {
    session = await getSession(request.headers.get('cookie') ?? undefined);
  } catch {
    return text(503, 'Please try again in a moment.');
  }
  if (!session?.active || !session.identity) return text(401, 'Please sign in.');

  const fd = await request.formData();
  try {
    verifyToken(String(fd.get('csrf_token') ?? ''), session.identity.id, 'passkey-name');
  } catch (err) {
    if (err instanceof CSRFError) return text(403, `CSRF: ${err.message}`);
    throw err;
  }

  let stored;
  try {
    stored = await getIdentity(session.identity.id);
  } catch (err) {
    console.error('[othala/passkey-name] identity read failed:', err);
    return text(503, 'Please try again in a moment.');
  }

  try {
    const verdict = await applyRename(stored, fd.get('credential_id'), fd.get('name'), patchPasskeyName);
    if (!verdict.ok) return text(verdict.status, verdict.error);
  } catch (err) {
    console.error('[othala/passkey-name] write failed:', err);
    return text(503, 'Could not save the name. Please try again.');
  }
  return redirect(browserFlows.settings(`${publicUrl}/auth/settings`), 303);
};

// POST /auth/passkey-name: rename one of the signed-in person's passkeys. Kratos v26.2.0 holds no passkey name, so the
// name is stored in metadata_admin.passkeyNames by a targeted admin patch. Needs the Kratos session (so the identity is
// the caller's own), a CSRF token minted for that identity, and a credential id that identity owns. Every outcome is a
// 303 back to the settings page (a plain-text answer would strand a script-driven post on a bare error page); a refusal
// leaves a one-minute cookie the page reads once to say why under that passkey's row.

import type { APIRoute } from 'astro';
import { browserFlows, getSession } from '../../lib/kratos';
import { getIdentity, patchPasskeyName } from '../../lib/admin-api';
import { csrfRefusal } from '../../lib/csrf';
import { applyRename, CREDENTIAL_ID_RE } from '../../lib/passkey-names';
import { publicUrl } from '../../lib/config';
import { RENAME_ERROR_COOKIE } from '../../lib/settings-flash';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect, cookies }) => {
  const back = () => redirect(browserFlows.settings(`${publicUrl}/auth/settings`), 303);
  let credentialId = '';
  const refuse = (code: string) => {
    cookies.set(RENAME_ERROR_COOKIE, `${credentialId}.${code}`, {
      path: '/auth/settings',
      maxAge: 60,
      httpOnly: true,
      sameSite: 'lax',
      secure: import.meta.env.PROD,
    });
    return back();
  };

  let session;
  try {
    session = await getSession(request.headers.get('cookie') ?? undefined);
  } catch {
    return redirect('/auth/login', 303);
  }
  if (!session?.active || !session.identity) return redirect('/auth/login', 303);

  const fd = await request.formData();
  const rawId = fd.get('credential_id');
  if (typeof rawId === 'string' && CREDENTIAL_ID_RE.test(rawId)) credentialId = rawId;
  if (csrfRefusal(String(fd.get('csrf_token') ?? ''), session.identity.id, 'passkey-name') !== null) return refuse('csrf');

  let stored;
  try {
    stored = await getIdentity(session.identity.id);
  } catch (err) {
    console.error('[othala/passkey-name] identity read failed:', err);
    return refuse('busy');
  }

  try {
    const verdict = await applyRename(stored, fd.get('credential_id'), fd.get('name'), patchPasskeyName);
    if (!verdict.ok) return refuse(verdict.code);
  } catch (err) {
    console.error('[othala/passkey-name] write failed:', err);
    return refuse('busy');
  }
  return back();
};

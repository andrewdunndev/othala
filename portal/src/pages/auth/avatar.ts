// POST /auth/avatar: set or remove the signed-in person's own picture. Needs the Kratos session (so the identity is the
// caller's own) and a CSRF token minted for that identity. Every outcome is a 303 back to the settings page; a one-minute
// cookie carries the result the page reads once.

import type { APIRoute } from 'astro';
import { browserFlows, getSession } from '../../lib/kratos';
import { csrfRefusal } from '../../lib/csrf';
import { publicUrl } from '../../lib/config';
import { AVATAR_BODY_MAX, readCapped } from '../../lib/avatar';
import { applyAvatarForm } from '../../lib/avatar-edit';
import { AVATAR_FLASH_COOKIE } from '../../lib/settings-flash';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect, cookies }) => {
  const back = (code: string) => {
    cookies.set(AVATAR_FLASH_COOKIE, code, {
      path: '/auth/settings',
      maxAge: 60,
      httpOnly: true,
      sameSite: 'lax',
      secure: import.meta.env.PROD,
    });
    return redirect(browserFlows.settings(`${publicUrl}/auth/settings#picture`), 303);
  };

  let session;
  try {
    session = await getSession(request.headers.get('cookie') ?? undefined);
  } catch {
    return redirect('/auth/login', 303);
  }
  if (!session?.active || !session.identity) return redirect('/auth/login', 303);

  const body = await readCapped(request, AVATAR_BODY_MAX);
  if (body === null) return back('too-large');
  let fd: FormData;
  try {
    fd = await new Response(new Blob([body as BlobPart]), { headers: { 'content-type': request.headers.get('content-type') ?? '' } }).formData();
  } catch {
    return back('type');
  }
  if (csrfRefusal(String(fd.get('csrf_token') ?? ''), session.identity.id, 'avatar') !== null) return back('csrf');

  try {
    const result = await applyAvatarForm(fd, session.identity.id);
    return back(result.ok ? result.change : result.code);
  } catch (err) {
    console.error('[othala/avatar] write failed:', err);
    return back('busy');
  }
};

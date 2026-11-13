// Portal middleware. Rebrands HTML 4xx/5xx responses with the portal's error
// pages via context.rewrite() (no body re-consumed), skipping non-HTML callers
// and the error routes themselves, and applies security headers to every
// response. The CSP omits script-src deliberately: a strict one breaks the
// Kratos WebAuthn ceremony and the portal's inline scripts.
//
// Denials happen at two layers and this middleware sees only one. Astro's `security.checkOrigin` runs ahead of user
// middleware and answers a bare 403 without calling next(), so nothing here can brand it; leave it on, since the bypass
// of this exact check (CVE-2024-56140) turned on content-type handling. A normal browser sends a matching Origin, so
// that 403 is effectively attacker-only. Past it, the guards (requireAdminSession, consent CSRF) return structured
// denials that redirect to auth/error with a `reason` that error-reasons.ts maps to copy. Both layers are asserted
// together in e2e r-admin-post-origin and h-member-admin-post. A new denial is a reason entry, never a new page.

import { defineMiddleware } from 'astro:middleware';
import { contentSecurityPolicy } from './lib/csp';
import { KRATOS_PUBLIC_URL } from './lib/constants';
import { apex, publicUrl } from './lib/config';

// Routes that are themselves error pages — rewriting these would loop.
const ERROR_ROUTE_PREFIXES = ['/auth/error', '/404', '/500'];

// Security response headers applied to every response (see the CSP note above).
function applySecurityHeaders(res: Response): void {
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('X-Content-Type-Options', 'nosniff');
  // same-origin, not no-referrer: no-referrer makes Chromium send `Origin: null`
  // on same-origin form POSTs, which Astro's checkOrigin then rejects. Nothing
  // still leaks cross-origin.
  res.headers.set('Referrer-Policy', 'same-origin');
  res.headers.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  // HSTS: 2-year max-age + includeSubDomains + preload.
  // The IdP is HTTPS-only behind Caddy and serves both the apex and subdomains.
  res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  // form-action allowlist: see lib/csp.ts. A route that set its own CSP keeps it.
  if (res.headers.has('Content-Security-Policy')) return;
  res.headers.set(
    'Content-Security-Policy',
    contentSecurityPolicy({
      apex,
      kratosUrls: [publicUrl, KRATOS_PUBLIC_URL],
    }),
  );
}

// HTTP status to /auth/error reason; unknown codes fall back to 'forbidden'.
const STATUS_REASON: Record<number, string> = {
  400: 'forbidden',
  401: 'session-expired',
  403: 'forbidden',
  404: 'not-found',
  429: 'rate-limited',
  500: 'server-error',
  502: 'unavailable',
  503: 'unavailable',
  504: 'unavailable',
};

export const onRequest = defineMiddleware(async (context, next) => {
  const res = await next();

  // Rebrand only error-range HTML navigations that are not already an error page or branded HTML (loop prevention).
  const path = context.url.pathname;
  const rebrand =
    res.status >= 400 &&
    (context.request.headers.get('accept') ?? '').includes('text/html') &&
    !ERROR_ROUTE_PREFIXES.includes(path) &&
    !(res.headers.get('content-type') ?? '').includes('text/html');
  if (!rebrand) {
    applySecurityHeaders(res);
    return res;
  }

  // Rewrite to the branded /auth/error page but keep the original status; the
  // reason only drives the copy. The rewritten Response is immutable, so build
  // a fresh one to apply security headers.
  const reason = STATUS_REASON[res.status] ?? 'forbidden';
  const branded = await context.rewrite(`/auth/error?reason=${reason}`);
  const final = new Response(branded.body, {
    status: res.status,
    statusText: res.statusText,
    headers: branded.headers,
  });
  applySecurityHeaders(final);
  return final;
});

// Portal middleware. Rebrands HTML 4xx/5xx responses with the portal's error
// pages via context.rewrite() (no body re-consumed), skipping non-HTML callers
// and the error routes themselves, and applies security headers to every
// response. The CSP omits script-src deliberately: a strict one breaks the
// Kratos WebAuthn ceremony and the portal's inline scripts.

import { defineMiddleware } from 'astro:middleware';
import { contentSecurityPolicy } from './lib/csp';
import { kratosBase } from './lib/kratos';
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
      kratosUrls: [publicUrl, kratosBase()],
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

  // Guard 1: only intercept error-range responses for rebrand.
  if (res.status < 400) {
    applySecurityHeaders(res);
    return res;
  }

  // Guard 2: only rewrite HTML navigations. Check the request Accept header.
  const accept = context.request.headers.get('accept') ?? '';
  if (!accept.includes('text/html')) {
    applySecurityHeaders(res);
    return res;
  }

  // Guard 3: don't rewrite error page routes themselves (loop prevention).
  const path = context.url.pathname;
  if (ERROR_ROUTE_PREFIXES.some((prefix) => path === prefix || path.startsWith(prefix + '?'))) {
    applySecurityHeaders(res);
    return res;
  }

  // Guard 4: don't rewrite an already-branded HTML response.
  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('text/html')) {
    // Already branded HTML (e.g. 404.astro, 500.astro); let it through.
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

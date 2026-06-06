// Othala portal middleware.
//
// After the page/route handler runs, inspects the response and rebrands
// HTML 4xx/5xx responses with the portal's error pages.
//
// Rules:
//   - Only rebrands HTML navigation requests (Accept: text/html).
//     API / OAuth2 / programmatic callers keep their machine responses.
//   - Only intercepts 4xx and 5xx responses.
//   - Does NOT rewrite requests already headed to /auth/error or /404 or /500
//     to prevent infinite loops.
//   - Uses context.rewrite() to a parameterless route so no request body is
//     re-consumed (avoids the "body already consumed" error on POST pages).
//
// Security notes:
//   - The Astro checkOrigin (security.checkOrigin) 403 fires BEFORE user
//     middleware and returns early, so this handler never sees it.
//     That case is handled at the Caddy edge layer — out of scope here.
//   - Never inject error details, stack traces, or upstream messages into
//     the rebranded response.

import { defineMiddleware } from 'astro:middleware';

// Routes that are themselves error pages — rewriting these would loop.
const ERROR_ROUTE_PREFIXES = ['/auth/error', '/404', '/500'];

// Map from HTTP status code to the /auth/error reason param.
// Entries here cover the most common app-emitted codes. Unknown status codes
// fall back to the generic 'forbidden' entry (which itself falls back to
// DEFAULT_ENTRY in /auth/error.astro).
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

  // Guard 1: only intercept error-range responses.
  if (res.status < 400) return res;

  // Guard 2: only rewrite HTML navigations. Check the request Accept header.
  const accept = context.request.headers.get('accept') ?? '';
  if (!accept.includes('text/html')) return res;

  // Guard 3: don't rewrite error page routes themselves (loop prevention).
  const path = context.url.pathname;
  if (ERROR_ROUTE_PREFIXES.some((prefix) => path === prefix || path.startsWith(prefix + '?'))) {
    return res;
  }

  // Guard 4: don't rewrite if the response is already branded HTML
  // (another middleware or an upstream forward has already handled it).
  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('text/html')) {
    // It's already HTML — let it through as-is; the page itself set the
    // status and rendered the branded response (e.g. 404.astro, 500.astro).
    return res;
  }

  // Rewrite to the branded /auth/error page, but PRESERVE the original status
  // code. /auth/error derives a status from the reason; we override it so a raw
  // 500 doesn't get downgraded to the reason's status (e.g. 403). The reason
  // only drives the human copy; res.status stays authoritative.
  const reason = STATUS_REASON[res.status] ?? 'forbidden';
  const branded = await context.rewrite(`/auth/error?reason=${reason}`);
  return new Response(branded.body, {
    status: res.status,
    statusText: res.statusText,
    headers: branded.headers,
  });
});

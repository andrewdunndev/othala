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
//   - Security response headers are applied to EVERY response (2xx, 3xx,
//     4xx, 5xx) after all other processing, including rebranded error pages.
//   - The Astro checkOrigin (security.checkOrigin) 403 fires BEFORE user
//     middleware and returns early, so this handler never sees it.
//     That case is handled at the Caddy edge layer — out of scope here.
//   - Never inject error details, stack traces, or upstream messages into
//     the rebranded response.
//
// CSP note:
//   - The CSP header below intentionally contains ONLY frame-ancestors,
//     object-src, and base-uri. A strict script-src is deliberately omitted:
//     it can break the Kratos WebAuthn login ceremony (which injects inline
//     <script> nodes) and the portal's own inline theme/modal scripts. Adding
//     a strict script-src requires live e2e validation of every auth flow.
//     Deferred to live-gate validation (tracked in docs/hardening.md §2).

import { defineMiddleware } from 'astro:middleware';

// Routes that are themselves error pages — rewriting these would loop.
const ERROR_ROUTE_PREFIXES = ['/auth/error', '/404', '/500'];

// Security response headers applied to every response.
// See CSP note in the file header for why script-src is absent.
function applySecurityHeaders(res: Response): void {
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('X-Content-Type-Options', 'nosniff');
  // Referrer-Policy: same-origin (not no-referrer — see work item #5).
  //
  // Intent this preserves: no-referrer's job was to stop the `flow` /
  // `consent_challenge` query-param tokens on the login/consent pages from
  // leaking to a third party in the Referer header (docs/hardening.md §2,
  // docs/security-review-2026-06-07.md HIGH-A/HIGH-B — originally the Google
  // Fonts CDN, before fonts were self-hosted). `same-origin` still sends NO
  // referrer at all to any cross-origin destination, so that leak is fully
  // closed; it only additionally allows the full referrer on same-origin
  // navigations, which discloses nothing Othala doesn't already know.
  //
  // Bug this fixes (work item #5): `no-referrer` also suppresses the Origin
  // header Chromium sends on a same-origin form-POST navigation (it arrives
  // as `Origin: null`). Astro's built-in security.checkOrigin CSRF gate then
  // 403s the request before any app code runs — every state-changing admin
  // POST (issue-recovery, force-relogin, deactivate, delete, grant/revoke-
  // admin, profile save) was unreachable from a real browser. `same-origin`
  // restores the same-origin Origin header and unblocks checkOrigin while
  // keeping the cross-origin privacy guarantee intact.
  res.headers.set('Referrer-Policy', 'same-origin');
  res.headers.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  // HSTS: 2-year max-age + includeSubDomains + preload.
  // The IdP is HTTPS-only behind Caddy and serves both the apex and subdomains.
  res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  // form-action: Kratos self-service forms POST to the portal origin ('self'),
  // but an OIDC login's post-login redirect lands on the requesting app's
  // domain — a subdomain of the estate apex — and form-action governs a form
  // submission's REDIRECT CHAIN, not just its action URL. So 'self' alone blocks
  // every OIDC app login (the redirect to e.g. larder.dunn.dev violates it).
  // Allow 'self' + the apex wildcard (https://*.<OTHALA_APEX>) — exactly the
  // estate's own apps; absent OTHALA_APEX, fall back to strict 'self'. Still
  // prevents credential exfiltration to arbitrary off-estate origins.
  // script-src deferred — see docs/hardening.md §2 and the file-level CSP note.
  const apex = process.env.OTHALA_APEX?.trim();
  const formAction = apex ? `'self' https://*.${apex}` : "'self'";
  res.headers.set(
    'Content-Security-Policy',
    `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action ${formAction}`,
  );
}

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

  // Guard 4: don't rewrite if the response is already branded HTML
  // (another middleware or an upstream forward has already handled it).
  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('text/html')) {
    // It's already HTML — let it through as-is; the page itself set the
    // status and rendered the branded response (e.g. 404.astro, 500.astro).
    applySecurityHeaders(res);
    return res;
  }

  // Rewrite to the branded /auth/error page, but PRESERVE the original status
  // code. /auth/error derives a status from the reason; we override it so a raw
  // 500 doesn't get downgraded to the reason's status (e.g. 403). The reason
  // only drives the human copy; res.status stays authoritative.
  //
  // Note: the branded Response is reconstructed via new Response(...) because
  // Response objects returned by context.rewrite() are immutable; we must build
  // a fresh mutable Response to apply security headers.
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

# Error handling and the two-layer deny model

Requests are denied at two layers and the application sees only one, which is
why the error surfaces look asymmetric. Read this before changing
`portal/src/middleware.ts` or any error page.

## The two layers

**Framework CSRF, before app code.** Astro's `security.checkOrigin` is on by
default: for form-content-type mutations it compares `Origin` against the
request host and returns a bare `403` without rendering. It is sequenced ahead
of user middleware and returns without calling `next()`, so nothing in
application code — middleware included — can observe or rebrand it. Never
disable or reimplement it; the bypass of this exact check (CVE-2024-56140)
turned on content-type handling.

**Application guards, inside the route.** Past `checkOrigin`,
`requireAdminSession` in `portal/src/lib/admin.ts` redirects a session below
`aal2` into the Kratos step-up flow and redirects an identity without the admin
marker to a branded error page; consent CSRF tampering answers `400`. Application-layer denials are structured and reachable by real users; the
`checkOrigin` 403 is effectively attacker-only because a normal browser sends a
matching `Origin`. Both layers are asserted together in
`e2e/playwright/tests/r-admin-post-origin.spec.ts` and
`h-member-admin-post.spec.ts` — an origin-less POST gets the framework 403, a
same-origin POST gets the application's structured deny.

## One branded surface, not many

Every branded status page renders through
`portal/src/components/StatusPage.astro` — status, title, message, an optional
reason badge, never any internals. Denials redirect to
`portal/src/pages/auth/error.astro` carrying a `reason` that page maps to copy;
middleware rebrands raw non-HTML application errors for HTML navigations only,
preserves the original status, and leaves API responses alone. Adding a denial reason is therefore a data change, not a new page.

## The one surface that stays unbranded

Because `checkOrigin` short-circuits before user middleware, the framework `403`
is the one deny the portal cannot brand. It ships bare. Branding it would mean intercepting upstream 4xx at the reverse
proxy and re-rendering the application's error page, a finicky sub-request
pattern for a population that is only attackers. The acceptance bar for doing
it: the branded page carries the original status, and a portal-down 502 or 503
falls back to something static rather than sub-requesting a dead application.

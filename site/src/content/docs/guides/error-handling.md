# Error handling and the two-layer deny model

An identity provider denies requests at two layers, and the application can only
see one of them. That split is why the error surfaces look asymmetric. Read this
before changing `portal/src/middleware.ts` or any error page.

## The two layers

**Framework CSRF, before app code.** Astro's `security.checkOrigin` is on by
default: for form-content-type mutations it compares `Origin` against the
request host and returns a bare `403` without rendering. It is sequenced ahead
of user middleware and returns without calling `next()`, so nothing in
application code — middleware included — can observe or rebrand it. Never
disable or reimplement it; the historical bypass of this exact check
(CVE-2024-56140) turned on content-type handling, and a hand-rolled equivalent
is a good way to reintroduce it.

**Application guards, inside the route.** Past `checkOrigin`,
`requireAdminSession` in `portal/src/lib/admin.ts` redirects a session below
`aal2` into the Kratos step-up flow and redirects an identity without the admin
marker to a branded error page; consent CSRF tampering answers `400`. The
distinction that matters: application-layer denials are structured,
human-meaningful, and reachable by real users, while the `checkOrigin` 403 is
effectively attacker-only because a normal browser always sends a matching
`Origin`. Both layers are asserted together in
`e2e/playwright/tests/r-admin-post-origin.spec.ts` and
`h-member-admin-post.spec.ts` — an origin-less POST gets the framework 403, a
same-origin POST gets the application's structured deny.

## One branded surface, not many

Every branded status page renders through
`portal/src/components/StatusPage.astro` — status, title, message, an optional
reason badge, never any internals. Denials redirect to
`portal/src/pages/auth/error.astro` carrying a `reason` that page maps to copy;
middleware rebrands raw non-HTML application errors for HTML navigations only,
preserves the original status, and leaves API responses alone. The single source
exists so that adding a denial reason is a data change rather than a new page.

## The one surface that stays unbranded

Because `checkOrigin` short-circuits before user middleware, the framework `403`
is the one deny the portal cannot brand. It ships bare, and that is the current
state rather than an oversight awaiting a fix. Branding it means intercepting
upstream 4xx at the reverse proxy and
re-rendering the application's own error page while preserving the status — a
sub-request pattern finicky enough to need validating against a live stack, and
nobody has paid that cost because the population it helps is attackers. If it is
ever picked up, the acceptance bar is: the branded page carries the original
status, and a portal-down 502 or 503 falls back to something static rather than
sub-requesting a dead application.

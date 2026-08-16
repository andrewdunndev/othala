# Error handling & the two-layer deny model

How Othala denies bad requests, and how every error surface is branded.

The non-obvious part, and the reason this page exists, is that there are two
independent deny layers and the application can only see one of them. Read it
before changing anything in `portal/src/middleware.ts` or the error pages,
because the split is what makes their shape look arbitrary.

## Two layers of denial

A request to a protected endpoint passes through two independent guards.
**Both are intentional defense-in-depth — neither replaces the other.**

1. **Framework CSRF (Astro `security.checkOrigin`, default-on).** For
   `POST/PATCH/PUT/DELETE` with a form content-type
   (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`),
   Astro checks the `Origin` header against the request host. A forged
   cross-origin or origin-less form POST gets a bare **`403`** and the page
   never renders. This runs **before** user middleware (sequenced first in
   `astro/dist/core/base-pipeline.js` via `unshift` + `sequence`, and it
   returns early without `next()`), so nothing in app code — including
   `src/middleware.ts` — can see or rebrand it.
   - **Never disable or reimplement `checkOrigin`.** CVE-2024-56140 was a
     bypass of this exact check (content-type tricks), fixed upstream well
     before the version this portal pins in `portal/package.json`.
     Reimplementing risks reintroducing the bypass.

2. **Application guards (in the page/route).** Once a request passes
   `checkOrigin`, the app's own guards run:
   - `requireAdminSession()` (`portal/src/lib/admin.ts`): session below
     `aal2` → `302 …/self-service/login/browser?aal=aal2&refresh&return_to=…`
     (step-up); identity without the `metadata_admin.admin` marker (ADR 08)
     → `302 /auth/error?reason=not-admin`. These fire for **all** HTTP
     methods.
   - Consent CSRF (`portal/src/lib/oauth2-handlers.ts`): a tampered
     `csrf_token` → `400`.

These are structured, human-meaningful denials and are the ones a real user
might encounter. The `checkOrigin` 403 is effectively **attacker-only** —
a normal browser always sends a matching `Origin`.

The e2e specs (`e2e/playwright/tests/{e,f,h}*.spec.ts`) assert **both** layers:
an origin-less POST → `403`, and a same-origin POST → the app's structured
deny.

## Branded error surfaces (portal)

So users never see raw framework output. Single source of truth:
`portal/src/components/StatusPage.astro` (house-style tokens/classes; renders
status + title + message + optional reason badge — **never** internals).

| Surface | File | Notes |
|---|---|---|
| Not found | `src/pages/404.astro` | Astro native; sets status 404 |
| Server error | `src/pages/500.astro` | Astro native; **evaluates `error`, logs server-side, leaks nothing** |
| Denials / auth errors | `src/pages/auth/error.astro` | The redirect target for `reason=` denials; maps reason → (status, copy) |
| Stray app 4xx/5xx | `src/middleware.ts` | Rebrands **raw non-HTML** app errors for **HTML navigations only** (API/JSON untouched); already-HTML responses pass through so the native pages stand; **preserves the original status**; loop-guarded |

`reason` values (`auth/error.astro`): `not-admin`, `not-authorised`,
`auth-unreachable`, `session-expired`, `forbidden`, `unavailable`,
`not-found`, `rate-limited`, `server-error`, + a generic default.

## The one surface that stays unbranded

Because `checkOrigin` short-circuits before user middleware (above), the
framework `403` is the one deny the portal cannot brand. It ships bare, and
that is the current state, not an oversight waiting on a fix.

The gap is deliberately small. That 403 is effectively attacker-only, so the
population that sees it is not the family. Branding it would mean intercepting
upstream 4xx at the reverse proxy and re-rendering the app's own error page
while preserving the original status, which is a Caddy `handle_response`
sub-request pattern that is finicky enough to need validating against a live
stack before it ships. Nobody has paid that cost, because the surface it
improves is one an attacker sees.

If it is ever picked up, the acceptance bar is: the branded page carries the
original status, and a portal-down 502/503 falls back to something static
rather than sub-requesting a dead app.

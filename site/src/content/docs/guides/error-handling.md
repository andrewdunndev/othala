# Error handling & the two-layer deny model

How Othala denies bad requests, and how every error surface is branded.
Status: portal layer **implemented** (static-validated); Caddy edge belt +
live validation **pending**.

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
     bypass of this exact check (content-type tricks); it's fixed in 4.16.17
     and we run Astro 6.2.1. Reimplementing risks reintroducing the bypass.

2. **Application guards (in the page/route).** Once a request passes
   `checkOrigin`, the app's own guards run:
   - `requireAdminSession()` (`portal/src/lib/admin.ts`): not in the admin
     allowlist → `302 /auth/error?reason=not-admin`; session below `aal2` →
     `302 …/self-service/login/browser?aal=aal2&refresh&return_to=…`
     (step-up). These fire for **all** HTTP methods.
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

## Pending: Caddy edge belt for the `checkOrigin` 403

Because `checkOrigin` short-circuits before user middleware (above), the one
surface the portal layer cannot brand is the framework `403`. Brand it at the
**edge** (the reverse proxy's intended pathway — `caddy/Caddyfile` worked
example), leaving Astro's CSRF
untouched.

Shape (intercept upstream 4xx/5xx, render the branded page, **preserve the
original status**):

```caddyfile
reverse_proxy othala:8080 {
    @err status 400 401 403 404 405 429 500 502 503 504
    handle_response @err {
        # render the app's branded /auth/error, keep the original status
        # (the exact directive combo — rewrite + reverse_proxy + status
        #  preservation — must be confirmed against a live Caddy + stack)
    }
}
```

> **Needs live validation.** Caddy `handle_response` status-preservation +
> sub-request behavior is finicky; do not ship this blind. Validate on the
> lodestone stack with a real Caddy in front.

## Live-validation checklist (when an operator + stack are available)

- [ ] 404, 500, `/auth/error?reason=<each>` render branded with correct status.
- [ ] `src/middleware.ts`: a raw non-HTML app 4xx for a navigation rebrands;
      confirm **loop-safety** and **status preservation** at runtime
      (rewrite re-entry only shows up live).
- [ ] e2e `{e,f,h}` specs green (origin-less 403 + same-origin app guard).
- [ ] Caddy belt brands the `checkOrigin` 403 with the original status, and a
      portal-down 502/503 has a static fallback (don't sub-request a dead app).

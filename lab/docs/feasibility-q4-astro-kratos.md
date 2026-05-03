# Q4: Astro on CF Pages driving Kratos at auth.dunn.dev

## Verdict

**GREEN, with one architectural correction and two operational caveats.**

Load-bearing reason: every primitive required (parent-domain session cookie, CORS allowlist with credentials, parent-domain WebAuthn RP id, Hydra skip-consent) is supported by stock Kratos / Hydra / browser specs, and `home.dunn.dev` plus `auth.dunn.dev` share `dunn.dev` as a registrable parent (eTLD+1), so the cross-subdomain primitives all activate cleanly.

The architectural correction: Cloudflare's Astro adapter dropped Pages as a deployment target. New Astro deployments to Cloudflare go to **Workers** (with static assets), not Pages. Functionally near-identical for this use case, but the routing, KV bindings, and `wrangler.jsonc` story all live on the Workers side now.

Operational caveats:
1. The Hydra consent endpoint must run somewhere with access to the Hydra **admin** API (not exposed to the browser). The Astro Workers runtime can do this if the admin endpoint is reachable from Cloudflare's edge, or it needs a private path (Cloudflare Tunnel to carmine, or a separate consent service hosted next to Hydra).
2. Kratos' configuration-time RP id is global. Setting it to `dunn.dev` is the right move, but it's a one-way decision: changing it later invalidates every existing passkey credential.

## Cookie domain semantics

### Kratos config

Two paths exist; the session-specific one overrides the global. Use both for clarity:

```yaml
cookies:
  domain: dunn.dev
  path: /
  same_site: Lax

session:
  cookie:
    domain: dunn.dev
    path: /
    same_site: Lax
```

`cookies.domain` covers CSRF and continuity cookies that Kratos sets during self-service flows (`csrf_token`, `ory_kratos_continuity`). `session.cookie.domain` covers the session cookie specifically. Both must be set for cross-subdomain to work end-to-end.

### SameSite / Secure / HttpOnly

- `same_site: Lax` is sufficient for this topology. The Astro UI navigates user to Hydra (top-level navigation, Lax-compatible) and makes same-site `fetch()` calls (the request origin and cookie target both live under `dunn.dev`, so they're same-site). `Strict` would break the OIDC redirect dance because the browser treats redirects from `client.dunn.dev` to `auth.dunn.dev` as navigations and would withhold a Strict cookie on the first hop.
- `Secure` is enforced by Kratos unless `--dev` is set. Both subdomains are HTTPS-only, no action needed.
- `HttpOnly` is **always on, not configurable**. Kratos session cookies are never visible to JS via `document.cookie`. This is fine: the SPA pattern is to call `GET /sessions/whoami` with `credentials: "include"` and read the JSON response, not to read the cookie directly.

### Cross-subdomain behavior

Setting `domain: dunn.dev` causes the browser to send the cookie on any request to any `*.dunn.dev` host. JS at `home.dunn.dev` calling `fetch('https://auth.dunn.dev/...', { credentials: 'include' })` will attach the cookie. The cookie is "same-site" in the browser's terminology because both hosts share the eTLD+1, so SameSite=Lax does not block these requests.

The "two top-level domains" enterprise feature is **not** what we're hitting. That feature covers `mybrand.com` plus `myotherbrand.io` (two distinct registrable domains). We have one registrable domain (`dunn.dev`) with multiple subdomains, which is the supported open-source case.

Caveat: the encrypted-cookie value is signed with `secrets.cookie` / `secrets.default`. Any rotation of these secrets without proper key rotation invalidates every session and signs everyone out. Worth noting in the carmine secret-management story.

## CORS

### Kratos config supports allowlist: yes

```yaml
serve:
  public:
    cors:
      enabled: true
      allowed_origins:
        - https://home.dunn.dev
      allowed_methods:
        - GET
        - POST
        - PUT
        - PATCH
        - DELETE
      allowed_headers:
        - Authorization
        - Cookie
        - Content-Type
        - X-Session-Token
      exposed_headers:
        - Content-Type
        - Set-Cookie
      allow_credentials: true
      debug: false
```

Wildcard subdomain entries like `https://*.dunn.dev` are supported, but a bare `*` is **not**: Kratos refuses to combine `Access-Control-Allow-Origin: *` with credentialed requests (the spec forbids this combination, and Kratos surfaces it as an opaque CORS error rather than a clean rejection).

### Required headers

For SPA self-service flows that need to read CSRF and session cookies via `Set-Cookie`:

- Request must send `Accept: application/json` (this is what flips Kratos from redirect-mode to JSON-mode).
- Request must use `credentials: 'include'` (`fetch`) or `withCredentials: true` (axios / Ory SDK).
- Response must include `Access-Control-Allow-Credentials: true`. Kratos emits this automatically when `allow_credentials: true` is set under `serve.public.cors`.
- `Set-Cookie` must be in `exposed_headers` if any client code needs to inspect cookie metadata; for cookie *storage* this is not required (the browser stores them regardless), so this is largely cosmetic.

### Preflight gotchas

- Browsers preflight any request with `Content-Type: application/json` (which Kratos POST flows use). The preflight `OPTIONS` must hit `auth.dunn.dev` and get a 2xx with the right CORS headers. Kratos handles this, but any front-of-Kratos proxy (Caddy in carmine) must not strip CORS headers or short-circuit the OPTIONS.
- `Access-Control-Allow-Origin` must echo the exact request origin (`https://home.dunn.dev`), not a wildcard, when credentials are involved. This is automatic if the origin is in `allowed_origins`.
- The community wildcard-subdomain feature (`https://*.dunn.dev`) is implemented as origin-pattern matching, not wildcard echoing. Kratos still echoes the literal origin in the response header.
- Default Kratos public-API port is `4433`; avoid mistakenly pointing CORS / fetch at the UI port (`4455` in some Ory examples).

## WebAuthn RP-id

### Cross-subdomain assertion: works, with the right RP id

The WebAuthn spec lets the RP id be either the exact origin host or a **registrable domain suffix** (eTLD+1 or higher). For our topology, `dunn.dev` is the eTLD+1 and is a valid RP id from any `*.dunn.dev` origin. A passkey registered with `rp.id = "dunn.dev"` while the user sits on `auth.dunn.dev` can be asserted later from `home.dunn.dev`, `vaultwarden.dunn.dev`, or any other subdomain that lists itself in `rp.origins`.

### Recommended RP id config

Kratos passkey strategy:

```yaml
selfservice:
  methods:
    passkey:
      enabled: true
      config:
        rp:
          display_name: dunn.dev
          id: dunn.dev
          origins:
            - https://home.dunn.dev
            - https://auth.dunn.dev
```

Kratos WebAuthn strategy (for second-factor security keys, if used):

```yaml
selfservice:
  methods:
    webauthn:
      enabled: true
      config:
        passwordless: false
        rp:
          display_name: dunn.dev
          id: dunn.dev
          origin: https://auth.dunn.dev
```

Note the API asymmetry: the passkey strategy takes `rp.origins` (plural array), the WebAuthn strategy takes `rp.origin` (singular string). The passkey strategy is what we want for family UX; the WebAuthn strategy is only relevant if we offer roaming-key-based MFA on top of password.

### Browser security caveats

- The page initiating the ceremony must be served from an origin whose host is, or is a subdomain of, the RP id. So `home.dunn.dev` calling `navigator.credentials.get({ publicKey: { rpId: 'dunn.dev', ... } })` is allowed; calling with `rpId: 'auth.dunn.dev'` from `home.dunn.dev` would fail because `home.dunn.dev` is not a subdomain of `auth.dunn.dev`.
- The RP id **cannot** be a Public Suffix List entry (e.g., you can't use `dev` or `co.uk`). `dunn.dev` is fine because the registrable boundary is at the second level.
- Once a passkey is registered with `rp.id = dunn.dev`, you cannot change it to `auth.dunn.dev` or anything narrower without invalidating the credential. This is a permanent decision; pick the parent domain.
- Related Origins Request (ROR), the cross-registrable-domain extension, is not relevant here (we're on one registrable domain) and Kratos has no published support for ROR's `/.well-known/webauthn` manifest as of May 2026. Browser support for ROR is Chrome/Edge 128+ and Safari 18+; Firefox is positive-position-but-unimplemented. Park this for future cross-domain work, not for the current plan.
- Kratos passkey credentials are bound to the user identity, so adding a new origin to `rp.origins` later (e.g., adding `https://nas.dunn.dev` when we put SSO in front of TrueNAS) does not invalidate existing credentials. Origins are checked at ceremony time, RP id is checked at credential time.

## Astro architecture

### Static + client-fetches: feasible, with the right output mode

The minimum viable shape is fully static Astro pages that render a login form, then ship JS that does:

```js
const resp = await fetch('https://auth.dunn.dev/self-service/login/api', {
  credentials: 'include',
  headers: { Accept: 'application/json' },
})
```

This works if every consumer of the UI is a browser that supports `fetch` with credentials, which is every browser we care about. No SSR is required for the Kratos-only flows. The Astro build output is static HTML + JS, served from Cloudflare's edge directly to the browser, and the browser talks to `auth.dunn.dev` over the cookie / CORS plumbing above. Cloudflare is not in the request path between the browser and Kratos.

### Hybrid mode if needed

Hydra's consent endpoint is the one place where pure-static does not work, because the consent flow needs to call Hydra's admin API to fetch and accept the consent challenge. The admin API must not be exposed to the browser. Two options:

1. **Astro server-rendered route on Workers.** Mark `/auth/consent.astro` with `export const prerender = false` and let the Cloudflare Workers runtime handle it. The Workers fetch from Cloudflare's edge to Hydra's admin endpoint. This requires Hydra's admin API to be reachable from the Cloudflare edge (public + IP allowlist, mTLS, or Cloudflare Tunnel originating in carmine). This is the cleanest pattern.
2. **Separate consent service in carmine.** Run a small Go or Node service co-located with Hydra that handles `/auth/consent`. Astro UI redirects to it, it does its work, redirects back. This avoids exposing the admin API beyond carmine but adds a deployment unit.

The Astro 6 + Cloudflare adapter handles per-route prerender flags cleanly; the consent route can be SSR while every other route is static.

### Workers KV for health check

`@astrojs/cloudflare` exposes KV bindings via `cloudflare:workers`:

```js
import { env } from 'cloudflare:workers'
const kv = env.HEALTH_KV
const status = await kv.get('carmine-up')
```

KV bindings are configured in `wrangler.jsonc` (or `wrangler.toml`). For session-style storage Astro auto-wires a `SESSION` binding by default, customizable via the adapter's `sessionKVBindingName` option. KV is eventually consistent with ~60s propagation between regions, which is fine for a health-check banner ("services up / services down") but not for anything strongly consistent.

## CF Pages limitations

1. **Pages is no longer the recommended Astro target.** As of Astro 6 (early 2026) the `@astrojs/cloudflare` adapter targets Workers with static assets. Pages still works for fully-static sites (no SSR routes) but the Astro team's documentation has shifted toward Workers, and the dev-mode `workerd` runtime closely mirrors production Workers, not Pages Functions.
2. **Pages Functions and Workers are the same V8 isolate runtime under the hood.** Differences are routing model (file-based `/functions/` directory in Pages vs. configured routes in Workers) and feature surface. Functionally, anything Pages Functions can do, Workers can do; the reverse is not true.
3. **Workers-only features that Pages Functions lacks: Durable Objects, Cron Triggers, Queues, Tail Workers, Email Workers.** None are required for the Kratos / Hydra UI today, but Cron Triggers would matter if we ever want Astro-side scheduled work (e.g., periodic carmine health refreshes pushed into KV). Cron Triggers cannot run inside Pages Functions today.
4. **Cloudflare-managed mTLS to a private origin.** If the consent route needs to talk to Hydra admin via private connectivity, the Workers side has Cloudflare Tunnel and mTLS support. Pages Functions inherits this via the same Workers runtime, so it's not a hard blocker, just easier with the Workers-first deployment.
5. **Build time and asset count.** Pages and Workers both impose limits on number of files in the static deploy and on build duration. For a UI of our size (single-digit page count, no heavy media) this is irrelevant.
6. **No SSR-render of every page.** If we go static-by-default with one or two SSR routes (consent, maybe a health-check polling endpoint), we stay well below Workers CPU and request limits on the free / starter tier.
7. **Hybrid mode quirk.** A known Astro 6 issue (`withastro/astro#15237`) reports hybrid pages occasionally rendering in the wrong mode unless `export const prerender = false` is explicit on dynamic pages. Make the prerender flag explicit on every route, do not rely on a global default.

## Hydra consent UX

### Auto-accept pattern

Hydra exposes two signals on the consent request payload:

- `skip` is `true` when the user has already granted equivalent consent in this session (Hydra's built-in remember-me).
- `client.skip_consent` is `true` when the OAuth2 client itself was created with `--skip-consent` (the per-client trust toggle for first-party apps).

Either condition means the consent endpoint should auto-accept without rendering UI. Required call shape (TypeScript shown for clarity, but it's just the Hydra admin REST API):

```ts
const { data: req } = await hydra.getOAuth2ConsentRequest({ consentChallenge })

if (req.skip || req.client?.skip_consent) {
  const { data } = await hydra.acceptOAuth2ConsentRequest({
    consentChallenge,
    acceptOAuth2ConsentRequest: {
      grant_scope: req.requested_scope,
      grant_access_token_audience: req.requested_access_token_audience,
      session: {
        // id_token claims for OIDC userinfo
        id_token: { email: req.subject /* etc. */ },
      },
    },
  })
  return Response.redirect(data.redirect_to)
}

// otherwise render the consent UI
```

For our 16 carmine apps, mark every client with `--skip-consent` at registration time. Consent is then a transparent server-side hop: user clicks "Sign in with dunn.dev" at Vaultwarden, Hydra redirects to `home.dunn.dev/auth/consent?consent_challenge=...`, the SSR endpoint accepts the challenge and 302s back to Hydra, Hydra issues the token. Family-member-visible UI on the consent step: zero.

### Implementation in Astro

Concretely:

- `src/pages/auth/consent.astro` with `export const prerender = false`. Contents are essentially a server-side handler returning a redirect, with no client-side hydration.
- Environment binding `HYDRA_ADMIN_URL` plus `HYDRA_ADMIN_TOKEN` (if needed) wired through `wrangler.jsonc` and read via `import { env } from 'cloudflare:workers'`.
- Hydra admin endpoint must be reachable from the Cloudflare edge: simplest path is Cloudflare Tunnel from carmine to a non-public hostname like `hydra-admin.dunn.dev` that is locked to `cloudflared`-only ingress.
- A `/auth/consent` route that ever fails open (e.g., timing out and rendering "trust this app?" UI) is an unbounded auth risk. Fail closed: if the admin API is unreachable, redirect to a generic error page, do not render a fake consent screen.

### Login flow integration

Hydra's login flow points at a configured `urls.login`. That URL is hit with `?login_challenge=...` and the login app calls Hydra admin to accept. For us, the login app is the Kratos-fronted Astro UI. Pattern:

1. Hydra redirects to `home.dunn.dev/auth/login?login_challenge=X`.
2. Astro consumes the challenge, checks Kratos `whoami` for an active session.
3. If session valid, calls Hydra admin `acceptOAuth2LoginRequest` with the Kratos identity id as `subject`, redirects to `redirect_to`. Hydra then immediately fires the consent flow.
4. If no session, renders the Kratos login UI. On successful Kratos login, returns to step 2.

This is the same SSR-route pattern as consent. Both routes need Hydra admin access.

## Reference UIs to port from

### ory/kratos-selfservice-ui-node

Canonical reference. Express + Handlebars, server-rendered, BFF style. Implements every flow: login, registration, recovery, verification, settings, error. Calls Kratos public API server-side. Useful primarily as a flow-completeness checklist and for the data shape of each flow's UI nodes (Kratos returns a `nodes` array describing each form field; the UI's job is to render it into HTML). The Handlebars templates are direct ports of the node-rendering logic; that logic ports cleanly to Astro components.

Caveat: it is BFF-style, so it does not demonstrate the cross-subdomain SPA pattern. It assumes the UI and Kratos are reachable via the same origin (typically through a reverse proxy). For our topology we are doing the SPA shape, not the BFF shape.

### SvelteKit references (closest non-official)

- **karlis-vagalis/kratos-selfservice** (33 stars, dormant since March 2024). SvelteKit + Melt UI + Tailwind. Auth-only UI, no Hydra integration, no compose bundling. Useful for component-level patterns: how to render a Kratos `nodes` array as a form, how to handle the `messages` array on validation errors, how to wire the flow's `action` URL.
- **bessey/ory-kratos-sveltekit-demo**. BFF-style demo. Implements all flows including passkey. Source for the BFF pattern if we end up moving consent-style logic to a co-located service.
- **drejohnson/sveltekit-kratos**. Smaller, basic example.
- **MarkusThielker/next-ory** (47 stars, archived November 2025). Next.js + Hydra + Kratos + Keto, with admin dashboard. Last actively-maintained reference UI that integrates Hydra consent. Worth reading for the consent-handler shape even though the project is dead. Heavy use of Next.js server components; the patterns transfer to Astro SSR routes 1:1.

### Astro-specific Kratos UIs

**None found** as of May 2026. Awesome-ory lists no Astro projects. GitHub topic `ory-kratos` returns SvelteKit, Next.js, Express, Vue, but no Astro. We would be the first published example. This is consistent with the broader gap noted in `ory-homelab-research.md`: the Ory community has not invested in homelab-shaped or Astro-shaped UIs, which is why the kit does not exist.

### Common patterns documented in the Ory docs

- "Custom UI basic integration" page documents the SPA-vs-browser-flow distinction and the `Accept: application/json` switch.
- "Setting up CORS" page documents the `serve.public.cors` block.
- "Configuring cookies" page documents `session.cookie.domain` plus the `cookies.*` global block.
- "User login and consent flow" page documents the Hydra challenge-accept-redirect dance, with the `skip` and `client.skip_consent` signals.
- "Skip consent and logout consent" page documents the `--skip-consent` client flag and OIDC certification implication (skipping breaks OIDC certification, irrelevant for first-party homelab use).

## Sources

- [Advanced base URL, CSRF and session cookie settings | Ory](https://www.ory.com/docs/kratos/guides/multi-domain-cookies)
- [Cookie settings | Ory](https://www.ory.com/docs/kratos/guides/configuring-cookies)
- [Cross-origin resource sharing (CORS) settings | Ory](https://www.ory.com/docs/kratos/guides/setting-up-cors)
- [CORS Issue With Self Hosted Kratos (ory/kratos discussions/3583)](https://github.com/ory/kratos/discussions/3583)
- [Working with Kratos on different subdomains (ory/kratos discussions/2235)](https://github.com/ory/kratos/discussions/2235)
- [Make session cookie 'domain' property configurable (ory/kratos issues/516)](https://github.com/ory/kratos/issues/516)
- [Passwordless sign-in and sign-up with passkeys | Ory](https://www.ory.com/docs/kratos/passwordless/passkeys)
- [Multi-factor authentication with WebAuthn | Ory](https://www.ory.com/docs/kratos/mfa/webauthn-fido-yubikey)
- [SecurityError when using WebAuthn or Passkeys | Ory](https://www.ory.com/docs/troubleshooting/passkeys-webauthn-security-error)
- [RP ID deep dive | web.dev](https://web.dev/articles/webauthn-rp-id)
- [WebAuthn Related Origins (ROR): Cross-Domain Passkey Guide | Corbado](https://www.corbado.com/blog/webauthn-related-origins-cross-domain-passkeys)
- [Basic information you need to integrate your UI with Ory | Ory](https://www.ory.com/docs/kratos/bring-your-own-ui/custom-ui-basic-integration)
- [User login and consent flow | Ory](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)
- [Skip consent and logout consent | Ory](https://www.ory.com/docs/oauth2-oidc/skip-consent)
- [Skip showing OAuth2 consent screen for 1P apps | Ory Changelog](https://changelog.ory.sh/announcements/skip-showing-oauth2-consent-screen-for-1p-apps)
- [hydra create oauth2-client | Ory](https://www.ory.com/docs/hydra/cli/hydra-create-oauth2-client)
- [astrojs/cloudflare | Astro Docs](https://docs.astro.build/en/guides/integrations-guide/cloudflare/)
- [Astro | Cloudflare Workers docs](https://developers.cloudflare.com/workers/framework-guides/web-apps/astro/)
- [Astro | Cloudflare Pages docs](https://developers.cloudflare.com/pages/framework-guides/deploy-an-astro-site/)
- [Migrate from Pages to Workers | Cloudflare Workers docs](https://developers.cloudflare.com/workers/static-assets/migration-guides/migrate-from-pages/)
- [Functions | Cloudflare Pages docs](https://developers.cloudflare.com/pages/functions/)
- [Hybrid sites broken in Cloudflare workers in Astro 6 (withastro/astro issues/15237)](https://github.com/withastro/astro/issues/15237)
- [ory/kratos-selfservice-ui-node](https://github.com/ory/kratos-selfservice-ui-node)
- [karlis-vagalis/kratos-selfservice (SvelteKit)](https://github.com/karlis-vagalis/kratos-selfservice)
- [bessey/ory-kratos-sveltekit-demo](https://github.com/bessey/ory-kratos-sveltekit-demo)
- [MarkusThielker/next-ory (archived)](https://github.com/MarkusThielker/next-ory)

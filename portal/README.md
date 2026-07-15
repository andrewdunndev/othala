# portal

The Astro UI for the Othala auth substrate. Runs as a Node SSR pod (`@astrojs/node` standalone) on the same host as Kratos and Hydra. Hosts the user-facing portal AND the admin UI.

## Status

Phase 3 minimum-viable pass:

- Three-state landing (`/`)
- Login (`/auth/login`) — passkey method first, password fallback
- Settings (`/auth/settings`) — profile, passkey enrollment, password change, sign out
- Recovery (`/auth/recovery`) — code strategy, two-phase
- Logout (`/auth/logout`) — fetches the logout token, redirects through Kratos
- Verification + admin pages are stubs (deferred follow-up)

Build passes (`npm run build`). Type-check passes (`npm run check`). Container builds (`make image`).

## Why co-located with the Ory services, not Cloudflare Workers

adversarial-review-2 C1: the admin UI on Workers had no path to Kratos's admin port (`kratos:4434`) because that hostname resolves only inside the SSO pod network. Moving the portal to the same pod collapses the runtime complexity: one Node process, normal `process.env`, in-pod fetch to Kratos+Hydra admin ports, no Workers shims.

Cloudflare's role shrinks to DNS hosting + DNS-01 ACME. WebFinger lives at the dunn.dev apex (a Cloudflare Pages function in the dunn.dev apex repo), not here — Tailscale requires WebFinger at the email-domain apex, not the IdP subdomain.

## Architecture

The portal is the SSR layer between the user's browser and Kratos. Each
auth page reads the inbound `Cookie` header, fetches the relevant Kratos
flow object via `GET /self-service/<flow>/flows?id=...`, and renders an
HTML form with the inputs Kratos described in `flow.ui.nodes`. The form
posts back to Kratos at `flow.ui.action`; Kratos handles validation,
sets the session cookie on `.dunn.dev`, and 303s to the configured
return URL.

WebAuthn ceremonies run in the user's browser via the script Kratos
serves at `/.well-known/ory/webauthn.js`. We render that script tag
inline from the flow's script nodes; no client framework involved.

## Layout

```
portal/
├── package.json
├── astro.config.mjs        # output: 'server', @astrojs/node standalone, tailwind v4 vite plugin
├── Containerfile           # multi-stage build, builds from auth-repo-root context
├── Makefile                # install/dev/build/check/image/start/clean
├── src/
│   ├── layouts/
│   │   └── Layout.astro    # shared head/body wrapper; imports global.css
│   ├── lib/
│   │   ├── kratos.ts       # public Kratos API client (getSession, getLoginFlow, ...)
│   │   ├── nodes.ts        # FlowNode helpers (csrfToken, hasMethod, asInput, ...)
│   │   ├── types.ts        # Kratos OpenAPI types narrowed to what we render
│   │   ├── admin-api.ts    # Kratos admin API wrappers (in-pod kratos:4434)
│   │   ├── admin.ts        # AAL2 guard + Hydra admin client (in-pod hydra:4445)
│   │   ├── tiles.ts        # runtime tile loader: reads presentation: from MANIFEST_DIR
│   │   ├── manifests.ts    # runtime OIDC client loader: reads oidc:/consent: from MANIFEST_DIR
│   │   ├── register-clients.ts # in-app Hydra registrar (validateClients + OAuth2Api)
│   │   ├── app-slug.ts     # slug ⇄ access-<slug> helpers
│   │   ├── gate.ts / access.ts / claims.ts / revoke.ts  # access gate, group model, claims, revoke fan-out
│   ├── styles/
│   │   ├── global.css      # design-token-backed component classes
│   │   └── tokens/         # mirror of dunn.dev/design/tokens/
│   ├── pages/
│   │   ├── index.astro     # three-state landing/launcher (runtime tiles)
│   │   ├── apps/
│   │   │   └── [slug].astro     # per-app detail page (presentation + <slug>.md education content)
│   │   ├── auth/
│   │   │   ├── login.astro       # Kratos login flow
│   │   │   ├── recovery.astro    # Kratos recovery (code strategy)
│   │   │   ├── settings.astro    # Kratos settings (passkeys, password, profile)
│   │   │   ├── verification.astro
│   │   │   └── consent.astro     # in-process grant screen
│   │   ├── oauth2/
│   │   │   ├── login.ts          # Hydra login challenge handler
│   │   │   ├── consent.ts        # Hydra consent challenge handler (access gate + claims)
│   │   │   └── logout.ts         # Hydra logout challenge handler
│   │   └── admin/
│   │       ├── index.astro
│   │       ├── users/
│   │       │   ├── index.astro
│   │       │   ├── [id].astro
│   │       │   └── new.astro
│   │       ├── groups.astro
│   │       ├── oauth2.astro
│   │       └── activity.astro
│   └── server/             # listen.mjs dual-listener entry + admin runtime + register-clients CLI
└── public/                 # static assets only (favicons, images); WebFinger lives at the dunn.dev apex (LB-10)
```

## Locked decisions honored

| Decision | Where it shows up |
|---|---|
| Kratos `passkey` method (not `webauthn passwordless`) | `login.astro` renders the `passkey` node group; `autocomplete="username webauthn"` on the identifier triggers conditional UI |
| WebAuthn rp.id = `dunn.dev` | Set in `kratos/kratos.yml`; portal doesn't encode it |
| Cookie domain = `.dunn.dev` | Kratos sets it; portal forwards inbound Cookie on every flow fetch |
| Recovery via code strategy | `recovery.astro` renders the `code` group, posts `method: code` |
| Identity traits: `username, email, displayName?, recoveryEmail?` | `Identity.traits` type; surfaced in settings profile section |
| `metadata_admin.groups[]` controls tile visibility | `index.astro` filters the runtime tiles (`lib/tiles.ts: loadTiles`) by `access-<slug>` group membership |
| AAL2 only for admin pages | `admin.ts:requireAdminSession`; not enforced on family pages |
| WebFinger lives at dunn.dev apex, not here | Cloudflare Pages function in dunn.dev apex repo; Tailscale requires WebFinger at the email-domain apex (see `ARCHITECTURE.md` LB-10) |

## Dev workflow

```bash
make install                                          # npm ci
KRATOS_PUBLIC_URL=http://localhost:4433 make dev      # astro dev on :4321
make check                                            # astro check (type-check)
make build                                            # astro build -> dist/server + dist/client
make start                                            # node ./dist/server/entry.mjs (after build)
make image                                            # podman build -t dunn.dev/othala-portal:lab
```

`make image` runs `podman build` with `portal/` as the build context. As of v0.2.0 there is no manifest prebuild step: per-app manifests are read at runtime from `MANIFEST_DIR` (default `/etc/portal/manifests`), so the build no longer needs `hydra/clients/` or the larger repo context.

## prerender flag

Astro 6 dropped the `'hybrid'` output mode. We use `output: 'server'` (every page is SSR by default). Pages opt OUT of SSR with `export const prerender = true`. Today every page is SSR because they all read session cookies or call admin APIs server-side. Static-only pages would set `prerender = true` to land in `dist/client/`.

## AAL2 admin guard

`src/lib/admin.ts` exports `requireAdminSession(Astro)` which is the server-side guard for `/admin/*` routes. It:

1. Reads the Kratos session via whoami
2. Returns redirect to `/auth/login` if no session
3. Returns redirect to Kratos refresh-login with `?aal=aal2` if session is below aal2
4. Returns redirect to `/auth/error?reason=not-admin` unless `metadata_admin.admin === true`, fetched fresh from the Kratos admin API — whoami omits `metadata_admin` (ADR 08; the `admin` group is display-only)
5. Returns the validated session otherwise

Per adversarial review: AAL is enforced at this layer, NOT at Caddy. Caddy `forward_auth` only verifies "any session present"; the per-route AAL2 check is here.

## Build notes

- Node 22.12+ required (Astro 6 dropped Node 20 support).
- Vite is pinned to 7.x via `package.json#overrides` (kept from the
  Workers-era pin; the constraint was a Vite 8 issue with Astro internals).
- `output: 'server'` means SSR-by-default. Every existing page already
  declares `export const prerender = false` from the prior config; that's
  harmless under the new mode (it matches the new default).

## Deployment notes

The Node SSR pod reads:

- `KRATOS_PUBLIC_URL` (default `http://localhost:4433` in dev; set to your Kratos public URL in production)
- `KRATOS_ADMIN_URL` (default `http://kratos:4434`; in-pod hostname)
- `KRATOS_ADMIN_TOKEN` (optional; reserved for a future Oathkeeper interposer)
- `HYDRA_ADMIN_URL` (default `http://hydra:4445`; in-pod hostname)
- `HYDRA_ADMIN_TOKEN` (optional; same reservation)
- `HOST` / `PORT` (Astro Node adapter; default 0.0.0.0:8080 in container)
- `MANIFEST_DIR` (default `/etc/portal/manifests`; the directory `tiles.ts` + `manifests.ts` read per-app manifests from at runtime, volume-mounted read-only by the quadlet)

In the SSO pod the admin ports are reachable at the in-pod hostnames; production overrides default to those.

## Design rules

- Tokens are mirrored from `dunn.dev/design/tokens/` into `src/styles/tokens/`. The portal does not redefine colors or type sizes. Pages consume bare semantic names: `var(--bg)`, `var(--text)`, `var(--accent)`, `var(--danger)`, `var(--input-border)`, etc.
- New tokens go upstream into `dunn.dev/design/tokens/colors.css` (and `colors.json`), then are re-copied into `src/styles/tokens/`.
- Layout primitives + component classes (`.shell`, `.button`, `.field`, `.notice`, `.tile`, `.data-table`, `.panel`, `.nav-bar`) live in `src/styles/global.css`. Use these instead of inlining utility classes.
- Monospace for headings, sharp corners, dense rather than editorial.
- No em-dashes in body copy (title separators are fine).
- One auth feel: family sees only Kratos-driven flows, no Cloudflare challenges, no consent screens (auto-accept for trusted clients).

## Refreshing tokens from upstream

```bash
cp ../../design/tokens/colors.css     src/styles/tokens/colors.css
cp ../../design/tokens/colors.json    src/styles/tokens/colors.json
cp ../../design/tokens/typography.css src/styles/tokens/typography.css
cp ../../design/tokens/index.css      src/styles/tokens/index.css
```

(Symlinks were considered but bundling is unreliable with them; copy is the canonical path.)

## Endpoint usage map

| Page | Kratos API | Hydra/consent | Other |
|---|---|---|---|
| `/` | `GET /sessions/whoami` | — | `GET /health/alive` for state-A detection |
| `/auth/login` | `GET /self-service/login/flows?id=`; redirect to `/self-service/login/browser` if missing | — | renders passkey + password forms; webauthn.js inline |
| `/auth/recovery` | `GET /self-service/recovery/flows?id=`; redirect to `/self-service/recovery/browser` if missing | — | code strategy, two-phase |
| `/auth/settings` | `GET /self-service/settings/flows?id=`, `GET /self-service/logout/browser` | — | requires session |
| `/auth/verification` | (stub) | — | follow-up |
| `/auth/logout` | `GET /self-service/logout/browser` | — | redirects to logout_url |
| `/auth/consent` | — | `GET/PUT /admin/oauth2/auth/requests/consent` (in-pod `hydra:4445`) | in-process grant screen (`portal/src/pages/auth/consent.astro`) |
| `/admin/*` | `GET /sessions/whoami`, admin API via `requireAdminSession` (in-pod `kratos:4434`) | `GET /admin/clients` (read-only, in-pod `hydra:4445`) | |

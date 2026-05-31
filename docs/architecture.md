# Architecture

Production topology after the locked Ory pivot. Custom Caddy image at `registry.gitlab.com/dunn.dev/caddy-estate` (built with xcaddy + `caddy-dns/cloudflare` plugin), DNS-only Cloudflare in front, port-forward 443 on home router. Kratos + Hydra + glauth-kratos + consent service + Astro portal all on carmine, in the same pod network.

## Topology

```
                           Cloudflare DNS (gray cloud, no proxy)
                                  │
                                  ↓
                           home IP : 443 (port-forwarded)
                                  │
                                  ↓
                           carmine
                             ├─ Envoy (L4 SNI router on 80/443)
                             ├─ per-pod Caddy sidecars (dunn.dev/caddy-estate, DNS-01 ACME)
                             ├─ auth pod (single pod network)
                             │    ├─ kratos (4433 public, 4434 admin internal-only)
                             │    ├─ kratos-courier (singleton, sends recovery emails)
                             │    ├─ hydra (4444 public, 4445 admin internal-only)
                             │    ├─ hydra-migrate (init container, schema migrations)
                             │    ├─ consent service (4477 internal)
                             │    ├─ portal (Astro Node SSR, 8080 internal)
                             │    │    └─ auth.dunn.dev (path-shared with Kratos+Hydra+consent)
                             │    │        ├─ /                       session-gated tile dashboard
                             │    │        ├─ /apps/<slug>            per-app education page
                             │    │        ├─ /auth/{login,recovery,settings,verification}
                             │    │        └─ /admin/{users,groups,oauth2,activity}
                             │    │   (home.dunn.dev: reserved, not served)
                             │    │   (WebFinger: dunn.dev apex Pages function, not here)
                             │    └─ postgres (kratos + hydra databases)
                             ├─ jellyfin pod
                             │    ├─ jellyfin
                             │    └─ glauth-kratos bridge (LDAPS 636 in-pod)
                             └─ all other app pods
                                  ├─ caddy sidecar (TLS via DNS-01 ACME)
                                  └─ app container

home portal health check:
  index.astro → kratos:4433/health/alive (in-pod fetch, 2s timeout)
  No Workers KV: state determination is per-request, no edge cache.
```

## Cloudflare's role

DNS hosting + DNS-01 ACME via API. **Not in the auth or app request path** for the portal or OIDC flows. No CF Tunnel, no CF Access, no Worker for the portal, no KV for state. Cloudflare never sees TLS plaintext for app/auth flows.

Two narrow Cloudflare-served endpoints exist on the dunn.dev apex:
- **WebFinger** at `dunn.dev/.well-known/webfinger` — Pages function returning the OIDC issuer JRD for Tailscale tenant setup (consulted once, never per-login).
- The marketing landing page at `dunn.dev/` — outside the auth substrate's concern.

## Why portal-on-carmine, not Workers

adversarial-review-2 C1: with the portal on Workers, the admin pages had to fetch `kratos:4434` (the Kratos admin port). That hostname resolves only inside the carmine pod network; from a Worker it's unreachable. The locked decision "admin port stays internal" jointly with "Astro on Workers" was inconsistent.

Putting the portal on carmine in the same pod network as Kratos and Hydra makes the admin port reachable directly. It also collapses runtime complexity: one Node process, normal `process.env`, no Workers shims, no `wrangler` deploy step.

(Note: an earlier shape of this repo served WebFinger from the portal at `auth.dunn.dev/.well-known/webfinger`. That handler was deleted in v0.1.4 — Tailscale's KB-1240 requires WebFinger at the email-domain apex, not on the IdP subdomain. Production serves it from a Cloudflare Pages function on the dunn.dev apex repo. See `docs/apex-webfinger-followup.md`.)

The portal's two original Workers motivations were addressable separately:

- *Status page when carmine is down.* Replaced by a static fallback page served by Cloudflare (DNS records pointing at a static asset, or a simple HTML on a CF Worker that does nothing but render "services starting up"). That fallback is small enough not to be load-bearing for the substrate.
- *DNS hosting + DNS-01 ACME.* Cloudflare keeps both. They never required Workers.

## Bootstrap order on carmine

1. Carmine boots (bootc immutable image, ZFS pools, networking)
2. Postgres pod up
3. **Hydra schema migration** (init container; runs `hydra migrate sql up`)
4. Kratos + Hydra serve up
5. Consent service up
6. Caddy sidecars obtain DNS-01 certs
7. App pods come up as Hydra OIDC clients (or LDAP via bridge for Jellyfin)
8. Tailscale joins as Hydra OIDC client (custom-OIDC + WebFinger)

Tailscale is not load-bearing. Admin paths work without it.

## Auth patterns

### OIDC native — keep, larder, listen, memory, vault, library, forge, observe

Per-app Caddyfile snippet:
```caddyfile
keep.dunn.dev {
  import oidc-app vaultwarden 80
}
```

App handles its own OIDC redirect to `https://auth.dunn.dev/oauth2/auth?...`, exchanges code for tokens via `https://auth.dunn.dev/oauth2/token`. Caddy is just the TLS terminator + reverse proxy.

### LDAP outpost — cinema (Jellyfin)

The glauth-kratos bridge co-located in the Jellyfin pod presents identities over LDAPS:636. Jellyfin's LDAP plugin binds against `localhost:636`. Bridge translates BIND to a Kratos public-API login flow; SEARCH to Kratos admin-API identity listing.

Per-app Caddyfile:
```caddyfile
cinema.dunn.dev {
  import ldap-app jellyfin 8096
}
```

LDAP traffic never hits Caddy.

### Forward auth — tune (Navidrome), gather/* (Sonarr, Radarr, etc.)

Caddy forward_auth against Kratos `/sessions/whoami`. Subsonic API and shares bypass auth (native clients use HTTP Basic).

```caddyfile
tune.dunn.dev {
  @subsonic path /rest/* /share/*
  handle @subsonic {
    reverse_proxy navidrome:4533
  }
  handle {
    import forward-auth navidrome 4533
  }
}
```

### Client-credentials — llm (vLLM)

Caddy validates the `Authorization: Bearer` token via Hydra's `/admin/oauth2/introspect`. Same in-pod sidecar pattern.

### Custom OIDC — Tailscale

Tailscale custom-OIDC against Hydra. Doesn't use PKCE.

**WebFinger lives at the email-domain apex**, not on the IdP subdomain.
Tailscale's KB-1240 requires `https://${email-domain}/.well-known/webfinger`
— for our family emails (`<user>@dunn.dev`), that's `https://dunn.dev/.well-known/webfinger`.
Served by a Cloudflare Pages function in the dunn.dev apex repo. Returns
`Content-Type: application/jrd+json`, `Access-Control-Allow-Origin: *`,
issuer `href` byte-matching Hydra's `urls.self.issuer` in `hydra/hydra.yml`
(currently `https://auth.dunn.dev/` with trailing slash; Tailscale rejects
any mismatch).

The WebFinger endpoint is consulted exactly once during tailnet setup;
the issuer is locked-in afterward and changing it requires Tailscale
support per KB-1240. See `docs/apex-webfinger-followup.md` for
implementation + verification.

## Admin path gating

```
Family member hits auth.dunn.dev/admin/*
  ↓
Caddy forward_auth → Kratos /sessions/whoami
  - 401: redirect to auth.dunn.dev/auth/login
  - 200: user is authenticated (any AAL); pass through
  ↓
Astro SSR page (admin/*.astro) calls requireAdminSession(Astro):
  - whoami again on the SSR side
  - Identity must be in admin group (metadata_admin.groups includes "admin")
  - authenticator_assurance_level must be aal2
    - If aal1: redirect to https://auth.dunn.dev/self-service/login/browser?refresh=true&aal=aal2&return_to=...
  ↓
On aal2: render admin UI
```

Per adversarial review: AAL is enforced at the SSR layer because Kratos AAL is per-flow, not per-route. Caddy alone can't conditionally gate on JSON-body claims.

## Group model

Two types of groups in `metadata_admin.groups[]`:

**Identity groups**: who you are. Canonical order:
`admin`, `family`, `friends`, `kids`. The admin form writes
`metadata_admin.groups` in canonical order on save (see
`portal/src/lib/access.ts: normalizeGroupOrder`); both the consent
service (`consent/manifest.go: LookupRole`) and the portal Effective
Access view walk stored order, so canonical order IS the precedence.
Adding a new identity group means updating `IDENTITY_GROUP_ORDER` in
`access.ts` AND the form's checkbox list (M11 / C4); otherwise the
new group lands out of order and the cross-implementation invariant
breaks.

**Access groups**: what you can reach (one per app):
`access-keep`, `access-larder`, `access-listen`, `access-cinema`,
`access-tune`, `access-memory`, `access-vault`, `access-gather`,
`access-library`, `access-llm`, `access-forge`, `access-observe`.

The home portal tile launcher renders only tiles for `access-*` groups
the user is in. Apps enforce authz reading the OIDC `groups` claim
(injected by the consent service from `metadata_admin.groups`). The
consent service ALSO enforces `access-<client_id>` membership at the
OIDC entry gate (D2 / C2): a user without the matching access group
cannot complete consent regardless of session state.

## Group and credential change lag (M5)

Edits to a user's groups or credentials don't propagate instantly.
Worst-case lag per consumer:

| Surface | Lag | Source |
|---|---|---|
| Home portal tile launcher | next page load | reads Kratos directly |
| LDAP bridge SEARCH | up to 30s | identity cache TTL |
| LDAP bridge BIND (old password) | up to 30s | bind cache TTL (positive results) |
| Consent flow (new flow) | up to 30s | consent identity cache TTL |
| Consent flow (decision remembered) | up to 1h | Hydra `consentRememberFor` |
| App refresh-token horizon | up to 30 days | Hydra refresh token TTL |

The fast revocation path is `Revoke sessions` on the admin user page,
which kills the Kratos session and Hydra's remember in one action.
Family runbook: when a member loses a device, an admin clicks Revoke,
not Wait.

## Custom Caddy image

`registry.gitlab.com/dunn.dev/caddy-estate`: built with xcaddy + `caddy-dns/cloudflare` plugin. Forward-auth via Caddy's built-in `forward_auth` directive against Kratos.

## Image tag pinning (L6)

Production posture: pin every image to a known-good version. Renovate
proposes bumps stack-wide. Never roll to `latest` to "see if it fixes
things."

| Image | Pin (v0.1.4 baseline) | Renovate-managed |
|---|---|---|
| `docker.io/oryd/kratos` | `v26.2.0` | yes |
| `docker.io/oryd/hydra` | `v26.2.0` | yes |
| `docker.io/library/postgres` | `18-alpine` | yes |
| `registry.gitlab.com/dunn.dev/caddy-estate` | semver tag | yes |
| `registry.gitlab.com/dunn.dev/auth/consent` | `v0.1.4` (this repo's release tag) | self-managed |
| `registry.gitlab.com/dunn.dev/auth/portal` | `v0.1.4` | self-managed |
| `registry.gitlab.com/dunn.dev/auth/ldap-bridge` | `v0.1.4` | self-managed |
| `registry.gitlab.com/dunn.dev/auth/util` | `v0.1.4` | self-managed |

Bumping pins:

1. Pull the candidate image to a lab VM (or the QEMU-CI lab, when wired).
2. Run the lab substrate against it; smoke-test through Playwright.
3. If green, update the pin in `dunn.dev/iac/services/auth/` quadlets.
4. `make auth-deploy HOST=carmine`, verify, document.

Ory's release cadence is approximately annual minor releases with
infrequent breaking changes (v1.3 → v25.4 → v26.2 spanned ~16 months
with one breaking-change set in v25.4 that didn't touch our integration).
The `docs/golden-path.md` doc lists the integration choices that kept
us durable through that transition.

CVE-driven bumps follow the same loop with the lab step compressed:
review the advisory, decide whether the surface area is in scope (the
consent service uses zero non-stdlib deps for HTTP, so most Hydra/Kratos
CVEs are scoped to the Hydra/Kratos containers themselves).

## Trust boundary topology (A1)

The auth pod is one trust domain. Kratos (public + admin), Hydra
(public + admin), the consent service, the portal, and Postgres all
sit on the same pod network. Defense-in-depth between services inside
the pod is partial-and-deliberate:

| Edge | Posture | Enforcer |
|---|---|---|
| Caddy → Kratos public / Hydra public / consent public | TLS terminated at Caddy; HTTP within the pod | Caddyfile + pod network |
| Kratos → consent (recovery-gate webhook) | Shared secret in `X-Webhook-Auth`, constant-time compared (MEDIUM-2) | consent code + Kratos web_hook config |
| portal → consent (`/admin/revoke-user`) | Bearer in `Authorization`, constant-time compared (MEDIUM-1) | consent code |
| portal → Kratos admin (`:4434`) | No auth; pod-network isolation | pod network |
| portal → Hydra admin (`:4445`) | No auth; pod-network isolation | pod network |
| consent → Hydra admin (`:4445`) | No auth; pod-network isolation | pod network |
| consent → ldap-bridge admin (MEDIUM-5) | Bearer in `Authorization`, constant-time compared | bridge code |
| ldap-bridge → Kratos admin (`:4434`) | Admin token (env-resolved) | Kratos admin token |

Tier-2 attackers (RCE on a non-auth-pod app like Vaultwarden) are
network-isolated to their own pod and cannot reach this trust domain.
Tier-2 RCE on an auth-pod service (consent, portal) yields the bearer
tokens in that service's process memory; the listener-split posture
(MEDIUM-1) limits the blast radius to "things this service was already
authorized to do."

## metadata_admin write boundary (MEDIUM-3)

All `metadata_admin` writes go through `portal/src/lib/metadata-admin.ts`
(`validateMetadataAdmin`). Kratos validates `traits` against the
identity schema but treats `metadata_admin` as opaque, so a typo
(`grupos` instead of `groups`) would otherwise be accepted silently.
The application-layer validator catches that.

Production posture: the Kratos admin port (`:4434`) is reachable only
from inside the auth pod (`portal`, `consent`, `ldap-bridge`). No
external write path exists. If a future write path is added (CLI
tool, migration script), the validator factors out into a Go package
shared with consent so both languages enforce the same shape.

## Recovery-gate fail-closed (A4)

If the consent service is down during a recovery flow, Kratos's
`web_hook` timeout fires and the flow aborts (fail-closed): Kratos
will not issue a privileged settings session if the can_interrupt hook
returns non-2xx OR times out. UX cost: non-admin family recovery
aborts during a consent outage. Acceptable: family-scale outages are
operator-resolved within minutes, not autoscaled away.

## Cookie domain + CORS posture (A5)

A compromised app on `<app>.dunn.dev` can read its own cookies but
NOT the Kratos session cookie (HttpOnly). The browser treats
`auth.dunn.dev` and `<app>.dunn.dev` as same-site (registrable parent
`dunn.dev`), so:

- Service-worker fetch-with-credentials: blocked at the IDP CORS
  layer. Kratos `allowed_origins` lists only `https://home.dunn.dev`;
  Hydra likewise. A service worker on `<app>.dunn.dev` calling
  `auth.dunn.dev` carrying the session cookie is rejected at CORS.
- Form-driven CSRF (HIGH-1): SameSite=Lax permits same-site POSTs, so
  a top-level form on `<app>.dunn.dev` posting to
  `auth.dunn.dev/admin/users/<id>` would carry the session cookie.
  This is the path HIGH-1 closed by adding per-request CSRF tokens to
  every admin form POST.

Cross-subdomain cookie reach is the design constraint that motivates
the parent-domain decision (locked: WebAuthn rp.id requires it). The
CSRF gate is the matching mitigation.

## Backup correctness across Hydra encryption-at-rest (A6)

`docs/runbooks/postgres-backup.md` covers the basics. Partial-state
restore (Postgres consistent at the database level but not across
the `kratos` and `hydra` databases) yields drift between Kratos
identities and Hydra remembered-consent rows. At family scale the
recovery is "wipe Hydra remembered-consent rows + force re-login,"
not "fix the row." See the runbook's "Partial-state restore" section.

## mTLS gap (A7)

No mTLS between auth-pod services. Plain HTTP across `consent →
hydra:4445`, `portal → kratos:4434`, `kratos → consent:4478`. The pod
boundary is the trust unit; podman network isolation prevents
cross-pod traffic; SELinux + ZFS-backed storage close other lateral
paths.

Tier-2 implication: RCE on any auth-pod service yields full
pod-internal lateral. Family scale and single-tenancy mean this is
acceptable; the gap to enterprise-grade posture (mTLS or SPIFFE) is
not justified at this scale. Documenting the choice so it doesn't
quietly drift.

## Reversibility

If lab outcomes red, fallback is kanidm (single-binary, bus-factor and AI-ban accepted in exchange for substrate quality). Bench harness reusable. Eval evidence in `lab/docs/`.

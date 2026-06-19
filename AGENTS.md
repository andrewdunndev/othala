# Othala

**Ory for your home.** Othala is a self-hostable home authentication substrate:
a single-sign-on plane you can run on one box for the handful of apps a
household or small lab actually uses. It wraps the upstream Ory stack with one
converged web app and a small LDAP shim, so adding an app is a config file —
not a code change, not an image rebuild.

This document orients humans and coding agents working in the repo. It describes
what the project is, how the tree is laid out, the runtime-manifest model, and
how to run, test, and extend it locally.

---

## What Othala is

Othala composes three upstream pieces and adds two of its own:

- **Ory Kratos** (identity management, v26.2.0) — self-service login,
  registration, recovery, verification, settings; passkeys, passwords, TOTP.
- **Ory Hydra** (OAuth2 / OIDC provider, v26.2.0) — issues tokens to relying
  applications via the standard authorization-code + OIDC flows.
- **PostgreSQL** — the datastore both Ory services persist to.
- **`portal/`** — one Astro (Node SSR) application that front-ends *all* of the
  above: the Kratos self-service UI, the Hydra login/consent/logout challenge
  handlers, the access gate, the id_token claims builder, and an admin surface.
- **LDAP bridge** — the glauth-kratos Go binary that presents Kratos identities
  over LDAP for non-OAuth clients (Jellyfin, Apple TV / Infuse SSO) is now a
  separate sibling project: `gitlab.com/dunn.dev/kratos-ldap`. It no longer
  lives in this repo.

Ory ships its services headless and expects you to bring your own UI and your
own glue. Othala *is* that UI and glue, opinionated for the single-operator,
small-user-count case.

### The converged portal

`portal/` is the heart of the project. A single Astro Node-SSR app holds:

- **Kratos self-service flows.** A generic `ui.nodes` renderer drives
  registration, recovery, verification, and settings from Kratos's own flow
  payloads (one renderer, every flow). The login page keeps a bespoke
  passkey/password experience and the project's greeting on top of the same
  node model.
- **Hydra challenge handlers.** Login, consent, and logout challenge endpoints
  (`portal/src/pages/oauth2/*`) accept Hydra's redirect, resolve the current
  Kratos session, and accept/reject the challenge back to Hydra.
- **A fail-closed access gate.** A user reaches an app only if they are a member
  of that app's `access-<clientId>` group **and** their Kratos identity state
  is `active`. Anything ambiguous denies (see `portal/src/lib/gate.ts`,
  `access.ts`).
- **The id_token claims builder.** Per-app role and claim mapping, derived from
  the app's manifest, injected into the issued token
  (`portal/src/lib/claims.ts`, `manifests.ts`).
- **A dual-listener server.** Public SSR on `:8080`; a loopback-only admin
  listener on `:4431` carries privileged routes (`/admin/revoke-user`,
  `/admin/recovery-gate`) so they are never exposed on the public interface
  (`portal/src/server/listen.mjs`, `portal/src/lib/admin-port.*`).

Admin authority is a single allowlist: the email addresses in
`OTHALA_ADMIN_IDS` are the only admins. Identity-group membership shown in
the admin UI is display metadata, not an authority gate.

---

## Repo layout

```
portal/        Astro Node-SSR app: self-service UI, OIDC handlers, gate,
               claims, admin surface, dual-listener server.
kratos/        Ory Kratos config (kratos.yml), identity schema, hooks.
hydra/         Ory Hydra config (hydra.yml).
e2e/           Compose-based stand-up: the canonical "run Othala on Docker/
               Podman compose" worked example AND the CI/VM validation harness.
docs/          Architecture, decisions, runbooks, status.
```

Key files inside `portal/src/`:

```
lib/config.ts        All OTHALA_* env consumption (the only place env is read).
lib/tiles.ts         Dashboard tile loader (reads `presentation:` blocks).
lib/manifests.ts     OIDC client loader + validator (reads `oidc:`/`consent:`).
lib/gate.ts          Fail-closed access gate.
lib/access.ts        access-<clientId> group resolution.
lib/claims.ts        id_token claim construction.
lib/nodes.ts         Generic Kratos ui.nodes renderer.
lib/oauth2-handlers.ts  Shared Hydra challenge logic.
lib/admin-*.ts       Admin allowlist, admin API, loopback admin port.
lib/register-clients.ts Registers manifest-declared clients into Hydra.
pages/auth/*         Kratos self-service pages (login, recovery, settings, …).
pages/oauth2/*       Hydra login/consent/logout challenge endpoints.
pages/apps/[slug]    Per-app detail/education page.
pages/admin/*        Admin UI (users, groups, OAuth2 clients, activity).
server/listen.mjs    Dual-listener entrypoint (public :8080 + admin :4431).
```

---

## The runtime-manifest model

This is the single most important convention in the project.

**Apps are read at request time from a manifest directory.** There is no
build-time app catalog. The directory is `MANIFEST_DIR` (default
`/etc/portal/manifests`). Adding, changing, or removing an app is a change to
that directory — **no image rebuild**.

### One unified `<slug>.yaml` per app

Each app is one YAML file with disjoint top-level blocks:

```yaml
# <slug>.yaml
presentation:        # dashboard tile metadata — read by lib/tiles.ts
  name: Observe
  description: Dashboards and metrics for the lab.
  url: https://observe.example.test
  icon: OB
  icon_slug: grafana          # simple-icons slug (optional)
  auth_kind: oidc             # oidc | oidc+ldap | forward_auth | ldap | external
  access_group: access-observe   # must equal access-<slug>
  order: 110

oidc:                # OAuth2 client registration — read by lib/manifests.ts
  client_id: observe
  client_name: Grafana
  grant_types: [authorization_code, refresh_token]
  response_types: [code]
  scope: openid email profile groups offline_access
  redirect_uris: [https://observe.example.test/login/generic_oauth]
  audience: [https://observe.example.test]
  token_endpoint_auth_method: client_secret_basic
  skip_consent: true
  backchannel_logout_uri: https://observe.example.test/login/generic_oauth/logout

consent:             # role / claim mapping — read by lib/manifests.ts
  emit_groups_claim: true
  roles:
    admin:
      description: "Full admin."
      claim_emit: { grafana_role: ["GrafanaAdmin"], groups: ["admin"] }
    viewer:
      description: "Read-only."
      claim_emit: { grafana_role: ["Viewer"] }
  group_role_map:
    admin: admin
    family: viewer
```

A sibling **`<slug>.md`** is optional education/onboarding content for the app's
detail page; it is rendered to HTML with `marked`.

### Two loaders, one file

- **`lib/tiles.ts`** reads only the `presentation:` block to build the dashboard
  tiles and the `/apps/<slug>` detail pages.
- **`lib/manifests.ts`** reads only the `oidc:` / `consent:` blocks to register
  the OAuth2 client and compute role → claim mappings.

A manifest with a `presentation:` block but **no `oidc:` block** is
presentation-only (a tile for a `forward_auth`, `ldap`, or `external` app that
has no OAuth2 client). `lib/manifests.ts` skips those rather than failing.

Both loaders cache for ~30s and invalidate on file mtime change, so an edit
takes effect within the cache window without a restart. `lib/manifests.ts`
validates the candidate set before swapping its cache: it rejects duplicate
`client_id`s, an empty `audience`, an `audience` whose origin matches no
`redirect_uri`, a `group_role_map` value naming an undeclared role, a role
missing `claim_emit`, and the `emit_groups_claim:false` + role-emits-`groups`
contradiction. A bad manifest set is rejected with the prior good state intact.

### Adding an app

1. Write `<slug>.yaml` (and optionally `<slug>.md`) in `MANIFEST_DIR`.
2. If it declares an `oidc:` block, the client registrar
   (`lib/register-clients.ts`) registers it into Hydra.
3. The dashboard tile and the access gate (`access-<slug>` group) come online
   automatically. No rebuild.

---

## Configuration: `OTHALA_*`

Every instance-specific value is an environment variable, consumed in exactly
one module (`portal/src/lib/config.ts`). In production a required var that is
absent throws at startup; in dev/test it falls back to a safe local default with
a warning.

| Var | Purpose |
| --- | --- |
| `OTHALA_PUBLIC_URL` | Public FQDN / OIDC issuer (no trailing slash). Required in prod. |
| `OTHALA_APEX` | Registrable parent domain — drives cookie domain and WebAuthn `rp.id`. |
| `OTHALA_ADMIN_IDS` | Comma-separated Kratos identity UUIDs; the **sole** admin authorization (CVP-P1). |
| `OTHALA_SITE_NAME` | Brand name in titles/headers. |
| `OTHALA_INSTANCE_NAME` | TOTP issuer / WebAuthn display / SMTP From label. |
| `OTHALA_ADMIN_CONTACT` | Contact hint shown to locked-out users. |
| `OTHALA_IDENTITY_GROUPS` | Ordered group list for the admin UI (`admin` always first). |
| `OTHALA_DEFAULT_SCHEMA_ID` | Kratos schema_id for portal-created identities. |
| `OTHALA_WEBAUTHN_RP_ID`, `OTHALA_WEBAUTHN_RP_ORIGINS` | WebAuthn relying-party config. |
| `OTHALA_SMTP_FROM_ADDRESS` | From address for Kratos courier mail **and** the portal contact form. |
| `OTHALA_SMTP_CONNECTION_URI` | SMTP relay URI (`smtps://user:pass@host:465`). **Single source** shared by `kratos.yml` courier and the portal contact-form mailer (`lib/mailer.ts`). Required in prod. |
| `OTHALA_CONTACT_RECIPIENT` | Where the dashboard request form delivers. Required in production (no fallback; `OTHALA_ADMIN_IDS` stores UUIDs, not addresses). |
| `OTHALA_PASSWORD_MIN_LENGTH`, `OTHALA_HIBP_ENABLED` | Password policy knobs. |
| `KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST` | Admin-API bind addresses (render vars, not portal config). `0.0.0.0` single-network (e2e); segmented deployments bind the admin-plane network IP. |

**Ory configs are rendered, not natively expanded.** Ory has no native
`${VAR}` expansion. The `kratos/` and `hydra/` YAML are TEMPLATES whose
`${VAR}` placeholders are substituted by **`scripts/render-config.sh`** — the
single canonical render, shared by the e2e harness (`e2e/validate.sh`) and the
deploy plane (`dunn.dev/iac`). The variable contract is derived from the
template itself: render-config.sh fails fast, listing missing variable NAMES
(never rendered content), if any `${VAR}` token is unset or empty. Only braced
`${VAR}` tokens are substituted, and only those appearing in the template — a
wide caller environment cannot leak into the output.

---

## Running locally / the e2e harness

`e2e/` is both the worked "stand Othala up on compose" example and the CI/VM
validation harness. It uses the RFC 6761 reserved test domain **`othala.test`**
(and `dc=othala,dc=test` for LDAP), so nothing leaks onto a real domain.

```
e2e/compose.yml        Postgres + Kratos + Hydra + portal + Caddy.
e2e/gen-secrets.sh     Generate the local .env (secrets + OTHALA_* values).
e2e/validate.sh        Top-level orchestrator: render configs, up, health-wait,
                       run the OIDC dance + smoke matrix.
e2e/smoke.sh           Probe matrix (pass/fail counters across the stack).
e2e/oidc-dance.mjs     End-to-end authorization-code flow exercise.
e2e/manifests/         Example unified manifests for the test apps.
e2e/playwright/        Browser specs for the self-service UI.
```

Typical loop, from `e2e/`:

```sh
./gen-secrets.sh              # writes a local .env
bash validate.sh             # render → up → wait → dance → smoke
```

`validate.sh` renders the Ory configs, brings the stack up, waits on health
(the portal's healthcheck hits its loopback admin `/healthz` on `:4431`), runs
the OIDC dance, then the smoke matrix. The compose stack mounts the *rendered*
config copies, never the canonical sources directly. Caddy fronts the stack so
specs can hit `othala.test` hostnames over TLS. The harness is validated end to
end on a QEMU CI runner.

To iterate on the portal UI alone without the full stack, run the Astro dev
server: `cd portal && npm run dev` (port 4321; config falls back to dev
defaults).

---

## Test / build commands

**Portal (`portal/`):**

```sh
npm test          # node --test over scripts/*.test.mjs (incl. fuzz suites)
npm run check     # astro check (type + content checks)
npm run build     # astro build + bundle the listener / admin / registrar
npm run dev       # astro dev on :4321
npm run start     # run the built dual-listener server
```

The `scripts/*.test.mjs` suite covers the access gate, claims injection, CSRF,
the manifest loader/validator, admin auth + allowlist, the Kratos node renderer,
and the recovery gate — including property-based `*.fuzz.test.mjs` suites.

**LDAP bridge:** extracted to `gitlab.com/dunn.dev/kratos-ldap`. No Go
sources or workspace remain in this repo.

---

## Key conventions

- **Manifests are the API for apps.** Want a new app online? Add a manifest. Do
  not add app-specific code paths to the portal — the loaders and the gate are
  generic by design.
- **`access-<slug>` is load-bearing.** A tile's `access_group` must equal
  `access-<slug>`; the loader rejects a mismatch so one bad tile cannot poison
  the dashboard. The same convention names the group the gate checks.
- **Env is read in one place.** All `OTHALA_*` consumption lives in
  `lib/config.ts`. Add new instance config there, with a documented prod
  behavior (throw) and dev default.
- **The admin port is loopback-only.** Privileged routes live on `:4431` and
  must stay off the public listener. Don't move admin routes to the public mux.
- **Fail closed.** The gate, the audience/redirect check, and the manifest
  validator all default to deny / reject on anything ambiguous. Preserve that.
- **Parser parity.** `lib/manifests.ts` faithfully mirrors the manifest
  semantics of the bridge's Go side (e.g. the `claim_emit == nil` vs `{}`
  distinction, case-insensitive `client_id`). Keep the two in step when you
  touch manifest shape.

### Dependencies worth knowing

- **`@dunn.dev/reference`** — the design-system / component dependency the portal
  builds its UI on (public npm package).
- **`dunn.dev/pipeline`** — the CI catalog the project's pipeline extends
  (public). The repo's own `.gitlab-ci.yml` consumes it.
- Standard library deps: `astro` + `@astrojs/node`, `@ory/client-fetch`,
  `yaml`, `marked`, `tailwindcss`; `fast-check` + `tsx` for tests.

---

## Upstream alignment

For every durable upstream this repo builds on, reach for the upstream's
intended extension point before hand-rolling an equivalent. The upstream
maintains it, the docs match it, and version bumps don't surprise us. Only
deviate when the upstream pathway is genuinely broken on our hardware — and
then document *why* at the deviation site.

- **Ory Kratos / Hydra config** — use native Kratos/Hydra YAML config fields
  directly. Ory has no built-in `${VAR}` expansion; the sanctioned bridge is
  `scripts/render-config.sh` — the single canonical render producing
  `*.rendered.yml` before the services start, with a template-derived
  missing-variable guard. Don't bypass it with separate config-management
  templating. CAUTION for deploy planes: docker compose interpolates `${VAR}`
  inside compose.yml natively, but systemd/quadlet `Environment=` does NOT
  (it empties or passes `${}` literally) — the compose pattern must never be
  copied into a quadlet; quadlet consumers mount a rendered config instead.
- **`@ory/client-fetch` SDK** — use the generated Ory SDK for all Kratos/Hydra
  API calls (`portal/src/lib/`). Bespoke `fetch()` calls against the Ory admin
  or public APIs are a maintenance trap: SDK types and endpoint paths track
  upstream releases automatically.
- **`@ory/elements`** — when the Astro layout admits a standard Ory UI component,
  prefer elements over a bespoke equivalent. The current portal uses a custom
  `ui.nodes` renderer for Kratos self-service flows because the branded Astro
  layout doesn't accommodate elements; if that constraint lifts, elements is the
  right first reach.

## Where to read next

- `ARCHITECTURE.md` — the full architecture narrative.
- `docs/golden-path.md`, `docs/per-app-oidc.md` — the intended deploy shape and
  the per-app OIDC contract.
- `e2e/README.md` — the harness in detail.
- `gitlab.com/dunn.dev/kratos-ldap` — the LDAP bridge (separate repo).

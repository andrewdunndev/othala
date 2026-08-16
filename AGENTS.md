# Othala — house rules for whoever maintains this repo

This file is the working agreement for whoever is maintaining Othala, human or
model. It is not a spec anyone is expected to satisfy, and it is not the project
description: `ARCHITECTURE.md` is the authoritative account of what is built and
why. Read this for what to *do*.

**When this file and the code disagree, the code is right.** Fixing this file is
part of the change that made it wrong. Every rule below names the file that
enforces it, so a rule that has quietly stopped being true can be checked in one
step instead of believed. A confidently wrong sentence here is the most expensive
kind of bug this project has: it is read before anything else, by a co-maintainer
who has no other context yet.

Othala is one family's single sign-on plane. It runs as `dag.dunn.dev` on one
host for a handful of relatives and friends, maintained by one person working
with an LLM. It is public so it can be read and copied, not because it is
seeking users or contributors. It composes the upstream Ory stack behind one
converged web app, so adding an app is a config file rather than a code change
or an image rebuild.

---

## What it is made of

Othala composes three upstream pieces and adds one of its own:

- **Ory Kratos** (identity management) — self-service login, registration,
  recovery, verification, settings; passkeys, passwords, TOTP.
- **Ory Hydra** (OAuth2 / OIDC provider) — issues tokens to relying
  applications via the standard authorization-code + OIDC flows.
- **PostgreSQL** — the datastore both Ory services persist to.
- **`portal/`** — one Astro (Node SSR) application that front-ends *all* of the
  above: the Kratos self-service UI, the Hydra login/consent/logout challenge
  handlers, the access gate, the id_token claims builder, and an admin surface.

Versions are not stated here. The deploy quadlets carry the authoritative image
pins; `CHANGELOG.md` and git tags carry release state (`ARCHITECTURE.md`
"Doc source-of-truth hierarchy").

There is also an LDAP bridge, `gitlab.com/dunn.dev/kratos-ldap`, which presents
Kratos identities over LDAP. **It is an unmaintained reference and it is not
deployed.** It is a separate repo, it is shelved (`docs/access-model.md` §13),
and nothing here runs it: Cinema (Jellyfin) moved to OIDC, with a Jellyfin-local
password for native clients. The pointer stays because the code may be worth
reading. It is not an offering, no test in this repo exercises the LDAP
transport, and the `ldap` / `oidc+ldap` values of `auth_kind` describe a
capability nothing currently uses. Substrate choice decided in
docs/adr/01-auth-substrate-ory.md.

Ory ships its services headless and expects you to bring your own UI and your
own glue. Othala *is* that UI and glue, shaped for one operator and about twenty
people.

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
- **A fail-closed access gate.** A user reaches an app only if their Kratos
  identity state is `active` **and** they hold at least one of the groups that
  app's manifest binds for entry (`presentation.access:`, OR-semantics). The
  gating group is a manifest binding; it is never derived from the slug or the
  `client_id`. Anything ambiguous denies — including a client with no manifest,
  and a manifest with an empty binding (`portal/src/lib/gate.ts`
  `enforceAccessGate`; the binding is parsed by `lib/access-groups.ts`).
- **The id_token claims builder.** Per-app role and claim mapping, derived from
  the app's manifest, injected into the issued token
  (`portal/src/lib/claims.ts`, `manifests.ts`).
- **A dual-listener server.** Public SSR on `:8080`; a loopback-only admin
  listener on `:4431` carries privileged routes (`/admin/revoke-user`,
  `/admin/recovery-gate`) so they are never exposed on the public interface
  (`portal/src/server/listen.mjs`, `portal/src/lib/admin-port.*`).

Admin authority *for this portal* is the `metadata_admin.admin` marker on the
Kratos identity: admin-API-only-writable, read fresh from the admin API on every
check (`portal/src/lib/admin-auth.ts` `isAdminMarker`, ADR 08). No group grants
it, and no group can take it away. Do not confuse it with a `<svc>-admin` group,
which grants an elevated role inside one downstream app through that app's
`group_role_map` and grants nothing in this portal. Group membership shown in
the admin UI is assignment data and display metadata, not a portal authority
gate.

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
lib/manifests.ts     OIDC client loader + validator (reads `oidc:`/`consent:`,
                     plus `presentation.access:` for the entry binding).
lib/manifest-store.ts Serving-path loader: last known good set, never throws.
lib/manifest-lint.ts Manifest findings + the BLOCK/WARN severity matrix.
lib/access-groups.ts Parses `presentation.access:` into the entry binding.
lib/group-registry.ts Group TYPE (identity / access / role) derived from
                     bindings, never from the group's name.
lib/gate.ts          Fail-closed access gate (entry).
lib/access.ts        Effective per-app role resolution from those bindings.
lib/claims.ts        id_token claim construction (role → claim emission).
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
  auth_kind: oidc             # oidc | forward_auth | external
                              # (ldap | oidc+ldap parse, but the bridge is shelved)
  access:                     # ENTRY binding. Group names are the operator's.
    - observe-access          # No naming rule is enforced anywhere.
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
  group_role_map:      # ROLE binding — a separate axis from entry, above.
    observe-admin: admin
    observe-access: viewer
```

A sibling **`<slug>.md`** is optional education/onboarding content for the app's
detail page; it is rendered to HTML with `marked`.

### Entry and role are two separate bindings

This is the part most worth getting right, because it is the part a reader will
otherwise infer wrongly.

- **Entry** is `presentation.access:`. Holding one of the listed groups is what
  lets a person in. That is true for everyone, admins included.
- **Role** is `consent.group_role_map`. It decides what a person is once they
  are inside the downstream app. It never grants entry.

Nothing is derived from anything else. An admin holds **both** `<svc>-access`
and `<svc>-admin` explicitly. An identity holding only `<svc>-admin` is *not*
admitted — that is a misconfigured identity, not a shortcut, and no code will
rescue it. The whole point is that "can this person get in?" is answered by
looking at one group with no rule to remember. If you are ever tempted to add
`<svc>-admin` to an `access:` list so an admin can get in, that is the
derivation this model deliberately abolished; add the `-access` group to the
identity instead.

The group names above are illustrative. Naming is the operator's choice
throughout; see "Group names are convention, not mechanism" under Key
conventions.

### Three readers, one file

- **`lib/tiles.ts`** reads the `presentation:` block for the dashboard tiles and
  the `/apps/<slug>` detail pages, including the entry binding.
- **`lib/manifests.ts`** reads `oidc:` / `consent:` to register the OAuth2 client
  and compute role → claim mappings, and parses `presentation.access:` into the
  `accessGroups` binding the gate keys off.
- **`lib/manifest-store.ts`** is what every request path actually calls.

A manifest with a `presentation:` block but **no `oidc:` block** is
presentation-only (a tile for a `forward_auth` or `external` app with no OAuth2
client). `lib/manifests.ts` skips those rather than failing.

Both loaders cache for ~30s and invalidate on file mtime change, so an edit
takes effect within the cache window without a restart. `lib/manifests.ts`
validates the candidate set before swapping its cache and BLOCKs the reload on:
duplicate `client_id`s, an empty `audience`, an `audience` whose origin matches
no `redirect_uri`, a `group_role_map` value naming an undeclared role, a role
missing `claim_emit`, the `emit_groups_claim:false` + role-emits-`groups`
contradiction, an empty access binding with no `skip_access_check`, and the same
group listed twice in one binding. The full severity matrix, BLOCK and WARN, is
the header comment of `lib/manifest-lint.ts`; run it with `npm run
lint:manifests`.

**A broken manifest must never take the portal down.** `lib/manifest-store.ts`
is the serving path: on a failed load it keeps serving the last known good set,
logs to stderr under `[portal:manifests]`, retries on every call, and surfaces
staleness through `manifestHealth()` so nobody reads a stale app list as the
live one. With no last known good set it serves the empty set, which denies
everywhere it lands. Strict callers — the registrar and the lint CLI — go to
`lib/manifests.ts` directly and must keep throwing. Do not collapse the two.

### Adding an app

1. Write `<slug>.yaml` (and optionally `<slug>.md`) in `MANIFEST_DIR`, including
   a `presentation.access:` binding. There is no implicit fallback: a manifest
   that binds no access group is rejected at load, not silently opened.
2. If it declares an `oidc:` block, the client registrar
   (`lib/register-clients.ts`) registers it into Hydra.
3. The dashboard tile and the access gate come online against the groups that
   `access:` list names. No rebuild.
4. Put people in the group. Membership is an explicit admin act; nothing
   auto-assigns.

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
| `OTHALA_SITE_NAME` | Brand name in titles/headers. |
| `OTHALA_INSTANCE_NAME` | TOTP issuer / WebAuthn display / SMTP From label. |
| `OTHALA_ADMIN_CONTACT` | Contact hint shown to locked-out users. |
| `OTHALA_IDENTITY_GROUPS` | Ordered identity-group list offered by the admin UI (`admin` is prepended if omitted). Assignment data for the selector; it grants nothing on its own. |
| `OTHALA_DEFAULT_GROUP` | Default tile-visibility group (default `everyone`), used only by a `presentation:` block that binds no access group at all. Membership is never auto-assigned. The OIDC entry gate has no such fallback — it denies. |
| `OTHALA_DEFAULT_SCHEMA_ID` | Kratos schema_id for portal-created identities. |
| `OTHALA_WEBAUTHN_RP_ID`, `OTHALA_WEBAUTHN_RP_ORIGINS` | WebAuthn relying-party config. |
| `OTHALA_SMTP_FROM_ADDRESS` | From address for Kratos courier mail **and** the portal contact form. |
| `OTHALA_SMTP_CONNECTION_URI` | SMTP relay URI (`smtps://user:pass@host:465`). **Single source** shared by `kratos.yml` courier and the portal contact-form mailer (`lib/mailer.ts`). Required in prod. |
| `OTHALA_CONTACT_RECIPIENT` | Where the dashboard request form delivers. Required in production (no fallback — admin authority is a marker, not an email list; ADR 08). |
| `OTHALA_PASSWORD_MIN_LENGTH`, `OTHALA_HIBP_ENABLED` | Password policy knobs. |
| `KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST` | Admin-API bind addresses (render vars, not portal config). `0.0.0.0` single-network (e2e); segmented deployments bind the admin-plane network IP. |
| `OTHALA_CORS_ALLOWED_ORIGINS` | Hydra CORS allowlist (render var, not portal config). Comma-separated, unquoted origins — a browser SPA client that fetches Hydra's discovery/token endpoints directly would need its origin here, beyond `OTHALA_PUBLIC_URL` itself. Today none does: the deployed value is the single `OTHALA_PUBLIC_URL` origin, which is also the default. |

**Ory configs are rendered, not natively expanded.** Ory has no native
`${VAR}` expansion. The `kratos/` and `hydra/` YAML are TEMPLATES whose
`${VAR}` placeholders are substituted by **`scripts/render-config.sh`** — the
single canonical render, shared by the e2e harness (`e2e/validate.sh`) and the
production deploy plane. The variable contract is derived from the
template itself: render-config.sh fails fast, listing missing variable NAMES
(never rendered content), if any `${VAR}` token is unset or empty. Only braced
`${VAR}` tokens are substituted, and only those appearing in the template — a
wide caller environment cannot leak into the output.

---

## Running locally / the e2e harness

`e2e/` is both the worked "stand Othala up on compose" example and the CI/VM
validation harness. It uses the RFC 6761 reserved test domain **`othala.test`**,
so nothing leaks onto a real domain. No LDAP service is in the stack and no spec
exercises LDAP (`e2e/compose.yml` header).

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
npm test              # tsx --test over scripts/*.test.mjs (incl. fuzz suites)
npm run test:unit     # vitest run over src/lib/*.test.ts
npm run check         # astro check (type + content checks)
npm run lint:manifests # manifest lint over ../e2e/manifests
npm run build         # astro build + bundle listener / admin / registrar / lint
npm run dev           # astro dev on :4321
npm run start         # run the built dual-listener server
```

Two suites, two harnesses, both required. `scripts/*.test.mjs` (tsx `--test`)
covers the access gate, claims injection, CSRF, the manifest loader/validator,
admin auth + allowlist, the Kratos node renderer, and the recovery gate,
including property-based `*.fuzz.test.mjs` suites. `src/lib/*.test.ts` (vitest,
config in `portal/vitest.config.ts`) is the TypeScript-native lib suite. CI's
`test-portal` job runs both; `check-portal` runs `npm run check` and `npm test`.
If you add a `src/lib/*.test.ts` file it is picked up automatically — do not
assume it runs just because it exists, though: check `.gitlab-ci.yml` names the
script that globs it.

`npm run lint:manifests` is not wired into CI. The manifest checks that do gate
CI are the ones `validateClients` enforces at load, exercised by the `e2e` job's
`register-clients` service.

**LDAP bridge:** lives at `gitlab.com/dunn.dev/kratos-ldap`, unmaintained and
undeployed. No Go sources or workspace remain in this repo, and no test here
covers the LDAP transport.

---

## Key conventions

- **Manifests are the API for apps.** Want a new app online? Add a manifest. Do
  not add app-specific code paths to the portal — the loaders and the gate are
  generic by design.
- **Group names are convention, not mechanism.** A group's type — identity,
  access, or role — comes from which manifest field binds it, never from its
  name. `lib/group-registry.ts` derives it (see its header comment, which
  records the retirement of the old name-based inference), `lib/gate.ts` gates
  on the binding, and `lib/access-groups.ts` validates only a charset
  (`^[a-z0-9][a-z0-9-]*$`). Nothing anywhere requires a prefix, a suffix, or a
  match against the slug. The deployed estate happens to name its groups
  `<svc>-access` and `<svc>-admin`; that is a habit that makes the catalog
  readable, and no code will notice if you break it. **Do not "fix" a manifest
  to satisfy a naming rule — there isn't one.** The nearest thing to
  enforcement is `lib/manifest-lint.ts`, which WARNs on a group name that no
  binding knows (the typo-to-silent-lockout case) and never blocks on style.
- **Four files are byte-vendored into the deploy plane.**
  `kratos/kratos.yml`, `hydra/hydra.yml`, `kratos/identity.schema.json`, and
  `kratos/hooks/recovery-gate.jsonnet` are copied verbatim into the deploy
  repo, which fails its own drift check on any divergence. Editing one of
  them here starts a re-vendor, not a local change: tag a release, then the
  operator syncs and re-reviews. ADR 13 is the written contract. This applies
  to comments too — a comment inside those files ships to production.
- **Env is read in one place.** All `OTHALA_*` consumption lives in
  `lib/config.ts`. Add new instance config there, with a documented prod
  behavior (throw) and dev default.
- **The admin port is loopback-only.** Privileged routes live on `:4431` and
  must stay off the public listener. Don't move admin routes to the public mux.
- **Fail closed.** The gate, the audience/redirect check, and the manifest
  validator all default to deny / reject on anything ambiguous. Preserve that.
- **Entry is never derived.** Holding `<svc>-access` is what admits a person,
  for everyone including admins. Do not reintroduce a rule that infers entry
  from an admin group, a role, a marker, or a name — the whole model exists so
  that one lookup answers the question.
- **The Go lineage is history, not a contract.** `lib/manifests.ts` and
  `lib/claims.ts` began as ports of a retired Go consent service, which is why
  their headers cite `consent/claims.go` and preserve details like the
  `claim_emit == nil` vs `{}` distinction and case-insensitive `client_id`.
  There is nothing left to stay in step with: the surviving Go project,
  kratos-ldap, does not read manifests at all. Where the TypeScript diverges on
  purpose it says so at the definition — `lookupRole` picks the highest-ranked
  matched role where Go took the first stored-order match, which is what makes
  the result independent of group order. Keep the divergence and its
  explanation together; do not "restore parity".

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

## Writing in this repo

### What to write

Describe what is deployed. This is one family's SSO, open so it can be read and
copied, and the tone is "here is how we do it, help yourself" — generosity,
never apology. "A stranger could not drop this into their organisation" is the
design working, not a defect, and it must never be written up as one.

Two things follow, and they are house rules:

- **Do not add abstraction, extension points, or config surface for hypothetical
  adopters.** Every knob is unpaid maintenance on a single-maintainer project.
  Describing what is ours plainly — "`dag.dunn.dev` is this instance's value;
  substitute your own" — is right. Promising to generalise is not.
- **Do not state a rule the code does not enforce.** Name the enforcing file
  next to the rule. If you cannot name one, you are writing a habit, and it
  should be labelled as a habit. The bullet this file used to carry about
  `access-<slug>` is the worked example of what that failure costs.

Status honesty is part of this. A capability that is intended, shelved, or
parked says so, in the same sentence that describes it. Nothing that is not
running may be written as if it were.

### How to write it

Apply the estate voice rules to any text that leaves this repo — PR and MR
descriptions, issue replies, upstream comments, blog posts:

- No em-dashes; use colons, parentheses, or semicolons.
- Direct phrasing, no filler ("comprehensive", "robust", "leverage",
  "straightforward").
- State uncertainty plainly. Do not hedge.
- No trailing summaries.

DCO sign-off where a project requires it. No AI-assisted trailers. Draft to a
file first; a human reviews before anything is posted.

## Where to read next

- `ARCHITECTURE.md` — the full architecture narrative, and the authoritative
  description of the system. Where it and this file overlap, it wins.
- `docs/access-model.md` — the access-binding layer in full; the code cites it
  by section number.
- `site/src/content/docs/guides/golden-path.md`,
  `site/src/content/docs/guides/per-app-oidc.md` — the intended deploy shape and
  the per-app OIDC contract. These are the docs-site sources; they render at
  `/guides/golden-path/` and `/guides/per-app-oidc/`.
- `e2e/README.md` — the harness in detail.
- `docs/adr/` — one-time decisions, numbered. The numbers are cited from inside
  the Ory configs that the deploy plane vendors verbatim, so ADRs are rewritten
  in place and never renumbered.
- `gitlab.com/dunn.dev/kratos-ldap` — the LDAP bridge: separate repo,
  unmaintained reference, not deployed.

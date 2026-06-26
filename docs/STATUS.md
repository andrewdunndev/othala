# Status

The single source of release/version state for this repo. For cold
orientation (what the app is, the load-bearing decisions) read
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) first. For the deploy
contract read [`../DEPLOY.md`](../DEPLOY.md). Those files defer to this
one for version state and assert none of their own.

Updated 2026-06-24.

## Where we are

**v0.3.0 release-prep complete on main (CVP hardening pass + access-model +
OTel tracing + dependency security bumps). 48 commits landed since v0.3.0-rc;
tag is imminent (operator/joint). Deploy pending, operator-gated.**

The OSS project is **Othala** ("Ory for your home"); the deployed
instance host is **dag.dunn.dev**. The stack has converged to a single
all-TS application fronting upstream Ory:

- One Astro Node SSR app (`portal/`) holds the Kratos self-service
  flows (one generic `ui.nodes` renderer, `FlowNodes.astro`; login
  keeps the bespoke passkey/password UX + the ᛞ→ᛟ rune greeting), the
  Hydra login/consent/logout challenge handlers, the fail-closed
  access-gate (`gate.ts`: `access-<clientId>` group membership AND
  Kratos identity state `== active`), the id_token claims builder
  (`claims.ts`), and the dual-listener (`listen.mjs`: public SSR on
  `PORT` (code default 4321, set to 8080 in compose/prod) + loopback
  admin on `ADMIN_PORT` (code default 4431, set to 4431 in
  compose/prod) carrying `/admin/revoke-user` +
  `/admin/recovery-gate`).
- `revokeSubject()` (`revoke.ts`) runs the in-process revocation
  fan-out (Kratos deactivate + sessions, Hydra login/consent session
  revoke, best-effort LDAP bind-cache flush). No identity cache: the hot
  path fetches fresh, so a revoked subject fails the gate's state-check
  on the next fetch.
- Admin authz is the `metadata_admin.admin` marker (ADR 0008;
  admin-API-only writable), the sole authz at `requireAdminSession` +
  recovery-gate + page gates. The `admin` group is display-only.
- Back-channel logout is Hydra-native. The app holds no signing key at
  rest; the custom private-key signer was deleted.
- Apps are **runtime manifests** (v0.2.0). Each app is one unified
  `<slug>.yaml` read at request time from `MANIFEST_DIR` (default
  `/etc/portal/manifests`): `presentation:` drives the tile
  (`tiles.ts`), `oidc:`/`consent:` drive the client (`manifests.ts`), and
  a presentation-only manifest is skipped by the OIDC loader. Adding an
  app is a manifest drop, no image rebuild. The v0.1 split (Astro Content
  Collection under `portal/src/content/apps/` + `hydra/clients/`) is gone.
  Generic worked examples live in `e2e/manifests/`.

The standalone Go consent service and the `util` runner have been
**removed from the tree** — consent folded into the converged app,
`util` retired. They are not the current architecture.

**Stack:** Ory Kratos + Ory Hydra (OAuth2/OIDC) + Postgres 18 + the
converged Astro Node SSR Othala app on carmine + custom Caddy edge
(`registry.gitlab.com/dunn.dev/caddy-estate`). The Go glauth-kratos LDAP
bridge (`gitlab.com/dunn.dev/kratos-ldap`) is a separate sibling project;
it is **shelved as of 2026-06-26** (parked, not deleted).
Estate design tokens via `@dunn.dev/reference`.

## Pending state

| Item | Wave | Status |
|---|---|---|
| **Image name reconcile `portal` → `othala`** | CP | Done. The converged app builds as `build-othala` and publishes at the registry root `registry.gitlab.com/dunn.dev/othala` (`publish_at_root: true`); the `dag-consent` + `util` image builds + their SBOMs are removed; at E1 the `consent/` + `util/` source dirs were deleted and the `verify-consent` go-build job removed; the LDAP bridge (`ldap-bridge/`) has been extracted to a separate project (`gitlab.com/dunn.dev/kratos-ldap`) — no Go workspace remains in this repo. The deploy repo's `dag-portal` quadlet pins the root path. First tag under the new name was `v0.2.0`; current release target is `v0.3.0`. |
| **Deploy cutover** | — | Pending. Retire `dag-consent` + `util` from the pod; wire the dual-listener admin port + its admin env targets; repoint the Kratos recovery-hook to the Othala admin port `:4431/admin/recovery-gate`. See `DEPLOY.md`. |
| **Production deploy** | — | Pending, operator-gated. Fresh `dag_*` sops keys (carmine pre-reinstall) + deploy repo config sync/pin + `make dag-deploy`. |

The deploy repo's `dag-*` quadlets remain at the pre-cutover shape until the
cutover (`dag-portal` still depends on `dag-consent` and carries the old
`CONSENT_ADMIN_BEARER` / consent-URL wiring).

## Strengths (CV audit)

Real, substantive coverage:

- **Fail-closed gate tests** exercise both checks independently (group
  membership AND identity state), including the closed-on-lookup-failure
  path.
- **Revoke fan-out** has order + abort tests (a session-revoke failure
  aborts the fan-out; the deactivate-first ordering is enforced).
- **Dual-listener mux-disjointness** is tested: no public/challenge
  path resolves on the admin port and the SSR handler never sees admin
  paths.
- The `metadata_admin.admin` **marker** (ADR 0008) as the **sole admin
  authz** is asserted at every gate.
- **Native back-channel logout / no key at rest** is verified by the
  signer's absence.

## Caveat (CV audit)

There is **no standing linter** on the app: `astro-check` reports a
handful of type hints that are not gated in CI. The manifest loaders run
`validateClients` at load time and the `e2e` harness registers the
example manifest set against a live Hydra; treat those as the build-time
/ release-gate guards, not a continuous type gate. This is honest current
state, not a regression.

## Locked decisions

| | Decision |
|---|---|
| WebAuthn rp.id | `dunn.dev` (registrable parent, one-way) |
| Issuer URL | `https://dag.dunn.dev/` (non-changeable once any RP is wired) |
| Username | `first.last` |
| Cookie domain | `.dunn.dev`, SameSite=Lax, HttpOnly |
| Passkey policy | Preferred + password fallback |
| MFA / AAL2 | Optional default; AAL2 enforced at SSR on `/admin/*` |
| Sessions | 90d normal, 1d admin |
| Identity schema | `traits.{username,email,displayName?}` + `metadata_admin.{groups[],roles{}}` |
| Subject identifier | `public` |
| **Topology** | Single FQDN `dag.dunn.dev` for the whole SSO stack |
| **Admin authz** | `metadata_admin.admin` marker (ADR 0008); admin-API-only writable; `admin` group is display-only |
| Access gate | `access-<clientId>` group AND Kratos state `== active`, fail-closed, on login + consent |
| Back-channel logout | Hydra-native (Hydra-signed); app holds no signing key at rest |
| LDAP bridge | Go glauth-kratos binary at `gitlab.com/dunn.dev/kratos-ldap` (separate project; no `.so` plugins); stays Go. **Shelved 2026-06-26; parked, not deleted.** |
| LDAP DN | `uid=<username>,ou=users,dc=dunn,dc=dev` (bridge parked; retained as capability reference) |
| Postgres | Single instance (`postgres:18-alpine`), separate `kratos` + `hydra` DBs |
| Recovery | Code via Fastmail; admin subjects BLOCKED at the recovery-gate (console-only break-glass) |
| Hydra admin | In-pod only; never public |
| Public reachability | DNS-only Cloudflare + port-forward 443. No CF Tunnel/Access |
| `secrets.system` | NON-ROTATABLE (Hydra at-rest encryption); break-glass in `runbooks/secrets-rotation.md` |
| **Secrets store** | sops + age, estate-wide |
| **Deploy plane** | The deploy repo's `services/dag/` owns runtime topology; vendors Othala configs by tag-pin (no submodule). This repo owns app code + authoritative configs |
| Design tokens | `@dunn.dev/reference` is the single source. Never redefine locally |

Full rationale per decision: `decision.md`. Upgrade-durability choices:
`golden-path.md`. Load-bearing decisions map: `../ARCHITECTURE.md`.

## Not yet working / placeholders

- **`/admin/activity`** is **retired** from the shipped product: the route
  now redirects to `/admin` (admin gate preserved) rather than rendering a
  dead placeholder. A real activity log (alloy→Loki archival + a
  Postgres-summary table for the in-UI view) is out of scope for this
  release.
- **OIDC client registration** runs the in-app all-TS registrar
  (`manifests.ts` + `register-clients.ts` + `validateClients`, bundled to
  `dist/server/register-clients.mjs`) as a deliberate `--rm` one-shot. CI
  exercises it in the `e2e` harness against `MANIFEST_DIR`; the deploy plane
  invokes the same bundle via `make dag-apply-clients`. The legacy shell
  `apply-clients.sh` + Go `util` runner were retired at E1.
- **Postgres backup**: posture documented; implementation is the next
  deploy-layer work stream.
- **No standing app linter** (see Caveat).

## Production cutover (remaining, operator-gated)

1. **Image name reconcile** `portal` → `othala` (Wave CP).
2. **Deploy cutover** (see `DEPLOY.md`): retire consent + util, wire the
   dual-listener admin port + its env targets, repoint the Kratos
   recovery-hook to `:4431/admin/recovery-gate`.
3. **Regenerate `dag_*` sops keys fresh** before first deploy (carmine
   pre-reinstall: Fastmail SMTP, per-OIDC-consumer secrets, and the
   admin secrets behind `OTHALA_ADMIN_IDS` /
   `OTHALA_ADMIN_ENDPOINT_BEARER` / `RECOVERY_GATE_SECRET`).
4. **`make dag-sync-configs`** + bump quadlet pins to the released tag,
   then **`make dag-secrets && make dag-preflight && make dag-deploy
   HOST=carmine`**.
5. **`make dag-apply-clients HOST=carmine`** to register OIDC clients.
6. **`make dag-smoke HOST=carmine`** to validate the live substrate.
7. **DNS + port-forward**: `dag.dunn.dev` record + router 443 → carmine.
8. **First-user pilot**, then **family rollout**.

## Where to look

| Topic | File |
|---|---|
| **Load-bearing decisions + topology + flows** | `../ARCHITECTURE.md` (root) |
| **Deploy contract** | `../DEPLOY.md` (root) + the deploy repo's `services/dag/` |
| Upgrade-durability choices | `golden-path.md` |
| Historical substrate rationale (the Ory choice); architecture superseded | `decision.md` |
| Per-app OIDC integration | `per-app-oidc.md` |
| Runbooks | `runbooks/*.md` |
| WebFinger Pages function spec | `apex-webfinger-followup.md` |

## Conventions

- Push requires explicit human approval per action.
- Estate voice: no em-dashes, no filler, direct.
- The Othala pod is one security domain; defense-in-depth between in-pod
  services is partial-and-deliberate.
- Update this file whenever release/version state shifts. It is the
  only place that asserts it.
- Reading discipline (single maintainer + LLM leverage): read
  `../ARCHITECTURE.md` first, then `golden-path.md`, then this file.

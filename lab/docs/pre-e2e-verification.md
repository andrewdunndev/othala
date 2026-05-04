# Pre-E2E verification

## Verdict: YELLOW

Two missing env-var declarations block a clean compose-up on a fresh checkout. Both are mechanical fixes (one-line additions to `.env.example` and `gen-secrets.sh`). No code defects, no schema drift, no logic gaps. Once the env-var gap closes, the substrate is ready for lab E2E.

## Compile / build / test results

### consent (Go)
- `go mod tidy`: clean.
- `go build`: clean.
- `go vet ./...`: clean.
- `go test ./...`: pass (cached).
- Targeted `go test -run TestC4 -v`: pass (7 sub-tests covering canonical-order agreement and non-canonical drift detection).
- `./consent --validate-manifests --manifest-dir ../hydra/clients`: `ok: 11 manifests in ../hydra/clients`.

### ldap-bridge (Go)
- `go mod tidy`: clean.
- `go build`: clean.
- `go vet ./...`: clean.
- `go test ./...`: pass (kratos sub-package; root has no test files).

### portal (Astro / Node SSR)
- `npm install`: 364 packages, 5 moderate-severity audit findings (no breaking changes pending).
- `npm run build`: clean. Manifests rebuilt from 11 yamls. Astro server build completes in ~600ms.
- `npm run check`: 0 errors, 0 warnings, 6 hints (all `ts(6133)` unused-variable hints in `src/pages/auth/{login,recovery,settings,verification}.astro`). Cosmetic only; do not block.

## Yaml validation

`./consent --validate-manifests --manifest-dir ../hydra/clients` returns `ok: 11 manifests`.

All 11 client yamls (cinema, forge, keep, larder, library, listen, llm, memory, observe, tailscale, vault):
- Have `oidc:` and `consent:` top-level namespaces (no flat `client_id` at root).
- Have non-empty `oidc.audience` (single-element list pointing at the app's public host; tailscale points at `https://login.tailscale.com`; llm at `https://llm.dunn.dev`).
- Either set `oidc.backchannel_logout_uri` (forge, keep, larder, listen, memory, observe, vault) or carry an explanatory comment on the omission (cinema/jellyfin-plugin-sso, library/BookLore, llm/client_credentials, tailscale/custom-OIDC).

## Spot-check results

| # | Item | Status |
|---|------|--------|
| 3 | Yaml namespace migration | PASS |
| 4 | WebFinger byte-match (`https://auth.dunn.dev/`) | PASS |
| 5 | Caddyfile (lab) path-matcher order: kratos-wellknown -> portal-webfinger -> hydra-login -> hydra-other -> hydra-public -> portal-pages -> kratos-ui -> kratos-public catch-all | PASS (most-specific first) |
| 5 | `caddy/snippets/portal.caddy` mirrors lab order with consent service + carmine hosts | PASS |
| 6 | `compose.yml` portal service: image `dunn.dev/auth-portal:lab`, depends_on kratos+hydra+login-consent, env `KRATOS_PUBLIC_URL`/`KRATOS_ADMIN_URL`/`HYDRA_PUBLIC_URL`/`HYDRA_ADMIN_URL` | PASS |
| 6 | All `${VAR}` substitutions match `.env.example` | **FAIL** (see Issues) |
| 7 | Identity schema metadata_admin shape (groups + roles + `additionalProperties: false`) identical between `kratos/identity.schema.json` and `lab/compose/identity.schema.json` | PASS (only formatting + description differ) |
| 8 | Recovery webhook in `kratos/kratos.yml` -> `http://consent:4477/webhooks/recovery-gate` with `can_interrupt: true` | PASS |
| 8 | `consent/recovery_gate.go` rejects identities carrying `admin` group | PASS |
| 9 | `kratos.yml` `secrets.cookie` is two-entry list (CURRENT, PREVIOUS) | PASS |
| 9 | `kratos.yml` `secrets.cipher` is two-entry list | PASS |
| 9 | `hydra.yml` `secrets.cookie` is two-entry list | PASS |
| 9 | `gen-secrets.sh` emits both _CURRENT and _PREVIOUS slots for kratos cookie, kratos cipher, hydra cookie | PASS |
| 10 | `portal/src/lib/access.ts` walks `identity.metadata_admin.groups` in stored order; `normalizeGroupOrder` enforces canonical order at admin save | PASS |
| 10 | `consent/manifest.go LookupRole` walks `identityGroups(meta)` in declared order | PASS |
| 10 | `c4_canonical_order_test.go` covers admin-wins, family-only, kids-only, no-match, admin+family+friends | PASS |
| 11 | `consent/backchannel.go` fetches `/admin/keys/hydra.openid.id-token` (constant `hydraIDTokenKeySet`) | PASS |
| 11 | Logout token `iss` set from `cfg.Issuer` (env `HYDRA_ISSUER`, default `https://auth.dunn.dev/`); same byte string as `hydra.yml urls.self.issuer` | PASS |
| 12 | `portal/src/pages/admin/{index,activity,groups,oauth2}.astro` and `users/{index,new,[id]}.astro` exist and route via `requireAdminSession` (AAL2 guard) | PASS |
| 12 | `users/[id].astro` renders Force re-login button with `name="action" value="force-relogin"` and calls `revokeUserSessions` | PASS |
| 12 | `portal/src/lib/admin.ts` exports `revokeUserSessions(subject)` and enforces `session.authenticator_assurance_level === 'aal2'` | PASS |
| 13 | `consent/handlers.go` `handleLogin` calls `enforceAccessGate` (skip-consent path) and `enforceAccessGateFromGroups` (UI path); `handleConsent` calls `enforceAccessGateFromGroups` | PASS |
| 13 | `consent/manifest.go Reload` runs `validateClients(next)` BEFORE swapping `m.clients` (M2 pre-swap guard) | PASS |

## Issues found

### 1. Missing env-var declarations (compose-up will warn / fail strict mode)

`lab/compose/compose.yml` references two variables not declared anywhere:

- `KRATOS_UI_COOKIE_SECRET` (line 137, kratos-ui service)
- `KRATOS_UI_CSRF_SECRET` (line 139, kratos-ui service)

`lab/compose/.env.example` declares 13 variables. `lab/scripts/gen-secrets.sh` emits 13 variables. Neither covers the two kratos-ui secrets. A fresh checkout running `bash lab/scripts/gen-secrets.sh > lab/compose/.env && podman compose up` will pass empty strings to the kratos-ui container; depending on the upstream image's behavior this may either crash, generate ephemeral cookies on each restart (CSRF token rejected on every POST), or warn loudly.

**Fix:** add to both files:

```bash
# .env.example
KRATOS_UI_COOKIE_SECRET=
KRATOS_UI_CSRF_SECRET=
```

```bash
# gen-secrets.sh, in the kratos block
KRATOS_UI_COOKIE_SECRET=$(gen)
KRATOS_UI_CSRF_SECRET=$(gen)
```

### 2. compose-ldap.yml has the same gap plus one more

`compose-ldap.yml` references `KRATOS_BRIDGE_ADMIN_TOKEN` plus the same `KRATOS_UI_*` pair. Not in `.env.example` or `gen-secrets.sh`. Only matters when running the LDAP variant; flag it now so the same patch covers both paths.

### 3. Cosmetic: 6 unused-variable hints in portal auth pages

`src/pages/auth/{login,recovery,settings,verification}.astro` import `browserFlows` but don't use it; `login.astro` reads `refresh` and `returnTo` from search params but doesn't pass them through. Either consume them (the AAL2 step-up flow expects them) or drop the imports. Does not block lab E2E because `astro check` returns 0 errors / 0 warnings.

## Lab E2E test plan

Derived from `docs/adversarial-review-2.md` "Validation simulation gaps" section plus the env-var gap above.

### Pre-flight (block on these)

1. Patch `lab/scripts/gen-secrets.sh` and `lab/compose/.env.example` to add `KRATOS_UI_COOKIE_SECRET`, `KRATOS_UI_CSRF_SECRET`, `KRATOS_BRIDGE_ADMIN_TOKEN`.
2. `bash lab/scripts/gen-secrets.sh > lab/compose/.env`, fill `DOMAIN=test.dunn.dev` (or chosen lab domain).
3. `make -C portal image` to build `dunn.dev/auth-portal:lab`.
4. `podman compose -f lab/compose/compose.yml up -d`. Confirm all healthchecks pass: postgres, kratos, hydra, kratos-ui, login-consent, vaultwarden, portal, caddy.
5. `bash lab/scripts/apply-clients.sh` against the lab Hydra. Capture the per-client accept/reject/strip behavior (review item 4: C3).

### Substrate validation

6. **Webfinger byte-match (review item 5).** `tailscale up --login-server=https://auth-lab.test.dunn.dev/`. Compare the WebFinger href against `https://auth-lab.test.dunn.dev/.well-known/openid-configuration` `issuer` and `hydra.lab.yml urls.self.issuer`. Tailscale should accept; if not, capture the byte that differs.

7. **Admin UI from Workers (review item 1).** Deploy `portal/` to a wrangler dev environment with `KRATOS_ADMIN_URL=https://auth-lab.test.dunn.dev/admin`. Render `/admin/users`. Confirm Workers can hit Kratos admin (or document the architectural blocker).

8. **Postgres backup/restore (review item 7).** `podman exec auth-postgres pg_dump -U postgres kratos > /tmp/kratos.sql`, drop the volume, restore. Confirm identities survive.

### Identity + access flows

9. **Consent without access-* group (review item 2).** Create identity with `metadata_admin.groups: ["family"]` only (no `access-keep`). Navigate to Vaultwarden OIDC redirect. Confirm the consent service rejects with the access-gate response (`enforceAccessGate` rejects on missing access group).

10. **Admin form non-canonical group order (review item 3).** Create identity via admin form. Confirm `normalizeGroupOrder` writes groups in canonical order regardless of input order. Confirm consent service emits the role the portal "Effective Access" panel predicts.

11. **Admin recovery rejection (review item 8, H1/D3).** Trigger a recovery flow for an identity with `admin` group. Confirm the Kratos webhook hits `/webhooks/recovery-gate` and Kratos surfaces the rejection. Confirm a non-admin identity recovers normally.

12. **Verification flow (review item 11, M8).** Create identity with verification required. Walk through `/auth/verification`. Today this page is a stub; document what gaps surface.

### Logout + session lifecycle

13. **Logout propagation (review item 10, M9).** Sign in to two apps with back-channel logout (e.g., observe + forge). Click portal logout. Confirm both apps end the local session via the `/admin/keys/hydra.openid.id-token` -signed logout token. Sign in to Jellyfin (no back-channel). Document the residual session.

14. **Force re-login (D4).** From admin UI `users/[id].astro`, click Force re-login on a logged-in user. Confirm Kratos sessions revoked AND back-channel logout sent to all consenting RPs.

15. **SIGHUP reload mid-apply (review item 9, M6).** While `apply-clients.sh` is running, fire `kill -HUP $(pgrep consent)`. Confirm consent stays up with the previous manifest set if validation fails on the new set; confirm new clients become live if validation passes.

### LDAP bridge (Phase 2 prerequisite for Jellyfin)

16. **Anonymous LDAP bind (review item 6, H10).** Bring up `compose-ldap.yml`. Configure Jellyfin LDAP plugin against glauth-kratos. Capture the bind sequence (anonymous discovery vs. service-account bind). Decide the production shape.

17. **Bind cache rotation (review item 12, M4).** Bind a user, change Kratos password, re-bind with old password within the cache window. Confirm cache behavior matches the documented 30s TTL.

### Cookie rotation drill (H3)

18. Walk through `docs/runbooks/cookie-rotation.md`: generate new `KRATOS_COOKIE_SECRET_CURRENT`, set `KRATOS_COOKIE_SECRET_PREVIOUS` to the old value, restart Kratos. Confirm existing browser sessions remain valid until natural expiry, then clear `_PREVIOUS` and confirm session continuity.

### Pass criteria

Lab spike is GREEN when items 6-18 either pass or have a documented Phase-2/Phase-3 follow-up. Items 1-5 are pre-flight; without them the substrate doesn't reach a state where 6-18 can run.

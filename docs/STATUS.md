# Status

Read this first if you're picking up the project cold.

Last updated: 2026-05-04.

## Where we are

**Phase:** code complete; production cutover pending operator work.

**Substrate:** Ory Kratos (identity) + Ory Hydra (OAuth2/OIDC) + custom glauth-kratos LDAP bridge (we build) + Astro portal on carmine (Node SSR, in-pod) + custom Caddy image at `registry.gitlab.com/dunn.dev/caddy-estate` (xcaddy + caddy-dns/cloudflare).

**Estate-wide design:** consumes `@dunn.dev/design` v0.3.0 (tokens + site chrome public export). Auth portal mirrors the visual language of `design.dunn.dev`.

**Why Ory:** total UI control, composable (Kratos + Hydra each do one thing), no commercial-tier creep, the LDAP bridge is publishable as a glauth contribution.

## Locked decisions (irreversible without redoing work)

| | Decision | Why |
|---|---|---|
| WebAuthn rp.id | `dunn.dev` (registrable parent) | Cross-subdomain passkey assertion. **One-way.** Changing later invalidates every enrolled passkey. |
| Username | `first.last` | Readable, LDAP DN-friendly. |
| Cookie domain | `.dunn.dev` (parent), SameSite=Lax, HttpOnly | Cross-subdomain Astro UI calls Kratos. |
| Passkey policy | Preferred + password fallback | Family won't enroll consistently; lockout protection. |
| MFA | Optional default; AAL2 enforced at app-layer SSR on `/admin/*` | Adversarial review: Kratos AAL is global-or-per-flow, not per-route. |
| Sessions | 90d normal, 1d admin | Family UX vs admin posture. |
| Identity schema | `traits.{username,email,displayName?}` + `metadata_admin.{groups[],roles{}}` | groups: identity (admin/family/kids/friends) + access-* per app. roles: per-user-per-app override. |
| Consent | `skip_consent: true` per client for the 11 OIDC clients | Family never sees consent screens. |
| Subject identifier | `public` | Family scale. |
| WebFinger | Astro endpoint at `auth.dunn.dev/.well-known/webfinger`, env-driven issuer | Real handler controls Content-Type + byte-match issuer. |
| LDAP bridge | Custom binary linking glauth/ldap server library directly. NOT a runtime .so plugin (glauth has no public Handler registry per Phase 2 finding) | Phase 2 lab proven. |
| LDAP DN format | `uid=<username>,ou=users,dc=dunn,dc=dev` | uid as RDN. |
| Bridge deployment | Co-located in Jellyfin pod | Locality, smaller blast radius. |
| Postgres | Single instance, separate `kratos` and `hydra` databases | Ory's recommended pattern. |
| Recovery | Code strategy (numeric code emailed). Admin-group identities BLOCKED at the recovery-gate webhook (console-only break-glass per docs/runbooks/admin-recovery.md). | Adversarial review H1/D3. Stolen-Fastmail does not equal admin takeover. |
| SMTP | Fastmail | Already in family stack. |
| Onboarding | Admin creates user in Kratos → admin UI emits one-time enrollment URL → texts via Signal/iMessage | No password ever transits a channel. |
| Astro adapter | `@astrojs/node` standalone on carmine | Workers couldn't reach Kratos admin port. Portal in-pod gives direct admin access. CF role: DNS hosting + DNS-01 ACME only. |
| Hydra admin reachability | In-pod only (`http://hydra:4445`); never public | Adversarial review C1. |
| Audit log | alloy → Loki + small admin "recent activity" table | Operational + immediate UI. |
| Public reachability | DNS-only Cloudflare + port-forward 443 on home router | No CF Tunnel, no CF Access in auth path. |
| Tailscale | Not load-bearing | Admin/auth/recovery paths must work without it. |
| Cookie / cipher rotation | Two-slot env (CURRENT + PREVIOUS), gen-secrets seeds both with distinct values, rotation runbook at docs/runbooks/cookie-rotation.md | Adversarial review H3. |
| Per-app role mapping | Declared in `hydra/clients/*.yaml` under `consent:` block. Resolution: identity's `metadata_admin.roles[client_id]` override → fallback to `group_role_map` walk in user-group order. | Per-app-oidc.md has the full table. |
| Single source of design tokens | `@dunn.dev/design` package; auth portal imports `@import '@dunn.dev/design/tokens/index.css'` and `@import '@dunn.dev/design/site/site.css'`. NEVER redefine color, type, spacing, motion locally. | Estate consistency. |

## What's done

### Code (committed + pushed)
- **Phase 1 substrate:** Kratos + Hydra + Postgres + reference UIs + Vaultwarden, lab-validated GREEN at `lab/docs/spike-evidence.md`.
- **Phase 2 LDAP bridge:** custom binary linking glauth/ldap directly. BIND + SEARCH + filters + cache validated GREEN at `lab/docs/phase2-evidence.md`.
- **Phase 3 consent service:** v2.1. Login + consent + logout handlers, yaml-namespaced manifest (oidc/consent split), per-app role mapping, deep-merge claim_emit, emit_groups_claim flag, back-channel logout JWT signing (RS256/ES256, OIDC BCL 1.0 compliant, stdlib only no jose), identity cache, listener split (`:4477` public, `:4478` admin), HMAC webhook auth, recovery gate webhook (admin-group rejection), 3-attempt back-channel retry with backoff. ~50 tests.
- **Phase 3 portal:** Astro Node SSR. Pages: index (three-state landing with dev preview), auth/{login,settings,recovery,verification,logout}, admin/{index,users,users/[id],users/new,groups,oauth2,activity}. CSRF tokens on admin POSTs. metadata-admin app-layer validator. AAL2 step-up at SSR layer. WebFinger endpoint with env-driven byte-match issuer.
- **Phase 3 ldap-bridge:** per-process bind cache salt; LDAP injection regression cases in DN parser; fuzz harness for DN parsing.
- **Phase 3 client manifests:** all 11 OIDC yamls populated with roles + group_role_map + backchannel_logout_uri (where supported); audience invariant validated.
- **Phase 3 design integration:** `@dunn.dev/design` v0.3.0 consumed via package import; tokens + site chrome (header, page, section, hero, footer) imported from upstream.
- **Phase 3 estate-wide design language:** auth pages refactored to use page-eyebrow / page-title / page-lede / section patterns; mark in chrome; theme toggle; restraint.
- **Phase 3.5 caddy-estate rename:** `dunn.dev/immutable/caddy-cloudflare` moved + renamed to `dunn.dev/caddy-estate`. All consumers updated across 6 repos. CI pipeline green; image at `registry.gitlab.com/dunn.dev/caddy-estate:latest`.

### Validation evidence
- `lab/docs/spike-evidence.md` — Phase 1 lab GREEN
- `lab/docs/phase2-evidence.md` — Phase 2 lab GREEN
- `lab/docs/phase3-evidence.md` — Phase 3 rev1 (5 failures, all fixed in code)
- `lab/docs/phase3-readiness.md` — Phase 3 rev2 GREEN summary
- `lab/docs/security-validation.md` — security-remediation lab cycle GREEN

### Adversarial reviews (all addressed)
- `lab/docs/adversarial-review.md` — Phase 0 review (substrate decisions)
- `docs/security-review-2026-05-04.md` — Phase 3 security review: 4 HIGH + 7 MEDIUM + 5 LOW + 7 architectural. All remediated.

### Runbooks
- `docs/runbooks/admin-recovery.md` — break-glass for admin (console-only)
- `docs/runbooks/cookie-rotation.md` — _CURRENT / _PREVIOUS slot semantics
- `docs/runbooks/secrets-rotation.md` — `secrets.system` non-rotatable break-glass
- `docs/runbooks/postgres-backup.md` — placeholder; needs implementation before family pilot
- `docs/runbooks/email-recovery.md` — Fastmail SPF/DKIM verification

### Per-app integration
- `docs/per-app-oidc.md` — table for each of 14 surfaces (11 OIDC + 1 LDAP + 2 forward-auth) with claim shape, JIT support, audience verification status

### Fuzz harnesses
- `consent/backchannel_fuzz_test.go` — JWK alg validation (caught real bug)
- `consent/manifest_fuzz_test.go` — yaml manifest parsing
- `ldap-bridge/kratos/dn_fuzz_test.go` — DN parser (caught LDAP injection)

## What's next (production cutover, in order)

The substrate is built and validated. Carmine cutover is the next gate. These five steps are operator-flavored:

### Step 1 — Pyinfra carmine quadlets (longest pole)
Author quadlet manifests for kratos, kratos-courier (singleton), kratos-migrate (init), hydra, hydra-migrate (init), consent, portal, postgres. Caddy already lives via per-pod sidecar pattern in carmine; auth pod adds its own Caddy sidecar pulling from `registry.gitlab.com/dunn.dev/caddy-estate:latest`. Reference pattern: `immutable/carmine/services/<app>/.config/containers/systemd/`. Estimated: 1-2 days of focused operator work.

### Step 2 — Production secrets
Generate via `lab/scripts/gen-secrets.sh`-equivalent for production; store in Bitwarden + carmine env. Required: `KRATOS_PG_PASS`, `KRATOS_COOKIE_SECRET_{CURRENT,PREVIOUS}`, `KRATOS_CIPHER_SECRET_{CURRENT,PREVIOUS}`, `HYDRA_PG_PASS`, `HYDRA_SYSTEM_SECRET` (NON-ROTATABLE), `HYDRA_COOKIE_SECRET_{CURRENT,PREVIOUS}`, `HYDRA_PAIRWISE_SALT`, `CSRF_SECRET`, `RECOVERY_GATE_SECRET`, `CONSENT_ADMIN_BEARER`, `LDAP_BRIDGE_ADMIN_BEARER`, per-app OIDC `<APP>_CLIENT_SECRET`. ~30 min.

### Step 3 — DNS + port-forward
Cloudflare DNS records for `auth.dunn.dev`, `home.dunn.dev`, per-app `<app>.dunn.dev` pointed at home IP (DNS-only / gray cloud). Home router 443 → carmine. ~30 min.

### Step 4 — First-user pilot
Admin (operator) creates own identity via Kratos admin; admin UI issues one-time enrollment URL; enroll passkey on real DNS; validate full OIDC flow against one app (Vaultwarden recommended). ~30 min.

### Step 5 — Family rollout
Per family member: admin creates identity, sends enrollment URL via Signal/iMessage, family member enrolls passkey. Pilot one user before fanning out. ~30 min/user × 5–25 users.

## Operational gaps to close before family rollout (NOT blockers for first-user pilot)
- **Postgres backup** — runbook is a placeholder. Configure pg_dump cron + ZFS snapshot integration. Document restore drill including `secrets.system` rehydration. Per `docs/runbooks/postgres-backup.md`. ~1 day.
- **Per-app audience verification audit** — every client manifest sets `audience` but no per-app audit confirms each downstream app verifies aud. Tracked in `docs/per-app-oidc.md` (currently NEEDS-VERIFY for all). Lab-validate during Phase 4 wiring of each app.
- **`docs/decision.md` and `docs/substrate-comparison.md`** still contain "direct go build, no xcaddy" language. Caddy image actually uses xcaddy. Small follow-up commit to scrub.

## Open architectural questions (informational, not blockers)
- A2: `secrets.system` non-rotatable. Single-key risk for Hydra at-rest encryption of client secrets. Mitigation procedural (Bitwarden + carmine env). See `docs/runbooks/secrets-rotation.md`.
- A3: Per-app aud verification audit pending Phase 4 lab work.
- A7: No mTLS in-pod. Pod boundary = trust unit. Acceptable at family scale.

## Cloudflare-Containers thought experiment
Considered but rejected: Cloudflare doesn't natively offer Postgres; running Postgres-in-Container on CF is just hosting it in their datacenter without HA. For "single company for the family" goal, Hetzner Cloud single VM is closer than CF (but accepted carmine for $0 marginal cost). Decision: ship to carmine. Revisit CF Containers as a redundancy lab later if useful.

## Where to look

| If you want to know about... | Read |
|---|---|
| What's currently in flight | this file (`docs/STATUS.md`) |
| The architectural shape | `docs/architecture.md` |
| The locked decisions in detail | `docs/decision.md` |
| Why Ory and not Authentik/kanidm/etc | `docs/substrate-comparison.md`, `lab/docs/eval-*.md` |
| Per-app integration shapes | `docs/per-app-oidc.md` |
| Phase 0 (substrate-pick) review | `lab/docs/adversarial-review.md` |
| Phase 3 security review + remediation | `docs/security-review-2026-05-04.md` |
| Lab evidence | `lab/docs/spike-evidence.md` (Phase 1), `phase2-evidence.md`, `phase3-evidence.md`, `phase3-readiness.md`, `security-validation.md` |
| Ory homelab gap analysis | `lab/docs/ory-homelab-research.md` |
| Runbooks | `docs/runbooks/*.md` |
| Contribution strategy (what we publish upstream) | `docs/contribution-strategy.md` |

## Working conventions

- All commits require explicit human approval before push.
- This STATUS.md gets updated whenever phase shifts; it's the canonical cross-session resume doc.
- Apply estate voice in any external text: no em-dashes; direct phrasing; no filler ("comprehensive", "robust", "leverage", "straightforward").
- The auth pod is a single security domain; defense-in-depth between in-pod services is partial-and-deliberate.

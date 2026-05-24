# Status

Canonical cross-session resume doc. Read first.

Updated 2026-05-24.

## Where we are

**Shippable.** Container builds + supply-chain artifacts are signed,
SBOM'd, and pinned. Carmine is online and ready for service deploys.
Next session: pyinfra carmine quadlets.

**Stack:** Ory Kratos (identity) + Ory Hydra (OAuth2/OIDC) + custom glauth-kratos LDAP bridge + Astro Node SSR portal on carmine + custom Caddy image at `registry.gitlab.com/dunn.dev/caddy-estate` (UBI 9 via dunn.dev/pipeline catalog, no xcaddy). Estate design via `@dunn.dev/reference@^0.2.0` (tokens + chrome + journal pattern).

## Released artifacts (v0.1.3)

| Path | What |
|---|---|
| `registry.gitlab.com/dunn.dev/auth/consent:v0.1.3` + `:latest` | Go HTTP, signed by digest via cosign keyless |
| `registry.gitlab.com/dunn.dev/auth/ldap-bridge:v0.1.3` + `:latest` | glauth-kratos LDAP bridge, signed |
| `registry.gitlab.com/dunn.dev/auth/portal:v0.1.3` + `:latest` | Astro Node SSR, signed |
| `gitlab.com/dunn.dev/auth/-/releases/v0.1.3` | GitLab Release; SBOMs linked from `/-/packages/generic/auth/v0.1.3/` |

All three images on `dunn.dev/pipeline/ci-runtime-{go,node}:2.3.3` (UBI 9.8). Container registry cleanup policy active: semver + `:latest` + cosign sigs kept forever, everything else pruned after 30d.

## Locked decisions

| | Decision |
|---|---|
| WebAuthn rp.id | `dunn.dev` (registrable parent, **one-way**) |
| Username | `first.last` |
| Cookie domain | `.dunn.dev`, SameSite=Lax, HttpOnly |
| Passkey policy | Preferred + password fallback |
| MFA / AAL2 | Optional default; AAL2 enforced at SSR on `/admin/*` |
| Sessions | 90d normal, 1d admin |
| Identity schema | `traits.{username,email,displayName?}` + `metadata_admin.{groups[],roles{}}` |
| Consent | `skip_consent: true` per client (11 trusted OIDC clients) |
| Subject identifier | `public` |
| WebFinger | Astro endpoint, env-driven byte-match issuer |
| LDAP bridge | Custom binary linking glauth/ldap directly (no .so plugins) |
| LDAP DN | `uid=<username>,ou=users,dc=dunn,dc=dev`, bridge co-located in Jellyfin pod |
| Postgres | Single instance, separate `kratos` + `hydra` DBs |
| Recovery | Code via Fastmail; admin group BLOCKED at recovery-gate webhook (console-only break-glass) |
| Onboarding | Admin creates → enrollment URL → Signal/iMessage |
| Astro adapter | `@astrojs/node` standalone on carmine (Workers can't reach admin port) |
| Hydra admin | In-pod only; never public |
| Public reachability | DNS-only Cloudflare + port-forward 443. No CF Tunnel/Access |
| Tailscale | Not load-bearing |
| Cookie/cipher rotation | Two-slot env (CURRENT + PREVIOUS), seeded distinct |
| Per-app role mapping | In `hydra/clients/*.yaml` `consent:` block; resolution: `metadata_admin.roles[client_id]` override → group_role_map walk in user-group order |
| Design tokens | `@dunn.dev/reference` is the single source (design was archived 2026-05-24). Never redefine locally |
| `secrets.system` | NON-ROTATABLE (Hydra at-rest encryption); break-glass procedure in runbook |

Full rationale per decision: `docs/decision.md`.

## What's done (committed + pushed)

- Phase 1 substrate, Phase 2 LDAP bridge, Phase 3 consent service v2.1 + Astro portal + admin UI
- Adversarial security review: 4 HIGH + 7 MEDIUM + 5 LOW + 7 architectural — all remediated
- 3 fuzz harnesses (caught 2 real bugs: JWK alg, LDAP DN escape)
- Estate design migrated from `@dunn.dev/design` to `@dunn.dev/reference` (design archived)
- `caddy-estate` rename across 6 repos
- UBI 9.8 containerization via dunn.dev/pipeline 2.3.3; consent, ldap-bridge, portal published at v0.1.3 with cosign keyless sigs + CycloneDX SBOMs + GitLab Release record
- Container registry cleanup policy active (keep semver/latest/sigs; prune else after 30d)

Lab-validated GREEN twice (Phase 3 rev2 + post-security-remediation). All VMs torn down.

## Production cutover (5 steps remaining)

Pull-from-tag images at `registry.gitlab.com/dunn.dev/auth/{consent,ldap-bridge,portal}:v0.1.3`. Caddy sidecar at `registry.gitlab.com/dunn.dev/caddy-estate:latest` (UBI 9.8). Carmine online per `0a73f2` (2026-05-23).

1. **Pyinfra carmine quadlets** (~1-2 days). kratos, kratos-courier, kratos-migrate, hydra, hydra-migrate, consent, portal, postgres + Caddy sidecar. Pin each to a specific tag (no `:latest` in production quadlets). Reference: `immutable/carmine/services/<app>/.config/containers/systemd/`. Cosign verify each image by digest before deploy (verify cert identity = GitLab OIDC keyless).
2. **Production secrets** (~30 min). Generate via gen-secrets.sh equivalent; Bitwarden + carmine env. Full env list in `lab/scripts/gen-secrets.sh`.
3. **DNS + port-forward** (~30 min). CF DNS-only records + home router 443 → carmine.
4. **First-user pilot** (~30 min). Admin self-creates → enrollment URL → passkey → validate one OIDC app.
5. **Family rollout**. Per user 30 min × 5–25 users.

## Pre-rollout gaps (not blockers for first-user pilot)

- **Postgres backup** runbook is placeholder; implementation needed before family fanout. ~1 day.
- **Per-app `aud` verification** audit pending Phase 4 wiring (table in `docs/per-app-oidc.md`).
- **`docs/substrate-comparison.md`** is a pre-Ory-pivot evaluation
  that concluded with Authentik; superseded by `decision.md`. Banner
  added 2026-05-23. The "no xcaddy" claim is now accurate (both this
  repo's historical caddy/ artifact and the production
  `dunn.dev/caddy-estate` repo migrated to the same main.go
  side-effect-imports pattern as part of the estate UBI uplift on
  2026-05-24).

## Where to look

| Topic | File |
|---|---|
| Architecture | `docs/architecture.md` |
| Locked decisions in detail | `docs/decision.md` |
| Per-app integration | `docs/per-app-oidc.md` |
| Phase 0 substrate review | `lab/docs/adversarial-review.md` |
| Phase 3 security review | `docs/security-review-2026-05-04.md` |
| Lab evidence | `lab/docs/{spike,phase2,phase3}-evidence.md`, `phase3-readiness.md`, `security-validation.md` |
| Runbooks | `docs/runbooks/*.md` |
| Substrate comparison (why Ory) | `docs/substrate-comparison.md`, `lab/docs/eval-*.md` |
| Contribution strategy | `docs/contribution-strategy.md` |

## Conventions

- Push requires explicit human approval per action.
- Estate voice: no em-dashes, no filler, direct.
- The auth pod is one security domain; defense-in-depth between in-pod services is partial-and-deliberate.
- Update this file whenever a phase shifts.

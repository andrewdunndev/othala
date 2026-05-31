# Status

Release-state + resume doc; for cold orientation read ARCHITECTURE.md first.

Updated 2026-05-31.

## Where we are

**v0.1.4 in flight.** Topology B rewrite (auth.dunn.dev consolidated;
home.dunn.dev reserved as future tile-dashboard host); portal Astro
Content Collections for the apps registry; runtime-read manifests
(no rebuild per new OIDC client); auth-util image scaffolded for
apply-clients; doc-drift sweep complete (sops everywhere, no
Bitwarden); WebFinger relocated to the dunn.dev apex per Tailscale
KB-1240. Carmine has the iac quadlets ready, pinned at `:v0.1.3`
with bump markers awaiting `v0.1.4` tag.

**Stack:** Ory Kratos v26.2.0 (identity) + Ory Hydra v26.2.0
(OAuth2/OIDC) + Postgres 18 + custom glauth-kratos LDAP bridge +
Astro Node SSR portal on carmine + custom Caddy image at
`registry.gitlab.com/dunn.dev/caddy-estate` + auth-util one-shot
container for apply-clients. Estate design via `@dunn.dev/reference@^0.2.0`.

## Released artifacts (v0.1.3 → tagging v0.1.4)

| Path | What |
|---|---|
| `registry.gitlab.com/dunn.dev/auth/consent:v0.1.3` + `:latest` | Go HTTP, signed by digest via cosign keyless |
| `registry.gitlab.com/dunn.dev/auth/ldap-bridge:v0.1.3` + `:latest` | glauth-kratos LDAP bridge, signed |
| `registry.gitlab.com/dunn.dev/auth/portal:v0.1.3` + `:latest` | Astro Node SSR, signed |
| `registry.gitlab.com/dunn.dev/auth/util:v0.1.4` (new) | apply-clients runner: UBI 9 minimal + curl + jq + yq + apply-clients.sh |
| `gitlab.com/dunn.dev/auth/-/releases/v0.1.3` | GitLab Release; SBOMs linked from `/-/packages/generic/auth/v0.1.3/` |

Container registry cleanup policy active: semver + `:latest` + cosign
sigs kept forever, everything else pruned after 30d.

## Locked decisions (v0.1.4 baseline)

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
| **Topology** | **Single FQDN `auth.dunn.dev` for the whole SSO stack** (Topology B). home.dunn.dev reserved as future tile-dashboard host, not served today. |
| **Tile dashboard** | **Session-gated home page at `auth.dunn.dev/`**; reads `portal/src/content/apps/*.md` (Astro Content Collection) + filters by user's `metadata_admin.groups` containing `access-<slug>`. Per-app detail pages at `/apps/<slug>` render MD education content. |
| WebFinger | **Cloudflare Pages function at `dunn.dev/.well-known/webfinger` (apex)** per Tailscale KB-1240. NOT on this project's portal. |
| LDAP bridge | Custom binary linking glauth/ldap directly (no .so plugins) |
| LDAP DN | `uid=<username>,ou=users,dc=dunn,dc=dev` |
| Postgres | Single instance (`postgres:18-alpine`), separate `kratos` + `hydra` DBs |
| Recovery | Code via Fastmail; admin group BLOCKED at recovery-gate webhook (console-only break-glass) |
| Onboarding | Admin creates → enrollment URL → Signal/iMessage |
| Astro adapter | `@astrojs/node` standalone on carmine |
| Hydra admin | In-pod only; never public |
| Public reachability | DNS-only Cloudflare + port-forward 443. No CF Tunnel/Access |
| Tailscale | Not load-bearing |
| Cookie/cipher rotation | Substrate-secret collapse: one sops key feeds both CURRENT and PREVIOUS slots (homelab-scope simplification documented in `docs/golden-path.md` LB#10) |
| Per-app role mapping | In `hydra/clients/*.yaml` `consent:` block; resolution: `metadata_admin.roles[client_id]` override → group_role_map walk in user-group order |
| Design tokens | `@dunn.dev/reference` is the single source (design was archived 2026-05-24). Never redefine locally |
| `secrets.system` | NON-ROTATABLE (Hydra at-rest encryption); break-glass procedure in `docs/runbooks/secrets-rotation.md`. Stored in sops as `carmine.hydra_system_secret`. |
| **Secrets store** | **sops + age** estate-wide. Bitwarden eliminated 2026-05-30. |
| **Deploy plane** | **`dunn.dev/iac/services/auth/`** owns runtime topology (quadlets, secret provisioning, sync targets). This repo owns application code + authoritative configs. |

Full rationale per decision: `docs/decision.md`. Upgrade-durability
choices: `docs/golden-path.md`. Load-bearing decisions map: `ARCHITECTURE.md`.

## What's done at v0.1.4 (committed + pushed)

In addition to the v0.1.3 baseline:

- **Topology B**: kratos.yml + hydra.yml + portal env + Caddy snippet now consolidate on `auth.dunn.dev/*`. home.dunn.dev reserved unused.
- **Tile dashboard**: `portal/src/content/apps/*.md` Astro Content Collection; session-gated home page filters by `access-<slug>` groups; per-app detail pages render MD bodies.
- **Runtime manifest read**: portal reads `hydra/clients/*.yaml` from a mounted directory at request-time, not build-time. Adding a new OIDC client = edit yaml + restart, no image rebuild.
- **auth-util image**: UBI 9 minimal + curl + jq + yq + apply-clients.sh moved from `hydra/`. One-shot quadlet in iac applies OIDC client manifests against Hydra admin.
- **Security review annotated**: every HIGH / MEDIUM / LOW carries inline `Status: REMEDIATED|ACCEPTED|OPEN` with evidence citations. Counts: 0 OPEN, 16 REMEDIATED, 1 ACCEPTED.
- **Doc drift swept**: Bitwarden mentions → sops; pyinfra-play references → iac make targets; image pins updated (v1.3/v2.2 → v26.2.0).
- **WebFinger relocated**: portal handler deleted; spec-compliant placement at dunn.dev apex documented in `docs/apex-webfinger-followup.md`.
- **`DEPLOY.md`** (new, repo root): bidirectional pointer to iac.
- **`ARCHITECTURE.md`** (new, repo root): load-bearing decisions map for new operators (or LLMs picking up the repo cold).
- **`docs/golden-path.md`** (new): the 12 integration choices that keep us durable across Ory upgrades.
- **`docs/apex-webfinger-followup.md`** (new): WebFinger Pages function spec for the dunn.dev apex repo.

## Production cutover (remaining)

1. **Tag dunn.dev/auth v0.1.4** (this repo). CI publishes consent/portal/ldap-bridge/util images at `:v0.1.4`. Operator action.
2. **Bump iac quadlet pins** from `:v0.1.3` to `:v0.1.4` in `dunn.dev/iac/services/auth/.config/containers/systemd/*.container`. Operator action; comment markers placed in iac.
3. **Add missing sops keys** before first deploy:
   - `shared.fastmail_smtp_user`
   - `shared.fastmail_smtp_password`
   - Per-OIDC-consumer secrets (`keep_oidc_client_secret` + `observe_oidc_client_secret` already present; add others as each app is wired).
4. **`make auth-secrets HOST=carmine && make auth-deploy HOST=carmine`** from iac. Validates substrate end-to-end.
5. **`make auth-sync-manifests HOST=carmine && make auth-apply-clients HOST=carmine`** to register OIDC clients in Hydra and populate the consent service's manifest dir.
6. **`make auth-smoke HOST=carmine`** validates the live substrate (openid-configuration, issuer byte-match, health endpoints, registered client_ids).
7. **uuid-ossp Postgres extension verify**: defensively added to `services/auth/postgres/init.sh`; check with `\dx` after first deploy if curious.
8. **DNS + port-forward**: `auth.dunn.dev` record + home router 443 → carmine. home.dunn.dev not yet served — defer or alias.
9. **First-user pilot**: admin self-creates → enrollment URL → passkey → validate keep + observe OIDC flows.
10. **Family rollout**: per user 30 min × 5-25 users.

## Pre-rollout gaps (not blockers for first-user pilot)

- **Postgres backup**: `docs/runbooks/postgres-backup.md` is updated to point at the Backblaze B2 (rclone) + onsite zpool posture; implementation lives in iac and is the next iac work stream.
- **Per-app `aud` verification audit**: Phase 4 wiring, per consumer.
- **QEMU-CI lab**: `lab/compose/` carries a legacy banner; the CI-driven lab that replaces it leverages carmine as the GitLab Runner host (QEMU + podman). Follow-up issue to file.
- **Tailscale**: WebFinger function on dunn.dev apex repo + first tenant setup. Tracked at `docs/apex-webfinger-followup.md`.

## Where to look

| Topic | File |
|---|---|
| **Load-bearing decisions map + topology + flows** | `ARCHITECTURE.md` (root) |
| **Deploy plane** | `DEPLOY.md` (root) + `dunn.dev/iac/services/auth/` |
| **Upgrade-durability choices** | `docs/golden-path.md` |
| Historical substrate rationale (the Ory choice); architecture superseded | `docs/decision.md` |
| Per-app integration | `docs/per-app-oidc.md` |
| Phase 0 substrate review | `lab/docs/adversarial-review.md` |
| Phase 3 security review | `docs/security-review-2026-05-04.md` |
| Lab evidence | `lab/docs/{spike,phase2,phase3}-evidence.md`, `phase3-readiness.md`, `security-validation.md` |
| Runbooks | `docs/runbooks/*.md` |
| Substrate comparison (why Ory) | `lab/docs/eval-*.md` |
| Contribution strategy | `docs/contribution-strategy.md` |
| WebFinger Pages function spec | `docs/apex-webfinger-followup.md` |

## Conventions

- Push requires explicit human approval per action.
- Estate voice: no em-dashes, no filler, direct.
- The auth pod is one security domain; defense-in-depth between in-pod services is partial-and-deliberate.
- Update this file whenever a phase shifts.
- **Single-maintainer + LLM-leverage reading discipline**: when picking up cold, read `ARCHITECTURE.md` first, then `docs/golden-path.md`, then this file. Don't widen the integration surface without checking the golden-path doc.

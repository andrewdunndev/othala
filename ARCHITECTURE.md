# Architecture map

Load-bearing decisions catalog. Read this if you (human or LLM) are
picking up the codebase cold and need to understand where the
landmines are.

This is NOT a tutorial. It's a finger-pointer at the decisions that
matter — what they are, where the code lives, and what would break
if you changed them. Each entry is short on purpose; follow the cross-references for depth.

## Reading order

1. **Right now (this file)** — what's load-bearing, where to find it.
2. `docs/golden-path.md` — the upgrade-durability commitments.
3. `docs/architecture.md` — full topology + flows.
4. `docs/decision.md` — historical decisions, each with rationale.
5. `docs/STATUS.md` — current release state + what's next.
6. `DEPLOY.md` — bidirectional pointer to `dunn.dev/iac` where production lives.

## The 12 load-bearing decisions

### LB-1: WebAuthn `rp.id = dunn.dev`

`kratos/kratos.yml: selfservice.methods.webauthn.config.rp.id`. One-way.
Changing this invalidates every passkey already enrolled. Documented
in `docs/decision.md` "WebAuthn rp.id" row.

**If you change it**: every family member re-enrolls passkeys. Don't.

### LB-2: Issuer URL `https://auth.dunn.dev/`

`hydra/hydra.yml: urls.self.issuer`. Embedded in every id_token's
`iss` claim. Once a consumer (Tailscale, Vaultwarden, etc.) is
configured against this issuer, changing it means re-onboarding the
consumer.

Also byte-matches the WebFinger response on the dunn.dev apex (see
`docs/apex-webfinger-followup.md`).

**If you change it**: re-register every OIDC client and Tailscale
contacts support to migrate.

### LB-3: `secrets.system` is non-rotatable

`hydra/hydra.yml: secrets.system`. Hydra's at-rest encryption key for
OAuth2 client secrets. Rotation is a database rebuild. Stored in sops
(`carmine.hydra_system_secret`). Runbook: `docs/runbooks/secrets-rotation.md`.

**If you lose it**: every Hydra-encrypted column is unrecoverable.
Backup the sops file + age key separately and durably.

### LB-4: Cookie domain `.dunn.dev`

`kratos/kratos.yml: session.cookie.domain`. Parent-domain cookie so
the session is readable across every `*.dunn.dev` subdomain. Same-site
implication: `auth.dunn.dev` and `<app>.dunn.dev` are same-site to
the browser; CSRF posture must account for this (HIGH-1 in the security
review documents the specific path; csrf.ts is the mitigation).

**If you change it**: cross-subdomain SSO breaks; tighten the security
review for whatever new posture you adopt.

### LB-5: `subject_types: ["public"]`

`hydra/hydra.yml: oidc.subject_identifiers.supported_types`. Same `sub`
per user across every OIDC client. Tailscale needs this for stable user
identity. Apps that demand pairwise (cross-client correlation prevention)
would need a separate hydra config and a per-client decision.

### LB-6: Pod is one trust domain, no mTLS

`docs/architecture.md` "Trust boundary topology" + `docs/golden-path.md`
"No mTLS in-cluster." In-pod HTTP is unauthenticated except where
specific bearer tokens gate (`CONSENT_ADMIN_BEARER` for portal→consent
admin, `X-Webhook-Auth` for kratos→consent recovery-gate). All other
in-pod calls are trust-by-network-isolation.

**If you change it**: introduce mTLS or SPIFFE — every in-pod call
gets a new failure mode.

### LB-7: Recovery-gate is the only Kratos hook

`consent/recovery_gate.go` + `kratos/kratos.yml: selfservice.flows.recovery.after.code.hooks`.
Intercepts the post-recovery-code session-issue and returns 403 for
admin identities (admin email recovery is disabled; console-only). LOW-5
extends this to refuse-on-empty-groups as a defense against schema drift.

**If you add more Kratos hooks**: every new hook is a contract with
Kratos's webhook config schema across versions. Each addition is
upgrade-burden.

### LB-8: Portal owns metadata_admin writes

`portal/src/lib/metadata-admin.ts: validateMetadataAdmin`. Kratos's
schema treats `metadata_admin` as opaque; the portal is the only
writer. Documented in `docs/security-review-2026-05-04.md` MEDIUM-3.

**If you add a second writer**: factor `validateMetadataAdmin` into a
Go package shared with consent so both languages enforce.

### LB-9: Apps registry is `portal/src/content/apps/*.mdx`

Astro Content Collection. Each MDX file is one app's metadata
(frontmatter: name, slug, url, icon, description, access_group) plus
education content (MDX body). The tile dashboard reads this collection,
filters by the active user's `metadata_admin.groups` (must include
`access-<slug>`), and renders.

OIDC clients are a **subset**: only apps that need Hydra registration
have a corresponding `hydra/clients/<slug>.yaml`. Forward-auth apps
(tune/Navidrome, gather/Sonarr, etc.) have MDX entries but no Hydra yaml.

**If you change this convention**: the slug across MDX and yaml is
the cross-reference; renaming either side breaks the lookup.

### LB-10: WebFinger lives at dunn.dev apex, NOT here

Tailscale KB-1240 requires WebFinger at `${email-domain}/.well-known/webfinger`.
For dunn.dev family emails this is `dunn.dev/.well-known/webfinger`,
served by a Cloudflare Pages function in the dunn.dev apex repo.
**Not** by this project, **not** by the portal.

Consulted exactly once during Tailscale tenant setup; lock-in
afterward. See `docs/apex-webfinger-followup.md`.

**If you add a Webfinger handler here**: Tailscale won't find it.
Spec-violating to put it on a subdomain.

### LB-11: Sops + age is the single secrets source

`dunn.dev/iac/pyinfra/secrets.enc.yaml`. Bitwarden is OUT (the migration
landed in iac on 2026-05-30). Documented in `docs/runbooks/secrets-rotation.md`,
`docs/runbooks/cookie-rotation.md`, `docs/runbooks/postgres-backup.md`.

**If you write a Bitwarden mention into a runbook**: stale; correct
to sops.

### LB-12: `dunn.dev/iac` is the deploy plane

This repo is the application; iac is what runs it on carmine.
Authoritative configs (kratos.yml, hydra.yml) live HERE but iac vendors
copies with provenance headers naming this repo as upstream. Drift
between the two is a deploy-time hazard.

See `DEPLOY.md` (in this repo) + `dunn.dev/iac/services/auth/` (the
deploy plane).

**If you edit a vendored copy in iac without syncing back here**: the
next sync will silently overwrite your iac change.

## Where the code lives

| Service | Path | Language | Purpose |
|---|---|---|---|
| Kratos config | `kratos/` | YAML | Identity (login, recovery, MFA, session) |
| Hydra config | `hydra/` | YAML | OIDC OP, OAuth2 AS |
| OIDC client manifests | `hydra/clients/` | YAML | Per-app `oidc:` + `consent:` blocks |
| Consent service | `consent/` | Go | Login/consent/logout handlers + recovery-gate webhook + admin revoke-user |
| LDAP bridge | `ldap-bridge/` | Go | glauth-kratos: LDAPS → Kratos identity backend (Jellyfin native clients) |
| Portal | `portal/` | Astro + TS | Tile dashboard + auth flows + admin UI |
| Apps registry | `portal/src/content/apps/` | MDX | Per-app tile metadata + education content |
| Util image | `util/` | Bash + UBI 9 | One-shot apply-clients runner (deployed as a quadlet, not a long-running service) |
| Lab compose | `lab/compose/` | YAML | LEGACY single-VM lab; replaced by QEMU-CI lab (follow-up) |
| CI / build | `.gitlab-ci.yml` | GitLab CI YAML | Per-service verify + container-image + sbom + release |

## Test surface

| Test set | Lives in | Asserts |
|---|---|---|
| Consent unit + integration | `consent/*_test.go` | Per-client role lookup, back-channel logout signing, recovery-gate logic, HTTP handlers |
| Consent fuzz | `consent/*_fuzz_test.go` | Manifest parsing edge cases, JWK alg-confusion |
| LDAP bridge unit | `ldap-bridge/kratos/*_test.go` | Bind cache, DN parse + escape (caught a real bug) |
| Portal unit | `portal/scripts/*.test.mjs` | csrf token shape, admin-recovery-gate fail-closed |
| Lab evidence | `lab/docs/*-evidence.md` | Live-stack validation (current set is from v0.1.3 GREEN runs) |
| CI lab (TODO) | `.gitlab-ci.yml` + `lab/ci/` | Full substrate up + smoke + teardown on every push |

## Where to look when you're confused

| Question | Answer |
|---|---|
| "Why does this code exist?" | `git log --follow <file>` first; then `docs/decision.md` for high-level rationale. |
| "Why is this CHOICE locked-in?" | `docs/golden-path.md` for upgrade-durability choices; `docs/decision.md` for one-time decisions. |
| "Where does production-X live?" | `dunn.dev/iac/services/auth/` for runtime configs; THIS repo for application code. |
| "What's open vs fixed?" | `docs/STATUS.md` for top-level; `docs/security-review-2026-05-04.md` for security findings. |
| "How do I deploy?" | `DEPLOY.md` (this repo's root). |
| "How do I add a new OIDC client?" | Add `hydra/clients/<slug>.yaml` + `portal/src/content/apps/<slug>.mdx` + `<slug>_oidc_client_secret` to sops + `make auth-apply-clients HOST=carmine` in iac. |
| "How do I rotate a secret?" | `docs/runbooks/*-rotation.md`. |

## Don't-Add-Here list

Things that would expand the codebase without obvious value at family
scale. Each is something an over-eager future contributor (or LLM)
might propose:

- **A full audit-log subsystem**. Stub TODO exists in `portal/src/pages/admin/activity.astro`. `journalctl` is the current audit; expand only if family scale requires.
- **OIDC self-service registration**. See `docs/golden-path.md` LB#1.
- **mTLS / SPIFFE inside the auth pod**. See LB-6.
- **Pairwise OIDC subjects**. See LB-5.
- **A federated identity story**. Single Kratos instance is the family scope.
- **K8s migration**. Podman + quadlets is the substrate. No K8s.
- **Helm charts**. Same.
- **Account Experience UI from Ory (closed-source OEL)**. Astro portal is the family UI.

If you find yourself adding one of these, ask first: is this what
"single maintainer + LLM leverage at family scale" actually needs?

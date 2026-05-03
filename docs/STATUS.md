# Status

Read this first if you're picking up the project cold.

## Where we are

**Phase:** 0 — drafting locked Ory configs and skeletons.

**Substrate:** Ory Kratos (identity) + Ory Hydra (OAuth2/OIDC) + custom glauth-kratos LDAP bridge (we build) + Astro UI on Cloudflare Workers (we build) + custom Caddy image (built directly via go build, no xcaddy). Decided after evaluating Authentik, kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel.

**Why Ory:** total UI control to match dunn.dev/design, composable architecture, no commercial-tier creep, the LDAP bridge is publishable as a glauth plugin (upstream contribution opportunity).

**Why not the others:** Authentik flow designer was unwanted complexity (we don't want flow customization, we want UX excellence). kanidm has explicit AI/LLM ban + closed contribution doors. Authelia has no LDAP server. Pocket-ID/voidauth have no LDAP server and immature single-maintainer projects. Zitadel is multi-container architecture mismatch + CVE cadence concerning.

## Locked decisions (irreversible without redoing work)

| | Decision | Why |
|---|---|---|
| WebAuthn rp.id | `dunn.dev` (registrable parent) | Cross-subdomain passkey assertion. **One-way.** Changing later invalidates every enrolled passkey. |
| Username | `first.last` | Readable, LDAP DN-friendly. |
| Cookie domain | `.dunn.dev` (parent), SameSite=Lax, HttpOnly | Cross-subdomain Astro UI calls Kratos. |
| Passkey policy | Preferred + password fallback | Family won't enroll consistently; lockout protection. |
| MFA | Optional default; AAL2 enforced at app-layer SSR on `/admin/*` | Adversarial review: Kratos AAL is global-or-per-flow, not per-route. Caddy gates session-present only. |
| Sessions | 90d normal, 1d admin | Family UX vs admin posture. |
| Identity schema | `traits.{username,email,displayName?,recoveryEmail?}` + `metadata_admin.groups[]` | Groups as admin-managed metadata (Ory-shaped, prevents user self-escalation). |
| Consent | `skip_consent: true` per client for 16 trusted apps | Family never sees consent screens. |
| Subject identifier | `public` | Family scale, no app-to-app correlation concern. |
| WebFinger | Static JSON file at `home.dunn.dev/.well-known/webfinger` | Simple, edge-cached. |
| LDAP bridge | glauth Handler interface, embedded plugin (custom binary, direct go build) | Not runtime .so. Adversarial review: glauth Backend interface is wrong; Handler is current. |
| LDAP DN format | `uid=<username>,ou=users,dc=dunn,dc=dev` | uid as RDN attribute. |
| Bridge deployment | Co-located in Jellyfin pod | Locality, smaller blast radius. |
| Postgres | Single instance, separate `kratos` and `hydra` databases | Ory's recommended pattern. |
| Recovery | Code strategy (numeric code emailed) + admin-issued URL | Magic link is deprecated in current Kratos. |
| SMTP | Fastmail | Already in family stack. |
| Onboarding | Admin creates user → emits one-time enrollment URL → texts via Signal/iMessage | No password ever transits a channel. |
| Astro adapter | Cloudflare Workers (not Pages — Astro 6 dropped Pages target) | |
| Hydra admin reachability | Consent service on carmine (NOT Workers calling Hydra admin) | Adversarial review: keeps admin port off public internet. |
| Audit log | alloy → Loki + small admin "recent activity" table | Operational + immediate UI. |
| Public reachability | DNS-only Cloudflare + port-forward 443 | No CF Tunnel, no CF Access in auth path. Single auth feel for family. |
| Tailscale | Not load-bearing | Admin/auth/recovery paths must work without it. |
| No split identity | All login through Kratos | Bitwarden master password is the one intentional exception. |

## What's done

- Repo scaffolded at `/Users/andrewdunn/gitlab.com/dunn.dev/auth/`, pushed to gitlab.com/dunn.dev/auth (private)
- 7 substrate evaluations completed: Authelia, Hanko, voidauth, Zitadel, kanidm (deep), Pocket-ID, Authentik (deep). Per-candidate evidence under `lab/docs/eval-*.md`.
- 4 feasibility validations (Q1-Q4) for the Ory architecture, all GREEN/YELLOW. Under `lab/docs/feasibility-q*.md`.
- Adversarial review against upstream Ory/Hydra/glauth/Astro 6 docs completed. Two CRITICAL findings caught and corrected (AAL2 enforcement layer, glauth interface). Six HIGH findings folded into the design. At `lab/docs/adversarial-review.md`.
- Authentik blueprints removed from working tree (preserved in git history at commit `9cebdd8`).
- Caddy custom image (`dunn.dev/caddy-estate`) Containerfile written: direct go build, one plugin (`caddy-dns/cloudflare`).
- Maintainer-walk findings for kanidm (the rejection evidence) at `upstream/firstyear-walk/findings.md`.

## What's next (immediate)

In priority order, all in Phase 0:

1. Draft `kratos/kratos.yml`, `kratos/identity.schema.json`, `hydra/hydra.yml`
2. Draft Caddy snippets at `caddy/snippets/{admin-session,oidc-app,ldap-app,forward-auth}.caddy`
3. Draft 14 OIDC client manifests at `hydra/clients/*.yaml` (one per app)
4. Draft `ldap-bridge/` skeleton: main.go, kratos/handler.go, Containerfile, Makefile, README
5. Draft `consent/` service skeleton (Go, runs on carmine alongside Hydra)
6. Draft `portal/` Astro 6 project with Cloudflare Workers adapter; pages for login/recovery/settings/consent + admin/{users,groups,oauth2,activity}
7. Draft static WebFinger response at `portal/public/.well-known/webfinger`
8. Rewrite `lab/compose/compose.yml` and `lab/compose/Caddyfile` for Kratos+Hydra+bridge
9. Adapt `lab/scripts/deploy.sh` for Hydra schema migration init + courier singleton
10. Rewrite `docs/decision.md`, `docs/architecture.md`, `docs/contribution-strategy.md` for Ory
11. Commit + push as the Ory pivot lock

## After Phase 0 — phased plan

Tracked as synthesist tasks t39-t44 in the auth/bench spec. Each is human-gated (you review, then approve to proceed):

- **Phase 1** (3-5 days): GCP lab spike, validate Kratos+Hydra+one OIDC flow + WebAuthn ceremonies
- **Phase 2** (1-2 weeks): Build glauth-kratos plugin, validate against Jellyfin LDAP plugin
- **Phase 3** (1-2 weeks): Astro UI implementation
- **Phase 4** (3-5 days): All 16 apps wired, Playwright suite
- **Phase 5** (3-5 days): Carmine production cutover via pyinfra
- **Phase 6** (ongoing): Extract glauth-kratos as standalone repo, contribute upstream

Aggressive total: 4-6 weeks to family-on-SSO.

## Open questions / blockers

(none currently — all gated decisions are locked)

## Where to look

| If you want to know about... | Read |
|---|---|
| Why Ory and not Authentik/kanidm/etc | `docs/substrate-comparison.md`, `lab/docs/eval-*.md` |
| The architectural shape | `docs/architecture.md` |
| The locked decisions | `docs/decision.md` (this STATUS file is the summary) |
| Why we don't contribute upstream Authentik or kanidm | `docs/contribution-strategy.md`, `upstream/firstyear-walk/findings.md` |
| What the adversarial review caught | `lab/docs/adversarial-review.md` |
| Per-feasibility-question evidence | `lab/docs/feasibility-q1-kratos-bind.md`, `q2-jellyfin-ldap.md`, `q3-tailscale-hydra.md`, `q4-astro-kratos.md` |
| The Ory homelab gap analysis | `lab/docs/ory-homelab-research.md` |
| What's currently in flight | this file (`docs/STATUS.md`) |

## Working conventions

- All commits require explicit human approval before push
- Synthesist tasks (in auth/bench spec) track build phases for cross-session continuity
- This STATUS.md gets updated when phases shift; it's the canonical "where we are" doc
- No upstream code contributions to Authentik or kanidm; possibly to glauth (the bridge is a candidate)
- Apply estate voice conventions to any external text (no em-dashes, direct phrasing, no filler)

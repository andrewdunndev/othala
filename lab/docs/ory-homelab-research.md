# Ory homelab feasibility, research findings

## Summary

No "Ory homelab kit" exists in 2026. The closest community attempts (ory-kit, next-ory) are both archived/unmaintained, and the only Ory-curated list (awesome-ory) lists zero homelab-targeted bundles, zero LDAP integrations, and zero common-app OIDC recipes. There is no Go binary, glauth plugin, or sidecar that exposes Kratos identities over LDAP, and Kratos has no native LDAP, so the right-shape "Kratos as source of truth, LDAP as presentation layer" tool is something we would have to build (the webhook hooks and admin Identities API exist as primitives, but nobody has assembled them). Public discussion explicitly frames Ory as too complex for homelab use and points homelabbers to Authentik / Authelia / kanidm / Pocket-ID; no community project has tried to refute that framing with a kit.

## Q1: Does an Ory homelab kit exist?

### Closest projects found

- **MarkusThielker/ory-kit** (SvelteKit UI + Kratos + Hydra docker-compose). Repository is **archived as of May 2024**, 9 stars, 1 fork, single contributor. Self-described as "an easy-to-use starting point to self-host Ory Kratos with OAuth2 and OIDC." Scope is auth flows only, no homelab-app OIDC recipes (Vaultwarden / Immich / Jellyfin etc.).
- **MarkusThielker/next-ory** (the explicit successor: Next.js UI + Kratos + Hydra + Keto + admin dashboard). **Marked unmaintained November 2025**, 47 stars, 9 forks, 159 commits, single contributor. Maintainer's literal note: "This project is currently unmaintained. Feel free to fork it and continue development." Admin dashboard was work-in-progress when development stopped.
- **karlis-vagalis/kratos-selfservice** (SvelteKit UI, Melt UI, TailwindCSS). 33 stars, 6 forks, 1 contributor, last release v0.2 March 2024. Functional but lightly maintained; ships a Dockerfile but no compose bundling. Auth UI only.
- **bessey/ory-kratos-sveltekit-demo** (BFF-style SvelteKit demo). Demo, not a kit.
- **ory/kratos-selfservice-ui-react-nextjs** and **ory/kratos-selfservice-ui-node** (official reference implementations). Reference UIs only, no homelab framing, no compose bundle, no app recipes.
- **radekg/ory-reference-compose** (Hydra + Kratos + Keto + Oathkeeper docker-compose). **Archived July 2022**, 65 stars. Reference plumbing, not a homelab kit.

No project surfaced that claims to be an "Ory homelab kit," "Ory for selfhosters," or similar. No Astro reference UI for Kratos was found.

### Maturity

Universally low. Every community kit-shaped project is archived, unmaintained, or single-contributor with double-digit stars. No project ships pre-baked OIDC client configs for common homelab apps (Vaultwarden, Mealie, Jellyfin, Immich, Navidrome, *arr stack). No project ships compose stacks plus reverse-proxy templates plus IaC for the common-case homelab.

### Activity

- ory-kit: development stopped May 2024.
- next-ory: development stopped November 2025.
- ory-reference-compose: archived July 2022.
- karlis-vagalis/kratos-selfservice: dormant since March 2024.

### Verdict

**No kit exists.** The gap is real, not just under-discoverable. Homelabbers searching for an Ory bundle find archived hobby projects and bounce to Authentik or Authelia. Awesome-ory (the project's own curated list) contains zero homelab-targeted entries, zero LDAP integrations, and a single docker-compose example (Kratos + Oathkeeper + Kong) which is not homelab-shaped.

## Q2: Kratos-to-LDAP bridge

### Existing projects that do this

**None found.** Ory issue #274 (LDAP authentication) is closed-stale with no Ory maintainer engagement and no community follow-through. A community fork (`neutronth/kratos` on a `strategy-ldap` branch) exists but is stale and inverts the desired shape: it makes Kratos consume LDAP as an identity strategy, not expose Kratos identities over LDAP.

A community proposal in the Ory forum (archive.ory.com thread 22935559) suggested an external REST-style LDAP bridge similar to Oathkeeper's pattern. The thread had no Ory engagement and no implementation followed. (The archive returned 403 / 429 on direct fetch but the search snippets confirm the proposal existed without resulting code.)

### glauth + Kratos backend

glauth's plugin model could in principle host a Kratos backend, but no such plugin exists. Notes:

- glauth ships built-in backends: config-file, ownCloud, LDAP-proxy. Database backends (SQLite, MySQL, Postgres) ship as Go plugins.
- Plugins use Go's `plugin` package, which means **Linux/macOS only** (Windows incompatible). An `embed` workaround is in flight.
- **No HTTP/REST backend exists.** A user requested exactly that ("running this in front of an existing REST API authentication service to provide an LDAP interface" - glauth issue #11) and it remains an unfilled feature request.
- The closest reference plugin is `dereulenspiegel/glauth-authelia`, which watches Authelia's YAML user file. It is filesystem-watcher-shaped, not API-client-shaped, so it would only be a partial template for a Kratos plugin.
- glauth-sqlite (the official SQL plugin) is the better template: it implements the backend interface with structured user/group tables. A Kratos plugin would need to map Kratos identity schemas to glauth's user/group/include-group tables, paginate the admin Identities API, and cache results.

So: glauth is plausible scaffolding for a Kratos LDAP bridge, but the bridge does not exist. Building one is a Go plugin against the glauth backend interface plus a Kratos admin-API client.

### Webhook/sync patterns

Ory ships the **right primitives** but not the right artifact:

- **Ory Actions / webhooks** fire on registration, login, settings update, recovery, verification across all methods (passkeys, TOTP, password, OIDC). Authentication is API-key or HTTP Basic.
- **Admin Identities API** lists, imports, updates, deletes identities with pagination and metadata fields (`metadata_admin`, `metadata_public`).
- The 20papercups article ("Syncing Ory Kratos Identities with Other Systems") is the canonical walkthrough: use a single post-registration webhook to mirror to a downstream store, keep IDs identical to avoid mapping. It is webhook-to-database guidance, not LDAP-specific.
- **lldap is not the right primitive for downstream presentation.** lldap issue #301 confirms write-sync from external systems is explicitly **not on the roadmap**, and lldap is designed to be the source of truth, not a read-replica. Using lldap as a downstream store would require running it as the truth-store and reverse-syncing Kratos into it via webhooks plus admin-API calls. Workable but inverts the desired shape.

### Verdict

**The right shape does not exist; we'd be building it.** The components needed:

1. A Kratos admin-API client with caching/pagination.
2. Either (a) a glauth plugin in Go that translates Kratos identities into glauth's user/group tables, or (b) a standalone LDAP server in Go (e.g. `go-ldap/ldap` server-side) backed by Kratos.
3. Optional: a webhook receiver to invalidate cache on identity change.

Estimate: a small Go service, 500-1500 LOC plus tests. The schema mapping (Kratos identity traits to LDAP attributes) is the only design judgement; the rest is plumbing.

## Q3: Cloud-native to homelab bridge framing

### Public discussions

- **HN 39466091** ("Ory Kratos is so complicated. Authentik is much simpler"): Ory team member (arekkas) acknowledged the complexity feedback and pointed at a four-CLI-command setup, but the original commenter and others stuck with Authentik.
- **HN 45915114** (October 2025 discussion of self-hosted Ory): mixed sentiment. One operator runs Kratos for 3M users on 4 small k8s pods and reports it stable. The dominant complaints: documentation is poor, SAML / SCIM / org features are gated behind enterprise license, "backend driven UI" is unintuitive. Commenters routinely recommended Authentik / Keycloak / Zitadel / kanidm as alternatives. **No homelab kit framing appeared in any thread.**
- **HN 26712244** ("smaller scale homelab/selfhosting people really need a better solution"): general homelab-auth gap acknowledged by community, but no Ory-specific kit response.
- The **archive.ory.com forum** thread "is there really no front end for self-hosted Ory" returned 403 on direct fetch, but the title alone confirms the user-perceived gap. Search snippets do not show an Ory team rebuttal.

### Maintainer signals

- Ory's own positioning (ory.com/blog/ory-network-or-self-hosting): self-hosted is "a great fit for individuals, researchers, hackers, and companies that want to experiment, prototype, or run unimportant workloads." That framing is welcoming-but-not-investing: they neither discourage homelab use nor ship anything that targets it.
- The HN exchanges show Ory team members responding politely to complexity criticism but not committing to a homelab-friendly bundle. SAML / SCIM / B2B / multi-tenancy are explicitly enterprise-license features, which is a clear "we sell up-market" signal.
- Awesome-ory contains zero homelab projects and Ory has not curated or promoted any community kit.

### Why no kit exists

Most likely a stack of factors:

1. **Audience mismatch.** Ory's commercial gravity is B2B SaaS / Ory Network. Homelabbers are not the buying customer, so polish doesn't get invested.
2. **Headless-by-design tax.** Kratos is intentionally headless. That makes it a great library and a poor product for the median homelabber, who wants something Authentik-shaped out of the box.
3. **Scope creep risk.** A "kit" is a maintained product (UI + compose + recipes + docs), and the only person who built one (Markus Thielker) burned out and archived twice in 18 months.
4. **No flywheel.** Competing options (Authentik, Authelia, kanidm, Pocket-ID) already absorbed the homelab demand. Anyone arriving with a hammer-shaped problem finds those tools first; Ory shows up later as "the complicated cloud-native one."
5. **No technical blocker.** Hooks, admin API, OIDC, OAuth2, MFA, passkeys, social sign-in, identity schemas all ship in the open-source build. The kit is assembly, not invention.

## What we'd be building if we did this ourselves

A homelab-targeted Ory bundle would assemble:

1. **A reference UI** (Astro or SvelteKit) that drives Kratos self-service flows: login, register, settings, recovery, verification, MFA, passkey enrollment, social sign-in. Themeable, dark-mode, mobile-friendly, container-shipped. Closest existing artifact: ory/kratos-selfservice-ui-node (Express + Handlebars, official) or karlis-vagalis/kratos-selfservice (SvelteKit, dormant). Astro adoption is a green-field opportunity since no Astro reference exists.
2. **A docker-compose stack** with Kratos, Hydra, optional Keto, Postgres, MailSlurper or real SMTP, the reference UI, and a reverse proxy (Caddy first because of its automatic-TLS story, optional Traefik). Sane defaults: same-domain hosting (Kratos's CORS / cookie constraint), passkeys-on, MFA-on, public registration off by default.
3. **An LDAP bridge** (Q2 verdict: build it). Either glauth-kratos plugin or a standalone Go LDAP server reading the admin Identities API. Translates Kratos traits to inetOrgPerson + posixAccount as needed. Solves the Jellyfin-Apple-TV / Infuse SSO LDAP-only-app gap without making the LDAP server a parallel truth-store.
4. **Common-app OIDC recipes**: Hydra OAuth2 client configs for Vaultwarden, Immich, Mealie, Jellyfin, Navidrome, *arr stack, Forgejo, Nextcloud, Paperless, Home Assistant, Grafana, Open WebUI. Each recipe: client registration JSON, app-side env vars, role/claim mapping, redirect URIs, common gotchas (e.g. Vaultwarden's email/OIDC binding rules).
5. **IaC config templates**: Kratos identity schemas (default + admin + service-account), Hydra client JSONs, Keto namespace policies, identity-trait-to-LDAP-attribute mapping. Versioned, GitOps-friendly.
6. **Deployment docs**: bring-your-own-domain setup, automatic-HTTPS via Caddy + Cloudflare DNS-01, SMTP wiring, backup/restore for Postgres, upgrade discipline (Kratos has frequent breaking-change releases, document the dance).
7. **Optional, harder**: a small admin UI (next-ory's unfinished piece) for inviting users, resetting passkeys, viewing sessions. Not strictly required if the bundle owner is comfortable with `kratos identities` CLI.

## Community-contribution potential

The gap is real, the demand is real (HN threads, Lemmy threads, archive.ory forum question), and the technical lift is assembly rather than invention. A well-named, well-iconographed kit that delivered (1) + (2) + (4) + (6) would absorb users who currently bounce to Authentik but want Ory's headless cleanness, passkey / WebAuthn quality, and OIDC / OAuth2 maturity.

Ory team's likely posture: indifferent-but-friendly. They are not investing in this segment but they have not pushed back on prior community attempts (ory-kit, next-ory) and they curate awesome-ory (so a high-quality kit could land there). Risk that they dislike a "homelab Ory" framing is low given their own self-hosted page explicitly welcomes "hackers" and "individuals."

Risk factors:

- **Maintenance treadmill.** Kratos's release cadence is fast and breaking-change-y. Recipes and IaC templates need active CI against new Kratos releases or they rot inside 6 months. ory-kit and next-ory both died on this rock (single-maintainer fatigue).
- **Demand size.** The homelab SSO market already has Authentik and Authelia covering the easy cases and Pocket-ID covering the passkey-only case. The kit's natural buyers are the subset who specifically want passkey-first, headless, OIDC-clean Ory primitives. Real but niche.
- **LDAP bridge is novel.** The Kratos-to-LDAP bridge is the most differentiated piece and the one with no existing prior art. It is also the one most likely to attract upstream interest if the design is clean, because Ory issue #274 is closed-stale and the broader cloud-native crowd has the same gap.

Net read: this is a meaningful gap, a small enough kit to ship, and the LDAP bridge in particular would have value beyond the kit (it is a useful standalone artifact). The differentiating bet is "Ory primitives + opinionated assembly + LDAP presentation layer for legacy-app SSO." Treat as a 1-2 person side-project; do not bet a roadmap on it.

## Sources

- [MarkusThielker/ory-kit (archived)](https://github.com/MarkusThielker/ory-kit)
- [markusthielker/next-ory (unmaintained)](https://github.com/markusthielker/next-ory)
- [karlis-vagalis/kratos-selfservice](https://github.com/karlis-vagalis/kratos-selfservice)
- [bessey/ory-kratos-sveltekit-demo](https://github.com/bessey/ory-kratos-sveltekit-demo)
- [ory/kratos-selfservice-ui-react-nextjs](https://github.com/ory/kratos-selfservice-ui-react-nextjs)
- [ory/kratos-selfservice-ui-node](https://github.com/ory/kratos-selfservice-ui-node)
- [radekg/ory-reference-compose (archived)](https://github.com/radekg/ory-reference-compose)
- [ory/awesome-ory](https://github.com/ory/awesome-ory)
- [ory/kratos](https://github.com/ory/kratos)
- [ory/kratos issue #274 (LDAP authentication, closed stale)](https://github.com/ory/kratos/issues/274)
- [neutronth/kratos strategy-ldap branch](https://github.com/neutronth/kratos/tree/strategy-ldap)
- [glauth/glauth](https://github.com/glauth/glauth)
- [glauth/glauth issue #11 (additional backends)](https://github.com/glauth/glauth/issues/11)
- [glauth/glauth-sqlite (plugin reference)](https://github.com/glauth/glauth-sqlite)
- [dereulenspiegel/glauth-authelia (plugin reference)](https://github.com/dereulenspiegel/glauth-authelia)
- [glauth backends documentation](https://glauth.github.io/docs/backends.html)
- [lldap/lldap issue #301 (two-way sync request, declined)](https://github.com/lldap/lldap/issues/301)
- [Syncing Ory Kratos Identities with Other Systems (20papercups)](https://20papercups.net/mappi-ory-kratos-identities-with-other-systems/)
- [Ory Actions / webhook hooks documentation](https://www.ory.com/docs/kratos/hooks/configure-hooks)
- [Ory Network or self-hosted? (Ory blog)](https://www.ory.com/blog/ory-network-or-self-hosting-explained-use-cases)
- [HN 39466091 (Ory Kratos vs Authentik complexity)](https://news.ycombinator.com/item?id=39466091)
- [HN 45915114 (Kratos self-hosted, Oct 2025 discussion)](https://news.ycombinator.com/item?id=45915114)
- [HN 29330048 (is Kratos really self-hostable)](https://news.ycombinator.com/item?id=29330048)
- [HN 26712244 (homelab self-hosting auth gap)](https://news.ycombinator.com/item?id=26712244)
- [Authelia vs Authentik 2026 (Cerbos)](https://www.cerbos.dev/blog/authelia-vs-authentik-2026-idp)
- [Authelia vs Authentik 2025 (House of Foss)](https://blog.houseoffoss.com/post/authelia-vs-authentik-which-self-hosted-identity-provider-is-better-in-2025)
- [Top 7 Ory Kratos Alternatives (Descope)](https://www.descope.com/blog/post/ory-kratos-alternatives)
- [Kanidm comparisons](https://kanidm.com/comparisons/)
- [Ory community thread: LDAP/AD proposal](https://archive.ory.com/t/22935559/i-made-a-proposal-for-a-different-approach-to-ldap-active-di)
- [Ory community thread: front-end for self-hosted Ory](https://archive.ory.com/t/29717195/is-there-really-no-front-end-for-self-hosted-ory-i-found-htt)
- [OpenID Connect with Kratos and Hydra tutorial (Carcano)](https://grimoire.carcano.ch/blog/openid-connect-with-kratos-and-hydra-tutorial-gitea-oauth/)
- [Ory Kratos for Next.js (Better Stack)](https://betterstack.com/community/guides/scaling-nodejs/ory-kratos/)

# Pocket-ID evaluation

## Summary

Red for our shape. Pocket-ID is a focused, well-maintained, Go-native passkey-only OIDC IdP, and on the OIDC-only dimension it would be the easiest of the three candidates to operate. It is disqualified by a single load-bearing fact: **Pocket-ID does not serve LDAP**. Its `LDAP_*` configuration is for *consuming* an external LDAP user store (lldap, OpenLDAP, AD), not for serving LDAP to clients. Jellyfin Apple TV / Infuse needs an LDAPS-backed user store; Pocket-ID cannot be that user store, and it has no internal LDAP server on the roadmap. Secondary concerns: four security advisories in the OAuth/OIDC core in March-April 2026 (two high, including a refresh-token revocation bypass), and zero CSS/branding hooks today.

## Maintenance + sustainability

- **Project age:** Repo created 2024-08-11 (~21 months at time of writing). v1.0 reached June 2025. v2.x stream has been the active branch since v2.0.0 on 2026-01-02.
- **Last release:** v2.6.2 on 2026-04-21 (about 11 days before the writing date).
- **Commit cadence:** Heavy. Roughly weekly minor releases through Jan-April 2026 (v2.0.0 → v2.6.2 = 9 tagged releases in 4 months). Recent commits show daily activity, dependency upgrades, translations, and feature work (`select_account`, `response_mode=form_post`, accessibility fixes) all in the past two weeks.
- **Contributors:** 30 total per the GitHub contributors API. Distribution is bus-factor-shaped: stonith404 (Elias Schneider, original author) 759 commits; kmendell (Kyle Mendell) 130; ItalyPaleAle (Alessandro Segala) 81; everyone else <30. Top three account for ~95% of contributions.
- **Governance / bus factor:** Effectively a 2-3 person project. stonith404 is the BDFL, kmendell is acting as a co-maintainer (he cuts releases, e.g. release: 2.6.2 commit), and ItalyPaleAle is the most active outside contributor and now lands feature-sized PRs. No foundation, no company. Funding goes to two GitHub Sponsors accounts (stonith404 and kmendell). 5-year horizon is plausible if Elias stays interested but is not structurally protected.
- **Funding:** GitHub Sponsors only. No commercial entity, no enterprise tier, no announced commercialization plans. Demo site runs at demo.pocket-id.org; project advertises ~9,700 active instances on its homepage.
- **Sustainability verdict:** **yellow.** Active, healthy, fast-moving, but a 2-3 person project with no foundation backing. Good now; 5-year question depends on one person's continued interest.

## Security practices

- **Substrate language:** Go (backend, Gin), SvelteKit (frontend). Frontend is statically served by the Go backend in production, so the deployed surface is a single Go binary plus an embedded SPA.
- **CVE history:** Four GitHub Security Advisories so far, all in 2026 and all in the OIDC/OAuth core:
  - **GHSA-qh6q-598w-w6m2** (high, 2026-03-07): Improper Authorization Code Validation Allows Cross-Client Token Exchange and Expired Code Reuse. Token endpoint rejected codes only when both client_id was wrong AND code expired (AND instead of OR).
  - **GHSA-9h33-g3ww-mqff** (high, 2026-03-07): OAuth redirect_uri validation bypass via userinfo/host confusion. Open redirect via crafted `user@host` redirect_uri.
  - **GHSA-w6p7-2fxx-4f44** (high, 2026-04-26): OIDC refresh-token flow bypasses authorization revocation, account disabling, and group restrictions. `createTokenFromRefreshToken` validated crypto integrity but not current authorization state. Disabled users could keep refreshing tokens; revoked clients could keep refreshing; group-restriction changes did not propagate.
  - **GHSA-hp74-gm6m-2qm5** (medium, 2026-04-26): Reauthentication bypass via one-time access token login: passkey step-up was defeated by a JWT freshness check that accepted any login method.
- These are not novice mistakes (no SQL injection, no auth-token-in-URL), but they are exactly the class of bugs you get when a small team writes their own OIDC server: subtle protocol-state errors. Three of four are post-v2.0 — the codebase is being audited under load now.
- Worth noting on the upside: each advisory has a clean writeup in the `description` field (root cause + fix), advisories are filed on schedule rather than buried in commits, and the team ships patch releases within hours of disclosure (v2.6.1 and v2.6.2 same-day on 2026-04-21).
- **Default-secure posture:** Passkey-only — no password fallback, no TOTP fallback, no email-magic-link by default. Encryption at rest for sensitive fields requires `ENCRYPTION_KEY` (file form recommended). Requires HTTPS ("Pocket ID requires a secure context"). `TRUST_PROXY=false` by default.
- **Audit reports:** None published. No third-party audit advertised on the site or in SECURITY.md. SECURITY.md is two paragraphs and explicitly states "older versions don't get security updates" — single-stream support only.
- **Recovery story:** Currently *no recovery codes*. PR #1449 (feat: add emergency recovery codes) was opened 2026-04-22 and is still open at writing. Until that lands, recovery from "all passkeys lost" requires admin intervention or LDAP-backed accounts (where the LDAP source is the IdP). Issue #18 (fallback auth, closed) confirms this is a deliberate philosophical stance, but it is a sharp edge for a family of 5-25.
- **Verdict:** **yellow.** Substrate is fine (Go, single binary, encryption-at-rest hooks, passkey-only by design). Track record shows real protocol bugs in the core flow that should make you nervous about depending on this for an estate's identity layer until the codebase has cycled through a couple more advisory rounds.

## Capabilities for our app stack

- **OIDC IDP:** Yes, this is the design center. Group claims supported. Custom claims supported (with one current bug, #1273, where claims with the same key from multiple groups overwrite rather than merge — this would bite us with our 10 access groups + 3 identity groups crossing on a `groups` claim). Multiple redirect URIs per client supported. `select_account` prompt and `response_mode=form_post` both landed in the last week of April 2026.
- **LDAP server (built-in): NO.** This is the make-or-break for our shape and Pocket-ID fails it. Pocket-ID's LDAP feature is an *inbound sync*: it acts as an LDAP client, pulling users and groups from an external LDAP server (lldap, OpenLDAP, AD) on a one-hour cron. There is no LDAP listener. Quote from the docs: "Sync your users and groups from your LDAP server to Pocket ID." Issue tracker has zero open or closed feature requests for "act as LDAP server" — the model is "Pocket-ID is downstream of your user store, not your user store."
- **Forward-auth:** No, not built-in, and the project explicitly disclaims it. Quote from docs/guides/proxy-services: "The goal of Pocket ID is to function exclusively as an OIDC provider. As such, we don't have a built-in proxy provider." Recommended layering: OAuth2-Proxy, caddy-security, Traefik forward-auth, or tinyauth. Working homelab writeups (msfjarvis.dev, thesynack.com) all use OAuth2-Proxy or caddy-security as the forward-auth shim.
- **SAML:** No. Two feature requests (#604, #1250) both closed without implementation. Not on the roadmap.
- **Passkey as primary:** Yes — the entire product is built around this. WebAuthn implementation; supports platform authenticators, Yubikeys, password-manager passkeys (1Password, Bitwarden). Multi-passkey per account. PIN-as-MFA layered on top of passkey was added (#895 closed). Implementation quality looks reasonable in the Go source, though see the recent step-up bypass advisory (GHSA-hp74-gm6m-2qm5).
- **SCIM:** Yes (outbound). SCIM 2.0 provisioning was added in v2.0 (PR #1002 / #1182). Pocket-ID can push users/groups out to a SCIM endpoint. Three open issues (#1276, #1295, #1296) on rough edges (no TLS verification toggle, group-sync failures, deletion behavior). Inbound SCIM is not a feature.
- **User self-service:** Passkey enrollment yes. Profile edits yes (limited if user is LDAP-sourced — those are read-only in the UI). Recovery flow: not yet (see PR #1449).
- **Tailscale custom-IDP (WebFinger):** Yes. WebFinger landed (issues #24, #128, #350 all closed). RFC 7033 endpoint at `/.well-known/webfinger`. Tailscale's custom-OIDC flow should work directly without needing a Caddy webfinger shim.
- **OAuth2 client-credentials (vLLM):** Standard OIDC client-credentials grant should work. There is no public note saying it does not, and the OIDC client model in the admin UI supports per-client secrets.

### Per-app fit table

| App | Pattern | Pocket-ID path |
|-----|---------|----------------|
| Vaultwarden | OIDC | Direct. Works. |
| Mealie | OIDC | Direct. Works. |
| Audiobookshelf | OIDC | Direct. Works. |
| Immich | OIDC | Direct. Works. |
| BookLore | OIDC | Direct. Works. |
| oCIS | OIDC | Direct. Works. Custom-claims bug #1273 may affect group-based authz. |
| Grafana | OIDC | Direct. Works. |
| GitLab | OIDC | Direct. Works. |
| Jellyfin (web) | OIDC | Works via Jellyfin SSO plugin. Documented. |
| **Jellyfin (Apple TV / Infuse)** | **LDAPS** | **Blocked.** Requires LDAP server. Pocket-ID does not have one. Would need to keep lldap or kanidm in front of Pocket-ID, then sync into Pocket-ID for OIDC apps — i.e. lldap (or kanidm) is still the root of identity, Pocket-ID is a downstream OIDC face. |
| Navidrome | forward-auth + Subsonic API bypass | Needs OAuth2-Proxy or caddy-security in front. Doable, second moving part. |
| Gather *arr stack | forward-auth + API bypass | Same as Navidrome. |
| vLLM | OAuth2 client-credentials | Works. |
| Tailscale | OIDC + WebFinger | Works (WebFinger native since v2.x). |

## Customizability

- **BYO UI:** No. The frontend is a SvelteKit app statically served by the Go backend. To replace the UI you would fork and rebuild. There is no template-override system.
- **Theming:** Light/dark mode follows system preference. No user-facing CSS, color, or font customization. Issue #1380 ("Custom CSS field / file input", opened 2026-03-12) is open with zero comments — it explicitly notes that prior custom-font requests have been closed because the maintainer wants to keep the UI clutter-free. The project's stance is "we choose the UI." Two prior font-customization issues were closed without implementation.
- **Custom flows:** No. There is no flow editor, no policy expression language, no flow stage system (which is exactly the point of the project — it is the anti-Authentik). Login is "tap your passkey." Period.
- **Branding:** Limited. You can set an application logo via the admin UI (and there was a recent bug, #1024, around the logo endpoint being removed and restored). You cannot change colors, fonts, or copy. Login background was tweaked recently (commit 975d3c7, "fix: restore login screen background from not showing up").
- **Verdict on customizability:** This is a stated design choice, not an oversight. If the user wants a branded "ourfamily.com" SSO portal, Pocket-ID will give them the Pocket-ID logo and palette with their app name written on a card. That is the entire customization surface today.

## Architecture

- **Single container:** Yes. One Go binary, static SvelteKit assets embedded. Image is `ghcr.io/pocket-id/pocket-id:v2`. Single binaries per OS/arch are also published per release.
- **Database:** SQLite (default, `data/pocket-id.db`) or PostgreSQL (libpq DSN via `DB_CONNECTION_STRING`). MySQL is *not* supported. CockroachDB and Yugabyte work via the Postgres wire protocol per discussion #1160. Migration between SQLite and Postgres is via `pocket-id export` / `pocket-id import` — pgloader explicitly does not work because it loses passkeys and OIDC clients.
- **Footprint:** Not formally documented but sized for SQLite-on-a-volume homelab use. The Go binary is small; deployments routinely run on 256-512 MB of RAM. Demo site advertises low-overhead operation. No formal benchmarks.
- **User store:** **Own store**, optionally backed by an upstream LDAP for sync. Without LDAP sync, Pocket-ID is the root of identity and stores users in its SQLite/Postgres. With LDAP sync, the upstream LDAP is the root of identity and Pocket-ID's local rows are downstream copies (read-only in the UI).
- **Reverse-proxy integration shape:** Front it with any reverse proxy doing TLS termination (Caddy, NGINX, Traefik). It does not act as a reverse proxy itself. Set `TRUST_PROXY=true` if you terminate TLS upstream. WebFinger is served on the same listener, so the proxy must pass through `/.well-known/webfinger`.

## Community + ecosystem

- **Homelab traction:** Strong. 7,706 stars (as of 2026-05-02), 243 forks, ~9,700 active instances per the homepage. Self-Hosted podcast episode 148 ("Homelab Disaster Prep") features it. AwesomeHomelab listing. Listed as a Coolify service. NetBird's docs include a "PocketID with NetBird Self-Hosted" guide. LXD has a first-party "configure Pocket ID as login method for LXD" howto. r/selfhosted, Lemmy, and HN threads consistently surface it as the "I switched from Authentik because it was overkill" pick.
- **Tutorials:** Plentiful. msfjarvis.dev has "Setting up forward auth with Caddy and Pocket ID." thesynack.com has "Securing Self-Hosted Apps with Pocket ID / OAuth2-Proxy." blackvoid.club has a passkey-OIDC review. Caddy community has an OAuth2-Proxy + Pocket-ID template thread. Jim's Garage video series covers it.
- **Documentation quality:** Generally praised. Site at pocket-id.org/docs. Has dedicated "Client Examples" section with per-app guides (Jellyfin, NetBird, LXD, oCIS, etc.). The proxy-services guide is direct about what Pocket-ID is not (it is not a forward-auth provider).
- **Validated integrations with our app list:**
  - Vaultwarden: documented and validated.
  - Mealie: validated by community, no first-party guide.
  - Immich: documented in client-examples.
  - Jellyfin: documented (web only — limitation explicitly called out).
  - Grafana: documented.
  - GitLab: validated by community.
  - oCIS: documented; bug #1273 affects multi-group custom claims.
  - Audiobookshelf, BookLore, Navidrome, *arr stack, vLLM: not first-party documented; standard OIDC client config applies.
- **Comparison signal — what do switchers cite?**
  - From Authentik: "overkill for us," "Pocket ID is pretty simple to use and has a very nice interface to add your users and clients. Uncluttered and straight and to the point." (Lemmy, r/selfhosted, HN).
  - From Authelia: "wanted passkey-first instead of password+2FA," "wanted family members not to deal with passwords at all" (Stephen O'Toole, beyondwatts.social).
  - From VoidAuth: O'Toole moved from VoidAuth to Pocket-ID for "ease of implementation for parents with passkeys" and "removing even the option for a password login makes it easier for family members."
  - From Kanidm: less common as a switcher origin. The HN comparison thread shows Kanidm as a peer, not as something people leave for Pocket-ID. People who pick Kanidm tend to want LDAP and policy depth; Pocket-ID has neither.

## AI/LLM contribution policy

**Unspecified.** Pocket-ID's CONTRIBUTING.md does not mention AI-assisted contributions one way or the other. There is no DCO requirement, no AI-content ban, no AI-required-disclosure rule. The project itself uses Crowdin's auto-translation (DeepL-backed) for new strings — issue #728 ("Don't use Crowdin AI translations Please") shows the maintainer defending this practice as a pragmatic translation-coverage choice. Net: no policy either way. Compare to kanidm, which has an explicit ban; Pocket-ID does not. This is not necessarily a problem for our use, but it is a difference from kanidm worth flagging.

## Pros for our use

- Single Go binary, single container, SQLite-default. Lowest operational footprint of the three candidates.
- Passkey-first matches the user-stated goal of "remove passwords for the family."
- WebFinger native — Tailscale custom-IDP works without a Caddy shim.
- Strong active maintenance (release every 2-4 weeks), responsive to security disclosures (same-day patch releases).
- Strong homelab community, abundant tutorials, validated against most of our OIDC apps.
- Documentation is honest about scope (the proxy-services page tells you "we are not a forward-auth provider, here is what to layer on top").
- License is permissive (BSD-2-Clause).

## Cons for our use

- **No LDAP server.** Cannot replace lldap/kanidm/389ds for the Jellyfin Apple TV / Infuse path. If we adopt Pocket-ID we still need a separate LDAP server upstream of it, and *that* server is the actual root of identity. Pocket-ID is then a second moving part offering an OIDC face on top of an LDAP we already own.
- No forward-auth. We need OAuth2-Proxy or caddy-security for Navidrome (with Subsonic bypass) and the *arr stack. Two more moving parts.
- No SAML. Probably fine for our app list, but closes the door if any future app is SAML-only.
- No CSS/branding. Login looks like Pocket-ID's login. Issue #1380 sits open with no maintainer response.
- No recovery codes yet (PR #1449 open). For a family of 5-25 with passkey-only, this is a real operational risk until it lands.
- Four security advisories in the OIDC core in the past two months. They were filed and patched cleanly, but they are evidence that the protocol-implementation surface is still being shaken out.
- 2-3 person project. Strong now, structurally fragile on a 5-year horizon.
- Custom-claims-with-same-key bug (#1273) would cause real problems for our 10-access-group / 3-identity-group setup if we wanted layered claims.

## Verdict

**Red.** The load-bearing reason is that Pocket-ID is not an LDAP server. Our shape requires an LDAP server (Jellyfin Apple TV / Infuse via the LDAP plugin), and Pocket-ID's LDAP feature is the wrong direction — it consumes LDAP, it does not serve it. Adopting Pocket-ID would mean keeping lldap or kanidm anyway as the actual user store, with Pocket-ID layered on top as an OIDC face. That is more moving parts than picking an IdP that does both.

The secondary reasons (no forward-auth, no branding, four CVEs in two months, no recovery codes yet) would each individually be yellow. The LDAP-server-shaped hole is the red one.

If we ever drop the Apple TV / Infuse Jellyfin requirement, this evaluation would flip from red to a strong yellow (probably green for OIDC-only homelabs). The Pocket-ID team has built a focused, honest, fast-moving product. It is just not the shape we need.

## How does it compare to Authelia and kanidm?

- **vs Authelia:** Authelia is also OIDC-only with no LDAP server, but Authelia *does* ship a forward-auth endpoint as a first-class feature, which removes the OAuth2-Proxy moving part for Navidrome and the *arr stack. Authelia is older, has more contributors, and has been through more security review cycles. Authelia is configuration-as-YAML where Pocket-ID is admin-UI; for our shape (declarative, version-controlled estate) Authelia's config-file model is closer to fit. Both fail the LDAP-server test the same way.
- **vs kanidm:** Kanidm is the only one of the three that ships an LDAP server natively, which means it can be the *only* identity component for the Jellyfin Apple TV / Infuse path. Kanidm has stronger policy depth, native replication, and an explicit anti-LLM contribution policy that aligns with the user's stated security posture. Kanidm's downsides (heavier operational model, smaller homelab community than Pocket-ID, BYO-UI is also constrained) are real but the LDAP-server fact is decisive.
- **Net:** On the three stated criteria (active maintenance, security, customizability), Pocket-ID is roughly tied with Authelia and ahead of kanidm on community/momentum, and behind kanidm on policy/protocol breadth. On capability fit for *our* app stack, Pocket-ID is third of three because of the LDAP gap.

## Sources

- https://github.com/pocket-id/pocket-id
- https://pocket-id.org/
- https://pocket-id.org/docs/introduction
- https://pocket-id.org/docs/setup/installation
- https://pocket-id.org/docs/configuration/ldap (LDAP is consume-only)
- https://pocket-id.org/docs/guides/proxy-services ("we don't have a built-in proxy provider")
- https://pocket-id.org/docs/client-examples/jellyfin (browser-only OIDC, no native app / no LDAP path)
- https://github.com/pocket-id/pocket-id/security/advisories/GHSA-w6p7-2fxx-4f44 (refresh-token revocation bypass, high, 2026-04-26)
- https://github.com/pocket-id/pocket-id/security/advisories/GHSA-hp74-gm6m-2qm5 (passkey step-up bypass, medium, 2026-04-26)
- https://github.com/pocket-id/pocket-id/security/advisories/GHSA-9h33-g3ww-mqff (redirect_uri userinfo confusion, high, 2026-03-07)
- https://github.com/pocket-id/pocket-id/security/advisories/GHSA-qh6q-598w-w6m2 (cross-client code exchange, high, 2026-03-07)
- https://github.com/pocket-id/pocket-id/issues/1380 (custom CSS feature request, open)
- https://github.com/pocket-id/pocket-id/issues/1273 (custom-claims-same-key bug, open)
- https://github.com/pocket-id/pocket-id/pull/1449 (emergency recovery codes, open)
- https://github.com/pocket-id/pocket-id/issues/728 (Crowdin AI translations debate)
- https://github.com/pocket-id/pocket-id/issues/350 (Tailscale + WebFinger, closed-implemented)
- https://github.com/pocket-id/pocket-id/discussions/980 (SQLite-to-Postgres migration)
- https://github.com/pocket-id/pocket-id/discussions/1160 (CockroachDB on Pocket-ID)
- https://o-toole.com/my-year-2025-self-hosting/ (Stephen O'Toole switching VoidAuth -> Pocket-ID)
- https://www.blackvoid.club/pocket-id-passkey-oidc-provider/ (passkey OIDC review)
- https://thesynack.com/posts/securing-with-oauth2-proxy/ (Pocket-ID + OAuth2-Proxy as forward-auth)
- https://msfjarvis.dev/posts/setting-up-forward-auth-with-caddy-and-pocket-id/ (forward-auth via caddy-security)
- https://news.ycombinator.com/item?id=44915862 (HN: OSS OIDC server of choice)
- https://lemmy.world/post/27017603 (self-hosted SSO discussion)
- https://caddy.community/t/oauth2-authentication-template-with-group-checks-using-oauth2-proxy-and-self-hosted-oidc/31611
- https://advisories.gitlab.com/pkg/golang/github.com/pocket-id/pocket-id/backend/CVE-2026-28512/
- https://advisories.gitlab.com/pkg/golang/github.com/pocket-id/pocket-id/backend/CVE-2026-28513/
- https://documentation.ubuntu.com/lxd/latest/howto/oidc_pocket_id/
- https://docs.netbird.io/selfhosted/identity-providers/pocketid

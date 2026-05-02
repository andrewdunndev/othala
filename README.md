# auth

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE) ![built with GitLab](https://img.shields.io/badge/built_with-GitLab-FC6D26?logo=gitlab)

SSO substrate for the dunn.dev estate: Authentik IDP, custom Caddy image, lab harness, Astro home portal, and the IaC/YAML for the entire auth deployment.

## Status

Substrate locked: **Authentik** with eyes-open hardening. After evaluating six alternatives (kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel) the original choice held. See `docs/decision.md` for the locked architecture and `docs/substrate-comparison.md` for the evaluation evidence.

This repo supersedes `dunn.dev/bench-sso-iac` as the single home for auth-related IaC.

## Layout

| Path | Contents |
|---|---|
| `docs/` | Decision doc, architecture, contribution strategy, substrate comparison |
| `authentik/blueprints/` | Authentik IaC: flows, groups, scopes, brand, per-app providers (the canonical blueprints — same in lab and production) |
| `caddy/` | Custom `dunn.dev/caddy-estate` image build (direct `go build` from upstream Caddy + cloudflare-dns plugin) |
| `caddy/snippets/` | Reusable Caddyfile patterns (admin-path basicauth, OIDC-app, LDAP-app, forward-auth) |
| `lab/` | GCP-based test environment for pattern validation (compose stack, Playwright suite, scripts) |
| `lab/docs/` | Per-candidate evaluations from the substrate eval (eval-*.md) and headless-API research notes |
| `portal/` | Astro home portal app: three-state page (login bounce, tile launcher, infra-down status) for Cloudflare Pages |
| `upstream/` | Maintainer-walk findings (kept for historical context from the eval) |

## Architecture

Three layers:

1. **Substrate (Authentik).** Free OSS tier; LDAP outpost (co-located in Jellyfin pod for Apple TV / Infuse SSO); proxy outpost (native forward-auth for Navidrome / Gather); blueprint-driven IaC.
2. **Reverse-proxy gate (custom Caddy).** Built directly from upstream Caddy + plugin Go modules with `go build`. Same pattern as basef builds ZFS and NVIDIA from source: pull the modules, link in one binary, no helper tool. One plugin: `caddy-dns/cloudflare` for DNS-01 ACME.
3. **Family-facing portal (Astro on Cloudflare Pages).** Single URL `home.dunn.dev`, three states: pre-auth (Sign-In button → bounce to auth.dunn.dev), post-auth (tile launcher filtered by group claims), infra-down (status panel via Cloudflare Worker polling Authentik).

Cloudflare's role: DNS hosting + DNS-01 ACME via API + hosting the Astro home portal on Pages. None of these are in the synchronous auth request path. Family auth flow has one feel (Authentik), no third-party in the loop.

## Working conventions

- All commits require explicit human approval; no force-pushes; no skipping hooks
- Bug reports to upstream Authentik are hand-written, no AI-assisted text in posted content
- Lab cost: ~$0.03/hr for the GCP VM, auto-deletes after 2hr safety net
- Production deploys via pyinfra against carmine, referencing this repo's blueprints + Caddyfile patterns

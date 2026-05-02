# auth

SSO substrate for the dunn.dev estate: kanidm as the central IDP, custom Astro home portal, custom Caddy image for forward-auth, lab harness for validating patterns, and upstream contribution drafts.

## Status

Provisional. The substrate decision (kanidm replacing Authentik) is documented in `docs/decision.md` but contingent on Phase 0 research and Phase 1 lab outcomes. Reversible at the post-lab decision gate.

## Scope

This project consolidates everything that touches family identity and access:

| Path | Contents |
|---|---|
| `docs/` | Decision doc, architecture, contribution strategy |
| `lab/` | Kanidm + app stubs on GCP, Playwright harness, validates patterns before carmine cutover |
| `portal/` | Astro home portal app — three-state page (login, tile launcher, status) for Cloudflare Pages |
| `caddy/` | Custom Caddy image build (direct `go build` from upstream modules) — DNS-01 + forward-auth plugins, the universal sidecar substrate |
| `kanidm/` | Production kanidm config scripts (CLI-driven, idempotent) |
| `upstream/` | Drafts of upstream kanidm contributions (forward-auth endpoint, headless flow API) |

## What this is not

- **Not a kanidm fork.** Upstream contributions go to the kanidm project. This repo holds drafts and patterns.
- **Not a deployment tool.** Carmine's pyinfra deploys the kanidm pod. This repo holds the configuration that pyinfra references.
- **Not the bench-sso-iac repo.** That repo was the Authentik-era test harness; the lab work moves here under `lab/`.

## Architecture

Three layers:

1. **Substrate (kanidm).** Memory-safe Rust IDP, single binary, opinionated-secure defaults, built-in LDAPS + OIDC, passkeys as primary auth.
2. **Forward-auth gate (custom Caddy).** Same xcaddy image already used for cloudflare DNS-01 plugin, extended with a forward-auth plugin so any "no native SSO" app gets gated identically.
3. **Family-facing portal (Astro on Cloudflare Pages).** Single URL `home.dunn.dev`, three states by reachability of kanidm: pre-auth (login), post-auth (tile launcher filtered by group claims), infra-down (status panel).

## Working conventions

- All commits require explicit human approval; no force-pushes; no skipping hooks.
- Upstream contributions: DCO sign-off, no AI-Assisted trailers, no LLM-verbatim text, draft to file before posting.

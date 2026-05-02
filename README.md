# auth

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE) ![built with GitLab](https://img.shields.io/badge/built_with-GitLab-FC6D26?logo=gitlab)

SSO substrate for the dunn.dev estate: central IDP, custom Astro home portal, custom Caddy image for forward-auth, lab harness for validating patterns, and (where applicable) upstream contribution drafts.

## Status

Substrate evaluation in progress. Authentik was originally chosen, kanidm was the second narrowing, and a wider eval (Authelia, Hanko, voidauth, Zitadel, kanidm) is now landing. See `docs/decision.md` for the current state of analysis. Lab artifacts are deferred until the substrate is locked.

## Scope

This project consolidates everything that touches family identity and access:

| Path | Contents |
|---|---|
| `docs/` | Decision doc, architecture, contribution strategy |
| `lab/` | IDP + app stubs on GCP, Playwright harness, validates patterns before carmine cutover |
| `portal/` | Astro home portal app: three-state page (login, tile launcher, status) for Cloudflare Pages |
| `caddy/` | Custom Caddy image build (direct `go build` from upstream modules): DNS-01 + forward-auth plugins, the universal sidecar substrate |
| `kanidm/` | Substrate-specific config scripts (populated once a substrate is locked) |
| `upstream/` | Maintainer-walk findings and any contribution drafts |

## What this is not

- **Not a deployment tool.** Carmine's pyinfra deploys the IDP pod. This repo holds the configuration that pyinfra references.
- **Not the bench-sso-iac repo.** That repo was the Authentik-era test harness; the lab work moves here under `lab/`.

## Architecture

Three layers:

1. **Substrate (TBD).** Currently leaning kanidm; the wider eval may shift this. See `docs/decision.md`.
2. **Forward-auth gate (custom Caddy).** Built directly from upstream Caddy + plugin Go modules with `go build`. Same pattern as basef builds ZFS and NVIDIA from source: pull the modules, link in one binary, no helper tool.
3. **Family-facing portal (Astro on Cloudflare Pages).** Single URL `home.dunn.dev`, three states by IDP reachability: pre-auth (login), post-auth (tile launcher filtered by group claims), infra-down (status panel).

## Working conventions

- All commits require explicit human approval; no force-pushes; no skipping hooks.
- Upstream contributions: DCO sign-off, no AI-Assisted trailers, no LLM-verbatim text, draft to file before posting.

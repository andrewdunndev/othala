# AGENTS.md

The working contract for whoever maintains this repo, human or model. Read it
first. `ARCHITECTURE.md` describes what is built; `DECISIONS.md` is the
do-not-reverse list; this, how to work on it.

**When this file and the code disagree, the code is right, and fixing this file
is part of the change that made it wrong.**

## The two rules

**1. The audience test.** Every file, section and sentence must serve a stranger
adopting Ory patterns. Anything that serves only one deployment does not
appear: no instance hostnames, no personal names, no private-stack applications
(`scripts/check-purity.sh` checks the whole index). The `e2e/` fixtures are the
only example apps, so docs and tests agree by construction. A rule with no named
enforcer is held by review.

**2. Docs state WHY; code states WHAT.** Never restate code behaviour in prose:
it rots. Point at the test that enforces it. Cite a file plus a symbol, never a
line number. Delete a wrong sentence before considering a replacement; a
pointer to the enforcing file does not go stale. Direct phrasing, no filler.
Nothing not running is written as though it were. No abstraction, extension
point or configuration surface for unknown adopters.

## The byte-vendored files

- `kratos/kratos.yml`
- `hydra/hydra.yml`
- `kratos/identity.schema.json`
- `kratos/hooks/recovery-gate.jsonnet`
- `kratos/courier/*.gotmpl`

Downstream deployments run `check-ory` against these byte for byte, so any
edit, comments included, ships to them.

## The gates

**`scripts/check-purity.sh`** scans the git index, not the worktree, so the
corpus is the same locally and in CI. Each check is a row in a data table with
an embedded canary; a check that scans nothing or whose pattern misses its
canary is an error, never a pass.

`check-purity` runs on every pipeline; `check-portal` and e2e run on every MR, on tags
and on web/api runs. `e2e-upgrade` runs on tags, web/api runs and MRs that touch
`deploy/`, `kratos/`, `hydra/`, `DEPLOY.md` or the upgrade harness. A push to main runs `check-purity` and the catalog's component jobs, and none of the heavy chain.

## Conventions that hold the design together

- **Manifests are the API for apps.** Apps are read at request time from
  `/etc/othala/apps`. Adding one is a file, never an app-specific code path
  or an image rebuild.
- **Env belongs in one module** (`portal/src/lib/config.ts`): throw in
  production, default with a warning in dev. The surface is identity
  (`OTHALA_PUBLIC_URL`, `OTHALA_APEX`, `OTHALA_INSTANCE_NAME`),
  `OTHALA_CONTACT_RECIPIENT`, secrets, optional `OTHALA_OTLP_ENDPOINT`, and the
  deployer binds (`KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST`,
  `PORTAL_ADMIN_BIND_HOST`); everything else is derived or a constant there.
  Only `listen.ts`, `config-cli.ts` and `otel.mjs` read env themselves.
- **Ory configs are templates.** Ory has no native `${VAR}` expansion;
  `portal/src/lib/render.ts` is the one render, shipped in the image as
  `dist/server/config.mjs`, failing with variable NAMES, never rendered content
  (`portal/scripts/render.test.mjs`).
- **Reach for the upstream extension point first**: native Kratos and Hydra
  config fields, the generated `@ory/client-fetch` SDK. Deviate only where
  upstream is broken here, and say why at the deviation site.
- **Robust where it protects an account, simple everywhere else.** Robust: the
  gates, aal2 and freshness on admin and the device grant, admin recovery
  console-only, HIBP fail-closed, consent revocation. Simple: no knob whose
  default can contradict the shipped config, no key restating an upstream
  default, no second layer duplicating a control, limits sized for a household.
  Acceptance is the household journey through the UI on a fresh stack
  (`e2e/playwright/tests/zi-household-journey.spec.ts`).

## Commands

Tools come from `mise.toml` (`mise install`); every recipe is in the `justfile`.

```sh
just setup    # once: npm ci in portal, e2e and site
just test     # vitest: portal/src/**/*.test.ts + portal/scripts/*.test.mjs
just check    # the CI check-portal sequence: astro check, tsc over e2e and site, vitest, manifest lint, YAML parse
just build    # production bundle
just dev      # UI iteration without the full stack; dev-only CONTENT_DIR and OTHALA_DEV_MOCK_GROUPS (.env.example)
just purity   # the purity gate, then bash -n over tracked shell scripts
just e2e      # build both images from the working tree, then run deploy/example under the e2e overlay
just backup   # custom-format pg_dump of the kratos and hydra databases from a running stack
```

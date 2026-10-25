# AGENTS.md

The working contract for whoever maintains this repo, human or model. Read it
first. `ARCHITECTURE.md` describes what is built; this, how to work on it.

**When this file and the code disagree, the code is right, and fixing this file
is part of the change that made it wrong.**

## The two rules

**1. The audience test.** Every file, section and sentence must serve a stranger
adopting Ory patterns. Anything that serves only this deployment does not
appear: no instance hostnames, no personal names, no private-stack applications
(whole-index checks in `scripts/check-purity.sh`; the private-name patterns
live in the file named by `PURITY_PRIVATE_NAMES`, outside the tree). The `e2e/`
fixtures are the only example apps, so docs and tests agree by construction. Judging the rest is a habit.

**2. Docs state WHY; code states WHAT.** Never restate code behaviour in prose:
it rots. Where behaviour must be referenced, point at the TEST that enforces it.
A rule with no named enforcer is a habit and must be labelled one, starting with
this rule, which nothing but review enforces.

## Citations

Reference a **file plus a symbol**: a function, constant, directive or heading.
Never a line number.

`scripts/check-purity.sh` enforces the line-pin half for the vendored files
(`no-line-pins-into-vendored-files`). The rest is a habit.

Worked example: the canonical group-name policy is `GROUP_RE` in
`portal/src/lib/access-groups.ts`. Name it and stop.

## Correcting documentation: delete, do not rewrite (a habit)

Delete the wrong sentence before considering a replacement: a fresher value
goes stale on the same schedule, a pointer to the enforcing file does not.
Nothing enforces this.

## The byte-vendored files

- `kratos/kratos.yml`
- `hydra/hydra.yml`
- `kratos/identity.schema.json`
- `kratos/hooks/recovery-gate.jsonnet`
- `kratos/courier/*.gotmpl`

These are vendored verbatim into a separate deployment repository, which fails
its own drift check on any divergence. Editing one here starts a re-vendor costing a release tag and an operator
review. Comments count, because they ship to production.

## The gates

One local script. CI runs the same checks and more.

**`scripts/check-purity.sh`** runs its checks over the git **index**, not the
worktree, so the corpus is identical locally and in CI. Every check is a row in
a data table (pattern branches, canaries, pathspec); `scan()` plus the loop over
it is the whole runner. Some rows take the whole index as their corpus
(instance names, personal names, private-stack application names, vendored
line-pins) because a pathspec-scoped check cannot catch what is outside its glob.

Each row proves itself against its own embedded canary (`selftest()`) on every
run, so there is no separate probe script to keep in sync. A check that scanned
zero files, weighed zero bytes, whose pattern no longer fires on its canary, or
whose `grep` hit an I/O error is an ERROR, never a pass.

`check-purity` runs on every push, MR and tag; `check-portal` runs on tags and on MRs
that change the heavy paths. `shellcheck` is not in their image and nothing here curl-installs a linter.

## Conventions that hold the design together

- **Manifests are the API for apps.** Apps are read at request time from
  `/etc/othala/apps`. Adding one is a file, never an app-specific code path
  or an image rebuild. The loaders and the gate are generic.
- **Entry is never derived.** Membership in a group the app's own manifest binds
  is what admits a person, admins included (`enforceAccessGate`,
  `portal/src/lib/gate.ts`). Do not reintroduce inference from a name, a slug, a
  role mapping, or the admin marker.
- **A group's type comes from its binding, never its name**
  (`portal/src/lib/group-registry.ts`). Do not "fix" a manifest to satisfy a
  naming rule; there is none. `portal/src/lib/manifest-lint.ts` WARNs on a name
  no binding knows (the typo-to-silent-lockout case) and never blocks on style.
- **Fail closed.** The access gate, the audience and redirect check and the
  manifest validator deny on anything ambiguous; the loader quarantines an invalid
  manifest (its app is refused, the rest serve) and `portal/src/lib/manifest-store.ts`
  serves the last known good set or the empty set when the directory cannot load.
- **Env belongs in one module** (`portal/src/lib/config.ts`): throw in
  production, default with a warning in dev. The surface is identity
  (`OTHALA_PUBLIC_URL`, `OTHALA_APEX`, `OTHALA_INSTANCE_NAME`),
  `OTHALA_CONTACT_RECIPIENT`, secrets, optional `OTHALA_OTLP_ENDPOINT`, and the deployer binds
  (`KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST`, `PORTAL_ADMIN_BIND_HOST`);
  everything else is derived or a constant there. A habit, not a gate; only the
  `listen.ts` (startup checks run before config.ts loads), `config-cli.ts` (the Ory render) and `otel.mjs` read env themselves.
- **The admin listener binds the internal-network address** (`PORTAL_ADMIN_BIND_HOST`), never the public mux, and its
  mux is disjoint from the public one (`portal/src/server/listen.ts`). Never move a privileged route onto the public mux.
- **Ory configs are templates.** Ory has no native `${VAR}` expansion;
  `portal/src/lib/render.ts` is the one render, shipped in the image as
  `dist/server/config.mjs`, failing with variable NAMES, never rendered content
  (`portal/scripts/render.test.mjs`).
- **Reach for the upstream extension point first**: native Kratos and Hydra
  config fields, the generated `@ory/client-fetch` SDK. Deviate only where
  upstream is broken here, and say why at the deviation site. A habit.
- **Robust where it protects a family account, simple everywhere else.** Robust:
  the gates, aal2 and freshness on admin and the device grant, admin recovery console-only, HIBP
  fail-closed, consent revocation. Simple: no knob whose default can contradict
  the shipped config, no key restating an upstream default, no second layer
  duplicating a control, limits sized for a household. Acceptance is the
  household journey through the UI on a fresh stack
  (`e2e/playwright/tests/zi-household-journey.spec.ts`).

## Commands

```sh
cd portal && npm test           # vitest: src/**/*.test.ts + scripts/*.test.mjs, incl. the fuzz suites
cd portal && npm run check      # type + content check
cd portal && npm run dev        # UI iteration without the full stack; dev-only CONTENT_DIR and OTHALA_DEV_MOCK_GROUPS (.env.example)
cd e2e && bash validate.sh      # deploy/example under the e2e overlay
bash scripts/check-purity.sh    # the purity gate
```

## Writing (habits — nothing enforces these)

Direct phrasing, no filler, no hedging, no trailing summaries. Anything intended
or shelved says so in its own sentence; nothing not running is written as though it were.

Corrections are wanted. Generalization is not: no abstraction, extension points
or configuration surface for unknown adopters.

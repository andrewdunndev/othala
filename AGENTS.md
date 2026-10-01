# AGENTS.md

The working contract for whoever maintains this repo, human or model. Read it
first. `ARCHITECTURE.md` describes what is built; this, how to work on it.

**When this file and the code disagree, the code is right, and fixing this file
is part of the change that made it wrong.** A confidently wrong sentence here is
this project's most expensive bug: it is read first, with no other context.

## The two rules

**1. The audience test.** Every file, section and sentence must serve a stranger
adopting Ory patterns. Anything that serves only this deployment does not
appear: no instance hostnames, no personal names, no private-stack applications
(three whole-index checks in `scripts/check-purity.sh`). `grafana` and
`audiobookshelf` are the only example apps, being the `e2e/` fixtures, so docs
and tests agree by construction. Judging what else serves a stranger is a habit.

**2. Docs state WHY; code states WHAT.** Never restate code behaviour in prose:
it rots. Where behaviour must be referenced, point at the TEST that enforces it.
A rule with no named enforcer is a habit and must be labelled one, starting with
this rule, which nothing but review enforces.

## Citations

Reference a **file plus a symbol**: a function, constant, directive or heading.
Never a line number or an ADR number: `docs/adr/` and `docs/access-model.md` no
longer exist, so references to them dangle.

`scripts/check-purity.sh` enforces the line-pin half for the vendored files
(`no-line-pins-into-vendored-files`). The rest is a habit.

Worked example: the canonical group-name policy is `GROUP_RE` in
`portal/src/lib/access-groups.ts`. Name it and stop.

## The prose budget

Tracked prose is capped, and the cap is enforced. **Adding documentation means
removing documentation, in the same commit.** Growing the corpus back toward the
ceiling is the failure mode, not the fix. If you cannot name what a new page
displaces, do not write it.

The `prose-budget` check in `scripts/check-purity.sh` fails the build when the
total exceeds `PROSE_CEILING_BYTES`, and prints the total, the ceiling and the
headroom on every run. Raising the ceiling is deliberately awkward: an edit to
that constant, in a commit whose message says what grew and why it earned the
room.

## Correcting documentation: delete, do not rewrite (a habit)

When a document is wrong, delete the wrong sentence before considering a
replacement: a fresher value goes stale on the same schedule, a pointer to the
enforcing file does not. Nothing enforces this.

## The four byte-vendored files

- `kratos/kratos.yml`
- `hydra/hydra.yml`
- `kratos/identity.schema.json`
- `kratos/hooks/recovery-gate.jsonnet`

These are vendored verbatim into a separate deployment repository, which fails
its own drift check on any divergence. Editing one here starts a re-vendor
costing a release tag and an operator review: a deliberate act with a downstream
cost. Comments count, because a comment inside these files ships to production.
`e2e/compose.yml` mounts them from `kratos/`.

## The gates

Two local scripts. CI runs the same checks and more.

**`scripts/check-purity.sh`** runs its checks over the git **index**, not the
worktree, so the corpus is identical locally and in CI. Every check is a row in
a data table (pattern branches, canaries, pathspec); `scan()` plus the loop over
it is the whole runner. Four rows take the whole index as their corpus
(instance names, personal names, private-stack application names, vendored
line-pins) because a pathspec-scoped check cannot catch what is outside its glob.

Each row proves itself against its own embedded canary (`selftest()`) on every
run, so there is no separate probe script to keep in sync. A check that scanned
zero files, weighed zero bytes, whose pattern no longer fires on its canary, or
whose `grep` hit an I/O error is an ERROR, never a pass.

The `check-portal` and `check-purity` jobs run on every push, MR and tag;
`shellcheck` is not in their image and nothing here curl-installs a linter.

## Conventions that hold the design together

- **Manifests are the API for apps.** Apps are read at request time from
  `/etc/portal/manifests`. Adding one is a file, never an app-specific code path
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
  manifest validator deny on anything ambiguous; `portal/src/lib/manifest-store.ts`
  serves the last known good set or the empty set, never a partial one.
- **Env belongs in one module** (`portal/src/lib/config.ts`): throw in
  production, default with a warning in dev. The surface is identity
  (`OTHALA_PUBLIC_URL`, `OTHALA_APEX`, `OTHALA_INSTANCE_NAME`),
  `OTHALA_CONTACT_RECIPIENT`, secrets, optional `OTHALA_OTLP_ENDPOINT`, and the deployer binds
  (`KRATOS_ADMIN_BIND_HOST`, `HYDRA_ADMIN_BIND_HOST`, `ADMIN_HOST`);
  everything else is derived or a constant there. A habit, not a gate; only the
  plain-ESM `listen.mjs` and `otel.mjs` read env themselves.
- **The admin listener is loopback-only** and its mux is disjoint from the public
  one (`portal/src/server/listen.mjs`). Never move a privileged route onto the
  public mux.
- **Ory configs are templates.** Ory has no native `${VAR}` expansion;
  `scripts/render-config.sh` is the one render, failing with missing variable
  NAMES, never rendered content.
- **Reach for the upstream extension point first**: native Kratos and Hydra
  config fields, the generated `@ory/client-fetch` SDK. Deviate only where
  upstream is broken here, and say why at the deviation site. A habit.
- **Robust where it protects a family account, simple everywhere else.** Robust:
  the gates, aal2 and freshness on admin, admin recovery console-only, HIBP
  fail-closed, consent revocation. Simple: no knob whose default can contradict
  the shipped config, no key restating an upstream default, no second layer
  duplicating a control, limits sized for a household. Acceptance is the
  household journey through the UI on a fresh stack
  (`e2e/playwright/tests/zi-household-journey.spec.ts`).

## Commands

```sh
cd portal && npm test           # vitest: src/**/*.test.ts + scripts/*.test.mjs, incl. the fuzz suites
cd portal && npm run check      # type + content check
cd portal && npm run dev        # UI iteration without the full stack
cd e2e && ./gen-secrets.sh && bash validate.sh   # full compose stand-up
bash scripts/check-purity.sh    # the purity gate
```

## Writing (habits — nothing enforces these)

Direct phrasing, no filler. State uncertainty plainly, no hedging. No trailing
summary paragraphs. Anything intended, shelved or parked says so in its own
sentence; nothing that is not running is written as though it were.

Corrections are wanted. Generalization requests are not: no abstraction,
extension points or configuration surface for adopters we have never met. That a
stranger cannot drop this in unchanged is the design working, never a defect.

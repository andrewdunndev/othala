# AGENTS.md

The working contract for whoever maintains this repo, human or model. Read it
first. `ARCHITECTURE.md` describes what is built; this describes how to work on
it without breaking it.

**When this file and the code disagree, the code is right, and fixing this file
is part of the change that made it wrong.** A confidently wrong sentence here is
this project's most expensive bug: it is read first, by a co-maintainer with no
other context.

## The two rules

**1. The audience test.** Every file, section and sentence must serve a stranger
adopting Ory patterns. Anything that serves only this deployment does not
appear: no instance hostnames, no personal names, no private-stack applications
— the three whole-index checks in `scripts/check-purity.sh`. `grafana` and
`audiobookshelf` are the only example apps, because they are the `e2e/`
fixtures, so the docs and the tests agree by construction. Judging what else
serves a stranger is a habit: nothing checks it.

**2. Docs state WHY; code states WHAT.** Never restate code behaviour in prose:
it rots on the next code change, and it produced five consecutive review rounds
finding 3, 7, 8, 9 and 7 defects. Where behaviour must be referenced, point at
the TEST that enforces it. A rule with no named enforcer is a habit, and must be
labelled one — starting with this rule, which nothing but review enforces.

## Citations

Reference a **file plus a symbol**: a function, constant, directive or heading.
Never a line number, and never an ADR number. The deleted ADR corpus accumulated
243 citations of which roughly 31% of the line pins were already wrong before
anyone noticed. `docs/adr/` and `docs/access-model.md` no longer exist, so every
reference to them dangles.

`scripts/check-purity.sh` enforces the line-pin half of this for the vendored
files (`no-line-pins-into-vendored-files`). The rest is a habit, and on you.

The worked example, and the reason this file exists in this shape: the canonical
group-name policy is `GROUP_RE` in `portal/src/lib/access-groups.ts`. Name it and
stop. A previous version of this file spelled the regex out as a literal; the
code changed, the literal did not, and the rule it stated was false for as long
as anyone believed it.

## The prose budget

Tracked prose is capped, and the cap is enforced. **Adding documentation means
removing documentation, in the same commit.** The corpus was cut by half because
it had grown past what one maintainer and a model can hold in context; growing
it back is the failure mode, not the fix. If you cannot name what a new page
displaces, do not write it.

The `prose-budget` check in `scripts/check-purity.sh` fails the build when the
total exceeds `PROSE_CEILING_BYTES`, and prints the current total, the ceiling
and the remaining headroom on every run, passing or failing. Raising the ceiling
is allowed and deliberately awkward: it is an edit to that constant, in a commit
whose message says what grew and why it earned the room.

## Correcting documentation: delete, do not rewrite (a habit)

When a document is wrong, delete the wrong sentence before considering a
replacement: a fresher value goes stale on the same schedule as the one it
replaced, and a pointer to the enforcing file does not. Nothing enforces this.

## The four byte-vendored files

- `kratos/kratos.yml`
- `hydra/hydra.yml`
- `kratos/identity.schema.json`
- `kratos/hooks/recovery-gate.jsonnet`

These are vendored verbatim into a separate deployment repository, which fails
its own drift check on any divergence. Editing one here is not a local change: it
starts a re-vendor costing a release tag and an operator review, so it is a
deliberate act with a downstream cost. Comments count, because a comment inside
these files ships to production. `e2e/` carries working copies of the schema and
the hook; `scripts/pre-tag-check.sh` fails if either drifts.

## The gates

Two local scripts. CI runs the same checks and more.

**`scripts/check-purity.sh`** runs its checks over the git **index**, not the
worktree, so the corpus is identical locally and in CI. Each check names and
explains itself at its call site; that is the list, and it is not repeated here.
Three of them take the whole index as their corpus — instance names, personal
names, private-stack application names — because the earlier narrow pathspecs
reported all-clear over an instance name in `.gitlab-ci.yml` and application
names in `DEPLOY.md`, a runbook and two published diagrams.

Its anti-vacuity contract at the top of the file is the point of it: a check that
scanned zero files, weighed zero bytes, whose pattern no longer fires on its own
canary, or whose `grep` exited with an I/O error is an ERROR, never a pass.
`scripts/probe-check-purity.sh` mutation-tests the gate — one probe per pattern
branch, each planted in a real file — and CI runs both in one job so neither can
hide a rotted other.

**`scripts/pre-tag-check.sh`** runs 11 steps before a tag: portal `npm test`,
`npm run test:unit`, `npm run check` and `npm run build`; the docs-site build;
`bash -n` plus shellcheck over `e2e/*.sh`; a YAML parse of the tracked plain-YAML
set; the purity gate; and the two vendored-copy drift comparisons. It does NOT
run the container builds, the SBOM and release stages, or the `e2e/` harness,
which need a registry and the QEMU runner. Every step decides from a RESULT, not
an exit status: a suite reporting zero tests, and a YAML file parsing to an empty
document, are both errors. Both scripts also assert their own size
(`EXPECTED_CHECKS`, `EXPECTED_STEPS`): adding or removing a check means bumping
the constant in the same commit, or the gate errors instead of quietly shrinking.

## Conventions that hold the design together

- **Manifests are the API for apps.** Apps are read at request time from
  `MANIFEST_DIR`. Adding one is a file, never an app-specific code path in the
  portal and never an image rebuild. The loaders and the gate are generic.
- **Entry is never derived.** Membership in a group the app's own manifest binds
  is what admits a person, admins included (`enforceAccessGate`,
  `portal/src/lib/gate.ts`). Do not reintroduce inference from a name, a slug, a
  role mapping, or the admin marker.
- **A group's type comes from its binding, never its name**
  (`portal/src/lib/group-registry.ts`). No prefix, suffix or slug match is
  required. Do not "fix" a manifest to satisfy a naming rule; there is not one.
  `portal/src/lib/manifest-lint.ts` WARNs on a name no binding knows, which is
  the typo-to-silent-lockout case, and never blocks on style.
- **Fail closed.** The access gate, the audience and redirect check, and the
  manifest validator all deny on anything ambiguous, and
  `portal/src/lib/manifest-store.ts` serves the last known good set or the empty
  set rather than a partially validated one. Preserve that.
- **Env belongs in one module** (`portal/src/lib/config.ts`): throw in
  production, safe default with a warning in dev. A habit, not a gate, and not
  held everywhere today.
- **The admin listener is loopback-only** and its mux is disjoint from the public
  one (`portal/src/server/listen.mjs`). Never move a privileged route onto the
  public mux.
- **Ory configs are templates.** Ory has no native `${VAR}` expansion;
  `scripts/render-config.sh` is the single canonical render, failing fast with
  missing variable NAMES and never rendered content.
- **Reach for the upstream extension point first**: native Kratos and Hydra
  config fields, the generated `@ory/client-fetch` SDK. Deviate only where
  upstream is genuinely broken here, and say why at the deviation site. A
  habit; no gate can tell a justified deviation from a lazy one.

## Commands

```sh
cd portal && npm test           # scripts/*.test.mjs, incl. the fuzz suites
cd portal && npm run test:unit  # src/lib/*.test.ts; BOTH suites are required
cd portal && npm run check      # type + content check
cd portal && npm run dev        # UI iteration without the full stack
cd e2e && ./gen-secrets.sh && bash validate.sh   # full compose stand-up
bash scripts/pre-tag-check.sh   # everything above plus the gates, before a tag
```

## Writing (habits — nothing enforces these)

Direct phrasing, no filler. State uncertainty plainly rather than hedging. No
trailing summary paragraphs. Anything intended, shelved or parked says so in the
sentence that describes it; nothing that is not running is written as though it
were.

Corrections are wanted. Generalization requests are not: do not add abstraction,
extension points or configuration surface for adopters we have never met. That a
stranger cannot drop this in unchanged is the design working, never a defect.

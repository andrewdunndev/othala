# 13 — Vendored-config contract: othala is canonical, the deploy plane byte-enforces

## Status

Accepted (2026-08-15). Four files in this repo are byte-canonical for production
config; the deploy plane vendors verbatim copies and enforces the match. The
contract has been enforced in code since the deploy plane started vendoring, but
was written down only in the deploy repo — so from inside this repo it was
invisible, and an edit was made and discarded on that basis in the week this
record was added.

See also [11](11-hardening-tuning.md) (a stale comment inside one of the four
files, whose correction is deferred *because* of this contract) and
[15](15-forward-auth-gate-aal1.md) (the setting that was nearly deleted from one
of the four on othala-local reasoning alone — the canonical case for
Consequence (a)).

## Context

Othala is developed here and deployed from a different repo:
`gitlab.com/dunn.dev/iac`, which owns the host, the quadlets, the secrets, the
service catalog and the deploy runbooks. There is no submodule, no subtree and
no symlink between the two — see `ARCHITECTURE.md` (LB-12) and `DEPLOY.md` for
the promotion path.

That separation raises a question these four files answer differently from
everything else in this repo: **which bytes actually run?**

For the portal, the answer is "whatever is in the published image", so this repo
is trivially the source. For Kratos and Hydra it is not. Their config is not
built into any image — it is read from a host path mounted read-only into the
container:

```
Volume=/var/srv/dag/kratos/kratos.rendered.yml:/etc/config/kratos/kratos.yml:ro,Z
Volume=/var/srv/dag/kratos/identity.schema.json:/etc/config/kratos/identity.schema.json:ro,Z
Volume=/var/srv/dag/kratos/hooks/recovery-gate.jsonnet:/etc/config/kratos/hooks/recovery-gate.jsonnet:ro,Z
Volume=/var/srv/dag/hydra/hydra.rendered.yml:/etc/config/hydra/hydra.yml:ro,Z
```

(`iac deploy/hosts/lodestone/services/dag/.config/containers/systemd/dag-kratos.container:45-47`
and `dag-hydra.container:42`.) The `*.rendered.yml` files are produced at deploy
time by the deploy plane's renderer, which substitutes `${VAR}` placeholders; the
pre-render source is the vendored copy. So the running configuration is a
derivative of the deploy repo's copy, and an edit made only here changes nothing
on the host until it is re-vendored.

Without a stated contract, the two obvious failure modes are both live hazards: a
maintainer edits the vendored copy directly (correct on the host, silently
divergent from the readable source), or a maintainer edits here and assumes it
shipped (readable source correct, host unchanged).

## Decision

**These four files are canonical here:**

- `kratos/kratos.yml`
- `hydra/hydra.yml`
- `kratos/identity.schema.json`
- `kratos/hooks/recovery-gate.jsonnet`

The deploy plane vendors each one verbatim under
`iac deploy/hosts/lodestone/services/dag/`, beneath a short provenance header
naming the othala ref it was taken from, and byte-enforces the match.

**Enforcer:** `iac deploy/checks/check_vendored_drift.sh`. These four are its
`STRICT_IAC` / `STRICT_OTHALA` pair list. It strips the provenance header and
requires byte equality of everything below it; **zero content deviations are
permitted**, so deploy-side commentary goes in that repo's service README rather
than into the file. It runs in CI as the `dag-vendored-drift` job
(`iac .gitlab-ci.yml`), which parses the ref out of the vendored `kratos.yml`
provenance header, asserts the ref is reachable on origin, clones othala at it,
and fails the pipeline on drift.

**The edit direction is one-way: corrections land here first and are then
re-vendored.** *UNENFORCED — convention only* on its own terms: the gate compares
bytes and cannot see which side was typed into. What the gate does enforce is
that a deploy-side edit cannot stand alone — it reddens `dag-vendored-drift`
until the othala side matches at the pinned ref. An othala-side edit to one of
these four **is not done until it is re-vendored**, because the running host has
not changed.

Nothing about *deployment* primacy changes here. The deploy repo remains the
primary deployment view — it owns the host, holds the pin, and decides when to
consume a new release. This record is about authorship of the bytes, which is a
separate question.

## Consequences

- **(a) Every line in these four files is live production documentation.** A
  setting or a comment may not be removed on the strength of othala-local
  reasoning alone — *UNENFORCED — convention only*, because a deletion made on
  both sides is byte-consistent and the drift gate has nothing to say about it.
  `session.whoami.required_aal: aal1`
  (`kratos/kratos.yml:264-272`) is the canonical case: it looked like dead config
  attached to a shelved feature, and deleting it would have locked every
  MFA-enrolled user out of every forward_auth-fronted app at once. See
  [15](15-forward-auth-gate-aal1.md). Before deleting anything here, find the
  consumer.

- **(b) ADR numbers are mechanically permanent, and this is why.** These files
  cite ADRs in comments — currently [05](05-passkey-first-auth.md),
  [08](08-admin-authority-model.md), [11](11-hardening-tuning.md) and
  [12](12-oidc-client-topology.md). Retiring or renumbering any cited record is
  therefore a **vendored-config edit**, which forces a re-vendor into the deploy
  repo. Independently, this repo's own gate — `scripts/check-purity.sh:150-166`,
  step `adr-pointers-resolve` — greps the whole tree for `ADR NN` and
  `docs/adr/NN-` pointers and hard-fails if a cited number has no matching file.
  Between the two, "numbers are stable identifiers, never an ordering" is a
  mechanical constraint, not a README convention.

- **(c) A rationale comment inside `kratos.yml` or `hydra.yml` cites an ADR,
  never the instance FQDN.** `scripts/check-purity.sh` step
  `no-dunn-dev-in-configs` greps exactly those two files for the instance domain
  and fails the build on a hit. Point at the record; the record may name the
  instance freely.

- **(d) HONEST GAP — the pin is a moving ref.** `ARCHITECTURE.md` (LB-12) and
  `DEPLOY.md` both describe the contract as a *released tag*, and the CI job's
  own error text tells the operator to update the header to a published tag. The
  vendored provenance headers currently name `main`. The job parses that ref and
  clones it, so today the gate compares against othala's `main` HEAD rather than
  a fixed release: a merge here can redden the deploy pipeline with no iac change,
  and the header alone does not pin what is deployed. Re-litigation trigger: the
  next othala release tag — bump the headers to it.

- **(e) HONEST GAP — the header names the wrong path for its own gate.** The
  provenance headers point at `pyinfra/checks/check_vendored_drift.sh`; there is
  no `pyinfra/` directory in the deploy repo. The script is at
  `deploy/checks/check_vendored_drift.sh`. Follow the path in this record.

- **(f) `identity.schema.json` carries no provenance header**, because JSON has
  no comment syntax. It is compared whole (header-stripping is a no-op on it) and
  records no ref of its own; the CI job takes the ref from `kratos.yml` and
  applies it to all four. Do not "fix" the schema by adding a header — that is
  content, and the gate would reject it as drift.

- **(g) Renaming or moving any of the four is a cross-repo change.** The gate
  refuses to pass on partial coverage: under `OTHALA_REQUIRED=1` (how CI runs it),
  a STRICT file missing on either side is an error, not a skip. An othala-side
  reorg fails the deploy gate until the pair list is updated.

- **(h) The deploy plane's sync helper covers more than the gate enforces.**
  `iac deploy/hosts/lodestone/services/dag/sync-configs.sh` also diffs
  `e2e/postgres-init.sh` against the deploy copy of the Postgres init script.
  That pair is **not** in the STRICT list, so it is synced by hand and unguarded.
  Treat a change to it as unverified until diffed deliberately.

- **(i) A correction here has a deploy cost, and that cost is a legitimate reason
  to defer.** Fixing a stale comment in one of these four is an othala commit
  *plus* an iac re-vendor. [11](11-hardening-tuning.md) records exactly such a
  deferral rather than pretending the comment is right.

**Depends on:** `iac deploy/checks/check_vendored_drift.sh` (STRICT pair list),
the `dag-vendored-drift` job in `iac .gitlab-ci.yml`, and
`scripts/check-purity.sh:150-166` in this repo.

## Alternatives considered

- **Submodule or subtree instead of vendored copies.** Rejected when the deploy
  plane was built (`ARCHITECTURE.md` LB-12): the contract wanted is a released
  artifact, not a live pointer. A submodule also makes a deploy-time bump look
  like an upstream change in the deploy repo's history, which is the opposite of
  what the operator needs to read there.

- **Generate the configs in the deploy plane from a template here.** Rejected:
  the files would stop being readable as *the thing that runs*. The rationale
  comments and ADR pointers inside them are the main way anyone — human or LLM —
  learns why a setting exists, and a generator inserts a translation step exactly
  where confident misreadings are most expensive.

- **Permit documented deviations on these four.** The gate already supports the
  shape: alongside the STRICT list it carries `WARN` pairs, which are diffed and
  reported but do not fail the build. The WARN arrays are empty today; the
  comment beside them records that the LDAP bridge's `glauth.cfg` pair belongs
  there and would be restored there if `kratos-ldap` were ever revived. Rejected
  as the default posture: every permitted deviation is a place where the deployed
  bytes and the readable source disagree, and the disagreement has to be
  re-derived by hand at every bump.

- **Document the contract only in the deploy repo.** That is where it lived, and
  it is precisely why the contract was invisible from here. The person about to
  edit these four files is reading *this* repo.

- **Let CI here refuse edits to the four files without a re-vendor note.**
  Rejected as ceremony a single maintainer will not pay: this repo cannot see the
  deploy repo's state, so any such gate would be a nag rather than a check. The
  real check exists on the side that can actually observe both trees.

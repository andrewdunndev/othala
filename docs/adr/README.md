# Architecture Decision Records

This directory is the canonical home of the decisions that shaped Othala. Each
record explains a choice that is not obvious from the code alone: what was
decided, why the alternatives were real options, and what consequences follow.

## The contract these records are held to

**They describe `dag.dunn.dev` as deployed.** A sentence that is no longer true
of the running system is a defect in this corpus, even if it was true the day it
was written. That is the single standard everything else here serves.

**They name real things.** Records cite the deploy repo (`gitlab.com/dunn.dev/iac`),
its paths, its commits and its gates whenever those carry the evidence, and they
cite this repo's files by path. Nothing is genericized into "the instance" or
"any deployment" to keep a record portable. The purity gate
(`scripts/check-purity.sh`) scopes its instance-string checks to the Ory config
files, `portal/scripts/`, `e2e/manifests/` and `docs/runbooks/` — **`docs/adr/`
is deliberately outside every one of those matchers**, so naming the instance
here is allowed on purpose, not an oversight.

Othala is open source because we are kind, not because it aims to be general. A
reader who wants to copy any of this is welcome to it and will be better served
by an accurate account of one real deployment than by an abstraction of a
deployment nobody runs. Adopters are readers here, not a constituency these
records answer to, and "a stranger could not lift this into their organisation"
is not a defect to fix.

**They are written to be safe for a reader with no context** — a new maintainer,
or an LLM that grepped a term and landed mid-file. Text that is confidently
wrong is worse than no text. See [00-template.md](00-template.md) for the three
rules that follow from that: Status leads with the current dated truth, Status
is binary with tombstone supersession, and every normative "must" either names
its enforcer by path or is marked `UNENFORCED — convention only`.

## Format

MADR-lite: Status / Context / Decision / Consequences / Alternatives considered.
The template is [00-template.md](00-template.md).

**Numbers are permanent identifiers, never an ordering and never a title.** A
number is retired only by deletion, and nothing has been retired — so no file may
ever be created at a number that once existed. This is mechanical, not a
convention: `scripts/check-purity.sh` fails the build when any `ADR NN` or
`docs/adr/NN-` reference anywhere in the tree has no matching file, and ADR
numbers are cited from the four byte-vendored Ory config files, so renumbering
would force a re-vendor into the deploy plane
([13](13-vendored-config-contract.md)).

**Filenames are stable identifiers too, not titles.** External repos link these
files by path and cannot always be edited in the same change, so a filename
whose slug has drifted from its title stays as it is. `09-capability-group-access-model.md`
is the live example: the title changed, the filename did not.

## Index

### Substrate and shape

| # | Title |
|---|---|
| [01](01-auth-substrate-ory.md) | Auth substrate: Ory Kratos + Hydra |
| [02](02-custom-portal-oidc-registrar.md) | Custom portal with in-app OIDC registrar |
| [07](07-three-layer-naming.md) | Three-layer naming: Othala / dag.dunn.dev / kratos+hydra |

### Transport and PKI

| # | Title |
|---|---|
| [03](03-proxy-originated-mtls.md) | mTLS is proxy-originated, not in-app |
| [06](06-two-pki.md) | Two-PKI: step-ca internal mesh CA + LE edge, never chained |
| [16](16-sslmode-disable-db-hop.md) | `sslmode=disable` on the Ory → Postgres DSNs |

### Identity and credentials

| # | Title |
|---|---|
| [04](04-identity-linking-on-username.md) | Identity linking on username, never email |
| [05](05-passkey-first-auth.md) | Passkey-first auth posture |
| [14](14-enrollment-out-of-band.md) | Enrollment: admin-created identities, out-of-band link and code |

### Authorization

| # | Title |
|---|---|
| [08](08-admin-authority-model.md) | Admin authority model: bootstrap floor + `metadata_admin`-managed admins |
| [09](09-capability-group-access-model.md) | Access model: two groups per service, explicit by default |
| [15](15-forward-auth-gate-aal1.md) | Forward-auth gate, and why `session.whoami` stays aal1 |

### OAuth2 and OIDC client posture

| # | Title |
|---|---|
| [10](10-first-party-skip-consent.md) | skip-consent for trusted first-party clients |
| [11](11-hardening-tuning.md) | Hardening tuning: lifetimes, cost factors, and the PKCE posture |
| [12](12-oidc-client-topology.md) | OIDC client topology: portal-owned challenge routes, single-origin CORS |

### This repo's contract with the deploy plane

| # | Title |
|---|---|
| [13](13-vendored-config-contract.md) | Vendored-config contract: othala is canonical, the deploy plane byte-enforces |

**Numbers and titles only, on purpose.** This index used to carry a one-line
summary per record. The summaries drifted — the ADR 09 row taught a group model
that had been retired, and it stayed readable for weeks after the code changed.
A number and a title cannot rot the same way, and dropping the column removes a
maintenance surface at zero cost to a reader who is going to open the record
anyway.

## Where else this list is copied

The public site's `/decisions/` page is a hand-maintained card grid in
`site/src/lib/sections.ts`, with each card linking out to the file here. It is a
third copy of this index, and the one a stranger actually reads. **Adding or
retitling a record means updating its card in the same commit.** Nothing checks
whether a card's blurb is *true* — that is maintainer discipline, and the blurbs
have drifted before.

## What ADRs are

An ADR answers "why does it work this way?" rather than "how does it work?"
(that is `ARCHITECTURE.md`'s job, and the mechanism reference for the access
model is `docs/access-model.md`). A good record is short enough to read in two
minutes and honest enough that the reader understands the tradeoff, not just the
conclusion — including the tradeoffs that went badly.

# Architecture Decision Records

This directory captures the significant decisions that shaped Othala's design.
Each record explains a choice that is not obvious from the code alone: what was
decided, why the alternatives were real options, and what consequences follow.

## Format

ADRs use MADR-lite: Status / Context / Decision / Consequences / Alternatives
considered. See [0000-template.md](0000-template.md).

Status values: `Proposed` | `Accepted` | `Superseded by [NNNN](...)` | `Deprecated`.
Dates appear in the status line only when they carry information (a supersession
date, or a gate milestone date). Cross-references to related ADRs appear at the
end of the status block.

## Index

| # | Title | Summary |
|---|---|---|
| [0001](0001-auth-substrate-ory.md) | Auth substrate: Ory Kratos + Hydra | Six substrates evaluated; Ory wins on BYO-UI, single-binary, Apache-2, full feature set in self-hosted edition. |
| [0002](0002-custom-portal-oidc-registrar.md) | Custom portal with in-app OIDC registrar | Consent service retired into the portal; shell-script client registration replaced with a typed TypeScript registrar. |
| [0003](0003-proxy-originated-mtls.md) | mTLS is proxy-originated, not in-app | Caddy sidecar holds the step-ca client cert; application code talks plain HTTP. |
| [0004](0004-identity-linking-on-username.md) | Identity linking on username, never email | `preferred_username` (immutable) is the link key; email is mutable without re-auth and is never used. |
| [0005](0005-passkey-first-auth.md) | Passkey-first auth posture | Passkey is the primary credential, not a second factor; password is the recovery on-ramp back to passkey. |
| [0006](0006-two-pki.md) | Two-PKI: step-ca internal mesh CA + LE edge, never chained | LE for browser-facing FQDNs; step-ca for internal mesh and outpost client certs; the two roots are never chained. |
| [0007](0007-three-layer-naming.md) | Three-layer naming: Othala / dag.dunn.dev / kratos+hydra | Othala = OSS project, dag.dunn.dev = operator instance, kratos/hydra = Ory functional names; used consistently and never conflated. |

## What ADRs are

An ADR answers the question "why does it work this way?" rather than "how does
it work?" (that is the job of ARCHITECTURE.md). A good ADR is short enough to
read in two minutes and honest enough that a new contributor understands the
tradeoff, not just the conclusion.

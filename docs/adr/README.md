# Architecture Decision Records

This directory is the canonical home of the decisions that shaped Othala's
design. Each record explains a choice that is not obvious from the code alone:
what was decided, why the alternatives were real options, and what consequences
follow. These records describe the system **as deployed** — where the running
instance (`dag.dunn.dev`) has diverged from an original decision, the record
says so rather than hiding the gap.

The othala.dunn.dev site's Decisions section links out to these files; they are
not rendered as website pages, so this directory is the single source of truth.

## Format

ADRs use MADR-lite: Status / Context / Decision / Consequences / Alternatives
considered. See [00-template.md](00-template.md).

Status values: `Proposed` | `Accepted` | `Superseded by [NN](NN-title.md)` |
`Deprecated`. A date in the status line records when the decision was accepted,
amended, or superseded. Cross-references to related ADRs appear at the end of
the status block; references to the `iac` repo (the deployment) or to other
private repos are given in prose, not as links.

## Index

| # | Title | Summary |
|---|---|---|
| [01](01-auth-substrate-ory.md) | Auth substrate: Ory Kratos + Hydra | Six substrates evaluated; Ory wins on BYO-UI, single-binary, Apache-2, full self-hosted feature set. The substrate is Kratos (identity) + Hydra (OIDC); the glauth→Kratos LDAP bridge was evaluated, never deployed, and is retired. |
| [02](02-custom-portal-oidc-registrar.md) | Custom portal with in-app OIDC registrar | Consent folded into the portal; client registration is a typed TypeScript registrar — create/update-only, never deletes — reconciled by a one-shot CLI (`just dag-reload-clients`) on `SIGHUP`. The no-delete rule is why a decommissioned service can leave a ghost Hydra client. |
| [03](03-proxy-originated-mtls.md) | mTLS is proxy-originated, not in-app | Apps talk plain HTTP; a sidecar holds the cert. The dag admin-proxy instantiation was reverted (2026-07-01) to a direct internal hop guarded by network isolation; the proxy-holds-the-cert pattern survives on the inference-serving path. |
| [04](04-identity-linking-on-username.md) | Identity linking on username, never email | The durable OIDC subject is the Kratos identity UUID (`sub`); username is the human migration on-ramp and is user-mutable (hardening owed for the username-forever apps); email is never a configured link key. |
| [05](05-passkey-first-auth.md) | Passkey-first auth posture | Three tiers: passkey primary, email one-time-code as a full-login secondary ranked above password, password demoted to a tertiary recovery on-ramp. Admin step-up is AAL2 at the portal. |
| [06](06-two-pki.md) | Two-PKI: step-ca mesh CA + LE edge, never chained | Two never-chained roots estate-wide. dag is single-PKI (Let's Encrypt edge only) as deployed; the live step-ca consumer is the inference metering hop, not dag. |
| [07](07-three-layer-naming.md) | Three-layer naming: Othala / dag.dunn.dev / kratos+hydra | Othala = OSS project, `dag.dunn.dev` = the operator's instance, kratos/hydra = Ory functional names; siblings resolve each other by ContainerName, never a network alias. |
| [08](08-admin-authority-model.md) | Admin authority model: bootstrap floor + `metadata_admin`-managed admins | Live admin grant/revoke via admin-managed metadata + AAL2 step-up, retiring the env allowlist; the Ory-native network admin plane is the bootstrap floor and break-glass. Two honest gaps recorded: the identity schema does not enumerate the admin marker, and break-glass is root-by-role (no dedicated identity yet). |
| [09](09-capability-group-access-model.md) | Capability-group access model | Authorization as `access-<svc>` (member) + `admin-<svc>` (per-service admin) + `root` (estate-wide) capability groups; path-selective forward-auth, set-union group claim, scope-gated. The legacy family/friends/kids cohorts persist as a compatibility layer pending migration. The OSS record stays abstract; the concrete roster lives in the instance. |
| [10](10-first-party-skip-consent.md) | skip-consent for trusted first-party clients | `skip_consent: true` per first-party client so the household never sees a consent screen; a documented threat-model acceptance (a stolen session yields tokens for all auth-touching surfaces, OK at family scale), revisited at the first banking-tier client. |
| [11](11-hardening-tuning.md) | Hardening tuning: lifetimes, cost factors, client quirks | Deliberate deviations from Ory defaults: 30m consent-challenge TTL, 30-day sessions, bcrypt cost 14, highest-available AAL on credential change + revoke-on-change. PKCE off globally (a non-PKCE RP; no per-client knob) but forced for public clients; `audience` is validator-only for `client_id`-keyed RPs. |
| [12](12-oidc-client-topology.md) | OIDC client topology: CORS origins + portal-owned challenge routing | `allowed_origins` is keyed by client type — browser-fetching SPAs need an entry each, redirect-flow clients never do. Challenge flows land on portal-owned `/oauth2/{login,consent,logout}`; the standalone Go consent service is retired, and the fronting proxy must match the challenge paths before any `/oauth2/*` wildcard. |

## What ADRs are

An ADR answers the question "why does it work this way?" rather than "how does
it work?" (that is the job of `ARCHITECTURE.md`). A good ADR is short enough to
read in two minutes and honest enough that a new contributor understands the
tradeoff, not just the conclusion.

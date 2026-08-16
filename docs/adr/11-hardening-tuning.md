# 11 — Hardening tuning: lifetimes, cost factors, and the PKCE posture

## Status

Accepted (2026-08-15). Records the deliberate deviations from Ory defaults —
token/flow lifetimes, hash cost, credential-change AAL — and the PKCE posture.
**The PKCE section changed materially at this revision**: the client that
motivated the global relaxation is not deployed, and this record now carries the
reasons not to flip the setting anyway.

All the values below live in `hydra/hydra.yml` and `kratos/kratos.yml`, which
are byte-vendored into the deploy plane — read
[13](13-vendored-config-contract.md) before editing either.

See also [01](01-auth-substrate-ory.md) (substrate),
[05](05-passkey-first-auth.md) (login tiers),
[08](08-admin-authority-model.md) (admin authority + AAL2 step-up),
[12](12-oidc-client-topology.md) (client topology).

## Context

Ory's defaults are tuned for large, general-purpose deployments. A small
self-hosted IdP can afford tighter windows, and a couple of knobs were set by
what connected clients could actually do rather than by preference. These
tunings accreted as config comments carrying security-review shorthand
(`CVP-P2`, `P8`) with no durable home and no legend; this ADR is that home, and
the codes retire with it.

## Decision

**Lifetimes.**

- `ttl.login_consent_request: 30m` (Hydra default 1h). A stolen challenge
  redirect is usable for the full window; halving it halves the exposure at no
  UX cost — nobody leaves a browser tab open that long mid-login.
- `session.lifespan: 720h` — 30 days, reduced from 90. The apex-scoped session
  cookie is replayable by any compromised subdomain app for its entire
  lifespan; a 30-day window meaningfully cuts that blast radius, and passkey
  re-login is one tap ([05](05-passkey-first-auth.md)). The admin surface never
  rides this window: it enforces its own 15-minute freshness
  (`privileged_session_max_age`) and AAL2 ([08](08-admin-authority-model.md)).
  The cookie stays persistent and apex-scoped — apex scope is what makes
  cross-subdomain SSO work; the tuning is the lifespan, not the scope.

**Cost factors.**

- `oauth2.hashers.bcrypt.cost: 14` (default 10; ~700 ms on modern hardware).
  Meaningfully raises the offline brute-force bar for stolen client-secret
  hashes. The cost lands on the token endpoint for confidential clients —
  negligible at this scale.

**Credential-change AAL.**

- `selfservice.flows.settings.required_aal: highest_available`. An identity
  with an enrolled second factor must step up before modifying passwords,
  passkeys, or MFA seeds. AAL1-only identities are unaffected
  (`highest_available` resolves to `aal1` for them) and first-passkey
  enrollment is not blocked. Complemented by `revoke_active_sessions` hooks on
  every credential-change method — an attacker who swaps a TOTP seed or
  rotates backup codes must not keep a re-entry path through a surviving
  session.
- This applies to the **settings** flow only. `session.whoami.required_aal`
  stays `aal1` for a separate and load-bearing reason that has its own record:
  [15](15-forward-auth-gate-aal1.md). Do not "make AAL consistent" across the
  two; they are different flows with different consumers.

**PKCE.**

`oauth2.pkce.enforced: false` globally, with
`oauth2.pkce.enforced_for_public_clients: true` as the forward guard.

The historical justification for the global relaxation was a single RP —
Tailscale — that cannot do PKCE, combined with Hydra having no per-client PKCE
knob. **Tailscale is not deployed.** It is struck from the catalog until a
rollout actually exists, and every OIDC client currently in the catalog is
confidential (each carries a `token_endpoint_auth_method` of
`client_secret_basic` or `client_secret_post`). So `enforced_for_public_clients:
true` is a no-op today, and nothing live requires `enforced: false`.

**Do not flip `enforced` to `true` on that fact alone.** Hydra still has no
per-client PKCE knob, so global enforcement is all-or-nothing across every
registered client. "No client needs the relaxation" is not the same claim as
"every client actually sends a PKCE challenge" — a confidential RP that omits
`code_challenge` today would break the moment enforcement went on, and that is
an eight-app outage discovered at login time, not at deploy time. Enforcement
therefore requires first verifying, per deployed client, that it sends PKCE.

Re-litigation triggers, in the order they are likely to fire:

- **Tailscale ships.** Keep `enforced: false`; the original constraint returns.
- **The Tailscale rollout is abandoned.** Verify every deployed confidential RP
  sends PKCE, then enforce globally.
- **Hydra ships a per-client PKCE knob.** Enforce per client and delete the
  global question entirely.

**Known stale comment, deliberately not fixed here.** The live vendored
`hydra/hydra.yml` still carries `enforced: false  # Tailscale doesn't do PKCE;
Hydra has no per-client knob` next to the setting — a live production setting
justified by a client that is not deployed. That is the same defect class as the
`whoami` aal1 comment that nearly caused an eight-app lockout, and it is real.
Correcting it is a byte-vendored edit that forces a re-vendor into the deploy
plane ([13](13-vendored-config-contract.md)), so it is deferred to the next
deliberate vendored-config pass rather than done piecemeal. **This paragraph is
the interim mitigation**: a reader who follows the comment lands here and finds
the truth.

**Audience.** Separately, and unrelated to PKCE: `oidc.audience` is required
non-empty on every OIDC client manifest, and at least one audience must match a
redirect URI by exact origin. That is a real invariant with a real enforcer —
`validateClients` in `portal/src/lib/manifests.ts`, via `audienceMatchesRedirect`
— because `id_token` `aud` verification needs it. An earlier revision of this
record described `audience` as an entry that "exists to satisfy manifest
validation, not the RP", citing Tailscale's habit of validating by `client_id`
and ignoring `aud`. That framing goes with Tailscale: the field is not a
workaround, it is a checked invariant that every deployed client satisfies.

## Consequences

- Sessions expire monthly instead of quarterly; the everyday cost is one
  passkey tap. Admin freshness is unaffected (it was always tighter).
- Client-secret verification costs ~700 ms per token-endpoint call — fine for
  a handful of confidential clients, and the knob to revisit first if a
  high-frequency machine client ever appears.
- The PKCE posture is now a **deliberate hold**, not a constraint: the thing
  that forced it is gone, and the reason not to change it is the unverified
  behavior of the clients that are actually deployed. That is a weaker
  justification than the original and should be treated as debt, not as a
  settled position.
- The retired review codes (`CVP-P2`, `P8`) in older comments and histories
  resolve here.

## Alternatives considered

- **An explicit `oauth2.strategies` pin** (`access_token: opaque`,
  `scope: exact`) was tried: Hydra v26.2.0's config schema rejects it
  (`additionalProperties "strategies" not allowed`) and the IdP refuses to
  boot — caught by the live e2e stand-up. Both values are already the Hydra
  defaults and the live OIDC dance confirms the behavior, so the defaults are
  relied on rather than gambling on an unverified key location. Revisit if a
  supported pin surfaces upstream.
- **Flip to global PKCE enforcement now that the non-PKCE RP is gone.** The
  tempting move, and the one this record exists to slow down. Rejected until
  every deployed confidential RP is verified to send a PKCE challenge; see the
  do-not-flip guard above.
- **Keeping the 90-day session default.** Rejected: pure apex-cookie replay
  exposure with no UX gain once passkeys are the primary credential.

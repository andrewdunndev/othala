# 11 — Hardening tuning: lifetimes, cost factors, and client-capability quirks

## Status

Accepted. Records the deliberate deviations from Ory defaults — token/flow
lifetimes, hash cost, credential-change AAL — and the PKCE / audience posture
forced by what connected clients can actually do. See also
[01](01-auth-substrate-ory.md) (substrate),
[05](05-passkey-first-auth.md) (login tiers),
[08](08-admin-authority-model.md) (admin authority + AAL2 step-up),
[12](12-oidc-client-topology.md) (client topology).
Reference: `hydra/hydra.yml` (`ttl`, `oauth2`), `kratos/kratos.yml`
(`selfservice.flows.settings`, `session`).

## Context

Ory's defaults are tuned for large, general-purpose deployments. A small
self-hosted IdP can afford tighter windows, and several knobs are constrained
not by preference but by the capabilities of the clients that connect to it.
These tunings accreted as config comments carrying security-review shorthand
(`CVP-P2`, `P8`) with no durable home and no legend; this ADR is that home,
and the codes retire with it.

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
  negligible at self-hosted scale.

**Credential-change AAL.**

- `selfservice.flows.settings.required_aal: highest_available`. An identity
  with an enrolled second factor must step up before modifying passwords,
  passkeys, or MFA seeds. AAL1-only identities are unaffected
  (`highest_available` resolves to `aal1` for them) and first-passkey
  enrollment is not blocked. Complemented by `revoke_active_sessions` hooks on
  every credential-change method — an attacker who swaps a TOTP seed or
  rotates backup codes must not keep a re-entry path through a surviving
  session.

**Client-capability quirks.**

- `oauth2.pkce.enforced: false` globally: at least one connected RP
  (Tailscale) cannot do PKCE, and Hydra has no per-client PKCE knob — global
  enforcement would break that client outright.
  `enforced_for_public_clients: true` is the forward guard: every current
  client is confidential, so it is a no-op today, but it blocks a silent PKCE
  skip if a public client is ever added.
- Some RPs validate the relying party by `client_id` and ignore `aud`
  entirely (Tailscale again). For such clients, a manifest `audience` entry
  exists to satisfy manifest validation, not the RP — recorded once here
  rather than re-explained per client.

## Consequences

- Sessions expire monthly instead of quarterly; the everyday cost is one
  passkey tap. Admin freshness is unaffected (it was always tighter).
- Client-secret verification costs ~700 ms per token-endpoint call — fine for
  a handful of confidential clients, and the knob to revisit first if a
  high-frequency machine client ever appears.
- The PKCE posture is client-capability-driven, not preference: re-litigate if
  the non-PKCE RP gains PKCE support or Hydra ships per-client enforcement.
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
- **Global PKCE enforcement.** Breaks the non-PKCE RP; rejected until
  per-client enforcement exists.
- **Keeping the 90-day session default.** Rejected: pure apex-cookie replay
  exposure with no UX gain once passkeys are the primary credential.

# 10 — skip-consent for trusted first-party clients

## Status

Accepted (2026-08-15). Every registered OIDC client is first-party and is
registered `skip_consent: true`, so a user with a live session never sees a
consent screen. As deployed, **no client uses the consent screen**, which makes
the per-client flag behaviorally identical to a server-wide default today; it
stays per-client as a deliberate tripwire (see Decision).

Builds on [01](01-auth-substrate-ory.md),
[02](02-custom-portal-oidc-registrar.md), and [05](05-passkey-first-auth.md)
(the session whose theft defines the blast radius below).

## Context

An OAuth2/OIDC authorization-code flow normally interrupts the user with a
**consent screen**: "App X wants access to your profile — Allow / Deny." That
screen exists for an open ecosystem of *third-party* clients an operator does not
control, where the user is the only party who can vouch for the app.

Othala's clients are not that. Every client is **first-party**: registered by the
operator through the in-app registrar ([02](02-custom-portal-oidc-registrar.md)),
running on infrastructure the operator owns, serving a small, known set of users
(a household). The consent screen in that setting is pure friction — a prompt the
user can only ever answer "Allow," shown for apps they already trust by
construction. For a family whose whole login UX is passkey-based
([05](05-passkey-first-auth.md)), an extra "Allow this app?" tap is noise.

Ory Hydra exposes exactly the right knob: a client marked **`skip_consent`**
causes the consent handler to auto-accept without rendering a screen. The
decision is *which* clients earn that mark, and what threat it accepts.

## Decision

**Set `skip_consent: true` for trusted first-party clients**, declared per client
in the catalog manifest that the registrar reads. The consent handler
(`portal/src/pages/oauth2/consent.ts` → `handleConsent` in
`portal/src/lib/oauth2-handlers.ts`) honors the manifest flag and auto-accepts
the requested scopes; a client without the flag 302-bounces to the interactive
`/auth/consent` screen instead.

This is **opt-in per client, not a server default** — and that distinction is
worth stating carefully, because as deployed it currently makes no behavioral
difference. Every registered client carries the flag, so nothing exercises the
interactive path. **This record deliberately does not restate how many clients
that is.** The enforcing artifact is the catalog manifest set in the deploy
plane; a count written here would be correct on the day it was typed and wrong
the next time a service ships. (An earlier revision of this record claimed "9 of
the 18 registered clients carry `skip_consent: true`; the rest use the normal
consent screen." Both halves were false, and the second half described a
population that has never existed.)

The flag stays per-client anyway, for two reasons that survive the "it's the
same as a default" objection:

1. **It is the greppable audit trail.** "Which apps skip consent?" is answered
   by grepping the manifests, not by reading server config and inferring that
   the answer is "all of them, always."
2. **It is a tripwire for the first non-first-party client.** A default would
   grant the skip silently to whatever gets registered next. Per-client means a
   future client must be *given* the skip explicitly, and can be refused it
   without config surgery — the interactive path already exists in the handler,
   so refusing costs a manifest line, not a feature.

The threat this accepts is documented, not hidden: **a stolen or hijacked session
yields tokens for every first-party surface, with no consent prompt to act as a
tripwire.** The consent screen is the one place a victim might notice "wait, I
didn't open that app" — `skip_consent` removes that tripwire by design. This is
**accepted at family scale** (few users, passkey-primary credentials,
operator-controlled enrollment). The named re-litigation trigger is the first
banking-tier or money-moving client: money movement, irreversible account
changes, or destructive admin operations would warrant per-action re-consent or
step-up regardless of this posture.

## Consequences

- **The UX goal is met.** A user with a live passkey session reaches any
  first-party app with zero extra taps — no "Allow this app?" interstitial ever.
- **The consent tripwire is gone.** A stolen session can mint tokens across every
  first-party surface silently; there is no consent prompt for a victim to catch.
  This is the explicit, accepted cost, bounded by the small user set and
  passkey-primary sessions ([05](05-passkey-first-auth.md)).
- **Session security becomes load-bearing.** With consent removed as a check, the
  session cookie *is* the perimeter — session lifespan ([11](11-hardening-tuning.md)),
  AAL enforcement, and admin step-up ([08](08-admin-authority-model.md)) carry
  the weight that a consent screen would otherwise share.
- **The interactive consent path is implemented but unexercised.** Nothing in
  production takes it, so it is code that has never been proven against a real
  client. If a future client is refused the skip, treat the first run of that
  path as untested and verify it end to end rather than assuming it works.
- **A clear trigger to revisit.** The decision names its own expiry condition:
  the first banking-tier operation. Drop `skip_consent` for that client and
  require per-action consent or step-up — without re-litigating the whole
  posture.

## Alternatives considered

- **Consent screen for every client (Hydra default).** The correct posture for an
  open third-party ecosystem. Rejected here: every client is first-party and
  operator-owned, so the screen only ever collects a rubber-stamp "Allow" while
  adding friction to a family login flow.
- **Remember-consent (accept once, skip thereafter).** Hydra can persist a prior
  consent so the screen shows only on first use. Rejected: it still shows the
  screen at least once per client per user, keeps consent state to manage, and
  buys nothing over `skip_consent` when the client is trusted by construction.
- **Per-scope consent UI even for first-party.** Useful when scopes are
  user-negotiable. Rejected: first-party scopes are operator-decided at
  registration, so there is nothing for the user to negotiate.
- **`skip_consent` as a server-wide default.** Simpler config, and — given that
  every deployed client carries the flag — currently indistinguishable in
  behavior. Rejected on the two grounds above: it destroys the greppable audit
  trail and silently extends the accepted threat to whatever is registered next.

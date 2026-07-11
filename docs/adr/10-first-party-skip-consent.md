# 10 — skip-consent for trusted first-party clients

## Status

Accepted (2026-06-27). Builds on [01](01-auth-substrate-ory.md),
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

**Set `skip_consent: true` for trusted first-party clients** (declared per client
manifest / OIDC registration), so a user with a live session never sees a consent
screen. The consent handler (`portal/src/pages/oauth2/consent.ts` →
`handleConsent` in `portal/src/lib/oauth2-handlers.ts`) recognizes the flag and
auto-accepts the requested scopes.

This is **opt-in per client, not a server default.** A client only gets
`skip_consent` because the operator registered it as first-party and trusted. Any
client that is *not* operator-owned, or that gains higher-stakes operations (see
Consequences), keeps the normal consent screen.

The threat this accepts is documented, not hidden: **a stolen or hijacked session
yields tokens for every auth-touching surface, with no consent prompt to act as a
tripwire.** The consent screen is the one place a victim might notice "wait, I
didn't open that app" — `skip_consent` removes that tripwire by design. This is
**accepted at family scale** (few users, all-passkey AAL, operator-controlled
enrollment) and is to be **revisited the moment any client gains banking-tier
operations** (money movement, irreversible account changes, destructive admin),
which would warrant per-action re-consent or step-up regardless.

## Consequences

- **The UX goal is met.** A user with a live passkey session reaches any
  first-party app with zero extra taps — no "Allow this app?" interstitial ever.
- **The consent tripwire is gone.** A stolen session can mint tokens across every
  first-party surface silently; there is no consent prompt for a victim to catch.
  This is the explicit, accepted cost, bounded by the small user set and
  passkey-AAL sessions ([05](05-passkey-first-auth.md)).
- **Session security becomes load-bearing.** With consent removed as a check, the
  session cookie *is* the perimeter — short-lived sessions, AAL enforcement, and
  admin step-up ([08](08-admin-authority-model.md)) carry the weight that a
  consent screen would otherwise share.
- **The trust boundary is per client, auditable.** `skip_consent` lives on the
  client manifest, so "which apps skip consent" is a greppable list, not implicit
  behavior. On the deployed instance, 9 of the 18 registered clients carry
  `skip_consent: true`; the rest use the normal consent screen.
- **A clear trigger to revisit.** The decision names its own expiry condition: the
  first banking-tier operation. An adopter who adds a money-moving or destructive
  client should drop `skip_consent` for it and require per-action consent or
  step-up — without re-litigating the whole posture.

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
- **`skip_consent` as a server-wide default.** Simpler config. Rejected: it would
  silently extend the accepted threat to any future non-first-party client; the
  flag stays opt-in per client so the trust decision is explicit each time.

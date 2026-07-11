<!-- TODO(site-rewrite): Delink `docs/decision.md` (CUT — not published); this ADR promotes content out of it, so a pointer back is optional. This comment is stripped at render time and does not appear on the published page. -->

# 0010 — skip-consent for trusted first-party clients

## Status

Accepted (2026-06-27)

Promoted out of the now-superseded [`docs/decision.md`](../decision.md) — the
"Consent" row (`oidc.skip_consent: true` per client manifest) and the HIGH
threat-model note it carried — into a durable, single-concept record. Builds on
[0001 — auth substrate](0001-auth-substrate-ory.md),
[0002 — in-app OIDC registrar + consent handler](0002-custom-portal-oidc-registrar.md),
and [0005 — passkey-first auth](0005-passkey-first-auth.md) (the session whose
theft defines the blast radius below).

## Context

An OAuth2/OIDC authorization-code flow normally interrupts the user with a
**consent screen**: "App X wants access to your profile — Allow / Deny." That
screen exists for an open ecosystem of *third-party* clients an operator does not
control, where the user is the only party who can vouch for the app.

Othala's clients are not that. Every client is **first-party**: registered by the
operator through the in-app registrar ([0002](0002-custom-portal-oidc-registrar.md)),
running on infrastructure the operator owns, serving a small, known set of users
(a household). The consent screen in that setting is pure friction — a prompt the
user can only ever answer "Allow," shown for apps they already trust by
construction. For a family on Apple devices whose whole login UX is "Face ID and
you're in" ([0005](0005-passkey-first-auth.md)), an extra "Allow this app?" tap
is noise.

Ory Hydra exposes exactly the right knob: a client marked **`skip_consent`**
causes the consent handler to auto-accept without rendering a screen. The
decision is *which* clients earn that mark, and what threat it accepts.

## Decision

**Set `skip_consent: true` for trusted first-party clients** (declared per client
manifest / OIDC registration), so a user with a live session never sees a consent
screen. The consent handler ([0002](0002-custom-portal-oidc-registrar.md))
recognizes the flag and auto-accepts the requested scopes.

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

## Diagram

Authorize flow — consent auto-accepted for a first-party client, versus the
screen that a non-first-party client would still see:

```{mermaid}
sequenceDiagram
    autonumber
    actor U as User (live session)
    participant App as Client app
    participant H as Hydra (OAuth2/OIDC)
    participant P as Portal consent handler
    participant K as Kratos (session)

    U->>App: open app
    App->>H: /oauth2/auth (authorize)
    H->>P: login_challenge
    P->>K: session check (passkey AAL)
    K-->>P: session OK
    P-->>H: accept login
    H->>P: consent_challenge
    alt client.skip_consent == true  (trusted first-party)
        P-->>H: AUTO-ACCEPT scopes — no screen rendered
        Note over U,P: user never sees a consent prompt
    else not first-party / higher-stakes
        P-->>U: render "Allow App access?" screen
        U-->>P: Allow
        P-->>H: accept consent
    end
    H-->>App: auth code → tokens
    App-->>U: signed in
```

Blast radius the decision accepts — one captured session fans out to every
surface with zero consent friction (reference instance: ~14 = 11 OIDC + 1 LDAP +
2 forward-auth):

```{mermaid}
flowchart TD
    S["One stolen / hijacked session<br/>(single passkey-AAL cookie)"]
    S --> G{"consent screen<br/>= tripwire"}
    G -. removed by skip_consent .-> X["no prompt, nothing to notice"]
    X --> O["OIDC apps<br/>silent token issuance"]
    X --> L["LDAP consumers<br/>e.g. media / TV"]
    X --> F["forward-auth surfaces"]
    O --> T["all auth-touching surfaces reachable<br/>accepted at family scale"]
    L --> T
    F --> T
    T --> R{{"revisit if any client gains<br/>banking-tier operations"}}
```

## Consequences

- **The UX goal is met.** A user with a live passkey session reaches any
  first-party app with zero extra taps — no "Allow this app?" interstitial ever.
- **The consent tripwire is gone.** A stolen session can mint tokens across every
  first-party surface silently; there is no consent prompt for a victim to catch.
  This is the explicit, accepted cost, bounded by the small user set and
  passkey-AAL sessions ([0005](0005-passkey-first-auth.md)).
- **Session security becomes load-bearing.** With consent removed as a check, the
  session cookie *is* the perimeter — short-lived sessions, AAL enforcement, and
  admin step-up ([0008](0008-admin-authority-model.md)) carry the weight that a
  consent screen would otherwise share.
- **The trust boundary is per client, auditable.** `skip_consent` lives on the
  client manifest, so "which apps skip consent" is a greppable list, not implicit
  behavior.
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

## Links

- Promoted from [`docs/decision.md`](../decision.md) — the "Consent" row and its
  HIGH threat-model note (a stolen session = tokens for all auth-touching
  surfaces; OK at family scale).
- [0001 — auth substrate: Ory Kratos + Hydra](0001-auth-substrate-ory.md) — the
  Hydra that provides `skip_consent`.
- [0002 — in-app OIDC registrar + consent handler](0002-custom-portal-oidc-registrar.md)
  — where the flag is honored and where first-party clients are registered.
- [0005 — passkey-first auth](0005-passkey-first-auth.md) — the session whose
  theft defines this decision's blast radius.
- [0008 — admin authority model](0008-admin-authority-model.md) — step-up and
  admin gating that carry the weight consent no longer does.
- [0000-template.md](0000-template.md) — record shape.

*The operator's instance records its concrete deployed surface count and edge
topology in its own (private) estate ADRs; this OSS record stays adopter-generic.*

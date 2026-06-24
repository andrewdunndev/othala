# 0005 — Passkey-first auth posture

## Status

Accepted. Passkey is the primary credential everywhere. Username + password is a
fallback used only when a passkey is unavailable, and the fallback flow's purpose
is to get a passkey back on file. See also [0001](0001-auth-substrate-ory.md)
(substrate), [0004](0004-identity-linking-on-username.md) (identity linking).
Reference: `docs/decision.md` "Auth policy"; `kratos/kratos.yml`.

## Context

The estate serves a family on Apple devices (iPhone, iPad, Mac), so Face ID and
Touch ID are present on every device. The operator controls enrollment: identities
are admin-created, the enrollment URL is delivered out-of-band, there is no
self-service signup, and no password ever transits a channel.

This ADR exists because the first cut got it wrong in an instructive way. The
initial Ory integration wired WebAuthn the conventional way, as a *second factor*
stacked on top of a password (the "register a security key as 2FA" pattern that
tooling, examples, and model priors all default to). That is the wrong mental model
for this estate: a passkey is not a second factor bolted onto a password. It is the
modern, simpler, and stronger *primary* credential. The correction was deliberate:
look at what passkeys actually are today and build passkey-native, rather than
accept the inherited webauthn-as-2FA default. (Same discipline the deploy plane
applies under "research the current path, don't ship the training default.")

The intended UX, stated plainly: **passkey everywhere. It is superior and simple.
When it fails, fall back to username + password and get a passkey back on file.**

Two constraints shape the edges:

- **LDAP-bound consumers.** Jellyfin and Apple TV bind through the LDAP bridge with
  a password and cannot do passkeys or OIDC. A password credential must exist for
  those identities.
- **Admin recovery.** Admin identities must not be recoverable through a transient
  mailbox (a compromised inbox would otherwise mint an admin session). The recovery
  gate refuses email-code login and email recovery for admins; admins authenticate
  by passkey.

## Decision

**Passkey (WebAuthn, via Kratos's `webauthn` method) is the primary credential** for
family users, presented first and used everywhere. It is not a second factor.

**Username + password is the fallback**, reached only when a passkey is unavailable
(a new or lost device, or an LDAP-bound consumer). On the password path the login
flow's goal is to **re-enroll a passkey** so the user returns to passkey-first; the
password is a recovery on-ramp, not a co-equal everyday credential.

**Password + LDAP is retained only for the consumers that cannot do passkey or OIDC**
(Jellyfin, Apple TV). It is available, never promoted.

**Email code is the lost-all-passkeys recovery path** for non-admin identities: it
issues a settings session to enroll a fresh passkey, not a full login session.
Admins are excluded by the recovery gate.

The webauthn-as-optional-2FA framing is explicitly rejected: passkeys *are* the
login method, not a factor stacked on a password.

## Consequences

- On a recognized device, a user authenticates with Face ID / Touch ID and never
  sees a password prompt. The family UX goal is met.
- The password path is a recovery on-ramp back to passkey, not a parallel everyday
  credential. This keeps "passkey everywhere" true in practice, not just in intent.
- Password credentials must still be set for every identity that uses Jellyfin or
  Apple TV over LDAP; the operator sets these at enrollment.
- Admin step-up to AAL2 on `/admin/*` is enforced in the Astro SSR layer
  (`requireAdminSession`), redirecting to Kratos with `?aal=aal2&refresh=true`;
  Kratos AAL is per-flow, so a `forward_auth` check alone cannot gate on it. A
  second passkey or security key serves as the admin step-up factor, a genuine
  second factor distinct from the primary passkey login.
- `selfservice.flows.settings.required_aal: highest_available` prevents a
  first-factor-only session from changing credentials on an account that already has
  a second factor (CVP hardening). First passkey enrollment is not blocked.
- The ᛞ→ᛟ rune greeting renders on `/auth/login` regardless of method: brand
  identity, not a method indicator.
- Adopters who want a different primary can reorder the login-page nodes. The Kratos
  config and the portal login page are the two places this posture is encoded.

## Alternatives considered

- **Password-first, passkey as optional 2FA.** The common homelab pattern, and the
  default that tooling and model priors reach for. Rejected: it misframes the
  passkey as a second factor, contradicts the family "Face ID is the default" goal,
  and forces users to maintain a password they would rarely type. This was the first
  cut, and correcting it is why this ADR exists.
- **Passkey-only (no password at all).** The cleanest security posture. Blocked by
  the LDAP consumers (Jellyfin, Apple TV) that cannot bind via WebAuthn; a password
  credential type must remain.
- **Email magic link as a primary or recovery method.** The `link` strategy is
  deprecated in current Kratos in favor of `code`; not a candidate regardless.

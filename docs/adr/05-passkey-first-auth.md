# 05 — Passkey-first auth posture

## Status

Accepted. Passkey is the primary credential everywhere. Email one-time-code is a
full-login secondary, ranked above password. Username + password is demoted to a
tertiary recovery on-ramp and break-glass credential. See also
[01](01-auth-substrate-ory.md) (substrate; LDAP bridge shelved),
[04](04-identity-linking-on-username.md) (identity linking),
[08](08-admin-authority-model.md) (admin authority + AAL2 step-up).
Reference: `kratos/kratos.yml` (`selfservice.methods`).

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
When it fails, fall back and get a passkey back on file.**

The fallback edge has since grown a middle rung. A user on a brand-new or borrowed
device — before any passkey is enrolled there — needs a way in that does not depend
on a typed secret. Email one-time-code fills that gap: it is a real login method,
not just recovery, and it sits *above* password so the everyday fallback never
reaches for a password the user would rarely type.

## Decision

Three tiers, in descending precedence, all verified against `kratos/kratos.yml`.

**Tier 1 — Passkey is the primary credential.** Kratos's dedicated `passkey`
strategy is enabled (`selfservice.methods.passkey.enabled: true`), giving
discoverable credentials plus conditional UI — the usernameless one-tap experience
(tap "Sign in with passkey" and you're in, no username typed). This is distinct
from the legacy `webauthn` strategy, which Ory now treats as legacy with weaker
discoverability. Passkey is presented first and used everywhere. It is not a second
factor.

**Tier 2 — Email one-time-code is a full-login secondary.** The `code` strategy is
enabled with `passwordless_enabled: true`, which makes it a first-class login method
(email OTP), not merely a recovery on-ramp. It establishes a real login session and
is ranked **above** password. A user on a new device without a passkey receives a
single-use, flow-lifetime-bounded code (`max_submissions: 5`, `lifespan: 15m`) and
signs in, then enrolls a passkey. This tier was previously unrecorded in this ADR;
it is now the intended second rung of the fallback.

**Tier 3 — Username + password is the tertiary recovery on-ramp.** The `password`
method remains enabled (`selfservice.methods.password.enabled: true`) but sits at
the bottom. The legacy `webauthn` strategy is kept only as a hardware-security-key
*second* factor (`webauthn.config.passwordless: false`), so it never duplicates the
passwordless primary. On the password path the flow's goal is to re-enroll a passkey
so the user returns to passkey-first; the password is a recovery on-ramp, not a
co-equal everyday credential.

Email code (Tier 2) also serves as the lost-all-passkeys recovery path for
non-admin identities via the `code`-based recovery flow. Admin recovery is refused
by the recovery-gate webhook (see [08](08-admin-authority-model.md)).

The webauthn-as-optional-2FA framing is explicitly rejected: passkeys *are* the
login method, not a factor stacked on a password.

## Consequences

- On a recognized device, a user authenticates with Face ID / Touch ID and never
  sees a password prompt. The family UX goal is met.
- The everyday fallback is email one-time-code, not password. A user on a new
  device gets in without a typed secret and enrolls a passkey. "Passkey everywhere,
  password almost never" holds in practice, not just in intent.
- **Why password is retained (the LDAP justification is stale).** The LDAP bridge
  is shelved — no `dag-ldap-bridge` unit runs, Jellyfin authenticates via its OIDC
  plugin plus a Jellyfin-local password, and the estate identity's Kratos password
  is not consumed by any native client (see [01](01-auth-substrate-ory.md); the
  retirement is recorded in the private deploy repo). Password stays
  enabled for two live reasons: (1) the seeded break-glass / bootstrap-floor
  identity signs in with a SOPS-backed password plus TOTP step-up — the
  always-available admin recovery path when passkey or email is degraded (the
  deployment's break-glass convention and rebuild-verification decisions;
  [08](08-admin-authority-model.md) Tier 2 floor); and (2) a last-resort
  recovery on-ramp back to passkey for any user.
- **Admin login-gate hook retired (2026-06-25) — honest residue.** A Kratos
  `login.after.code` webhook (`login-gate.jsonnet`) used to interrupt email-code
  login for admin identities, forcing them through passkey or console so a
  transient mailbox could not mint an admin AAL1 session. That hook is retired:
  `kratos/kratos.yml`'s login flow no longer wires any `after.code.hooks`. The
  canonical enforcement is now AAL2 step-up in the portal (`requireAdminSession`
  redirects to `?aal=aal2&refresh=true`) plus `settings.required_aal:
  highest_available` on credential changes — see [08](08-admin-authority-model.md).
  The `login-gate.jsonnet` file is still volume-mounted into `dag-kratos` and still
  written by the deploy step, but nothing references it — it is inert residue, not
  an active mechanism, and should be pruned on the next config pass.
- Admin step-up to AAL2 on `/admin/*` is enforced in the portal SSR layer, not in
  the login flow: Kratos AAL is per-flow, so a `forward_auth` check alone cannot
  gate on it. A second passkey or hardware key (legacy `webauthn`, `passwordless:
  false`) or TOTP serves as the admin step-up factor — a genuine second factor
  distinct from the primary passkey login.
- `selfservice.flows.settings.required_aal: highest_available` prevents a
  first-factor-only session from changing credentials on an account that already has
  a second factor. First passkey enrollment is not blocked (it resolves to `aal1`
  for an `aal1`-only identity).
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
  the break-glass requirement: the bootstrap-floor identity must be recoverable when
  passkey enrollment and email delivery are both degraded, which needs a
  SOPS-seeded password plus TOTP. A password credential type must therefore remain.
- **Password as the everyday fallback (no email-code login).** Rejected: it forces
  users on new devices to type a rarely-used secret. Email one-time-code gives a
  passwordless second rung that lands them straight into passkey enrollment.
- **Email magic link as a primary or recovery method.** The `link` strategy is
  deprecated in current Kratos in favor of `code` (and is disabled in config); not a
  candidate regardless.

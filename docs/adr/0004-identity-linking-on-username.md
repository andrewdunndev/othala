# 0004 — Identity linking on username (immutable), never email (mutable)

## Status

Accepted. Reference: `campaigns/othala/account-linking-plan.md`.

## Context

When an OIDC-capable app receives a first login from the IDP, it needs to link
the incoming identity to an existing local account (or create a new one). The
claim it uses as the linking key determines whether re-linking, orphaning, or
account takeover is possible.

Othala issues the following stable claims from Kratos:

- `sub` -- the Hydra-assigned opaque public identifier. Stable for the lifetime
  of the Hydra database. Immutable.
- `preferred_username` -- `traits.username`. Operator-assigned at identity
  creation. Not editable via self-service (no settings-flow mechanism exists).
  Immutable in practice.
- `email` -- `traits.email`. Editable by the user via the Kratos settings flow.
  The settings flow does not revoke the session. Mutable.

The risk: if an app links on `email` and a user changes their email before or
after OIDC is enabled on that app, the next login either creates a shadow account
(old email was the stored key, new email does not match) or matches the wrong
account (another user had the same new email). At family scale, shadow accounts
are operationally recoverable but require operator intervention. At any scale,
email-as-linking-key is an unsafe posture when email is user-mutable without a
re-authentication gate.

Several apps in the estate default to email-based linking (Mealie, GitLab CE)
or have an email-fallback that must be blocked (Immich -- the email fallback on
first login stamps `oauthId` permanently; if the fallback fires on the wrong
email, the binding is wrong for the life of the account).

## Decision

Identity linking uses `preferred_username` as the primary key for apps that
support configurable claim selection, and `sub` as the key for apps that
hardcode their link claim. Email is never used as a link key. For each app, the
claim is set explicitly before OIDC is enabled:

- Apps defaulting to email (Mealie, GitLab CE): the link claim is reconfigured
  to `preferred_username` before enabling OIDC.
- Apps that hardcode `sub` (Immich, Audiobookshelf): the `sub` value is
  pre-seeded into the app's local user record before enabling OIDC, so the
  automatic email fallback never fires.
- Apps that default to `preferred_username` (Jellyfin via the SSO plugin):
  the default is verified and left in place.

This policy applies across all estate apps and is a hard gate before flipping
any app to OIDC.

## Consequences

- Each OIDC migration requires a pre-migration audit: enumerate existing local
  accounts, confirm linking-key values match Kratos traits, execute any
  DB/config fix, then enable OIDC.
- For Immich specifically, the pre-seed is an explicit SQL update. The
  email-fallback auto-link path ("let it link on first login") is not available
  under this policy, even if email addresses happen to match at migration time.
- `preferred_username` (format: `first.last`) is immutable by design. The Kratos
  identity schema has no settings-flow attribute for username. If the estate ever
  adds a username-change mechanism, this ADR must be revisited.
- `sub` stability is tied to the Hydra database. If the Hydra DB is rebuilt (the
  `secrets.system` non-rotatable key is lost), all `sub` values change and every
  app that links on `sub` must have its pre-seed re-run. Document this in the
  disaster-recovery runbook.
- Vaultwarden is a deliberate exception: it links on `{issuer}/{sub}` after
  first login (which uses email for account provisioning). The first-login email
  step is a one-time provisioning event, not a recurring link; the permanent key
  is `iss+sub` (both stable). This is recorded in the account-linking plan as an
  accepted exception.

## Alternatives considered

- **Link on email by default.** Simplest for initial setup. Unsafe when email is
  mutable. Rejected as a policy default even though it would work at migration
  time if all emails currently match.
- **Link on sub everywhere.** Universally safe and stable. Apps that cannot
  configure the link claim are forced onto this path anyway. For apps that
  support `preferred_username`, using it is preferable because it is
  human-meaningful to operators (easier to audit which account corresponds to
  which person).
- **Restrict email mutability (require re-auth for email changes).** Kratos
  supports `required_aal: aal2` for the settings flow. This would make email
  harder to change, not immutable. It does not make email safe as a link key;
  a passkey-enrolled user with a fresh AAL2 session can still change email. The
  correct fix is to not use email as a link key.

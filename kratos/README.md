# kratos

Ory Kratos configuration as IaC.

| File | Purpose |
|---|---|
| `kratos.yml` | Server config: DSN, serve URLs, CORS, self-service flow URLs and methods, session lifespan, cookie domain, courier (SMTP), secrets, hashers |
| `identity.schema.json` | Identity schema: traits {username, email, displayName?, recoveryEmail?}. Groups live in `metadata_admin`, not traits. |

## metadata_admin convention

Kratos doesn't enforce schema on `metadata_admin`. By convention we use:

```json
{
  "metadata_admin": {
    "groups": ["admin", "<svc>-access", "<svc>-admin"]
  }
}
```

`<svc>` is a placeholder for a service slug. Othala tracks no service inventory.

The `admin` entry is an identity-group name, not portal authority. `../portal/src/lib/config.ts` puts `admin` first in the identity-group list regardless of what the operator sets (`const base = ['admin', ...parsed.filter((g) => g !== 'admin')];`), so it renders as an assignable checkbox and can land in an identity's `metadata_admin.groups` like any other name. Portal `/admin` authority is a different field: `requireAdminSession` (`../portal/src/lib/admin.ts`) calls `isAdminMarker`, which returns true only for `metadata_admin.admin === true` (`../portal/src/lib/admin-auth.ts`). No portal code path compares a group against the literal `admin` — the group comparisons in `../portal/src/lib/gate.ts` are against values supplied by a manifest binding or by the forward-auth query param (`../docs/adr/08-admin-authority-model.md`).

Access groups: two per service by convention — `<svc>-access` for entry, `<svc>-admin` for the elevated role. The suffixes are unenforced. `/api/forward-auth` accepts any group matching `/^[a-z0-9][a-z0-9-]*$/`, and `../portal/src/lib/manifest-lint.ts` records a `warn`, not a `block`, when a referenced group falls outside the known set. The canonical description is `../docs/access-model.md` §6.

What othala's own gate checks:

- OIDC login and consent — `enforceAccessGate` (`../portal/src/lib/gate.ts`) admits when `identity.state === 'active'` and the identity holds any group in `manifest.accessGroups` (OR-semantics). A manifest setting `skipAccessCheck` bypasses the membership check; the active-state check is never bypassed.
- forward-auth — `enforceGroupGate` (same file) admits when `identity.state === 'active'` and the identity holds the single group named in the `group` query param of `../portal/src/pages/api/forward-auth.ts`. There is no manifest and no bypass on that path.

Both gates decide by binding, never by name: a group is access-bearing because a manifest binds it or an edge names it. A manifest whose access binding lists `<svc>-access` and not `<svc>-admin` therefore denies an identity holding only `<svc>-admin`. What a deploying edge additionally requires is a property of the deployment, not of othala.

The admin UI writes this array — `../portal/src/pages/admin/users/[id].astro` calls `updateIdentity` with `metadataAdmin.groups`. The consent handler reads it into the ID token: `composeIDTokenClaims` (`../portal/src/lib/claims.ts`) copies `metadata_admin.groups` to a `groups` claim and deletes that claim when the client manifest opts out, and `acceptConsentRequest` (`../portal/src/lib/oauth2-handlers.ts`) hands the result to Hydra as `session.id_token`.

An LDAP bridge (`gitlab.com/dunn.dev/kratos-ldap`) exposes this array as `memberOf`. It is an unmaintained reference and is not deployed — see `../README.md` and `../docs/access-model.md` §13.

## SMTP

Recovery (`selfservice.flows.recovery.enabled`) and verification (`selfservice.flows.verification.enabled`) are both `true` and send through the courier. The entire courier connection is one env var, `OTHALA_SMTP_CONNECTION_URI`, interpolated at `courier.smtp.connection_uri` and shared with the portal's contact-form mailer.

## Secret rotation

In the `secrets:` block, `secrets.cookie` and `secrets.cipher` each hold a single-element array. Rotation is prepend-new, restart, then drop the old entry once the session lifespan has elapsed. The procedure is `../docs/runbooks/cookie-rotation.md`, restated in the comment that opens the `secrets:` block.

## AAL semantics

Kratos AAL is enforced per-flow, not per-route. `kratos.yml` sets `required_aal` in two places, and pointedly does not set it in a third:

- `session.whoami.required_aal: aal1` — must stay aal1. Setting it to `highest_available` makes whoami return `session.identity = null` for MFA-enabled identities, and the forward-auth gate returns 401 when `session.identity.id` is missing (`../portal/src/pages/api/forward-auth.ts`). See the `CRITICAL:` comment directly above that key and `../docs/adr/15-forward-auth-gate-aal1.md`.
- `selfservice.flows.login` sets no `required_aal` key — it is a `settings`/`session` knob, not a login-flow one, as the comment under that flow records. AAL2 is requested per-flow instead, never enforced globally at the flow level.
- `selfservice.flows.settings.required_aal: highest_available` — credential-changing settings ops require AAL2 step-up; the comment above that key states that first-passkey enrollment is not blocked. See `../docs/adr/11-hardening-tuning.md` and `../docs/adr/08-admin-authority-model.md`.

The Astro admin pages (`../portal/src/pages/admin/`) don't read AAL themselves — each calls `requireAdminSession` (`../portal/src/lib/admin.ts`), which requires `session.authenticator_assurance_level === 'aal2'` server-side and otherwise redirects to the Kratos login flow with `aal=aal2` and `refresh=true`.

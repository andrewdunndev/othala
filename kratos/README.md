# kratos

Ory Kratos configuration as IaC.

| File | Purpose |
|---|---|
| `kratos.yml` | Server config: DSN, serve URLs, CORS, self-service flow URLs, methods (password, webauthn, totp, code), session lifespan, cookie domain, courier (SMTP), secrets, hashers |
| `identity.schema.json` | Identity schema: traits {username, email, displayName?, recoveryEmail?}. Groups live in `metadata_admin`, not traits. |

## metadata_admin convention

Kratos doesn't enforce schema on `metadata_admin`. By convention we use:

```json
{
  "metadata_admin": {
    "groups": ["admin", "family", "access-keep", "access-larder", "access-listen", "access-cinema", "access-tune", "access-memory", "access-vault", "access-gather", "access-library", "access-llm", "access-forge", "access-observe"]
  }
}
```

Identity groups: `admin`, `family`, `friends`, `kids` (defer).
Access groups: one per app, `access-<slug>`.

The admin UI manipulates this array. The consent handler reads it to inject the `groups` claim into Hydra-issued ID tokens. The LDAP bridge reads it to compute LDAP `memberOf`.

## SMTP setup

Recovery and verification use Fastmail SMTP. App password (not Fastmail master password) lives in the `SMTP_PASS` env var sourced from Bitwarden.

## Secret rotation

- `secrets.cookie`: rotate by prepending a new value. Old sessions valid until they expire.
- `secrets.cipher`: don't rotate without re-encrypting credential data. Treat as non-rotatable for the life of the database.

## AAL semantics

Kratos AAL is enforced per-flow, not per-route. Three values appear in `kratos.yml`:

- `session.whoami.required_aal: aal1` — whoami returns full session for aal1 sessions; setting to `highest_available` breaks the LDAP bridge BIND path (whoami returns `session.identity = null` for MFA-enabled identities).
- `selfservice.flows.login.required_aal: aal1` — login flow defaults to first-factor; AAL2 step-up requested via `?aal=aal2&refresh=true` query when the admin SSR pages need it.
- `selfservice.flows.settings.required_aal: aal1` — settings allow most edits at aal1; sensitive ops use `privileged_session_max_age` instead.

The Astro admin pages (in `../portal/src/pages/admin/`) read `session.authenticator_assurance_level` from whoami and redirect to a refresh login with `?aal=aal2` if not aal2.

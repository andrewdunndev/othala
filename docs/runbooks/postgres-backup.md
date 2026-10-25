# Postgres backup and restore

The backup posture for the `kratos` and `hydra` databases and the restore
procedure. The runner (scheduler, off-host copy, snapshot policy) is
deploy-plane work; this runbook is the contract it must satisfy.

## Stakes

The databases hold every passkey enrollment, active session, recovery-code
state, and the Hydra OAuth2 clients (secrets hashed) and signing keys (private keys and
session data encrypted at rest under `secrets.system`). Losing them without a backup means
every member re-enrolls, every OIDC client is re-created, and `secrets.system` must be restored from
your secret store or even a partial restore cannot decrypt.

## Required posture

1. **Nightly `pg_dump`** in custom format (`pg_restore`-compatible) to
   `/var/lib/postgres/backups/<UTC-timestamp>.dump`, both databases per
   timestamp. Retention: 30 daily and 12 monthly.
2. **Filesystem snapshots**, if the data volume supports them, alongside the
   dumps: snapshot for quick rollback, dump for long-term archive.
3. **Off-host copy** to at least one destination outside a single-host
   failure; two independent destinations are stronger.
4. **`secrets.system` stays out of the dump.** It is an env var held in your secret
   store. Restore it into the env before starting Hydra;
   otherwise the JWK private keys and session data are permanently ciphertext. Back up the
   secret-store key separately.
5. **Quarterly restore drill.** Restore the latest dump into a throwaway VM
   with fresh Kratos and Hydra pods and confirm one identity signs in, one
   OIDC client emits a token, and WebAuthn credentials still verify (this
   tests `secrets.cipher` rehydration).

## Partial-state restore

Consistency is per-database, and the two are written in different
transactions. A backup between a Kratos write and the matching Hydra write
restores with drift: an identity with no remembered-consent row, or the
reverse. Do not reconcile rows:

1. Restore both databases from the most recent compatible pair of dumps.
2. Clear Hydra's remembered consent and login sessions to force re-consent, per subject,
   through the Hydra admin API (from the othala container):
   `DELETE /admin/oauth2/auth/sessions/consent?subject=<id>&all=true` and
   `DELETE /admin/oauth2/auth/sessions/login?subject=<id>`. For a whole-instance wipe:

   ```sql
   TRUNCATE hydra_oauth2_flow, hydra_oauth2_authentication_session CASCADE;
   ```

   This also drops in-flight flows and every issued token.

3. **Sign out everywhere** for every active member (`/admin/users/<id>`),
   dropping their Kratos session and relying-party state.
4. Each member re-authenticates at their next app visit.

## Related

- `docs/runbooks/secrets-rotation.md`: rotation of `secrets.system`.
- `docs/runbooks/cookie-rotation.md`: the rotatable secrets.
- `docs/runbooks/admin-recovery.md`: recovery, which needs Postgres alive.

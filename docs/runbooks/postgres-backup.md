# Postgres backup and restore

What must be backed up, and how to restore it. Scheduling, retention and where copies live are yours to choose; this is
the contract they must satisfy.

## Stakes

The `kratos` and `hydra` databases hold every passkey enrolment, session and recovery-code state, the Hydra OAuth2
clients (secrets hashed) and its signing keys (private keys and session data encrypted at rest under
`HYDRA_SYSTEM_SECRET`). Without a backup every member re-enrols and every client is re-created. Without the secrets, a
restore cannot decrypt. Keep `KRATOS_CIPHER_SECRET_CURRENT` in `secrets.env` too; it covers only upstream-provider tokens and OIDC flow state, so nothing in this stack depends on it, but an adopter who enables a provider does.

## What to back up

1. **Both databases** with `pg_dump` in custom format, taken together. The example deployment keeps them in one volume
   (`postgres-data`), which holds every credential; a copy of that volume or a dump of both databases is the backup.
   In the example stack, `just backup <dir>` writes `kratos.dump` and `hydra.dump` there.
2. **`secrets.env`**, stored with the dump but not inside it. It carries the system and cipher secrets and the cookie
   secrets, and it is the only copy.
3. **At least one copy off the host.**
4. **A restore you have tried**, into a throwaway stack: one identity signs in, one OIDC client issues a token, and a
   passkey still signs in.

## Restore

1. Put `secrets.env` back first, then restore both databases from the most recent compatible pair of dumps.
2. Restart Kratos and Hydra, then re-run client registration: Hydra's clients and their secrets come back as of the
   dump, so an app added or re-keyed since is missing or stale until the portal registers again.

   ```sh
   docker compose kill -s SIGHUP othala
   ```

   Confirm readiness (the portal reports 503 until its last registration pass succeeds):

   ```sh
   docker compose exec -T othala node -e "fetch('http://'+process.env.PORTAL_ADMIN_BIND_HOST+':4431/readyz').then(r=>process.exit(r.ok?0:1))"
   ```

3. Clear Hydra's remembered consent and login sessions so apps ask again, per subject through the Hydra admin API from
   the othala container: `DELETE /admin/oauth2/auth/sessions/consent?subject=<id>&all=true` and
   `DELETE /admin/oauth2/auth/sessions/login?subject=<id>`. For the whole instance:

   ```sql
   TRUNCATE hydra_oauth2_flow, hydra_oauth2_authentication_session CASCADE;
   ```

   This also drops in-flight flows and every issued token.
4. Sign out everywhere for every active member from their admin page. Each member signs in again at their next app
   visit.

## Drift between the two databases

The databases are written in separate transactions, so a backup between a Kratos write and its Hydra write restores
with an identity that has no remembered consent, or the reverse. Do not reconcile rows; restore a compatible pair and
run steps 2 to 4.

## Related

- `docs/runbooks/secrets-rotation.md`: the rotatable secrets.
- `docs/runbooks/admin-recovery.md`: recovery, which needs Postgres alive.

# secrets.system rotation (break-glass)

`secrets.system` is the symmetric key Hydra uses to encrypt its JWK private
keys and stored OAuth2 session data at rest in Postgres. (Client secrets are
hashed, not encrypted.) Do this only on known compromise of the key (secret-store
exposure, a leak to a chat, log or commit); no cadence is required.

## Why this rebuilds the database

Ory itself rotates this secret in place: a `[new, old]` list encrypts with the
first entry and decrypts with all of them. Othala renders a single entry from
`HYDRA_SYSTEM_SECRET` (no `_PREVIOUS`), so a new value cannot read what the old
one wrote. The procedure therefore rebuilds the Hydra database.

## What rotation costs

- The encrypted JWK private keys and session data become unreadable, so the
  database is rebuilt; the in-app registrar re-creates each client from the
  manifests.
- Outstanding tokens, grants and in-flight consent flows are lost; users
  mid-flow retry and sign in again.
- Hydra's id_token signing keys do not survive; the rebuilt database mints new ones.

A brief disruption, best in a low-traffic window.

## Procedure

Prerequisites: shell on the host and write access to your secret store.

1. Generate the new secret: `openssl rand -base64 48`.
2. Store it as the Hydra system secret in your secret store.
3. Stop Hydra and its migrate unit.
4. Drop and recreate the Hydra database:

   ```sh
   docker compose exec postgres psql -U postgres -c \
     "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   ```

5. Re-provision the host secrets so the new value lands, using your deploy tooling.
6. Run the Hydra migration, then start Hydra, in that order: Postgres, migration
   (which populates a fresh schema under the new secret), Hydra.
7. Re-register the clients: the registrar runs inside othala, so restart it or
   send `docker compose kill -s SIGHUP othala`; it re-creates each Hydra client
   from the manifests with its `<SLUG>_CLIENT_SECRET`.
8. If any `<slug>_oidc_client_secret` changed, update and redeploy each affected app.
9. Verify an OIDC flow end to end.

## Verification

- The othala log shows `reconcile complete` with every manifest processed.
- A test login through an OIDC client completes.
- Hydra logs show no decryption errors.
- The secret store holds only the new system secret.

## Not covered

- Kratos cookie and cipher rotation: `cookie-rotation.md`.
- id_token and back-channel-logout signing keys: rotate by adding a key to the
  set through Hydra's `/admin/keys/{set}`; they do not involve `secrets.system`,
  and the app holds no signing key.
- Postgres credential rotation: stop the substrate, rotate the password,
  redeploy. No rebuild, since the password is independent of at-rest encryption.

## Related

- `hydra/hydra.yml` `secrets.system`
- `docs/runbooks/cookie-rotation.md`
- `docs/runbooks/admin-recovery.md`

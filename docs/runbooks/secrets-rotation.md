# secrets.system rotation (break-glass)

`secrets.system` is the symmetric key Hydra uses to encrypt its JWK private
keys and stored OAuth2 session data at rest in Postgres. (Client secrets are
hashed, not encrypted.) Rotation rebuilds the Hydra
database; do it only on known compromise of the key (sops file or age key
exposure, a leak to a chat, log or commit). No cadence is required: Hydra
treats this key like a database master key, not a session cookie.

## What rotation costs

- The encrypted JWK private keys and session data become unreadable, so the
  database is rebuilt; the in-app registrar re-creates each client from the
  manifests.
- Outstanding tokens, grants and in-flight consent flows are lost; users
  mid-flow retry and sign in again.
- Hydra's id_token signing keys do not survive; the rebuilt database mints new ones.

A brief disruption, best in a low-traffic window.

## Procedure

Prerequisites: shell on the host, and sops with the age key
(`SOPS_AGE_KEY_FILE`).

1. Generate the new secret: `openssl rand -base64 48`.
2. Set the `hydra_system_secret` entry in your sops file to it.
3. Stop Hydra and its migrate unit.
4. Drop and recreate the Hydra database:

   ```sh
   podman exec -it <postgres-container> psql -U postgres -c \
     "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   ```

5. Re-provision the host secrets so the new value lands, using your deploy tooling.
6. Run the Hydra migration, then start Hydra, in that order: Postgres, migration
   (which populates a fresh schema under the new secret), Hydra.
7. Run the Othala registrar as a `--rm` one-shot; it re-creates each Hydra
   client from the manifests with its `<SLUG>_CLIENT_SECRET`.
8. If any `<slug>_oidc_client_secret` changed, update and redeploy each affected app.
9. Verify an OIDC flow end to end.

## Verification

- The registrar exited 0 for every manifest.
- A test login through an OIDC client completes.
- Hydra logs show no decryption errors.
- The sops file holds only the new `hydra_system_secret`.

## Not covered

- Kratos cookie and cipher rotation: `cookie-rotation.md`.
- id_token and back-channel-logout signing keys: Hydra's `/admin/keys/.../rotate`
  rotates them without touching `secrets.system`; Hydra signs natively, so the
  app holds no signing key.
- Postgres credential rotation: stop the substrate, rotate the password,
  redeploy. No rebuild, since the password is independent of at-rest encryption.

## Related

- `hydra/hydra.yml` `secrets.system`
- `docs/runbooks/cookie-rotation.md`
- `docs/runbooks/admin-recovery.md`

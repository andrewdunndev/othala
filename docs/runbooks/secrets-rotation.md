# secrets.system rotation (break-glass)

`secrets.system` is the symmetric key Hydra uses to encrypt OAuth2
client secrets and consent challenges at rest in Postgres. Rotation is
a database-rebuild operation, not a periodic maintenance task. Run
this only on a known compromise of the key (Bitwarden vault breach,
on-disk leak, accidental commit).

## When to rotate

- The Bitwarden entry holding `HYDRA_SYSTEM_SECRET` was accessed by an
  unexpected party.
- The value appeared in a chat / log / commit and you cannot guarantee
  it never reached a third party.
- A planned-rotation cadence is NOT required at family scale. Hydra's
  threat model treats this key like a database master key, not a
  session cookie.

## What rotation costs

- Every Hydra-stored OAuth2 client secret becomes unreadable. Apps
  re-receive new client_secret values via `apply-clients.sh`.
- Outstanding consent challenges (in-flight OAuth2 flows) become
  invalid. Users mid-flow see an error and re-attempt.
- Hydra's signing keys (id_token JWKS) are unaffected; they live in a
  different table and use a different key.

So rotation is a brief disruption, not a multi-day migration. Family
schedule it for a low-traffic window.

## Procedure

Prereqs: SSH access to carmine + sudo + Bitwarden access.

1. Generate the new secret (32+ bytes, random):

   ```sh
   openssl rand -base64 48
   ```

2. Update Bitwarden: replace `HYDRA_SYSTEM_SECRET` with the new value.

3. Stop Hydra:

   ```sh
   sudo systemctl stop hydra.service
   ```

4. Drop and recreate the Hydra schema (Postgres-side):

   ```sh
   sudo podman exec -it auth-postgres psql -U postgres -c \
     "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   ```

5. Re-run the Hydra migration to populate the schema under the new
   secret:

   ```sh
   sudo systemctl start hydra-migrate.service
   ```

   Wait for it to exit cleanly.

6. Push the new secret to the Hydra quadlet:

   ```sh
   sudo systemctl edit hydra.service
   # set HYDRA_SYSTEM_SECRET=<new value>
   sudo systemctl daemon-reload
   sudo systemctl start hydra.service
   ```

7. Re-issue every client secret. From `auth/`:

   ```sh
   make -C hydra apply-clients
   ```

   This walks `hydra/clients/*.yaml` and re-creates each client with
   the new secret.

8. Update each app's `<APP>_CLIENT_SECRET` env from the new
   apply-clients output. Apps that don't pick up env changes need a
   pod restart.

9. Bump the SIGUSR1 on the consent service (the back-channel logout
   signing key cache holds the old key for up to 15 min; SIGUSR1
   skips the wait):

   ```sh
   sudo podman exec auth-consent kill -USR1 1
   ```

10. Verify a known OIDC flow end-to-end (login at home.dunn.dev →
    keep.dunn.dev signin) before clearing the runbook.

## Verification

After rotation:

- `apply-clients` exited 0 for every yaml in `hydra/clients/`.
- A test login through Vaultwarden (or any OIDC client) completes.
- Hydra logs show no decryption errors.
- The Bitwarden vault has only the new `HYDRA_SYSTEM_SECRET` entry;
  the old one is deleted.

## What this does NOT cover

- Kratos cookie/cipher rotation. See `cookie-rotation.md`.
- id_token signing key rotation. Hydra's `/admin/keys/.../rotate`
  handles that without touching `secrets.system`. The consent
  service's signing-key cache picks up the new key on next refresh
  (15 min) or on SIGUSR1.
- Postgres credential rotation. Separate procedure, separate
  Bitwarden entry.

## Related

- `docs/architecture.md` "A2: secrets.system single-key risk"
- `docs/runbooks/cookie-rotation.md`
- `hydra/hydra.yml` `secrets.system` field

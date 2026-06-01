# secrets.system rotation (break-glass)

`secrets.system` is the symmetric key Hydra uses to encrypt OAuth2
client secrets and consent challenges at rest in Postgres. Rotation is
a database-rebuild operation, not a periodic maintenance task. Run
this only on a known compromise of the key (sops file or age key
exposure, on-disk leak, accidental commit).

## When to rotate

- The sops entry `carmine.hydra_system_secret` was accessed by an
  unexpected party, OR the age private key (`~/.config/sops/age/keys.txt`
  on the operator workstation) was exposed.
- The value appeared in a chat / log / commit and you cannot guarantee
  it never reached a third party.
- A planned-rotation cadence is NOT required at family scale. Hydra's
  threat model treats this key like a database master key, not a
  session cookie.

## What rotation costs

- Every Hydra-stored OAuth2 client secret becomes unreadable. Apps
  re-receive new client_secret values via the `auth-util` container
  running `apply-clients.sh`.
- Outstanding consent challenges (in-flight OAuth2 flows) become
  invalid. Users mid-flow see an error and re-attempt.
- Hydra's signing keys (id_token JWKS) are unaffected; they live in a
  different table and use a different key.

So rotation is a brief disruption, not a multi-day migration. Family
schedule it for a low-traffic window.

## Procedure

Prereqs: SSH access to carmine + sudo + sops+age access on the operator
workstation (`SOPS_AGE_KEY_FILE` pointing at the age private key).

1. Generate the new secret (32+ bytes, random):

   ```sh
   openssl rand -base64 48
   ```

2. Update sops:

   ```sh
   sops dunn.dev/iac/pyinfra/secrets.enc.yaml
   # Set carmine.hydra_system_secret to the new value.
   ```

3. Stop Hydra on carmine:

   ```sh
   ssh agd@carmine.dunn.dev 'systemctl --user stop auth-hydra.service'
   ```

4. Drop and recreate the Hydra schema (Postgres-side):

   ```sh
   ssh agd@carmine.dunn.dev '
     systemctl --user stop auth-hydra-migrate.service;
     podman exec -it auth-postgres psql -U postgres -c \
       "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   '
   ```

5. Re-provision podman secrets on carmine so the new sops value lands:

   ```sh
   cd dunn.dev/iac
   make auth-secrets HOST=carmine
   ```

6. Re-run the Hydra migration + restart Hydra:

   ```sh
   cd dunn.dev/iac
   make auth-deploy HOST=carmine
   ```

   The deploy restarts auth-postgres, auth-hydra-migrate (populates
   fresh schema under the new secret), and auth-hydra.

7. Re-issue every client secret:

   ```sh
   cd dunn.dev/iac
   make auth-apply-clients HOST=carmine
   ```

   This runs the `auth-util` oneshot container which walks
   `hydra/clients/*.yaml` and re-creates each Hydra client with its
   sops-sourced `<svc>_oidc_client_secret`.

8. Update consumer-service podman secrets if any `<svc>_oidc_client_secret`
   changed:

   ```sh
   cd dunn.dev/iac
   make keep-secrets HOST=carmine
   make keep-deploy HOST=carmine
   # ...repeat for each OIDC consumer that needs to pick up a new secret.
   ```

9. Force the consent service to drop its cached signing key (the
   back-channel logout signing key cache holds the old key for up to
   15 min; SIGUSR1 forces refresh):

   ```sh
   ssh agd@carmine.dunn.dev 'podman exec auth-consent kill -USR1 1'
   ```

10. Verify a known OIDC flow end-to-end (login at dag.dunn.dev →
    keep.dunn.dev signin) before clearing the runbook. Or run:

    ```sh
    cd dunn.dev/iac
    make auth-smoke HOST=carmine
    ```

## Verification

After rotation:

- `make auth-apply-clients` exited 0 for every yaml in `hydra/clients/`.
- A test login through Vaultwarden (or any OIDC client) completes.
- Hydra logs show no decryption errors: `journalctl --user -u auth-hydra.service -n 50`.
- The sops file has only the new `carmine.hydra_system_secret` value.

## What this does NOT cover

- Kratos cookie/cipher rotation. See `cookie-rotation.md`.
- id_token signing key rotation. Hydra's `/admin/keys/.../rotate`
  handles that without touching `secrets.system`. The consent
  service's signing-key cache picks up the new key on next refresh
  (15 min) or on SIGUSR1.
- Postgres credential rotation (the `carmine.auth_db_password` sops
  entry). Separate procedure: stop the substrate, rotate the password,
  re-deploy. No db rebuild needed since the password is independent
  of at-rest encryption.

## Related

- `ARCHITECTURE.md` "LB-3: `secrets.system` is non-rotatable"
- `docs/runbooks/cookie-rotation.md`
- `docs/runbooks/admin-recovery.md`
- `hydra/hydra.yml` `secrets.system` field
- `dunn.dev/iac/services/auth/` — deploy plane

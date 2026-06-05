# secrets.system rotation (break-glass)

`secrets.system` is the symmetric key Hydra uses to encrypt OAuth2
client secrets and consent challenges at rest in Postgres. Rotation is
a database-rebuild operation, not a periodic maintenance task. Run
this only on a known compromise of the key (sops file or age key
exposure, on-disk leak, accidental commit).

## When to rotate

- The sops entry for `hydra_system_secret` was accessed by an
  unexpected party, OR the age private key (`~/.config/sops/age/keys.txt`
  on the operator workstation) was exposed.
- The value appeared in a chat / log / commit and you cannot guarantee
  it never reached a third party.
- A planned-rotation cadence is NOT required at family scale. Hydra's
  threat model treats this key like a database master key, not a
  session cookie.

## What rotation costs

- Every Hydra-stored OAuth2 client secret becomes unreadable. Apps
  re-receive new client_secret values when the in-app registrar re-runs
  (`make dag-apply-clients`).
- Outstanding consent challenges (in-flight OAuth2 flows) become
  invalid. Users mid-flow see an error and re-attempt.
- Hydra's signing keys (id_token JWKS) are unaffected; they live in a
  different table and use a different key.

So rotation is a brief disruption, not a multi-day migration. Family
schedule it for a low-traffic window.

## Procedure

Prereqs: SSH access to the SSO host + sudo + sops+age access on the
operator workstation (`SOPS_AGE_KEY_FILE` pointing at the age private
key).

1. Generate the new secret (32+ bytes, random):

   ```sh
   openssl rand -base64 48
   ```

2. Update sops:

   ```sh
   sops <your-deploy-repo>/pyinfra/secrets.enc.yaml
   # Set the hydra_system_secret entry to the new value.
   ```

3. Stop Hydra on the SSO host:

   ```sh
   ssh <operator>@<sso-host> 'systemctl --user stop dag-hydra.service'
   ```

4. Drop and recreate the Hydra schema (Postgres-side):

   ```sh
   ssh <operator>@<sso-host> '
     systemctl --user stop dag-hydra-migrate.service;
     podman exec -it dag-postgres psql -U postgres -c \
       "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   '
   ```

5. Re-provision podman secrets on the SSO host so the new sops value lands:

   ```sh
   # using your operator tooling, e.g.:
   make dag-secrets HOST=<sso-host>
   ```

6. Re-run the Hydra migration + restart Hydra:

   ```sh
   make dag-deploy HOST=<sso-host>
   ```

   The deploy restarts dag-postgres, dag-hydra-migrate (populates
   fresh schema under the new secret), and dag-hydra.

7. Re-issue every client secret:

   ```sh
   make dag-apply-clients HOST=<sso-host>
   ```

   This runs the Othala in-app registrar as a `--rm` one-shot, which
   walks the manifests in `MANIFEST_DIR` and re-creates each Hydra client
   with its sops-sourced `<SLUG>_CLIENT_SECRET`.

8. Update consumer-service podman secrets if any `<slug>_oidc_client_secret`
   changed, then redeploy each affected consumer (operator-side, e.g.
   `make <consumer>-secrets HOST=<sso-host> && make <consumer>-deploy HOST=<sso-host>`).

9. Verify a known OIDC flow end-to-end before clearing the runbook:

   ```sh
   make dag-smoke HOST=<sso-host>
   ```

## Verification

After rotation:

- `make dag-apply-clients` exited 0 for every manifest in `MANIFEST_DIR`.
- A test login through any OIDC client completes.
- Hydra logs show no decryption errors: `journalctl --user -u dag-hydra.service -n 50`.
- The sops file has only the new `hydra_system_secret` value.

## What this does NOT cover

- Kratos cookie/cipher rotation. See `cookie-rotation.md`.
- id_token + back-channel-logout signing key rotation. Hydra's
  `/admin/keys/.../rotate` handles that without touching
  `secrets.system`; Hydra signs natively, so the Othala app holds no
  signing key at rest and there is no app-side cache to refresh.
- Postgres credential rotation (the `dag_db_password` sops entry).
  Separate procedure: stop the substrate, rotate the password,
  re-deploy. No db rebuild needed since the password is independent
  of at-rest encryption.

## Related

- `ARCHITECTURE.md` "LB-3: `secrets.system` is non-rotatable"
- `docs/runbooks/cookie-rotation.md`
- `docs/runbooks/admin-recovery.md`
- `hydra/hydra.yml` `secrets.system` field
- the deploy repo's `services/dag/` — deploy plane

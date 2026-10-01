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
  re-receive new client_secret values when the in-app registrar re-runs.
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
   ssh <operator>@<sso-host> 'systemctl --user stop <hydra-unit>'
   ```

4. Drop and recreate the Hydra schema (Postgres-side):

   ```sh
   ssh <operator>@<sso-host> '
     systemctl --user stop <hydra-migrate-unit>;
     podman exec -it <postgres-container> psql -U postgres -c \
       "DROP DATABASE hydra; CREATE DATABASE hydra OWNER hydra;"
   '
   ```

5. Re-provision podman secrets on the SSO host so the new sops value lands,
   using your deploy tooling.

6. Re-run the Hydra migration and restart the substrate, again with your
   deploy tooling. Order matters: Postgres up, then the migration (which
   populates a fresh schema under the new secret), then Hydra.

7. Re-issue every client secret by running the Othala in-app registrar as a
   `--rm` one-shot. It walks the manifests and re-creates
   each Hydra client with its sops-sourced `<SLUG>_CLIENT_SECRET`.

8. Update consumer-service podman secrets if any `<slug>_oidc_client_secret`
   changed, then redeploy each affected consumer (operator-side, e.g.
   `make <consumer>-secrets HOST=<sso-host> && make <consumer>-deploy HOST=<sso-host>`).

9. Verify a known OIDC flow end-to-end, via your deployment's smoke suite,
   before clearing the runbook.

## Verification

After rotation:

- The registrar one-shot exited 0 for every manifest.
- A test login through any OIDC client completes.
- Hydra logs show no decryption errors:
  `journalctl --user -u <hydra-unit> -n 50`.
- The sops file has only the new `hydra_system_secret` value.

## What this does NOT cover

- Kratos cookie/cipher rotation. See `cookie-rotation.md`.
- id_token + back-channel-logout signing key rotation. Hydra's
  `/admin/keys/.../rotate` handles that without touching
  `secrets.system`; Hydra signs natively, so the Othala app holds no
  signing key at rest and there is no app-side cache to refresh.
- Postgres credential rotation (the database-password sops entry).
  Separate procedure: stop the substrate, rotate the password,
  re-deploy. No db rebuild needed since the password is independent
  of at-rest encryption.

## Related

- `ARCHITECTURE.md` "LB-3: `secrets.system` is non-rotatable"
- `docs/runbooks/cookie-rotation.md`
- `docs/runbooks/admin-recovery.md`
- `hydra/hydra.yml` `secrets.system` field

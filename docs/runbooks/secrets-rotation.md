# secrets.system rotation

`secrets.system` is the symmetric key Hydra uses to encrypt its JWK private
keys and stored OAuth2 session data at rest in Postgres. (Client secrets are
hashed, not encrypted.) Rotate on known compromise of the key (secret-store
exposure, a leak to a chat, log or commit); no cadence is required.

## Procedure

1. Generate the new secret: `openssl rand -base64 48`.
2. Set it as `HYDRA_SYSTEM_SECRET` and the old value as `HYDRA_SYSTEM_SECRET_PREVIOUS`.
3. Recreate: `docker compose up -d --force-recreate render kratos hydra othala caddy`.
4. Verify an OIDC flow end to end; Hydra logs show no decryption errors.

Keep `_PREVIOUS`: Hydra's JWKs stay encrypted under the key that created them,
so drop it only after the stored keys and tokens that predate the rotation are
gone or re-created.

## Not covered

- Kratos cookie and cipher rotation: `cookie-rotation.md`.
- id_token and back-channel-logout signing keys: rotate by adding a key to the
  set through Hydra's `/admin/keys/{set}`; they do not involve `secrets.system`,
  and the app holds no signing key.
- Postgres credential rotation: stop the substrate, rotate the password,
  redeploy. No rebuild, since the password is independent of at-rest encryption.

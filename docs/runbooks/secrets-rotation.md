# secrets.system rotation

`secrets.system` is the symmetric key Hydra uses to encrypt its JWK private
keys and stored OAuth2 session data at rest in Postgres. (Client secrets are
hashed, not encrypted.) Rotate on known compromise of the key (secret-store
exposure, a leak to a chat, log or commit); no cadence is required.

## Procedure

1. Generate the new secret: `openssl rand -base64 48`.
2. Set it as `HYDRA_SYSTEM_SECRET` and the old value as `HYDRA_SYSTEM_SECRET_PREVIOUS`, then recreate: `docker compose up -d --force-recreate render kratos hydra othala caddy`.
3. Delete the ID-token key set so Hydra re-creates it under the new secret:
   `docker compose exec -T othala node -e "fetch('http://hydra:4445/admin/keys/hydra.openid.id-token',{method:'DELETE'}).then(r=>{console.log(r.status);process.exit(r.ok?0:1)})"`
4. Confirm `/.well-known/jwks.json` lists a key and an OIDC flow works end to end.
5. Drop `HYDRA_SYSTEM_SECRET_PREVIOUS` and recreate as in step 2.

Session data is encrypted at rest, so dropping `HYDRA_SYSTEM_SECRET_PREVIOUS` makes
anything still encrypted under the old secret unreadable: refresh tokens stop working and those members sign in again. After a compromise, drop it
at once. To rotate without signing anyone out, keep it until the longest token
lifetime (`ttl.refresh_token` in `hydra.yml`) has passed.

Hydra keeps its stored keys encrypted under the secret that created them, and
stays healthy while unable to read them. ID tokens signed by the old keys no
longer verify, so relying parties re-fetch the JWKS.

## Not covered

- Kratos cookie and cipher rotation: `cookie-rotation.md`.
- id_token and back-channel-logout signing keys: rotate by adding a key to the
  set through Hydra's `/admin/keys/{set}`; they do not involve `secrets.system`,
  and the app holds no signing key.
- Postgres credential rotation: stop the substrate, rotate the password,
  redeploy. No rebuild, since the password is independent of at-rest encryption.

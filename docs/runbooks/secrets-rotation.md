# Secret rotation

Rotates the Kratos and Hydra cookie secrets, the Kratos cipher secret and the Hydra system secret. It is one
procedure: each secret takes an optional `<NAME>_PREVIOUS`, and a rotation sets the new value as `_CURRENT`, the old
one as `_PREVIOUS`, and later drops `_PREVIOUS`. Rotate on a suspected leak, an operator handover or an incident that
may have exposed one; no cadence is required.

| Secret | Generate | Length | Drop `_PREVIOUS` |
|---|---|---|---|
| `KRATOS_COOKIE_SECRET` | `openssl rand -hex 16` | 16, 24 or 32 characters each; never shorter than 16 | after the longest session lifetime; after a leak, as soon as in-flight flows finish |
| `KRATOS_CIPHER_SECRET` | `openssl rand -hex 16` | exactly 32 | at once; it covers only upstream-provider tokens and OIDC flow state, and no provider is enabled |
| `HYDRA_COOKIE_SECRET` | `openssl rand -hex 16` | at least 16 characters | after the longest session lifetime |
| `HYDRA_SYSTEM_SECRET` | `openssl rand -base64 48` | at least 16 characters | after the longest refresh-token lifetime (`ttl.refresh_token` in `hydra.yml`); after a compromise, at once |

Kratos session cookies verify under both entries, but its continuity cookies (settings flows in progress) use the pair
as one key, signed with the first and encrypted with the second. A Kratos cookie pair must therefore be 16, 24 or 32
characters per entry: a 64-character pair fails those flows with `crypto/aes: invalid key size 64`. A deployment still
on a 64-character Kratos cookie secret first rotates once, single-slot, to a 32-character one, which signs members out.
A `_PREVIOUS` equal to its `_CURRENT` is refused too. `check` with the new values in the environment reports every refusal before anything is rendered.

An adopter who enables an upstream provider keeps `KRATOS_CIPHER_SECRET_PREVIOUS` until those members have signed in again through it.

## Procedure

1. Generate the new value, then in your secret store set it as `_CURRENT` and the old one as `_PREVIOUS`.
2. Recreate what reads it (`restart` does not re-render):
   `docker compose up -d --force-recreate render kratos hydra othala caddy`. Confirm the render step exited 0
   (`docker compose ps -a render` shows `Exited (0)`): a refusal exits 1 and leaves the earlier render serving, so
   the new secrets are not in effect.
3. For `HYDRA_SYSTEM_SECRET` only, delete the ID-token key set so Hydra re-creates it under the new secret:
   `docker compose exec -T othala node -e "fetch('http://hydra:4445/admin/keys/hydra.openid.id-token',{method:'DELETE'}).then(r=>{console.log(r.status);process.exit(r.ok?0:1)})"`
   Confirm `/.well-known/jwks.json` lists a key and an OIDC flow works end to end. ID tokens signed by the old keys
   stop verifying, so apps re-fetch the JWKS.
4. Check readiness, then your smoke suite. Members stay signed in.

   ```sh
   docker compose exec -T othala node -e "fetch('http://'+process.env.PORTAL_ADMIN_BIND_HOST+':4431/readyz').then(r=>process.exit(r.ok?0:1))"
   ```

5. Drop each `_PREVIOUS` when the table says, and recreate as in step 2. Dropping early signs out sessions not yet
   re-issued and interrupts settings flows in progress; dropping `HYDRA_SYSTEM_SECRET_PREVIOUS` makes anything still
   encrypted under the old secret unreadable, so refresh tokens stop working and those members sign in again. Hydra
   stays healthy while it cannot read them.

If Kratos or Hydra refuses to start, a secret rendered empty or the wrong length; restore it from your secret store.
Members bounced to login means a `_PREVIOUS` was dropped early or never set.

## Not covered

- ID-token and back-channel-logout signing keys: add a key to the set through Hydra's `/admin/keys/{set}`. They do
  not involve `HYDRA_SYSTEM_SECRET`, and the app holds no signing key.
- Postgres credentials: stop the stack, rotate the password and redeploy. It is independent of at-rest encryption.
- `node dist/server/config.mjs gen-secrets` mints a fresh `_CURRENT` for each secret.

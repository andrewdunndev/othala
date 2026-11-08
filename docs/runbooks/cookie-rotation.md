# Cookie / cipher secret rotation

Rotates the Kratos and Hydra cookie secrets and the Kratos cipher (at-rest
encryption) secret without signing members out.

## When

Quarterly, or on a suspected leak, operator handover, or an incident where the
secret may have been exposed. For the Hydra system secret see
`secrets-rotation.md`.

## How it works

Each secret takes an optional `<NAME>_PREVIOUS` (`KRATOS_COOKIE_SECRET_PREVIOUS`,
`KRATOS_CIPHER_SECRET_PREVIOUS`, `HYDRA_COOKIE_SECRET_PREVIOUS`). Unset, one entry
renders; set, `[current, previous]` renders. Kratos session cookies verify and
decrypt under both entries, but its continuity cookies (sign-in and recovery
flows in progress) use the pair as one key: signed with the first, encrypted
with the second. So a Kratos cookie pair must be 16, 24 or 32 characters per
entry (a 64-character pair fails continuity flows with `crypto/aes: invalid key
size 64`); the cipher is exactly 32. A deployment still on a 64-character Kratos
cookie secret first rotates once, single-slot, to a 32-character one; that
rotation signs members out.

## Procedure

1. Generate each new secret with `openssl rand -hex 16` (32 characters).
2. In your secret store (lab: `e2e/secrets.env`) set the new value as
   `_CURRENT` and the old one as `_PREVIOUS`.
3. Recreate what reads it (`restart` does not re-render):
   `docker compose up -d --force-recreate render kratos hydra othala caddy`.
4. Verify readiness from the compose directory:

   ```sh
   docker compose exec -T othala node -e "fetch('http://'+process.env.PORTAL_ADMIN_BIND_HOST+':4431/readyz').then(r=>process.exit(r.ok?0:1))"
   ```

   then your smoke suite. Members stay signed in.
5. After the longest session lifetime, remove the cookie `_PREVIOUS` values and recreate again. After a suspected leak, remove the Kratos one as soon as in-flight flows finish: while set, the previous secret encrypts continuity cookies. Keep `KRATOS_CIPHER_SECRET_PREVIOUS` until members have signed in again through their upstream provider.

## Failure modes

- **Kratos or Hydra refuses to start:** a secret rendered empty or the wrong
  length. Restore from your secret store.
- **Sessions bounced to login:** a `_PREVIOUS` was dropped early or never set.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `node dist/server/config.mjs gen-secrets`: mints a fresh `_CURRENT` per secret.

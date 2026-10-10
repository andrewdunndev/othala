# Cookie / cipher secret rotation

Rotates the Kratos and Hydra cookie signing secrets and the Kratos cipher
(at-rest credential encryption) secret without invalidating active sessions.

## When

Quarterly, or on a suspected leak, operator handover, or an incident where the
secret may have been exposed.

`HYDRA_SYSTEM_SECRET` is non-rotatable for the life of the Hydra database; do
not touch it here (see `hydra/hydra.yml`).

## Single-slot model

Kratos `secrets.cookie` and `secrets.cipher` and Hydra `secrets.cookie` accept
a list: the first entry signs, every entry verifies. Ory enforces
`uniqueItems` on these arrays, so there is one active `_CURRENT` value per
secret at rest (`KRATOS_COOKIE_SECRET_CURRENT`, `KRATOS_CIPHER_SECRET_CURRENT`,
`HYDRA_COOKIE_SECRET_CURRENT`; no `_PREVIOUS`). Rotation prepends the new value
to the YAML list; the old one stays as a secondary verifier until every cookie
minted under it has expired, then is removed.

## Procedure

1. Generate a secret: `openssl rand -hex 32`.
2. Set it in your sops file (production) or `e2e/.env` (lab) as the single
   `_CURRENT` value.
3. Restart Kratos and Hydra (lab: `podman compose restart kratos hydra`;
   production: re-provision secrets and redeploy).
4. Verify health: `curl -fsS https://<your-othala-host>/health/ready`, then
   your smoke suite. Active sessions stay valid, since the old value still
   verifies; a fresh sign-in carries a `Set-Cookie` with a new MAC.
5. Wait out the session lifespan: Kratos 30 days (720h), with admin
   re-authentication at AAL2 daily; Hydra 30 days (`ttl.refresh_token`).
6. Remove the old value from the Kratos and Hydra `secrets.*` lists and from
   sops (or `.env`), leaving only the new `_CURRENT`, and restart again.

## Failure modes

- **Old entry dropped before sessions expire:** every active session is
  bounced to login. A UX hit, not a security regression.
- **Empty secrets list:** Kratos and Hydra refuse to start. Restore from the
  operator store.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `e2e/gen-secrets.sh`: mints a fresh `_CURRENT` per secret.

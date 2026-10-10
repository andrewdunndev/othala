# Cookie / cipher secret rotation

Rotates the Kratos and Hydra cookie signing secrets and the Kratos cipher
(at-rest encryption) secret. Rotation logs every member out.

## When

Quarterly, or on a suspected leak, operator handover, or an incident where the
secret may have been exposed.

`HYDRA_SYSTEM_SECRET` is non-rotatable for the life of the Hydra database; do
not touch it here (see `hydra/hydra.yml`).

## Single-slot model

Ory accepts a list for Kratos `secrets.cookie` and `secrets.cipher` and Hydra
`secrets.cookie` (the first entry signs, every entry verifies), but enforces
`uniqueItems`, and the shipped config renders exactly one entry from one
`_CURRENT` value per secret (`KRATOS_COOKIE_SECRET_CURRENT`,
`KRATOS_CIPHER_SECRET_CURRENT`, `HYDRA_COOKIE_SECRET_CURRENT`; no
`_PREVIOUS`). The old value therefore cannot stay as a verifier: rotation
replaces it, and every session and flow cookie signed under it stops
verifying.

## Procedure

1. Generate a secret: `openssl rand -hex 32`.
2. Set it in your sops file (production) or `e2e/.env` (lab) as the single
   `_CURRENT` value.
3. Restart Kratos and Hydra (lab: `podman compose restart kratos hydra`;
   production: re-provision secrets and redeploy).
4. Verify health: `curl -fsS https://<your-othala-host>/health/ready`, then
   your smoke suite. Every member signs in again.

Rotating `secrets.cipher` also makes data Kratos encrypted under the old value
unreadable; rotate it only on suspected exposure.

## Failure modes

- **Sessions bounced to login after rotation:** expected, see above.
- **Empty secrets list:** Kratos and Hydra refuse to start. Restore from the
  operator store.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `e2e/gen-secrets.sh`: mints a fresh `_CURRENT` per secret.

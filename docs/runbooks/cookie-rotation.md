# Cookie / cipher secret rotation

Rotates the Kratos and Hydra cookie signing secrets and the Kratos cipher
(at-rest encryption) secret. As shipped, rotation logs every member out.

## When

Quarterly, or on a suspected leak, operator handover, or an incident where the
secret may have been exposed. For the Hydra system secret see
`secrets-rotation.md`.

## Single-slot rendering

Ory accepts a list for each of these secrets: the first entry signs or
encrypts, every entry verifies or decrypts, so `[new, old]` rotates without
logging anyone out (`uniqueItems` only rejects duplicates). A two-entry Kratos cookie list is untested with othala's 64-character cookie secrets; the continuity cookie needs 16, 24 or 32 characters. Othala renders one
entry from one `_CURRENT` value per secret (`KRATOS_COOKIE_SECRET_CURRENT`,
`KRATOS_CIPHER_SECRET_CURRENT`, `HYDRA_COOKIE_SECRET_CURRENT`; no `_PREVIOUS`),
so the old value stops verifying: every session and flow cookie signed under
it is rejected, and rotating the cipher drops the OIDC upstream tokens Kratos
stored under the old value.

## Procedure

1. Generate the cookie secrets with `openssl rand -hex 32` and the cipher
   secret with `openssl rand -hex 16`; Kratos requires exactly 32 characters
   for the cipher.
2. Set each as the single `_CURRENT` value in your secret store (lab:
   `e2e/secrets.env`).
3. Restart Kratos and Hydra (lab: `docker compose restart kratos hydra`;
   deployed: re-provision secrets and redeploy).
4. Verify readiness from the compose directory:

   ```sh
   docker compose exec -T othala node -e "fetch('http://'+process.env.PORTAL_ADMIN_BIND_HOST+':4431/readyz').then(r=>process.exit(r.ok?0:1))"
   ```

   then your smoke suite. Every member signs in again.

## Failure modes

- **Sessions bounced to login after rotation:** expected, see above.
- **Kratos or Hydra refuses to start:** a secret rendered empty or too short
  (cipher: not exactly 32 characters). Restore from your secret store.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `node dist/server/config.mjs gen-secrets`: mints a fresh `_CURRENT` per secret.

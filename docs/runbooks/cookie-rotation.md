# Cookie / cipher secret rotation

Rotates the Kratos and Hydra cookie signing secrets and the Kratos
cipher (at-rest credential encryption) secret without invalidating
active sessions.

## When

- Quarterly, or sooner on any of:
  - Suspected leak (env-file disclosure, host compromise)
  - Operator handover
  - Incident closeout where the secret was potentially exposed

## What stays the same forever

`HYDRA_SYSTEM_SECRET` is non-rotatable for the life of the Hydra
database. Do not touch it during cookie rotation. See `hydra/hydra.yml`
header comment.

## Single-slot model (collapsed key)

Both Kratos `secrets.cookie` and `secrets.cipher`, plus Hydra
`secrets.cookie`, accept a list of values. The first entry signs new
material; every entry in the list verifies.

Ory v26.2.0 enforces `uniqueItems` on these arrays, which rules out a
two-identical-slot approach. Production collapses the rotation model to
a **single active `_CURRENT` key per secret** (`gen-secrets.sh` mints
one value per slot — no `_PREVIOUS` at rest). Rotation works by
prepending a new `_CURRENT` directly into the YAML list in the Kratos
and Hydra config; the old value remains in the list as a secondary
verifier until all cookies minted under it have expired, then it is
removed. The `.env.example` and `gen-secrets.sh` reflect this: only
`KRATOS_COOKIE_SECRET_CURRENT`, `KRATOS_CIPHER_SECRET_CURRENT`, and
`HYDRA_COOKIE_SECRET_CURRENT` exist. There is no `_PREVIOUS` env var.

## Procedure

1. Generate a fresh secret:

   ```sh
   openssl rand -hex 32
   ```

2. Update sops (production) or `.env` (lab):

   Production (sops-backed operator repo, e.g. `dunn.dev/iac`):

   ```sh
   sops <your-iac-repo>/pyinfra/secrets.enc.yaml
   # Update auth_session_secret to the new value (single _CURRENT per
   # secret; no _PREVIOUS slot in the operator store).
   ```

   E2E harness (`e2e/.env`): only `_CURRENT` exists (no `_PREVIOUS`
   slot). Update the single value:

   ```diff
   -KRATOS_COOKIE_SECRET_CURRENT=<old value>
   +KRATOS_COOKIE_SECRET_CURRENT=<new value>
   ```

3. Restart Kratos and Hydra:
   - Lab: `podman compose restart kratos hydra`
   - Production: re-provision secrets and redeploy via your operator tooling
     (the secrets re-provision picks up the new value; redeploy restarts
     the substrate)

4. Verify both services healthy:

   ```sh
   curl -fsS https://<your-othala-host>/health/ready
   # run your operator smoke suite, e.g.: make dag-smoke HOST=<sso-host>
   ```

5. Active sessions: still valid. Existing cookies were signed with the
   old secret; verification still succeeds because the old value
   remains in the YAML list as a secondary verifier.

6. Wait for the session lifespan to elapse:
   - Kratos: 90 days for normal sessions, 1 day for admin enforcement
     (admin SSR forces re-auth at AAL2 daily).
   - Hydra: 30 days for refresh tokens (the ttl.refresh_token cap).

7. After the wait, no live cookie was minted under the old secret.
   Remove the old value from the Kratos and Hydra `secrets.*` YAML
   lists so only the new `_CURRENT` remains, then update sops (or
   `.env` for the lab) to match:

   ```sh
   # The kratos.yml / hydra.yml secrets.cookie list now has only one entry.
   sops <your-iac-repo>/pyinfra/secrets.enc.yaml
   # Remove the stale old value from auth_session_secret (or whichever
   # key feeds the list); only the value from step 1 should remain.
   ```

8. Restart again. The single-slot posture is restored; the old signing
   key is no longer in memory or config anywhere except the operator's
   archive.

## Validation

Sign in via home portal after step 3, observe the new cookie's
`Set-Cookie` header carrying a fresh MAC. The old session cookie is
honored until its own expiry.

## Failure modes

- **Restart with new CURRENT but old entry accidentally dropped from
  the list before sessions expire:** every active session gets bounced
  to login. UX hit, not a security regression.
- **Restart with the secrets list empty:** Kratos refuses to start
  (`secrets.cookie: at least one entry required`). Same for Hydra.
  Restore from operator store.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `e2e/gen-secrets.sh`: produces a fresh `_CURRENT` for each secret
  (no `_PREVIOUS` — single-slot / collapsed-key model).
- `docs/decision.md`: H4 "Hydra cookie-secret rotation" lock.

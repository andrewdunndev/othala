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

## Two-slot model

Both Kratos `secrets.cookie` and `secrets.cipher`, plus Hydra
`secrets.cookie`, accept a list of values. The first entry signs new
material; every entry in the list verifies. The convention used by this
repo:

```
SECRET_CURRENT  = active signing key (signs new cookies)
SECRET_PREVIOUS = secondary verification key
```

Both slots are populated with distinct values at all times. On first
provision, `gen-secrets.sh` mints two fresh secrets: `_CURRENT` is the
active signer; `_PREVIOUS` is a sentinel that becomes meaningful on
the first rotation (when it gets set to the prior `_CURRENT`).

Why not leave `_PREVIOUS` empty on first provision: Kratos and Hydra
reject empty list elements in `secrets.cookie` / `secrets.cipher` as
YAML schema violations after envsubst expansion. The two-distinct-secret
posture keeps the rendered config well-formed with no special-case
templating, and removes a class of "first deploy fails because the
runbook didn't account for it" bugs.

## Procedure

1. Generate a fresh secret:

   ```sh
   openssl rand -hex 32
   ```

2. Update sops (production) or `.env` (lab):

   Production (`dunn.dev/iac/pyinfra/secrets.enc.yaml`):

   Production (sops-backed operator repo, e.g. `dunn.dev/iac`):

   ```sh
   sops <your-iac-repo>/pyinfra/secrets.enc.yaml
   # Edit the auth_session_secret entry to the new value.
   # Substrate-secret model (v0.2.0): a single `auth_session_secret` key
   # feeds both _CURRENT and _PREVIOUS slots — rotation is a single
   # value swap; collapsing the two-slot semantic into one sops entry
   # is the homelab-scope simplification documented in
   # docs/golden-path.md "Substrate secret collapse" entry.
   ```

   Lab (`lab/.env`):

   ```diff
   -KRATOS_COOKIE_SECRET_PREVIOUS=
   +KRATOS_COOKIE_SECRET_PREVIOUS=<old current value>
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
   # run your operator smoke suite, e.g.: make auth-smoke HOST=<sso-host>
   ```

5. Active sessions: still valid. Existing cookies were signed with the
   old secret; verification still succeeds because `_PREVIOUS` is in
   the list.

6. Wait for the session lifespan to elapse:
   - Kratos: 90 days for normal sessions, 1 day for admin enforcement
     (admin SSR forces re-auth at AAL2 daily).
   - Hydra: 30 days for refresh tokens (the ttl.refresh_token cap).

7. After the wait, no live cookie was minted under the old secret. The
   prior `_PREVIOUS` is now obsolete. Set `_PREVIOUS` to a fresh
   sentinel (so the slot is still populated) so the next rotation
   inherits the same posture:

   ```diff
   -KRATOS_COOKIE_SECRET_PREVIOUS=<old current>
   +KRATOS_COOKIE_SECRET_PREVIOUS=<openssl rand -hex 32>
   ```

8. Restart again. Both slots remain populated with distinct values; the
   old signing key is no longer in memory anywhere except the
   operator's archive.

## Validation

Sign in via home portal after step 3, observe the new cookie's
`Set-Cookie` header carrying a fresh MAC. The old session cookie is
honored until its own expiry.

## Failure modes

- **Restart with new CURRENT but PREVIOUS empty before old sessions
  expire:** every active session gets bounced to login. UX hit, not a
  security regression.
- **Restart with both CURRENT and PREVIOUS empty:** Kratos refuses to
  start (`secrets.cookie: at least one entry required`). Same for
  Hydra. Restore from operator store.

## Related

- `kratos/kratos.yml`, `hydra/hydra.yml`: the env-var indirection.
- `lab/scripts/gen-secrets.sh`: produces fresh `_CURRENT` AND fresh
  `_PREVIOUS` (distinct values) for first provisioning.
- `docs/decision.md`: H4 "Hydra cookie-secret rotation" lock.

# Postgres backup and restore (TODO)

Status: NOT IMPLEMENTED. Placeholder runbook listing what has to land
before family rollout. Tracked as H11 from the adversarial review.

## Stakes

The Postgres `kratos` and `hydra` databases hold:

- Every passkey enrollment.
- Every active session.
- Every Hydra OAuth2 client secret (encrypted at rest under
  `secrets.system`, which is itself non-rotatable).
- Every recovery-code state.

Disk failure on carmine without backups means: every family member
re-enrolls passkeys, the admin manually re-creates 11 OIDC clients
with secrets pushed to every app, and `secrets.system` rehydrates
from Bitwarden (otherwise even partial restore can't decrypt). At
family scale the human cost is hours of re-enrollment plus operator
panic; it's the worst single-failure outcome in the auth substrate.

## Required deliverables (before family rollout)

1. **pg_dump cron job**
   - Run nightly via systemd timer or cron in the postgres pod.
   - Output written to `/var/lib/postgres/backups/<UTC-timestamp>.dump`
     (custom format, suitable for `pg_restore`).
   - Both databases (kratos + hydra) in one dump per timestamp, or
     one each. Decide based on restore drill ergonomics.
   - Retention: 30 daily + 12 monthly. Configurable.

2. **ZFS snapshot integration**
   - The `pg_data` dataset gets snapshotted by the existing carmine
     ZFS snapshot policy (sanoid or estate equivalent).
   - Snapshots live alongside dumps for two-tier recovery (quick
     rollback via ZFS, long-term archive via pg_dump).

3. **Off-host copy**
   - Dumps rsync'd to a separate machine (NAS? secondary VM?). Same
     dunn.dev estate; not sent off-LAN.
   - `secrets.system` lives in Bitwarden, not in the dump (it's an env
     var). On restore from a fresh DB, the operator pulls
     `secrets.system` from Bitwarden into the env and only then
     starts Hydra; otherwise the encrypted client secrets in the
     dump can't decrypt.

4. **Restore drill**
   - Quarterly: spin up a throwaway VM, restore the latest dump,
     point a fresh Hydra+Kratos pod at it, confirm (a) one identity
     can sign in, (b) one OIDC client emits a token, (c) WebAuthn
     credentials still verify (this last one tests
     `secrets.cipher` rehydration).
   - Document drill results inline here on each run.

5. **Restore runbook (this file, expanded)**
   - Step-by-step for an operator who isn't the author. Include the
     `secrets.system` rehydration path, the env-var setup, the
     pg_restore invocation, and the post-restore smoke test.

## Effort estimate

1 day of configuration plus one drill. The work is all on carmine
(pyinfra hooks for the pg_dump cron + ZFS plumbing); no Kratos / Hydra
config changes needed.

## Why this isn't done yet

Phase 0 (config drafting) and Phase 1 (lab spike) explicitly
de-prioritized backup tooling because the lab is throwaway. The
adversarial review (H11) flags this as a pre-family-rollout requirement
and that's where the work lands.

## Partial-state restore (A6)

Postgres point-in-time consistency is per-database. The auth substrate
touches both `kratos` and `hydra` databases in different transactions,
so a backup taken between a Kratos write (e.g., new identity created)
and the corresponding Hydra write (e.g., remembered consent rows)
yields drift on restore: a Kratos identity exists with no Hydra
remembered-consent row, or vice versa.

At family scale the recovery is NOT "fix the row." Instead:

1. Restore both databases from the most recent compatible pair of
   dumps.
2. Truncate Hydra's remembered-consent rows for any Kratos identity
   whose state in Hydra looks inconsistent. SQL:

   ```sql
   -- Kratos has identity, Hydra has consent rows. Force a re-consent
   -- for every family member by clearing their Hydra session cache.
   TRUNCATE hydra_oauth2_consent_request_handled;
   TRUNCATE hydra_oauth2_authentication_session;
   ```

3. Force re-login from the admin UI for every active family member
   (`/admin/users/<id>` → "Force re-login" button). This drops
   their Kratos session and any RP-side state.

4. Each member re-authenticates at their next app visit. The cost is
   a one-time login prompt across 14 apps, much lower than per-row
   reconciliation.

This is the canonical drift response. Documenting it here so a
post-restore operator doesn't waste hours hunting for orphan rows.

## Related

- `docs/decision.md`: H4 row covers `secrets.system` non-rotatability.
- `docs/runbooks/secrets-rotation.md`: A2 break-glass rotation.
- `docs/runbooks/cookie-rotation.md`: separate runbook for the
  rotatable secrets.
- `docs/runbooks/admin-recovery.md`: the recovery path that depends on
  Postgres being alive.

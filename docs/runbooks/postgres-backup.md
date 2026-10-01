# Postgres backup and restore

This runbook records the **backup posture** for the auth substrate's
Postgres state and the **restore procedure** an operator follows. The
backup *implementation* (the cron/quadlet runner, off-host copy, ZFS
snapshot policy) is deploy-plane work, not auth-project code — see
"Where it lives" below. The stakes, the required posture, and the
partial-state restore drill documented here are the contract the
deploy-layer runner must satisfy.

## Stakes

The Postgres `kratos` and `hydra` databases hold:

- Every passkey enrollment.
- Every active session.
- Every Hydra OAuth2 client secret (encrypted at rest under
  `secrets.system`, which is itself non-rotatable).
- Every recovery-code state.

Disk failure on the SSO host without backups means: every family member
re-enrolls passkeys, the admin manually re-creates 11 OIDC clients
with secrets pushed to every app, and `secrets.system` rehydrates
from Bitwarden (otherwise even partial restore can't decrypt). At
family scale the human cost is hours of re-enrollment plus operator
panic; it's the worst single-failure outcome in the auth substrate.

## Required posture (the deploy-layer runner must satisfy this)

1. **pg_dump cron job**
   - Run nightly via systemd timer or cron in the postgres pod.
   - Output written to `/var/lib/postgres/backups/<UTC-timestamp>.dump`
     (custom format, suitable for `pg_restore`).
   - Both databases (kratos + hydra) in one dump per timestamp, or
     one each. Decide based on restore drill ergonomics.
   - Retention: 30 daily + 12 monthly. Configurable.

2. **Filesystem snapshot integration (if the data volume supports it)**
   - The Postgres data volume gets snapshotted by whatever snapshot
     policy the host already runs.
   - Snapshots live alongside dumps for two-tier recovery: quick
     rollback via snapshot, long-term archive via pg_dump.

3. **Off-host copy**
   - Dumps copied off the host to at least one destination outside the
     blast radius of a single-host failure — two independent
     destinations (e.g. onsite-to-another-host plus offsite/cloud) is
     stronger than one.
   - `secrets.system` lives in sops (the `hydra_system_secret` entry), not
     in the dump (it's an env var). On restore from a fresh DB, the
     operator pulls `secrets.system` from sops into the env and only
     then starts Hydra; otherwise the encrypted client secrets in the
     dump can't decrypt. Sops + age key are themselves backed up
     separately — losing both means the dump is decryptable as raw
     postgres data but the Hydra client_secret column is permanently
     ciphertext.

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

## Where it lives

The backup runner is deploy-plane work, not auth-project code — the
cron/quadlet that runs pg_dump, the off-host copy mechanism and
destinations, and the on-host snapshot policy are all deploy-plane
choices. This runbook is the contract those choices must satisfy: the
required posture above, and the restore drill and partial-state
response below.

## Partial-state restore

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

3. Sign out everywhere from the admin UI for every active family member
   (`/admin/users/<id>` → "Sign out everywhere" button). This drops
   their Kratos session and any RP-side state.

4. Each member re-authenticates at their next app visit. The cost is
   a one-time login prompt across 14 apps, much lower than per-row
   reconciliation.

This is the canonical drift response. Documenting it here so a
post-restore operator doesn't waste hours hunting for orphan rows.

## Related

- `docs/runbooks/secrets-rotation.md`: break-glass rotation of
  `secrets.system` itself.
- `docs/runbooks/cookie-rotation.md`: separate runbook for the
  rotatable secrets.
- `docs/runbooks/admin-recovery.md`: the recovery path that depends on
  Postgres being alive.

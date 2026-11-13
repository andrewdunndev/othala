# Admin account recovery

An admin cannot use email recovery: the recovery-gate webhook refuses any identity carrying the admin marker, so a
stolen admin mailbox yields nothing (SECURITY.md has the boundary). Losing access therefore needs its own ladder.
Start at the position that matches what you still hold.

## Enrol so you rarely need it

Two passkeys on different devices, an authenticator app (TOTP), backup codes, and one security key. The security key
is what makes a lost phone survivable: the portal refuses to remove an admin's last authenticator app or security
key, so replacing a TOTP means adding a key first.

## Console commands

Steps C to E use the Kratos admin API, which is never published; call it from the othala container. The marker is
`metadata_admin.admin`; patch that key and nothing else, because a whole-object replace also strips the admin's
`groups`. The update endpoint takes a JSON Patch array.

```sh
admin() { docker compose exec -T othala node -e "fetch('http://kratos:4434/admin/'+process.argv[1],{method:process.argv[2],headers:{'Content-Type':'application/json'},body:process.argv[3]}).then(async r=>{console.log(r.status,await r.text());process.exit(r.ok?0:1)})" "$@"; }
admin identities/<id> GET                                                   # read the marker and groups first
admin identities/<id> PATCH '[{"op":"remove","path":"/metadata_admin/admin"}]'   # clear
admin identities/<id> PATCH '[{"op":"add","path":"/metadata_admin/admin","value":true}]'   # restore
admin recovery/code POST '{"identity_id":"<id>","expires_in":"1h"}'         # recovery_link and recovery_code; nothing is emailed
admin identities/<id>/credentials/totp DELETE
admin identities/<id>/credentials/lookup_secret DELETE                      # backup codes
admin identities/<id>/credentials/webauthn DELETE                           # every security key; passkeys stay
```

The admin API cannot delete a passkey; only its owner removes one, from their own settings. Deleting a credential type
the identity does not hold returns 404, and the helper exits 1.

## Step A: another passkey still works

Sign in with it, open settings and remove the lost passkey.

## Step B: lost authenticator app, but a passkey and backup codes remain

Order matters. Removing the authenticator app is refused while it is the last app or key, and replacing it is a
removal.

1. Sign in with the passkey and step up with a backup code when asked.
2. Within five minutes of that step-up, add a security key.
3. Remove the old authenticator app, set up the new one, and generate new backup codes (each set is single-use).
4. Remove the stand-in security key if you do not want to keep it.

A device with no WebAuthn cannot add a key; delete the `totp` credential from the console instead (Step D) and enrol
the new app.

## Step C: another admin recovers you

The portal refuses to issue a setup link for an admin target, so a stolen mailbox or a stray click cannot mint one.
That guard stops the mailbox path, not another admin: an admin session can clear the target's marker, issue a link
and restore the marker. Treat the second admin as someone who can take over the first, and the reverse.

The working admin runs Step D against the locked-out identity and hands over `recovery_link` and `recovery_code`
over a channel you both already trust; both are needed.

## Step D: no admin has a working session

1. Read the identity, then clear the marker. The gate reads it live, so the next step lands at once.
2. Delete what the locked-out admin can no longer answer. Recovery signs in at the first factor only, and settings
   then demands a second factor the admin does not have, so: with no authenticator app, no backup codes and no key,
   delete `totp` and `lookup_secret`, plus `webauthn` for a lost key. An admin who still holds an app or a backup
   code skips this and steps up when asked.
3. Issue a recovery code and hand over the link and code.
4. In that session enrol passkeys first, so the sign-in that follows the five-minute privileged window has a first
   factor; then the authenticator app, step up with it, and generate new backup codes. A lost phone's passkey stays
   until its owner removes it from settings.
5. Restore the marker and compare the identity with what you read in step 1.
6. Sign the identity out everywhere from its admin page, and confirm the admin pages open (the proof the marker
   works, not the patch's 200).

## Step E: no devices and no admin API

Get physical access to the host, bring up Kratos and its database, and follow Step D. There is no procedure that
edits a password hash in Postgres; it would be too easy to abuse.

## Adding a second admin

Create the identity, grant the groups it needs, and have them enrol as above. Then set the marker from the console
(or the admin page) only once enrolment is done: with the marker present, recovery is refused. The first admin of a
deployment is made the same way, from `DEPLOY.md`.

## Related

- `docs/runbooks/lost-device.md`: removing a credential from a member.
- `docs/runbooks/secrets-rotation.md`: rotate cookies after a console recovery.
- Pinned by `e2e/playwright/tests/zt-recovery-step-b.spec.ts` (Step B) and `e2e/playwright/tests/zu-recovery-step-d.spec.ts` and `e2e/playwright/tests/zw-recovery-refresh.spec.ts` (Step D, and the refresh sign-in with the new passkey).

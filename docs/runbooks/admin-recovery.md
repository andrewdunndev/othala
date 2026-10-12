# Admin account recovery and AAL operations

Admin accounts cannot use ordinary email recovery (Section 3), so losing access
needs its own ladder: what to enroll so you rarely need it, how admin authority
works, and break-glass steps in order of decreasing convenience. Deploy-specific
transcripts (SSH, container exec, host storage) belong in your deploy plane's runbook.

---

## 1. Prevention: what every admin should have enrolled

### Passkeys (AAL1 — primary login)

Enroll a passkey on at least two physical devices. Losing one is then a
non-event: log in from the other and remove the lost credential from Settings.
A hardware key as a third is a good bonus.

### TOTP (AAL2 — required for admin actions)

Admin pages require AAL2. Enroll TOTP from Settings → Two-factor
authentication → Add authenticator app; any TOTP client works. Admin pages then
prompt for the step-up automatically.

### Backup codes (recovery insurance)

After enrolling TOTP, download the backup codes (`lookup_secret` in Kratos
terms) into a password manager. They are the AAL2 fallback.

**Fully enrolled** means: 2+ passkeys on different devices, TOTP in an
authenticator app, and backup codes saved.

---

## 2. How admin authority works

Admin status is the `metadata_admin.admin` flag on a Kratos identity, a
boolean set only via the Kratos admin API, never through self-service flows
or OIDC claims. The portal reads it fresh on every request via
`GET /admin/identities/:id`, so nobody can elevate themselves by editing their
own identity; the only write path is the network-gated admin API.

The admin API's identity-update endpoint takes a JSON Patch **array**, not a
merge object — a bare `{"metadata_admin": …}` body is rejected:

```sh
curl -fsS -X PATCH -H 'Content-Type: application/json' \
  -d '[{"op":"add","path":"/metadata_admin/admin","value":true}]' \
  http://localhost:4434/admin/identities/<UUID>
```

If `metadata_admin` is null, send `add /metadata_admin {"admin":true}` instead;
Kratos does not create the parent (`patchAdminMarker` pre-fetches for this).
Patch the marker and nothing else — sending a
whole `metadata_admin` object replaces `groups` too, silently stripping an
admin's app access while they can still sign in.

**Groups are separate, and nothing is derived from the marker.** Entry to an
app comes from holding that app's `<svc>-access` group, admins included;
`<svc>-admin` grants the elevated role *inside* an app and admits nobody on
its own. An admin who also uses a service holds both, explicitly. The full
model is `portal/src/lib/gate.ts` and `portal/src/lib/identity-facts.ts`.

---

## 3. Why admin email-recovery is intentionally blocked

For regular members, "Forgot account?" emails a code. For admins that path is
blocked: a compromised admin mailbox would otherwise yield full admin access.

The recovery-gate webhook (`kratos/hooks/recovery-gate.jsonnet` +
`fetchAdminMarker` in `portal/src/server/listen.ts`) intercepts every
recovery attempt after code verification. Kratos posts the identity id; the
gate reads the authoritative `metadata_admin.admin` flag from the admin API and,
if `true`, returns 403 and Kratos (`can_interrupt: true`) aborts the flow, even
with a correct code.

The gate re-reads the flag live on every attempt, with no cache and no
allow-list, which is what lets the Section 4 console procedure clear the
marker, recover, and restore it.

If a member reports an authenticator app they did not add, remove it from their account page; they are signed out everywhere.

---

## 4. Admin recovery ladder

Work from top to bottom. Each step is less convenient and more drastic than
the one above it.

> Steps A and B are ordinary product paths, exercised by the e2e suite. Steps
> C, D and E are console procedures on the Kratos admin API; rehearse them
> against a throwaway stack. An admin-issued recovery code does not bypass the
> gate, which is why Step D clears the marker first.

### Step A: You have another enrolled device

With a working passkey anywhere, this is not a lockout. Sign in from that
device and remove the lost credential in Settings → Security → Passkeys, or
(lost TOTP app) use a backup code (Step B) to step up and enroll a fresh TOTP app.

### Step B: You lost your TOTP app but have a backup code

Sign in with your passkey. When prompted for TOTP, choose "Use backup
code". You are in at AAL2; enroll a new TOTP app before the session expires.
Backup codes are single-use; generate a fresh set after re-enrolling.

### Step C: The other admin recovers you (dual-admin)

The recommended path when a second admin exists. The portal UI refuses to
issue a recovery URL for an admin target (`shouldRefuseRecovery` in
`portal/src/lib/access.ts`), so a compromised admin browser session cannot mint
one for the other admin. Admin-to-admin recovery is console-only: the
working admin runs Step D against the locked-out identity, then hands
the `recovery_link` **and** `recovery_code` over a channel you both already
trust. Both are needed and the code is short-lived. Restoring the marker (last
step of D) is not optional: until then the locked-out admin is a normal member.

### Step D: Console break-glass (no working admin session)

Use this when no admin has a working browser session but you can reach the
Kratos admin API (SSH, `kubectl exec`, or however your deploy plane exposes it;
the API is never published to the network).

1. **Save, then clear the admin marker.** The recovery-gate refuses recovery
   for any identity carrying it (Section 3), and it re-reads the marker live
   — clearing it first is what makes the next step land. Record the
   `metadata_admin` value before clearing it; you restore it at step 4.
   Removing the `admin` key only (never a whole-object replace) leaves
   `groups` untouched.
2. **Issue a recovery code**, not a link: `POST /admin/recovery/code`. `kratos.yml`
   enables only the `code` method (`selfservice.methods.code.enabled: true`) for
   recovery; the `link` method is not enabled. The response carries both
   a `recovery_link` and a `recovery_code`; nothing is emailed. The code's
   lifetime is bounded by `selfservice.methods.code.config.lifespan`
   regardless of the `expires_in` requested; issue a fresh one if it expires.
3. **Open the link, enter the code**, and re-enroll in that session before
   the tab closes: two passkeys across two devices, fresh TOTP, new backup
   codes.
4. **Restore the admin marker**, re-add-only, and compare the result against
   what step 1 recorded. It takes effect on the next request — no restart.
5. **Verify:** two-plus passkeys visible, TOTP + backup codes present, the
   marker back with `groups` unchanged, `/admin` reachable again (proof the
   marker works, not just that the patch returned 200), and old
   session cookies invalidated (`revoke_active_sessions` fires automatically
   on credential change). Record the event — date, reason, and the window the
   marker was off — in your ops log.

**Why the marker comes off and goes back on.** The recovery-gate webhook is
wired at the flow level (`selfservice.flows.recovery.after.hooks`,
`can_interrupt: true`) with no exemption for admin-API-issued flows. Clearing the
marker makes the procedure work whether or not the hook fires for them, and costs
nothing: anyone who can call the admin API can already do far more.

### Step E: No devices, no admin-API access — physical access only

The last resort. Get physical (or BMC/serial) access to the host, unlock
its data volume, start Kratos, and follow Step D from the local console.

There is deliberately no "edit the password hash in Postgres" procedure: it
would be a trivially abusable break-glass. Get Kratos running and use Step D.

---

## 5. The dual-admin model (recommended)

Two admins — carrying the `metadata_admin.admin` marker on separate
identities — removes the single point of human failure: either can recover
the other via Step C without an Asteroid-grade event, and either can manage
family accounts without waiting on the other. The co-admin runs Step D
against themself the same way an operator would; the portal UI blocks
browser-based admin-to-admin recovery for both of them equally, so console
access is the only path either has.

To add a co-admin: create their identity, toggle the admin marker on (admin
UI, or the marker-only JSON Patch from Section 2 — never a whole
`metadata_admin` object), grant the groups they need (each app's
`<svc>-access`, plus `<svc>-admin` wherever they hold the elevated role), and
have them enroll a second passkey and TOTP per Section 1. Takes effect
immediately, no restart. Both admins should be able to reach the console
independently (SSH key, `kubectl` access — whatever your deploy plane uses).

---

## 6. Webhook authentication note

The recovery-gate webhook requires `RECOVERY_GATE_SECRET` to match on both
Kratos (`Authorization: Bearer <secret>`) and the portal (constant-time
comparison on receive). Empty or mismatched secret fails closed — recovery is
denied, not allowed. Rotate by updating the secret and restarting both
services; verify with a non-admin recovery that the gate still allows it.

---

## Related runbooks and source files

- `docs/runbooks/lost-device.md` — lost/stolen device eviction procedure.
  Read this first when responding to a lost device — force re-login alone is
  insufficient if a credential was enrolled on the device.
- `docs/runbooks/cookie-rotation.md` — rotate session cookies after a console
  recovery.
- `docs/runbooks/secrets-rotation.md` — break-glass rotation of
  `secrets.system`.
- `kratos/kratos.yml` — `selfservice.flows.recovery.after.hooks` (the gate
  wire-up and `can_interrupt: true`).
- `kratos/hooks/recovery-gate.jsonnet` — webhook body template.
- `portal/src/server/listen.ts` (`fetchAdminMarker`, `handleRecoveryGate`) —
  the gate handler.
- `portal/src/lib/admin.ts` (`requireAdminSession`) — AAL2 step-up at the SSR
  layer.

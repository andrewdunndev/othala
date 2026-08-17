# 16 — `sslmode=disable` on the Ory → Postgres DSNs

## Status

Accepted (2026-08-16). Both Ory services reach Postgres over a plaintext
connection: `kratos/kratos.yml` and `hydra/hydra.yml` each carry
`?sslmode=disable` in their `dsn`. This record states the measured topology that
bounds that choice, and marks — rather than invents — the part of the rationale
that is still owed.

Both files are byte-vendored; read [13](13-vendored-config-contract.md) before
editing either.

See also [03](03-proxy-originated-mtls.md) (network isolation as the
load-bearing control on the other unauthenticated hop across the same network)
and [11](11-hardening-tuning.md) (the other deliberate deviations living in
these two files).

## Context

The setting was in the configs long before it was in a record, and both configs
knew it. Each describes its own plaintext OTLP export as carrying the "Same
accepted-risk posture as the sslmode=disable DSN above" (`kratos/kratos.yml:340`,
`hydra/hydra.yml:135`) — a forward reference to a rationale neither file, nor any
record in this directory, ever wrote down. The public hardening guide
(`site/src/content/docs/guides/hardening.md`) now discloses the setting plainly.
A disclosed security-relevant setting with no recorded reasoning reads as an
oversight even when it is not, so the fact needs a decision behind it.

**Where the setting is, exactly.**

- `kratos/kratos.yml:12` —
  `dsn: "postgres://kratos:${KRATOS_PG_PASS}@${KRATOS_PG_HOST}:5432/kratos?sslmode=disable"`
- `hydra/hydra.yml:8` —
  `dsn: "postgres://hydra:${HYDRA_PG_PASS}@${HYDRA_PG_HOST}:5432/hydra?sslmode=disable"`

The database host is a variable on purpose. `hydra/hydra.yml:3-6`: "DSN host is
env-substituted so the same file lands in both topologies. Lab compose sets
`HYDRA_PG_HOST=postgres` (compose service name); the production quadlets set
`HYDRA_PG_HOST` to the container name on the pod-internal network."

**What that variable resolves to, measured, in each topology.**

*The end-to-end harness.* `e2e/compose.yml:140` sets
`DSN: postgres://kratos:${KRATOS_PG_PASS}@postgres:5432/kratos?sslmode=disable`
— a compose service name, resolved on the single bridge network the file
declares (`e2e/compose.yml:552-558`: `driver: bridge`, `subnet: 10.89.11.0/24`).
The `postgres` service definition (`e2e/compose.yml:48-99`) declares no `ports:`
key; the only published host port anywhere in the file is the edge proxy's
`"8088:80"` (`e2e/compose.yml:481-482`). The database is therefore reachable
from containers on that one bridge and from nowhere else — and reachable from
*every* container on it, since the file declares no second network and no
per-service segmentation.

*The deployment.* `ARCHITECTURE.md:732-734`: "Kratos (public + admin), Hydra
(public + admin), the Othala app (public + loopback admin listeners), and
Postgres all sit on the same pod network." The topology sketch places the
database inside that pod with the rest (`ARCHITECTURE.md:437`), and — unlike the
Ory listeners, which are annotated with their public and internal-only ports —
it carries no published-port annotation at all.

So the connection has one shape in both topologies: **container to container on
a single private network, addressed by a name that only resolves on that
network, never crossing a host boundary.**

## Decision

**`sslmode=disable` stays on both DSNs, and the reason it is tolerable is the
topology above — stated here so it is an accepted risk with a named boundary
rather than a bare setting.**

State what transport encryption on this hop would actually buy, precisely: it
would protect the Kratos and Hydra row traffic — identity traits, credential
material, session and consent rows — from an attacker who can already read
frames on the private network that the Ory services and the database share.
That is the entire benefit. It is not nothing, but it is bounded by who can hold
that position.

An attacker who holds it holds considerably more than the database hop.
[03](03-proxy-originated-mtls.md) records, for the same network, that "network
isolation, not client authentication, is the load-bearing control on that hop"
— the Kratos admin API sitting on it has no client authentication of its own,
and reaching it is enough to create, modify and delete identities. Encrypting
the database connection while that door stands open on the same segment does not
raise the floor; it re-secures one path into a store whose front door is already
open to anything with that foothold. `ARCHITECTURE.md:807-811` already records
the general form: "No mTLS between SSO-pod services. The pod boundary is the
trust unit... Tier-2 RCE on any SSO-pod service yields full pod-internal
lateral." The DSN is one instance of that recorded gap, not a second,
independent one.

**What this does not protect against — including if it were enabled.**

- It is not client authentication. Anything that can dial `5432` on that network
  still authenticates as a Postgres role with the password carried in the DSN,
  encrypted hop or not.
- It does not restrict *who* can dial `5432`. In the harness nothing segments
  the bridge (`e2e/compose.yml:552-558` declares one network for all services);
  in the deployment the database shares the pod network with everything else in
  it (`ARCHITECTURE.md:732-734`).
- It does not close the unauthenticated admin APIs reachable across the same
  network ([03](03-proxy-originated-mtls.md)).
- It says nothing about data at rest or about backups; those are
  `ARCHITECTURE.md`'s A6 section and `docs/runbooks/postgres-backup.md`.

**Enforcement.** This decision leans entirely on one property: the database port
is not reachable from outside the private network the Ory services sit on.

- In the harness the property holds *by construction* — the `postgres` service
  declares no `ports:` key (`e2e/compose.yml:48-99`) — but nothing fails if a
  future edit adds one. `UNENFORCED — convention only`.
- For the deployment the property is one the deployment must have, and this repo
  cannot check that it does: no file here declares the deployment's networks or
  its port publications, and no gate here fails when the database port becomes
  reachable beyond that network. `UNENFORCED — convention only`.

**What this record deliberately does not say.** It does not record *why* the
tradeoff was accepted beyond the topology, and it does not state a threat model
past the tiers already in `ARCHITECTURE.md`. No file in this repo states either,
so neither is written here. A plausible-sounding motive invented to fill the gap
would be worse than the gap: the next maintainer would weigh a real change
against a reason nobody ever held. That reasoning is owed, and until it is
supplied this record carries the measurement and not the motive.

**Scope of the argument.** Everything above rests on the database sharing a
private network with the services that dial it. If that stops being true — the
database moved to another host, another pod, or a managed service, or its port
published beyond that network — the argument in this record no longer applies to
the new topology, and what should replace it is not decided here.

## Consequences

- The two configs' forward reference finally resolves: a reader who follows
  "Same accepted-risk posture as the sslmode=disable DSN above" lands somewhere.
- **The comparison those comments draw is looser than it reads, and this record
  does not extend to the other hop.** The OTLP note continues "the hop reaches
  only the firewall-scoped host OTLP port" (`kratos/kratos.yml:341-342`,
  `hydra/hydra.yml:136-137`) — a *host* port, so that hop leaves the container
  network, which the database hop does not. Same posture, different boundary.
  Whatever justifies the OTLP hop needs its own account; nothing here supplies
  it.
- The published hardening guide's disclosure now has a decision behind it
  instead of an open question.
- The record is only as true as the topology, and nothing fails when the
  topology changes. That is the standing obligation this creates: a change to
  where the database lives is a change to this record, caught by a maintainer or
  not at all.
- Hardening the hop later is not a one-line change. Both DSNs are in
  byte-vendored files, so editing them forces a re-vendor
  ([13](13-vendored-config-contract.md)) on top of whatever certificate work the
  new mode needs.

## Alternatives considered

- **`sslmode=require`.** Encrypts the connection without requiring the client to
  verify the server. Not adopted: it would encrypt a hop whose exposure is
  already bounded by the network above, while adding a server certificate and a
  renewal path on the database in both topologies. How much `require` — as
  distinct from `verify-full` — would raise the bar against an attacker already
  positioned on that network is a libpq-semantics question this record does not
  settle, and it should be settled before the mode is chosen rather than after.
- **`verify-full` against the internal mesh CA.** An internal CA already exists
  ([06](06-two-pki.md)) and could issue the database a server certificate, so
  this is the technically strongest option on the table. It is also the one that
  puts certificate lifecycle where this corpus has consistently refused to put
  it: [03](03-proxy-originated-mtls.md) settles on "TLS is a proxy concern, not
  an application concern", with renewal owned by a sidecar or a host timer
  beside it — and the database has no sidecar in either topology
  (`e2e/compose.yml:48-99`, `ARCHITECTURE.md:437`). Adopting it means either
  giving the database one or making it the first component here to renew its own
  certificate.
- **A Unix socket instead of TCP.** Removes the network hop rather than
  encrypting it. Not available in either topology as built: both DSNs address
  the database by host and TCP port `5432` (`kratos/kratos.yml:12`,
  `hydra/hydra.yml:8`), and the services are separate containers from the
  database (`e2e/compose.yml:48-99` and `ARCHITECTURE.md:437`), so a socket
  would have to be shared across container boundaries — and the change would hit
  the byte-vendored files anyway.
- **Leave it undocumented.** The status quo until now, and the thing the
  hardening guide flagged. Rejected: the setting is public either way, and a
  public security-relevant setting whose only trace is a cross-reference to a
  rationale that was never written invites a future maintainer to either "fix"
  it blind or assume a justification that does not exist.

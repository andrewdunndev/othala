# NN — Title

<!--
Not a decision record. This is the skeleton every record in docs/adr/ follows,
plus three rules that make a record safe for a reader with no context — a new
maintainer, or an LLM that grepped its way into the middle of the file.

Copy the five headings below. Delete this comment and the rule text under each
heading, keep the rules themselves in mind.
-->

## Status

`Accepted (YYYY-MM-DD)` or `Superseded by [NN](NN-title.md) (YYYY-MM-DD)`.
Cross-references to related records follow on their own lines.

**Rule 1 — Status leads with the current dated truth.** The first sentence
states what is true of the running system today, not what was resolved when the
record was first written. A reader who stops after Status must not be misled.
When the record is amended, the sentence and the date change together.

**Rule 2 — Status is binary, and supersession is a tombstone.** There are two
values: `Accepted` and `Superseded by NN`. There is no `Proposed`, no
`Deprecated`, and no "superseded in practice". When a record is superseded, its
**body is replaced** by a short tombstone — one paragraph saying what it used to
decide and where the live decision now lives — and the old prose is deleted.
Annotating a status banner over still-readable normative prose is forbidden:
someone greps a term, lands mid-body, finds a confident definition, and rebuilds
a retired model. That has already happened here twice.

## Context

What is the problem or question being decided? Include the technical and
operational forces in play. Be specific enough that someone reading this later
can understand why the alternatives were real options, not strawmen.

Context is where superseded history belongs while a record is still Accepted —
"this was tried, here is why it changed" — clearly marked as history.

## Decision

State the decision in one sentence. Flesh out what it means in practice: what is
configured, what is built, what is ruled out.

**Rule 3 — every normative "must" names its enforcer or is marked unenforced.**
A sentence that tells a future maintainer they must do something either cites
the file that fails when they do not — a CI step, a gate script, a code path,
by path — or carries the literal marker `UNENFORCED — convention only`. That
marker is a legal and load-bearing value: plenty of this corpus's conventions
are held by habit, and saying so is better than implying a check that does not
exist. Claiming an enforcer that is not there is the worst of the three
outcomes, because the next maintainer will "fix" correct code to satisfy a rule
nothing was ever checking.

Prefer citing the enforcing artifact over restating what it contains. Counts,
IP addresses, FQDNs, group rosters and client tallies rot; a pointer to the file
that holds them does not.

## Consequences

What does this decision make easier? What does it make harder? What ongoing
obligations does it create? Report live consequences honestly, including the
ugly ones — a known gap stated plainly is worth more than a tidy record.

Where a consequence is a gap rather than a tradeoff, mark it and name the
condition that reopens the question, so a future reader knows whether the
argument is settled or merely deferred.

## Alternatives considered

List the alternatives that were genuinely evaluated. For each, state why it was
not chosen. Be honest about tradeoffs — if an alternative was good but did not
fit the specific constraints, say so.

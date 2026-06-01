# Contribution strategy

The dunn.dev/othala project as both consumer and contributor. We use Ory Kratos + Hydra without modification (no fork, no patch series). The novel piece — `glauth-kratos`, our LDAP bridge — has standalone upstream value beyond our deployment.

## Posture: consumer of Ory; contributor to glauth (potentially)

### Ory Kratos and Hydra: consumer

We run upstream Ory Kratos and Hydra release images. No patches, no fork. The architecture decision is to use these projects as-shipped because:

- Ory ships fast (release cadence ~monthly); a patch series ages out fast
- The composable architecture means we can route around limitations rather than patch them
- Operational gaps (consent app, login app, LDAP bridge) are documented BYO-extension points, not bugs

Possible future contributions to Ory, if a deployment-derived issue surfaces:

- Bug reports backed by logs and repro steps
- Documentation issues (e.g., the AAL semantics gap that the adversarial review caught is poorly documented)
- A Kratos admin-API webhook event for identity CRUD — would benefit our LDAP bridge cache and any other admin-facing consumer; small contribution, general value

These are speculative. Default posture: ship deployment, monitor advisories, file bugs as encountered.

### glauth: contribution candidate

`glauth-kratos` (the bridge in `ldap-bridge/`) is built as a glauth embedded plugin: a Handler implementation that satisfies glauth's Bind/Search interface against Kratos. Once it proves out in production, the natural contribution path is:

1. Extract `ldap-bridge/kratos/` plus the surrounding Containerfile/Makefile to its own repo: `gitlab.com/dunn.dev/glauth-kratos` (with GitHub mirror)
2. Open a PR against glauth itself proposing the kratos backend as an upstream embedded plugin
3. Maintain the standalone repo as the authoritative source; the upstream contribution is a pointer

The bridge's standalone value: anyone running Kratos who needs LDAP. The community of homelabbers + small-org Kratos deployments has the same gap; we're not the first to hit it (just the first to assemble the pieces).

#### Module-path rename plan (L5)

Both `consent/go.mod` and `ldap-bridge/go.mod` currently declare module
paths under `dunn.dev/auth/...` (the marketing domain). For the
upstream extraction this becomes `gitlab.com/dunn.dev/glauth-kratos`
(or `github.com/glauth/glauth-kratos` if the path lands on glauth's
account). The rename is mechanical:

1. `go mod edit -module gitlab.com/dunn.dev/glauth-kratos`
2. `find . -name '*.go' -exec sed -i '' 's|dunn.dev/auth/ldap-bridge|gitlab.com/dunn.dev/glauth-kratos|g' {} +`
3. `go mod tidy && go build ./...`
4. Update Containerfile / Makefile import lines, README install
   instructions, and the GitLab pipeline include if any.

The consent service stays at `dunn.dev/auth/consent` (it's
deployment-specific, not a candidate for upstreaming). No rename
needed there.

Defer until after lab proves the bridge against Jellyfin (Phase 2).
The rename is a downstream-of-extraction step, not a blocker for
estate use today.

## What we do NOT contribute

- **Patches to evaluated-but-rejected stacks (kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel).** Out of scope; kanidm specifically has explicit AI/LLM bans.
- **A fork of Ory.** If Ory itself fails us, we revisit substrate, not patch-and-maintain.
- **A standalone "Ory homelab kit" project.** The `dunn.dev/othala` repo IS the kit, but extracted only as components (the bridge first; the Astro UI is more opinionated and possibly less generally useful). We don't pre-publish the entire kit because:
  - Maintenance treadmill killed every prior Ory homelab kit (see `lab/docs/ory-homelab-research.md`)
  - We dogfood on carmine; that's the structural difference vs prior solo maintainers
  - If the bridge proves valuable as a standalone, that's where the leverage is — focus there

## Posture if asked

If someone asks "can I use your kit?" the answer is: the bridge is open-source, the Astro UI is a reference, the rest is dunn.dev-specific config. Take what's useful. Patches welcome on the bridge specifically.

## Watch-outs

- Ory Network commercial trajectory tightens free-tier OSS — currently no signs, but if SCIM, advanced AAL flows, or other features migrate to Network-only, revisit
- glauth governance health — single-maintainer concern; if the project goes quiet for >6 months, our bridge becomes a maintenance burden we own alone
- Kratos breaking changes — fast release cadence is the published strength and the latent risk; we pin major versions, test against new versions in lab before bumping carmine

## Voice for upstream

Apply estate voice rules to any external text (PR descriptions, issue replies, blog posts):
- No em-dashes (use colons, parentheses, semicolons)
- Direct phrasing, no filler ("comprehensive", "robust", "leverage", "straightforward")
- State uncertainty plainly; don't hedge
- No trailing summaries

DCO sign-off where projects require it. No AI-Assisted trailers. Drafts to file first; human review before posting.

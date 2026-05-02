# Contribution strategy

How dunn.dev/auth relates to the upstream kanidm project, and what we do if upstream isn't a viable home for our patterns.

## Posture

**Upstream-first.** The dunn.dev estate already has a contribution arc through bootc (3 PRs merged), composefs, and rpm-ostree. Kanidm joins that pattern. Where we identify a gap that benefits the broader kanidm community (forward-auth endpoint, headless flow API), we attempt to land it upstream.

**Document independently as fallback.** If a contribution is rejected, stalled, or doesn't fit kanidm's design philosophy, we document the pattern in this repo and ship it locally. We do **not** abandon kanidm and migrate to a different IDP unless something grave surfaces (kanidm fundamentally cannot deliver on family UX, headless API can't be made to work even with patches, or maintainer engagement signals the project is not durable).

The bias is strong: stay with kanidm. The original evaluation considered Ory and rejected it for being shaped wrong for our use case (B2B SaaS, not homelab). That conclusion stands even if upstream contributions are harder than expected.

## Sequencing

Before any contribution code, follow the orient-before-build pattern:

1. **Walk the maintainer.** William Brown (Firstyear) — recent activity on Mastodon, blog, kanidm GitHub. Extract stance on the specific area we want to contribute. Same pattern used for cgwalters on bootc.
2. **Search the issue tracker.** Existing discussions, RFCs, prior rejections. Don't propose what's already been declined unless we have a meaningfully new angle.
3. **File an RFC issue first.** Get a stance read. Apply voice rules. No code yet.
4. **Only then PR.** DCO sign-off, no AI-Assisted trailers, no LLM-verbatim text.

## Targets

### 1. Forward-auth endpoint

**What:** A new HTTP route on kanidm (e.g., `/oauth2/forward_auth`) that takes a session cookie + original-URL header from a reverse proxy and returns either:
- 200 + `X-Kanidm-Username`, `X-Kanidm-Groups`, etc. headers (authenticated, allowed)
- 401 (not authenticated) or 302 to the login flow with `redirect_to=`

**Why:** Closes the only architectural gap kanidm has for our app stack. Currently the Caddy plugin layer does the OIDC client work itself; this endpoint would simplify the proxy-side config to a single call.

**Estimated scope:** Comparable to a medium bootc PR. ~500-1500 LOC Rust + tests + docs. Probably 2-4 weeks of evening work including upstream review cycles.

**Risk:** Forward auth has known footguns (header injection from untrusted upstream proxies, identity-header trust boundary). The PR has to land with safe defaults: trusted-proxy CIDR allowlist, fail-closed on missing cookie-domain config, rate limiting.

**Fallback if rejected:** The Caddy plugin pattern (caddy-security or our own plugin) keeps doing the OIDC client work. Performance and complexity are acceptable; the contribution would be polish, not necessity. Document the pattern in `caddy/README.md` and `lab/docs/forward-auth-pattern.md`.

### 2. Headless flow API + reference frontend

**Conditional on Phase 0 research finding the current `/v1/auth/*` API too immature for BYO frontend.** If kanidm's headless support is already mature, this contribution isn't needed.

**What:** Formalize the auth-flow API for external consumers (stable contract, documented, typed JS/TS bindings), plus a reference Astro frontend showing the BYO-UI pattern.

**Why:** The "match dunn.dev/design exactly" goal requires a custom login page driving kanidm's auth API directly. If the API is undocumented or unstable, every BYO frontend has to reverse-engineer the Yew UI's API calls. Formalizing this benefits every kanidm consumer who wants their own UI.

**Estimated scope:** Larger than forward-auth (API formalization + JS/TS client + reference UI), but high-leverage.

**Risk:** kanidm's design philosophy is opinionated UIs by default. The maintainer may prefer to keep the built-in UI as the canonical experience. If so, our reference frontend is fine in our own repo, but the API formalization itself may be the harder ask.

**Fallback if rejected:** Layer 1 (CSS skin on the Yew UI) is our ceiling. Document the calling patterns we discovered in `lab/docs/headless-api-notes.md` so other estate operators don't have to reverse-engineer them. Eventually we may need to fork or maintain a patch series; that's a future decision.

## What we will not contribute

- **SMS recovery.** Kanidm philosophy is anti-SMS (SIM swap risk). Our family use case has better answers (admin-issued recovery URL via Signal, multiple passkeys per account, Fastmail-with-passkey for email recovery). Not worth the goodwill spend.
- **Fork-only patches.** If a contribution is rejected, the answer is documented patterns in this repo, not maintaining a private fork of kanidm. Forking is a last resort and should trigger a re-evaluation of kanidm itself.

## What "grave" looks like

The bar for abandoning kanidm and revisiting Ory is high. It would take one of:

- **Project abandonment.** Maintainer disappears, no successor, security advisories unaddressed for >90 days.
- **Fundamental UX failure.** Phone test reveals passkey UX is unworkable for the family even after our customizations, with no upstream path to fix.
- **Architectural mismatch.** Some property we haven't thought of (replication, scaling, integration) makes kanidm unable to grow with the estate over the next 5+ years.

Routine friction (rejected PRs, slow review, opinionated maintainer) is not grave. We absorb that and document independently.

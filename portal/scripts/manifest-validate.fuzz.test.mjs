// Adversarial property-based fuzz test for the manifest-validate security surface.
//
// SECURITY INVARIANT:
//   validateClients MUST reject any OIDC client whose audience entries do not
//   have exact-origin matches in the redirect_uri set (rule 3).
//   audienceMatchesRedirect MUST compare by parsed ORIGIN (scheme://host[:port])
//   ONLY — no substring/prefix match, no fragment confusion, no credential
//   injection (user:pass@), no subdomain suffix confusion.
//
// Run with: tsx --test scripts/manifest-validate.fuzz.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { audienceMatchesRedirect, validateClients, parseManifest } from '../src/lib/manifests.ts';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a minimal ClientManifest object for testing, bypassing YAML parsing so
 * we can inject precise values that parseManifest might sanitise.
 */
function makeManifest({ clientId = 'test-client', redirectUris = [], audience = [] } = {}) {
  return {
    clientId,
    clientName: clientId,
    redirectUris,
    postLogoutRedirectUris: [],
    scopes: ['openid'],
    scope: 'openid',
    audience,
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    presentationOnly: false,
    accessGroups: [`access-${clientId}`],
    roles: [],
    groupRoleMap: {},
    emitGroupsClaim: null,
    skipAccessCheck: false,
    sourcePath: `${clientId}.yaml`,
  };
}

/** originOf mirrors the private function in manifests.ts. */
function originOf(raw) {
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

// ─── Catalogue of known adversarial patterns (deterministic) ─────────────────

const TRUSTED_ORIGIN = 'https://keep.dunn.dev';
const TRUSTED_REDIRECT = 'https://keep.dunn.dev/callback';

/**
 * Each entry: { label, audience, redirectUris, shouldPass }
 *
 * shouldPass = true  → validator must NOT fire rule 3.
 * shouldPass = false → validator MUST fire rule 3.
 */
const ADVERSARIAL_CASES = [
  // --- Cases the validator should REJECT (audience origin ≠ redirect origin) ---
  {
    label: 'credential injection: user:pass@host hides the real host',
    audience: ['https://keep.dunn.dev:443@evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'credential injection: trusted host as username, evil host',
    audience: ['https://keep.dunn.dev@evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'subdomain suffix: evil.com suffix on trusted host',
    audience: ['https://keep.dunn.dev.evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'fragment confusion: trusted origin in fragment of evil URL',
    audience: ['https://evil.com#keep.dunn.dev'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'scheme mismatch: http vs https',
    audience: ['http://keep.dunn.dev'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'port mismatch: unexpected port',
    audience: ['https://keep.dunn.dev:8443'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'path appended to audience does not hide the wrong host',
    audience: ['https://evil.com/keep.dunn.dev'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'null-byte in audience: URL parse throws → fail-closed (null origin)',
    audience: ['https://keep.dunn.dev\x00.evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'unicode lookalike: cyrillic е punycodes to different origin',
    audience: ['https://keep.dunn.dеv'],   // Cyrillic е (U+0435) → xn--dv-nlc, not ASCII e
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'IPv6 with embedded trusted host: URL parse throws → fail-closed',
    audience: ['https://[::1]keep.dunn.dev'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  // NOTE: WHATWG URL normalises scheme-relative and backslash forms to canonical origin.
  // https:keep.dunn.dev  → origin: https://keep.dunn.dev  (matches; not a bypass)
  // https:\\keep.dunn.dev → origin: https://keep.dunn.dev (matches; not a bypass)
  // These are NOT attack vectors: the URL parser resolves them to the same origin as the
  // trusted redirect, so the validator correctly accepts them.
  // The residual risk is the stored audience string is non-canonical (e.g. "https:app.example.com"
  // in the token), which would cause client-side aud verification to fail at runtime — a
  // consistency/correctness issue, not a security bypass. Documented below under notes.

  // --- Redirect-side crafting: redirect_uri looks like it matches but does not ---
  {
    label: 'redirect with user:pass@trusted does NOT give the trusted origin',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://evil.com:443@keep.dunn.dev/cb'],
    // originOf('https://evil.com:443@keep.dunn.dev/cb') = 'https://keep.dunn.dev'
    // So this SHOULD pass — the redirect is keep.dunn.dev and audience is keep.dunn.dev
    // This is NOT an attack (the manifest operator controls redirect_uris)
    shouldPass: true,
  },
  {
    label: 'redirect with evil subdomain does NOT match trusted audience',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://keep.dunn.dev.evil.com/cb'],
    shouldPass: false,
  },
  {
    label: 'redirect with scheme mismatch does NOT match trusted audience',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['http://keep.dunn.dev/cb'],
    shouldPass: false,
  },

  // --- Cases the validator SHOULD accept ---
  {
    label: 'exact match: audience origin == redirect origin (happy path)',
    audience: [TRUSTED_ORIGIN],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: true,
  },
  {
    label: 'explicit port 443 in redirect matches audience without port',
    // new URL('https://keep.dunn.dev:443/cb').origin === 'https://keep.dunn.dev'
    // (WHATWG URL normalises default ports away)
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://keep.dunn.dev:443/callback'],
    shouldPass: true,
  },
  {
    label: 'multiple redirect uris: at least one matches each audience',
    audience: ['https://app1.example.com', 'https://app2.example.com'],
    redirectUris: ['https://app1.example.com/cb', 'https://app2.example.com/cb'],
    shouldPass: true,
  },
  {
    label: 'empty audience: validator passes (nothing to constrain)',
    audience: [],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: true,
  },
  {
    label: 'no redirect_uris: rule 3 skipped entirely',
    audience: [TRUSTED_ORIGIN],
    redirectUris: [],
    shouldPass: true, // rule 3 only fires when BOTH audience AND redirectUris are non-empty
  },
  {
    label: 'fragment in redirect normalised away by WHATWG URL — origin still matches',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://keep.dunn.dev/callback#section'],
    shouldPass: true,
  },
];

// ─── Deterministic adversarial test cases ────────────────────────────────────

test('adversarial catalogue: each case meets its shouldPass expectation', () => {
  for (const { label, audience, redirectUris, shouldPass } of ADVERSARIAL_CASES) {
    const manifest = makeManifest({ redirectUris, audience });
    const errs = validateClients([manifest]);
    const rule3Fired = errs.some((e) => e.includes('no oidc.audience origin matches'));

    if (shouldPass) {
      assert.equal(
        rule3Fired,
        false,
        `INVARIANT VIOLATION (false reject): "${label}"\n  audience: ${JSON.stringify(audience)}\n  redirectUris: ${JSON.stringify(redirectUris)}\n  errors: ${JSON.stringify(errs)}`,
      );
    } else {
      assert.equal(
        rule3Fired,
        true,
        `INVARIANT VIOLATION (false accept): "${label}"\n  audience: ${JSON.stringify(audience)}\n  redirectUris: ${JSON.stringify(redirectUris)}\n  errors: ${JSON.stringify(errs)}`,
      );
    }
  }
});

// ─── Property 1: origin-exact matching is never a substring match ─────────────
//
// If parsed origin of audience != parsed origin of every redirect, rule 3 must fire.

test('property: audienceMatchesRedirect is fail-closed when origins differ', () => {
  fc.assert(
    fc.property(
      // A known-good audience URL
      fc.constantFrom(
        'https://app.example.com',
        'https://keep.dunn.dev',
        'https://jellyfin.dunn.dev',
        'https://login.tailscale.com',
      ),
      // A crafted redirect whose parsed origin is DIFFERENT from the audience
      fc.oneof(
        // Subdomain suffix: audience + extra suffix
        fc.constantFrom('.evil.com', '.attacker.net', '.phish.io').map(
          (suffix) => `https://app.example.com${suffix}/cb`,
        ),
        // Credential injection: trusted host as user info
        fc.constantFrom('evil.com', 'attacker.net').map(
          (host) => `https://app.example.com@${host}/cb`,
        ),
        // Scheme change
        fc.constantFrom('http://', 'ftp://').map((scheme) => `${scheme}app.example.com/cb`),
        // Port change
        fc.constantFrom(':8080', ':9443', ':3000').map(
          (port) => `https://app.example.com${port}/cb`,
        ),
        // Random non-matching URL
        fc
          .webUrl({ withQueryParameters: false })
          .filter((u) => {
            const o = originOf(u);
            return o !== null && o !== 'https://app.example.com';
          }),
      ),
      (audience, redirect) => {
        const audienceOrigin = originOf(audience);
        const redirectOrigin = originOf(redirect);

        // Precondition: origins must genuinely differ for the invariant to apply.
        if (audienceOrigin === null || redirectOrigin === null) return;
        if (audienceOrigin === redirectOrigin) return; // same origin → valid, skip

        const manifest = makeManifest({
          redirectUris: [redirect],
          audience: [audience],
        });
        const result = audienceMatchesRedirect(manifest, [audience]);
        assert.equal(
          result,
          false,
          `INVARIANT VIOLATION: audienceMatchesRedirect returned true when origins differ\n  audience: ${audience} (origin: ${audienceOrigin})\n  redirect: ${redirect} (origin: ${redirectOrigin})`,
        );
      },
    ),
    { numRuns: 1000, verbose: true },
  );
});

// ─── Property 2: origin match is sufficient (no false rejections) ─────────────
//
// If every audience entry's origin IS in the redirect_uri origin set, rule 3
// must NOT fire. This guards against regressions that tighten the check too far.

test('property: audienceMatchesRedirect accepts when every audience origin is covered', () => {
  fc.assert(
    fc.property(
      // Generate matching (audience, redirect) pairs from a common base URL
      fc.array(
        fc.record({
          base: fc.constantFrom(
            'https://app.example.com',
            'https://keep.dunn.dev',
            'https://jellyfin.dunn.dev',
          ),
          audPath: fc.stringMatching(/^[a-z0-9\-]{0,8}$/),
          redPath: fc.stringMatching(/^[a-z0-9\/\-]{0,16}$/),
        }),
        { minLength: 1, maxLength: 4 },
      ),
      (pairs) => {
        const audience = pairs.map(({ base, audPath }) => `${base}/${audPath}`);
        const redirectUris = pairs.map(({ base, redPath }) => `${base}/${redPath}`);

        // All audience origins are covered by redirect_uri origins by construction.
        const manifest = makeManifest({ redirectUris, audience });
        const result = audienceMatchesRedirect(manifest, audience);
        assert.equal(
          result,
          true,
          `INVARIANT VIOLATION: audienceMatchesRedirect returned false when origins match\n  audience: ${JSON.stringify(audience)}\n  redirects: ${JSON.stringify(redirectUris)}`,
        );
      },
    ),
    { numRuns: 1000 },
  );
});

// ─── Property 3: crafted hostnames that embed a trusted string must not pass ──
//
// Generates adversarial hostnames that CONTAIN "keep.dunn.dev" as a substring
// but are not equal to it. Verifies the validator rejects them as audiences
// when the redirect is the real keep.dunn.dev.

test('property: substring-embedded trusted host in audience does not pass', () => {
  const trustedRedirect = 'https://keep.dunn.dev/callback';
  const trustedOrigin = 'https://keep.dunn.dev';

  fc.assert(
    fc.property(
      // Generate a prefix and suffix that wrap the trusted host in various ways
      fc.record({
        prefix: fc.stringMatching(/^[a-z0-9\-]{0,12}$/),
        suffix: fc.constantFrom('.evil.com', '.attacker.net', '.phish.io', ''),
        scheme: fc.constantFrom('https://', 'http://'),
        userInfo: fc.constantFrom('', 'keep.dunn.dev@', 'keep.dunn.dev:443@'),
      }),
      ({ prefix, suffix, scheme, userInfo }) => {
        // Build candidate audience URL
        let host;
        if (prefix && suffix) {
          host = `${prefix}.keep.dunn.dev${suffix}`;
        } else if (prefix) {
          host = `${prefix}.keep.dunn.dev`;
        } else if (suffix) {
          host = `keep.dunn.dev${suffix}`;
        } else {
          // No wrapping — this is the legitimate case, skip
          return;
        }

        const candidate = `${scheme}${userInfo}${host}/path`;
        const candidateOrigin = originOf(candidate);

        // Only assert on parseable URLs that differ from the trusted origin
        if (candidateOrigin === null || candidateOrigin === trustedOrigin) return;

        const manifest = makeManifest({
          redirectUris: [trustedRedirect],
          audience: [candidate],
        });
        const errs = validateClients([manifest]);
        const rule3Fired = errs.some((e) => e.includes('no oidc.audience origin matches'));

        assert.equal(
          rule3Fired,
          true,
          `INVARIANT VIOLATION: crafted audience "${candidate}" (origin: ${candidateOrigin}) slipped past rule 3 against redirect "${trustedRedirect}"`,
        );
      },
    ),
    { numRuns: 1000 },
  );
});

// ─── Property 4: random (audience, redirect) pairs satisfy origin-equality ────
//
// For any two parseable URLs: audienceMatchesRedirect(m, [aud]) === true
// if and only if originOf(aud) is in { originOf(r) : r in m.redirectUris }.

test('property: audienceMatchesRedirect is equivalent to set-membership on origins', () => {
  fc.assert(
    fc.property(
      fc.array(fc.webUrl({ withQueryParameters: false }), { minLength: 1, maxLength: 5 }),
      fc.array(fc.webUrl({ withQueryParameters: false }), { minLength: 1, maxLength: 3 }),
      (redirectUris, audience) => {
        const manifest = makeManifest({ redirectUris, audience });
        const result = audienceMatchesRedirect(manifest, audience);

        const redirectOrigins = new Set(
          redirectUris.map(originOf).filter((o) => o !== null),
        );

        if (redirectOrigins.size === 0) {
          // No usable redirect origins: should be fail-closed (false)
          assert.equal(result, false, 'Expected false when no usable redirect origins');
          return;
        }

        const allAudsCovered = audience.every((a) => {
          const o = originOf(a);
          return o !== null && redirectOrigins.has(o);
        });

        assert.equal(
          result,
          allAudsCovered,
          `audienceMatchesRedirect(${JSON.stringify(audience)}, redirects=${JSON.stringify(redirectUris)}) = ${result} but expected ${allAudsCovered}`,
        );
      },
    ),
    { numRuns: 1000 },
  );
});

// ─── Explicit: null/undefined manifest is fail-closed ─────────────────────────

test('audienceMatchesRedirect(undefined, ...) is always false', () => {
  fc.assert(
    fc.property(
      fc.array(fc.webUrl(), { maxLength: 5 }),
      (auds) => {
        assert.equal(audienceMatchesRedirect(undefined, auds), false);
      },
    ),
    { numRuns: 200 },
  );
});

// ─── Explicit: empty audience is always true for a known client ───────────────

test('audienceMatchesRedirect(manifest, []) is always true (nothing to constrain)', () => {
  const manifest = makeManifest({ redirectUris: [TRUSTED_REDIRECT], audience: [TRUSTED_ORIGIN] });
  assert.equal(audienceMatchesRedirect(manifest, []), true);
  assert.equal(audienceMatchesRedirect(manifest, undefined), true);
});

// ─── Explicit: no-redirect-uris + non-empty audience is fail-closed ───────────

test('audienceMatchesRedirect is false when manifest has no redirect_uris (no usable origins)', () => {
  const manifest = makeManifest({ redirectUris: [], audience: [TRUSTED_ORIGIN] });
  assert.equal(audienceMatchesRedirect(manifest, [TRUSTED_ORIGIN]), false);
});

// ─── Explicit: multi-audience, one bad entry fails the whole check ────────────

test('validateClients rule 3 fires if ANY audience entry has no matching redirect origin', () => {
  const manifest = makeManifest({
    redirectUris: ['https://keep.dunn.dev/cb'],
    audience: ['https://keep.dunn.dev', 'https://evil.com'],
  });
  const errs = validateClients([manifest]);
  assert.ok(
    errs.some((e) => e.includes('no oidc.audience origin matches')),
    `Expected rule 3 to fire, got: ${JSON.stringify(errs)}`,
  );
});

// ─── Explicit: non-canonical URL forms normalised by WHATWG URL parser ────────
//
// FINDING (low severity / correctness, not security bypass):
//
// The WHATWG URL parser normalises several non-canonical URL forms to the same
// origin as the canonical form. Examples:
//
//   https:keep.dunn.dev      → origin: https://keep.dunn.dev  (scheme-relative missing //)
//   HTTPS://keep.dunn.dev    → origin: https://keep.dunn.dev  (uppercase scheme)
//   https:\\keep.dunn.dev    → origin: https://keep.dunn.dev  (backslash separator)
//   https://keep.dunn.dev:443 → origin: https://keep.dunn.dev (default port elided)
//
// The validator ACCEPTS these because originOf() correctly sees them as the
// same origin — and they ARE the same origin from a browser security model
// perspective. This is NOT a security bypass.
//
// However, the non-canonical string (e.g. "https:keep.dunn.dev") is stored
// verbatim as the audience value and placed into the id_token's aud claim.
// An OIDC client doing string-literal audience comparison
// (e.g. aud === "https://keep.dunn.dev") would FAIL verification at runtime.
// This is a consistency/correctness bug, not an access-control bypass.
//
// Mitigation: the manifest validator could optionally warn when an audience
// or redirect_uri is not in canonical form (i.e. `new URL(raw).href !== raw`).
// Tracked as a low-severity lint improvement.
//
// These tests document the current (correct) behavior for the normalised cases:

test('WHATWG URL: non-canonical scheme forms normalise to same origin (not a bypass)', () => {
  const nonCanonical = [
    'https:keep.dunn.dev',           // missing //
    'HTTPS://keep.dunn.dev',          // uppercase scheme
    'https:\\\\keep.dunn.dev',        // backslash separator (Node normalises)
    'https://keep.dunn.dev:443',      // explicit default port (elided by URL)
  ];
  for (const nc of nonCanonical) {
    const o = originOf(nc);
    // These all parse to the trusted origin — not a bypass, but non-canonical
    assert.equal(
      o,
      TRUSTED_ORIGIN,
      `Expected ${nc} to normalise to ${TRUSTED_ORIGIN}, got ${o}`,
    );
    // And validator accepts them (correct — origin IS the trusted origin)
    const manifest = makeManifest({ redirectUris: [TRUSTED_REDIRECT], audience: [nc] });
    const errs = validateClients([manifest]);
    const rule3Fired = errs.some((e) => e.includes('no oidc.audience origin matches'));
    assert.equal(
      rule3Fired,
      false,
      `Non-canonical URL ${nc} accepted by origin comparison (expected), but rule 3 fired unexpectedly: ${JSON.stringify(errs)}`,
    );
  }
});

// ─── Property 5: validateClients rule 3 correctness under random generation ───
//
// For random manifests where audience origins are NOT all in redirect origins:
// validateClients MUST return at least one error mentioning "audience origin".

test('property: validateClients rule 3 fires whenever audience origins are not covered', () => {
  fc.assert(
    fc.property(
      // Use distinct base domains to guarantee disjoint origins
      fc.record({
        redirectBase: fc.constantFrom('https://redirect.example.com', 'https://redirect2.example.com'),
        audienceBase: fc.constantFrom('https://aud.different.net', 'https://aud2.different.net'),
      }),
      ({ redirectBase, audienceBase }) => {
        if (originOf(redirectBase) === originOf(audienceBase)) return; // skip if same (shouldn't happen with our constants)

        const manifest = makeManifest({
          redirectUris: [`${redirectBase}/callback`],
          audience: [audienceBase],
        });
        const errs = validateClients([manifest]);
        assert.ok(
          errs.some((e) => e.includes('no oidc.audience origin matches')),
          `INVARIANT VIOLATION: rule 3 did not fire for mismatched origins.\n  redirect: ${redirectBase}\n  audience: ${audienceBase}\n  errs: ${JSON.stringify(errs)}`,
        );
      },
    ),
    { numRuns: 500 },
  );
});

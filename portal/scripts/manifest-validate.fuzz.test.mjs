// Invariant: validateClients rejects any OIDC client whose audience entries are not bound to its own redirects.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { audienceMatchesRedirect, validateClients, parseManifest } from '../src/lib/manifests.ts';

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

function originOf(raw) {
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}

const TRUSTED_ORIGIN = 'https://proxywatch.othala.test';
const TRUSTED_REDIRECT = 'https://proxywatch.othala.test/callback';

const ADVERSARIAL_CASES = [
  {
    label: 'credential injection: user:pass@host hides the real host',
    audience: ['https://proxywatch.othala.test:443@evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'credential injection: trusted host as username, evil host',
    audience: ['https://proxywatch.othala.test@evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'subdomain suffix: evil.com suffix on trusted host',
    audience: ['https://proxywatch.othala.test.evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'fragment confusion: trusted origin in fragment of evil URL',
    audience: ['https://evil.com#proxywatch.othala.test'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'scheme mismatch: http vs https',
    audience: ['http://proxywatch.othala.test'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'port mismatch: unexpected port',
    audience: ['https://proxywatch.othala.test:8443'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'path appended to audience does not hide the wrong host',
    audience: ['https://evil.com/proxywatch.othala.test'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'null-byte in audience: URL parse throws → fail-closed (null origin)',
    audience: ['https://proxywatch.othala.test\x00.evil.com'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'unicode lookalike: cyrillic е punycodes to different origin',
    audience: ['https://proxywatch.dunn.dеv'],   // Cyrillic е (U+0435) → xn--dv-nlc, not ASCII e
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },
  {
    label: 'IPv6 with embedded trusted host: URL parse throws → fail-closed',
    audience: ['https://[::1]proxywatch.othala.test'],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: false,
  },

  {
    label: 'redirect with user:pass@trusted does NOT give the trusted origin',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://evil.com:443@proxywatch.othala.test/cb'],
    shouldPass: true,
  },
  {
    label: 'redirect with evil subdomain does NOT match trusted audience',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://proxywatch.othala.test.evil.com/cb'],
    shouldPass: false,
  },
  {
    label: 'redirect with scheme mismatch does NOT match trusted audience',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['http://proxywatch.othala.test/cb'],
    shouldPass: false,
  },

  {
    label: 'exact match: audience origin == redirect origin (happy path)',
    audience: [TRUSTED_ORIGIN],
    redirectUris: [TRUSTED_REDIRECT],
    shouldPass: true,
  },
  {
    label: 'explicit port 443 in redirect matches audience without port',
    audience: [TRUSTED_ORIGIN],
    redirectUris: ['https://proxywatch.othala.test:443/callback'],
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
    redirectUris: ['https://proxywatch.othala.test/callback#section'],
    shouldPass: true,
  },
];

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

test('property: audienceMatchesRedirect is fail-closed when origins differ', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(
        'https://app.example.com',
        'https://proxywatch.othala.test',
        'https://filedrop.othala.test',
        'https://login.example.net',
      ),
      fc.oneof(
        fc.constantFrom('.evil.com', '.attacker.net', '.phish.io').map(
          (suffix) => `https://app.example.com${suffix}/cb`,
        ),
        fc.constantFrom('evil.com', 'attacker.net').map(
          (host) => `https://app.example.com@${host}/cb`,
        ),
        fc.constantFrom('http://', 'ftp://').map((scheme) => `${scheme}app.example.com/cb`),
        fc.constantFrom(':8080', ':9443', ':3000').map(
          (port) => `https://app.example.com${port}/cb`,
        ),
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

test('property: audienceMatchesRedirect accepts when every audience origin is covered', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.record({
          base: fc.constantFrom(
            'https://app.example.com',
            'https://proxywatch.othala.test',
            'https://filedrop.othala.test',
          ),
          audPath: fc.stringMatching(/^[a-z0-9\-]{0,8}$/),
          redPath: fc.stringMatching(/^[a-z0-9\/\-]{0,16}$/),
        }),
        { minLength: 1, maxLength: 4 },
      ),
      (pairs) => {
        const audience = pairs.map(({ base, audPath }) => `${base}/${audPath}`);
        const redirectUris = pairs.map(({ base, redPath }) => `${base}/${redPath}`);

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

test('property: substring-embedded trusted host in audience does not pass', () => {
  const trustedRedirect = 'https://proxywatch.othala.test/callback';
  const trustedOrigin = 'https://proxywatch.othala.test';

  fc.assert(
    fc.property(
      fc.record({
        prefix: fc.stringMatching(/^[a-z0-9\-]{0,12}$/),
        suffix: fc.constantFrom('.evil.com', '.attacker.net', '.phish.io', ''),
        scheme: fc.constantFrom('https://', 'http://'),
        userInfo: fc.constantFrom('', 'proxywatch.othala.test@', 'proxywatch.othala.test:443@'),
      }),
      ({ prefix, suffix, scheme, userInfo }) => {
        let host;
        if (prefix && suffix) {
          host = `${prefix}.proxywatch.othala.test${suffix}`;
        } else if (prefix) {
          host = `${prefix}.proxywatch.othala.test`;
        } else if (suffix) {
          host = `proxywatch.othala.test${suffix}`;
        } else {
          return;
        }

        const candidate = `${scheme}${userInfo}${host}/path`;
        const candidateOrigin = originOf(candidate);

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

test('audienceMatchesRedirect(manifest, []) is always true (nothing to constrain)', () => {
  const manifest = makeManifest({ redirectUris: [TRUSTED_REDIRECT], audience: [TRUSTED_ORIGIN] });
  assert.equal(audienceMatchesRedirect(manifest, []), true);
  assert.equal(audienceMatchesRedirect(manifest, undefined), true);
});

test('audienceMatchesRedirect is false when manifest has no redirect_uris (no usable origins)', () => {
  const manifest = makeManifest({ redirectUris: [], audience: [TRUSTED_ORIGIN] });
  assert.equal(audienceMatchesRedirect(manifest, [TRUSTED_ORIGIN]), false);
});

test('validateClients rule 3 fires if ANY audience entry has no matching redirect origin', () => {
  const manifest = makeManifest({
    redirectUris: ['https://proxywatch.othala.test/cb'],
    audience: ['https://proxywatch.othala.test', 'https://evil.com'],
  });
  const errs = validateClients([manifest]);
  assert.ok(
    errs.some((e) => e.includes('no oidc.audience origin matches')),
    `Expected rule 3 to fire, got: ${JSON.stringify(errs)}`,
  );
});

test('WHATWG URL: non-canonical scheme forms normalise to same origin (not a bypass)', () => {
  const nonCanonical = [
    'https:proxywatch.othala.test',           // missing //
    'HTTPS://proxywatch.othala.test',          // uppercase scheme
    'https:\\\\proxywatch.othala.test',        // backslash separator (Node normalises)
    'https://proxywatch.othala.test:443',      // explicit default port (elided by URL)
  ];
  for (const nc of nonCanonical) {
    const o = originOf(nc);
    assert.equal(
      o,
      TRUSTED_ORIGIN,
      `Expected ${nc} to normalise to ${TRUSTED_ORIGIN}, got ${o}`,
    );
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

test('property: validateClients rule 3 fires whenever audience origins are not covered', () => {
  fc.assert(
    fc.property(
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

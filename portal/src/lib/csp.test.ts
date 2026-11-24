import { describe, expect, it } from 'vitest';
import { contentSecurityPolicy, formActionSources, redirectSchemeSource } from './csp';

describe('formActionSources', () => {
  it('is self plus the apex wildcard plus each Kratos origin', () => {
    expect(
      formActionSources({
        apex: 'example.test',
        kratosUrls: ['https://auth.example.test/', 'http://kratos:4433'],
      }),
    ).toBe("'self' https://*.example.test https://auth.example.test http://kratos:4433");
  });

  it('keeps the Kratos origin when the apex is unset', () => {
    expect(formActionSources({ kratosUrls: ['https://id.other.test/path'] })).toBe(
      "'self' https://id.other.test",
    );
  });

  it('lists a shared origin once', () => {
    expect(
      formActionSources({ kratosUrls: ['https://auth.example.test/', 'https://auth.example.test'] }),
    ).toBe("'self' https://auth.example.test");
  });

  it('drops unset, unparseable and non-http values', () => {
    expect(
      formActionSources({ apex: '  ', kratosUrls: [undefined, '', 'not a url', 'javascript:alert(1)'] }),
    ).toBe("'self'");
  });
});

describe('native-app redirect schemes', () => {
  it('adds each custom redirect_uri scheme once, lowercased, after the origins', () => {
    expect(
      formActionSources({
        apex: 'example.test',
        kratosUrls: ['https://auth.example.test/'],
        redirectUris: ['https://app.example.test/cb', 'app.photos:///oauth-callback', 'App.Photos:/other', 'com.example.native:/cb'],
      }),
    ).toBe("'self' https://*.example.test https://auth.example.test app.photos: com.example.native:");
  });

  it('refuses http(s) and script- or document-bearing schemes', () => {
    for (const raw of ['https://x.test/cb', 'http://x.test/cb', 'javascript:alert(1)', 'JavaScript:alert(1)', 'data:text/html,x', 'blob:https://x.test/1', 'filesystem:https://x.test/t', 'about:blank', 'file:///etc/passwd', 'vbscript:x', 'wss://x.test']) {
      expect(redirectSchemeSource(raw), raw).toBeNull();
    }
    expect(formActionSources({ kratosUrls: [], redirectUris: ['javascript:alert(1)', 'data:x', 'https://evil.test/'] })).toBe("'self'");
  });

  it('ignores malformed values', () => {
    for (const raw of [undefined, '', '   ', 'no-scheme', '/relative/cb', '1app:/cb', '-app:/cb', 'a b:/cb', 'app_x:/cb', "app'x:/cb"]) {
      expect(redirectSchemeSource(raw), String(raw)).toBeNull();
    }
  });
});

describe('contentSecurityPolicy', () => {
  it('keeps the fixed directives and ends with form-action', () => {
    expect(contentSecurityPolicy({ kratosUrls: [] })).toBe(
      "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
    );
  });
});

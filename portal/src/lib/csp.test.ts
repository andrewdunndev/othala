import { describe, expect, it } from 'vitest';
import { contentSecurityPolicy, formActionSources } from './csp';

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

describe('contentSecurityPolicy', () => {
  it('keeps the fixed directives and ends with form-action', () => {
    expect(contentSecurityPolicy({ kratosUrls: [] })).toBe(
      "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
    );
  });
});

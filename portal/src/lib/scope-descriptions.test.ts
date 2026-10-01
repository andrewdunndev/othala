import { describe, it, expect } from 'vitest';
import { describeScopeList } from './scope-descriptions';

describe('describeScopeList', () => {
  it('words profile, email and groups in plain terms, in request order', () => {
    const d = describeScopeList(['profile', 'email', 'groups']).map((s) => s.description);
    expect(d).toEqual(['Your name and username', 'Your email address', 'Your access level in this app']);
  });
  it('keeps an unknown scope visible, and never maps prototype names', () => {
    expect(describeScopeList(['calendar'])[0].description).toContain('calendar');
    expect(describeScopeList(['constructor'])[0].description).toContain('constructor');
  });

  it('names the app for the groups scope', () => {
    expect(describeScopeList(['groups'], 'Jellyfin')[0].description).toBe('Your access level in Jellyfin');
  });
});

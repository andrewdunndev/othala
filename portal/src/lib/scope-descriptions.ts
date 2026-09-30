// Plain-language descriptions of well-known OIDC/OAuth2 scopes for the consent
// screen (/auth/consent). Unlisted scopes fall back to the raw scope name.

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'your identity (required)',
  email: 'your email address',
  profile: 'your display name and username',
  groups: 'your group memberships',
  offline_access: 'stay signed in across sessions',
};

export interface ScopeDescription {
  scope: string;
  description: string;
}

/**
 * Map a list of scope strings to human-readable descriptions.
 * Unknown scopes fall back to the raw scope name as the description.
 */
export function describeScopeList(scopes: string[]): ScopeDescription[] {
  return scopes.map((scope) => ({
    scope,
    description: SCOPE_DESCRIPTIONS[scope] ?? scope,
  }));
}

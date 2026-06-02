// Human-readable descriptions for well-known OIDC/OAuth2 scopes.
//
// Used by the consent grant screen (/auth/consent) to show a plain-language
// list of what the client is requesting access to.
//
// Scope names that do not appear in this table fall back to the raw scope
// name itself (no silent omission).

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

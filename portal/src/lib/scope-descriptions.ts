// Plain-language descriptions of well-known OIDC/OAuth2 scopes for the consent screen (/auth/consent): what the app will
// see, as a noun phrase under "will see". Unlisted scopes keep their raw name so nothing is granted unseen.

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'That it is you, so it can sign you in',
  profile: 'Your name and username',
  email: 'Your email address',
  groups: 'Which household groups you belong to',
  offline_access: 'Staying signed in on this device between visits',
};

export interface ScopeDescription {
  scope: string;
  description: string;
}

/** Describe each scope in order; an unknown scope reads "Something else it asked for (name)". */
export function describeScopeList(scopes: string[]): ScopeDescription[] {
  return scopes.map((scope) => ({
    scope,
    description: Object.hasOwn(SCOPE_DESCRIPTIONS, scope) ? SCOPE_DESCRIPTIONS[scope] : `Something else it asked for (${scope})`,
  }));
}

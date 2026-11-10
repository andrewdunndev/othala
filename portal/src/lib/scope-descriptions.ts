// Plain-language descriptions of well-known OIDC/OAuth2 scopes for the consent screen (/auth/consent): what the app will
// see, as a noun phrase under "will see". Unlisted scopes keep their raw name so nothing is granted unseen.

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'That it is you, so it can sign you in',
  profile: 'Your name, username and picture',
  email: 'Your email address',
  groups: 'Your access level in this app',
  offline_access: 'Staying signed in on this device between visits',
};

export interface ScopeDescription {
  scope: string;
  description: string;
}

/** Describe each scope in order, naming the app for groups (the claim carries only that app's own level); an unknown scope reads "Something else it asked for (name)". */
export function describeScopeList(scopes: string[], appName?: string): ScopeDescription[] {
  return scopes.map((scope) => ({
    scope,
    description:
      scope === 'groups' && appName
        ? `Your access level in ${appName}`
        : Object.hasOwn(SCOPE_DESCRIPTIONS, scope)
          ? SCOPE_DESCRIPTIONS[scope]
          : `Something else it asked for (${scope})`,
  }));
}

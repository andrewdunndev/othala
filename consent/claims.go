package main

// BuildIDTokenClaims maps a Kratos identity into the OIDC id_token claims
// the apps consume. Hydra does not auto-populate these from Kratos; the
// consent step is the only place to inject them.
//
// Mapping rules (matches docs/architecture.md group model + identity.schema):
//
//	email              = traits.email                       (required)
//	email_verified     = verifiable_addresses[email].verified (omitted if no record)
//	name               = traits.displayName, fallback traits.username
//	preferred_username = traits.username
//	groups             = metadata_admin.groups (string array)
//	sub                = identity.id (set by Hydra from Subject; not here)
//
// Anything missing is omitted rather than emitted as null. Apps that read
// these claims (Vaultwarden, Mealie, Jellyfin, etc.) tolerate missing fields
// better than null fields.
func BuildIDTokenClaims(id *Identity) map[string]any {
	claims := map[string]any{}
	if id == nil {
		return claims
	}

	traits := id.Traits

	if email, ok := stringTrait(traits, "email"); ok {
		claims["email"] = email
		if verified, ok := emailVerified(id, email); ok {
			claims["email_verified"] = verified
		}
	}

	username, hasUsername := stringTrait(traits, "username")
	if hasUsername {
		claims["preferred_username"] = username
	}

	if display, ok := stringTrait(traits, "displayName"); ok {
		claims["name"] = display
	} else if hasUsername {
		claims["name"] = username
	}

	if groups := extractGroups(id.MetadataAdmin); groups != nil {
		claims["groups"] = groups
	}

	return claims
}

// deepMergeClaims merges src into dst recursively. Conflict semantics:
//
//   - Missing key in dst: copy src[k] into dst[k].
//   - Both values are map[string]any: recurse.
//   - Both values are []any (or compatible slice shapes): src wins
//     wholesale. Last-write-wins; we deliberately do not array-union
//     because the existing behavior for the auto `groups` claim has been
//     "role's claim_emit groups overrides identity groups" and we keep it.
//   - Type mismatch or scalar conflict: src wins.
//
// yaml.v3 unmarshals nested mappings under `claim_emit map[string]any`
// values as map[string]any (not map[interface{}]interface{}), so the
// shape this function sees on the manifest side matches what dst (the
// id_token claims) holds.
//
// Only one role applies per user per client, so the array-union question
// is moot in practice; the chosen behavior is what's documented in
// consent/README.md "Claim emission semantics".
func deepMergeClaims(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	for k, sv := range src {
		dv, present := dst[k]
		if !present {
			dst[k] = sv
			continue
		}
		dm, dOk := dv.(map[string]any)
		sm, sOk := sv.(map[string]any)
		if dOk && sOk {
			deepMergeClaims(dm, sm)
			continue
		}
		// Slice merge is defined as last-write-wins. See doc comment.
		dst[k] = sv
	}
}

func stringTrait(traits map[string]any, key string) (string, bool) {
	if traits == nil {
		return "", false
	}
	v, ok := traits[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// emailVerified picks the verifiable_addresses entry matching the email
// trait. Falls back to the first entry if no exact match. Returns ok=false
// if no addresses exist so the claim is omitted entirely.
func emailVerified(id *Identity, email string) (bool, bool) {
	if len(id.VerifiableAddresses) == 0 {
		return false, false
	}
	for _, a := range id.VerifiableAddresses {
		if a.Value == email {
			return a.Verified, true
		}
	}
	return id.VerifiableAddresses[0].Verified, true
}

// extractGroups tolerates either []string or []any (which is what
// encoding/json gives us when decoding into map[string]any).
func extractGroups(meta map[string]any) []string {
	if meta == nil {
		return nil
	}
	raw, ok := meta["groups"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

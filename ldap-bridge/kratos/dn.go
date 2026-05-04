// DN parsing for the bridge.
//
// LDAP DN convention (locked decision E2):
//
//	uid=<username>,ou=users,<base_dn>
//
// Examples (with base_dn = dc=dunn,dc=dev):
//
//	uid=andrew.dunn,ou=users,dc=dunn,dc=dev
//	uid=jane,ou=users,dc=dunn,dc=dev
package kratos

import (
	"errors"
	"strings"
)

// parseUsernameFromDN extracts the username from a bind DN, validating
// that the DN matches the expected format and base.
//
// Smuggle-defense (fuzz finding): the returned username MUST NOT
// contain LDAP DN separators ("," "=") or NUL. A bindDN like
// "uid=a\,b,ou=users,..." that escapes a comma inside the uid value
// would otherwise round-trip a comma in the returned username and
// any caller that concatenates `"uid=" + username + "," + baseDN`
// produces an attacker-controlled DN string. We reject the DN rather
// than try to canonicalise the escape.
func parseUsernameFromDN(bindDN, baseDN string) (string, error) {
	bindDN = strings.ToLower(strings.TrimSpace(bindDN))
	baseDN = strings.ToLower(strings.TrimSpace(baseDN))

	expectedSuffix := ",ou=users," + baseDN
	if !strings.HasSuffix(bindDN, expectedSuffix) {
		return "", errors.New("bind DN does not match expected suffix")
	}

	rdn := strings.TrimSuffix(bindDN, expectedSuffix)
	if !strings.HasPrefix(rdn, "uid=") {
		return "", errors.New("bind DN RDN must use uid attribute")
	}
	username := strings.TrimPrefix(rdn, "uid=")

	if username == "" {
		return "", errors.New("bind DN has empty uid")
	}

	// Reject any uid value carrying a DN separator or NUL. Includes
	// escaped sequences like "a\,b" — `\` and `,` both land as smuggle
	// chars; tolerating them widens the attack surface for downstream
	// consumers that string-concat the username.
	if strings.ContainsAny(username, ",=\x00\\") {
		return "", errors.New("bind DN uid contains forbidden character")
	}

	return username, nil
}

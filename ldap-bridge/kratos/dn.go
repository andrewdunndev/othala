// DN parsing for the bridge.
//
// LDAP DN convention (locked decision E2):
//   uid=<username>,ou=users,<base_dn>
//
// Examples (with base_dn = dc=dunn,dc=dev):
//   uid=andrew.dunn,ou=users,dc=dunn,dc=dev
//   uid=jane.dunn,ou=users,dc=dunn,dc=dev
package kratos

import (
	"errors"
	"strings"
)

// parseUsernameFromDN extracts the username from a bind DN, validating
// that the DN matches the expected format and base.
func parseUsernameFromDN(bindDN, baseDN string) (string, error) {
	bindDN = strings.ToLower(strings.TrimSpace(bindDN))
	baseDN = strings.ToLower(strings.TrimSpace(baseDN))

	expectedSuffix := ",ou=users," + baseDN
	if !strings.HasSuffix(bindDN, expectedSuffix) {
		return "", errors.New("bind DN does not match expected suffix")
	}

	// Strip suffix; what remains is the RDN, e.g., "uid=andrew.dunn"
	rdn := strings.TrimSuffix(bindDN, expectedSuffix)
	if !strings.HasPrefix(rdn, "uid=") {
		return "", errors.New("bind DN RDN must use uid attribute")
	}
	username := strings.TrimPrefix(rdn, "uid=")

	if username == "" {
		return "", errors.New("bind DN has empty uid")
	}

	return username, nil
}

// applyFilter is a placeholder for the filter logic glauth provides
// helpers for; the real implementation will use github.com/glauth/glauth
// helpers to evaluate searchReq.Filter against entries.
func applyFilter(entries []interface{}, filter string) []interface{} {
	// TODO: glauth provides filter evaluation helpers; wire up.
	return entries
}

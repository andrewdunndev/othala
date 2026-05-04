package kratos

import (
	"strings"
	"testing"
)

// FuzzParseUsernameFromDN exercises parseUsernameFromDN against
// arbitrary (bindDN, baseDN) pairs. Invariants:
//
//   - The function never panics on any input.
//   - A returned non-error username never contains the LDAP DN
//     separators "," or "=" or a NUL byte. These would be smuggle
//     vectors if a downstream consumer concatenated the username back
//     into a DN string.
//
// Seeded with the cases from dn_test.go.
func FuzzParseUsernameFromDN(f *testing.F) {
	f.Add("uid=andrew.dunn,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("UID=Jane,ou=Users,DC=dunn,DC=dev", "dc=dunn,dc=dev")
	f.Add("cn=foo,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("uid=,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("  uid=foo,ou=users,dc=dunn,dc=dev  ", "dc=dunn,dc=dev")
	f.Add("", "")
	f.Add("uid=a\\,b,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")

	f.Fuzz(func(t *testing.T, bindDN, baseDN string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseUsernameFromDN panicked on (%q, %q): %v", bindDN, baseDN, r)
			}
		}()
		username, err := parseUsernameFromDN(bindDN, baseDN)
		if err != nil {
			return
		}
		// Invariant: no DN separators or NUL in the returned username.
		// If any of these slipped through, a downstream string-concat
		// of "uid=" + username + "," + baseDN would produce an
		// attacker-controlled DN.
		if strings.ContainsAny(username, ",=\x00") {
			t.Fatalf("parseUsernameFromDN returned username with smuggle char: %q (bindDN=%q baseDN=%q)",
				username, bindDN, baseDN)
		}
	})
}

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
	// Additional adversarial seeds: metachar injection attempts.
	f.Add("uid=a=b,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("uid=\x00,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("uid=(foo),ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	f.Add("uid=foo+bar,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	// baseDN injection: attacker supplies a baseDN that ends the expected
	// suffix early and appends a second ou.
	f.Add("uid=foo,ou=users,dc=evil,dc=org,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	// Unicode look-alikes and homoglyphs.
	f.Add("uid=андрей,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	// Long strings / oversized.
	f.Add("uid="+strings.Repeat("a", 256)+",ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev")
	// NUL in baseDN.
	f.Add("uid=foo,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=\x00ev")

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

// dnMetaChars is the set of characters that escapeDNValue will escape per
// RFC 4514 §2.4. A value containing any of these chars will be escaped, so
// the "exact match" invariant (no escaping expected) applies only to values
// that contain none of these chars (and no leading/trailing space or leading #).
// Note: use an interpreted string literal (double-quoted) so \x00 is a real NUL.
const dnMetaChars = "\",=()\\+#;<>\x00"

// countUnescapedCommas counts commas in s that are NOT preceded by a backslash.
// After RFC 4514 escaping, a literal comma in an attribute value appears as "\,"
// in the DN string; these are not DN component separators.
func countUnescapedCommas(s string) int {
	n := 0
	for i, c := range s {
		if c == ',' && (i == 0 || s[i-1] != '\\') {
			n++
		}
	}
	return n
}

// FuzzUserDN exercises the userDN builder (handler.go).
//
// Security invariant (post-fix): userDN MUST escape any LDAP DN metacharacters
// in the username so that the resulting DN has exactly the expected number of
// unescaped (structural) commas regardless of what the username contains.
// Before the fix, a username containing "," injected extra DN components.
// After the fix, escapeDNValue() encodes "," as "\," which is NOT a structural
// separator, so the unescaped-comma count stays correct.
func FuzzUserDN(f *testing.F) {
	// Normal cases.
	f.Add("andrew.dunn", "dc=dunn,dc=dev")
	f.Add("jane", "dc=dunn,dc=dev")
	f.Add("foo", "dc=example,dc=com")
	// Metachar injection attempts: these are the adversarial corpus.
	f.Add("a,b", "dc=dunn,dc=dev")          // comma injection
	f.Add("a=b", "dc=dunn,dc=dev")          // equals injection
	f.Add("a,ou=evil", "dc=dunn,dc=dev")    // OU injection
	f.Add("a,dc=evil,dc=org", "dc=dunn,dc=dev") // base escape
	f.Add("a\x00b", "dc=dunn,dc=dev")       // NUL in username
	f.Add("(foo)", "dc=dunn,dc=dev")        // filter metachar
	f.Add("a\\b", "dc=dunn,dc=dev")         // backslash
	f.Add(strings.Repeat("a", 512), "dc=dunn,dc=dev") // oversized
	f.Add("", "dc=dunn,dc=dev")             // empty username
	f.Add("foo", "")                        // empty baseDN

	// We need a Handler to call userDN; build a minimal one.
	f.Fuzz(func(t *testing.T, username, baseDN string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("userDN panicked on (%q, %q): %v", username, baseDN, r)
			}
		}()

		h := &Handler{cfg: Config{BaseDN: baseDN}}
		dn := h.userDN(username)

		// The returned DN must start with "uid=".
		if !strings.HasPrefix(dn, "uid=") {
			t.Fatalf("userDN did not start with 'uid=': %q", dn)
		}

		// Security invariant (post-fix): the number of UNESCAPED (structural)
		// commas in the resulting DN must equal exactly:
		//   1 (between uid RDN and ou=users) + 1 (between ou=users and baseDN)
		//   + strings.Count(baseDN, ",") (commas within baseDN itself).
		// Escaped commas (\,) in the value are NOT structural separators and
		// must not be counted. After escapeDNValue, no matter what the username
		// contains, the structural comma count must be correct.
		expectedUnescapedCommas := 1 + strings.Count(baseDN, ",") + 1 // ou=users + baseDN commas
		actualUnescapedCommas := countUnescapedCommas(dn)

		if actualUnescapedCommas > expectedUnescapedCommas {
			t.Fatalf("INJECTION: userDN produced extra structural DN components from username %q: dn=%q (expected %d unescaped commas, got %d)",
				username, dn, expectedUnescapedCommas, actualUnescapedCommas)
		}

		// Verify the DN is exactly as expected when username has no metacharacters
		// AND no leading/trailing space (RFC 4514 §2.4 requires escaping those).
		if !strings.ContainsAny(username, dnMetaChars) &&
			!strings.HasPrefix(username, " ") && !strings.HasPrefix(username, "#") &&
			!strings.HasSuffix(username, " ") {
			expectedDN := "uid=" + username + ",ou=users," + baseDN
			if dn != expectedDN {
				t.Fatalf("userDN produced unexpected result for clean username %q baseDN %q: got %q want %q",
					username, baseDN, dn, expectedDN)
			}
		}
	})
}

// FuzzGroupDN exercises the groupDN builder. Same structural invariant as
// FuzzUserDN but for group names (post-fix: escape-aware).
func FuzzGroupDN(f *testing.F) {
	// Normal cases.
	f.Add("admins", "dc=dunn,dc=dev")
	f.Add("users", "dc=dunn,dc=dev")
	// Adversarial corpus.
	f.Add("a,ou=evil", "dc=dunn,dc=dev")   // OU injection
	f.Add("a=b", "dc=dunn,dc=dev")         // equals injection
	f.Add("admins,dc=evil,dc=org", "dc=dunn,dc=dev") // base escape
	f.Add("(objectClass=*)", "dc=dunn,dc=dev") // filter injection
	f.Add("a\x00b", "dc=dunn,dc=dev")      // NUL
	f.Add("a\\,b", "dc=dunn,dc=dev")       // escaped comma
	f.Add("", "dc=dunn,dc=dev")            // empty name
	f.Add(strings.Repeat("x", 512), "dc=dunn,dc=dev") // oversized

	f.Fuzz(func(t *testing.T, groupName, baseDN string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("groupDN panicked on (%q, %q): %v", groupName, baseDN, r)
			}
		}()

		h := &Handler{cfg: Config{BaseDN: baseDN}}
		dn := h.groupDN(groupName)

		if !strings.HasPrefix(dn, "cn=") {
			t.Fatalf("groupDN did not start with 'cn=': %q", dn)
		}

		// Security invariant (post-fix): count only UNESCAPED structural commas.
		// escapeDNValue encodes metacharacters so they cannot inject extra components.
		expectedUnescapedCommas := 1 + strings.Count(baseDN, ",") + 1
		actualUnescapedCommas := countUnescapedCommas(dn)

		if actualUnescapedCommas > expectedUnescapedCommas {
			t.Fatalf("INJECTION: groupDN produced extra structural DN components from groupName %q: dn=%q (expected %d unescaped commas, got %d)",
				groupName, dn, expectedUnescapedCommas, actualUnescapedCommas)
		}

		// Exact-match check for clean inputs (no metacharacters and no
		// leading/trailing space, which RFC 4514 §2.4 also requires escaping).
		if !strings.ContainsAny(groupName, dnMetaChars) &&
			!strings.HasPrefix(groupName, " ") && !strings.HasPrefix(groupName, "#") &&
			!strings.HasSuffix(groupName, " ") {
			expectedDN := "cn=" + groupName + ",ou=groups," + baseDN
			if dn != expectedDN {
				t.Fatalf("groupDN produced unexpected result for clean name %q baseDN %q: got %q want %q",
					groupName, baseDN, dn, expectedDN)
			}
		}
	})
}

// FuzzUserDNRoundTrip verifies the round-trip property: for any username
// that parseUsernameFromDN would accept from a valid user bind, building
// the DN with userDN and then re-parsing must yield the original username.
// A violation here means the builder and parser are inconsistent.
func FuzzUserDNRoundTrip(f *testing.F) {
	f.Add("andrew.dunn", "dc=dunn,dc=dev")
	f.Add("jane", "dc=dunn,dc=dev")
	f.Add("foo-bar", "dc=example,dc=com")
	f.Add("user123", "dc=corp,dc=internal")

	f.Fuzz(func(t *testing.T, username, baseDN string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("round-trip panicked on (%q, %q): %v", username, baseDN, r)
			}
		}()

		h := &Handler{cfg: Config{BaseDN: baseDN}}
		built := h.userDN(username)
		parsed, err := parseUsernameFromDN(built, baseDN)
		if err != nil {
			// If the parser rejects the built DN, check whether the username
			// itself was safe. If username was safe (no metacharacters, non-empty)
			// and baseDN is non-empty and trimmed (no leading/trailing whitespace),
			// a rejection is a bug in the builder or parser.
			//
			// Note: parseUsernameFromDN always TrimSpaces baseDN, but userDN uses
			// the raw cfg.BaseDN. In production New() trims BaseDN so these are
			// consistent. Fuzz tests that inject whitespace-padded baseDN values
			// expose that inconsistency deliberately; we exclude those from the
			// "must round-trip" invariant.
			if username != "" &&
				!strings.ContainsAny(username, dnMetaChars) &&
				// RFC 4514 §2.4: leading '#', leading space, and trailing space
				// are also escaped by escapeDNValue. parseUsernameFromDN rejects
				// backslash in the uid value, so these usernames can't round-trip.
				!strings.HasPrefix(username, "#") &&
				!strings.HasPrefix(username, " ") &&
				!strings.HasSuffix(username, " ") &&
				baseDN != "" &&
				strings.TrimSpace(baseDN) == baseDN &&
				!strings.ContainsAny(baseDN, "\x00") {
				t.Fatalf("round-trip: parseUsernameFromDN rejected DN built from safe username %q baseDN %q: built=%q err=%v",
					username, baseDN, built, err)
			}
			return
		}

		// If parsing succeeded, the round-tripped username must equal the
		// lowercased original (parseUsernameFromDN lowercases).
		expected := strings.ToLower(strings.TrimSpace(username))
		if parsed != expected {
			t.Fatalf("round-trip mismatch: username=%q built=%q re-parsed=%q (expected %q)",
				username, built, parsed, expected)
		}
	})
}

package kratos

import "testing"

func TestParseUsernameFromDN(t *testing.T) {
	cases := []struct {
		name    string
		bindDN  string
		baseDN  string
		want    string
		wantErr bool
	}{
		{"simple", "uid=andrew.dunn,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev", "andrew.dunn", false},
		{"uppercase normalized", "UID=Jane,ou=Users,DC=dunn,DC=dev", "dc=dunn,dc=dev", "jane", false},
		{"wrong rdn attr", "cn=foo,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev", "", true},
		{"wrong ou", "uid=foo,ou=people,dc=dunn,dc=dev", "dc=dunn,dc=dev", "", true},
		{"wrong base", "uid=foo,ou=users,dc=other,dc=org", "dc=dunn,dc=dev", "", true},
		{"empty uid", "uid=,ou=users,dc=dunn,dc=dev", "dc=dunn,dc=dev", "", true},
		{"trailing whitespace", "  uid=foo,ou=users,dc=dunn,dc=dev  ", "dc=dunn,dc=dev", "foo", false},
		// Smuggle-defense (fuzz finding): an escaped comma in the uid
		// value MUST be refused. Round-tripping it would let a caller
		// build an attacker-controlled DN by concat.
		{"escaped comma in uid", `uid=a\,b,ou=users,dc=dunn,dc=dev`, "dc=dunn,dc=dev", "", true},
		{"escaped equals in uid", `uid=a\=b,ou=users,dc=dunn,dc=dev`, "dc=dunn,dc=dev", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseUsernameFromDN(c.bindDN, c.baseDN)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

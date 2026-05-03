module dunn.dev/auth/ldap-bridge

go 1.22

require (
	github.com/glauth/glauth/v2 v2.5.0
	github.com/go-ldap/ldap/v3 v3.4.6
)

// Pin transitive deps via go.sum after `go mod tidy`.

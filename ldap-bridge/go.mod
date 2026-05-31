module dunn.dev/auth/ldap-bridge

go 1.22

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/glauth/glauth/v2 v2.4.0 // NOTE: glauth/ldap and glauth/glauth pins must advance together; the handler interface is defined in glauth/glauth and implemented against glauth/ldap types
	github.com/glauth/ldap v0.0.0-20260119000349-19bd16af77bb
)

require github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect

// glauth-kratos: a custom glauth binary with the Kratos backend
// embedded at compile time.
//
// Same build pattern as the custom Caddy image: direct go build, no
// runtime plugin loading. main.go imports glauth + our handler as
// side-effect imports; glauth's framework registers them in init() and
// loads our handler when the config selects it.
//
// Build:
//   go build -o glauth-kratos .
//
// Run:
//   ./glauth-kratos --config glauth.cfg
package main

import (
	glauth "github.com/glauth/glauth/v2/cmd"

	// Import our Kratos handler so glauth's plugin registry sees it.
	// The package's init() registers the handler with the name "kratos"
	// which glauth.cfg references via `backend.handler = kratos`.
	_ "dunn.dev/auth/ldap-bridge/kratos"
)

func main() {
	glauth.Run()
}

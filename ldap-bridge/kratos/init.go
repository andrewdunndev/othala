// Package init: register the kratos handler with glauth's plugin registry.
package kratos

import (
	"github.com/glauth/glauth/v2/pkg/handler"
)

// init registers our handler under the name "kratos" so glauth.cfg can
// reference it via:
//
//	[backend]
//	handler = kratos
//	[backend.kratos]
//	public_url = "http://kratos:4433"
//	admin_url = "http://kratos:4434"
//	admin_token_env = "KRATOS_BRIDGE_ADMIN_TOKEN"
//	base_dn = "dc=dunn,dc=dev"
//	identity_cache_ttl = "30s"
//	bind_cache_ttl = "30s"
//
// glauth invokes our factory with the parsed config map.
func init() {
	handler.Register("kratos", func(cfg map[string]interface{}) (handler.Handler, error) {
		c, err := configFromMap(cfg)
		if err != nil {
			return nil, err
		}
		return New(c)
	})
}

// configFromMap unmarshals glauth's config map into our typed Config.
// (glauth uses mapstructure under the hood; this is a thin wrapper.)
func configFromMap(m map[string]interface{}) (Config, error) {
	// TODO: real implementation via mapstructure.Decode
	return Config{}, nil
}

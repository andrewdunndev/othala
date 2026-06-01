// Config loader for glauth-kratos.
//
// File format mirrors glauth.cfg (TOML) so operator habits transfer.
// Secrets are not stored inline: keys named `*_env` name an environment
// variable that holds the actual value; the loader resolves them at
// startup.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"dunn.dev/othala/ldap-bridge/kratos"

	"github.com/BurntSushi/toml"
)

type fileConfig struct {
	Debug   bool        `toml:"debug"`
	LDAP    listenerCfg `toml:"ldap"`
	LDAPS   listenerCfg `toml:"ldaps"`
	Backend backendCfg  `toml:"backend"`
}

type listenerCfg struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
	Cert    string `toml:"cert"`
	Key     string `toml:"key"`
}

type backendCfg struct {
	BaseDN string        `toml:"baseDN"`
	Kratos kratosFileCfg `toml:"kratos"`
}

// kratosFileCfg is the raw TOML shape. We materialize a kratos.Config
// from this after env-var resolution.
//
// public_url / admin_url accept *_env companions following the same
// shape as admin_token_env: the canonical glauth.cfg in this repo
// uses public_url_env + admin_url_env so the file is topology-neutral.
// Lab compose sets KRATOS_PUBLIC_URL=http://kratos:4433; iac quadlets
// set KRATOS_PUBLIC_URL=http://auth-kratos:4433. Same shape as how
// admin_token_env carries the dummy bearer.
type kratosFileCfg struct {
	PublicURL        string `toml:"public_url"`
	PublicURLEnv     string `toml:"public_url_env"`
	AdminURL         string `toml:"admin_url"`
	AdminURLEnv      string `toml:"admin_url_env"`
	AdminToken       string `toml:"admin_token"`
	AdminTokenEnv    string `toml:"admin_token_env"`
	BaseDN           string `toml:"base_dn"`
	IdentityCacheTTL string `toml:"identity_cache_ttl"`
	BindCacheTTL     string `toml:"bind_cache_ttl"`
	// ServiceBindDN is the read-only DN for non-OAuth LDAP clients (e.g.
	// Jellyfin). When empty, the service-account bind feature is disabled.
	ServiceBindDN string `toml:"service_bind_dn"`
	// ServiceBindPasswordEnv names the env var that holds the service-account
	// password. Required when service_bind_dn is non-empty; resolved like
	// admin_token_env. Never inline the value here.
	ServiceBindPasswordEnv string `toml:"service_bind_password_env"`
}

// Config is the runtime config: kratosFileCfg becomes kratos.Config and
// env vars are resolved.
type Config struct {
	Debug   bool
	LDAP    listenerCfg
	LDAPS   listenerCfg
	Backend struct {
		BaseDN string
		Kratos kratos.Config
	}
}

func loadConfig(path string) (*Config, error) {
	var raw fileConfig
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}

	cfg := &Config{
		Debug: raw.Debug,
		LDAP:  raw.LDAP,
		LDAPS: raw.LDAPS,
	}
	cfg.Backend.BaseDN = raw.Backend.BaseDN

	k := raw.Backend.Kratos

	token := k.AdminToken
	if k.AdminTokenEnv != "" {
		v, ok := os.LookupEnv(k.AdminTokenEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("admin_token_env %q not set or empty", k.AdminTokenEnv)
		}
		token = v
	}

	publicURL := k.PublicURL
	if k.PublicURLEnv != "" {
		v, ok := os.LookupEnv(k.PublicURLEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("public_url_env %q not set or empty", k.PublicURLEnv)
		}
		publicURL = v
	}

	adminURL := k.AdminURL
	if k.AdminURLEnv != "" {
		v, ok := os.LookupEnv(k.AdminURLEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("admin_url_env %q not set or empty", k.AdminURLEnv)
		}
		adminURL = v
	}

	// Service-account bind: optional. If configured, the password env MUST
	// resolve to a non-empty value — a misconfigured secret is an error,
	// not a silent no-op.
	var servicePW string
	if k.ServiceBindDN != "" {
		if k.ServiceBindPasswordEnv == "" {
			return nil, fmt.Errorf("service_bind_dn is set but service_bind_password_env is empty")
		}
		v, ok := os.LookupEnv(k.ServiceBindPasswordEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("service_bind_password_env %q not set or empty", k.ServiceBindPasswordEnv)
		}
		servicePW = v
	}

	idTTL, err := parseTTL(k.IdentityCacheTTL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("identity_cache_ttl: %w", err)
	}
	bdTTL, err := parseTTL(k.BindCacheTTL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("bind_cache_ttl: %w", err)
	}

	baseDN := k.BaseDN
	if baseDN == "" {
		baseDN = raw.Backend.BaseDN
	}

	cfg.Backend.Kratos = kratos.Config{
		PublicURL:           publicURL,
		AdminURL:            adminURL,
		AdminToken:          token,
		BaseDN:              baseDN,
		IdentityCacheTTL:    idTTL,
		BindCacheTTL:        bdTTL,
		ServiceBindDN:       k.ServiceBindDN,
		ServiceBindPassword: servicePW,
	}

	return cfg, nil
}

func parseTTL(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	return time.ParseDuration(s)
}

// Validate enforces the invariants the binary cannot start without.
func (c *Config) Validate() error {
	if c.Backend.Kratos.PublicURL == "" {
		return errors.New("backend.kratos.public_url is required")
	}
	if c.Backend.Kratos.AdminURL == "" {
		return errors.New("backend.kratos.admin_url is required")
	}
	if c.Backend.Kratos.AdminToken == "" {
		return errors.New("backend.kratos admin token is required (set admin_token_env)")
	}
	if c.Backend.Kratos.BaseDN == "" {
		return errors.New("backend.kratos.base_dn is required")
	}
	if c.LDAPS.Enabled {
		if c.LDAPS.Cert == "" || c.LDAPS.Key == "" {
			return errors.New("ldaps requires cert and key paths")
		}
	}
	return nil
}

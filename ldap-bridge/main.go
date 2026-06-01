// glauth-kratos: LDAP bridge to Ory Kratos.
//
// Implements glauth's Handler interface against a Kratos backend.
// Translates LDAP BIND and SEARCH to Kratos public-API and admin-API
// calls. Identities live in Kratos.
//
// The binary owns its own entrypoint and config loader because glauth
// v2.5 has no public handler-registration API: backends are wired by a
// hard-coded switch in pkg/server, and the embed path is build-tag
// gated to sqlite. This binary links github.com/glauth/ldap (the same
// LDAP server library glauth uses) and registers our handler's methods
// directly. The kratos package implements glauth's Handler interface,
// so it remains drop-in for any future upstream registration API.
//
// Build:
//
//	go build -o glauth-kratos .
//
// Run:
//
//	./glauth-kratos --config glauth.cfg
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"dunn.dev/othala/ldap-bridge/kratos"

	"github.com/glauth/ldap"
)

// adminListenEnv names the env var carrying the bridge's admin HTTP
// listener address (default :6478). Pod-internal only; not exposed
// publicly. Hosts POST /admin/flush-bind-cache?subject=<id>, used by
// the consent service after a force-relogin (MEDIUM-5).
const adminListenEnv = "LDAP_BRIDGE_ADMIN_LISTEN"

// adminBearerEnv names the env var holding the bearer token gating the
// bridge's admin endpoint. Constant-time compare. If unset, the admin
// listener still starts but rejects every request (fail-closed).
const adminBearerEnv = "LDAP_BRIDGE_ADMIN_BEARER"

func main() {
	configPath := flag.String("config", "/etc/glauth/glauth.cfg", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	handler, err := kratos.New(cfg.Backend.Kratos)
	if err != nil {
		fmt.Fprintf(os.Stderr, "handler: %v\n", err)
		os.Exit(2)
	}

	server := ldap.NewServer()
	server.EnforceLDAP = true

	base := cfg.Backend.Kratos.BaseDN
	server.BindFunc(base, handler)
	server.SearchFunc(base, handler)
	server.AddFunc(base, handler)
	server.ModifyFunc(base, handler)
	server.DeleteFunc(base, handler)
	server.CloseFunc(base, handler)

	errs := make(chan error, 3)

	if cfg.LDAP.Enabled {
		go func() {
			log.Printf("ldap: listening on %s", cfg.LDAP.Listen)
			errs <- server.ListenAndServe(cfg.LDAP.Listen)
		}()
	}

	if cfg.LDAPS.Enabled {
		go func() {
			log.Printf("ldaps: listening on %s", cfg.LDAPS.Listen)
			errs <- server.ListenAndServeTLS(cfg.LDAPS.Listen, cfg.LDAPS.Cert, cfg.LDAPS.Key)
		}()
	}

	if !cfg.LDAP.Enabled && !cfg.LDAPS.Enabled {
		fmt.Fprintln(os.Stderr, "config: at least one of [ldap] or [ldaps] must be enabled")
		os.Exit(2)
	}

	// MEDIUM-5: bridge admin HTTP listener for cache-flush hooks. Default
	// :6478, pod-internal only. Bearer-gated; constant-time compare.
	adminAddr := os.Getenv(adminListenEnv)
	if adminAddr == "" {
		adminAddr = ":6478"
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/flush-bind-cache", flushBindCacheHandler(handler))
	adminMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() {
		log.Printf("admin: listening on %s", adminAddr)
		errs <- http.ListenAndServe(adminAddr, adminMux)
	}()

	if err := <-errs; err != nil {
		log.Fatalf("server: %v", err)
	}
}

// flushBindCacheHandler returns the bearer-gated handler for
// POST /admin/flush-bind-cache?subject=<username>.
//
// Subject is a username (uid attribute) since that's what the bridge
// keys cache entries by. The consent service maps Kratos identity_id
// to username before posting (or trims to localpart of the email,
// matching parseUsernameFromDN convention).
func flushBindCacheHandler(h *kratos.Handler) http.HandlerFunc {
	bearer := os.Getenv(adminBearerEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if bearer == "" {
			http.Error(w, "admin endpoints disabled (LDAP_BRIDGE_ADMIN_BEARER unset)", http.StatusForbidden)
			return
		}
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		got := strings.TrimPrefix(hdr, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(bearer)) != 1 {
			http.Error(w, "invalid bearer", http.StatusUnauthorized)
			return
		}
		subject := r.URL.Query().Get("subject")
		if subject == "" {
			http.Error(w, "missing subject query param", http.StatusBadRequest)
			return
		}
		h.FlushBindCacheFor(subject)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

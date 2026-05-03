// consent: small HTTP service handling Hydra OAuth2 consent challenges.
// Co-located with Hydra on carmine. NEVER exposed publicly — Hydra admin
// port stays internal to the pod network.
//
// Why this service exists:
//
//	The Astro UI on Cloudflare Workers cannot reach Hydra's admin port
//	(internal to carmine). This service runs alongside Hydra, takes
//	consent_challenge and login_challenge requests redirected from the
//	Astro UI, validates the user's Kratos session, calls Hydra admin
//	internally to accept/reject, and redirects back to Hydra to complete
//	the OAuth2 flow.
//
// Endpoints:
//
//	GET /consent?consent_challenge=<id>
//	GET /login?login_challenge=<id>
//	GET /healthz
//
// Behavior:
//
//	For trusted clients (everything in hydra/clients/*.yaml has
//	skip_consent: true), auto-accept the challenge with the user's
//	Kratos session subject and group claims. Redirect back to Hydra.
//
//	For untrusted clients (none today; future), this service is the
//	hook to render a consent UI. Out of scope for v1.
//
// Status: skeleton (Phase 0). Real implementation in Phase 3.
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/consent", handleConsent(cfg))
	mux.HandleFunc("/login", handleLogin(cfg))
	mux.HandleFunc("/healthz", handleHealth)

	addr := os.Getenv("CONSENT_LISTEN")
	if addr == "" {
		addr = ":4477"
	}

	log.Printf("consent service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// Config is loaded from environment.
type Config struct {
	HydraAdminURL  string // http://hydra:4445
	KratosPublicURL string // http://kratos:4433
}

func loadConfig() Config {
	return Config{
		HydraAdminURL:   getenv("HYDRA_ADMIN_URL", "http://hydra:4445"),
		KratosPublicURL: getenv("KRATOS_PUBLIC_URL", "http://kratos:4433"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

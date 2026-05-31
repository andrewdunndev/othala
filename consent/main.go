// consent: small HTTP service handling Hydra OAuth2 login/consent/logout
// challenges. Co-located with Hydra on carmine. NEVER exposed publicly.
// The Hydra admin port stays internal to the pod network.
//
// Why this service exists:
//
//	The Astro UI on Cloudflare Workers cannot reach Hydra's admin port
//	(internal to carmine). This service runs alongside Hydra, takes the
//	consent_challenge, login_challenge, and logout_challenge redirects
//	from Hydra (via auth.dunn.dev), validates the user's Kratos session,
//	calls Hydra admin internally to accept/reject, and redirects back to
//	Hydra to complete the OAuth2 flow.
//
// Endpoints:
//
//	GET  /login?login_challenge=<id>
//	GET  /consent?consent_challenge=<id>
//	GET  /logout?logout_challenge=<id>
//	POST /admin/revoke-user             (bearer-gated; D4 force re-login)
//	POST /webhooks/recovery-gate         (Kratos hook; pod-internal)
//	GET  /healthz
//
// Behavior:
//
//	For trusted clients (everything in hydra/clients/*.yaml has
//	skip_consent: true), auto-accept the challenge with the user's
//	Kratos session subject and inject id_token claims (email,
//	email_verified, name, preferred_username, groups). Redirect back
//	to Hydra.
//
//	For untrusted clients (none today; future), reject with
//	consent_required. Rendering a consent UI is out of scope for v1.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	validate := flag.Bool("validate-manifests", false, "Lint hydra/clients/*.yaml manifests and exit. Non-zero exit on any problem.")
	manifestDir := flag.String("manifest-dir", "", "Path to hydra/clients directory (default: $HYDRA_CLIENT_DIR or ../hydra/clients).")
	flag.Parse()

	cfg := loadConfig(*manifestDir)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if *validate {
		os.Exit(runValidate(cfg.ManifestDir))
	}

	manifest, err := NewManifest(cfg.ManifestDir)
	if err != nil {
		slog.Error("manifest load failed", "dir", cfg.ManifestDir, "err", err)
		os.Exit(1)
	}
	cfg.Manifest = manifest
	slog.Info("manifests loaded", "dir", cfg.ManifestDir, "count", len(manifest.Clients()))

	// SIGHUP triggers a manifest reload. Lab convenience; in production
	// the deploy pipeline rolls the pod, but reload is cheap and the
	// alternative (file watcher) pulls in a dep we don't need.
	go reloadOnSIGHUP(manifest)

	// MEDIUM-1: listener split.
	//
	// Public mux on PUBLIC_LISTEN (default :4477). Caddy proxies these:
	//   auth.dunn.dev/login
	//   auth.dunn.dev/consent
	//   auth.dunn.dev/logout
	//   /healthz (pod readiness probe)
	//
	// Admin mux on ADMIN_LISTEN (default :4478). Pod-internal only. Caddy
	// does NOT proxy these:
	//   /admin/revoke-user        (CONSENT_ADMIN_BEARER + portal-only)
	//   /webhooks/recovery-gate   (Kratos calls via in-pod hostname)
	//
	// Splitting the listeners removes the ambient risk that a future
	// Caddy edit would expose /admin/* publicly and leave the bearer as
	// the only gate. Network-layer isolation is now joint with the
	// in-process bearer check.
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/login", handleLogin(cfg))
	publicMux.HandleFunc("/consent", handleConsent(cfg))
	publicMux.HandleFunc("/logout", handleLogout(cfg))
	publicMux.HandleFunc("/healthz", handleHealth)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/revoke-user", handleRevokeUser(cfg))
	adminMux.HandleFunc("/webhooks/recovery-gate", handleRecoveryGate(cfg))
	adminMux.HandleFunc("/healthz", handleHealth)

	publicAddr := getenv("PUBLIC_LISTEN", getenv("CONSENT_LISTEN", ":4477"))
	adminAddr := getenv("ADMIN_LISTEN", ":4478")

	slog.Info("consent service starting",
		"public_addr", publicAddr,
		"admin_addr", adminAddr,
		"hydra_admin", cfg.HydraAdminURL,
		"kratos_public", cfg.KratosPublicURL,
		"kratos_admin", cfg.KratosAdminURL,
		"login_url", cfg.LoginURL,
		"manifest_dir", cfg.ManifestDir,
	)

	// SIGUSR1 (MEDIUM-6): flush the back-channel signing-key cache so the
	// next sign call refetches Hydra's id-token JWKS. Operator runbook
	// for key rotation: rotate via Hydra admin, then `kill -USR1 <pid>`
	// instead of waiting out the 15min refresh window.
	if cfg.LogoutSigner != nil {
		go flushSignerOnSIGUSR1(cfg.LogoutSigner)
	}

	errs := make(chan error, 2)
	go func() {
		errs <- http.ListenAndServe(publicAddr, publicMux)
	}()
	go func() {
		errs <- http.ListenAndServe(adminAddr, adminMux)
	}()

	if err := <-errs; err != nil {
		slog.Error("listen failed", "err", err)
		os.Exit(1)
	}
}

// runValidate loads every manifest in dir and prints lint findings. Returns
// 0 if clean, 1 on parse / IO error, 2 on lint findings.
func runValidate(dir string) int {
	m, err := NewManifest(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load failed: %v\n", err)
		return 1
	}
	errs := m.ValidateManifests()
	if len(errs) == 0 {
		fmt.Printf("ok: %d manifests in %s\n", len(m.Clients()), dir)
		return 0
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, e.Error())
	}
	fmt.Fprintf(os.Stderr, "%d problem(s) across %d manifest(s)\n", len(errs), len(m.Clients()))
	return 2
}

// reloadOnSIGHUP runs forever; each SIGHUP triggers a Reload. A reload
// failure is logged and the previous state stays in place (Reload is
// atomic on success, no-op on error).
func reloadOnSIGHUP(m *Manifest) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		if err := m.Reload(); err != nil {
			slog.Error("manifest reload failed", "err", err)
			continue
		}
		slog.Info("manifests reloaded", "count", len(m.Clients()))
	}
}

// flushSignerOnSIGUSR1 (MEDIUM-6) runs forever; each SIGUSR1 drops the
// cached back-channel logout signing key. The next Sign call refetches
// from Hydra. Used by the operator runbook for id_token key rotation
// to skip the 15-min cache window.
func flushSignerOnSIGUSR1(s *LogoutTokenSigner) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for range ch {
		s.refreshKey()
		slog.Info("backchannel signing key cache flushed (SIGUSR1)")
	}
}

// Config bundles env-driven settings + lazily constructed clients so the
// handlers don't have to know about HTTP construction.
type Config struct {
	HydraAdminURL   string
	KratosPublicURL string
	KratosAdminURL  string
	LoginURL        string
	ManifestDir     string
	Issuer          string
	AdminBearer     string

	Hydra        *HydraAdminClient
	Kratos       *KratosClient
	Manifest     *Manifest
	LogoutSigner *LogoutTokenSigner
}

func loadConfig(manifestDirFlag string) Config {
	hydraAdmin := getenv("HYDRA_ADMIN_URL", "http://hydra:4445")
	kratosPublic := getenv("KRATOS_PUBLIC_URL", "http://kratos:4433")
	kratosAdmin := getenv("KRATOS_ADMIN_URL", "http://kratos:4434")
	loginURL := getenv("LOGIN_URL", "https://auth.dunn.dev/auth/login")
	// HYDRA_ISSUER is the public issuer string Hydra mints into id_tokens
	// (`urls.self.issuer` in hydra.yml). The consent service uses it as
	// `iss` on back-channel logout tokens so RPs verify them against the
	// same JWKS they trust for id_tokens.
	issuer := getenv("HYDRA_ISSUER", "https://auth.dunn.dev/")
	adminBearer := os.Getenv(adminBearerEnv)
	manifestDir := manifestDirFlag
	if manifestDir == "" {
		manifestDir = getenv("HYDRA_CLIENT_DIR", "../hydra/clients")
	}

	return Config{
		HydraAdminURL:   hydraAdmin,
		KratosPublicURL: kratosPublic,
		KratosAdminURL:  kratosAdmin,
		LoginURL:        loginURL,
		ManifestDir:     manifestDir,
		Issuer:          issuer,
		AdminBearer:     adminBearer,
		Hydra:           NewHydraAdminClient(hydraAdmin),
		Kratos:          NewKratosClient(kratosPublic, kratosAdmin),
		LogoutSigner:    NewLogoutTokenSigner(hydraAdmin, issuer),
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

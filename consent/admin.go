package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// adminBearerEnv names the env var holding the bearer token that gates
// the consent service's /admin/* endpoints. Set on the consent quadlet
// from a secret in Bitwarden; the admin UI reads it via the portal's
// CONSENT_ADMIN_BEARER env and forwards in the Authorization header.
//
// Posture (after MEDIUM-1 listener split):
//   - /admin/* is bound to the ADMIN_LISTEN port (default :4478),
//     network-isolated to the auth pod. Caddy on dag.dunn.dev does
//     NOT forward /admin/* publicly.
//   - The bearer is in-process defense-in-depth even with the listener
//     split: every caller in the pod must present a valid bearer.
//   - If CONSENT_ADMIN_BEARER is unset, the /admin/* endpoints refuse
//     all requests (fail closed). The portal probes this on boot; an
//     unset bearer surfaces as a 503 from the admin UI.
const adminBearerEnv = "CONSENT_ADMIN_BEARER"

// ldapBridgeAdminURLEnv names the env var pointing at the LDAP bridge's
// admin endpoint base URL (no trailing slash). When set, the consent
// service calls POST <base>/admin/flush-bind-cache?subject=<id> after a
// revoke so the bridge's positive-bind cache (default 30s TTL) drops
// the stale entry immediately. Skip silently if unset.
const ldapBridgeAdminURLEnv = "LDAP_BRIDGE_ADMIN_URL"

// ldapBridgeAdminBearerEnv names the env var carrying the bearer for the
// LDAP bridge's admin endpoint. Constant-time-compared on the bridge
// side. If LDAP_BRIDGE_ADMIN_URL is set, this MUST also be set.
const ldapBridgeAdminBearerEnv = "LDAP_BRIDGE_ADMIN_BEARER"

// RevokeUserRequest is the body the admin UI POSTs to /admin/revoke-user.
type RevokeUserRequest struct {
	Subject string `json:"subject"`
}

// RevokeUserResult is the response body. KratosSessionsRevoked is best-
// effort: Kratos returns 204 with no count, so the field is currently
// always 0 on success.
type RevokeUserResult struct {
	Subject                  string `json:"subject"`
	KratosSessionsRevoked    int    `json:"kratos_sessions_revoked"`
	IdentityCacheInvalidated bool   `json:"identity_cache_invalidated"`
}

// handleRevokeUser handles POST /admin/revoke-user.
//
// Steps:
//  1. Bearer auth.
//  2. Parse body for subject (identity ID).
//  3. Kratos DELETE /admin/identities/{id}/sessions.
//  4. Invalidate the identity cache so the next consent flow picks up
//     fresh group state immediately.
//  5. Best-effort LDAP bridge bind-cache flush.
//  6. Return summary.
//
// Back-channel logout to the RPs is NOT done here: Hydra delivers OIDC
// back-channel logout tokens natively on admin session revocation, and
// the portal's revokeSubject (CU3) drives that revocation. See the note
// in the handler body.
func handleRevokeUser(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := requireAdminBearer(r, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var req RevokeUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Subject == "" {
			http.Error(w, "missing subject", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		result := RevokeUserResult{
			Subject: req.Subject,
		}

		// Step 1: Kratos session revoke. If this fails, don't bother
		// with back-channel logout: the user can still re-acquire a
		// Kratos session and we'd be sending stale logout tokens.
		if _, err := cfg.Kratos.DeleteIdentitySessions(ctx, req.Subject); err != nil {
			slog.Error("revoke-user: kratos session delete failed", "subject", req.Subject, "err", err)
			http.Error(w, "kratos: "+err.Error(), http.StatusBadGateway)
			return
		}
		result.KratosSessionsRevoked = 1 // Kratos doesn't return a count; report 1 on success for UI clarity

		// Step 2: invalidate the identity cache so the next consent
		// flow picks up fresh state immediately rather than waiting
		// out the 30s TTL.
		globalIdentityCache.invalidate(req.Subject)
		result.IdentityCacheInvalidated = true

		// Back-channel logout is no longer sent from here. Hydra
		// (oryd/hydra:v26.2.0) signs + POSTs OIDC back-channel logout
		// tokens to each client's backchannel_logout_uri NATIVELY, using
		// its own id_token key, when sessions are revoked via the admin
		// API. The portal's revokeSubject (CU3) calls
		// revokeOAuth2LoginSessions + revokeOAuth2ConsentSessions, which
		// is exactly what triggers Hydra's native BCL delivery to the RPs.
		// The custom JOSE signer that used to live here (and the private
		// id_token key fetch it required) has been deleted; native BCL
		// owns this path now.

		// MEDIUM-5: best-effort flush of the LDAP bridge bind cache for
		// the named identity. Skip silently if the bridge admin URL is
		// not configured (lab without bridge); log on failure but do not
		// fail the revoke, since the Kratos+RP work has already been
		// done.
		flushBridgeBindCache(ctx, cfg, req.Subject)

		slog.Info("revoke-user complete",
			"subject", req.Subject,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

// requireAdminBearer checks the Authorization header against
// CONSENT_ADMIN_BEARER. Constant-time compare; no logging of the
// presented token. If the env var is empty, every call is rejected
// (fail-closed posture).
func requireAdminBearer(r *http.Request, cfg Config) error {
	if cfg.AdminBearer == "" {
		return errors.New("admin endpoints disabled (CONSENT_ADMIN_BEARER unset)")
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return errors.New("missing bearer token")
	}
	got := strings.TrimPrefix(hdr, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.AdminBearer)) != 1 {
		return errors.New("invalid bearer token")
	}
	return nil
}

// flushBridgeBindCache (MEDIUM-5) calls the LDAP bridge's admin endpoint
// to drop any positive-bind cache entry for the named identity. The
// bridge's bind cache otherwise lags up to 30s (BindCacheTTL); without
// this call, a password rotation followed by an immediate force-relogin
// could leave the OLD password binding via LDAP for the rest of the
// cache window.
//
// Best-effort: log on failure, do not fail the revoke. Skip silently
// when LDAP_BRIDGE_ADMIN_URL is unset (lab without the bridge).
func flushBridgeBindCache(ctx context.Context, cfg Config, subject string) {
	base := os.Getenv(ldapBridgeAdminURLEnv)
	if base == "" {
		return
	}
	bearer := os.Getenv(ldapBridgeAdminBearerEnv)
	if bearer == "" {
		slog.Warn("ldap-bridge flush skipped: LDAP_BRIDGE_ADMIN_URL set but LDAP_BRIDGE_ADMIN_BEARER unset",
			"subject", subject)
		return
	}

	endpoint := strings.TrimRight(base, "/") + "/admin/flush-bind-cache?subject=" + url.QueryEscape(subject)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		slog.Warn("ldap-bridge flush request build failed", "err", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Warn("ldap-bridge flush call failed", "err", err, "subject", subject)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Warn("ldap-bridge flush non-2xx",
			"status", resp.StatusCode,
			"body", string(body),
			"subject", subject,
		)
		return
	}
	slog.Info("ldap-bridge flush ok", "subject", subject)
}

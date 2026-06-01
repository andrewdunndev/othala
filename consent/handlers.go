package main

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

// loginRememberFor: how long Hydra remembers the login decision before
// asking again. 24h matches the admin-session policy (1d) and is shorter
// than the 90d Kratos session, so revoking a Kratos session takes effect
// for new OIDC flows within a day even if Hydra has cached a remembered
// login. Apps with longer SSO horizons fall back to Kratos session checks.
const loginRememberFor = 86400

// consentRememberFor: 1h. Trusted clients all skip_consent anyway, so
// remember is mostly belt and suspenders. Short window keeps blast radius
// small if a group changes mid-session.
const consentRememberFor = 3600

// accessGroupPrefix is the per-app entry-gate group convention. Every
// OIDC client expects callers to be in `access-<client_id>`; the consent
// service refuses to issue an id_token to anyone who isn't (D2 / C2).
//
// Override per-client by setting consent.skip_access_check: true in the
// yaml. No client uses that today.
const accessGroupPrefix = "access-"

// handleLogin handles Hydra login_challenge.
//
// Flow:
//  1. Read login_challenge.
//  2. GET /admin/oauth2/auth/requests/login. If skip == true, Hydra already
//     knows the subject (remembered login); accept with that subject.
//  3. Otherwise validate the user's Kratos session via /sessions/whoami
//     forwarding the request cookies. No session: redirect to home portal
//     login UI with return_to set so they come back here after auth.
//  4. Active session: enforce access-<client_id> group; if missing, reject
//     with access_denied. Otherwise accept with subject = identity.id.
//  5. Redirect to whatever Hydra hands back.
//
// The access-* gate fires here AND in handleConsent. Doing it at login
// saves a redirect roundtrip when a user lands on an app they have no
// entitlement to; doing it at consent guarantees the gate even if Hydra
// short-circuits login (skip_consent flows still hit consent).
func handleLogin(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		challenge := r.URL.Query().Get("login_challenge")
		if challenge == "" {
			http.Error(w, "missing login_challenge", http.StatusBadRequest)
			return
		}

		login, err := cfg.Hydra.GetLoginRequest(ctx, challenge)
		if err != nil {
			slog.Error("hydra get login request failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// Hydra already remembers this subject. Honor the remembered subject;
		// don't override from the current cookie (could differ if a different
		// user is now in the browser). The access-* gate still has to fire,
		// so look up the identity by the remembered subject and check.
		if login.Skip {
			if rejected := enforceAccessGate(ctx, w, r, cfg, login.Subject, login.Client.ClientID, "login", challenge, true); rejected {
				return
			}
			redir, err := cfg.Hydra.AcceptLoginRequest(ctx, challenge, AcceptLoginRequest{
				Subject: login.Subject,
			})
			if err != nil {
				slog.Error("hydra accept login (skip) failed", "challenge", challenge, "err", err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			slog.Info("login accepted via skip", "subject", login.Subject, "client", login.Client.ClientID)
			http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
			return
		}

		session, err := cfg.Kratos.Whoami(ctx, r.Cookies())
		if err != nil {
			slog.Error("kratos whoami failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if session == nil || !session.Active {
			// Send the user to the home portal login flow and have them come
			// back to this exact URL once Kratos has minted a session.
			returnTo := buildReturnTo(r)
			loginURL := cfg.LoginURL + "?return_to=" + url.QueryEscape(returnTo)
			slog.Info("no active session, redirecting to login UI", "challenge", challenge, "return_to", returnTo)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// Kratos /sessions/whoami strips metadata_admin by design (it's
		// admin-only and never sent to public surfaces). For the access-*
		// gate we need group membership, which lives in metadata_admin.
		// Look up the identity via the admin API (cached) and use that
		// for gate evaluation.
		identity, err := getIdentityCached(ctx, cfg, session.Identity.ID)
		if err != nil {
			slog.Error("kratos get identity (login gate) failed", "subject", session.Identity.ID, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if rejected := enforceAccessGateFromGroups(ctx, w, r, cfg, identityGroupsFromIdentity(identity), login.Client.ClientID, "login", challenge); rejected {
			return
		}

		redir, err := cfg.Hydra.AcceptLoginRequest(ctx, challenge, AcceptLoginRequest{
			Subject:     session.Identity.ID,
			Remember:    true,
			RememberFor: loginRememberFor,
			ACR:         session.AuthenticatorAssuranceLevel,
		})
		if err != nil {
			slog.Error("hydra accept login failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		slog.Info("login accepted", "subject", session.Identity.ID, "client", login.Client.ClientID, "aal", session.AuthenticatorAssuranceLevel)
		http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
	}
}

// handleConsent handles Hydra consent_challenge.
//
// All trusted clients have skip_consent: true. We auto-accept after
// fetching the identity to inject id_token claims. If skip_consent is
// false (no client today, future third-party app), reject with consent_required.
// A consent UI for that path is out of scope for v1.
//
// The access-<client_id> gate fires after GetIdentity. A user without the
// matching access group cannot complete consent regardless of session
// state. This is the canonical OIDC entry gate (D2).
func handleConsent(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		challenge := r.URL.Query().Get("consent_challenge")
		if challenge == "" {
			http.Error(w, "missing consent_challenge", http.StatusBadRequest)
			return
		}

		consent, err := cfg.Hydra.GetConsentRequest(ctx, challenge)
		if err != nil {
			slog.Error("hydra get consent request failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		if !consent.Skip && !consent.Client.SkipConsent {
			// No untrusted clients today; if one ever appears we'd render a
			// consent UI here. Reject loudly so the misconfig is visible.
			slog.Warn("rejecting consent: untrusted client", "client", consent.Client.ClientID)
			redir, err := cfg.Hydra.RejectConsentRequest(ctx, challenge, RejectRequest{
				Error:            "consent_required",
				ErrorDescription: "consent UI not implemented for untrusted clients",
				StatusCode:       http.StatusForbidden,
			})
			if err != nil {
				slog.Error("hydra reject consent failed", "challenge", challenge, "err", err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
			return
		}

		// M1: 30s in-process identity cache. Absorbs reconnect storms
		// (Tailscale token renew, Immich mobile reconnect) hitting the
		// Kratos admin API hard. Trade-off: up to 30s lag on group
		// changes (M5).
		identity, err := getIdentityCached(ctx, cfg, consent.Subject)
		if err != nil {
			slog.Error("kratos get identity failed", "subject", consent.Subject, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// Access gate. The login handler already enforces this when it
		// runs (skip path or fresh whoami), but consent must enforce too:
		// Hydra's consent challenge can fire even when the login decision
		// was remembered, and skip_access_check could be set per-client
		// in the future.
		if rejected := enforceAccessGateFromGroups(ctx, w, r, cfg, identityGroupsFromIdentity(identity), consent.Client.ClientID, "consent", challenge); rejected {
			return
		}

		idTokenClaims := BuildIDTokenClaims(identity)

		// Per-app claim emission.
		//
		// 1. If the client manifest sets `emit_groups_claim: false`, drop
		//    the auto groups claim. The role's claim_emit (below) may
		//    still inject a groups field of its own; that's a separate
		//    decision made by the manifest author.
		// 2. If the manifest declares a roles section, resolve the user's
		//    role and deep-merge its claim_emit map into the id_token.
		//    Conflict at any leaf path is last-write-wins (role overrides
		//    auto-emitted claims). See consent/README.md "Claim emission
		//    semantics".
		var roleName string
		var clientManifest *ClientManifest
		if cfg.Manifest != nil {
			clientManifest = cfg.Manifest.Client(consent.Client.ClientID)
		}
		if clientManifest != nil && !clientManifest.ShouldEmitGroups() {
			delete(idTokenClaims, "groups")
		}
		if cfg.Manifest != nil && identity != nil {
			if name, claims, ok := cfg.Manifest.LookupRole(consent.Client.ClientID, identity.MetadataAdmin); ok {
				roleName = name
				deepMergeClaims(idTokenClaims, claims)
			}
		}

		redir, err := cfg.Hydra.AcceptConsentRequest(ctx, challenge, AcceptConsentRequest{
			GrantScope:               consent.RequestedScope,
			GrantAccessTokenAudience: consent.RequestedAccessTokenAudience,
			Remember:                 true,
			RememberFor:              consentRememberFor,
			Session: ConsentSession{
				IDToken:     idTokenClaims,
				AccessToken: map[string]any{},
			},
		})
		if err != nil {
			slog.Error("hydra accept consent failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		slog.Info("consent accepted", "subject", consent.Subject, "client", consent.Client.ClientID, "scope", consent.RequestedScope, "role", roleName)
		http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
	}
}

// handleLogout handles Hydra logout_challenge.
// Hydra's logout flow is consent-style: it asks our service whether to
// proceed. We always accept; Kratos session invalidation is handled by the
// portal logout button hitting Kratos public /self-service/logout directly.
// Per-app session propagation (back-channel logout) is handled by the
// admin /admin/revoke-user endpoint, not here.
func handleLogout(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		challenge := r.URL.Query().Get("logout_challenge")
		if challenge == "" {
			http.Error(w, "missing logout_challenge", http.StatusBadRequest)
			return
		}

		logout, err := cfg.Hydra.GetLogoutRequest(ctx, challenge)
		if err != nil {
			slog.Error("hydra get logout request failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		redir, err := cfg.Hydra.AcceptLogoutRequest(ctx, challenge)
		if err != nil {
			slog.Error("hydra accept logout failed", "challenge", challenge, "err", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		slog.Info("logout accepted", "subject", logout.Subject, "client", logout.Client.ClientID)
		http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
	}
}

// enforceAccessGate checks identity membership in `access-<clientID>`. If
// the gate rejects, it issues the appropriate Hydra reject call (login or
// consent), redirects, and returns true. Caller must stop processing.
//
// Looks the identity up via Kratos admin (used by the login-skip path
// where we don't already have a whoami response).
//
// The skip_access_check escape hatch reads from the manifest. No client
// sets it today; reserved for future use.
func enforceAccessGate(ctx interface{ Done() <-chan struct{} }, w http.ResponseWriter, r *http.Request, cfg Config, subject, clientID, phase, challenge string, viaSkip bool) bool {
	if cfg.Manifest != nil {
		if cm := cfg.Manifest.Client(clientID); cm != nil && cm.Consent.SkipAccessCheck {
			return false
		}
	}
	identity, err := getIdentityCached(r.Context(), cfg, subject)
	if err != nil {
		slog.Error("kratos get identity (gate) failed", "subject", subject, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return true
	}
	return enforceAccessGateFromGroups(ctx, w, r, cfg, identityGroupsFromIdentity(identity), clientID, phase, challenge)
}

// enforceAccessGateFromGroups is the gate when the caller already has the
// identity's groups in hand (login fresh-session path, consent path).
// Avoids a redundant Kratos admin call.
func enforceAccessGateFromGroups(_ interface{ Done() <-chan struct{} }, w http.ResponseWriter, r *http.Request, cfg Config, groups []string, clientID, phase, challenge string) bool {
	if cfg.Manifest != nil {
		if cm := cfg.Manifest.Client(clientID); cm != nil && cm.Consent.SkipAccessCheck {
			return false
		}
	}
	expected := accessGroupPrefix + strings.ToLower(clientID)
	if slices.Contains(groups, expected) {
		return false
	}

	slog.Warn("rejecting: missing access group",
		"phase", phase,
		"client", clientID,
		"expected_group", expected,
		"groups", groups,
	)
	desc := "User is not in " + expected + " group"
	body := RejectRequest{
		Error:            "access_denied",
		ErrorDescription: desc,
		StatusCode:       http.StatusForbidden,
	}

	var redir *RedirectTo
	var err error
	switch phase {
	case "login":
		redir, err = cfg.Hydra.RejectLoginRequest(r.Context(), challenge, body)
	case "consent":
		redir, err = cfg.Hydra.RejectConsentRequest(r.Context(), challenge, body)
	default:
		http.Error(w, "internal: unknown gate phase", http.StatusInternalServerError)
		return true
	}
	if err != nil {
		slog.Error("hydra reject (gate) failed", "phase", phase, "challenge", challenge, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return true
	}
	http.Redirect(w, r, redir.RedirectTo, http.StatusFound)
	return true
}

// identityGroupsFromIdentity is the consent-handler-side mirror of
// identityGroups(meta). Kept here because manifest.go's identityGroups
// reads a generic map, while this version reads the typed Identity from
// the Kratos client. Both produce the same []string, deliberately.
func identityGroupsFromIdentity(id *Identity) []string {
	if id == nil {
		return nil
	}
	return identityGroups(id.MetadataAdmin)
}

// buildReturnTo reconstructs the absolute URL the user landed on so the
// login UI can send them back here after Kratos mints a session.
//
// Trust posture (HIGH-2): X-Forwarded-Host / X-Forwarded-Proto are
// IGNORED. The consent service has no `trusted_proxies` concept and
// only one upstream (Caddy) sits in front of it; the header indirection
// added attack surface without value. If CONSENT_PUBLIC_URL is set, it
// supplies scheme + host (Caddy terminates TLS, so the in-pod request
// arrives plaintext but the public URL is https). Otherwise scheme is
// derived from r.TLS and host from r.Host. Kratos's allowed_return_urls
// is the second line of defense (H5 / LOW-3).
func buildReturnTo(r *http.Request) string {
	if base := publicBaseURL(); base != "" {
		return base + r.URL.RequestURI()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// publicBaseURL returns the configured public base (scheme://host with no
// trailing slash) for return_to construction, or "" if unset.
//
// Empty return means buildReturnTo falls back to r.Host + r.TLS sniffing.
// In production CONSENT_PUBLIC_URL is set to "https://dag.dunn.dev"; in
// the lab compose stack to "https://auth-lab.<sslip>".
func publicBaseURL() string {
	v := os.Getenv("CONSENT_PUBLIC_URL")
	if v == "" {
		return ""
	}
	for len(v) > 0 && v[len(v)-1] == '/' {
		v = v[:len(v)-1]
	}
	return v
}

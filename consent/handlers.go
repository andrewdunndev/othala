package main

import (
	"net/http"
)

// handleLogin handles Hydra login_challenge.
//
// Flow:
//  1. Read login_challenge from query string
//  2. GET <hydra_admin>/admin/oauth2/auth/requests/login?login_challenge=<id>
//     to fetch the challenge details (subject, requested scopes, client_id)
//  3. Read user's Kratos session cookie from request, validate via
//     <kratos_public>/sessions/whoami
//     - If valid: subject = identity.id; auto-accept
//     - If invalid: redirect user to home.dunn.dev/auth/login with
//       return_to set so they come back here after authenticating
//  4. PUT <hydra_admin>/admin/oauth2/auth/requests/login/accept
//     with { subject: <id>, remember: true, remember_for: <ttl> }
//  5. Redirect to the redirect_to URL Hydra returns
func handleLogin(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: real implementation per the flow above.
		// 1. challenge := r.URL.Query().Get("login_challenge")
		// 2. login, err := hydraAdmin.GetLoginRequest(challenge)
		// 3. session, err := kratosPublic.Whoami(r.Cookies())
		//    if !session.Active → redirect to home.dunn.dev/auth/login?return_to=...
		// 4. accept := { Subject: session.Identity.ID, Remember: true, RememberFor: 86400 }
		//    redirect, err := hydraAdmin.AcceptLoginRequest(challenge, accept)
		// 5. http.Redirect(w, r, redirect.RedirectTo, 302)

		http.Error(w, "not implemented", http.StatusNotImplemented)
	}
}

// handleConsent handles Hydra consent_challenge.
//
// Flow:
//  1. Read consent_challenge from query string
//  2. GET <hydra_admin>/admin/oauth2/auth/requests/consent?consent_challenge=<id>
//  3. If challenge.skip == true OR challenge.client.skip_consent == true:
//     a. Validate user's Kratos session (same as login handler)
//     b. Read identity.metadata_admin.groups for the groups claim
//     c. PUT <hydra_admin>/admin/oauth2/auth/requests/consent/accept
//        with grant_scope, session.id_token = { email, email_verified,
//        name, groups }
//     d. Redirect
//  4. Else: render consent UI (out of scope for v1; reject with error)
func handleConsent(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: real implementation.
		// Critical: the id_token session must include email, email_verified
		// (from identity.verifiable_addresses[0].verified), name, and groups
		// (from metadata_admin.groups). Hydra does NOT auto-populate these
		// from Kratos; the consent step is where we inject them.

		http.Error(w, "not implemented", http.StatusNotImplemented)
	}
}

// Kratos API client. Two surfaces: public (for BIND password verification)
// and admin (for SEARCH identity listing).
package kratos

import (
	"context"
	"net/http"
	"time"
)

// Client is a thin Kratos API wrapper.
type Client struct {
	publicURL  string
	adminURL   string
	adminToken string
	httpClient *http.Client
}

func newClient(cfg Config) *Client {
	return &Client{
		publicURL:  cfg.PublicURL,
		adminURL:   cfg.AdminURL,
		adminToken: cfg.AdminToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// VerifyPassword runs a Kratos API-flow login as the bridge's BIND
// verification mechanism.
//
// Flow:
//
//	POST {publicURL}/self-service/login/api
//	  → 200 { "id": flow_id, "ui": ... }
//	POST {publicURL}/self-service/login?flow={flow_id}
//	  body: { "method": "password", "identifier": username, "password": pw }
//	  headers: Accept: application/json, Content-Type: application/json
//	  → 200 { "session": ... }      success
//	  → 400 { "error": ... }        wrong password
//	  → 4xx                         other failure
//	  → 5xx                         transient
//
// We do not retain the session token; this call is verification-only.
//
// CSRF is not required for API flows (only for browser flows).
func (c *Client) VerifyPassword(ctx context.Context, username, password string) (bool, error) {
	// TODO: real implementation
	// 1. POST <publicURL>/self-service/login/api with Accept: application/json
	// 2. Parse flow ID from response body
	// 3. POST <publicURL>/self-service/login?flow=<id> with the credential body
	// 4. Map response status to (verified, error)
	return false, nil
}

// IdentityList holds a slim representation of identities for the bridge cache.
type IdentityList []Identity

// Identity is the bridge-facing slice of a Kratos identity.
type Identity struct {
	ID       string
	Username string
	Email    string
	Display  string
	Groups   []string
}

// ListIdentities fetches all identities from Kratos admin API.
//
// Endpoint: GET {adminURL}/admin/identities (paginated; we walk all pages)
// Auth: Authorization: Bearer {admin_token}
//
// We project the response shape down to the slim Identity struct above.
// Trait fields read: traits.username, traits.email, traits.displayName.
// metadata_admin.groups is mapped to Identity.Groups.
func (c *Client) ListIdentities(ctx context.Context) (IdentityList, error) {
	// TODO: real implementation
	// 1. Walk paginated /admin/identities (?page_token=...)
	// 2. For each item, project to bridge.Identity:
	//      ID: identity.id
	//      Username: identity.traits.username
	//      Email: identity.traits.email
	//      Display: identity.traits.displayName (fallback: username)
	//      Groups: identity.metadata_admin.groups (default: [])
	// 3. Return aggregated list
	return nil, nil
}

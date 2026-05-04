package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// KratosClient covers both the public (whoami via session cookie) and admin
// (identity lookup by ID) surfaces. Public and admin URLs are typically
// different ports on Kratos: 4433 public, 4434 admin.
type KratosClient struct {
	PublicURL string
	AdminURL  string
	HTTP      *http.Client
}

func NewKratosClient(publicURL, adminURL string) *KratosClient {
	return &KratosClient{
		PublicURL: publicURL,
		AdminURL:  adminURL,
		HTTP:      &http.Client{Timeout: 10 * time.Second},
	}
}

// VerifiableAddress mirrors Kratos's address record. We only use Verified
// for the email_verified id_token claim.
type VerifiableAddress struct {
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
	Via      string `json:"via"`
}

// Identity is the subset of the Kratos identity we need for claim mapping.
// Traits is decoded as a map so the schema can evolve without forcing a
// recompile of this service. The schema today is in lab/compose/identity.schema.json
// (username, email, displayName?).
//
// LOW-2: this struct trusts whatever Kratos returns. If Kratos's identity
// schema is widened (e.g., via an admin metadata write that Kratos
// accepts), the Go side just ignores unknown fields, which is fine. No
// shape validation here is intentional: a tier-4 attacker (Kratos itself
// compromised) is out of scope; tier-2 callers cannot reach the admin
// API thanks to pod-network isolation.
type Identity struct {
	ID                  string            `json:"id"`
	Traits              map[string]any    `json:"traits"`
	VerifiableAddresses []VerifiableAddress `json:"verifiable_addresses"`
	MetadataAdmin       map[string]any    `json:"metadata_admin"`
}

// Session is the Kratos session shape returned by /sessions/whoami.
type Session struct {
	ID                          string   `json:"id"`
	Active                      bool     `json:"active"`
	AuthenticatorAssuranceLevel string   `json:"authenticator_assurance_level"`
	Identity                    Identity `json:"identity"`
}

// Whoami forwards the user's cookies to Kratos public /sessions/whoami and
// returns the session if active. A 401 response means no session, which we
// surface as (nil, nil) so the caller can redirect to the login UI.
func (c *KratosClient) Whoami(ctx context.Context, cookies []*http.Cookie) (*Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.PublicURL+"/sessions/whoami", nil)
	if err != nil {
		return nil, err
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("kratos whoami: %d %s", resp.StatusCode, string(body))
	}

	out := &Session{}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteIdentitySessions revokes every Kratos session for the given
// identity ID via DELETE /admin/identities/{id}/sessions. Used by the
// admin /admin/revoke-user endpoint as the first step of "force
// re-login": Kratos drops the session cookies, then the consent
// service emits OIDC back-channel logout tokens to apps that support
// them.
//
// Returns the count of sessions revoked when Kratos provides it (in
// the response body), or 0 with err==nil when the call succeeds and
// the body is empty.
func (c *KratosClient) DeleteIdentitySessions(ctx context.Context, id string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.AdminURL+"/admin/identities/"+id+"/sessions", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		// Kratos v1.x returns 204 with no body. Older versions might
		// return a small JSON envelope; ignore decode errors and let
		// the caller treat success as success.
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return 0, fmt.Errorf("kratos delete identity sessions %s: %d %s", id, resp.StatusCode, string(body))
}

// GetIdentity fetches an identity by ID via the admin API. Used during
// consent to read traits + metadata_admin for id_token claim injection.
func (c *KratosClient) GetIdentity(ctx context.Context, id string) (*Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AdminURL+"/admin/identities/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("kratos get identity %s: %d %s", id, resp.StatusCode, string(body))
	}

	out := &Identity{}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}

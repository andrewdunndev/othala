package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HydraAdminClient is a thin stdlib wrapper around the Hydra v2 admin API.
// We hand-roll instead of pulling the Ory SDK to keep the dep tree empty
// (currently zero non-stdlib imports) and the binary small.
type HydraAdminClient struct {
	BaseURL string
	HTTP    *http.Client
}

func NewHydraAdminClient(baseURL string) *HydraAdminClient {
	return &HydraAdminClient{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// OAuth2Client is the subset of the Hydra client object we need.
type OAuth2Client struct {
	ClientID    string   `json:"client_id"`
	ClientName  string   `json:"client_name"`
	SkipConsent bool     `json:"skip_consent"`
	Audience    []string `json:"audience,omitempty"`
}

// LoginRequest is the response from GET /admin/oauth2/auth/requests/login.
type LoginRequest struct {
	Challenge                    string       `json:"challenge"`
	Skip                         bool         `json:"skip"`
	Subject                      string       `json:"subject"`
	Client                       OAuth2Client `json:"client"`
	RequestURL                   string       `json:"request_url"`
	RequestedScope               []string     `json:"requested_scope"`
	RequestedAccessTokenAudience []string     `json:"requested_access_token_audience"`
	SessionID                    string       `json:"session_id"`
}

// AcceptLoginRequest is the body for PUT .../login/accept.
type AcceptLoginRequest struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember,omitempty"`
	RememberFor int64  `json:"remember_for,omitempty"`
	ACR         string `json:"acr,omitempty"`
}

// ConsentRequest is the response from GET /admin/oauth2/auth/requests/consent.
type ConsentRequest struct {
	Challenge                    string       `json:"challenge"`
	Skip                         bool         `json:"skip"`
	Subject                      string       `json:"subject"`
	Client                       OAuth2Client `json:"client"`
	RequestURL                   string       `json:"request_url"`
	RequestedScope               []string     `json:"requested_scope"`
	RequestedAccessTokenAudience []string     `json:"requested_access_token_audience"`
	LoginChallenge               string       `json:"login_challenge"`
	LoginSessionID               string       `json:"login_session_id"`
}

// ConsentSession matches Hydra's session.{access_token,id_token} envelope.
type ConsentSession struct {
	AccessToken map[string]any `json:"access_token,omitempty"`
	IDToken     map[string]any `json:"id_token,omitempty"`
}

// AcceptConsentRequest is the body for PUT .../consent/accept.
type AcceptConsentRequest struct {
	GrantScope                []string       `json:"grant_scope,omitempty"`
	GrantAccessTokenAudience  []string       `json:"grant_access_token_audience,omitempty"`
	Remember                  bool           `json:"remember,omitempty"`
	RememberFor               int64          `json:"remember_for,omitempty"`
	Session                   ConsentSession `json:"session"`
}

// LogoutRequest is the response from GET /admin/oauth2/auth/requests/logout.
type LogoutRequest struct {
	Challenge   string       `json:"challenge"`
	RequestURL  string       `json:"request_url"`
	RPInitiated bool         `json:"rp_initiated"`
	Subject     string       `json:"subject"`
	SID         string       `json:"sid"`
	Client      OAuth2Client `json:"client"`
}

// RejectRequest is the body for PUT .../{login,consent}/reject.
type RejectRequest struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	StatusCode       int64  `json:"status_code,omitempty"`
}

// RedirectTo is the standard "go here next" envelope returned by every
// accept/reject endpoint.
type RedirectTo struct {
	RedirectTo string `json:"redirect_to"`
}

func (c *HydraAdminClient) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *HydraAdminClient) put(ctx context.Context, path string, query url.Values, body, out any) error {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	} else {
		buf = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *HydraAdminClient) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("hydra admin %s %s: %d %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *HydraAdminClient) GetLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error) {
	out := &LoginRequest{}
	q := url.Values{"login_challenge": {challenge}}
	if err := c.get(ctx, "/admin/oauth2/auth/requests/login", q, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) AcceptLoginRequest(ctx context.Context, challenge string, body AcceptLoginRequest) (*RedirectTo, error) {
	out := &RedirectTo{}
	q := url.Values{"login_challenge": {challenge}}
	if err := c.put(ctx, "/admin/oauth2/auth/requests/login/accept", q, body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) RejectLoginRequest(ctx context.Context, challenge string, body RejectRequest) (*RedirectTo, error) {
	out := &RedirectTo{}
	q := url.Values{"login_challenge": {challenge}}
	if err := c.put(ctx, "/admin/oauth2/auth/requests/login/reject", q, body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error) {
	out := &ConsentRequest{}
	q := url.Values{"consent_challenge": {challenge}}
	if err := c.get(ctx, "/admin/oauth2/auth/requests/consent", q, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) AcceptConsentRequest(ctx context.Context, challenge string, body AcceptConsentRequest) (*RedirectTo, error) {
	out := &RedirectTo{}
	q := url.Values{"consent_challenge": {challenge}}
	if err := c.put(ctx, "/admin/oauth2/auth/requests/consent/accept", q, body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) RejectConsentRequest(ctx context.Context, challenge string, body RejectRequest) (*RedirectTo, error) {
	out := &RedirectTo{}
	q := url.Values{"consent_challenge": {challenge}}
	if err := c.put(ctx, "/admin/oauth2/auth/requests/consent/reject", q, body, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) GetLogoutRequest(ctx context.Context, challenge string) (*LogoutRequest, error) {
	out := &LogoutRequest{}
	q := url.Values{"logout_challenge": {challenge}}
	if err := c.get(ctx, "/admin/oauth2/auth/requests/logout", q, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HydraAdminClient) AcceptLogoutRequest(ctx context.Context, challenge string) (*RedirectTo, error) {
	out := &RedirectTo{}
	q := url.Values{"logout_challenge": {challenge}}
	if err := c.put(ctx, "/admin/oauth2/auth/requests/logout/accept", q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

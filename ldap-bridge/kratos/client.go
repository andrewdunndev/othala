// Kratos API client. Two surfaces: public (for BIND password
// verification) and admin (for SEARCH identity listing).
package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
		publicURL:  strings.TrimRight(cfg.PublicURL, "/"),
		adminURL:   strings.TrimRight(cfg.AdminURL, "/"),
		adminToken: cfg.AdminToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// loginFlowResponse is the relevant subset of POST /self-service/login/api
// and POST /self-service/login response shapes.
type loginFlowResponse struct {
	ID string `json:"id"`
}

// VerifyPassword runs a Kratos API-flow login as the bridge's BIND
// verification mechanism.
//
// Flow:
//
//	POST {publicURL}/self-service/login/api
//	  -> 200 { "id": flow_id, ... }
//	POST {publicURL}/self-service/login?flow={flow_id}
//	  body: { "method": "password", "identifier": username, "password": pw }
//	  headers: Accept: application/json, Content-Type: application/json
//	  -> 200 success
//	  -> 4xx wrong password / other client failure
//	  -> 5xx transient
//
// The returned session token is discarded. CSRF is not required for
// API flows. ErrUnavailable signals 5xx or transport error so the
// caller can map to LDAPResultUnavailable.
func (c *Client) VerifyPassword(ctx context.Context, username, password string) (bool, error) {
	flowID, err := c.initLoginFlow(ctx)
	if err != nil {
		return false, err
	}

	body, err := json.Marshal(map[string]string{
		"method":     "password",
		"identifier": username,
		"password":   password,
	})
	if err != nil {
		return false, err
	}

	endpoint := fmt.Sprintf("%s/self-service/login?flow=%s", c.publicURL, url.QueryEscape(flowID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("kratos login submit: %w", ErrUnavailable)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode == 200:
		return true, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return false, nil
	default:
		return false, fmt.Errorf("kratos login submit: status %d: %w", resp.StatusCode, ErrUnavailable)
	}
}

func (c *Client) initLoginFlow(ctx context.Context) (string, error) {
	endpoint := c.publicURL + "/self-service/login/api"
	// Kratos serves flow init as GET on /self-service/login/api; POST is
	// reserved for the action URL with ?flow=<id>.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kratos login init: %w", ErrUnavailable)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("kratos login init: status %d: %w", resp.StatusCode, ErrUnavailable)
	}

	var flow loginFlowResponse
	if err := json.NewDecoder(resp.Body).Decode(&flow); err != nil {
		return "", fmt.Errorf("kratos login init decode: %w", err)
	}
	if flow.ID == "" {
		return "", errors.New("kratos login init: empty flow id")
	}
	return flow.ID, nil
}

// IdentityList holds slim identities for the bridge cache.
type IdentityList []Identity

// Identity is the bridge-facing slice of a Kratos identity.
type Identity struct {
	ID       string
	Username string
	Email    string
	Display  string
	Groups   []string
}

// kratosIdentity is the response shape from /admin/identities. Only
// the fields we project are decoded.
type kratosIdentity struct {
	ID     string          `json:"id"`
	Traits identityTraits  `json:"traits"`
	Meta   *identityMeta   `json:"metadata_admin,omitempty"`
}

type identityTraits struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}

type identityMeta struct {
	Groups []string `json:"groups"`
}

// ListIdentities walks the /admin/identities pagination and returns
// the flattened slim identity list.
//
// Kratos uses Link-header pagination with a `page_token` query param.
// We follow `rel="next"` until exhausted.
func (c *Client) ListIdentities(ctx context.Context) (IdentityList, error) {
	endpoint := c.adminURL + "/admin/identities?per_page=250"
	var out IdentityList

	for endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.adminToken)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("kratos list identities: %w", ErrUnavailable)
		}

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("kratos list identities: status %d: %s: %w",
				resp.StatusCode, strings.TrimSpace(string(body)), ErrUnavailable)
		}

		var page []kratosIdentity
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("kratos list identities decode: %w", err)
		}
		next := nextPageURL(resp.Header.Get("Link"))
		resp.Body.Close()

		for _, k := range page {
			ident := Identity{
				ID:       k.ID,
				Username: k.Traits.Username,
				Email:    k.Traits.Email,
				Display:  k.Traits.DisplayName,
			}
			if ident.Display == "" {
				ident.Display = ident.Username
			}
			if k.Meta != nil {
				ident.Groups = append([]string(nil), k.Meta.Groups...)
			}
			if ident.Username != "" {
				out = append(out, ident)
			}
		}

		endpoint = next
	}

	return out, nil
}

// nextPageURL parses an RFC 5988 Link header and returns the URL of the
// rel="next" link, or "" if absent.
func nextPageURL(h string) string {
	if h == "" {
		return ""
	}
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		segs := strings.Split(part, ";")
		if len(segs) < 2 {
			continue
		}
		urlPart := strings.TrimSpace(segs[0])
		if !strings.HasPrefix(urlPart, "<") || !strings.HasSuffix(urlPart, ">") {
			continue
		}
		urlPart = urlPart[1 : len(urlPart)-1]
		for _, attr := range segs[1:] {
			attr = strings.TrimSpace(attr)
			if attr == `rel="next"` || attr == "rel=next" {
				return urlPart
			}
		}
	}
	return ""
}

// ErrUnavailable signals a transport- or 5xx-level Kratos failure that
// should map to LDAPResultUnavailable, distinct from a plain wrong-
// password 4xx.
var ErrUnavailable = errors.New("kratos unavailable")

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// M13: HTTP-layer tests for handleLogin / handleConsent / handleLogout.
// Mock Hydra admin and Kratos public+admin servers; assert redirects,
// reject paths, and the access-* gate (C2).

// hydraMock returns a httptest server emulating the four Hydra admin
// endpoints handlers care about. Behavior is steered via the seed map
// (route -> response).
type hydraMock struct {
	t          *testing.T
	loginReq   LoginRequest
	consentReq ConsentRequest
	logoutReq  LogoutRequest
	// recordedRejects captures the (phase, error) of any reject call.
	recordedRejects []rejectCall
	// recordedAccepts captures the subject from the accept call so tests
	// can check that gate-rejected flows didn't accept.
	acceptCount int
}

type rejectCall struct {
	phase string
	error string
}

func newHydraMock(t *testing.T) (*httptest.Server, *hydraMock) {
	m := &hydraMock{t: t}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/oauth2/auth/requests/login":
			_ = json.NewEncoder(w).Encode(m.loginReq)
		case r.URL.Path == "/admin/oauth2/auth/requests/login/accept":
			m.acceptCount++
			_ = json.NewEncoder(w).Encode(RedirectTo{RedirectTo: "https://hydra.test/continue"})
		case r.URL.Path == "/admin/oauth2/auth/requests/login/reject":
			var body RejectRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.recordedRejects = append(m.recordedRejects, rejectCall{phase: "login", error: body.Error})
			_ = json.NewEncoder(w).Encode(RedirectTo{RedirectTo: "https://hydra.test/login-rejected"})
		case r.URL.Path == "/admin/oauth2/auth/requests/consent":
			_ = json.NewEncoder(w).Encode(m.consentReq)
		case r.URL.Path == "/admin/oauth2/auth/requests/consent/accept":
			m.acceptCount++
			_ = json.NewEncoder(w).Encode(RedirectTo{RedirectTo: "https://hydra.test/consent-continue"})
		case r.URL.Path == "/admin/oauth2/auth/requests/consent/reject":
			var body RejectRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.recordedRejects = append(m.recordedRejects, rejectCall{phase: "consent", error: body.Error})
			_ = json.NewEncoder(w).Encode(RedirectTo{RedirectTo: "https://hydra.test/consent-rejected"})
		case r.URL.Path == "/admin/oauth2/auth/requests/logout":
			_ = json.NewEncoder(w).Encode(m.logoutReq)
		case r.URL.Path == "/admin/oauth2/auth/requests/logout/accept":
			m.acceptCount++
			_ = json.NewEncoder(w).Encode(RedirectTo{RedirectTo: "https://hydra.test/logout-continue"})
		default:
			t.Errorf("unexpected hydra path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, m
}

// kratosMock emulates /sessions/whoami (public) and /admin/identities/{id}
// (admin). Responses steered via the embedded session/identity fields.
type kratosMock struct {
	session  *Session
	identity *Identity
}

func newKratosMock(t *testing.T) (*httptest.Server, *kratosMock) {
	m := &kratosMock{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/sessions/whoami"):
			if m.session == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(m.session)
		case strings.HasPrefix(r.URL.Path, "/admin/identities/"):
			if m.identity == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(m.identity)
		default:
			t.Errorf("unexpected kratos path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, m
}

// newTestConfig wires the mocks into a Config and (optionally) a
// manifest dir. Returns ready-to-use cfg.
func newTestConfig(t *testing.T, hydraURL, kratosURL string) Config {
	t.Helper()
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", `
oidc:
  client_id: keep
  client_name: Vaultwarden
  audience:
    - https://keep.dunn.dev
  redirect_uris:
    - https://keep.dunn.dev/identity/connect/oidc-signin
  skip_consent: true
consent:
  roles:
    user:
      description: Vaultwarden user
      claim_emit:
        role: user
  group_role_map:
    family: user
`)
	mset, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	return Config{
		HydraAdminURL:   hydraURL,
		KratosPublicURL: kratosURL,
		KratosAdminURL:  kratosURL,
		LoginURL:        "https://auth.dunn.dev/auth/login",
		Hydra:           NewHydraAdminClient(hydraURL),
		Kratos:          NewKratosClient(kratosURL, kratosURL),
		Manifest:        mset,
	}
}

// TestHandleLogin_SkipPath_Accepts: Hydra remembers the subject; consent
// service skips Kratos whoami and accepts. Access gate still has to fire,
// so Kratos admin GetIdentity is consulted.
func TestHandleLogin_SkipPath_Accepts(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      true,
		Subject:   "user-uuid-1",
		Client:    OAuth2Client{ClientID: "keep", SkipConsent: true},
	}
	kMock.identity = &Identity{
		ID:     "user-uuid-1",
		Traits: map[string]any{"username": "andrew", "email": "a@x"},
		MetadataAdmin: map[string]any{
			"groups": []any{"family", "access-keep"},
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	r.Host = "auth.dunn.dev"
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/continue") {
		t.Fatalf("redirect: got %q, want /continue", loc)
	}
	if hMock.acceptCount != 1 {
		t.Fatalf("acceptCount: got %d, want 1", hMock.acceptCount)
	}
}

// TestHandleLogin_SkipPath_RejectsWithoutAccessGroup: skip flow with a
// remembered subject but the user is missing access-keep. Reject with
// access_denied; never accept.
func TestHandleLogin_SkipPath_RejectsWithoutAccessGroup(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      true,
		Subject:   "user-uuid-2",
		Client:    OAuth2Client{ClientID: "keep", SkipConsent: true},
	}
	kMock.identity = &Identity{
		ID: "user-uuid-2",
		MetadataAdmin: map[string]any{
			"groups": []any{"family"}, // no access-keep
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 0 {
		t.Fatalf("should not accept; acceptCount=%d", hMock.acceptCount)
	}
	if len(hMock.recordedRejects) != 1 {
		t.Fatalf("rejects: got %d, want 1", len(hMock.recordedRejects))
	}
	if hMock.recordedRejects[0].error != "access_denied" {
		t.Fatalf("reject error: got %q, want access_denied", hMock.recordedRejects[0].error)
	}
}

// TestHandleLogin_NoSession_RedirectsToLoginUI: not skip, no whoami
// session: redirect to home portal login URL with return_to.
func TestHandleLogin_NoSession_RedirectsToLoginUI(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, _ := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      false,
		Client:    OAuth2Client{ClientID: "keep"},
	}
	// kMock.session left nil -> 401 from whoami

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	r.Host = "auth.dunn.dev"
	r.Header.Set("X-Forwarded-Host", "auth.dunn.dev")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cfg.LoginURL) {
		t.Fatalf("redirect: got %q, want prefix %q", loc, cfg.LoginURL)
	}
	if !strings.Contains(loc, "return_to=") {
		t.Fatalf("redirect missing return_to: %q", loc)
	}
	if hMock.acceptCount != 0 {
		t.Fatalf("should not accept on no-session path")
	}
}

// TestHandleLogin_ActiveSession_Accepts: not skip, active whoami session
// with the access group, accept with subject = identity.id.
//
// F1: Kratos /sessions/whoami strips metadata_admin by design, so the gate
// MUST fetch the identity via the admin API. Whoami carries only the
// identity ID; the admin lookup carries metadata_admin (groups).
func TestHandleLogin_ActiveSession_Accepts(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      false,
		Client:    OAuth2Client{ClientID: "keep"},
	}
	// Whoami: realistic shape — identity.id present, metadata_admin absent.
	kMock.session = &Session{
		Active: true,
		Identity: Identity{
			ID: "user-uuid-3",
		},
	}
	// Admin API: returns full identity with metadata_admin populated.
	kMock.identity = &Identity{
		ID: "user-uuid-3",
		MetadataAdmin: map[string]any{
			"groups": []any{"family", "access-keep"},
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 1 {
		t.Fatalf("acceptCount: got %d, want 1", hMock.acceptCount)
	}
	if len(hMock.recordedRejects) != 0 {
		t.Fatalf("should not reject; got %d rejects", len(hMock.recordedRejects))
	}
}

// TestHandleLogin_ActiveSession_RejectsWithoutAccessGroup (F1): the
// fresh-login path (skip=false) MUST consult the admin API for
// metadata_admin. Whoami strips that field, so the gate would over-reject
// (or over-accept) if it relied on the session payload alone. This test
// proves the admin-API fallback is wired in: whoami carries identity.id
// only; admin returns the identity without access-keep; gate rejects.
func TestHandleLogin_ActiveSession_RejectsWithoutAccessGroup(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      false,
		Client:    OAuth2Client{ClientID: "keep"},
	}
	kMock.session = &Session{
		Active: true,
		Identity: Identity{
			ID: "user-uuid-no-access",
		},
	}
	kMock.identity = &Identity{
		ID: "user-uuid-no-access",
		MetadataAdmin: map[string]any{
			"groups": []any{"family"}, // no access-keep
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 0 {
		t.Fatalf("should not accept; acceptCount=%d", hMock.acceptCount)
	}
	if len(hMock.recordedRejects) != 1 || hMock.recordedRejects[0].error != "access_denied" {
		t.Fatalf("expected one access_denied reject, got %+v", hMock.recordedRejects)
	}
}

// TestHandleLogin_ActiveSession_WhoamiMissingMetadataAdmin (F1 regression):
// reproduces the production-shape whoami payload (identity.id set,
// metadata_admin nil, traits map populated) and asserts the gate still
// reaches the right verdict by going through admin lookup. Catches a
// future regression where someone reverts the handler to read groups
// off the whoami session.
func TestHandleLogin_ActiveSession_WhoamiMissingMetadataAdmin(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.loginReq = LoginRequest{
		Challenge: "abc",
		Skip:      false,
		Client:    OAuth2Client{ClientID: "keep"},
	}
	// Whoami payload that mirrors what Kratos actually sends to public:
	// identity.id and traits, no metadata_admin field.
	kMock.session = &Session{
		Active: true,
		Identity: Identity{
			ID:     "user-uuid-real-shape",
			Traits: map[string]any{"username": "andrew", "email": "a@x"},
			// MetadataAdmin: deliberately nil
		},
	}
	kMock.identity = &Identity{
		ID:     "user-uuid-real-shape",
		Traits: map[string]any{"username": "andrew", "email": "a@x"},
		MetadataAdmin: map[string]any{
			"groups": []any{"family", "access-keep"},
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 1 {
		t.Fatalf("acceptCount: got %d, want 1 (gate must accept after admin lookup)", hMock.acceptCount)
	}
	if len(hMock.recordedRejects) != 0 {
		t.Fatalf("should not reject; got %d rejects", len(hMock.recordedRejects))
	}
}

// TestHandleConsent_TrustedClient_Accepts: skip_consent=true, identity
// with access group, no role -> accept with default claims.
func TestHandleConsent_TrustedClient_Accepts(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.consentReq = ConsentRequest{
		Challenge: "cc1",
		Skip:      false,
		Subject:   "user-uuid-4",
		Client:    OAuth2Client{ClientID: "keep", SkipConsent: true},
	}
	kMock.identity = &Identity{
		ID: "user-uuid-4",
		MetadataAdmin: map[string]any{
			"groups": []any{"family", "access-keep"},
		},
		Traits: map[string]any{"email": "x@y", "username": "u"},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc1", nil)
	w := httptest.NewRecorder()
	handleConsent(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 1 {
		t.Fatalf("acceptCount: got %d, want 1", hMock.acceptCount)
	}
}

// TestHandleConsent_RejectsWithoutAccessGroup (C2): consent challenge
// for a user missing the access group must reject, regardless of
// skip_consent.
func TestHandleConsent_RejectsWithoutAccessGroup(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, kMock := newKratosMock(t)

	hMock.consentReq = ConsentRequest{
		Challenge: "cc2",
		Skip:      false,
		Subject:   "user-uuid-5",
		Client:    OAuth2Client{ClientID: "keep", SkipConsent: true},
	}
	kMock.identity = &Identity{
		ID: "user-uuid-5",
		MetadataAdmin: map[string]any{
			"groups": []any{"family"}, // no access-keep
		},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc2", nil)
	w := httptest.NewRecorder()
	handleConsent(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 0 {
		t.Fatalf("should not accept without access group")
	}
	if len(hMock.recordedRejects) != 1 || hMock.recordedRejects[0].error != "access_denied" {
		t.Fatalf("expected one access_denied reject, got %+v", hMock.recordedRejects)
	}
}

// TestHandleConsent_UntrustedClient_RejectsConsentRequired: skip_consent
// is false and consent.Skip is false -> reject with consent_required.
// (No client today is configured this way; future-proofing.)
func TestHandleConsent_UntrustedClient_RejectsConsentRequired(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, _ := newKratosMock(t)

	hMock.consentReq = ConsentRequest{
		Challenge: "cc3",
		Skip:      false,
		Subject:   "user-uuid-6",
		Client:    OAuth2Client{ClientID: "future-untrusted", SkipConsent: false},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc3", nil)
	w := httptest.NewRecorder()
	handleConsent(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 0 {
		t.Fatalf("should not accept untrusted client")
	}
	if len(hMock.recordedRejects) != 1 || hMock.recordedRejects[0].error != "consent_required" {
		t.Fatalf("expected one consent_required reject, got %+v", hMock.recordedRejects)
	}
}

// TestHandleLogout_AlwaysAccepts: logout flow always accepts; per-app
// session propagation is the admin "Revoke sessions" path, not here.
func TestHandleLogout_AlwaysAccepts(t *testing.T) {
	hSrv, hMock := newHydraMock(t)
	kSrv, _ := newKratosMock(t)

	hMock.logoutReq = LogoutRequest{
		Challenge: "lc1",
		Subject:   "user-uuid-7",
		Client:    OAuth2Client{ClientID: "keep"},
	}

	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=lc1", nil)
	w := httptest.NewRecorder()
	handleLogout(cfg)(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	if hMock.acceptCount != 1 {
		t.Fatalf("acceptCount: got %d, want 1", hMock.acceptCount)
	}
}

// TestHandleConsent_MissingChallenge: 400 on missing query param.
func TestHandleConsent_MissingChallenge(t *testing.T) {
	hSrv, _ := newHydraMock(t)
	kSrv, _ := newKratosMock(t)
	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/consent", nil)
	w := httptest.NewRecorder()
	handleConsent(cfg)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", w.Code)
	}
}

// TestHandleLogin_MissingChallenge: 400 on missing query param.
func TestHandleLogin_MissingChallenge(t *testing.T) {
	hSrv, _ := newHydraMock(t)
	kSrv, _ := newKratosMock(t)
	cfg := newTestConfig(t, hSrv.URL, kSrv.URL)
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handleLogin(cfg)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", w.Code)
	}
}

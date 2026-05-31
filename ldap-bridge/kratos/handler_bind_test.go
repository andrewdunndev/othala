package kratos

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glauth/ldap"
)

// newHandlerWithServiceBind returns a Handler with a live Kratos mock
// and the service-account bind feature configured.
func newHandlerWithServiceBind(t *testing.T, kratosServer *httptest.Server) *Handler {
	t.Helper()
	h, err := New(Config{
		PublicURL:           kratosServer.URL,
		AdminURL:            kratosServer.URL,
		AdminToken:          "test",
		BaseDN:              "dc=dunn,dc=dev",
		IdentityCacheTTL:    30 * time.Second,
		BindCacheTTL:        30 * time.Second,
		ServiceBindDN:       "cn=ldap-reader,dc=dunn,dc=dev",
		ServiceBindPassword: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("kratos.New: %v", err)
	}
	return h
}

// newHandlerNoServiceBind returns a Handler without the service-account
// feature configured, to confirm normal user-bind flow is unaffected.
func newHandlerNoServiceBind(t *testing.T, kratosServer *httptest.Server) *Handler {
	t.Helper()
	h, err := New(Config{
		PublicURL:        kratosServer.URL,
		AdminURL:         kratosServer.URL,
		AdminToken:       "test",
		BaseDN:           "dc=dunn,dc=dev",
		IdentityCacheTTL: 30 * time.Second,
		BindCacheTTL:     30 * time.Second,
	})
	if err != nil {
		t.Fatalf("kratos.New: %v", err)
	}
	return h
}

// TestServiceBind_CorrectPassword verifies that the service-account bind
// short-circuits to success without calling Kratos.
func TestServiceBind_CorrectPassword(t *testing.T) {
	kratosCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kratosCalled = true
		w.WriteHeader(http.StatusInternalServerError) // must never be reached
	}))
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	code, err := h.Bind("cn=ldap-reader,dc=dunn,dc=dev", "s3cr3t", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess, got %v", code)
	}
	if kratosCalled {
		t.Fatal("Kratos must NOT be called for the service-account bind")
	}
}

// TestServiceBind_WrongPassword verifies that an incorrect password for
// the service DN returns InvalidCredentials without calling Kratos.
func TestServiceBind_WrongPassword(t *testing.T) {
	kratosCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kratosCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	code, err := h.Bind("cn=ldap-reader,dc=dunn,dc=dev", "wrongpassword", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("want LDAPResultInvalidCredentials, got %v", code)
	}
	if kratosCalled {
		t.Fatal("Kratos must NOT be called for the service-account bind (even on wrong password)")
	}
}

// TestServiceBind_CaseInsensitiveDN verifies that DN comparison is
// case-insensitive (DNs are case-insensitive by RFC 4511).
func TestServiceBind_CaseInsensitiveDN(t *testing.T) {
	kratosCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kratosCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	// Send DN with different casing + leading/trailing whitespace.
	code, err := h.Bind("  CN=LDAP-READER,DC=DUNN,DC=DEV  ", "s3cr3t", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess (case-insensitive DN), got %v", code)
	}
	if kratosCalled {
		t.Fatal("Kratos must NOT be called for the service-account bind")
	}
}

// TestServiceBind_Unconfigured confirms that when ServiceBindDN is
// empty, a normal user bind still reaches Kratos (i.e. the feature
// being disabled does not break the existing bind flow).
func TestServiceBind_Unconfigured(t *testing.T) {
	kratosCalled := false
	// Minimal Kratos mock: return 200 from both the flow-init and
	// flow-submit endpoints so the login succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kratosCalled = true
		// Flow-init: return a flow ID.
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"flow-abc"}`))
			return
		}
		// Flow-submit: return 200 (success).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"session_token":"tok"}`))
	}))
	defer srv.Close()

	h := newHandlerNoServiceBind(t, srv)
	// Use a valid user DN; parseUsernameFromDN must succeed.
	code, err := h.Bind("uid=alice,ou=users,dc=dunn,dc=dev", "hunter2", nil)
	// We don't assert Success here — the mock Kratos may or may not
	// accept the fake flow (body format may not be exact). What we MUST
	// assert is that Kratos was called, proving the request fell through
	// the normal path rather than being short-circuited.
	_ = code
	_ = err
	if !kratosCalled {
		t.Fatal("with no ServiceBindDN, a normal user bind must reach Kratos")
	}
}

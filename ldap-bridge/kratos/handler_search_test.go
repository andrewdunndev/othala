package kratos

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glauth/ldap"
)

// mockAdminServer returns a minimal Kratos admin mock that serves an
// empty identity list for the identity-cache refresh path.
func mockAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
}

// TestSearch_AnonymousBound verifies that an empty boundDN (anonymous /
// failed-bind connection) gets zero entries back, not the full directory.
func TestSearch_AnonymousBound(t *testing.T) {
	srv := mockAdminServer(t)
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	result, err := h.Search("", ldap.SearchRequest{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("anonymous Search must return zero entries, got %d", len(result.Entries))
	}
}

// TestSearch_NonServiceDNBound verifies that a connection bound as a
// non-service DN (e.g. a regular user) also gets zero entries.
func TestSearch_NonServiceDNBound(t *testing.T) {
	srv := mockAdminServer(t)
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	result, err := h.Search("uid=alice,ou=users,dc=dunn,dc=dev", ldap.SearchRequest{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("non-service-DN Search must return zero entries, got %d", len(result.Entries))
	}
}

// TestSearch_ServiceDNBound verifies that a connection bound as the
// configured service DN receives the full directory (roster).
// A fresh Handler's identity cache has a zero expiresAt, so it is
// immediately stale and the mock admin server is hit on the first Search.
func TestSearch_ServiceDNBound(t *testing.T) {
	// Serve one identity so we can assert Entries is non-empty.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"abc","traits":{"email":"alice@dunn.dev","username":"alice"},"metadata_admin":null}]`))
	}))
	defer srv.Close()

	h := newHandlerWithServiceBind(t, srv)
	result, err := h.Search("cn=ldap-reader,dc=dunn,dc=dev", ldap.SearchRequest{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) == 0 {
		t.Fatal("service-DN Search must return at least one entry")
	}
}

// TestSearch_ServiceDNUnconfigured verifies the fail-closed default:
// when ServiceBindDN is empty, all searches return zero entries.
func TestSearch_ServiceDNUnconfigured(t *testing.T) {
	srv := mockAdminServer(t)
	defer srv.Close()

	h := newHandlerNoServiceBind(t, srv)
	result, err := h.Search("uid=alice,ou=users,dc=dunn,dc=dev", ldap.SearchRequest{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Fatalf("want LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("unconfigured ServiceBindDN must return zero entries, got %d", len(result.Entries))
	}
}

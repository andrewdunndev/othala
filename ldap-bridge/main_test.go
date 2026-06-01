package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dunn.dev/othala/ldap-bridge/kratos"
)

// TestFlushBindCacheHandler exercises MEDIUM-5: the bridge admin
// endpoint. Bearer-gated, constant-time-compared. Empty bearer env =
// fail-closed.

func newTestHandler(t *testing.T) *kratos.Handler {
	t.Helper()
	h, err := kratos.New(kratos.Config{
		PublicURL:        "http://kratos:4433",
		AdminURL:         "http://kratos:4434",
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

func TestFlushBindCache_RequiresPOST(t *testing.T) {
	t.Setenv(adminBearerEnv, "secret-bearer-32-bytes-aaaaaaaaa")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodGet, "/admin/flush-bind-cache?subject=alice", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", w.Code)
	}
}

func TestFlushBindCache_FailsClosedWithoutBearer(t *testing.T) {
	t.Setenv(adminBearerEnv, "")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodPost, "/admin/flush-bind-cache?subject=alice", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no env bearer: want 403, got %d", w.Code)
	}
}

func TestFlushBindCache_RejectsMissingBearer(t *testing.T) {
	t.Setenv(adminBearerEnv, "secret-bearer-32-bytes-aaaaaaaaa")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodPost, "/admin/flush-bind-cache?subject=alice", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no header: want 401, got %d", w.Code)
	}
}

func TestFlushBindCache_RejectsWrongBearer(t *testing.T) {
	t.Setenv(adminBearerEnv, "secret-bearer-32-bytes-aaaaaaaaa")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodPost, "/admin/flush-bind-cache?subject=alice", nil)
	req.Header.Set("Authorization", "Bearer wrong-bearer")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer: want 401, got %d", w.Code)
	}
}

func TestFlushBindCache_RejectsMissingSubject(t *testing.T) {
	t.Setenv(adminBearerEnv, "secret-bearer-32-bytes-aaaaaaaaa")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodPost, "/admin/flush-bind-cache", nil)
	req.Header.Set("Authorization", "Bearer secret-bearer-32-bytes-aaaaaaaaa")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing subject: want 400, got %d", w.Code)
	}
}

func TestFlushBindCache_AcceptsCorrectBearer(t *testing.T) {
	t.Setenv(adminBearerEnv, "secret-bearer-32-bytes-aaaaaaaaa")
	h := newTestHandler(t)
	handler := flushBindCacheHandler(h)
	req := httptest.NewRequest(http.MethodPost, "/admin/flush-bind-cache?subject=alice", nil)
	req.Header.Set("Authorization", "Bearer secret-bearer-32-bytes-aaaaaaaaa")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("right bearer + subject: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

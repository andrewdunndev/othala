package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testRecoveryGateSecret = "test-recovery-gate-secret-32bytes-aaaaaaaa"

// postRecoveryGate posts a body with a valid X-Webhook-Auth secret. The
// secret env is set fresh in each test via t.Setenv (so parallel tests
// don't observe leakage).
func postRecoveryGate(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv(recoveryGateSecretEnv, testRecoveryGateSecret)
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhooks/recovery-gate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(recoveryGateAuthHeader, testRecoveryGateSecret)
	w := httptest.NewRecorder()
	handleRecoveryGate(Config{})(w, req)
	return w
}

func TestRecoveryGate_AdminGroupRejected(t *testing.T) {
	w := postRecoveryGate(t, map[string]any{
		"identity_id": "abc-123",
		"groups":      []string{"admin", "family", "access-keep"},
		"traits":      map[string]any{"email": "agd@dunn.dev"},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin recovery: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "messages") {
		t.Fatalf("admin recovery: want kratos-shape error envelope, got %s", w.Body.String())
	}
}

func TestRecoveryGate_NonAdminAllowed(t *testing.T) {
	w := postRecoveryGate(t, map[string]any{
		"identity_id": "xyz-789",
		"groups":      []string{"family", "kids", "access-listen"},
		"traits":      map[string]any{"email": "kid@dunn.dev"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("non-admin recovery: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestRecoveryGate_EmptyGroupsRejected (LOW-5):
// An identity_id with an empty groups array is a schema-drift smell.
// The gate fails closed (403) rather than permitting recovery. This is
// the renamed-and-flipped version of the prior EmptyGroupsAllowed test.
func TestRecoveryGate_EmptyGroupsRejected(t *testing.T) {
	w := postRecoveryGate(t, map[string]any{
		"identity_id": "new-user",
		"groups":      []string{},
		"traits":      map[string]any{"email": "new@dunn.dev"},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("empty groups: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestRecoveryGate_MissingGroupsField(t *testing.T) {
	// Kratos jsonnet uses std.get with a default empty array, so this
	// case shouldn't happen in practice. With LOW-5 the gate refuses on
	// empty groups, but only when identity_id is non-empty. A truly
	// malformed body without identity_id should not crash.
	w := postRecoveryGate(t, map[string]any{
		"traits": map[string]any{"email": "weird@dunn.dev"},
	})
	if w.Code >= 500 {
		t.Fatalf("missing groups: handler crashed with %d", w.Code)
	}
}

func TestRecoveryGate_WrongMethod(t *testing.T) {
	t.Setenv(recoveryGateSecretEnv, testRecoveryGateSecret)
	req := httptest.NewRequest(http.MethodGet, "/webhooks/recovery-gate", nil)
	w := httptest.NewRecorder()
	handleRecoveryGate(Config{})(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", w.Code)
	}
}

func TestRecoveryGate_BadJSON(t *testing.T) {
	t.Setenv(recoveryGateSecretEnv, testRecoveryGateSecret)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/recovery-gate", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(recoveryGateAuthHeader, testRecoveryGateSecret)
	w := httptest.NewRecorder()
	handleRecoveryGate(Config{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: want 400, got %d", w.Code)
	}
}

// TestRecoveryGate_MissingSecret: when RECOVERY_GATE_SECRET is unset,
// every webhook call is rejected (MEDIUM-2 fail-closed).
func TestRecoveryGate_MissingSecret(t *testing.T) {
	t.Setenv(recoveryGateSecretEnv, "")
	b, _ := json.Marshal(map[string]any{
		"identity_id": "x",
		"groups":      []string{"family"},
	})
	req := httptest.NewRequest(http.MethodPost, "/webhooks/recovery-gate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRecoveryGate(Config{})(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing secret: want 403, got %d", w.Code)
	}
}

// TestRecoveryGate_WrongSecret: a presented secret that doesn't match
// the configured one is rejected (MEDIUM-2). Constant-time-compared on
// the receiver side; the test exercises the rejection path.
func TestRecoveryGate_WrongSecret(t *testing.T) {
	t.Setenv(recoveryGateSecretEnv, testRecoveryGateSecret)
	b, _ := json.Marshal(map[string]any{
		"identity_id": "x",
		"groups":      []string{"family"},
	})
	req := httptest.NewRequest(http.MethodPost, "/webhooks/recovery-gate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(recoveryGateAuthHeader, "different-secret")
	w := httptest.NewRecorder()
	handleRecoveryGate(Config{})(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong secret: want 403, got %d", w.Code)
	}
}

// TestRecoveryGate_RightSecret: presented secret matches; the handler
// reaches the body-decode path and returns 200 for a non-admin.
func TestRecoveryGate_RightSecret(t *testing.T) {
	w := postRecoveryGate(t, map[string]any{
		"identity_id": "ok",
		"groups":      []string{"family"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("right secret + non-admin: want 200, got %d", w.Code)
	}
}

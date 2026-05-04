package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testContext returns a context bound to t.Cleanup.
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// fakeHydraJWKAdmin serves a single private RSA JWK at
// /admin/keys/hydra.openid.id-token. The signing test uses it to drive
// LogoutTokenSigner.Sign without needing a real Hydra.
type fakeHydraJWKAdmin struct {
	priv *rsa.PrivateKey
	kid  string
}

func newFakeHydraJWKAdmin(t *testing.T) *fakeHydraJWKAdmin {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &fakeHydraJWKAdmin{priv: priv, kid: "test-key-1"}
}

func (f *fakeHydraJWKAdmin) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwk := map[string]string{
			"use": "sig",
			"kty": "RSA",
			"alg": "RS256",
			"kid": f.kid,
			"n":   base64.RawURLEncoding.EncodeToString(f.priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.priv.E)).Bytes()),
			"d":   base64.RawURLEncoding.EncodeToString(f.priv.D.Bytes()),
			"p":   base64.RawURLEncoding.EncodeToString(f.priv.Primes[0].Bytes()),
			"q":   base64.RawURLEncoding.EncodeToString(f.priv.Primes[1].Bytes()),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{jwk},
		})
	})
}

func TestLogoutTokenSigner_Sign_ProducesValidJWT(t *testing.T) {
	fa := newFakeHydraJWKAdmin(t)
	srv := httptest.NewServer(fa.handler())
	defer srv.Close()

	signer := NewLogoutTokenSigner(srv.URL, "https://auth.dunn.dev/")
	tok, err := signer.Sign(testContext(t), LogoutTokenClaims{
		Issuer:   "https://auth.dunn.dev/",
		Audience: "keep",
		Subject:  "01J0TESTID",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := splitJWT(tok)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWS parts, got %d", len(parts))
	}

	header, payload := decodeJWTParts(t, parts[0], parts[1])

	// Header invariants per OIDC Back-Channel Logout 1.0.
	if header["alg"] != "RS256" {
		t.Errorf("header.alg: got %v want RS256", header["alg"])
	}
	if header["typ"] != "logout+jwt" {
		t.Errorf("header.typ: got %v want logout+jwt", header["typ"])
	}
	if header["kid"] != fa.kid {
		t.Errorf("header.kid: got %v want %s", header["kid"], fa.kid)
	}

	// Payload invariants.
	if payload["iss"] != "https://auth.dunn.dev/" {
		t.Errorf("iss: got %v", payload["iss"])
	}
	if payload["aud"] != "keep" {
		t.Errorf("aud: got %v", payload["aud"])
	}
	if payload["sub"] != "01J0TESTID" {
		t.Errorf("sub: got %v", payload["sub"])
	}
	if _, ok := payload["jti"]; !ok {
		t.Error("jti missing")
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("iat missing")
	}
	if _, ok := payload["exp"]; ok {
		t.Errorf("exp must not be present (OIDC BCL §2.6); got %v", payload["exp"])
	}
	events, ok := payload["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing or wrong type: %T", payload["events"])
	}
	if _, ok := events[backchannelLogoutEvent]; !ok {
		t.Errorf("events missing %s key: %+v", backchannelLogoutEvent, events)
	}
}

func TestLogoutTokenSigner_Sign_RejectsEmptySubject(t *testing.T) {
	fa := newFakeHydraJWKAdmin(t)
	srv := httptest.NewServer(fa.handler())
	defer srv.Close()

	signer := NewLogoutTokenSigner(srv.URL, "https://auth.dunn.dev/")
	_, err := signer.Sign(testContext(t), LogoutTokenClaims{
		Issuer:   "https://auth.dunn.dev/",
		Audience: "keep",
		// Subject intentionally empty.
	})
	if err == nil {
		t.Fatal("expected error when subject is empty")
	}
}

// splitJWT splits a compact-serialised JWT into its three parts. Pure
// stdlib so the test stays dep-free.
func splitJWT(tok string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			out = append(out, tok[start:i])
			start = i + 1
		}
	}
	out = append(out, tok[start:])
	return out
}

func decodeJWTParts(t *testing.T, headerB64, payloadB64 string) (map[string]any, map[string]any) {
	t.Helper()
	hb, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var header, payload map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	return header, payload
}

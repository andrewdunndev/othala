package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// tlsConnectionStateMarker is a stub TLS connection state used by tests
// that want to assert "request arrived over TLS" without setting up a
// real cert chain. The buildReturnTo helper checks `r.TLS != nil`.
var tlsConnectionStateMarker = tls.ConnectionState{HandshakeComplete: true}

// TestBuildReturnTo_IgnoresForwardedHeaders verifies the HIGH-2 fix: the
// helper no longer reads X-Forwarded-Host / X-Forwarded-Proto. A spoofed
// header from a hypothetical upstream-bypass attacker has no effect on
// the constructed URL. Without CONSENT_PUBLIC_URL, the URL falls back
// to scheme=http (no r.TLS) + r.Host.
func TestBuildReturnTo_IgnoresForwardedHeaders(t *testing.T) {
	t.Setenv("CONSENT_PUBLIC_URL", "")

	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc", nil)
	r.Host = "internal:4477"
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "javascript")

	got := buildReturnTo(r)
	want := "http://internal:4477/login?login_challenge=abc"
	if got != want {
		t.Fatalf("buildReturnTo: want %q got %q (X-Forwarded headers must NOT influence output)", want, got)
	}
}

// TestBuildReturnTo_PublicBaseURL_OverridesHost: when CONSENT_PUBLIC_URL
// is set (production posture), it supplies scheme + host. Caddy terminates
// TLS upstream so the in-pod request is plaintext but the public URL is
// https.
func TestBuildReturnTo_PublicBaseURL_OverridesHost(t *testing.T) {
	t.Setenv("CONSENT_PUBLIC_URL", "https://auth.dunn.dev")

	r := httptest.NewRequest(http.MethodGet, "/login?login_challenge=xyz", nil)
	r.Host = "internal:4477"
	r.Header.Set("X-Forwarded-Host", "evil.example")

	got := buildReturnTo(r)
	want := "https://auth.dunn.dev/login?login_challenge=xyz"
	if got != want {
		t.Fatalf("buildReturnTo with public URL: want %q got %q", want, got)
	}
}

// TestBuildReturnTo_PublicBaseURL_StripsTrailingSlash: tolerate operator
// configs that include or omit the trailing slash on CONSENT_PUBLIC_URL.
func TestBuildReturnTo_PublicBaseURL_StripsTrailingSlash(t *testing.T) {
	t.Setenv("CONSENT_PUBLIC_URL", "https://auth.dunn.dev/")

	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc", nil)
	r.Host = "internal:4477"

	got := buildReturnTo(r)
	want := "https://auth.dunn.dev/consent?consent_challenge=cc"
	if got != want {
		t.Fatalf("trailing-slash strip: want %q got %q", want, got)
	}
}

// TestBuildReturnTo_TLSImpliesHTTPS: in the (lab-only) shape where the
// request hits the consent service directly with TLS, scheme is https.
// X-Forwarded headers are still ignored.
func TestBuildReturnTo_TLSImpliesHTTPS(t *testing.T) {
	t.Setenv("CONSENT_PUBLIC_URL", "")

	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc", nil)
	r.Host = "auth.dunn.dev"
	r.Header.Set("X-Forwarded-Proto", "javascript")
	tls := tlsConnectionStateMarker
	r.TLS = &tls

	got := buildReturnTo(r)
	want := "https://auth.dunn.dev/consent?consent_challenge=cc"
	if got != want {
		t.Fatalf("TLS->https: want %q got %q", want, got)
	}
}

func TestBuildReturnTo_PreservesQueryString(t *testing.T) {
	t.Setenv("CONSENT_PUBLIC_URL", "https://auth.dunn.dev")

	r := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=cc&extra=1", nil)
	r.Host = "auth.dunn.dev"

	got := buildReturnTo(r)
	want := "https://auth.dunn.dev/consent?consent_challenge=cc&extra=1"
	if got != want {
		t.Fatalf("buildReturnTo: want %q got %q", want, got)
	}
}

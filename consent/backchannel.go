package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// hydraIDTokenKeySet is the JWK set Hydra uses to sign id_tokens. The
// consent service fetches the matching private key from Hydra's admin
// API to sign back-channel logout tokens with the same `kid` and
// `alg`, so apps can verify them using the same JWKS they already
// trust for id_token verification.
//
// Hydra creates this set on first boot and rotates it via
// `/admin/keys/<set>/rotate`. The consent service refreshes its cache
// every 15 minutes (less than the typical id_token lifetime) and on
// any signature failure.
const hydraIDTokenKeySet = "hydra.openid.id-token"

// backchannelLogoutEvent is the constant URI defined by OIDC Back-
// Channel Logout 1.0 § 2.4. It identifies the events claim shape every
// RP looks for.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// backchannelLogoutContentType is the request body content type RPs
// expect at their backchannel_logout_uri (§ 2.5).
const backchannelLogoutContentType = "application/x-www-form-urlencoded"

// LogoutTokenSigner reads Hydra's id_token signing key from the admin
// API and signs OIDC back-channel logout tokens with the same key. The
// signed tokens are verifiable by every RP using Hydra's published
// JWKS without any per-RP key distribution.
//
// Goroutine-safe; the cached key+kid live behind an RWMutex.
type LogoutTokenSigner struct {
	HydraAdminURL string
	HTTP          *http.Client
	Issuer        string

	mu     sync.RWMutex
	cache  *signingKey
	expiry time.Time
}

type signingKey struct {
	kid string
	alg string
	// Exactly one of these is non-nil.
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// NewLogoutTokenSigner returns a signer pointed at hydraAdminURL.
// Issuer is the public issuer string (Hydra's `urls.self.issuer`); the
// signed logout tokens carry it as `iss` so RP verification passes.
func NewLogoutTokenSigner(hydraAdminURL, issuer string) *LogoutTokenSigner {
	return &LogoutTokenSigner{
		HydraAdminURL: hydraAdminURL,
		Issuer:        issuer,
		HTTP:          &http.Client{Timeout: 5 * time.Second},
	}
}

// LogoutTokenClaims is the OIDC Back-Channel Logout 1.0 § 2.4 token
// shape. iat/exp/jti are filled by Sign; the caller supplies the rest.
type LogoutTokenClaims struct {
	Issuer   string
	Audience string // app's client_id
	Subject  string // identity id
	SID      string // optional Hydra session id; empty if not tracked
}

// Sign produces a serialised, signed JWT logout token. The caller posts
// the result to the RP's backchannel_logout_uri as
// `logout_token=<jwt>` form-urlencoded, content-type
// application/x-www-form-urlencoded.
//
// Per OIDC Back-Channel Logout 1.0 § 2.4, the token MUST contain:
//   - iss, aud, iat, jti, events; AND
//   - exactly one of sub or sid (or both).
//
// We always include sub. sid is included when the caller passes it.
func (s *LogoutTokenSigner) Sign(ctx context.Context, c LogoutTokenClaims) (string, error) {
	if c.Subject == "" {
		return "", errors.New("logout token: sub is required (sid alone is not currently emitted)")
	}
	key, err := s.getKey(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch signing key: %w", err)
	}

	jti, err := randomJTI()
	if err != nil {
		return "", err
	}

	header := map[string]any{
		"alg": key.alg,
		"typ": "logout+jwt",
		"kid": key.kid,
	}
	now := time.Now().Unix()
	payload := map[string]any{
		"iss": c.Issuer,
		"aud": c.Audience,
		"iat": now,
		// Logout tokens have no exp per OIDC Back-Channel Logout § 2.6
		// (must NOT have an exp). Apps treat them as one-shot.
		"jti": jti,
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
		"sub": c.Subject,
	}
	if c.SID != "" {
		payload["sid"] = c.SID
	}

	headerB, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadB, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64URLEncode(headerB) + "." + base64URLEncode(payloadB)

	sig, err := signJWS(key, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign jws: %w", err)
	}
	return signingInput + "." + base64URLEncode(sig), nil
}

// getKey returns the cached signing key, refreshing from Hydra admin
// every 15 minutes. The 15-minute cache window matches Hydra's typical
// rotation cadence (operators rotate via the admin API; the cache
// refresh picks up new keys without a service restart).
func (s *LogoutTokenSigner) getKey(ctx context.Context) (*signingKey, error) {
	s.mu.RLock()
	if s.cache != nil && time.Now().Before(s.expiry) {
		k := s.cache
		s.mu.RUnlock()
		return k, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check after acquiring the write lock.
	if s.cache != nil && time.Now().Before(s.expiry) {
		return s.cache, nil
	}

	key, err := s.fetchKey(ctx)
	if err != nil {
		return nil, err
	}
	s.cache = key
	s.expiry = time.Now().Add(15 * time.Minute)
	return key, nil
}

// refreshKey (MEDIUM-6) drops the cached signing key. The next Sign
// call refetches from Hydra. Goroutine-safe. Used:
//   - SIGUSR1 handler in main.go (operator runbook for key rotation).
//   - On RP-rejected logout token (4xx response in PostLogoutToken
//     wrapper); see signAndPostWithRefresh.
func (s *LogoutTokenSigner) refreshKey() {
	s.mu.Lock()
	s.cache = nil
	s.expiry = time.Time{}
	s.mu.Unlock()
}

// hydraJWKSetResponse is the subset of /admin/keys/{set} we read.
type hydraJWKSetResponse struct {
	Keys []hydraJWK `json:"keys"`
}

type hydraJWK struct {
	Use string `json:"use"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	// RSA private fields
	N, E, D, P, Q, DP, DQ, QI string
	// EC fields
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// EC private field shadows RSA D
}

// UnmarshalJSON keeps the fields readable while letting us decode a
// single payload for both RSA and EC keys.
func (k *hydraJWK) UnmarshalJSON(b []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	k.Use = raw["use"]
	k.Kty = raw["kty"]
	k.Kid = raw["kid"]
	k.Alg = raw["alg"]
	k.N = raw["n"]
	k.E = raw["e"]
	k.D = raw["d"]
	k.P = raw["p"]
	k.Q = raw["q"]
	k.DP = raw["dp"]
	k.DQ = raw["dq"]
	k.QI = raw["qi"]
	k.Crv = raw["crv"]
	k.X = raw["x"]
	k.Y = raw["y"]
	return nil
}

func (s *LogoutTokenSigner) fetchKey(ctx context.Context) (*signingKey, error) {
	u := strings.TrimRight(s.HydraAdminURL, "/") + "/admin/keys/" + url.PathEscape(hydraIDTokenKeySet)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("hydra admin /admin/keys/%s: %d %s", hydraIDTokenKeySet, resp.StatusCode, string(body))
	}
	var set hydraJWKSetResponse
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	for _, jwk := range set.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		// Pick the first private key. Hydra returns both private and
		// public for each kid; the private one carries `d`.
		if jwk.D == "" {
			continue
		}
		return jwkToSigningKey(jwk)
	}
	return nil, errors.New("hydra admin: no private signing key in id-token key set")
}

func jwkToSigningKey(jwk hydraJWK) (*signingKey, error) {
	switch jwk.Kty {
	case "RSA":
		key, err := rsaFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		alg := jwk.Alg
		if alg == "" {
			alg = "RS256"
		}
		if !isSupportedRSAAlg(alg) {
			return nil, fmt.Errorf("unsupported rsa alg %q", alg)
		}
		return &signingKey{kid: jwk.Kid, alg: alg, rsa: key}, nil
	case "EC":
		key, err := ecFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		alg := jwk.Alg
		if alg == "" {
			alg = "ES256"
		}
		if !isSupportedECAlg(alg) {
			return nil, fmt.Errorf("unsupported ec alg %q", alg)
		}
		return &signingKey{kid: jwk.Kid, alg: alg, ec: key}, nil
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", jwk.Kty)
	}
}

func isSupportedRSAAlg(a string) bool {
	switch a {
	case "RS256", "RS384", "RS512":
		return true
	}
	return false
}

func isSupportedECAlg(a string) bool {
	switch a {
	case "ES256", "ES384", "ES512":
		return true
	}
	return false
}

func rsaFromJWK(jwk hydraJWK) (*rsa.PrivateKey, error) {
	n, err := decodeJWKBigInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("rsa.n: %w", err)
	}
	e, err := decodeJWKBigInt(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("rsa.e: %w", err)
	}
	d, err := decodeJWKBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("rsa.d: %w", err)
	}
	p, err := decodeJWKBigInt(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("rsa.p: %w", err)
	}
	q, err := decodeJWKBigInt(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("rsa.q: %w", err)
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("rsa key invalid: %w", err)
	}
	priv.Precompute()
	return priv, nil
}

func ecFromJWK(jwk hydraJWK) (*ecdsa.PrivateKey, error) {
	curve, hashSize := curveFor(jwk.Crv)
	if curve == nil {
		return nil, fmt.Errorf("unsupported ec curve %q", jwk.Crv)
	}
	x, err := decodeJWKBigInt(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("ec.x: %w", err)
	}
	y, err := decodeJWKBigInt(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("ec.y: %w", err)
	}
	d, err := decodeJWKBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("ec.d: %w", err)
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	_ = hashSize // reserved for future curve-specific size validation
	return priv, nil
}

func decodeJWKBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// signJWS produces the signature bytes for a JWS Compact Serialization
// signing input. RS256 / RS384 / RS512 / ES256 / ES384 / ES512 covered.
func signJWS(k *signingKey, signingInput []byte) ([]byte, error) {
	hash, err := hashForAlg(k.alg)
	if err != nil {
		return nil, err
	}
	digester := hash.New()
	digester.Write(signingInput)
	digest := digester.Sum(nil)

	switch {
	case k.rsa != nil:
		return rsa.SignPKCS1v15(rand.Reader, k.rsa, hash, digest)
	case k.ec != nil:
		r, sigS, err := ecdsa.Sign(rand.Reader, k.ec, digest)
		if err != nil {
			return nil, err
		}
		// JOSE concatenates fixed-width R || S.
		curveBits := k.ec.Curve.Params().BitSize
		size := (curveBits + 7) / 8
		out := make([]byte, 2*size)
		rBytes := r.Bytes()
		sBytes := sigS.Bytes()
		copy(out[size-len(rBytes):size], rBytes)
		copy(out[2*size-len(sBytes):], sBytes)
		return out, nil
	}
	return nil, errors.New("no key material loaded")
}

func hashForAlg(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "ES512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported alg %q", alg)
}

func curveFor(crv string) (curve, int) { // returns (elliptic.Curve, hash size in bits)
	// Imported lazily to keep init cheap; crypto/elliptic curves are
	// referenced via the closure below to satisfy the linter without
	// exposing the elliptic import to packages that don't use EC keys.
	return curveLookup[crv].curve, curveLookup[crv].hash
}

// curveLookup is initialised in backchannel_curves.go (separate file
// keeps the elliptic import isolated and easy to drop if we ever
// constrain Hydra to RSA-only signing).
var _ = curveLookup // ensure init order

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomJTI() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// RPError is the typed failure from a back-channel logout post. The
// Status field lets callers distinguish 4xx (likely key/kid mismatch,
// retry after key refresh) from 5xx (RP transient: retry without
// refresh) and from non-HTTP errors (network, timeout: Status==0).
type RPError struct {
	Endpoint string
	Status   int
	Body     string
}

func (e *RPError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s: %s", e.Endpoint, e.Body)
	}
	return fmt.Sprintf("%s: %d %s", e.Endpoint, e.Status, e.Body)
}

// IsClientReject reports whether an error came from a 4xx response from
// the RP (signature rejection, kid not found in JWKS, etc.). Callers
// use this to decide whether a key refresh + retry is worth it.
func IsClientReject(err error) bool {
	var rpe *RPError
	if !errorAs(err, &rpe) {
		return false
	}
	return rpe.Status >= 400 && rpe.Status < 500
}

// errorAs is a tiny shim around errors.As to keep the rest of the file
// stdlib-shaped without dragging the import into the top-level when only
// one call site needs it.
func errorAs(err error, target any) bool {
	return errors.As(err, target)
}

// PostLogoutToken delivers a signed logout token to the RP's
// backchannel_logout_uri per OIDC Back-Channel Logout 1.0 § 2.6.
// Returns nil on 200/204; *RPError on a non-2xx HTTP response; or a
// plain error on transport failure.
func PostLogoutToken(ctx context.Context, httpClient *http.Client, endpoint, signedToken string) error {
	form := url.Values{"logout_token": {signedToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", backchannelLogoutContentType)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return &RPError{Endpoint: endpoint, Status: 0, Body: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &RPError{Endpoint: endpoint, Status: resp.StatusCode, Body: string(body)}
}

// SignAndPostWithKeyRefresh (MEDIUM-6) wraps the sign+post pair so a
// 4xx response from the RP triggers one signing-key refresh followed by
// a single retry. Beats the 15min cache TTL when an operator just
// rotated Hydra's id_token key.
func (s *LogoutTokenSigner) SignAndPostWithKeyRefresh(
	ctx context.Context,
	httpClient *http.Client,
	endpoint string,
	claims LogoutTokenClaims,
) error {
	token, err := s.Sign(ctx, claims)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := PostLogoutToken(ctx, httpClient, endpoint, token); err != nil {
		if !IsClientReject(err) {
			return err
		}
		// 4xx: kid mismatch is the most plausible cause. Drop cache,
		// re-sign with the fresh key, retry once. Server (5xx) and
		// transport errors do not refresh: retrying with a new key
		// won't help if the RP is unreachable or down.
		s.refreshKey()
		retryToken, err2 := s.Sign(ctx, claims)
		if err2 != nil {
			return fmt.Errorf("sign-after-refresh: %w", err2)
		}
		if err3 := PostLogoutToken(ctx, httpClient, endpoint, retryToken); err3 != nil {
			return err3
		}
		return nil
	}
	return nil
}

// makeIntFromBytes is unused but reserved for callers that want to
// parse the RSA exponent as a fixed-width int rather than a big.Int.
// Kept here to document the intent.
func makeIntFromBytes(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) < 8 {
		pad := make([]byte, 8-len(b))
		b = append(pad, b...)
	}
	return binary.BigEndian.Uint64(b)
}

var _ = sha256.Size
var _ = sha512.Size

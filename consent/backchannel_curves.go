package main

import "crypto/elliptic"

// curve is an alias of elliptic.Curve, scoped to this package so the
// LogoutTokenSigner can pick a curve from a JWK `crv` parameter.
type curve = elliptic.Curve

// curveEntry is one row in the JWK crv → (Go curve, hash size) table.
type curveEntry struct {
	curve curve
	hash  int // hash size in bits, advisory
}

// curveLookup maps the JOSE-standard `crv` strings to the matching
// crypto/elliptic curve plus the hash size paired with each by
// convention. The JWA registry pairs:
//
//	P-256 with ES256 / SHA-256
//	P-384 with ES384 / SHA-384
//	P-521 with ES512 / SHA-512
var curveLookup = map[string]curveEntry{
	"P-256": {elliptic.P256(), 256},
	"P-384": {elliptic.P384(), 384},
	"P-521": {elliptic.P521(), 512},
}

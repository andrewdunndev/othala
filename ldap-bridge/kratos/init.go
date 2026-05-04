// Package init notes.
//
// glauth v2.5 has no public handler-registration API: backends are
// wired by a hard-coded switch in pkg/server, and the embed path is
// build-tag gated to sqlite. So this package does NOT call any
// handler.Register at init time. The binary's main package wires the
// Handler directly onto a github.com/glauth/ldap server. Our Handler
// implements glauth's pkg/handler.Handler interface, so the kratos
// package remains drop-in for any future upstream registration API
// without code changes here.
package kratos

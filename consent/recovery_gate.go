package main

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"slices"
)

// adminGroup is the identity-group name that toggles admin recovery
// rejection. Matches the canonical IDENTITY_GROUP_ORDER list in
// portal/src/lib/access.ts.
const adminGroup = "admin"

// recoveryGateSecretEnv names the env var holding the shared secret
// Kratos sends as the X-Webhook-Auth header on recovery webhook posts
// (MEDIUM-2). Constant-time-compared on this end. If unset, the gate
// fails closed: every webhook call is rejected.
const recoveryGateSecretEnv = "RECOVERY_GATE_SECRET"

// recoveryGateAuthHeader is the request header carrying the shared
// secret. Kratos's web_hook config places it via either an `auth: api_key`
// block (Kratos v1.3+) or via the jsonnet body's outgoing headers (older
// shape). Either path lands here.
const recoveryGateAuthHeader = "X-Webhook-Auth"

// recoveryGateRequest mirrors the body kratos/hooks/recovery-gate.jsonnet
// emits. We don't decode the full Kratos identity here; only the fields
// the gate consults.
type recoveryGateRequest struct {
	IdentityID string         `json:"identity_id"`
	Groups     []string       `json:"groups"`
	Traits     map[string]any `json:"traits"`
}

// kratosWebhookError is the response shape Kratos expects when a
// can_interrupt webhook denies a flow. The `messages` array surfaces in
// the recovery flow UI.
//
//	{
//	  "messages": [
//	    {
//	      "instance_ptr": "#/",
//	      "messages": [
//	        {"id": 1, "text": "...", "type": "error"}
//	      ]
//	    }
//	  ]
//	}
type kratosWebhookError struct {
	Messages []kratosWebhookErrorScope `json:"messages"`
}

type kratosWebhookErrorScope struct {
	InstancePtr string                  `json:"instance_ptr"`
	Messages    []kratosWebhookMessage  `json:"messages"`
}

type kratosWebhookMessage struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"`
}

// handleRecoveryGate is mounted at POST /webhooks/recovery-gate (admin
// listener since MEDIUM-1). It inspects the recovery target's identity
// groups and rejects flows for admins, allowing flows for everyone else.
//
// Posture (D3):
//   - Email recovery is allowed for non-admin family members.
//   - Admins MUST use shell/console recovery (see
//     docs/runbooks/admin-recovery.md), so a compromised Fastmail does
//     not yield admin takeover.
//
// MEDIUM-2: the gate verifies a shared secret on every call before
// reading the body. Kratos sends RECOVERY_GATE_SECRET as the
// X-Webhook-Auth header (configured via `auth: api_key` in kratos.yml
// where supported, or via the jsonnet body's headers section).
//
// LOW-5: the gate refuses on empty req.Groups when req.IdentityID is
// non-empty. Active identities always carry at least one group; an
// empty array signals schema drift, and "fail closed" is the correct
// default for a recovery-permitting webhook.
//
// _ cfg: reserved for future Manifest/Hydra access from the gate.
func handleRecoveryGate(_ Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// MEDIUM-2: verify shared secret BEFORE decoding the body. Fail
		// closed if the env var is empty so a misdeploy is loud rather
		// than silent.
		secret := os.Getenv(recoveryGateSecretEnv)
		if secret == "" {
			slog.Error("recovery-gate: RECOVERY_GATE_SECRET unset; rejecting all webhook calls")
			http.Error(w, "webhook auth disabled", http.StatusForbidden)
			return
		}
		got := r.Header.Get(recoveryGateAuthHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
			slog.Warn("recovery-gate: webhook secret mismatch")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var req recoveryGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Kratos retries on 5xx; replying 4xx makes the failure visible
			// in the operator's logs without a retry storm.
			slog.Error("recovery-gate: bad request body", "err", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// LOW-5: refuse-on-empty groups (defensive default). Kratos'
		// jsonnet uses std.get with empty-array defaults, so a missing
		// metadata_admin path arrives as groups=[]; we'd rather fail
		// closed than silently permit admin recovery if the schema
		// drifts.
		if req.IdentityID != "" && len(req.Groups) == 0 {
			slog.Warn("recovery-gate: refusing on empty groups (schema-drift defensive default)",
				"identity_id", req.IdentityID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(kratosWebhookError{
				Messages: []kratosWebhookErrorScope{{
					InstancePtr: "#/",
					Messages: []kratosWebhookMessage{{
						ID:   4000002,
						Type: "error",
						Text: "Recovery is unavailable due to a schema configuration issue. Contact an admin.",
					}},
				}},
			})
			return
		}

		if slices.Contains(req.Groups, adminGroup) {
			slog.Warn("recovery-gate: rejecting admin recovery",
				"identity_id", req.IdentityID,
				"groups", req.Groups,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(kratosWebhookError{
				Messages: []kratosWebhookErrorScope{{
					InstancePtr: "#/",
					Messages: []kratosWebhookMessage{{
						ID:   4000001,
						Type: "error",
						Text: "Email recovery is disabled for admin accounts. Contact another admin or follow the console-recovery runbook.",
					}},
				}},
			})
			return
		}

		slog.Info("recovery-gate: allow", "identity_id", req.IdentityID)
		w.WriteHeader(http.StatusOK)
	}
}

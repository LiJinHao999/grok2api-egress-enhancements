package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func schedulerCandidateAvailable(candidate pluginapi.SchedulerAuthCandidate) bool {
	status := strings.ToLower(strings.TrimSpace(candidate.Status))
	// Empty status is retained for older CPA hosts. Any explicit lifecycle or
	// cooldown state other than active/ready must stay with CPA's retry logic.
	switch status {
	case "", "active", "ready":
		return true
	case "disabled", "unavailable", "error", "cooling", "cooldown", "pending", "refreshing", "retrying":
		return false
	default:
		// Unknown explicit states are fail-closed; selecting them can bypass CPA's
		// own cooldown scheduler.
		return false
	}
}

// handleSchedulerPick hands auth selection entirely back to the host.
//
// CPA only consults SessionAffinitySelector on the legacy path when the plugin
// responds Handled:false (conductor.pickNextLegacy: "if !handled { selector.Pick }").
// Any Handled:true answer — pinning AuthID or DelegateBuiltin — routes into
// pickViaBuiltinScheduler, a bare round-robin cursor that bypasses session
// affinity entirely and rotates auths on every request.
//
// Quarantined nodes are still defended without taking over selection:
// migrateAuthsOffNode first disables affected auths (CPA drops candidate.Disabled),
// then rebinds them to a healthy exit; disableAuthsOnNode is the fallback when
// migration cannot complete. handleRequestIntercept closes the race between
// host selection and that disable/migrate window.
func handleSchedulerPick(request []byte) ([]byte, error) {
	_ = request
	return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
}

// handleRequestInterceptAfterAuth closes the small race between auth selection
// and synchronous quarantine migration. A request selected during that window
// receives a retryable response instead of reaching a known bad egress.
func handleRequestIntercept(request []byte, afterAuth bool) ([]byte, error) {
	ensureStore()
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode request interceptor request: %w", err)
	}
	if !afterAuth || len(req.Metadata) == 0 {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	selected := firstString(req.Metadata, "selected_auth_id", "selectedAuthID", "auth_id", "authID")
	if selected == "" {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	nodeID := resolveNodeIDForAuth(store, selected)
	if nodeID == "" {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	node, ok := store.getNode(nodeID)
	// Fallback only for non-schedulable exits: guard quarantine and the
	// account-window cool-off. Healthy nodes pass through.
	if !ok || nodeSchedulable(node) {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    "egress_quarantined",
			"message": "当前账号出口正在隔离迁移，请重试",
		},
	})
	return okEnvelope(pluginapi.RequestInterceptResponse{
		Terminate:  true,
		StatusCode: http.StatusServiceUnavailable,
		ResponseHeaders: http.Header{
			"Content-Type": []string{"application/json"},
			"Retry-After":  []string{"1"},
		},
		ResponseBody: body,
	})
}

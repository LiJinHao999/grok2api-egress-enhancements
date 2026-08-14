package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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

func quarantinedInterceptResponse() ([]byte, error) {
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

func storeHasGuardQuarantine(s *stateStore) bool {
	if s == nil {
		return false
	}
	for _, node := range s.listNodes() {
		if node != nil && node.DisabledByGuard {
			return true
		}
	}
	return false
}

// selectedAuthKeysFromMetadata collects every host-published auth identifier.
// CPA writes both selected_auth_id (runtime ID, often the relative filename)
// and selected_auth_index (stable EnsureIndex hash). The first non-empty key
// is not enough: a cache hit on index must still be tried when the ID misses.
func selectedAuthKeysFromMetadata(meta map[string]any) []string {
	if len(meta) == 0 {
		return nil
	}
	keys := []string{
		"selected_auth_id", "selectedAuthID",
		"selected_auth_index", "selectedAuthIndex",
		"auth_id", "authID", "AuthID",
		"AuthIndex", "auth_index",
	}
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		value := strings.TrimSpace(firstString(meta, key))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// handleRequestInterceptAfterAuth closes the small race between auth selection
// and synchronous quarantine migration. A request selected during that window
// receives a retryable response instead of reaching a known bad egress.
//
// After handing selection back to CPA, this interceptor is the only request-
// level gate. Missing selected-auth metadata during an xAI quarantine
// fail-closes. A known selected auth that does not map to a managed node is
// unmanaged (direct / unknown proxy) and must pass — another node's isolation
// must not 503 the rest of the pool. Clearly non-xAI traffic is left alone.
func handleRequestIntercept(request []byte, afterAuth bool) ([]byte, error) {
	ensureStore()
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode request interceptor request: %w", err)
	}
	if !afterAuth {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	selected := selectedAuthKeysFromMetadata(req.Metadata)
	if len(selected) == 0 {
		if storeHasGuardQuarantine(store) && !interceptLooksLikeNonXAI(req) {
			return quarantinedInterceptResponse()
		}
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	nodeID := resolveNodeIDForAuth(store, selected...)
	if nodeID == "" {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	node, ok := store.getNode(nodeID)
	if !ok || !node.DisabledByGuard {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	return quarantinedInterceptResponse()
}

func interceptLooksLikeNonXAI(req pluginapi.RequestInterceptRequest) bool {
	blob := strings.ToLower(strings.Join([]string{
		req.Model,
		req.RequestedModel,
		req.ToFormat,
		req.SourceFormat,
		firstString(req.Metadata, "provider", "Provider", "model_provider"),
		firstString(req.Metadata, "model", "Model"),
	}, " "))
	if strings.Contains(blob, "xai") || strings.Contains(blob, "grok") {
		return false
	}
	for _, marker := range []string{"gemini", "claude", "anthropic", "openai", "gpt-", "copilot", "vertex", "bedrock"} {
		if strings.Contains(blob, marker) {
			return true
		}
	}
	return false
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
// migrateAuthsOffNode first disables affected auths, then rebinds them to a
// healthy exit; disableAuthsOnNode is the fallback when migration cannot
// complete. CPA v7.2.113 host.auth.save does not apply file disabled /
// proxy_url to the runtime Auth immediately, so handleRequestIntercept is
// the request-level gate for both the pick/migrate race and the watcher
// settle window after every bind save.
func handleSchedulerPick(request []byte) ([]byte, error) {
	_ = request
	return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
}

// authRuntimeSettle is how long a just-saved auth stays blocked at the
// interceptor. CPA v7.2.113 host.auth.save rebuilds runtime Auth as
// StatusActive with an empty ProxyURL; the file watcher usually copies
// disabled / proxy_url back from disk on the next Write event. Two
// seconds covers local fsnotify and a slow Docker notify hop. Tests
// override authSettleNow rather than sleeping.
const authRuntimeSettle = 2 * time.Second

var (
	authSettleNow = time.Now
	authHoldMu    sync.Mutex
	authHolds     map[string]time.Time
)

func resetAuthRuntimeHolds() {
	authHoldMu.Lock()
	authHolds = nil
	authHoldMu.Unlock()
}

func authIdentityKeys(a authFile) []string {
	keys := []string{
		a.Index, a.ID, a.Name, a.Path, a.Email,
		strings.TrimSuffix(a.Name, ".json"),
		filepath.Base(a.Path),
	}
	if a.Email != "" {
		keys = append(keys, "xai-"+a.Email+".json")
	}
	return keys
}

func markAuthRuntimeUnsettled(a authFile, extraKeys ...string) {
	until := authSettleNow().Add(authRuntimeSettle)
	keys := append(authIdentityKeys(a), extraKeys...)
	authHoldMu.Lock()
	if authHolds == nil {
		authHolds = map[string]time.Time{}
	}
	now := authSettleNow()
	for key, expiry := range authHolds {
		if !expiry.After(now) {
			delete(authHolds, key)
		}
	}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		authHolds[key] = until
	}
	authHoldMu.Unlock()
}

func markAuthRuntimeUnsettledFromSave(name string, obj map[string]any) {
	email := ""
	if obj != nil {
		email, _ = obj["email"].(string)
	}
	identity := authFile{Name: name, Email: email}
	authListMu.Lock()
	for _, cached := range authListCache {
		if cached.Name == name || cached.ID == name || cached.Index == name {
			identity = cached
			identity.Name = name
			if email != "" {
				identity.Email = email
			}
			break
		}
	}
	authListMu.Unlock()
	markAuthRuntimeUnsettled(identity, name)
}

func selectedAuthRuntimeHold(keys ...string) (remaining time.Duration, held bool) {
	now := authSettleNow()
	authHoldMu.Lock()
	defer authHoldMu.Unlock()
	var latest time.Time
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		until, ok := authHolds[key]
		if !ok || !until.After(now) {
			continue
		}
		if until.After(latest) {
			latest = until
		}
	}
	if latest.IsZero() {
		return 0, false
	}
	return latest.Sub(now), true
}

func retryAfterSeconds(remaining time.Duration) int {
	if remaining <= 0 {
		return 1
	}
	seconds := int(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	if seconds > 5 {
		return 5
	}
	return seconds
}

func quarantinedInterceptResponse() ([]byte, error) {
	return quarantinedInterceptResponseWithRetry(time.Second)
}

func quarantinedInterceptResponseWithRetry(remaining time.Duration) ([]byte, error) {
	retryAfter := retryAfterSeconds(remaining)
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
			"Retry-After":  []string{strconv.Itoa(retryAfter)},
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

// handleRequestIntercept is the only request-level gate after selection is
// handed back to CPA. It fail-closes when:
//   - the selected auth was just rebound (runtime ProxyURL/Disabled still stale)
//   - selected-auth metadata is missing during an xAI quarantine
//   - the selected key cannot be resolved (cold cache / list miss)
//   - the selected proxy matches a quarantined node
//   - the selected proxy is known but matches no node, during quarantine
//
// Only an auth we positively know is unmanaged (empty / sentinel proxy) may
// pass while another node is isolated. Clearly non-xAI traffic is left alone.
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
	if remaining, held := selectedAuthRuntimeHold(selected...); held && !interceptLooksLikeNonXAI(req) {
		return quarantinedInterceptResponseWithRetry(remaining)
	}
	if len(selected) == 0 {
		if storeHasGuardQuarantine(store) && !interceptLooksLikeNonXAI(req) {
			return quarantinedInterceptResponse()
		}
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	binding := lookupAuthBinding(store, selected...)
	if !binding.Known {
		if storeHasGuardQuarantine(store) && !interceptLooksLikeNonXAI(req) {
			return quarantinedInterceptResponse()
		}
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	if binding.Unmanaged {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	if binding.NodeID == "" {
		if storeHasGuardQuarantine(store) && !interceptLooksLikeNonXAI(req) {
			return quarantinedInterceptResponse()
		}
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	node, ok := store.getNode(binding.NodeID)
	if !ok || !node.DisabledByGuard {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	return quarantinedInterceptResponse()
}

func interceptLooksLikeNonXAI(req pluginapi.RequestInterceptRequest) bool {
	// Wire format (ToFormat/SourceFormat=openai) is not provider identity.
	// CPA OpenAI-compat clients set SourceFormat=openai for Grok too.
	provider := strings.ToLower(firstString(req.Metadata, "provider", "Provider", "model_provider"))
	model := strings.ToLower(strings.Join([]string{
		req.Model,
		req.RequestedModel,
		firstString(req.Metadata, "model", "Model"),
	}, " "))
	blob := strings.TrimSpace(provider + " " + model)
	if strings.Contains(blob, "xai") || strings.Contains(blob, "grok") {
		return false
	}
	for _, marker := range []string{"gemini", "claude", "anthropic", "copilot", "vertex", "bedrock"} {
		if strings.Contains(blob, marker) {
			return true
		}
	}
	// Explicit non-xAI provider only. Model aliases like gpt-4 may be Grok.
	return strings.Contains(provider, "openai")
}

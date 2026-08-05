package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var schedulerCursor atomic.Uint64

func isXAIProvider(provider string) bool {
	provider = strings.ToLower(strings.TrimSpace(provider))
	return strings.Contains(provider, "xai") || strings.Contains(provider, "grok")
}

func requestIncludesXAI(provider string, providers []string) bool {
	if isXAIProvider(provider) {
		return true
	}
	for _, candidate := range providers {
		if isXAIProvider(candidate) {
			return true
		}
	}
	return false
}

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

// handleSchedulerPick keeps the host scheduler from selecting an auth whose
// proxy node is quarantined. Unmanaged providers and unbound accounts are
// delegated to CPA's native scheduler.
func handleSchedulerPick(request []byte) ([]byte, error) {
	ensureStore()
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode scheduler request: %w", err)
	}
	if !requestIncludesXAI(req.Provider, req.Providers) {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}

	// If PerfectAI currently points at a quarantined leaf, switch first so
	// shared mixed-port auths become eligible again instead of hard-failing.
	_, _ = ensureHealthyClashExit(store)

	eligible, managed, nonXAIAvailable := collectEligibleSchedulerAuths(req)
	if !managed {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}
	if len(eligible) == 0 {
		// Active leaf is often already quarantined while Clash still points at it.
		// Force switch (and clear active mark if needed) then recollect.
		switched, err := ensureHealthyClashExit(store)
		if err != nil {
			// Last resort: pick any healthy clash leaf and switch production group.
			if forceErr := forceSwitchAnyHealthyClash(store); forceErr == nil {
				switched = true
				err = nil
			}
		}
		if switched || err == nil {
			eligible, managed, nonXAIAvailable = collectEligibleSchedulerAuths(req)
		}
	}
	if len(eligible) == 0 {
		// Still empty: try force switch once more then fail soft for mixed providers.
		_ = forceSwitchAnyHealthyClash(store)
		eligible, managed, nonXAIAvailable = collectEligibleSchedulerAuths(req)
	}
	if len(eligible) == 0 {
		if strings.TrimSpace(req.Provider) == "" && nonXAIAvailable {
			return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
		}
		return errorEnvelope("egress_no_healthy_auth", "没有可用的健康 CPA 出口账号"), nil
	}
	index := schedulerCursor.Add(1) - 1
	selected := eligible[index%uint64(len(eligible))]
	return okEnvelope(pluginapi.SchedulerPickResponse{Handled: true, AuthID: selected})
}

func collectEligibleSchedulerAuths(req pluginapi.SchedulerPickRequest) (eligible []string, managed bool, nonXAIAvailable bool) {
	nodes := store.listNodes()
	byProxy := make(map[string][]*nodeRecord, len(nodes))
	for _, node := range nodes {
		if node.ProxyURL != "" {
			byProxy[node.ProxyURL] = append(byProxy[node.ProxyURL], node)
		}
	}
	cache := refreshAuthProxyCache()
	activeClash := activeClashNodeID(store)
	eligible = make([]string, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		if !isXAIProvider(candidate.Provider) {
			nonXAIAvailable = true
			continue
		}
		proxy := cache[candidate.ID]
		node := resolveSchedulerNode(proxy, byProxy, activeClash)
		if node == nil {
			continue
		}
		managed = true
		if !schedulerCandidateAvailable(candidate) {
			continue
		}
		if node.Enabled && !node.DisabledByGuard {
			eligible = append(eligible, candidate.ID)
		}
	}
	return eligible, managed, nonXAIAvailable
}

func resolveSchedulerNode(proxy string, byProxy map[string][]*nodeRecord, activeClash string) *nodeRecord {
	if proxy != "" {
		owners := byProxy[proxy]
		if len(owners) == 1 {
			return owners[0]
		}
		if len(owners) > 1 {
			for _, o := range owners {
				if o.ID == activeClash || (o.Source == nodeSourceClash && o.ClashActive) {
					// Prefer active leaf only when it is still schedulable.
					if o.Enabled && !o.DisabledByGuard {
						return o
					}
					break
				}
			}
			// Shared Clash proxy: pick any healthy clash leaf owner.
			for _, o := range owners {
				if o.Enabled && !o.DisabledByGuard {
					return o
				}
			}
			// Fall back to active (even if bad) so caller sees managed+empty eligible
			// and can trigger ensureHealthyClashExit recovery.
			for _, o := range owners {
				if o.ID == activeClash || (o.Source == nodeSourceClash && o.ClashActive) {
					return o
				}
			}
			return owners[0]
		}
	}
	if activeClash != "" {
		if n, ok := store.getNode(activeClash); ok {
			return n
		}
	}
	return nil
}

// handleRequestIntercept closes the race between auth selection and quarantine
// migration. Keyword isolation intentionally does NOT run here: operators want
// response-body matches (model/tool output), not request-body matches.
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
	if !ok || !node.DisabledByGuard {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}

	// Clash shared mixed-port: switch PerfectAI to a healthy leaf and let the
	// request continue on the same auth (proxy URL unchanged). Without this the
	// panel shows healthy nodes but live traffic still 503s on the dead exit.
	if node.Source == nodeSourceClash || activeClashNodeID(store) != "" {
		if switched, err := ensureHealthyClashExit(store); err == nil && switched {
			// Re-resolve: if attribution now lands on a healthy leaf, proceed.
			if nextID := resolveNodeIDForAuth(store, selected); nextID != "" {
				if next, ok := store.getNode(nextID); ok && next != nil && next.Enabled && !next.DisabledByGuard {
					return okEnvelope(pluginapi.RequestInterceptResponse{})
				}
			}
			// Even if attribution still points at the old leaf id, the real exit
			// has been switched; shared-proxy requests are safe to continue.
			if active := activeClashNodeID(store); active != "" {
				if n, ok := store.getNode(active); ok && n != nil && n.Enabled && !n.DisabledByGuard {
					return okEnvelope(pluginapi.RequestInterceptResponse{})
				}
			}
		}
	}

	// Non-Clash exclusive proxy: try migrating this auth off the dead node.
	if node.Source != nodeSourceClash && node.ProxyURL != "" {
		if err := migrateAuthsOffNode(store, node); err == nil {
			// Auth proxy may have changed; host already selected this auth for
			// this request, so still ask client to retry with Retry-After.
			return terminateQuarantinedRequest("egress_quarantined", "当前账号出口已迁移，请重试")
		}
	}
	return terminateQuarantinedRequest("egress_quarantined", "当前账号出口正在隔离迁移，请重试")
}

// handleResponseIntercept scans the completed non-stream response body for
// operator isolation keywords and quarantines the selected egress on hit.
func handleResponseIntercept(request []byte) ([]byte, error) {
	ensureStore()
	keywords := store.policy().IsolationKeywords
	if len(keywords) == 0 {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	var req pluginapi.ResponseInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode response interceptor request: %w", err)
	}
	if matched := matchIsolationKeyword(req.Body, keywords); matched != "" {
		quarantineFromMetadata(req.Metadata, matched)
	}
	// Never rewrite successful response content; isolation is a side effect only.
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

// handleStreamChunkIntercept scans stream chunks (and recent history) for
// isolation keywords. Streaming chat is the common path for Grok tool_use text.
func handleStreamChunkIntercept(request []byte) ([]byte, error) {
	ensureStore()
	keywords := store.policy().IsolationKeywords
	if len(keywords) == 0 {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	var req pluginapi.StreamChunkInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode stream chunk interceptor request: %w", err)
	}
	// Header-only init has no payload.
	if len(req.Body) == 0 && len(req.HistoryChunks) == 0 {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	// Prefer current chunk; fall back to a cheap join of recent history so a
	// keyword split across chunks can still be detected without full buffering.
	if matched := matchIsolationKeyword(req.Body, keywords); matched != "" {
		quarantineFromMetadata(req.Metadata, matched)
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	if len(req.HistoryChunks) > 0 {
		var b strings.Builder
		// Cap history scan.
		const maxHist = 64 << 10
		n := 0
		for i := len(req.HistoryChunks) - 1; i >= 0 && n < maxHist; i-- {
			chunk := req.HistoryChunks[i]
			if len(chunk) == 0 {
				continue
			}
			take := chunk
			if n+len(take) > maxHist {
				take = take[len(take)-(maxHist-n):]
			}
			// Prepend in reverse so we keep the most recent bytes.
			b.Write(take)
			n += len(take)
		}
		if matched := matchIsolationKeyword([]byte(b.String()), keywords); matched != "" {
			quarantineFromMetadata(req.Metadata, matched)
		}
	}
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

func quarantineFromMetadata(meta map[string]any, matched string) {
	if matched == "" || len(meta) == 0 {
		return
	}
	selected := firstString(meta, "selected_auth_id", "selectedAuthID", "auth_id", "authID")
	if selected == "" {
		return
	}
	nodeID := resolveNodeIDForAuth(store, selected)
	if nodeID == "" {
		return
	}
	node, ok := store.getNode(nodeID)
	if !ok || node == nil || node.DisabledByGuard {
		return
	}
	quarantineNode(store, nodeID, "响应关键词隔离: "+matched, 0, "keyword")
}

// matchIsolationKeyword returns the first configured keyword found as a
// case-sensitive substring of body. Empty keywords are ignored.
func matchIsolationKeyword(body []byte, keywords []string) string {
	if len(body) == 0 || len(keywords) == 0 {
		return ""
	}
	// Bound scan cost for oversized payloads.
	const maxScan = 256 << 10 // 256 KiB
	haystack := body
	if len(haystack) > maxScan {
		haystack = haystack[:maxScan]
	}
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		if strings.Contains(string(haystack), kw) {
			return kw
		}
	}
	return ""
}

func terminateQuarantinedRequest(errType, message string) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    errType,
			"message": message,
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


// forceSwitchAnyHealthyClash ignores the current active mark and switches
// production PerfectAI to any enabled non-quarantined Clash leaf.
func forceSwitchAnyHealthyClash(store *stateStore) error {
	if store == nil {
		return fmt.Errorf("store 未初始化")
	}
	var chosen *nodeRecord
	for _, n := range store.listNodes() {
		if n.Source != nodeSourceClash || n.ClashName == "" || !n.Enabled || n.DisabledByGuard {
			continue
		}
		chosen = n
		break
	}
	if chosen == nil {
		return fmt.Errorf("没有可切换的健康 Clash 节点")
	}
	if err := ensureClashSelectedForNode(store, chosen); err != nil {
		return err
	}
	store.appendEvent(guardEvent{
		Event:    "clash_switched",
		NodeID:   chosen.ID,
		NodeName: chosen.Name,
		Reason:   "调度无健康账号，强制切换生产组到 " + chosen.ClashName,
	})
	return nil
}

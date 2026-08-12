package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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

// handleSchedulerPick hands auth selection entirely back to the host.
//
// CPA only consults SessionAffinitySelector on the legacy path when the plugin
// responds Handled:false (conductor.pickNextLegacy: "if !handled { selector.Pick }").
// Any Handled:true answer — pinning AuthID or DelegateBuiltin — routes into
// pickViaBuiltinScheduler, a bare round-robin cursor that bypasses session
// affinity entirely and rotates auths on every request.
//
// Quarantined/disabled nodes are still defended: operator/auto disables write
// the auth file (CPA drops candidate.Disabled), node-window disables migrate
// accounts off the node, and handleRequestIntercept backs up the race between
// selection and quarantine.
func handleSchedulerPick(request []byte) ([]byte, error) {
	ensureStore()
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode scheduler request: %w", err)
	}
	if requestIncludesXAI(req.Provider, req.Providers) {
		recordRotation(rotationEvent{
			SessionID:  schedulerSessionID(req),
			Provider:   req.Provider,
			Model:      req.Model,
			Candidates: len(req.Candidates),
			Eligible:   len(req.Candidates),
			Delegated:  false,
		})
	}
	return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
}

// schedulerSessionID extracts the CPA session-affinity header, if any.
func schedulerSessionID(req pluginapi.SchedulerPickRequest) string {
	for _, key := range []string{"X-Session-ID", "X-Session-Id", "x-session-id"} {
		if vals := req.Options.Headers[key]; len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			return strings.TrimSpace(vals[0])
		}
	}
	return ""
}

// handleRequestIntercept closes the race between auth selection and quarantine
// migration.
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
	// Fallback only for non-schedulable exits: guard quarantine, operator
	// disable, and node-window cool-off. Healthy nodes pass through.
	if !ok || nodeSchedulable(node) {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}

	// Clash shared mixed-port: switch PerfectAI to a healthy leaf and let the
	// request continue on the same auth (proxy URL unchanged). Without this the
	// panel shows healthy nodes but live traffic still 503s on the dead exit.
	if node.Source == nodeSourceClash || activeClashNodeID(store) != "" {
		if switched, err := ensureHealthyClashExit(store); err == nil && switched {
			// Re-resolve: if attribution now lands on a healthy leaf, proceed.
			if nextID := resolveNodeIDForAuth(store, selected); nextID != "" {
				if next, ok := store.getNode(nextID); ok && next != nil && nodeSchedulable(next) {
					return okEnvelope(pluginapi.RequestInterceptResponse{})
				}
			}
			// Even if attribution still points at the old leaf id, the real exit
			// has been switched; shared-proxy requests are safe to continue.
			if active := activeClashNodeID(store); active != "" {
				if n, ok := store.getNode(active); ok && n != nil && nodeSchedulable(n) {
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func computeTPS(outputTokens, durationMs, firstTokenMs, minGenerationMs int64) float64 {
	if outputTokens <= 0 || durationMs <= 0 {
		return 0
	}
	denom := durationMs - firstTokenMs
	if minGenerationMs <= 0 {
		minGenerationMs = 1000
	}
	if denom < minGenerationMs {
		denom = durationMs
	}
	if denom < minGenerationMs {
		return 0
	}
	return float64(outputTokens) / (float64(denom) / 1000.0)
}

var (
	authProxyMu    sync.Mutex
	authProxyCache map[string]string
	authProxyAt    time.Time
)

func invalidateAuthProxyCache() {
	authProxyMu.Lock()
	authProxyAt = time.Time{}
	authProxyMu.Unlock()
}

func refreshAuthProxyCache() map[string]string {
	authProxyMu.Lock()
	defer authProxyMu.Unlock()
	if authProxyCache != nil && time.Since(authProxyAt) < 15*time.Second {
		return authProxyCache
	}
	out := map[string]string{}
	auths, err := listAuthFiles()
	if err == nil {
		for _, a := range auths {
			if a.ProxyURL == "" {
				continue
			}
			if a.Index != "" {
				out[a.Index] = a.ProxyURL
			}
			if a.ID != "" {
				out[a.ID] = a.ProxyURL
			}
			if a.Name != "" {
				out[a.Name] = a.ProxyURL
				out[strings.TrimSuffix(a.Name, ".json")] = a.ProxyURL
			}
			if a.Email != "" {
				out["xai-"+a.Email+".json"] = a.ProxyURL
				out[a.Email] = a.ProxyURL
			}
			if a.Path != "" {
				out[a.Path] = a.ProxyURL
				out[filepath.Base(a.Path)] = a.ProxyURL
			}
		}
	}
	authProxyCache = out
	authProxyAt = time.Now()
	return out
}

func resolveNodeIDForAuth(store *stateStore, authKeys ...string) string {
	cache := refreshAuthProxyCache()
	var proxy string
	for _, k := range authKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if p, ok := cache[k]; ok && p != "" {
			proxy = p
			break
		}
		if a, err := getAuthFile(k); err == nil && a.ProxyURL != "" {
			proxy = a.ProxyURL
			break
		}
	}
	if proxy == "" {
		// Clash mode: even without per-auth proxy, attribute to the active leaf.
		return activeClashNodeID(store)
	}
	matches := make([]*nodeRecord, 0)
	for _, n := range store.listNodes() {
		if n.ProxyURL == proxy {
			matches = append(matches, n)
		}
	}
	if len(matches) == 0 {
		return activeClashNodeID(store)
	}
	if len(matches) == 1 {
		return matches[0].ID
	}
	// Shared mixed-port (Clash): multiple nodes share one proxy_url. Attribute
	// passive usage to the currently selected PerfectAI leaf.
	for _, n := range matches {
		if n.Source == nodeSourceClash && n.ClashActive && nodeSchedulable(n) {
			return n.ID
		}
	}
	for _, n := range matches {
		if n.Source == nodeSourceClash && n.ClashActive {
			return n.ID
		}
	}
	for _, n := range matches {
		if nodeSchedulable(n) {
			return n.ID
		}
	}
	return matches[0].ID
}

func activeClashNodeID(store *stateStore) string {
	if store == nil {
		return ""
	}
	for _, n := range store.listNodes() {
		if n.Source == nodeSourceClash && n.ClashActive && nodeSchedulable(n) {
			return n.ID
		}
	}
	for _, n := range store.listNodes() {
		if n.Source == nodeSourceClash && n.ClashActive {
			return n.ID
		}
	}
	return ""
}

// thinkingFieldNonEmpty reports whether a delta/message field carries real
// thinking/reasoning text. Empty strings and whitespace-only values do not count.
func thinkingFieldNonEmpty(v any) bool {
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) != ""
}

// mapHasThinkingContent inspects OpenAI-compatible delta/message maps for the
// thinking markers used by Grok/xAI streams (thinking_content / reasoning_content).
func mapHasThinkingContent(m map[string]any) bool {
	if m == nil {
		return false
	}
	for _, key := range []string{
		"thinking_content", "ThinkingContent", "thinkingContent",
		"reasoning_content", "ReasoningContent", "reasoningContent",
		"thinking", "Thinking",
	} {
		if thinkingFieldNonEmpty(m[key]) {
			return true
		}
	}
	return false
}

// recordHasThinking derives a thinking signal from a CPA usage event.
// Prefer explicit thinking/reasoning body fields; fall back to reasoning_tokens > 0
// because passive usage rarely includes full response text.
func recordHasThinking(record map[string]any) bool {
	if record == nil {
		return false
	}
	if mapHasThinkingContent(record) {
		return true
	}
	for _, nestKey := range []string{"Detail", "detail", "Message", "message", "Response", "response", "Delta", "delta"} {
		if nested, ok := record[nestKey].(map[string]any); ok && mapHasThinkingContent(nested) {
			return true
		}
	}
	for _, key := range []string{"has_thinking", "HasThinking", "hasThinking", "has_reasoning", "HasReasoning"} {
		switch v := record[key].(type) {
		case bool:
			if v {
				return true
			}
		case string:
			if strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1" {
				return true
			}
		}
	}
	if firstInt(record, "reasoning_tokens", "ReasoningTokens", "reasoningTokens") > 0 {
		return true
	}
	for _, nestKey := range []string{"Detail", "detail", "Usage", "usage"} {
		if nested, ok := record[nestKey].(map[string]any); ok {
			if firstInt(nested, "reasoning_tokens", "ReasoningTokens", "reasoningTokens") > 0 {
				return true
			}
		}
	}
	return false
}

// classifyQuality classifies a successful generation sample. Thinking is the
// ONLY quality signal: missing thinking is hard 降智, present thinking healthy.
func classifyQuality(tps float64, outputTokens int64, hasThinking bool, pol policyConfig) string {
	if outputTokens <= 0 || tps <= 0 {
		return "unknown"
	}
	if pol.MinOutputTokens > 0 && outputTokens < pol.MinOutputTokens {
		return "ignored"
	}
	if !hasThinking {
		return "hard"
	}
	return "healthy"
}

func classifyFailureKind(status int, body string) string {
	lower := strings.ToLower(body)
	if status == http.StatusProxyAuthRequired {
		return "transport_error"
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusConflict || status == http.StatusUnprocessableEntity || status == http.StatusTooManyRequests {
		return "account_error"
	}
	for _, marker := range []string{"invalid token", "expired", "no auth", "quota", "rate limit", "ratelimit", "too many requests", "permission denied", "forbidden"} {
		if strings.Contains(lower, marker) {
			return "account_error"
		}
	}
	for _, marker := range []string{"connection refused", "connection reset", "dial tcp", "timeout", "timed out", "eof", "tls handshake", "no such host", "proxyconnect", "proxy authentication"} {
		if strings.Contains(lower, marker) {
			return "transport_error"
		}
	}
	if status >= 500 && status <= 599 {
		return "upstream_error"
	}
	return "request_error"
}

func maxInt64(values ...int64) int64 {
	var result int64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func outputTokensFromUsage(usage map[string]any) int64 {
	if usage == nil {
		return 0
	}
	return maxInt64(
		anyInt(usage["completion_tokens"]),
		anyInt(usage["output_tokens"]),
		anyInt(usage["CompletionTokens"]),
		anyInt(usage["OutputTokens"]),
		anyInt(usage["completionTokens"]),
		anyInt(usage["outputTokens"]),
		anyInt(usage["reasoning_tokens"]),
		anyInt(usage["ReasoningTokens"]),
		anyInt(usage["reasoningTokens"]),
	)
}


type qualityResult struct {
	Classification  string  `json:"classification"`
	TPS             float64 `json:"tps"`
	OutputTokens    int64   `json:"output_tokens"`
	DurationMs      int64   `json:"duration_ms"`
	FirstTokenMs    int64   `json:"first_token_ms"`
	ExitIP          string  `json:"exit_ip,omitempty"`
	Error           string  `json:"error,omitempty"`
	ErrorKind       string  `json:"error_kind,omitempty"`
	Model           string  `json:"model,omitempty"`
	HasThinking     bool    `json:"has_thinking,omitempty"`
	ReasoningTokens int64   `json:"reasoning_tokens,omitempty"`
	AuthID          string  `json:"auth_id,omitempty"`
	AuthLabel       string  `json:"auth_label,omitempty"`
}


const missingThinkingReason = "探测响应缺少 thinking（疑似降智）"

// quarantineSeconds is the fixed isolation duration for one 降智 (missing
// thinking). It used to be a policy knob; thinking 是唯一判断标准，一次即隔离，
// 到期由 guard worker 自动恢复，无需再配置。
const quarantineSeconds = 120

// isNodeTransportHard reports probe failures that mean the exit is flaky/unreachable,
// not that the model/account lost thinking. These still isolate the node, but must
// never be attributed to per-account 降智 stats (otherwise TLS/EOF inflates 降智率).
func isNodeTransportHard(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "probe_unstable", "probe_timeout", "transport_error":
		return true
	default:
		return false
	}
}


// deltaHasThinking reports whether a streamed delta/message carries any
// thinking / reasoning signal. Downgraded nodes answer without these fields.
func deltaHasThinking(delta map[string]any) bool {
	if delta == nil {
		return false
	}
	for _, key := range []string{
		"reasoning_content", "reasoningContent",
		"thinking", "thinking_content", "thinkingContent",
		"reasoning", "reasoning_text", "reasoningText",
	} {
		switch v := delta[key].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return true
			}
		case map[string]any:
			if deltaHasThinking(v) {
				return true
			}
		}
	}
	// Nested details used by some OpenAI-compatible gateways.
	for _, key := range []string{"reasoning_details", "reasoningDetails"} {
		if nested, ok := delta[key].(map[string]any); ok && deltaHasThinking(nested) {
			return true
		}
	}
	// Anthropic-style content blocks: [{type:"thinking", thinking:"..."}]
	if blocks, ok := delta["content"].([]any); ok {
		for _, raw := range blocks {
			block, _ := raw.(map[string]any)
			if block == nil {
				continue
			}
			typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(block["type"])))
			if typ == "thinking" || typ == "reasoning" || typ == "reasoning_content" {
				return true
			}
			for _, key := range []string{"thinking", "reasoning", "text", "reasoning_content"} {
				if s, ok := block[key].(string); ok && strings.TrimSpace(s) != "" && (typ == "thinking" || typ == "reasoning" || key != "text") {
					if typ == "thinking" || typ == "reasoning" || key == "thinking" || key == "reasoning" || key == "reasoning_content" {
						return true
					}
				}
			}
		}
	}
	return false
}

func usageReasoningTokens(u map[string]any) int64 {
	if u == nil {
		return 0
	}
	total := maxInt64(
		anyInt(u["reasoning_tokens"]),
		anyInt(u["reasoningTokens"]),
		anyInt(u["ReasoningTokens"]),
	)
	for _, key := range []string{
		"completion_tokens_details", "completionTokensDetails",
		"output_tokens_details", "outputTokensDetails",
	} {
		if details, ok := u[key].(map[string]any); ok {
			total = maxInt64(total,
				anyInt(details["reasoning_tokens"]),
				anyInt(details["reasoningTokens"]),
				anyInt(details["ReasoningTokens"]),
			)
		}
	}
	return total
}

func chunkDebugSummary(chunk map[string]any) string {
	if chunk == nil {
		return "{}"
	}
	keys := make([]string, 0, len(chunk))
	for k := range chunk {
		keys = append(keys, k)
	}
	summary := "keys=" + strings.Join(keys, ",")
	if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
		if cm, ok := choices[0].(map[string]any); ok {
			if delta, ok := cm["delta"].(map[string]any); ok {
				dk := make([]string, 0, len(delta))
				for k, v := range delta {
					switch t := v.(type) {
					case string:
						dk = append(dk, fmt.Sprintf("%s(str:%d)", k, len(t)))
					default:
						dk = append(dk, fmt.Sprintf("%s(%T)", k, v))
					}
				}
				summary += " delta=[" + strings.Join(dk, ",") + "]"
			}
			if msg, ok := cm["message"].(map[string]any); ok {
				mk := make([]string, 0, len(msg))
				for k := range msg {
					mk = append(mk, k)
				}
				summary += " message=[" + strings.Join(mk, ",") + "]"
			}
		}
	}
	if u, ok := chunk["usage"].(map[string]any); ok {
		summary += fmt.Sprintf(" usage(reason=%d out=%d)", usageReasoningTokens(u), outputTokensFromUsage(u))
	}
	return summary
}

func rotationAllowed(cfg pluginConfig, nodeID string) bool {
	if strings.TrimSpace(cfg.RotationURL) == "" || strings.TrimSpace(nodeID) == "" {
		return false
	}
	for _, allowed := range cfg.RotatableNodeIDs {
		if strings.TrimSpace(allowed) == nodeID {
			return true
		}
	}
	return false
}

func rotateNodeIfConfigured(store *stateStore, node *nodeRecord) (bool, error) {
	if node == nil {
		return false, nil
	}
	value := currentConfig.Load()
	if value == nil {
		return false, nil
	}
	cfg, ok := value.(pluginConfig)
	if !ok || !rotationAllowed(cfg, node.ID) {
		return false, nil
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.RotationURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return false, fmt.Errorf("换 IP Webhook URL 无效")
	}
	payload, _ := json.Marshal(map[string]any{"nodeId": node.ID, "oldExitIp": node.ExitIP})
	req, err := http.NewRequest(http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if envName := strings.TrimSpace(cfg.RotationTokenEnv); envName != "" {
		if token := strings.TrimSpace(os.Getenv(envName)); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	timeout := time.Duration(cfg.RotationTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("换 IP 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("换 IP 返回 HTTP %d", resp.StatusCode)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, fmt.Errorf("换 IP 响应无效")
	}
	newIP := firstString(result, "newExitIp", "new_exit_ip", "exitIp", "exit_ip")
	if newIP == "" || (node.ExitIP != "" && newIP == node.ExitIP) {
		return false, fmt.Errorf("换 IP 未确认出口变化")
	}
	updated, err := store.updateNode(node.ID, func(n *nodeRecord) error {
		n.ExitIP = newIP
		n.LastReason = "已换 IP，等待真实模型复测"
		return nil
	})
	if err != nil || updated == nil {
		return false, fmt.Errorf("保存换 IP 状态失败")
	}
	store.appendEvent(guardEvent{Event: "node_rotated", NodeID: node.ID, NodeName: node.Name, Reason: "Webhook 已确认出口 IP 变化"})
	return true, nil
}



func anyInt(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		i, _ := t.Int64()
		return i
	default:
		return 0
	}
}

// maybeAutoDisableNode permanently stops a leaf after repeated quarantine cycles.
// Unlike quarantine, this sets DisabledByOperator so recovery probes and scheduling
// stay off across restarts until an operator re-enables the node.
func maybeAutoDisableNode(store *stateStore, nodeID, reason string) {
	if store == nil || strings.TrimSpace(nodeID) == "" {
		return
	}
	pol := store.policy()
	if !pol.NodeAutoDisable {
		return
	}
	threshold := pol.NodeAutoDisableMinQuarantines
	if threshold <= 0 {
		threshold = 3
	}
	n, ok := store.getNode(nodeID)
	if !ok || n == nil || n.DisabledByOperator {
		return
	}
	if n.QuarantineCount < int64(threshold) {
		return
	}
	why := fmt.Sprintf("持续降智自动停用：累计隔离 %d 次（阈值 %d）", n.QuarantineCount, threshold)
	if rs := strings.TrimSpace(reason); rs != "" {
		why = why + " · " + rs
		if len(why) > 240 {
			why = why[:240]
		}
	}
	updated, err := store.updateNode(nodeID, func(node *nodeRecord) error {
		if node.DisabledByOperator {
			return nil
		}
		if node.QuarantineCount < int64(threshold) {
			return nil
		}
		applyOperatorEnabledLocked(node, false, "auto", why)
		// Keep guard mark so UI still shows last isolation context, but clear the
		// recovery timer — 停用 nodes must not re-enter the quality queue.
		node.DisabledByGuard = true
		node.QuarantinedUntil = 0
		return nil
	})
	if err != nil || updated == nil || !updated.DisabledByOperator {
		return
	}
	store.appendEvent(guardEvent{
		Event:          "node_auto_disabled",
		NodeID:         updated.ID,
		NodeName:       updated.Name,
		Reason:         why,
		Classification: "hard",
	})
	log.Printf("egress-guard: node auto-disable id=%s name=%q quarantine_count=%d threshold=%d",
		updated.ID, updated.Name, updated.QuarantineCount, threshold)
	// If this leaf is currently selected in Clash, switch production away.
	if updated.Source == nodeSourceClash {
		if err := switchClashAwayFromNode(store, updated); err != nil {
			store.appendEvent(guardEvent{Event: "clash_switch_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
		}
	}
}

// maybeAutoDisableAuth disables a host auth when per-account degrade evidence
// crosses the configured multi-node full-rate threshold.
func maybeAutoDisableAuth(store *stateStore, authID, label string) {
	authID = strings.TrimSpace(authID)
	if store == nil || authID == "" || authID == "probe-api" {
		return
	}
	pol := store.policy()
	if !pol.AuthAutoDisable {
		return
	}
	rec := store.getAuthDegradeRecord(authID)
	if !shouldAutoDisableAuth(rec, pol) {
		return
	}
	nodes := distinctDegradedNodes(rec)
	reason := fmt.Sprintf("降智 %d/%d (100%%) · 跨 %d 节点", rec.DegradedCount, rec.SampleCount, nodes)
	a, err := disableAuthByID(authID, "auto", reason)
	if err != nil {
		log.Printf("egress-guard: auth auto-disable failed id=%s err=%v", authID, err)
		store.appendEvent(guardEvent{Event: "auth_auto_disable_failed", AuthID: authID, Reason: err.Error()})
		return
	}
	fullReason := authDisableReason(a)
	if fullReason == "" {
		fullReason = "egress-guard account-auto: " + reason
	}
	store.markAuthDisabled(authID, "auto", fullReason)
	if label == "" {
		label = firstNonEmpty(a.Email, a.Name, authID)
	}
	log.Printf("egress-guard: auth auto-disable id=%s label=%s hits=%d/%d nodes=%d", authID, label, rec.DegradedCount, rec.SampleCount, nodes)
	store.appendEvent(guardEvent{Event: "auth_auto_disabled", AuthID: authID, Reason: fullReason, Classification: "hard"})
}

func applyObservation(store *stateStore, nodeID, source string, res qualityResult) {
	pol := store.policy()
	if res.Classification == "error" && res.ErrorKind != "transport_error" {
		res.Classification = "ignored"
	}
	now := float64(time.Now().Unix())
	var (
		doRestore     bool
		doQuarantine  bool
		quarantineWhy string
		nodeCopy      nodeRecord
	)
	updated, err := store.updateNode(nodeID, func(n *nodeRecord) error {
		n.LastClassification = res.Classification
		n.LastOutputTPS = res.TPS
		n.LastFirstTokenMs = res.FirstTokenMs
		n.LastDurationMs = res.DurationMs
		n.LastOutputTokens = res.OutputTokens
		n.LastSource = source
		n.LastObservedAt = now
		if res.ExitIP != "" {
			n.ExitIP = res.ExitIP
		}
		if res.Error != "" {
			n.LastReason = res.Error
		} else if res.Classification == "healthy" {
			n.LastReason = ""
		}
		switch res.Classification {
		case "healthy":
			n.ErrorStrikes = 0
			n.ThinkingStrikes = 0
			// Restore only when the observation actually carried thinking.
			if n.DisabledByGuard && !n.DisabledByOperator && res.HasThinking {
				markNodeRestored(n, now)
				n.DisabledByGuard = false
				n.QuarantinedUntil = 0
				doRestore = true
			} else if n.DisabledByOperator {
				// Operator/auto permanent stop: never auto-restore into the schedule.
				n.Enabled = false
				n.QuarantinedUntil = 0
				if n.DisabledReason != "" {
					n.LastReason = n.DisabledReason
				}
			}
			// Credit real healthy usage (not idle selected wall-clock).
			if !n.DisabledByGuard {
				recordHealthyObservation(n, res.DurationMs)
			}
		case "hard":
			// Thinking is the only hard signal: one missing-thinking 降智 immediately
			// isolates the exit IP and bans the account (see account branch below).
			n.ThinkingStrikes++
			if strings.TrimSpace(res.Error) != "" {
				quarantineWhy = res.Error
			} else {
				quarantineWhy = missingThinkingReason
			}
			recordDegradedObservation(n)
			// Always re-enter quarantine path. quarantineNodeOpts handles both the
			// first isolation and already-isolated failed recovery cycles (count +
			// auto-disable). Do NOT only refresh the timer here — that made continuous
			// 降智 nodes loop recovery forever with quarantine_count stuck at 1.
			doQuarantine = true
		case "error":
			n.ThinkingStrikes = 0
			n.ErrorStrikes++
			// Transport/node-side errors count as degraded observations.
			recordDegradedObservation(n)
			if n.ErrorStrikes >= pol.ConsecutiveErrors {
				doQuarantine = true
				quarantineWhy = "连续传输错误: " + res.Error
			}
		}
		nodeCopy = *n
		return nil
	})
	if err != nil || updated == nil {
		store.bumpStat(source, res.Classification, res.OutputTokens)
		return
	}
	// Per-account 降智 stats:
	// - sample: real generation outcomes (healthy/hard quality), not errors/ignored
	// - degraded: this observation itself is a quality-degrade hit for THIS auth
	// Passive missing-thinking immediately counts as degrade for the audited account
	// and immediately bans it (AuthAutoDisable on) — no cross-node threshold needed.
	// Node transport flakiness (TLS/EOF/timeout) still isolates the node, but is
	// NOT an account 降智 sample — otherwise 断流 inflates account degrade rate.
	if res.AuthID != "" && res.Classification != "error" && res.Classification != "ignored" && res.Classification != "unknown" &&
		!isNodeTransportHard(res.ErrorKind) {
		degraded := res.Classification == "hard"
		reason := res.Error
		if degraded && reason == "" {
			reason = missingThinkingReason
		}
		store.recordAuthObservation(res.AuthID, res.AuthLabel, source, nodeCopy.ID, nodeCopy.Name, res.Classification, reason, res.TPS, degraded)
		if degraded {
			// 缺 thinking 立即禁用账号（阈值即时触发，见 shouldAutoDisableAuth）。
			maybeAutoDisableAuth(store, res.AuthID, res.AuthLabel)
		}
	}
	if res.Classification == "ignored" {
		store.bumpStat(source, "ignored", res.OutputTokens)
		return
	}
	if doRestore {
		store.bumpAction("restored")
		store.appendEvent(guardEvent{Event: "node_restored", NodeID: nodeCopy.ID, NodeName: nodeCopy.Name, Classification: "healthy", OutputTPS: res.TPS})
		go func(nn nodeRecord) { _ = enableAuthsOnNode(&nn) }(nodeCopy)
	}
	if doQuarantine {
		quarantineNode(store, nodeCopy.ID, quarantineWhy, res.TPS, res.Classification)
	}
	store.bumpStat(source, res.Classification, res.OutputTokens)
}

func quarantineNode(store *stateStore, nodeID, reason string, tps float64, class string) {
	_, _ = quarantineNodeOpts(store, nodeID, reason, tps, class, false)
}

// quarantineNodeOpts isolates a node. When force is true (manual panel
// "降智隔离"), MinHealthyNodes suppression is bypassed so operators can always
// mark a degraded exit even if it is the last healthy one.
func quarantineNodeOpts(store *stateStore, nodeID, reason string, tps float64, class string, force bool) (*nodeRecord, error) {
	if store == nil {
		return nil, fmt.Errorf("store 未初始化")
	}
	pol := store.policy()
	enabledHealthy := 0
	var target *nodeRecord
	for _, o := range store.listNodes() {
		if o.ID == nodeID {
			target = o
			continue
		}
		if o.Enabled && !o.DisabledByGuard {
			enabledHealthy++
		}
	}
	if target == nil {
		return nil, fmt.Errorf("节点不存在")
	}
	if target.DisabledByGuard {
		// Already quarantined — refresh reason/countdown, and count this as another
		// continuous-degrade cycle. Recovery hard retests used to only refresh the
		// timer, so quarantine_count stayed at 1 and NodeAutoDisable never fired.
		// Keep original LastQuarantinedAt so continuous quarantine wall-clock stays accurate.
		updated, err := store.updateNode(nodeID, func(n *nodeRecord) error {
			n.DisabledByGuard = true
			n.QuarantinedUntil = float64(time.Now().Add(quarantineSeconds * time.Second).Unix())
			n.LastReason = reason
			if class != "" {
				n.LastClassification = class
			}
			if n.LastQuarantinedAt <= 0 {
				markNodeQuarantined(n, float64(time.Now().Unix()))
			} else {
				// Same isolation stint: do not reset LastQuarantinedAt, but bump the
				// cycle counter so repeated failed recoveries reach auto-disable.
				n.QuarantineCount++
			}
			return nil
		})
		if err != nil || updated == nil {
			if err == nil {
				err = fmt.Errorf("隔离续期失败")
			}
			return nil, err
		}
		store.appendEvent(guardEvent{
			Event:          "node_quarantine_extended",
			NodeID:         updated.ID,
			NodeName:       updated.Name,
			Reason:         reason,
			Classification: class,
			OutputTPS:      tps,
		})
		// Continuous 降智 while still isolated: same auto-stop path as a fresh quarantine.
		maybeAutoDisableNode(store, updated.ID, reason)
		if latest, ok := store.getNode(updated.ID); ok && latest != nil {
			updated = latest
		}
		// If auto-disable did not fire and this Clash leaf somehow became selected,
		// push production off it again.
		if updated.Source == nodeSourceClash && updated.Enabled && !updated.DisabledByOperator {
			if err := switchClashAwayFromNode(store, updated); err != nil {
				store.appendEvent(guardEvent{Event: "clash_switch_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
			}
		}
		return updated, nil
	}
	if !force && enabledHealthy < pol.MinHealthyNodes {
		store.bumpAction("suppressed")
		store.appendEvent(guardEvent{Event: "quarantine_suppressed", NodeID: target.ID, NodeName: target.Name, Reason: "低于最低健康节点数", OutputTPS: tps})
		updated, err := store.updateNode(nodeID, func(n *nodeRecord) error {
			n.LastReason = "隔离已抑制: " + reason
			return nil
		})
		if err != nil {
			return nil, err
		}
		return updated, fmt.Errorf("隔离已抑制：健康节点数低于下限 %d", pol.MinHealthyNodes)
	}
	updated, err := store.updateNode(nodeID, func(n *nodeRecord) error {
		nowUnix := float64(time.Now().Unix())
		markNodeQuarantined(n, nowUnix)
		n.DisabledByGuard = true
		n.QuarantinedUntil = float64(time.Now().Add(quarantineSeconds * time.Second).Unix())
		n.LastReason = reason
		if class != "" {
			n.LastClassification = class
		}
		return nil
	})
	if err != nil || updated == nil {
		if err == nil {
			err = fmt.Errorf("隔离失败")
		}
		return nil, err
	}
	store.bumpAction("quarantined")
	store.appendEvent(guardEvent{Event: "node_quarantined", NodeID: updated.ID, NodeName: updated.Name, Reason: reason, Classification: class, OutputTPS: tps})
	// Continuous 降智: permanently stop the leaf after N quarantine cycles so recovery
	// probes stop burning traffic. Operator must re-enable explicitly.
	maybeAutoDisableNode(store, updated.ID, reason)
	// Clash-sourced nodes share one mixed-port URL. The real recovery action is
	// switching 🏜️ PerfectAI (or configured group) to another healthy leaf.
	if updated.Source == nodeSourceClash {
		if err := switchClashAwayFromNode(store, updated); err != nil {
			store.appendEvent(guardEvent{Event: "clash_switch_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
		}
	} else if err := migrateAuthsOffNode(store, updated); err != nil {
		store.appendEvent(guardEvent{Event: "accounts_migration_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
	}
	if _, err := rotateNodeIfConfigured(store, updated); err != nil {
		store.appendEvent(guardEvent{Event: "node_rotation_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
	}
	return updated, nil
}

// disableNodeForWindow ends the 24h account-window cool-off aftermath: push
// production off the node and clear its bound accounts from scheduling so host
// candidates never include a marked exit. Recovery is time-based, not probe-based.
func disableNodeForWindow(store *stateStore, nodeID, reason string) {
	if store == nil || nodeID == "" {
		return
	}
	n, ok := store.getNode(nodeID)
	if !ok || n == nil || !n.DisabledByNodeWindow {
		return
	}
	store.appendEvent(guardEvent{
		Event:    "node_window_disabled",
		NodeID:   n.ID,
		NodeName: n.Name,
		Reason:   reason,
	})
	if n.Source == nodeSourceClash {
		if err := switchClashAwayFromNode(store, n); err != nil {
			store.appendEvent(guardEvent{Event: "clash_switch_failed", NodeID: n.ID, NodeName: n.Name, Reason: err.Error()})
		}
	} else if err := migrateAuthsOffNode(store, n); err != nil {
		store.appendEvent(guardEvent{Event: "accounts_migration_failed", NodeID: n.ID, NodeName: n.Name, Reason: err.Error()})
	}
}

// manualQuarantineNode is the panel "降智隔离" action: always force-isolate.
func manualQuarantineNode(store *stateStore, nodeID, reason string) (*nodeRecord, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "人工降智隔离"
	}
	if len(reason) > 240 {
		reason = reason[:240]
	}
	return quarantineNodeOpts(store, nodeID, reason, 0, "manual", true)
}

// restoreQuarantinedNode clears guard isolation so the node can be scheduled again.
func restoreQuarantinedNode(store *stateStore, nodeID string) (*nodeRecord, error) {
	if store == nil {
		return nil, fmt.Errorf("store 未初始化")
	}
	n, ok := store.getNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	if !n.DisabledByGuard && !n.DisabledByOperator {
		return n, nil
	}
	updated, err := store.updateNode(nodeID, func(node *nodeRecord) error {
		markNodeRestored(node, float64(time.Now().Unix()))
		node.DisabledByGuard = false
		node.QuarantinedUntil = 0
		node.ErrorStrikes = 0
		node.ThinkingStrikes = 0
		// Panel "恢复" also clears durable stop so a quarantined+auto-disabled leaf
		// can re-enter the pool without a separate 启用 click.
		applyOperatorEnabledLocked(node, true, "", "")
		node.LastReason = "人工恢复"
		node.LastClassification = "healthy"
		return nil
	})
	if err != nil || updated == nil {
		if err == nil {
			err = fmt.Errorf("恢复失败")
		}
		return nil, err
	}
	store.bumpAction("restored")
	store.appendEvent(guardEvent{
		Event:          "node_restored",
		NodeID:         updated.ID,
		NodeName:       updated.Name,
		Reason:         "人工恢复",
		Classification: "healthy",
	})
	go func(nn nodeRecord) { _ = enableAuthsOnNode(&nn) }(*updated)
	return updated, nil
}

func handlePassiveUsage(store *stateStore, record map[string]any) {
	pol := store.policy()
	provider := strings.ToLower(firstString(record, "Provider", "provider"))
	if provider != "" && !strings.Contains(provider, "xai") && !strings.Contains(provider, "grok") {
		return
	}
	authID := firstString(record, "AuthID", "auth_id", "authId", "AuthIndex", "auth_index")
	authIndex := firstString(record, "AuthIndex", "auth_index")
	failed := false
	if v, ok := record["Failed"]; ok {
		failed, _ = v.(bool)
	}
	if v, ok := record["failed"]; ok {
		failed, _ = v.(bool)
	}

	var outTokens, durMs, ttftMs int64
	if detail, ok := record["Detail"].(map[string]any); ok {
		outTokens = outputTokensFromUsage(detail)
	}
	if detail, ok := record["detail"].(map[string]any); ok {
		if outTokens == 0 {
			outTokens = outputTokensFromUsage(detail)
		}
	}
	if outTokens == 0 {
		outTokens = maxInt64(firstInt(record, "output_tokens", "OutputTokens", "completion_tokens", "completionTokens"), firstInt(record, "reasoning_tokens", "ReasoningTokens"))
	}
	durMs = firstInt(record, "duration_ms", "DurationMs", "latency_ms")
	if durMs == 0 {
		if lat, ok := record["Latency"].(float64); ok {
			if lat > 1e6 {
				durMs = int64(lat / 1e6)
			} else {
				durMs = int64(lat)
			}
		}
		if lat, ok := record["latency"].(float64); ok && durMs == 0 {
			if lat > 1e6 {
				durMs = int64(lat / 1e6)
			} else {
				durMs = int64(lat)
			}
		}
	}
	ttftMs = firstInt(record, "first_token_ms", "FirstTokenMs", "ttft_ms")
	if ttftMs == 0 {
		if t, ok := record["TTFT"].(float64); ok {
			if t > 1e6 {
				ttftMs = int64(t / 1e6)
			} else {
				ttftMs = int64(t)
			}
		}
	}

	class := "unknown"
	tps := 0.0
	errorKind := ""
	hasThinking := false
	if failed {
		failure, _ := record["Failure"].(map[string]any)
		if failure == nil {
			failure, _ = record["failure"].(map[string]any)
		}
		status := int(firstInt(failure, "StatusCode", "status_code", "status"))
		body := firstString(failure, "Body", "body", "message", "error")
		errorKind = classifyFailureKind(status, body)
		if errorKind == "transport_error" {
			class = "error"
		} else {
			class = "ignored"
		}
	} else {
		tps = computeTPS(outTokens, durMs, ttftMs, pol.MinGenerationMs)
		hasThinking = recordHasThinking(record)
		class = classifyQuality(tps, outTokens, hasThinking, pol)
	}

	if class == "hard" {
		invalidateAuthProxyCache()
	}
	nodeID := resolveNodeIDForAuth(store, authID, authIndex,
		filepath.Base(authID), strings.TrimSuffix(filepath.Base(authID), ".json"))
	authKey := firstNonEmpty(authID, authIndex)
	res := qualityResult{
		Classification: class,
		TPS:            tps,
		OutputTokens:   outTokens,
		DurationMs:     durMs,
		FirstTokenMs:   ttftMs,
		HasThinking:    hasThinking,
		ErrorKind:      errorKind,
		AuthID:         authKey,
		AuthLabel:      authKey,
	}
	if class == "hard" && !failed && !hasThinking {
		res.Error = missingThinkingReason
		res.ErrorKind = "missing_thinking"
	}
	// Account-window cool-off: real requests (never probes or failures) count
	// distinct auths per egress. At the threshold the node is isolated for 24h
	// so a shared exit cannot mark more accounts.
	if nodeID != "" && class != "error" && class != "ignored" && !failed && authKey != "" && authKey != "probe-api" {
		if store.recordNodeAuthUsage(nodeID, authKey) {
			if n, ok := store.getNode(nodeID); ok && n != nil {
				disableNodeForWindow(store, nodeID, n.NodeWindowReason)
			}
		}
	}
	if nodeID == "" {
		store.bumpStat("passive", class, outTokens)
		if class == "hard" {
			store.appendEvent(guardEvent{
				Event:          "unmapped_hard",
				AuthID:         authKey,
				Classification: class,
				OutputTPS:      tps,
				Reason:         fmt.Sprintf("usage 未映射到出口节点 auth=%s idx=%s tokens=%d dur=%dms ttft=%dms", authID, authIndex, outTokens, durMs, ttftMs),
			})
		}
		// Unmapped egress: still attribute account samples.
		if authKey != "" && class != "error" && class != "ignored" && class != "unknown" {
			degraded := false
			reason := res.Error
			if class == "hard" && !failed {
				degraded = true
				if reason == "" {
					reason = missingThinkingReason
				}
			}
			store.recordAuthObservation(authKey, authKey, "passive", "", "", class, reason, tps, degraded)
		}
		return
	}
	applyObservation(store, nodeID, "passive", res)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func startGuardWorker(ctx context.Context, store *stateStore) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := float64(time.Now().Unix())
				for _, n := range store.listNodes() {
					// Account-window cool-off expiry: time-based restore, never
					// probe-based, so a marked exit needs no traffic to come back.
					if n.DisabledByNodeWindow && n.NodeWindowUntil > 0 && now >= n.NodeWindowUntil {
						if store.clearNodeWindow(n.ID) {
							store.appendEvent(guardEvent{
								Event:    "node_window_restored",
								NodeID:   n.ID,
								NodeName: n.Name,
								Reason:   "账号窗口冷却到期，自动恢复",
							})
						}
						continue
					}
					// Guard quarantine expiry: time-based restore. Isolated leaves
					// re-enter the pool without any recovery probe traffic.
					if n.DisabledByGuard && n.QuarantinedUntil > 0 && now >= n.QuarantinedUntil {
						store.updateNode(n.ID, func(node *nodeRecord) error {
							markNodeRestored(node, now)
							node.DisabledByGuard = false
							node.QuarantinedUntil = 0
							node.ErrorStrikes = 0
							node.ThinkingStrikes = 0
							node.LastReason = "隔离到期自动恢复"
							node.LastClassification = "healthy"
							return nil
						})
						store.appendEvent(guardEvent{
							Event:          "node_restored",
							NodeID:         n.ID,
							NodeName:       n.Name,
							Reason:         "隔离到期自动恢复",
							Classification: "healthy",
						})
						continue
					}
				}
			}
		}
	}()
}

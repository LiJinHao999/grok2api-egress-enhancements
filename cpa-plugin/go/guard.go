package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
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
		if n.Source == nodeSourceClash && n.ClashActive && !n.DisabledByGuard {
			return n.ID
		}
	}
	for _, n := range matches {
		if n.Source == nodeSourceClash && n.ClashActive {
			return n.ID
		}
	}
	for _, n := range matches {
		if n.Enabled && !n.DisabledByGuard {
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
		if n.Source == nodeSourceClash && n.ClashActive && n.Enabled && !n.DisabledByGuard {
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

func classifyTPS(tps float64, soft, hard float64) string {
	if tps <= 0 {
		return "unknown"
	}
	if tps >= hard {
		return "hard"
	}
	if tps >= soft {
		return "soft"
	}
	return "healthy"
}

func classifyQuality(tps float64, outputTokens int64, pol policyConfig) string {
	if outputTokens <= 0 || tps <= 0 {
		return "unknown"
	}
	if pol.MinOutputTokens > 0 && outputTokens < pol.MinOutputTokens {
		return "ignored"
	}
	return classifyTPS(tps, pol.SoftTPS, pol.HardTPS)
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

func httpClientThroughProxy(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if strings.TrimSpace(proxyURL) != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("代理 URL 无效")
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func probeConnectivity(proxyURL string) (exitIP string, latencyMs int64, err error) {
	client, err := httpClientThroughProxy(proxyURL, 20*time.Second)
	if err != nil {
		return "", 0, err
	}
	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, "https://api.ipify.org", nil)
	req.Header.Set("User-Agent", "CPA-egress-guard/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Since(start).Milliseconds(), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	ip := strings.TrimSpace(string(body))
	if resp.StatusCode >= 400 || ip == "" {
		return "", time.Since(start).Milliseconds(), fmt.Errorf("连通性失败 HTTP %d", resp.StatusCode)
	}
	return ip, time.Since(start).Milliseconds(), nil
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
}

// qualityProbePrompt is intentionally a short common-sense question that still
// elicits a thinking/reasoning block on healthy Grok exits. Downgraded exits
// typically answer without any thinking block.
const qualityProbePrompt = "我要去洗车，但洗车店离我家只有5m,我应该走路去还是开车去？请思考后直接给出答案"

const missingThinkingReason = "探测响应缺少 thinking（疑似降智）"
const probeTimeoutReason = "探测超时（按降智处理）"
const probeUnstableReason = "不一定降智，但节点断流不稳定，标记为降智，暂不使用"

func isProbeTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client.timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "i/o timeout") ||
		(strings.Contains(msg, "timeout") && strings.Contains(msg, "waiting for"))
}

// Transport flakiness that often means the exit is unusable even if not "dumb".
func isProbeUnstableErr(err error) bool {
	if err == nil {
		return false
	}
	if isProbeTimeoutErr(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	markers := []string{
		"unexpected eof", "eof", "connection reset", "connection refused",
		"broken pipe", "stream error", "http2: stream", "server closed idle connection",
		"tls:", "tls handshake", "use of closed network connection",
	}
	for _, m := range markers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func probeAPIConfigured(pol policyConfig) bool {
	return strings.TrimSpace(pol.ProbeAPIBase) != "" && strings.TrimSpace(pol.ProbeAPIKey) != ""
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

func applyGrokClientHeaders(req *http.Request, auth authFile) {
	req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	req.Header.Set("x-grok-client-version", "0.2.93")
	req.Header.Set("x-grok-client-identifier", "grok-shell")
	req.Header.Set("User-Agent", "CPA-egress-guard/1.0")
	if headers, ok := auth.Raw["headers"].(map[string]any); ok {
		for k, v := range headers {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				req.Header.Set(k, s)
			}
		}
	}
	if req.Header.Get("X-XAI-Token-Auth") == "" {
		req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	}
	if req.Header.Get("x-grok-client-version") == "" {
		req.Header.Set("x-grok-client-version", "0.2.93")
	}
	if req.Header.Get("x-grok-client-identifier") == "" {
		req.Header.Set("x-grok-client-identifier", "grok-shell")
	}
}

func isAuthExpired(auth authFile) bool {
	exp, _ := auth.Raw["expired"].(string)
	if exp == "" {
		return false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, exp); err == nil {
			return time.Now().After(t.Add(-2 * time.Minute))
		}
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z07:00", exp); err == nil {
		return time.Now().After(t.Add(-2 * time.Minute))
	}
	return false
}

func isAuthErrorRetryable(status int, body string) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "invalid or expired") ||
		strings.Contains(lower, "no auth context") ||
		strings.Contains(lower, "permissiondenied") ||
		strings.Contains(lower, "x_xai_token_auth=none")
}

// free-usage / quota exhaustion is an account problem, never a node degradation.
// Always try another CPA xAI account before giving up the probe.
func isAccountQuotaExhausted(status int, body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "free-usage-exhausted") ||
		strings.Contains(lower, "free_usage_exhausted") ||
		strings.Contains(lower, "subscription:free-usage") ||
		strings.Contains(lower, "included free usage") {
		return true
	}
	if status == http.StatusTooManyRequests && (strings.Contains(lower, "quota") || strings.Contains(lower, "usage") || strings.Contains(lower, "rate")) {
		return true
	}
	return strings.Contains(lower, "quota") && strings.Contains(lower, "exhaust")
}

func shouldRetryProbeWithNextAuth(status int, body, kind string, hasMore bool) bool {
	if !hasMore {
		return false
	}
	if isAccountQuotaExhausted(status, body) {
		return true
	}
	return kind == "account_error" || isAuthErrorRetryable(status, body)
}

const qualityProbeTimeout = 75 * time.Second

func probeQuality(store *stateStore, node *nodeRecord) qualityResult {
	return probeQualityContext(context.Background(), store, node)
}

func probeQualityContext(ctx context.Context, store *stateStore, node *nodeRecord) qualityResult {
	if ctx == nil {
		ctx = context.Background()
	}
	pol := store.policy()
	res := qualityResult{Model: pol.Model}
	if node == nil || node.ProxyURL == "" {
		res.Classification = "error"
		res.ErrorKind = "request_error"
		res.Error = "节点缺少代理"
		return res
	}

	if ip, _, errIP := probeConnectivity(node.ProxyURL); errIP == nil {
		res.ExitIP = ip
	} else {
		log.Printf("egress-guard: quality connectivity warn node=%s err=%v", node.ID, errIP)
	}

	usePublicAPI := probeAPIConfigured(pol)
	var candidates []authFile
	var err error
	if usePublicAPI {
		// Public gateway records free-usage cooling itself; one synthetic auth slot.
		candidates = []authFile{{Name: "probe-api", Raw: map[string]any{"access_token": pol.ProbeAPIKey, "base_url": pol.ProbeAPIBase}}}
	} else {
		// Prefer several accounts so free-usage-exhausted can rotate. Timeout /
		// missing-thinking / unstable EOF still return as node verdicts.
		candidates, err = listAuthsForNode(node, 5)
		if err != nil || len(candidates) == 0 {
			res.Classification = "error"
			res.ErrorKind = "no_account"
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Error = "没有可用的 CPA xAI 账号"
			}
			return res
		}
	}

	client, err := httpClientThroughProxy(node.ProxyURL, qualityProbeTimeout)
	if err != nil {
		res.Classification = "error"
		res.ErrorKind = "transport_error"
		res.Error = err.Error()
		return res
	}

	maxTok := pol.MaxOutputTokensProbe
	if maxTok <= 0 {
		maxTok = 256
	}
	payload := map[string]any{
		"model": pol.Model,
		"messages": []map[string]string{
			{"role": "user", "content": qualityProbePrompt},
		},
		"stream":      true,
		"max_tokens":  maxTok,
		"temperature": 0.7,
	}
	body, _ := json.Marshal(payload)
	mode := "cli-chat-proxy"
	if usePublicAPI {
		mode = "public-api"
	}
	log.Printf("egress-guard: quality probe begin node=%s name=%q model=%s mode=%s base=%s candidates=%d max_tokens=%d",
		node.ID, node.Name, pol.Model, mode, pol.ProbeAPIBase, len(candidates), maxTok)

	var lastErr string
	for i, auth := range candidates {
		if err := ctx.Err(); err != nil {
			res.Classification = "error"
			res.ErrorKind = "transport_error"
			res.Error = "探测已取消: " + err.Error()
			return res
		}
		token, _ := auth.Raw["access_token"].(string)
		if strings.TrimSpace(token) == "" {
			lastErr = "账号缺少 access_token"
			continue
		}
		if !usePublicAPI && isAuthExpired(auth) && i+1 < len(candidates) {
			continue
		}
		baseURL, _ := auth.Raw["base_url"].(string)
		if usePublicAPI {
			baseURL = pol.ProbeAPIBase
		} else if baseURL == "" {
			baseURL = "https://cli-chat-proxy.grok.com/v1"
		}
		baseURL = strings.TrimRight(baseURL, "/")
		authLabel := firstNonEmpty(auth.Email, auth.Name, auth.ID, auth.Index)
		if usePublicAPI {
			authLabel = "probe-api"
		}

		req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
		if errReq != nil {
			res.Classification = "error"
			res.ErrorKind = "request_error"
			res.Error = "无法创建探测请求"
			return res
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		if !usePublicAPI {
			applyGrokClientHeaders(req, auth)
		} else {
			req.Header.Set("User-Agent", "CPA-egress-guard/1.1")
		}

		start := time.Now()
		log.Printf("egress-guard: quality request node=%s auth=%s mode=%s url=%s/chat/completions", node.ID, authLabel, mode, baseURL)
		resp, errDo := client.Do(req)
		if errDo != nil {
			res.DurationMs = time.Since(start).Milliseconds()
			log.Printf("egress-guard: quality request failed node=%s auth=%s dur=%dms err=%v", node.ID, authLabel, res.DurationMs, errDo)
			if isProbeTimeoutErr(errDo) || isProbeTimeoutErr(ctx.Err()) {
				res.Classification = "hard"
				res.ErrorKind = "probe_timeout"
				res.Error = probeTimeoutReason
				res.HasThinking = false
				log.Printf("egress-guard: quality TIMEOUT -> hard node=%s auth=%s dur=%dms", node.ID, authLabel, res.DurationMs)
				return res
			}
			if isProbeUnstableErr(errDo) {
				res.Classification = "hard"
				res.ErrorKind = "probe_unstable"
				res.Error = probeUnstableReason + " (" + truncate(errDo.Error(), 80) + ")"
				res.HasThinking = false
				log.Printf("egress-guard: quality UNSTABLE EOF/reset -> hard node=%s auth=%s err=%v", node.ID, authLabel, errDo)
				return res
			}
			lastErr = "模型探测请求失败: " + truncate(errDo.Error(), 160)
			res.ErrorKind = "transport_error"
			continue
		}

		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			msg := fmt.Sprintf("上游 HTTP %d: %s", resp.StatusCode, truncate(string(b), 160))
			lastErr = msg
			res.ErrorKind = classifyFailureKind(resp.StatusCode, string(b))
			res.DurationMs = time.Since(start).Milliseconds()
			bodyText := string(b)
			log.Printf("egress-guard: quality upstream error node=%s auth=%s status=%d kind=%s body=%q", node.ID, authLabel, resp.StatusCode, res.ErrorKind, truncate(bodyText, 200))
			hasMore := i+1 < len(candidates)
			if shouldRetryProbeWithNextAuth(resp.StatusCode, bodyText, res.ErrorKind, hasMore) {
				if isAccountQuotaExhausted(resp.StatusCode, bodyText) {
					log.Printf("egress-guard: quality free-usage exhausted -> retry next auth node=%s auth=%s remain=%d", node.ID, authLabel, len(candidates)-i-1)
				}
				continue
			}
			// Quota exhausted on the last candidate is still an account problem: ignored, not node hard.
			if isAccountQuotaExhausted(resp.StatusCode, bodyText) {
				res.Classification = "ignored"
				res.ErrorKind = "account_quota"
				res.Error = "账号 free 额度耗尽，已无更多可切换账号: " + truncate(bodyText, 120)
				log.Printf("egress-guard: quality free-usage exhausted, no more auths node=%s", node.ID)
				return res
			}
			res.Classification = "error"
			res.Error = msg
			return res
		}

		var (
			firstTokenAt   time.Time
			contentLen     int
			reasoningLen   int
			usageOut       int64
			usageReason    int64
			hasThinking    bool
			chunkCount     int
			sampleLogged   int
			lastChunkDebug string
		)
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				_ = resp.Body.Close()
				res.Classification = "error"
				res.ErrorKind = "transport_error"
				res.Error = "探测已取消: " + err.Error()
				res.DurationMs = time.Since(start).Milliseconds()
				return res
			}
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "" || data == "[DONE]" {
				if data == "[DONE]" {
					break
				}
				continue
			}
			var chunk map[string]any
			if json.Unmarshal([]byte(data), &chunk) != nil {
				continue
			}
			chunkCount++
			if sampleLogged < 4 {
				lastChunkDebug = chunkDebugSummary(chunk)
				log.Printf("egress-guard: quality chunk sample node=%s auth=%s n=%d %s raw=%q",
					node.ID, authLabel, chunkCount, lastChunkDebug, truncate(data, 240))
				sampleLogged++
			}
			if u, ok := chunk["usage"].(map[string]any); ok {
				usageOut = maxInt64(usageOut, outputTokensFromUsage(u))
				usageReason = maxInt64(usageReason, usageReasoningTokens(u))
				if usageReason > 0 {
					hasThinking = true
				}
			}
			choices, _ := chunk["choices"].([]any)
			for _, c := range choices {
				cm, _ := c.(map[string]any)
				if cm == nil {
					continue
				}
				if msg, ok := cm["message"].(map[string]any); ok {
					if deltaHasThinking(msg) {
						hasThinking = true
					}
				}
				delta, _ := cm["delta"].(map[string]any)
				if delta == nil {
					continue
				}
				if deltaHasThinking(delta) {
					hasThinking = true
					if firstTokenAt.IsZero() {
						firstTokenAt = time.Now()
					}
					for _, key := range []string{"reasoning_content", "reasoningContent", "thinking", "thinking_content", "reasoning"} {
						if t, ok := delta[key].(string); ok && t != "" {
							reasoningLen += len([]rune(t))
							contentLen += len([]rune(t))
						}
					}
				}
				if t, ok := delta["content"].(string); ok && t != "" {
					if firstTokenAt.IsZero() {
						firstTokenAt = time.Now()
					}
					contentLen += len([]rune(t))
				}
			}
		}
		_ = resp.Body.Close()
		if scanErr := scanner.Err(); scanErr != nil {
			res.DurationMs = time.Since(start).Milliseconds()
			log.Printf("egress-guard: quality stream read failed node=%s auth=%s err=%v", node.ID, authLabel, scanErr)
			if isProbeTimeoutErr(scanErr) || isProbeTimeoutErr(ctx.Err()) {
				res.Classification = "hard"
				res.ErrorKind = "probe_timeout"
				res.Error = probeTimeoutReason
				res.HasThinking = false
				log.Printf("egress-guard: quality stream TIMEOUT -> hard node=%s auth=%s dur=%dms", node.ID, authLabel, res.DurationMs)
				return res
			}
			if isProbeUnstableErr(scanErr) {
				res.Classification = "hard"
				res.ErrorKind = "probe_unstable"
				res.Error = probeUnstableReason + " (" + truncate(scanErr.Error(), 80) + ")"
				res.HasThinking = false
				log.Printf("egress-guard: quality stream UNSTABLE -> hard node=%s auth=%s err=%v", node.ID, authLabel, scanErr)
				return res
			}
			lastErr = "模型探测流读取失败: " + truncate(scanErr.Error(), 160)
			res.ErrorKind = "transport_error"
			continue
		}
		if err := ctx.Err(); isProbeTimeoutErr(err) {
			res.DurationMs = time.Since(start).Milliseconds()
			res.Classification = "hard"
			res.ErrorKind = "probe_timeout"
			res.Error = probeTimeoutReason
			res.HasThinking = false
			log.Printf("egress-guard: quality ctx TIMEOUT -> hard node=%s auth=%s dur=%dms", node.ID, authLabel, res.DurationMs)
			return res
		}

		duration := time.Since(start)
		res.DurationMs = duration.Milliseconds()
		if !firstTokenAt.IsZero() {
			res.FirstTokenMs = firstTokenAt.Sub(start).Milliseconds()
		}
		outTokens := usageOut
		if usageReason > outTokens {
			outTokens = usageReason
		}
		if outTokens <= 0 {
			outTokens = int64(contentLen / 4)
			if outTokens == 0 && contentLen > 0 {
				outTokens = 1
			}
		}
		res.OutputTokens = outTokens
		res.ReasoningTokens = usageReason
		res.HasThinking = hasThinking || usageReason > 0 || reasoningLen > 0
		res.TPS = computeTPS(outTokens, res.DurationMs, res.FirstTokenMs, pol.MinGenerationMs)
		// Thinking probe verdict first. MinOutputTokens only applies to TPS soft/hard,
		// not to "has thinking => healthy" for this short car-wash prompt.
		if !res.HasThinking {
			res.Classification = "hard"
			res.Error = missingThinkingReason
			res.ErrorKind = "missing_thinking"
			log.Printf("egress-guard: quality MISSING thinking node=%s auth=%s class=hard chunks=%d out_tokens=%d sample=%s",
				node.ID, authLabel, chunkCount, outTokens, lastChunkDebug)
			return res
		}
		if outTokens == 0 {
			lastErr = "探测无输出"
			res.ErrorKind = "no_output"
			res.Classification = "error"
			log.Printf("egress-guard: quality no output node=%s auth=%s", node.ID, authLabel)
			continue
		}
		// Has thinking: node is not degraded. Keep TPS class only for diagnostics;
		// never ignore a successful thinking probe as "too few tokens".
		tpsClass := classifyQuality(res.TPS, outTokens, pol)
		if tpsClass == "ignored" || tpsClass == "unknown" || tpsClass == "" {
			res.Classification = "healthy"
		} else if tpsClass == "soft" || tpsClass == "hard" {
			// Still has thinking, so do not isolate on TPS alone from active probe.
			res.Classification = "healthy"
			log.Printf("egress-guard: quality thinking present, TPS class=%s ignored for isolation node=%s tps=%.1f", tpsClass, node.ID, res.TPS)
		} else {
			res.Classification = tpsClass
		}
		log.Printf("egress-guard: quality stream done node=%s auth=%s chunks=%d thinking=true reason_tokens=%d reason_chars=%d content_chars=%d out_tokens=%d tps=%.1f class=%s dur=%dms sample=%s",
			node.ID, authLabel, chunkCount, usageReason, reasoningLen, contentLen, outTokens, res.TPS, res.Classification, res.DurationMs, lastChunkDebug)
		res.Error = ""
		res.ErrorKind = ""
		return res
	}

	res.Classification = "error"
	if res.ErrorKind == "" {
		res.ErrorKind = "transport_error"
	}
	if lastErr == "" {
		lastErr = "所有候选账号探测失败"
	}
	res.Error = lastErr
	return res
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

func applyObservation(store *stateStore, nodeID, source string, res qualityResult) {
	pol := store.policy()
	if res.Classification == "error" && res.ErrorKind != "transport_error" {
		res.Classification = "ignored"
	}
	now := float64(time.Now().Unix())
	var (
		doRestore     bool
		doQuarantine  bool
		queueThinking bool
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
		if source == "active" {
			n.LastProbeAt = now
		}
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
			n.SoftStrikes = 0
			n.ErrorStrikes = 0
			// Restore only when the probe actually saw thinking. A "healthy" TPS
			// without thinking is rewritten to hard in probeQuality.
			if n.DisabledByGuard && res.HasThinking && (source == "active" || pol.Mode == "passive") {
				markNodeRestored(n, now)
				n.DisabledByGuard = false
				n.QuarantinedUntil = 0
				doRestore = true
			}
			// Credit real healthy usage (not idle selected wall-clock).
			if !n.DisabledByGuard {
				recordHealthyObservation(n, res.DurationMs)
			}
		case "soft":
			// Soft TPS is only a suspicion. Do NOT isolate on soft alone.
			// Queue a thinking probe; only missing thinking becomes hard isolation.
			n.SoftStrikes++
			if n.DisabledByGuard {
				n.LastReason = fmt.Sprintf("软阈值 Token/s=%.1f · 已隔离，等待 thinking 复测", res.TPS)
			} else {
				n.LastReason = fmt.Sprintf("软阈值 Token/s=%.1f · 排队 thinking 复测确认", res.TPS)
				queueThinking = true
				// Soft still means the exit produced a usable response; count as
				// non-degraded observation until hard/thinking confirms otherwise.
				recordHealthyObservation(n, res.DurationMs)
			}
		case "hard":
			if strings.TrimSpace(res.Error) != "" {
				quarantineWhy = res.Error
			} else if res.ErrorKind == "probe_timeout" {
				quarantineWhy = probeTimeoutReason
			} else if res.ErrorKind == "probe_unstable" {
				quarantineWhy = probeUnstableReason
			} else if res.ErrorKind == "missing_thinking" || !res.HasThinking {
				quarantineWhy = missingThinkingReason
			} else {
				quarantineWhy = fmt.Sprintf("硬阈值 Token/s=%.1f", res.TPS)
			}
			recordDegradedObservation(n)
			if !n.DisabledByGuard {
				doQuarantine = true
			} else {
				// Already isolated: refresh countdown + reason so recovery retests
				// keep the operator-visible thinking verdict.
				n.QuarantinedUntil = float64(time.Now().Add(time.Duration(pol.QuarantineSec) * time.Second).Unix())
				n.LastReason = quarantineWhy
				n.LastClassification = "hard"
			}
		case "error":
			n.ErrorStrikes++
			// Transport/node-side errors count as degraded observations.
			recordDegradedObservation(n)
			if n.ErrorStrikes >= pol.ConsecutiveErrors && !n.DisabledByGuard {
				doQuarantine = true
				quarantineWhy = "连续探测错误: " + res.Error
			}
		}
		nodeCopy = *n
		return nil
	})
	if err != nil || updated == nil {
		store.bumpStat(source, res.Classification, res.OutputTokens)
		return
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
	if queueThinking {
		store.appendEvent(guardEvent{
			Event:          "thinking_recheck_queued",
			NodeID:         nodeCopy.ID,
			NodeName:       nodeCopy.Name,
			Classification: "soft",
			OutputTPS:      res.TPS,
			Reason:         fmt.Sprintf("软阈值 Token/s=%.1f，排队 thinking 复测；无 thinking 才隔离", res.TPS),
		})
		log.Printf("egress-guard: soft TPS -> queue thinking recheck node=%s name=%q tps=%.1f source=%s",
			nodeCopy.ID, nodeCopy.Name, res.TPS, source)
		_, _ = queueNodeQuality(store, nodeCopy.ID, "soft-recheck", false)
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
		// Already quarantined — refresh reason / countdown for manual re-mark.
		// Keep original LastQuarantinedAt so continuous quarantine duration is accurate.
		updated, err := store.updateNode(nodeID, func(n *nodeRecord) error {
			n.QuarantinedUntil = float64(time.Now().Add(time.Duration(pol.QuarantineSec) * time.Second).Unix())
			n.LastReason = reason
			if class != "" {
				n.LastClassification = class
			}
			if n.LastQuarantinedAt <= 0 {
				markNodeQuarantined(n, float64(time.Now().Unix()))
			}
			return nil
		})
		if err != nil {
			return nil, err
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
		n.QuarantinedUntil = float64(time.Now().Add(time.Duration(pol.QuarantineSec) * time.Second).Unix())
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
	// Clash-sourced nodes share one mixed-port URL. The real recovery action is
	// switching 🏜️ PerfectAI (or configured group) to another healthy leaf.
	if updated.Source == nodeSourceClash {
		if err := switchClashAwayFromNode(store, updated); err != nil {
			store.appendEvent(guardEvent{Event: "clash_switch_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
			if pol.DisableAuthOnHard {
				_ = disableAuthsOnNode(store, updated, "egress-guard 降智隔离: "+reason)
			}
		}
	} else if err := migrateAuthsOffNode(store, updated); err != nil {
		store.appendEvent(guardEvent{Event: "accounts_migration_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
		if pol.DisableAuthOnHard {
			_ = disableAuthsOnNode(store, updated, "egress-guard 降智隔离: "+reason)
		}
	}
	if rotated, err := rotateNodeIfConfigured(store, updated); err != nil {
		store.appendEvent(guardEvent{Event: "node_rotation_failed", NodeID: updated.ID, NodeName: updated.Name, Reason: err.Error()})
	} else if rotated {
		_, _ = queueNodeQuality(store, updated.ID, "rotate", false)
	}
	return updated, nil
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
	if !n.DisabledByGuard {
		return n, nil
	}
	updated, err := store.updateNode(nodeID, func(node *nodeRecord) error {
		markNodeRestored(node, float64(time.Now().Unix()))
		node.DisabledByGuard = false
		node.QuarantinedUntil = 0
		node.SoftStrikes = 0
		node.ErrorStrikes = 0
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

func runNodeConnectivity(store *stateStore, id string) (map[string]any, error) {
	n, ok := store.getNode(id)
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	ip, ms, err := probeConnectivity(n.ProxyURL)
	status := "ok"
	if err != nil {
		status = "error"
	}
	_, _ = store.updateNode(id, func(node *nodeRecord) error {
		node.ProbeStatus = status
		node.ProbeLatencyMs = ms
		node.LastProbeAt = float64(time.Now().Unix())
		if ip != "" {
			node.ExitIP = ip
		}
		if err != nil {
			node.LastReason = err.Error()
		}
		return nil
	})
	out := map[string]any{"id": id, "status": status, "exitIp": ip, "latencyMs": ms}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

// executeNodeQuality runs one real-model quality probe. Callers that may race
// Clash group selection must go through queueNodeQuality instead.
func executeNodeQuality(store *stateStore, id, source string) (map[string]any, error) {
	if strings.TrimSpace(source) == "" {
		source = "manual"
	}
	// Observation source controls restore/strike bookkeeping. Recovery/rotate/
	// manual/active probes all need the same "active" accounting so LastProbeAt
	// advances and thinking-based hard hits apply.
	obsSource := "active"

	n, ok := store.getNode(id)
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	log.Printf("egress-guard: quality start source=%s node=%s name=%q clash=%v leaf=%q quarantined=%v",
		source, id, n.Name, n.Source == nodeSourceClash, n.ClashName, n.DisabledByGuard)

	// Quality probes always go internal cli-chat-proxy with CPA xAI tokens, via
	// TestPort + :7953 so production PerfectAI/:7890 is undisturbed.
	// (Optional public probe_api_* remains supported if operator sets it later.)
	probeNode := *n
	testGroup := ""
	pol := store.policy()
	usePublic := probeAPIConfigured(pol)
	if usePublic {
		// Explicit public API only: dial direct, no clash proxy.
		probeNode.ProxyURL = ""
		log.Printf("egress-guard: quality public-api direct dial base=%s node=%s", pol.ProbeAPIBase, id)
	} else {
		if n.Source == nodeSourceClash && n.ClashName != "" {
			g, err := ensureClashSelectedForQuality(store, n)
			testGroup = g
			if err != nil {
				log.Printf("egress-guard: quality test-group switch failed node=%s leaf=%q group=%q err=%v", id, n.ClashName, g, err)
				return nil, fmt.Errorf("切换测试策略组失败: %w", err)
			}
			log.Printf("egress-guard: quality test-group switch ok node=%s leaf=%q group=%q", id, n.ClashName, g)
		}
		if proxy := qualityProbeProxyURL(n); proxy != "" {
			probeNode.ProxyURL = proxy
			log.Printf("egress-guard: quality dial proxy=%s (test path / cli-chat-proxy) node=%s", redactProxyURL(proxy), id)
		}
	}

	// Hard deadline so one hung upstream stream cannot freeze the whole queue.
	probeCtx, cancel := context.WithTimeout(context.Background(), qualityProbeTimeout+15*time.Second)
	defer cancel()
	res := probeQualityContext(probeCtx, store, &probeNode)
	if res.Classification == "error" && res.ErrorKind != "transport_error" {
		res.Classification = "ignored"
	}

	reason := strings.TrimSpace(res.Error)
	if reason == "" {
		if res.HasThinking {
			reason = fmt.Sprintf("thinking=有 · class=%s · tps=%.1f · tokens=%d · reason_tokens=%d · dur=%dms · source=%s",
				res.Classification, res.TPS, res.OutputTokens, res.ReasoningTokens, res.DurationMs, source)
		} else {
			reason = fmt.Sprintf("thinking=无 · class=%s · tps=%.1f · tokens=%d · dur=%dms · source=%s",
				res.Classification, res.TPS, res.OutputTokens, res.DurationMs, source)
		}
	} else if !strings.Contains(strings.ToLower(reason), "thinking") {
		think := "无"
		if res.HasThinking {
			think = "有"
		}
		reason = fmt.Sprintf("%s · thinking=%s · class=%s · source=%s", reason, think, res.Classification, source)
	}

	applyObservation(store, id, obsSource, res)
	store.appendEvent(guardEvent{
		Event:          "quality_probe_completed",
		NodeID:         id,
		NodeName:       n.Name,
		Classification: res.Classification,
		OutputTPS:      res.TPS,
		Reason:         reason,
	})
	log.Printf("egress-guard: quality done source=%s node=%s name=%q class=%s thinking=%v reason_tokens=%d tps=%.1f tokens=%d dur=%dms kind=%s err=%q",
		source, id, n.Name, res.Classification, res.HasThinking, res.ReasoningTokens, res.TPS, res.OutputTokens, res.DurationMs, res.ErrorKind, res.Error)

	out := map[string]any{
		"id":              id,
		"classification":  res.Classification,
		"tps":             res.TPS,
		"outputTokens":    res.OutputTokens,
		"durationMs":      res.DurationMs,
		"firstTokenMs":    res.FirstTokenMs,
		"exitIp":          res.ExitIP,
		"error":           res.Error,
		"errorKind":       res.ErrorKind,
		"model":           res.Model,
		"hasThinking":     res.HasThinking,
		"reasoningTokens": res.ReasoningTokens,
		"source":          source,
		"reason":          reason,
		"testGroup":       testGroup,
		"testProxy":       redactProxyURL(probeNode.ProxyURL),
	}
	return out, nil
}

// runNodeQuality is the panel/API entry: enqueue and wait for the serial slot.
func runNodeQuality(store *stateStore, id string) (map[string]any, error) {
	return queueNodeQuality(store, id, "manual", true)
}

type qualityOutcome struct {
	data map[string]any
	err  error
}

type qualityJob struct {
	id         int64
	nodeID     string
	nodeName   string
	source     string
	enqueuedAt time.Time
	startedAt  time.Time
	waiters    []chan qualityOutcome
}

// qualityScheduler serializes all real-model probes. Clash PerfectAI can only
// point at one leaf at a time; concurrent quality tests would cross-wire exits.
//
// The worker loop is process-lifetime: CPA reconfigure fires many times at
// startup and must NOT tear down / respawn the queue worker, or jobs freeze
// mid-flight and multiple workers race Clash selection.
type qualityScheduler struct {
	mu      sync.Mutex
	cond    *sync.Cond
	nextID  int64
	active  *qualityJob
	pending []*qualityJob
	started bool
	stop    context.CancelFunc
}

var qualitySched = func() *qualityScheduler {
	s := &qualityScheduler{}
	s.cond = sync.NewCond(&s.mu)
	return s
}()

func qualitySourceLabel(source string) string {
	switch source {
	case "manual":
		return "手动"
	case "active":
		return "主动"
	case "recovery":
		return "隔离复测"
	case "rotate":
		return "换 IP 复测"
	case "soft-recheck":
		return "软阈值复测"
	default:
		if source == "" {
			return "检测"
		}
		return source
	}
}

func (s *qualityScheduler) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := make([]map[string]any, 0, len(s.pending))
	for i, job := range s.pending {
		if job == nil {
			continue
		}
		pending = append(pending, map[string]any{
			"position":     i + 1,
			"node_id":      job.nodeID,
			"node_name":    job.nodeName,
			"source":       job.source,
			"source_label": qualitySourceLabel(job.source),
			"enqueued_at":  float64(job.enqueuedAt.Unix()),
		})
	}
	out := map[string]any{
		"pending":       pending,
		"pending_count": len(pending),
		"total":         len(pending),
		"busy":          s.active != nil || len(pending) > 0,
	}
	if s.active != nil {
		out["active"] = map[string]any{
			"position":     0,
			"node_id":      s.active.nodeID,
			"node_name":    s.active.nodeName,
			"source":       s.active.source,
			"source_label": qualitySourceLabel(s.active.source),
			"enqueued_at":  float64(s.active.enqueuedAt.Unix()),
			"started_at":   float64(s.active.startedAt.Unix()),
		}
		out["total"] = len(pending) + 1
	}
	return out
}

func (s *qualityScheduler) findLocked(nodeID string) *qualityJob {
	if s.active != nil && s.active.nodeID == nodeID {
		return s.active
	}
	for _, job := range s.pending {
		if job != nil && job.nodeID == nodeID {
			return job
		}
	}
	return nil
}

// queueNodeQuality enqueues a quality probe. When wait is true the caller blocks
// until this node's job finishes (attaching to an in-flight/pending job if any).
// When wait is false, duplicate node IDs are deduped and the call returns immediately.
func queueNodeQuality(store *stateStore, nodeID, source string, wait bool) (map[string]any, error) {
	if store == nil {
		return nil, fmt.Errorf("store 未初始化")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, fmt.Errorf("节点 ID 为空")
	}
	n, ok := store.getNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	if strings.TrimSpace(source) == "" {
		source = "manual"
	}

	s := qualitySched
	s.mu.Lock()
	if existing := s.findLocked(nodeID); existing != nil {
		if !wait {
			s.mu.Unlock()
			return map[string]any{
				"id":      nodeID,
				"queued":  true,
				"deduped": true,
				"status":  "already_queued",
			}, nil
		}
		ch := make(chan qualityOutcome, 1)
		existing.waiters = append(existing.waiters, ch)
		s.mu.Unlock()
		out := <-ch
		return out.data, out.err
	}

	s.nextID++
	job := &qualityJob{
		id:         s.nextID,
		nodeID:     nodeID,
		nodeName:   n.Name,
		source:     source,
		enqueuedAt: time.Now(),
	}
	var ch chan qualityOutcome
	if wait {
		ch = make(chan qualityOutcome, 1)
		job.waiters = []chan qualityOutcome{ch}
	}
	s.pending = append(s.pending, job)
	s.cond.Signal()
	s.mu.Unlock()

	if !wait {
		return map[string]any{
			"id":     nodeID,
			"queued": true,
			"status": "queued",
		}, nil
	}
	out := <-ch
	return out.data, out.err
}

func startQualityWorker(_ context.Context, _ *stateStore) {
	s := qualitySched
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	s.stop = lifeCancel
	s.started = true
	s.mu.Unlock()

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("egress-guard: quality worker panic: %v\n%s", rec, debug.Stack())
			}
			s.mu.Lock()
			s.started = false
			active := s.active
			s.active = nil
			pendingLeft := len(s.pending)
			s.stop = nil
			s.mu.Unlock()
			if active != nil {
				for _, w := range active.waiters {
					w <- qualityOutcome{err: fmt.Errorf("质量检测 worker 异常退出")}
				}
			}
			// Only auto-restart on unexpected panic while the plugin is still up.
			// Explicit stopQualityWorker cancels lifeCtx and must not respawn.
			if lifeCtx.Err() == nil && pendingLeft > 0 {
				log.Printf("egress-guard: quality worker restarting after panic pending=%d", pendingLeft)
				startQualityWorker(context.Background(), nil)
			}
		}()

		log.Printf("egress-guard: quality worker started (process lifetime)")
		for {
			s.mu.Lock()
			for len(s.pending) == 0 && lifeCtx.Err() == nil {
				s.cond.Wait()
			}
			if lifeCtx.Err() != nil {
				// Plugin shutdown: fail waiters, keep pending list for diagnostics.
				leftover := append([]*qualityJob{}, s.pending...)
				if s.active != nil {
					leftover = append(leftover, s.active)
				}
				s.pending = nil
				s.active = nil
				s.mu.Unlock()
				for _, job := range leftover {
					for _, w := range job.waiters {
						w <- qualityOutcome{err: fmt.Errorf("质量检测队列已停止")}
					}
				}
				log.Printf("egress-guard: quality worker stopped")
				return
			}
			job := s.pending[0]
			s.pending = s.pending[1:]
			job.startedAt = time.Now()
			s.active = job
			pendingAfter := len(s.pending)
			s.mu.Unlock()

			// Always use the live global store — reconfigure swaps it under us.
			live := store
			log.Printf("egress-guard: quality dequeue source=%s node=%s name=%q pending_left=%d",
				job.source, job.nodeID, job.nodeName, pendingAfter)

			var (
				data map[string]any
				err  error
			)
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						err = fmt.Errorf("质量检测 panic: %v", rec)
						log.Printf("egress-guard: quality job panic source=%s node=%s: %v\n%s",
							job.source, job.nodeID, rec, debug.Stack())
					}
				}()
				if live == nil {
					err = fmt.Errorf("store 未初始化")
					return
				}
				data, err = executeNodeQuality(live, job.nodeID, job.source)
			}()

			s.mu.Lock()
			if s.active == job {
				s.active = nil
			}
			waiters := job.waiters
			job.waiters = nil
			nextPending := len(s.pending)
			s.mu.Unlock()
			if err != nil {
				log.Printf("egress-guard: quality finish ERR source=%s node=%s name=%q err=%v pending_left=%d",
					job.source, job.nodeID, job.nodeName, err, nextPending)
			} else {
				class, _ := data["classification"].(string)
				log.Printf("egress-guard: quality finish OK source=%s node=%s name=%q class=%s pending_left=%d",
					job.source, job.nodeID, job.nodeName, class, nextPending)
			}
			for _, w := range waiters {
				w <- qualityOutcome{data: data, err: err}
			}
		}
	}()
}

func stopQualityWorker() {
	s := qualitySched
	s.mu.Lock()
	stop := s.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	s.cond.Broadcast()
}

func handlePassiveUsage(store *stateStore, record map[string]any) {
	pol := store.policy()
	if pol.Mode == "active" {
		return
	}
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
		class = classifyQuality(tps, outTokens, pol)
	}

	if class == "hard" || class == "soft" {
		invalidateAuthProxyCache()
	}
	nodeID := resolveNodeIDForAuth(store, authID, authIndex,
		filepath.Base(authID), strings.TrimSuffix(filepath.Base(authID), ".json"))
	res := qualityResult{
		Classification: class,
		TPS:            tps,
		OutputTokens:   outTokens,
		DurationMs:     durMs,
		FirstTokenMs:   ttftMs,
		ErrorKind:      errorKind,
	}
	if nodeID == "" {
		store.bumpStat("passive", class, outTokens)
		if class == "hard" || class == "soft" {
			store.appendEvent(guardEvent{
				Event:          "unmapped_" + class,
				AuthID:         firstNonEmpty(authID, authIndex),
				Classification: class,
				OutputTPS:      tps,
				Reason:         fmt.Sprintf("usage 未映射到出口节点 auth=%s idx=%s tokens=%d dur=%dms ttft=%dms", authID, authIndex, outTokens, durMs, ttftMs),
			})
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

func busiestEnabledNode(store *stateStore) string {
	bestID := ""
	bestN := -1
	for _, n := range store.listNodes() {
		if !n.Enabled || n.DisabledByGuard || n.ProxyURL == "" {
			continue
		}
		if n.AssignedAccountCount > bestN {
			bestN = n.AssignedAccountCount
			bestID = n.ID
		}
	}
	return bestID
}

func startGuardWorker(ctx context.Context, store *stateStore) {
	startQualityWorker(ctx, store)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pol := store.policy()
				now := float64(time.Now().Unix())
				// Enqueue only — never run probes inline. Clash leaf selection is
				// global; the quality scheduler keeps PerfectAI switches serial.
				for _, n := range store.listNodes() {
					if n.DisabledByGuard && n.QuarantinedUntil > 0 && now >= n.QuarantinedUntil {
						_, _ = queueNodeQuality(store, n.ID, "recovery", false)
						continue
					}
					if pol.Mode == "active" || pol.Mode == "hybrid" {
						if n.Enabled && !n.DisabledByGuard && (n.LastProbeAt == 0 || now-n.LastProbeAt >= float64(pol.ActiveIntervalSec)) {
							_, _ = queueNodeQuality(store, n.ID, "active", false)
							break
						}
					}
				}
				// Counts are refreshed lazily from UI/status and after migrations.
				// Doing a full auth fan-out every 30s is a major CPU/host-call cost.
			}
		}
	}()
}

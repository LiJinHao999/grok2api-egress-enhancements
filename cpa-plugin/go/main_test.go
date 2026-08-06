package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestComputeTPSUsesGenerationWindow(t *testing.T) {
	// 1050 tokens over 500ms generation window (1100-600) => 2100 TPS
	if got := computeTPS(1050, 1100, 600, 200); got < 2099 || got > 2101 {
		t.Fatalf("computeTPS()=%v, want ~2100", got)
	}
	// tiny generation window falls back to full duration (avoid false hard)
	// 100 tokens / 1000ms => 100 TPS
	if got := computeTPS(100, 1000, 950, 200); got < 99 || got > 101 {
		t.Fatalf("computeTPS()=%v, want ~100 with min window fallback", got)
	}
	if got := computeTPS(100, 0, 0, 200); got != 0 {
		t.Fatalf("computeTPS()=%v, want 0", got)
	}
}

func TestFailureClassificationDoesNotTreatAuthErrorsAsTransport(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		kind   string
	}{
		{401, "invalid or expired token", "account_error"},
		{429, "rate limit", "account_error"},
		{0, "dial tcp 10.0.0.1: i/o timeout", "transport_error"},
		{503, "upstream unavailable", "upstream_error"},
	} {
		if got := classifyFailureKind(test.status, test.body); got != test.kind {
			t.Fatalf("classifyFailureKind(%d, %q)=%q, want %q", test.status, test.body, got, test.kind)
		}
	}
}

func TestXAITokenAccountingDoesNotDoubleCountReasoning(t *testing.T) {
	if got := maxInt64(180, 75); got != 180 {
		t.Fatalf("max token total=%d, want 180", got)
	}
	if got := outputTokensFromUsage(map[string]any{
		"completion_tokens": 180,
		"output_tokens":     180,
		"reasoning_tokens":  75,
	}); got != 180 {
		t.Fatalf("authoritative token total=%d, want 180", got)
	}
}

func TestSmallOutputIsIgnoredBeforeTPSThreshold(t *testing.T) {
	pol := defaultPolicy()
	if got := classifyQuality(5000, pol.MinOutputTokens-1, true, pol); got != "ignored" {
		t.Fatalf("small output classification=%q, want ignored", got)
	}
	if got := classifyQuality(5000, pol.MinOutputTokens, true, pol); got != "hard" {
		t.Fatalf("threshold output classification=%q, want hard", got)
	}
}

func TestManualDisabledAuthIsNotRestored(t *testing.T) {
	if isGuardDisabledAuth(authFile{Disabled: true, Raw: map[string]any{"disabled_reason": "operator: maintenance"}}) {
		t.Fatal("operator-disabled auth must not be treated as guard-managed")
	}
}

func TestSchedulerSkipsCoolingStatuses(t *testing.T) {
	for _, status := range []string{"disabled", "unavailable", "error", "cooling", "pending", "refreshing", "future-state"} {
		if schedulerCandidateAvailable(pluginapi.SchedulerAuthCandidate{Status: status}) {
			t.Fatalf("status %q should not be selected", status)
		}
	}
	for _, status := range []string{"", "active", "ready"} {
		if !schedulerCandidateAvailable(pluginapi.SchedulerAuthCandidate{Status: status}) {
			t.Fatalf("status %q should be selectable", status)
		}
	}
}

func TestMigrationFailsClosedAndVerifiesHostAuthSave(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(good.ID, func(node *nodeRecord) error {
		node.LastClassification = "healthy"
		node.LastProbeAt = float64(time.Now().Unix())
		node.ExitIP = "198.51.100.2"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(node *nodeRecord) error {
		node.ExitIP = "198.51.100.1"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	auths := map[string]map[string]any{
		"bad.json": {
			"type": "xai", "email": "bad@example.test", "access_token": "bad-token", "proxy_url": bad.ProxyURL, "disabled": false,
		},
		"good.json": {
			"type": "xai", "email": "good@example.test", "access_token": "good-token", "proxy_url": good.ProxyURL, "disabled": false,
		},
		"manual.json": {
			"type": "xai", "email": "manual@example.test", "access_token": "manual-token", "proxy_url": bad.ProxyURL, "disabled": true, "disabled_reason": "operator maintenance",
		},
	}
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := make([]pluginapi.HostAuthFileEntry, 0, len(auths))
			for name, raw := range auths {
				disabled, _ := raw["disabled"].(bool)
				entries = append(entries, pluginapi.HostAuthFileEntry{ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai", Disabled: disabled})
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw, ok := auths[name]
			if !ok {
				return nil, fmt.Errorf("auth not found: %s", name)
			}
			body, _ := json.Marshal(raw)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		case pluginabi.MethodHostAuthSave:
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			updated := map[string]any{}
			if err := json.Unmarshal(request.JSON, &updated); err != nil {
				return nil, err
			}
			auths[request.Name] = updated
			return json.Marshal(pluginapi.HostAuthSaveResponse{Name: request.Name, Path: "/auths/" + request.Name})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = originalHostCall
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
	}()

	if err := migrateAuthsOffNode(store, bad); err != nil {
		t.Fatalf("migrateAuthsOffNode() error = %v", err)
	}
	if got := auths["bad.json"]["proxy_url"]; got != good.ProxyURL {
		t.Fatalf("bad auth proxy=%q, want healthy proxy", got)
	}
	if disabled, _ := auths["bad.json"]["disabled"].(bool); disabled {
		t.Fatal("migrated auth remains disabled")
	}
	if got := auths["manual.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("manual auth proxy=%q, want unchanged bad proxy", got)
	}
	if disabled, _ := auths["manual.json"]["disabled"].(bool); !disabled {
		t.Fatal("manual disabled auth was re-enabled")
	}
}

func TestSchedulerSkipsQuarantinedNode(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(node *nodeRecord) error { node.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-bad": bad.ProxyURL, "auth-good": good.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.SchedulerPickRequest{
		Provider: "xai",
		Candidates: []pluginapi.SchedulerAuthCandidate{
			{ID: "auth-bad", Provider: "xai"},
			{ID: "auth-good", Provider: "xai"},
		},
	})
	raw, err := handleSchedulerPick(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("scheduler envelope=%s err=%v", raw, err)
	}
	var response pluginapi.SchedulerPickResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Handled || response.AuthID != "auth-good" {
		t.Fatalf("scheduler response=%+v", response)
	}
}

func TestRequestInterceptorRejectsQuarantinedAuth(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-bad": node.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "auth-bad"}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var response pluginapi.RequestInterceptResponse
	_ = json.Unmarshal(env.Result, &response)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("interceptor response=%+v", response)
	}
}

func TestMatchIsolationKeyword(t *testing.T) {
	if got := matchIsolationKeyword([]byte(`{"name":"ListMcpResourcesTool"}`), []string{"ListMcpResourcesTool"}); got != "ListMcpResourcesTool" {
		t.Fatalf("match=%q", got)
	}
	if got := matchIsolationKeyword([]byte(`{"name":"other"}`), []string{"ListMcpResourcesTool"}); got != "" {
		t.Fatalf("unexpected match=%q", got)
	}
	if got := matchIsolationKeyword(nil, []string{"ListMcpResourcesTool"}); got != "" {
		t.Fatalf("empty body match=%q", got)
	}
}

func TestNormalizeIsolationKeywords(t *testing.T) {
	got := normalizeIsolationKeywords([]string{"  ListMcpResourcesTool ", "", "ListMcpResourcesTool", "other"})
	if len(got) != 2 || got[0] != "ListMcpResourcesTool" || got[1] != "other" {
		t.Fatalf("normalize=%#v", got)
	}
}

func TestResponseInterceptorKeywordIsolatesNode(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	if _, err := store.createNode("spare", "http://127.0.0.1:7950", true, false, 0); err != nil {
		t.Fatal(err)
	}
	node, err := store.createNode("target", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.IsolationKeywords = []string{"ListMcpResourcesTool"}
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-kw": node.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()

	// Request body must NOT quarantine.
	reqRaw, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		Metadata: map[string]any{"selected_auth_id": "auth-kw"},
		Body:     []byte(`{"content":[{"type":"tool_use","name":"ListMcpResourcesTool"}]}`),
	})
	if _, err := handleRequestIntercept(reqRaw, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.getNode(node.ID); n.DisabledByGuard {
		t.Fatal("request body must not quarantine")
	}

	respRaw, _ := json.Marshal(pluginapi.ResponseInterceptRequest{
		Metadata: map[string]any{"selected_auth_id": "auth-kw"},
		Body:     []byte(`{"content":[{"type":"tool_use","name":"ListMcpResourcesTool"}]}`),
	})
	if _, err := handleResponseIntercept(respRaw); err != nil {
		t.Fatal(err)
	}
	updated, ok := store.getNode(node.ID)
	if !ok || !updated.DisabledByGuard {
		t.Fatalf("node not quarantined: ok=%v node=%#v", ok, updated)
	}
	if !strings.Contains(updated.LastReason, "ListMcpResourcesTool") {
		t.Fatalf("reason=%q", updated.LastReason)
	}
}

func TestStreamChunkInterceptorKeywordIsolatesNode(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	if _, err := store.createNode("spare", "http://127.0.0.1:7950", true, false, 0); err != nil {
		t.Fatal(err)
	}
	node, err := store.createNode("target", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.IsolationKeywords = []string{"ListMcpResourcesTool"}
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-stream": node.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()

	raw, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		Metadata: map[string]any{"selected_auth_id": "auth-stream"},
		Body:     []byte(`data: {"delta":{"content":"ListMcpResourcesTool"}}`),
	})
	if _, err := handleStreamChunkIntercept(raw); err != nil {
		t.Fatal(err)
	}
	updated, ok := store.getNode(node.ID)
	if !ok || !updated.DisabledByGuard {
		t.Fatalf("stream keyword did not quarantine: ok=%v %#v", ok, updated)
	}
}

func TestClassifyTPS(t *testing.T) {
	if classifyTPS(1200, 500, 1000) != "hard" {
		t.Fatal("expected hard")
	}
	if classifyTPS(600, 500, 1000) != "soft" {
		t.Fatal("expected soft")
	}
	if classifyTPS(100, 500, 1000) != "healthy" {
		t.Fatal("expected healthy")
	}
}

func TestStoreNodeCRUD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	n, err := s.createNode("ch-1", "http://127.0.0.1:7951", true, false, 200)
	if err != nil {
		t.Fatal(err)
	}
	if n.ID == "" || n.ProxyURL == "" {
		t.Fatalf("bad node %#v", n)
	}
	pub := publicNode(n)
	if _, ok := pub["proxy_url"]; ok {
		t.Fatal("public node must not expose proxy_url")
	}
	if pub["hasProxy"] != true {
		t.Fatal("hasProxy")
	}
	list := s.listNodes()
	if len(list) != 1 {
		t.Fatalf("len=%d", len(list))
	}
	// reload
	s2 := newStateStore(path)
	n2, ok := s2.getNode(n.ID)
	if !ok || n2.ProxyURL != "http://127.0.0.1:7951" {
		t.Fatalf("reload failed %#v", n2)
	}
	_ = s2.deleteNodes([]string{n.ID})
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCreateNodesIsAllOrNothing(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	created, err := s.createNodes([]nodeCreateInput{
		{Name: "a", ProxyURL: "http://127.0.0.1:7951", Enabled: true, AccountCapacity: 100},
		{Name: "b", ProxyURL: "http://127.0.0.1:7952", Enabled: true, ProxyPool: true, AccountCapacity: 120},
	})
	if err != nil || len(created) != 2 || len(s.listNodes()) != 2 {
		t.Fatalf("created=%d nodes=%d err=%v", len(created), len(s.listNodes()), err)
	}
	if _, err := s.createNodes([]nodeCreateInput{
		{Name: "valid", ProxyURL: "http://127.0.0.1:7953", Enabled: true},
		{Name: "invalid", ProxyURL: "", Enabled: true},
	}); err == nil {
		t.Fatal("expected invalid import to fail")
	}
	if len(s.listNodes()) != 2 {
		t.Fatal("invalid batch must not create partial nodes")
	}
}

func TestRenderStatusPage(t *testing.T) {
	page := renderPageHTML()
	for _, want := range []string{
		"出口守护", "纯 CPA", "data-batch=\"enable\"", "重平衡账号", "批量添加", "/nodes/import",
		"页面每 15 秒刷新", "最短生成窗口", "X-Grok2API-Egress-UI",
		"queue-banner", "测试队列", "质量检测队列空闲", "quality_queue", "hasThinking",
		"账号降智统计", "EgressAccountsPanel", "panel-accounts-host",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") || strings.Contains(page, "/*__ACCOUNTS_PANEL_JS__*/") {
		t.Fatal("embed placeholders not replaced")
	}
}

func TestRecordAuthDegradeStats(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	store.recordAuthObservation("a1@x", "a1@x", "passive", "1", "n1", "hard", "响应缺少 thinking_content（降智）", 10, true)
	store.recordAuthObservation("a1@x", "a1@x", "passive", "1", "n1", "healthy", "", 8, false)
	store.recordAuthObservation("b2@x", "b2@x", "passive", "2", "n2", "hard", "响应缺少 thinking_content（降智）", 12, true)
	items := store.listAuthDegradeStats()
	if len(items) != 2 {
		t.Fatalf("auth stats len=%d, want 2", len(items))
	}
	var a1 *authDegradeRecord
	for _, it := range items {
		if it.AuthID == "a1@x" {
			a1 = it
		}
	}
	if a1 == nil || a1.DegradedCount != 1 || a1.SampleCount != 2 {
		t.Fatalf("a1 stats=%+v", a1)
	}
	store.clearAuthDegradeStats()
	if len(store.listAuthDegradeStats()) != 0 {
		t.Fatal("clearAuthDegradeStats should empty list")
	}
}

func TestApplyObservationRecordsAuthStats(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("n2", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}
	// Passive missing-thinking immediately counts as degrade for the audited account,
	// even when ThinkingCrossVerify queues a recheck (node isolation is deferred).
	passive := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		OutputTokens:   64,
		TPS:            10,
		AuthID:         "heidi@x",
		AuthLabel:      "heidi@x",
		Error:          missingThinkingReason,
		ErrorKind:      "missing_thinking",
	}
	applyObservation(store, node.ID, "passive", passive)
	items := store.listAuthDegradeStats()
	if len(items) != 1 || items[0].AuthID != "heidi@x" || items[0].SampleCount != 1 || items[0].DegradedCount != 1 {
		t.Fatalf("passive missing-thinking should degrade that account immediately: %+v", items)
	}

	// Cross-verify uses a different account that is healthy: record that account
	// as a normal sample only — do not merge into the passive account.
	crossOK := qualityResult{
		Classification: "healthy",
		HasThinking:    true,
		OutputTokens:   80,
		TPS:            20,
		AuthID:         "probe@x",
		AuthLabel:      "probe@x",
	}
	applyObservation(store, node.ID, "soft-recheck", crossOK)
	items = store.listAuthDegradeStats()
	byID := map[string]*authDegradeRecord{}
	for _, it := range items {
		byID[it.AuthID] = it
	}
	if heidi := byID["heidi@x"]; heidi == nil || heidi.DegradedCount != 1 || heidi.SampleCount != 1 {
		t.Fatalf("passive account stats must stay independent: %+v", heidi)
	}
	if probe := byID["probe@x"]; probe == nil || probe.DegradedCount != 0 || probe.SampleCount != 1 {
		t.Fatalf("cross-verify healthy account should sample only: %+v", probe)
	}

	// Cross-verify with a third account that is also missing thinking: that
	// probe account is degraded on its own, without touching heidi@x.
	crossBad := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		OutputTokens:   40,
		TPS:            8,
		AuthID:         "other@x",
		AuthLabel:      "other@x",
		Error:          missingThinkingReason,
		ErrorKind:      "missing_thinking",
	}
	applyObservation(store, node.ID, "active", crossBad)
	items = store.listAuthDegradeStats()
	byID = map[string]*authDegradeRecord{}
	for _, it := range items {
		byID[it.AuthID] = it
	}
	if heidi := byID["heidi@x"]; heidi == nil || heidi.DegradedCount != 1 || heidi.SampleCount != 1 {
		t.Fatalf("heidi must remain 1/1 after other accounts: %+v", heidi)
	}
	if other := byID["other@x"]; other == nil || other.DegradedCount != 1 || other.SampleCount != 1 {
		t.Fatalf("cross-verify missing-thinking account should degrade itself: %+v", other)
	}
}

func TestDeltaHasThinking(t *testing.T) {
	if !deltaHasThinking(map[string]any{"reasoning_content": "step 1"}) {
		t.Fatal("reasoning_content should count as thinking")
	}
	if !deltaHasThinking(map[string]any{"thinking": "why walk"}) {
		t.Fatal("thinking field should count")
	}
	if !deltaHasThinking(map[string]any{"content": []any{map[string]any{"type": "thinking", "thinking": "..."}}}) {
		t.Fatal("anthropic-style thinking block should count")
	}
	if deltaHasThinking(map[string]any{"content": "走路去"}) {
		t.Fatal("plain content must not count as thinking")
	}
	if deltaHasThinking(nil) {
		t.Fatal("nil delta must not count")
	}
}

func TestQualityQueueDedupesAndSnapshots(t *testing.T) {
	// Isolate global scheduler state for this test.
	qualitySched.mu.Lock()
	qualitySched.pending = nil
	qualitySched.active = nil
	qualitySched.started = false
	qualitySched.nextID = 0
	qualitySched.mu.Unlock()

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	a, err := store.createNode("node-a", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.createNode("node-b", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Do not start the worker: jobs stay pending so we can assert queue shape.
	if _, err := queueNodeQuality(store, a.ID, "manual", false); err != nil {
		t.Fatal(err)
	}
	if _, err := queueNodeQuality(store, b.ID, "active", false); err != nil {
		t.Fatal(err)
	}
	dup, err := queueNodeQuality(store, a.ID, "manual", false)
	if err != nil {
		t.Fatal(err)
	}
	if dup["deduped"] != true {
		t.Fatalf("expected dedupe for same node, got %#v", dup)
	}

	snap := qualitySched.snapshot()
	if snap["busy"] != true {
		t.Fatalf("snapshot busy=%v", snap["busy"])
	}
	if snap["total"] != 2 {
		t.Fatalf("total=%v want 2", snap["total"])
	}
	pending, _ := snap["pending"].([]map[string]any)
	if len(pending) != 2 {
		t.Fatalf("pending=%d %#v", len(pending), snap["pending"])
	}
	if pending[0]["node_id"] != a.ID || pending[0]["source_label"] != "手动" {
		t.Fatalf("first pending=%#v", pending[0])
	}
	if pending[1]["node_id"] != b.ID || pending[1]["source_label"] != "主动" {
		t.Fatalf("second pending=%#v", pending[1])
	}

	// Clean up so later tests do not inherit queued jobs.
	qualitySched.mu.Lock()
	qualitySched.pending = nil
	qualitySched.active = nil
	qualitySched.started = false
	qualitySched.mu.Unlock()
}

func TestQualityProbePromptIsCarWash(t *testing.T) {
	if !strings.Contains(qualityProbePrompt, "洗车") {
		t.Fatalf("probe prompt=%q", qualityProbePrompt)
	}
	if !strings.Contains(missingThinkingReason, "thinking") {
		t.Fatalf("missing thinking reason=%q", missingThinkingReason)
	}
}

func TestDisabledNodeSkipsAutomaticQualityQueue(t *testing.T) {
	qualitySched.mu.Lock()
	qualitySched.pending = nil
	qualitySched.active = nil
	qualitySched.started = false
	qualitySched.nextID = 0
	qualitySched.mu.Unlock()

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	n, err := store.createNode("disabled-leaf", "http://127.0.0.1:7959", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(n.ID, func(node *nodeRecord) error {
		node.Enabled = false
		node.DisabledByGuard = true
		node.QuarantinedUntil = float64(time.Now().Add(-time.Minute).Unix())
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	out, err := queueNodeQuality(store, n.ID, "recovery", false)
	if err != nil {
		t.Fatal(err)
	}
	if out["skipped"] != true || out["status"] != "skipped_disabled" {
		t.Fatalf("expected skip for disabled recovery, got %#v", out)
	}
	out, err = queueNodeQuality(store, n.ID, "post-switch", false)
	if err != nil {
		t.Fatal(err)
	}
	if out["skipped"] != true {
		t.Fatalf("expected skip for disabled post-switch, got %#v", out)
	}
	// Manual panel probe is still allowed so operators can diagnose a stopped leaf.
	out, err = queueNodeQuality(store, n.ID, "manual", false)
	if err != nil {
		t.Fatal(err)
	}
	if out["queued"] != true {
		t.Fatalf("manual probe should still queue on disabled node, got %#v", out)
	}

	qualitySched.mu.Lock()
	if len(qualitySched.pending) != 1 || qualitySched.pending[0].source != "manual" {
		t.Fatalf("pending=%#v", qualitySched.pending)
	}
	qualitySched.pending = nil
	qualitySched.active = nil
	qualitySched.started = false
	qualitySched.mu.Unlock()
}

func TestQualitySourceLabelPostSwitch(t *testing.T) {
	if qualitySourceLabel("post-switch") != "切后复测" {
		t.Fatalf("label=%q", qualitySourceLabel("post-switch"))
	}
}

func TestProbeTimeoutErrorsAreDetected(t *testing.T) {
	if !isProbeTimeoutErr(context.DeadlineExceeded) {
		t.Fatal("deadline exceeded must be timeout")
	}
	if !isProbeTimeoutErr(fmt.Errorf("Post url: context deadline exceeded (Client.Timeout exceeded while awaiting headers)")) {
		t.Fatal("client timeout string must match")
	}
	if isProbeTimeoutErr(fmt.Errorf("connection refused")) {
		t.Fatal("connection refused is not timeout")
	}
}

func TestUIProxyRejectsMissingHeader(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodGet, Path: "/nodes"})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"StatusCode":403`) {
		t.Fatalf("got %s", raw)
	}
}

func TestDispatchNodesList(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	_, _ = store.createNode("a", "http://127.0.0.1:1", true, false, 0)
	headers := make(http.Header)
	headers.Set("X-Grok2API-Egress-UI", "1")
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodGet, Path: "/nodes"})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var resp managementResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"name":"a"`) {
		t.Fatalf("body %s", resp.Body)
	}
}

func TestDispatchNodesImportRedactsProxyURLs(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "s.json"))
	headers := make(http.Header)
	headers.Set("X-Grok2API-Egress-UI", "1")
	requestBody, _ := json.Marshal(map[string]any{
		"items": []map[string]any{
			{"name": "fixed-a", "proxyURL": "http://user:pass@127.0.0.1:7951", "accountCapacity": 100},
			{"proxy_url": "http://user:pass@127.0.0.1:7952", "proxy_pool": true},
		},
	})
	body, _ := json.Marshal(uiProxyRequest{Method: http.MethodPost, Path: "/nodes/import", Body: requestBody})
	raw, err := handleUIProxy(managementRequest{Method: http.MethodPost, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	var resp managementResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), `"created":2`) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	if strings.Contains(string(resp.Body), "user:pass") || strings.Contains(string(resp.Body), "proxy_url") {
		t.Fatalf("response leaked proxy URL: %s", resp.Body)
	}
	if len(store.listNodes()) != 2 {
		t.Fatalf("node count=%d", len(store.listNodes()))
	}
}


func TestDeleteManagedNodesIsImmediate(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	// Two Clash-like leaves sharing one proxy must not block delete on host auth I/O.
	shared := "http://127.0.0.1:7890"
	a, err := store.createNode("leaf-a", shared, true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.createNode("leaf-b", shared, true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.updateNode(a.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "A"
		return nil
	})
	_, _ = store.updateNode(b.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "B"
		return nil
	})

	// Delete itself must stay host-free. Async unbind/count refresh may touch host
	// later; those calls must not block the delete path under test.
	orig := hostCall
	hostCalls := 0
	defer func() { hostCall = orig }()
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		hostCalls++
		return nil, fmt.Errorf("host disabled in delete test: %s", method)
	}

	deleted, exclusive := deleteManagedNodes(store, []string{a.ID})
	if hostCalls != 0 {
		t.Fatalf("delete path issued %d host calls", hostCalls)
	}
	if deleted != 1 {
		t.Fatalf("deleted=%d", deleted)
	}
	if len(exclusive) != 0 {
		t.Fatalf("shared proxy must not unbind exclusively: %#v", exclusive)
	}
	if _, ok := store.getNode(a.ID); ok {
		t.Fatal("node a still present")
	}
	if _, ok := store.getNode(b.ID); !ok {
		t.Fatal("node b should remain")
	}

	// Exclusive manual proxy is scheduled for async unbind, but delete itself stays host-free.
	manual, err := store.createNode("manual", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	deleted, exclusive = deleteManagedNodes(store, []string{manual.ID})
	if deleted != 1 || len(exclusive) != 1 || exclusive[0] != "http://127.0.0.1:7951" {
		t.Fatalf("deleted=%d exclusive=%#v", deleted, exclusive)
	}
	if _, ok := store.getNode(manual.ID); ok {
		t.Fatal("manual node still present after exclusive delete")
	}
	// Async unbind / assigned-count refresh may touch host after return; that is
	// intentional and must not be asserted as a synchronous delete-path failure.
	time.Sleep(20 * time.Millisecond)
}

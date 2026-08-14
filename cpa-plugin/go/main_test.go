package main

import (
	"encoding/json"
	"errors"
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

func TestThinkingPresenceIsPrimaryQualitySignal(t *testing.T) {
	pol := defaultPolicy()
	pol.ThinkingGuard = true
	// Small output without thinking is not enough evidence.
	if got := classifyQuality(5000, pol.MinOutputTokens-1, false, pol); got != "ignored" {
		t.Fatalf("small output without thinking=%q, want ignored", got)
	}
	// Enough output but no thinking → 降智 / hard.
	if got := classifyQuality(5000, pol.MinOutputTokens, false, pol); got != "hard" {
		t.Fatalf("no-thinking classification=%q, want hard", got)
	}
	// Thinking present falls back to original Token/s thresholds.
	if got := classifyQuality(5000, pol.MinOutputTokens, true, pol); got != "hard" {
		t.Fatalf("with-thinking high TPS classification=%q, want hard", got)
	}
	if got := classifyQuality(10, 200, true, pol); got != "healthy" {
		t.Fatalf("with-thinking low TPS classification=%q, want healthy", got)
	}
	if got := classifyQuality(750, 200, true, pol); got != "soft" {
		t.Fatalf("with-thinking mid TPS classification=%q, want soft", got)
	}
}

func TestThinkingGuardOffFallsBackToTPSOnly(t *testing.T) {
	pol := defaultPolicy()
	pol.ThinkingGuard = false
	if got := classifyQuality(5000, 200, false, pol); got != "hard" {
		t.Fatalf("guard off high TPS=%q, want hard", got)
	}
	if got := classifyQuality(10, 200, false, pol); got != "healthy" {
		t.Fatalf("guard off low TPS without thinking=%q, want healthy", got)
	}
}

func TestRecordHasThinkingFallsBackToReasoningTokens(t *testing.T) {
	if recordHasThinking(map[string]any{
		"Detail": map[string]any{"reasoning_tokens": float64(12)},
	}) != true {
		t.Fatal("reasoning_tokens in Detail should count as thinking")
	}
	if recordHasThinking(map[string]any{
		"delta": map[string]any{"thinking_content": "step 1"},
	}) != true {
		t.Fatal("thinking_content should count as thinking")
	}
	if recordHasThinking(map[string]any{
		"output_tokens": float64(64),
	}) != false {
		t.Fatal("plain output without reasoning must not count as thinking")
	}
}

func TestAccountQuotaExhaustedDetection(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   bool
	}{
		{200, "free-usage-exhausted for plan", true},
		{403, "FREE_USAGE_EXHAUSTED", true},
		{400, "subscription:free-usage limit", true},
		{400, "Included Free Usage has ended", true},
		{429, "rate limit exceeded", true},
		{429, "quota remaining 0", true},
		{429, "daily usage cap", true},
		{200, "quota exhausted on account", true},
		{429, "please slow down", false},
		{500, "internal error", false},
	} {
		if got := isAccountQuotaExhausted(test.status, test.body); got != test.want {
			t.Fatalf("isAccountQuotaExhausted(%d, %q)=%v, want %v", test.status, test.body, got, test.want)
		}
	}
}

func TestShouldRetryProbeWithNextAuth(t *testing.T) {
	if !shouldRetryProbeWithNextAuth(true, 429, "free-usage-exhausted", "account_error") {
		t.Fatal("quota exhaustion must retry next auth")
	}
	if shouldRetryProbeWithNextAuth(false, 429, "free-usage-exhausted", "account_error") {
		t.Fatal("no next auth must not retry")
	}
	if !shouldRetryProbeWithNextAuth(true, 401, "invalid or expired token", "account_error") {
		t.Fatal("auth error must retry next auth")
	}
	if shouldRetryProbeWithNextAuth(true, 502, "bad gateway", "upstream_error") {
		t.Fatal("upstream error must not switch auth")
	}
}

func TestProbeUnstableErrDetection(t *testing.T) {
	for _, msg := range []string{
		"read: connection reset by peer",
		"unexpected EOF",
		"http2: stream closed",
		"tls: handshake failure",
		"i/o timeout",
	} {
		if !isProbeUnstableErr(errors.New(msg)) {
			t.Fatalf("expected unstable for %q", msg)
		}
	}
	if isProbeUnstableErr(errors.New("json: cannot unmarshal")) {
		t.Fatal("parse errors are not probe instability")
	}
	res := probeUnstableResult(qualityResult{Model: "grok-4.5"}, errors.New("connection reset by peer"), 1234)
	if res.Classification != "hard" || res.ErrorKind != "probe_unstable" {
		t.Fatalf("unstable result=%+v", res)
	}
	if !strings.Contains(res.Error, "断流不稳定") {
		t.Fatalf("error text=%q", res.Error)
	}
}

func TestDefaultPolicyDefaults(t *testing.T) {
	pol := defaultPolicy()
	if !pol.ThinkingGuard {
		t.Fatal("default ThinkingGuard should be on")
	}
	if pol.ThinkingCrossVerify {
		t.Fatal("default ThinkingCrossVerify should be off to minimize active probes")
	}
	if pol.SoftCrossVerify {
		t.Fatal("default SoftCrossVerify should be off to minimize active probes")
	}
	if pol.ConsecutiveMissingThinking != 1 {
		t.Fatalf("default consecutive missing thinking=%d, want 1", pol.ConsecutiveMissingThinking)
	}
	if pol.QuarantineSec != 3600 {
		t.Fatalf("default quarantine seconds=%d, want 3600", pol.QuarantineSec)
	}
	if pol.PolicySchema != 4 {
		t.Fatalf("default policy schema=%d, want 4", pol.PolicySchema)
	}
	if got := classifyQuality(100, 64, false, pol); got != "hard" {
		t.Fatalf("missing thinking with guard=%q, want hard", got)
	}
}

func TestNormalizePolicyFillsAbsentBoolDefaults(t *testing.T) {
	// Pure old state: no redesign keys, schema 0.
	p := policyConfig{HardTPS: 1000, SoftTPS: 500}
	normalizePolicy(&p, map[string]any{
		"hard_tps": 1000,
		"soft_tps": 500,
	})
	if !p.ThinkingGuard {
		t.Fatal("absent thinking_guard must default on")
	}
	if p.ThinkingCrossVerify {
		t.Fatal("schema migration must default thinking_cross_verify off")
	}
	if p.SoftCrossVerify {
		t.Fatal("absent soft_cross_verify must default off")
	}
	if p.ConsecutiveMissingThinking != 1 {
		t.Fatalf("consecutive_missing_thinking=%d, want 1", p.ConsecutiveMissingThinking)
	}
	if p.PolicySchema != 4 {
		t.Fatalf("policy_schema=%d, want 4", p.PolicySchema)
	}
	if p.QuarantineSec != 3600 {
		t.Fatalf("migrated quarantine_seconds=%d, want 3600", p.QuarantineSec)
	}

	// Intermediate build: explicit thinking_cross_verify=false but schema still 0.
	pMid := policyConfig{HardTPS: 1000, SoftTPS: 500, ThinkingGuard: true, ThinkingCrossVerify: false, ConsecutiveMissingThinking: 1}
	normalizePolicy(&pMid, map[string]any{
		"hard_tps":                     1000,
		"soft_tps":                     500,
		"thinking_guard":               true,
		"thinking_cross_verify":        false,
		"consecutive_missing_thinking": 1,
	})
	if pMid.ThinkingCrossVerify {
		t.Fatal("schema<2 must migrate thinking_cross_verify to default off even if true was persisted")
	}
	if pMid.SoftCrossVerify {
		t.Fatal("schema migration must turn soft_cross_verify off")
	}
	if pMid.PolicySchema != 4 {
		t.Fatalf("migrated policy_schema=%d, want 4", pMid.PolicySchema)
	}

	// Live 1.0.8 leftover: schema 3 with both cross-verify flags still true.
	pLive := policyConfig{HardTPS: 1000, SoftTPS: 500, ThinkingGuard: true, ThinkingCrossVerify: true, SoftCrossVerify: true, ConsecutiveMissingThinking: 1, QuarantineSec: 120, PolicySchema: 3}
	normalizePolicy(&pLive, map[string]any{
		"hard_tps":              1000,
		"soft_tps":              500,
		"thinking_guard":        true,
		"thinking_cross_verify": true,
		"soft_cross_verify":     true,
		"quarantine_seconds":    120,
		"policy_schema":         3,
	})
	if pLive.ThinkingCrossVerify {
		t.Fatal("schema 3 leftover thinking_cross_verify=true must migrate off")
	}
	if pLive.SoftCrossVerify {
		t.Fatal("schema 3 leftover soft_cross_verify=true must migrate off")
	}
	if pLive.QuarantineSec != 3600 {
		t.Fatalf("schema 3 leftover quarantine 120s must migrate to 3600, got %d", pLive.QuarantineSec)
	}
	if pLive.PolicySchema != 4 {
		t.Fatalf("live leftover policy_schema=%d, want 4", pLive.PolicySchema)
	}

	// Operator-chosen quarantine interval must survive the schema bump.
	pCustom := policyConfig{HardTPS: 1000, SoftTPS: 500, ThinkingGuard: true, ThinkingCrossVerify: true, SoftCrossVerify: true, QuarantineSec: 300, PolicySchema: 3}
	normalizePolicy(&pCustom, map[string]any{
		"hard_tps":              1000,
		"soft_tps":              500,
		"thinking_guard":        true,
		"thinking_cross_verify": true,
		"soft_cross_verify":     true,
		"quarantine_seconds":    300,
		"policy_schema":         3,
	})
	if pCustom.QuarantineSec != 300 {
		t.Fatalf("custom quarantine_seconds must stay 300, got %d", pCustom.QuarantineSec)
	}
	if pCustom.ThinkingCrossVerify || pCustom.SoftCrossVerify {
		t.Fatal("schema 3 leftover cross-verify flags must migrate off even when quarantine is custom")
	}

	// After schema 4, explicit true must stick (operator re-enabled in panel).
	p2 := policyConfig{HardTPS: 1000, SoftTPS: 500, ThinkingGuard: true, ThinkingCrossVerify: true, SoftCrossVerify: true, ConsecutiveMissingThinking: 2, PolicySchema: 4}
	normalizePolicy(&p2, map[string]any{
		"hard_tps":                     1000,
		"soft_tps":                     500,
		"thinking_guard":               true,
		"thinking_cross_verify":        true,
		"soft_cross_verify":            true,
		"consecutive_missing_thinking": 2,
		"policy_schema":                4,
	})
	if !p2.ThinkingCrossVerify || !p2.SoftCrossVerify {
		t.Fatal("explicit true after schema 4 must stay true")
	}

	// Explicit thinking_guard=false stays false and forces cross-verify off.
	p3 := policyConfig{HardTPS: 1000, SoftTPS: 500, ThinkingGuard: false}
	normalizePolicy(&p3, map[string]any{
		"hard_tps":       1000,
		"soft_tps":       500,
		"thinking_guard": false,
	})
	if p3.ThinkingGuard || p3.ThinkingCrossVerify {
		t.Fatal("explicit thinking_guard=false must disable guard and cross-verify")
	}
}

func TestMissingThinkingRequiresConsecutiveStrikes(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Keep min_healthy satisfiable so quarantine is not suppressed.
	if _, err := store.createNode("n2", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.ThinkingGuard = true
	pol.ThinkingCrossVerify = false
	pol.ConsecutiveMissingThinking = 2
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	res := qualityResult{Classification: "hard", HasThinking: false, OutputTokens: 64, TPS: 10}
	applyObservation(store, node.ID, "passive", res)
	got, _ := store.getNode(node.ID)
	if got.DisabledByGuard {
		t.Fatal("first missing-thinking must not quarantine when threshold=2")
	}
	if got.ThinkingStrikes != 1 {
		t.Fatalf("thinking strikes=%d, want 1", got.ThinkingStrikes)
	}
	applyObservation(store, node.ID, "passive", res)
	got, _ = store.getNode(node.ID)
	if !got.DisabledByGuard {
		t.Fatal("second missing-thinking should quarantine when threshold=2 and cross-verify off")
	}
}

func TestThinkingCrossVerifySchedulesInsteadOfQuarantine(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Add a second healthy node so quarantine is not suppressed by min_healthy.
	if _, err := store.createNode("n2", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.ThinkingGuard = true
	pol.ThinkingCrossVerify = true
	pol.ConsecutiveMissingThinking = 1
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	res := qualityResult{Classification: "hard", HasThinking: false, OutputTokens: 64, TPS: 10}
	applyObservation(store, node.ID, "passive", res)
	got, _ := store.getNode(node.ID)
	if got.DisabledByGuard {
		t.Fatal("passive missing-thinking with cross-verify must not quarantine immediately")
	}
	if got.ThinkingStrikes < 1 {
		t.Fatal("thinking strikes should accumulate")
	}
	// Active confirmation quarantines without re-scheduling.
	applyObservation(store, node.ID, "active", res)
	got, _ = store.getNode(node.ID)
	if !got.DisabledByGuard {
		t.Fatal("active missing-thinking confirmation should quarantine")
	}
	endCrossVerify(node.ID)
}

func TestSoftCrossVerifySchedulesInsteadOfQuarantine(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("n2", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.SoftCrossVerify = true
	pol.ConsecutiveSoft = 1
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	res := qualityResult{Classification: "soft", HasThinking: true, OutputTokens: 64, TPS: 600}
	applyObservation(store, node.ID, "passive", res)
	got, _ := store.getNode(node.ID)
	if got.DisabledByGuard {
		t.Fatal("soft cross-verify must defer quarantine")
	}
	applyObservation(store, node.ID, "active", res)
	got, _ = store.getNode(node.ID)
	if !got.DisabledByGuard {
		t.Fatal("active soft confirmation should quarantine")
	}
	endCrossVerify(node.ID)
}

func TestAuthDegradeCountsPassiveEvenWhenCrossVerifyScheduled(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("n2", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.ThinkingGuard = true
	pol.ThinkingCrossVerify = true
	pol.ConsecutiveMissingThinking = 1
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	passive := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		OutputTokens:   64,
		TPS:            10,
		AuthID:         "passive@x",
		AuthLabel:      "passive@x",
		Error:          "响应缺少 thinking_content（降智）",
	}
	applyObservation(store, node.ID, "passive", passive)
	items := store.listAuthDegradeStats()
	if len(items) != 1 || items[0].AuthID != "passive@x" || items[0].SampleCount != 1 || items[0].DegradedCount != 1 {
		t.Fatalf("passive missing-thinking must count degrade immediately: %+v", items)
	}
	// Cross-verify uses a different account and must not merge into the passive one.
	// Healthy retest → only the probe account gets a normal sample.
	probeOK := qualityResult{
		Classification: "healthy",
		HasThinking:    true,
		OutputTokens:   80,
		TPS:            40,
		AuthID:         "probe@x",
		AuthLabel:      "probe@x",
	}
	applyObservation(store, node.ID, "active", probeOK)
	items = store.listAuthDegradeStats()
	byID := map[string]*authDegradeRecord{}
	for _, it := range items {
		byID[it.AuthID] = it
	}
	if p := byID["passive@x"]; p == nil || p.DegradedCount != 1 || p.SampleCount != 1 {
		t.Fatalf("passive stats must stay degrade=1 sample=1, got %+v", p)
	}
	if p := byID["probe@x"]; p == nil || p.DegradedCount != 0 || p.SampleCount != 1 {
		t.Fatalf("healthy cross-verify account must be sample=1 degrade=0, got %+v", p)
	}
	// Same probe account missing thinking on a later retest counts only for itself.
	probeBad := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		OutputTokens:   64,
		TPS:            10,
		AuthID:         "probe@x",
		AuthLabel:      "probe@x",
		Error:          "响应缺少 thinking_content（降智）",
	}
	applyObservation(store, node.ID, "active", probeBad)
	items = store.listAuthDegradeStats()
	byID = map[string]*authDegradeRecord{}
	for _, it := range items {
		byID[it.AuthID] = it
	}
	if p := byID["passive@x"]; p == nil || p.DegradedCount != 1 || p.SampleCount != 1 {
		t.Fatalf("passive must remain untouched after other-account retest: %+v", p)
	}
	if p := byID["probe@x"]; p == nil || p.DegradedCount != 1 || p.SampleCount != 2 {
		t.Fatalf("probe missing-thinking want degrade=1 sample=2, got %+v", p)
	}
	endCrossVerify(node.ID)
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
	if items[0].AuthID != "a1@x" && items[0].DegradedCount < items[1].DegradedCount {
		t.Fatalf("expected higher degrade count first: %+v", items)
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
}

func TestManualDisabledAuthIsNotRestored(t *testing.T) {
	if isGuardDisabledAuth(authFile{Disabled: true, Raw: map[string]any{"disabled_reason": "operator: maintenance"}}) {
		t.Fatal("operator-disabled auth must not be treated as guard-managed")
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
		case pluginabi.MethodHostAuthGetRuntime:
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
			disabled, _ := raw["disabled"].(bool)
			status := "active"
			if disabled {
				status = "disabled"
			}
			return json.Marshal(pluginapi.HostAuthGetRuntimeResponse{Auth: pluginapi.HostAuthFileEntry{
				ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai",
				Disabled: disabled, Status: status,
			}})
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
		invalidateAuthListCache()
		resetAuthRuntimeHolds()
		authSettleNow = time.Now
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

func withMockAuths(t *testing.T, auths map[string]map[string]any) {
	t.Helper()
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
		case pluginabi.MethodHostAuthGetRuntime:
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
			disabled, _ := raw["disabled"].(bool)
			status := "active"
			if disabled {
				status = "disabled"
			}
			return json.Marshal(pluginapi.HostAuthGetRuntimeResponse{Auth: pluginapi.HostAuthFileEntry{
				ID: name, AuthIndex: name, Name: name, Provider: "xai", Type: "xai",
				Disabled: disabled, Status: status,
			}})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	t.Cleanup(func() {
		hostCall = originalHostCall
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
		invalidateAuthListCache()
		resetAuthRuntimeHolds()
		authSettleNow = time.Now
	})
}

func TestMigrationFallsBackWithoutRecentProbe(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": bad.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	if err := migrateAuthsOffNode(store, bad); err != nil {
		t.Fatalf("cold-start fallback should succeed: %v", err)
	}
	if got := auths["stuck.json"]["proxy_url"]; got != good.ProxyURL {
		t.Fatalf("auth proxy=%q, want fallback node %q", got, good.ProxyURL)
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); disabled {
		t.Fatal("fallback-migrated auth remains disabled")
	}
}

func TestMigrationFailureReenablesAuths(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	only, err := store.createNode("only", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": only.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	if err := migrateAuthsOffNode(store, only); err == nil {
		t.Fatal("expected migrate error when no other node exists")
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); disabled {
		t.Fatal("no-target migrate must roll back the fail-closed disable")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != only.ProxyURL {
		t.Fatalf("auth proxy=%q, want original", got)
	}
}

func TestQuarantineDisableAuthOnHardFalseDoesNotLeaveDisabled(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	pol.DisableAuthOnHard = false
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": bad.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		if method == pluginabi.MethodHostAuthSave {
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			_ = json.Unmarshal(payload, &request)
			updated := map[string]any{}
			_ = json.Unmarshal(request.JSON, &updated)
			if updated["proxy_url"] == good.ProxyURL {
				return nil, fmt.Errorf("simulated dest bind failure")
			}
		}
		return original(method, payload)
	}
	t.Cleanup(func() { hostCall = original })
	quarantineNode(store, bad.ID, "missing thinking", 10, "hard")
	got, _ := store.getNode(bad.ID)
	if !got.DisabledByGuard {
		t.Fatal("node must still be quarantined")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("failed dest bind must leave auth on original node, got %q", got)
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); disabled {
		t.Fatal("DisableAuthOnHard=false must not leave the account disabled after migrate-fail rollback")
	}
}

func TestQuarantineDisableAuthOnHardLeavesLeftoverDisabled(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	pol := store.policy()
	if !pol.DisableAuthOnHard {
		t.Fatal("default DisableAuthOnHard must be true")
	}
	pol.MinHealthyNodes = 1
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": bad.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		if method == pluginabi.MethodHostAuthSave {
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			_ = json.Unmarshal(payload, &request)
			updated := map[string]any{}
			_ = json.Unmarshal(request.JSON, &updated)
			if updated["proxy_url"] == good.ProxyURL {
				return nil, fmt.Errorf("simulated dest bind failure")
			}
		}
		return original(method, payload)
	}
	t.Cleanup(func() { hostCall = original })
	quarantineNode(store, bad.ID, "missing thinking", 10, "hard")
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("failed dest bind must leave auth on original node, got %q", got)
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); !disabled {
		t.Fatal("default DisableAuthOnHard must leave leftover disabled on the original proxy")
	}
}

func TestApplyAuthBindingVerifyFailureKeepsDisabledSnapshot(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {
			"type": "xai", "email": "stuck@example.test", "access_token": "tok",
			"proxy_url": bad.ProxyURL, "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
	}
	withMockAuths(t, auths)
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		if method == pluginabi.MethodHostAuthGet {
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw := auths[name]
			stale := map[string]any{}
			for k, v := range raw {
				stale[k] = v
			}
			stale["proxy_url"] = bad.ProxyURL
			body, _ := json.Marshal(stale)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		}
		return original(method, payload)
	}
	t.Cleanup(func() { hostCall = original })
	items, err := listAuthFiles()
	if err != nil || len(items) != 1 {
		t.Fatalf("listAuthFiles err=%v items=%+v", err, items)
	}
	if err := applyAuthBinding(items[0], good.ProxyURL, false, ""); err == nil {
		t.Fatal("stale GET must fail dest verify")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("host file proxy=%q, want original", got)
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); !disabled {
		t.Fatal("verify-fail rollback must keep the pre-call disabled snapshot")
	}
}

func TestNodeSchedulableFlags(t *testing.T) {
	if nodeSchedulable(nil) {
		t.Fatal("nil must not be schedulable")
	}
	if !nodeSchedulable(&nodeRecord{Enabled: true, ProxyURL: "http://127.0.0.1:1"}) {
		t.Fatal("enabled node with proxy must be schedulable")
	}
	if nodeSchedulable(&nodeRecord{Enabled: true, DisabledByGuard: true, ProxyURL: "http://127.0.0.1:1"}) {
		t.Fatal("quarantined node must not be schedulable")
	}
	if nodeSchedulable(&nodeRecord{Enabled: true}) {
		t.Fatal("node without proxy must not be schedulable")
	}
}

func TestNodeFallbackEligibleExcludesDegraded(t *testing.T) {
	cold := &nodeRecord{Enabled: true, ProxyURL: "http://127.0.0.1:1"}
	if !nodeFallbackEligible(cold) {
		t.Fatal("never-probed node must stay fallback-eligible")
	}
	healthy := &nodeRecord{Enabled: true, ProxyURL: "http://127.0.0.1:1", LastClassification: "healthy"}
	if !nodeFallbackEligible(healthy) {
		t.Fatal("healthy node must stay fallback-eligible")
	}
	for _, class := range []string{"soft", "hard", "error"} {
		n := &nodeRecord{Enabled: true, ProxyURL: "http://127.0.0.1:1", LastClassification: class}
		if nodeFallbackEligible(n) {
			t.Fatalf("classification %q must not be a fallback target", class)
		}
	}
	ignoredOnly := &nodeRecord{Enabled: true, ProxyURL: "http://127.0.0.1:1", LastClassification: "ignored"}
	if !nodeFallbackEligible(ignoredOnly) {
		t.Fatal("never-quality ignored must stay fallback-eligible")
	}
}

func TestIgnoredObservationDoesNotEraseSoftFallbackBlock(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	soft, err := store.createNode("soft", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	applyObservation(store, soft.ID, "passive", qualityResult{
		Classification: "soft", HasThinking: true, OutputTokens: 64, TPS: 600,
	})
	applyObservation(store, soft.ID, "active", qualityResult{
		Classification: "error", ErrorKind: "no_account", Error: "节点没有可用的绑定账号",
	})
	got, _ := store.getNode(soft.ID)
	if got.LastClassification != "soft" {
		t.Fatalf("ignored/no_account must not overwrite soft, got %q", got.LastClassification)
	}
	if got.SoftStrikes == 0 {
		t.Fatal("ignored sample must not reset soft strikes")
	}
	if nodeFallbackEligible(got) {
		t.Fatal("soft node must stay ineligible after an ignored sample")
	}
	targets := fallbackMigrationTargets(store, bad)
	for _, target := range targets {
		if target.ID == soft.ID {
			t.Fatal("soft-then-ignored node must not be a fallback dest")
		}
	}
}

func TestAuthIsBorrowedTreatsUnboundAsForeign(t *testing.T) {
	node := &nodeRecord{ProxyURL: "http://127.0.0.1:7951"}
	if !authIsBorrowed(authFile{ProxyURL: ""}, node) {
		t.Fatal("unbound auth is borrowed relative to a managed node")
	}
	if authIsBorrowed(authFile{ProxyURL: node.ProxyURL}, node) {
		t.Fatal("same-proxy auth is not borrowed")
	}
	if !authIsBorrowed(authFile{ProxyURL: "http://127.0.0.1:7952"}, node) {
		t.Fatal("other-proxy auth is borrowed")
	}
}

func TestAssignedCountIgnoresDisabledAndExpired(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("n1", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"live.json": {
			"type": "xai", "email": "live@example.test", "access_token": "tok",
			"proxy_url": node.ProxyURL, "disabled": false,
		},
		"disabled.json": {
			"type": "xai", "email": "off@example.test", "access_token": "tok",
			"proxy_url": node.ProxyURL, "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
		"expired.json": {
			"type": "xai", "email": "old@example.test", "access_token": "tok",
			"proxy_url": node.ProxyURL, "disabled": false, "expired": "2020-01-01T00:00:00Z",
		},
	}
	withMockAuths(t, auths)
	refreshAssignedCounts(store)
	got, _ := store.getNode(node.ID)
	if got.AssignedAccountCount != 1 {
		t.Fatalf("AssignedAccountCount=%d, want 1 live binding", got.AssignedAccountCount)
	}
}

func TestMigrationVerifyFailureRollsBackHostAndCache(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {
			"type": "xai", "email": "stuck@example.test", "access_token": "tok",
			"proxy_url": bad.ProxyURL, "disabled": false,
		},
	}
	withMockAuths(t, auths)
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		if method == pluginabi.MethodHostAuthGet {
			var request map[string]string
			_ = json.Unmarshal(payload, &request)
			name := request["auth_index"]
			if name == "" {
				name = request["name"]
			}
			raw := auths[name]
			stale := map[string]any{}
			for k, v := range raw {
				stale[k] = v
			}
			stale["proxy_url"] = bad.ProxyURL
			body, _ := json.Marshal(stale)
			return json.Marshal(hostAuthGetResponse{AuthIndex: name, Name: name, Path: "/auths/" + name, JSON: body})
		}
		return original(method, payload)
	}
	t.Cleanup(func() { hostCall = original })
	if err := migrateAuthsOffNode(store, bad); err == nil {
		t.Fatal("stale GET must fail dest verify")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("host file proxy=%q, want rolled back to original", got)
	}
	cached, err := listAuthFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cached {
		if item.Name == "stuck.json" && item.ProxyURL != bad.ProxyURL {
			t.Fatalf("list cache proxy=%q, want original after verify rollback", item.ProxyURL)
		}
	}
}

func TestNodeHasBoundRestoreFuelIgnoresExpired(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("iso", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	withMockAuths(t, map[string]map[string]any{
		"expired.json": {
			"type": "xai", "email": "old@example.test", "access_token": "tok",
			"proxy_url": node.ProxyURL, "disabled": false, "expired": "2020-01-01T00:00:00Z",
		},
	})
	if nodeHasBoundRestoreFuel(node) {
		t.Fatal("expired-only leftover must not count as restore fuel")
	}

	withMockAuths(t, map[string]map[string]any{
		"guard.json": {
			"type": "xai", "email": "guard@example.test", "access_token": "tok",
			"proxy_url": node.ProxyURL, "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
	})
	if !nodeHasBoundRestoreFuel(node) {
		t.Fatal("guard-disabled leftover with a live token is restore fuel")
	}
}

func TestPlanGuardWorkerJobsLimitsRestoreAndSkipsEmptyModelProbe(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	emptyA, err := store.createNode("empty-a", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	emptyB, err := store.createNode("empty-b", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	live, err := store.createNode("live", "http://127.0.0.1:7953", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := float64(time.Now().Unix())
	if _, err := store.updateNode(emptyA.ID, func(n *nodeRecord) error {
		n.DisabledByGuard = true
		n.QuarantinedUntil = now - 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(emptyB.ID, func(n *nodeRecord) error {
		n.DisabledByGuard = true
		n.QuarantinedUntil = now - 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(live.ID, func(n *nodeRecord) error {
		n.AssignedAccountCount = 3
		n.LastProbeAt = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	withMockAuths(t, map[string]map[string]any{
		"other.json": {
			"type": "xai", "email": "other@example.test", "access_token": "tok",
			"proxy_url": live.ProxyURL, "disabled": false,
		},
	})
	emptyA, _ = store.getNode(emptyA.ID)
	emptyB, _ = store.getNode(emptyB.ID)
	live, _ = store.getNode(live.ID)
	jobs := planGuardWorkerJobs([]*nodeRecord{emptyA, emptyB, live}, now, store.policy())
	if len(jobs) != 1 {
		t.Fatalf("jobs=%+v, want exactly one restore", jobs)
	}
	if jobs[0].Kind != guardWorkerJobConnectivity {
		t.Fatalf("empty isolated restore kind=%q, want connectivity", jobs[0].Kind)
	}

	leftover, err := store.createNode("leftover", "http://127.0.0.1:7954", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(leftover.ID, func(n *nodeRecord) error {
		n.DisabledByGuard = true
		n.QuarantinedUntil = now - 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	leftover, _ = store.getNode(leftover.ID)
	withMockAuths(t, map[string]map[string]any{
		"guard.json": {
			"type": "xai", "email": "guard@example.test", "access_token": "tok",
			"proxy_url": leftover.ProxyURL, "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
	})
	jobs = planGuardWorkerJobs([]*nodeRecord{leftover}, now, store.policy())
	if len(jobs) != 1 || jobs[0].Kind != guardWorkerJobQuality {
		t.Fatalf("leftover isolated restore jobs=%+v, want quality", jobs)
	}
}

func TestSchedulerHandsSelectionBackToHost(t *testing.T) {
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
	if response.Handled || response.AuthID != "" {
		t.Fatalf("scheduler must hand selection back to host affinity selector, response=%+v", response)
	}
}

func decodeIntercept(t *testing.T, raw []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var response pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func interceptSelected(t *testing.T, meta map[string]any) pluginapi.RequestInterceptResponse {
	t.Helper()
	rawRequest, err := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	return decodeIntercept(t, raw)
}

func TestListAuthsForNodeRecoverySkipsOperatorDisabled(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	isolated, err := store.createNode("iso", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.createNode("other", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"manual.json": {
			"type": "xai", "email": "manual@example.test", "access_token": "manual-tok",
			"proxy_url": isolated.ProxyURL, "disabled": true, "disabled_reason": "operator maintenance",
		},
		"guard.json": {
			"type": "xai", "email": "guard@example.test", "access_token": "guard-tok",
			"proxy_url": isolated.ProxyURL, "disabled": true, "disabled_reason": "egress-guard 隔离中",
		},
		"other.json": {
			"type": "xai", "email": "other@example.test", "access_token": "other-tok",
			"proxy_url": other.ProxyURL, "disabled": false,
		},
	}
	withMockAuths(t, auths)
	got, err := listAuthsForNodeMode(isolated, 8, authListRecovery)
	if err != nil || len(got) == 0 {
		t.Fatalf("recovery list err=%v got=%+v", err, got)
	}
	if got[0].Name != "guard.json" {
		t.Fatalf("recovery must prefer guard-disabled leftover, got %+v", got[0])
	}
	for _, item := range got {
		if item.Name == "manual.json" {
			t.Fatal("operator-disabled leftover must not be used for restore probes")
		}
	}

	delete(auths, "guard.json")
	invalidateAuthListCache()
	got, err = listAuthsForNodeMode(isolated, 8, authListRecovery)
	if err == nil {
		t.Fatalf("empty isolated recovery must not borrow a foreign auth, got %+v", got)
	}
	if !strings.Contains(err.Error(), "没有可用于隔离复测") {
		t.Fatalf("error=%v", err)
	}
}

func TestListAuthsForNodeDoesNotBorrowForeign(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	emptyNode, err := store.createNode("empty", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.createNode("other", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"other.json": {"type": "xai", "email": "other@example.test", "access_token": "tok", "proxy_url": other.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	got, err := listAuthsForNode(emptyNode, 8)
	if err == nil {
		t.Fatalf("empty node must not borrow a foreign auth, got %+v", got)
	}
	if !strings.Contains(err.Error(), "没有可用的绑定账号") {
		t.Fatalf("error=%v", err)
	}
}

func TestMigrationSkipsDegradedFallbackTarget(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	soft, err := store.createNode("soft", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(soft.ID, func(n *nodeRecord) error {
		n.LastClassification = "soft"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": bad.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	if err := migrateAuthsOffNode(store, bad); err == nil {
		t.Fatal("soft dest must not be a fallback target")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("auth proxy=%q, want original", got)
	}
	if disabled, _ := auths["stuck.json"]["disabled"].(bool); disabled {
		t.Fatal("failed fallback must roll back disable")
	}
}

func TestMigrationSkipsSameExitIPFallback(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	twin, err := store.createNode("twin", "http://127.0.0.1:7952", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(n *nodeRecord) error {
		n.ExitIP = "203.0.113.10"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(twin.ID, func(n *nodeRecord) error {
		n.ExitIP = "203.0.113.10"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bad, _ = store.getNode(bad.ID)
	auths := map[string]map[string]any{
		"stuck.json": {"type": "xai", "email": "stuck@example.test", "access_token": "tok", "proxy_url": bad.ProxyURL, "disabled": false},
	}
	withMockAuths(t, auths)
	if err := migrateAuthsOffNode(store, bad); err == nil {
		t.Fatal("same exit IP must not be a silent fallback success")
	}
	if got := auths["stuck.json"]["proxy_url"]; got != bad.ProxyURL {
		t.Fatalf("auth proxy=%q, want original", got)
	}
}

func TestLoadMigratesSchemaAndRecordsEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	raw := `{"version":1,"policy":{"mode":"hybrid","hard_tps":1000,"soft_tps":500,"thinking_guard":true,"thinking_cross_verify":true,"soft_cross_verify":true,"quarantine_seconds":120,"policy_schema":3},"nodes":{},"next_id":1}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newStateStore(path)
	pol := s.policy()
	if pol.PolicySchema != 4 || pol.ThinkingCrossVerify || pol.SoftCrossVerify || pol.QuarantineSec != 3600 {
		t.Fatalf("migrated policy=%+v", pol)
	}
	found := false
	for _, ev := range s.events() {
		if ev.Event == "policy_migrated" {
			found = true
			if !strings.Contains(ev.Reason, "schema 3") {
				t.Fatalf("migration reason=%q", ev.Reason)
			}
		}
	}
	if !found {
		t.Fatal("schema upgrade must append policy_migrated")
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

func TestRequestInterceptorFailClosedWithoutSelectedAuth(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("missing selected auth during quarantine must fail closed, response=%+v", response)
	}

	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = false; return nil }); err != nil {
		t.Fatal(err)
	}
	raw, err = handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response = decodeIntercept(t, raw)
	if response.Terminate {
		t.Fatalf("missing selected auth with no quarantine must pass, response=%+v", response)
	}
}

func TestRequestInterceptorAllowsUnmappedAuthDuringQuarantine(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"direct-unmanaged": authProxyUnmanaged}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "direct-unmanaged"}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if response.Terminate {
		t.Fatalf("known unmanaged selected auth must pass during another node's quarantine, response=%+v", response)
	}
}

func TestRequestInterceptorAllowsHealthySiblingDuringQuarantine(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-bad": bad.ProxyURL, "auth-good": good.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "auth-good"}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if response.Terminate {
		t.Fatalf("healthy sibling auth must pass while another node is quarantined, response=%+v", response)
	}
}

func TestRequestInterceptorResolvesSelectedAuthIndex(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"idx-bad": node.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{
		"selected_auth_id":    "runtime-uuid-not-in-cache",
		"selected_auth_index": "idx-bad",
	}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("index fallback must still reject quarantined auth, response=%+v", response)
	}
}

func TestRequestInterceptorFailClosedOnUnresolvedAuthDuringQuarantine(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "maybe-quarantined"}})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unresolved selected auth during quarantine must fail closed, response=%+v", response)
	}
}

func TestRequestInterceptorFailClosedIgnoresOpenAIWireFormat(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		ToFormat:     "openai",
		SourceFormat: "openai",
		Metadata:     map[string]any{},
	})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("openai wire format without selected auth must still fail closed, response=%+v", response)
	}

	rawRequest, _ = json.Marshal(pluginapi.RequestInterceptRequest{
		Model:        "grok-4.5",
		ToFormat:     "openai",
		SourceFormat: "openai",
		Metadata:     map[string]any{},
	})
	raw, err = handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response = decodeIntercept(t, raw)
	if !response.Terminate {
		t.Fatal("grok model with openai wire format must still fail closed")
	}
}

func TestRequestInterceptorAllowsNonXAIWithoutSelectedAuth(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		Model:    "claude-sonnet-4",
		Metadata: map[string]any{},
	})
	raw, err := handleRequestIntercept(rawRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeIntercept(t, raw)
	if response.Terminate {
		t.Fatalf("explicit non-xAI model must pass during xAI quarantine, response=%+v", response)
	}
}

func withAuthRuntimeProbe(t *testing.T, probe func(keys []string) (authRuntimeSnapshot, error)) {
	t.Helper()
	original := probeAuthRuntime
	probeAuthRuntime = probe
	t.Cleanup(func() {
		probeAuthRuntime = original
		resetAuthRuntimeHolds()
		authSettleNow = time.Now
	})
}

func TestRequestInterceptorReleasesWhenRuntimeProxyMatches(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_000, 0)
	authSettleNow = func() time.Time { return base }
	destURL := "http://127.0.0.1:7952"
	snapshot := authRuntimeSnapshot{Found: true, Disabled: false, Status: "active"}
	withAuthRuntimeProbe(t, func(keys []string) (authRuntimeSnapshot, error) {
		return snapshot, nil
	})

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	dest, err := store.createNode("good", destURL, true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-moved": dest.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()

	markAuthRuntimeUnsettled(authFile{ID: "auth-moved", Name: "moved.json", Index: "idx-moved", ProxyURL: destURL})
	response := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("empty runtime proxy must stay blocked, response=%+v", response)
	}

	snapshot = authRuntimeSnapshot{Found: true, Disabled: false, Status: "active", ProxyURL: destURL, ProxyURLKnown: true}
	authSettleNow = func() time.Time { return base.Add(authRuntimeProbeInterval) }
	response = interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if response.Terminate {
		t.Fatalf("runtime proxy match must release immediately, response=%+v", response)
	}
}

func TestRequestInterceptorKeepsHoldWhenRuntimeProxyStillEmpty(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_050, 0)
	authSettleNow = func() time.Time { return base }
	destURL := "http://127.0.0.1:7952"
	withAuthRuntimeProbe(t, func(keys []string) (authRuntimeSnapshot, error) {
		return authRuntimeSnapshot{Found: true, Disabled: false, Status: "active", ProxyURL: "", ProxyURLKnown: true}, nil
	})

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	dest, err := store.createNode("good", destURL, true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-moved": dest.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()

	markAuthRuntimeUnsettled(authFile{ID: "auth-moved", Name: "moved.json", ProxyURL: destURL})
	authSettleNow = func() time.Time { return base.Add(authRuntimeSettle + time.Second) }
	response := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if !response.Terminate {
		t.Fatal("known-empty runtime proxy must stay blocked after the 2s hop")
	}
}

func TestRequestInterceptorHoldBlocksUntilRuntimeDisabled(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_100, 0)
	authSettleNow = func() time.Time { return base }
	snapshot := authRuntimeSnapshot{Found: true, Disabled: false, Status: "active"}
	withAuthRuntimeProbe(t, func(keys []string) (authRuntimeSnapshot, error) {
		return snapshot, nil
	})

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	bad, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(bad.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"sticky-auth": bad.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	markAuthRuntimeUnsettled(authFile{ID: "sticky-auth", Name: "sticky.json", ProxyURL: bad.ProxyURL, Disabled: true})

	first := interceptSelected(t, map[string]any{"selected_auth_id": "sticky-auth"})
	if !first.Terminate {
		t.Fatal("affinity retry during disable settle must 503")
	}
	authSettleNow = func() time.Time { return base.Add(authRuntimeSettle + time.Second) }
	second := interceptSelected(t, map[string]any{"selected_auth_id": "sticky-auth"})
	if !second.Terminate {
		t.Fatal("disable hold must not expire on the 2s clock")
	}

	snapshot = authRuntimeSnapshot{Found: true, Disabled: true, Status: "disabled"}
	authSettleNow = func() time.Time { return base.Add(authRuntimeSettle + time.Second + authRuntimeProbeInterval) }
	third := interceptSelected(t, map[string]any{"selected_auth_id": "sticky-auth"})
	if !third.Terminate {
		t.Fatal("runtime disable confirmed, but selected auth is still on a quarantined node")
	}
}

func TestRequestInterceptorHiddenProxyFallsBackToSettleWindow(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_200, 0)
	authSettleNow = func() time.Time { return base }
	withAuthRuntimeProbe(t, func(keys []string) (authRuntimeSnapshot, error) {
		return authRuntimeSnapshot{Found: true, Disabled: false, Status: "active"}, nil
	})

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	dest, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-moved": dest.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	markAuthRuntimeUnsettled(authFile{ID: "auth-moved", Name: "moved.json", ProxyURL: dest.ProxyURL})

	first := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if !first.Terminate {
		t.Fatal("hidden runtime proxy must wait the last-resort hop")
	}
	if got := first.ResponseHeaders.Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After=%q, want 2 while waiting for the hidden-proxy hop", got)
	}

	authSettleNow = func() time.Time { return base.Add(authRuntimeSettle + authRuntimeProbeInterval) }
	second := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if second.Terminate {
		t.Fatalf("hidden-proxy last-resort hop must release after 2s when get_runtime works, response=%+v", second)
	}
}

func TestRequestInterceptorHoldExpiresAtMaxWhenRuntimeNeverConfirms(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_300, 0)
	authSettleNow = func() time.Time { return base }
	withAuthRuntimeProbe(t, func(keys []string) (authRuntimeSnapshot, error) {
		return authRuntimeSnapshot{}, fmt.Errorf("host down")
	})

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	dest, err := store.createNode("good", "http://127.0.0.1:7952", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-moved": dest.ProxyURL}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	markAuthRuntimeUnsettled(authFile{ID: "auth-moved", Name: "moved.json", ProxyURL: dest.ProxyURL})

	mid := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if !mid.Terminate {
		t.Fatal("unreachable get_runtime must keep the hold")
	}

	authSettleNow = func() time.Time { return base.Add(authRuntimeHoldMax + time.Millisecond) }
	done := interceptSelected(t, map[string]any{"selected_auth_id": "auth-moved"})
	if done.Terminate {
		t.Fatalf("hold max is a circuit breaker, response=%+v", done)
	}
}

func TestRequestInterceptorFailClosedOnUnmatchedProxyDuringQuarantine(t *testing.T) {
	resetAuthRuntimeHolds()
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	node, err := store.createNode("bad", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.updateNode(node.ID, func(value *nodeRecord) error { value.DisabledByGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"typo-auth": "http://127.0.0.1:65535"}
	authProxyAt = time.Now()
	authProxyMu.Unlock()
	response := interceptSelected(t, map[string]any{"selected_auth_id": "typo-auth"})
	if !response.Terminate || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unmatched proxy during quarantine must fail closed, response=%+v", response)
	}
}

func TestDecodeAuthRuntimeSnapshotReadsProxyURL(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"auth": map[string]any{
			"id":        "moved.json",
			"name":      "moved.json",
			"disabled":  false,
			"status":    "active",
			"proxy_url": "http://127.0.0.1:7952",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := decodeAuthRuntimeSnapshot(raw)
	if !ok || !snapshot.Found || !snapshot.ProxyURLKnown || snapshot.ProxyURL != "http://127.0.0.1:7952" {
		t.Fatalf("snapshot=%+v ok=%v", snapshot, ok)
	}
}

func TestSaveAuthFileMarksRuntimeHold(t *testing.T) {
	resetAuthRuntimeHolds()
	base := time.Unix(1_700_000_200, 0)
	authSettleNow = func() time.Time { return base }
	t.Cleanup(func() {
		resetAuthRuntimeHolds()
		authSettleNow = time.Now
	})
	auths := map[string]map[string]any{
		"hold.json": {
			"type": "xai", "email": "hold@example.test", "access_token": "tok",
			"proxy_url": "http://127.0.0.1:7951", "disabled": false,
		},
	}
	withMockAuths(t, auths)
	if err := setAuthProxyAndFlags(authFile{
		Name: "hold.json", Email: "hold@example.test",
		ProxyURL: "http://127.0.0.1:7951",
		Raw:      auths["hold.json"],
	}, "http://127.0.0.1:7952", false, ""); err != nil {
		t.Fatal(err)
	}
	if _, held := selectedAuthRuntimeHold("hold.json", "hold@example.test", "xai-hold@example.test.json"); !held {
		t.Fatal("successful save must mark the auth unsettled for the interceptor")
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

func TestConfigureAcceptsStoreInstallYAMLWithoutHostAuth(t *testing.T) {
	// Mirrors the YAML CPA passes on plugin.register after a store install:
	// enabled + store manifest + optional plugin fields. Must succeed without
	// any host.auth.* callbacks so the plugin becomes 已注册/生效中 immediately.
	prevStore := store
	prevCancel := workerCancel
	prevHost := hostCall
	t.Cleanup(func() {
		if workerCancel != nil {
			workerCancel()
		}
		workerCancel = prevCancel
		store = prevStore
		hostCall = prevHost
	})
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		t.Fatalf("configure must not call host during register, got %s", method)
		return nil, fmt.Errorf("unexpected host call %s", method)
	}

	statePath := filepath.Join(t.TempDir(), "egress-guard", "state.json")
	configYAML := []byte(fmt.Sprintf(`
enabled: true
priority: 0
state_file: %s
store:
  schema-version: 1
  id: grok2api-egress
  version: 1.0.8
  release-tag: v1.0.8
  repository: https://github.com/lij768423-svg/grok2api-egress-enhancements
  install:
    type: github-release
`, statePath))
	lifecycle, err := json.Marshal(lifecycleRequest{ConfigYAML: configYAML})
	if err != nil {
		t.Fatal(err)
	}
	if err := configure(lifecycle); err != nil {
		t.Fatalf("configure(store install yaml): %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodPluginRegister, lifecycle)
	if err != nil {
		t.Fatalf("plugin.register: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("register envelope ok=%v err=%v raw=%s", env.OK, err, raw)
	}
	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.Metadata.Name != pluginName || reg.Metadata.Version != pluginVersion {
		t.Fatalf("metadata=%+v", reg.Metadata)
	}
	if !reg.Capabilities.ManagementAPI || !reg.Capabilities.Scheduler {
		t.Fatalf("capabilities=%+v", reg.Capabilities)
	}
	cfg, _ := currentConfig.Load().(pluginConfig)
	if cfg.StateFile != statePath {
		t.Fatalf("state_file=%q want %q", cfg.StateFile, statePath)
	}
}

func TestConfigureFallsBackWhenYAMLIsGarbage(t *testing.T) {
	prevStore := store
	prevCancel := workerCancel
	t.Cleanup(func() {
		if workerCancel != nil {
			workerCancel()
		}
		workerCancel = prevCancel
		store = prevStore
	})
	lifecycle, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(":\n  - not: valid")})
	if err := configure(lifecycle); err != nil {
		t.Fatalf("configure must tolerate bad yaml: %v", err)
	}
	if store == nil {
		t.Fatal("store must still be initialized")
	}
}

func TestResolveDefaultStateFileIsWritable(t *testing.T) {
	path := resolveDefaultStateFile()
	if path == "" {
		t.Fatal("empty state path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe-write")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatalf("resolved path not writable: %v", err)
	}
	_ = os.Remove(probe)
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
	page := strings.Replace(pageTemplate, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)
	for _, want := range []string{"出口守护", "纯 CPA", "data-batch=\"enable\"", "重平衡账号", "批量添加", "/nodes/import", "页面每 15 秒刷新", "最短生成窗口", "X-Grok2API-Egress-UI"} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") {
		t.Fatal("tokens not replaced in test helper path only")
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

func TestAuthListCacheAvoidsRepeatedHostGets(t *testing.T) {
	invalidateAuthListCache()
	calls := map[string]int{}
	auths := map[string]map[string]any{
		"a.json": {"type": "xai", "email": "a@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:1", "disabled": false},
		"b.json": {"type": "xai", "email": "b@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:2", "disabled": false},
	}
	original := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		calls[method]++
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
				return nil, fmt.Errorf("missing %s", name)
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
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	defer func() {
		hostCall = original
		invalidateAuthListCache()
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
	}()

	first, err := listAuthFiles()
	if err != nil || len(first) != 2 {
		t.Fatalf("first list: n=%d err=%v", len(first), err)
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("cold list host calls list=%d get=%d, want 1/2", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
	for i := 0; i < 5; i++ {
		if _, err := listAuthFiles(); err != nil {
			t.Fatal(err)
		}
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("warm path re-hit host: list=%d get=%d", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
	if err := saveAuthFile("a.json", map[string]any{
		"type": "xai", "email": "a@example.test", "access_token": "t", "proxy_url": "http://127.0.0.1:9", "disabled": false,
	}); err != nil {
		t.Fatal(err)
	}
	// patched cache must reflect new proxy without another full list/get sweep
	got, err := listAuthFiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range got {
		if a.Name == "a.json" && a.ProxyURL == "http://127.0.0.1:9" {
			found = true
		}
	}
	if !found {
		t.Fatal("cache was not patched after save")
	}
	if calls[pluginabi.MethodHostAuthList] != 1 || calls[pluginabi.MethodHostAuthGet] != 2 {
		t.Fatalf("save+list triggered refetch list=%d get=%d", calls[pluginabi.MethodHostAuthList], calls[pluginabi.MethodHostAuthGet])
	}
}

func TestDebouncedPersistCoalescesStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	s.flushDelay = 50 * time.Millisecond
	for i := 0; i < 20; i++ {
		s.bumpStat("passive", "healthy", 10)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st guardState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Stats.Passive.Total != 20 {
		t.Fatalf("passive total=%d want 20", st.Stats.Passive.Total)
	}
}

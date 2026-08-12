package main

import (
	"encoding/base64"
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
	if got := classifyQuality(5000, pol.MinOutputTokens, true, pol); got != "healthy" {
		t.Fatalf("thinking output classification=%q, want healthy", got)
	}
	if got := classifyQuality(1, pol.MinOutputTokens, false, pol); got != "hard" {
		t.Fatalf("missing thinking classification=%q, want hard", got)
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
		node.LastObservedAt = float64(time.Now().Unix())
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
	if response.Handled || response.AuthID != "" {
		t.Fatalf("scheduler must hand selection back to host affinity selector, response=%+v", response)
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
		"queue-banner", "rotation-banner", "选号轮换", "metric-rotation", "rotation-list",
		"账号降智统计", "EgressAccountsPanel", "panel-accounts-host",
		"插件禁用账号", "disabled-auths-list", "账号自动禁用", "policy-auth-auto-disable",
		"auth-search", "clear-auth-stats", "disabled-auths-count",
		"node-search", "node-filter", "select-filtered", "全选筛选",
		"出口持续降智自动停用", "policy-node-auto-disable",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(page, "/*__HALLMARK_TOKENS__*/") || strings.Contains(page, "/*__ACCOUNTS_PANEL_JS__*/") {
		t.Fatal("embed placeholders not replaced")
	}
}

func TestFindAuthFileByIDMatchesPanelKeysWhenHostNameOpaque(t *testing.T) {
	// Real CPA hosts may return an opaque Name/ID from host.auth.get while the
	// panel/stat key is the file name (xai-{email}.json) or a bare email.
	// findAuthFileByID must still locate the account via normalized / email match.
	file := "xai-AimeeDean7323@outlook.com.json"
	email := "AimeeDean7323@outlook.com"
	auths := map[string]map[string]any{
		file: {"type": "xai", "email": email, "access_token": "tok", "disabled": false},
	}
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			entries := []pluginapi.HostAuthFileEntry{
				{ID: "rt-uuid-1234", AuthIndex: "idx-uuid-1234", Name: file, Provider: "xai", Type: "xai", Disabled: false},
			}
			return json.Marshal(hostAuthListResponse{Files: entries})
		case pluginabi.MethodHostAuthGet:
			// opaque Name/ID — NOT the file name
			return json.Marshal(hostAuthGetResponse{
				AuthIndex: "idx-uuid-1234",
				Name:      "idx-uuid-1234",
				Path:      "/auths/" + file,
				JSON:      mustJSON(auths[file]),
			})
		case pluginabi.MethodHostAuthSave:
			var request struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			_ = json.Unmarshal(payload, &request)
			updated := map[string]any{}
			_ = json.Unmarshal(request.JSON, &updated)
			auths[file] = updated
			return json.Marshal(pluginapi.HostAuthSaveResponse{Name: request.Name, Path: "/auths/" + request.Name})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = originalHostCall
		authListMu.Lock()
		authListCache = nil
		authListAt = time.Time{}
		authListMu.Unlock()
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
	}()

	// File-name key (as recorded from usage events) resolves via email fallback.
	if a, ok := findAuthFileByID(file); !ok || a.Email != email {
		t.Fatalf("findAuthFileByID(%q) = %+v, ok=%v", file, a, ok)
	}
	// Bare email resolves too.
	if a, ok := findAuthFileByID(email); !ok || a.Email != email {
		t.Fatalf("findAuthFileByID(%q) not found: %+v", email, a)
	}
	// Case / suffix insensitive.
	if a, ok := findAuthFileByID("XAI-" + email + ".JSON"); !ok || a.Email != email {
		t.Fatalf("findAuthFileByID(normalized variant) not found: %+v", a)
	}
	// Unknown id stays unknown.
	if _, ok := findAuthFileByID("no-such-account@x.invalid.json"); ok {
		t.Fatal("unknown account resolved")
	}

	// And a disable round-trip through the panel endpoint really persists to the
	// host auth file (disabled=true + account-manual reason).
	a, err := disableAuthByID(file, "manual", "面板手动禁用")
	if err != nil {
		t.Fatalf("disableAuthByID() error = %v", err)
	}
	if disabled, _ := auths[file]["disabled"].(bool); !disabled {
		t.Fatal("host auth file not disabled after disableAuthByID")
	}
	reason, _ := auths[file]["disabled_reason"].(string)
	if !strings.Contains(reason, "account-manual") {
		t.Fatalf("reason=%q, want account-manual tag", reason)
	}
	_ = a
}

func TestSetAuthProxyAndFlagsWritesDisabledToAuthFile(t *testing.T) {
	dir := t.TempDir()
	origDirs := authFileDirCandidatesList
	authFileDirCandidatesList = []string{dir}
	defer func() { authFileDirCandidatesList = origDirs }()

	name := "xai-test@x.json"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(`{"type":"xai","email":"test@x","access_token":"tok","disabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// host.auth.save still runs (keeps CPA runtime in sync) but, like the real
	// CPA host, it persists proxy_url / other fields while ignoring the disabled
	// flag. The physical-file write is what actually flips disabled.
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		if method != pluginabi.MethodHostAuthSave {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		var req struct {
			Name string          `json:"name"`
			JSON json.RawMessage `json:"json"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		obj := map[string]any{}
		if err := json.Unmarshal(req.JSON, &obj); err != nil {
			return nil, err
		}
		obj["disabled"] = false // simulate CPA host dropping the disabled flag
		raw, _ := json.MarshalIndent(obj, "", "  ")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, err
		}
		return json.Marshal(pluginapi.HostAuthSaveResponse{Name: name, Path: "/auths/" + name})
	}
	defer func() {
		hostCall = originalHostCall
		authListMu.Lock()
		authListCache = nil
		authListAt = time.Time{}
		authListMu.Unlock()
		authProxyMu.Lock()
		authProxyCache = nil
		authProxyAt = time.Time{}
		authProxyMu.Unlock()
	}()

	readObj := func() map[string]any {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		obj := map[string]any{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		return obj
	}

	a := authFile{Name: name, Raw: map[string]any{"type": "xai", "email": "test@x", "access_token": "tok", "disabled": false}}
	if err := setAuthProxyAndFlags(a, "http://127.0.0.1:7951", true, "egress-guard account-manual: 测试禁用"); err != nil {
		t.Fatal(err)
	}
	obj := readObj()
	if obj["disabled"] != true {
		t.Fatalf("file disabled=%v, want true", obj["disabled"])
	}
	if obj["proxy_url"] != "http://127.0.0.1:7951" {
		t.Fatalf("proxy_url=%v", obj["proxy_url"])
	}
	if !strings.Contains(fmt.Sprint(obj["disabled_reason"]), "account-manual") {
		t.Fatalf("reason=%v", obj["disabled_reason"])
	}

	// Enable back: disabled=false, reason cleared.
	if err := setAuthProxyAndFlags(a, "http://127.0.0.1:7951", false, ""); err != nil {
		t.Fatal(err)
	}
	obj = readObj()
	if obj["disabled"] != false {
		t.Fatalf("file disabled after enable=%v, want false", obj["disabled"])
	}
	if _, ok := obj["disabled_reason"]; ok {
		t.Fatalf("disabled_reason not cleared after enable: %#v", obj)
	}
}

func TestShouldAutoDisableAuth(t *testing.T) {
	pol := defaultPolicy()
	pol.AuthAutoDisable = true
	mk := func(hits int) *authDegradeRecord {
		return &authDegradeRecord{AuthID: "a@x", DegradedCount: int64(hits), SampleCount: int64(hits)}
	}
	if shouldAutoDisableAuth(mk(0), pol) {
		t.Fatal("no degrade must not trigger")
	}
	if !shouldAutoDisableAuth(mk(1), pol) {
		t.Fatal("first missing-thinking degrade must trigger immediately")
	}
	disabled := mk(1)
	disabled.DisabledByPlugin = true
	if shouldAutoDisableAuth(disabled, pol) {
		t.Fatal("already-disabled account must not re-trigger")
	}
	if shouldAutoDisableAuth(nil, pol) {
		t.Fatal("nil record must not trigger")
	}
	pol.AuthAutoDisable = false
	if shouldAutoDisableAuth(mk(1), pol) {
		t.Fatal("policy disabled must not trigger")
	}
}

func TestPublicAuthDegradeRecordEnriches(t *testing.T) {
	pol := defaultPolicy()
	rec := &authDegradeRecord{AuthID: "a@x", DegradedCount: 8, SampleCount: 8}
	pub := publicAuthDegradeRecord(rec, pol)
	if pub["auto_disable_eligible"] != true {
		t.Fatal("any degraded account must be eligible with immediate-disable semantics")
	}
	if _, ok := pub["auto_disable_progress"]; ok {
		t.Fatal("auto_disable_progress must be gone")
	}
	clean := &authDegradeRecord{AuthID: "b@x"}
	if publicAuthDegradeRecord(clean, pol)["auto_disable_eligible"] != false {
		t.Fatal("clean account must not be eligible")
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
	// Passive missing-thinking immediately counts as degrade for the audited account.
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

	// Another account's healthy sample stays independent of heidi@x.
	crossOK := qualityResult{
		Classification: "healthy",
		HasThinking:    true,
		OutputTokens:   80,
		TPS:            20,
		AuthID:         "probe@x",
		AuthLabel:      "probe@x",
	}
	applyObservation(store, node.ID, "passive", crossOK)
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

func TestApplyObservationTransportHardDoesNotCountAuthDegrade(t *testing.T) {
	store := newStateStore(filepath.Join(t.TempDir(), "state.json"))
	// Keep a second healthy node so quarantine is not suppressed by "last healthy exit".
	node, err := store.createNode("jp-unstable", "http://127.0.0.1:7951", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("backup", "http://127.0.0.1:7952", true, false, 10); err != nil {
		t.Fatal(err)
	}

	// TLS / EOF style probe failure: node is hard-isolated, but account stats stay clean.
	unstable := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		AuthID:         "AlexChang925085@outlook.com",
		AuthLabel:      "AlexChang925085@outlook.com",
		Error:          `断流不稳定 (Post "https://cli-chat-proxy.grok.com/v1/chat/completions": net/http: TLS handsh…)`,
		ErrorKind:      "probe_unstable",
	}
	applyObservation(store, node.ID, "active", unstable)
	if items := store.listAuthDegradeStats(); len(items) != 0 {
		t.Fatalf("probe_unstable must not create account 降智 samples: %+v", items)
	}
	got, _ := store.getNode(node.ID)
	if got == nil || !got.DisabledByGuard {
		t.Fatalf("probe_unstable should still quarantine the node: %+v", got)
	}
	if !strings.Contains(got.LastReason, "断流不稳定") && !strings.Contains(got.LastReason, "TLS") {
		t.Fatalf("node last reason should keep unstable text: %q", got.LastReason)
	}
	if got.DegradedObsCount < 1 {
		t.Fatalf("node degraded obs should still increment for transport hard: %+v", got)
	}

	// Timeout is likewise node-side, not account 降智.
	timeoutNode, err := store.createNode("timeout-leaf", "http://127.0.0.1:7953", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	timeout := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		AuthID:         "timeout-user@x",
		AuthLabel:      "timeout-user@x",
		Error:          "探测超时（按降智处理）",
		ErrorKind:      "probe_timeout",
	}
	applyObservation(store, timeoutNode.ID, "active", timeout)
	if items := store.listAuthDegradeStats(); len(items) != 0 {
		t.Fatalf("probe_timeout must not create account 降智 samples: %+v", items)
	}

	// Real missing-thinking still attributes to the account.
	thinkNode, err := store.createNode("think-leaf", "http://127.0.0.1:7954", true, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	missing := qualityResult{
		Classification: "hard",
		HasThinking:    false,
		OutputTokens:   40,
		TPS:            12,
		AuthID:         "real-degrade@x",
		AuthLabel:      "real-degrade@x",
		Error:          missingThinkingReason,
		ErrorKind:      "missing_thinking",
	}
	applyObservation(store, thinkNode.ID, "passive", missing)
	items := store.listAuthDegradeStats()
	if len(items) != 1 || items[0].AuthID != "real-degrade@x" || items[0].DegradedCount != 1 {
		t.Fatalf("missing_thinking must still count as account degrade: %+v", items)
	}
}

func TestIsNodeTransportHard(t *testing.T) {
	if !isNodeTransportHard("probe_unstable") || !isNodeTransportHard("probe_timeout") || !isNodeTransportHard("transport_error") {
		t.Fatal("expected transport hard kinds")
	}
	if isNodeTransportHard("missing_thinking") || isNodeTransportHard("") || isNodeTransportHard("no_output") {
		t.Fatal("quality kinds must not be treated as transport hard")
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

func TestAuthDisableEnableDisabledEndpoints(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	auths := map[string]map[string]any{
		"a1.json": {"type": "xai", "email": "a1@x", "access_token": "t1", "disabled": false},
		"a2.json": {"type": "xai", "email": "a2@x", "access_token": "t2", "disabled": false},
		"op.json": {"type": "xai", "email": "op@x", "access_token": "t3", "disabled": true, "disabled_reason": "operator maintenance"},
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
		authListMu.Lock()
		authListCache = nil
		authListAt = time.Time{}
		authListMu.Unlock()
	}()

	decodeResp := func(raw []byte) (int, []byte) {
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		var resp managementResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Body
	}
	dispatch := func(method, path string, body json.RawMessage) []byte {
		t.Helper()
		raw, err := dispatchAPI(method, path, nil, body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	asMap := func(body []byte) map[string]any {
		out := map[string]any{}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Seed one degrade sample so a1 shows up and is eligible for a manual disable.
	store.recordAuthObservation("a1.json", "a1@x", "passive", "n1", "n1", "hard", "响应缺少 thinking_content（降智）", 5, true)

	// Disable a1 via the panel endpoint.
	status, body := decodeResp(dispatch(http.MethodPost, "/auth-stats/disable", json.RawMessage(`{"ids":["a1.json"]}`)))
	if status != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", status, body)
	}
	res := asMap(body)
	if res["disabled"] != float64(1) {
		t.Fatalf("disable result=%s", body)
	}
	if disabled, _ := auths["a1.json"]["disabled"].(bool); !disabled {
		t.Fatal("a1 not disabled on host after endpoint")
	}
	reason, _ := auths["a1.json"]["disabled_reason"].(string)
	if !strings.Contains(reason, "account-manual") {
		t.Fatalf("reason=%q, want account-manual tag", reason)
	}
	if rec := store.getAuthDegradeRecord("a1.json"); rec == nil || !rec.DisabledByPlugin {
		t.Fatalf("mirror not marked disabled: %+v", rec)
	}

	// Disabled list reflects host state with manual source.
	status, body = decodeResp(dispatch(http.MethodGet, "/auth-stats/disabled", nil))
	if status != http.StatusOK {
		t.Fatalf("disabled list status=%d body=%s", status, body)
	}
	res = asMap(body)
	items, _ := res["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("disabled list items=%d body=%s", len(items), body)
	}
	first := items[0].(map[string]any)
	if first["auth_id"] != "a1.json" || first["disabled_source"] != "manual" {
		t.Fatalf("disabled item=%#v", first)
	}

	// Restore a1 (resets its degrade stats by default).
	status, body = decodeResp(dispatch(http.MethodPost, "/auth-stats/enable", json.RawMessage(`{"ids":["a1.json"]}`)))
	if status != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", status, body)
	}
	res = asMap(body)
	if res["enabled"] != float64(1) {
		t.Fatalf("enable result=%s", body)
	}
	if disabled, _ := auths["a1.json"]["disabled"].(bool); disabled {
		t.Fatal("a1 still disabled on host after restore")
	}
	if _, ok := auths["a1.json"]["disabled_reason"]; ok {
		t.Fatal("a1 disabled_reason not cleared on restore")
	}
	if store.getAuthDegradeRecord("a1.json") != nil {
		t.Fatal("restore should reset degrade stats for a1")
	}

	// Operator-disabled account must refuse restore.
	status, body = decodeResp(dispatch(http.MethodPost, "/auth-stats/enable", json.RawMessage(`{"ids":["op.json"]}`)))
	if status != http.StatusOK {
		t.Fatalf("operator-enable status=%d body=%s", status, body)
	}
	res = asMap(body)
	if res["enabled"] != float64(0) {
		t.Fatalf("operator account must not be re-enabled: %s", body)
	}
	opItems, _ := res["items"].([]any)
	if len(opItems) != 1 {
		t.Fatalf("operator items=%d body=%s", len(opItems), body)
	}
	if _, hasErr := opItems[0].(map[string]any)["error"]; !hasErr {
		t.Fatalf("operator item missing error: %s", body)
	}
	if disabled, _ := auths["op.json"]["disabled"].(bool); !disabled {
		t.Fatal("operator account was re-enabled")
	}
}


func TestPolicySaveSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	pol := s.policy()
	pol.AuthAutoDisable = false
	pol.NodeAutoDisable = false
	pol.NodeAutoDisableMinQuarantines = 7
	if err := s.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	s2 := newStateStore(path)
	got := s2.policy()
	if got.AuthAutoDisable || got.NodeAutoDisable {
		t.Fatalf("bool flags force-reset to defaults: auth=%v node=%v", got.AuthAutoDisable, got.NodeAutoDisable)
	}
	if got.NodeAutoDisableMinQuarantines != 7 {
		t.Fatalf("node threshold lost: %d", got.NodeAutoDisableMinQuarantines)
	}
}

func TestSwitchClashAwaySkipsNonActiveLeaf(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	currentConfig.Store(pluginConfig{ClashEnabled: true, ClashAPIURL: "http://127.0.0.1:9", ClashGroup: "g"})
	// Without a real Clash client, switchClashAwayFromNode returns error from getClashClient
	// when enabled but unreachable — build two nodes and mark only B active in store,
	// then call with A and expect either skip (if client works) or client error without
	// mutating active marks when client fails before switch.
	a, err := store.createNode("a", "http://127.0.0.1:1", true, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.createNode("b", "http://127.0.0.1:1", true, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.updateNode(a.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "node-a"
		n.ClashGroup = "g"
		n.ClashActive = false
		return nil
	})
	_, _ = store.updateNode(b.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "node-b"
		n.ClashGroup = "g"
		n.ClashActive = true
		return nil
	})
	// Disable clash so getClashClient fails fast; switchAway should return err and
	// must not clear B's active mark.
	currentConfig.Store(pluginConfig{ClashEnabled: false})
	_ = switchClashAwayFromNode(store, func() *nodeRecord { n, _ := store.getNode(a.ID); return n }())
	b2, _ := store.getNode(b.ID)
	if !b2.ClashActive {
		t.Fatal("non-active quarantine path must not clear current active mark")
	}
}

func TestEnsureHealthyDoesNotPromoteWhenActiveHealthy(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	currentConfig.Store(pluginConfig{ClashEnabled: false})
	a, err := store.createNode("keep-me", "http://127.0.0.1:1", true, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.updateNode(a.ID, func(n *nodeRecord) error {
		n.Source = nodeSourceClash
		n.ClashName = "keep-me"
		n.ClashActive = true
		n.Enabled = true
		n.DisabledByGuard = false
		return nil
	})
	// Second healthy leaf that old code would promote when activeID empty / random order.
	if _, err := store.createNode("other", "http://127.0.0.1:2", true, true, 0); err != nil {
		t.Fatal(err)
	}
	ok, err := ensureHealthyClashExit(store)
	// Clash disabled → cannot read live selection; with active mark healthy should still return true
	// without switching (getClashClient fails only in reconcile path which is ignored).
	if err != nil && !ok {
		// acceptable when client required; ensure it did not flip active off
	}
	a2, _ := store.getNode(a.ID)
	if !a2.ClashActive || !a2.Enabled {
		t.Fatalf("healthy active leaf must remain: %+v err=%v ok=%v", a2, err, ok)
	}
}


func TestOperatorDisablePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newStateStore(path)
	n, err := s.createNode("leaf-a", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.setBatchEnabled([]string{n.ID}, false); err != nil {
		t.Fatal(err)
	}
	got, ok := s.getNode(n.ID)
	if !ok || got.Enabled || !got.DisabledByOperator {
		t.Fatalf("disable not durable in memory: %+v", got)
	}
	s2 := newStateStore(path)
	got2, ok := s2.getNode(n.ID)
	if !ok || got2.Enabled || !got2.DisabledByOperator {
		t.Fatalf("disable lost after reload: %+v", got2)
	}
	if err := s2.setBatchEnabled([]string{n.ID}, true); err != nil {
		t.Fatal(err)
	}
	s3 := newStateStore(path)
	got3, ok := s3.getNode(n.ID)
	if !ok || !got3.Enabled || got3.DisabledByOperator {
		t.Fatalf("enable not durable: %+v", got3)
	}
}

func TestMaybeAutoDisableNodeAfterRepeatedQuarantine(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	pol := store.policy()
	pol.MinHealthyNodes = 1
	pol.NodeAutoDisable = true
	pol.NodeAutoDisableMinQuarantines = 3
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	a, err := store.createNode("a", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("b", "http://127.0.0.1:7952", true, false, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = restoreQuarantinedNode(store, a.ID)
		if _, err := quarantineNodeOpts(store, a.ID, fmt.Sprintf("hard-degrade-%d", i+1), 0, "hard", true); err != nil {
			t.Fatalf("quarantine %d: %v", i+1, err)
		}
	}
	got, ok := store.getNode(a.ID)
	if !ok || !got.DisabledByOperator || got.Enabled {
		t.Fatalf("expected auto permanent disable: %+v", got)
	}
	if got.DisabledSource != "auto" {
		t.Fatalf("source=%q", got.DisabledSource)
	}
}

// Failed recovery while still isolated must bump quarantine_count and auto-stop
// without an artificial restore between cycles (the production bug: timer-only refresh).
func TestFailedRecoveryWhileIsolatedAutoDisables(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	pol := store.policy()
	pol.MinHealthyNodes = 1
	pol.NodeAutoDisable = true
	pol.NodeAutoDisableMinQuarantines = 3
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	a, err := store.createNode("bad-leaf", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("healthy-leaf", "http://127.0.0.1:7952", true, false, 0); err != nil {
		t.Fatal(err)
	}

	// Cycle 1: first isolation.
	if _, err := quarantineNodeOpts(store, a.ID, "hard-1", 0, "hard", true); err != nil {
		t.Fatal(err)
	}
	got, _ := store.getNode(a.ID)
	if !got.DisabledByGuard || got.QuarantineCount != 1 || got.DisabledByOperator {
		t.Fatalf("after first quarantine: %+v", got)
	}
	startAt := got.LastQuarantinedAt
	if startAt <= 0 {
		t.Fatalf("LastQuarantinedAt should be set: %+v", got)
	}

	// Cycles 2-3: still isolated, recovery-style hard observations (no restore).
	hard := qualityResult{
		Classification: "hard",
		TPS:            1.2,
		OutputTokens:   10,
		DurationMs:     5000,
		HasThinking:    false,
		ErrorKind:      "missing_thinking",
		Error:          missingThinkingReason,
	}
	applyObservation(store, a.ID, "recovery", hard)
	got, _ = store.getNode(a.ID)
	if got.QuarantineCount != 2 {
		t.Fatalf("failed recovery should bump quarantine_count to 2, got %+v", got)
	}
	if got.LastQuarantinedAt != startAt {
		t.Fatalf("continuous stint must keep LastQuarantinedAt: start=%v got=%v", startAt, got.LastQuarantinedAt)
	}
	if got.DisabledByOperator {
		t.Fatalf("threshold is 3; should not auto-disable yet: %+v", got)
	}

	applyObservation(store, a.ID, "recovery", hard)
	got, _ = store.getNode(a.ID)
	if got.QuarantineCount < 3 {
		t.Fatalf("second failed recovery should reach count>=3, got %+v", got)
	}
	if !got.DisabledByOperator || got.Enabled {
		t.Fatalf("expected auto permanent disable after failed recoveries: %+v", got)
	}
	if got.DisabledSource != "auto" {
		t.Fatalf("source=%q want auto", got.DisabledSource)
	}
	if got.QuarantinedUntil != 0 {
		t.Fatalf("auto-disable must clear recovery timer, quarantined_until=%v", got.QuarantinedUntil)
	}
}

func TestQuarantineExtendBumpsCountWithoutResettingStart(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	pol := store.policy()
	pol.MinHealthyNodes = 1
	pol.NodeAutoDisable = false // isolate counting from auto-stop side effects
	if err := store.updatePolicy(pol); err != nil {
		t.Fatal(err)
	}
	a, err := store.createNode("n", "http://127.0.0.1:7951", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("other", "http://127.0.0.1:7952", true, false, 0); err != nil {
		t.Fatal(err)
	}
	first, err := quarantineNodeOpts(store, a.ID, "first", 0, "hard", true)
	if err != nil {
		t.Fatal(err)
	}
	start := first.LastQuarantinedAt
	second, err := quarantineNodeOpts(store, a.ID, "extend", 0, "hard", true)
	if err != nil {
		t.Fatal(err)
	}
	if second.QuarantineCount != 2 {
		t.Fatalf("re-quarantine while isolated should count cycle 2, got %+v", second)
	}
	if second.LastQuarantinedAt != start {
		t.Fatalf("LastQuarantinedAt must stay %v, got %v", start, second.LastQuarantinedAt)
	}
	if second.LastReason != "extend" {
		t.Fatalf("reason not refreshed: %+v", second)
	}
}


func TestReconfigureKeepsStoreWhenStateFileUnchanged(t *testing.T) {
	originalHostCall := hostCall
	hostCall = func(method string, payload []byte) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return json.Marshal(hostAuthListResponse{Files: []pluginapi.HostAuthFileEntry{}})
		default:
			return nil, fmt.Errorf("unexpected host callback %s", method)
		}
	}
	defer func() {
		hostCall = originalHostCall
		if workerCancel != nil {
			workerCancel()
			workerCancel = nil
		}
		store = nil
	}()

	stateFile := filepath.Join(t.TempDir(), "state.json")
	yamlCfg := "state_file: " + stateFile + "\n"
	// ConfigYAML 是 []byte 字段,JSON 载荷中按 base64 传递(与 CPA host 一致)。
	raw := []byte(`{"config_yaml": "` + base64.StdEncoding.EncodeToString([]byte(yamlCfg)) + `"}`)

	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	first := store
	if first == nil {
		t.Fatal("store not created by first configure")
	}
	first.appendEvent(guardEvent{Event: "keep_me", TS: 1})

	// CPA 在 auth 文件写入(自动刷新/导入)时频繁触发 reconfigure。
	// state_file 未变时重建 store,会让运行中的探测记账写进旧 store,
	// 随后被新 store 的周期持久化覆盖(记账/事件/统计丢失)。
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("store nil after reconfigure")
	}
	if store != first {
		t.Fatal("reconfigure with unchanged state_file must keep the same store instance")
	}
	found := false
	for _, e := range store.events() {
		if e.Event == "keep_me" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("event written before reconfigure was lost")
	}
}

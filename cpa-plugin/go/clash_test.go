package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestClashInfoAndGroupFilters(t *testing.T) {
	if !isClashInfoNode("DIRECT") || !isClashInfoNode("Traffic: 10GB") {
		t.Fatal("info/special nodes must be filtered")
	}
	if isClashInfoNode("[mesl]🇸🇬 新加坡 01") {
		t.Fatal("real leaf should not be treated as info")
	}
	if !isClashGroupType("Fallback") || isClashGroupType("Shadowsocks") {
		t.Fatal("group type detection failed")
	}
}

func TestClashClientSwitchAndList(t *testing.T) {
	current := "[花云]🇸🇬 新加坡标准 IEPL 专线 7"
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": true, "version": "v1.19.29"})
	})
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies" {
			// fallthrough to more specific handler via trailing path in ServeMux is exact;
			// keep list handler only for exact /proxies
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proxies": map[string]any{
				"🏜️ PerfectAI": map[string]any{
					"name": "🏜️ PerfectAI",
					"type": "Fallback",
					"now":  current,
					"all": []string{
						"DIRECT",
						"Traffic: 1GB",
						"[mesl]🇸🇬 新加坡 01",
						"[花云]🇸🇬 新加坡标准 IEPL 专线 7",
						"⚡ 自动选择",
					},
				},
				"[mesl]🇸🇬 新加坡 01": map[string]any{
					"name": "[mesl]🇸🇬 新加坡 01", "type": "Shadowsocks",
				},
				"[花云]🇸🇬 新加坡标准 IEPL 专线 7": map[string]any{
					"name": "[花云]🇸🇬 新加坡标准 IEPL 专线 7", "type": "Shadowsocks",
				},
				"⚡ 自动选择": map[string]any{
					"name": "⚡ 自动选择", "type": "URLTest", "all": []string{"a", "b"},
				},
			},
		})
	})
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			current = body["name"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "🏜️ PerfectAI",
			"type": "Fallback",
			"now":  current,
			"all":  []string{"[mesl]🇸🇬 新加坡 01", "[花云]🇸🇬 新加坡标准 IEPL 专线 7"},
		})
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := newClashClient(clashRuntimeConfig{
		Enabled:          true,
		APIURL:           server.URL,
		Secret:           "123",
		Group:            "🏜️ PerfectAI",
		CloseConnections: true,
		TimeoutSec:       5,
	})
	if err != nil {
		t.Fatal(err)
	}
	all, err := client.listProxies()
	if err != nil {
		t.Fatal(err)
	}
	leaves := client.leafCandidates("🏜️ PerfectAI", all)
	if len(leaves) != 2 {
		t.Fatalf("leaves=%v, want 2 real ss nodes (exclude DIRECT/info/URLTest)", leaves)
	}
	after, err := client.switchTo("[mesl]🇸🇬 新加坡 01")
	if err != nil {
		t.Fatal(err)
	}
	if after != "[mesl]🇸🇬 新加坡 01" {
		t.Fatalf("after=%q", after)
	}
}

func TestSyncClashNodesCreatesSharedProxyNodes(t *testing.T) {
	current := "node-a"
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "test"})
	})
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proxies": map[string]any{
				"🏜️ PerfectAI": map[string]any{
					"type": "Fallback", "now": current,
					"all": []string{"node-a", "node-b", "DIRECT"},
				},
				"node-a": map[string]any{"type": "Shadowsocks"},
				"node-b": map[string]any{"type": "Shadowsocks"},
			},
		})
	})
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			current = body["name"]
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "Fallback", "now": current, "all": []string{"node-a", "node-b"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	currentConfig.Store(pluginConfig{
		ClashEnabled:  true,
		ClashAPIURL:   server.URL,
		ClashGroup:    "🏜️ PerfectAI",
		ClashProxyURL: "http://172.19.0.1:7890",
		ClashSecret:   "x",
	})
	clashMu.Lock()
	clashCached = nil
	clashCfgSnap = clashRuntimeConfig{}
	clashMu.Unlock()

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	result, err := syncClashNodes(store)
	if err != nil {
		t.Fatal(err)
	}
	if result["created"].(int) != 2 {
		t.Fatalf("created=%v", result["created"])
	}
	nodes := store.listNodes()
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d", len(nodes))
	}
	for _, n := range nodes {
		if n.Source != nodeSourceClash || n.ProxyURL != "http://172.19.0.1:7890" || n.ClashGroup == "" {
			t.Fatalf("node not clash-shaped: %+v", n)
		}
	}
	active := 0
	for _, n := range nodes {
		if n.ClashActive {
			active++
			if n.ClashName != "node-a" {
				t.Fatalf("active=%s", n.ClashName)
			}
		}
	}
	if active != 1 {
		t.Fatalf("active count=%d", active)
	}

	var bad *nodeRecord
	for _, n := range nodes {
		if n.ClashName == "node-a" {
			cp := *n
			bad = &cp
		}
	}
	if bad == nil {
		t.Fatal("missing node-a")
	}
	// mark the other as healthy migration target
	for _, n := range nodes {
		if n.ClashName == "node-b" {
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				node.LastClassification = "healthy"
				node.LastObservedAt = 1e12
				node.ExitIP = "198.51.100.2"
				return nil
			})
		}
	}
	_, _ = store.updateNode(bad.ID, func(node *nodeRecord) error {
		node.ExitIP = "198.51.100.1"
		return nil
	})

	if err := switchClashAwayFromNode(store, bad); err != nil {
		t.Fatal(err)
	}
	if current != "node-b" {
		t.Fatalf("clash current=%s want node-b", current)
	}
}

func TestClashUIConfigOverridesRuntime(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	currentConfig.Store(pluginConfig{
		ClashEnabled:  true,
		ClashAPIURL:   "http://yaml.example:7888",
		ClashGroup:    "YAML-Group",
		ClashProxyURL: "http://yaml.example:7890",
		ClashSecret:   "yaml-secret",
	})
	clashMu.Lock()
	clashCached = nil
	clashCfgSnap = clashRuntimeConfig{}
	clashMu.Unlock()

	enabled := true
	_, err := store.updateClashUI(clashUIConfig{
		Enabled:  &enabled,
		APIURL:   "http://panel.example:9090",
		Group:    "🏜️ PerfectAI",
		ProxyURL: "http://panel.example:7890",
		Secret:   "panel-secret",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadClashRuntimeConfig()
	if cfg.APIURL != "http://panel.example:9090" || cfg.Group != "🏜️ PerfectAI" || cfg.ProxyURL != "http://panel.example:7890" || cfg.Secret != "panel-secret" {
		t.Fatalf("panel override not applied: %+v", cfg)
	}

	off := false
	if _, err := store.updateClashUI(clashUIConfig{Enabled: &off}, false); err != nil {
		t.Fatal(err)
	}
	cfg = loadClashRuntimeConfig()
	if cfg.Enabled {
		t.Fatal("panel enabled=false must disable runtime")
	}
}

func TestEnsureHealthyClashExitSwitchesOffQuarantined(t *testing.T) {
	current := "node-a"
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "test"})
	})
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proxies": map[string]any{
				"🏜️ PerfectAI": map[string]any{
					"type": "Fallback", "now": current,
					"all": []string{"node-a", "node-b"},
				},
				"node-a": map[string]any{"type": "Shadowsocks"},
				"node-b": map[string]any{"type": "Shadowsocks"},
			},
		})
	})
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			current = body["name"]
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "Fallback", "now": current, "all": []string{"node-a", "node-b"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	currentConfig.Store(pluginConfig{
		ClashEnabled:  true,
		ClashAPIURL:   server.URL,
		ClashGroup:    "🏜️ PerfectAI",
		ClashProxyURL: "http://172.19.0.1:7890",
		ClashSecret:   "x",
	})
	clashMu.Lock()
	clashCached = nil
	clashCfgSnap = clashRuntimeConfig{}
	clashMu.Unlock()

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	if _, err := syncClashNodes(store); err != nil {
		t.Fatal(err)
	}
	var badID string
	for _, n := range store.listNodes() {
		if n.ClashName == "node-a" {
			badID = n.ID
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				node.DisabledByGuard = true
				node.ClashActive = true
				return nil
			})
		}
		if n.ClashName == "node-b" {
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				node.LastClassification = "healthy"
				node.LastObservedAt = 1e12
				node.ExitIP = "198.51.100.2"
				node.ClashActive = false
				return nil
			})
		}
	}
	if badID == "" {
		t.Fatal("missing node-a")
	}
	ok, err := ensureHealthyClashExit(store)
	if err != nil || !ok {
		t.Fatalf("ensureHealthyClashExit ok=%v err=%v", ok, err)
	}
	if current != "node-b" {
		t.Fatalf("current=%s want node-b", current)
	}
}

func TestManualQuarantineAndRestore(t *testing.T) {
	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	// Two healthy nodes so automatic quarantine wouldn't be suppressed either;
	// force path must still work with min_healthy_nodes.
	a, err := store.createNode("a", "http://127.0.0.1:1", true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createNode("b", "http://127.0.0.1:2", true, false, 0); err != nil {
		t.Fatal(err)
	}
	_ = store.updatePolicy(func() policyConfig {
		p := store.policy()
		p.MinHealthyNodes = 2
		return p
	}())

	// Without force, quarantine is suppressed when only one other healthy remains...
	// With two other? We have a+b, quarantining a leaves 1 healthy < 2 → suppressed.
	quarantineNode(store, a.ID, "auto", 0, "hard")
	if n, _ := store.getNode(a.ID); n.DisabledByGuard {
		t.Fatal("auto quarantine should be suppressed by min healthy")
	}

	updated, err := manualQuarantineNode(store, a.ID, "人工降智隔离")
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || !updated.DisabledByGuard {
		t.Fatalf("manual quarantine failed: %+v", updated)
	}

	restored, err := restoreQuarantinedNode(store, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.DisabledByGuard {
		t.Fatal("restore should clear guard isolation")
	}
}

func TestSchedulerHandsBackSelectionWhenActiveQuarantined(t *testing.T) {
	current := "node-a"
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "test"})
	})
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proxies": map[string]any{
				"🏜️ PerfectAI": map[string]any{"type": "Fallback", "now": current, "all": []string{"node-a", "node-b"}},
				"node-a":       map[string]any{"type": "Shadowsocks"},
				"node-b":       map[string]any{"type": "Shadowsocks"},
			},
		})
	})
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			current = body["name"]
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "Fallback", "now": current, "all": []string{"node-a", "node-b"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	currentConfig.Store(pluginConfig{
		ClashEnabled: true, ClashAPIURL: server.URL, ClashGroup: "🏜️ PerfectAI",
		ClashProxyURL: "http://172.19.0.1:7890", ClashSecret: "x",
	})
	clashMu.Lock()
	clashCached = nil
	clashCfgSnap = clashRuntimeConfig{}
	clashMu.Unlock()

	store = newStateStore(filepath.Join(t.TempDir(), "state.json"))
	if _, err := syncClashNodes(store); err != nil {
		t.Fatal(err)
	}
	shared := "http://172.19.0.1:7890"
	for _, n := range store.listNodes() {
		if n.ClashName == "node-a" {
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				node.DisabledByGuard = true
				node.ClashActive = true
				return nil
			})
		}
		if n.ClashName == "node-b" {
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				node.LastClassification = "healthy"
				node.LastObservedAt = 1e12
				node.ExitIP = "198.51.100.9"
				node.ClashActive = false
				return nil
			})
		}
	}
	authProxyMu.Lock()
	authProxyCache = map[string]string{"auth-1": shared}
	authProxyAt = time.Now()
	authProxyMu.Unlock()

	rawRequest, _ := json.Marshal(pluginapi.SchedulerPickRequest{
		Provider:   "xai",
		Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "auth-1", Provider: "xai"}},
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
		t.Fatalf("expected selection handed back to host (Handled=false), got %+v", response)
	}
	if current != "node-a" {
		t.Fatalf("scheduler pick must not force-switch production, current=%s", current)
	}
}

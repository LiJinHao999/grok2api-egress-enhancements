package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	nodeSourceManual = "manual"
	nodeSourceClash  = "clash"
)

var (
	clashSpecialNames = map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "PASS": {}, "COMPATIBLE": {},
	}
	clashInfoPrefixes = []string{"Traffic:", "Expire:", "流量", "到期", "剩余", "套餐", "官网", "更新"}
	clashGroupTypes   = map[string]struct{}{
		"Selector": {}, "URLTest": {}, "Fallback": {}, "LoadBalance": {}, "Relay": {},
	}
)

type clashRuntimeConfig struct {
	Enabled    bool
	APIURL     string
	Secret     string
	UnixSocket string
	Group      string
	ProxyURL   string
	// TestGroup/TestProxyURL isolate quality probes from production traffic.
	TestGroup        string
	TestProxyURL     string
	CloseConnections bool
	SyncOnStart      bool
	ExcludeKeywords  []string
	PreferKeywords   []string
	TimeoutSec       int
}

type clashClient struct {
	cfg    clashRuntimeConfig
	client *http.Client
	base   string
}

type clashProxyInfo struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	History []struct {
		Delay int `json:"delay"`
	} `json:"history"`
	Alive bool `json:"alive"`
}

var (
	clashMu      sync.Mutex
	clashCached  *clashClient
	clashCfgSnap clashRuntimeConfig
)

func loadClashRuntimeConfig() clashRuntimeConfig {
	value := currentConfig.Load()
	if value == nil {
		return clashRuntimeConfig{}
	}
	cfg, ok := value.(pluginConfig)
	if !ok {
		return clashRuntimeConfig{}
	}
	out := clashRuntimeConfig{
		Enabled:          cfg.ClashEnabled,
		APIURL:           strings.TrimSpace(cfg.ClashAPIURL),
		UnixSocket:       strings.TrimSpace(cfg.ClashUnixSocket),
		Group:            strings.TrimSpace(cfg.ClashGroup),
		ProxyURL:         strings.TrimSpace(cfg.ClashProxyURL),
		TestGroup:        strings.TrimSpace(cfg.ClashTestGroup),
		TestProxyURL:     strings.TrimSpace(cfg.ClashTestProxyURL),
		CloseConnections: cfg.ClashCloseConnections,
		SyncOnStart:      cfg.ClashSyncOnStart,
		ExcludeKeywords:  append([]string{}, cfg.ClashExcludeKeywords...),
		PreferKeywords:   append([]string{}, cfg.ClashPreferKeywords...),
		TimeoutSec:       cfg.ClashTimeoutSec,
	}

	// Panel overrides (state.json) win over YAML so friends can pick group /
	// API endpoint without editing host plugin config.
	var ui clashUIConfig
	if store != nil {
		ui = store.clashUI()
	}
	if ui.Enabled != nil {
		out.Enabled = *ui.Enabled
	}
	if v := strings.TrimSpace(ui.APIURL); v != "" {
		out.APIURL = v
		// UI API endpoint implies HTTP controller; clear socket so it is used.
		out.UnixSocket = ""
	}
	if v := strings.TrimSpace(ui.Group); v != "" {
		out.Group = v
	}
	if v := strings.TrimSpace(ui.ProxyURL); v != "" {
		out.ProxyURL = v
	}
	if v := strings.TrimSpace(ui.TestGroup); v != "" {
		out.TestGroup = v
	}
	if v := strings.TrimSpace(ui.TestProxyURL); v != "" {
		out.TestProxyURL = v
	}

	if out.Group == "" {
		out.Group = "🏜️ PerfectAI"
	}
	if out.ProxyURL == "" {
		out.ProxyURL = "http://172.19.0.1:7890"
	}
	if out.TestGroup == "" {
		out.TestGroup = "➖ PerfectAI_TestPort"
	}
	if out.TestProxyURL == "" {
		out.TestProxyURL = "http://172.19.0.1:7953"
	}
	if out.APIURL == "" && out.UnixSocket == "" {
		out.APIURL = "http://172.19.0.1:7888"
	}
	if out.TimeoutSec <= 0 {
		out.TimeoutSec = 8
	}
	secretEnv := strings.TrimSpace(cfg.ClashSecretEnv)
	if secretEnv == "" {
		secretEnv = "CLASH_API_SECRET"
	}
	// Priority: panel secret > env > YAML secret.
	if v := strings.TrimSpace(ui.Secret); v != "" {
		out.Secret = v
	} else if token := strings.TrimSpace(os.Getenv(secretEnv)); token != "" {
		out.Secret = token
	} else {
		out.Secret = strings.TrimSpace(cfg.ClashSecret)
	}
	// Enable when user provided any Clash field, UI override, or explicit flag.
	if out.Enabled || cfg.ClashEnabled || cfg.ClashAPIURL != "" || cfg.ClashUnixSocket != "" || cfg.ClashGroup != "" || cfg.ClashProxyURL != "" || cfg.ClashSecret != "" || cfg.ClashSecretEnv != "" || ui.APIURL != "" || ui.Group != "" || ui.ProxyURL != "" || ui.Secret != "" || ui.Enabled != nil {
		out.Enabled = true
		if ui.Enabled != nil && !*ui.Enabled {
			out.Enabled = false
		}
	}
	return out
}

// publicClashUIConfig redacts secret for API responses while exposing has_secret.
func publicClashUIConfig(ui clashUIConfig, runtime clashRuntimeConfig) map[string]any {
	enabled := runtime.Enabled
	if ui.Enabled != nil {
		enabled = *ui.Enabled
	}
	return map[string]any{
		"enabled":           enabled,
		"api_url":           firstNonEmpty(strings.TrimSpace(ui.APIURL), runtime.APIURL),
		"group":             firstNonEmpty(strings.TrimSpace(ui.Group), runtime.Group),
		"proxy_url":         firstNonEmpty(strings.TrimSpace(ui.ProxyURL), redactProxyURL(runtime.ProxyURL)),
		"test_group":        firstNonEmpty(strings.TrimSpace(ui.TestGroup), runtime.TestGroup),
		"test_proxy_url":    firstNonEmpty(strings.TrimSpace(ui.TestProxyURL), redactProxyURL(runtime.TestProxyURL)),
		"has_secret":        strings.TrimSpace(ui.Secret) != "" || strings.TrimSpace(runtime.Secret) != "",
		"ui_override":       ui.APIURL != "" || ui.Group != "" || ui.ProxyURL != "" || ui.TestGroup != "" || ui.TestProxyURL != "" || ui.Secret != "" || ui.Enabled != nil,
		"updated_at":        ui.UpdatedAt,
		"unix_socket":       runtime.UnixSocket != "",
		"close_connections": runtime.CloseConnections,
	}
}

// listClashGroups returns selector-like proxy groups for the panel dropdown.
func listClashGroups() ([]map[string]any, error) {
	client, err := getClashClient()
	if err != nil {
		return nil, err
	}
	all, err := client.listProxies()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0)
	for name, info := range all {
		if !isClashGroupType(info.Type) {
			continue
		}
		if isClashInfoNode(name) {
			continue
		}
		out = append(out, map[string]any{
			"name": name,
			"type": info.Type,
			"now":  strings.TrimSpace(info.Now),
			"all":  len(info.All),
		})
	}
	cfgGroup := client.cfg.Group
	sort.Slice(out, func(i, j int) bool {
		ai, _ := out[i]["name"].(string)
		aj, _ := out[j]["name"].(string)
		if ai == cfgGroup && aj != cfgGroup {
			return true
		}
		if aj == cfgGroup && ai != cfgGroup {
			return false
		}
		return ai < aj
	})
	return out, nil
}

// ensureHealthyClashExit switches PerfectAI (or configured group) off a
// quarantined/disabled active leaf onto another healthy Clash-sourced node.
// Returns true when a switch happened (or active was already healthy).
func ensureHealthyClashExit(store *stateStore) (bool, error) {
	if store == nil {
		return false, nil
	}
	activeID := activeClashNodeID(store)
	if activeID == "" {
		// No active mark — try to promote any healthy Clash leaf.
		for _, n := range store.listNodes() {
			if n.Source == nodeSourceClash && n.Enabled && !n.DisabledByGuard && n.ClashName != "" {
				if err := ensureClashSelectedForNode(store, n); err != nil {
					return false, err
				}
				queuePostSwitchProbe(store, n, "")
				return true, nil
			}
		}
		return false, fmt.Errorf("没有可用的健康 Clash 出口")
	}
	active, ok := store.getNode(activeID)
	if !ok || active == nil {
		return false, nil
	}
	if active.Enabled && !active.DisabledByGuard {
		return true, nil
	}
	// Active leaf is bad — switch away.
	if err := switchClashAwayFromNode(store, active); err != nil {
		// switchClashAwayFromNode may fail when candidates list is empty or Clash API
		// flaps; fall through to a direct pick of any healthy leaf.
		for _, n := range store.listNodes() {
			if n.Source == nodeSourceClash && n.Enabled && !n.DisabledByGuard && n.ClashName != "" && n.ID != active.ID {
				if err2 := ensureClashSelectedForNode(store, n); err2 == nil {
					queuePostSwitchProbe(store, n, active.Name)
					return true, nil
				}
			}
		}
		return false, err
	}
	return true, nil
}

// queuePostSwitchProbe enqueues an immediate quality check on a newly selected
// production leaf. Shared by quarantine switch and emergency failover paths.
func queuePostSwitchProbe(store *stateStore, chosen *nodeRecord, isolatedName string) {
	if store == nil || chosen == nil || chosen.ID == "" {
		return
	}
	if _, qerr := queueNodeQuality(store, chosen.ID, "post-switch", false); qerr != nil {
		log.Printf("egress-guard: post-switch probe enqueue failed node=%s name=%q err=%v",
			chosen.ID, chosen.Name, qerr)
		return
	}
	reason := fmt.Sprintf("切换后立即复测新出口 %s", chosen.ClashName)
	if isolatedName != "" {
		reason = fmt.Sprintf("隔离 %s 后立即复测新出口 %s", isolatedName, chosen.ClashName)
	}
	store.appendEvent(guardEvent{
		Event:    "post_switch_probe_queued",
		NodeID:   chosen.ID,
		NodeName: chosen.Name,
		Reason:   reason,
	})
	log.Printf("egress-guard: post-switch probe queued node=%s name=%q after isolating %q",
		chosen.ID, chosen.Name, isolatedName)
}

func clashCfgEqual(a, b clashRuntimeConfig) bool {
	return a.Enabled == b.Enabled &&
		a.APIURL == b.APIURL &&
		a.Secret == b.Secret &&
		a.UnixSocket == b.UnixSocket &&
		a.Group == b.Group &&
		a.ProxyURL == b.ProxyURL &&
		a.TestGroup == b.TestGroup &&
		a.TestProxyURL == b.TestProxyURL &&
		a.TimeoutSec == b.TimeoutSec &&
		a.CloseConnections == b.CloseConnections
}

func getClashClient() (*clashClient, error) {
	cfg := loadClashRuntimeConfig()
	if !cfg.Enabled {
		return nil, fmt.Errorf("未启用 Clash 对接")
	}
	if cfg.APIURL == "" && cfg.UnixSocket == "" {
		return nil, fmt.Errorf("未配置 clash_api_url 或 clash_unix_socket")
	}
	clashMu.Lock()
	defer clashMu.Unlock()
	if clashCached != nil && clashCfgEqual(clashCfgSnap, cfg) {
		return clashCached, nil
	}
	client, err := newClashClient(cfg)
	if err != nil {
		return nil, err
	}
	clashCached = client
	clashCfgSnap = cfg
	return client, nil
}

func newClashClient(cfg clashRuntimeConfig) (*clashClient, error) {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       30 * time.Second,
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.APIURL), "/")
	if sock := strings.TrimSpace(cfg.UnixSocket); sock != "" {
		socketPath := sock
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}
		if base == "" {
			base = "http://localhost"
		}
	}
	return &clashClient{
		cfg:    cfg,
		base:   base,
		client: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

func (c *clashClient) do(method, path string, body any) ([]byte, int, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Secret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return raw, resp.StatusCode, fmt.Errorf("Clash API HTTP %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	return raw, resp.StatusCode, nil
}

func (c *clashClient) version() (map[string]any, error) {
	raw, _, err := c.do(http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out, nil
}

func (c *clashClient) listProxies() (map[string]clashProxyInfo, error) {
	raw, _, err := c.do(http.MethodGet, "/proxies", nil)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Proxies map[string]clashProxyInfo `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("解析 /proxies 失败: %w", err)
	}
	if envelope.Proxies == nil {
		envelope.Proxies = map[string]clashProxyInfo{}
	}
	return envelope.Proxies, nil
}

func (c *clashClient) getProxy(name string) (clashProxyInfo, error) {
	path := "/proxies/" + url.PathEscape(name)
	raw, _, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return clashProxyInfo{}, err
	}
	var info clashProxyInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return clashProxyInfo{}, err
	}
	if info.Name == "" {
		info.Name = name
	}
	return info, nil
}

func (c *clashClient) selectProxy(group, node string) error {
	path := "/proxies/" + url.PathEscape(group)
	_, _, err := c.do(http.MethodPut, path, map[string]string{"name": node})
	return err
}

func (c *clashClient) closeConnections() {
	if !c.cfg.CloseConnections {
		return
	}
	_, _, _ = c.do(http.MethodDelete, "/connections", nil)
}

func (c *clashClient) proxyDelay(name string, timeoutMs int) (int, error) {
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	q := url.Values{}
	q.Set("url", "https://www.gstatic.com/generate_204")
	q.Set("timeout", fmt.Sprintf("%d", timeoutMs))
	path := "/proxies/" + url.PathEscape(name) + "/delay?" + q.Encode()
	raw, _, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	var out struct {
		Delay int `json:"delay"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.Delay <= 0 {
		return 0, fmt.Errorf("无延迟数据")
	}
	return out.Delay, nil
}

func isClashInfoNode(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return true
	}
	if _, ok := clashSpecialNames[n]; ok {
		return true
	}
	for _, p := range clashInfoPrefixes {
		if strings.HasPrefix(n, p) || strings.Contains(n, p) {
			return true
		}
	}
	if strings.Contains(n, "GB") && (strings.Contains(n, "|") || strings.Contains(n, "流量")) {
		return true
	}
	return false
}

func isClashGroupType(t string) bool {
	_, ok := clashGroupTypes[t]
	return ok
}

func (c *clashClient) leafCandidates(group string, all map[string]clashProxyInfo) []string {
	info, ok := all[group]
	if !ok {
		var err error
		info, err = c.getProxy(group)
		if err != nil {
			return nil
		}
	}
	out := make([]string, 0, len(info.All))
	seen := map[string]struct{}{}
	for _, name := range info.All {
		n := strings.TrimSpace(name)
		if n == "" || isClashInfoNode(n) {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		meta, hasMeta := all[n]
		if hasMeta && isClashGroupType(meta.Type) {
			continue
		}
		if hasMeta && len(meta.All) > 0 && isClashGroupType(meta.Type) {
			continue
		}
		skip := false
		for _, kw := range c.cfg.ExcludeKeywords {
			if kw != "" && strings.Contains(n, kw) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(c.cfg.PreferKeywords) == 0 {
		return out
	}
	preferred := make([]string, 0, len(out))
	others := make([]string, 0, len(out))
	for _, n := range out {
		hit := false
		for _, kw := range c.cfg.PreferKeywords {
			if kw != "" && strings.Contains(n, kw) {
				hit = true
				break
			}
		}
		if hit {
			preferred = append(preferred, n)
		} else {
			others = append(others, n)
		}
	}
	return append(preferred, others...)
}

func (c *clashClient) currentGroupSelection() (string, error) {
	info, err := c.getProxy(c.cfg.Group)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(info.Now), nil
}

func (c *clashClient) switchTo(node string) (string, error) {
	node = strings.TrimSpace(node)
	if node == "" {
		return "", fmt.Errorf("目标节点为空")
	}
	before, _ := c.currentGroupSelection()
	if err := c.selectProxy(c.cfg.Group, node); err != nil {
		return before, err
	}
	c.closeConnections()
	after, err := c.currentGroupSelection()
	if err != nil {
		return before, err
	}
	if after != node {
		return after, fmt.Errorf("切换后当前节点为 %q，期望 %q", after, node)
	}
	return after, nil
}

func clashStatusPayload() map[string]any {
	cfg := loadClashRuntimeConfig()
	var ui clashUIConfig
	if store != nil {
		ui = store.clashUI()
	}
	out := map[string]any{
		"enabled":           cfg.Enabled,
		"api_url":           cfg.APIURL,
		"unix_socket":       cfg.UnixSocket != "",
		"group":             cfg.Group,
		"proxy_url":         redactProxyURL(cfg.ProxyURL),
		"test_group":        cfg.TestGroup,
		"test_proxy_url":    redactProxyURL(cfg.TestProxyURL),
		"close_connections": cfg.CloseConnections,
		"sync_on_start":     cfg.SyncOnStart,
		"has_secret":        strings.TrimSpace(cfg.Secret) != "",
		"ui_override":       ui.APIURL != "" || ui.Group != "" || ui.ProxyURL != "" || ui.TestGroup != "" || ui.TestProxyURL != "" || ui.Secret != "" || ui.Enabled != nil,
		"config":            publicClashUIConfig(ui, cfg),
	}
	if !cfg.Enabled {
		out["reachable"] = false
		out["message"] = "未启用 Clash 对接"
		return out
	}
	client, err := getClashClient()
	if err != nil {
		out["reachable"] = false
		out["message"] = err.Error()
		return out
	}
	ver, err := client.version()
	if err != nil {
		out["reachable"] = false
		out["message"] = err.Error()
		return out
	}
	out["reachable"] = true
	out["version"] = ver
	now, err := client.currentGroupSelection()
	if err != nil {
		out["message"] = "已连接，但读取策略组失败: " + err.Error()
		return out
	}
	out["now"] = now
	out["message"] = "已连接"
	return out
}

func redactProxyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	return u.String()
}

// syncClashNodes imports PerfectAI (or configured group) leaf proxies as CPA nodes.
// All Clash-sourced nodes share the same local mixed-port proxy URL; the real exit
// is selected by switching the Clash group when that node becomes active / healthy.
func syncClashNodes(store *stateStore) (map[string]any, error) {
	client, err := getClashClient()
	if err != nil {
		return nil, err
	}
	all, err := client.listProxies()
	if err != nil {
		return nil, err
	}
	group := client.cfg.Group
	if _, ok := all[group]; !ok {
		// fuzzy match by suffix / contains
		for name := range all {
			if name == group || strings.Contains(name, group) || strings.HasSuffix(name, group) {
				group = name
				break
			}
		}
	}
	if _, ok := all[group]; !ok {
		return nil, fmt.Errorf("找不到策略组 %q", client.cfg.Group)
	}
	// Keep runtime group name accurate for subsequent switches.
	client.cfg.Group = group

	leaves := client.leafCandidates(group, all)
	if len(leaves) == 0 {
		return nil, fmt.Errorf("策略组 %q 下没有可导入的叶子节点", group)
	}

	nowSel := ""
	if info, ok := all[group]; ok {
		nowSel = strings.TrimSpace(info.Now)
	}

	existing := store.listNodes()
	byClashName := map[string]*nodeRecord{}
	for _, n := range existing {
		if n.Source == nodeSourceClash && n.ClashName != "" {
			byClashName[n.ClashName] = n
		}
	}

	created := 0
	updated := 0
	kept := 0
	proxyURL := client.cfg.ProxyURL
	for _, leaf := range leaves {
		if old, ok := byClashName[leaf]; ok {
			kept++
			_, _ = store.updateNode(old.ID, func(n *nodeRecord) error {
				n.Name = leaf
				n.Source = nodeSourceClash
				n.ClashName = leaf
				n.ClashGroup = group
				if n.ProxyURL == "" {
					n.ProxyURL = proxyURL
				}
				// Keep shared mixed-port URL in sync with config.
				if client.cfg.ProxyURL != "" {
					n.ProxyURL = proxyURL
				}
				n.UpdatedAt = time.Now().UTC()
				return nil
			})
			updated++
			delete(byClashName, leaf)
			continue
		}
		n, err := store.createNode(leaf, proxyURL, true, true, 0)
		if err != nil {
			return nil, fmt.Errorf("创建节点 %q 失败: %w", leaf, err)
		}
		_, err = store.updateNode(n.ID, func(node *nodeRecord) error {
			node.Source = nodeSourceClash
			node.ClashName = leaf
			node.ClashGroup = group
			node.ProxyPool = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		created++
	}

	// Disable Clash-sourced nodes that disappeared from the group (do not delete —
	// preserve quarantine history / assigned counts until operator cleans up).
	disabledMissing := 0
	for _, stale := range byClashName {
		_, _ = store.updateNode(stale.ID, func(n *nodeRecord) error {
			if n.Enabled {
				n.Enabled = false
				disabledMissing++
			}
			n.LastReason = "Clash 策略组中已不存在该节点"
			return nil
		})
	}

	// Mark which node is currently selected in Clash and track service sessions.
	if nowSel != "" {
		nowUnix := float64(time.Now().Unix())
		for _, n := range store.listNodes() {
			if n.Source != nodeSourceClash {
				continue
			}
			active := n.ClashName == nowSel
			_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
				applyClashActiveTransition(node, active, nowUnix)
				return nil
			})
		}
	}

	store.appendEvent(guardEvent{
		Event:  "clash_nodes_synced",
		Reason: fmt.Sprintf("组=%s 叶子=%d 新建=%d 更新=%d 缺失停用=%d 当前=%s", group, len(leaves), created, updated, disabledMissing, nowSel),
	})

	return map[string]any{
		"group":            group,
		"leaf_count":       len(leaves),
		"created":          created,
		"updated":          updated,
		"kept":             kept,
		"disabled_missing": disabledMissing,
		"now":              nowSel,
		"proxy_url":        redactProxyURL(proxyURL),
	}, nil
}

// qualityProbeProxyURL is the proxy quality probes dial. Prefer the dedicated
// test mixed-port so probes never share production :7890 sticky sessions.
func qualityProbeProxyURL(node *nodeRecord) string {
	cfg := loadClashRuntimeConfig()
	if v := strings.TrimSpace(cfg.TestProxyURL); v != "" {
		return v
	}
	if node != nil && strings.TrimSpace(node.ProxyURL) != "" {
		return node.ProxyURL
	}
	return strings.TrimSpace(cfg.ProxyURL)
}

// ensureClashSelectedForQuality switches the TEST selector group to the node
// leaf. Production PerfectAI is never touched. Connections are not bulk-closed.
func ensureClashSelectedForQuality(store *stateStore, node *nodeRecord) (string, error) {
	if node == nil || node.Source != nodeSourceClash || node.ClashName == "" {
		return "", nil
	}
	cfg := loadClashRuntimeConfig()
	group := strings.TrimSpace(cfg.TestGroup)
	if group == "" {
		group = strings.TrimSpace(cfg.Group)
	}
	if group == "" {
		return "", fmt.Errorf("未配置质量探测策略组")
	}
	client, err := getClashClient()
	if err != nil {
		return group, err
	}
	client.cfg.Group = group
	client.cfg.CloseConnections = false

	now, err := client.currentGroupSelection()
	if err != nil {
		return group, err
	}
	if now == node.ClashName {
		if store != nil {
			store.appendEvent(guardEvent{
				Event:    "clash_test_switched",
				NodeID:   node.ID,
				NodeName: node.Name,
				Reason:   fmt.Sprintf("测试组 %s 已在 %s", group, now),
			})
		}
		return group, nil
	}
	after, err := client.switchTo(node.ClashName)
	if err != nil {
		if store != nil {
			store.appendEvent(guardEvent{
				Event:    "clash_test_switch_failed",
				NodeID:   node.ID,
				NodeName: node.Name,
				Reason:   fmt.Sprintf("测试组 %s: %s", group, err.Error()),
			})
		}
		return group, err
	}
	if store != nil {
		store.appendEvent(guardEvent{
			Event:    "clash_test_switched",
			NodeID:   node.ID,
			NodeName: node.Name,
			Reason:   fmt.Sprintf("测试组 %s: %s → %s", group, now, after),
		})
	}
	return group, nil
}

// ensureClashSelectedForNode switches the Clash group to the node's leaf when
// the node is Clash-sourced. Shared mixed-port proxy_url alone is not enough —
// the real exit is whatever PerfectAI currently points to.
func ensureClashSelectedForNode(store *stateStore, node *nodeRecord) error {
	if node == nil || node.Source != nodeSourceClash || node.ClashName == "" {
		return nil
	}
	client, err := getClashClient()
	if err != nil {
		return err
	}
	if node.ClashGroup != "" {
		client.cfg.Group = node.ClashGroup
	}
	now, err := client.currentGroupSelection()
	if err != nil {
		return err
	}
	nowUnix := float64(time.Now().Unix())
	if now == node.ClashName {
		_, _ = store.updateNode(node.ID, func(n *nodeRecord) error {
			applyClashActiveTransition(n, true, nowUnix)
			return nil
		})
		return nil
	}
	after, err := client.switchTo(node.ClashName)
	if err != nil {
		store.appendEvent(guardEvent{
			Event:    "clash_switch_failed",
			NodeID:   node.ID,
			NodeName: node.Name,
			Reason:   err.Error(),
		})
		return err
	}
	for _, n := range store.listNodes() {
		if n.Source != nodeSourceClash {
			continue
		}
		active := n.ClashName == after
		_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
			applyClashActiveTransition(node, active, nowUnix)
			if active {
				node.LastReason = "Clash 已切换到该节点"
			}
			return nil
		})
	}
	store.appendEvent(guardEvent{
		Event:    "clash_switched",
		NodeID:   node.ID,
		NodeName: node.Name,
		Reason:   fmt.Sprintf("%s → %s", now, after),
	})
	return nil
}

// switchClashAwayFromNode is called on quarantine: pick another healthy
// Clash-sourced node and switch PerfectAI to it.
//
// After a successful production switch it immediately enqueues a post-switch
// quality probe on the new leaf. If that probe hard-fails, quarantine runs
// again and chains: A bad → B → probe B → B bad → C → probe C → … until a
// leaf stays healthy or no candidates remain. Probes are serial via the
// quality scheduler so PerfectAI/TestGroup selection stays race-free.
func switchClashAwayFromNode(store *stateStore, bad *nodeRecord) error {
	if bad == nil || bad.Source != nodeSourceClash {
		return nil
	}
	client, err := getClashClient()
	if err != nil {
		return err
	}
	if bad.ClashGroup != "" {
		client.cfg.Group = bad.ClashGroup
	}
	// Prefer recently healthy Clash nodes with different observed exit IP.
	candidates := verifiedMigrationTargets(store, bad)
	var chosen *nodeRecord
	for _, n := range candidates {
		if n.Source == nodeSourceClash && n.ClashName != "" && n.ClashName != bad.ClashName {
			chosen = n
			break
		}
	}
	if chosen == nil {
		// Fall back to any enabled non-quarantined Clash leaf.
		// Unverified leaves are OK: the post-switch probe below will confirm
		// (or chain-quarantine) them immediately instead of leaving production
		// parked on a possibly already-degraded exit until the next 30s tick.
		for _, n := range store.listNodes() {
			if n.ID == bad.ID || n.Source != nodeSourceClash || n.ClashName == "" || !n.Enabled || n.DisabledByGuard {
				continue
			}
			chosen = n
			break
		}
	}
	if chosen == nil {
		return fmt.Errorf("没有可切换的 Clash 健康节点")
	}
	after, err := client.switchTo(chosen.ClashName)
	if err != nil {
		store.appendEvent(guardEvent{
			Event:    "clash_switch_failed",
			NodeID:   bad.ID,
			NodeName: bad.Name,
			Reason:   err.Error(),
		})
		return err
	}
	nowUnix := float64(time.Now().Unix())
	for _, n := range store.listNodes() {
		if n.Source != nodeSourceClash {
			continue
		}
		active := n.ClashName == after
		_, _ = store.updateNode(n.ID, func(node *nodeRecord) error {
			applyClashActiveTransition(node, active, nowUnix)
			return nil
		})
	}
	store.appendEvent(guardEvent{
		Event:    "clash_switched",
		NodeID:   chosen.ID,
		NodeName: chosen.Name,
		Reason:   fmt.Sprintf("隔离 %s 后切换到 %s", bad.Name, after),
	})
	// Chain: verify the newly selected production leaf right away.
	if chosen.ID != "" && chosen.ID != bad.ID {
		queuePostSwitchProbe(store, chosen, bad.Name)
	}
	return nil
}

func selectClashNodeAPI(store *stateStore, id string) (map[string]any, error) {
	n, ok := store.getNode(id)
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	if n.Source != nodeSourceClash || n.ClashName == "" {
		return nil, fmt.Errorf("该节点不是 Clash 同步节点")
	}
	if err := ensureClashSelectedForNode(store, n); err != nil {
		return nil, err
	}
	fresh, _ := store.getNode(id)
	now := ""
	if client, err := getClashClient(); err == nil {
		now, _ = client.currentGroupSelection()
	}
	return map[string]any{
		"id":          id,
		"clash_name":  n.ClashName,
		"clash_group": n.ClashGroup,
		"now":         now,
		"active":      fresh != nil && fresh.ClashActive,
	}, nil
}

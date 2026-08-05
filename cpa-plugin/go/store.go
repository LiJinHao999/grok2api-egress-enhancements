package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type policyConfig struct {
	Mode                 string  `json:"mode"`
	ActiveIntervalSec    int     `json:"active_interval_seconds"`
	PassivePollSec       int     `json:"passive_poll_seconds"`
	QuarantineSec        int     `json:"quarantine_seconds"`
	SoftTPS              float64 `json:"soft_tps"`
	HardTPS              float64 `json:"hard_tps"`
	ConsecutiveSoft      int     `json:"consecutive_soft"`
	ConsecutiveErrors    int     `json:"consecutive_errors"`
	MinHealthyNodes      int     `json:"min_healthy_nodes"`
	MinGenerationMs      int64   `json:"min_generation_ms"`
	MinOutputTokens      int64   `json:"min_output_tokens"`
	Model                string  `json:"model"`
	DisableAuthOnHard    bool    `json:"disable_auth_on_hard"`
	MaxOutputTokensProbe int     `json:"max_output_tokens"`
	// ProbeAPIBase / ProbeAPIKey: public OpenAI-compatible endpoint used for
	// quality probes so free-usage cooling is recorded by the normal gateway
	// (instead of bypassing via cli-chat-proxy with raw xAI tokens).
	ProbeAPIBase string `json:"probe_api_base"`
	ProbeAPIKey  string `json:"probe_api_key"`
	// IsolationKeywords lists request-body substrings that quarantine the
	// currently selected egress after auth. Empty disables keyword isolation.
	IsolationKeywords []string `json:"isolation_keywords"`
}

type nodeRecord struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	ProxyURL             string  `json:"-"` // never serialize to API clients in clear form via dedicated DTO
	ProxyURLStored       string  `json:"proxy_url"`
	Enabled              bool    `json:"enabled"`
	ProxyPool            bool    `json:"proxy_pool"`
	AccountCapacity      int     `json:"account_capacity"`
	Source               string  `json:"source,omitempty"`      // manual | clash
	ClashName            string  `json:"clash_name,omitempty"`  // leaf proxy name inside Clash group
	ClashGroup           string  `json:"clash_group,omitempty"` // e.g. 🏜️ PerfectAI
	ClashActive          bool    `json:"clash_active,omitempty"`
	ExitIP               string  `json:"exit_ip,omitempty"`
	ProbeStatus          string  `json:"probe_status,omitempty"`
	ProbeLatencyMs       int64   `json:"probe_latency_ms,omitempty"`
	AssignedAccountCount int     `json:"assigned_account_count"`
	DisabledByGuard      bool    `json:"disabled_by_guard"`
	QuarantinedUntil     float64 `json:"quarantined_until,omitempty"`
	ErrorStrikes         int     `json:"error_strikes"`
	SoftStrikes          int     `json:"soft_strikes"`
	LastClassification   string  `json:"last_classification,omitempty"`
	LastOutputTPS        float64 `json:"last_output_tps,omitempty"`
	LastFirstTokenMs     int64   `json:"last_first_token_ms,omitempty"`
	LastDurationMs       int64   `json:"last_duration_ms,omitempty"`
	LastOutputTokens     int64   `json:"last_output_tokens,omitempty"`
	LastReason           string  `json:"last_reason,omitempty"`
	LastSource           string  `json:"last_source,omitempty"`
	LastObservedAt       float64 `json:"last_observed_at,omitempty"`
	LastProbeAt          float64 `json:"last_probe_at,omitempty"`
	// Availability / quality tracking.
	// Healthy side is observation-based (real request/probe usage), NOT wall-clock
	// selected time — idle selection must not inflate quality.
	// Quarantine side is wall-clock state duration (time spent marked degraded).
	LastActiveAt             float64   `json:"last_active_at,omitempty"` // production selected since (display)
	LastQuarantinedAt        float64   `json:"last_quarantined_at,omitempty"`
	TotalActiveMs            int64     `json:"total_active_ms,omitempty"` // healthy usage ms from observations
	TotalQuarantinedMs       int64     `json:"total_quarantined_ms,omitempty"`
	SessionHealthyUsageMs    int64     `json:"session_healthy_usage_ms,omitempty"`
	HealthyObsCount          int64     `json:"healthy_obs_count,omitempty"`
	DegradedObsCount         int64     `json:"degraded_obs_count,omitempty"`
	SessionHealthyObs        int64     `json:"session_healthy_obs,omitempty"`
	SessionDegradedObs       int64     `json:"session_degraded_obs,omitempty"`
	ActiveSessions           int64     `json:"active_sessions,omitempty"`
	QuarantineCount          int64     `json:"quarantine_count,omitempty"`
	LastActiveDurationMs     int64     `json:"last_active_duration_ms,omitempty"` // last session healthy usage ms
	LastQuarantineDurationMs int64     `json:"last_quarantine_duration_ms,omitempty"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type nodeCreateInput struct {
	Name            string
	ProxyURL        string
	Enabled         bool
	ProxyPool       bool
	AccountCapacity int
}

type guardEvent struct {
	TS             float64 `json:"ts"`
	Event          string  `json:"event"`
	NodeID         string  `json:"node_id,omitempty"`
	NodeName       string  `json:"node_name,omitempty"`
	AuthID         string  `json:"auth_id,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	Classification string  `json:"classification,omitempty"`
	OutputTPS      float64 `json:"output_tps,omitempty"`
}

type probeStats struct {
	Total        int64 `json:"total"`
	Healthy      int64 `json:"healthy"`
	Soft         int64 `json:"soft"`
	Hard         int64 `json:"hard"`
	Errors       int64 `json:"errors"`
	Ignored      int64 `json:"ignored"`
	OutputTokens int64 `json:"output_tokens"`
}

type actionStats struct {
	Quarantined int64 `json:"quarantined"`
	Restored    int64 `json:"restored"`
	Suppressed  int64 `json:"suppressed"`
}

type statistics struct {
	StartedAt float64     `json:"started_at"`
	Active    probeStats  `json:"active"`
	Passive   probeStats  `json:"passive"`
	Actions   actionStats `json:"actions"`
}

// clashUIConfig is panel-editable Clash connection settings.
// Non-empty fields override the CPA plugin YAML config so friends can
// set group / API endpoint without touching host config files.
type clashUIConfig struct {
	Enabled      *bool   `json:"enabled,omitempty"`
	APIURL       string  `json:"api_url,omitempty"`
	Secret       string  `json:"secret,omitempty"`
	Group        string  `json:"group,omitempty"`
	ProxyURL     string  `json:"proxy_url,omitempty"`
	TestGroup    string  `json:"test_group,omitempty"`
	TestProxyURL string  `json:"test_proxy_url,omitempty"`
	UpdatedAt    float64 `json:"updated_at,omitempty"`
}

type guardState struct {
	Version   int                    `json:"version"`
	Policy    policyConfig           `json:"policy"`
	ClashUI   clashUIConfig          `json:"clash_ui,omitempty"`
	Nodes     map[string]*nodeRecord `json:"nodes"`
	Events    []guardEvent           `json:"events"`
	Stats     statistics             `json:"statistics"`
	NextID    int                    `json:"next_id"`
	UpdatedAt float64                `json:"updated_at"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	data guardState
}

func defaultPolicy() policyConfig {
	return policyConfig{
		Mode:                 "hybrid",
		ActiveIntervalSec:    1800,
		PassivePollSec:       5,
		QuarantineSec:        120,
		SoftTPS:              500,
		HardTPS:              1000,
		ConsecutiveSoft:      2,
		ConsecutiveErrors:    2,
		MinHealthyNodes:      1,
		MinGenerationMs:      1000,
		MinOutputTokens:      32,
		Model:                "grok-4.5",
		DisableAuthOnHard:    true,
		MaxOutputTokensProbe: 384,
		ProbeAPIBase:         "",
		ProbeAPIKey:          "",
		IsolationKeywords:    nil,
	}
}

func normalizeIsolationKeywords(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		kw := strings.TrimSpace(raw)
		if kw == "" {
			continue
		}
		// Cap individual keyword length so operators cannot store multi-KB blobs.
		if len(kw) > 128 {
			kw = kw[:128]
		}
		if _, ok := seen[kw]; ok {
			continue
		}
		seen[kw] = struct{}{}
		out = append(out, kw)
		if len(out) >= 64 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func newStateStore(path string) *stateStore {
	// Drop process-local auth caches so a fresh store never inherits bindings
	// from a previous test or previous state_file path.
	invalidateAuthListCache()
	s := &stateStore{path: path}
	s.data = guardState{
		Version: 1,
		Policy:  defaultPolicy(),
		Nodes:   map[string]*nodeRecord{},
		Events:  nil,
		Stats:   statistics{StartedAt: float64(time.Now().Unix())},
		NextID:  1,
	}
	_ = s.load()
	return s
}

func (s *stateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.persistLocked()
		}
		return err
	}
	var data guardState
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data.Nodes == nil {
		data.Nodes = map[string]*nodeRecord{}
	}
	if data.NextID <= 0 {
		data.NextID = 1
	}
	if data.Policy.HardTPS <= 0 {
		data.Policy = defaultPolicy()
	}
	if data.Policy.MinGenerationMs <= 0 {
		data.Policy.MinGenerationMs = 1000
	}
	if data.Policy.MinOutputTokens <= 0 {
		data.Policy.MinOutputTokens = 32
	}
	if data.Policy.MaxOutputTokensProbe <= 0 {
		data.Policy.MaxOutputTokensProbe = 384
	}
	data.Policy.IsolationKeywords = normalizeIsolationKeywords(data.Policy.IsolationKeywords)
	data.Policy.ProbeAPIBase = strings.TrimRight(strings.TrimSpace(data.Policy.ProbeAPIBase), "/")
	data.Policy.ProbeAPIKey = strings.TrimSpace(data.Policy.ProbeAPIKey)
	// Public probe API left empty on purpose: quality probes use cli-chat-proxy +
	// per-account tokens via TestPort. Panel can still set probe_api_* later.
	if data.Policy.Mode == "" {
		data.Policy.Mode = "hybrid"
	}
	if data.Policy.ActiveIntervalSec <= 0 {
		data.Policy.ActiveIntervalSec = 1800
	}
	if data.Policy.PassivePollSec <= 0 {
		data.Policy.PassivePollSec = 5
	}
	if data.Policy.QuarantineSec <= 0 {
		data.Policy.QuarantineSec = 120
	}
	// hydrate private proxy field
	for _, n := range data.Nodes {
		n.ProxyURL = n.ProxyURLStored
		if n.Source == "" {
			if n.ClashName != "" {
				n.Source = nodeSourceClash
			} else {
				n.Source = nodeSourceManual
			}
		}
	}
	s.data = data
	return nil
}

// persistLocked writes state; caller MUST hold s.mu.
func (s *stateStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	s.data.UpdatedAt = float64(time.Now().Unix())
	for _, n := range s.data.Nodes {
		n.ProxyURLStored = n.ProxyURL
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *stateStore) snapshot() guardState {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.data)
	var out guardState
	_ = json.Unmarshal(raw, &out)
	if out.Nodes == nil {
		out.Nodes = map[string]*nodeRecord{}
	}
	for id, n := range s.data.Nodes {
		if out.Nodes[id] != nil {
			out.Nodes[id].ProxyURL = n.ProxyURL
		}
	}
	return out
}

func (s *stateStore) policy() policyConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Policy
}

func (s *stateStore) updatePolicy(p policyConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.SoftTPS <= 0 || p.HardTPS <= 0 || p.SoftTPS >= p.HardTPS {
		return fmt.Errorf("软阈值必须低于硬阈值且都大于 0")
	}
	if p.Mode == "" {
		p.Mode = "hybrid"
	}
	if p.Mode != "active" && p.Mode != "passive" && p.Mode != "hybrid" {
		return fmt.Errorf("模式必须是 active、passive 或 hybrid")
	}
	if p.Model == "" {
		p.Model = "grok-4.5"
	}
	p.ProbeAPIBase = strings.TrimRight(strings.TrimSpace(p.ProbeAPIBase), "/")
	if len(p.ProbeAPIBase) > 512 {
		return fmt.Errorf("探测 API 端点过长")
	}
	p.ProbeAPIKey = strings.TrimSpace(p.ProbeAPIKey)
	if len(p.ProbeAPIKey) > 512 {
		return fmt.Errorf("探测 API Key 过长")
	}
	if p.ConsecutiveSoft <= 0 {
		p.ConsecutiveSoft = 2
	}
	if p.ConsecutiveErrors <= 0 {
		p.ConsecutiveErrors = 2
	}
	if p.QuarantineSec <= 0 {
		p.QuarantineSec = 120
	}
	if p.ActiveIntervalSec < 60 || p.ActiveIntervalSec > 86400 {
		return fmt.Errorf("主动检测间隔需在 60 到 86400 秒之间")
	}
	if p.PassivePollSec < 1 || p.PassivePollSec > 3600 {
		return fmt.Errorf("被动审计间隔需在 1 到 3600 秒之间")
	}
	if p.QuarantineSec < 10 || p.QuarantineSec > 86400 {
		return fmt.Errorf("隔离复测间隔需在 10 到 86400 秒之间")
	}
	if p.MinHealthyNodes <= 0 {
		p.MinHealthyNodes = 1
	}
	if p.MinGenerationMs < 200 || p.MinGenerationMs > 10000 {
		return fmt.Errorf("最短生成窗口需在 200 到 10000 毫秒之间")
	}
	if p.MinOutputTokens < 1 || p.MinOutputTokens > 10000 {
		return fmt.Errorf("最小判定 Token 数需在 1 到 10000 之间")
	}
	if p.MaxOutputTokensProbe < 16 || p.MaxOutputTokensProbe > 4096 {
		return fmt.Errorf("主动探测最大输出需在 16 到 4096 Token 之间")
	}
	p.IsolationKeywords = normalizeIsolationKeywords(p.IsolationKeywords)
	s.data.Policy = p
	return s.persistLocked()
}

func (s *stateStore) clashUI() clashUIConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.ClashUI
}

func (s *stateStore) updateClashUI(in clashUIConfig, clearSecret bool) (clashUIConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.data.ClashUI
	if in.Enabled != nil {
		cur.Enabled = in.Enabled
	}
	if v := strings.TrimSpace(in.APIURL); v != "" {
		if !looksLikeHTTPURL(v) && !strings.HasPrefix(v, "unix://") {
			return clashUIConfig{}, fmt.Errorf("Clash API 端点需为 http(s):// 地址")
		}
		if len(v) > 512 {
			return clashUIConfig{}, fmt.Errorf("Clash API 端点过长")
		}
		cur.APIURL = v
	}
	if clearSecret {
		cur.Secret = ""
	} else if v := strings.TrimSpace(in.Secret); v != "" {
		if len(v) > 256 {
			return clashUIConfig{}, fmt.Errorf("Clash secret 过长")
		}
		cur.Secret = v
	}
	if v := strings.TrimSpace(in.Group); v != "" {
		if len(v) > 200 {
			return clashUIConfig{}, fmt.Errorf("策略组名过长")
		}
		cur.Group = v
	}
	if v := strings.TrimSpace(in.ProxyURL); v != "" {
		if _, err := url.Parse(v); err != nil {
			return clashUIConfig{}, fmt.Errorf("代理 URL 无效: %w", err)
		}
		if len(v) > 512 {
			return clashUIConfig{}, fmt.Errorf("代理 URL 过长")
		}
		cur.ProxyURL = v
	}
	if v := strings.TrimSpace(in.TestGroup); v != "" {
		if len(v) > 200 {
			return clashUIConfig{}, fmt.Errorf("测试策略组名过长")
		}
		cur.TestGroup = v
	}
	if v := strings.TrimSpace(in.TestProxyURL); v != "" {
		if _, err := url.Parse(v); err != nil {
			return clashUIConfig{}, fmt.Errorf("测试代理 URL 无效: %w", err)
		}
		if len(v) > 512 {
			return clashUIConfig{}, fmt.Errorf("测试代理 URL 过长")
		}
		cur.TestProxyURL = v
	}
	cur.UpdatedAt = float64(time.Now().Unix())
	s.data.ClashUI = cur
	if err := s.persistLocked(); err != nil {
		return clashUIConfig{}, err
	}
	return cur, nil
}

func looksLikeHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

func (s *stateStore) listNodes() []*nodeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*nodeRecord, 0, len(s.data.Nodes))
	for _, n := range s.data.Nodes {
		cp := *n
		cp.ProxyURL = n.ProxyURL
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *stateStore) getNode(id string) (*nodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Nodes[id]
	if !ok {
		return nil, false
	}
	cp := *n
	cp.ProxyURL = n.ProxyURL
	return &cp, true
}

func (s *stateStore) createNode(name, proxyURL string, enabled, pool bool, capacity int) (*nodeRecord, error) {
	created, err := s.createNodes([]nodeCreateInput{{
		Name:            name,
		ProxyURL:        proxyURL,
		Enabled:         enabled,
		ProxyPool:       pool,
		AccountCapacity: capacity,
	}})
	if err != nil {
		return nil, err
	}
	return created[0], nil
}

func (s *stateStore) createNodes(inputs []nodeCreateInput) ([]*nodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(inputs) == 0 {
		return nil, fmt.Errorf("至少提供一个节点")
	}
	if len(inputs) > 500 {
		return nil, fmt.Errorf("单次最多导入 500 个节点")
	}
	for index := range inputs {
		inputs[index].Name = strings.TrimSpace(inputs[index].Name)
		inputs[index].ProxyURL = strings.TrimSpace(inputs[index].ProxyURL)
		if inputs[index].Name == "" || inputs[index].ProxyURL == "" {
			return nil, fmt.Errorf("第 %d 个节点缺少名称或代理 URL", index+1)
		}
		if err := validateProxyURL(inputs[index].ProxyURL); err != nil {
			return nil, fmt.Errorf("第 %d 个节点代理 URL 无效: %w", index+1, err)
		}
		if inputs[index].AccountCapacity < 0 || inputs[index].AccountCapacity > 100000 {
			return nil, fmt.Errorf("第 %d 个节点容量需在 0 到 100000 之间", index+1)
		}
	}
	previousNextID := s.data.NextID
	now := time.Now().UTC()
	created := make([]*nodeRecord, 0, len(inputs))
	createdIDs := make([]string, 0, len(inputs))
	for _, input := range inputs {
		id := fmt.Sprintf("%d", s.data.NextID)
		s.data.NextID++
		n := &nodeRecord{
			ID:              id,
			Name:            input.Name,
			ProxyURL:        input.ProxyURL,
			ProxyURLStored:  input.ProxyURL,
			Enabled:         input.Enabled,
			ProxyPool:       input.ProxyPool,
			AccountCapacity: input.AccountCapacity,
			Source:          nodeSourceManual,
			ProbeStatus:     "unknown",
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.data.Nodes[id] = n
		createdIDs = append(createdIDs, id)
		cp := *n
		created = append(created, &cp)
	}
	if err := s.persistLocked(); err != nil {
		for _, id := range createdIDs {
			delete(s.data.Nodes, id)
		}
		s.data.NextID = previousNextID
		return nil, err
	}
	return created, nil
}

func (s *stateStore) updateNode(id string, mut func(*nodeRecord) error) (*nodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Nodes[id]
	if !ok {
		return nil, fmt.Errorf("节点不存在")
	}
	if err := mut(n); err != nil {
		return nil, err
	}
	if n.ProxyURL != "" {
		if err := validateProxyURL(n.ProxyURL); err != nil {
			return nil, err
		}
	}
	n.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	cp := *n
	cp.ProxyURL = n.ProxyURL
	return &cp, nil
}

func validateProxyURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("代理 URL 必须包含主机和端口")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return fmt.Errorf("代理协议仅支持 http、https、socks5 或 socks5h")
	}
}

func (s *stateStore) deleteNodes(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.data.Nodes, id)
	}
	return s.persistLocked()
}

func (s *stateStore) setBatchEnabled(ids []string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if n, ok := s.data.Nodes[id]; ok {
			n.Enabled = enabled
			n.UpdatedAt = time.Now().UTC()
		}
	}
	return s.persistLocked()
}

func (s *stateStore) appendEvent(ev guardEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.TS == 0 {
		ev.TS = float64(time.Now().Unix())
	}
	s.data.Events = append(s.data.Events, ev)
	if len(s.data.Events) > 100 {
		s.data.Events = s.data.Events[len(s.data.Events)-100:]
	}
	_ = s.persistLocked()
}

func (s *stateStore) events() []guardEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]guardEvent, len(s.data.Events))
	copy(out, s.data.Events)
	return out
}

func (s *stateStore) stats() statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Stats
}

func (s *stateStore) bumpStat(source, class string, tokens int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ps *probeStats
	if source == "active" {
		ps = &s.data.Stats.Active
	} else {
		ps = &s.data.Stats.Passive
	}
	ps.Total++
	ps.OutputTokens += tokens
	switch class {
	case "healthy":
		ps.Healthy++
	case "soft":
		ps.Soft++
	case "hard":
		ps.Hard++
	case "error":
		ps.Errors++
	case "ignored", "account_error", "upstream_error", "no_account":
		ps.Ignored++
	}
	_ = s.persistLocked()
}

func (s *stateStore) bumpAction(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "quarantined":
		s.data.Stats.Actions.Quarantined++
	case "restored":
		s.data.Stats.Actions.Restored++
	case "suppressed":
		s.data.Stats.Actions.Suppressed++
	}
	_ = s.persistLocked()
}

func (s *stateStore) setAssignedCounts(counts map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range s.data.Nodes {
		n.AssignedAccountCount = counts[id]
	}
	_ = s.persistLocked()
}

func publicNode(n *nodeRecord) map[string]any {
	if n == nil {
		return nil
	}
	source := n.Source
	if source == "" {
		source = nodeSourceManual
	}
	now := float64(time.Now().Unix())
	avail := nodeAvailabilitySnapshot(n, now)
	return map[string]any{
		"id":                          n.ID,
		"name":                        n.Name,
		"enabled":                     n.Enabled,
		"proxyPool":                   n.ProxyPool,
		"accountCapacity":             n.AccountCapacity,
		"source":                      source,
		"clashName":                   n.ClashName,
		"clashGroup":                  n.ClashGroup,
		"clashActive":                 n.ClashActive,
		"exitIp":                      n.ExitIP,
		"probeStatus":                 n.ProbeStatus,
		"probeLatencyMs":              n.ProbeLatencyMs,
		"assignedAccountCount":        n.AssignedAccountCount,
		"disabled_by_guard":           n.DisabledByGuard,
		"quarantined_until":           n.QuarantinedUntil,
		"error_strikes":               n.ErrorStrikes,
		"soft_strikes":                n.SoftStrikes,
		"last_classification":         n.LastClassification,
		"last_output_tps":             n.LastOutputTPS,
		"last_first_token_ms":         n.LastFirstTokenMs,
		"last_duration_ms":            n.LastDurationMs,
		"last_output_tokens":          n.LastOutputTokens,
		"last_reason":                 n.LastReason,
		"last_source":                 n.LastSource,
		"last_observed_at":            n.LastObservedAt,
		"last_probe_at":               n.LastProbeAt,
		"last_active_at":              n.LastActiveAt,
		"last_quarantined_at":         n.LastQuarantinedAt,
		"total_active_ms":             avail["total_active_ms"],
		"total_quarantined_ms":        avail["total_quarantined_ms"],
		"current_active_ms":           avail["current_active_ms"],
		"current_quarantined_ms":      avail["current_quarantined_ms"],
		"current_selected_ms":         avail["current_selected_ms"],
		"last_active_duration_ms":     n.LastActiveDurationMs,
		"last_quarantine_duration_ms": n.LastQuarantineDurationMs,
		"healthy_obs_count":           n.HealthyObsCount,
		"degraded_obs_count":          n.DegradedObsCount,
		"session_healthy_obs":         n.SessionHealthyObs,
		"session_degraded_obs":        n.SessionDegradedObs,
		"active_sessions":             n.ActiveSessions,
		"quarantine_count":            n.QuarantineCount,
		"quality_score":               avail["quality_score"],
		"hasProxy":                    n.ProxyURL != "",
		"createdAt":                   n.CreatedAt,
		"updatedAt":                   n.UpdatedAt,
	}
}

// nodeAvailabilitySnapshot derives live quarantine duration and quality.
// Healthy metrics are observation-based (real usage), never idle selected time.
// quality_score prefers healthy_obs/(healthy+degraded obs); falls back to
// healthy_usage_ms/(healthy_usage_ms+quarantined_ms).
func nodeAvailabilitySnapshot(n *nodeRecord, now float64) map[string]any {
	out := map[string]any{
		"total_active_ms":        int64(0),
		"total_quarantined_ms":   int64(0),
		"current_active_ms":      int64(0),
		"current_quarantined_ms": int64(0),
		"current_selected_ms":    int64(0),
		"quality_score":          nil,
	}
	if n == nil {
		return out
	}
	if now <= 0 {
		now = float64(time.Now().Unix())
	}

	// Healthy usage is already closed into totals + open session accumulator.
	activeMs := n.TotalActiveMs
	currentActive := n.SessionHealthyUsageMs
	if currentActive < 0 {
		currentActive = 0
	}

	qMs := n.TotalQuarantinedMs
	var currentQ int64
	if n.LastQuarantinedAt > 0 && n.DisabledByGuard {
		if d := int64((now - n.LastQuarantinedAt) * 1000); d > 0 {
			currentQ = d
			qMs += d
		}
	}

	var selectedMs int64
	if n.LastActiveAt > 0 && n.ClashActive && !n.DisabledByGuard {
		if d := int64((now - n.LastActiveAt) * 1000); d > 0 {
			selectedMs = d
		}
	}

	out["total_active_ms"] = activeMs + currentActive
	out["total_quarantined_ms"] = qMs
	out["current_active_ms"] = currentActive
	out["current_quarantined_ms"] = currentQ
	out["current_selected_ms"] = selectedMs

	// Prefer response-count score: 未降智响应 / 全部判定响应
	healthyObs := n.HealthyObsCount
	degradedObs := n.DegradedObsCount
	obsTotal := healthyObs + degradedObs
	if obsTotal > 0 {
		score := float64(healthyObs) / float64(obsTotal) * 100
		out["quality_score"] = float64(int64(score*10+0.5)) / 10
		return out
	}
	// Fallback: actual healthy usage time vs quarantine wall time
	usage := activeMs + currentActive
	total := usage + qMs
	if total > 0 {
		score := float64(usage) / float64(total) * 100
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		out["quality_score"] = float64(int64(score*10+0.5)) / 10
	}
	return out
}

// markNodeBecameActive records production selection. Does NOT credit healthy
// time — that only accrues from real healthy/soft observations.
func markNodeBecameActive(n *nodeRecord, now float64) {
	if n == nil {
		return
	}
	if now <= 0 {
		now = float64(time.Now().Unix())
	}
	if n.LastActiveAt > 0 {
		return
	}
	n.LastActiveAt = now
	n.ActiveSessions++
	n.SessionHealthyUsageMs = 0
	n.SessionHealthyObs = 0
	n.SessionDegradedObs = 0
}

// markNodeBecameInactive ends production selection. Flushes session healthy
// usage (observation-based) into totals; selected idle time is discarded.
func markNodeBecameInactive(n *nodeRecord, now float64) {
	if n == nil {
		return
	}
	if n.LastActiveAt <= 0 && n.SessionHealthyUsageMs <= 0 && n.SessionHealthyObs <= 0 {
		return
	}
	if n.SessionHealthyUsageMs > 0 {
		n.TotalActiveMs += n.SessionHealthyUsageMs
		n.LastActiveDurationMs = n.SessionHealthyUsageMs
		n.SessionHealthyUsageMs = 0
	} else if n.LastActiveDurationMs == 0 && n.SessionHealthyObs == 0 {
		// no real usage this session — last duration stays previous or 0
		n.LastActiveDurationMs = 0
	}
	n.LastActiveAt = 0
	n.SessionHealthyObs = 0
	n.SessionDegradedObs = 0
}

// recordHealthyObservation credits real non-degraded usage (healthy/soft).
// durationMs is the request/probe generation time; ignored idle selected time.
func recordHealthyObservation(n *nodeRecord, durationMs int64) {
	if n == nil || n.DisabledByGuard {
		return
	}
	if durationMs < 0 {
		durationMs = 0
	}
	n.HealthyObsCount++
	n.SessionHealthyObs++
	if durationMs > 0 {
		n.SessionHealthyUsageMs += durationMs
		n.LastActiveDurationMs = n.SessionHealthyUsageMs
	}
}

// recordDegradedObservation credits a hard/error observation that indicates
// quality failure (whether or not quarantine is suppressed).
func recordDegradedObservation(n *nodeRecord) {
	if n == nil {
		return
	}
	n.DegradedObsCount++
	n.SessionDegradedObs++
}

// markNodeQuarantined starts quarantine wall-clock and flushes healthy session.
func markNodeQuarantined(n *nodeRecord, now float64) {
	if n == nil {
		return
	}
	if now <= 0 {
		now = float64(time.Now().Unix())
	}
	// Flush healthy usage from this service stint before quarantine.
	if n.SessionHealthyUsageMs > 0 {
		n.TotalActiveMs += n.SessionHealthyUsageMs
		n.LastActiveDurationMs = n.SessionHealthyUsageMs
		n.SessionHealthyUsageMs = 0
	}
	n.LastActiveAt = 0
	n.SessionHealthyObs = 0
	n.SessionDegradedObs = 0
	if n.LastQuarantinedAt > 0 {
		return
	}
	n.LastQuarantinedAt = now
	n.QuarantineCount++
}

// markNodeRestored closes quarantine wall-clock. Does not invent healthy usage.
func markNodeRestored(n *nodeRecord, now float64) {
	if n == nil {
		return
	}
	if now <= 0 {
		now = float64(time.Now().Unix())
	}
	if n.LastQuarantinedAt > 0 {
		if d := int64((now - n.LastQuarantinedAt) * 1000); d > 0 {
			n.TotalQuarantinedMs += d
			n.LastQuarantineDurationMs = d
		}
		n.LastQuarantinedAt = 0
	}
	// Still selected after restore: open a new selection window, but healthy
	// credit waits for the next real healthy observation.
	if n.ClashActive {
		if n.LastActiveAt <= 0 {
			n.LastActiveAt = now
			n.ActiveSessions++
		}
		n.SessionHealthyUsageMs = 0
		n.SessionHealthyObs = 0
		n.SessionDegradedObs = 0
	}
}

// applyClashActiveTransition updates ClashActive and selection boundaries only.
func applyClashActiveTransition(n *nodeRecord, active bool, now float64) {
	if n == nil {
		return
	}
	if now <= 0 {
		now = float64(time.Now().Unix())
	}
	wasActive := n.ClashActive
	n.ClashActive = active
	if active {
		if !n.DisabledByGuard && n.LastActiveAt <= 0 {
			markNodeBecameActive(n, now)
		}
	} else if wasActive || n.LastActiveAt > 0 || n.SessionHealthyUsageMs > 0 {
		markNodeBecameInactive(n, now)
	}
}

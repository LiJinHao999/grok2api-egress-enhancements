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
	ConsecutiveErrors int     `json:"consecutive_errors"`
	MinHealthyNodes   int     `json:"min_healthy_nodes"`
	MinGenerationMs   int64   `json:"min_generation_ms"`
	MinOutputTokens   int64   `json:"min_output_tokens"`
	// AuthAutoDisable bans an account as soon as one missing-thinking degrade is
	// observed (thinking 是唯一判断标准). Panel can also disable/restore accounts
	// manually; auto-disable and manual disable share the same host-side
	// "account-manual"/"account-auto" tags.
	AuthAutoDisable bool `json:"auth_auto_disable"`
	// NodeAutoDisable permanently stops a leaf after repeated quarantine cycles so
	// continuous 降智 exits stop burning production traffic until an operator
	// re-enables them. Distinct from temporary DisabledByGuard quarantine.
	// A "cycle" is either a fresh isolation or a failed recovery/recheck that keeps
	// the leaf isolated (quarantine_count bumps without requiring an artificial restore).
	NodeAutoDisable               bool `json:"node_auto_disable"`
	NodeAutoDisableMinQuarantines int  `json:"node_auto_disable_min_quarantines"`
	// NodeWindowMaxAuths isolates a node for NodeWindowHours when that many
	// distinct accounts used it within the rolling window. 0 disables the guard.
	NodeWindowMaxAuths int     `json:"node_window_max_auths"`
	NodeWindowHours    float64 `json:"node_window_hours"`
	// PolicySchema tracks policy feature revisions. Bump when new defaults must be
	// force-migrated once for existing state.json files.
	PolicySchema int `json:"policy_schema,omitempty"`
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
	AssignedAccountCount int     `json:"assigned_account_count"`
	DisabledByGuard      bool    `json:"disabled_by_guard"`
	// DisabledByOperator is a durable operator/auto stop flag. Unlike quarantine it
	// survives restarts and is never cleared by recovery probes. Panel 停用 and
	// continuous-degrade auto-disable both set this; only explicit 启用 clears it.
	DisabledByOperator bool    `json:"disabled_by_operator,omitempty"`
	DisabledSource     string  `json:"disabled_source,omitempty"` // manual | auto | missing
	DisabledAt         float64 `json:"disabled_at,omitempty"`
	DisabledReason     string  `json:"disabled_reason,omitempty"`
	QuarantinedUntil   float64 `json:"quarantined_until,omitempty"`
	// DisabledByNodeWindow is a temporary 24h cool-off when too many distinct
	// accounts used this egress within the rolling window (Grok flags shared
	// exits). Auto-cleared by the guard worker when NodeWindowUntil passes.
	DisabledByNodeWindow bool              `json:"disabled_by_node_window,omitempty"`
	NodeWindowUntil      float64           `json:"node_window_until,omitempty"`
	NodeWindowReason     string            `json:"node_window_reason,omitempty"`
	NodeWindowAuths      map[string]float64 `json:"node_window_auths,omitempty"` // authID -> last used unix sec
	ErrorStrikes         int               `json:"error_strikes"`
	ThinkingStrikes      int               `json:"thinking_strikes"`
	LastClassification   string  `json:"last_classification,omitempty"`
	LastOutputTPS        float64 `json:"last_output_tps,omitempty"`
	LastFirstTokenMs     int64   `json:"last_first_token_ms,omitempty"`
	LastDurationMs       int64   `json:"last_duration_ms,omitempty"`
	LastOutputTokens     int64   `json:"last_output_tokens,omitempty"`
	LastReason           string  `json:"last_reason,omitempty"`
	LastSource           string  `json:"last_source,omitempty"`
	LastObservedAt       float64 `json:"last_observed_at,omitempty"`
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

// degradationRecord keeps one detected quality-degrade sample (missing-thinking
// hard hit or transport error) with account/IP attribution for profiling.
type degradationRecord struct {
	TS           float64 `json:"ts"`
	NodeID       string  `json:"node_id,omitempty"`
	NodeName     string  `json:"node_name,omitempty"`
	AuthID       string  `json:"auth_id,omitempty"`
	ExitIP       string  `json:"exit_ip,omitempty"`
	Class        string  `json:"class"`
	Reason       string  `json:"reason,omitempty"`
	ErrorKind    string  `json:"error_kind,omitempty"`
	OutputTokens int64   `json:"output_tokens,omitempty"`
	FirstTokenMs int64   `json:"first_token_ms,omitempty"`
	DurationMs   int64   `json:"duration_ms,omitempty"`
	TPS          float64 `json:"tps,omitempty"`
}

type probeStats struct {
	Total        int64 `json:"total"`
	Healthy      int64 `json:"healthy"`
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

// authDegradeRecord tracks per-account 降智 hits.
// Each observation is attributed to the AuthID that produced it (passive audit
// account and cross-verify probe account are never merged).
type authDegradeRecord struct {
	AuthID        string  `json:"auth_id"`
	Label         string  `json:"label,omitempty"`
	DegradedCount int64   `json:"degraded_count"`
	SampleCount   int64   `json:"sample_count"`
	LastAt        float64 `json:"last_at,omitempty"`
	LastReason    string  `json:"last_reason,omitempty"`
	LastNodeID    string  `json:"last_node_id,omitempty"`
	LastNodeName  string  `json:"last_node_name,omitempty"`
	LastOutputTPS float64 `json:"last_output_tps,omitempty"`
	LastSource    string  `json:"last_source,omitempty"`

	// 新增：跨节点降智证据（用于自动禁用阈值判定）
	DegradedNodes map[string]float64 `json:"degraded_nodes,omitempty"` // nodeID -> unix timestamp

	// 插件侧禁用镜像（与 host auth 状态同步）
	DisabledByPlugin bool    `json:"disabled_by_plugin,omitempty"`
	DisabledSource   string  `json:"disabled_source,omitempty"` // manual | auto
	DisabledAt       float64 `json:"disabled_at,omitempty"`
	DisabledReason   string  `json:"disabled_reason,omitempty"`
}

// clashUIConfig is panel-editable Clash connection settings.
// Non-empty fields override the CPA plugin YAML config so friends can
// set group / API endpoint without touching host config files.
type clashUIConfig struct {
	Enabled      *bool   `json:"enabled,omitempty"`
	APIURL       string  `json:"api_url,omitempty"`
	Secret       string  `json:"secret,omitempty"`
	Group     string  `json:"group,omitempty"`
	ProxyURL  string  `json:"proxy_url,omitempty"`
	UpdatedAt float64 `json:"updated_at,omitempty"`
}

type guardState struct {
	Version   int                           `json:"version"`
	Policy    policyConfig                  `json:"policy"`
	ClashUI   clashUIConfig                 `json:"clash_ui,omitempty"`
	Nodes         map[string]*nodeRecord        `json:"nodes"`
	Events        []guardEvent                  `json:"events"`
	Degradations  []degradationRecord           `json:"degradations,omitempty"`
	Stats         statistics                    `json:"statistics"`
	AuthStats map[string]*authDegradeRecord `json:"auth_stats"`
	NextID    int                           `json:"next_id"`
	UpdatedAt float64                       `json:"updated_at"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	data guardState
}

func defaultPolicy() policyConfig {
	return policyConfig{
		ConsecutiveErrors:          2,
		MinHealthyNodes:            1,
		MinGenerationMs:            1000,
		MinOutputTokens:            32,
		AuthAutoDisable:            true,
		NodeAutoDisable:               true,
		NodeAutoDisableMinQuarantines: 3,
		NodeWindowMaxAuths:         3,
		NodeWindowHours:            24,
		PolicySchema:               5,
	}
}

// normalizePolicyFlags fills zero / missing fields with defaults.
// Bool feature flags that default to true cannot be distinguished from explicit
// false after a plain Unmarshal; load paths pass the raw policy object so absent
// keys become defaults instead of false.
func normalizePolicyFlags(p *policyConfig, rawPolicy map[string]any) {
	if p == nil {
		return
	}
	def := defaultPolicy()
	if p.ConsecutiveErrors <= 0 {
		p.ConsecutiveErrors = def.ConsecutiveErrors
	}
	if p.MinHealthyNodes <= 0 {
		p.MinHealthyNodes = def.MinHealthyNodes
	}
	if p.MinGenerationMs <= 0 {
		p.MinGenerationMs = def.MinGenerationMs
	}
	if p.MinOutputTokens <= 0 {
		p.MinOutputTokens = def.MinOutputTokens
	}

	has := func(keys ...string) bool {
		if rawPolicy == nil {
			return false
		}
		for _, k := range keys {
			if _, ok := rawPolicy[k]; ok {
				return true
			}
		}
		return false
	}
	if !has("auth_auto_disable", "authAutoDisable") {
		p.AuthAutoDisable = def.AuthAutoDisable
	}
	if !has("node_auto_disable", "nodeAutoDisable") {
		p.NodeAutoDisable = def.NodeAutoDisable
	}
	if p.NodeAutoDisableMinQuarantines <= 0 {
		p.NodeAutoDisableMinQuarantines = def.NodeAutoDisableMinQuarantines
	}
	// 0 means "guard disabled" for NodeWindowMaxAuths; only default when the key
	// is absent (old state.json) or explicitly negative.
	if !has("node_window_max_auths", "nodeWindowMaxAuths") || p.NodeWindowMaxAuths < 0 {
		p.NodeWindowMaxAuths = def.NodeWindowMaxAuths
	}
	if p.NodeWindowHours <= 0 {
		p.NodeWindowHours = def.NodeWindowHours
	}

	// policy_schema migrations fill ABSENT keys only. Never force-overwrite
	// operator-saved values on restart — that wiped panel strategy settings.
	// schema < 2: thinking redesign defaults; < 4: account auto-disable; < 5: node
	// continuous-degrade auto-disable. Removed feature fields need no migration.
	if p.PolicySchema < def.PolicySchema {
		if !has("auth_auto_disable", "authAutoDisable") {
			p.AuthAutoDisable = def.AuthAutoDisable
		}
		if !has("node_auto_disable", "nodeAutoDisable") {
			p.NodeAutoDisable = def.NodeAutoDisable
		}
		if p.NodeAutoDisableMinQuarantines <= 0 {
			p.NodeAutoDisableMinQuarantines = def.NodeAutoDisableMinQuarantines
		}
		p.PolicySchema = def.PolicySchema
	}
}

func newStateStore(path string) *stateStore {
	// Drop process-local auth caches so a fresh store never inherits bindings
	// from a previous test or previous state_file path.
	invalidateAuthListCache()
	s := &stateStore{path: path}
	s.data = guardState{
		Version:   1,
		Policy:    defaultPolicy(),
		Nodes:     map[string]*nodeRecord{},
		Events:    nil,
		Stats:     statistics{StartedAt: float64(time.Now().Unix())},
		AuthStats: map[string]*authDegradeRecord{},
		NextID:    1,
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
	if data.AuthStats == nil {
		data.AuthStats = map[string]*authDegradeRecord{}
	}
	if data.NextID <= 0 {
		data.NextID = 1
	}
	// Preserve raw policy keys so newly introduced bool defaults stay ON when an
	// older state.json omitted them (plain bool zero value would look like false).
	var rawRoot map[string]any
	_ = json.Unmarshal(raw, &rawRoot)
	var rawPolicy map[string]any
	if rp, ok := rawRoot["policy"].(map[string]any); ok {
		rawPolicy = rp
	}
	beforeSchema := 0
	if rawPolicy != nil {
		if v, ok := rawPolicy["policy_schema"].(float64); ok {
			beforeSchema = int(v)
		}
	}
	if data.Policy.MinHealthyNodes <= 0 {
		data.Policy = defaultPolicy()
		rawPolicy = nil
	}
	normalizePolicyFlags(&data.Policy, rawPolicy)
	// hydrate private proxy field + durable disable migration
	for _, n := range data.Nodes {
		n.ProxyURL = n.ProxyURLStored
		if n.Source == "" {
			if n.ClashName != "" {
				n.Source = nodeSourceClash
			} else {
				n.Source = nodeSourceManual
			}
		}
		// Legacy state only had enabled=false. Promote to operator-disable so a
		// restart never re-schedules those leaves, and recovery probes stay skipped.
		if !n.Enabled && !n.DisabledByOperator {
			n.DisabledByOperator = true
			if n.DisabledSource == "" {
				if strings.Contains(n.LastReason, "Clash 策略组中已不存在") {
					n.DisabledSource = "missing"
				} else {
					n.DisabledSource = "manual"
				}
			}
			if n.DisabledReason == "" {
				n.DisabledReason = n.LastReason
				if n.DisabledReason == "" {
					n.DisabledReason = "历史停用（迁移）"
				}
			}
			if n.DisabledAt <= 0 {
				if !n.UpdatedAt.IsZero() {
					n.DisabledAt = float64(n.UpdatedAt.Unix())
				} else {
					n.DisabledAt = float64(time.Now().Unix())
				}
			}
		}
		if n.DisabledByOperator {
			n.Enabled = false
		}
	}
	s.data = data
	// Persist once when redesign migration ran so defaults become explicit keys.
	if beforeSchema < defaultPolicy().PolicySchema {
		_ = s.persistLocked()
	}
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
	if p.ConsecutiveErrors <= 0 {
		p.ConsecutiveErrors = 2
	}
	// Keep operator-saved schema; only raise when below current product schema so
	// future one-shot migrations can run once. Do NOT rewrite other fields here.
	if p.PolicySchema < defaultPolicy().PolicySchema {
		p.PolicySchema = defaultPolicy().PolicySchema
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
	if p.NodeAutoDisableMinQuarantines <= 0 {
		p.NodeAutoDisableMinQuarantines = defaultPolicy().NodeAutoDisableMinQuarantines
	}
	if p.NodeAutoDisableMinQuarantines > 100 {
		p.NodeAutoDisableMinQuarantines = 100
	}
	if p.NodeWindowMaxAuths < 0 || p.NodeWindowMaxAuths > 50 {
		return fmt.Errorf("节点账号窗口阈值需在 0 到 50 之间（0=禁用）")
	}
	if p.NodeWindowHours <= 0 || p.NodeWindowHours > 168 {
		return fmt.Errorf("节点账号窗口小时数需在 1 到 168 之间")
	}
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
		n, ok := s.data.Nodes[id]
		if !ok {
			continue
		}
		applyOperatorEnabledLocked(n, enabled, "manual", "面板手动停用")
		n.UpdatedAt = time.Now().UTC()
	}
	return s.persistLocked()
}

// applyOperatorEnabledLocked flips Enabled and the durable operator-disable mark.
// caller MUST hold s.mu when n belongs to the store.
func applyOperatorEnabledLocked(n *nodeRecord, enabled bool, source, reason string) {
	if n == nil {
		return
	}
	now := float64(time.Now().Unix())
	if enabled {
		n.Enabled = true
		n.DisabledByOperator = false
		n.DisabledSource = ""
		n.DisabledAt = 0
		n.DisabledReason = ""
		if strings.HasPrefix(n.LastReason, "已停用") || strings.Contains(n.LastReason, "持续降智自动停用") || strings.HasPrefix(n.LastReason, "面板手动停用") {
			n.LastReason = ""
		}
		return
	}
	n.Enabled = false
	n.DisabledByOperator = true
	if source == "" {
		source = "manual"
	}
	n.DisabledSource = source
	n.DisabledAt = now
	if reason == "" {
		reason = "已停用"
	}
	n.DisabledReason = reason
	n.LastReason = reason
	// Stop recovery countdown so a later re-enable does not immediately re-probe
	// under a stale quarantine timer from before the stop.
	n.QuarantinedUntil = 0
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

// rotationEvent records one scheduler-pick decision. Kept in memory only: the
// scheduler runs on every request, so persisting here would rewrite state.json
// continuously. Recent picks are shown on the panel as rotation status.
type rotationEvent struct {
	TS         float64 `json:"ts"`
	SessionID  string  `json:"session_id,omitempty"`
	Provider   string  `json:"provider,omitempty"`
	Model      string  `json:"model,omitempty"`
	Candidates int     `json:"candidates"`
	Eligible   int     `json:"eligible"`
	Delegated  bool    `json:"delegated"`
	Error      string  `json:"error,omitempty"`
}

var (
	rotationMu   sync.Mutex
	rotationLog  []rotationEvent
	rotationMax  = 200
)

func recordRotation(ev rotationEvent) {
	rotationMu.Lock()
	defer rotationMu.Unlock()
	if ev.TS == 0 {
		ev.TS = float64(time.Now().Unix())
	}
	rotationLog = append(rotationLog, ev)
	if len(rotationLog) > rotationMax {
		rotationLog = rotationLog[len(rotationLog)-rotationMax:]
	}
}

func recentRotation(n int) []rotationEvent {
	rotationMu.Lock()
	defer rotationMu.Unlock()
	if n <= 0 || n > len(rotationLog) {
		n = len(rotationLog)
	}
	out := make([]rotationEvent, n)
	copy(out, rotationLog[len(rotationLog)-n:])
	return out
}

func (s *stateStore) events() []guardEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]guardEvent, len(s.data.Events))
	copy(out, s.data.Events)
	return out
}

func (s *stateStore) recordDegradation(d degradationRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.TS == 0 {
		d.TS = float64(time.Now().Unix())
	}
	s.data.Degradations = append(s.data.Degradations, d)
	if len(s.data.Degradations) > 200 {
		s.data.Degradations = s.data.Degradations[len(s.data.Degradations)-200:]
	}
	_ = s.persistLocked()
}

func (s *stateStore) degradations() []degradationRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]degradationRecord, len(s.data.Degradations))
	copy(out, s.data.Degradations)
	return out
}

func (s *stateStore) recordAuthObservation(authID, label, source, nodeID, nodeName, class, reason string, tps float64, degraded bool) {
	authID = strings.TrimSpace(authID)
	if authID == "" || s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AuthStats == nil {
		s.data.AuthStats = map[string]*authDegradeRecord{}
	}
	rec := s.data.AuthStats[authID]
	if rec == nil {
		rec = &authDegradeRecord{AuthID: authID}
		s.data.AuthStats[authID] = rec
	}
	if label != "" {
		rec.Label = label
	}
	rec.SampleCount++
	if degraded {
		rec.DegradedCount++
	}
	rec.LastAt = float64(time.Now().Unix())
	rec.LastSource = source
	if reason != "" {
		rec.LastReason = reason
	} else if degraded {
		rec.LastReason = "响应缺少 thinking_content（降智）"
	}
	if nodeID != "" {
		rec.LastNodeID = nodeID
	}
	if nodeName != "" {
		rec.LastNodeName = nodeName
	}
	if nodeID != "" && degraded {
		if rec.DegradedNodes == nil {
			rec.DegradedNodes = make(map[string]float64)
		}
		rec.DegradedNodes[nodeID] = float64(time.Now().Unix())
	}
	if tps > 0 {
		rec.LastOutputTPS = tps
	}
	_ = class // kept for API symmetry / future filtering
	_ = s.persistLocked()
}

// nodeSchedulable is the single source of truth for "may this egress carry
// traffic": operator stop, guard quarantine and the 24h account-window cool-off
// all disqualify a node from scheduling and probing.
func nodeSchedulable(n *nodeRecord) bool {
	return n != nil && n.Enabled && !n.DisabledByGuard && !n.DisabledByOperator && !n.DisabledByNodeWindow
}

// recordNodeAuthUsage credits a real (non-probe) request auth to the node's
// rolling account window. When the window fills up to the policy threshold the
// node is isolated for NodeWindowHours; the return value reports that trigger.
func (s *stateStore) recordNodeAuthUsage(nodeID, authID string) bool {
	authID = strings.TrimSpace(authID)
	if s == nil || nodeID == "" || authID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.data.Nodes[nodeID]
	if n == nil {
		return false
	}
	pol := s.data.Policy
	limit := pol.NodeWindowMaxAuths
	if limit <= 0 {
		return false
	}
	hours := pol.NodeWindowHours
	if hours <= 0 {
		hours = 24
	}
	now := float64(time.Now().Unix())
	cutoff := now - hours*3600

	if n.NodeWindowAuths == nil {
		n.NodeWindowAuths = map[string]float64{}
	}
	if n.DisabledByNodeWindow {
		// Already cooling off: keep the window fresh for the restore-time reset,
		// but never extend the expiry from stragglers.
		n.NodeWindowAuths[authID] = now
		_ = s.persistLocked()
		return false
	}
	for k, last := range n.NodeWindowAuths {
		if last < cutoff {
			delete(n.NodeWindowAuths, k)
		}
	}
	n.NodeWindowAuths[authID] = now
	if len(n.NodeWindowAuths) < limit {
		_ = s.persistLocked()
		return false
	}
	n.DisabledByNodeWindow = true
	n.NodeWindowUntil = now + hours*3600
	n.NodeWindowReason = fmt.Sprintf("24h 窗口累计 %d 个不同账号使用该出口（阈值 %d）", len(n.NodeWindowAuths), limit)
	_ = s.persistLocked()
	return true
}

// clearNodeWindow ends the account-window cool-off early and resets the window,
// so a restored node starts a fresh counting period instead of instantly
// re-isolating from stale entries.
func (s *stateStore) clearNodeWindow(nodeID string) bool {
	if s == nil || nodeID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.data.Nodes[nodeID]
	if n == nil || !n.DisabledByNodeWindow {
		return false
	}
	n.DisabledByNodeWindow = false
	n.NodeWindowUntil = 0
	n.NodeWindowReason = ""
	n.NodeWindowAuths = nil
	_ = s.persistLocked()
	return true
}

func authDegradeRate(rec *authDegradeRecord) float64 {
	if rec == nil || rec.SampleCount <= 0 {
		return 0
	}
	return float64(rec.DegradedCount) / float64(rec.SampleCount)
}

func distinctDegradedNodes(rec *authDegradeRecord) int {
	if rec == nil || rec.DegradedNodes == nil {
		return 0
	}
	return len(rec.DegradedNodes)
}

// shouldAutoDisableAuth is immediate: any observed missing-thinking degrade
// bans the account right away (thinking 是唯一判断标准，单次缺 thinking 即停用)。
func shouldAutoDisableAuth(rec *authDegradeRecord, pol policyConfig) bool {
	if rec == nil || !pol.AuthAutoDisable || rec.DisabledByPlugin {
		return false
	}
	return rec.DegradedCount > 0
}

func cloneAuthDegradeRecord(rec *authDegradeRecord) *authDegradeRecord {
	if rec == nil {
		return nil
	}
	cp := *rec
	if rec.DegradedNodes != nil {
		cp.DegradedNodes = make(map[string]float64, len(rec.DegradedNodes))
		for k, v := range rec.DegradedNodes {
			cp.DegradedNodes[k] = v
		}
	}
	return &cp
}

func publicAuthDegradeRecord(rec *authDegradeRecord, pol policyConfig) map[string]any {
	if rec == nil {
		return nil
	}
	nodes := distinctDegradedNodes(rec)
	rate := authDegradeRate(rec)
	return map[string]any{
		"auth_id":                 rec.AuthID,
		"label":                   rec.Label,
		"degraded_count":          rec.DegradedCount,
		"sample_count":            rec.SampleCount,
		"last_at":                 rec.LastAt,
		"last_reason":             rec.LastReason,
		"last_node_id":            rec.LastNodeID,
		"last_node_name":          rec.LastNodeName,
		"last_output_tps":         rec.LastOutputTPS,
		"last_source":             rec.LastSource,
		"distinct_degraded_nodes": nodes,
		"degrade_rate":            rate,
		"disabled_by_plugin":      rec.DisabledByPlugin,
		"disabled_source":         rec.DisabledSource,
		"disabled_at":             rec.DisabledAt,
		"disabled_reason":         rec.DisabledReason,
		"auto_disable_eligible":   shouldAutoDisableAuth(rec, pol) && !rec.DisabledByPlugin,
	}
}

func (s *stateStore) listAuthDegradeStats() []*authDegradeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*authDegradeRecord, 0, len(s.data.AuthStats))
	for _, rec := range s.data.AuthStats {
		if rec == nil {
			continue
		}
		out = append(out, cloneAuthDegradeRecord(rec))
	}
	// 100% degrade rate first, then by degrade count, rate, recency, id.
	sort.Slice(out, func(i, j int) bool {
		fullI := out[i].SampleCount > 0 && out[i].DegradedCount == out[i].SampleCount
		fullJ := out[j].SampleCount > 0 && out[j].DegradedCount == out[j].SampleCount
		if fullI != fullJ {
			return fullI
		}
		if out[i].DegradedCount != out[j].DegradedCount {
			return out[i].DegradedCount > out[j].DegradedCount
		}
		rateI, rateJ := authDegradeRate(out[i]), authDegradeRate(out[j])
		if rateI != rateJ {
			return rateI > rateJ
		}
		if out[i].LastAt != out[j].LastAt {
			return out[i].LastAt > out[j].LastAt
		}
		return out[i].AuthID < out[j].AuthID
	})
	return out
}

func (s *stateStore) clearAuthDegradeStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AuthStats = map[string]*authDegradeRecord{}
	_ = s.persistLocked()
}

func (s *stateStore) getAuthDegradeRecord(authID string) *authDegradeRecord {
	authID = strings.TrimSpace(authID)
	if s == nil || authID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AuthStats == nil {
		return nil
	}
	return cloneAuthDegradeRecord(s.data.AuthStats[authID])
}

func (s *stateStore) markAuthDisabled(authID, source, reason string) *authDegradeRecord {
	authID = strings.TrimSpace(authID)
	if s == nil || authID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AuthStats == nil {
		s.data.AuthStats = map[string]*authDegradeRecord{}
	}
	rec := s.data.AuthStats[authID]
	if rec == nil {
		rec = &authDegradeRecord{AuthID: authID}
		s.data.AuthStats[authID] = rec
	}
	rec.DisabledByPlugin = true
	rec.DisabledSource = source
	rec.DisabledAt = float64(time.Now().Unix())
	rec.DisabledReason = reason
	_ = s.persistLocked()
	return cloneAuthDegradeRecord(rec)
}

func (s *stateStore) clearAuthDisabled(authID string, resetStats bool) *authDegradeRecord {
	authID = strings.TrimSpace(authID)
	if s == nil || authID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AuthStats == nil {
		return nil
	}
	rec := s.data.AuthStats[authID]
	if rec == nil {
		if resetStats {
			return &authDegradeRecord{AuthID: authID}
		}
		return nil
	}
	if resetStats {
		delete(s.data.AuthStats, authID)
		_ = s.persistLocked()
		return &authDegradeRecord{AuthID: authID}
	}
	rec.DisabledByPlugin = false
	rec.DisabledSource = ""
	rec.DisabledAt = 0
	rec.DisabledReason = ""
	_ = s.persistLocked()
	return cloneAuthDegradeRecord(rec)
}

func (s *stateStore) countPluginDisabledAuths() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rec := range s.data.AuthStats {
		if rec != nil && rec.DisabledByPlugin {
			n++
		}
	}
	return n
}

func (s *stateStore) listPublicAuthDegradeStats() []map[string]any {
	pol := s.policy()
	items := s.listAuthDegradeStats()
	out := make([]map[string]any, 0, len(items))
	for _, rec := range items {
		out = append(out, publicAuthDegradeRecord(rec, pol))
	}
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
		"assignedAccountCount":        n.AssignedAccountCount,
		"disabled_by_guard":           n.DisabledByGuard,
		"disabled_by_operator":       n.DisabledByOperator,
		"disabled_source":            n.DisabledSource,
		"disabled_at":                n.DisabledAt,
		"disabled_reason":            n.DisabledReason,
		"quarantined_until":           n.QuarantinedUntil,
		"disabled_by_node_window":     n.DisabledByNodeWindow,
		"node_window_until":           n.NodeWindowUntil,
		"node_window_reason":          n.NodeWindowReason,
		"node_window_auth_count":      len(n.NodeWindowAuths),
		"error_strikes":               n.ErrorStrikes,
		"last_classification":         n.LastClassification,
		"last_output_tps":             n.LastOutputTPS,
		"last_first_token_ms":         n.LastFirstTokenMs,
		"last_duration_ms":            n.LastDurationMs,
		"last_output_tokens":          n.LastOutputTokens,
		"last_reason":                 n.LastReason,
		"last_source":                 n.LastSource,
		"last_observed_at":            n.LastObservedAt,
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

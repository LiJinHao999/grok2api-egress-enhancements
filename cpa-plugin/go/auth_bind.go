package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type hostAuthGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

type authFile struct {
	ID       string
	Index    string
	Name     string
	Path     string
	Email    string
	Disabled bool
	ProxyURL string
	Raw      map[string]any
}

// auth list cache: avoids the host.auth.list + N×host.auth.get stampede on
// every scheduler / usage / worker tick. Mutations patch the cache in place;
// a 60s TTL still picks up external CPA auth changes.
const authListCacheTTL = 60 * time.Second

var (
	authListMu      sync.Mutex
	authListCache   []authFile
	authListAt      time.Time
	authListLoading bool
	authListWait    = sync.NewCond(&authListMu)
)

func invalidateAuthListCache() {
	authListMu.Lock()
	authListCache = nil
	authListAt = time.Time{}
	authListMu.Unlock()
}

func cloneAuthFiles(in []authFile) []authFile {
	if in == nil {
		return nil
	}
	out := make([]authFile, len(in))
	copy(out, in)
	return out
}

// listAuthFiles returns xAI auth files, preferring a warm cache.
func listAuthFiles() ([]authFile, error) {
	return listAuthFilesCached(false)
}

// listAuthFilesFresh bypasses TTL (management UI, rebalance entry).
func listAuthFilesFresh() ([]authFile, error) {
	return listAuthFilesCached(true)
}

func listAuthFilesCached(force bool) ([]authFile, error) {
	authListMu.Lock()
	for authListLoading {
		authListWait.Wait()
	}
	if !force && authListCache != nil && time.Since(authListAt) < authListCacheTTL {
		out := cloneAuthFiles(authListCache)
		authListMu.Unlock()
		return out, nil
	}
	authListLoading = true
	authListMu.Unlock()

	loaded, err := fetchAuthFilesFromHost()

	authListMu.Lock()
	authListLoading = false
	if err == nil {
		authListCache = loaded
		authListAt = time.Now()
	}
	out := cloneAuthFiles(authListCache)
	authListWait.Broadcast()
	authListMu.Unlock()
	if err != nil {
		if out != nil {
			// serve stale on transient host errors to keep hot path alive
			return out, nil
		}
		return nil, err
	}
	return out, nil
}

func fetchAuthFilesFromHost() ([]authFile, error) {
	raw, err := hostCall(pluginabi.MethodHostAuthList, mustJSON(map[string]any{}))
	if err != nil {
		return nil, err
	}
	var resp hostAuthListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		// some hosts return bare array
		var files []pluginapi.HostAuthFileEntry
		if err2 := json.Unmarshal(raw, &files); err2 != nil {
			return nil, fmt.Errorf("decode auth list: %w", err)
		}
		resp.Files = files
	}
	out := make([]authFile, 0, len(resp.Files))
	for _, f := range resp.Files {
		idx := strings.TrimSpace(f.AuthIndex)
		if idx == "" {
			idx = strings.TrimSpace(f.ID)
		}
		if idx == "" {
			idx = strings.TrimSpace(f.Name)
		}
		if idx == "" {
			continue
		}
		// prefer xai provider/type from list entry
		prov := strings.ToLower(strings.TrimSpace(f.Provider + " " + f.Type + " " + f.Name))
		if prov != "" && !strings.Contains(prov, "xai") {
			continue
		}
		got, err := getAuthFile(idx)
		if err != nil {
			// try by name
			if f.Name != "" {
				got, err = getAuthFile(f.Name)
			}
			if err != nil {
				continue
			}
		}
		if t, _ := got.Raw["type"].(string); strings.ToLower(t) != "xai" && strings.ToLower(t) != "" {
			if !strings.HasPrefix(strings.ToLower(got.Name), "xai-") {
				continue
			}
		}
		got.ID = strings.TrimSpace(f.ID)
		out = append(out, got)
	}
	return out, nil
}

// patchAuthListCacheAfterSave updates one entry after host.auth.save so migrate
// of hundreds of accounts does not re-trigger N+1 list/get.
func patchAuthListCacheAfterSave(name string, obj map[string]any) {
	if name == "" || obj == nil {
		return
	}
	proxy, _ := obj["proxy_url"].(string)
	proxy = strings.TrimSpace(proxy)
	disabled, _ := obj["disabled"].(bool)
	email, _ := obj["email"].(string)

	authListMu.Lock()
	defer authListMu.Unlock()
	if authListCache == nil {
		return
	}
	for i := range authListCache {
		a := &authListCache[i]
		if a.Name != name && a.Index != name && a.ID != name {
			continue
		}
		a.ProxyURL = proxy
		a.Disabled = disabled
		a.Raw = obj
		if email != "" {
			a.Email = email
		}
		return
	}
}

func getAuthFile(authIndex string) (authFile, error) {
	raw, err := hostCall(pluginabi.MethodHostAuthGet, mustJSON(map[string]any{"auth_index": authIndex}))
	if err != nil {
		// try name field
		raw, err = hostCall(pluginabi.MethodHostAuthGet, mustJSON(map[string]any{"name": authIndex}))
		if err != nil {
			return authFile{}, err
		}
	}
	var resp hostAuthGetResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return authFile{}, err
	}
	obj := map[string]any{}
	if len(resp.JSON) > 0 {
		_ = json.Unmarshal(resp.JSON, &obj)
	}
	email, _ := obj["email"].(string)
	proxy, _ := obj["proxy_url"].(string)
	disabled, _ := obj["disabled"].(bool)
	name := resp.Name
	if name == "" {
		name = filepath.Base(resp.Path)
	}
	if name == "" && email != "" {
		name = "xai-" + email + ".json"
	}
	idx := resp.AuthIndex
	if idx == "" {
		idx = authIndex
	}
	return authFile{
		Index:    idx,
		Name:     name,
		Path:     resp.Path,
		Email:    email,
		Disabled: disabled,
		ProxyURL: strings.TrimSpace(proxy),
		Raw:      obj,
	}, nil
}

func saveAuthFile(name string, obj map[string]any) error {
	if name == "" {
		return fmt.Errorf("auth name required")
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = hostCall(pluginabi.MethodHostAuthSave, mustJSON(map[string]any{
		"name": name,
		"json": json.RawMessage(raw),
	}))
	if err == nil {
		patchAuthListCacheAfterSave(name, obj)
		// Rebuild proxy map from the patched list cache (no host round-trips).
		invalidateAuthProxyCache()
	}
	return err
}

func setAuthProxyAndFlags(a authFile, proxyURL string, disabled bool, reason string) error {
	// Clone before mutate: a.Raw is shared with the auth-list cache. A failed
	// host.auth.save must not leave the in-memory snapshot pointing at the dest.
	obj := map[string]any{}
	for k, v := range a.Raw {
		obj[k] = v
	}
	if proxyURL == "" {
		delete(obj, "proxy_url")
	} else {
		obj["proxy_url"] = proxyURL
	}
	obj["disabled"] = disabled
	if disabled && reason != "" {
		obj["disabled_reason"] = reason
		obj["disabled_at"] = nowRFC3339()
	} else {
		delete(obj, "disabled_reason")
		delete(obj, "disabled_at")
	}
	if _, ok := obj["type"]; !ok {
		obj["type"] = "xai"
	}
	return saveAuthFile(a.Name, obj)
}

func isGuardDisabledAuth(a authFile) bool {
	if !a.Disabled {
		return false
	}
	reason, _ := a.Raw["disabled_reason"].(string)
	return strings.Contains(reason, "egress-guard") || strings.Contains(reason, "降智")
}

// applyAuthBinding writes proxy/disabled flags, then read-back verifies.
// If verify fails after a successful save, roll the host file and list cache
// back to the pre-call binding so leftovers are not stranded on a dest the
// host never confirmed.
func applyAuthBinding(a authFile, proxyURL string, disabled bool, reason string) error {
	prevProxy := a.ProxyURL
	prevDisabled := a.Disabled
	prevReason := ""
	if a.Raw != nil {
		prevReason, _ = a.Raw["disabled_reason"].(string)
	}
	if err := setAuthProxyAndFlags(a, proxyURL, disabled, reason); err != nil {
		return err
	}
	if err := verifyAuthBinding(a, proxyURL, disabled); err != nil {
		if rbErr := setAuthProxyAndFlags(a, prevProxy, prevDisabled, prevReason); rbErr != nil {
			invalidateAuthListCache()
		}
		return err
	}
	return nil
}

func verifyAuthBinding(a authFile, expectedProxy string, expectedDisabled bool) error {
	key := firstNonEmpty(a.Index, a.Name)
	if key == "" {
		return fmt.Errorf("账号缺少 auth index")
	}
	got, err := getAuthFile(key)
	if err == nil && got.ProxyURL == expectedProxy && got.Disabled == expectedDisabled {
		return nil
	}
	// A host may regenerate the runtime auth index after host.auth.save. Verify
	// by stable name/path with single gets — never re-list the whole auth pool.
	for _, candidate := range []string{a.Name, filepath.Base(a.Path), a.Index, a.ID} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == key {
			continue
		}
		got2, err2 := getAuthFile(candidate)
		if err2 == nil && got2.ProxyURL == expectedProxy && got2.Disabled == expectedDisabled {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("读取迁移结果失败: %w", err)
	}
	return fmt.Errorf("迁移结果未生效")
}

func listAuthFilesBestEffort() []authFile {
	items, err := listAuthFiles()
	if err != nil {
		return nil
	}
	return items
}

func rebalanceAuthsToNodes(store *stateStore) (map[string]int, error) {
	// Fresh list so operator-driven rebalance sees latest CPA auth files.
	auths, err := listAuthFilesFresh()
	if err != nil {
		return nil, err
	}
	nodes := store.listNodes()
	// eligible nodes: enabled, not guard-quarantined, has proxy
	eligible := make([]*nodeRecord, 0)
	for _, n := range nodes {
		if nodeSchedulable(n) {
			eligible = append(eligible, n)
		}
	}
	counts := map[string]int{}
	if len(eligible) == 0 {
		// clear proxies? keep as-is but zero counts
		store.setAssignedCounts(counts)
		return counts, fmt.Errorf("没有可调度出口节点")
	}
	// only rebalance non-disabled auths; disabled stay put
	active := make([]authFile, 0)
	for _, a := range auths {
		if a.Disabled {
			// still count if matches a node proxy
			for _, n := range nodes {
				if a.ProxyURL != "" && a.ProxyURL == n.ProxyURL {
					counts[n.ID]++
				}
			}
			continue
		}
		active = append(active, a)
	}
	// capacity-aware round robin
	cursor := 0
	for _, a := range active {
		// pick next node with capacity room
		var chosen *nodeRecord
		for tried := 0; tried < len(eligible); tried++ {
			n := eligible[cursor%len(eligible)]
			cursor++
			cap := n.AccountCapacity
			if cap > 0 && counts[n.ID] >= cap {
				continue
			}
			chosen = n
			break
		}
		if chosen == nil {
			// all full — pile on last eligible
			chosen = eligible[len(eligible)-1]
		}
		if a.ProxyURL == chosen.ProxyURL && !a.Disabled {
			counts[chosen.ID]++
			continue
		}
		if err := applyAuthBinding(a, chosen.ProxyURL, false, ""); err != nil {
			return counts, fmt.Errorf("绑定 %s 失败: %w", a.Name, err)
		}
		counts[chosen.ID]++
	}
	// Capacity above may count disabled leftovers as occupied slots.
	// AssignedAccountCount is probe fuel: enabled, non-expired bindings only.
	refreshAssignedCounts(store)
	out := map[string]int{}
	for _, n := range store.listNodes() {
		out[n.ID] = n.AssignedAccountCount
	}
	return out, nil
}

func authCountsTowardAssignment(a authFile) bool {
	if a.Disabled || strings.TrimSpace(a.ProxyURL) == "" {
		return false
	}
	tok, _ := a.Raw["access_token"].(string)
	if strings.TrimSpace(tok) == "" {
		return false
	}
	return !isAuthExpired(a)
}

func refreshAssignedCounts(store *stateStore) {
	auths, err := listAuthFiles()
	if err != nil {
		return
	}
	nodes := store.listNodes()
	byProxy := map[string]string{}
	for _, n := range nodes {
		if n.ProxyURL != "" {
			byProxy[n.ProxyURL] = n.ID
		}
	}
	counts := map[string]int{}
	for _, a := range auths {
		if !authCountsTowardAssignment(a) {
			continue
		}
		if id, ok := byProxy[a.ProxyURL]; ok {
			counts[id]++
		}
	}
	store.setAssignedCounts(counts)
}

func disableAuthsOnNode(store *stateStore, node *nodeRecord, reason string) error {
	if node == nil || node.ProxyURL == "" {
		return nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return err
	}
	for _, a := range auths {
		if a.ProxyURL == node.ProxyURL && !a.Disabled {
			if err := setAuthProxyAndFlags(a, a.ProxyURL, true, reason); err != nil {
				return fmt.Errorf("停用 %s 失败: %w", a.Name, err)
			}
		}
	}
	return nil
}

func enableAuthsOnNode(node *nodeRecord) error {
	if node == nil || node.ProxyURL == "" {
		return nil
	}
	auths, err := listAuthFiles()
	if err != nil {
		return err
	}
	for _, a := range auths {
		if a.ProxyURL == node.ProxyURL && a.Disabled {
			reason, _ := a.Raw["disabled_reason"].(string)
			if strings.Contains(reason, "egress-guard") || strings.Contains(reason, "降智") {
				_ = setAuthProxyAndFlags(a, a.ProxyURL, false, "")
			}
		}
	}
	return nil
}

func pickAuthForNode(node *nodeRecord) (authFile, error) {
	list, err := listAuthsForNode(node, 1)
	if err != nil {
		return authFile{}, err
	}
	if len(list) == 0 {
		return authFile{}, fmt.Errorf("没有可用的 CPA xAI 账号")
	}
	return list[0], nil
}

type authListMode int

const (
	// authListBoundOnly is the default: only enabled accounts already bound
	// to this node's proxy. Regular active probes must not borrow a foreign
	// account and burn another egress's quota.
	authListBoundOnly authListMode = iota
	// authListRecovery is for quarantined restore / rotate confirmation /
	// manual quality on an isolated node. Prefer bound accounts (including
	// guard-disabled leftovers), then borrow one foreign token. The HTTP
	// client still goes through the quarantined proxy.
	authListRecovery
)

// listAuthsForNode returns up to limit enabled xAI auths bound to the node
// proxy, preferring non-expired tokens. It never borrows a foreign account:
// an empty or drained schedulable node must not burn another egress's probe
// quota or attribute 降智 to the borrowed auth.
func listAuthsForNode(node *nodeRecord, limit int) ([]authFile, error) {
	return listAuthsForNodeMode(node, limit, authListBoundOnly)
}

func listAuthsForNodeMode(node *nodeRecord, limit int, mode authListMode) ([]authFile, error) {
	if limit <= 0 {
		limit = 5
	}
	if node == nil || node.ProxyURL == "" {
		return nil, fmt.Errorf("节点没有可用的绑定账号")
	}
	auths, err := listAuthFiles()
	if err != nil {
		return nil, err
	}
	var primary, expired, disabledBound, foreign, foreignExpired []authFile
	for _, a := range auths {
		tok, _ := a.Raw["access_token"].(string)
		if strings.TrimSpace(tok) == "" {
			continue
		}
		onNode := a.ProxyURL == node.ProxyURL
		if a.Disabled {
			if mode == authListRecovery && onNode && isGuardDisabledAuth(a) {
				disabledBound = append(disabledBound, a)
			}
			continue
		}
		if onNode {
			if isAuthExpired(a) {
				expired = append(expired, a)
				continue
			}
			primary = append(primary, a)
			continue
		}
		if mode != authListRecovery {
			continue
		}
		if isAuthExpired(a) {
			foreignExpired = append(foreignExpired, a)
			continue
		}
		foreign = append(foreign, a)
	}
	out := make([]authFile, 0, limit)
	out = append(out, primary...)
	if len(out) == 0 {
		out = append(out, expired...)
	}
	if len(out) == 0 && mode == authListRecovery {
		out = append(out, disabledBound...)
	}
	if len(out) == 0 && mode == authListRecovery {
		if picked, ok := pickForeignAuthForNode(node, foreign, foreignExpired); ok {
			out = append(out, picked)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	if len(out) == 0 {
		if mode == authListRecovery {
			return nil, fmt.Errorf("没有可用于隔离复测的 CPA xAI 账号")
		}
		return nil, fmt.Errorf("节点没有可用的绑定账号")
	}
	return out, nil
}

func pickForeignAuthForNode(node *nodeRecord, foreign, foreignExpired []authFile) (authFile, bool) {
	pool := foreign
	if len(pool) == 0 {
		pool = foreignExpired
	}
	if len(pool) == 0 {
		return authFile{}, false
	}
	if node == nil || node.ID == "" || len(pool) == 1 {
		return pool[0], true
	}
	sum := 0
	for _, r := range node.ID {
		sum = sum*31 + int(r)
	}
	if sum < 0 {
		sum = -sum
	}
	return pool[sum%len(pool)], true
}

// nodeHasBoundRestoreFuel reports leftover tokens already on this proxy
// (enabled or guard-disabled). Empty isolated nodes must not borrow a
// foreign account just to decide whether a model probe is possible.
func nodeHasBoundRestoreFuel(node *nodeRecord) bool {
	if node == nil || node.ProxyURL == "" {
		return false
	}
	auths, err := listAuthFiles()
	if err != nil {
		return false
	}
	for _, a := range auths {
		if a.ProxyURL != node.ProxyURL {
			continue
		}
		tok, _ := a.Raw["access_token"].(string)
		if strings.TrimSpace(tok) == "" {
			continue
		}
		if !a.Disabled || isGuardDisabledAuth(a) {
			return true
		}
	}
	return false
}

func authIsBorrowed(auth authFile, node *nodeRecord) bool {
	if node == nil {
		return false
	}
	return strings.TrimSpace(auth.ProxyURL) != node.ProxyURL
}

// listBoundAuthSummaries returns lightweight account info for a node (no secrets).
func listBoundAuthSummaries(node *nodeRecord) ([]map[string]any, error) {
	// UI path: prefer fresh data so operators see post-rebalance bindings immediately.
	auths, err := listAuthFilesFresh()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0)
	if node == nil || node.ProxyURL == "" {
		return out, nil
	}
	for _, a := range auths {
		if a.ProxyURL != node.ProxyURL {
			continue
		}
		out = append(out, map[string]any{
			"name":     a.Name,
			"email":    a.Email,
			"disabled": a.Disabled,
			"expired":  isAuthExpired(a),
		})
	}
	return out, nil
}

func nodeSchedulable(n *nodeRecord) bool {
	return n != nil && n.Enabled && !n.DisabledByGuard && n.ProxyURL != ""
}

// nodeFallbackEligible is the cold-start / unverified path: schedulable and
// not already classified as degraded. Never-probed, unknown, ignored-only
// and healthy stay eligible. applyObservation keeps a prior soft/hard/
// healthy/error class when a later sample is ignored/unknown, so a short
// reply cannot turn a degraded node into a dump target.
func nodeFallbackEligible(n *nodeRecord) bool {
	if !nodeSchedulable(n) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(n.LastClassification)) {
	case "soft", "hard", "error":
		return false
	default:
		return true
	}
}

func verifiedMigrationTargets(store *stateStore, bad *nodeRecord) []*nodeRecord {
	if store == nil || bad == nil {
		return nil
	}
	pol := store.policy()
	freshness := time.Duration(pol.ActiveIntervalSec*2) * time.Second
	if freshness < time.Hour {
		freshness = time.Hour
	}
	cutoff := float64(time.Now().Add(-freshness).Unix())
	targets := make([]*nodeRecord, 0)
	for _, n := range store.listNodes() {
		if n.ID == bad.ID || !nodeSchedulable(n) {
			continue
		}
		if n.LastClassification != "healthy" || n.LastProbeAt <= cutoff || n.ExitIP == "" {
			continue
		}
		if bad.ExitIP != "" && n.ExitIP == bad.ExitIP {
			continue
		}
		targets = append(targets, n)
	}
	return targets
}

// fallbackMigrationTargets is the cold-start / unverified path: other
// schedulable egresses that are not already classified as degraded.
// A known-same exit IP is never a silent success — that is the same
// residential line under another listener.
func fallbackMigrationTargets(store *stateStore, bad *nodeRecord) []*nodeRecord {
	if store == nil || bad == nil {
		return nil
	}
	var preferred, any []*nodeRecord
	for _, n := range store.listNodes() {
		if n.ID == bad.ID || !nodeFallbackEligible(n) || n.ProxyURL == bad.ProxyURL {
			continue
		}
		if bad.ExitIP != "" && n.ExitIP != "" && n.ExitIP == bad.ExitIP {
			continue
		}
		any = append(any, n)
		if bad.ExitIP != "" && n.ExitIP != "" && n.ExitIP != bad.ExitIP {
			preferred = append(preferred, n)
		}
	}
	if len(preferred) > 0 {
		return preferred
	}
	return any
}

func pickMigrationTargets(store *stateStore, bad *nodeRecord) (targets []*nodeRecord, fallback bool) {
	if verified := verifiedMigrationTargets(store, bad); len(verified) > 0 {
		return verified, false
	}
	return fallbackMigrationTargets(store, bad), true
}

// migrateAuthsOffNode fails closed, then moves guard-managed accounts off the
// isolated egress. Prefer recently active-verified nodes with a different exit
// IP; if none exist (cold start, never probed), fall back to other schedulable
// nodes that are not already soft/hard/error and do not share a known exit IP.
// When even that is empty, roll back the fail-closed disable so accounts are
// not stranded until the 1h retest.
func migrateAuthsOffNode(store *stateStore, bad *nodeRecord) error {
	if bad == nil || bad.ProxyURL == "" {
		return nil
	}
	// Force a fresh snapshot once; subsequent saves patch the cache in place.
	auths, err := listAuthFilesFresh()
	if err != nil {
		return err
	}
	affected := make([]authFile, 0)
	for _, a := range auths {
		if a.ProxyURL == bad.ProxyURL && (!a.Disabled || isGuardDisabledAuth(a)) {
			affected = append(affected, a)
		}
	}
	if len(affected) == 0 {
		return nil
	}
	// Remove every affected account from scheduling before changing its proxy.
	for _, a := range affected {
		if a.Disabled {
			continue
		}
		if err := setAuthProxyAndFlags(a, a.ProxyURL, true, "egress-guard 隔离中"); err != nil {
			_ = enableAuthsOnNode(bad)
			return fmt.Errorf("隔离账号 %s 失败: %w", a.Name, err)
		}
	}
	healthy, usedFallback := pickMigrationTargets(store, bad)
	if len(healthy) == 0 {
		_ = enableAuthsOnNode(bad)
		return fmt.Errorf("没有可迁入的健康通道")
	}
	cursor := 0
	moved := 0
	failed := 0
	for _, a := range affected {
		dest := healthy[cursor%len(healthy)]
		cursor++
		if err := applyAuthBinding(a, dest.ProxyURL, false, ""); err != nil {
			failed++
			continue
		}
		moved++
	}
	refreshAssignedCounts(store)
	if moved > 0 {
		kind := "健康通道"
		if usedFallback {
			kind = "可调度通道（冷启动/无近期探测，已排除异常分类与同出口 IP）"
		}
		store.appendEvent(guardEvent{
			Event:    "accounts_migrated",
			NodeID:   bad.ID,
			NodeName: bad.Name,
			Reason:   fmt.Sprintf("隔离后迁出 %d 个账号到%s，失败 %d 个", moved, kind, failed),
		})
	}
	if failed > 0 {
		// Leftovers are still bound here and disabled; undo so they are not
		// stranded until quarantine retest. DisableAuthOnHard re-applies.
		_ = enableAuthsOnNode(bad)
		return fmt.Errorf("%d 个账号迁移或验证失败", failed)
	}
	return nil
}

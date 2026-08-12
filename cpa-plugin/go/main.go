package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginName          = "grok2api-egress"
	pluginVersion       = "1.1.36"
	resourcePath        = "/status"
	managementAPIPath   = "/v0/management/grok2api-egress/api"
	resourceContentType = "text/html; charset=utf-8"
	defaultStateFile    = "/CLIProxyAPI/plugin-data/egress-guard/state.json"
)

//go:embed page.html
var pageTemplate string

//go:embed tokens.css
var tokenCSS string

//go:embed accounts-panel.js
var accountsPanelJS string

//go:embed accounts-panel.css
var accountsPanelCSS string

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	StateFile          string   `yaml:"state_file" json:"state_file"`
	RotationURL        string   `yaml:"rotation_url" json:"rotation_url"`
	RotationTokenEnv   string   `yaml:"rotation_token_env" json:"rotation_token_env"`
	RotationTimeoutSec int      `yaml:"rotation_timeout_seconds" json:"rotation_timeout_seconds"`
	RotatableNodeIDs   []string `yaml:"rotatable_node_ids" json:"rotatable_node_ids"`

	// Clash / Mihomo local controller integration.
	// Nodes synced from Clash share one mixed-port proxy_url; the real exit is
	// selected by PUT /proxies/{group} on quarantine / manual switch.
	ClashEnabled    bool   `yaml:"clash_enabled" json:"clash_enabled"`
	ClashAPIURL     string `yaml:"clash_api_url" json:"clash_api_url"`
	ClashUnixSocket string `yaml:"clash_unix_socket" json:"clash_unix_socket"`
	ClashSecret     string `yaml:"clash_secret" json:"clash_secret"` // prefer env; kept for local single-user setups
	ClashSecretEnv  string `yaml:"clash_secret_env" json:"clash_secret_env"`
	ClashGroup            string   `yaml:"clash_group" json:"clash_group"`
	ClashProxyURL         string   `yaml:"clash_proxy_url" json:"clash_proxy_url"`
	ClashCloseConnections bool     `yaml:"clash_close_connections" json:"clash_close_connections"`
	ClashSyncOnStart      bool     `yaml:"clash_sync_on_start" json:"clash_sync_on_start"`
	ClashTimeoutSec       int      `yaml:"clash_timeout_seconds" json:"clash_timeout_seconds"`
	ClashExcludeKeywords  []string `yaml:"clash_exclude_keywords" json:"clash_exclude_keywords"`
	ClashPreferKeywords   []string `yaml:"clash_prefer_keywords" json:"clash_prefer_keywords"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ManagementAPI      bool `json:"management_api"`
	UsagePlugin        bool `json:"usage_plugin"`
	Scheduler          bool `json:"scheduler"`
	RequestInterceptor bool `json:"request_interceptor"`
}

type managementRegistration struct {
	Routes    []managementRoute    `json:"routes,omitempty"`
	Resources []managementResource `json:"resources,omitempty"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description"`
}

type managementResource struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type managementRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
	Body    []byte
}

type uiProxyRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type managementResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

var (
	store         *stateStore
	workerCancel  context.CancelFunc
	currentConfig atomic.Value // pluginConfig
	startedAt     = time.Now().UTC()
	// hostCall is replaceable in unit tests. Production always uses the C ABI
	// callback implemented by callHost below.
	hostCall = callHost
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	currentConfig.Store(pluginConfig{StateFile: defaultStateFile})
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	if workerCancel != nil {
		workerCancel()
	}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := configure(request); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration{
			Routes:    []managementRoute{{Method: http.MethodPost, Path: "/grok2api-egress/api", Description: "CPA 出口守护 UI API"}},
			Resources: []managementResource{{Path: resourcePath, Menu: "出口守护", Description: "纯 CPA 出口节点 · 降智隔离 · 被动观测（不依赖 Grok2API）"}},
		})
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	case pluginabi.MethodSchedulerPick:
		return handleSchedulerPick(request)
	case pluginabi.MethodRequestInterceptBefore:
		return handleRequestIntercept(request, false)
	case pluginabi.MethodRequestInterceptAfter:
		return handleRequestIntercept(request, true)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
	}
	cfg := pluginConfig{StateFile: defaultStateFile}
	if len(req.ConfigYAML) > 0 {
		if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.StateFile) == "" {
		cfg.StateFile = defaultStateFile
	}
	if cfg.RotationTimeoutSec <= 0 {
		cfg.RotationTimeoutSec = 45
	}
	if cfg.ClashTimeoutSec <= 0 {
		cfg.ClashTimeoutSec = 8
	}
	if strings.TrimSpace(cfg.ClashGroup) == "" {
		cfg.ClashGroup = "🏜️ PerfectAI"
	}
	if strings.TrimSpace(cfg.ClashSecretEnv) == "" {
		cfg.ClashSecretEnv = "CLASH_API_SECRET"
	}
	// Default close old connections after switch so sticky sessions pick the new exit.
	if !cfg.ClashCloseConnections && (cfg.ClashEnabled || cfg.ClashAPIURL != "" || cfg.ClashProxyURL != "") {
		cfg.ClashCloseConnections = true
	}
	currentConfig.Store(cfg)
	// Drop cached Clash client so new credentials take effect.
	clashMu.Lock()
	clashCached = nil
	clashCfgSnap = clashRuntimeConfig{}
	clashMu.Unlock()
	// 仅在 state_file 路径变化时才重建 store。CPA 在 auth 文件写入(自动刷新/
	// 导入)时会触发插件 reconfigure;无条件重建会让运行中的观测记账写进旧
	// store,随后被新 store 的周期持久化覆盖(记账/事件/统计全部丢失)。
	if store == nil || store.path != cfg.StateFile {
		store = newStateStore(cfg.StateFile)
	}
	if workerCancel != nil {
		workerCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	workerCancel = cancel
	startGuardWorker(ctx, store)
	refreshAssignedCountsAsync(store)
	if loadClashRuntimeConfig().Enabled && cfg.ClashSyncOnStart {
		go func() {
			if _, err := syncClashNodes(store); err != nil {
				store.appendEvent(guardEvent{Event: "clash_sync_failed", Reason: err.Error()})
			}
		}()
	}
	return nil
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "lij768423-svg",
			GitHubRepository: "https://github.com/lij768423-svg/grok2api-egress-enhancements",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "state_file", Type: pluginapi.ConfigFieldTypeString, Description: "出口守护状态文件路径（节点/策略/事件）"},
				{Name: "rotation_url", Type: pluginapi.ConfigFieldTypeString, Description: "可选、受信任的内部换 IP Webhook；仅对 rotatable_node_ids 生效"},
				{Name: "rotation_token_env", Type: pluginapi.ConfigFieldTypeString, Description: "从 CPA 进程环境变量读取 Webhook Bearer Token，避免写入配置"},
				{Name: "rotation_timeout_seconds", Type: pluginapi.ConfigFieldTypeInteger, Description: "换 IP Webhook 超时（秒）"},
				{Name: "rotatable_node_ids", Type: pluginapi.ConfigFieldTypeArray, Description: "允许自动换 IP 的节点 ID；留空时禁止自动换 IP"},
				{Name: "clash_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用本机 Clash/Mihomo 对接（节点列表与切换走 Clash API）"},
				{Name: "clash_api_url", Type: pluginapi.ConfigFieldTypeString, Description: "Clash external-controller，例如 http://172.19.0.1:7888"},
				{Name: "clash_unix_socket", Type: pluginapi.ConfigFieldTypeString, Description: "可选：Clash Unix Socket（仅 CPA 与 Clash 同机）"},
				{Name: "clash_secret_env", Type: pluginapi.ConfigFieldTypeString, Description: "从环境变量读取 Clash secret（默认 CLASH_API_SECRET）"},
				{Name: "clash_secret", Type: pluginapi.ConfigFieldTypeString, Description: "Clash secret（优先用 clash_secret_env）"},
				{Name: "clash_group", Type: pluginapi.ConfigFieldTypeString, Description: "生产策略组（账号流量），默认 🏜️ PerfectAI"},
				{Name: "clash_proxy_url", Type: pluginapi.ConfigFieldTypeString, Description: "生产 mixed-port，例如 http://172.19.0.1:7890"},
				{Name: "clash_close_connections", Type: pluginapi.ConfigFieldTypeBoolean, Description: "生产组切换后关闭旧连接"},
				{Name: "clash_sync_on_start", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启动时从 PerfectAI 同步节点"},
				{Name: "clash_timeout_seconds", Type: pluginapi.ConfigFieldTypeInteger, Description: "Clash API 超时（秒）"},
				{Name: "clash_exclude_keywords", Type: pluginapi.ConfigFieldTypeArray, Description: "同步时排除名称包含这些词的节点"},
				{Name: "clash_prefer_keywords", Type: pluginapi.ConfigFieldTypeArray, Description: "同步时优先这些关键词"},
			},
		},
		Capabilities: registrationCapabilities{ManagementAPI: true, UsagePlugin: true, Scheduler: true, RequestInterceptor: true},
	}
}

func handleManagement(request []byte) ([]byte, error) {
	var req managementRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = resourcePath
	}
	base := "/v0/resource/plugins/" + pluginName
	switch {
	case path == resourcePath, path == "/", path == base, path == base+"/", path == base+resourcePath, strings.HasSuffix(path, "/status"):
		return okEnvelope(managementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"content-type": []string{resourceContentType}},
			Body:       []byte(renderPageHTML()),
		})
	case path == managementAPIPath:
		return handleUIProxy(req)
	default:
		return okEnvelope(managementResponse{
			StatusCode: http.StatusNotFound,
			Headers:    http.Header{"content-type": []string{"text/plain; charset=utf-8"}},
			Body:       []byte("not found"),
		})
	}
}

func handleUIProxy(req managementRequest) ([]byte, error) {
	if !strings.EqualFold(strings.TrimSpace(req.Method), http.MethodPost) || req.Headers.Get("X-Grok2API-Egress-UI") != "1" {
		return managementJSON(http.StatusForbidden, map[string]any{"error": map[string]string{"code": "forbidden", "message": "forbidden"}})
	}
	var input uiProxyRequest
	if len(req.Body) == 0 || json.Unmarshal(req.Body, &input) != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "invalidRequest", "message": "invalid request"}})
	}
	parsed, err := url.ParseRequestURI(strings.TrimSpace(input.Path))
	if err != nil || parsed.IsAbs() || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "invalidPath", "message": "invalid path"}})
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	return dispatchAPI(method, parsed.Path, parsed.Query(), input.Body)
}

func dispatchAPI(method, path string, query url.Values, body json.RawMessage) ([]byte, error) {
	ensureStore()
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")

	switch {
	case path == "/status" || path == "/quality-guard":
		if method != http.MethodGet {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		return managementJSON(http.StatusOK, buildStatus())

	case path == "/auth-stats" || path == "/quality-guard/auth-stats":
		if method == http.MethodGet {
			items := store.listPublicAuthDegradeStats()
			return managementJSON(http.StatusOK, map[string]any{"data": map[string]any{"items": items, "total": len(items)}, "items": items, "total": len(items)})
		}
		if method == http.MethodDelete {
			store.clearAuthDegradeStats()
			return managementJSON(http.StatusOK, map[string]any{"data": map[string]any{"cleared": true}, "ok": true})
		}
		return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))

	case path == "/auth-stats/disabled" || path == "/quality-guard/auth-stats/disabled":
		if method != http.MethodGet {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		items := listPluginDisabledAuthSummaries()
		return managementJSON(http.StatusOK, map[string]any{
			"data":  map[string]any{"items": items, "total": len(items), "disabled_count": len(items)},
			"items": items, "total": len(items),
		})

	case path == "/auth-stats/disable" || path == "/quality-guard/auth-stats/disable":
		if method != http.MethodPost {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		ids := stringIDs(raw["ids"])
		reason, _ := raw["reason"].(string)
		items := make([]map[string]any, 0, len(ids))
		ok := 0
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			a, err := disableAuthByID(id, "manual", reason)
			entry := map[string]any{"auth_id": id, "ok": err == nil}
			if err != nil {
				entry["error"] = err.Error()
			} else {
				ok++
				entry["label"] = firstNonEmpty(a.Email, a.Name, a.ID, a.Index)
			}
			if err == nil {
				store.markAuthDisabled(id, "manual", authDisableReason(a))
				store.appendEvent(guardEvent{Event: "auth_manual_disabled", AuthID: id, Reason: authDisableReason(a)})
			}
			items = append(items, entry)
		}
		return managementJSON(http.StatusOK, map[string]any{"ok": true, "disabled": ok, "items": items, "data": map[string]any{"disabled": ok, "items": items}})

	case path == "/auth-stats/enable" || path == "/quality-guard/auth-stats/enable":
		if method != http.MethodPost {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		ids := stringIDs(raw["ids"])
		resetStats := true
		if v, ok := raw["reset_stats"].(bool); ok {
			resetStats = v
		}
		items := make([]map[string]any, 0, len(ids))
		ok := 0
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			a, err := enableAuthByID(id)
			entry := map[string]any{"auth_id": id, "ok": err == nil}
			if err != nil {
				entry["error"] = err.Error()
			} else {
				ok++
				entry["label"] = firstNonEmpty(a.Email, a.Name, a.ID, a.Index)
			}
			if err == nil {
				store.clearAuthDisabled(id, resetStats)
				store.appendEvent(guardEvent{Event: "auth_manual_enabled", AuthID: id, Reason: "面板手动恢复账号"})
			}
			items = append(items, entry)
		}
		return managementJSON(http.StatusOK, map[string]any{"ok": true, "enabled": ok, "items": items, "data": map[string]any{"enabled": ok, "items": items}})


	case path == "/policy" || path == "/quality-guard/config":
		if method == http.MethodGet {
			return managementJSON(http.StatusOK, map[string]any{"data": publicPolicy(store.policy()), "config": publicPolicy(store.policy())})
		}
		if method == http.MethodPut || method == http.MethodPost {
			var p policyConfig
			// accept both snake and camel
			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "invalid body"))
			}
			p = store.policy()
			p.ConsecutiveErrors = intPick(raw, p.ConsecutiveErrors, "consecutive_errors", "consecutiveErrors")
			p.MinHealthyNodes = intPick(raw, p.MinHealthyNodes, "min_healthy_nodes", "minHealthyNodes")
			p.MinGenerationMs = int64(intPick(raw, int(p.MinGenerationMs), "min_generation_ms", "minGenerationMs"))
			p.MinOutputTokens = int64(intPick(raw, int(p.MinOutputTokens), "min_output_tokens", "minOutputTokens"))
			if v, ok := raw["auth_auto_disable"].(bool); ok {
				p.AuthAutoDisable = v
			}
			if v, ok := raw["authAutoDisable"].(bool); ok {
				p.AuthAutoDisable = v
			}
			if v, ok := raw["node_auto_disable"].(bool); ok {
				p.NodeAutoDisable = v
			}
			if v, ok := raw["nodeAutoDisable"].(bool); ok {
				p.NodeAutoDisable = v
			}
			p.NodeAutoDisableMinQuarantines = intPick(raw, p.NodeAutoDisableMinQuarantines, "node_auto_disable_min_quarantines", "nodeAutoDisableMinQuarantines")
			p.NodeWindowMaxAuths = intPick(raw, p.NodeWindowMaxAuths, "node_window_max_auths", "nodeWindowMaxAuths")
			p.NodeWindowHours = floatPick(raw, p.NodeWindowHours, "node_window_hours", "nodeWindowHours")
			// Preserve schema from body when present so load-time migrations do not re-fire.
			p.PolicySchema = intPick(raw, p.PolicySchema, "policy_schema", "policySchema")
			if err := store.updatePolicy(p); err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("invalidPolicy", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": publicPolicy(store.policy()), "ok": true})
		}

	case path == "/nodes":
		if method == http.MethodGet {
			refreshAssignedCountsAsync(store)
			items := store.listNodes()
			out := make([]map[string]any, 0, len(items))
			for _, n := range items {
				out = append(out, publicNode(n))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": map[string]any{"items": out, "total": len(out)}, "items": out, "total": len(out)})
		}
		if method == http.MethodPost {
			var raw map[string]any
			_ = json.Unmarshal(body, &raw)
			name, _ := raw["name"].(string)
			proxy, _ := raw["proxyURL"].(string)
			if proxy == "" {
				proxy, _ = raw["proxy_url"].(string)
			}
			enabled := true
			if v, ok := raw["enabled"].(bool); ok {
				enabled = v
			}
			pool, _ := raw["proxyPool"].(bool)
			if !pool {
				pool, _ = raw["proxy_pool"].(bool)
			}
			cap := intPick(raw, 0, "accountCapacity", "account_capacity")
			n, err := store.createNode(strings.TrimSpace(name), strings.TrimSpace(proxy), enabled, pool, cap)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("createFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": publicNode(n)})
		}
		if method == http.MethodDelete {
			var raw map[string]any
			_ = json.Unmarshal(body, &raw)
			ids := stringIDs(raw["ids"])
			deleted, _ := deleteManagedNodes(store, ids)
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
		}

	case path == "/nodes/batch":
		if method == http.MethodPatch || method == http.MethodPost {
			var raw map[string]any
			_ = json.Unmarshal(body, &raw)
			ids := stringIDs(raw["ids"])
			if v, ok := raw["enabled"].(bool); ok {
				_ = store.setBatchEnabled(ids, v)
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true})
		}

	case path == "/nodes/import":
		if method == http.MethodPost {
			var raw struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "批量节点数据无效"))
			}
			if len(raw.Items) == 0 || len(raw.Items) > 500 {
				return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "单次需导入 1 到 500 个节点"))
			}
			inputs := make([]nodeCreateInput, 0, len(raw.Items))
			for index, item := range raw.Items {
				name, _ := item["name"].(string)
				proxy, _ := item["proxyURL"].(string)
				if proxy == "" {
					proxy, _ = item["proxy_url"].(string)
				}
				if strings.TrimSpace(name) == "" {
					name = fmt.Sprintf("Node %03d", index+1)
				}
				enabled := true
				if value, ok := item["enabled"].(bool); ok {
					enabled = value
				}
				pool, _ := item["proxyPool"].(bool)
				if !pool {
					pool, _ = item["proxy_pool"].(bool)
				}
				inputs = append(inputs, nodeCreateInput{
					Name:            name,
					ProxyURL:        proxy,
					Enabled:         enabled,
					ProxyPool:       pool,
					AccountCapacity: intPick(item, 0, "accountCapacity", "account_capacity"),
				})
			}
			created, err := store.createNodes(inputs)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("importFailed", err.Error()))
			}
			items := make([]map[string]any, 0, len(created))
			for _, node := range created {
				items = append(items, publicNode(node))
			}
			return managementJSON(http.StatusOK, map[string]any{
				"ok":      true,
				"data":    map[string]any{"items": items, "created": len(items)},
				"items":   items,
				"created": len(items),
			})
		}


	case path == "/nodes/rebalance" || path == "/rebalance":
		if method == http.MethodPost {
			counts, err := rebalanceAuthsToNodes(store)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("rebalanceFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "counts": counts})
		}

	case len(parts) == 2 && parts[0] == "nodes" && safeID(parts[1]):
		id := parts[1]
		if method == http.MethodGet {
			n, ok := store.getNode(id)
			if !ok {
				return managementJSON(http.StatusNotFound, errMsg("notFound", "not found"))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": publicNode(n)})
		}
		if method == http.MethodPut || method == http.MethodPatch {
			var raw map[string]any
			_ = json.Unmarshal(body, &raw)
			n, err := store.updateNode(id, func(node *nodeRecord) error {
				if v, ok := raw["name"].(string); ok && strings.TrimSpace(v) != "" {
					node.Name = strings.TrimSpace(v)
				}
				if v, ok := raw["enabled"].(bool); ok {
					applyOperatorEnabledLocked(node, v, "manual", "面板手动停用")
				}
				if v, ok := raw["proxyPool"].(bool); ok {
					node.ProxyPool = v
				}
				if v, ok := raw["proxy_pool"].(bool); ok {
					node.ProxyPool = v
				}
				if _, ok := raw["accountCapacity"]; ok {
					node.AccountCapacity = intPick(raw, node.AccountCapacity, "accountCapacity", "account_capacity")
				}
				proxy, _ := raw["proxyURL"].(string)
				if proxy == "" {
					proxy, _ = raw["proxy_url"].(string)
				}
				if strings.TrimSpace(proxy) != "" {
					node.ProxyURL = strings.TrimSpace(proxy)
				}
				return nil
			})
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("updateFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": publicNode(n)})
		}
		if method == http.MethodDelete {
			deleted, _ := deleteManagedNodes(store, []string{id})
			if deleted == 0 {
				return managementJSON(http.StatusNotFound, errMsg("notFound", "not found"))
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
		}


	case len(parts) == 3 && parts[0] == "nodes" && safeID(parts[1]) && parts[2] == "accounts":
		if method == http.MethodGet {
			n, ok := store.getNode(parts[1])
			if !ok {
				return managementJSON(http.StatusNotFound, errMsg("notFound", "not found"))
			}
			items, err := listBoundAuthSummaries(n)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("listFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"data": map[string]any{"items": items, "total": len(items)}, "items": items, "total": len(items)})
		}


	case path == "/clash" || path == "/clash/status":
		if method != http.MethodGet {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		return managementJSON(http.StatusOK, map[string]any{"data": clashStatusPayload()})

	case path == "/clash/config":
		if method == http.MethodGet {
			cfg := loadClashRuntimeConfig()
			ui := store.clashUI()
			return managementJSON(http.StatusOK, map[string]any{"data": publicClashUIConfig(ui, cfg), "ok": true})
		}
		if method == http.MethodPut || method == http.MethodPost {
			var raw map[string]any
			if len(body) > 0 {
				if err := json.Unmarshal(body, &raw); err != nil {
					return managementJSON(http.StatusBadRequest, errMsg("invalidBody", "invalid body"))
				}
			}
			in := clashUIConfig{}
			clearSecret := false
			if v, ok := raw["enabled"].(bool); ok {
				in.Enabled = &v
			}
			if v, ok := raw["api_url"].(string); ok {
				in.APIURL = v
			} else if v, ok := raw["apiUrl"].(string); ok {
				in.APIURL = v
			}
			if v, ok := raw["group"].(string); ok {
				in.Group = v
			}
			if v, ok := raw["proxy_url"].(string); ok {
				in.ProxyURL = v
			} else if v, ok := raw["proxyUrl"].(string); ok {
				in.ProxyURL = v
			}
			if v, ok := raw["secret"].(string); ok {
				in.Secret = v
			}
			if v, ok := raw["clear_secret"].(bool); ok && v {
				clearSecret = true
			} else if v, ok := raw["clearSecret"].(bool); ok && v {
				clearSecret = true
			}
			updated, err := store.updateClashUI(in, clearSecret)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("clashConfigFailed", err.Error()))
			}
			// Drop cached client so new endpoint/secret/group take effect immediately.
			clashMu.Lock()
			clashCached = nil
			clashCfgSnap = clashRuntimeConfig{}
			clashMu.Unlock()
			runtime := loadClashRuntimeConfig()
			return managementJSON(http.StatusOK, map[string]any{
				"ok":   true,
				"data": publicClashUIConfig(updated, runtime),
			})
		}
		return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))

	case path == "/clash/groups":
		if method != http.MethodGet {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		groups, err := listClashGroups()
		if err != nil {
			return managementJSON(http.StatusBadRequest, errMsg("clashGroupsFailed", err.Error()))
		}
		return managementJSON(http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"items": groups}, "items": groups})

	case path == "/clash/sync" || path == "/nodes/sync-clash":
		if method != http.MethodPost {
			return managementJSON(http.StatusMethodNotAllowed, errMsg("methodNotAllowed", "method not allowed"))
		}
		r, err := syncClashNodes(store)
		if err != nil {
			return managementJSON(http.StatusBadRequest, errMsg("clashSyncFailed", err.Error()))
		}
		refreshAssignedCountsAsync(store)
		return managementJSON(http.StatusOK, map[string]any{"ok": true, "data": r})

	case len(parts) == 3 && parts[0] == "nodes" && safeID(parts[1]) && (parts[2] == "select" || parts[2] == "clash-select"):
		if method == http.MethodPost {
			r, err := selectClashNodeAPI(store, parts[1])
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("clashSelectFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "data": r})
		}

	case len(parts) == 3 && parts[0] == "nodes" && safeID(parts[1]) && (parts[2] == "quarantine" || parts[2] == "degrade"):
		if method == http.MethodPost {
			reason := "人工降智隔离"
			if len(body) > 0 {
				var raw map[string]any
				if json.Unmarshal(body, &raw) == nil {
					if v, ok := raw["reason"].(string); ok && strings.TrimSpace(v) != "" {
						reason = strings.TrimSpace(v)
					}
				}
			}
			n, err := manualQuarantineNode(store, parts[1], reason)
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("quarantineFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "data": publicNode(n)})
		}

	case len(parts) == 3 && parts[0] == "nodes" && safeID(parts[1]) && (parts[2] == "restore" || parts[2] == "unquarantine"):
		if method == http.MethodPost {
			n, err := restoreQuarantinedNode(store, parts[1])
			if err != nil {
				return managementJSON(http.StatusBadRequest, errMsg("restoreFailed", err.Error()))
			}
			return managementJSON(http.StatusOK, map[string]any{"ok": true, "data": publicNode(n)})
		}
	}

	return managementJSON(http.StatusNotFound, errMsg("notFound", "not found"))
}

func publicPolicy(p policyConfig) map[string]any {
	return map[string]any{
		"consecutive_errors":           p.ConsecutiveErrors,
		"min_healthy_nodes":            p.MinHealthyNodes,
		"min_generation_ms":            p.MinGenerationMs,
		"min_output_tokens":            p.MinOutputTokens,
		"auth_auto_disable":                 p.AuthAutoDisable,
		"node_auto_disable":                 p.NodeAutoDisable,
		"node_auto_disable_min_quarantines": p.NodeAutoDisableMinQuarantines,
		"node_window_max_auths":             p.NodeWindowMaxAuths,
		"node_window_hours":                 p.NodeWindowHours,
		"policy_schema":                p.PolicySchema,
	}
}

func buildStatus() map[string]any {
	ensureStore()
	refreshAssignedCountsAsync(store)
	nodes := store.listNodes()
	nodeMap := map[string]any{}
	for _, n := range nodes {
		nowUnix := float64(time.Now().Unix())
		avail := nodeAvailabilitySnapshot(n, nowUnix)
		nodeMap[n.ID] = map[string]any{
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
			"thinking_strikes":            n.ThinkingStrikes,
			"last_classification":         n.LastClassification,
			"last_output_tps":             n.LastOutputTPS,
			"last_first_token_ms":         n.LastFirstTokenMs,
			"last_duration_ms":            n.LastDurationMs,
			"last_output_tokens":          n.LastOutputTokens,
			"last_reason":                 n.LastReason,
			"last_source":                 n.LastSource,
			"last_observed_at":            n.LastObservedAt,
			"source":                      n.Source,
			"clash_name":                  n.ClashName,
			"clash_group":                 n.ClashGroup,
			"clash_active":                n.ClashActive,
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
		}
	}
	pol := store.policy()
	st := store.stats()
	authStats := store.listPublicAuthDegradeStats()
	return map[string]any{
		"available":         true,
		"updatedAt":         store.snapshot().UpdatedAt,
		"config":            publicPolicy(pol),
		"editable":          true,
		"nodes":             nodeMap,
		"statistics":        st,
		"authStats":         authStats,
		"authDisabledCount": store.countPluginDisabledAuths(),
		"recentEvents":      store.events(),
		"rotation":          recentRotation(50),
		"plugin":            pluginName,
		"version":           pluginVersion,
		"started_at":        startedAt.Format(time.RFC3339),
		"engine":            "cpa-native",
		"clash":             clashStatusPayload(),
		"hint":              "纯 CPA 出口守护：可对接本机 Clash PerfectAI；降智时走 Clash API 切换叶子节点，账号统一走本机 mixed-port。被动观测判定健康，无主动探测流量。",
	}
}

func renderPageHTML() string {
	out := pageTemplate
	out = strings.Replace(out, "/*__HALLMARK_TOKENS__*/", tokenCSS, 1)
	out = strings.Replace(out, "/*__ACCOUNTS_PANEL_CSS__*/", accountsPanelCSS, 1)
	out = strings.Replace(out, "/*__ACCOUNTS_PANEL_JS__*/", accountsPanelJS, 1)
	return out
}

func handleUsage(request []byte) ([]byte, error) {
	ensureStore()
	var payload map[string]any
	if len(request) > 0 {
		_ = json.Unmarshal(request, &payload)
	}
	// Also accept nested record
	if rec, ok := payload["record"].(map[string]any); ok {
		payload = rec
	}
	handlePassiveUsage(store, payload)
	return okEnvelope(map[string]any{"recorded": true})
}

func ensureStore() {
	if store == nil {
		cfg := pluginConfig{StateFile: defaultStateFile}
		if v := currentConfig.Load(); v != nil {
			if c, ok := v.(pluginConfig); ok {
				cfg = c
			}
		}
		store = newStateStore(cfg.StateFile)
	}
}

func managementJSON(status int, v any) ([]byte, error) {
	body, _ := json.Marshal(v)
	// UI expects payload.data — also top-level
	return okEnvelope(managementResponse{
		StatusCode: status,
		Headers:    http.Header{"content-type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	})
}

func errMsg(code, message string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": message}}
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func stringIDs(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

func intPick(raw map[string]any, def int, keys ...string) int {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			return int(anyInt(v))
		}
	}
	return def
}

func floatPick(raw map[string]any, def float64, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			switch t := v.(type) {
			case float64:
				return t
			case int:
				return float64(t)
			case json.Number:
				f, _ := t.Float64()
				return f
			}
		}
	}
	return def
}

func firstString(payload map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	// nested
	for _, wrap := range []string{"usage", "meta", "request", "data"} {
		if m, ok := payload[wrap].(map[string]any); ok {
			if s := firstString(m, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

func firstInt(payload map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			if n := anyInt(v); n != 0 {
				return n
			}
		}
	}
	return 0
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func callHost(method string, payload []byte) (json.RawMessage, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var response C.cliproxy_buffer
	var reqPtr *C.uint8_t
	if len(payload) > 0 {
		reqPtr = (*C.uint8_t)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(reqPtr))
	}
	code := C.call_host_api(cMethod, reqPtr, C.size_t(len(payload)), &response)
	if code != 0 {
		return nil, fmt.Errorf("host callback %s code=%d", method, int(code))
	}
	if response.ptr == nil || response.len == 0 {
		return nil, fmt.Errorf("host callback %s empty", method)
	}
	raw := C.GoBytes(response.ptr, C.int(response.len))
	C.free_host_buffer(response.ptr, response.len)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw, nil
	}
	if !env.OK {
		msg := "host error"
		if env.Error != nil {
			msg = env.Error.Message
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil {
		return
	}
	if len(raw) == 0 {
		response.ptr = nil
		response.len = 0
		return
	}
	response.ptr = C.CBytes(raw)
	response.len = C.size_t(len(raw))
}

// silence unused html import used by tests/templates indirectly
var _ = html.EscapeString

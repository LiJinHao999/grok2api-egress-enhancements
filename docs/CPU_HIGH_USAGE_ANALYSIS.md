# grok2api-egress 高 CPU 占用问题分析报告

| 项 | 内容 |
|---|---|
| 插件 | `grok2api-egress`（CPA 出口守护） |
| 分析基线版本 | v1.0.5（引入 Clash 对接之前） |
| 当前运行环境 | CLIProxyAPI 容器 `cli-proxy-api` |
| 账号规模 | 约 **940+** 个 xAI auth 文件 |
| 观测时间 | 2026-08-04 |
| 严重程度 | **高**（生产上可把 CPA 进程 CPU 推到数百百分比） |

---

## 1. 结论摘要

`grok2api-egress` 的高 CPU **不是** 模型推理、Clash API、或质量探测本身导致的主因。

真正的主因是：

> **对 CPA Host Auth API 做全量账号 N+1 读取，并在多个周期性路径上反复触发。**

核心调用链：

```text
listAuthFiles()
  └─ host.auth.list                     # 1 次
  └─ for each xAI auth:
       getAuthFile(index)
         └─ host.auth.get               # N 次（失败再按 name 再 get 一次）
```

在约 940 个账号的环境中，一次完整 `listAuthFiles()` 就是：

- `1 + ~940` 次 Host 回调（最坏接近 `1 + 1880`）
- 每次回调都走插件 ABI / JSON marshal-unmarshal / 读 auth 文件
- 再叠加后台 30 秒 ticker、管理面板 15 秒刷新、删除/重平衡/状态查询等多条路径

结果就是：**CPU 持续偏高，管理 API 卡顿，删除节点也会像“卡住删不掉”。**

---

## 2. 生产观测证据

### 2.1 运行时 CPU

```text
CONTAINER        CPU %      MEM
cli-proxy-api    780.38%    ~203 MiB
```

说明：这是 CPA 宿主进程整体 CPU。插件以内嵌 `.so` 方式跑在同一进程中，高 CPU 会直接反映在宿主上。

### 2.2 账号规模

```text
/CLIProxyAPI/auths 下 auth 文件总数 ≈ 952
其中 xAI 相关 ≈ 940
```

这是典型“多账号出口守护”规模。插件每次全量扫账号，成本会近似线性增长。

### 2.3 管理 API 延迟

在旧逻辑（同步全量扫账号）期间，面板请求日志曾出现：

```text
POST /v0/management/grok2api-egress/api   9s ~ 13s
```

同一接口在缓解后可降到约：

```text
POST /v0/management/grok2api-egress/api   160ms ~ 270ms
```

说明瓶颈主要是 **插件内部同步 Host Auth 扇出**，不是前端渲染本身。

### 2.4 面板自动刷新放大效应

管理页 `page.html` 默认每 15 秒刷新：

```text
load()
  ├─ GET /quality-guard   → buildStatus() → refreshAssignedCounts(...)
  └─ GET /nodes           → refreshAssignedCounts(...)
```

即：**用户只要开着面板，就会稳定制造周期性全量账号扫描。**

---

## 3. 根因：v1.0.5 原代码中的高成本设计

以下均来自 **Clash 对接之前** 的 v1.0.5 代码（commit `8eda046`）。

### 3.1 `listAuthFiles()` 是经典 N+1

```go
func listAuthFiles() ([]authFile, error) {
    raw, err := hostCall(pluginabi.MethodHostAuthList, ...)
    // ...
    for _, f := range resp.Files {
        // 过滤 xAI
        got, err := getAuthFile(idx)          // 每个账号 1 次 HostAuthGet
        if err != nil && f.Name != "" {
            got, err = getAuthFile(f.Name)    // 失败再 1 次
        }
        // ...
    }
}
```

问题点：

1. **HostAuthList 只返回索引/元数据，不含 `proxy_url`**
2. 插件为了拿到 `proxy_url` / disabled / token 等字段，必须对每个账号再 `HostAuthGet`
3. 该函数被大量业务复用，成为全局热点

### 3.2 后台 worker 每 30 秒强制全量刷新

```go
func startGuardWorker(...) {
    t := time.NewTicker(30 * time.Second)
    for {
        case <-t.C:
            // 可能做质量探测
            refreshAssignedCounts(store)   // 每 30 秒一次全量 listAuthFiles()
    }
}
```

即使没有任何异常、没有任何隔离、面板都没打开，后台也会：

```text
每 30 秒 × 全量账号 N+1 扫描
```

这是 **空载也会烧 CPU** 的关键原因。

### 3.3 `refreshAssignedCounts()` 只为了算“每节点绑了多少账号”

```go
func refreshAssignedCounts(store *stateStore) {
    auths, err := listAuthFiles()   // 全量
    // 用 proxy_url 映射到 node.id，写 assigned_account_count
}
```

它被触发的位置很多（v1.0.5）：

| 触发点 | 频率/时机 | 是否必要 |
|---|---|---|
| `startGuardWorker` 30s ticker | 常驻 | 过高 |
| `GET /nodes` | 面板刷新 / 手动刷新 | 过高（同步） |
| `GET /quality-guard` / `buildStatus` | 面板刷新 | 过高（同步） |
| 启动 `configure` | 启动时一次 | 可接受 |
| rebalance / migrate 后 | 变更后 | 可接受 |

其中 **ticker + 面板轮询** 是持续高 CPU 的主力。

### 3.4 删除节点路径把 N+1 放到了请求关键路径

v1.0.5 删除逻辑：

```go
// DELETE /nodes
for _, id := range ids {
    if n, ok := store.getNode(id); ok {
        auths, _ := listAuthFiles()          // 全量 N+1
        for _, a := range auths {
            if a.ProxyURL == n.ProxyURL {
                setAuthProxyAndFlags(...)    // 再 HostAuthSave
            }
        }
    }
}
store.deleteNodes(ids)
```

后果：

1. **删节点前必须等完整账号扫描结束**
2. 账号越多，删除越慢（常见 10s+）
3. UI 确认按钮长时间 busy，表现为“删不掉 / 卡死”

这不是前端 bug，是后端把 O(账号数) 的 Host I/O 塞进了删除请求。

### 3.5 被动 usage / 调度路径也会间接触发扫号

```go
resolveNodeIDForAuth()
  └─ refreshAuthProxyCache()
       └─ listAuthFiles()   // cache miss 时全量扫
```

`refreshAuthProxyCache` 虽有 15 秒缓存，但：

- cache miss 一次就是全量 N+1
- 与 worker / 面板刷新叠加时，缓存很容易被打穿或刚过期就再扫

---

## 4. 成本模型（为什么 940 账号会很痛）

设：

- `N` = xAI 账号数 ≈ 940
- `C_get` = 单次 `host.auth.get` 成本（磁盘读 + JSON + ABI）
- `F` = 每分钟触发全量扫描次数

### 4.1 单次全量扫描

```text
Cost_once ≈ C_list + N * C_get
         ≈ O(N)
```

实测管理 API 同步扫号时可达 **9–13 秒/次**。

### 4.2 仅后台 worker

```text
F_worker = 2 次/分钟   # 每 30 秒一次
```

### 4.3 面板打开时

```text
F_ui ≈ 4 次/分钟       # 15 秒一轮，且 /status + /nodes 可能各扫一次
F_total ≈ F_worker + F_ui
```

粗算：

```text
每分钟 HostAuthGet 次数 ≈ F_total * N
若 F_total=6, N=940  → 约 5600 次/分钟
若某次 cache 失效重叠 → 瞬时更高
```

这会表现为：

- 容器 CPU 数百百分比
- 管理接口毛刺到秒级
- 删除/重平衡等写路径“假死”

---

## 5. 为什么说“Clash 之前就有”

### 5.1 时间线

| 阶段 | 内容 | 是否已有 N+1 扫号 |
|---|---|---|
| v1.0.5 | 纯手动节点 + proxy_url 粘性 + 质量隔离 | **是** |
| 后续 | 增加 Clash PerfectAI 同步/切换 | 是（并增加共享 proxy 语义） |

### 5.2 Clash 做了什么 / 没做什么

Clash 对接主要增加：

- 从 PerfectAI 同步叶子节点
- 隔离时 `PUT /proxies/{group}` 切换出口
- 多叶子共享同一个 mixed-port `proxy_url`

它 **没有** 发明 `listAuthFiles()` N+1。  
N+1 在 v1.0.5 的 `auth_bind.go` 里已经存在，并且已经被 worker / 状态刷新 / 删除路径使用。

### 5.3 Clash 如何“放大”问题（次要因素）

1. **共享 mixed-port**  
   多个 Clash 叶子节点 `proxy_url` 相同。旧删除逻辑按 `proxy_url` 解绑时，删一个叶子可能误伤整池账号绑定，并引发更多 `HostAuthSave`。

2. **节点数量变多**  
   同步出几十/上百叶子后，面板刷新更频繁、列表更大，但 **CPU 主因仍是账号 N，不是节点 M**。

3. **排查时容易误判**  
   因为问题在接入 Clash 后更明显，容易以为是 Clash API；实际上 Clash API 超时通常是毫秒～数秒级单次调用，撑不起持续数百百分比 CPU。

---

## 6. 已经做过的缓解（本仓库后续修复）

以下修复用于验证根因，并作为给作者的建议基线。

### 6.1 去掉 worker 内的周期全量扫号

```go
// startGuardWorker tick 内
// 旧：refreshAssignedCounts(store)
// 新：不再每 30s 全量扫；改为 UI/迁移后懒刷新
```

### 6.2 `listAuthFiles` 增加短缓存

- 命中缓存则直接返回
- 避免面板 15s 刷新 + worker 30s 刷新叠加时反复 N+1

### 6.3 `refreshAssignedCounts` 改为异步 + 节流

- `GET /nodes`、`buildStatus` 不再同步等待全量扫号
- 增加 in-flight / 时间窗去重，防止风暴

### 6.4 删除节点改为“先删后解绑”

- 先从插件状态删除节点（毫秒级返回）
- 仅对 **独占 proxy_url** 异步清绑定
- 共享 Clash mixed-port 不在删除路径上全量解绑

### 6.5 效果

| 指标 | 旧（同步 N+1） | 缓解后 |
|---|---|---|
| 管理 API | 常见 9–13s | 约 0.16–0.27s |
| 删除节点 | 长时间卡住 | 状态立刻消失 |
| 空载 CPU | 易被周期扫号抬高 | 显著下降（仍取决于是否部署新 so） |

> 注意：若生产仍加载旧 `.so`，源码修复不会生效。必须以实际加载的 plugin 文件/版本为准。

---

## 7. 给作者的修复建议（按优先级）

### P0 — 必须改：消灭默认路径上的全量 N+1

1. **`HostAuthList` 直接返回 `proxy_url` / `disabled` 等插件需要的字段**  
   这是最根本的修复。插件不应为了读一个 proxy 字段对 N 个账号各 get 一次。

2. **或提供批量 `HostAuthGetMany`**  
   至少把 N 次 RPC 收成 1 次。

3. **插件侧对 `listAuthFiles` 做强制缓存/单飞（singleflight）**  
   在 Host API 未改前，这是必要的防护。

### P0 — 必须改：后台 worker 不要周期全量扫账号

- `assigned_account_count` 是展示字段，不应每 30 秒全量重算
- 建议：
  - 仅在 bind/unbind/rebalance/migrate 后增量更新
  - 或最低 5–15 分钟懒刷新
  - 面板展示允许短暂不精确

### P1 — 删除/重平衡等写路径 fail-open

- 删除节点：先改本地状态，再异步清理绑定
- 不要让 Host Auth I/O 阻塞 UI 关键路径
- 共享 proxy（Clash mixed-port）删除叶子时，禁止按 proxy 字符串全量解绑

### P1 — 面板刷新与后端刷新解耦

- 前端 15s 刷新只拉轻量状态
- 后端提供 `ETag` / `updated_at`，无变更则 304
- 避免每次 refresh 都间接触发扫号

### P2 — 可观测性

建议插件暴露：

```text
egress_auth_list_calls_total
egress_auth_get_calls_total
egress_auth_list_duration_seconds
egress_assigned_refresh_total
egress_assigned_refresh_inflight
```

没有这些指标时，高 CPU 很容易被误判成“CPA 本身”或“Clash”。

### P2 — Host API 契约建议

如果作者维护的是 CPA Host 而不是本插件，优先考虑：

| 现状 | 建议 |
|---|---|
| `HostAuthFileEntry` 无 proxy 字段 | 增加 `proxy_url` / `disabled` / `disabled_reason` |
| 只有单条 get | 增加 bulk get |
| list 很轻、get 很重 | 让 list 直接满足调度/统计场景 |

---

## 8. 复现步骤（供作者验证）

1. 准备 **500+** xAI auth 文件（越多越明显）
2. 安装 v1.0.5 逻辑的插件（含 30s `refreshAssignedCounts` + 同步删除扫号）
3. 打开管理页并保持前台（15s 自动刷新）
4. 观察：
   - `docker stats` / 进程 CPU
   - `POST /v0/management/grok2api-egress/api` 延迟
5. 点击删除任意节点：
   - 旧逻辑会先全量 `listAuthFiles`，数秒到十余秒无响应
6. 关闭面板、仅留后台 worker：
   - CPU 仍会因 30s 周期扫号抬升（账号越多越明显）

可选对比实验：

- A：注释掉 worker 里的 `refreshAssignedCounts`  
- B：给 `listAuthFiles` 加 60s 缓存  
- C：删除路径改为先 `deleteNodes` 再异步解绑  

A/B/C 任一落地，CPU 与管理延迟都会立刻下降，可反证根因。

---

## 9. 非根因（排查时容易误判）

| 嫌疑点 | 为什么不是主因 |
|---|---|
| Clash external-controller | 单次 API 成本低；无法解释持续数百 % CPU |
| 主动 quality probe | hybrid/active 下有节流（每 tick 至多 1 个节点），且不是每 30s 全账号扫 |
| 前端 DOM 渲染 | 前端卡只是症状；服务端 API 已先到 10s 级 |
| 单纯“账号文件多” | 文件多不是问题；**每次周期性 N+1 get** 才是问题 |
| 商业流量请求本身 | usage 被动路径有 cache；真正空载高 CPU 来自周期扫号 |

---

## 10. 一句话给作者

> **`grok2api-egress` 在大账号池下会因为“为了读 proxy_url 而对全部 auth 做 HostAuthGet N+1”，再被 30 秒后台任务和管理页刷新反复触发，从而把 CPA 进程 CPU 打满。该设计在 Clash 接入前的 v1.0.5 就已存在；修复重点是 Host Auth 批量/富列表能力，以及插件侧禁止在默认路径上全量扫号。**

---

## 11. 附录：关键代码位置

### v1.0.5（问题基线）

- `cpa-plugin/go/auth_bind.go` → `listAuthFiles` / `getAuthFile` / `refreshAssignedCounts`
- `cpa-plugin/go/guard.go` → `startGuardWorker`（30s + `refreshAssignedCounts`）
- `cpa-plugin/go/main.go` → `GET /nodes`、`buildStatus`、`DELETE /nodes`
- `cpa-plugin/go/page.html` → 15s `setInterval(load)`

### 本仓库后续缓解（参考）

- `listAuthFiles` 缓存
- `refreshAssignedCountsAsync` 节流
- worker 去掉每 30s 全量扫
- `deleteManagedNodes` 先删后异步解绑

---

## 12. 联系与环境信息（可附给作者）

```text
Host: CLIProxyAPI (docker)
Plugin id: grok2api-egress
Auth dir: /CLIProxyAPI/auths
Plugin dir: /CLIProxyAPI/plugins/linux/amd64/
Approx auth count: ~940 xAI
Symptom: CPU multi-core high; management API multi-second latency; node delete appears stuck
Root cause class: periodic full-account HostAuth N+1 fan-out
Clash related: no (amplifier only)
```

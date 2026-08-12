/* accounts-panel.js — 账号降智统计面板（与节点面板解耦） */
(function (global) {
  const PAGE_SIZE = 20;
  const DISABLED_REFRESH_MS = 8000;
  let ctx = null;
  let disabledCache = { at: 0, items: [] };

  const html = `    <div id="panel-accounts" class="panel stack" data-panel-root="accounts" hidden>
      <section class="section" aria-labelledby="auth-degrade-title">
        <div class="section-head">
          <div>
            <h2 id="auth-degrade-title">账号降智统计</h2>
            <p>按账号累计降智次数与样本数。被动观测发现缺 thinking 即记该账号一次降智，按观测账号单独记账，用于交叉检查降智归因（账号 vs 出口）。</p>
            <p class="section-note">只统计模型质量（缺 thinking / 硬阈值）。节点断流、TLS handshake、传输错误只隔离节点，不记入账号降智。降智可能与 IP 有关，也可能与账号有关；仅当样本足够多且降智率持续 100% 时才基本可怀疑是账号问题。达到「自动禁用」阈值（默认 ≥5 个不同节点、降智率 100%、降智次数 >10）会自动禁用，且不再把节点打成全红隔离。</p>
          </div>
          <div class="toolbar">
            <input id="auth-search" class="search" type="search" placeholder="搜索账号 / 标签" aria-label="搜索账号">
            <button id="clear-auth-stats" class="button danger" type="button" title="清空账号降智统计">清空统计</button>
          </div>
        </div>
        <div class="table-wrap desktop-table">
          <table>
            <thead><tr>
              <th>账号</th>
              <th>禁用</th>
              <th class="numeric">降智次数</th>
              <th class="numeric">样本数</th>
              <th class="numeric">降智率</th>
              <th class="numeric">自动禁用进度</th>
              <th>最近出口</th>
              <th>最近原因</th>
              <th>最近时间</th>
              <th>操作</th>
            </tr></thead>
            <tbody id="auth-degrade-body"><tr><td colspan="11" class="loading">正在加载账号统计</td></tr></tbody>
          </table>
        </div>
        <div id="auth-degrade-pager" class="batch-bar" hidden>
          <span id="auth-page-info">第 1 页</span>
          <div class="batch-actions">
            <button id="auth-page-prev" class="button" type="button">上一页</button>
            <button id="auth-page-next" class="button" type="button">下一页</button>
          </div>
        </div>
        <div id="auth-degrade-cards" class="node-cards" aria-label="账号降智卡片"></div>
      </section>

      <section class="section" aria-labelledby="disabled-auths-title">
        <div class="section-head">
          <div>
            <h2 id="disabled-auths-title">插件禁用账号</h2>
            <p class="section-note">插件手动禁用 / 自动禁用 / 节点隔离波及的账号（以 host 账号文件为准）。恢复后重新进入选号候选；「清空统计」不影响这里的禁用状态。</p>
          </div>
          <div class="toolbar">
            <span id="disabled-auths-count" class="badge muted">…</span>
            <button id="restore-all-auths" class="button" type="button" title="恢复列表内全部插件禁用账号">全部恢复</button>
          </div>
        </div>
        <div id="disabled-auths-list" class="account-list"><div class="empty">加载中…</div></div>
      </section>
    </div>
`;

  function $(id) {
    return document.getElementById(id);
  }

  // Module-scope escaper; render() may shadow it with ctx.esc, that is fine.
  function esc(value) {
    return ctx && ctx.esc ? ctx.esc(value) : String(value == null ? '' : value);
  }

  function authStatsList(state) {
    const raw = state?.status?.authStats || state?.status?.auth_stats || [];
    return Array.isArray(raw) ? raw : [];
  }

  function sortedRows(state) {
    const query = String(state.authSearch || '').trim().toLowerCase();
    let rows = authStatsList(state).slice();
    if (query) {
      rows = rows.filter((row) => [row.auth_id, row.label].some((v) => String(v || '').toLowerCase().includes(query)));
    }
    rows.sort((a, b) => {
      const sa = Number(a.sample_count || 0), sb = Number(b.sample_count || 0);
      const da = Number(a.degraded_count || 0), db = Number(b.degraded_count || 0);
      const fullA = sa > 0 && da === sa, fullB = sb > 0 && db === sb;
      if (fullA !== fullB) return fullA ? -1 : 1;
      if (da !== db) return db - da;
      const ra = sa > 0 ? da / sa : 0, rb = sb > 0 ? db / sb : 0;
      if (ra !== rb) return rb - ra;
      return String(a.auth_id || '').localeCompare(String(b.auth_id || ''));
    });
    return rows;
  }

  function rowMeta(row) {
    const samples = Number(row.sample_count || 0);
    const degraded = Number(row.degraded_count || 0);
    const fullRate = samples > 0 && degraded === samples;
    const rate = samples > 0 ? ((degraded / samples) * 100).toFixed(1) + '%' : '-';
    const disabled = Boolean(row.disabled_by_plugin);
    const auto = row.disabled_source === 'auto';
    const badge = disabled
      ? '<span class="badge ' + (auto ? 'bad' : 'muted') + '">' + (auto ? '自动禁用' : '停用') + '</span>'
      : '<span class="badge good">可用</span>';
    const action = disabled ? 'enable' : 'disable';
    const actionText = disabled ? '恢复' : '禁用';
    const progress = disabled
      ? '<span class="progress-line tone-muted">已禁用</span>'
      : '<span class="progress-line' + (degraded ? ' tone-bad' : '') + '" title="任一次缺 thinking 降智即触发自动禁用">' + esc(degraded + '/' + (samples || 0)) + ' 降智</span>';
    return { samples, degraded, fullRate, rate, disabled, auto, badge, action, actionText, progress };
  }

  function actionButton(row, label) {
    const meta = rowMeta(row);
    const id = esc(row.auth_id || '');
    const lab = esc(label);
    return '<div class="auth-actions">' +
      '<button class="button ghost auth-action" type="button" data-auth-action="' + meta.action +
      '" data-auth-id="' + id + '" data-auth-label="' + lab + '">' + meta.actionText + '</button>' +
      '</div>';
  }

  function render(state) {
    if (!ctx) return;
    const body = $('auth-degrade-body');
    const cards = $('auth-degrade-cards');
    const pager = $('auth-degrade-pager');
    if (!body) return;
    const { esc, number, time, relative } = ctx;
    const rows = sortedRows(state);
    const pageSize = Number(state.authPageSize || PAGE_SIZE);
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1);
    let page = Number(state.authPage || 1);
    if (page > totalPages) page = totalPages;
    if (page < 1) page = 1;
    state.authPage = page;
    const start = (page - 1) * pageSize;
    const pageRows = rows.slice(start, start + pageSize);
    if (pager) {
      pager.hidden = total === 0;
      const info = $('auth-page-info');
      if (info) info.textContent = total ? ('第 ' + page + ' / ' + totalPages + ' 页 · 共 ' + total + ' 个账号') : '暂无数据';
      const prev = $('auth-page-prev');
      const next = $('auth-page-next');
      if (prev) prev.disabled = page <= 1;
      if (next) next.disabled = page >= totalPages;
    }
    if (!pageRows.length) {
      const empty = state.authSearch ? '没有匹配的账号' : '暂无账号降智样本';
      body.innerHTML = '<tr><td colspan="11" class="empty">' + empty + '</td></tr>';
      if (cards) cards.innerHTML = '<div class="empty">' + empty + '</div>';
      refreshDisabled(false);
      return;
    }
    body.innerHTML = pageRows.map((row) => {
      const meta = rowMeta(row);
      const label = row.label || row.auth_id || '-';
      const node = row.last_node_name || row.last_node_id || '-';
      const reason = row.last_reason || '-';
      const when = row.last_at ? relative(row.last_at) : '-';
      const authId = row.auth_id || '';
      return '<tr class="' + (meta.fullRate ? 'row-quarantined' : '') + (meta.disabled ? ' row-disabled' : '') + '">' +
        '<td><div class="node-name" title="' + esc(authId) + '">' + esc(label) + '</div><div class="subtext">' + esc(authId) + '</div></td>' +
        '<td>' + meta.badge + '</td>' +
        '<td class="numeric ' + (meta.degraded ? 'tone-bad' : '') + '">' + number(meta.degraded) + '</td>' +
        '<td class="numeric">' + number(meta.samples) + '</td>' +
        '<td class="numeric ' + (meta.fullRate ? 'tone-bad' : (meta.degraded ? 'tone-warn' : '')) + '">' + meta.rate + '</td>' +
        '<td class="numeric">' + meta.progress + '</td>' +
        '<td>' + esc(node) + '</td>' +
        '<td><div class="subtext" title="' + esc(reason) + '">' + esc(reason) + '</div></td>' +
        '<td title="' + esc(time(row.last_at, true)) + '">' + when + '</td>' +
        '<td>' + actionButton(row, label) + '</td>' +
        '</tr>';
    }).join('');
    if (cards) {
      cards.innerHTML = pageRows.map((row) => {
        const meta = rowMeta(row);
        const label = row.label || row.auth_id || '-';
        return '<article class="node-card' + (meta.fullRate ? ' row-quarantined' : '') + (meta.disabled ? ' row-disabled' : '') + '">' +
          '<div class="node-card-head"><div><strong>' + esc(label) + '</strong><div class="subtext">' + esc(row.auth_id || '') + '</div></div>' + meta.badge + '</div>' +
          '<div class="node-card-meta">' +
            '<div><span>样本</span><strong>' + number(meta.samples) + '</strong></div>' +
            '<div><span>降智率</span><strong>' + meta.rate + '</strong></div>' +
            '<div><span>进度</span><strong>' + meta.progress + '</strong></div>' +
            '<div><span>最近出口</span><strong>' + esc(row.last_node_name || row.last_node_id || '-') + '</strong></div>' +
          '</div>' +
          '<div class="subtext" title="' + esc(row.last_reason || '') + '">' + esc(row.last_reason || '-') + '</div>' +
          '<div class="node-card-actions">' + actionButton(row, label) + '</div>' +
        '</article>';
      }).join('');
    }
    refreshDisabled(false);
  }

  function renderDisabled(items) {
    const { esc } = ctx || {};
    const list = $('disabled-auths-list');
    if (!list) return;
    const count = $('disabled-auths-count');
    if (count) {
      count.textContent = '共 ' + items.length + ' 个';
      count.className = 'badge ' + (items.length ? 'bad' : 'good');
    }
    const allBtn = $('restore-all-auths');
    if (allBtn) allBtn.disabled = !items.length;
    if (!items.length) {
      list.innerHTML = '<div class="empty">无插件禁用账号</div>';
      return;
    }
    const srcName = { auto: '自动', manual: '手动', node: '节点' };
    list.innerHTML = items.map((item) => {
      const label = item.label || item.auth_id || '-';
      const reason = item.disabled_reason || '-';
      const src = item.disabled_source || 'other';
      return '<div class="account-row disabled-row">' +
        '<div class="node-name" title="' + esc(item.auth_id || '') + '">' + esc(label) +
          '<div class="subtext">' + esc(item.auth_id || '') + ' · <span class="badge ' + (src === 'auto' ? 'bad' : 'muted') + '">' + (srcName[src] || '插件') + '禁用</span></div></div>' +
        '<div class="row-actions disabled-actions">' +
          '<div class="subtext" title="' + esc(reason) + '">' + esc(reason) + '</div>' +
          '<button class="button ghost" type="button" data-auth-action="enable" data-auth-id="' + esc(item.auth_id || '') + '" data-auth-label="' + esc(label) + '">恢复</button>' +
        '</div></div>';
    }).join('');
  }

  async function refreshDisabled(force) {
    if (!ctx || !ctx.api) return;
    const panel = $('panel-accounts');
    if (!panel || panel.hidden) return;
    const now = Date.now();
    if (!force && now - disabledCache.at < DISABLED_REFRESH_MS) return;
    try {
      const res = await ctx.api('/auth-stats/disabled');
      const items = res.items || res.data?.items || [];
      disabledCache = { at: now, items };
      renderDisabled(items);
    } catch (_) {
      // keep last known list on transient failure
    }
  }

  async function doAuthAction(action, ids, okMsg) {
    if (!ctx || !ctx.api) return;
    try {
      const res = await ctx.api('/auth-stats/' + action, { method: 'POST', body: { ids } });
      const n = action === 'disable' ? (res.disabled ?? res.data?.disabled) : (res.enabled ?? res.data?.enabled);
      ctx.toast(okMsg + '（' + (n ?? ids.length) + ' 个）');
      disabledCache = { at: 0, items: disabledCache.items }; // force next refresh
      if (ctx.load) await ctx.load(true);
      await refreshDisabled(true);
    } catch (error) {
      ctx.toast(error.message, 'error');
    }
  }

  function onPanelAction(event) {
    const btn = event.target.closest('[data-auth-action]');
    if (!btn) return;
    event.preventDefault();
    const action = btn.dataset.authAction;
    const id = btn.dataset.authId;
    const label = btn.dataset.authLabel || id;
    if (!id) return;
    if (action === 'disable') {
      if (!window.confirm('禁用账号「' + label + '」？\n禁用后该账号不再参与选号与调度，可从「插件禁用账号」恢复。')) return;
      doAuthAction('disable', [id], '账号已禁用');
    } else if (action === 'enable') {
      if (!window.confirm('恢复账号「' + label + '」？\n恢复后重新进入选号候选，并清空其降智统计。')) return;
      doAuthAction('enable', [id], '账号已恢复');
    }
  }

  async function onRestoreAll() {
    if (!ctx || !ctx.api) return;
    const items = disabledCache.items || [];
    if (!items.length) return;
    if (!window.confirm('恢复全部 ' + items.length + ' 个插件禁用账号？')) return;
    const ids = items.map((item) => item.auth_id).filter(Boolean);
    await doAuthAction('enable', ids, '已恢复');
  }

  function bind() {
    const { state, api, toast, busy, load } = ctx;
    const root = $('panel-accounts');
    if (root) root.addEventListener('click', onPanelAction);
    if (root) root.addEventListener('change', onPanelAction);
    $('restore-all-auths')?.addEventListener('click', onRestoreAll);
    const authSearch = $('auth-search');
    if (authSearch) {
      authSearch.addEventListener('input', (event) => {
        state.authSearch = event.target.value;
        state.authPage = 1;
        render(state);
      });
    }
    $('auth-page-prev')?.addEventListener('click', () => {
      state.authPage = Math.max(1, Number(state.authPage || 1) - 1);
      render(state);
    });
    $('auth-page-next')?.addEventListener('click', () => {
      state.authPage = Number(state.authPage || 1) + 1;
      render(state);
    });
    $('clear-auth-stats')?.addEventListener('click', async () => {
      if (!window.confirm('清空所有账号降智统计？此操作不可恢复，节点隔离与账号禁用状态不受影响。')) return;
      const button = $('clear-auth-stats');
      busy(button, true);
      try {
        await api('/auth-stats', { method: 'DELETE' });
        toast('账号降智统计已清空');
        await load(true);
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        busy(button, false);
      }
    });
  }

  function mount(options) {
    ctx = options || {};
    if (ctx.state) {
      if (ctx.state.authPage == null) ctx.state.authPage = 1;
      if (ctx.state.authPageSize == null) ctx.state.authPageSize = PAGE_SIZE;
      if (ctx.state.authSearch == null) ctx.state.authSearch = '';
    }
    const host = ctx.host || document.getElementById('panel-accounts-host');
    if (host && !host.dataset.mounted) {
      host.innerHTML = html;
      host.dataset.mounted = '1';
      bind();
    }
    render(ctx.state);
    refreshDisabled(true);
  }

  global.EgressAccountsPanel = { mount, render, bind };
})(window);

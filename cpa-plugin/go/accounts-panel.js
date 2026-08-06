/* accounts-panel.js — 账号降智统计面板（与节点面板解耦） */
(function (global) {
  const PAGE_SIZE = 20;
  let ctx = null;

  const html = `    <div id="panel-accounts" class="panel stack" data-panel-root="accounts" hidden>
      <section class="section" aria-labelledby="auth-degrade-title">
        <div class="section-head">
          <div>
            <h2 id="auth-degrade-title">账号降智统计</h2>
            <p>按账号累计降智次数（最终确认的质量降智事件）；样本数为参与质量判定的成功生成次数。交叉验证确认前不计入降智。</p>
            <p class="section-note">降智可能与 IP 有关，也可能与账号有关。仅当样本足够多且降智率持续 100% 时，才基本可怀疑是账号问题；可再结合风控字段等旁证。本页只展示统计信息。</p>
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
              <th class="numeric">降智次数</th>
              <th class="numeric">样本数</th>
              <th class="numeric">降智率</th>
              <th>最近出口</th>
              <th>最近原因</th>
              <th>最近时间</th>
            </tr></thead>
            <tbody id="auth-degrade-body"><tr><td colspan="7" class="loading">正在加载账号统计</td></tr></tbody>
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
    </div>
`;

  function $(id) {
    return document.getElementById(id);
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
      body.innerHTML = '<tr><td colspan="7" class="empty">' + empty + '</td></tr>';
      if (cards) cards.innerHTML = '<div class="empty">' + empty + '</div>';
      return;
    }
    body.innerHTML = pageRows.map((row) => {
      const samples = Number(row.sample_count || 0);
      const degraded = Number(row.degraded_count || 0);
      const fullRate = samples > 0 && degraded === samples;
      const rate = samples > 0 ? ((degraded / samples) * 100).toFixed(1) + '%' : '-';
      const label = row.label || row.auth_id || '-';
      const node = row.last_node_name || row.last_node_id || '-';
      const reason = row.last_reason || '-';
      const when = row.last_at ? relative(row.last_at) : '-';
      return '<tr class="' + (fullRate ? 'row-quarantined' : '') + '">' +
        '<td><div class="node-name" title="' + esc(row.auth_id || '') + '">' + esc(label) + '</div><div class="subtext">' + esc(row.auth_id || '') + '</div></td>' +
        '<td class="numeric ' + (degraded ? 'tone-bad' : '') + '">' + number(degraded) + '</td>' +
        '<td class="numeric">' + number(samples) + '</td>' +
        '<td class="numeric ' + (fullRate ? 'tone-bad' : (degraded ? 'tone-warn' : '')) + '">' + rate + '</td>' +
        '<td>' + esc(node) + '</td>' +
        '<td><div class="subtext" title="' + esc(reason) + '">' + esc(reason) + '</div></td>' +
        '<td title="' + esc(time(row.last_at, true)) + '">' + when + '</td>' +
        '</tr>';
    }).join('');
    if (cards) {
      cards.innerHTML = pageRows.map((row) => {
        const samples = Number(row.sample_count || 0);
        const degraded = Number(row.degraded_count || 0);
        const fullRate = samples > 0 && degraded === samples;
        const rate = samples > 0 ? ((degraded / samples) * 100).toFixed(1) + '%' : '-';
        const label = row.label || row.auth_id || '-';
        return '<article class="node-card' + (fullRate ? ' row-quarantined' : '') + '">' +
          '<div class="node-card-head"><div><strong>' + esc(label) + '</strong><div class="subtext">' + esc(row.auth_id || '') + '</div></div>' +
          (degraded ? '<span class="badge bad">降智 ' + number(degraded) + '</span>' : '<span class="badge muted">无降智</span>') + '</div>' +
          '<div class="node-card-meta">' +
            '<div><span>样本</span><strong>' + number(samples) + '</strong></div>' +
            '<div><span>降智率</span><strong>' + rate + '</strong></div>' +
            '<div><span>最近出口</span><strong>' + esc(row.last_node_name || row.last_node_id || '-') + '</strong></div>' +
            '<div><span>最近</span><strong>' + (row.last_at ? relative(row.last_at) : '-') + '</strong></div>' +
          '</div>' +
          '<div class="subtext" title="' + esc(row.last_reason || '') + '">' + esc(row.last_reason || '-') + '</div>' +
        '</article>';
      }).join('');
    }
  }

  function bind() {
    const { state, api, toast, busy, load } = ctx;
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
      if (!window.confirm('清空所有账号降智统计？此操作不可恢复，节点隔离状态不受影响。')) return;
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
  }

  global.EgressAccountsPanel = { mount, render, bind };
})(window);

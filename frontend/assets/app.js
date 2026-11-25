/**
 * OMCP ONION — Main SPA Router, Auth, Client Dashboard & Server Management Views
 */
import { api, toast, escapeHtml, formatBytes, openModal, brandLogoSvg } from './api.js';
import { renderAdminApp } from './admin.js';

const state = {
  brand: { panel_name: 'OMCP ONION' },
  user: null,
  area: 'client', // 'client' | 'admin'
  clientRoute: 'servers', // 'servers' | 'server' | 'account'
  adminSection: 'dashboard',
  currentServerId: null,
  currentServerTab: 'console',
  activeWs: null,
  consoleFontSize: 13,
  consoleAutoScroll: true,
  consoleLogs: [],
};

function closeActiveWs() {
  if (state.activeWs) {
    try { state.activeWs.close(); } catch (_) {}
    state.activeWs = null;
  }
}

function applyBranding(brand) {
  state.brand = brand || { panel_name: 'OMCP ONION' };
  document.title = `${state.brand.panel_name || 'OMCP ONION'} — Game Server Control Panel`;
  if (state.brand.panel_favicon) {
    const link = document.getElementById('dynamic-favicon');
    if (link) link.href = state.brand.panel_favicon;
  }
}

function brandHeaderHtml() {
  const logo = state.brand.panel_logo
    ? `<img src="${escapeHtml(state.brand.panel_logo)}" alt="Logo" />`
    : brandLogoSvg();
  return `<div class="brand-lockup" style="margin:0;">${logo}<span class="brand-title">${escapeHtml(state.brand.panel_name || 'OMCP ONION')}</span></div>`;
}

async function boot() {
  try {
    const bootRes = await api.get('/api/auth/bootstrap');
    applyBranding(bootRes.data);
  } catch (_) {}

  try {
    const me = await api.get('/api/auth/user');
    state.user = me.data;
    renderApp();
  } catch (_) {
    renderAuth('login');
  }
}

/* ==================== AUTH VIEWS ==================== */
function renderAuth(mode = 'login') {
  closeActiveWs();
  const app = document.getElementById('app');
  const bgMedia = state.brand.background_video_url
    ? `<video class="auth-bg-media" src="${escapeHtml(state.brand.background_video_url)}" autoplay muted loop playsinline></video>`
    : (state.brand.background_image_url ? `<img class="auth-bg-media" src="${escapeHtml(state.brand.background_image_url)}" alt="" />` : '');

  const showReg = state.brand.needs_initial_setup || state.brand.registration_enabled === 'true';

  app.innerHTML = `
    <div class="auth-shell">
      ${bgMedia}
      <div class="auth-card">
        <div class="brand-lockup">
          ${state.brand.panel_logo ? `<img src="${escapeHtml(state.brand.panel_logo)}" alt="Logo" />` : brandLogoSvg()}
          <div>
            <div class="brand-title">${escapeHtml(state.brand.panel_name || 'OMCP ONION')}</div>
            <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(state.brand.login_branding_subtitle || 'Game Server Orchestration')}</div>
          </div>
        </div>
        ${state.brand.needs_initial_setup ? `<div class="toast info" style="margin-bottom:14px;">First-time setup: create the initial Administrator account.</div>` : ''}
        <div id="auth-form-area"></div>
      </div>
    </div>
  `;

  const area = document.getElementById('auth-form-area');
  if (mode === 'login' && !state.brand.needs_initial_setup) {
    area.innerHTML = `
      <form id="login-form">
        <div class="form-group"><label class="form-label">Username or Email</label><input class="input" name="identifier" required autocomplete="username" /></div>
        <div class="form-group"><label class="form-label">Password</label><input class="input" type="password" name="password" required autocomplete="current-password" /></div>
        <button class="btn btn-primary" style="width:100%;margin-top:6px;" type="submit">Sign In</button>
      </form>
      <div class="btn-row" style="justify-content:space-between;margin-top:16px;font-size:12.5px;">
        ${showReg ? `<a href="#" id="go-reg">Create Account</a>` : `<span></span>`}
        <a href="#" id="go-forgot">Forgot Password?</a>
      </div>
    `;
    document.getElementById('login-form').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api.post('/api/auth/login', { identifier: fd.get('identifier'), password: fd.get('password') });
        api.setToken(res.data.token);
        state.user = res.data.user;
        toast(`Welcome back, ${state.user.username}`, 'success');
        renderApp();
      } catch (err) { toast(err.message, 'error'); }
    };
    const regLink = document.getElementById('go-reg');
    if (regLink) regLink.onclick = (e) => { e.preventDefault(); renderAuth('register'); };
    document.getElementById('go-forgot').onclick = (e) => { e.preventDefault(); renderAuth('forgot'); };
  } else if (mode === 'register' || state.brand.needs_initial_setup) {
    area.innerHTML = `
      <form id="reg-form">
        <div class="form-group"><label class="form-label">Username</label><input class="input" name="username" required minlength="3" /></div>
        <div class="form-group"><label class="form-label">Email</label><input class="input" type="email" name="email" required /></div>
        <div class="form-group"><label class="form-label">Password (min 8 chars)</label><input class="input" type="password" name="password" required minlength="8" /></div>
        <button class="btn btn-primary" style="width:100%;" type="submit">${state.brand.needs_initial_setup ? 'Create Admin Account' : 'Create Account'}</button>
      </form>
      ${!state.brand.needs_initial_setup ? `<div style="margin-top:14px;text-align:center;font-size:12.5px;"><a href="#" id="go-login">Back to Sign In</a></div>` : ''}
    `;
    document.getElementById('reg-form').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api.post('/api/auth/register', {
          username: fd.get('username'), email: fd.get('email'), password: fd.get('password')
        });
        api.setToken(res.data.token);
        state.user = res.data.user;
        state.brand.needs_initial_setup = false;
        toast('Account created!', 'success');
        renderApp();
      } catch (err) { toast(err.message, 'error'); }
    };
    const gl = document.getElementById('go-login');
    if (gl) gl.onclick = (e) => { e.preventDefault(); renderAuth('login'); };
  } else if (mode === 'forgot') {
    area.innerHTML = `
      <form id="forgot-form">
        <div class="form-group"><label class="form-label">Account Email</label><input class="input" type="email" name="email" required /></div>
        <button class="btn btn-primary" style="width:100%;" type="submit">Request Reset Token</button>
      </form>
      <div id="reset-step" style="margin-top:16px;"></div>
      <div style="margin-top:14px;text-align:center;font-size:12.5px;"><a href="#" id="go-login">Back to Sign In</a></div>
    `;
    document.getElementById('go-login').onclick = (e) => { e.preventDefault(); renderAuth('login'); };
    document.getElementById('forgot-form').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api.post('/api/auth/forgot-password', { email: fd.get('email') });
        toast(res.message, 'info');
        const preview = res.data?.reset_token_preview || '';
        document.getElementById('reset-step').innerHTML = `
          <form id="reset-form">
            <div class="form-group"><label class="form-label">Reset Token</label><input class="input mono" name="token" value="${escapeHtml(preview)}" required /></div>
            <div class="form-group"><label class="form-label">New Password</label><input class="input" type="password" name="new_password" minlength="8" required /></div>
            <button class="btn btn-success" style="width:100%;" type="submit">Reset Password</button>
          </form>
        `;
        document.getElementById('reset-form').onsubmit = async (ev) => {
          ev.preventDefault();
          const rfd = new FormData(ev.target);
          try {
            await api.post('/api/auth/reset-password', { token: rfd.get('token'), new_password: rfd.get('new_password') });
            toast('Password updated. Please sign in.', 'success');
            renderAuth('login');
          } catch (err) { toast(err.message, 'error'); }
        };
      } catch (err) { toast(err.message, 'error'); }
    };
  }
}

/* ==================== MAIN SHELL ==================== */
export function renderApp() {
  closeActiveWs();
  if (state.area === 'admin' && state.user?.role === 'admin') {
    renderAdminApp(state, {
      brandHeaderHtml,
      switchToClient: () => { state.area = 'client'; state.clientRoute = 'servers'; renderApp(); },
      logout: doLogout,
      applyBranding,
    });
    return;
  }

  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">${brandHeaderHtml()}</div>
        <nav class="sidebar-nav">
          <div class="nav-section-label">Client Panel</div>
          <button class="nav-item ${state.clientRoute === 'servers' ? 'active' : ''}" data-nav="servers">My Servers</button>
          <button class="nav-item ${state.clientRoute === 'account' ? 'active' : ''}" data-nav="account">Account &amp; API Keys</button>
          ${state.user.role === 'admin' ? `
            <div class="nav-section-label">Administration</div>
            <button class="nav-item" id="switch-admin-btn">Administrator Panel &rarr;</button>
          ` : ''}
        </nav>
        <div class="sidebar-footer">
          <div class="user-chip">
            <div class="avatar">${escapeHtml((state.user.username || 'U')[0].toUpperCase())}</div>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:700;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(state.user.username)}</div>
              <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(state.user.role.toUpperCase())}</div>
            </div>
          </div>
          <button class="btn btn-sm" id="logout-btn">Sign Out</button>
        </div>
      </aside>
      <div class="main-area">
        <header class="topbar">
          <div class="topbar-title">
            <button class="btn btn-sm mobile-toggle" id="mobile-menu-btn">Menu</button>
            <span id="page-title">My Servers</span>
          </div>
          <div class="btn-row" id="topbar-actions"></div>
        </header>
        <main class="content" id="main-content"><div class="boot-screen"><div class="spinner"></div></div></main>
      </div>
    </div>
  `;

  document.getElementById('mobile-menu-btn').onclick = () => document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('logout-btn').onclick = doLogout;
  document.querySelectorAll('[data-nav]').forEach(btn => {
    btn.onclick = () => {
      state.clientRoute = btn.dataset.nav;
      state.currentServerId = null;
      renderApp();
    };
  });
  const adm = document.getElementById('switch-admin-btn');
  if (adm) adm.onclick = () => { state.area = 'admin'; state.adminSection = 'dashboard'; renderApp(); };

  if (state.clientRoute === 'servers') renderServerList();
  else if (state.clientRoute === 'server' && state.currentServerId) renderServerDetail(state.currentServerId);
  else if (state.clientRoute === 'account') renderAccountView();
}

async function doLogout() {
  try { await api.post('/api/auth/logout'); } catch (_) {}
  api.setToken('');
  state.user = null;
  renderAuth('login');
}

/* ==================== CLIENT SERVER DASHBOARD ==================== */
async function renderServerList() {
  document.getElementById('page-title').textContent = 'My Servers';
  const main = document.getElementById('main-content');
  main.innerHTML = `
    <div class="card" style="margin-bottom:16px;">
      <div class="btn-row" style="justify-content:space-between;">
        <div class="btn-row" style="flex:1;">
          <input class="input" id="srv-search" placeholder="Search servers by name or game..." style="max-width:320px;" />
          <select class="select" id="srv-status-filter" style="max-width:170px;">
            <option value="">All Statuses</option>
            <option value="running">Online</option>
            <option value="offline">Offline</option>
            <option value="installing">Installing</option>
          </select>
        </div>
        <button class="btn btn-sm" id="srv-refresh-btn">Refresh</button>
      </div>
    </div>
    <div id="server-cards-grid" class="grid-3"></div>
  `;

  const load = async () => {
    const q = document.getElementById('srv-search').value;
    const st = document.getElementById('srv-status-filter').value;
    const grid = document.getElementById('server-cards-grid');
    try {
      const res = await api.get(`/api/client/servers?search=${encodeURIComponent(q)}&status_filter=${encodeURIComponent(st)}`);
      const servers = res.data || [];
      if (!servers.length) {
        grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;"><h3>No servers found</h3><p style="margin-top:6px;">${state.user.role === 'admin' ? 'Provision a server from the Administrator Panel to get started.' : 'No game servers are assigned to your account yet.'}</p></div>`;
        return;
      }
      grid.innerHTML = servers.map(s => {
        const r = s.resources || {};
        const stName = r.state || s.status || 'offline';
        return `
          <div class="server-card" data-open-srv="${escapeHtml(s.id)}">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
              <div>
                <div style="font-size:16px;font-weight:700;">${escapeHtml(s.name)}</div>
                <div style="font-size:12px;color:var(--text-secondary);">${escapeHtml(s.egg_name)} &bull; ${escapeHtml(s.node_name)}</div>
              </div>
              <span class="status-pill status-${escapeHtml(stName)}"><span class="dot"></span>${escapeHtml(stName)}</span>
            </div>
            <div class="mono" style="color:var(--sky);font-size:12px;">${escapeHtml(s.connection_address)}</div>
            <div class="meter-row">
              <div class="meter-box"><div class="meter-label">CPU</div><div class="meter-val">${Number(r.cpu_percent || 0).toFixed(1)}% / ${s.cpu_percent}%</div></div>
              <div class="meter-box"><div class="meter-label">RAM</div><div class="meter-val">${formatBytes(r.memory_bytes)} / ${s.memory_mb}MB</div></div>
              <div class="meter-box"><div class="meter-label">Disk</div><div class="meter-val">${formatBytes(r.disk_bytes)}</div></div>
            </div>
            <div class="btn-row" style="justify-content:space-between;">
              <div class="btn-row">
                <button class="btn btn-sm btn-success" data-power="start" data-id="${escapeHtml(s.id)}">Start</button>
                <button class="btn btn-sm btn-warning" data-power="restart" data-id="${escapeHtml(s.id)}">Restart</button>
                <button class="btn btn-sm btn-danger" data-power="stop" data-id="${escapeHtml(s.id)}">Stop</button>
              </div>
              <span style="font-size:11px;color:var(--text-muted);">Net: ${formatBytes((r.network_rx_bytes || 0) + (r.network_tx_bytes || 0))}</span>
            </div>
          </div>
        `;
      }).join('');

      grid.querySelectorAll('[data-open-srv]').forEach(card => {
        card.onclick = (e) => {
          if (e.target.closest('[data-power]')) return;
          state.clientRoute = 'server';
          state.currentServerId = card.dataset.openSrv;
          state.currentServerTab = 'console';
          renderApp();
        };
      });
      grid.querySelectorAll('[data-power]').forEach(btn => {
        btn.onclick = async (e) => {
          e.stopPropagation();
          try {
            await api.post(`/api/client/servers/${btn.dataset.id}/power`, { action: btn.dataset.power });
            toast(`Power action '${btn.dataset.power}' dispatched`, 'success');
            setTimeout(load, 450);
          } catch (err) { toast(err.message, 'error'); }
        };
      });
    } catch (err) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">Error loading servers: ${escapeHtml(err.message)}</div>`;
    }
  };

  document.getElementById('srv-search').oninput = load;
  document.getElementById('srv-status-filter').onchange = load;
  document.getElementById('srv-refresh-btn').onclick = load;
  load();
}

/* ==================== SERVER MANAGEMENT DETAIL ==================== */
async function renderServerDetail(serverId) {
  const main = document.getElementById('main-content');
  let srv;
  try {
    const res = await api.get(`/api/client/servers/${serverId}`);
    srv = res.data;
  } catch (err) {
    main.innerHTML = `<div class="empty-state">${escapeHtml(err.message)}</div>`;
    return;
  }

  document.getElementById('page-title').innerHTML = `
    <button class="btn btn-sm" id="back-to-servers">&larr; Servers</button>
    <span>${escapeHtml(srv.name)}</span>
    <span class="mono" style="font-size:12px;color:var(--sky);">${escapeHtml(srv.connection_address)}</span>
  `;
  document.getElementById('back-to-servers').onclick = () => { state.clientRoute = 'servers'; renderApp(); };

  const perms = new Set(srv.permissions || []);
  const tabs = [
    { id: 'console', label: 'Console', req: 'console.access' },
    { id: 'files', label: 'Files', req: 'file.read' },
    { id: 'startup', label: 'Startup', req: 'startup.manage' },
    { id: 'backups', label: 'Backups', req: 'backup.manage' },
    { id: 'schedules', label: 'Schedules', req: 'schedule.manage' },
    { id: 'users', label: 'Users', req: 'user.manage' },
    { id: 'databases', label: 'Databases', req: 'database.manage' },
    { id: 'network', label: 'Network', req: 'network.manage' },
    { id: 'settings', label: 'Settings', req: 'settings.manage' },
    { id: 'activity', label: 'Activity', req: 'activity.read' },
  ].filter(t => perms.has(t.req));

  if (!tabs.some(t => t.id === state.currentServerTab) && tabs.length) {
    state.currentServerTab = tabs[0].id;
  }

  main.innerHTML = `
    <div class="server-tabs">
      ${tabs.map(t => `<button class="tab-btn ${state.currentServerTab === t.id ? 'active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
    </div>
    <div id="server-tab-body"></div>
  `;

  main.querySelectorAll('[data-tab]').forEach(btn => {
    btn.onclick = () => {
      closeActiveWs();
      state.currentServerTab = btn.dataset.tab;
      renderServerDetail(serverId);
    };
  });

  const body = document.getElementById('server-tab-body');
  const handlers = {
    console: () => renderConsoleTab(srv, perms, body),
    files: () => renderFilesTab(srv, perms, body),
    startup: () => renderStartupTab(srv, body),
    backups: () => renderBackupsTab(srv, body),
    schedules: () => renderSchedulesTab(srv, body),
    users: () => renderSubusersTab(srv, body),
    databases: () => renderDatabasesTab(srv, body),
    network: () => renderNetworkTab(srv, body),
    settings: () => renderSettingsTab(srv, body),
    activity: () => renderActivityTab(srv, body),
  };
  if (handlers[state.currentServerTab]) handlers[state.currentServerTab]();
}

/* ---- 1. LIVE CONSOLE ---- */
function renderConsoleTab(srv, perms, body) {
  state.consoleLogs = [];
  const res = srv.resources || {};
  body.innerHTML = `
    <div class="grid-4">
      <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value" id="con-state">${escapeHtml(res.state || srv.status)}</div><div class="stat-sub" id="ws-conn-badge">Connecting WebSocket...</div></div>
      <div class="stat-card"><div class="stat-label">CPU Usage</div><div class="stat-value" id="con-cpu">${Number(res.cpu_percent || 0).toFixed(1)}%</div><div class="stat-sub">Limit: ${srv.cpu_percent}%</div></div>
      <div class="stat-card"><div class="stat-label">Memory</div><div class="stat-value" id="con-ram">${formatBytes(res.memory_bytes)}</div><div class="stat-sub">Limit: ${srv.memory_mb} MB</div></div>
      <div class="stat-card"><div class="stat-label">Disk Usage</div><div class="stat-value" id="con-disk">${formatBytes(res.disk_bytes)}</div><div class="stat-sub">Limit: ${srv.disk_mb} MB</div></div>
    </div>
    <div class="console-box">
      <div class="console-toolbar">
        <div class="btn-row">
          ${perms.has('power.control') ? `
            <button class="btn btn-sm btn-success" data-act="start">Start</button>
            <button class="btn btn-sm btn-warning" data-act="restart">Restart</button>
            <button class="btn btn-sm btn-danger" data-act="stop">Stop</button>
            <button class="btn btn-sm btn-danger" data-act="kill">Kill</button>
          ` : ''}
        </div>
        <div class="btn-row">
          <input class="input" id="con-search" placeholder="Search console..." style="width:170px;padding:5px 9px;" />
          <label style="font-size:12px;display:flex;align-items:center;gap:5px;"><input type="checkbox" id="con-autoscroll" ${state.consoleAutoScroll ? 'checked' : ''} /> Auto-scroll</label>
          <select class="select" id="con-font" style="width:82px;padding:4px 6px;">
            <option value="11" ${state.consoleFontSize === 11 ? 'selected' : ''}>11px</option>
            <option value="13" ${state.consoleFontSize === 13 ? 'selected' : ''}>13px</option>
            <option value="15" ${state.consoleFontSize === 15 ? 'selected' : ''}>15px</option>
          </select>
          <button class="btn btn-sm" id="con-clear">Clear</button>
        </div>
      </div>
      <div class="console-output" id="con-output" style="font-size:${state.consoleFontSize}px;"></div>
      ${perms.has('console.command') ? `
        <form class="console-input-row" id="con-cmd-form">
          <input id="con-cmd-input" placeholder="Type a server command (e.g. status, say Hello, stop) and press Enter..." autocomplete="off" />
          <button class="btn btn-primary" style="border-radius:0;" type="submit">Send</button>
        </form>
      ` : ''}
    </div>
  `;

  const outEl = document.getElementById('con-output');
  const renderLines = () => {
    const q = (document.getElementById('con-search')?.value || '').toLowerCase();
    outEl.innerHTML = state.consoleLogs.map(line => {
      const safe = escapeHtml(line);
      return q && line.toLowerCase().includes(q) ? `<div class="console-line-match">${safe}</div>` : `<div>${safe}</div>`;
    }).join('');
    if (state.consoleAutoScroll) outEl.scrollTop = outEl.scrollHeight;
  };

  document.getElementById('con-search').oninput = renderLines;
  document.getElementById('con-autoscroll').onchange = (e) => { state.consoleAutoScroll = e.target.checked; };
  document.getElementById('con-font').onchange = (e) => { state.consoleFontSize = Number(e.target.value); outEl.style.fontSize = `${state.consoleFontSize}px`; };
  document.getElementById('con-clear').onclick = () => { state.consoleLogs = []; renderLines(); };

  body.querySelectorAll('[data-act]').forEach(btn => {
    btn.onclick = async () => {
      try {
        const res = await api.post(`/api/client/servers/${srv.id}/power`, { action: btn.dataset.act });
        document.getElementById('con-state').textContent = res.data.state;
        toast(`Sent '${btn.dataset.act}'`, 'success');
      } catch (err) { toast(err.message, 'error'); }
    };
  });

  const cmdForm = document.getElementById('con-cmd-form');
  if (cmdForm) {
    cmdForm.onsubmit = async (e) => {
      e.preventDefault();
      const inp = document.getElementById('con-cmd-input');
      const cmd = inp.value.trim();
      if (!cmd) return;
      inp.value = '';
      if (state.activeWs && state.activeWs.readyState === WebSocket.OPEN) {
        state.activeWs.send(JSON.stringify({ type: 'command', command: cmd }));
      } else {
        try { await api.post(`/api/client/servers/${srv.id}/command`, { command: cmd }); }
        catch (err) { toast(err.message, 'error'); }
      }
    };
  }

  const connectWs = () => {
    const ws = new WebSocket(api.wsUrl(`/api/client/servers/${srv.id}/console/ws`));
    state.activeWs = ws;
    ws.onopen = () => { const b = document.getElementById('ws-conn-badge'); if (b) b.textContent = 'WebSocket Connected'; };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'log') {
          state.consoleLogs.push(msg.line);
          if (state.consoleLogs.length > 600) state.consoleLogs.shift();
          renderLines();
        } else if (msg.type === 'status') {
          const sEl = document.getElementById('con-state');
          if (sEl) sEl.textContent = msg.state;
        } else if (msg.type === 'error') {
          toast(msg.detail, 'error');
        }
      } catch (_) {}
    };
    ws.onclose = () => {
      const b = document.getElementById('ws-conn-badge');
      if (b) b.textContent = 'Reconnecting...';
      if (state.currentServerId === srv.id && state.currentServerTab === 'console') {
        setTimeout(() => { if (state.currentServerTab === 'console') connectWs(); }, 2500);
      }
    };
  };
  connectWs();
}

/* ---- 2. FILE & ARCHIVE MANAGER ---- */
function renderFilesTab(srv, perms, body, currentDir = '') {
  let selected = new Set();
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="btn-row" style="justify-content:space-between;margin-bottom:10px;">
        <div class="breadcrumbs" id="fm-breadcrumbs"></div>
        <div class="btn-row">
          <input class="input" id="fm-search" placeholder="Search files..." style="width:180px;padding:6px 10px;" />
          ${perms.has('file.write') ? `<button class="btn btn-sm" id="fm-new-file">+ File</button><button class="btn btn-sm" id="fm-new-dir">+ Folder</button>` : ''}
          ${perms.has('file.upload') ? `<label class="btn btn-sm btn-primary" style="cursor:pointer;">Upload<input type="file" id="fm-upload-input" multiple hidden /></label>` : ''}
          ${perms.has('file.write') ? `<button class="btn btn-sm" id="fm-zip-btn">Create ZIP</button>` : ''}
          ${perms.has('file.delete') ? `<button class="btn btn-sm btn-danger" id="fm-bulk-del">Delete Selected</button>` : ''}
        </div>
      </div>
      ${perms.has('file.upload') ? `<div class="dropzone" id="fm-dropzone">Drag and drop files here to upload to <span class="mono">/${escapeHtml(currentDir)}</span></div>` : ''}
      <div style="font-size:12px;color:var(--text-muted);" id="fm-storage">Loading storage...</div>
    </div>
    <div class="table-wrap"><table><thead><tr><th style="width:34px;"><input type="checkbox" id="fm-check-all" /></th><th>Name</th><th>Size</th><th>Mode</th><th>Modified</th><th>Actions</th></tr></thead><tbody id="fm-rows"></tbody></table></div>
  `;

  const renderCrumbs = () => {
    const parts = currentDir ? currentDir.split('/').filter(Boolean) : [];
    const bc = document.getElementById('fm-breadcrumbs');
    let html = `<button data-dir="">/root</button>`;
    let acc = '';
    parts.forEach(p => {
      acc = acc ? `${acc}/${p}` : p;
      html += ` / <button data-dir="${escapeHtml(acc)}">${escapeHtml(p)}</button>`;
    });
    bc.innerHTML = html;
    bc.querySelectorAll('button').forEach(b => b.onclick = () => renderFilesTab(srv, perms, body, b.dataset.dir));
  };

  const loadFiles = async (search = '') => {
    renderCrumbs();
    try {
      const res = await api.get(`/api/client/servers/${srv.id}/files?directory=${encodeURIComponent(currentDir)}&search=${encodeURIComponent(search)}`);
      const files = res.data.files || [];
      document.getElementById('fm-storage').textContent = `Storage used: ${formatBytes(res.data.storage_used_bytes)} / ${srv.disk_mb} MB`;
      const tbody = document.getElementById('fm-rows');
      if (!files.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:28px;">Directory is empty.</td></tr>`;
        return;
      }
      tbody.innerHTML = files.map(f => {
        const isArch = /\.(zip|tar|tar\.gz|tgz|tar\.bz2|tar\.xz)$/i.test(f.name);
        return `
          <tr>
            <td><input type="checkbox" class="fm-sel" value="${escapeHtml(f.path)}" /></td>
            <td>
              <button class="btn btn-sm" style="background:none;border:none;padding:0;color:${f.is_dir ? 'var(--amber)' : 'var(--text-primary)'};" data-open="${escapeHtml(f.path)}" data-isdir="${f.is_dir ? '1' : '0'}">
                ${f.is_dir ? '&#128193;' : '&#128196;'} ${escapeHtml(f.name)}
              </button>
            </td>
            <td class="mono">${f.is_dir ? '—' : formatBytes(f.size)}</td>
            <td class="mono">${escapeHtml(f.mode)}</td>
            <td style="font-size:12px;color:var(--text-muted);">${escapeHtml(f.modified_at)}</td>
            <td>
              <div class="btn-row">
                ${!f.is_dir ? `<a class="btn btn-sm" href="/api/client/servers/${srv.id}/files/download?path=${encodeURIComponent(f.path)}" target="_blank">Download</a>` : ''}
                ${isArch && perms.has('file.write') ? `<button class="btn btn-sm btn-warning" data-extract="${escapeHtml(f.path)}">Extract</button>` : ''}
                ${perms.has('file.write') ? `<button class="btn btn-sm" data-rename="${escapeHtml(f.path)}">Rename</button>` : ''}
                ${perms.has('file.delete') ? `<button class="btn btn-sm btn-danger" data-del="${escapeHtml(f.path)}">Delete</button>` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');

      tbody.querySelectorAll('.fm-sel').forEach(cb => {
        cb.onchange = () => { cb.checked ? selected.add(cb.value) : selected.delete(cb.value); };
      });
      tbody.querySelectorAll('[data-open]').forEach(btn => {
        btn.onclick = () => {
          if (btn.dataset.isdir === '1') renderFilesTab(srv, perms, body, btn.dataset.open);
          else openFileEditor(srv, btn.dataset.open, perms.has('file.write'));
        };
      });
      tbody.querySelectorAll('[data-extract]').forEach(btn => {
        btn.onclick = async () => {
          try {
            const r = await api.post(`/api/client/servers/${srv.id}/files/extract`, { archive_path: btn.dataset.extract, destination: currentDir, overwrite: false });
            toast(`Extracted ${r.data.extracted_count} files`, 'success');
            loadFiles();
          } catch (err) { toast(err.message, 'error'); }
        };
      });
      tbody.querySelectorAll('[data-rename]').forEach(btn => {
        btn.onclick = () => {
          const oldPath = btn.dataset.rename;
          openModal('Rename / Move File', `<div class="form-group"><label class="form-label">New Path</label><input class="input mono" id="ren-dst" value="${escapeHtml(oldPath)}" /></div><button class="btn btn-primary" id="ren-save">Save</button>`, (close) => {
            document.getElementById('ren-save').onclick = async () => {
              try {
                await api.post(`/api/client/servers/${srv.id}/files/rename`, { source: oldPath, destination: document.getElementById('ren-dst').value });
                toast('Renamed successfully', 'success');
                close(); loadFiles();
              } catch (err) { toast(err.message, 'error'); }
            };
          });
        };
      });
      tbody.querySelectorAll('[data-del]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm(`Delete ${btn.dataset.del}?`)) return;
          try {
            await api.post(`/api/client/servers/${srv.id}/files/delete`, { paths: [btn.dataset.del] });
            toast('Deleted', 'success'); loadFiles();
          } catch (err) { toast(err.message, 'error'); }
        };
      });
    } catch (err) { toast(err.message, 'error'); }
  };

  document.getElementById('fm-search').oninput = (e) => loadFiles(e.target.value);
  document.getElementById('fm-check-all').onchange = (e) => {
    document.querySelectorAll('.fm-sel').forEach(cb => { cb.checked = e.target.checked; cb.checked ? selected.add(cb.value) : selected.delete(cb.value); });
  };
  const nf = document.getElementById('fm-new-file');
  if (nf) nf.onclick = () => openModal('Create File', `<div class="form-group"><label class="form-label">Filename</label><input class="input mono" id="nf-name" placeholder="config.yml" /></div><div class="form-group"><label class="form-label">Content</label><textarea class="code-editor" id="nf-content" style="min-height:180px;"></textarea></div><button class="btn btn-primary" id="nf-save">Create</button>`, (close) => {
    document.getElementById('nf-save').onclick = async () => {
      const fn = document.getElementById('nf-name').value.trim();
      if (!fn) return;
      const p = currentDir ? `${currentDir}/${fn}` : fn;
      try { await api.post(`/api/client/servers/${srv.id}/files/write`, { path: p, content: document.getElementById('nf-content').value }); toast('File created', 'success'); close(); loadFiles(); }
      catch (err) { toast(err.message, 'error'); }
    };
  });
  const nd = document.getElementById('fm-new-dir');
  if (nd) nd.onclick = () => openModal('Create Folder', `<div class="form-group"><label class="form-label">Folder Name</label><input class="input mono" id="nd-name" placeholder="plugins" /></div><button class="btn btn-primary" id="nd-save">Create</button>`, (close) => {
    document.getElementById('nd-save').onclick = async () => {
      const fn = document.getElementById('nd-name').value.trim();
      if (!fn) return;
      const p = currentDir ? `${currentDir}/${fn}` : fn;
      try { await api.post(`/api/client/servers/${srv.id}/files/mkdir`, { path: p }); toast('Folder created', 'success'); close(); loadFiles(); }
      catch (err) { toast(err.message, 'error'); }
    };
  });
  const uploadFiles = async (fileList) => {
    for (const file of fileList) {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('directory', currentDir);
      try { await api.post(`/api/client/servers/${srv.id}/files/upload`, fd); toast(`Uploaded ${file.name}`, 'success'); }
      catch (err) { toast(`Upload failed: ${err.message}`, 'error'); }
    }
    loadFiles();
  };
  const upInp = document.getElementById('fm-upload-input');
  if (upInp) upInp.onchange = (e) => uploadFiles(e.target.files);
  const dz = document.getElementById('fm-dropzone');
  if (dz) {
    dz.ondragover = (e) => { e.preventDefault(); dz.classList.add('dragover'); };
    dz.ondragleave = () => dz.classList.remove('dragover');
    dz.ondrop = (e) => { e.preventDefault(); dz.classList.remove('dragover'); uploadFiles(e.dataTransfer.files); };
  }
  const zipBtn = document.getElementById('fm-zip-btn');
  if (zipBtn) zipBtn.onclick = async () => {
    if (!selected.size) return toast('Select files to compress first', 'info');
    try {
      const r = await api.post(`/api/client/servers/${srv.id}/files/compress`, { paths: [...selected], archive_name: `archive_${Date.now()}.zip`, directory: currentDir });
      toast(`Created ${r.data.archive}`, 'success'); loadFiles();
    } catch (err) { toast(err.message, 'error'); }
  };
  const bdBtn = document.getElementById('fm-bulk-del');
  if (bdBtn) bdBtn.onclick = async () => {
    if (!selected.size || !confirm(`Delete ${selected.size} selected items?`)) return;
    try { await api.post(`/api/client/servers/${srv.id}/files/delete`, { paths: [...selected] }); selected.clear(); toast('Deleted selected items', 'success'); loadFiles(); }
    catch (err) { toast(err.message, 'error'); }
  };

  loadFiles();
}

async function openFileEditor(srv, path, canWrite) {
  try {
    const res = await api.get(`/api/client/servers/${srv.id}/files/read?path=${encodeURIComponent(path)}`);
    openModal(`Editor — ${path}`, `
      <textarea class="code-editor" id="ed-content" ${canWrite ? '' : 'readonly'}>${escapeHtml(res.data.content)}</textarea>
      <div class="btn-row" style="justify-content:flex-end;margin-top:12px;">
        ${canWrite ? `<button class="btn btn-primary" id="ed-save">Save Changes</button>` : ''}
      </div>
    `, (close) => {
      const sv = document.getElementById('ed-save');
      if (sv) sv.onclick = async () => {
        try { await api.post(`/api/client/servers/${srv.id}/files/write`, { path, content: document.getElementById('ed-content').value }); toast('Saved file', 'success'); close(); }
        catch (err) { toast(err.message, 'error'); }
      };
    });
  } catch (err) { toast(err.message, 'error'); }
}

/* ---- 3. STARTUP ---- */
function renderStartupTab(srv, body) {
  const imgs = srv.available_images?.length ? srv.available_images : [srv.docker_image];
  body.innerHTML = `
    <div class="card">
      <div class="card-title" style="margin-bottom:14px;">Startup &amp; Runtime Configuration</div>
      <form id="startup-form">
        <div class="form-group"><label class="form-label">Startup Command</label><input class="input mono" name="startup_command" value="${escapeHtml(srv.startup_command)}" /></div>
        <div class="form-group"><label class="form-label">Docker / Runtime Image</label>
          <select class="select mono" name="docker_image">
            ${imgs.map(i => `<option value="${escapeHtml(i)}" ${i === srv.docker_image ? 'selected' : ''}>${escapeHtml(i)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group"><label class="form-label">Environment Variables (JSON)</label><textarea class="textarea" name="env_vars">${escapeHtml(JSON.stringify(srv.env_vars || {}, null, 2))}</textarea></div>
        <button class="btn btn-primary" type="submit">Save Startup Config</button>
      </form>
    </div>
  `;
  document.getElementById('startup-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const envObj = JSON.parse(fd.get('env_vars') || '{}');
      await api.put(`/api/client/servers/${srv.id}/startup`, { startup_command: fd.get('startup_command'), docker_image: fd.get('docker_image'), env_vars: envObj });
      toast('Startup configuration saved', 'success');
    } catch (err) { toast(err.message, 'error'); }
  };
}

/* ---- 4. BACKUPS ---- */
async function renderBackupsTab(srv, body) {
  const res = await api.get(`/api/client/servers/${srv.id}/backups`);
  const list = res.data || [];
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="btn-row" style="justify-content:space-between;">
        <div><strong>Backups</strong> <span class="badge">${list.length} / ${res.limit}</span></div>
        <form id="bk-create-form" class="btn-row">
          <input class="input" name="name" placeholder="Backup name (optional)" style="width:220px;" />
          <button class="btn btn-primary" type="submit">Create Backup</button>
        </form>
      </div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Size</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>
      ${list.length ? list.map(b => `
        <tr>
          <td>${escapeHtml(b.name)}</td>
          <td class="mono">${formatBytes(b.size_bytes)}</td>
          <td><span class="status-pill status-${escapeHtml(b.status)}">${escapeHtml(b.status)}</span></td>
          <td style="font-size:12px;color:var(--text-muted);">${escapeHtml(b.created_at)}</td>
          <td class="btn-row">
            <a class="btn btn-sm" href="/api/client/servers/${srv.id}/backups/${b.id}/download" target="_blank">Download</a>
            <button class="btn btn-sm btn-warning" data-restore="${b.id}">Restore</button>
            <button class="btn btn-sm btn-danger" data-del-bk="${b.id}">Delete</button>
          </td>
        </tr>
      `).join('') : `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No backups yet.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('bk-create-form').onsubmit = async (e) => {
    e.preventDefault();
    try { await api.post(`/api/client/servers/${srv.id}/backups`, { name: new FormData(e.target).get('name') }); toast('Backup created', 'success'); renderBackupsTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  };
  body.querySelectorAll('[data-restore]').forEach(btn => btn.onclick = async () => {
    if (!confirm('Restore this backup safely (existing unrelated files will be preserved)?')) return;
    try { await api.post(`/api/client/servers/${srv.id}/backups/${btn.dataset.restore}/restore`, { truncate: false }); toast('Backup restored safely', 'success'); }
    catch (err) { toast(err.message, 'error'); }
  });
  body.querySelectorAll('[data-del-bk]').forEach(btn => btn.onclick = async () => {
    if (!confirm('Delete this backup?')) return;
    try { await api.del(`/api/client/servers/${srv.id}/backups/${btn.dataset.delBk}`); toast('Backup deleted', 'success'); renderBackupsTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
}

/* ---- 5. SCHEDULES ---- */
async function renderSchedulesTab(srv, body) {
  const res = await api.get(`/api/client/servers/${srv.id}/schedules`);
  const list = res.data || [];
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title" style="margin-bottom:10px;">Create Schedule</div>
      <form id="sch-form" class="btn-row">
        <input class="input" name="name" placeholder="Nightly Backup" required style="width:180px;" />
        <input class="input mono" name="cron" value="0 4 * * *" required style="width:130px;" />
        <select class="select" name="action" style="width:140px;"><option value="command">Console Command</option><option value="backup">Create Backup</option><option value="power">Power Action</option></select>
        <input class="input mono" name="payload" placeholder="say Saving... / restart" style="width:200px;" />
        <button class="btn btn-primary" type="submit">Add Schedule</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Cron</th><th>Next Run</th><th>Last Status</th><th>Tasks</th><th>Actions</th></tr></thead><tbody>
      ${list.length ? list.map(s => `
        <tr>
          <td><strong>${escapeHtml(s.name)}</strong></td>
          <td class="mono">${escapeHtml(s.cron_expression)}</td>
          <td style="font-size:12px;">${escapeHtml(s.next_run_at || '—')}</td>
          <td><span class="status-pill status-${s.last_status === 'failed' ? 'failed' : 'running'}">${escapeHtml(s.last_status)}</span></td>
          <td style="font-size:12px;">${(s.tasks || []).map(t => `${escapeHtml(t.action)}: ${escapeHtml(t.payload)}`).join(', ')}</td>
          <td class="btn-row">
            <button class="btn btn-sm btn-success" data-run-sch="${s.id}">Run Now</button>
            <button class="btn btn-sm btn-danger" data-del-sch="${s.id}">Delete</button>
          </td>
        </tr>
      `).join('') : `<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No schedules configured.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('sch-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api.post(`/api/client/servers/${srv.id}/schedules`, {
        name: fd.get('name'), cron_expression: fd.get('cron'), is_active: true,
        tasks: [{ action: fd.get('action'), payload: fd.get('payload') || '' }],
      });
      toast('Schedule created', 'success'); renderSchedulesTab(srv, body);
    } catch (err) { toast(err.message, 'error'); }
  };
  body.querySelectorAll('[data-run-sch]').forEach(b => b.onclick = async () => {
    try { const r = await api.post(`/api/client/servers/${srv.id}/schedules/${b.dataset.runSch}/execute`); toast(`Schedule executed: ${r.data.execution_status}`, 'success'); renderSchedulesTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
  body.querySelectorAll('[data-del-sch]').forEach(b => b.onclick = async () => {
    try { await api.del(`/api/client/servers/${srv.id}/schedules/${b.dataset.delSch}`); toast('Schedule deleted', 'success'); renderSchedulesTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
}

/* ---- 6. SUBUSERS & PERMISSIONS ---- */
async function renderSubusersTab(srv, body) {
  const [uRes, pRes] = await Promise.all([api.get(`/api/client/servers/${srv.id}/users`), api.get('/api/client/permissions')]);
  const users = uRes.data || [];
  const allPerms = pRes.data || [];
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title" style="margin-bottom:10px;">Invite Subuser</div>
      <form id="sub-form">
        <div class="form-group"><label class="form-label">User Email</label><input class="input" type="email" name="email" required style="max-width:340px;" /></div>
        <div class="perm-grid" style="margin-bottom:12px;">
          ${allPerms.map(p => `<label class="perm-item"><input type="checkbox" name="perms" value="${escapeHtml(p)}" /><span>${escapeHtml(p)}</span></label>`).join('')}
        </div>
        <button class="btn btn-primary" type="submit">Add Subuser</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>User</th><th>Email</th><th>Permissions</th><th>Actions</th></tr></thead><tbody>
      ${users.length ? users.map(u => `
        <tr>
          <td>${escapeHtml(u.username)}</td>
          <td>${escapeHtml(u.email)}</td>
          <td>${(u.permissions || []).map(p => `<span class="badge" style="margin:2px;">${escapeHtml(p)}</span>`).join('')}</td>
          <td><button class="btn btn-sm btn-danger" data-del-sub="${u.id}">Revoke</button></td>
        </tr>
      `).join('') : `<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">No subusers assigned.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('sub-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post(`/api/client/servers/${srv.id}/users`, { email: fd.get('email'), permissions: fd.getAll('perms') }); toast('Subuser added', 'success'); renderSubusersTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  };
  body.querySelectorAll('[data-del-sub]').forEach(b => b.onclick = async () => {
    try { await api.del(`/api/client/servers/${srv.id}/users/${b.dataset.delSub}`); toast('Subuser revoked', 'success'); renderSubusersTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
}

/* ---- 7. DATABASES ---- */
async function renderDatabasesTab(srv, body) {
  const res = await api.get(`/api/client/servers/${srv.id}/databases`);
  const list = res.data || [];
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="btn-row" style="justify-content:space-between;">
        <div><strong>Databases</strong> <span class="badge">${list.length} / ${res.limit}</span></div>
        <form id="db-form" class="btn-row">
          <input class="input" name="name" placeholder="gameplay" required style="width:170px;" />
          <input class="input mono" name="remote_host" value="%" style="width:110px;" />
          <button class="btn btn-primary" type="submit">Create Database</button>
        </form>
      </div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Database</th><th>Endpoint</th><th>Username</th><th>Password</th><th>Actions</th></tr></thead><tbody>
      ${list.length ? list.map(d => `
        <tr>
          <td class="mono">${escapeHtml(d.db_name)}</td>
          <td class="mono">${escapeHtml(d.host)}:${d.port}</td>
          <td class="mono">${escapeHtml(d.db_username)}</td>
          <td class="mono"><span data-pw="${escapeHtml(d.db_password)}">••••••••</span> <button class="btn btn-sm" data-reveal>Show</button></td>
          <td class="btn-row">
            <button class="btn btn-sm" data-test-db="${d.id}">Test</button>
            <button class="btn btn-sm btn-danger" data-del-db="${d.id}">Delete</button>
          </td>
        </tr>
      `).join('') : `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No databases created.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('db-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post(`/api/client/servers/${srv.id}/databases`, { name: fd.get('name'), remote_host: fd.get('remote_host') }); toast('Database created', 'success'); renderDatabasesTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  };
  body.querySelectorAll('[data-reveal]').forEach(btn => btn.onclick = () => {
    const sp = btn.previousElementSibling;
    sp.textContent = sp.textContent === '••••••••' ? sp.dataset.pw : '••••••••';
  });
  body.querySelectorAll('[data-test-db]').forEach(btn => btn.onclick = async () => {
    try { const r = await api.post(`/api/client/servers/${srv.id}/databases/${btn.dataset.testDb}/test`); toast(r.data.detail, r.data.reachable ? 'success' : 'info'); }
    catch (err) { toast(err.message, 'error'); }
  });
  body.querySelectorAll('[data-del-db]').forEach(btn => btn.onclick = async () => {
    try { await api.del(`/api/client/servers/${srv.id}/databases/${btn.dataset.delDb}`); toast('Database deleted', 'success'); renderDatabasesTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
}

/* ---- 8. NETWORK ALLOCATIONS ---- */
async function renderNetworkTab(srv, body) {
  const res = await api.get(`/api/client/servers/${srv.id}/network/allocations`);
  const list = res.data || [];
  body.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="btn-row" style="justify-content:space-between;">
        <div><strong>Network Allocations</strong> <span class="badge">${list.length} / ${res.limit}</span></div>
        <button class="btn btn-primary" id="net-add-btn">Assign Additional Port</button>
      </div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Connection Address</th><th>Internal IP</th><th>Port</th><th>Role</th><th>Actions</th></tr></thead><tbody>
      ${list.map(a => `
        <tr>
          <td class="mono" style="color:var(--sky);">${escapeHtml(a.connection_address)}</td>
          <td class="mono">${escapeHtml(a.ip)}</td>
          <td class="mono">${a.port}</td>
          <td>${a.is_primary ? `<span class="badge badge-admin">Primary</span>` : `<span class="badge">Secondary</span>`}</td>
          <td class="btn-row">
            ${!a.is_primary ? `<button class="btn btn-sm" data-mk-prim="${a.id}">Make Primary</button><button class="btn btn-sm btn-danger" data-rm-al="${a.id}">Remove</button>` : '—'}
          </td>
        </tr>
      `).join('')}
    </tbody></table></div>
  `;
  document.getElementById('net-add-btn').onclick = async () => {
    try { await api.post(`/api/client/servers/${srv.id}/network/allocations`); toast('Allocation assigned', 'success'); renderNetworkTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  };
  body.querySelectorAll('[data-mk-prim]').forEach(b => b.onclick = async () => {
    try { await api.post(`/api/client/servers/${srv.id}/network/allocations/${b.dataset.mkPrim}/primary`); toast('Primary allocation updated', 'success'); renderServerDetail(srv.id); }
    catch (err) { toast(err.message, 'error'); }
  });
  body.querySelectorAll('[data-rm-al]').forEach(b => b.onclick = async () => {
    try { await api.del(`/api/client/servers/${srv.id}/network/allocations/${b.dataset.rmAl}`); toast('Allocation removed', 'success'); renderNetworkTab(srv, body); }
    catch (err) { toast(err.message, 'error'); }
  });
}

/* ---- 9. SETTINGS ---- */
function renderSettingsTab(srv, body) {
  body.innerHTML = `
    <div class="grid-2">
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Server Details</div>
        <form id="srv-set-form">
          <div class="form-group"><label class="form-label">Server Name</label><input class="input" name="name" value="${escapeHtml(srv.name)}" required /></div>
          <div class="form-group"><label class="form-label">Description</label><textarea class="textarea" name="description">${escapeHtml(srv.description || '')}</textarea></div>
          <button class="btn btn-primary" type="submit">Update Details</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Connection &amp; Reinstall</div>
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:10px;">SFTP Endpoint: <span class="mono">sftp://${escapeHtml(srv.node_fqdn)}:${srv.sftp_port}</span></p>
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px;">Server UUID: <span class="mono">${escapeHtml(srv.id)}</span></p>
        <button class="btn btn-danger" id="reinstall-btn">Reinstall Server</button>
      </div>
    </div>
  `;
  document.getElementById('srv-set-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.put(`/api/client/servers/${srv.id}/settings`, { name: fd.get('name'), description: fd.get('description') }); toast('Settings updated', 'success'); renderServerDetail(srv.id); }
    catch (err) { toast(err.message, 'error'); }
  };
  document.getElementById('reinstall-btn').onclick = async () => {
    if (!confirm('Re-run the installation script on this server?')) return;
    try { await api.post(`/api/client/servers/${srv.id}/reinstall`); toast('Server reinstalled cleanly', 'success'); }
    catch (err) { toast(err.message, 'error'); }
  };
}

/* ---- 10. ACTIVITY ---- */
async function renderActivityTab(srv, body) {
  const res = await api.get(`/api/client/servers/${srv.id}/activity`);
  const logs = res.data || [];
  body.innerHTML = `
    <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Actor</th><th>Event</th><th>IP</th><th>Metadata</th></tr></thead><tbody>
      ${logs.length ? logs.map(l => `
        <tr>
          <td class="mono" style="font-size:12px;">${escapeHtml(l.created_at)}</td>
          <td>${escapeHtml(l.actor_username)}</td>
          <td><span class="badge">${escapeHtml(l.event)}</span></td>
          <td class="mono">${escapeHtml(l.ip_address)}</td>
          <td class="mono" style="font-size:11.5px;color:var(--text-secondary);">${escapeHtml(l.metadata)}</td>
        </tr>
      `).join('') : `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No activity recorded yet.</td></tr>`}
    </tbody></table></div>
  `;
}

/* ==================== ACCOUNT & CLIENT API KEYS ==================== */
async function renderAccountView() {
  document.getElementById('page-title').textContent = 'Account & API Keys';
  const main = document.getElementById('main-content');
  const [accRes, keyRes] = await Promise.all([api.get('/api/client/account'), api.get('/api/client/account/api-keys')]);
  const acc = accRes.data;
  const keys = keyRes.data || [];
  main.innerHTML = `
    <div class="grid-2">
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Profile &amp; Password</div>
        <form id="acc-form">
          <div class="form-group"><label class="form-label">First Name</label><input class="input" name="first_name" value="${escapeHtml(acc.first_name || '')}" /></div>
          <div class="form-group"><label class="form-label">Last Name</label><input class="input" name="last_name" value="${escapeHtml(acc.last_name || '')}" /></div>
          <div class="form-group"><label class="form-label">Current Password (only to change password)</label><input class="input" type="password" name="current_password" /></div>
          <div class="form-group"><label class="form-label">New Password</label><input class="input" type="password" name="new_password" /></div>
          <button class="btn btn-primary" type="submit">Save Account</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Client API Keys</div>
        <form id="ckey-form" class="btn-row" style="margin-bottom:14px;">
          <input class="input" name="memo" placeholder="CLI / CI Token Description" required style="flex:1;" />
          <button class="btn btn-primary" type="submit">Generate Key</button>
        </form>
        <div id="new-key-banner"></div>
        <div class="table-wrap"><table><thead><tr><th>Identifier</th><th>Memo</th><th>Created</th><th></th></tr></thead><tbody>
          ${keys.length ? keys.map(k => `<tr><td class="mono">${escapeHtml(k.identifier)}</td><td>${escapeHtml(k.memo)}</td><td style="font-size:12px;">${escapeHtml(k.created_at)}</td><td><button class="btn btn-sm btn-danger" data-del-ck="${k.id}">Revoke</button></td></tr>`).join('') : `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No API keys.</td></tr>`}
        </tbody></table></div>
      </div>
    </div>
  `;
  document.getElementById('acc-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.put('/api/client/account', { first_name: fd.get('first_name'), last_name: fd.get('last_name'), current_password: fd.get('current_password') || null, new_password: fd.get('new_password') || null }); toast('Account updated', 'success'); }
    catch (err) { toast(err.message, 'error'); }
  };
  document.getElementById('ckey-form').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api.post('/api/client/account/api-keys', { memo: new FormData(e.target).get('memo') });
      document.getElementById('new-key-banner').innerHTML = `<div class="toast success" style="margin-bottom:10px;">Copy your new token now: <span class="mono">${escapeHtml(r.data.secret_token)}</span></div>`;
      renderAccountView();
    } catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-ck]').forEach(b => b.onclick = async () => {
    try { await api.del(`/api/client/account/api-keys/${b.dataset.delCk}`); toast('Key revoked', 'success'); renderAccountView(); }
    catch (err) { toast(err.message, 'error'); }
  });
}

boot();

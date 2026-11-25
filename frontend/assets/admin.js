/**
 * OMCP ONION — Administrator Panel (All 17 Sections + Server Provisioning Wizard)
 */
import { api, toast, escapeHtml, formatBytes, openModal } from './api.js';

const ADMIN_NAV = [
  { id: 'dashboard', label: '1. Dashboard' },
  { id: 'users', label: '2. Users' },
  { id: 'servers', label: '3. Servers' },
  { id: 'nodes', label: '4. Nodes' },
  { id: 'locations', label: '5. Locations' },
  { id: 'nests', label: '6. Nests' },
  { id: 'eggs', label: '7. Eggs' },
  { id: 'allocations', label: '8. Allocations' },
  { id: 'database-hosts', label: '9. Database Hosts' },
  { id: 'mounts', label: '10. Mounts' },
  { id: 'images', label: '11. Server Images' },
  { id: 'activity', label: '12. Activity Logs' },
  { id: 'system-settings', label: '13. System Settings' },
  { id: 'app-settings', label: '14. Application Settings' },
  { id: 'api-keys', label: '15. API Management' },
  { id: 'security', label: '16. Security' },
  { id: 'maintenance', label: '17. Maintenance' },
];

export function renderAdminApp(state, ctx) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar" id="admin-sidebar">
        <div class="sidebar-header">${ctx.brandHeaderHtml()}</div>
        <nav class="sidebar-nav">
          <div class="nav-section-label">Administrator Panel</div>
          ${ADMIN_NAV.map(n => `<button class="nav-item ${state.adminSection === n.id ? 'active' : ''}" data-asec="${n.id}">${n.label}</button>`).join('')}
        </nav>
        <div class="sidebar-footer">
          <button class="btn btn-sm" id="back-client-btn">&larr; Client Panel</button>
          <button class="btn btn-sm btn-danger" id="admin-logout-btn">Sign Out</button>
        </div>
      </aside>
      <div class="main-area">
        <header class="topbar">
          <div class="topbar-title">
            <button class="btn btn-sm mobile-toggle" id="admin-mob-btn">Menu</button>
            <span id="admin-page-title">Admin Dashboard</span>
            <span class="badge badge-admin">ADMIN</span>
          </div>
          <div class="btn-row" id="admin-topbar-actions"></div>
        </header>
        <main class="content" id="admin-content"><div class="boot-screen"><div class="spinner"></div></div></main>
      </div>
    </div>
  `;

  document.getElementById('admin-mob-btn').onclick = () => document.getElementById('admin-sidebar').classList.toggle('open');
  document.getElementById('back-client-btn').onclick = ctx.switchToClient;
  document.getElementById('admin-logout-btn').onclick = ctx.logout;
  document.querySelectorAll('[data-asec]').forEach(btn => {
    btn.onclick = () => { state.adminSection = btn.dataset.asec; renderAdminApp(state, ctx); };
  });

  const main = document.getElementById('admin-content');
  const titleEl = document.getElementById('admin-page-title');
  const sec = state.adminSection;
  const navObj = ADMIN_NAV.find(x => x.id === sec);
  titleEl.textContent = navObj ? navObj.label : 'Administrator';

  const map = {
    dashboard: () => viewDashboard(main),
    users: () => viewUsers(main),
    servers: () => viewServers(main),
    nodes: () => viewNodes(main),
    locations: () => viewLocations(main),
    nests: () => viewNests(main),
    eggs: () => viewEggs(main),
    allocations: () => viewAllocations(main),
    'database-hosts': () => viewDbHosts(main),
    mounts: () => viewMounts(main),
    images: () => viewImages(main),
    activity: () => viewActivity(main),
    'system-settings': () => viewSystemSettings(main, ctx.applyBranding),
    'app-settings': () => viewAppSettings(main),
    'api-keys': () => viewApiKeys(main),
    security: () => viewSecurity(main),
    maintenance: () => viewMaintenance(main),
  };
  if (map[sec]) map[sec]();
}

async function viewDashboard(main) {
  const res = await api.get('/api/application/overview');
  const d = res.data;
  const st = d.stats;
  main.innerHTML = `
    <div class="grid-4">
      <div class="stat-card"><div class="stat-label">Total Users</div><div class="stat-value">${st.total_users}</div><div class="stat-sub">Registered accounts</div></div>
      <div class="stat-card"><div class="stat-label">Servers</div><div class="stat-value">${st.online_servers} / ${st.total_servers}</div><div class="stat-sub">${st.offline_servers} offline</div></div>
      <div class="stat-card"><div class="stat-label">Nodes Online</div><div class="stat-value">${st.online_nodes} / ${st.total_nodes}</div><div class="stat-sub">${st.cpu_cores} total CPU cores</div></div>
      <div class="stat-card"><div class="stat-label">Cluster Memory</div><div class="stat-value">${formatBytes(st.memory_used_bytes)}</div><div class="stat-sub">of ${formatBytes(st.memory_total_bytes)} RAM</div></div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Node Health</div>
        <div class="table-wrap"><table><thead><tr><th>Node</th><th>FQDN</th><th>Status</th><th>Running</th></tr></thead><tbody>
          ${d.nodes.length ? d.nodes.map(n => `<tr><td>${escapeHtml(n.name)}</td><td class="mono">${escapeHtml(n.fqdn)}</td><td><span class="status-pill status-${n.health.status === 'online' ? 'online' : 'offline'}">${escapeHtml(n.health.status)}</span></td><td>${n.health.running_servers || 0}</td></tr>`).join('') : `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No nodes configured.</td></tr>`}
        </tbody></table></div>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Recent Server Installations</div>
        <div class="table-wrap"><table><thead><tr><th>Server</th><th>Owner</th><th>Game</th><th>Status</th></tr></thead><tbody>
          ${d.recent_installations.length ? d.recent_installations.map(s => `<tr><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.owner_username)}</td><td>${escapeHtml(s.egg_name)}</td><td><span class="status-pill status-${escapeHtml(s.status)}">${escapeHtml(s.status)}</span></td></tr>`).join('') : `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No servers yet.</td></tr>`}
        </tbody></table></div>
      </div>
    </div>
  `;
}

async function viewUsers(main) {
  const res = await api.get('/api/application/users');
  const list = res.data || [];
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title" style="margin-bottom:10px;">Create User</div>
      <form id="au-form" class="btn-row">
        <input class="input" name="username" placeholder="username" required style="width:150px;" />
        <input class="input" type="email" name="email" placeholder="user@domain.com" required style="width:200px;" />
        <input class="input" type="password" name="password" placeholder="Password (8+)" required minlength="8" style="width:160px;" />
        <select class="select" name="role" style="width:120px;"><option value="user">User</option><option value="admin">Admin</option></select>
        <button class="btn btn-primary" type="submit">Create</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Servers</th><th>Status</th><th>Actions</th></tr></thead><tbody>
      ${list.map(u => `
        <tr>
          <td><strong>${escapeHtml(u.username)}</strong></td>
          <td>${escapeHtml(u.email)}</td>
          <td><span class="badge ${u.role === 'admin' ? 'badge-admin' : ''}">${escapeHtml(u.role)}</span></td>
          <td>${u.server_count}</td>
          <td>${u.is_suspended ? `<span class="status-pill status-suspended">Suspended</span>` : `<span class="status-pill status-online">Active</span>`}</td>
          <td class="btn-row">
            ${u.is_suspended ? `<button class="btn btn-sm btn-success" data-unsusp="${u.id}">Unsuspend</button>` : `<button class="btn btn-sm btn-warning" data-susp="${u.id}">Suspend</button>`}
            <button class="btn btn-sm btn-danger" data-del-u="${u.id}">Delete</button>
          </td>
        </tr>
      `).join('')}
    </tbody></table></div>
  `;
  document.getElementById('au-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/users', Object.fromEntries(fd)); toast('User created', 'success'); viewUsers(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-susp]').forEach(b => b.onclick = async () => { try { await api.post(`/api/application/users/${b.dataset.susp}/suspend`); toast('User suspended', 'info'); viewUsers(main); } catch (e) { toast(e.message, 'error'); } });
  main.querySelectorAll('[data-unsusp]').forEach(b => b.onclick = async () => { try { await api.post(`/api/application/users/${b.dataset.unsusp}/unsuspend`); toast('User unsuspended', 'success'); viewUsers(main); } catch (e) { toast(e.message, 'error'); } });
  main.querySelectorAll('[data-del-u]').forEach(b => b.onclick = async () => { if (!confirm('Delete user?')) return; try { await api.del(`/api/application/users/${b.dataset.delU}`); toast('User deleted', 'success'); viewUsers(main); } catch (e) { toast(e.message, 'error'); } });
}

async function viewServers(main) {
  const res = await api.get('/api/application/servers');
  const list = res.data || [];
  main.innerHTML = `
    <div class="btn-row" style="justify-content:space-between;margin-bottom:14px;">
      <div style="color:var(--text-secondary);">Manage and provision game servers across all nodes.</div>
      <button class="btn btn-primary" id="open-srv-wizard">+ Create Server Wizard</button>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Owner</th><th>Node</th><th>Game / Egg</th><th>Address</th><th>Limits</th><th>Status</th><th>Actions</th></tr></thead><tbody>
      ${list.length ? list.map(s => `
        <tr>
          <td><strong>${escapeHtml(s.name)}</strong><div class="mono" style="font-size:11px;color:var(--text-muted);">${escapeHtml(s.uuid_short)}</div></td>
          <td>${escapeHtml(s.owner_username)}</td>
          <td>${escapeHtml(s.node_name)}</td>
          <td>${escapeHtml(s.egg_name)}</td>
          <td class="mono">${escapeHtml(s.connection_address)}</td>
          <td class="mono" style="font-size:11.5px;">${s.memory_mb}MB / ${s.cpu_percent}% / ${s.disk_mb}MB</td>
          <td><span class="status-pill status-${escapeHtml(s.status)}">${escapeHtml(s.status)}</span></td>
          <td class="btn-row">
            ${s.is_suspended ? `<button class="btn btn-sm btn-success" data-unsusp-s="${s.id}">Unsuspend</button>` : `<button class="btn btn-sm btn-warning" data-susp-s="${s.id}">Suspend</button>`}
            <button class="btn btn-sm btn-danger" data-del-s="${s.id}">Delete</button>
          </td>
        </tr>
      `).join('') : `<tr><td colspan="8" style="text-align:center;padding:28px;color:var(--text-muted);">No servers provisioned yet.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('open-srv-wizard').onclick = () => openServerWizard(() => viewServers(main));
  main.querySelectorAll('[data-susp-s]').forEach(b => b.onclick = async () => { try { await api.post(`/api/application/servers/${b.dataset.suspS}/suspend`); toast('Server suspended', 'info'); viewServers(main); } catch (e) { toast(e.message, 'error'); } });
  main.querySelectorAll('[data-unsusp-s]').forEach(b => b.onclick = async () => { try { await api.post(`/api/application/servers/${b.dataset.unsuspS}/unsuspend`); toast('Server unsuspended', 'success'); viewServers(main); } catch (e) { toast(e.message, 'error'); } });
  main.querySelectorAll('[data-del-s]').forEach(b => b.onclick = async () => { if (!confirm('Permanently delete server and all its files?')) return; try { await api.del(`/api/application/servers/${b.dataset.delS}`); toast('Server deleted', 'success'); viewServers(main); } catch (e) { toast(e.message, 'error'); } });
}

async function openServerWizard(onDone) {
  const [uRes, nRes, eRes, aRes] = await Promise.all([
    api.get('/api/application/users'),
    api.get('/api/application/nodes'),
    api.get('/api/application/eggs'),
    api.get('/api/application/allocations?unassigned_only=true'),
  ]);
  const users = uRes.data || [], nodes = nRes.data || [], eggs = eRes.data || [], allocs = aRes.data || [];
  openModal('Provision New Game Server', `
    <form id="srv-wiz-form">
      <div class="grid-2" style="gap:10px;">
        <div class="form-group"><label class="form-label">Server Name</label><input class="input" name="name" required placeholder="Survival SMP #1" /></div>
        <div class="form-group"><label class="form-label">Owner</label><select class="select" name="owner_id" required>${users.map(u => `<option value="${u.id}">${escapeHtml(u.username)} (${escapeHtml(u.email)})</option>`).join('')}</select></div>
        <div class="form-group"><label class="form-label">Node</label><select class="select" name="node_id" id="wiz-node" required>${nodes.map(n => `<option value="${n.id}">${escapeHtml(n.name)} (${escapeHtml(n.fqdn)})</option>`).join('')}</select></div>
        <div class="form-group"><label class="form-label">Primary Allocation</label><select class="select mono" name="primary_allocation_id" required>${allocs.map(a => `<option value="${a.id}">${escapeHtml(a.node_name)} — ${escapeHtml(a.ip)}:${a.port}</option>`).join('')}</select></div>
        <div class="form-group"><label class="form-label">Game / Egg</label><select class="select" name="egg_id" id="wiz-egg" required>${eggs.map(e => `<option value="${e.id}">${escapeHtml(e.name)}</option>`).join('')}</select></div>
        <div class="form-group"><label class="form-label">Docker Image</label><input class="input mono" name="docker_image" id="wiz-img" value="${escapeHtml(eggs[0]?.docker_images?.[0] || 'python:3.11-slim')}" required /></div>
        <div class="form-group"><label class="form-label">Memory (MB)</label><input class="input" type="number" name="memory_mb" value="1024" required /></div>
        <div class="form-group"><label class="form-label">CPU Limit (%)</label><input class="input" type="number" name="cpu_percent" value="100" required /></div>
        <div class="form-group"><label class="form-label">Disk Limit (MB)</label><input class="input" type="number" name="disk_mb" value="5120" required /></div>
        <div class="form-group"><label class="form-label">Backup Limit</label><input class="input" type="number" name="backup_limit" value="5" required /></div>
      </div>
      <div class="form-group"><label class="form-label">Environment Variables (JSON)</label><textarea class="textarea" name="env_vars">{}</textarea></div>
      <button class="btn btn-primary" type="submit" style="width:100%;">Create &amp; Install on Node Agent</button>
    </form>
  `, (close) => {
    document.getElementById('wiz-egg').onchange = (e) => {
      const eg = eggs.find(x => x.id === e.target.value);
      if (eg && eg.docker_images?.[0]) document.getElementById('wiz-img').value = eg.docker_images[0];
    };
    document.getElementById('srv-wiz-form').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api.post('/api/application/servers', {
          name: fd.get('name'), owner_id: fd.get('owner_id'), node_id: fd.get('node_id'),
          egg_id: fd.get('egg_id'), primary_allocation_id: fd.get('primary_allocation_id'),
          docker_image: fd.get('docker_image'), memory_mb: Number(fd.get('memory_mb')),
          cpu_percent: Number(fd.get('cpu_percent')), disk_mb: Number(fd.get('disk_mb')),
          backup_limit: Number(fd.get('backup_limit')), env_vars: JSON.parse(fd.get('env_vars') || '{}'),
        });
        toast(`Server provisioned: ${res.data.name}`, 'success');
        close(); onDone();
      } catch (err) { toast(err.message, 'error'); }
    };
  });
}

async function viewNodes(main) {
  const [nRes, lRes] = await Promise.all([api.get('/api/application/nodes'), api.get('/api/application/locations')]);
  const nodes = nRes.data || [], locs = lRes.data || [];
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title" style="margin-bottom:10px;">Add Node</div>
      <form id="nd-form" class="btn-row">
        <select class="select" name="location_id" required style="width:150px;">${locs.map(l => `<option value="${l.id}">${escapeHtml(l.short_code)}</option>`).join('')}</select>
        <input class="input" name="name" placeholder="EU-Central-01" required style="width:150px;" />
        <input class="input mono" name="fqdn" placeholder="node1.example.com" required style="width:170px;" />
        <input class="input mono" name="ip_address" placeholder="127.0.0.1" required style="width:130px;" />
        <input class="input mono" type="number" name="daemon_port" value="8443" required style="width:90px;" />
        <input class="input mono" name="daemon_token" placeholder="Agent Token (optional)" style="width:180px;" />
        <button class="btn btn-primary" type="submit">Add Node</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Location</th><th>Endpoint</th><th>Status</th><th>Servers</th><th>Actions</th></tr></thead><tbody>
      ${nodes.length ? nodes.map(n => `
        <tr>
          <td><strong>${escapeHtml(n.name)}</strong></td>
          <td><span class="badge">${escapeHtml(n.location_code)}</span></td>
          <td class="mono">${escapeHtml(n.scheme)}://${escapeHtml(n.ip_address)}:${n.daemon_port}</td>
          <td><span class="status-pill status-${n.status === 'online' ? 'online' : 'offline'}">${escapeHtml(n.status)}</span></td>
          <td>${n.server_count}</td>
          <td class="btn-row">
            <button class="btn btn-sm" data-ping-n="${n.id}">Check Health</button>
            <button class="btn btn-sm btn-danger" data-del-n="${n.id}">Delete</button>
          </td>
        </tr>
      `).join('') : `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px;">Create a Location first, then add a Node.</td></tr>`}
    </tbody></table></div>
  `;
  document.getElementById('nd-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api.post('/api/application/nodes', {
        location_id: fd.get('location_id'), name: fd.get('name'), fqdn: fd.get('fqdn'),
        ip_address: fd.get('ip_address'), daemon_port: Number(fd.get('daemon_port')),
        daemon_token: fd.get('daemon_token') || null,
      });
      toast('Node added', 'success'); viewNodes(main);
    } catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-ping-n]').forEach(b => b.onclick = async () => {
    const r = await api.get(`/api/application/nodes/${b.dataset.pingN}/health`);
    toast(`Node status: ${r.data.status}`, r.data.status === 'online' ? 'success' : 'error');
    viewNodes(main);
  });
  main.querySelectorAll('[data-del-n]').forEach(b => b.onclick = async () => {
    try { await api.del(`/api/application/nodes/${b.dataset.delN}`); toast('Node deleted', 'success'); viewNodes(main); }
    catch (err) { toast(err.message, 'error'); }
  });
}

async function viewLocations(main) {
  const res = await api.get('/api/application/locations');
  const list = res.data || [];
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="loc-form" class="btn-row">
        <input class="input mono" name="short_code" placeholder="us-east-1" required style="width:160px;" />
        <input class="input" name="description" placeholder="New York Datacenter" style="flex:1;" />
        <button class="btn btn-primary" type="submit">Create Location</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Short Code</th><th>Description</th><th>Nodes</th><th>Actions</th></tr></thead><tbody>
      ${list.map(l => `<tr><td class="mono"><strong>${escapeHtml(l.short_code)}</strong></td><td>${escapeHtml(l.description)}</td><td>${l.node_count}</td><td><button class="btn btn-sm btn-danger" data-del-l="${l.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('loc-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/locations', { short_code: fd.get('short_code'), description: fd.get('description') }); toast('Location created', 'success'); viewLocations(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-l]').forEach(b => b.onclick = async () => { try { await api.del(`/api/application/locations/${b.dataset.delL}`); viewLocations(main); } catch (e) { toast(e.message, 'error'); } });
}

async function viewNests(main) {
  const res = await api.get('/api/application/nests');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="nest-form" class="btn-row">
        <input class="input" name="name" placeholder="Nest Name" required style="width:200px;" />
        <input class="input" name="description" placeholder="Description" style="flex:1;" />
        <button class="btn btn-primary" type="submit">Create Nest</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Description</th><th>Eggs</th><th>Actions</th></tr></thead><tbody>
      ${(res.data || []).map(n => `<tr><td><strong>${escapeHtml(n.name)}</strong></td><td>${escapeHtml(n.description)}</td><td>${n.egg_count}</td><td><button class="btn btn-sm btn-danger" data-del-ns="${n.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('nest-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/nests', { name: fd.get('name'), description: fd.get('description') }); toast('Nest created', 'success'); viewNests(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-ns]').forEach(b => b.onclick = async () => { try { await api.del(`/api/application/nests/${b.dataset.delNs}`); viewNests(main); } catch (e) { toast(e.message, 'error'); } });
}

async function viewEggs(main) {
  const [eRes, nRes] = await Promise.all([api.get('/api/application/eggs'), api.get('/api/application/nests')]);
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title" style="margin-bottom:10px;">Create Egg</div>
      <form id="egg-form">
        <div class="grid-3" style="gap:10px;">
          <select class="select" name="nest_id" required>${(nRes.data || []).map(n => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join('')}</select>
          <input class="input" name="name" placeholder="Egg Name (e.g. Valheim)" required />
          <input class="input mono" name="startup_command" placeholder="Startup command" required />
        </div>
        <button class="btn btn-primary" type="submit" style="margin-top:10px;">Create Egg</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Egg</th><th>Nest</th><th>Startup Command</th><th>Defaults</th></tr></thead><tbody>
      ${(eRes.data || []).map(e => `<tr><td><strong>${escapeHtml(e.name)}</strong></td><td>${escapeHtml(e.nest_name || e.nest_id)}</td><td class="mono" style="font-size:11.5px;">${escapeHtml(e.startup_command)}</td><td class="mono">${e.default_memory_mb}MB / ${e.default_cpu_percent}%</td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('egg-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/eggs', { nest_id: fd.get('nest_id'), name: fd.get('name'), startup_command: fd.get('startup_command') }); toast('Egg created', 'success'); viewEggs(main); }
    catch (err) { toast(err.message, 'error'); }
  };
}

async function viewAllocations(main) {
  const [aRes, nRes] = await Promise.all([api.get('/api/application/allocations'), api.get('/api/application/nodes')]);
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="al-form" class="btn-row">
        <select class="select" name="node_id" required style="width:170px;">${(nRes.data || []).map(n => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join('')}</select>
        <input class="input mono" name="ip" value="0.0.0.0" required style="width:140px;" />
        <input class="input mono" name="ip_alias" placeholder="play.example.com" style="width:170px;" />
        <input class="input mono" name="ports" placeholder="25565,25566" required style="width:160px;" />
        <button class="btn btn-primary" type="submit">Add Allocations</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Node</th><th>IP</th><th>Alias</th><th>Port</th><th>Assigned Server</th><th>Actions</th></tr></thead><tbody>
      ${(aRes.data || []).map(a => `<tr><td>${escapeHtml(a.node_name)}</td><td class="mono">${escapeHtml(a.ip)}</td><td class="mono">${escapeHtml(a.ip_alias || '—')}</td><td class="mono">${a.port}</td><td>${escapeHtml(a.server_name || 'Unassigned')}</td><td>${!a.server_id ? `<button class="btn btn-sm btn-danger" data-del-al="${a.id}">Delete</button>` : 'In Use'}</td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('al-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const ports = String(fd.get('ports')).split(',').map(x => Number(x.trim())).filter(Boolean);
    try { await api.post('/api/application/allocations', { node_id: fd.get('node_id'), ip: fd.get('ip'), ip_alias: fd.get('ip_alias'), ports }); toast('Allocations created', 'success'); viewAllocations(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-al]').forEach(b => b.onclick = async () => { try { await api.del(`/api/application/allocations/${b.dataset.delAl}`); viewAllocations(main); } catch (e) { toast(e.message, 'error'); } });
}

async function viewDbHosts(main) {
  const res = await api.get('/api/application/database-hosts');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="dbh-form" class="btn-row">
        <input class="input" name="name" placeholder="Primary MySQL" required style="width:160px;" />
        <input class="input mono" name="host" placeholder="127.0.0.1" required style="width:140px;" />
        <input class="input mono" type="number" name="port" value="3306" style="width:90px;" />
        <input class="input" name="username" placeholder="root" required style="width:120px;" />
        <input class="input" type="password" name="password" placeholder="password" required style="width:140px;" />
        <button class="btn btn-primary" type="submit">Add Host</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Endpoint</th><th>Username</th><th>Databases</th><th>Actions</th></tr></thead><tbody>
      ${(res.data || []).map(h => `<tr><td>${escapeHtml(h.name)}</td><td class="mono">${escapeHtml(h.host)}:${h.port}</td><td class="mono">${escapeHtml(h.username)}</td><td>${h.database_count} / ${h.max_databases}</td><td><button class="btn btn-sm btn-danger" data-del-dbh="${h.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('dbh-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/database-hosts', { name: fd.get('name'), host: fd.get('host'), port: Number(fd.get('port')), username: fd.get('username'), password: fd.get('password') }); toast('Database host added', 'success'); viewDbHosts(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-dbh]').forEach(b => b.onclick = async () => { await api.del(`/api/application/database-hosts/${b.dataset.delDbh}`); viewDbHosts(main); });
}

async function viewMounts(main) {
  const res = await api.get('/api/application/mounts');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="mt-form" class="btn-row">
        <input class="input" name="name" placeholder="Shared Maps" required style="width:160px;" />
        <input class="input mono" name="source_path" placeholder="/mnt/maps" required style="width:180px;" />
        <input class="input mono" name="target_path" placeholder="/maps" required style="width:150px;" />
        <button class="btn btn-primary" type="submit">Add Mount</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Source</th><th>Target</th><th>Read-Only</th><th>Actions</th></tr></thead><tbody>
      ${(res.data || []).map(m => `<tr><td>${escapeHtml(m.name)}</td><td class="mono">${escapeHtml(m.source_path)}</td><td class="mono">${escapeHtml(m.target_path)}</td><td>${m.read_only ? 'Yes' : 'No'}</td><td><button class="btn btn-sm btn-danger" data-del-mt="${m.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('mt-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/mounts', { name: fd.get('name'), source_path: fd.get('source_path'), target_path: fd.get('target_path') }); toast('Mount created', 'success'); viewMounts(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-mt]').forEach(b => b.onclick = async () => { await api.del(`/api/application/mounts/${b.dataset.delMt}`); viewMounts(main); });
}

async function viewImages(main) {
  const res = await api.get('/api/application/images');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="img-form" class="btn-row">
        <input class="input" name="name" placeholder="Java 21" required style="width:160px;" />
        <input class="input mono" name="image_ref" placeholder="ghcr.io/onion-images/java:21" required style="flex:1;" />
        <input class="input" name="category" value="game" style="width:120px;" />
        <button class="btn btn-primary" type="submit">Add Image</button>
      </form>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Image Ref</th><th>Category</th><th>Actions</th></tr></thead><tbody>
      ${(res.data || []).map(i => `<tr><td>${escapeHtml(i.name)}</td><td class="mono">${escapeHtml(i.image_ref)}</td><td><span class="badge">${escapeHtml(i.category)}</span></td><td><button class="btn btn-sm btn-danger" data-del-img="${i.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('img-form').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try { await api.post('/api/application/images', Object.fromEntries(fd)); toast('Image added', 'success'); viewImages(main); }
    catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-img]').forEach(b => b.onclick = async () => { await api.del(`/api/application/images/${b.dataset.delImg}`); viewImages(main); });
}

async function viewActivity(main) {
  const res = await api.get('/api/application/activity?limit=100');
  main.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody>
    ${(res.data || []).map(l => `<tr><td class="mono" style="font-size:12px;">${escapeHtml(l.created_at)}</td><td>${escapeHtml(l.actor_username)}</td><td><span class="badge">${escapeHtml(l.event)}</span></td><td class="mono">${escapeHtml(l.ip_address)}</td><td class="mono" style="font-size:11.5px;">${escapeHtml(l.metadata)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

async function viewSystemSettings(main, applyBranding) {
  const res = await api.get('/api/application/settings');
  const s = res.data || {};
  main.innerHTML = `
    <div class="grid-2">
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Branding &amp; General Settings</div>
        <form id="sys-set-form">
          <div class="form-group"><label class="form-label">Panel Name</label><input class="input" name="panel_name" value="${escapeHtml(s.panel_name || 'OMCP ONION')}" /></div>
          <div class="form-group"><label class="form-label">Panel URL</label><input class="input" name="panel_url" value="${escapeHtml(s.panel_url || '')}" /></div>
          <div class="form-group"><label class="form-label">Support Email</label><input class="input" name="support_email" value="${escapeHtml(s.support_email || '')}" /></div>
          <div class="form-group"><label class="form-label">Login Title</label><input class="input" name="login_branding_title" value="${escapeHtml(s.login_branding_title || '')}" /></div>
          <div class="form-group"><label class="form-label">Background Image URL</label><input class="input" name="background_image_url" value="${escapeHtml(s.background_image_url || '')}" /></div>
          <div class="form-group"><label class="form-label">Background Video URL</label><input class="input" name="background_video_url" value="${escapeHtml(s.background_video_url || '')}" /></div>
          <div class="form-group"><label class="form-label">Timezone</label><input class="input" name="timezone" value="${escapeHtml(s.timezone || 'UTC')}" /></div>
          <div class="form-group"><label class="form-label">Public Registration</label><select class="select" name="registration_enabled"><option value="true" ${s.registration_enabled === 'true' ? 'selected' : ''}>Enabled</option><option value="false" ${s.registration_enabled === 'false' ? 'selected' : ''}>Disabled</option></select></div>
          <button class="btn btn-primary" type="submit">Save Settings</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:12px;">Logo &amp; Favicon Uploads</div>
        <div class="form-group"><label class="form-label">Upload Sidebar &amp; Login Logo</label><input class="input" type="file" id="up-logo" accept="image/*" /></div>
        <div class="form-group"><label class="form-label">Upload Browser Favicon</label><input class="input" type="file" id="up-fav" accept="image/*,.ico" /></div>
      </div>
    </div>
  `;
  document.getElementById('sys-set-form').onsubmit = async (e) => {
    e.preventDefault();
    const obj = Object.fromEntries(new FormData(e.target));
    try { await api.put('/api/application/settings', { settings: obj }); applyBranding({ ...s, ...obj }); toast('System settings saved', 'success'); }
    catch (err) { toast(err.message, 'error'); }
  };
  const uploadBrand = async (assetType, file) => {
    if (!file) return;
    const fd = new FormData();
    fd.append('asset_type', assetType);
    fd.append('file', file);
    try { const r = await api.post('/api/application/settings/upload-brand', fd); toast(`Uploaded ${assetType}: ${r.data.url}`, 'success'); }
    catch (err) { toast(err.message, 'error'); }
  };
  document.getElementById('up-logo').onchange = (e) => uploadBrand('logo', e.target.files[0]);
  document.getElementById('up-fav').onchange = (e) => uploadBrand('favicon', e.target.files[0]);
}

async function viewAppSettings(main) {
  const res = await api.get('/api/application/settings');
  const s = res.data || {};
  main.innerHTML = `
    <div class="card" style="max-width:640px;">
      <div class="card-title" style="margin-bottom:12px;">Application, Email &amp; Backup Configuration</div>
      <form id="app-set-form">
        <div class="form-group"><label class="form-label">SMTP Host</label><input class="input" name="smtp_host" value="${escapeHtml(s.smtp_host || '')}" /></div>
        <div class="form-group"><label class="form-label">SMTP Port</label><input class="input" name="smtp_port" value="${escapeHtml(s.smtp_port || '587')}" /></div>
        <div class="form-group"><label class="form-label">Backup Storage Driver</label><select class="select" name="backup_driver"><option value="local" ${s.backup_driver === 'local' ? 'selected' : ''}>Local</option><option value="s3" ${s.backup_driver === 's3' ? 'selected' : ''}>S3-Compatible Remote</option></select></div>
        <div class="form-group"><label class="form-label">Min Password Length</label><input class="input" type="number" name="security_min_password_length" value="${escapeHtml(s.security_min_password_length || '8')}" /></div>
        <div class="form-group"><label class="form-label">API Rate Limit (req/min)</label><input class="input" type="number" name="security_rate_limit_rpm" value="${escapeHtml(s.security_rate_limit_rpm || '120')}" /></div>
        <button class="btn btn-primary" type="submit">Save Application Settings</button>
      </form>
    </div>
  `;
  document.getElementById('app-set-form').onsubmit = async (e) => {
    e.preventDefault();
    try { await api.put('/api/application/settings', { settings: Object.fromEntries(new FormData(e.target)) }); toast('Application settings saved', 'success'); }
    catch (err) { toast(err.message, 'error'); }
  };
}

async function viewApiKeys(main) {
  const res = await api.get('/api/application/api-keys');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;">
      <form id="ak-form" class="btn-row">
        <input class="input" name="memo" placeholder="Billing / Automation Key" required style="flex:1;" />
        <button class="btn btn-primary" type="submit">Generate Application Key</button>
      </form>
      <div id="ak-banner" style="margin-top:10px;"></div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Identifier</th><th>Type</th><th>User</th><th>Memo</th><th>Created</th><th></th></tr></thead><tbody>
      ${(res.data || []).map(k => `<tr><td class="mono">${escapeHtml(k.identifier)}</td><td><span class="badge">${escapeHtml(k.key_type)}</span></td><td>${escapeHtml(k.username)}</td><td>${escapeHtml(k.memo)}</td><td style="font-size:12px;">${escapeHtml(k.created_at)}</td><td><button class="btn btn-sm btn-danger" data-del-ak="${k.id}">Revoke</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  document.getElementById('ak-form').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api.post('/api/application/api-keys', { memo: new FormData(e.target).get('memo') });
      document.getElementById('ak-banner').innerHTML = `<div class="toast success">Secret Key (shown once): <span class="mono">${escapeHtml(r.data.secret_token)}</span></div>`;
      viewApiKeys(main);
    } catch (err) { toast(err.message, 'error'); }
  };
  main.querySelectorAll('[data-del-ak]').forEach(b => b.onclick = async () => { await api.del(`/api/application/api-keys/${b.dataset.delAk}`); viewApiKeys(main); });
}

async function viewSecurity(main) {
  const res = await api.get('/api/application/security/sessions');
  main.innerHTML = `
    <div class="card" style="margin-bottom:14px;"><strong>Active Sessions</strong> — Revoke any active user session immediately.</div>
    <div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>IP Address</th><th>Created</th><th>Actions</th></tr></thead><tbody>
      ${(res.data || []).map(s => `<tr><td>${escapeHtml(s.username)}</td><td><span class="badge">${escapeHtml(s.role)}</span></td><td class="mono">${escapeHtml(s.ip_address)}</td><td style="font-size:12px;">${escapeHtml(s.created_at)}</td><td><button class="btn btn-sm btn-danger" data-rev-s="${s.id}">Revoke</button></td></tr>`).join('')}
    </tbody></table></div>
  `;
  main.querySelectorAll('[data-rev-s]').forEach(b => b.onclick = async () => { await api.del(`/api/application/security/sessions/${b.dataset.revS}`); toast('Session revoked', 'info'); viewSecurity(main); });
}

async function viewMaintenance(main) {
  const res = await api.get('/api/application/maintenance/status');
  const d = res.data;
  main.innerHTML = `
    <div class="card" style="max-width:600px;">
      <div class="card-title" style="margin-bottom:10px;">Maintenance &amp; Diagnostics</div>
      <p style="margin-bottom:12px;color:var(--text-secondary);">Panel Version: <span class="mono">${escapeHtml(d.panel_version)}</span></p>
      <p style="margin-bottom:16px;">Maintenance Mode: <span class="status-pill ${d.maintenance_mode ? 'status-suspended' : 'status-online'}">${d.maintenance_mode ? 'ENABLED' : 'DISABLED'}</span></p>
      <button class="btn ${d.maintenance_mode ? 'btn-success' : 'btn-warning'}" id="maint-toggle">${d.maintenance_mode ? 'Disable Maintenance Mode' : 'Enable Maintenance Mode'}</button>
    </div>
  `;
  document.getElementById('maint-toggle').onclick = async () => {
    await api.post(`/api/application/maintenance/toggle?enabled=${!d.maintenance_mode}`);
    toast('Maintenance state updated', 'success');
    viewMaintenance(main);
  };
}

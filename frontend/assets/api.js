/**
 * OMCP ONION API Client & WebSocket Helper
 */

export const api = {
  token: localStorage.getItem('omcp_onion_token') || '',

  setToken(token) {
    this.token = token || '';
    if (this.token) {
      localStorage.setItem('omcp_onion_token', this.token);
    } else {
      localStorage.removeItem('omcp_onion_token');
    }
  },

  async request(method, path, body = null) {
    const headers = { 'Accept': 'application/json' };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    const opts = { method, headers, credentials: 'same-origin' };
    if (body !== null && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    } else if (body instanceof FormData) {
      opts.body = body;
    }
    const res = await fetch(path, opts);
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json() : await res.text();
    if (!res.ok) {
      const msg = (data && data.detail) ? data.detail : `HTTP ${res.status}`;
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    return data;
  },

  get: (p) => api.request('GET', p),
  post: (p, b) => api.request('POST', p, b),
  put: (p, b) => api.request('PUT', p, b),
  del: (p) => api.request('DELETE', p),

  wsUrl(path) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const sep = path.includes('?') ? '&' : '?';
    const tok = this.token ? `${sep}token=${encodeURIComponent(this.token)}` : '';
    return `${proto}//${location.host}${path}${tok}`;
  }
};

export function toast(message, type = 'info') {
  const root = document.getElementById('toast-container');
  if (!root) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  root.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function formatBytes(bytes) {
  const b = Number(bytes || 0);
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

export function openModal(title, bodyHtml, onMount) {
  const root = document.getElementById('modal-root');
  root.innerHTML = `
    <div class="modal-backdrop" id="modal-backdrop">
      <div class="modal-panel">
        <div class="card-header">
          <div class="card-title">${escapeHtml(title)}</div>
          <button class="btn btn-sm" id="modal-close-btn">Close</button>
        </div>
        <div id="modal-body">${bodyHtml}</div>
      </div>
    </div>
  `;
  const close = () => { root.innerHTML = ''; };
  document.getElementById('modal-close-btn').onclick = close;
  document.getElementById('modal-backdrop').onclick = (e) => {
    if (e.target.id === 'modal-backdrop') close();
  };
  if (onMount) onMount(close);
}

export function brandLogoSvg() {
  return `<svg width="34" height="34" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs><linearGradient id="onionGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#a855f7"/><stop offset="100%" stop-color="#f59e0b"/></linearGradient></defs>
    <rect width="64" height="64" rx="16" fill="#131826" stroke="#252f4a" stroke-width="2"/>
    <circle cx="32" cy="35" r="19" stroke="url(#onionGrad)" stroke-width="4"/>
    <circle cx="32" cy="35" r="11" stroke="#c084fc" stroke-width="3"/>
    <circle cx="32" cy="35" r="4.5" fill="#f59e0b"/>
    <path d="M32 9V16" stroke="#10b981" stroke-width="4" stroke-linecap="round"/>
  </svg>`;
}

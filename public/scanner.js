// ── State ──────────────────────────────────────────────────────────────────────
let _token = null;
let _adminName = '';
let _adminRole = '';
let _events = [];
let _scanner = null;
let _scanning = false;
let _lastScanned = null;
let _pendingReg = null;   // { registration_id, name } awaiting confirm
let _csrfToken = null;
let _regsCache = {};      // eventId → registrations array

// ── CSRF ───────────────────────────────────────────────────────────────────────
async function fetchCsrf() {
  try {
    const r = await fetch('/api/csrf-token');
    if (!r.ok) return;
    const d = await r.json();
    if (d.csrf_token) _csrfToken = d.csrf_token;
  } catch {}
}

// Fetch CSRF on load — disable login button until it's ready (5s max wait)
document.getElementById('login-btn').disabled = true;
const _csrfReady = fetchCsrf();
const _csrfTimeout = new Promise(r => setTimeout(r, 5000));
Promise.race([_csrfReady, _csrfTimeout]).then(() => {
  document.getElementById('login-btn').disabled = false;
});

// Auto-refresh CSRF every 3.5 hours (token valid 4h)
setInterval(fetchCsrf, 3.5 * 60 * 60 * 1000);

// ── API helper ─────────────────────────────────────────────────────────────────
async function api(method, url, body) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ..._token ? { 'Authorization': `Bearer ${_token}` } : {},
      ..._csrfToken && method !== 'GET' ? { 'x-csrf-token': _csrfToken } : {},
    },
    credentials: 'include',
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

// Auto-refresh token every 12 min
setInterval(async () => {
  if (!_token) return;
  const r = await fetch('/api/admin/refresh', { method: 'POST', credentials: 'include',
    headers: { 'x-csrf-token': _csrfToken || '' } });
  if (r.ok) { const d = await r.json(); _token = d.token; }
}, 12 * 60 * 1000);

// ── LOGIN ──────────────────────────────────────────────────────────────────────
let _needTotp = false;

document.getElementById('l-pass').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});
document.getElementById('l-totp')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

async function doLogin() {
  const btn = document.getElementById('login-btn');
  const errEl = document.getElementById('login-error');
  errEl.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  const username = document.getElementById('l-user').value.trim();
  const password  = document.getElementById('l-pass').value;
  const totp_code = document.getElementById('l-totp').value.trim();

  try {
    // Login does NOT need CSRF — call fetch directly, not via api()
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, ...(totp_code ? { totp_code } : {}) }),
    });

    let data = {};
    try { data = await res.json(); } catch(_) {}

    console.log('[scanner login] status:', res.status, 'data:', data);

    if (!res.ok) {
      errEl.textContent = data.error || `Login failed (${res.status})`;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Sign in';
      return;
    }

    if (data.require_totp) {
      _needTotp = true;
      document.getElementById('totp-field').style.display = 'block';
      document.getElementById('l-totp').focus();
      btn.disabled = false;
      btn.textContent = 'Verify';
      return;
    }

    // Check permission — must have 'events' or be master
    const perms = data.permissions || [];
    if (data.role !== 'master' && !perms.includes('events')) {
      errEl.textContent = 'Access denied: no events permission.';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Sign in';
      return;
    }

    _token = data.token;
    _adminName = data.name;
    _adminRole = data.role;

    await fetchCsrf();
    await bootApp();
  } catch (e) {
    console.error('[scanner login] exception:', e);
    errEl.textContent = 'Network error — ' + (e.message || 'check connection.');
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

async function doLogout() {
  try { await api('POST', '/api/admin/logout', {}); } catch {}
  _token = null;
  _scanning = false;
  if (_scanner) { try { await _scanner.stop(); } catch {} _scanner = null; }
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('l-pass').value = '';
  document.getElementById('l-totp').value = '';
  document.getElementById('totp-field').style.display = 'none';
  document.getElementById('login-btn').textContent = 'Sign in';
}

// ── BOOT APP ───────────────────────────────────────────────────────────────────
async function bootApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('topbar-admin').textContent = _adminName;

  await loadEvents();
}

async function loadEvents() {
  const { ok, data } = await api('GET', '/api/events');
  if (!ok) return;

  // Only upcoming or recent events
  _events = (data || []).sort((a, b) => {
    // upcoming first, then by date desc
    if (a.is_upcoming !== b.is_upcoming) return a.is_upcoming ? -1 : 1;
    return new Date(b.event_date || 0) - new Date(a.event_date || 0);
  });

  const opts = _events.map(e =>
    `<option value="${e.id}">${e.is_upcoming ? '🟢' : '⚫'} ${e.title}${e.event_date ? ' — ' + new Date(e.event_date).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : ''}</option>`
  ).join('');

  document.getElementById('event-select').innerHTML = '<option value="">— Select event —</option>' + opts;
  document.getElementById('data-event-select').innerHTML = '<option value="">— Select event —</option>' + opts;

  // Auto-select the first upcoming event (or first event if none upcoming)
  const defaultEvent = _events.find(e => e.is_upcoming) || _events[0];
  if (defaultEvent) {
    const id = String(defaultEvent.id);
    document.getElementById('event-select').value = id;
    document.getElementById('data-event-select').value = id;
    // Update topbar label
    document.getElementById('topbar-event').textContent = defaultEvent.title;
  }
}

// ── TAB SWITCHING ──────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.getElementById('tab-scanner').classList.toggle('visible', tab === 'scanner');
  document.getElementById('tab-data').classList.toggle('visible', tab === 'data');
  document.getElementById('tab-btn-scanner').classList.toggle('active', tab === 'scanner');
  document.getElementById('tab-btn-data').classList.toggle('active', tab === 'data');

  if (tab === 'data') {
    const sel = document.getElementById('data-event-select');
    // Sync selected event from scanner tab if set, otherwise keep data-tab's own value
    const scanEvent = document.getElementById('event-select').value;
    if (scanEvent) sel.value = scanEvent;
    if (sel.value) loadRegistrations();
  } else {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
  }
}

// ── EVENT SELECT ───────────────────────────────────────────────────────────────
function onEventChange() {
  const sel = document.getElementById('event-select');
  const ev = _events.find(e => String(e.id) === String(sel.value));
  document.getElementById('topbar-event').textContent = ev ? ev.title : 'Select event';
  // Reset result card
  hideResult();
}

// ── SCANNER ────────────────────────────────────────────────────────────────────
async function startCamera() {
  const eventId = document.getElementById('event-select').value;
  if (!eventId) { toast('Select an event first'); return; }

  document.getElementById('start-scan-btn').style.display = 'none';
  document.getElementById('qr-reader-wrap').style.display = 'block';
  document.getElementById('scan-hint').style.display = 'block';

  _scanner = new Html5Qrcode('qr-reader');
  try {
    await _scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 200, height: 200 }, aspectRatio: 1.0 },
      onQrScanned,
      () => {}
    );
    _scanning = true;
  } catch (e) {
    console.error('Camera error:', e);
    toast('Camera not accessible — check permissions');
    document.getElementById('start-scan-btn').style.display = 'flex';
    document.getElementById('qr-reader-wrap').style.display = 'none';
    document.getElementById('scan-hint').style.display = 'none';
  }
}

let _scanCooldown = false;

async function onQrScanned(text) {
  if (_scanCooldown) return;
  if (text === _lastScanned) return; // same QR, ignore repeat
  _lastScanned = text;
  _scanCooldown = true;
  setTimeout(() => { _scanCooldown = false; }, 2500);

  // Pause scanner visually while processing
  showResult({ status: 'loading' });

  const eventId = document.getElementById('event-select').value;
  const { ok, data } = await api('POST', '/api/admin/scan-qr/lookup', { qr_token: text, event_id: eventId });

  if (!ok || data.status === 'invalid') {
    flashBody('red');
    vibrateDevice([100, 50, 100]);
    showResult({ status: 'invalid', error: data?.error || 'Invalid QR code — not a KFS ticket.' });
    return;
  }

  if (data.status === 'already_used') {
    flashBody('red');
    vibrateDevice([200, 100, 200]);
    showResult({ status: 'already_used', ...data });
    return;
  }

  if (data.status === 'valid') {
    flashBody('green');
    vibrateDevice([50]);
    _pendingReg = { registration_id: data.registration_id, name: data.name };
    showResult({ status: 'valid', ...data });
  }
}

function showResult(d) {
  const card = document.getElementById('result-card');
  card.style.display = 'block';

  const icon = document.getElementById('res-icon');
  const label = document.getElementById('res-label');
  const sublabel = document.getElementById('res-sublabel');
  const info = document.getElementById('res-info');
  const actions = document.getElementById('res-actions');

  card.className = '';
  icon.textContent = '';
  label.textContent = '';
  sublabel.textContent = '';
  info.innerHTML = '';
  actions.innerHTML = '';
  document.getElementById('confirm-success').style.display = 'none';
  document.getElementById('scan-again-hint').style.display = 'none';

  if (d.status === 'loading') {
    card.classList.add('valid');
    icon.textContent = '⏳';
    label.textContent = 'Checking…';
    return;
  }

  if (d.status === 'invalid') {
    card.classList.add('invalid');
    icon.textContent = '✗';
    label.textContent = 'Invalid QR';
    sublabel.textContent = d.error || '';
    actions.innerHTML = `<button class="btn btn-ghost btn-sm" onclick="resumeScanner()">Scan again</button>`;
    return;
  }

  if (d.status === 'already_used') {
    card.classList.add('used');
    icon.textContent = '⛔';
    label.textContent = 'Already checked in';
    const when = d.checked_in_at ? new Date(d.checked_in_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : '';
    sublabel.textContent = when ? `Scanned at ${when}` : '';
    info.innerHTML = `
      <div class="info-row"><span class="info-label">Name</span><span class="info-value name">${esc(d.name)}</span></div>
      ${d.roll_no ? `<div class="info-row"><span class="info-label">Roll No</span><span class="info-value">${esc(d.roll_no)}</span></div>` : ''}
      ${d.email ? `<div class="info-row"><span class="info-label">Email</span><span class="info-value">${esc(d.email)}</span></div>` : ''}
      ${d.checked_in_by ? `<div class="info-row"><span class="info-label">By</span><span class="info-value" style="color:var(--muted)">${esc(d.checked_in_by)}</span></div>` : ''}
    `;
    actions.innerHTML = `<button class="btn btn-ghost btn-sm" onclick="resumeScanner()">Scan again</button>`;
    return;
  }

  if (d.status === 'valid') {
    card.classList.add('valid');
    icon.textContent = '✓';
    label.textContent = 'Valid ticket';
    sublabel.textContent = d.event || '';
    info.innerHTML = `
      <div class="info-row"><span class="info-label">Name</span><span class="info-value name">${esc(d.name)}</span></div>
      ${d.roll_no ? `<div class="info-row"><span class="info-label">Roll No</span><span class="info-value">${esc(d.roll_no)}</span></div>` : ''}
      ${d.email ? `<div class="info-row"><span class="info-label">Email</span><span class="info-value">${esc(d.email)}</span></div>` : ''}
    `;
    actions.innerHTML = `
      <button class="btn btn-green" id="confirm-btn" onclick="confirmEntry()">
        ✓ Allow Entry
      </button>
      <button class="btn btn-ghost btn-sm" onclick="resumeScanner()">Skip</button>
    `;
  }
}

function hideResult() {
  document.getElementById('result-card').style.display = 'none';
  document.getElementById('confirm-success').style.display = 'none';
  document.getElementById('scan-again-hint').style.display = 'none';
  _pendingReg = null;
  _lastScanned = null;
  _scanCooldown = false;
}

async function confirmEntry() {
  if (!_pendingReg) return;
  const btn = document.getElementById('confirm-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>'; }

  const { ok, data } = await api('POST', '/api/admin/scan-qr/confirm', {
    registration_id: _pendingReg.registration_id,
    event_id: document.getElementById('event-select').value,
  });

  if (!ok) {
    toast(data?.error || 'Confirm failed');
    if (btn) { btn.disabled = false; btn.textContent = '✓ Allow Entry'; }
    return;
  }

  // Show success
  const successEl = document.getElementById('confirm-success');
  document.getElementById('confirm-name').textContent = _pendingReg.name;
  successEl.style.display = 'flex';
  document.getElementById('result-card').style.display = 'none';
  document.getElementById('scan-again-hint').style.display = 'block';

  vibrateDevice([80, 40, 80, 40, 120]);

  // Auto-resume after 3s — clear all scan state so next scan works immediately
  setTimeout(() => {
    _pendingReg = null;
    _lastScanned = null;
    _scanCooldown = false;
    resumeScanner();
  }, 3000);

  // Invalidate data cache for this event
  const eventId = document.getElementById('event-select').value;
  if (eventId) delete _regsCache[eventId];
}

function resumeScanner() {
  hideResult();
  _lastScanned = null;
}

// ── DATA TAB ───────────────────────────────────────────────────────────────────
let _allRegs = [];
let _searchQuery = '';

async function loadRegistrations() {
  const sel = document.getElementById('data-event-select');
  const eventId = sel.value;
  if (!eventId) return;

  const content = document.getElementById('data-content');
  content.innerHTML = '<div class="loading-state">Loading…</div>';

  const { ok, data } = await api('GET', `/api/admin/events/${eventId}/registrations`);
  if (!ok) { content.innerHTML = '<div class="empty-state"><div class="icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.4"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>Failed to load registrations</div>'; return; }

  _allRegs = data || [];
  _regsCache[eventId] = _allRegs;
  renderDataTab(eventId);
  startAutoRefresh(eventId);
}

let _autoRefreshTimer = null;

function startAutoRefresh(eventId) {
  if (_autoRefreshTimer) clearInterval(_autoRefreshTimer);
  _autoRefreshTimer = setInterval(() => silentRefresh(eventId), 15000);
}

async function silentRefresh(eventId) {
  const sel = document.getElementById('data-event-select');
  if (!sel || sel.value !== String(eventId)) { clearInterval(_autoRefreshTimer); return; }
  const { ok, data } = await api('GET', `/api/admin/events/${eventId}/registrations`);
  if (!ok) return;
  _allRegs = data || [];
  _regsCache[eventId] = _allRegs;

  const total = _allRegs.length;
  const checked = _allRegs.filter(r => r.checked_in).length;
  const totalEl = document.querySelector('.stat-box:nth-child(1) .num');
  const checkedEl = document.querySelector('.stat-box.checked .num');
  const pendingEl = document.querySelector('.stat-box.pending .num');
  if (totalEl) totalEl.textContent = total;
  if (checkedEl) checkedEl.textContent = checked;
  if (pendingEl) pendingEl.textContent = total - checked;

  const lastEl = document.getElementById('last-updated');
  if (lastEl) lastEl.textContent = `Updated ${new Date().toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit', second:'2-digit' })}`;

  const q = document.getElementById('regs-search')?.value || '';
  const filtered = q ? _allRegs.filter(r =>
    (r.name||'').toLowerCase().includes(q.toLowerCase()) ||
    (r.email||'').toLowerCase().includes(q.toLowerCase()) ||
    (r.roll_no||'').toLowerCase().includes(q.toLowerCase())
  ) : _allRegs;
  renderRegsList(filtered);
}

async function refreshRegistrations() {
  const sel = document.getElementById('data-event-select');
  const eventId = sel?.value;
  if (!eventId) return;
  const btn = document.getElementById('refresh-btn');
  if (btn) { btn.disabled = true; btn.style.opacity = '.5'; }
  await silentRefresh(eventId);
  if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
}

function renderDataTab(eventId) {
  const total = _allRegs.length;
  const checked = _allRegs.filter(r => r.checked_in).length;
  const pending = total - checked;

  const ev = _events.find(e => String(e.id) === String(eventId));

  document.getElementById('data-content').innerHTML = `
    <div class="data-header">
      <div>
        <h2>${ev ? ev.title : 'Registrations'}</h2>
        <div id="last-updated" style="font-size:10px;color:var(--muted);margin-top:2px">Updated just now</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <button class="btn btn-ghost btn-sm" id="refresh-btn" onclick="refreshRegistrations()" title="Refresh" style="padding:10px;width:auto">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
        <button class="btn btn-ghost btn-sm" onclick="exportData('${eventId}')">↓ Export</button>
      </div>
    </div>

    <div class="stats-strip">
      <div class="stat-box">
        <div class="num">${total}</div>
        <div class="label">Total</div>
      </div>
      <div class="stat-box checked">
        <div class="num">${checked}</div>
        <div class="label">Present</div>
      </div>
      <div class="stat-box pending">
        <div class="num">${pending}</div>
        <div class="label">Pending</div>
      </div>
    </div>

    <div class="data-toolbar">
      <input type="text" id="regs-search" placeholder="Search name, email, roll no…" oninput="filterRegs(this.value)">
    </div>

    <div id="regs-list"></div>
  `;

  renderRegsList(_allRegs);
}

function filterRegs(q) {
  _searchQuery = q.toLowerCase();
  const filtered = _allRegs.filter(r =>
    (r.name || '').toLowerCase().includes(_searchQuery) ||
    (r.email || '').toLowerCase().includes(_searchQuery) ||
    (r.roll_no || '').toLowerCase().includes(_searchQuery)
  );
  renderRegsList(filtered);
}

function renderRegsList(regs) {
  const list = document.getElementById('regs-list');
  if (!list) return;

  if (!regs.length) {
    const emptyIcon = _searchQuery
      ? `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.4"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`
      : `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.4"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.6 1.27h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.68 2.81a2 2 0 0 1-.45 2.11L7.91 9a16 16 0 0 0 6.1 6.1l1.27-1.27a2 2 0 0 1 2.11-.45c.91.32 1.85.55 2.81.68a2 2 0 0 1 1.72 2.03z"/></svg>`;
    list.innerHTML = `<div class="empty-state"><div class="icon">${emptyIcon}</div>${_searchQuery ? 'No matches' : 'No registrations yet'}</div>`;
    return;
  }

  list.innerHTML = regs.map(r => `
    <div class="reg-card ${r.checked_in ? 'checked-in' : ''}" onclick="openRegDetail(${r.id})">
      <div class="reg-dot"></div>
      <div class="reg-info">
        <div class="reg-name">${esc(r.name)}</div>
        <div class="reg-sub">${esc(r.email)}${r.roll_no ? ' · ' + r.roll_no : ''}</div>
      </div>
      <div class="reg-time">
        ${r.checked_in
          ? (r.checked_in_at ? new Date(r.checked_in_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : '✓')
          : (r.created_at ? new Date(r.created_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : '')
        }
      </div>
    </div>
  `).join('');
}

function openRegDetail(id) {
  const r = _allRegs.find(x => x.id === id);
  if (!r) return;

  const evId = document.getElementById('data-event-select').value;

  document.getElementById('modal-content').innerHTML = `
    <div class="modal-name">${esc(r.name)}</div>
    <div class="modal-sub">${esc(r.email)}</div>

    <div class="modal-fields">
      ${r.roll_no ? `<div class="mfield"><span class="mfield-label">Roll No</span><span class="mfield-value">${esc(r.roll_no)}</span></div>` : ''}
      ${r.phone   ? `<div class="mfield"><span class="mfield-label">Phone</span><span class="mfield-value">${esc(r.phone)}</span></div>` : ''}
      <div class="mfield">
        <span class="mfield-label">Status</span>
        <span class="mfield-value">
          ${r.checked_in
            ? `<span class="badge green">✓ Checked in</span>`
            : `<span class="badge grey">Pending</span>`}
        </span>
      </div>
      ${r.checked_in && r.checked_in_at ? `
        <div class="mfield"><span class="mfield-label">Check-in</span><span class="mfield-value">${new Date(r.checked_in_at).toLocaleString('en-IN', { timeZone:'Asia/Kolkata' })}</span></div>
        ${r.checked_in_by ? `<div class="mfield"><span class="mfield-label">By</span><span class="mfield-value" style="color:var(--muted)">${esc(r.checked_in_by)}</span></div>` : ''}
      ` : ''}
      <div class="mfield"><span class="mfield-label">Registered</span><span class="mfield-value">${new Date(r.created_at).toLocaleString('en-IN', { timeZone:'Asia/Kolkata' })}</span></div>
    </div>

    <div style="display:flex;gap:8px">
      <button class="btn btn-danger btn-sm" onclick="deleteReg(${r.id}, '${evId}')">Delete</button>
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Close</button>
    </div>
  `;
  document.getElementById('modal-overlay').classList.add('visible');
}

async function deleteReg(id, eventId) {
  if (!confirm('Delete this registration?')) return;
  const { ok } = await api('DELETE', `/api/admin/events/${eventId}/registrations/${id}`);
  if (!ok) { toast('Delete failed'); return; }
  closeModal();
  toast('Registration deleted');
  _allRegs = _allRegs.filter(r => r.id !== id);
  renderDataTab(eventId);
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('visible');
}

async function exportData(eventId) {
  if (!eventId) return;
  // Download via direct link with auth header isn't possible; use window.open with token in query
  // Instead open a fresh fetch + blob download
  try {
    const r = await fetch(`/api/admin/events/${eventId}/registrations/export`, {
      headers: { 'Authorization': `Bearer ${_token}`, 'x-csrf-token': _csrfToken || '' },
    });
    if (!r.ok) { toast('Export failed'); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kfs-registrations-event-${eventId}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    toast('Export failed — check connection');
  }
}

// ── UTILS ──────────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

let _toastTimer;
function toast(msg, duration = 2500) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), duration);
}

function flashBody(color) {
  document.body.classList.remove('flash-green', 'flash-red');
  void document.body.offsetWidth; // reflow
  document.body.classList.add(`flash-${color}`);
  setTimeout(() => document.body.classList.remove(`flash-${color}`), 600);
}

function vibrateDevice(pattern) {
  if (navigator.vibrate) navigator.vibrate(pattern);
}

// Try to auto-login on page load via refresh cookie
(async function autoLogin() {
  try {
    const r = await fetch('/api/admin/refresh', {
      method: 'POST', credentials: 'include',
      headers: { 'x-csrf-token': _csrfToken || '' },
    });
    if (!r.ok) return;
    const d = await r.json();
    if (!d.token) return;

    const perms = d.permissions || [];
    if (d.role !== 'master' && !perms.includes('events')) return; // no scanner access

    _token = d.token;
    _adminName = d.name;
    _adminRole = d.role;
    await bootApp();
  } catch {}
})();

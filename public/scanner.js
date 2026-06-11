// ── KFS Scanner JS v2.0 ──────────────────────────────────────────────────────
// Full rewrite: Apple-style UI, comprehensive logging, all bugs fixed.

// ── State ─────────────────────────────────────────────────────────────────────
let _token       = null;
let _adminName   = '';
let _adminRole   = '';
let _events      = [];
let _scanner     = null;
let _scanning    = false;
let _lastScanned = null;
let _pendingReg  = null;   // { registration_id, name } awaiting confirm
let _csrfToken   = null;
let _regsCache   = {};     // eventId → registrations array
let _allRegs     = [];
let _searchQuery = '';
let _autoRefreshTimer = null;
let _scanCooldown = false;

// ── Logging helper ────────────────────────────────────────────────────────────
function log(tag, ...args) {
  console.log(`[scanner][${tag}]`, ...args);
}
function warn(tag, ...args) {
  console.warn(`[scanner][${tag}]`, ...args);
}
function err(tag, ...args) {
  console.error(`[scanner][${tag}]`, ...args);
}

// ── CSRF ──────────────────────────────────────────────────────────────────────
async function fetchCsrf() {
  try {
    const r = await fetch('/api/csrf-token');
    if (!r.ok) { warn('csrf', 'fetch failed', r.status); return; }
    const d = await r.json();
    if (d.csrf_token) {
      _csrfToken = d.csrf_token;
      log('csrf', 'token refreshed');
    }
  } catch (e) {
    warn('csrf', 'exception:', e.message);
  }
}

// Fetch CSRF on load — disable login until ready (5s max)
document.getElementById('login-btn').disabled = true;
Promise.race([fetchCsrf(), new Promise(r => setTimeout(r, 5000))]).then(() => {
  document.getElementById('login-btn').disabled = false;
});
// Auto-refresh every 3.5 hours
setInterval(fetchCsrf, 3.5 * 60 * 60 * 1000);

// ── API helper ────────────────────────────────────────────────────────────────
async function api(method, url, body) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ..._token        ? { 'Authorization': `Bearer ${_token}` } : {},
      ..._csrfToken && method !== 'GET' ? { 'x-csrf-token': _csrfToken } : {},
    },
    credentials: 'include',
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const r    = await fetch(url, opts);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      warn('api', `${method} ${url} → ${r.status}`, data);
    }
    return { ok: r.ok, status: r.status, data };
  } catch (e) {
    err('api', `${method} ${url} FAILED:`, e.message);
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

// Auto-refresh token every 12 min
setInterval(async () => {
  if (!_token) return;
  try {
    const r = await fetch('/api/admin/refresh', {
      method: 'POST', credentials: 'include',
      headers: { 'x-csrf-token': _csrfToken || '' },
    });
    if (r.ok) {
      const d = await r.json();
      if (d.token) { _token = d.token; log('auth', 'token refreshed'); }
    }
  } catch (e) {
    warn('auth', 'refresh failed:', e.message);
  }
}, 12 * 60 * 1000);

// ── LOGIN ─────────────────────────────────────────────────────────────────────
document.getElementById('l-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
document.getElementById('l-totp')?.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

async function doLogin() {
  const btn   = document.getElementById('login-btn');
  const errEl = document.getElementById('login-error');

  errEl.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  const username  = document.getElementById('l-user').value.trim();
  const password  = document.getElementById('l-pass').value;
  const totp_code = document.getElementById('l-totp').value.trim();

  log('login', `attempt username="${username}"`);

  try {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, ...(totp_code ? { totp_code } : {}) }),
    });

    let data = {};
    try { data = await res.json(); } catch (_) {}

    log('login', `response status=${res.status}`, data);

    if (!res.ok) {
      const msg = data.error || `Login failed (HTTP ${res.status})`;
      showLoginError(msg);
      btn.disabled = false;
      btn.textContent = 'Sign in';
      return;
    }

    if (data.require_totp) {
      document.getElementById('totp-field').style.display = 'block';
      document.getElementById('l-totp').focus();
      btn.disabled = false;
      btn.textContent = 'Verify';
      return;
    }

    // Permission check
    const perms = data.permissions || [];
    if (data.role !== 'master' && !perms.includes('events')) {
      showLoginError('Access denied — no events permission.');
      btn.disabled = false;
      btn.textContent = 'Sign in';
      return;
    }

    _token     = data.token;
    _adminName = data.name;
    _adminRole = data.role;
    log('login', `✓ logged in as ${_adminName} (${_adminRole})`);

    await fetchCsrf();
    await bootApp();

  } catch (e) {
    err('login', 'exception:', e.message);
    showLoginError('Network error — ' + (e.message || 'check connection.'));
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

function showLoginError(msg) {
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.style.display = 'block';
}

async function doLogout() {
  try { await api('POST', '/api/admin/logout', {}); } catch {}
  _token = null;
  if (_scanner) { try { await _scanner.stop(); } catch {} _scanner = null; }
  _scanning = false;
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('l-pass').value = '';
  document.getElementById('l-totp').value = '';
  document.getElementById('totp-field').style.display = 'none';
  document.getElementById('login-btn').textContent = 'Sign in';
  document.getElementById('login-error').style.display = 'none';
  log('auth', 'logged out');
}

// ── BOOT APP ──────────────────────────────────────────────────────────────────
async function bootApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('topbar-admin').textContent = _adminName;
  log('boot', 'app started, loading events...');
  await loadEvents();
}

async function loadEvents() {
  log('events', 'fetching from /api/admin/scanner/events');
  const { ok, data, status } = await api('GET', '/api/admin/scanner/events');
  if (!ok) {
    err('events', `fetch failed status=${status}`, data);
    toast('Failed to load events');
    return;
  }

  _events = (data || []).sort((a, b) => {
    if (a.is_upcoming !== b.is_upcoming) return a.is_upcoming ? -1 : 1;
    return new Date(b.event_date || 0) - new Date(a.event_date || 0);
  });

  log('events', `loaded ${_events.length} events`);

  const opts = _events.map(e =>
    `<option value="${e.id}">${e.is_upcoming ? '●' : '○'} ${esc(e.title)}${e.event_date ? '  ·  ' + new Date(e.event_date).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : ''}</option>`
  ).join('');

  const emptyOpt = '<option value="">— Select event —</option>';
  document.getElementById('event-select').innerHTML = emptyOpt + opts;
  document.getElementById('data-event-select').innerHTML = emptyOpt + opts;

  // Auto-select first upcoming event
  const def = _events.find(e => e.is_upcoming) || _events[0];
  if (def) {
    const id = String(def.id);
    document.getElementById('event-select').value = id;
    document.getElementById('data-event-select').value = id;
    onEventChange();
    loadRegistrations();
  }
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  ['scan', 'data'].forEach(t => {
    document.getElementById(`tab-${t}`).classList.toggle('visible', t === tab);
    document.getElementById(`tab-btn-${t}`).classList.toggle('active', t === tab);
  });
  if (tab === 'data') {
    const scanEv = document.getElementById('event-select').value;
    const dataEl = document.getElementById('data-event-select');
    if (scanEv) dataEl.value = scanEv;
    if (dataEl.value) loadRegistrations();
  } else {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
  }
}

// ── EVENT SELECT ──────────────────────────────────────────────────────────────
function onEventChange() {
  const sel = document.getElementById('event-select');
  const ev  = _events.find(e => String(e.id) === String(sel.value));
  document.getElementById('topbar-event').textContent = ev ? ev.title : 'Select event';
  hideResult();
  _scanCooldown = false;
  _lastScanned  = null;
  log('event-select', `selected event_id=${sel.value} "${ev?.title || 'none'}"`);
}

// ── SCANNER ───────────────────────────────────────────────────────────────────
async function startCamera() {
  const eventId = document.getElementById('event-select').value;
  if (!eventId) { toast('Select an event first'); return; }

  document.getElementById('start-scan-btn').style.display = 'none';
  document.getElementById('qr-reader-wrap').style.display = 'block';

  _scanner = new Html5Qrcode('qr-reader');
  const boxSize = Math.min(Math.floor(Math.min(window.innerWidth, window.innerHeight) * 0.6), 260);
  log('camera', `starting, boxSize=${boxSize}`);

  try {
    await _scanner.start(
      { facingMode: 'environment' },
      { fps: 12, qrbox: { width: boxSize, height: boxSize } },
      onQrScanned,
      () => {}
    );
    _scanning = true;
    log('camera', 'started ✓');
  } catch (e) {
    err('camera', 'start failed:', e.message);
    toast('Camera not accessible — check permissions');
    _scanner = null;
    document.getElementById('start-scan-btn').style.display = 'flex';
    document.getElementById('qr-reader-wrap').style.display = 'none';
  }
}

async function onQrScanned(rawText) {
  if (_scanCooldown) return;

  // Normalise: trim + lowercase — QR tokens are UUIDs stored lowercase
  const text = String(rawText).trim().toLowerCase();
  if (!text) return;

  log('scan', `raw="${rawText.trim().slice(0, 40)}" normalised="${text.slice(0, 40)}"`);

  if (text === _lastScanned) {
    log('scan', 'skipping duplicate scan');
    return;
  }

  _lastScanned  = text;
  _scanCooldown = true;
  setTimeout(() => {
    _scanCooldown = false;
    log('scan', 'cooldown cleared');
  }, 2500);

  showResult({ status: 'loading' });

  const eventId = document.getElementById('event-select').value;
  log('scan', `calling lookup qr_token="${text.slice(0,8)}..." event_id=${eventId}`);

  const { ok, status, data } = await api('POST', '/api/admin/scan-qr/lookup', {
    qr_token: text,
    event_id: eventId,
  });

  log('scan', `lookup response ok=${ok} status=${status} data.status=${data?.status}`);

  if (!ok) {
    flashBody('red');
    vibrateDevice([100, 50, 100]);
    if (status === 404 || data?.status === 'invalid') {
      showResult({ status: 'invalid', error: data?.error || 'Invalid QR code — not a KFS ticket.' });
    } else {
      showResult({ status: 'invalid', error: `Server error (HTTP ${status}) — try again.` });
    }
    return;
  }

  if (data.status === 'invalid') {
    flashBody('red');
    vibrateDevice([100, 50, 100]);
    showResult({ status: 'invalid', error: data.error || 'Invalid QR code.' });
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
    log('scan', `valid — reg_id=${data.registration_id} name="${data.name}"`);
    showResult({ status: 'valid', ...data });
  }
}

function showResult(d) {
  const card      = document.getElementById('result-card');
  const icon      = document.getElementById('res-icon');
  const label     = document.getElementById('res-label');
  const sublabel  = document.getElementById('res-sublabel');
  const fields    = document.getElementById('res-fields');
  const actions   = document.getElementById('res-actions');

  card.style.display = 'block';
  card.className     = '';
  icon.textContent   = '';
  label.textContent  = '';
  sublabel.textContent = '';
  fields.innerHTML   = '';
  actions.innerHTML  = '';
  document.getElementById('confirm-success').style.display = 'none';
  document.getElementById('scan-next-hint').style.display  = 'none';

  if (d.status === 'loading') {
    card.classList.add('loading');
    icon.innerHTML  = '<div class="spinner spinner-dark"></div>';
    label.textContent = 'Checking…';
    sublabel.style.display = 'none';
    return;
  }

  sublabel.style.display = '';

  if (d.status === 'invalid') {
    card.classList.add('invalid');
    icon.textContent    = '✕';
    label.textContent   = 'Invalid QR code';
    sublabel.textContent = d.error || 'Not a valid KFS ticket.';
    actions.innerHTML   = `<button class="btn btn-ghost" style="width:auto" onclick="resumeScanner()">Scan again</button>`;
    return;
  }

  if (d.status === 'already_used') {
    card.classList.add('used');
    icon.textContent    = '⊘';
    label.textContent   = 'Already checked in';
    const when = d.checked_in_at
      ? new Date(d.checked_in_at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })
      : '';
    sublabel.textContent = when ? `Scanned at ${when}` : 'This ticket was already used.';
    fields.innerHTML = buildFields([
      { label: 'Name',   value: d.name,    big: true },
      { label: 'Email',  value: d.email },
      { label: 'Roll',   value: d.roll_no },
      { label: 'Scanned by', value: d.checked_in_by },
    ]);
    actions.innerHTML = `<button class="btn btn-ghost" style="width:auto" onclick="resumeScanner()">Scan again</button>`;
    return;
  }

  if (d.status === 'valid') {
    card.classList.add('valid');
    icon.textContent     = '✓';
    label.textContent    = 'Valid ticket';
    sublabel.textContent = d.event || '';
    fields.innerHTML = buildFields([
      { label: 'Name',  value: d.name,    big: true },
      { label: 'Email', value: d.email },
      { label: 'Roll',  value: d.roll_no },
    ]);
    actions.innerHTML = `
      <button class="btn btn-green" id="confirm-btn" onclick="confirmEntry()">✓ Allow Entry</button>
      <button class="btn btn-ghost" style="width:auto" onclick="resumeScanner()">Skip</button>
    `;
  }
}

function buildFields(items) {
  return items.filter(i => i.value).map(i => `
    <div class="rfield">
      <span class="rfield-label">${esc(i.label)}</span>
      <span class="rfield-value${i.big ? ' name-value' : ''}">${esc(i.value)}</span>
    </div>
  `).join('');
}

function hideResult() {
  document.getElementById('result-card').style.display = 'none';
  document.getElementById('confirm-success').style.display = 'none';
  document.getElementById('scan-next-hint').style.display  = 'none';
  _pendingReg  = null;
  _lastScanned = null;
  _scanCooldown = false;
}

async function confirmEntry() {
  if (!_pendingReg) return;

  const btn = document.getElementById('confirm-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>'; }

  const eventId = document.getElementById('event-select').value;
  log('confirm', `reg_id=${_pendingReg.registration_id} event_id=${eventId}`);

  const { ok, data } = await api('POST', '/api/admin/scan-qr/confirm', {
    registration_id: _pendingReg.registration_id,
    event_id: eventId,
  });

  log('confirm', `response ok=${ok}`, data);

  if (!ok) {
    err('confirm', 'confirm failed:', data?.error);
    toast(data?.error || 'Confirm failed — try again.');
    if (btn) { btn.disabled = false; btn.textContent = '✓ Allow Entry'; }
    return;
  }

  // Success UI
  const name = _pendingReg.name;
  document.getElementById('confirm-name-sub').textContent = `${name} has been admitted`;
  document.getElementById('confirm-success').style.display = 'block';
  document.getElementById('result-card').style.display = 'none';
  document.getElementById('scan-next-hint').style.display = 'block';

  vibrateDevice([60, 40, 60, 40, 100]);
  log('confirm', `✓ ${name} checked in`);

  // Invalidate data cache for this event
  if (eventId) delete _regsCache[eventId];

  // Auto-resume after 3s
  setTimeout(() => {
    _pendingReg   = null;
    _lastScanned  = null;
    _scanCooldown = false;
    resumeScanner();
  }, 3000);
}

function resumeScanner() {
  hideResult();
  _lastScanned  = null;
  _scanCooldown = false;
}

// ── DATA TAB ──────────────────────────────────────────────────────────────────
async function loadRegistrations() {
  const sel     = document.getElementById('data-event-select');
  const eventId = sel.value;
  if (!eventId) return;

  const content = document.getElementById('data-content');
  content.innerHTML = `
    <div class="state-box">
      <div class="spinner spinner-dark" style="width:28px;height:28px;border-width:3px"></div>
      <div class="state-sub" style="margin-top:8px">Loading registrations…</div>
    </div>`;

  log('data', `fetching registrations for event_id=${eventId}`);
  const { ok, data, status } = await api('GET', `/api/admin/events/${eventId}/registrations`);

  if (!ok) {
    err('data', `fetch failed status=${status}`, data);
    content.innerHTML = `
      <div class="state-box">
        <div class="state-icon">⚠</div>
        <div class="state-title">Failed to load</div>
        <div class="state-sub">${esc(data?.error || `HTTP ${status}`)}</div>
      </div>`;
    return;
  }

  _allRegs = data || [];
  _regsCache[eventId] = _allRegs;
  log('data', `loaded ${_allRegs.length} registrations for event_id=${eventId}`);

  if (_allRegs.length === 0) {
    // Try debug endpoint to diagnose
    const dbg = await api('GET', `/api/admin/events/${eventId}/registrations/debug`);
    log('data', 'debug info:', dbg.data);
  }

  renderDataTab(eventId);
  startAutoRefresh(eventId);
}

function startAutoRefresh(eventId) {
  if (_autoRefreshTimer) clearInterval(_autoRefreshTimer);
  _autoRefreshTimer = setInterval(() => silentRefresh(eventId), 15000);
}

async function silentRefresh(eventId) {
  const sel = document.getElementById('data-event-select');
  if (!sel || String(sel.value) !== String(eventId)) {
    clearInterval(_autoRefreshTimer);
    return;
  }
  const { ok, data } = await api('GET', `/api/admin/events/${eventId}/registrations`);
  if (!ok) return;

  _allRegs = data || [];
  _regsCache[eventId] = _allRegs;

  // Update stats
  const total   = _allRegs.length;
  const checked = _allRegs.filter(r => r.checked_in).length;
  const tEl = document.querySelector('.stat-card:nth-child(1) .stat-num');
  const cEl = document.querySelector('.stat-card.present .stat-num');
  const pEl = document.querySelector('.stat-card.pending .stat-num');
  if (tEl) tEl.textContent = total;
  if (cEl) cEl.textContent = checked;
  if (pEl) pEl.textContent = total - checked;

  const lastEl = document.getElementById('last-updated');
  if (lastEl) lastEl.textContent = 'Updated ' + new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const q = document.getElementById('regs-search')?.value || '';
  renderRegsList(q ? filterRegsBy(q) : _allRegs);
}

async function refreshRegistrations() {
  const sel     = document.getElementById('data-event-select');
  const eventId = sel?.value;
  if (!eventId) return;
  const btn = document.getElementById('refresh-btn');
  if (btn) { btn.disabled = true; }
  await loadRegistrations();
  if (btn) { btn.disabled = false; }
}

function renderDataTab(eventId) {
  const total   = _allRegs.length;
  const checked = _allRegs.filter(r => r.checked_in).length;
  const ev      = _events.find(e => String(e.id) === String(eventId));

  document.getElementById('data-content').innerHTML = `
    <div class="data-header">
      <div>
        <div class="data-title">${ev ? esc(ev.title) : 'Registrations'}</div>
        <div class="data-title-sub" id="last-updated">Updated just now</div>
      </div>
      <div class="data-actions">
        <button class="btn btn-icon" id="refresh-btn" onclick="refreshRegistrations()" title="Refresh" aria-label="Refresh">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
        </button>
        <button class="btn btn-ghost" onclick="exportData('${eventId}')" style="font-size:13px">Export</button>
      </div>
    </div>

    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-num">${total}</div>
        <div class="stat-label">Total</div>
      </div>
      <div class="stat-card present">
        <div class="stat-num">${checked}</div>
        <div class="stat-label">Present</div>
      </div>
      <div class="stat-card pending">
        <div class="stat-num">${total - checked}</div>
        <div class="stat-label">Pending</div>
      </div>
    </div>

    <div class="search-wrap">
      <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input type="text" id="regs-search" placeholder="Search name, email, roll no…" oninput="onSearch(this.value)">
    </div>

    <div id="regs-list"></div>
  `;

  renderRegsList(_allRegs);
}

function onSearch(q) {
  _searchQuery = q;
  renderRegsList(filterRegsBy(q));
}

function filterRegsBy(q) {
  if (!q) return _allRegs;
  const ql = q.toLowerCase();
  return _allRegs.filter(r =>
    (r.name    || '').toLowerCase().includes(ql) ||
    (r.email   || '').toLowerCase().includes(ql) ||
    (r.roll_no || '').toLowerCase().includes(ql)
  );
}

function renderRegsList(regs) {
  const list = document.getElementById('regs-list');
  if (!list) return;

  if (!regs.length) {
    list.innerHTML = `
      <div class="state-box" style="padding:40px 20px">
        <div class="state-icon">${_searchQuery ? '🔍' : '📭'}</div>
        <div class="state-title">${_searchQuery ? 'No matches' : 'No registrations yet'}</div>
        <div class="state-sub">${_searchQuery ? 'Try a different search' : 'Registrations will appear here once people sign up'}</div>
      </div>`;
    return;
  }

  // Group: checked-in first (sorted by check-in time desc), then pending (sorted by created_at desc)
  const present = regs.filter(r => r.checked_in).sort((a, b) => new Date(b.checked_in_at) - new Date(a.checked_in_at));
  const pending = regs.filter(r => !r.checked_in).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const grouped = [...present, ...pending];

  list.innerHTML = grouped.map((r, i) => {
    const isFirst = i === 0;
    const isLast  = i === grouped.length - 1;
    const borderRadius = isFirst && isLast ? 'var(--radius-md)'
      : isFirst ? 'var(--radius-md) var(--radius-md) 0 0'
      : isLast  ? '0 0 var(--radius-md) var(--radius-md)'
      : '0';
    return `
    <div class="reg-item" style="border-radius:${borderRadius}" onclick="openRegDetail(${r.id})">
      <div class="reg-status-dot ${r.checked_in ? 'present' : ''}"></div>
      <div class="reg-info">
        <div class="reg-name">${esc(r.name)}</div>
        <div class="reg-email">${esc(r.email)}${r.roll_no ? ' · ' + esc(r.roll_no) : ''}</div>
      </div>
      <div class="reg-time ${r.checked_in ? 'present' : ''}">
        ${r.checked_in
          ? (r.checked_in_at ? new Date(r.checked_in_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : '✓')
          : (r.created_at ? new Date(r.created_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : '')
        }
      </div>
    </div>`;
  }).join('');
}

function openRegDetail(id) {
  const r     = _allRegs.find(x => x.id === id);
  if (!r) return;
  const evId  = document.getElementById('data-event-select').value;

  const fields = [
    r.roll_no ? `<div class="sfield"><span class="sfield-label">Roll No</span><span class="sfield-value">${esc(r.roll_no)}</span></div>` : '',
    r.phone   ? `<div class="sfield"><span class="sfield-label">Phone</span><span class="sfield-value">${esc(r.phone)}</span></div>` : '',
    `<div class="sfield">
      <span class="sfield-label">Status</span>
      <span class="sfield-value">
        ${r.checked_in
          ? `<span class="badge badge-green">✓ Checked in</span>`
          : `<span class="badge badge-grey">Pending</span>`}
      </span>
    </div>`,
    r.checked_in && r.checked_in_at ? `<div class="sfield"><span class="sfield-label">Check-in</span><span class="sfield-value">${new Date(r.checked_in_at).toLocaleString('en-IN', { timeZone:'Asia/Kolkata' })}</span></div>` : '',
    r.checked_in && r.checked_in_by ? `<div class="sfield"><span class="sfield-label">Scanned by</span><span class="sfield-value" style="color:var(--label-secondary)">${esc(r.checked_in_by)}</span></div>` : '',
    `<div class="sfield"><span class="sfield-label">Registered</span><span class="sfield-value">${new Date(r.created_at).toLocaleString('en-IN', { timeZone:'Asia/Kolkata' })}</span></div>`,
  ].filter(Boolean).join('');

  document.getElementById('modal-content').innerHTML = `
    <div class="sheet-name">${esc(r.name)}</div>
    <div class="sheet-email">${esc(r.email)}</div>
    <div class="sheet-fields">${fields}</div>
    <div class="sheet-actions">
      <button class="btn btn-danger" style="width:auto" onclick="deleteReg(${r.id}, '${evId}')">Delete</button>
      <button class="btn btn-ghost" onclick="closeModal()">Close</button>
    </div>
  `;
  document.getElementById('modal-overlay').classList.add('visible');
}

async function deleteReg(id, eventId) {
  if (!confirm('Delete this registration? This cannot be undone.')) return;
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
  try {
    const r = await fetch(`/api/admin/events/${eventId}/registrations/export`, {
      headers: {
        'Authorization': `Bearer ${_token}`,
        'x-csrf-token': _csrfToken || '',
      },
    });
    if (!r.ok) { toast('Export failed'); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `kfs-registrations-event-${eventId}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
    log('export', `event_id=${eventId} downloaded`);
  } catch (e) {
    err('export', e.message);
    toast('Export failed — check connection');
  }
}

// ── UTILS ─────────────────────────────────────────────────────────────────────
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
  void document.body.offsetWidth;
  document.body.classList.add(`flash-${color}`);
  setTimeout(() => document.body.classList.remove(`flash-${color}`), 600);
}

function vibrateDevice(pattern) {
  if (navigator.vibrate) navigator.vibrate(pattern);
}

// ── AUTO-LOGIN (cookie session) ───────────────────────────────────────────────
(async function autoLogin() {
  if (!document.cookie.split(';').some(c => c.trim().startsWith('kfs_session='))) return;
  log('autologin', 'session cookie found, refreshing token...');
  try {
    const r = await fetch('/api/admin/refresh', {
      method: 'POST', credentials: 'include',
      headers: { 'x-csrf-token': _csrfToken || '' },
    });
    if (!r.ok) { log('autologin', `refresh failed: ${r.status}`); return; }
    const d = await r.json();
    if (!d.token) { log('autologin', 'no token in response'); return; }
    const perms = d.permissions || [];
    if (d.role !== 'master' && !perms.includes('events')) {
      log('autologin', 'insufficient permissions');
      return;
    }
    _token     = d.token;
    _adminName = d.name;
    _adminRole = d.role;
    log('autologin', `✓ auto-logged in as ${_adminName}`);
    await bootApp();
  } catch (e) {
    warn('autologin', 'exception:', e.message);
  }
})();

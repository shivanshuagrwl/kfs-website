// ═══════════════════════════════════════════════════════════════════════════════
// KFS Member Portal — membersaccess.js
// All logic extracted from inline <script>. No onclick= in HTML.
// Wired via addEventListener inside DOMContentLoaded.
// ═══════════════════════════════════════════════════════════════════════════════

const API = '';  // same-origin
let _token      = null;
let _member     = null;
let _csrfToken  = null;

// ── Helpers ───────────────────────────────────────────────────────────────────

function $id(id) { return document.getElementById(id); }
function showEl(id) { const el = $id(id); if (el) el.style.display = ''; }
function hideEl(id) { const el = $id(id); if (el) el.style.display = 'none'; }
function setText(id, txt) { const el = $id(id); if (el) el.textContent = txt; }
function showMsg(id, msg, ok = true) {
  const el = $id(id); if (!el) return;
  el.textContent = msg;
  el.className = ok ? 'ok-msg' : 'err-msg';
  el.style.display = 'block';
  if (ok) setTimeout(() => { el.style.display = 'none'; }, 4000);
}

async function getCsrf() {
  if (_csrfToken) return _csrfToken;
  const r = await fetch('/api/csrf-token', { credentials: 'include' });
  const d = await r.json();
  _csrfToken = d.csrf_token;
  return _csrfToken;
}

async function api(method, path, body, isForm = false) {
  const headers = {};
  if (_token) headers['Authorization'] = `Bearer ${_token}`;
  if (!isForm) headers['Content-Type'] = 'application/json';
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
    headers['x-csrf-token'] = await getCsrf();
  }
  const opts = { method, headers, credentials: 'include' };
  if (body) opts.body = isForm ? body : JSON.stringify(body);
  const r = await fetch(API + path, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Request failed');
  return d;
}

async function refreshToken() {
  try {
    const csrf = await getCsrf();
    const r = await fetch('/api/member/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'x-csrf-token': csrf },
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.token) {
      _token = d.token;
      localStorage.setItem('kfs-member-token', d.token);
      if (d.member) {
        _member = d.member;
        localStorage.setItem('kfs-member-data', JSON.stringify(d.member));
        window._member = d.member;
      }
      return true;
    }
    return false;
  } catch { return false; }
}

function relTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

// ── Social URL helpers ────────────────────────────────────────────────────────

/**
 * Validate a URL is safe (http/https only, no javascript:, data: etc.)
 * Returns cleaned URL string or empty string if invalid.
 */
function sanitizeSocialUrl(raw) {
  if (!raw) return '';
  const val = raw.trim();
  if (!val) return '';
  try {
    const u = new URL(val);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
    return u.href;
  } catch {
    return '';
  }
}

/**
 * Validate a bare username (no spaces, no special chars other than . - _)
 * Returns sanitized username or empty string.
 */
function sanitizeUsername(raw) {
  if (!raw) return '';
  // Strip leading @ if present, remove whitespace, allow only safe chars
  return raw.trim().replace(/^@+/, '').replace(/[^\w.\-]/g, '').slice(0, 100);
}

/**
 * Validate all social fields. Returns { valid: bool, errors: string[] }.
 */
function validateSocialLinks(fields) {
  const errors = [];
  const urlFields = ['linkedin', 'youtube', 'website'];
  urlFields.forEach(k => {
    const v = fields[k];
    if (v && sanitizeSocialUrl(v) === '') {
      errors.push(`${k.charAt(0).toUpperCase() + k.slice(1)} must be a valid https:// URL.`);
    }
  });
  return { valid: errors.length === 0, errors };
}

let _portalMembers = null;

async function loadPortalMembers() {
  if (_portalMembers) return _portalMembers;
  try {
    const r = await fetch('/api/members');
    if (r.ok) _portalMembers = await r.json();
  } catch {}
  return _portalMembers || [];
}

function splitCrew(str) {
  if (!str) return [];
  // Support both ";;" and "," separators
  const sep = str.includes(';;') ? ';;' : ',';
  return str.split(sep).map(s => s.trim()).filter(Boolean);
}

// ── Member Picker (portal) ────────────────────────────────────────────────────

class MemberPortalPicker {
  constructor(containerId, multi = false) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;
    this.multi = multi;
    this.selected = [];
    this._render();
  }
  _render() {
    this.container.innerHTML = `
      <div style="position:relative">
        <input class="portal-mpicker-input" placeholder="Type name or search members…" autocomplete="off" />
        <div class="portal-mpicker-dropdown" style="display:none"></div>
      </div>
      <div class="portal-mpicker-tags"></div>`;
    this._input    = this.container.querySelector('.portal-mpicker-input');
    this._dd       = this.container.querySelector('.portal-mpicker-dropdown');
    this._tagsEl   = this.container.querySelector('.portal-mpicker-tags');
    this._input.addEventListener('input',   () => this._onInput());
    this._input.addEventListener('keydown', e => {
      if (e.key === 'Enter')  { e.preventDefault(); this._addFreeText(); }
      if (e.key === 'Escape') this._hideDd();
    });
    this._input.addEventListener('blur', () => setTimeout(() => this._hideDd(), 150));
    this._renderTags();
  }
  _onInput() {
    const q = this._input.value.trim().toLowerCase();
    if (!q) { this._hideDd(); return; }
    const members = _portalMembers || [];
    const matches = members.filter(m => m.name.toLowerCase().includes(q)).slice(0, 8);
    if (!matches.length) { this._hideDd(); return; }
    this._dd.innerHTML = matches.map(m => `
      <div class="portal-mpicker-opt" data-id="${m.id}">
        ${m.photo
          ? `<img src="${m.photo}" alt="" />`
          : `<div class="portal-mpicker-avatar">${(m.name || '?')[0].toUpperCase()}</div>`}
        <span class="portal-mpicker-opt-name">${m.name}</span>
        <span class="portal-mpicker-opt-role">${m.role || ''}</span>
      </div>`).join('');
    this._dd.querySelectorAll('.portal-mpicker-opt').forEach(el => {
      el.addEventListener('mousedown', e => {
        e.preventDefault();
        const m = members.find(x => String(x.id) === el.dataset.id);
        if (m) this._select({ id: m.id, name: m.name, photo: m.photo, role: m.role });
      });
    });
    this._dd.style.display = 'block';
  }
  _addFreeText() {
    const v = this._input.value.trim();
    if (!v) return;
    this._select({ id: null, name: v, photo: null, role: '' });
  }
  _select(item) {
    if (!this.multi) this.selected = [];
    if (!this.selected.find(s => s.name === item.name)) this.selected.push(item);
    this._input.value = '';
    this._hideDd();
    this._renderTags();
  }
  _remove(name) {
    this.selected = this.selected.filter(s => s.name !== name);
    this._renderTags();
  }
  _renderTags() {
    if (!this._tagsEl) return;
    this._tagsEl.innerHTML = this.selected.map(s => `
      <span class="portal-mpicker-tag">
        ${s.photo
          ? `<img src="${s.photo}" alt="" />`
          : `<span class="portal-mpicker-tag-avatar">${(s.name || '?')[0].toUpperCase()}</span>`}
        <span>${s.name}</span>
        <span class="portal-mpicker-tag-remove" data-name="${s.name}">×</span>
      </span>`).join('');
    this._tagsEl.querySelectorAll('.portal-mpicker-tag-remove').forEach(el => {
      el.addEventListener('click', () => this._remove(el.dataset.name));
    });
  }
  _hideDd() { if (this._dd) this._dd.style.display = 'none'; }
  getValue() {
    return this.selected.map(s => s.id ? `${s.name}||${s.id}` : s.name).join(';;');
  }
  setValue(str) {
    this.selected = [];
    if (!str) { this._renderTags(); return; }
    splitCrew(str).forEach(part => {
      const pipes = part.split('||');
      const name  = pipes[0].trim();
      const id    = pipes[1] ? pipes[1].trim() : null;
      const member = id && _portalMembers ? _portalMembers.find(m => String(m.id) === id) : null;
      this.selected.push(member
        ? { id: member.id, name: member.name, photo: member.photo, role: member.role }
        : { id: null, name, photo: null, role: '' });
    });
    this._renderTags();
  }
}

let _formPickers = {};

function initMovieFormPickers() {
  const pickerFields = ['director','producer','dop','writer','editor','sound','management','gd','actors','support'];
  pickerFields.forEach(f => {
    _formPickers[f] = new MemberPortalPicker(`mfpick-${f}`, true);
  });
}

// ── Genre tag-input helpers ───────────────────────────────────────────────────

function renderMfGenreTags(tags) {
  const wrap  = $id('mf-genre-wrap');
  const input = $id('mf-genre-input');
  if (!wrap || !input) return;
  wrap.querySelectorAll('.mf-tag-chip').forEach(c => c.remove());
  tags.forEach((tag, i) => {
    const chip = document.createElement('span');
    chip.className = 'mf-tag-chip';
    chip.innerHTML = `${tag}<button type="button" aria-label="Remove ${tag}">×</button>`;
    chip.querySelector('button').addEventListener('click', () => {
      const cur = JSON.parse($id('mf-genre').value || '[]');
      cur.splice(i, 1);
      $id('mf-genre').value = JSON.stringify(cur);
      renderMfGenreTags(cur);
    });
    wrap.insertBefore(chip, input);
  });
}

function addMfGenreTag(raw) {
  raw.split(/[,،]+/).map(s => s.trim()).filter(Boolean).forEach(tag => {
    const cur = JSON.parse($id('mf-genre').value || '[]');
    if (!cur.includes(tag)) { cur.push(tag); $id('mf-genre').value = JSON.stringify(cur); renderMfGenreTags(cur); }
  });
}

function initMfGenreInput() {
  const wrap  = $id('mf-genre-wrap');
  const input = $id('mf-genre-input');
  if (!wrap || !input) return;
  wrap.addEventListener('click', () => input.focus());
  input.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
      e.preventDefault(); addMfGenreTag(input.value); input.value = '';
    } else if (e.key === 'Backspace' && !input.value) {
      const cur = JSON.parse($id('mf-genre').value || '[]');
      if (cur.length) { cur.pop(); $id('mf-genre').value = JSON.stringify(cur); renderMfGenreTags(cur); }
    }
  });
  input.addEventListener('blur', () => { if (input.value.trim()) { addMfGenreTag(input.value); input.value = ''; } });
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  wireStaticButtons();

  // Try to restore session via refresh token cookie
  if (document.cookie.includes('kfs_member_session=1')) {
    const ok = await refreshToken();
    if (ok) { await loadDashboard(); return; }
  }
  showLoginScreen();
});

// ── Wire all static HTML buttons via addEventListener ─────────────────────────

function wireStaticButtons() {
  // Auth flow
  on('login-btn',         'click', handleLogin);
  on('totp-btn',          'click', submitTotp);
  on('back-to-login-btn', 'click', backToLogin);
  on('cp-btn',            'click', handleChangePw);
  on('setup-totp-btn',    'click', verify2FASetup);

  // Logout buttons
  on('mobile-logout-btn', 'click', logoutMember);
  on('sidebar-logout-btn','click', logoutMember);

  // Nav items — delegate on both nav containers
  document.querySelectorAll('[data-panel]').forEach(el => {
    el.addEventListener('click', () => switchPanel(el));
  });

  // Profile
  on('profile-photo-input', 'change', function() { previewPhoto(this); });
  on('profile-save-btn',    'click',  saveProfile);

  // Movies
  on('new-movie-btn',    'click', () => showMovieForm(null));
  on('movie-submit-btn', 'click', submitMovie);
  on('cancel-movie-btn', 'click', hideMovieForm);

  // Security
  on('sec-change-pw-btn',  'click', changePasswordFromSecurity);
  on('revoke-sessions-btn','click', revokeAllSessions);

  // Collab
  on('new-collab-btn',    'click', showCollabForm);
  on('cancel-collab-btn', 'click', hideCollabForm);
  on('collab-submit-btn', 'click', submitCollab);
  const cfDesc = $id('cf-description');
  if (cfDesc) cfDesc.addEventListener('input', () => { const cnt = $id('cf-desc-count'); if(cnt) cnt.textContent = cfDesc.value.length; });

  // Collab edit modal
  on('collab-edit-submit-btn', 'click', submitCollabEdit);
  on('collab-edit-cancel-btn', 'click', closeCollabEditModal);
  const ceDesc = $id('ce-description');
  if (ceDesc) ceDesc.addEventListener('input', () => { const cnt = $id('ce-desc-count'); if(cnt) cnt.textContent = ceDesc.value.length; });
  const editOverlay = $id('collab-edit-modal-overlay');
  if (editOverlay) editOverlay.addEventListener('click', e => { if (e.target === editOverlay) closeCollabEditModal(); });


  // Work edit modal
  on('work-edit-submit-btn', 'click', submitWorkEditRequest);
  on('work-edit-cancel-btn', 'click', closeWorkEditModal);
  const overlay = $id('work-edit-modal-overlay');
  if (overlay) overlay.addEventListener('click', e => { if (e.target === overlay) closeWorkEditModal(); });

  // Enter key support
  document.addEventListener('keydown', handleEnterKey);
}

function on(id, evt, fn) {
  const el = $id(id);
  if (el) el.addEventListener(evt, fn);
}

// ── Auth screen ───────────────────────────────────────────────────────────────

function showLoginScreen() {
  $id('auth-screen').style.display = 'flex';
  $id('app-screen').style.display  = 'none';
  showStep('login');
  const u = $id('login-username'); if (u) u.value = '';
  const p = $id('login-password'); if (p) p.value = '';
  hideEl('login-err');
  _csrfToken = null; // force fresh CSRF on next login attempt
}

async function loadDashboard() {
  $id('auth-screen').style.display = 'none';
  $id('app-screen').style.display  = 'flex';
  loadPortalMembers(); // preload for pickers (non-blocking)
  await loadProfile();
  loadMovies();
  loadSecurity();
  loadActivity();
  loadMyWorks();
  // Hash routing: /membersaccess#collab opens collab panel directly
  const hash = window.location.hash.replace('#', '');
  if (hash && document.querySelector(`[data-panel="${hash}"]`)) {
    switchPanel(document.querySelector(`[data-panel="${hash}"]`));
  }
  // Clear hash after use so back-navigation stays clean
  if (hash) history.replaceState(null, '', window.location.pathname);
}

// ── Login ─────────────────────────────────────────────────────────────────────

let _pendingUsername = null, _pendingPassword = null;

async function handleLogin() {
  const username = $id('login-username').value.trim();
  const password = $id('login-password').value;
  if (!username || !password) {
    showMsg('login-err', 'Username and password required', false);
    return;
  }
  const btn = $id('login-btn');
  btn.disabled = true; btn.textContent = 'Signing in…';
  hideEl('login-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username, password }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('login-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('login-err', d.error || 'Login failed', false); return; }

    if (d.require_totp) {
      _pendingUsername = username;
      _pendingPassword = password;
      showStep('totp');
      return;
    }
    _token  = d.token;
    _member = d.member;
    // Persist token + member data so index.html collab gate can read them
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;

    if (d.must_change_password) { showStep('change-pw'); return; }
    if (!d.totp_enabled) {
      btn.textContent = 'Setting up 2FA…';
      await initiate2FASetup();
      return;
    }
    await loadDashboard();
  } catch (e) {
    showMsg('login-err', e.message || 'Could not connect to server', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

async function submitTotp() {
  const code = $id('totp-input').value.trim();
  if (!code) return;
  const btn = $id('totp-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _pendingUsername, password: _pendingPassword, totp_code: code }),
      credentials: 'include',
    });
    const d = await r.json();
    if (!r.ok) { showMsg('totp-err', d.error || 'Invalid code', false); return; }
    _token  = d.token;
    _member = d.member;
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;
    if (d.must_change_password) { showStep('change-pw'); return; }
    await loadDashboard();
  } catch (e) {
    showMsg('totp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
}

function backToLogin() { showStep('login'); }

function showStep(step) {
  ['login', 'totp', 'change-pw', '2fa-setup'].forEach(s => {
    const el = $id(`step-${s}`);
    if (el) el.style.display = s === step ? 'block' : 'none';
  });
}

// ── Change Password (forced) ──────────────────────────────────────────────────

async function handleChangePw() {
  const cur = $id('cp-current').value;
  const nw  = $id('cp-new').value;
  const cf  = $id('cp-confirm').value;
  if (nw !== cf) { showMsg('cp-err', 'Passwords do not match', false); return; }
  const btn = $id('cp-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('POST', '/api/member/change-password', { currentPassword: cur, newPassword: nw });
    await refreshToken();
    await initiate2FASetup();
  } catch (e) {
    showMsg('cp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Set Password';
  }
}

// ── 2FA Setup (forced) ───────────────────────────────────────────────────────

async function initiate2FASetup() {
  showStep('2fa-setup');
  $id('qr-box').innerHTML = '<div class="spinner"></div>';
  try {
    const d = await api('GET', '/api/member/2fa/setup');
    $id('qr-box').innerHTML = `
      <img src="${d.qr}" width="180" height="180" alt="QR Code" />
      <div class="qr-secret">Manual entry: <strong>${d.secret}</strong></div>
    `;
  } catch (e) {
    $id('qr-box').innerHTML = `<span style="color:var(--danger)">Failed to load QR: ${e.message}</span>`;
  }
}

async function verify2FASetup() {
  const code = $id('setup-totp-input').value.trim();
  if (!code) return;
  const btn = $id('setup-totp-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    await api('POST', '/api/member/2fa/verify', { totp_code: code });
    await refreshToken();
    await loadDashboard();
  } catch (e) {
    showMsg('setup-totp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Enable 2FA & Continue';
  }
}

// ── Logout ────────────────────────────────────────────────────────────────────

async function logoutMember() {
  try { await api('POST', '/api/member/logout'); } catch (_) {}
  _token = null; _member = null; _csrfToken = null;
  localStorage.removeItem('kfs-member-token');
  localStorage.removeItem('kfs-member-data');
  localStorage.removeItem('kfs-member-profile');
  window._member = null;
  window._memberProfile = null;
  showLoginScreen();
}

// ── Panel switching ───────────────────────────────────────────────────────────

function switchPanel(el) {
  const panel = el.dataset.panel;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll(`.nav-item[data-panel="${panel}"]`).forEach(n => n.classList.add('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $id('panel-' + panel)?.classList.add('active');
  if (panel === 'security') loadSecurity();
  if (panel === 'activity') loadActivity();
  if (panel === 'movies')   loadMovies();
  if (panel === 'works')    loadMyWorks();
  if (panel === 'collab')   loadMyCollabs();
}

// ── Profile ───────────────────────────────────────────────────────────────────

async function loadProfile() {
  try {
    const d = await api('GET', '/api/member/profile');
    const changes  = await api('GET', '/api/member/profile/pending-changes');
    const pending  = changes.some(c => c.status === 'pending');
    $id('profile-pending-banner').style.display = pending ? 'block' : 'none';

    let displayData = { ...d };
    if (pending) {
      const latestPending = changes.find(c => c.status === 'pending');
      if (latestPending && latestPending.new_values) displayData = { ...d, ...latestPending.new_values };
    }

    window._memberProfile = d; // cache raw profile globally for collab + notifications
    // Persist profile to localStorage so index.html collab gate can read it cross-tab
    localStorage.setItem('kfs-member-profile', JSON.stringify(d));
    // Ensure email/mobile are available on window._member for collab gate
    if (!window._member) window._member = {};
    if (d.email)  window._member.email  = d.email;
    if (d.mobile) window._member.mobile = d.mobile;
    if (d.name)   window._member.name   = d.name;
    fillProfile(displayData);
    setText('sidebar-name', displayData.name || '—');
    setText('sidebar-role', displayData.role || displayData.domain || '—');
    const av = $id('sidebar-avatar');
    if (displayData.photo) {
      av.innerHTML = `<img src="${displayData.photo}" style="width:32px;height:32px;border-radius:50%;object-fit:cover" />`;
    } else {
      av.textContent = (displayData.name || '?')[0].toUpperCase();
    }
  } catch (e) {
    console.error('loadProfile:', e);
  }
}

function fillProfile(d) {
  const fields = ['name','roll_no','mobile','email','batch','domain','role','bio','instagram','linkedin','github','twitter','youtube','website'];
  const ids    = ['pf-name','pf-roll','pf-mobile','pf-email','pf-batch','pf-domain','pf-role','pf-bio','pf-instagram','pf-linkedin','pf-github','pf-twitter','pf-youtube','pf-website'];
  fields.forEach((f, i) => {
    const el = $id(ids[i]); if (el) el.value = d[f] || '';
  });
  const ph = $id('profile-photo-preview');
  if (d.photo) {
    ph.innerHTML = `<img src="${d.photo}" style="width:80px;height:80px;border-radius:50%;object-fit:cover" />`;
  } else {
    ph.textContent = (d.name || '?')[0].toUpperCase();
    Object.assign(ph.style, { fontSize:'28px', display:'flex', alignItems:'center', justifyContent:'center',
      width:'80px', height:'80px', borderRadius:'50%', background:'var(--faint)' });
  }
}

function previewPhoto(input) {
  if (!input.files[0]) return;
  const url = URL.createObjectURL(input.files[0]);
  $id('profile-photo-preview').innerHTML = `<img src="${url}" style="width:80px;height:80px;border-radius:50%;object-fit:cover" />`;
}

async function saveProfile() {
  const btn = $id('profile-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  hideEl('profile-msg'); hideEl('profile-err'); hideEl('social-link-err');

  // Client-side social URL validation
  const rawLinkedin = $id('pf-linkedin').value.trim();
  const rawYoutube  = $id('pf-youtube').value.trim();
  const rawWebsite  = $id('pf-website').value.trim();
  const socialValidation = validateSocialLinks({ linkedin: rawLinkedin, youtube: rawYoutube, website: rawWebsite });
  if (!socialValidation.valid) {
    const errEl = $id('social-link-err');
    if (errEl) { errEl.textContent = socialValidation.errors.join(' '); errEl.style.display = 'block'; }
    btn.disabled = false; btn.textContent = 'Save Changes';
    return;
  }

  try {
    const form = new FormData();
    // NOTE: domain and role are admin-only — intentionally not sent.
    const fields = {
      name:      $id('pf-name').value,
      roll_no:   $id('pf-roll').value,
      mobile:    $id('pf-mobile').value,
      batch:     $id('pf-batch').value,
      bio:       $id('pf-bio').value,
      instagram: sanitizeUsername($id('pf-instagram').value),
      linkedin:  sanitizeSocialUrl(rawLinkedin),
      github:    sanitizeUsername($id('pf-github').value),
      twitter:   sanitizeUsername($id('pf-twitter').value),
      youtube:   sanitizeSocialUrl(rawYoutube),
      website:   sanitizeSocialUrl(rawWebsite),
    };
    Object.entries(fields).forEach(([k, v]) => form.append(k, v));
    const photoFile = $id('profile-photo-input').files[0];
    if (photoFile) form.append('photo', photoFile);

    const csrf = await getCsrf();
    const r = await fetch('/api/member/profile', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${_token}`, 'x-csrf-token': csrf },
      credentials: 'include',
      body: form,
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Failed to save');
    showMsg('profile-msg', d.pending ? 'Update submitted — pending admin review.' : 'Profile saved!');
    await loadProfile();
  } catch (e) {
    showMsg('profile-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Changes';
  }
}

// ── Movies ────────────────────────────────────────────────────────────────────

async function loadMovies() {
  try {
    const subs = await api('GET', '/api/member/movies');
    const list = $id('movies-list');
    if (!subs.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No submissions yet. Click "Submit Movie" to get started.</div>';
      return;
    }
    list.innerHTML = subs.map(s => {
      const md = s.movie_data;
      const statusBadge = { pending:'badge-pending', approved:'badge-approved', rejected:'badge-rejected' }[s.status] || 'badge-changes';
      const statusLabel = s.status === 'changes_requested' ? 'Changes Requested' : s.status.charAt(0).toUpperCase() + s.status.slice(1);
      const notes   = s.reviewer_notes ? `<div class="movie-notes"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:5px;flex-shrink:0"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>Admin feedback: ${s.reviewer_notes}</div>` : '';
      const editBtn = ['pending','changes_requested'].includes(s.status)
        ? `<button class="btn-sm movie-edit-btn" style="margin-top:10px;background:#1a1a1a;border:1px solid var(--border);color:var(--muted);border-radius:6px;font-size:12px" data-id="${s.id}">Edit</button>` : '';
      const poster  = md.poster_image
        ? `<img class="movie-poster" src="${md.poster_image}" />`
        : `<div class="movie-poster" style="display:flex;align-items:center;justify-content:center"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg></div>`;
      return `
        <div class="movie-card">
          ${poster}
          <div class="movie-info">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
              <div class="movie-title">${md.title || 'Untitled'}</div>
              <span class="badge ${statusBadge}">${statusLabel}</span>
            </div>
            <div class="movie-meta">${md.language || ''} ${md.genre ? '· ' + (Array.isArray(md.genre) ? md.genre.join(', ') : md.genre) : ''} ${md.runtime ? '· ' + md.runtime + ' min' : ''}</div>
            <div class="movie-meta" style="margin-top:4px">Submitted ${relTime(s.created_at)}</div>
            ${notes}${editBtn}
          </div>
        </div>`;
    }).join('');

    // Wire edit buttons (dynamically generated, so addEventListener here)
    list.querySelectorAll('.movie-edit-btn').forEach(btn => {
      btn.addEventListener('click', () => showMovieForm(btn.dataset.id));
    });
  } catch (e) {
    console.error('loadMovies:', e);
  }
}

async function showMovieForm(id) {
  hideEl('movie-form-err'); hideEl('movie-form-ok');
  $id('movie-edit-id').value = id || '';
  $id('movie-form-title').textContent = id ? 'Edit Submission' : 'New Submission';
  $id('movie-submit-btn').textContent = id ? 'Update Submission' : 'Submit for Review';

  // Ensure members are loaded before init pickers
  await loadPortalMembers();
  initMovieFormPickers();
  initMfGenreInput();

  if (id) {
    try {
      const subs = await api('GET', '/api/member/movies');
      const sub  = subs.find(s => String(s.id) === String(id));
      if (sub) {
        const md = sub.movie_data;
        $id('mf-title').value       = md.title || '';
        $id('mf-desc').value        = md.description || '';
        $id('mf-trailer').value     = md.trailer_url || '';
        $id('mf-watch').value       = md.watch_url || '';
        $id('mf-runtime').value     = md.runtime || '';
        $id('mf-language').value    = md.language || '';
        $id('mf-year').value        = md.release_year || '';
        $id('mf-spotify').value     = md.spotify_url || '';
        $id('mf-apple-music').value = md.apple_music_url || '';
        // Genre tags
        const genres = Array.isArray(md.genre) ? md.genre : (md.genre ? String(md.genre).split(',').map(s=>s.trim()).filter(Boolean) : []);
        $id('mf-genre').value = JSON.stringify(genres);
        renderMfGenreTags(genres);
        // Fill pickers
        _formPickers['director']?.setValue(md.director || '');
        _formPickers['producer']?.setValue(md.producer || '');
        _formPickers['dop']?.setValue(md.dop || '');
        _formPickers['writer']?.setValue(md.writer || '');
        _formPickers['editor']?.setValue(md.video_editor || '');
        _formPickers['sound']?.setValue(md.sound_design || '');
        _formPickers['management']?.setValue(md.management || '');
        _formPickers['gd']?.setValue(md.graphic_design || '');
        _formPickers['actors']?.setValue(md.actors || '');
        _formPickers['support']?.setValue(md.support_crew || '');
      }
    } catch (_) {}
  } else {
    ['mf-title','mf-desc','mf-trailer','mf-watch','mf-runtime','mf-language','mf-year','mf-spotify','mf-apple-music']
      .forEach(fid => { const el = $id(fid); if (el) el.value = ''; });
    $id('mf-genre').value = '[]';
    renderMfGenreTags([]);
    // Clear all pickers
    Object.values(_formPickers).forEach(p => { if (p) { p.selected = []; p._renderTags?.(); } });
  }

  $id('movie-form').style.display    = 'block';
  $id('new-movie-btn').style.display = 'none';
  $id('movie-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideMovieForm() {
  $id('movie-form').style.display    = 'none';
  $id('new-movie-btn').style.display = '';
}

async function submitMovie() {
  const editId = $id('movie-edit-id').value;
  const btn    = $id('movie-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('movie-form-err'); hideEl('movie-form-ok');
  try {
    const form       = new FormData();
    const genreRaw   = JSON.parse($id('mf-genre').value || '[]');
    form.append('title',           $id('mf-title').value);
    form.append('release_year',    $id('mf-year').value);
    form.append('description',     $id('mf-desc').value);
    form.append('trailer_url',     $id('mf-trailer').value);
    form.append('watch_url',       $id('mf-watch').value);
    form.append('runtime',         $id('mf-runtime').value);
    form.append('language',        $id('mf-language').value);
    form.append('genre',           JSON.stringify(genreRaw));
    form.append('spotify_url',     $id('mf-spotify').value);
    form.append('apple_music_url', $id('mf-apple-music').value);
    form.append('director',        _formPickers['director']?.getValue()    || '');
    form.append('producer',        _formPickers['producer']?.getValue()    || '');
    form.append('dop',             _formPickers['dop']?.getValue()         || '');
    form.append('writer',          _formPickers['writer']?.getValue()      || '');
    form.append('video_editor',    _formPickers['editor']?.getValue()      || '');
    form.append('sound_design',    _formPickers['sound']?.getValue()       || '');
    form.append('management',      _formPickers['management']?.getValue()  || '');
    form.append('graphic_design',  _formPickers['gd']?.getValue()          || '');
    form.append('actors',          _formPickers['actors']?.getValue()      || '');
    form.append('support_crew',    _formPickers['support']?.getValue()     || '');
    const posterFile = $id('mf-poster').files[0];
    if (posterFile) form.append('poster', posterFile);

    const csrf     = await getCsrf();
    const method   = editId ? 'PUT' : 'POST';
    const endpoint = editId ? `/api/member/movies/${editId}` : '/api/member/movies';
    const r = await fetch(endpoint, {
      method,
      headers: { Authorization: `Bearer ${_token}`, 'x-csrf-token': csrf },
      credentials: 'include',
      body: form,
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Submission failed');
    showMsg('movie-form-ok', editId ? 'Submission updated!' : 'Movie submitted for review!');
    setTimeout(() => { hideMovieForm(); loadMovies(); }, 1500);
  } catch (e) {
    showMsg('movie-form-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = editId ? 'Update Submission' : 'Submit for Review';
  }
}

// ── Security ──────────────────────────────────────────────────────────────────

async function loadSecurity() {
  loadSessions();
  load2FAStatus();
}

async function changePasswordFromSecurity() {
  const cur = $id('sec-cur-pw').value;
  const nw  = $id('sec-new-pw').value;
  const cf  = $id('sec-confirm-pw').value;
  if (nw !== cf) { showMsg('sec-pw-err', 'Passwords do not match', false); return; }
  try {
    await api('POST', '/api/member/change-password', { currentPassword: cur, newPassword: nw });
    showMsg('sec-pw-msg', 'Password updated successfully!');
    $id('sec-cur-pw').value = $id('sec-new-pw').value = $id('sec-confirm-pw').value = '';
  } catch (e) {
    showMsg('sec-pw-err', e.message, false);
  }
}

async function load2FAStatus() {
  const card = $id('twofa-status');
  if (!card || !_token) return;
  try {
    const payload = JSON.parse(atob(_token.split('.')[1]));
    if (payload.totp_enabled) {
      card.innerHTML = `
        <div style="font-size:13px;color:var(--success);margin-bottom:16px;display:flex;align-items:center;gap:6px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Two-factor authentication is enabled</div>
        <button class="btn-sm btn-danger" id="twofa-disable-toggle-btn">Disable 2FA</button>
        <div id="twofa-disable-form" style="display:none;margin-top:16px">
          <div class="form-group" style="max-width:280px">
            <label>Password</label><input id="twofa-dis-pw" type="password" />
          </div>
          <div class="form-group" style="max-width:200px">
            <label>TOTP Code</label><input id="twofa-dis-code" type="text" maxlength="6" />
          </div>
          <button class="btn-primary" id="twofa-disable-confirm-btn" style="max-width:160px">Confirm Disable</button>
          <div id="twofa-dis-err" class="err-msg" style="display:none"></div>
        </div>`;
      on('twofa-disable-toggle-btn', 'click', show2FADisable);
      on('twofa-disable-confirm-btn','click', disable2FA);
    } else {
      card.innerHTML = `
        <div style="font-size:13px;color:var(--muted);margin-bottom:16px">Two-factor authentication is not enabled</div>
        <button class="btn-primary" id="twofa-enable-btn" style="max-width:180px">Enable 2FA</button>
        <div id="twofa-setup-inline" style="display:none;margin-top:20px"></div>`;
      on('twofa-enable-btn', 'click', startSetup2FA);
    }
  } catch (_) {}
}

function show2FADisable() {
  const f = $id('twofa-disable-form');
  if (f) f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function disable2FA() {
  const pw   = $id('twofa-dis-pw').value;
  const code = $id('twofa-dis-code').value;
  try {
    await api('POST', '/api/member/2fa/disable', { password: pw, totp_code: code });
    await refreshToken();
    load2FAStatus();
  } catch (e) {
    showMsg('twofa-dis-err', e.message, false);
  }
}

async function startSetup2FA() {
  const container = $id('twofa-setup-inline');
  container.style.display = 'block';
  container.innerHTML = '<div class="spinner"></div>';
  try {
    const d = await api('GET', '/api/member/2fa/setup');
    container.innerHTML = `
      <div class="qr-box" style="padding:0;margin-bottom:16px">
        <img src="${d.qr}" width="160" height="160" alt="QR" style="border-radius:8px" />
        <div class="qr-secret">Manual: <strong>${d.secret}</strong></div>
      </div>
      <div class="form-group" style="max-width:200px">
        <label>Enter code to confirm</label>
        <input id="inline-totp" type="text" maxlength="6" inputmode="numeric" />
      </div>
      <button class="btn-primary" id="inline-totp-confirm-btn" style="max-width:160px">Activate 2FA</button>
      <div id="inline-totp-err" class="err-msg" style="display:none"></div>`;
    on('inline-totp-confirm-btn', 'click', confirmInline2FA);
  } catch (e) {
    container.innerHTML = `<span style="color:var(--danger)">${e.message}</span>`;
  }
}

async function confirmInline2FA() {
  const code = $id('inline-totp').value.trim();
  try {
    await api('POST', '/api/member/2fa/verify', { totp_code: code });
    await refreshToken();
    load2FAStatus();
  } catch (e) {
    showMsg('inline-totp-err', e.message, false);
  }
}

async function loadSessions() {
  const list = $id('sessions-list');
  try {
    const sessions = await api('GET', '/api/member/sessions');
    if (!sessions.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No active sessions</div>';
      return;
    }
    list.innerHTML = sessions.map(s => `
      <div class="session-item">
        <div>
          <div style="font-size:13px;font-weight:600">Session</div>
          <div style="font-size:11px;color:var(--muted)">Created ${relTime(s.created_at)} · Expires ${new Date(s.expires_at).toLocaleDateString()}</div>
        </div>
        <span class="badge badge-approved">Active</span>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

async function revokeAllSessions() {
  try {
    await api('DELETE', '/api/member/sessions/all');
    showMsg('sessions-msg', 'All sessions revoked. You will be signed out.');
    setTimeout(() => logoutMember(), 1500);
  } catch (e) {
    console.error(e);
  }
}

// ── My Works ──────────────────────────────────────────────────────────────────

let _pendingEditMovieId = null;
let _pendingEditMovieTitle = null;

async function loadMyWorks() {
  const list = $id('works-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  try {
    const works = await api('GET', '/api/member/works');
    if (!works.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No films found in the KFS filmography for your profile yet.</div>';
      return;
    }
    list.innerHTML = `
      <div class="works-grid">
        ${works.map(w => `
          <div class="work-card">
            <div class="work-poster">
              ${w.poster_image
                ? `<img src="${w.poster_image}" alt="${w.title}" />`
                : `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.3"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>`}
            </div>
            <div class="work-info">
              <div class="work-title" title="${w.title}">${w.title}</div>
              <div class="work-role">${w.role}</div>
              ${w.release_year ? `<div class="work-year">${w.release_year}</div>` : ''}
              <button class="btn-edit-request" data-movie-id="${w.id}" data-movie-title="${w.title.replace(/"/g,'&quot;')}"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>Request Edit</button>
            </div>
          </div>`).join('')}
      </div>`;

    list.querySelectorAll('.btn-edit-request').forEach(btn => {
      btn.addEventListener('click', () => openWorkEditModal(btn.dataset.movieId, btn.dataset.movieTitle));
    });
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

function openWorkEditModal(movieId, movieTitle) {
  _pendingEditMovieId    = movieId;
  _pendingEditMovieTitle = movieTitle;
  const overlay = $id('work-edit-modal-overlay');
  setText('work-edit-movie-name', movieTitle || 'this film');
  const desc = $id('work-edit-desc'); if (desc) desc.value = '';
  hideEl('work-edit-msg'); hideEl('work-edit-err');
  overlay.classList.add('open');
}

function closeWorkEditModal() {
  $id('work-edit-modal-overlay')?.classList.remove('open');
  _pendingEditMovieId = null; _pendingEditMovieTitle = null;
}

async function submitWorkEditRequest() {
  const desc = $id('work-edit-desc')?.value?.trim();
  if (!desc) { showMsg('work-edit-err', 'Please describe what needs to change', false); return; }
  const btn = $id('work-edit-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('work-edit-msg'); hideEl('work-edit-err');
  try {
    await api('POST', '/api/member/work-edit-request', {
      movie_id:    _pendingEditMovieId,
      movie_title: _pendingEditMovieTitle,
      description: desc,
    });
    showMsg('work-edit-msg', 'Edit request submitted! Admin will review it shortly.');
    setTimeout(() => closeWorkEditModal(), 2000);
  } catch (e) {
    showMsg('work-edit-err', e.message, false);
  } finally {
    btn.disabled = false; btn.textContent = 'Submit Request';
  }
}

// ── Activity ──────────────────────────────────────────────────────────────────

async function loadActivity() {
  const list = $id('activity-list');
  try {
    const items = await api('GET', '/api/member/activity?limit=30');
    if (!items.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No activity yet</div>';
      return;
    }
    const labelMap = {
      login:                    'Signed in',
      logout:                   'Signed out',
      password_change:          'Changed password',
      profile_update_requested: 'Profile update submitted',
      profile_updated:          'Profile updated',
      movie_submit:             'Movie submitted',
      movie_resubmit:           'Movie resubmitted',
      '2fa_setup':              '2FA enabled',
      '2fa_disable':            '2FA disabled',
      session_revoke_all:       'All sessions revoked',
      work_edit_requested:      'Work edit request submitted',
    };
    list.innerHTML = items.map(a => `
      <div class="activity-item">
        <div class="activity-dot"></div>
        <div>
          <div class="activity-text">${labelMap[a.action] || a.action}</div>
          <div class="activity-time">${relTime(a.created_at)} · IP: ${a.ip_address || 'unknown'}</div>
        </div>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ── Notifications (slide-in panel) ────────────────────────────────────────────

let _notifOpen = false;
let _notifLoading = false;

// Icon per notification type
function _notifIcon(type) {
  const icons = {
    movie_approved:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    movie_rejected:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    profile_change:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
    event:           `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
    announcement:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
    default:         `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  };
  return icons[type] || icons.default;
}

async function loadNotifications() {
  if (!_token || _notifLoading) return;
  _notifLoading = true;
  const list = $id('notif-list');
  if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-title" style="color:#333">Loading…</div></div>';
  try {
    const items = await api('GET', '/api/member/notifications');
    const unread = items.filter(n => !n.is_read);
    const badge = $id('notif-badge');
    if (badge) {
      badge.textContent = unread.length > 9 ? '9+' : unread.length;
      badge.classList.toggle('visible', unread.length > 0);
    }
    if (!list) return;
    if (!items.length) {
      list.innerHTML = `
        <div class="notif-empty">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          <div class="notif-empty-title">All caught up</div>
          <div class="notif-empty-sub">No new notifications</div>
        </div>`;
      return;
    }
    list.innerHTML = items.map(n => `
      <div class="notif-item ${n.is_read ? '' : 'unread'}" onclick="markNotifRead('${n.id}', this)">
        <div class="notif-icon-bubble">${_notifIcon(n.type)}</div>
        <div class="notif-item-content">
          <div class="notif-item-title">${n.title}</div>
          ${n.body ? `<div class="notif-item-body">${n.body}</div>` : ''}
          <div class="notif-item-time">${relTime(n.created_at)}</div>
        </div>
        <div class="notif-unread-pip ${n.is_read ? 'read' : ''}"></div>
      </div>`).join('');
  } catch(e) {
    if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-sub">Could not load notifications</div></div>';
  } finally { _notifLoading = false; }
}

function toggleNotifPanel() {
  _notifOpen ? closeNotifPanel() : openNotifPanel();
}

function openNotifPanel() {
  _notifOpen = true;
  const panel    = $id('notif-panel');
  const backdrop = $id('notif-panel-backdrop');
  const btn      = $id('notif-bell-btn');
  if (panel)    { panel.classList.add('open'); }
  if (backdrop) { backdrop.classList.add('open'); }
  if (btn)      { btn.classList.add('active'); }
  loadNotifications();
}

function closeNotifPanel() {
  _notifOpen = false;
  const panel    = $id('notif-panel');
  const backdrop = $id('notif-panel-backdrop');
  const btn      = $id('notif-bell-btn');
  if (panel)    { panel.classList.remove('open'); }
  if (backdrop) { backdrop.classList.remove('open'); }
  if (btn)      { btn.classList.remove('active'); }
}

async function markNotifRead(id, el) {
  if (el) {
    el.classList.remove('unread');
    const pip = el.querySelector('.notif-unread-pip');
    if (pip) pip.classList.add('read');
  }
  try { await api('POST', `/api/member/notifications/${id}/read`); } catch(e) {}
  const remaining = document.querySelectorAll('#notif-list .notif-item.unread').length;
  const badge = $id('notif-badge');
  if (badge) { badge.textContent = remaining > 9 ? '9+' : remaining; badge.classList.toggle('visible', remaining > 0); }
}

async function markAllNotifsRead() {
  document.querySelectorAll('#notif-list .notif-item').forEach(el => {
    el.classList.remove('unread');
    const pip = el.querySelector('.notif-unread-pip'); if (pip) pip.classList.add('read');
  });
  const badge = $id('notif-badge');
  if (badge) { badge.textContent = ''; badge.classList.remove('visible'); }
  try { await api('POST', '/api/member/notifications/read-all'); } catch(e) {}
}

// Close panel on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && _notifOpen) closeNotifPanel();
  if (e.key === 'Escape' && _editingCollabToken) closeCollabEditModal();
});

// ── Admin-change sync ─────────────────────────────────────────────────────────
// Uses both localStorage events (cross-tab) and visibilitychange (same-tab refocus)

let _lastAdminChange = localStorage.getItem('kfs_admin_data_change') || '0';

function _handleAdminDataChange() {
  const latest = localStorage.getItem('kfs_admin_data_change') || '0';
  if (latest !== _lastAdminChange) {
    _lastAdminChange = latest;
    // Only refresh if user is logged in and app is visible
    if (!_token || $id('app-screen')?.style.display === 'none') return;
    // Silently refresh data panels that could have changed
    loadProfile();
    loadMyWorks();
    loadMovies();
  }
}

window.addEventListener('storage', e => {
  if (e.key === 'kfs_admin_data_change') _handleAdminDataChange();
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') _handleAdminDataChange();
});

// ── Collaborate ───────────────────────────────────────────────────────────────

function showCollabForm() {
  hideEl('collab-form-err'); hideEl('collab-form-ok');
  // Prefill email & phone from cached profile
  const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
  const emailEl = $id('cf-email');
  const phoneEl = $id('cf-phone');
  if (emailEl && profile.email)  emailEl.value = profile.email;
  if (phoneEl && profile.mobile) phoneEl.value = profile.mobile;
  // Set min date to today
  const dateEl = $id('cf-date');
  if (dateEl) dateEl.min = new Date().toISOString().split('T')[0];
  $id('collab-form').style.display = 'block';
  $id('collab-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideCollabForm() {
  $id('collab-form').style.display = 'none';
  ['cf-title','cf-role','cf-domain','cf-skills','cf-description','cf-timeline','cf-date','cf-phone'].forEach(id => {
    const el = $id(id); if (el) el.value = '';
  });
  // Reset email to profile value
  const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
  const emailEl = $id('cf-email');
  if (emailEl) emailEl.value = profile.email || '';
  const cnt = $id('cf-desc-count'); if (cnt) cnt.textContent = '0';
}

async function submitCollab() {
  hideEl('collab-form-err'); hideEl('collab-form-ok');
  const title       = ($id('cf-title')?.value || '').trim();
  const role        = ($id('cf-role')?.value || '').trim();
  const description = ($id('cf-description')?.value || '').trim();
  const date        = ($id('cf-date')?.value || '').trim();
  const email       = ($id('cf-email')?.value || '').trim();
  const phone       = ($id('cf-phone')?.value || '').trim();

  if (!title || !role || !description || !date) {
    showMsg('collab-form-err', 'Title, role, description, and fulfillment date are required.', false);
    return;
  }
  if (!email || !phone) {
    showMsg('collab-form-err', 'Email and phone are required.', false);
    return;
  }

  const btn = $id('collab-submit-btn');
  btn.disabled = true; btn.textContent = 'Posting…';
  try {
    const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
    await api('POST', '/api/collaborate/member', {
      title,
      role,
      description,
      fulfillment_date: date,
      domain:        ($id('cf-domain')?.value || '').trim(),
      skills:        ($id('cf-skills')?.value || '').trim(),
      timeline:      ($id('cf-timeline')?.value || '').trim(),
      contact_name:  profile.name || '',
      contact_email: email,
      contact_phone: phone,
    });
    showMsg('collab-form-ok', '🎬 Collab post published! It\'s now live on the /collaborate page.');
    setTimeout(() => { hideCollabForm(); loadMyCollabs(); }, 2200);
  } catch (e) {
    showMsg('collab-form-err', e.message || 'Could not post — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Post Request';
  }
}

async function loadMyCollabs() {
  const list = $id('collab-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  try {
    const mine = await api('GET', '/api/collaborate/mine');
    if (!mine.length) {
      list.innerHTML = `
        <div class="collab-empty">
          <div class="collab-empty-icon">🤝</div>
          <div class="collab-empty-title">No posts yet</div>
          <div class="collab-empty-sub">Your collab requests will appear here once posted.</div>
        </div>`;
      return;
    }
    list.innerHTML = mine.map(c => {
      const until = new Date(c.fulfillment_date).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' });
      return `
        <div class="collab-posted-card">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div>
              <div class="collab-posted-title">${escHtml(c.title)}</div>
              <div class="collab-posted-role">${escHtml(c.role)}${c.domain ? ' · ' + escHtml(c.domain) : ''}</div>
            </div>
            <span class="badge badge-approved">Live</span>
          </div>
          ${c.description ? `<div style="font-size:13px;color:var(--muted);margin-bottom:12px;line-height:1.55">${escHtml(c.description.slice(0,180))}${c.description.length > 180 ? '…' : ''}</div>` : ''}
          <div class="collab-posted-meta">
            <div class="collab-posted-meta-item">Needed by <span>${until}</span></div>
            ${c.skills ? `<div class="collab-posted-meta-item">Skills <span>${escHtml(c.skills)}</span></div>` : ''}
            ${c.timeline ? `<div class="collab-posted-meta-item">Timeline <span>${escHtml(c.timeline)}</span></div>` : ''}
          </div>
          <div class="collab-card-actions">
            <a href="/collaborate" target="_blank" class="btn-sm" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;transition:all .12s">View on Site ↗</a>
            ${c.edit_token ? `<button class="btn-sm" onclick="openCollabEditModal('${c.edit_token}')" style="background:#1e1e1e;border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;transition:all .12s">Edit</button>` : ''}
            ${c.edit_token ? `<button class="btn-sm btn-danger" onclick="deleteCollab('${c.edit_token}', this)">Delete</button>` : ''}
          </div>
        </div>`;
    }).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ── Collab Edit Modal ─────────────────────────────────────────────────────────

let _editingCollabToken = null;

async function openCollabEditModal(token) {
  _editingCollabToken = token;
  hideEl('collab-edit-err'); hideEl('collab-edit-ok');
  // Fetch existing data
  const modal = $id('collab-edit-modal-overlay');
  if (!modal) return;
  modal.style.display = 'flex';
  try {
    const d = await api('GET', `/api/collaborate/edit/${token}`);
    const set = (id, val) => { const el = $id(id); if (el) el.value = val || ''; };
    set('ce-title',       d.title);
    set('ce-role',        d.role);
    set('ce-domain',      d.domain);
    set('ce-skills',      d.skills);
    set('ce-description', d.description);
    set('ce-timeline',    d.timeline);
    set('ce-date',        d.fulfillment_date);
    set('ce-email',       d.contact_email);
    set('ce-phone',       d.contact_phone);
    const cnt = $id('ce-desc-count'); if (cnt) cnt.textContent = (d.description || '').length;
    // Set min date
    const dateEl = $id('ce-date');
    if (dateEl) dateEl.min = new Date().toISOString().split('T')[0];
  } catch (e) {
    showMsg('collab-edit-err', 'Could not load post data: ' + e.message, false);
  }
}

function closeCollabEditModal() {
  const modal = $id('collab-edit-modal-overlay');
  if (modal) modal.style.display = 'none';
  _editingCollabToken = null;
}

async function submitCollabEdit() {
  if (!_editingCollabToken) return;
  hideEl('collab-edit-err'); hideEl('collab-edit-ok');

  const title       = ($id('ce-title')?.value || '').trim();
  const role        = ($id('ce-role')?.value || '').trim();
  const description = ($id('ce-description')?.value || '').trim();
  const date        = ($id('ce-date')?.value || '').trim();
  const email       = ($id('ce-email')?.value || '').trim();
  const phone       = ($id('ce-phone')?.value || '').trim();

  if (!title || !role || !description || !date) {
    showMsg('collab-edit-err', 'Title, role, description, and fulfillment date are required.', false);
    return;
  }
  if (!email || !phone) {
    showMsg('collab-edit-err', 'Email and phone are required.', false);
    return;
  }

  const btn = $id('collab-edit-submit-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('PUT', `/api/collaborate/member/${_editingCollabToken}`, {
      title, role, description, fulfillment_date: date,
      domain:        ($id('ce-domain')?.value || '').trim(),
      skills:        ($id('ce-skills')?.value || '').trim(),
      timeline:      ($id('ce-timeline')?.value || '').trim(),
      contact_email: email,
      contact_phone: phone,
    });
    showMsg('collab-edit-ok', '✅ Post updated successfully!');
    setTimeout(() => { closeCollabEditModal(); loadMyCollabs(); }, 1800);
  } catch (e) {
    showMsg('collab-edit-err', e.message || 'Could not update — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Save Changes';
  }
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function deleteCollab(token, btn) {
  if (!confirm('Delete this collab post? This cannot be undone.')) return;
  btn.disabled = true; btn.textContent = 'Deleting…';
  try {
    await api('DELETE', `/api/collaborate/${token}`);
    await loadMyCollabs();
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Delete';
    alert('Could not delete: ' + e.message);
  }
}

// ── Enter key support ─────────────────────────────────────────────────────────

function handleEnterKey(e) {
  if (e.key !== 'Enter') return;
  const loginStep    = $id('step-login');
  const totpStep     = $id('step-totp');
  const changePwStep = $id('step-change-pw');
  const setup2FAStep = $id('step-2fa-setup');
  if      (loginStep    && loginStep.style.display    !== 'none')  handleLogin();
  else if (totpStep     && totpStep.style.display     !== 'none')  submitTotp();
  else if (changePwStep && changePwStep.style.display === 'block') handleChangePw();
  else if (setup2FAStep && setup2FAStep.style.display === 'block') verify2FASetup();
}

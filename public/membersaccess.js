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
    if (r.ok && d.token) { _token = d.token; return true; }
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
  await loadProfile();
  loadMovies();
  loadSecurity();
  loadActivity();
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
}

// ── Profile ───────────────────────────────────────────────────────────────────

async function loadProfile() {
  try {
    const d = await api('GET', '/api/member/profile');
    fillProfile(d);
    setText('sidebar-name', d.name || '—');
    setText('sidebar-role', d.role || d.domain || '—');
    const av = $id('sidebar-avatar');
    if (d.photo) {
      av.innerHTML = `<img src="${d.photo}" style="width:32px;height:32px;border-radius:50%;object-fit:cover" />`;
    } else {
      av.textContent = (d.name || '?')[0].toUpperCase();
    }
    const changes  = await api('GET', '/api/member/profile/pending-changes');
    const pending  = changes.some(c => c.status === 'pending');
    $id('profile-pending-banner').style.display = pending ? 'block' : 'none';
  } catch (e) {
    console.error('loadProfile:', e);
  }
}

function fillProfile(d) {
  const fields = ['name','roll_no','mobile','batch','domain','role','bio','instagram','linkedin','github','website'];
  const ids    = ['pf-name','pf-roll','pf-mobile','pf-batch','pf-domain','pf-role','pf-bio','pf-instagram','pf-linkedin','pf-github','pf-website'];
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
  hideEl('profile-msg'); hideEl('profile-err');
  try {
    const form = new FormData();
    const fields = {
      name:      $id('pf-name').value,
      roll_no:   $id('pf-roll').value,
      mobile:    $id('pf-mobile').value,
      batch:     $id('pf-batch').value,
      domain:    $id('pf-domain').value,
      role:      $id('pf-role').value,
      bio:       $id('pf-bio').value,
      instagram: $id('pf-instagram').value,
      linkedin:  $id('pf-linkedin').value,
      github:    $id('pf-github').value,
      website:   $id('pf-website').value,
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
      const notes   = s.reviewer_notes ? `<div class="movie-notes">📝 Admin feedback: ${s.reviewer_notes}</div>` : '';
      const editBtn = ['pending','changes_requested'].includes(s.status)
        ? `<button class="btn-sm movie-edit-btn" style="margin-top:10px;background:#1a1a1a;border:1px solid var(--border);color:var(--muted);border-radius:6px;font-size:12px" data-id="${s.id}">Edit</button>` : '';
      const poster  = md.poster_image
        ? `<img class="movie-poster" src="${md.poster_image}" />`
        : `<div class="movie-poster" style="display:flex;align-items:center;justify-content:center;font-size:20px">🎬</div>`;
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

  const clearFields = ['mf-title','mf-desc','mf-trailer','mf-watch','mf-runtime','mf-language','mf-genre',
    'mf-director','mf-producer','mf-exec-producer','mf-writer','mf-dop','mf-editor',
    'mf-sound','mf-music','mf-actors','mf-support','mf-additional'];

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
        $id('mf-genre').value       = Array.isArray(md.genre) ? md.genre.join(', ') : (md.genre || '');
        $id('mf-director').value    = md.director || '';
        $id('mf-producer').value    = md.producer || '';
        $id('mf-exec-producer').value = md.executive_producer || '';
        $id('mf-writer').value      = md.writer || '';
        $id('mf-dop').value         = md.dop || '';
        $id('mf-editor').value      = md.video_editor || '';
        $id('mf-sound').value       = md.sound_design || '';
        $id('mf-music').value       = md.music_director || '';
        $id('mf-actors').value      = md.actors || '';
        $id('mf-support').value     = md.support_crew || '';
        $id('mf-additional').value  = md.additional_credits || '';
      }
    } catch (_) {}
  } else {
    clearFields.forEach(fid => { const el = $id(fid); if (el) el.value = ''; });
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
    const genreRaw   = $id('mf-genre').value.split(',').map(s => s.trim()).filter(Boolean);
    form.append('title',              $id('mf-title').value);
    form.append('description',        $id('mf-desc').value);
    form.append('trailer_url',        $id('mf-trailer').value);
    form.append('watch_url',          $id('mf-watch').value);
    form.append('runtime',            $id('mf-runtime').value);
    form.append('language',           $id('mf-language').value);
    form.append('genre',              JSON.stringify(genreRaw));
    form.append('director',           $id('mf-director').value);
    form.append('producer',           $id('mf-producer').value);
    form.append('executive_producer', $id('mf-exec-producer').value);
    form.append('writer',             $id('mf-writer').value);
    form.append('dop',                $id('mf-dop').value);
    form.append('video_editor',       $id('mf-editor').value);
    form.append('sound_design',       $id('mf-sound').value);
    form.append('music_director',     $id('mf-music').value);
    form.append('actors',             $id('mf-actors').value);
    form.append('support_crew',       $id('mf-support').value);
    form.append('additional_credits', $id('mf-additional').value);
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
        <div style="font-size:13px;color:var(--success);margin-bottom:16px">✓ Two-factor authentication is enabled</div>
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
      login:                    '🔑 Signed in',
      logout:                   '👋 Signed out',
      password_change:          '🔒 Changed password',
      profile_update_requested: '📝 Profile update submitted',
      profile_updated:          '✅ Profile updated',
      movie_submit:             '🎬 Movie submitted',
      movie_resubmit:           '🔄 Movie resubmitted',
      '2fa_setup':              '🛡️ 2FA enabled',
      '2fa_disable':            '⚠️ 2FA disabled',
      session_revoke_all:       '🚫 All sessions revoked',
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

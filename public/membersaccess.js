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
  on('skip-2fa-btn',      'click', skip2FASetup);

  // Forgot password flow
  on('forgot-password-link', 'click', startForgotPasswordFlow);
  on('fp-back-to-login-btn', 'click', backToLogin);
  on('fp-start-btn',         'click', fpSubmitUsername);
  on('fp-otp-back-btn',      'click', startForgotPasswordFlow);
  on('fp-verify-btn',        'click', fpSubmitOtp);
  on('fp-resend-btn',        'click', fpResendOtp);
  on('fp-reset-btn',         'click', fpSubmitNewPassword);
  on('fp-done-btn',          'click', backToLogin);
  const fpNewPw = $id('fp-new-password');
  if (fpNewPw) fpNewPw.addEventListener('input', () => updatePasswordStrength(fpNewPw.value));
  const fpOtpInput = $id('fp-otp-input');
  if (fpOtpInput) fpOtpInput.addEventListener('input', function() { this.value = this.value.replace(/\D/g, '').slice(0, 6); });

  // Logout buttons
  on('mobile-logout-btn', 'click', logoutMember);
  on('sidebar-logout-btn','click', logoutMember);

  // Nav items — delegate on both nav containers.
  // .btb-item elements are wired separately via btbSwitch() in _wireBtb() —
  // skip them here so a single tap doesn't fire switchPanel twice.
  document.querySelectorAll('[data-panel]:not(.btb-item)').forEach(el => {
    el.addEventListener('click', () => switchPanel(el));
  });

  // Profile
  on('profile-photo-input', 'change', function() { previewPhoto(this); });
  on('profile-save-btn',    'click',  saveProfile);

  // Recovery contact info banner + modal
  on('recovery-banner-add-btn',     'click', openContactInfoModal);
  on('recovery-banner-dismiss-btn', 'click', dismissRecoveryBanner);
  on('ci-save-btn',                 'click', saveContactInfo);
  on('ci-cancel-btn',                'click', closeContactInfoModal);
  const ciOverlay = $id('contact-info-modal-overlay');
  if (ciOverlay) ciOverlay.addEventListener('click', e => { if (e.target === ciOverlay) closeContactInfoModal(); });

  // Movies
  on('new-movie-btn',    'click', () => showMovieForm(null));
  on('movie-submit-btn', 'click', submitMovie);
  on('cancel-movie-btn', 'click', hideMovieForm);

  // Security
  on('sec-change-pw-btn',  'click', changePasswordFromSecurity);
  on('revoke-sessions-btn','click', revokeAllSessions);
  on('security-logout-btn','click', logoutMember);

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

  // Grievance / Suggestion
  on('grv-submit-btn', 'click', submitGrievance);
  const grvBody = $id('grv-body');
  if (grvBody) grvBody.addEventListener('input', () => { const cnt = $id('grv-body-count'); if (cnt) cnt.textContent = grvBody.value.length; });
  document.querySelectorAll('.grv-type-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.grv-type-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const typeEl = $id('grv-type-value');
      if (typeEl) typeEl.value = tab.dataset.grvType || 'general';
    });
  });


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
  document.body.classList.add('auth-active'); // hides the bottom pill nav while signed out
  showStep('login');
  const u = $id('login-username'); if (u) u.value = '';
  const p = $id('login-password'); if (p) p.value = '';
  hideEl('login-err');
  _csrfToken = null; // force fresh CSRF on next login attempt
  initGoogleSignIn();
}

// ── Google Sign-In ───────────────────────────────────────────────────────────
// Loads the (non-secret) Google OAuth Client ID from the server, then renders
// Google's own sign-in button into #google-signin-container. Google handles
// the account picker UI; we only get a signed ID token back via the callback,
// which we send straight to /api/member/google-login for verification.

let _googleInitialized = false;
let _pendingGoogleCredential = null; // held while a Google sign-in is waiting on a 2FA code

async function initGoogleSignIn() {
  const container = $id('google-signin-container');
  if (!container) return;
  hideEl('google-signin-err');

  if (typeof google === 'undefined' || !google.accounts?.id) {
    // Google's script may not have finished loading yet (it's loaded with
    // `defer`) — retry shortly instead of silently failing.
    setTimeout(() => { if ($id('step-login')?.style.display !== 'none') initGoogleSignIn(); }, 300);
    return;
  }

  try {
    if (!_googleInitialized) {
      const r = await fetch('/api/member/google-client-id');
      if (!r.ok) { container.style.display = 'none'; return; } // not configured — hide gracefully, password login still works
      const { client_id } = await r.json();
      if (!client_id) { container.style.display = 'none'; return; }

      google.accounts.id.initialize({
        client_id,
        callback: handleGoogleCredential,
      });
      _googleInitialized = true;
    }
    container.innerHTML = '';
    google.accounts.id.renderButton(container, {
      type: 'standard',
      theme: 'filled_black',
      size: 'large',
      text: 'signin_with',
      shape: 'pill',
      width: 320,
    });
  } catch (e) {
    container.style.display = 'none'; // fail quiet — password login is always the fallback
  }
}

async function handleGoogleCredential(response) {
  await submitGoogleCredential(response.credential, null);
}

async function submitGoogleCredential(credential, totpCode) {
  hideEl('google-signin-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/google-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ credential, totp_code: totpCode || undefined }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('google-signin-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('google-signin-err', d.error || 'Google sign-in failed', false); return; }

    if (d.require_totp) {
      _pendingGoogleCredential = d.google_credential || credential;
      showStep('totp');
      return;
    }
    _pendingGoogleCredential = null;
    _token  = d.token;
    _member = d.member;
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;

    if (d.must_change_password) { showStep('change-pw'); return; }
    // 2FA is opt-in, not forced — members can turn it on later from Security settings.
    await loadDashboard();
  } catch (e) {
    showMsg('google-signin-err', e.message || 'Could not connect to server', false);
  }
}

async function loadDashboard() {
  $id('auth-screen').style.display = 'none';
  $id('app-screen').style.display  = 'flex';
  document.body.classList.remove('auth-active'); // safe to show the bottom pill nav now
  loadPortalMembers(); // preload for pickers (non-blocking)
  await loadProfile();
  loadMovies();
  loadSecurity();
  loadActivity();
  loadMyWorks();
  loadNotificationBadge(); // populate badge count without opening the panel
  startNotifPolling();     // keep badge fresh while page is open

  // ── First-time login detection ──────────────────────────────────────────
  // We track this with a per-member localStorage key so it only fires once
  // per device. Keyed by member id so different members on the same device
  // get their own first-time flag.
  const memberId = (_member?.id || window._memberProfile?.id || 'unknown');
  const firstTimeKey = `kfs-strand-welcomed-${memberId}`;
  const isFirstTime = !localStorage.getItem(firstTimeKey);

  if (isFirstTime) {
    // Show onboarding overlay — direct them to profile
    const overlay = $id('onboarding-overlay');
    if (overlay) {
      overlay.classList.add('open');
      const goBtn   = $id('onboarding-go-btn');
      const skipBtn = $id('onboarding-skip-btn');
      if (goBtn) goBtn.addEventListener('click', () => {
        overlay.classList.remove('open');
        localStorage.setItem(firstTimeKey, '1');
        // Switch to profile panel
        const profileNav = document.querySelector('[data-panel="profile"]');
        if (profileNav) switchPanel(profileNav);
      }, { once: true });
      if (skipBtn) skipBtn.addEventListener('click', () => {
        overlay.classList.remove('open');
        localStorage.setItem(firstTimeKey, '1');
        // Go straight to feed
        _goToStrandFeed();
      }, { once: true });
    }
  } else {
    // Returning user — open Strand feed immediately unless hash says otherwise
    const hash = window.location.hash.replace('#', '');
    if (hash && document.querySelector(`[data-panel="${hash}"]`)) {
      switchPanel(document.querySelector(`[data-panel="${hash}"]`));
    } else {
      _goToStrandFeed();
    }
  }

  // Clear hash after use so back-navigation stays clean
  if (window.location.hash) history.replaceState(null, '', window.location.pathname);

  // Wire bottom tab bar if not already wired
  _wireBtb();
}

/** Switch directly to the Strand (Social Strand) feed panel. */
function _goToStrandFeed() {
  const studioNav = document.querySelector('[data-panel="studio"]');
  if (studioNav && window._memberProfile && !window._memberProfile.is_past) {
    switchPanel(studioNav);
  }
}

/** Wire the bottom tab bar (mobile) — safe to call multiple times. */
function _wireBtb() {
  // Already wired if btb-strand has a listener flag
  if (window._btbWired) return;
  window._btbWired = true;
  document.querySelectorAll('.btb-item[data-panel]').forEach(item => {
    item.addEventListener('click', () => btbSwitch(item));
  });
}

// ── Live lockout countdown ───────────────────────────────────────────────────
// Generic helper for any "locked out, try again in X" UI. Ticks every second,
// updates the error text + a depleting progress bar, disables the action
// button while locked, and auto re-enables everything the instant it expires
// (no page refresh needed). Mirrors the admin portal's version.
const _activeLockoutTimers = {}; // keyed by errEl id, so concurrent screens don't collide

function startLockoutCountdown({ errId, barTrackId, barFillId, btn, btnIdleText, lockedUntil, baseMessage }) {
  const errEl = $id(errId);
  const barTrack = barTrackId ? $id(barTrackId) : null;
  const barFill = barFillId ? $id(barFillId) : null;

  if (_activeLockoutTimers[errId]) clearInterval(_activeLockoutTimers[errId]);

  const totalMs = Math.max(lockedUntil - Date.now(), 0);
  if (totalMs <= 0) return;

  function formatRemaining(ms) {
    const totalSecs = Math.max(Math.ceil(ms / 1000), 0);
    if (totalSecs < 3600) {
      const m = Math.floor(totalSecs / 60);
      const s = totalSecs % 60;
      return `${m}:${String(s).padStart(2, '0')}`;
    }
    if (totalSecs < 86400) {
      const h = Math.floor(totalSecs / 3600);
      const m = Math.floor((totalSecs % 3600) / 60);
      return `${h}h ${m}m`;
    }
    const d = Math.floor(totalSecs / 86400);
    const h = Math.floor((totalSecs % 86400) / 3600);
    return `${d}d ${h}h`;
  }

  function tick() {
    const msLeft = lockedUntil - Date.now();
    if (msLeft <= 0) {
      clearInterval(_activeLockoutTimers[errId]);
      delete _activeLockoutTimers[errId];
      if (errEl) { errEl.textContent = ''; errEl.style.display = 'none'; }
      if (barTrack) barTrack.classList.remove('show');
      if (btn) { btn.disabled = false; if (btnIdleText) btn.textContent = btnIdleText; }
      return;
    }
    if (errEl) { errEl.textContent = `${baseMessage} ${formatRemaining(msLeft)}`; errEl.style.display = 'block'; errEl.className = 'err-msg'; }
    if (barTrack && barFill) {
      barTrack.classList.add('show');
      barFill.style.width = `${Math.max((msLeft / totalMs) * 100, 0)}%`;
    }
  }

  if (btn) btn.disabled = true;
  tick();
  _activeLockoutTimers[errId] = setInterval(tick, 1000);
}

// ── Login ─────────────────────────────────────────────────────────────────────

let _pendingUsername = null, _pendingPassword = null;
let _recoveryPromptDismissedThisSession = false;

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
  let lockedOut = false;
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
    if (r.status === 429 && d.locked_until) {
      lockedOut = true;
      startLockoutCountdown({
        errId: 'login-err',
        barTrackId: 'login-lockout-bar-track',
        barFillId: 'login-lockout-bar-fill',
        btn,
        btnIdleText: 'Sign in',
        lockedUntil: d.locked_until,
        baseMessage: 'Account locked. Try again in',
      });
      return;
    }
    if (!r.ok) { showMsg('login-err', d.error || 'Login failed', false); return; }

    if (d.require_totp) {
      _pendingUsername = username;
      _pendingPassword = password;
      showStep('totp');
      return;
    }
    _token  = d.token;
    _member = d.member;
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
    // Persist token + member data so index.html collab gate can read them
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;

    if (d.must_change_password) { showStep('change-pw'); return; }
    // 2FA is opt-in, not forced — members can turn it on later from Security settings.
    await loadDashboard();
  } catch (e) {
    showMsg('login-err', e.message || 'Could not connect to server', false);
  } finally {
    // Skip resetting the button if a live lockout countdown just took over —
    // it owns the disabled/text state until it hits 0:00.
    if (!lockedOut) {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  }
}

async function submitTotp() {
  const code = $id('totp-input').value.trim();
  if (!code) return;
  const btn = $id('totp-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    if (_pendingGoogleCredential) {
      await submitGoogleCredential(_pendingGoogleCredential, code);
      return;
    }
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
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
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

function backToLogin() { _pendingGoogleCredential = null; showStep('login'); }

function showStep(step) {
  ['login', 'totp', 'change-pw', '2fa-setup', 'fp-username', 'fp-otp', 'fp-reset', 'fp-success'].forEach(s => {
    const el = $id(`step-${s}`);
    if (el) el.style.display = s === step ? 'block' : 'none';
  });
}

// ── Forgot Password ─────────────────────────────────────────────────────────
// Three steps: username -> OTP (email) -> new password.
// Mirrors the existing login/TOTP UX so it doesn't feel like a bolted-on flow.

let _fpUsername = null, _fpResetToken = null, _fpResendCooldownTimer = null;

function startForgotPasswordFlow() {
  _fpUsername = null;
  _fpResetToken = null;
  const u = $id('fp-username'); if (u) u.value = '';
  const o = $id('fp-otp-input'); if (o) o.value = '';
  hideEl('fp-username-err');
  hideEl('fp-otp-err');
  showStep('fp-username');
  setTimeout(() => $id('fp-username')?.focus(), 50);
}

async function fpSubmitUsername() {
  const username = $id('fp-username').value.trim();
  if (!username) { showMsg('fp-username-err', 'Please enter your username', false); return; }
  const btn = $id('fp-start-btn');
  btn.disabled = true; btn.textContent = 'Sending…';
  hideEl('fp-username-err');
  let lockedOut = false;
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-username-err', 'Server error — please try again', false); return; }
    if (r.status === 429 && d.locked_until) {
      lockedOut = true;
      startLockoutCountdown({
        errId: 'fp-username-err',
        barTrackId: 'fp-username-lockout-bar-track',
        barFillId: 'fp-username-lockout-bar-fill',
        btn,
        btnIdleText: 'Send code',
        lockedUntil: d.locked_until,
        baseMessage: 'Too many attempts. Try again in',
      });
      return;
    }
    if (!r.ok) { showMsg('fp-username-err', d.error || 'Something went wrong', false); return; }
    if (d.reason === 'no_contact') {
      showMsg('fp-username-err', d.error || 'Your email is not on file yet. Please contact your site admin for assistance.', false);
      return;
    }

    _fpUsername = username;
    setFpChannelUI(d.channel, d.masked_destination);
    showStep('fp-otp');
    startFpResendCooldown();
    setTimeout(() => $id('fp-otp-input')?.focus(), 50);
  } catch (e) {
    showMsg('fp-username-err', e.message || 'Could not connect to server', false);
  } finally {
    if (!lockedOut) {
      btn.disabled = false;
      btn.textContent = 'Send code';
    }
  }
}

function setFpChannelUI(channel, maskedDestination) {
  const badge = $id('fp-channel-badge');
  const text  = $id('fp-channel-text');
  const sub   = $id('fp-otp-sub');
  if (!channel) {
    // Generic response (account/email couldn't be confirmed) — don't reveal anything extra.
    if (badge) badge.style.display = 'none';
    if (sub) sub.textContent = "If we found an email on file, a 6-digit code is on its way.";
    return;
  }
  if (sub) sub.textContent = `We've sent a 6-digit code to ${maskedDestination || 'your email on file'}.`;
  if (badge && text) {
    text.textContent = 'Sent via email';
    badge.style.display = 'inline-flex';
  }
}

async function fpSubmitOtp() {
  const code = $id('fp-otp-input').value.trim();
  if (!code || code.length !== 6) { showMsg('fp-otp-err', 'Enter the 6-digit code', false); return; }
  const btn = $id('fp-verify-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  hideEl('fp-otp-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername, code }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-otp-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('fp-otp-err', d.error || 'Incorrect code', false); return; }

    _fpResetToken = d.reset_token;
    const np = $id('fp-new-password'); if (np) np.value = '';
    const cp = $id('fp-confirm-password'); if (cp) cp.value = '';
    updatePasswordStrength('');
    showStep('fp-reset');
    setTimeout(() => $id('fp-new-password')?.focus(), 50);
  } catch (e) {
    showMsg('fp-otp-err', e.message || 'Could not connect to server', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify code';
  }
}

function startFpResendCooldown() {
  const btn = $id('fp-resend-btn');
  if (!btn) return;
  let seconds = 30;
  btn.disabled = true;
  btn.textContent = `Resend code (${seconds}s)`;
  clearInterval(_fpResendCooldownTimer);
  _fpResendCooldownTimer = setInterval(() => {
    seconds -= 1;
    if (seconds <= 0) {
      clearInterval(_fpResendCooldownTimer);
      btn.disabled = false;
      btn.textContent = 'Resend code';
    } else {
      btn.textContent = `Resend code (${seconds}s)`;
    }
  }, 1000);
}

async function fpResendOtp() {
  if (!_fpUsername) return;
  const btn = $id('fp-resend-btn');
  if (btn.disabled) return;
  hideEl('fp-otp-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (d && r.ok && d.reason === 'no_contact') {
      showMsg('fp-otp-err', d.error || 'Your email is not on file yet. Please contact your site admin for assistance.', false);
    } else if (d && r.ok) {
      setFpChannelUI(d.channel, d.masked_destination);
      showMsg('fp-otp-err', 'A new code has been sent.', true);
      startFpResendCooldown();
    } else {
      showMsg('fp-otp-err', d?.error || 'Could not resend code', false);
    }
  } catch (e) {
    showMsg('fp-otp-err', e.message || 'Could not connect to server', false);
  }
}

function updatePasswordStrength(pw) {
  const bars = document.querySelectorAll('#fp-pw-strength .pw-strength-bar');
  if (!bars.length) return;
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const level = score <= 1 ? 'weak' : score <= 3 ? 'medium' : 'strong';
  const litCount = score <= 1 ? 1 : score <= 3 ? 2 : 3;
  bars.forEach((bar, i) => {
    bar.className = 'pw-strength-bar' + (i < litCount && pw.length ? ` ${level}` : '');
  });
}

async function fpSubmitNewPassword() {
  const newPw = $id('fp-new-password').value;
  const confirmPw = $id('fp-confirm-password').value;
  hideEl('fp-reset-err');
  if (newPw !== confirmPw) { showMsg('fp-reset-err', 'Passwords do not match', false); return; }
  const isStrong = newPw.length >= 8 && /[A-Z]/.test(newPw) && /[0-9]/.test(newPw) && /[^A-Za-z0-9]/.test(newPw);
  if (!isStrong) { showMsg('fp-reset-err', 'Password must be ≥8 chars, with 1 uppercase, 1 number, 1 special character', false); return; }

  const btn = $id('fp-reset-btn');
  btn.disabled = true; btn.textContent = 'Updating…';
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername, reset_token: _fpResetToken, newPassword: newPw }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-reset-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('fp-reset-err', d.error || 'Could not update password', false); return; }

    _fpUsername = null; _fpResetToken = null;
    showStep('fp-success');
  } catch (e) {
    showMsg('fp-reset-err', e.message || 'Could not connect to server', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update password';
  }
}

// ── Recovery contact info (banner + modal) ───────────────────────────────────

function dismissRecoveryBanner() {
  const banner = $id('recovery-banner');
  if (banner) banner.classList.remove('show');
  _recoveryPromptDismissedThisSession = true;
  api('POST', '/api/member/contact-info/dismiss-prompt').catch(() => {});
}

function openContactInfoModal() {
  const d = window._memberProfile || {};
  const e = $id('ci-email');   if (e) e.value = d.email  || '';
  const p = $id('ci-phone');   if (p) p.value = d.mobile || '';
  hideEl('ci-err'); hideEl('ci-ok');
  $id('contact-info-modal-overlay')?.classList.add('open');
}
function closeContactInfoModal() {
  $id('contact-info-modal-overlay')?.classList.remove('open');
}

async function saveContactInfo() {
  const email = $id('ci-email').value.trim();
  const phone = $id('ci-phone').value.trim();
  hideEl('ci-err'); hideEl('ci-ok');
  if (!email) { showMsg('ci-err', 'Please provide an email for account recovery', false); return; }

  const btn = $id('ci-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('PUT', '/api/member/contact-info', { email, mobile: phone });
    showMsg('ci-ok', 'Saved! Your recovery email is now up to date.', true);
    const banner = $id('recovery-banner');
    if (banner) banner.classList.remove('show');
    // Refresh cached profile + pf-mobile/pf-email fields if visible
    await loadProfile();
    setTimeout(closeContactInfoModal, 900);
  } catch (e) {
    showMsg('ci-err', e.message || 'Could not save contact info', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
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

// ── 2FA Setup (optional — skippable) ─────────────────────────────────────────

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

// 2FA is optional — a member who doesn't want it yet can skip straight to
// their dashboard. They can always turn it on later from Security settings.
async function skip2FASetup() {
  await loadDashboard();
}

// ── Logout ────────────────────────────────────────────────────────────────────

async function logoutMember() {
  try { await api('POST', '/api/member/logout'); } catch (_) {}
  _token = null; _member = null; _csrfToken = null;
  _recoveryPromptDismissedThisSession = false;
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
  // Block studio access for alumni/past members
  if (panel === 'studio' && window._memberProfile?.is_past) return;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll(`.nav-item[data-panel="${panel}"]`).forEach(n => n.classList.add('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $id('panel-' + panel)?.classList.add('active');
  if (panel === 'security') loadSecurity();
  if (panel === 'activity') loadActivity();
  if (panel === 'movies')   loadMovies();
  if (panel === 'works')    loadMyWorks();
  if (panel === 'grievance') loadMyGrievances();
  if (panel === 'network') loadNetworkPanel();
  if (panel === 'dms') { if (typeof dmPanelOpened === 'function') dmPanelOpened(); }
  else {
    if (typeof dmPausePolling === 'function') dmPausePolling();
    if (typeof gcPausePolling === 'function') gcPausePolling();
  }
}

// ── Desktop Sidebar Settings Toggle ──────────────────────────────────────

function toggleSidebarSettings() {
  const items = $id('sidebar-settings-items');
  const chevron = $id('sidebar-settings-chevron');
  const toggle = $id('sidebar-settings-toggle');
  const isOpen = items?.classList.contains('open');
  items?.classList.toggle('open', !isOpen);
  chevron?.classList.toggle('open', !isOpen);
  toggle?.classList.toggle('open', !isOpen);
}

// ── Mini Settings Sheet (mobile bottom nav → Settings) ────────────────────────

function openSettingsSheet() {
  $id('settings-sheet-backdrop')?.classList.add('open');
  $id('settings-sheet')?.classList.add('open');
  document.querySelectorAll('.btb-item').forEach(i => i.classList.remove('active'));
  $id('btb-settings')?.classList.add('active');
}

function closeSettingsSheet() {
  $id('settings-sheet-backdrop')?.classList.remove('open');
  $id('settings-sheet')?.classList.remove('open');
}

// panel: 'profile' | 'analytics' | 'movies' | 'works' | 'security' | 'activity'
function settingsSheetGo(panel) {
  closeSettingsSheet();
  if (panel === 'analytics') {
    // Analytics lives inside the Strand/Studio panel as a tab
    const studioNav = document.querySelector('[data-panel="studio"]');
    if (studioNav) switchPanel(studioNav);
    swSwitchTab('analytics');
  } else {
    const navEl = document.querySelector(`[data-panel="${panel}"]`);
    if (navEl) switchPanel(navEl);
  }
  // Settings has no single matching bottom-bar icon — keep it highlighted
  // since the user is still "inside" the settings flow they tapped into.
  document.querySelectorAll('.btb-item').forEach(i => i.classList.remove('active'));
  $id('btb-settings')?.classList.add('active');
}

// ── Bottom Tab Bar sync ───────────────────────────────────────────────────────

function btbSwitch(el) {
  const panel = el.dataset.panel;
  if (!panel) return;
  // Use existing switchPanel logic
  const navEl = document.querySelector(`.sidebar [data-panel="${panel}"]`) ||
                document.querySelector(`.mobile-nav [data-panel="${panel}"]`) ||
                document.querySelector(`[data-panel="${panel}"]`);
  if (navEl) switchPanel(navEl);
  // Sync active state on bottom bar
  document.querySelectorAll('.btb-item').forEach(i => {
    i.classList.toggle('active', i.dataset.panel === panel);
  });
}

// Keep bottom tab bar in sync when panel changes from sidebar/desktop nav
const _origSwitchPanel = typeof switchPanel !== 'undefined' ? switchPanel : null;

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

    // Hide Studio nav for non-active (alumni/past) members
    const isActiveMember = !d.is_past;
    document.querySelectorAll('.nav-item[data-panel="studio"]').forEach(el => {
      el.style.display = isActiveMember ? '' : 'none';
    });
    // If a past member somehow lands on the studio panel, redirect to profile
    if (!isActiveMember && window.location.hash === '#studio') {
      window.location.hash = '';
    }

    fillProfile(displayData);
    renderStatusPicker(d.status);
    loadMySkills();
    setText('sidebar-name', displayData.name || '—');
    setText('sidebar-role', displayData.role || displayData.domain || '—');
    setText('sidebar-followers-count', swFmtNum ? swFmtNum(d.followers_count) : (d.followers_count||0));
    setText('sidebar-following-count', swFmtNum ? swFmtNum(d.following_count) : (d.following_count||0));
    const av = $id('sidebar-avatar');
    if (displayData.photo) {
      av.innerHTML = `<img src="${displayData.photo}" style="width:32px;height:32px;border-radius:50%;object-fit:cover" />`;
    } else {
      av.textContent = (displayData.name || '?')[0].toUpperCase();
    }

    // Recovery contact banner — show only if no email is on file (mobile
    // no longer satisfies forgot-password — Twilio removed), and the member
    // hasn't dismissed it (server-side flag from login, or this-session dismiss).
    const hasRecoveryContact = !!d.email;
    const banner = $id('recovery-banner');
    if (banner) banner.classList.toggle('show', !hasRecoveryContact && !_recoveryPromptDismissedThisSession);
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
let _notifPollTimer = null;

// Silently refresh the unread badge count without opening the panel
async function loadNotificationBadge() {
  if (!_token) return;
  try {
    const items  = await api('GET', '/api/member/notifications');
    const unread = items.filter(n => !n.is_read).length;
    const badge  = $id('notif-badge');
    if (badge) {
      badge.textContent = unread > 9 ? '9+' : unread;
      badge.classList.toggle('visible', unread > 0);
    }
    // If the panel is already open, refresh its contents too
    if (_notifOpen) loadNotifications();
  } catch (e) { /* silent — badge stays as-is */ }
}

// Poll for new notifications every 60 s while the page is visible
function startNotifPolling() {
  if (_notifPollTimer) return; // already running
  _notifPollTimer = setInterval(() => {
    if (document.visibilityState === 'visible') loadNotificationBadge();
  }, 60_000);
}

// Icon per notification type
function _notifIcon(type) {
  const icons = {
    movie_approved:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    movie_rejected:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    profile_change:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
    event:           `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
    announcement:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
    follow:          `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="4"/><path d="M2 20c0-4 3.1-6.5 7-6.5s7 2.5 7 6.5"/><line x1="18" y1="6" x2="18" y2="12"/><line x1="15" y1="9" x2="21" y2="9"/></svg>`,
    network:         `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="4"/><path d="M2 20c0-4 3.1-6.5 7-6.5s7 2.5 7 6.5"/><line x1="18" y1="6" x2="18" y2="12"/><line x1="15" y1="9" x2="21" y2="9"/></svg>`,
    new_post:        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/><circle cx="6.5" cy="6" r="0.8" fill="currentColor" stroke="none"/></svg>`,
    studio:          `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/></svg>`,
    default:         `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  };
  return icons[type] || icons.default;
}

// Tiny badge icon overlaid on the bottom-right of an actor's avatar —
// gives the same at-a-glance "what happened" signal Instagram uses.
function _notifBadgeIcon(type) {
  const badges = {
    follow:   { cls: 'follow',   svg: `<svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7z"/></svg>` },
    network:  { cls: 'follow',   svg: `<svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7z"/></svg>` },
    new_post: { cls: 'post',     svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M12 8v8M8 12h8"/></svg>` },
  };
  return badges[type] || null;
}

// Cache the most recently loaded notifications keyed by id so click
// handlers can navigate without fighting HTML-attribute escaping.
let _notifCache = new Map();

function onNotifClick(id) {
  const n = _notifCache.get(id);
  markNotifRead(id, document.querySelector(`.notif-item[data-notif-id="${id}"]`));
  if (!n) return;
  if (n.link_type === 'profile' && n.link_id) {
    closeNotifPanel();
    openMemberProfile(n.link_id);
  } else if (n.link_type === 'post' && n.link_id) {
    closeNotifPanel();
    const studioNav = document.querySelector('[data-panel="studio"]');
    if (studioNav) switchPanel(studioNav);
    swOpenDetail(n.link_id);
  }
}

async function loadNotifications() {
  if (!_token || _notifLoading) return;
  _notifLoading = true;
  const list = $id('notif-list');
  if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-title" style="color:#333">Loading…</div></div>';
  try {
    const items = await api('GET', '/api/member/notifications');
    _notifCache = new Map(items.map(n => [n.id, n]));
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
    list.innerHTML = items.map(n => {
      const badge = _notifBadgeIcon(n.type);
      const avatarHtml = n.actor_photo || n.actor_name
        ? `<div class="notif-avatar-wrap">
             ${swAvatar(n.actor_name, n.actor_photo, 38)}
             ${badge ? `<span class="notif-type-badge notif-type-badge--${badge.cls}">${badge.svg}</span>` : ''}
           </div>`
        : `<div class="notif-icon-bubble">${_notifIcon(n.type)}</div>`;
      return `
      <div class="notif-item ${n.is_read ? '' : 'unread'}" data-notif-id="${n.id}" onclick="onNotifClick('${n.id}')">
        ${avatarHtml}
        <div class="notif-item-content">
          <div class="notif-item-title">${swEsc(n.title)}</div>
          ${n.body ? `<div class="notif-item-body">${swEsc(n.body)}</div>` : ''}
          <div class="notif-item-time">${relTime(n.created_at)}</div>
        </div>
        <div class="notif-unread-pip ${n.is_read ? 'read' : ''}"></div>
      </div>`;
    }).join('');
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
  if (e.key === 'Escape' && $id('settings-sheet')?.classList.contains('open')) closeSettingsSheet();
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
  // Once logged in, #auth-screen is hidden — bail immediately. (We can't rely on
  // each individual step's own inline style.display: showStep() sets it to 'block'
  // when a step is shown but nothing ever resets it back to 'none' after a
  // successful login, so step-login.style.display stayed 'block' forever and this
  // function kept firing handleLogin() on every Enter press anywhere in the app —
  // including while sending a DM — which silently re-logged in and bounced the
  // user back to the Strand feed via loadDashboard().)
  if ($id('auth-screen')?.style.display === 'none') return;
  const loginStep    = $id('step-login');
  const totpStep     = $id('step-totp');
  const changePwStep = $id('step-change-pw');
  const setup2FAStep = $id('step-2fa-setup');
  const fpUserStep   = $id('step-fp-username');
  const fpOtpStep    = $id('step-fp-otp');
  const fpResetStep  = $id('step-fp-reset');
  if      (loginStep    && loginStep.style.display    !== 'none')  handleLogin();
  else if (totpStep     && totpStep.style.display     !== 'none')  submitTotp();
  else if (changePwStep && changePwStep.style.display === 'block') handleChangePw();
  else if (setup2FAStep && setup2FAStep.style.display === 'block') verify2FASetup();
  else if (fpUserStep   && fpUserStep.style.display   === 'block') fpSubmitUsername();
  else if (fpOtpStep    && fpOtpStep.style.display    === 'block') fpSubmitOtp();
  else if (fpResetStep  && fpResetStep.style.display  === 'block') fpSubmitNewPassword();
}

// ── Grievance / Suggestion ────────────────────────────────────────────────────

async function submitGrievance() {
  const subject  = ($id('grv-subject')?.value || '').trim();
  const body     = ($id('grv-body')?.value    || '').trim();
  const type     = ($id('grv-type-value')?.value || 'general');
  const anon     = !!$id('grv-anon')?.checked;

  if (!subject) { showMsg('grv-form-err', 'Please add a subject.', false); return; }
  if (!body)    { showMsg('grv-form-err', 'Please add some details.', false); return; }
  if (body.length < 10) { showMsg('grv-form-err', 'Details are too short — please be more descriptive.', false); return; }

  const btn = $id('grv-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('grv-form-err'); hideEl('grv-form-ok');
  try {
    await api('POST', '/api/member/grievances', { subject, body, type, anonymous: anon });
    showMsg('grv-form-ok', '✅ Submitted! We\'ll review it and update the status here.');
    // Reset form
    const subj = $id('grv-subject'); if (subj) subj.value = '';
    const bod  = $id('grv-body');   if (bod)  { bod.value = ''; const cnt = $id('grv-body-count'); if (cnt) cnt.textContent = '0'; }
    const anonEl = $id('grv-anon'); if (anonEl) anonEl.checked = false;
    // Reset type tab to suggestion
    document.querySelectorAll('.grv-type-tab').forEach(t => t.classList.remove('active'));
    const defTab = $id('grv-tab-suggestion'); if (defTab) defTab.classList.add('active');
    const typeEl = $id('grv-type-value'); if (typeEl) typeEl.value = 'suggestion';
    // Reload list
    await loadMyGrievances();
  } catch (e) {
    showMsg('grv-form-err', e.message || 'Could not submit — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Submit';
  }
}

function _grvStatusBanner(status, adminNote) {
  const cfg = {
    open:        { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>', text: 'Received — pending review by the team.' },
    in_progress: { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', text: 'Being worked on — your issue is actively being addressed.' },
    resolved:    { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>', text: 'Resolved — this has been addressed.' },
  };
  const c = cfg[status] || cfg.open;
  return `
    <div class="grv-status-banner ${status || 'open'}">
      ${c.icon}
      <div>
        <div>${c.text}</div>
        ${adminNote ? `<div class="grv-admin-note">Admin note: ${escHtml(adminNote)}</div>` : ''}
      </div>
    </div>`;
}

function _grvBadgeClass(status) {
  if (status === 'resolved')    return 'badge-resolved';
  if (status === 'in_progress') return 'badge-in-progress';
  return 'badge-open';
}

function _grvBadgeLabel(status) {
  if (status === 'resolved')    return 'Resolved';
  if (status === 'in_progress') return 'In Progress';
  return 'Open';
}

function _grvTypeLabel(type) {
  if (type === 'suggestion') return '💡 Suggestion';
  if (type === 'grievance')  return '🚨 Grievance';
  return '💬 General';
}

async function loadMyGrievances() {
  const list = $id('grv-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  try {
    const items = await api('GET', '/api/member/grievances');
    if (!items.length) {
      list.innerHTML = `
        <div class="grv-empty">
          <div class="grv-empty-icon">💬</div>
          <div class="grv-empty-title">Nothing submitted yet</div>
          <div class="grv-empty-sub">Use the form above to share feedback or raise a concern.</div>
        </div>`;
      return;
    }
    list.innerHTML = items.map(g => `
      <div class="grv-card">
        <div class="grv-card-header">
          <div class="grv-card-subject">${escHtml(g.subject)}</div>
          <span class="badge ${_grvBadgeClass(g.status)}">${_grvBadgeLabel(g.status)}</span>
        </div>
        <div class="grv-card-body">${escHtml(g.body)}</div>
        <div class="grv-card-meta">
          <span class="grv-card-type-chip">${_grvTypeLabel(g.type)}</span>
          <span class="grv-card-time">${relTime(g.created_at)}</span>
          ${g.anonymous ? '<span class="grv-card-time">· Anonymous</span>' : ''}
        </div>
        ${_grvStatusBanner(g.status, g.admin_note)}
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// KFS Social Strand — Client
// Routes: /api/member/studio/* (member-auth-gated, CSRF applied by server)
// ═══════════════════════════════════════════════════════════════════════════

const SW = {
  feedPage:             1,
  feedTag:              null,
  feedSort:             'latest', // 'latest' | 'foryou' (Phase 2 smart feed)
  feedExhausted:        false,
  feedLoading:          false,
  myReactions:          new Map(), // projectId → reactionType | null
  editingProjectId:     null,
  collabPickerSelected: [],
  detailProjectId:      null,
};

// ── Utilities ──────────────────────────────────────────────────────────────

function swEsc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function swFmtNum(n) {
  const num = Number(n) || 0;
  if (num >= 1_000_000) return (num/1_000_000).toFixed(1).replace(/\.0$/,'')+'M';
  if (num >= 1000)      return (num/1000).toFixed(1).replace(/\.0$/,'')+'k';
  return String(num);
}

function swRelTime(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff/60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m/60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h/24);
  if (d < 30) return `${d}d ago`;
  return new Date(ts).toLocaleDateString('en-GB', { month:'short', year:'numeric' });
}

function swVideoEmbedUrl(url, provider) {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (provider === 'youtube' || u.hostname.includes('youtube') || u.hostname.includes('youtu.be')) {
      const vid = u.searchParams.get('v') || u.pathname.split('/').pop();
      return `https://www.youtube.com/embed/${vid}?rel=0&modestbranding=1`;
    }
    if (provider === 'vimeo' || u.hostname.includes('vimeo')) {
      return `https://player.vimeo.com/video/${u.pathname.split('/').pop()}?title=0&byline=0&portrait=0`;
    }
  } catch {}
  return null;
}

function swAvatar(name, photo, size = 32) {
  // server stores field as `photo`, not `photo_url`
  if (photo) {
    return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;flex-shrink:0;background:#1a1a1a">`;
  }
  const initials = (name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;border:1px solid #2a2a2a;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.36)}px;font-weight:600;color:#666;flex-shrink:0;letter-spacing:-.01em">${swEsc(initials)}</div>`;
}

// SVG icon set — no emojis
const SW_ICONS = {
  eye:      `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  heart:    `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  heartF:   `<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  comment:  `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  play:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  trash:    `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
  edit:     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  close:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  user:     `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
  pin:      `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
  eyeLg:    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  heartLg:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  postsLg:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`,
};

const SW_REACTIONS = [
  { type:'wow',        label:'Wow',           icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>` },
  { type:'fire',       label:'Fire',          icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0011 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 01-7 7 7 7 0 01-4.5-1.5c1-.5 1.5-1 1-2z"/></svg>` },
  { type:'brilliant',  label:'Brilliant',     icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>` },
  { type:'seahaven',   label:'Seahaven',      icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="1" y1="18" x2="3" y2="18"/><line x1="21" y1="18" x2="23" y2="18"/><line x1="18.36" y1="11.64" x2="19.78" y2="10.22"/><line x1="23" y1="22" x2="1" y2="22"/><polyline points="8 6 12 2 16 6"/></svg>` },
  { type:'mind_blown', label:'Mind Blown',    icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>` },
];

// ── Feed card ─────────────────────────────────────────────────────────────

function swFeedCard(p) {
  const author   = p.members || {};
  const myRxn    = SW.myReactions.get(p.id) || p.my_reaction || null;
  const isLiked  = !!myRxn;
  const hasImage = !!p.cover_image;
  const hasVideo = !!p.video_url;
  const postType = p.post_type || (hasImage ? 'image' : hasVideo ? 'video' : 'text');

  // Avatar — with gradient ring like Instagram
  const avatarInner = author.photo
    ? `<img src="${swEsc(author.photo)}" alt="${swEsc(author.name)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;display:block;">`
    : `<div style="width:100%;height:100%;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#666;">${swEsc((author.name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase())}</div>`;

  // Media section — image, video, or text body
  let mediaHtml = '';
  if (hasImage) {
    mediaHtml = `<div class="ig-post-img-wrap"><img src="${swEsc(p.cover_image)}" alt="" class="ig-post-img" loading="lazy"></div>`;
  } else if (hasVideo) {
    const embedUrl = swVideoEmbedUrl(p.video_url, p.video_provider);
    if (embedUrl) {
      mediaHtml = `<div class="ig-post-img-wrap" style="position:relative;padding-bottom:56.25%;background:#000;"><iframe src="${swEsc(embedUrl)}" allowfullscreen loading="lazy" style="position:absolute;inset:0;width:100%;height:100%;border:none;"></iframe></div>`;
    } else {
      mediaHtml = `<div class="ig-post-img-wrap" style="aspect-ratio:16/9;background:#111;display:flex;align-items:center;justify-content:center;">${SW_ICONS.play}</div>`;
    }
  } else if (postType === 'text' && p.description) {
    // Text-only post — X/Twitter style: just inline text, no dark box
    mediaHtml = `<div class="ig-post-text-bg"><div class="ig-post-text-content">${swEsc(p.description)}</div></div>`;
  }

  // Caption: show title as headline, then description (if there's also an image)
  const hasCaption = hasImage || hasVideo;
  let captionHtml = '';
  if (hasCaption && (p.title || p.description)) {
    const captionBody = [p.title, (hasImage || hasVideo) ? p.description : null].filter(Boolean).join(' · ');
    captionHtml = `<div class="ig-post-caption"><span class="ig-post-caption-author" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">${swEsc(author.name||'Member')}</span> <span class="ig-post-caption-text">${swEsc(captionBody)}</span></div>`;
  } else if (postType !== 'text' && p.title) {
    captionHtml = `<div class="ig-post-caption"><span class="ig-post-caption-author" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">${swEsc(author.name||'Member')}</span> <span class="ig-post-caption-text">${swEsc(p.title)}</span></div>`;
  }

  // Tags
  const tagsHtml = p.tags?.length
    ? `<div class="ig-post-tags">${p.tags.map(t=>`<span class="ig-post-tag">#${swEsc(t)}</span>`).join(' ')}</div>` : '';

  // Comments count link + inline preview
  const previewComments = (p.latest_comments || []).slice(0,3);
  const commentsHtml = (() => {
    let html = '';
    if (previewComments.length) {
      html += `<div class="ig-post-comments-preview">`;
      previewComments.forEach(c => {
        const ca = c.members || {};
        html += `<div class="ig-comment-preview-row"><span class="ig-comment-preview-author">${swEsc(ca.name||'Member')}</span> <span class="ig-comment-preview-body">${swEsc(c.body||'')}</span></div>`;
      });
      html += `</div>`;
    }
    if (p.comments_count > previewComments.length) {
      const remaining = p.comments_count - previewComments.length;
      html += `<div class="ig-post-view-comments" onclick="event.stopPropagation();swOpenDetail('${swEsc(p.id)}')">View ${remaining > 0 && previewComments.length > 0 ? `${p.comments_count > 1 ? `all ${swFmtNum(p.comments_count)} comments` : '1 comment'}` : (p.comments_count === 1 ? '1 comment' : `all ${swFmtNum(p.comments_count)} comments`)}</div>`;
    } else if (p.comments_count === 0) {
      html += '';
    }
    return html;
  })();

  const likesLabel = p.reactions_count > 0
    ? `<div class="ig-post-likes">${swFmtNum(p.reactions_count)} ${p.reactions_count !== 1 ? 'reactions' : 'reaction'}</div>` : '';

  // Reaction popup is now a single body-level portal (#rxn-overlay), not per-card

  // Admin/KFS post indicator
  const isAdminPost = !!p.is_admin_post;
  const kfsBadgeHtml = isAdminPost
    ? `<span style="display:inline-flex;align-items:center;gap:4px;background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em;margin-left:6px;vertical-align:middle">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="#fff"><path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" stroke="none"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round"/></svg> KFS
       </span>` : '';

  return `<article class="ig-post" data-project-id="${swEsc(p.id)}"${isAdminPost ? ' style="border:1.5px solid #2d6a9f22;background:linear-gradient(180deg,rgba(45,106,159,.04),transparent)"' : ''} onclick="swOpenDetail('${swEsc(p.id)}')">
    <!-- Header -->
    <div class="ig-post-header">
      <div class="ig-post-avatar-wrap" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-avatar-inner">${avatarInner}</div>
      </div>
      <div class="ig-post-author-block" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-author-name">${swEsc(isAdminPost ? 'KFS' : (author.name||'Member'))}${kfsBadgeHtml}</div>
        <div class="ig-post-time">${swRelTime(p.created_at)}</div>
      </div>
      <button class="ig-post-options" onclick="event.stopPropagation();swShowPostMenu(event,'${swEsc(p.id)}','${swEsc(p.member_id)}',${isAdminPost})" title="More" aria-label="Post options">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>
      </button>
    </div>

    <!-- Media / text body -->
    ${mediaHtml}

    <!-- Action bar -->
    <div class="ig-post-actions">
      <button class="ig-action-btn ig-like-btn${isLiked?' liked':''}"
        data-project-id="${swEsc(p.id)}"
        title="${isLiked?'Liked':'Like'}"
        onclick="event.stopPropagation();swToggleReaction('${swEsc(p.id)}','wow')"
        onmouseenter="swShowRxnPopup('${swEsc(p.id)}')"
        onmouseleave="swHideRxnPopup('${swEsc(p.id)}')"
      ><svg width="24" height="24" viewBox="0 0 24 24" fill="${isLiked?'#4ba3d4':'none'}" stroke="${isLiked?'#4ba3d4':'currentColor'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>
      </button>
      <button class="ig-action-btn" onclick="event.stopPropagation();swOpenDetail('${swEsc(p.id)}')" title="Comment">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      </button>
      <span class="ig-post-views-inline"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>&nbsp;${swFmtNum(p.views_count||0)}</span>
    </div>

    <!-- Reactions count -->
    ${likesLabel}

    <!-- Caption -->
    ${captionHtml}

    <!-- Tags -->
    ${tagsHtml}

    <!-- Comments link -->
    ${commentsHtml}

    <!-- Timestamp -->
    <div class="ig-post-timestamp">${swRelTime(p.created_at)}</div>
  </article>`;
}

// ── Feed Load ─────────────────────────────────────────────────────────────

async function swLoadFeed(reset = false) {
  if (SW.feedLoading) return;
  if (!reset && SW.feedExhausted) return;
  if (reset) {
    SW.feedPage = 1;
    SW.feedExhausted = false;
    const grid = $id('studio-feed');
    if (grid) grid.innerHTML = '<div class="sw-loading">Loading…</div>';
  }
  SW.feedLoading = true;
  try {
    let url = `/api/member/studio/feed?page=${SW.feedPage}`;
    if (SW.feedTag) url += `&tag=${encodeURIComponent(SW.feedTag)}`;
    if (SW.feedSort === 'foryou') url += `&sort=foryou`;
    const resp = await api('GET', url);
    // server returns { feed, page, has_more }
    const data = resp.feed || resp; // fallback to flat array
    const hasMore = resp.has_more ?? (data.length === 20);

    const grid = $id('studio-feed');
    if (!grid) return;
    if (reset) grid.innerHTML = '';

    if (!data.length && SW.feedPage === 1) {
      grid.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon">${SW_ICONS.postsLg}</div><div class="sw-empty-title">No posts yet</div><div class="sw-empty-sub">Be the first to share your work.</div></div>`;
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = 'none';
      return;
    }

    if (!hasMore) {
      SW.feedExhausted = true;
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = 'none';
    } else {
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = '';
    }

    // Sync my_reaction into SW.myReactions map
    data.forEach(p => { if (p.my_reaction) SW.myReactions.set(p.id, p.my_reaction); });

    grid.insertAdjacentHTML('beforeend', data.map(swFeedCard).join(''));
    swAttachLongPress();
    SW.feedPage++;
  } catch (e) {
    const grid = $id('studio-feed');
    if (grid && reset) grid.innerHTML = `<div class="sw-error">Could not load feed. <button class="btn-ghost" onclick="swLoadFeed(true)" style="font-size:12px;padding:4px 10px;margin-left:6px">Retry</button></div>`;
  } finally {
    SW.feedLoading = false;
  }
}

// ── My Posts ──────────────────────────────────────────────────────────────

async function swLoadMyPosts() {
  const list = $id('studio-my-posts-list');
  if (!list) return;
  list.innerHTML = '<div class="sw-loading">Loading…</div>';
  try {
    const data = await api('GET', '/api/member/studio/mine');
    if (!data.length) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon">${SW_ICONS.postsLg}</div><div class="sw-empty-title">No posts yet</div><div class="sw-empty-sub">Post your first project to the Social Strand.</div></div>`;
      return;
    }
    list.innerHTML = data.map(p => `
      <div class="sw-my-post-row">
        <div class="sw-my-post-info">
          ${p.cover_image ? `<img src="${swEsc(p.cover_image)}" alt="" class="sw-my-post-thumb">` : `<div class="sw-my-post-thumb sw-my-post-thumb-blank">${SW_ICONS.play}</div>`}
          <div class="sw-my-post-text">
            <div class="sw-my-post-title">${swEsc(p.title)}</div>
            <div class="sw-my-post-meta">
              <span class="sw-stat">${SW_ICONS.eye}&nbsp;${swFmtNum(p.views_count)}</span>
              <span class="sw-stat">${SW_ICONS.heart}&nbsp;${swFmtNum(p.reactions_count)}</span>
              <span class="sw-stat">${SW_ICONS.comment}&nbsp;${swFmtNum(p.comments_count)}</span>
              ${p.status==='hidden'?'<span class="sw-badge-hidden">Hidden</span>':''}
            </div>
          </div>
        </div>
        <div class="sw-my-post-actions">
          <button class="sw-action-btn" title="Edit" onclick="swOpenEditModal('${swEsc(p.id)}')">${SW_ICONS.edit}</button>
          <button class="sw-action-btn sw-action-btn-danger" title="Delete" onclick="swDeletePost('${swEsc(p.id)}','${swEsc(p.title)}')">${SW_ICONS.trash}</button>
        </div>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${swEsc(e.message)}</span>`;
  }
}

// ── Analytics — views + reactions only ────────────────────────────────────

async function swLoadAnalytics() {
  const wrap = $id('studio-analytics-list');
  if (!wrap) return;
  wrap.innerHTML = '<div class="sw-loading">Loading…</div>';
  try {
    const data = await api('GET', '/api/member/studio/my-analytics');
    if (!data.length) {
      wrap.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#444" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg></div><div class="sw-empty-title">No data yet</div><div class="sw-empty-sub">Post work to start seeing your numbers.</div></div>`;
      return;
    }
    const totalViews     = data.reduce((s,p)=>s+(p.views_count||0),0);
    const totalReactions = data.reduce((s,p)=>s+(p.reactions_count||0),0);
    const maxViews       = Math.max(...data.map(p=>p.views_count||0),1);
    const maxReactions   = Math.max(...data.map(p=>p.reactions_count||0),1);

    wrap.innerHTML = `
      <div class="sw-analytics-kpis">
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--views">${SW_ICONS.eyeLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${swFmtNum(totalViews)}</div><div class="sw-analytics-kpi-label">Total Views</div></div>
        </div>
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--reactions">${SW_ICONS.heartLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${swFmtNum(totalReactions)}</div><div class="sw-analytics-kpi-label">Total Reactions</div></div>
        </div>
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--posts">${SW_ICONS.postsLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${data.length}</div><div class="sw-analytics-kpi-label">Published</div></div>
        </div>
      </div>
      <div class="sw-analytics-section-label">Per post</div>
      <div class="sw-analytics-rows">
        ${data.map(p=>{
          const v = p.views_count||0, r = p.reactions_count||0;
          const vPct = Math.round((v/maxViews)*100), rPct = Math.round((r/maxReactions)*100);
          return `<div class="sw-analytics-row">
            <div class="sw-analytics-row-head"><div class="sw-analytics-row-title" title="${swEsc(p.title)}">${swEsc(p.title)}</div></div>
            <div class="sw-analytics-metric-row">
              <div class="sw-analytics-metric-label"><span class="sw-analytics-metric-icon">${SW_ICONS.eye}</span><span class="sw-analytics-metric-num">${swFmtNum(v)}</span><span class="sw-analytics-metric-name">views</span></div>
              <div class="sw-analytics-bar-track"><div class="sw-analytics-bar-fill sw-analytics-bar-fill--views" style="width:${vPct}%"></div></div>
            </div>
            <div class="sw-analytics-metric-row">
              <div class="sw-analytics-metric-label"><span class="sw-analytics-metric-icon">${SW_ICONS.heart}</span><span class="sw-analytics-metric-num">${swFmtNum(r)}</span><span class="sw-analytics-metric-name">reactions</span></div>
              <div class="sw-analytics-bar-track"><div class="sw-analytics-bar-fill sw-analytics-bar-fill--reactions" style="width:${rPct}%"></div></div>
            </div>
          </div>`;
        }).join('')}
      </div>`;
  } catch (e) {
    wrap.innerHTML = `<span style="color:var(--danger);font-size:13px">${swEsc(e.message)}</span>`;
  }
}

// ── Detail Modal ──────────────────────────────────────────────────────────

async function swOpenDetail(projectId) {
  _rxnHideNow(); // dismiss reaction wheel if open
  SW.detailProjectId = projectId;
  const overlay = $id('studio-detail-modal-overlay');
  const body    = $id('studio-detail-body');
  if (!overlay||!body) return;
  body.innerHTML = '<div class="sw-loading" style="padding:60px 0;text-align:center">Loading…</div>';
  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
  try {
    const p = await api('GET', `/api/member/studio/projects/${projectId}`);
    const author   = p.members || {};
    const collabs  = (p.project_collaborators||[]).map(c=>c.members).filter(Boolean);
    const myRxn    = SW.myReactions.get(p.id) || p.my_reaction || null;
    SW.myReactions.set(p.id, myRxn);
    const embedUrl = swVideoEmbedUrl(p.video_url, p.video_provider);

    // Fetch comments
    const cResp = await api('GET', `/api/member/studio/projects/${projectId}/comments`);
    const comments = cResp.comments || cResp || [];

    body.innerHTML = `
      ${p.cover_image && !embedUrl ? `<img src="${swEsc(p.cover_image)}" alt="${swEsc(p.title)}" class="studio-detail-cover">` : ''}
      ${embedUrl ? `<div class="studio-detail-video-wrap"><iframe src="${swEsc(embedUrl)}" allowfullscreen loading="lazy"></iframe></div>` : ''}
      <div class="studio-detail-content">
        <div class="studio-detail-author-row">
          <span style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="openMemberProfile('${swEsc(p.member_id)}')">
            ${swAvatar(author.name, author.photo, 34)}
            <span><div class="studio-detail-author-name">${swEsc(author.name||'Member')}</div>${author.role?`<div class="studio-detail-author-role">${swEsc(author.role)}</div>`:''}</span>
          </span>
          ${p.domain?`<span class="studio-detail-domain-pill" style="margin-left:auto">${swEsc(p.domain)}</span>`:''}
        </div>
        <div class="studio-detail-title">${swEsc(p.title)}</div>
        ${p.description?`<div class="studio-detail-desc">${swEsc(p.description)}</div>`:''}
        <div class="studio-detail-meta">
          <span class="studio-detail-stat">${SW_ICONS.eye}&nbsp;${swFmtNum(p.views_count)}</span>
          <span class="studio-detail-stat">${SW_ICONS.heart}&nbsp;${swFmtNum(p.reactions_count)}</span>
          <span class="studio-detail-stat">${SW_ICONS.comment}&nbsp;${swFmtNum(p.comments_count)}</span>
        </div>
        ${p.tags?.length?`<div class="studio-detail-tags">${p.tags.map(t=>`<span class="sw-tag">${swEsc(t)}</span>`).join('')}</div>`:''}
        ${collabs.length?(()=>{
          const MAX=3;
          const shown=collabs.slice(0,MAX);
          const extra=collabs.length-shown.length;
          return `<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:16px">
            <span style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em">${SW_ICONS.user}&nbsp;With</span>
            ${shown.map(c=>`<span style="display:flex;align-items:center;gap:4px;font-size:11px;color:#bbb">${swAvatar(c.name,c.photo,16)}${swEsc(c.name)}</span>`).join('')}
            ${extra>0?`<span style="font-size:11px;color:var(--muted)">+${extra} more</span>`:''}
          </div>`;
        })():''}
        <div class="studio-reactions" id="detail-reactions-${swEsc(p.id)}">
          ${SW_REACTIONS.map(r=>`<button class="studio-rxn-btn ${myRxn===r.type?'active':''}" data-rxn="${swEsc(r.type)}" data-project="${swEsc(p.id)}" onclick="swToggleReaction('${swEsc(p.id)}','${swEsc(r.type)}')" title="${swEsc(r.label)}">${r.icon}<span class="sw-rxn-label">${swEsc(r.label)}</span></button>`).join('')}
        </div>
        <div class="studio-comments-section">
          <div class="studio-comments-title">Comments</div>
          <div class="studio-comment-input-row">
            <input id="sw-comment-input" type="text" placeholder="Add a comment…" class="studio-comment-input" maxlength="1000" onkeydown="if(event.key==='Enter')swPostComment('${swEsc(p.id)}',null)">
            <button class="studio-comment-post-btn" onclick="swPostComment('${swEsc(p.id)}',null)">Post</button>
          </div>
          <div id="sw-comments-list">${swRenderComments(comments, p.id)}</div>
        </div>
      </div>`;
  } catch (e) {
    body.innerHTML = `<div style="padding:48px;text-align:center;color:var(--muted);font-size:14px">${swEsc(e.message)}</div>`;
  }
}

function swRenderComments(comments, projectId) {
  // server nests replies under each comment's `.replies` array
  if (!comments.length) return `<div style="color:var(--muted);font-size:13px;padding:16px 0">No comments yet.</div>`;

  function renderOne(c, nested=false) {
    const a = c.members||{};
    return `<div class="studio-comment ${nested?'studio-comment-nested':''}">
      <div class="studio-comment-header">
        <span style="display:inline-flex;align-items:center;gap:8px;cursor:pointer" onclick="openMemberProfile('${swEsc(a.id)}')">
          ${swAvatar(a.name,a.photo,22)}
          <span class="studio-comment-author">${swEsc(a.name||'Member')}</span>
        </span>
        <span class="studio-comment-time">${swRelTime(c.created_at)}</span>
        ${c.is_pinned?`<span class="studio-comment-pinned-badge">${SW_ICONS.pin}&nbsp;Pinned</span>`:''}
      </div>
      <div class="studio-comment-body">${swEsc(c.body)}</div>
      <button class="studio-comment-reply-btn" onclick="swShowReplyInput('${swEsc(c.id)}','${swEsc(projectId)}')">Reply</button>
      <div id="sw-reply-input-${swEsc(c.id)}"></div>
      ${(c.replies||[]).map(r=>renderOne(r,true)).join('')}
    </div>`;
  }

  return comments.map(c=>renderOne(c,false)).join('');
}

function swShowReplyInput(commentId, projectId) {
  const wrap = $id(`sw-reply-input-${commentId}`);
  if (!wrap) return;
  if (wrap.innerHTML) { wrap.innerHTML=''; return; }
  wrap.innerHTML = `<div class="studio-comment-input-row" style="margin-top:8px;padding-left:30px">
    <input id="sw-reply-text-${swEsc(commentId)}" type="text" placeholder="Reply…" class="studio-comment-input" maxlength="1000"
      onkeydown="if(event.key==='Enter')swPostComment('${swEsc(projectId)}','${swEsc(commentId)}')">
    <button class="studio-comment-post-btn" onclick="swPostComment('${swEsc(projectId)}','${swEsc(commentId)}')">Reply</button>
  </div>`;
  $id(`sw-reply-text-${commentId}`)?.focus();
}

async function swPostComment(projectId, parentId) {
  const inputId = parentId ? `sw-reply-text-${parentId}` : 'sw-comment-input';
  const input   = $id(inputId);
  if (!input) return;
  const body = input.value.trim();
  if (!body) return;
  try {
    await api('POST', `/api/member/studio/projects/${projectId}/comments`, { body, parent_id: parentId||null });
    input.value = '';
    const cResp = await api('GET', `/api/member/studio/projects/${projectId}/comments`);
    const comments = cResp.comments || cResp || [];
    const list = $id('sw-comments-list');
    if (list) list.innerHTML = swRenderComments(comments, projectId);
    if (parentId) { const w=$id(`sw-reply-input-${parentId}`); if(w)w.innerHTML=''; }
  } catch (e) { alert(e.message||'Could not post comment.'); }
}

// ── Reactions ─────────────────────────────────────────────────────────────

async function swToggleReaction(projectId, reactionType) {
  const current = SW.myReactions.get(projectId)||null;
  SW.myReactions.set(projectId, current===reactionType ? null : reactionType);
  swUpdateReactionUI(projectId);
  try {
    const resp = await api('POST', `/api/member/studio/projects/${projectId}/react`, { reaction_type: reactionType });
    // Server returns { active, reaction_type }; sync state with server truth
    SW.myReactions.set(projectId, resp.active ? resp.reaction_type : null);
    swUpdateReactionUI(projectId);
  } catch {
    SW.myReactions.set(projectId, current);
    swUpdateReactionUI(projectId);
  }
}

function swUpdateReactionUI(projectId) {
  const myRxn = SW.myReactions.get(projectId)||null;
  // Update detail modal reactions
  $id(`detail-reactions-${projectId}`)?.querySelectorAll('.studio-rxn-btn').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.rxn === myRxn);
  });
  // Update inline feed like button on ig-post cards
  const feedCard = document.querySelector(`.ig-post[data-project-id="${CSS.escape(projectId)}"]`);
  if (feedCard) {
    const likeBtn = feedCard.querySelector('.ig-like-btn');
    if (likeBtn) {
      const isLiked = !!myRxn;
      likeBtn.classList.toggle('liked', isLiked);
      // Replace only the SVG (last child), keep the reaction popup
      const svg = likeBtn.querySelector('svg');
      if (svg) {
        svg.setAttribute('fill', isLiked ? '#4ba3d4' : 'none');
        svg.setAttribute('stroke', isLiked ? '#4ba3d4' : 'currentColor');
      }
    }
  }
  // Sync overlay active states if it's currently showing for this project
  if (RXN.currentId === projectId) _rxnSyncActive(projectId);
}

// ── Reaction Overlay — single body-level portal ────────────────────────────
// One shared #rxn-overlay div, positioned via getBoundingClientRect().
// Escapes all overflow:hidden / stacking context traps in the card layout.

const RXN = {
  overlay: null,
  pill: null,
  backdrop: null,
  currentId: null,
  showTimer: null,
  hideTimer: null,
};

function _rxnEnsureOverlay() {
  if (RXN.overlay) return;

  // Soft blurred backdrop behind the wheel — dims/blurs the rest of the page while it's open
  const backdrop = document.createElement('div');
  backdrop.id = 'rxn-backdrop';
  document.body.appendChild(backdrop);
  RXN.backdrop = backdrop;

  const el = document.createElement('div');
  el.id = 'rxn-overlay';
  el.innerHTML = `<div class="rxn-wheel">
    <button class="rxn-btn" data-rxn="wow" title="Like">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg></div>
      <span class="rxn-label">Like</span>
    </button>
    <button class="rxn-btn" data-rxn="fire" title="Fire">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0011 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 01-7 7 7 7 0 01-4.5-1.5c1-.5 1.5-1 1-2z"/></svg></div>
      <span class="rxn-label">Fire</span>
    </button>
    <button class="rxn-btn" data-rxn="brilliant" title="Brilliant">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div>
      <span class="rxn-label">Brilliant</span>
    </button>
    <button class="rxn-btn" data-rxn="seahaven" title="Seahaven">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="1" y1="18" x2="3" y2="18"/><line x1="21" y1="18" x2="23" y2="18"/><line x1="18.36" y1="11.64" x2="19.78" y2="10.22"/><line x1="23" y1="22" x2="1" y2="22"/><polyline points="8 6 12 2 16 6"/></svg></div>
      <span class="rxn-label">Seahaven</span>
    </button>
    <button class="rxn-btn" data-rxn="mind_blown" title="Whoa">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div>
      <span class="rxn-label">Whoa</span>
    </button>
  </div>`;
  document.body.appendChild(el);
  RXN.overlay = el;
  RXN.pill = el.querySelector('.rxn-wheel');

  // Delegate clicks on rxn-btn inside overlay
  el.addEventListener('click', e => {
    const btn = e.target.closest('.rxn-btn');
    if (btn && RXN.currentId) {
      e.stopPropagation();
      swToggleReaction(RXN.currentId, btn.dataset.rxn);
      _rxnHideNow();
    }
  });

  // Keep visible when hovering the overlay itself
  el.addEventListener('mouseenter', () => {
    clearTimeout(RXN.hideTimer);
  });
  el.addEventListener('mouseleave', () => {
    _rxnScheduleHide(150);
  });
}

function _rxnPosition(triggerEl) {
  const rect = triggerEl.getBoundingClientRect();
  const wheel = RXN.pill;
  const N = 5;
  // Overlay must be large enough to contain all buttons without clipping.
  // Buttons sit at radius R from the center; each button is BTN wide.
  // Minimum overlay size = 2*(R + BTN/2) + a little padding.
  const BTN = 42;        // must match CSS .rxn-btn width/height
  const R = 56;          // orbit radius — enough gap so buttons don't crowd the center
  const OVERLAY = 2 * (R + BTN / 2) + 16; // dynamic, keeps all buttons inside

  // Sync the overlay element's size so CSS clips nothing
  RXN.overlay.style.width  = `${OVERLAY}px`;
  RXN.overlay.style.height = `${OVERLAY}px`;

  // Position each button evenly around a full 360° circle, starting at 12 o'clock.
  // The overlay's center (OVERLAY/2, OVERLAY/2) will be placed exactly on the
  // like-button's center, so the like hand appears in the middle of the ring.
  wheel.querySelectorAll('.rxn-btn').forEach((btn, i) => {
    const angle = -90 + i * (360 / N);
    const rad = (angle * Math.PI) / 180;
    // cx/cy = top-left corner of button, relative to overlay top-left
    const cx = OVERLAY / 2 + R * Math.cos(rad) - BTN / 2;
    const cy = OVERLAY / 2 + R * Math.sin(rad) - BTN / 2;
    btn.style.left = `${Math.round(cx)}px`;
    btn.style.top  = `${Math.round(cy)}px`;
    // Burst vector for entrance animation
    const dx = (cx + BTN / 2) - OVERLAY / 2;
    const dy = (cy + BTN / 2) - OVERLAY / 2;
    btn.style.setProperty('--dx', `${dx.toFixed(1)}px`);
    btn.style.setProperty('--dy', `${dy.toFixed(1)}px`);
    btn.style.setProperty('--enter-delay', `${i * 30}ms`);
  });

  // Center the overlay exactly on the like button (fixed positioning = viewport coords)
  const btnCx = rect.left + rect.width  / 2;
  const btnCy = rect.top  + rect.height / 2;
  let left = btnCx - OVERLAY / 2;
  let top  = btnCy - OVERLAY / 2;

  // Keep the overlay inside the viewport with a small margin
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  left = Math.max(4, Math.min(left, vw - OVERLAY - 4));
  top  = Math.max(4, Math.min(top,  vh - OVERLAY - 4));

  RXN.overlay.style.left = `${Math.round(left)}px`;
  RXN.overlay.style.top  = `${Math.round(top)}px`;
  RXN.overlay.style.display = 'block';
}

function _rxnSyncActive(projectId) {
  const myRxn = SW.myReactions.get(projectId) || null;
  RXN.pill?.querySelectorAll('.rxn-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.rxn === myRxn);
  });
}

function _rxnShowNow(projectId, triggerEl) {
  _rxnEnsureOverlay();
  RXN.currentId = projectId;
  _rxnSyncActive(projectId);
  _rxnPosition(triggerEl);
  RXN.backdrop.style.display = 'block';
  // Force reflow so transitions play
  RXN.overlay.offsetHeight;
  RXN.overlay.classList.add('visible');
  RXN.backdrop.classList.add('visible');
}

function _rxnHideNow() {
  if (!RXN.overlay) return;
  RXN.overlay.classList.remove('visible');
  RXN.overlay.style.display = 'none';  // fully remove from hit-testing
  RXN.backdrop?.classList.remove('visible');
  if (RXN.backdrop) RXN.backdrop.style.display = 'none';
  RXN.currentId = null;
}

function _rxnScheduleHide(delay = 180) {
  clearTimeout(RXN.hideTimer);
  RXN.hideTimer = setTimeout(_rxnHideNow, delay);
}

// Public API called from HTML attributes
function swShowRxnPopup(projectId) {
  clearTimeout(RXN.hideTimer);
  clearTimeout(RXN.showTimer);
  RXN.showTimer = setTimeout(() => {
    const btn = document.querySelector(`.ig-like-btn[data-project-id="${CSS.escape(projectId)}"]`);
    if (btn) _rxnShowNow(projectId, btn);
  }, 280);
}

function swHideRxnPopup(projectId) {
  clearTimeout(RXN.showTimer);
  _rxnScheduleHide(160);
}

function swCancelHideRxnPopup(projectId) {
  // Legacy — no longer needed (overlay handles its own mouseenter)
  clearTimeout(RXN.hideTimer);
}

// Dismiss on scroll (repositioning on scroll would be expensive)
window.addEventListener('scroll', () => { if (RXN.overlay?.classList.contains('visible')) _rxnHideNow(); }, { passive: true });

// Dismiss when clicking anywhere outside the overlay or the like button
document.addEventListener('click', e => {
  if (!RXN.overlay?.classList.contains('visible')) return;
  if (RXN.overlay.contains(e.target)) return;
  if (e.target.closest('.ig-like-btn')) return;
  _rxnHideNow();
}, true);

// Mobile long-press: attach to feed after render
function swAttachLongPress() {
  document.querySelectorAll('.ig-like-btn[data-project-id]').forEach(btn => {
    if (btn._lpAttached) return;
    btn._lpAttached = true;
    let timer;
    btn.addEventListener('touchstart', () => {
      timer = setTimeout(() => {
        const pid = btn.dataset.projectId;
        _rxnShowNow(pid, btn);
        // Dismiss on outside touch
        const dismiss = (ev) => {
          if (!RXN.overlay?.contains(ev.target) && ev.target !== btn) {
            _rxnHideNow();
            document.removeEventListener('touchstart', dismiss, true);
          }
        };
        setTimeout(() => document.addEventListener('touchstart', dismiss, true), 50);
      }, 420);
    }, { passive: true });
    btn.addEventListener('touchend', () => clearTimeout(timer), { passive: true });
    btn.addEventListener('touchmove', () => clearTimeout(timer), { passive: true });
  });
}



let _composerPostType = 'image'; // 'image' | 'text' | 'video'

function swSetPostType(type) {
  _composerPostType = type;
  // Update type buttons
  document.querySelectorAll('.composer-type-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.postType === type);
  });
  // Show/hide sections
  ['image','text','video'].forEach(t => {
    const s = $id(`section-${t}`); if (s) s.style.display = t === type ? 'flex' : 'none';
  });
}

function _fillComposerAuthor() {
  const d = window._memberProfile || _member || {};
  const name = d.name || '';
  const photo = d.photo || '';
  const avEl = $id('composer-avatar-el');
  if (avEl) {
    if (photo) {
      avEl.innerHTML = `<img src="${swEsc(photo)}" style="width:36px;height:36px;border-radius:50%;object-fit:cover" />`;
    } else {
      avEl.textContent = (name || '?')[0].toUpperCase();
    }
  }
  const nameEl = $id('composer-author-name');
  if (nameEl) nameEl.textContent = name;
}

async function swOpenNewPostModal() {
  _rxnHideNow(); // dismiss reaction wheel if open
  SW.editingProjectId = null;
  const t = $id('studio-modal-title-text'); if(t) t.textContent = 'New Post';
  const s = $id('sw-submit-btn'); if(s) s.textContent = 'Post';
  swResetPostModal();
  swSetPostType('image');
  // Show type row for new posts
  const typeRow = $id('composer-type-row'); if (typeRow) typeRow.style.display = '';
  _fillComposerAuthor();
  const o = $id('studio-post-modal-overlay');
  if (o) { o.style.display = 'flex'; document.body.style.overflow = 'hidden'; }
}

async function swOpenEditModal(projectId) {
  try {
    const p = await api('GET', `/api/member/studio/projects/${projectId}`);
    SW.editingProjectId = projectId;
    const t = $id('studio-modal-title-text'); if(t) t.textContent = 'Edit Post';
    const s = $id('sw-submit-btn'); if(s) s.textContent = 'Save';
    swResetPostModal();
    // Hide type switcher when editing
    const typeRow = $id('composer-type-row'); if (typeRow) typeRow.style.display = 'none';

    // Detect type from stored data
    const hasVideo = !!p.video_url;
    const hasCover = !!p.cover_image;
    const hasCaptionOnly = !p.title && !hasVideo && !hasCover && p.description;
    if (hasVideo) swSetPostType('video');
    else if (hasCaptionOnly) swSetPostType('text');
    else swSetPostType('image');

    // Fill fields
    const f = id => $id(id);
    if (f('sw-title'))  f('sw-title').value  = p.title || '';
    if (f('sw-tags'))   f('sw-tags').value   = (p.tags || []).join(', ');
    if (f('sw-domain')) f('sw-domain').value = p.domain || '';
    // Caption / text
    const captionVal = p.description || '';
    if (f('sw-caption'))       { f('sw-caption').value = captionVal; $id('sw-caption-count').textContent = captionVal.length; }
    if (f('sw-text-body'))     { f('sw-text-body').value = captionVal; $id('sw-text-count').textContent = captionVal.length; }
    if (f('sw-video-caption')) { f('sw-video-caption').value = captionVal; $id('sw-video-caption-count').textContent = captionVal.length; }
    if (f('sw-video-url'))     f('sw-video-url').value = p.video_url || '';
    if (f('sw-video-provider')) f('sw-video-provider').value = p.video_provider || '';
    // Cover image preview
    if (p.cover_image) {
      const img = $id('sw-cover-img'); if (img) { img.src = p.cover_image; img.style.display = ''; }
      const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = 'none';
      const rm = $id('composer-img-remove'); if (rm) rm.style.display = '';
    }
    SW.collabPickerSelected = (p.project_collaborators || []).map(c => c.members).filter(Boolean)
      .map(m => ({ id: m.id, name: m.name, photo: m.photo || null }));
    swRenderCollabPicker();
    _fillComposerAuthor();
    const o = $id('studio-post-modal-overlay'); if (o) { o.style.display = 'flex'; document.body.style.overflow = 'hidden'; }
  } catch(e) { alert('Could not load post for editing: ' + e.message); }
}

function swResetPostModal() {
  // Clear all inputs
  ['sw-title','sw-tags','sw-domain','sw-caption','sw-text-body','sw-video-url','sw-video-caption'].forEach(id => {
    const el = $id(id); if (el) el.value = '';
  });
  ['sw-caption-count','sw-text-count','sw-video-caption-count'].forEach(id => {
    const el = $id(id); if (el) el.textContent = '0';
  });
  const p = $id('sw-video-provider'); if (p) p.value = '';
  const cv = $id('sw-cover'); if (cv) cv.value = '';
  const img = $id('sw-cover-img'); if (img) { img.src = ''; img.style.display = 'none'; }
  const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = '';
  const rm = $id('composer-img-remove'); if (rm) rm.style.display = 'none';
  const err = $id('sw-err'); if (err) err.style.display = 'none';
  SW.collabPickerSelected = [];
  swRenderCollabPicker();
}

async function swSubmitPost() {
  const type     = _composerPostType;
  const title    = ($id('sw-title')?.value || '').trim();
  // Pick description from whichever textarea is active
  let desc = '';
  if (type === 'text')  desc = ($id('sw-text-body')?.value || '').trim();
  else if (type === 'video') desc = ($id('sw-video-caption')?.value || '').trim();
  else desc = ($id('sw-caption')?.value || '').trim();

  const videoUrl = ($id('sw-video-url')?.value || '').trim();
  const provider = $id('sw-video-provider')?.value || '';
  const domain   = ($id('sw-domain')?.value || '').trim();
  const tagsRaw  = ($id('sw-tags')?.value || '').trim();
  const coverFile = $id('sw-cover')?.files?.[0] || null;
  const errEl = $id('sw-err'), btn = $id('sw-submit-btn');

  const showErr = msg => { if (errEl) { errEl.textContent = msg; errEl.style.display = ''; } };

  // Validation: at least something must be present
  if (type === 'text' && !desc) { showErr('Write something to post.'); return; }
  if (type === 'video' && !videoUrl) { showErr('Add a YouTube or Vimeo URL.'); return; }
  if (type === 'image' && !coverFile && !$id('sw-cover-img')?.src) { showErr('Pick a photo to post.'); return; }

  if (btn) { btn.disabled = true; btn.textContent = SW.editingProjectId ? 'Saving…' : 'Posting…'; }
  if (errEl) errEl.style.display = 'none';

  try {
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
    const collabIds = SW.collabPickerSelected.map(m => m.id);
    const fd = new FormData();
    fd.append('title', title || desc.slice(0, 80)); // use first 80 chars of body as title if blank
    fd.append('description', desc);
    fd.append('video_url', videoUrl);
    if (provider) fd.append('video_provider', provider);
    fd.append('domain', domain);
    fd.append('tags', JSON.stringify(tags));
    fd.append('collab_ids', JSON.stringify(collabIds));
    fd.append('post_type', type);
    if (coverFile) fd.append('cover_image', coverFile);

    if (SW.editingProjectId) {
      await api('PUT', `/api/member/studio/projects/${SW.editingProjectId}`, fd, true);
    } else {
      await api('POST', '/api/member/studio/projects', fd, true);
    }
    swClosePostModal();
    await swLoadFeed(true);
    await swLoadMyPosts();
  } catch(e) {
    showErr(e.message || 'Could not save post. Please try again.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = SW.editingProjectId ? 'Save' : 'Post'; }
  }
}

async function swDeletePost(projectId,title) {
  if(!confirm(`Delete "${title}"? This cannot be undone.`))return;
  try {
    await api('DELETE',`/api/member/studio/projects/${projectId}`);
    await swLoadMyPosts();
    await swLoadFeed(true);
  } catch(e){alert('Could not delete: '+e.message);}
}

function swClosePostModal() {
  const o=$id('studio-post-modal-overlay');if(o)o.style.display='none';
  document.body.style.overflow='';
  swResetPostModal();
}

function swCloseDetailModal() {
  const o=$id('studio-detail-modal-overlay');if(o)o.style.display='none';
  document.body.style.overflow='';
  SW.detailProjectId=null;
}

// ── Collaborator Picker ────────────────────────────────────────────────────

let _swCollabTimer=null;

function swRenderCollabPicker() {
  const wrap=$id('sw-collab-picker');if(!wrap)return;
  const chips=SW.collabPickerSelected.map(m=>`<span class="sw-collab-chip">${swAvatar(m.name,m.photo,18)}<span>${swEsc(m.name)}</span><button onclick="swRemoveCollab('${swEsc(m.id)}')" title="Remove">${SW_ICONS.close}</button></span>`).join('');
  wrap.innerHTML=`<div class="sw-collab-wrap">${chips}<input id="sw-collab-input" type="text" placeholder="Search members…" class="sw-collab-input" autocomplete="off" oninput="swCollabSearch(this.value)"></div><div id="sw-collab-dropdown" class="sw-collab-dropdown" style="display:none"></div>`;
}

async function swCollabSearch(q) {
  clearTimeout(_swCollabTimer);
  const dd=$id('sw-collab-dropdown');if(!dd)return;
  if(!q||q.length<2){dd.style.display='none';return;}
  _swCollabTimer=setTimeout(async()=>{
    try {
      const results=await api('GET',`/api/member/studio/members-search?q=${encodeURIComponent(q)}`);
      const filtered=results.filter(m=>!SW.collabPickerSelected.find(s=>s.id===m.id));
      if(!filtered.length){dd.style.display='none';return;}
      dd.style.display='';
      dd.innerHTML=filtered.map(m=>`<div class="sw-collab-option" onclick="swAddCollab('${swEsc(m.id)}','${swEsc(m.name)}','${swEsc(m.photo_url||'')}')">
        ${swAvatar(m.name,m.photo_url,24)}<span>${swEsc(m.name)}</span></div>`).join('');
    } catch{dd.style.display='none';}
  },250);
}

function swAddCollab(id,name,photo) {
  if(!SW.collabPickerSelected.find(m=>m.id===id)) SW.collabPickerSelected.push({id,name,photo:photo||null});
  swRenderCollabPicker();
}

function swRemoveCollab(id) {
  SW.collabPickerSelected=SW.collabPickerSelected.filter(m=>m.id!==id);
  swRenderCollabPicker();
}

// ── Tab switching ──────────────────────────────────────────────────────────

function swSwitchTab(tabName) {
  document.querySelectorAll('.studio-tab').forEach(t=>t.classList.toggle('active',t.dataset.studioTab===tabName));
  document.querySelectorAll('.studio-tab-panel').forEach(p=>p.classList.toggle('active',p.id===`studio-tab-${tabName}`));
  if(tabName==='my-posts')  swLoadMyPosts();
  if(tabName==='analytics') swLoadAnalytics();
}

// ── Init ──────────────────────────────────────────────────────────────────

function initStudioWall() {
  document.querySelectorAll('.studio-tab').forEach(btn=>{
    btn.addEventListener('click',()=>swSwitchTab(btn.dataset.studioTab));
  });

  $id('studio-new-post-btn')?.addEventListener('click', swOpenNewPostModal);
  $id('studio-new-post-btn2')?.addEventListener('click', swOpenNewPostModal);
  $id('studio-post-modal-close')?.addEventListener('click', swClosePostModal);
  $id('studio-post-modal-cancel')?.addEventListener('click', swClosePostModal);
  $id('studio-post-modal-overlay')?.addEventListener('click',e=>{if(e.target===$id('studio-post-modal-overlay'))swClosePostModal();});
  $id('studio-detail-close')?.addEventListener('click', swCloseDetailModal);
  $id('studio-detail-modal-overlay')?.addEventListener('click',e=>{if(e.target===$id('studio-detail-modal-overlay'))swCloseDetailModal();});
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'){
      if($id('studio-detail-modal-overlay')?.style.display==='flex')swCloseDetailModal();
      if($id('studio-post-modal-overlay')?.style.display==='flex')swClosePostModal();
    }
  });
  $id('sw-submit-btn')?.addEventListener('click', swSubmitPost);

  // Post type picker (Photo / Text / Video)
  document.querySelectorAll('.composer-type-btn').forEach(btn => {
    btn.addEventListener('click', () => swSetPostType(btn.dataset.postType));
  });

  // Tap the image zone (anywhere except the remove button) to open the file picker
  $id('composer-img-zone')?.addEventListener('click', e => {
    if (e.target.closest('#composer-img-remove')) return;
    $id('sw-cover')?.click();
  });

  // Remove the selected/loaded photo and go back to the placeholder state
  $id('composer-img-remove')?.addEventListener('click', e => {
    e.stopPropagation();
    const cv = $id('sw-cover'); if (cv) cv.value = '';
    const img = $id('sw-cover-img'); if (img) { img.src = ''; img.style.display = 'none'; }
    const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = '';
    e.currentTarget.style.display = 'none';
  });

  $id('sw-cover')?.addEventListener('change', e => {
    const f = e.target.files?.[0]; if (!f) return;
    const img = $id('sw-cover-img');
    const ph  = $id('composer-img-placeholder');
    const rm  = $id('composer-img-remove');
    if (img) { img.src = URL.createObjectURL(f); img.style.display = ''; }
    if (ph) ph.style.display = 'none';
    if (rm) rm.style.display = '';
  });
  $id('sw-desc')?.addEventListener('input',e=>{const c=$id('sw-desc-count');if(c)c.textContent=e.target.value.length;});

  let _tagTimer=null;
  $id('studio-tag-filter')?.addEventListener('input',e=>{
    clearTimeout(_tagTimer);
    _tagTimer=setTimeout(()=>{SW.feedTag=e.target.value.trim().toLowerCase()||null;swLoadFeed(true);},400);
  });
  $id('studio-load-more-btn')?.addEventListener('click',()=>swLoadFeed(false));

  // Smart feed — Latest / For You (Phase 2)
  $id('feed-sort-toggle')?.addEventListener('click', e => {
    const btn = e.target.closest('.feed-sort-btn');
    if (!btn || btn.classList.contains('active')) return;
    document.querySelectorAll('.feed-sort-btn').forEach(b => b.classList.toggle('active', b === btn));
    SW.feedSort = btn.dataset.feedSort === 'foryou' ? 'foryou' : 'latest';
    swLoadFeed(true);
  });

  // Load feed when Studio panel becomes active
  const panelEl=$id('panel-studio');
  if(panelEl){
    const obs=new MutationObserver(muts=>{
      muts.forEach(m=>{if(m.attributeName==='class'&&panelEl.classList.contains('active'))swLoadFeed(true);});
    });
    obs.observe(panelEl,{attributes:true});
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Network — Follow system (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const NW = {
  followersPage: 1, followersExhausted: false, followersLoading: false,
  followingPage: 1, followingExhausted: false, followingLoading: false,
  myFollowing: new Map(), // memberId → bool (local optimistic cache)
  profileMemberId: null,
};

function nwMyId() {
  return window._memberProfile?.id || window._member?.id || null;
}

// Maps a status slug (set by the Member Status feature) to its display label.
// Kept here too — not just in the status-editor UI — since follower/following
// rows and the mini-profile modal need to render it wherever it appears.
function nwStatusLabel(status) {
  const map = { open_to_collab: 'Open to collab', busy_on_set: 'Busy on set', alumni_mentor: 'Alumni mentor' };
  return map[status] || null;
}

function nwFollowBtn(m) {
  const myId = nwMyId();
  if (!m.id || m.id === myId) return '';
  const isFollowing = NW.myFollowing.has(m.id) ? NW.myFollowing.get(m.id) : !!m.is_following;
  return `<button class="nw-follow-btn ${isFollowing?'following':''}" data-member-id="${swEsc(m.id)}" onclick="event.stopPropagation();toggleFollow('${swEsc(m.id)}',this)">${isFollowing?'Following':'Follow'}</button>`;
}

function nwRenderRow(m) {
  const statusLabel = nwStatusLabel(m.status);
  return `<div class="nw-row" data-row-member="${swEsc(m.id)}">
    <span class="nw-row-info" onclick="openMemberProfile('${swEsc(m.id)}')">
      ${swAvatar(m.name, m.photo, 36)}
      <span>
        <div class="nw-row-name">${swEsc(m.name||'Member')}${statusLabel?`<span class="nw-status-pill">${swEsc(statusLabel)}</span>`:''}</div>
        <div class="nw-row-meta">${swEsc(m.role || m.domain || '')}</div>
      </span>
    </span>
    ${nwFollowBtn(m)}
  </div>`;
}

async function nwLoadFollowers(reset = false) {
  const myId = nwMyId();
  if (!myId) return;
  if (NW.followersLoading) return;
  if (!reset && NW.followersExhausted) return;
  if (reset) { NW.followersPage = 1; NW.followersExhausted = false; }
  const list = $id('network-followers-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  NW.followersLoading = true;
  try {
    const resp = await api('GET', `/api/member/network/followers/${myId}?page=${NW.followersPage}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, m.is_following));
    if (reset) list.innerHTML = '';
    if (!members.length && NW.followersPage === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No followers yet</div><div class="sw-empty-sub">Share work on the Social Strand to get noticed.</div></div>`;
      hideEl('network-followers-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('network-followers-more'); NW.followersPage++; }
    else { hideEl('network-followers-more'); NW.followersExhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load followers.</div>`;
  } finally {
    NW.followersLoading = false;
  }
}

async function nwLoadFollowing(reset = false) {
  const myId = nwMyId();
  if (!myId) return;
  if (NW.followingLoading) return;
  if (!reset && NW.followingExhausted) return;
  if (reset) { NW.followingPage = 1; NW.followingExhausted = false; }
  const list = $id('network-following-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  NW.followingLoading = true;
  try {
    const resp = await api('GET', `/api/member/network/following/${myId}?page=${NW.followingPage}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, true)); // by definition, people I follow
    if (reset) list.innerHTML = '';
    if (!members.length && NW.followingPage === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">Not following anyone yet</div><div class="sw-empty-sub">Follow members from their posts on the Social Strand.</div></div>`;
      hideEl('network-following-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('network-following-more'); NW.followingPage++; }
    else { hideEl('network-following-more'); NW.followingExhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load following.</div>`;
  } finally {
    NW.followingLoading = false;
  }
}

function loadNetworkPanel() {
  nwLoadFollowers(true);
  nwLoadFollowing(true);
}

function nwSwitchTab(tabName) {
  document.querySelectorAll('.nw-tab').forEach(t=>t.classList.toggle('active', t.dataset.networkTab===tabName));
  document.querySelectorAll('.nw-tab-panel').forEach(p=>p.classList.toggle('active', p.id===`network-tab-${tabName}`));
  if (tabName === 'discover')    loadDiscoverTab();
  if (tabName === 'leaderboard') loadLeaderboardTab();
  if (tabName === 'collab')      loadMyCollabs();
}

// ── Follow toggle — called from feed cards, member rows, and the mini-profile modal ──
async function toggleFollow(memberId, btnEl) {
  if (!memberId || btnEl?.disabled) return;
  if (btnEl) btnEl.disabled = true;
  try {
    const resp = await api('POST', `/api/member/network/follow/${memberId}`);
    NW.myFollowing.set(memberId, resp.following);
    // Update every rendered follow button for this member (feed cards, lists, modal)
    document.querySelectorAll(`.nw-follow-btn[data-member-id="${memberId}"]`).forEach(b => {
      b.classList.toggle('following', resp.following);
      b.textContent = resp.following ? 'Following' : 'Follow';
      b.disabled = false;
    });
    const statFollowers = $id('mpm-stat-followers');
    if (statFollowers && NW.profileMemberId === memberId) statFollowers.textContent = swFmtNum(resp.followers_count);
    // Following list membership just changed — refresh it next time that tab is visited
    NW.followingExhausted = false;
  } catch (e) {
    if (btnEl) btnEl.disabled = false;
    alert(e.message || 'Could not update follow status.');
  }
}

// ── Member mini-profile modal ────────────────────────────────────────────
async function openMemberProfile(memberId) {
  if (!memberId) return;
  NW.profileMemberId = memberId;
  const overlay = $id('member-profile-modal-overlay');
  const body    = $id('member-profile-modal-body');
  if (!overlay || !body) return;
  body.innerHTML = '<div class="sw-loading" style="padding:40px 0;text-align:center">Loading…</div>';
  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
  try {
    const m = await api('GET', `/api/member/network/profile/${memberId}`);
    NW.myFollowing.set(m.id, m.is_following);
    const statusLabel = nwStatusLabel(m.status);
    body.innerHTML = `
      <div class="mpm-head">
        ${swAvatar(m.name, m.photo, 64)}
        <div>
          <div class="mpm-name">${swEsc(m.name||'Member')}${statusLabel?`<span class="nw-status-pill">${swEsc(statusLabel)}</span>`:''}</div>
          <div class="mpm-role">${swEsc([m.role, m.domain].filter(Boolean).join(' · '))}</div>
        </div>
      </div>
      ${m.bio ? `<div class="mpm-bio">${swEsc(m.bio)}</div>` : ''}
      <div class="mpm-stats">
        <div class="mpm-stat"><div class="mpm-stat-val" id="mpm-stat-followers">${swFmtNum(m.followers_count)}</div><div class="mpm-stat-label">Followers</div></div>
        <div class="mpm-stat"><div class="mpm-stat-val">${swFmtNum(m.following_count)}</div><div class="mpm-stat-label">Following</div></div>
      </div>
      ${m.skills?.length ? `<div class="mpm-skills">${m.skills.map(s=>`<span class="mpm-skill-chip" onclick="closeMemberProfileModal();discFilterBySkill('${swEsc(s.name)}')" style="cursor:pointer">${swEsc(s.name)}</span>`).join('')}</div>` : ''}
      ${m.is_self ? '' : `<button class="nw-follow-btn ${m.is_following?'following':''}" id="mpm-follow-btn" data-member-id="${swEsc(m.id)}" style="width:100%;padding:11px" onclick="toggleFollow('${swEsc(m.id)}',this)">${m.is_following?'Following':'Follow'}</button>`}
    `;
  } catch (e) {
    body.innerHTML = `<div style="padding:32px;text-align:center;color:var(--muted);font-size:14px">${swEsc(e.message)}</div>`;
  }
}

function closeMemberProfileModal() {
  hideEl('member-profile-modal-overlay');
  document.body.style.overflow = '';
  NW.profileMemberId = null;
}

function initNetworkModule() {
  document.querySelectorAll('.nw-tab').forEach(btn => {
    btn.addEventListener('click', () => nwSwitchTab(btn.dataset.networkTab));
  });
  $id('network-followers-more-btn')?.addEventListener('click', () => nwLoadFollowers(false));
  $id('network-following-more-btn')?.addEventListener('click', () => nwLoadFollowing(false));
  $id('member-profile-modal-close')?.addEventListener('click', closeMemberProfileModal);
  $id('member-profile-modal-overlay')?.addEventListener('click', e => {
    if (e.target === $id('member-profile-modal-overlay')) closeMemberProfileModal();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $id('member-profile-modal-overlay')?.style.display === 'flex') closeMemberProfileModal();
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Member status (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

// Renders the active pill in the Profile panel's status picker.
// (nwStatusLabel(), above, renders the same slugs as a read-only pill
// wherever a member's status shows up elsewhere — feed cards, rows, modal.)
function renderStatusPicker(status) {
  document.querySelectorAll('#status-picker .status-pill-btn').forEach(b => {
    const isClear = b.classList.contains('status-pill-clear');
    b.classList.toggle('active', !isClear && b.dataset.status === (status || ''));
  });
}

async function setMemberStatus(status) {
  const picker = $id('status-picker');
  picker?.querySelectorAll('.status-pill-btn').forEach(b => b.disabled = true);
  hideEl('status-err');
  try {
    const resp = await api('POST', '/api/member/network/status', { status: status || null });
    renderStatusPicker(resp.status);
    if (window._memberProfile) window._memberProfile.status = resp.status;
    showMsg('status-msg', resp.status ? 'Status updated.' : 'Status cleared.');
  } catch (e) {
    showMsg('status-err', e.message || 'Could not update status.', false);
  } finally {
    picker?.querySelectorAll('.status-pill-btn').forEach(b => b.disabled = false);
  }
}

function initStatusModule() {
  $id('status-picker')?.addEventListener('click', e => {
    const btn = e.target.closest('.status-pill-btn');
    if (!btn || btn.disabled) return;
    const isClear = btn.classList.contains('status-pill-clear');
    if (!isClear && btn.classList.contains('active')) return; // already set — no-op
    setMemberStatus(isClear ? null : btn.dataset.status);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Skills / Interest graph (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const SKILLS = { mine: [], suggestTimer: null };

function skillChipHtml(tag) {
  return `<span class="skill-chip" data-tag-id="${swEsc(tag.id)}">${swEsc(tag.name)}<button type="button" class="skill-chip-remove" onclick="removeSkill('${swEsc(tag.id)}')" title="Remove" aria-label="Remove ${swEsc(tag.name)}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></span>`;
}

function renderSkillChips() {
  const wrap = $id('skill-chips');
  if (!wrap) return;
  if (!SKILLS.mine.length) {
    wrap.innerHTML = `<div class="skill-chip-empty">No skills tagged yet — add up to ${12} above.</div>`;
    return;
  }
  wrap.innerHTML = SKILLS.mine.map(skillChipHtml).join('');
}

async function loadMySkills() {
  try {
    SKILLS.mine = await api('GET', '/api/member/skills/mine');
    renderSkillChips();
  } catch (e) {
    console.error('loadMySkills:', e);
  }
}

async function addSkill(name) {
  const clean = (name || '').trim();
  if (!clean) return;
  hideEl('skill-err');
  try {
    const resp = await api('POST', '/api/member/skills', { name: clean });
    if (!SKILLS.mine.some(t => t.id === resp.tag.id)) {
      SKILLS.mine.push(resp.tag);
      renderSkillChips();
    }
    const input = $id('skill-input');
    if (input) input.value = '';
    hideEl('skill-suggestions');
  } catch (e) {
    showMsg('skill-err', e.message || 'Could not add skill.', false);
  }
}

async function removeSkill(tagId) {
  try {
    await api('DELETE', `/api/member/skills/${tagId}`);
    SKILLS.mine = SKILLS.mine.filter(t => t.id !== tagId);
    renderSkillChips();
  } catch (e) {
    showMsg('skill-err', e.message || 'Could not remove skill.', false);
  }
}

async function showSkillSuggestions(q) {
  const box = $id('skill-suggestions');
  if (!box) return;
  try {
    const results = await api('GET', `/api/member/skills/search?q=${encodeURIComponent(q)}`);
    const mineIds = new Set(SKILLS.mine.map(t => t.id));
    const filtered = results.filter(r => !mineIds.has(r.id));
    let html = filtered.map(r => `<div class="skill-suggestion-item" onclick="addSkill('${swEsc(r.name)}')"><span>${swEsc(r.name)}</span><span class="skill-suggestion-count">${swFmtNum(r.usage_count)} ${r.usage_count===1?'member':'members'}</span></div>`).join('');
    if (q && !results.some(r => r.name.toLowerCase() === q.toLowerCase())) {
      html += `<div class="skill-suggestion-item skill-suggestion-create" onclick="addSkill('${swEsc(q)}')">+ Add "${swEsc(q)}"</div>`;
    }
    if (!html) { hideEl('skill-suggestions'); return; }
    box.innerHTML = html;
    box.style.display = 'block';
  } catch (e) {
    hideEl('skill-suggestions');
  }
}

function initSkillsModule() {
  const input = $id('skill-input');
  if (!input) return;
  input.addEventListener('input', () => {
    clearTimeout(SKILLS.suggestTimer);
    const v = input.value.trim();
    if (!v) { hideEl('skill-suggestions'); return; }
    SKILLS.suggestTimer = setTimeout(() => showSkillSuggestions(v), 300);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addSkill(input.value); }
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.skill-input-wrap')) hideEl('skill-suggestions');
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Discovery & Explore (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const DISC = { facetsLoaded: false, page: 1, exhausted: false, loading: false };

async function discLoadFacets() {
  if (DISC.facetsLoaded) return;
  try {
    const { domains, batches } = await api('GET', '/api/member/network/facets');
    const dSel = $id('discover-domain-filter');
    const bSel = $id('discover-batch-filter');
    if (dSel) dSel.insertAdjacentHTML('beforeend', (domains||[]).map(d => `<option value="${swEsc(d)}">${swEsc(d)}</option>`).join(''));
    if (bSel) bSel.insertAdjacentHTML('beforeend', (batches||[]).map(b => `<option value="${swEsc(b)}">${swEsc(b)}</option>`).join(''));
    DISC.facetsLoaded = true;
  } catch (e) { console.error('discLoadFacets:', e); }
}

async function discLoadTrending() {
  const row = $id('discover-trending-row');
  if (!row) return;
  try {
    const { trending } = await api('GET', '/api/member/network/trending');
    if (!trending.length) { row.innerHTML = `<div class="skill-chip-empty">Nothing trending yet — be the first to post.</div>`; return; }
    row.innerHTML = trending.map(p => {
      const author = p.members || {};
      return `<div class="discover-trend-card" onclick="swOpenDetail('${swEsc(p.id)}')">
        <div class="discover-trend-media">${p.cover_image ? `<img src="${swEsc(p.cover_image)}" loading="lazy" alt="${swEsc(p.title)}">` : ''}</div>
        <div class="discover-trend-title">${swEsc(p.title)}</div>
        <div class="discover-trend-meta">${swEsc(author.name||'Member')} · ${swFmtNum(p.trending_score)} reactions/48h</div>
      </div>`;
    }).join('');
  } catch (e) {
    row.innerHTML = `<div class="sw-error">Could not load trending posts.</div>`;
  }
}

async function discLoadNewJoiners() {
  const row = $id('discover-newjoiners-row');
  if (!row) return;
  try {
    const joiners = await api('GET', '/api/member/network/new-joiners');
    if (!joiners.length) { row.innerHTML = `<div class="skill-chip-empty">No new joiners yet.</div>`; return; }
    row.innerHTML = joiners.map(m => `<div class="discover-joiner-card" onclick="openMemberProfile('${swEsc(m.id)}')">
        ${swAvatar(m.name, m.photo, 56)}
        <div class="discover-joiner-name">${swEsc(m.name||'Member')}</div>
        <div class="discover-joiner-meta">${swEsc(m.role || m.domain || '')}</div>
      </div>`).join('');
  } catch (e) {
    row.innerHTML = `<div class="sw-error">Could not load new joiners.</div>`;
  }
}

async function discLoadMembers(reset = false) {
  if (DISC.loading) return;
  if (!reset && DISC.exhausted) return;
  if (reset) { DISC.page = 1; DISC.exhausted = false; }
  const list = $id('discover-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  DISC.loading = true;
  try {
    const params = new URLSearchParams({ page: DISC.page });
    const q      = $id('discover-search')?.value.trim();
    const domain = $id('discover-domain-filter')?.value;
    const batch  = $id('discover-batch-filter')?.value;
    const skill  = $id('discover-skill-filter')?.value.trim();
    if (q)      params.set('q', q);
    if (domain) params.set('domain', domain);
    if (batch)  params.set('batch', batch);
    if (skill)  params.set('skill', skill);

    const resp = await api('GET', `/api/member/network/discover?${params.toString()}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, m.is_following));
    if (reset) list.innerHTML = '';
    if (!members.length && DISC.page === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No members match</div><div class="sw-empty-sub">Try a different filter.</div></div>`;
      hideEl('discover-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('discover-more'); DISC.page++; }
    else { hideEl('discover-more'); DISC.exhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load members.</div>`;
  } finally {
    DISC.loading = false;
  }
}

function loadDiscoverTab() {
  discLoadFacets();
  discLoadTrending();
  discLoadNewJoiners();
  discLoadMembers(true);
}

// Jump to Network → Discover, pre-filtered by a skill (called from a skill
// chip on the mini-profile modal).
function discFilterBySkill(skillName) {
  const input = $id('discover-skill-filter');
  if (input) input.value = skillName;
  const navNetwork = document.querySelector('.nav-item[data-panel="network"]');
  if (navNetwork) switchPanel(navNetwork);
  nwSwitchTab('discover');
}

function initDiscoverModule() {
  let searchTimer = null;
  const debouncedReload = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => discLoadMembers(true), 350); };
  $id('discover-search')?.addEventListener('input', debouncedReload);
  $id('discover-skill-filter')?.addEventListener('input', debouncedReload);
  $id('discover-domain-filter')?.addEventListener('change', () => discLoadMembers(true));
  $id('discover-batch-filter')?.addEventListener('change', () => discLoadMembers(true));
  $id('discover-more-btn')?.addEventListener('click', () => discLoadMembers(false));
}

// ═══════════════════════════════════════════════════════════════════════════
// Leaderboard / Hall of fame (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const LB = { period: 'weekly' };

function lbRankClass(rank) {
  if (rank === 1) return 'lb-rank-1';
  if (rank === 2) return 'lb-rank-2';
  if (rank === 3) return 'lb-rank-3';
  return '';
}

async function lbLoad() {
  const list = $id('lb-list');
  if (!list) return;
  list.innerHTML = '<div class="sw-loading">Loading…</div>';
  hideEl('lb-my-rank');
  try {
    const resp = await api('GET', `/api/member/network/leaderboard?period=${LB.period}`);
    const rows = resp.leaderboard || [];
    if (!rows.length) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No wows yet</div><div class="sw-empty-sub">${LB.period==='weekly' ? 'Check back once posts start getting reactions this week.' : 'The hall of fame fills up once posts start earning wow reactions.'}</div></div>`;
      return;
    }
    const wowIcon = SW_REACTIONS.find(r => r.type === 'wow')?.icon || '';
    list.innerHTML = rows.map(m => `<div class="lb-row" onclick="openMemberProfile('${swEsc(m.id)}')">
        <div class="lb-rank ${lbRankClass(m.rank)}">${m.rank}</div>
        ${swAvatar(m.name, m.photo, 36)}
        <div class="lb-info">
          <div class="lb-name">${swEsc(m.name||'Member')}</div>
          <div class="lb-meta">${swEsc(m.role || m.domain || '')}</div>
        </div>
        <div class="lb-wows">${wowIcon}${swFmtNum(m.wows_received)}</div>
      </div>`).join('');
    if (resp.my_rank) {
      const banner = $id('lb-my-rank');
      if (banner) { banner.style.display = 'block'; banner.textContent = `You're #${resp.my_rank} ${LB.period==='weekly' ? 'this week' : 'all-time'}.`; }
    }
  } catch (e) {
    list.innerHTML = `<div class="sw-error">Could not load the leaderboard.</div>`;
  }
}

function loadLeaderboardTab() { lbLoad(); }

function initLeaderboardModule() {
  document.querySelectorAll('.lb-period-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.classList.contains('active')) return;
      document.querySelectorAll('.lb-period-btn').forEach(b => b.classList.toggle('active', b === btn));
      LB.period = btn.dataset.lbPeriod === 'all_time' ? 'all_time' : 'weekly';
      lbLoad();
    });
  });
}

if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded',()=>{
    initStudioWall(); initNetworkModule();
    initStatusModule(); initSkillsModule(); initDiscoverModule(); initLeaderboardModule();
  });
}else{
  initStudioWall(); initNetworkModule();
  initStatusModule(); initSkillsModule(); initDiscoverModule(); initLeaderboardModule();
}

// ═══════════════════════════════════════════════════════════════════════════
// DM CHAT MODULE
// Uses member_notifications (type="dm") — zero new DB tables.
// conv_key = "<smaller_uuid>:<larger_uuid>" (deterministic pair key)
// ═══════════════════════════════════════════════════════════════════════════

const DM = {
  convs:         [],    // loaded conversations
  activeKey:     null,  // current conv_key
  activePeer:    null,  // { id, name, photo, role, batch, domain }
  msgs:          [],    // messages in active convo
  oldestSentAt:  null,  // for "load earlier" pagination
  poll:          null,  // setInterval handle
  members:       [],    // cached member list for picker
  pickerTimer:   null,
  panelVisible:  false,
  pendingBodies: new Set(), // bodies of in-flight optimistic messages (for poll dedup)
  loadingMsgs:   false,     // true while initial dmLoadMsgs fetch is in flight
};

const DM_POLL = 5000; // ms

// ─── Helpers ─────────────────────────────────────────────────────────────────

function dmMyId() {
  return window._memberProfile?.id || _member?.id || null;
}

function dmAvatar(name, photo, size) {
  if (photo) return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;background:#1e1e1e">`;
  const init = (name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
  return `<div class="dm-av-placeholder" style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size * .36)}px;font-weight:700;color:#666;flex-shrink:0">${swEsc(init)}</div>`;
}

function dmTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
  if (diff < 7 * 86400000) return `${Math.floor(diff / 86400000)}d`;
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

function dmFull(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ─── Badge ────────────────────────────────────────────────────────────────────

function dmSetBadge(n) {
  const show = n > 0;
  const label = n > 99 ? '99+' : String(n);
  [$id('dm-nav-badge'), $id('dm-btb-badge')].forEach(el => {
    if (!el) return;
    el.style.display = show ? '' : 'none';
    el.textContent = label;
  });
}

async function dmRefreshBadge() {
  if (!_token) return; // session not restored yet — avoid a guaranteed 401 during boot
  try {
    const d = await api('GET', '/api/member/dm/unread-count');
    dmSetBadge(d.count || 0);
  } catch { /* silent */ }
}

// ─── Conversation list ────────────────────────────────────────────────────────

async function dmLoadConvs() {
  try {
    const data = await api('GET', '/api/member/dm/conversations');
    DM.convs = data || [];
    dmRenderConvs(DM.convs);
    const total = DM.convs.reduce((s, c) => s + (c.unread_count || 0), 0);
    dmSetBadge(total);
  } catch (e) {
    console.error('[DM] loadConvs:', e.message);
  }
}

function dmRenderConvs(list) {
  const container = $id('dm-conv-list');
  if (!container) return;
  $id('dm-conv-loading') && ($id('dm-conv-loading').style.display = 'none');

  // Remove old rows
  container.querySelectorAll('.dm-conv-row').forEach(el => el.remove());

  if (!list || list.length === 0) {
    $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = '');
    return;
  }
  $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = 'none');

  list.forEach(c => {
    const row = document.createElement('div');
    row.className = 'dm-conv-row' + (c.conv_key === DM.activeKey ? ' dm-active-row' : '');
    row.dataset.key = c.conv_key;
    const preview = c.last_snippet
      ? (c.last_sender_is_me ? 'You: ' : '') + c.last_snippet
      : 'No messages yet';
    row.innerHTML = `
      ${dmAvatar(c.peer?.name, c.peer?.photo, 42)}
      <div class="dm-conv-info">
        <div class="dm-conv-name">${swEsc(c.peer?.name || 'Member')}</div>
        <div class="dm-conv-preview ${c.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
      </div>
      <div class="dm-conv-right">
        <span class="dm-conv-time">${dmTime(c.last_msg_at)}</span>
        ${c.unread_count > 0 ? `<span class="dm-unread-pill">${c.unread_count > 9 ? '9+' : c.unread_count}</span>` : ''}
      </div>`;
    row.addEventListener('click', () => dmOpenConv(c));
    container.appendChild(row);
  });
}

// ─── Open a conversation ──────────────────────────────────────────────────────

async function dmOpenConv(conv) {
  DM.activeKey   = conv.conv_key;
  DM.activePeer  = conv.peer;
  DM.msgs        = [];
  DM.oldestSentAt = null;

  // Highlight row
  document.querySelectorAll('.dm-conv-row').forEach(el => {
    el.classList.toggle('dm-active-row', el.dataset.key === conv.conv_key);
  });

  // Topbar
  const ta = $id('dm-topbar-avatar');
  if (ta) ta.innerHTML = dmAvatar(conv.peer?.name, conv.peer?.photo, 34);
  setText('dm-topbar-name', conv.peer?.name || 'Member');
  setText('dm-topbar-sub', [conv.peer?.role, conv.peer?.batch || conv.peer?.domain].filter(Boolean).join(' · '));

  // Show window, hide empty state
  $id('dm-window-empty') && ($id('dm-window-empty').style.display = 'none');
  $id('dm-active') && ($id('dm-active').style.display = 'flex');

  // Mobile slide
  $id('dm-sidebar')?.classList.add('dm-slide-out');
  $id('dm-window')?.classList.add('dm-slide-in');

  await dmLoadMsgs(false);
  $id('dm-input')?.focus();
}

// Open or create a conversation with a member by ID (called from Network cards)
async function dmStartWith(memberId, peerHint) {
  const navEl = document.querySelector('[data-panel="dms"]');
  if (navEl) switchPanel(navEl);
  document.querySelectorAll('.btb-item').forEach(el => {
    el.classList.toggle('active', el.dataset.panel === 'dms');
  });

  // Check if conversation already exists
  const existing = DM.convs.find(c => c.peer?.id === memberId);
  if (existing) { dmOpenConv(existing); return; }

  // No existing — show chat UI optimistically, conv created on first message
  DM.activeKey  = null;
  DM.activePeer = peerHint || { id: memberId, name: 'Member', photo: null };
  DM.msgs       = [];

  const ta = $id('dm-topbar-avatar');
  if (ta) ta.innerHTML = dmAvatar(DM.activePeer.name, DM.activePeer.photo, 34);
  setText('dm-topbar-name', DM.activePeer.name || 'Member');
  setText('dm-topbar-sub', [DM.activePeer.role, DM.activePeer.batch || DM.activePeer.domain].filter(Boolean).join(' · '));

  $id('dm-window-empty') && ($id('dm-window-empty').style.display = 'none');
  $id('dm-active') && ($id('dm-active').style.display = 'flex');
  $id('dm-msg-list') && ($id('dm-msg-list').innerHTML = '');
  $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
  $id('dm-sidebar')?.classList.add('dm-slide-out');
  $id('dm-window')?.classList.add('dm-slide-in');
  $id('dm-input')?.focus();
}

// ─── Load messages ────────────────────────────────────────────────────────────

async function dmLoadMsgs(prepend) {
  if (!DM.activeKey) return;
  if (!prepend) DM.loadingMsgs = true;
  try {
    const myId = dmMyId();
    let url = `/api/member/dm/messages/${encodeURIComponent(DM.activeKey)}?limit=40`;
    if (prepend && DM.oldestSentAt) url += `&before=${encodeURIComponent(DM.oldestSentAt)}`;

    const msgs = await api('GET', url);
    if (!msgs || !msgs.length) {
      if (prepend) $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
      return;
    }

    if (prepend) {
      // Preserve any optimistic messages already in DM.msgs that aren't in the fetched set
      const fetchedIds = new Set(msgs.map(m => m.id));
      const optimistic = DM.msgs.filter(m => m.id.startsWith('tmp-') && !fetchedIds.has(m.id));
      DM.msgs = [...msgs, ...DM.msgs.filter(m => !fetchedIds.has(m.id) && !m.id.startsWith('tmp-')), ...optimistic];
    } else {
      // Preserve any optimistic (tmp) messages that were added while this fetch was in flight
      const optimistic = DM.msgs.filter(m => m.id.startsWith('tmp-'));
      const fetchedIds = new Set(msgs.map(m => m.id));
      // Also preserve confirmed messages that arrived via poll but aren't in this batch
      DM.msgs = [...msgs, ...optimistic].filter((m, i, arr) =>
        !fetchedIds.has(m.id) || arr.findIndex(x => x.id === m.id) === i
      );
      // Sort: confirmed msgs first (by sent_at), optimistic at end
      DM.msgs.sort((a, b) => {
        const aOpt = a.id.startsWith('tmp-');
        const bOpt = b.id.startsWith('tmp-');
        if (aOpt && !bOpt) return 1;
        if (!aOpt && bOpt) return -1;
        return new Date(a.sent_at) - new Date(b.sent_at);
      });
    }
    DM.oldestSentAt = DM.msgs.find(m => !m.id.startsWith('tmp-'))?.sent_at || null;

    const list = $id('dm-msg-list');
    if (!list) return;

    if (!prepend) {
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
    } else {
      const area    = $id('dm-msgs');
      const prevH   = area.scrollHeight;
      const prevTop = area.scrollTop;
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      area.scrollTop = area.scrollHeight - prevH + prevTop;
    }

    const moreWrap = $id('dm-load-earlier-wrap');
    if (moreWrap) moreWrap.style.display = msgs.length >= 40 ? '' : 'none';

    // Zero this conv's unread in local state & refresh badge
    const conv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (conv) conv.unread_count = 0;
    const total = DM.convs.reduce((s, c) => s + (c.unread_count || 0), 0);
    dmSetBadge(total);
    // Re-render conv list to clear unread pill
    dmRenderConvs(DM.convs);
  } catch (e) {
    console.error('[DM] loadMsgs:', e.message);
  } finally {
    if (!prepend) DM.loadingMsgs = false;
  }
}

function dmRenderMsgs(msgs, container, myId, lastSenderHint) {
  // Group consecutive messages from same sender.
  // lastSenderHint: pass the sender_id of the last message already in the DOM
  // so incremental appends can continue an existing group instead of creating a new one.
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild
    : null;

  msgs.forEach(m => {
    const mine = m.sender_id === myId;
    const senderKey = m.sender_id;

    if (senderKey !== lastSender || !group) {
      group = document.createElement('div');
      group.className = `dm-msg-group ${mine ? 'mine' : 'theirs'}`;
      container.appendChild(group);
      lastSender = senderKey;
    }

    const isDeleted = m.body === '[deleted]';
    const bubble = document.createElement('div');
    bubble.className = `dm-bubble${isDeleted ? ' dm-deleted' : ''}`;
    bubble.textContent = m.body;

    const meta = document.createElement('div');
    meta.className = 'dm-meta';
    meta.innerHTML = `<span class="dm-msg-time">${dmFull(m.sent_at)}</span>${mine && !isDeleted ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

    const delBtn = meta.querySelector('.dm-del-btn');
    if (delBtn) {
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dmDeleteMsg(m.id, bubble, delBtn);
      });
    }

    group.appendChild(bubble);
    group.appendChild(meta);
  });
}

function dmScrollBottom() {
  const el = $id('dm-msgs');
  if (el) el.scrollTop = el.scrollHeight;
}

// ─── Send ─────────────────────────────────────────────────────────────────────

async function dmSend() {
  const input = $id('dm-input');
  if (!input) return;
  const body = input.value.trim();
  if (!body) return;

  const peerId = DM.activePeer?.id;
  if (!peerId) return;

  // If history is still loading (race: user typed before initial load finished),
  // disable the send button briefly and retry once the load clears
  if (DM.loadingMsgs) {
    const btn = $id('dm-send-btn');
    if (btn) btn.disabled = true;
    const waitForLoad = () => new Promise(resolve => {
      const check = () => { if (!DM.loadingMsgs) resolve(); else setTimeout(check, 50); };
      check();
    });
    await waitForLoad();
    if (btn) btn.disabled = false;
  }

  // Optimistic bubble
  const myId  = dmMyId();
  const tmpId = 'tmp-' + Date.now();
  const tmp   = { id: tmpId, sender_id: myId, body, sent_at: new Date().toISOString(), read_at: null };
  DM.msgs.push(tmp);
  // Tell the poll not to re-append this message body while the request is in-flight
  DM.pendingBodies.add(body);

  const list = $id('dm-msg-list');
  // Pass the previous sender so incremental append continues the right group
  const lastRenderedSender = DM.msgs.length > 1 ? DM.msgs[DM.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    dmRenderMsgs([tmp], list, myId, lastRenderedSender);
    // Tag the newly added bubble so we can swap it in-place without a full rerender
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) {
      allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
    }
  }
  dmScrollBottom();
  input.value = '';
  input.style.height = '';

  try {
    const res = await api('POST', '/api/member/dm/send', { to_member_id: peerId, body });

    // If this was a new conversation, update our active key
    if (!DM.activeKey && res.conv_key) DM.activeKey = res.conv_key;

    const realMsg = res.message;

    // Replace temp msg in DM.msgs with the real confirmed message
    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    if (realMsg) DM.msgs.push(realMsg);

    // Swap tmp bubble in-place — no DOM nuke, no flicker
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      // Update the delete button's data-id so deletion works after confirm
      const group  = tmpBubble.closest('.dm-msg-group');
      const delBtn = group?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
    } else if (list) {
      // Fallback: full rerender (bubble wasn't tagged somehow)
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
    }

    // Update conv list locally (avoid full refetch on every send)
    const existingConv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (existingConv) {
      existingConv.last_snippet      = body.slice(0, 80);
      existingConv.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existingConv.last_sender_is_me = true;
      dmRenderConvs(DM.convs);
    } else {
      // First message in a brand-new conv — need server data for peer info
      await dmLoadConvs();
    }
  } catch (e) {
    // Roll back: remove the tmp bubble from the DOM and from DM.msgs
    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const group = tmpBubble.closest('.dm-msg-group');
      const meta  = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (group && !group.querySelector('.dm-bubble')) group.remove();
    }
    console.error('[DM] send:', e.message);
  } finally {
    DM.pendingBodies.delete(body);
  }
}

// ─── Delete message ────────────────────────────────────────────────────────────

async function dmDeleteMsg(msgId, bubble, btn) {
  if (!confirm('Delete this message?')) return;
  try {
    await api('DELETE', `/api/member/dm/messages/${msgId}`);
    bubble.textContent = '[deleted]';
    bubble.classList.add('dm-deleted');
    btn.remove();
    const msg = DM.msgs.find(m => m.id === msgId);
    if (msg) msg.body = '[deleted]';
  } catch (e) {
    console.error('[DM] delete:', e.message);
  }
}

// ─── Polling ──────────────────────────────────────────────────────────────────

async function dmPollTick() {
  if (!DM.activeKey) return;
  try {
    const myId  = dmMyId();
    // Use newest known message as cursor — server only returns rows after this timestamp,
    // so the mark-read UPDATE only fires when there are genuinely new unread messages.
    const newest = DM.msgs.length ? DM.msgs[DM.msgs.length - 1].sent_at : null;
    const url    = `/api/member/dm/messages/${encodeURIComponent(DM.activeKey)}?limit=20`
                 + (newest ? `&since=${encodeURIComponent(newest)}` : '');
    const msgs   = await api('GET', url);
    if (!msgs?.length) return;
    // Dedup by id; also skip messages whose body is still in-flight as optimistic bubbles
    // (race condition: server returns the message before dmSend's try-block finishes)
    const known   = new Set(DM.msgs.map(m => m.id));
    const newMsgs = msgs.filter(m => !known.has(m.id) && !DM.pendingBodies.has(m.body));
    if (!newMsgs.length) return;
    DM.msgs.push(...newMsgs);
    const list = $id('dm-msg-list');
    if (!list) return;
    const area  = $id('dm-msgs');
    const atEnd = area ? area.scrollHeight - area.scrollTop - area.clientHeight < 80 : true;
    // Pass the last known sender so incremental append chains groups correctly
    const lastSender = DM.msgs.length > newMsgs.length
      ? DM.msgs[DM.msgs.length - newMsgs.length - 1].sender_id
      : null;
    dmRenderMsgs(newMsgs, list, myId, lastSender);
    if (atEnd) dmScrollBottom();
  } catch { /* silent */ }
}

function dmStartPolling() {
  dmPausePolling();
  DM.poll = setInterval(dmPollTick, DM_POLL);
}
function dmPausePolling() {
  if (DM.poll) { clearInterval(DM.poll); DM.poll = null; }
}

// ─── Panel open/close ─────────────────────────────────────────────────────────

async function dmPanelOpened() {
  DM.panelVisible = true;
  await dmLoadConvs();
  dmStartPolling();
}

// ─── Back button (mobile) ─────────────────────────────────────────────────────

function dmGoBack() {
  $id('dm-sidebar')?.classList.remove('dm-slide-out');
  $id('dm-window')?.classList.remove('dm-slide-in');
  $id('dm-active') && ($id('dm-active').style.display = 'none');
  $id('dm-window-empty') && ($id('dm-window-empty').style.display = '');
  DM.activeKey  = null;
  DM.activePeer = null;
  dmPausePolling(); // stop the poll interval when no conv is active
  document.querySelectorAll('.dm-conv-row').forEach(el => el.classList.remove('dm-active-row'));
}

// ─── Member picker ────────────────────────────────────────────────────────────

async function dmEnsureMembers() {
  if (DM.members.length) return;
  try {
    const data = await api('GET', '/api/members');
    const list = Array.isArray(data) ? data : (data.members || []);
    const myId = dmMyId();
    DM.members = list.filter(m => m.id !== myId);
  } catch { DM.members = []; }
}

function dmRenderPicker(q) {
  const results = $id('dm-picker-results');
  if (!results) return;
  const query = (q || '').toLowerCase().trim();
  const hits  = query
    ? DM.members.filter(m => (m.name || '').toLowerCase().includes(query) || (m.roll_no || '').includes(query))
    : DM.members.slice(0, 10);

  if (!hits.length) {
    results.innerHTML = `<div class="dm-state-msg" style="padding:16px">${query ? 'No members found.' : 'Start typing a name…'}</div>`;
    return;
  }
  results.innerHTML = hits.map(m => `
    <div class="dm-picker-row" data-id="${swEsc(m.id)}">
      ${dmAvatar(m.name, m.photo, 36)}
      <div>
        <div class="dm-picker-name">${swEsc(m.name || 'Member')}</div>
        <div class="dm-picker-meta">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
      </div>
    </div>`).join('');
  results.querySelectorAll('.dm-picker-row').forEach(row => {
    row.addEventListener('click', () => {
      const memberId = row.dataset.id;
      const m = DM.members.find(x => x.id === memberId);
      dmClosePicker();
      dmStartWith(memberId, m ? { id: m.id, name: m.name, photo: m.photo, role: m.role, batch: m.batch, domain: m.domain } : null);
    });
  });
}

function dmOpenPicker() {
  $id('dm-picker-overlay') && ($id('dm-picker-overlay').style.display = '');
  const inp = $id('dm-picker-input');
  if (inp) { inp.value = ''; inp.focus(); }
  dmEnsureMembers().then(() => dmRenderPicker(''));
}
function dmClosePicker() {
  $id('dm-picker-overlay') && ($id('dm-picker-overlay').style.display = 'none');
}

// ─── Conversation search/filter ───────────────────────────────────────────────

function dmFilterConvs(q) {
  const query = (q || '').toLowerCase().trim();
  dmRenderConvs(query ? DM.convs.filter(c => (c.peer?.name || '').toLowerCase().includes(query)) : DM.convs);
}

// ─── Init ─────────────────────────────────────────────────────────────────────

function initDM() {
  // New message button
  $id('dm-new-btn')?.addEventListener('click', dmOpenPicker);

  // Picker close
  $id('dm-picker-close')?.addEventListener('click', dmClosePicker);
  $id('dm-picker-overlay')?.addEventListener('click', e => { if (e.target === $id('dm-picker-overlay')) dmClosePicker(); });

  // Picker search
  $id('dm-picker-input')?.addEventListener('input', e => {
    clearTimeout(DM.pickerTimer);
    DM.pickerTimer = setTimeout(() => dmRenderPicker(e.target.value), 200);
  });

  // Conv search
  $id('dm-search')?.addEventListener('input', e => dmFilterConvs(e.target.value));

  // Send
  $id('dm-send-btn')?.addEventListener('click', dmSend);
  $id('dm-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); dmSend(); }
  });

  // Auto-grow textarea
  $id('dm-input')?.addEventListener('input', function () {
    this.style.height = '';
    this.style.height = Math.min(this.scrollHeight, 110) + 'px';
  });

  // Back (mobile)
  $id('dm-back-btn')?.addEventListener('click', dmGoBack);

  // Load earlier
  $id('dm-load-earlier')?.addEventListener('click', () => dmLoadMsgs(true));

  // Background unread badge refresh every 30s
  dmRefreshBadge();
  setInterval(dmRefreshBadge, 30000);
}

// Boot after DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDM);
} else {
  initDM();
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION: Content Reporting — Member Portal JS
// Covers: post options menu, report modal, DM report button
// ─────────────────────────────────────────────────────────────────────────────

// ── Post options menu (three-dot) ────────────────────────────────────────────
let _swPostMenuOpen = null;

function swShowPostMenu(event, postId, authorId, isAdminPost) {
  event.stopPropagation();
  // Close any open menu first
  swClosePostMenu();

  const myId = window._memberProfile?.id || '';
  const isOwn = myId && myId === authorId;
  const isAdmin = isAdminPost;

  const items = [];
  items.push({ label: '🔗 Copy link', fn: `swCopyPostLink('${postId}')` });
  if (!isAdmin) {
    // Don't show report on KFS official posts
    items.push({ label: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>Report post', fn: `swOpenReportModal('post','${postId}')`, danger: true });
  }
  if (isOwn) {
    items.push({ label: '🗑 Delete post', fn: `swConfirmDeletePost('${postId}')`, danger: true });
  }

  const menu = document.createElement('div');
  menu.id = 'sw-post-menu';
  menu.style.cssText = 'position:fixed;z-index:9999;background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.5);padding:6px;min-width:160px';
  menu.innerHTML = items.map(item =>
    `<button onclick="event.stopPropagation();swClosePostMenu();${item.fn}" style="display:block;width:100%;text-align:left;background:transparent;border:none;padding:10px 14px;font-size:13px;color:${item.danger?'#e53e3e':'var(--text,#f5f5f5)'};border-radius:8px;cursor:pointer" onmouseover="this.style.background='rgba(255,255,255,.06)'" onmouseout="this.style.background='transparent'">${item.label}</button>`
  ).join('');

  // Position near the button
  const btn = event.currentTarget || event.target;
  const rect = btn.getBoundingClientRect();
  const menuW = 180;
  let left = rect.right - menuW;
  if (left < 8) left = 8;
  let top = rect.bottom + 4;
  if (top + 160 > window.innerHeight) top = rect.top - 160;
  menu.style.left = left + 'px';
  menu.style.top  = top  + 'px';

  document.body.appendChild(menu);
  _swPostMenuOpen = menu;

  // Close on outside click
  setTimeout(() => {
    document.addEventListener('click', swClosePostMenu, { once: true, capture: true });
  }, 0);
}

function swClosePostMenu() {
  if (_swPostMenuOpen) { _swPostMenuOpen.remove(); _swPostMenuOpen = null; }
}

function swCopyPostLink(postId) {
  const url = `${location.origin}/social-strand/member/${postId}`;
  navigator.clipboard?.writeText(url).then(() => {
    swShowToast('Link copied!');
  }).catch(() => { swShowToast('Could not copy — try manually.'); });
}

function swConfirmDeletePost(postId) {
  if (!confirm('Delete this post? This cannot be undone.')) return;
  // Use existing delete function if available
  if (typeof swDeleteProject === 'function') { swDeleteProject(postId); return; }
  // Fallback
  fetch(`/api/member/studio/projects/${postId}`, {
    method: 'DELETE',
    credentials: 'include',
    headers: { 'Authorization': 'Bearer ' + (window._memberToken || ''), 'X-CSRF-Token': window._csrfToken || '' },
  }).then(r => {
    if (r.ok) {
      const card = document.querySelector(`.ig-post[data-project-id="${CSS.escape(postId)}"]`);
      if (card) card.remove();
      swShowToast('Post deleted.');
    } else { r.json().then(d => alert(d.error || 'Error')); }
  }).catch(() => alert('Network error'));
}

function swShowToast(msg, duration = 2800) {
  let t = document.getElementById('sw-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'sw-toast';
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#111;color:#f5f5f5;font-size:13px;padding:10px 20px;border-radius:24px;z-index:99999;box-shadow:0 4px 16px rgba(0,0,0,.5);transition:opacity .3s;pointer-events:none';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = '1';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, duration);
}

// ── Report modal ─────────────────────────────────────────────────────────────
// Creates a lightweight report modal inline (no external HTML needed)
function swOpenReportModal(contentType, contentId, extraLabel) {
  // Remove any existing modal
  let existing = document.getElementById('sw-report-modal-overlay');
  if (existing) existing.remove();

  const typeLabel = { post: 'post', dm: 'DM message', comment: 'comment' }[contentType] || contentType;
  const reasons = [
    'Harassment or bullying',
    'Hate speech or discrimination',
    'Spam or misleading content',
    'Inappropriate or explicit content',
    'Impersonation',
    'Other',
  ];

  const overlay = document.createElement('div');
  overlay.id = 'sw-report-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:99990;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:18px;padding:28px 24px;max-width:400px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,.6)">
      <h3 style="margin:0 0 6px;font-size:16px;font-weight:700">Report ${typeLabel}</h3>
      <p style="font-size:12px;color:var(--grey,#888);margin:0 0 18px">Please tell us why you're reporting this. Our team reviews all reports.</p>
      ${extraLabel ? `<p style="font-size:12px;color:var(--grey);margin:0 0 14px;font-style:italic">${extraLabel}</p>` : ''}
      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px">
        ${reasons.map((r, i) => `<label style="display:flex;align-items:center;gap:10px;font-size:13px;cursor:pointer"><input type="radio" name="sw-report-reason" value="${r}" ${i===0?'checked':''}> ${r}</label>`).join('')}
      </div>
      <div style="margin-bottom:16px">
        <label style="font-size:12px;color:var(--grey)">Additional details (optional)</label>
        <textarea id="sw-report-details" rows="2" placeholder="Any extra context…" style="width:100%;box-sizing:border-box;margin-top:6px;font-size:13px;background:var(--bg,#0a0a0a);border:1px solid var(--border,#222);border-radius:8px;padding:8px 10px;color:var(--text,#f5f5f5);resize:vertical"></textarea>
      </div>
      <div id="sw-report-msg" style="font-size:12px;color:#e53e3e;margin-bottom:10px;display:none"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="sw-report-cancel" style="background:transparent;border:1px solid var(--border,#222);color:var(--grey,#888);padding:9px 18px;border-radius:20px;font-size:13px;cursor:pointer">Cancel</button>
        <button id="sw-report-submit" style="background:#e53e3e;color:#fff;border:none;padding:9px 18px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer">Submit Report</button>
      </div>
    </div>`;

  document.body.appendChild(overlay);

  overlay.querySelector('#sw-report-cancel').onclick = () => overlay.remove();
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

  overlay.querySelector('#sw-report-submit').onclick = async () => {
    const reasonEl = overlay.querySelector('input[name="sw-report-reason"]:checked');
    const reason   = reasonEl?.value || '';
    const details  = overlay.querySelector('#sw-report-details')?.value.trim() || '';
    const msgEl    = overlay.querySelector('#sw-report-msg');

    if (!reason) { msgEl.textContent = 'Please select a reason.'; msgEl.style.display='block'; return; }

    try {
      const r = await fetch('/api/member/reports', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (window._memberToken || '') },
        body: JSON.stringify({ content_type: contentType, content_id: String(contentId), reason, details }),
      });
      const d = await r.json();
      if (!r.ok) { msgEl.textContent = d.error || 'Error submitting report.'; msgEl.style.display='block'; return; }
      overlay.remove();
      swShowToast('✓ Report submitted. Thank you.');
    } catch { msgEl.textContent = 'Network error. Please try again.'; msgEl.style.display = 'block'; }
  };
}

// ── Hook: add Report button in DM conversation view ──────────────────────────
// Called when DM message context-menu / long-press happens
function swReportDmMessage(msgId) {
  swOpenReportModal('dm', msgId, 'You are reporting a direct message.');
}

// ── Hook: add Report button for comments (in detail view) ────────────────────
function swReportComment(commentId) {
  swOpenReportModal('comment', commentId, 'You are reporting a comment.');
}

// ═══════════════════════════════════════════════════════════════════════════
// BLOCK / UNBLOCK MODULE
// ═══════════════════════════════════════════════════════════════════════════

const BLOCKS = {
  set: new Set(),   // IDs I have blocked
  loaded: false,
};

async function blocksEnsureLoaded() {
  if (BLOCKS.loaded) return;
  try {
    const ids = await api('GET', '/api/member/blocks');
    BLOCKS.set = new Set(Array.isArray(ids) ? ids : []);
    BLOCKS.loaded = true;
  } catch { BLOCKS.set = new Set(); }
}

async function blocksToggle(memberId, btn) {
  const nowBlocked = BLOCKS.set.has(memberId);
  try {
    btn && (btn.disabled = true);
    if (nowBlocked) {
      await api('DELETE', `/api/member/blocks/${memberId}`);
      BLOCKS.set.delete(memberId);
    } else {
      await api('POST', '/api/member/blocks', { member_id: memberId });
      BLOCKS.set.add(memberId);
    }
    // Update all block buttons for this member in the DOM
    document.querySelectorAll(`[data-block-member="${memberId}"]`).forEach(el => {
      const isNowBlocked = BLOCKS.set.has(memberId);
      el.textContent = isNowBlocked ? 'Unblock' : 'Block';
      el.classList.toggle('dm-block-active', isNowBlocked);
      el.title = isNowBlocked ? 'Unblock this member' : 'Block this member';
    });
    // If we just blocked the active DM peer, show blocked banner
    if (DM.activePeer?.id === memberId) dmUpdateBlockedBanner();
  } catch (e) {
    showMsg && showMsg('dm-error', e.message || 'Could not update block status.', false);
  } finally {
    btn && (btn.disabled = false);
  }
}

function dmUpdateBlockedBanner() {
  const peerId = DM.activePeer?.id;
  if (!peerId) return;
  const compose = $id('dm-compose');
  let banner = $id('dm-blocked-banner');
  const iBlocked     = BLOCKS.set.has(peerId);
  const theyBlockedMe = DM.activePeer?._blockedMe || false;
  const blocked = iBlocked || theyBlockedMe;
  if (blocked) {
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'dm-blocked-banner';
      banner.className = 'dm-blocked-banner';
      compose?.parentNode?.insertBefore(banner, compose);
    }
    banner.textContent = iBlocked
      ? 'You have blocked this member. Unblock to send messages.'
      : 'You can\'t message this person.';
    compose && (compose.style.display = 'none');
  } else {
    banner?.remove();
    compose && (compose.style.display = '');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// NICKNAME MODULE
// ═══════════════════════════════════════════════════════════════════════════

// In-memory store: conv_key → [{giver_id, target_id, nickname}]
const NICKS = {};

async function nicksLoad(convKey) {
  try {
    const data = await api('GET', `/api/member/nicknames/${encodeURIComponent(convKey)}`);
    NICKS[convKey] = Array.isArray(data) ? data : [];
  } catch {
    NICKS[convKey] = [];
  }
}

function nicksGetFor(convKey, targetId) {
  // Returns the nickname map: { [giverId]: nickname }
  const rows = NICKS[convKey] || [];
  const result = {};
  rows.filter(r => r.target_id === targetId).forEach(r => { result[r.giver_id] = r.nickname; });
  return result;
}

function nicksResolveDisplay(convKey, memberId, fallbackName) {
  // Returns the nickname set FOR this memberId by anyone, or fallbackName.
  // Priority: any nickname in this conv for this member (first found, or giver=me first)
  const myId = dmMyId();
  const rows = NICKS[convKey] || [];
  // Prefer nickname set by me
  const mine = rows.find(r => r.target_id === memberId && r.giver_id === myId);
  if (mine) return mine.nickname;
  // Then any other
  const any = rows.find(r => r.target_id === memberId);
  if (any) return any.nickname;
  return fallbackName;
}

// Open nickname edit modal
function nicksOpenModal(convKey, targetId, targetName, isGroup) {
  const myId = dmMyId();
  const existing = (NICKS[convKey] || []).find(r => r.giver_id === myId && r.target_id === targetId);
  const currentNick = existing?.nickname || '';

  let modal = $id('nick-modal-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'nick-modal-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `
      <div class="nick-modal" id="nick-modal">
        <div class="nick-modal-head">
          <span id="nick-modal-title">Nickname</span>
          <button class="dm-icon-btn" id="nick-modal-close" aria-label="Close">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <p class="nick-modal-hint" id="nick-modal-hint"></p>
        <input id="nick-input" class="nick-input" type="text" maxlength="40" autocomplete="off" placeholder="Enter nickname…">
        <div class="nick-modal-actions">
          <button class="nick-clear-btn" id="nick-clear-btn">Clear</button>
          <button class="nick-save-btn" id="nick-save-btn">Save</button>
        </div>
        <div id="nick-error" class="nick-error" style="display:none"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    $id('nick-modal-close')?.addEventListener('click', () => { modal.style.display = 'none'; });
  }

  $id('nick-modal-title').textContent = `Nickname for ${targetName}`;
  $id('nick-modal-hint').textContent = isGroup
    ? 'This nickname is visible to everyone in the group.'
    : 'This nickname is visible to both of you in this chat.';
  const inp = $id('nick-input');
  inp.value = currentNick;
  $id('nick-error').style.display = 'none';
  modal.style.display = 'flex';
  inp.focus();
  inp.select();

  const saveBtn  = $id('nick-save-btn');
  const clearBtn = $id('nick-clear-btn');

  // Remove old listeners by cloning
  const newSave  = saveBtn.cloneNode(true);
  const newClear = clearBtn.cloneNode(true);
  saveBtn.parentNode.replaceChild(newSave, saveBtn);
  clearBtn.parentNode.replaceChild(newClear, clearBtn);

  const doSave = async (nick) => {
    try {
      newSave.disabled = true;
      await api('PUT', '/api/member/nicknames', { conv_key: convKey, target_id: targetId, nickname: nick });
      // Update local cache
      const rows = NICKS[convKey] || (NICKS[convKey] = []);
      const idx  = rows.findIndex(r => r.giver_id === myId && r.target_id === targetId);
      if (nick) {
        if (idx >= 0) rows[idx].nickname = nick;
        else rows.push({ giver_id: myId, target_id: targetId, nickname: nick });
      } else {
        if (idx >= 0) rows.splice(idx, 1);
      }
      modal.style.display = 'none';
      // Refresh display name in topbar + conv list
      dmRefreshDisplayNames(convKey);
    } catch (e) {
      const err = $id('nick-error');
      err.textContent = e.message || 'Could not save.';
      err.style.display = '';
    } finally {
      newSave.disabled = false;
    }
  };

  newSave.addEventListener('click', () => doSave(inp.value.trim()));
  newClear.addEventListener('click', () => doSave(''));
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') doSave(inp.value.trim()); });
}

// Refresh display names after a nickname change
function dmRefreshDisplayNames(convKey) {
  // 1-1 DM
  if (DM.activeKey === convKey && DM.activePeer) {
    const peerId   = DM.activePeer.id;
    const peerName = DM.activePeer.name;
    const display  = nicksResolveDisplay(convKey, peerId, peerName);
    const topbarName = $id('dm-topbar-name');
    if (topbarName) topbarName.textContent = display;
  }
  // Conv list rows
  DM.convs.forEach(c => {
    if (c.conv_key !== convKey) return;
    const display = nicksResolveDisplay(convKey, c.peer?.id, c.peer?.name);
    const row = document.querySelector(`.dm-conv-row[data-key="${convKey}"] .dm-conv-name`);
    if (row) row.textContent = display;
  });
  // Group chat topbar
  if (GC.activeId === convKey) {
    const group = GC.groups.find(g => g.id === convKey);
    if (group) gcRefreshTopbarNicknames(convKey, group);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// GROUP CHAT MODULE (GC)
// ═══════════════════════════════════════════════════════════════════════════

const GC = {
  groups:         [],      // loaded group list
  activeId:       null,    // currently open group UUID
  activeGroup:    null,    // { id, name, members[], my_role, ... }
  msgs:           [],      // messages in active group
  oldestSentAt:   null,
  poll:           null,
  panelVisible:   false,
  pendingBodies:  new Set(),
  loadingMsgs:    false,
};

const GC_POLL = 5000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function gcMyId() { return window._memberProfile?.id || _member?.id || null; }

function gcAvatar(name, photo, size) {
  if (photo) return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;background:#1e1e1e">`;
  const init = (name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.36)}px;font-weight:700;color:#666;flex-shrink:0">${swEsc(init)}</div>`;
}

function gcGroupAvatar(group, size) {
  const text = group.avatar_text || (group.name?.[0] || '?').toUpperCase();
  return `<div class="gc-group-av" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.42)}px">${swEsc(text)}</div>`;
}

function gcTime(iso) { return dmTime(iso); }
function gcFull(iso) { return dmFull(iso); }

function gcSetBadge(n) {
  const show  = n > 0;
  const label = n > 99 ? '99+' : String(n);
  [$id('gc-nav-badge')].forEach(el => {
    if (!el) return;
    el.style.display = show ? '' : 'none';
    el.textContent   = label;
  });
}

async function gcRefreshBadge() {
  if (!_token) return;
  try {
    const d = await api('GET', '/api/member/groups/unread-count');
    gcSetBadge(d.count || 0);
  } catch { /* silent */ }
}

// ─── Group list ───────────────────────────────────────────────────────────────

async function gcLoadGroups() {
  try {
    const data = await api('GET', '/api/member/groups');
    GC.groups = data || [];
    gcRenderGroups(GC.groups);
    const total = GC.groups.reduce((s, g) => s + (g.unread_count || 0), 0);
    gcSetBadge(total);
  } catch (e) {
    console.error('[GC] loadGroups:', e.message);
  }
}

function gcRenderGroups(list) {
  const container = $id('gc-conv-list');
  if (!container) return;
  $id('gc-conv-loading') && ($id('gc-conv-loading').style.display = 'none');
  container.querySelectorAll('.gc-conv-row').forEach(el => el.remove());

  if (!list?.length) {
    $id('gc-conv-empty') && ($id('gc-conv-empty').style.display = '');
    return;
  }
  $id('gc-conv-empty') && ($id('gc-conv-empty').style.display = 'none');

  list.forEach(g => {
    const row = document.createElement('div');
    row.className = 'dm-conv-row gc-conv-row' + (g.id === GC.activeId ? ' dm-active-row' : '');
    row.dataset.key = g.id;
    const preview = g.last_snippet
      ? (g.last_sender_is_me ? 'You: ' : (g.last_sender_name ? g.last_sender_name + ': ' : '')) + g.last_snippet
      : 'No messages yet';
    row.innerHTML = `
      ${gcGroupAvatar(g, 42)}
      <div class="dm-conv-info">
        <div class="dm-conv-name">${swEsc(g.name)}</div>
        <div class="dm-conv-preview ${g.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
      </div>
      <div class="dm-conv-right">
        <span class="dm-conv-time">${gcTime(g.last_msg_at)}</span>
        ${g.unread_count > 0 ? `<span class="dm-unread-pill">${g.unread_count > 9 ? '9+' : g.unread_count}</span>` : ''}
      </div>`;
    row.addEventListener('click', () => gcOpenGroup(g));
    container.appendChild(row);
  });
}

// ─── Open a group ─────────────────────────────────────────────────────────────

async function gcOpenGroup(group) {
  GC.activeId    = group.id;
  GC.activeGroup = group;
  GC.msgs        = [];
  GC.oldestSentAt = null;

  document.querySelectorAll('.gc-conv-row').forEach(el => {
    el.classList.toggle('dm-active-row', el.dataset.key === group.id);
  });

  // Topbar
  const ta = $id('gc-topbar-avatar');
  if (ta) ta.innerHTML = gcGroupAvatar(group, 34);
  setText('gc-topbar-name', group.name);

  // Load full member list for topbar sub
  gcLoadGroupDetails(group.id);

  $id('gc-window-empty') && ($id('gc-window-empty').style.display = 'none');
  $id('gc-active') && ($id('gc-active').style.display = 'flex');
  $id('gc-sidebar')?.classList.add('dm-slide-out');
  $id('gc-window')?.classList.add('dm-slide-in');

  // Load nicknames
  await nicksLoad(group.id);
  await gcLoadMsgs(false);
  $id('gc-input')?.focus();
}

async function gcLoadGroupDetails(groupId) {
  try {
    const data = await api('GET', `/api/member/groups/${groupId}`);
    GC.activeGroup = { ...GC.activeGroup, ...data };
    const myId  = gcMyId();
    const count = data.members?.length || 0;
    setText('gc-topbar-sub', `${count} member${count !== 1 ? 's' : ''}`);

    // Topbar nickname button: show "Nicknames" button
    gcRefreshTopbarNicknames(groupId, data);

    // Update my_role for input/delete controls
    gcUpdateInputState();
  } catch { /* silent */ }
}

function gcRefreshTopbarNicknames(groupId, group) {
  // Nothing to show in topbar about nicknames; nickname setting is via the info panel
}

function gcUpdateInputState() {
  // Group chats: everyone can send (no blocking check needed here for simplicity)
  const compose = $id('gc-compose');
  if (compose) compose.style.display = '';
}

// ─── Load messages ────────────────────────────────────────────────────────────

async function gcLoadMsgs(prepend) {
  if (!GC.activeId) return;
  if (!prepend) GC.loadingMsgs = true;
  try {
    const myId = gcMyId();
    let url    = `/api/member/groups/${encodeURIComponent(GC.activeId)}/messages?limit=40`;
    if (prepend && GC.oldestSentAt) url += `&before=${encodeURIComponent(GC.oldestSentAt)}`;

    const resp = await api('GET', url);
    const msgs      = resp.messages || [];
    const nicknames = resp.nicknames || [];

    // Merge nicknames into cache
    if (nicknames.length) {
      NICKS[GC.activeId] = nicknames;
    }

    if (prepend) {
      const fetchedIds = new Set(msgs.map(m => m.id));
      const optimistic = GC.msgs.filter(m => m.id.startsWith('tmp-'));
      GC.msgs = [...msgs, ...GC.msgs.filter(m => !fetchedIds.has(m.id) && !m.id.startsWith('tmp-')), ...optimistic];
    } else {
      const optimistic = GC.msgs.filter(m => m.id.startsWith('tmp-'));
      const fetchedIds = new Set(msgs.map(m => m.id));
      GC.msgs = [...msgs, ...optimistic].filter((m, i, arr) =>
        !fetchedIds.has(m.id) || arr.findIndex(x => x.id === m.id) === i
      );
      GC.msgs.sort((a, b) => {
        const aO = a.id.startsWith('tmp-'), bO = b.id.startsWith('tmp-');
        if (aO && !bO) return 1; if (!aO && bO) return -1;
        return new Date(a.sent_at) - new Date(b.sent_at);
      });
    }

    GC.oldestSentAt = GC.msgs.find(m => !m.id.startsWith('tmp-'))?.sent_at || null;

    const list = $id('gc-msg-list');
    if (!list) return;

    if (!prepend) {
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      gcScrollBottom();
    } else {
      const area    = $id('gc-msgs');
      const prevH   = area.scrollHeight;
      const prevTop = area.scrollTop;
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      area.scrollTop = area.scrollHeight - prevH + prevTop;
    }

    const moreWrap = $id('gc-load-earlier-wrap');
    if (moreWrap) moreWrap.style.display = msgs.length >= 40 ? '' : 'none';

    const g = GC.groups.find(g => g.id === GC.activeId);
    if (g) { g.unread_count = 0; gcRenderGroups(GC.groups); }
  } catch (e) {
    console.error('[GC] loadMsgs:', e.message);
  } finally {
    if (!prepend) GC.loadingMsgs = false;
  }
}

function gcRenderMsgs(msgs, container, myId, lastSenderHint) {
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild : null;

  msgs.forEach(m => {
    const mine = m.sender_id === myId || (m.id.startsWith('tmp-') && !m.sender_id);
    const senderKey = mine ? '__mine__' : m.sender_id;
    const convKey   = GC.activeId;

    const displayName = mine
      ? 'You'
      : nicksResolveDisplay(convKey, m.sender_id, m.sender?.name || 'Member');

    if (senderKey !== lastSender || !group) {
      group = document.createElement('div');
      group.className = `dm-msg-group ${mine ? 'mine' : 'theirs'}`;

      if (!mine) {
        // Show avatar + name for group messages
        const header = document.createElement('div');
        header.className = 'gc-msg-header';
        header.innerHTML = `
          ${gcAvatar(m.sender?.name, m.sender?.photo, 22)}
          <span class="gc-msg-sender-name" data-member-id="${swEsc(m.sender_id)}" style="cursor:pointer">${swEsc(displayName)}</span>
        `;
        header.querySelector('.gc-msg-sender-name')?.addEventListener('click', (e) => {
          e.stopPropagation();
          // Open nickname modal for this member
          nicksOpenModal(GC.activeId, m.sender_id, m.sender?.name || 'Member', true);
        });
        group.appendChild(header);
      }

      container.appendChild(group);
      lastSender = senderKey;
    }

    const isDeleted = m.body === '[deleted]' || m.is_deleted;
    const bubble = document.createElement('div');
    bubble.className = `dm-bubble${isDeleted ? ' dm-deleted' : ''}`;
    bubble.textContent = m.body;

    const meta = document.createElement('div');
    meta.className = 'dm-meta';
    meta.innerHTML = `<span class="dm-msg-time">${gcFull(m.sent_at)}</span>${mine && !isDeleted && !m.id.startsWith('tmp-') ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

    const delBtn = meta.querySelector('.dm-del-btn');
    if (delBtn) {
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        gcDeleteMsg(m.id, bubble, delBtn);
      });
    }

    group.appendChild(bubble);
    group.appendChild(meta);
  });
}

function gcScrollBottom() {
  const el = $id('gc-msgs');
  if (el) el.scrollTop = el.scrollHeight;
}

// ─── Send ─────────────────────────────────────────────────────────────────────

async function gcSend() {
  const input = $id('gc-input');
  if (!input) return;
  const body = input.value.trim();
  if (!body || !GC.activeId) return;

  if (GC.loadingMsgs) {
    const btn = $id('gc-send-btn');
    if (btn) btn.disabled = true;
    await new Promise(resolve => { const c = () => { if (!GC.loadingMsgs) resolve(); else setTimeout(c, 50); }; c(); });
    if (btn) btn.disabled = false;
  }

  const myId  = gcMyId();
  const tmpId = 'tmp-' + Date.now();
  const tmp   = { id: tmpId, sender_id: myId, sender: window._memberProfile || { id: myId, name: 'You', photo: null }, body, sent_at: new Date().toISOString(), is_deleted: false };
  GC.msgs.push(tmp);
  GC.pendingBodies.add(body);

  const list = $id('gc-msg-list');
  const lastRenderedSender = GC.msgs.length > 1 ? GC.msgs[GC.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    gcRenderMsgs([tmp], list, myId, lastRenderedSender === myId ? '__mine__' : lastRenderedSender);
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
  }
  gcScrollBottom();
  input.value = '';
  input.style.height = '';

  try {
    const res = await api('POST', `/api/member/groups/${GC.activeId}/messages`, { body });
    const realMsg = res.message;

    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    if (realMsg) GC.msgs.push(realMsg);

    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      const grp    = tmpBubble.closest('.dm-msg-group');
      const delBtn = grp?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
    } else if (list) {
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      gcScrollBottom();
    }

    const existing = GC.groups.find(g => g.id === GC.activeId);
    if (existing) {
      existing.last_snippet      = body.slice(0, 80);
      existing.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existing.last_sender_is_me = true;
      gcRenderGroups(GC.groups);
    } else {
      await gcLoadGroups();
    }
  } catch (e) {
    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const grp  = tmpBubble.closest('.dm-msg-group');
      const meta = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (grp && !grp.querySelector('.dm-bubble')) grp.remove();
    }
    console.error('[GC] send:', e.message);
  } finally {
    GC.pendingBodies.delete(body);
  }
}

// ─── Delete ───────────────────────────────────────────────────────────────────

async function gcDeleteMsg(msgId, bubble, btn) {
  if (!confirm('Delete this message?')) return;
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/messages/${msgId}`);
    bubble.textContent = '[deleted]';
    bubble.classList.add('dm-deleted');
    btn.remove();
    const m = GC.msgs.find(m => m.id === msgId);
    if (m) { m.body = '[deleted]'; m.is_deleted = true; }
  } catch (e) {
    console.error('[GC] delete:', e.message);
  }
}

// ─── Polling ──────────────────────────────────────────────────────────────────

async function gcPollTick() {
  if (!GC.activeId) return;
  try {
    const myId   = gcMyId();
    const newest = GC.msgs.length ? GC.msgs[GC.msgs.length - 1].sent_at : null;
    const url    = `/api/member/groups/${encodeURIComponent(GC.activeId)}/messages?limit=20`
                 + (newest ? `&since=${encodeURIComponent(newest)}` : '');
    const resp   = await api('GET', url);
    const msgs   = resp.messages || [];
    if (!msgs.length) return;

    const known   = new Set(GC.msgs.map(m => m.id));
    const newMsgs = msgs.filter(m => !known.has(m.id) && !GC.pendingBodies.has(m.body));
    if (!newMsgs.length) return;

    // Merge new nicknames
    if (resp.nicknames?.length) {
      const existing = NICKS[GC.activeId] || [];
      const existMap = new Map(existing.map(n => `${n.giver_id}:${n.target_id}`));
      resp.nicknames.forEach(n => { existMap.set(`${n.giver_id}:${n.target_id}`, n); });
      NICKS[GC.activeId] = [...existMap.values()];
    }

    GC.msgs.push(...newMsgs);
    const list  = $id('gc-msg-list');
    if (!list) return;
    const area  = $id('gc-msgs');
    const atEnd = area ? area.scrollHeight - area.scrollTop - area.clientHeight < 80 : true;
    const lastSender = GC.msgs.length > newMsgs.length
      ? GC.msgs[GC.msgs.length - newMsgs.length - 1].sender_id
      : null;
    gcRenderMsgs(newMsgs, list, myId, lastSender === myId ? '__mine__' : lastSender);
    if (atEnd) gcScrollBottom();
  } catch { /* silent */ }
}

function gcStartPolling() { gcPausePolling(); GC.poll = setInterval(gcPollTick, GC_POLL); }
function gcPausePolling()  { if (GC.poll) { clearInterval(GC.poll); GC.poll = null; } }

// ─── Panel ────────────────────────────────────────────────────────────────────

async function gcPanelOpened() {
  GC.panelVisible = true;
  await gcLoadGroups();
  gcStartPolling();
}

function gcGoBack() {
  $id('gc-sidebar')?.classList.remove('dm-slide-out');
  $id('gc-window')?.classList.remove('dm-slide-in');
  $id('gc-active') && ($id('gc-active').style.display = 'none');
  $id('gc-window-empty') && ($id('gc-window-empty').style.display = '');
  GC.activeId    = null;
  GC.activeGroup = null;
  gcPausePolling();
  document.querySelectorAll('.gc-conv-row').forEach(el => el.classList.remove('dm-active-row'));
}

// ─── Create group modal ───────────────────────────────────────────────────────

function gcOpenCreateModal() {
  let modal = $id('gc-create-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gc-create-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `
      <div class="nick-modal gc-create-modal" id="gc-create-modal">
        <div class="nick-modal-head">
          <span>New Group Chat</span>
          <button class="dm-icon-btn" id="gc-create-close" aria-label="Close">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <input id="gc-create-name" class="nick-input" type="text" maxlength="60" placeholder="Group name…" autocomplete="off">
        <div style="margin-top:10px;font-size:12px;color:var(--muted);margin-bottom:6px">Add members</div>
        <div class="gc-create-search-wrap">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted)"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="gc-member-search" class="dm-search-input" style="padding-left:32px;width:100%;box-sizing:border-box" type="text" placeholder="Search members…" autocomplete="off">
        </div>
        <div id="gc-member-results" class="dm-picker-results" style="max-height:160px;margin-top:6px"></div>
        <div style="margin-top:8px;font-size:11px;color:var(--muted);margin-bottom:4px">Selected</div>
        <div id="gc-selected-chips" style="display:flex;flex-wrap:wrap;gap:6px;min-height:28px"></div>
        <div class="nick-modal-actions" style="margin-top:14px">
          <button class="nick-clear-btn" id="gc-create-cancel">Cancel</button>
          <button class="nick-save-btn" id="gc-create-submit">Create</button>
        </div>
        <div id="gc-create-error" class="nick-error" style="display:none"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) gcCloseCreateModal(); });
  }

  $id('gc-create-close')?.addEventListener('click', gcCloseCreateModal);
  $id('gc-create-cancel')?.addEventListener('click', gcCloseCreateModal);

  const selected = new Map(); // id → member object
  modal._selected = selected;

  const renderChips = () => {
    const chips = $id('gc-selected-chips');
    chips.innerHTML = '';
    selected.forEach((m, id) => {
      const chip = document.createElement('span');
      chip.className = 'gc-chip';
      chip.innerHTML = `${swEsc(m.name || 'Member')}<button data-id="${swEsc(id)}" class="gc-chip-remove">×</button>`;
      chip.querySelector('.gc-chip-remove')?.addEventListener('click', () => { selected.delete(id); renderChips(); });
      chips.appendChild(chip);
    });
  };

  const renderResults = (q) => {
    const results = $id('gc-member-results');
    const query   = (q || '').toLowerCase().trim();
    const myId    = gcMyId();
    const pool    = DM.members.length ? DM.members : [];
    const hits    = query
      ? pool.filter(m => (m.name || '').toLowerCase().includes(query) && !selected.has(m.id))
      : pool.filter(m => !selected.has(m.id)).slice(0, 8);
    results.innerHTML = hits.map(m => `
      <div class="dm-picker-row" data-id="${swEsc(m.id)}">
        ${gcAvatar(m.name, m.photo, 30)}
        <div>
          <div class="dm-picker-name">${swEsc(m.name || 'Member')}</div>
          <div class="dm-picker-meta">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
        </div>
      </div>`).join('');
    results.querySelectorAll('.dm-picker-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        const m  = pool.find(x => x.id === id);
        if (m) { selected.set(id, m); renderChips(); renderResults($id('gc-member-search')?.value); }
      });
    });
  };

  // Reset
  $id('gc-create-name').value = '';
  $id('gc-member-search').value = '';
  $id('gc-selected-chips').innerHTML = '';
  $id('gc-create-error').style.display = 'none';

  // Load members
  dmEnsureMembers().then(() => renderResults(''));

  let searchTimer;
  const searchInp = $id('gc-member-search');
  searchInp.oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => renderResults(searchInp.value), 150); };

  const submitBtn = $id('gc-create-submit');
  submitBtn.onclick = async () => {
    const name = ($id('gc-create-name').value || '').trim();
    if (!name) { $id('gc-create-error').textContent = 'Group name required.'; $id('gc-create-error').style.display = ''; return; }
    if (!selected.size) { $id('gc-create-error').textContent = 'Add at least one member.'; $id('gc-create-error').style.display = ''; return; }
    submitBtn.disabled = true;
    try {
      const res = await api('POST', '/api/member/groups', { name, member_ids: [...selected.keys()] });
      gcCloseCreateModal();
      await gcLoadGroups();
      if (res.group) gcOpenGroup(res.group);
    } catch (e) {
      $id('gc-create-error').textContent = e.message || 'Could not create group.';
      $id('gc-create-error').style.display = '';
    } finally {
      submitBtn.disabled = false;
    }
  };

  modal.style.display = 'flex';
  $id('gc-create-name').focus();
}

function gcCloseCreateModal() {
  const modal = $id('gc-create-overlay');
  if (modal) modal.style.display = 'none';
}

// ─── Group info panel ─────────────────────────────────────────────────────────

async function gcOpenInfo() {
  if (!GC.activeId) return;
  try {
    const data    = await api('GET', `/api/member/groups/${GC.activeId}`);
    GC.activeGroup = { ...GC.activeGroup, ...data };
    gcShowInfoModal(data);
  } catch { /* silent */ }
}

function gcShowInfoModal(data) {
  const myId  = gcMyId();
  let modal   = $id('gc-info-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gc-info-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `<div class="nick-modal gc-info-modal" id="gc-info-modal"></div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
  }

  const isAdminOrOwner = ['owner','admin'].includes(data.my_role);
  const convKey        = GC.activeId;

  modal.querySelector('#gc-info-modal').innerHTML = `
    <div class="nick-modal-head">
      <span>Group Info</span>
      <button class="dm-icon-btn" onclick="document.getElementById('gc-info-overlay').style.display='none'" aria-label="Close">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div style="text-align:center;margin:12px 0 16px">
      ${gcGroupAvatar(data, 56)}
      ${isAdminOrOwner
        ? `<div style="display:flex;align-items:center;justify-content:center;gap:6px;margin-top:8px">
             <span id="gc-info-name-display" style="font-weight:600;font-size:15px">${swEsc(data.name)}</span>
             <button class="dm-icon-btn" style="padding:3px" onclick="gcStartRename()" title="Rename"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></button>
           </div>`
        : `<div style="font-weight:600;font-size:15px;margin-top:8px">${swEsc(data.name)}</div>`
      }
    </div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-weight:600;letter-spacing:.04em">MEMBERS</div>
    <div id="gc-info-members" style="display:flex;flex-direction:column;gap:4px">
      ${(data.members || []).map(m => {
        const displayName = nicksResolveDisplay(convKey, m.id, m.name);
        return `<div class="gc-info-member-row" data-id="${swEsc(m.id)}">
          ${gcAvatar(m.name, m.photo, 34)}
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:500">${swEsc(displayName)}${m.group_role === 'owner' ? ' <span style="font-size:10px;color:var(--muted);background:rgba(255,255,255,.07);padding:1px 6px;border-radius:10px">owner</span>' : ''}</div>
            <div style="font-size:11px;color:var(--muted)">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
          </div>
          ${!m.is_me ? `<button class="dm-icon-btn gc-nick-btn" data-id="${swEsc(m.id)}" data-name="${swEsc(m.name)}" title="Set nickname" style="padding:4px">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </button>` : ''}
          ${isAdminOrOwner && !m.is_me ? `<button class="dm-icon-btn" style="color:#ef4444;padding:4px" onclick="gcRemoveMember('${swEsc(m.id)}')" title="Remove"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}
        </div>`;
      }).join('')}
    </div>
    <button class="dm-icon-btn" style="width:100%;margin-top:12px;padding:8px;border-radius:8px;color:#ef4444;justify-content:center;gap:6px;font-size:12px" onclick="gcLeave()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Leave group
    </button>`;

  // Nickname buttons
  modal.querySelectorAll('.gc-nick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id   = btn.dataset.id;
      const name = btn.dataset.name;
      nicksOpenModal(convKey, id, name, true);
    });
  });

  modal.style.display = 'flex';
}

async function gcStartRename() {
  const current = GC.activeGroup?.name || '';
  const newName = prompt('New group name:', current);
  if (!newName?.trim() || newName.trim() === current) return;
  try {
    await api('PATCH', `/api/member/groups/${GC.activeId}`, { name: newName.trim() });
    GC.activeGroup.name = newName.trim();
    setText('gc-topbar-name', newName.trim());
    await gcLoadGroups();
    document.getElementById('gc-info-overlay').style.display = 'none';
  } catch (e) {
    alert(e.message || 'Could not rename group.');
  }
}

async function gcRemoveMember(memberId) {
  if (!confirm('Remove this member from the group?')) return;
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/members/${memberId}`);
    document.getElementById('gc-info-overlay').style.display = 'none';
    gcOpenInfo();
  } catch (e) {
    alert(e.message || 'Could not remove member.');
  }
}

async function gcLeave() {
  if (!confirm('Leave this group?')) return;
  const myId = gcMyId();
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/members/${myId}`);
    document.getElementById('gc-info-overlay').style.display = 'none';
    gcGoBack();
    GC.groups = GC.groups.filter(g => g.id !== GC.activeId);
    gcRenderGroups(GC.groups);
  } catch (e) {
    alert(e.message || 'Could not leave group.');
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────

function initGC() {
  $id('gc-new-btn')?.addEventListener('click', gcOpenCreateModal);
  $id('gc-back-btn')?.addEventListener('click', gcGoBack);
  $id('gc-info-btn')?.addEventListener('click', gcOpenInfo);
  $id('gc-send-btn')?.addEventListener('click', gcSend);
  $id('gc-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); gcSend(); }
  });
  $id('gc-input')?.addEventListener('input', function () {
    this.style.height = '';
    this.style.height = Math.min(this.scrollHeight, 110) + 'px';
  });
  $id('gc-load-earlier')?.addEventListener('click', () => gcLoadMsgs(true));
  gcRefreshBadge();
  setInterval(gcRefreshBadge, 30000);
}

// ─── Patch dmOpenConv to load block status + nicknames ───────────────────────
// Hook into the existing DM module to load block + nickname data

const _origDmOpenConv = typeof dmOpenConv === 'function' ? dmOpenConv : null;
// (Actual monkey-patching done via initDMExtensions below, called after initDM)

function initDMExtensions() {
  // Ensure blocks are preloaded
  blocksEnsureLoaded();

  // Add nickname + block buttons to DM topbar when a conv is opened.
  // We listen on the DM topbar for the custom event dispatched from dmOpenConvPatched.
  // Instead of monkey-patching, we override the relevant functions by wrapping globals.

  const originalDmOpenConv = window.dmOpenConv;
  window.dmOpenConv = async function(conv) {
    await originalDmOpenConv.call(this, conv);
    // After opening: load block status + nicknames
    const peerId  = conv.peer?.id;
    const convKey = conv.conv_key;
    if (peerId) {
      // Check block status
      try {
        const status = await api('GET', `/api/member/blocks/check/${peerId}`);
        DM.activePeer = { ...DM.activePeer, _blockedMe: status.blocked_me };
        dmUpdateBlockedBanner();
        // Update topbar block button
        dmRenderTopbarExtras(convKey, peerId, conv.peer);
      } catch { /* silent */ }
      // Load nicknames
      await nicksLoad(convKey);
      // Apply nickname to topbar
      const peerName = conv.peer?.name;
      const display  = nicksResolveDisplay(convKey, peerId, peerName);
      const topbarName = $id('dm-topbar-name');
      if (topbarName) topbarName.textContent = display;
    }
  };

  const originalDmStartWith = window.dmStartWith;
  window.dmStartWith = async function(memberId, peerHint) {
    await originalDmStartWith.call(this, memberId, peerHint);
    if (memberId) {
      try {
        const status = await api('GET', `/api/member/blocks/check/${memberId}`);
        if (DM.activePeer) DM.activePeer._blockedMe = status.blocked_me;
        dmUpdateBlockedBanner();
        const convKey = DM.activeKey;
        const topbarActions = $id('dm-topbar-actions');
        if (!topbarActions) dmInjectTopbarActions();
        if (convKey) {
          await nicksLoad(convKey);
          const display = nicksResolveDisplay(convKey, memberId, peerHint?.name);
          const topbarName = $id('dm-topbar-name');
          if (topbarName) topbarName.textContent = display;
        }
        dmRenderTopbarExtras(convKey, memberId, peerHint);
      } catch { /* silent */ }
    }
  };
}

function dmInjectTopbarActions() {
  const topbar = $id('dm-topbar');
  if (!topbar || $id('dm-topbar-actions')) return;
  const actions = document.createElement('div');
  actions.id = 'dm-topbar-actions';
  actions.style.cssText = 'display:flex;align-items:center;gap:4px;margin-left:auto';
  topbar.appendChild(actions);
}

function dmRenderTopbarExtras(convKey, peerId, peer) {
  dmInjectTopbarActions();
  const actions = $id('dm-topbar-actions');
  if (!actions) return;
  const isBlocked = BLOCKS.set.has(peerId);

  actions.innerHTML = `
    <button class="dm-icon-btn dm-nick-topbar-btn" title="Set nickname" style="font-size:11px;padding:4px 8px;border-radius:8px;gap:4px">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
      Nickname
    </button>
    <button class="dm-icon-btn dm-block-btn" data-block-member="${swEsc(peerId)}" title="${isBlocked ? 'Unblock' : 'Block'} this member" style="font-size:11px;padding:4px 8px;border-radius:8px;gap:4px;${isBlocked ? 'color:#ef4444' : ''}">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
      ${isBlocked ? 'Unblock' : 'Block'}
    </button>`;

  actions.querySelector('.dm-nick-topbar-btn')?.addEventListener('click', () => {
    if (convKey) nicksOpenModal(convKey, peerId, peer?.name || DM.activePeer?.name || 'Member', false);
  });
  actions.querySelector('.dm-block-btn')?.addEventListener('click', function() {
    blocksToggle(peerId, this);
  });
}

// Hook into openMemberProfile to show block button in member profile modal
const _origOpenMemberProfile = window.openMemberProfile;
window.openMemberProfile = async function(memberId) {
  await (_origOpenMemberProfile || openMemberProfile).call(this, memberId);
  // Inject block button after the modal body renders
  const myId = gcMyId();
  if (!myId || memberId === myId) return;
  await blocksEnsureLoaded();
  const body = $id('member-profile-modal-body');
  if (!body || $id('mpm-block-btn')) return;
  const isBlocked = BLOCKS.set.has(memberId);
  const blockBtn  = document.createElement('button');
  blockBtn.id = 'mpm-block-btn';
  blockBtn.className = 'dm-icon-btn';
  blockBtn.dataset.blockMember = memberId;
  blockBtn.style.cssText = 'width:100%;padding:9px;border-radius:8px;justify-content:center;gap:6px;font-size:12px;margin-top:6px';
  if (isBlocked) blockBtn.style.color = '#ef4444';
  blockBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> ${isBlocked ? 'Unblock' : 'Block'}`;
  blockBtn.addEventListener('click', () => blocksToggle(memberId, blockBtn));
  body.appendChild(blockBtn);
};

// ── MA-35 Boot ────────────────────────────────────────────────────────────────
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => { initGC(); initDMExtensions(); });
} else {
  initGC();
  initDMExtensions();
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNIFIED INBOX — DMs + Groups merged into panel-dms conv list (Instagram-style)
// ═══════════════════════════════════════════════════════════════════════════════

(function() {

  // ── Helper: group avatar HTML (rounded square, letter fallback) ─────────────
  function inboxGroupAv(group, size) {
    if (group.photo_url) {
      return `<img src="${swEsc(group.photo_url)}" alt="${swEsc(group.name)}" style="width:${size}px;height:${size}px;border-radius:12px;object-fit:cover;flex-shrink:0">`;
    }
    const letter = (group.avatar_text || group.name?.[0] || '?').slice(0, 2).toUpperCase();
    return `<div class="gc-group-av" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px">${swEsc(letter)}</div>`;
  }

  // ── Unified render: merges DM.convs + GC.groups, sorts by last_msg_at ───────
  function inboxRender() {
    const container = $id('dm-conv-list');
    if (!container) return;

    $id('dm-conv-loading') && ($id('dm-conv-loading').style.display = 'none');
    container.querySelectorAll('.dm-conv-row, .gc-conv-row, .inbox-group-row').forEach(el => el.remove());

    const dms    = DM.convs  || [];
    const groups = GC.groups || [];

    if (!dms.length && !groups.length) {
      $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = '');
      return;
    }
    $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = 'none');

    // Tag each item with type and normalised sort key
    const items = [
      ...dms.map(c => ({ type: 'dm', data: c, ts: c.last_msg_at || '0' })),
      ...groups.map(g => ({ type: 'group', data: g, ts: g.last_msg_at || '0' })),
    ].sort((a, b) => (b.ts > a.ts ? 1 : b.ts < a.ts ? -1 : 0));

    items.forEach(item => {
      const row = document.createElement('div');

      if (item.type === 'dm') {
        const c = item.data;
        row.className = 'dm-conv-row' + (c.conv_key === DM.activeKey ? ' dm-active-row' : '');
        row.dataset.key  = c.conv_key;
        row.dataset.type = 'dm';
        const preview = c.last_snippet
          ? (c.last_sender_is_me ? 'You: ' : '') + c.last_snippet
          : 'No messages yet';
        row.innerHTML = `
          ${dmAvatar(c.peer?.name, c.peer?.photo, 42)}
          <div class="dm-conv-info">
            <div class="dm-conv-name">${swEsc(c.peer?.name || 'Member')}</div>
            <div class="dm-conv-preview ${c.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
          </div>
          <div class="dm-conv-right">
            <span class="dm-conv-time">${dmTime(c.last_msg_at)}</span>
            ${c.unread_count > 0 ? `<span class="dm-unread-pill">${c.unread_count > 9 ? '9+' : c.unread_count}</span>` : ''}
          </div>`;
        row.addEventListener('click', () => inboxOpenDm(c));

      } else {
        const g = item.data;
        row.className = 'dm-conv-row inbox-group-row' + (g.id === GC.activeId ? ' dm-active-row' : '');
        row.dataset.key  = g.id;
        row.dataset.type = 'group';
        const preview = g.last_snippet
          ? (g.last_sender_is_me ? 'You: ' : (g.last_sender_name ? g.last_sender_name + ': ' : '')) + g.last_snippet
          : 'No messages yet';
        row.innerHTML = `
          ${inboxGroupAv(g, 42)}
          <div class="dm-conv-info">
            <div class="dm-conv-name">${swEsc(g.name)}</div>
            <div class="dm-conv-preview ${g.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
          </div>
          <div class="dm-conv-right">
            <span class="dm-conv-time">${dmTime(g.last_msg_at)}</span>
            ${g.unread_count > 0 ? `<span class="dm-unread-pill">${g.unread_count > 9 ? '9+' : g.unread_count}</span>` : ''}
          </div>`;
        row.addEventListener('click', () => inboxOpenGroup(g));
      }

      container.appendChild(row);
    });
  }

  // ── Open DM — hides gc-window, shows dm-window ────────────────────────────
  function inboxOpenDm(conv) {
    // Switch windows
    const gcWin = $id('gc-window');
    const dmWin = $id('dm-window');
    if (gcWin) gcWin.style.display = 'none';
    if (dmWin) dmWin.style.display = '';

    GC.activeId    = null;
    GC.activeGroup = null;
    gcPausePolling();

    // Highlight row
    document.querySelectorAll('.dm-conv-row').forEach(el => {
      el.classList.toggle('dm-active-row', el.dataset.key === conv.conv_key && el.dataset.type === 'dm');
    });

    // Use the patched dmOpenConv (includes block/nick logic)
    if (typeof window.dmOpenConv === 'function') window.dmOpenConv(conv);
  }

  // ── Open Group — hides dm-window, shows gc-window ────────────────────────
  function inboxOpenGroup(group) {
    // Switch windows
    const dmWin = $id('dm-window');
    const gcWin = $id('gc-window');
    if (dmWin) dmWin.style.display = 'none';
    if (gcWin) gcWin.style.display = '';

    DM.activeKey  = null;
    DM.activePeer = null;

    // Highlight row
    document.querySelectorAll('.dm-conv-row').forEach(el => {
      el.classList.toggle('dm-active-row', el.dataset.key === group.id && el.dataset.type === 'group');
    });

    // gcOpenGroup handles topbar, messages, polling
    if (typeof gcOpenGroup === 'function') gcOpenGroup(group);
  }

  // ── Override gcGoBack to return to unified list ───────────────────────────
  window.gcGoBack = function() {
    const gcWin = $id('gc-window');
    const dmWin = $id('dm-window');
    if (gcWin) gcWin.style.display = 'none';
    if (dmWin) { dmWin.style.display = ''; }

    // Restore empty state on dm-window
    $id('dm-active') && ($id('dm-active').style.display = 'none');
    $id('dm-window-empty') && ($id('dm-window-empty').style.display = '');

    // Mobile: slide sidebar back
    $id('dm-sidebar')?.classList.remove('dm-slide-out');
    $id('dm-window')?.classList.remove('dm-slide-in');

    GC.activeId    = null;
    GC.activeGroup = null;
    gcPausePolling();
    document.querySelectorAll('.dm-conv-row').forEach(el => el.classList.remove('dm-active-row'));
  };

  // ── Also patch gcOpenGroup mobile slide to use dm-sidebar/dm-window ───────
  const _origGcOpenGroup = typeof gcOpenGroup === 'function' ? gcOpenGroup : null;
  if (_origGcOpenGroup) {
    window.gcOpenGroup = async function(group) {
      await _origGcOpenGroup(group);
      // Override the gc-sidebar/gc-window slide with dm-sidebar/dm-window
      $id('gc-sidebar')?.classList.remove('dm-slide-out'); // undo any gc slide
      $id('gc-window')?.classList.remove('dm-slide-in');
      $id('dm-sidebar')?.classList.add('dm-slide-out');
      $id('gc-window')?.classList.add('dm-slide-in');
    };
  }

  // ── Unified load: fetch both convs + groups, then render ─────────────────
  async function inboxLoad() {
    await Promise.all([
      (async () => {
        try {
          const data = await api('GET', '/api/member/dm/conversations');
          DM.convs = data || [];
        } catch { DM.convs = []; }
      })(),
      (async () => {
        try {
          const data = await api('GET', '/api/member/groups');
          GC.groups = data || [];
        } catch { GC.groups = []; }
      })(),
    ]);
    inboxRender();

    // Combined badge on the Messages nav/btb
    const dmUnread = (DM.convs || []).reduce((s, c) => s + (c.unread_count || 0), 0);
    const gcUnread = (GC.groups || []).reduce((s, g) => s + (g.unread_count || 0), 0);
    dmSetBadge(dmUnread + gcUnread);
  }

  // ── Override dmPanelOpened to use unified load ────────────────────────────
  window.dmPanelOpened = async function() {
    DM.panelVisible = true;
    GC.panelVisible = true;
    await inboxLoad();
    dmStartPolling();
    gcStartPolling();
  };

  // ── Override dmRenderConvs so DM polling updates also re-render unified ───
  window.dmRenderConvs = function(list) {
    DM.convs = list;
    inboxRender();
  };

  // ── Override gcRenderGroups so GC polling updates also re-render ──────────
  window.gcRenderGroups = function(list) {
    GC.groups = list;
    inboxRender();
  };

  // ── Override dmFilterConvs to also filter groups ──────────────────────────
  window.dmFilterConvs = function(q) {
    const query = (q || '').toLowerCase().trim();
    if (!query) { inboxRender(); return; }
    const filteredDms    = (DM.convs  || []).filter(c => (c.peer?.name || '').toLowerCase().includes(query));
    const filteredGroups = (GC.groups || []).filter(g => g.name.toLowerCase().includes(query));
    // Temp override for render
    const origDm = DM.convs, origGc = GC.groups;
    DM.convs  = filteredDms;
    GC.groups = filteredGroups;
    inboxRender();
    DM.convs  = origDm;
    GC.groups = origGc;
  };

  // ── New message dropdown wiring ───────────────────────────────────────────
  function initInboxNewBtn() {
    const btn      = $id('dm-new-btn');
    const dropdown = $id('dm-new-dropdown');
    const msgBtn   = $id('dm-new-msg-btn');
    const grpBtn   = $id('dm-new-grp-btn');
    if (!btn || !dropdown) return;

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.style.display = dropdown.style.display === 'none' ? '' : 'none';
    });
    document.addEventListener('click', () => { if (dropdown) dropdown.style.display = 'none'; });

    msgBtn?.addEventListener('click', () => {
      dropdown.style.display = 'none';
      dmOpenPicker();
    });
    grpBtn?.addEventListener('click', () => {
      dropdown.style.display = 'none';
      if (typeof gcOpenCreateModal === 'function') gcOpenCreateModal();
    });

    // Dropdown hover state
    [msgBtn, grpBtn].forEach(b => {
      if (!b) return;
      b.addEventListener('mouseenter', () => b.style.background = 'rgba(255,255,255,.05)');
      b.addEventListener('mouseleave', () => b.style.background = 'none');
    });
  }

  // ── switchPanel: remove 'groups' branch, gc windows live in 'dms' ─────────
  const _origSwitchPanelInbox = typeof switchPanel === 'function' ? switchPanel : null;
  if (_origSwitchPanelInbox) {
    window.switchPanel = function(el) {
      // Remap 'groups' to 'dms' since groups live inside the DMs panel now
      if (el?.dataset?.panel === 'groups') {
        const dmsEl = document.querySelector('[data-panel="dms"]');
        if (dmsEl) { _origSwitchPanelInbox(dmsEl); return; }
      }
      _origSwitchPanelInbox(el);
    };
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  function initUnifiedInbox() {
    initInboxNewBtn();

    // gc-back-btn uses gcGoBack which is now overridden above
    $id('gc-back-btn')?.addEventListener('click', () => window.gcGoBack());
    $id('gc-send-btn')?.addEventListener('click', gcSend);
    $id('gc-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); gcSend(); }
    });
    $id('gc-input')?.addEventListener('input', function() {
      this.style.height = '';
      this.style.height = Math.min(this.scrollHeight, 110) + 'px';
    });
    $id('gc-load-earlier')?.addEventListener('click', () => {
      if (typeof gcLoadMsgs === 'function') gcLoadMsgs(true);
    });
    $id('gc-info-btn')?.addEventListener('click', () => {
      if (typeof gcOpenInfoModal === 'function' && GC.activeId) gcOpenInfoModal(GC.activeId);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUnifiedInbox);
  } else {
    initUnifiedInbox();
  }

})();

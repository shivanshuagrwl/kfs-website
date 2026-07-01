/**
 * kfs-admin-refresh-patch.js — KFS Admin Panel Live Refresh v1.0
 * =========================================================
 * Problem: admin sections only ever loaded their data once, when you
 * clicked into them. Anything that changed on the server after that
 * (a new report, a member update, a new blog view, someone else's admin
 * action, etc.) only showed up after a manual hard refresh of the whole
 * page.
 *
 * This patch adds, to every `.admin-section`:
 *   1. A small "↻ Refresh" button in the section header (skipped where one
 *      already exists, e.g. Dashboard) that re-runs that section's existing
 *      load function on demand — no page reload.
 *   2. Silent background auto-refresh every 20s for whichever section is
 *      currently open, using the exact same authenticated fetch path
 *      (apiFetch / loadAdminData) the section already uses — no new
 *      endpoints, no new auth surface.
 *
 * Auto-refresh safety — it SKIPS a refresh cycle (and just waits for the
 * next tick) whenever any of these are true, so it never clobbers work in
 * progress:
 *   - the browser tab isn't visible
 *   - a modal is open
 *   - the user is currently focused in a text input / textarea / select /
 *     contenteditable field anywhere on the page (covers inline-edit cells)
 *   - a bulk-selection checkbox is currently checked in the visible section
 *
 * HOW TO DEPLOY:
 *   Add this line in index.html (before </body>), AFTER kfs-admin-patch.js:
 *     <script src="/kfs-admin-patch.js" defer></script>
 *     <script src="/kfs-admin-refresh-patch.js" defer></script>
 *
 * Namespaced under window.KFSAdminRefresh.
 */

(function () {
  'use strict';

  const AUTO_REFRESH_MS = 20000;
  const PREF_KEY = 'kfs-admin-autorefresh-enabled';

  function autoRefreshEnabled() {
    const v = localStorage.getItem(PREF_KEY);
    return v === null ? true : v === '1';
  }
  function setAutoRefreshEnabled(on) {
    try { localStorage.setItem(PREF_KEY, on ? '1' : '0'); } catch {}
  }

  function sectionNameFromEl(el) {
    return (el.id || '').replace(/^section-/, '');
  }

  function isEditingSomewhere() {
    const ae = document.activeElement;
    if (ae) {
      const tag = ae.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
      if (ae.isContentEditable) return true;
    }
    return false;
  }

  function isModalOpen() {
    return !!document.querySelector('.modal-overlay.open, .modal-overlay.active');
  }

  function hasBulkSelection(sectionEl) {
    return !!sectionEl.querySelector('.bulk-cb:checked');
  }

  function canRefreshNow(sectionEl) {
    if (document.hidden) return false;
    if (isModalOpen()) return false;
    if (isEditingSomewhere()) return false;
    if (hasBulkSelection(sectionEl)) return false;
    return true;
  }

  function refreshIconSvg(spinning) {
    return `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
      stroke-linecap="round" stroke-linejoin="round" style="${spinning ? 'animation:kfsSpin .7s linear infinite' : ''}">
      <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
      <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/>
    </svg>`;
  }

  function ensureSpinKeyframes() {
    if (document.getElementById('kfs-refresh-spin-style')) return;
    const s = document.createElement('style');
    s.id = 'kfs-refresh-spin-style';
    s.textContent = `@keyframes kfsSpin{to{transform:rotate(360deg)}}`;
    document.head.appendChild(s);
  }

  function buildControl(name) {
    const wrap = document.createElement('div');
    wrap.className = 'kfs-refresh-ctrl';
    wrap.style.cssText = 'display:flex;align-items:center;gap:8px;margin-left:auto;flex-shrink:0';
    wrap.innerHTML = `
      <span class="kfs-refresh-updated" style="font-size:11px;color:var(--grey);white-space:nowrap"></span>
      <button type="button" class="kfs-refresh-btn btn" title="Refresh this section"
        style="font-size:12px;padding:7px 12px;display:flex;align-items:center;gap:6px;background:transparent;border:1px solid var(--border);color:var(--grey);border-radius:8px;cursor:pointer">
        <span class="kfs-refresh-icon">${refreshIconSvg(false)}</span><span>Refresh</span>
      </button>
      <label title="Auto-refresh this panel every 20s" style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--grey);cursor:pointer;user-select:none">
        <input type="checkbox" class="kfs-refresh-auto-toggle" style="accent-color:#58a6ff;cursor:pointer">
        Auto
      </label>`;
    return wrap;
  }

  function setUpdatedLabel(wrap) {
    const el = wrap.querySelector('.kfs-refresh-updated');
    if (el) el.textContent = 'Updated just now';
  }

  async function doRefresh(name, wrap, { silent = false } = {}) {
    if (typeof window.loadAdminData !== 'function') return;
    const btn  = wrap.querySelector('.kfs-refresh-btn');
    const icon = wrap.querySelector('.kfs-refresh-icon');
    if (!silent && btn) { btn.disabled = true; }
    if (icon) icon.innerHTML = refreshIconSvg(true);
    try {
      await window.loadAdminData(name);
      setUpdatedLabel(wrap);
    } catch {
      // loadAdminData's own sections already surface errors inline; nothing extra to do here.
    } finally {
      if (icon) icon.innerHTML = refreshIconSvg(false);
      if (!silent && btn) { btn.disabled = false; }
    }
  }

  const timers = {}; // name -> interval handle

  function stopAutoRefresh(name) {
    if (timers[name]) { clearInterval(timers[name]); delete timers[name]; }
  }

  function startAutoRefresh(name, sectionEl, wrap) {
    stopAutoRefresh(name);
    timers[name] = setInterval(() => {
      if (!sectionEl.classList.contains('active')) { stopAutoRefresh(name); return; }
      if (!autoRefreshEnabled()) return;
      const toggle = wrap.querySelector('.kfs-refresh-auto-toggle');
      if (toggle && !toggle.checked) return;
      if (!canRefreshNow(sectionEl)) return; // just skip this tick, try again next time
      doRefresh(name, wrap, { silent: true });
    }, AUTO_REFRESH_MS);
  }

  function injectControl(sectionEl) {
    const name = sectionNameFromEl(sectionEl);
    if (!name) return;
    if (sectionEl.querySelector('.kfs-refresh-ctrl')) return; // already patched

    const header = sectionEl.querySelector('.admin-header');
    const wrap = buildControl(name);

    if (header) {
      header.appendChild(wrap);
    } else {
      // No standard header in this section — float a small control top-right instead.
      sectionEl.style.position = sectionEl.style.position || 'relative';
      wrap.style.cssText += ';position:absolute;top:10px;right:10px;z-index:2';
      sectionEl.insertBefore(wrap, sectionEl.firstChild);
    }

    const toggle = wrap.querySelector('.kfs-refresh-auto-toggle');
    if (toggle) toggle.checked = autoRefreshEnabled();

    wrap.querySelector('.kfs-refresh-btn')?.addEventListener('click', () => doRefresh(name, wrap));
    toggle?.addEventListener('change', () => {
      setAutoRefreshEnabled(toggle.checked);
      // Keep every section's toggle in sync since the preference is global.
      document.querySelectorAll('.kfs-refresh-auto-toggle').forEach(t => { t.checked = toggle.checked; });
    });
  }

  function patchAll() {
    ensureSpinKeyframes();
    document.querySelectorAll('.admin-section').forEach(sectionEl => {
      const name = sectionNameFromEl(sectionEl);
      if (!name) return;
      injectControl(sectionEl);
    });
  }

  // Hook showAdminSection so auto-refresh starts/stops as the admin navigates,
  // without needing to touch app.js.
  function hookShowAdminSection() {
    if (typeof window.showAdminSection !== 'function' || window.showAdminSection.__kfsRefreshWrapped) return;
    const orig = window.showAdminSection;
    const wrapped = function (name) {
      // Stop the previous section's timer before switching.
      Object.keys(timers).forEach(stopAutoRefresh);
      const ret = orig.apply(this, arguments);
      const sectionEl = document.getElementById('section-' + name);
      if (sectionEl) {
        injectControl(sectionEl);
        const wrap = sectionEl.querySelector('.kfs-refresh-ctrl');
        if (wrap) { setUpdatedLabel(wrap); startAutoRefresh(name, sectionEl, wrap); }
      }
      return ret;
    };
    wrapped.__kfsRefreshWrapped = true;
    window.showAdminSection = wrapped;
  }

  function init() {
    patchAll();
    hookShowAdminSection();
    // If the admin panel is already on a section when this loads (e.g. a
    // refresh that landed straight on a deep link), start its timer too.
    const activeSection = document.querySelector('.admin-section.active');
    if (activeSection) {
      const name = sectionNameFromEl(activeSection);
      const wrap = activeSection.querySelector('.kfs-refresh-ctrl');
      if (name && wrap) startAutoRefresh(name, activeSection, wrap);
    }
    document.addEventListener('visibilitychange', () => {
      // No action needed beyond canRefreshNow()'s document.hidden check —
      // timers keep running but simply no-op while hidden, and resume
      // refreshing on the next tick after the tab becomes visible again.
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.KFSAdminRefresh = { refreshSection: (name) => {
    const el = document.getElementById('section-' + name);
    const wrap = el?.querySelector('.kfs-refresh-ctrl');
    if (el && wrap) doRefresh(name, wrap);
  }};
})();

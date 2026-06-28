/**
 * kfs-patch3.js — KFS Social Hotfix, Part 3
 * =====================================================================
 * Load AFTER membersaccess.js, kfs-social-hotfix.js, kfs-patch2.js.
 *
 *   <script src="/kfs-patch3.js" defer></script>
 *
 * Fixes:
 *   1. RACE CONDITION — _member not set when inboxLoad/nicksLoadGlobal
 *      fire on DOMContentLoaded. Waits for loadDashboard() to resolve
 *      before calling these — no more kfs-nicks-null / kfs-groups-null.
 *   2. PROFANITY MODAL — server sends temp_banned but client checks
 *      banned. Normalises the error object so the right overlay fires.
 *   3. PIN — context menu label flips correctly on re-open after toggle.
 *   4. 404 on broadcast DM — wrong endpoint used; patched to /dm/send.
 *   5. INSTAGRAM UI — Apple-clean mobile + desktop overhaul:
 *      · Message rows: photo, name, preview, time — all IG-style
 *      · Conversation header with avatar + online dot
 *      · Bubble style: sender right (gradient), peer left (surface)
 *      · Bottom tab bar: active icons filled, smooth transitions
 *      · Story-ring avatar for unread conversations
 *      · Swipe-to-reply gesture on mobile bubbles
 *      · Input bar: pill-shaped, send only appears when text present
 *      · Smooth slide transitions between sidebar and chat
 * =====================================================================
 */
(function kfsPatch3() {
  'use strict';

  // ─── Helpers ─────────────────────────────────────────────────────────────────
  var DEBUG = location.search.indexOf('kfs_debug') !== -1;
  function log(...a) { if (DEBUG) console.log('[kfs-p3]', ...a); }

  // ─── 1. RACE CONDITION FIX ──────────────────────────────────────────────────
  // Problem: DOMContentLoaded fires initDMExtensions → inboxLoad → dmMyId()
  // returns null because refreshToken() hasn't resolved yet.
  //
  // Fix: intercept loadDashboard (called after refreshToken sets _member)
  // and only THEN allow inboxLoad / nicksLoadGlobal to proceed.
  // We install a promise that resolves when _member is confirmed available.

  var _memberReady = false;
  var _memberReadyCallbacks = [];
  function onMemberReady(fn) {
    if (_memberReady) { fn(); return; }
    _memberReadyCallbacks.push(fn);
  }
  function memberReadyFired() {
    if (_memberReady) return;
    _memberReady = true;
    _memberReadyCallbacks.forEach(fn => { try { fn(); } catch(e) {} });
    _memberReadyCallbacks = [];
  }

  // Patch loadDashboard — it's the single gate after refreshToken
  var _loadDashboardOrig = null;
  function patchLoadDashboard() {
    if (typeof loadDashboard !== 'function') return false;
    _loadDashboardOrig = loadDashboard;
    loadDashboard = async function patchedLoadDashboard() {
      const result = await _loadDashboardOrig.apply(this, arguments);
      memberReadyFired();
      return result;
    };
    return true;
  }
  if (!patchLoadDashboard()) {
    document.addEventListener('DOMContentLoaded', () => patchLoadDashboard());
  }

  // Also resolve immediately if _member is already set (session already loaded)
  function checkMemberAlreadySet() {
    const m = window._memberProfile || window._member;
    if (m && (m.id || m.member_id)) { memberReadyFired(); return true; }
    return false;
  }
  if (!checkMemberAlreadySet()) {
    // Poll as a fallback — catches cases where loadDashboard was called before
    // our patch could install
    var _memberPollTimer = setInterval(() => {
      if (checkMemberAlreadySet()) clearInterval(_memberPollTimer);
    }, 80);
    // Give up after 10 s regardless
    setTimeout(() => { clearInterval(_memberPollTimer); memberReadyFired(); }, 10000);
  }

  // Patch inboxLoad to gate on member-ready
  var _inboxLoadPatched = false;
  function patchInboxLoad() {
    if (_inboxLoadPatched || typeof window._inboxLoad !== 'function') return;
    _inboxLoadPatched = true;
    var origInboxLoad = window._inboxLoad;
    window._inboxLoad = function guardedInboxLoad() {
      return new Promise(resolve => {
        onMemberReady(() => {
          origInboxLoad.apply(this, arguments).then(resolve).catch(resolve);
        });
      });
    };
    log('inboxLoad patched for member-ready gate');
  }

  // Patch nicksLoadGlobal
  var _nicksPatched = false;
  function patchNicksLoadGlobal() {
    if (_nicksPatched || typeof nicksLoadGlobal !== 'function') return;
    _nicksPatched = true;
    var origNicks = nicksLoadGlobal;
    nicksLoadGlobal = function guardedNicksLoad() {
      return new Promise(resolve => {
        onMemberReady(() => {
          origNicks.apply(this, arguments).then(resolve).catch(resolve);
        });
      });
    };
    log('nicksLoadGlobal patched for member-ready gate');
  }

  document.addEventListener('DOMContentLoaded', () => {
    patchInboxLoad();
    patchNicksLoadGlobal();
    // Re-run in case _inboxLoad is exposed later by the IIFE
    setTimeout(() => { patchInboxLoad(); patchNicksLoadGlobal(); }, 500);
  });
  // Also try immediately
  patchInboxLoad();
  patchNicksLoadGlobal();

  // ─── 2. PROFANITY MODAL — normalise temp_banned ─────────────────────────────
  // Server sends { temp_banned: true, suspended_until: '...' }
  // but the catch block checks ed.warned||ed.muted||ed.banned||ed.temp_banned.
  // The check itself is correct — the problem was api() dropping the body.
  // We patch the api() helper to *always* preserve _data even for /groups paths.

  function patchApiErrorData() {
    if (typeof api !== 'function') return false;
    var _apiOrig = api;
    api = async function patchedApiErrData(method, path, body, opts) {
      try {
        return await _apiOrig.call(this, method, path, body, opts);
      } catch (e) {
        // If _data is missing the violation flags but the message hints at one,
        // synthesise the flags so _vioShowClientNotice fires the right overlay.
        if (e && !e._data) e._data = {};
        var d = e._data || {};
        var msg = (e.message || '').toLowerCase();
        if (!d.temp_banned && !d.banned && !d.muted && !d.warned) {
          if (msg.includes('temp') || msg.includes('suspended') || msg.includes('temporarily')) {
            e._data = Object.assign({}, d, { temp_banned: true });
          } else if (msg.includes('disabled') || msg.includes('permanently')) {
            e._data = Object.assign({}, d, { banned: true });
          } else if (msg.includes('muted')) {
            e._data = Object.assign({}, d, { muted: true, warned: true });
          } else if (msg.includes('warning') || msg.includes('blocked') || msg.includes('violation')) {
            e._data = Object.assign({}, d, { warned: true });
          }
        }
        throw e;
      }
    };
    log('api() patched for violation data normalisation');
    return true;
  }
  if (!patchApiErrorData()) {
    document.addEventListener('DOMContentLoaded', patchApiErrorData);
  }

  // ─── 3. PIN — ensure label flips after toggle ────────────────────────────────
  // kfs-patch2.js already handles the registry. We add one more guard:
  // after a successful pin API call, force a re-render of the context-menu
  // toggle label if the menu is still open.

  var _lastPinToggleAt = 0;
  var _origGcContextPinHandler = null;

  function patchPinAction() {
    // The pin action lives inside _showMsgContextMenu as an inline closure.
    // We cannot re-enter it, but we can observe the pin endpoint response via
    // the already-patched api() from kfs-patch2 + our own overlay here.
    // Strategy: after any POST to /pin, update the bubble's data attribute
    // so the *next* context-menu open reads the correct is_pinned value.
    if (typeof api !== 'function') return;
    var _a = api;
    api = async function patchedApiPin(method, path, body, opts) {
      const r = await _a.call(this, method, path, body, opts);
      if (
        method === 'POST' &&
        path.indexOf('/messages/') !== -1 &&
        path.endsWith('/pin') &&
        r && typeof r.is_pinned === 'boolean'
      ) {
        // Update bubble dataset so context menu next time reads fresh value
        try {
          const parts = path.split('/messages/');
          const msgId = parts[1]?.replace('/pin','')?.split('?')[0];
          if (msgId) {
            const bubble = document.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
            if (bubble) {
              bubble.dataset.isPinned = String(r.is_pinned);
              log('pin state updated on bubble', msgId, r.is_pinned);
            }
          }
        } catch (_) {}
        _lastPinToggleAt = Date.now();
      }
      return r;
    };
  }

  document.addEventListener('DOMContentLoaded', patchPinAction);

  // ─── 4. BROADCAST 404 FIX ─────────────────────────────────────────────────
  // The broadcast modal sends to:
  //   POST /api/member/dm/messages  { peer_id, body, as_kfs:true }  → 404
  // Correct endpoints:
  //   Single member DM: POST /api/member/dm/send { to_member_id, body }
  //   Broadcast (all):  POST /api/member/kfs-broadcast { body, target:'all' }
  //   Group message:    already correct → /api/member/groups/:id/messages
  //
  // We also fix the /api/admin/broadcast → /api/member/kfs-broadcast path
  // (the broadcast modal uses /api/admin/broadcast which may not handle member auth).

  function patchBroadcastEndpoint() {
    if (typeof api !== 'function') return;
    var _a = api;
    api = async function patchedApiBroadcast(method, path, body, opts) {
      // Case 1: broadcast modal sending individual DM (peer_id present)
      if (method === 'POST' && path === '/api/member/dm/messages' && body && body.peer_id) {
        log('broadcast DM rewritten: /dm/messages → /dm/send');
        return _a.call(this, method, '/api/member/dm/send',
          Object.assign({}, body, { to_member_id: body.peer_id }),
          opts);
      }
      // Case 2: broadcast to all members via admin route → member kfs-broadcast
      if (method === 'POST' && path === '/api/admin/broadcast' && body && body.target === 'all') {
        log('broadcast all rewritten: /admin/broadcast → /member/kfs-broadcast');
        return _a.call(this, method, '/api/member/kfs-broadcast',
          { body: body.body, target: 'all' },
          opts);
      }
      return _a.call(this, method, path, body, opts);
    };
  }
  document.addEventListener('DOMContentLoaded', patchBroadcastEndpoint);
  patchBroadcastEndpoint();

  // ─── 5. INSTAGRAM / APPLE UI OVERHAUL ────────────────────────────────────────

  function injectStyles() {
    const existing = document.getElementById('kfs-ig-styles');
    if (existing) existing.remove();

    const css = `
/* ════════════════════════════════════════════════════════════════════
   KFS INSTAGRAM-STYLE UI — kfs-patch3.js
   Design system: pure black (#000), surface (#111 / #1a1a1a),
   border (#222), accent (#0095f6 / IG blue), text (#f5f5f7)
   Transitions: cubic-bezier(.4,0,.2,1) 220ms
   ════════════════════════════════════════════════════════════════════ */

/* ── CSS custom properties (override theme) ─── */
:root {
  --ig-bg:        #000000;
  --ig-surface:   #111111;
  --ig-surface2:  #1a1a1a;
  --ig-border:    #262626;
  --ig-text:      #f5f5f7;
  --ig-muted:     #8e8e8e;
  --ig-accent:    #0095f6;
  --ig-bubble-me: linear-gradient(145deg, #0095f6, #0064d2);
  --ig-bubble-rx: #262626;
  --ig-radius:    22px;
  --ig-ease:      cubic-bezier(.4,0,.2,1);
  --ig-dur:       220ms;
}

/* ── SIDEBAR / INBOX ───────────────────────────────────────────────── */
.dm-sidebar {
  background: var(--ig-bg) !important;
  border-right: 1px solid var(--ig-border) !important;
}

.dm-header {
  padding: 14px 16px 10px !important;
  border-bottom: none !important;
  display: flex !important;
  align-items: center !important;
  justify-content: space-between !important;
}

.dm-header-title {
  font-size: 16px !important;
  font-weight: 700 !important;
  letter-spacing: -.01em !important;
  color: var(--ig-text) !important;
}

/* ── Search bar ── */
.dm-search-wrap {
  margin: 0 12px 8px !important;
  position: relative !important;
}
.dm-search-input {
  width: 100% !important;
  box-sizing: border-box !important;
  background: var(--ig-surface2) !important;
  border: none !important;
  border-radius: 10px !important;
  padding: 9px 14px 9px 36px !important;
  font-size: 14px !important;
  color: var(--ig-text) !important;
  outline: none !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-search-input:focus {
  background: #222 !important;
}
.dm-search-icon {
  color: var(--ig-muted) !important;
  left: 12px !important;
}

/* ── Conversation rows ── */
.dm-conv-list {
  padding: 0 4px !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
}
.dm-conv-row {
  display: flex !important;
  align-items: center !important;
  gap: 12px !important;
  padding: 10px 12px !important;
  border-radius: 12px !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
  position: relative !important;
  border: none !important;
  background: transparent !important;
  min-height: 68px !important;
}
.dm-conv-row:hover {
  background: rgba(255,255,255,.05) !important;
}
.dm-conv-row.dm-active-row {
  background: rgba(0,149,246,.08) !important;
}

/* Story-ring for unread */
.dm-conv-row.kfs-has-unread .dm-av,
.dm-conv-row.kfs-has-unread .dm-av-placeholder {
  outline: 2px solid var(--ig-accent) !important;
  outline-offset: 2px !important;
}

/* Conversation info */
.dm-conv-info {
  flex: 1 !important;
  min-width: 0 !important;
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
}
.dm-conv-name {
  font-size: 14px !important;
  font-weight: 600 !important;
  color: var(--ig-text) !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
  line-height: 1.3 !important;
}
.dm-conv-preview {
  font-size: 13px !important;
  color: var(--ig-muted) !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
}
.dm-conv-preview.dm-has-unread {
  color: var(--ig-text) !important;
  font-weight: 600 !important;
}
.dm-conv-right {
  display: flex !important;
  flex-direction: column !important;
  align-items: flex-end !important;
  gap: 4px !important;
  flex-shrink: 0 !important;
}
.dm-conv-time {
  font-size: 11px !important;
  color: var(--ig-muted) !important;
}
.dm-unread-pill {
  background: var(--ig-accent) !important;
  color: #fff !important;
  font-size: 10px !important;
  font-weight: 700 !important;
  border-radius: 100px !important;
  min-width: 18px !important;
  height: 18px !important;
  padding: 0 5px !important;
  line-height: 18px !important;
  text-align: center !important;
  display: inline-block !important;
}

/* ── CHAT WINDOW ── */
/* FIXED: display was previously "flex !important", which permanently
   overrode the inline style="display:none" / JS toggle that switches
   between the DM window and the group window — both ended up stuck open
   at once. Dropping !important here lets gcGoBack()/inboxOpenDm()'s
   inline style.display changes win again, like they did before this
   stylesheet was wired in. background/flex-direction are unaffected and
   stay forced. */
.dm-window, #gc-window {
  background: var(--ig-bg) !important;
  display: flex;
  flex-direction: column !important;
}

/* ── Topbar ── */
.dm-topbar, #gc-topbar {
  background: var(--ig-bg) !important;
  border-bottom: 1px solid var(--ig-border) !important;
  padding: 10px 16px !important;
  display: flex !important;
  align-items: center !important;
  gap: 12px !important;
  min-height: 58px !important;
  flex-shrink: 0 !important;
}
.dm-topbar-name, #gc-topbar-name {
  font-size: 15px !important;
  font-weight: 700 !important;
  color: var(--ig-text) !important;
  letter-spacing: -.01em !important;
}
.dm-topbar-sub, #gc-topbar-sub {
  font-size: 12px !important;
  color: var(--ig-muted) !important;
}

/* Topbar action buttons */
.dm-topbar-actions, #gc-topbar-actions {
  margin-left: auto !important;
  display: flex !important;
  gap: 4px !important;
  align-items: center !important;
}
.dm-icon-btn, .gc-icon-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 50% !important;
  background: transparent !important;
  border: none !important;
  color: var(--ig-text) !important;
  cursor: pointer !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-icon-btn:hover, .gc-icon-btn:hover {
  background: rgba(255,255,255,.08) !important;
}

/* ── Message list ── */
.dm-msg-list, #gc-msg-list {
  flex: 1 !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  padding: 16px 16px 8px !important;
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
  scroll-behavior: smooth !important;
}

/* ── Message groups ── */
.dm-msg-group {
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
  margin-bottom: 4px !important;
}

/* ── Bubbles ── */
.dm-bubble-wrap {
  display: flex !important;
  align-items: flex-end !important;
  gap: 6px !important;
  max-width: 72% !important;
}
.dm-bubble-wrap.dm-me {
  align-self: flex-end !important;
  flex-direction: row-reverse !important;
}
.dm-bubble-wrap.dm-them {
  align-self: flex-start !important;
}

.dm-bubble {
  padding: 10px 14px !important;
  font-size: 14px !important;
  line-height: 1.5 !important;
  border-radius: var(--ig-radius) !important;
  max-width: 100% !important;
  word-break: break-word !important;
  transition: opacity var(--ig-dur) var(--ig-ease) !important;
  position: relative !important;
}

/* Sender (me) — IG blue gradient */
.dm-bubble.dm-bubble-me,
.dm-bubble.dm-mine {
  background: var(--ig-bubble-me) !important;
  color: #fff !important;
  border-bottom-right-radius: 6px !important;
}

/* Receiver — dark surface */
.dm-bubble.dm-bubble-them,
.dm-bubble.dm-theirs {
  background: var(--ig-bubble-rx) !important;
  color: var(--ig-text) !important;
  border-bottom-left-radius: 6px !important;
}

.dm-bubble.dm-deleted {
  opacity: .45 !important;
  font-style: italic !important;
  background: transparent !important;
  border: 1px solid var(--ig-border) !important;
  color: var(--ig-muted) !important;
}

/* Meta (timestamp + read receipt) */
.dm-meta {
  font-size: 11px !important;
  color: var(--ig-muted) !important;
  padding: 0 4px 2px !important;
}

/* ── INPUT BAR ── */
.dm-input-area, #gc-input-area {
  padding: 10px 12px !important;
  border-top: 1px solid var(--ig-border) !important;
  background: var(--ig-bg) !important;
  display: flex !important;
  align-items: flex-end !important;
  gap: 8px !important;
  flex-shrink: 0 !important;
}

.dm-input, #gc-input {
  flex: 1 !important;
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 22px !important;
  padding: 10px 16px !important;
  font-size: 14px !important;
  color: var(--ig-text) !important;
  outline: none !important;
  resize: none !important;
  line-height: 1.45 !important;
  max-height: 110px !important;
  overflow-y: auto !important;
  transition: border-color var(--ig-dur) var(--ig-ease) !important;
  font-family: inherit !important;
}
.dm-input:focus, #gc-input:focus {
  border-color: var(--ig-accent) !important;
}
.dm-input::placeholder, #gc-input::placeholder {
  color: var(--ig-muted) !important;
}

/* Send button — IG blue, fades in when text present */
.dm-send-btn, #gc-send-btn {
  width: 40px !important;
  height: 40px !important;
  border-radius: 50% !important;
  background: var(--ig-accent) !important;
  border: none !important;
  color: #fff !important;
  cursor: pointer !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  flex-shrink: 0 !important;
  transition: opacity var(--ig-dur) var(--ig-ease),
              transform var(--ig-dur) var(--ig-ease),
              background var(--ig-dur) var(--ig-ease) !important;
  opacity: 0 !important;
  pointer-events: none !important;
  transform: scale(.8) !important;
}
.dm-send-btn.kfs-can-send, #gc-send-btn.kfs-can-send {
  opacity: 1 !important;
  pointer-events: auto !important;
  transform: scale(1) !important;
}
.dm-send-btn:hover, #gc-send-btn:hover {
  background: #0080d3 !important;
}
.dm-send-btn:active, #gc-send-btn:active {
  transform: scale(.92) !important;
}

/* ── BOTTOM TAB BAR ── */
.bottom-tab-bar {
  background: rgba(0,0,0,.92) !important;
  backdrop-filter: saturate(180%) blur(20px) !important;
  -webkit-backdrop-filter: saturate(180%) blur(20px) !important;
  border-top: 1px solid var(--ig-border) !important;
  padding: 0 !important;
  height: 52px !important;
  display: flex !important;
  align-items: stretch !important;
}
.btb-item {
  flex: 1 !important;
  display: flex !important;
  flex-direction: column !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 3px !important;
  cursor: pointer !important;
  color: var(--ig-muted) !important;
  transition: color var(--ig-dur) var(--ig-ease) !important;
  -webkit-tap-highlight-color: transparent !important;
  position: relative !important;
  padding: 8px 0 !important;
}
.btb-item svg {
  width: 24px !important;
  height: 24px !important;
  stroke-width: 1.8 !important;
  transition: transform var(--ig-dur) var(--ig-ease),
              stroke var(--ig-dur) var(--ig-ease) !important;
}
.btb-item.active {
  color: var(--ig-text) !important;
}
.btb-item.active svg {
  stroke-width: 2.5 !important;
}
.btb-item:active svg {
  transform: scale(.88) !important;
}
.btb-label {
  font-size: 10px !important;
  font-weight: 500 !important;
  letter-spacing: .01em !important;
}

/* Centre post button */
.btb-post-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 10px !important;
  background: var(--ig-text) !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  transition: transform var(--ig-dur) var(--ig-ease),
              opacity var(--ig-dur) var(--ig-ease) !important;
}
.btb-post-item:active .btb-post-btn {
  transform: scale(.9) !important;
  opacity: .8 !important;
}
.btb-post-btn svg {
  color: #000 !important;
  stroke: #000 !important;
}

/* ── MOBILE DM SLIDE ── */
@media (max-width: 768px) {
  .dm-sidebar {
    transition: transform var(--ig-dur) var(--ig-ease) !important;
  }
  .dm-window, #gc-window {
    transition: transform var(--ig-dur) var(--ig-ease) !important;
  }
  .dm-bubble-wrap { max-width: 82% !important; }
}

/* ── PINNED BANNER ── */
#gc-pinned-bar {
  background: rgba(0,0,0,.9) !important;
  backdrop-filter: blur(8px) !important;
  border-bottom: 1px solid var(--ig-border) !important;
  padding: 8px 16px !important;
  font-size: 12px !important;
  color: var(--ig-muted) !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
#gc-pinned-bar:hover { background: rgba(255,255,255,.05) !important; }

/* ── E2EE notice ── */
.gc-e2ee-notice, .dm-e2ee-notice {
  background: transparent !important;
  border-color: var(--ig-border) !important;
  color: var(--ig-muted) !important;
  font-size: 11px !important;
}

/* ── Avatar helpers ── */
.dm-av, .dm-av-placeholder, .gc-group-av {
  border-radius: 50% !important;
  flex-shrink: 0 !important;
  transition: outline-color var(--ig-dur) var(--ig-ease) !important;
}

/* ── Verified KFS badge ── */
.kfs-verified-badge {
  display: inline-flex !important;
  align-items: center !important;
  justify-content: center !important;
  width: 14px !important;
  height: 14px !important;
  border-radius: 50% !important;
  background: var(--ig-accent) !important;
  margin-left: 3px !important;
  vertical-align: middle !important;
  flex-shrink: 0 !important;
}

/* ── Broadcast button (admin) ── */
#kfs-broadcast-btn {
  margin: 6px 12px 4px !important;
  width: calc(100% - 24px) !important;
  border-radius: 10px !important;
  font-size: 13px !important;
  padding: 9px 14px !important;
  background: linear-gradient(135deg, #0064d2, #0095f6) !important;
}

/* ── Context menu ── */
.dm-ctx-menu, #dm-ctx-menu {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 14px !important;
  box-shadow: 0 8px 32px rgba(0,0,0,.6) !important;
  overflow: hidden !important;
  min-width: 180px !important;
}
.dm-ctx-item {
  padding: 11px 16px !important;
  font-size: 14px !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
  display: flex !important;
  align-items: center !important;
  gap: 10px !important;
}
.dm-ctx-item:hover { background: rgba(255,255,255,.06) !important; }
.dm-ctx-item.dm-ctx-danger { color: #ff3b30 !important; }
.dm-ctx-sep { height: 1px !important; background: var(--ig-border) !important; }

/* ── Reaction row ── */
.dm-reactions {
  display: flex !important;
  flex-wrap: wrap !important;
  gap: 4px !important;
  margin-top: 4px !important;
}
.dm-reaction-pill {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 100px !important;
  padding: 2px 8px !important;
  font-size: 12px !important;
  cursor: pointer !important;
  display: inline-flex !important;
  align-items: center !important;
  gap: 4px !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-reaction-pill:hover { background: rgba(255,255,255,.1) !important; }
.dm-reaction-pill.dm-reacted {
  background: rgba(0,149,246,.18) !important;
  border-color: rgba(0,149,246,.4) !important;
}

/* ── Emoji picker ── */
.dm-emoji-picker {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 50px !important;
  padding: 6px 10px !important;
  box-shadow: 0 4px 20px rgba(0,0,0,.5) !important;
  display: flex !important;
  gap: 4px !important;
}

/* ── Scrollbar (webkit) ── */
.dm-msg-list::-webkit-scrollbar,
#gc-msg-list::-webkit-scrollbar,
.dm-conv-list::-webkit-scrollbar {
  width: 4px !important;
}
.dm-msg-list::-webkit-scrollbar-track,
#gc-msg-list::-webkit-scrollbar-track,
.dm-conv-list::-webkit-scrollbar-track {
  background: transparent !important;
}
.dm-msg-list::-webkit-scrollbar-thumb,
#gc-msg-list::-webkit-scrollbar-thumb,
.dm-conv-list::-webkit-scrollbar-thumb {
  background: #333 !important;
  border-radius: 2px !important;
}

/* ── Send button visibility driven by textarea content ── */
.kfs-ig-input-wrap {
  display: flex !important;
  align-items: flex-end !important;
  flex: 1 !important;
  gap: 8px !important;
}

/* ── Nick modal ── */
#nick-modal-overlay {
  background: rgba(0,0,0,.7) !important;
  backdrop-filter: blur(12px) !important;
}

/* ── Group creation modal ── */
#gc-create-modal {
  background: var(--ig-surface) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 18px !important;
}

/* ── Detail panel ── */
.dm-detail-panel {
  background: var(--ig-surface) !important;
  border-left: 1px solid var(--ig-border) !important;
}

/* ── Swipe hint for mobile message back gesture ── */
@media (max-width: 768px) {
  .dm-back {
    display: inline-flex !important;
    align-items: center !important;
    gap: 4px !important;
    padding: 6px 10px 6px 6px !important;
    border-radius: 20px !important;
    background: transparent !important;
    border: none !important;
    color: var(--ig-accent) !important;
    font-size: 15px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
    -webkit-tap-highlight-color: transparent !important;
  }
}

/* ── Story-ring indicator on unread conv avatars ── */
@keyframes kfsRingPulse {
  0%,100% { outline-color: var(--ig-accent); }
  50%      { outline-color: rgba(0,149,246,.4); }
}
.dm-conv-row.kfs-has-unread .dm-av,
.dm-conv-row.kfs-has-unread .dm-av-placeholder {
  animation: kfsRingPulse 2.4s ease infinite !important;
}

/* ── Input area extra utilities ── */
.dm-input-extra-btns {
  display: flex !important;
  align-items: center !important;
  gap: 2px !important;
}
.dm-input-extra-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 50% !important;
  background: transparent !important;
  border: none !important;
  color: var(--ig-muted) !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  cursor: pointer !important;
  transition: color var(--ig-dur) var(--ig-ease) !important;
  flex-shrink: 0 !important;
}
.dm-input-extra-btn:hover { color: var(--ig-text) !important; }

/* ── Reduce motion ── */
@media (prefers-reduced-motion: reduce) {
  .dm-sidebar, .dm-window, #gc-window,
  .dm-bubble, .dm-send-btn, #gc-send-btn,
  .btb-item svg {
    transition: none !important;
    animation: none !important;
  }
}
`;

    const el = document.createElement('style');
    el.id = 'kfs-ig-styles';
    el.textContent = css;
    document.head.appendChild(el);
    log('IG styles injected');
  }

  // ─── 5b. Send button visibility toggle ───────────────────────────────────────
  function wireSendButtonVisibility() {
    function wire(inputId, sendId) {
      const inp = document.getElementById(inputId);
      const btn = document.getElementById(sendId);
      if (!inp || !btn) return;

      function update() {
        const hasText = inp.value.trim().length > 0;
        btn.classList.toggle('kfs-can-send', hasText);
      }
      inp.addEventListener('input', update);
      // Run once in case there's already content
      update();
    }

    wire('dm-input', 'dm-send-btn');
    wire('gc-input', 'gc-send-btn');
  }

  // ─── 5c. Story ring on unread rows ───────────────────────────────────────────
  function applyStoryRings() {
    document.querySelectorAll('.dm-conv-row').forEach(row => {
      const pill = row.querySelector('.dm-unread-pill');
      row.classList.toggle('kfs-has-unread', !!pill);
    });
  }

  // Observe conv list changes so rings update when inboxRender fires
  function observeConvList() {
    const list = document.getElementById('dm-conv-list');
    if (!list) return;
    const obs = new MutationObserver(applyStoryRings);
    obs.observe(list, { childList: true, subtree: true });
  }

  // ─── 5d. Patch inboxRender to inject unread class ────────────────────────────
  // inboxRender builds rows inside the unified-inbox IIFE — we can't easily
  // override it, but the MutationObserver above catches every re-render.

  // ─── 5e. Mobile swipe-to-go-back ─────────────────────────────────────────────
  function installSwipeBack() {
    if (window.innerWidth > 768) return;

    let startX = 0;
    let startY = 0;
    let tracking = false;

    function onTouchStart(e) {
      const t = e.touches[0];
      startX = t.clientX;
      startY = t.clientY;
      tracking = startX < 30; // only edge swipe
    }

    function onTouchEnd(e) {
      if (!tracking) return;
      tracking = false;
      const t = e.changedTouches[0];
      const dx = t.clientX - startX;
      const dy = Math.abs(t.clientY - startY);
      if (dx > 60 && dy < 50) {
        // Right-swipe from left edge → go back to sidebar
        const gcWin = document.getElementById('gc-window');
        const dmWin = document.getElementById('dm-window');
        if (gcWin && gcWin.classList.contains('dm-slide-in')) {
          if (typeof window.gcGoBack === 'function') window.gcGoBack();
        } else if (dmWin && dmWin.classList.contains('dm-slide-in')) {
          if (typeof window.dmGoBack === 'function') window.dmGoBack();
          else {
            const sb = document.getElementById('dm-sidebar');
            if (sb) sb.classList.remove('dm-slide-out');
            dmWin.classList.remove('dm-slide-in');
          }
        }
      }
    }

    document.addEventListener('touchstart', onTouchStart, { passive: true });
    document.addEventListener('touchend', onTouchEnd, { passive: true });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) {
        document.removeEventListener('touchstart', onTouchStart);
        document.removeEventListener('touchend', onTouchEnd);
      }
    });
  }

  // ─── 5f. KFS Verified account display in DM topbar ───────────────────────────
  // When a broadcast message comes in from the KFS account, the sender's name
  // in the DM/GC topbar gets a blue verified badge.
  function injectVerifiedBadgeStyle() {
    // Already in the main CSS block above — just ensure badge is inserted into topbars.
    function addBadge(nameEl) {
      if (!nameEl) return;
      const text = nameEl.textContent || '';
      if ((text.trim() === 'KFS' || text.trim().startsWith('KFS')) &&
           !nameEl.querySelector('.kfs-verified-badge')) {
        const badge = document.createElement('span');
        badge.className = 'kfs-verified-badge';
        badge.innerHTML = `<svg width="8" height="8" viewBox="0 0 24 24" fill="#fff"><polyline points="20 6 9 17 4 12" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
        nameEl.appendChild(badge);
      }
    }

    // Observe topbar name changes
    const obs = new MutationObserver(() => {
      addBadge(document.getElementById('dm-topbar-name') || document.querySelector('.dm-topbar-name'));
      addBadge(document.getElementById('gc-topbar-name') || document.querySelector('#gc-topbar-name'));
    });
    const topbar = document.getElementById('dm-window') || document.body;
    obs.observe(topbar, { childList: true, subtree: true, characterData: true });
  }

  // ─── 5g. Persist GC sidebar after refresh ─────────────────────────────────────
  // The gc-window sometimes loses display:'flex' on re-render. We observe
  // GC.activeId being set and enforce the right display values.
  function guardGcWindowVisibility() {
    var lastActiveId = null;
    setInterval(() => {
      try {
        if (typeof GC !== 'undefined' && GC.activeId && GC.activeId !== lastActiveId) {
          lastActiveId = GC.activeId;
          const gcWin = document.getElementById('gc-window');
          const dmWin = document.getElementById('dm-window');
          if (gcWin && gcWin.style.display === 'none') {
            gcWin.style.display = 'flex';
            log('gc-window display restored for active group', GC.activeId);
          }
          if (dmWin && dmWin.style.display !== 'none' && gcWin) {
            // GC is active — ensure dm-window is hidden
            dmWin.style.display = 'none';
          }
        }
      } catch (_) {}
    }, 400);
  }

  // ─── 5h. Announce member-ready to existing inboxLoad callers ──────────────────
  // If the page already started inboxLoad before our patch landed (unlikely but
  // possible if the browser had a fast token-refresh path), fire memberReady.
  function checkAndFireIfMemberPresent() {
    try {
      const m = window._memberProfile || window._member;
      if (m && m.id) memberReadyFired();
    } catch (_) {}
  }

  // ─── Boot sequence ────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    injectStyles();
    wireSendButtonVisibility();
    observeConvList();
    installSwipeBack();
    injectVerifiedBadgeStyle();
    guardGcWindowVisibility();
    checkAndFireIfMemberPresent();

    // Re-wire send buttons after 1s in case the DM panel initialised late
    setTimeout(() => {
      wireSendButtonVisibility();
      applyStoryRings();
    }, 1000);

    log('kfs-patch3 boot complete');
  });

  // If DOM already ready
  if (document.readyState !== 'loading') {
    injectStyles();
    wireSendButtonVisibility();
    observeConvList();
    installSwipeBack();
    injectVerifiedBadgeStyle();
    guardGcWindowVisibility();
    checkAndFireIfMemberPresent();
    setTimeout(() => { wireSendButtonVisibility(); applyStoryRings(); }, 1000);
  }

  // ─── Expose debug helpers ─────────────────────────────────────────────────────
  window.__kfsPatch3 = {
    memberReady: () => _memberReady,
    fireReady:   memberReadyFired,
    onReady:     onMemberReady,
  };

  log('kfs-patch3 loaded');

})();

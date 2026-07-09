/**
 * kfs-patch6.js — Instant Feed Refresh + Dynamic Composer Textareas
 * =====================================================================
 * Load this AFTER membersaccess.js and AFTER kfs-patch5.js.
 * Add at the bottom of membersaccess.html:
 *     <script src="/kfs-patch6.js" defer></script>
 *
 * -----------------------------------------------------------------------
 * BUG #1 — "I post, but it doesn't show up in the feed right away"
 * -----------------------------------------------------------------------
 * Root cause (found in server.js):
 *   GET /api/member/studio/feed sends `Cache-Control: public, max-age=30,
 *   stale-while-revalidate=60` (via cacheFor(res,30)), overriding the
 *   blanket `no-store` the rest of /api gets.
 *
 *   swSubmitPost() already does the right thing client-side — it calls
 *   `await swLoadFeed(true)` immediately after a successful post, and the
 *   server already busts its OWN in-memory cache on write
 *   (memInvalidate("studio:feed:")). Both of those are correct.
 *
 *   The problem is a third layer neither of those touches: the browser's
 *   own HTTP cache. Because the response is marked `public, max-age=30`,
 *   the very next GET to the exact same URL (?page=1) within 30s is
 *   answered straight from the browser cache and never reaches the
 *   network at all — so the poster's own client renders the pre-post
 *   snapshot. This is the same class of bug already fixed for
 *   /groups and /nicknames in the api() helper (see the comment there);
 *   /studio/feed just wasn't included in that fix.
 *
 * Fix: cache-bust GET requests to /studio/feed the same way, by wrapping
 * window.api so every feed fetch gets a unique query string. No server
 * change needed, and pagination/"foryou" behavior is untouched since the
 * server-side memCache (60s, keyed by page+tag) still does the real work
 * of keeping DB load down — this only defeats the browser-level cache.
 *
 * -----------------------------------------------------------------------
 * BUG #2 — "input textboxes need to be dynamic"
 * -----------------------------------------------------------------------
 * The composer textareas (#sw-caption, #sw-text-body, #sw-video-caption)
 * are fixed-height (`rows="3"`/`"4"`, `resize:none`) — typing past that
 * just scrolls inside a tiny box instead of the box growing. This patch
 * makes them auto-grow to fit content, and re-measures them whenever
 * their value is set programmatically (switching post type, opening the
 * edit modal with an existing long caption) since those don't fire an
 * `input` event on their own.
 */

(function () {
  'use strict';

  const GROW_IDS = ['sw-caption', 'sw-text-body', 'sw-video-caption'];

  function autoGrow(el) {
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = el.scrollHeight + 'px';
  }

  function autoGrowById(id) {
    autoGrow(document.getElementById(id));
  }

  function growAll() {
    GROW_IDS.forEach(autoGrowById);
  }

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  /* ── 1. Feed cache-busting ────────────────────────────────────────────── */

  function hookApiCacheBust() {
    if (typeof window.api !== 'function' || window.api.__kfsFeedCacheBustWrapped) return;
    const orig = window.api;
    const wrapped = function (method, path, body, isForm) {
      if (
        typeof path === 'string' &&
        String(method).toUpperCase() === 'GET' &&
        path.includes('/studio/feed') &&
        !path.includes('_cb=')
      ) {
        path += (path.includes('?') ? '&' : '?') + '_cb=' + Date.now() + Math.random().toString(36).slice(2);
      }
      return orig.call(this, method, path, body, isForm);
    };
    wrapped.__kfsFeedCacheBustWrapped = true;
    window.api = wrapped;
  }

  /* ── 2. Auto-grow textareas ───────────────────────────────────────────── */

  function hookInputListeners() {
    // Delegated so it works even though these fields live inside a modal
    // that may be re-rendered/hidden rather than always present.
    document.addEventListener('input', (e) => {
      if (e.target && GROW_IDS.includes(e.target.id)) autoGrow(e.target);
    });
  }

  function hookProgrammaticFills() {
    // swSetPostType shows/hides sections — resize on every switch so a
    // section that was hidden (and therefore had scrollHeight 0) is
    // measured correctly once visible.
    if (typeof window.swSetPostType === 'function' && !window.swSetPostType.__kfsGrowWrapped) {
      const orig = window.swSetPostType;
      const wrapped = function (type) {
        const ret = orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swSetPostType = wrapped;
    }
    // swOpenEditModal sets .value directly (pre-filling an existing long
    // caption/description) — no input event fires, so resize explicitly
    // once the fields are populated.
    if (typeof window.swOpenEditModal === 'function' && !window.swOpenEditModal.__kfsGrowWrapped) {
      const orig = window.swOpenEditModal;
      const wrapped = async function (projectId) {
        const ret = await orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swOpenEditModal = wrapped;
    }
    // swResetPostModal clears fields back to empty — collapse back down
    // to the natural min-height instead of staying stretched out.
    if (typeof window.swResetPostModal === 'function' && !window.swResetPostModal.__kfsGrowWrapped) {
      const orig = window.swResetPostModal;
      const wrapped = function () {
        const ret = orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swResetPostModal = wrapped;
    }
  }

  /* ── Boot ──────────────────────────────────────────────────────────────── */

  function init() {
    let tries = 0;
    const tryHook = () => {
      tries++;
      const haveCore = typeof window.api === 'function';
      if (haveCore) {
        hookApiCacheBust();
        hookInputListeners();
        hookProgrammaticFills();
        return;
      }
      if (tries < 40) setTimeout(tryHook, 250);
    };
    tryHook();
  }

  ready(init);
})();

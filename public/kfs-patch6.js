/**
 * kfs-patch6.js — Instant Feed Refresh + Dynamic Composer Textareas + Input Gap
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
 *
 * -----------------------------------------------------------------------
 * BUG #3 — "2-3px gap between the input border and the displayed text"
 * -----------------------------------------------------------------------
 * Applies to all post/comment input boxes:
 *   - Comment + reply input pill (.studio-comment-input-row)
 *   - Composer title/tags/domain rows (.composer-field-row)
 *   - Composer caption/text/video-caption textareas
 *
 * The comment input pill already uses the "border lives on the outer
 * wrapper, the actual <input> stays borderless inside it" structure —
 * its padding is just bigger than 2-3px, so we tighten it. The composer
 * field rows and caption textareas don't have that wrapper at all today
 * (rows use a bottom divider, textareas have no border), so this gives
 * them the same box: a bordered container with the real <input>/
 * <textarea> borderless and padded ~3px inside it — same technique,
 * done in CSS via padding/border on the row/field itself rather than an
 * extra DOM node, since the box model already guarantees text can't
 * touch the border once padding > 0. IDs are untouched, so none of the
 * existing swSubmitPost/swPostComment/char-counter code needs to change.
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

  /* ── 2. 2-3px border-to-text gap on post/comment input boxes ─────────── */

  function injectTightGapCSS() {
    if (document.getElementById('kfs-p6-tight-gap')) return;
    const style = document.createElement('style');
    style.id = 'kfs-p6-tight-gap';
    style.textContent = `
      /* Comment + reply input pill — already wrapper(border)+input(borderless);
         just tighten the vertical padding to ~3px. */
      .studio-comment-input-row {
        padding: 3px 6px 3px 14px !important;
      }

      /* Composer title/tags/domain — turn the bottom-divider list rows into
         individually boxed inputs, borderless <input> inside, ~3px gap. */
      .composer-field-row {
        border: 1px solid #1c1c1e !important;
        border-bottom: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 3px 12px !important;
        margin-bottom: 8px !important;
      }
      .composer-field-row:last-of-type {
        border-bottom: 1px solid #1c1c1e !important;
        margin-bottom: 8px !important;
      }
      .composer-field-row--collab {
        padding-top: 8px !important;
      }

      /* Composer caption / text-body / video-caption — give them a border
         box with a tight ~3px inset instead of sitting borderless flush
         against the section edge. */
      .composer-caption,
      .composer-text-body {
        border: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 3px 8px !important;
        box-sizing: border-box !important;
      }
    `;
    document.head.appendChild(style);
  }

  /* ── 3. Auto-grow textareas ───────────────────────────────────────────── */

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
    injectTightGapCSS(); // pure CSS, doesn't need to wait on membersaccess.js globals
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

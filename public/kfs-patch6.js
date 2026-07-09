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
 * its padding is just bigger than needed, so we tighten it. The composer
 * field rows and caption textareas don't have that wrapper at all today
 * (rows use a bottom divider, textareas have no border), so this gives
 * them the same box: a bordered container with the real <input>/
 * <textarea> borderless inside it — same technique, done in CSS via
 * padding/border on the row/field itself rather than an extra DOM node.
 * IDs are untouched, so none of the existing swSubmitPost/swPostComment/
 * char-counter code needs to change.
 *
 * Two follow-on issues showed up once the gap was actually this tight:
 *
 * 1) The sitewide base rule `input:focus, textarea:focus { box-shadow: 0
 *    0 0 3px rgba(10,132,255,.25) }` (membersaccess.html's global
 *    stylesheet) draws its blue glow flush against the element's own
 *    edge — which, with ~0 padding on the input itself, lands right on
 *    top of the leading character(s). Fixed by suppressing that glow on
 *    these fields and moving the focus indication to the wrapper's
 *    border-color instead, where there's room for it.
 *
 * 2) The comment pill's border-radius is 24px (a full pill). Shrinking
 *    the box's height without a big enough left inset means the rounded
 *    corner's own curve reaches past the padding into the text — not a
 *    focus-state thing at all, just geometry, and it was there whether
 *    focused or not. Fixed by giving the pill (and the other boxes, at
 *    their own smaller radii) enough left padding to clear the curve.
 *    The reply row's inline `padding-left:30px` indent is preserved by
 *    leaving padding-left off the !important list here.
 */

(function () {
  'use strict';

  // Version marker — bump this string every time this file changes.
  // Open DevTools Console after a hard refresh and look for this line.
  // If you DON'T see it (or see an older version string), your browser
  // is still running a cached copy of this file, not the one that was
  // just uploaded — that's almost certainly why a fix "doesn't show up"
  // even though the code itself is correct. Hard-refresh (Ctrl/Cmd+Shift+R)
  // or clear cache for this site and reload.
  console.log('[kfs-patch6] v3 loaded — input-gap padding: comment=22px, composer=16px/14px');

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
      /* Comment + reply input pill — already wrapper(border)+input(borderless).
         NOTE: border-radius here is 24px (full pill). Shrinking the box's
         height without enough left inset makes the rounded corner's own
         curve reach past the padding and into the text — which is exactly
         what was still happening. Padding-left is deliberately NOT
         !important so the reply row's inline padding-left:30px (its
         indent under the parent comment) still wins over this base value. */
      .studio-comment-input-row {
        padding-top: 6px !important;
        padding-bottom: 6px !important;
        padding-right: 10px !important;
        padding-left: 22px;
      }

      /* Composer title/tags/domain — turn the bottom-divider list rows into
         individually boxed inputs, borderless <input> inside. Left padding
         kept comfortably past the 10px corner radius so the curve can't
         reach the text. */
      .composer-field-row {
        border: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 6px 16px !important;
        margin-bottom: 8px !important;
      }
      .composer-field-row:last-of-type {
        margin-bottom: 8px !important;
      }
      .composer-field-row--collab {
        padding-top: 8px !important;
      }

      /* Composer caption / text-body / video-caption — same logic: padding
         kept clear of the 10px corner radius. */
      .composer-caption,
      .composer-text-body {
        border: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 7px 14px !important;
        box-sizing: border-box !important;
      }

      /* The actual inputs/textareas have ~0 padding of their own — all the
         spacing lives on the wrapper/box above. There's also a sitewide
         base rule (input:focus/textarea:focus) that adds a blue
         box-shadow glow (0 0 0 3px rgba(10,132,255,.25)) directly on the
         focused element itself. With zero padding on the element, that
         glow sits right on top of the text and clips the first
         character(s) — that's the blue cutting into "Add a comment...".
         Kill the glow/outline on the fields themselves and show focus on
         the box instead, where there's room for it. */
      .studio-comment-input:focus,
      .composer-input:focus,
      .composer-caption:focus,
      .composer-text-body:focus {
        outline: none !important;
        box-shadow: none !important;
      }
      .studio-comment-input-row:focus-within,
      .composer-field-row:focus-within {
        border-color: #0095f6 !important;
      }
      .composer-caption:focus,
      .composer-text-body:focus {
        border-color: #0095f6 !important;
      }
    `;
    // IMPORTANT: appended to the END of <body>, not <head>. This file has
    // several <style> blocks embedded inside <body> itself (not just the
    // usual <head> stylesheet), and <head> always precedes <body> in the
    // DOM regardless of when a script runs — so a style appended to <head>
    // can never win a same-specificity, non-!important cascade tie against
    // ANY of those body-embedded rules, including the base
    // .studio-comment-input-row padding-left this patch is meant to
    // override. Appending to the end of <body> guarantees this style is
    // last in source order and actually wins.
    document.body.appendChild(style);
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

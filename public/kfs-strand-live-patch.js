/**
 * kfs-strand-live-patch.js — Social Strand Live Updates v1.0
 * =========================================================
 * Problem: your own posts/reactions already update instantly (swLoadFeed /
 * swToggleReaction handle that), but content from OTHER members — new posts
 * to the feed, new comments on a post you have open — only appeared after
 * leaving and re-entering the page (a hard refresh).
 *
 * This patch adds, without modifying membersaccess.js:
 *   1. Feed: polls quietly every 25s. If there's a newer post than what's
 *      currently on screen, shows a small "New posts" pill above the feed —
 *      tapping it does a normal swLoadFeed(true) reset. (We show a pill
 *      rather than silently inserting posts so we never yank the feed out
 *      from under someone mid-scroll or mid-read.)
 *   2. Comments: while a post's detail/comments modal is open, polls every
 *      6s and refreshes the comment list in place if new comments have
 *      arrived. Skipped for a cycle (not cancelled — just retried next
 *      tick) if you're actively typing a reply, so nothing you're writing
 *      gets wiped.
 *
 * Both use the same authenticated `api()` helper and existing endpoints
 * already used by the page — no new endpoints, no new auth surface.
 *
 * HOW TO DEPLOY:
 *   Add this line in membersaccess.html (before </body>), AFTER kfs-patch4.js:
 *     <script src="/kfs-patch4.js" defer></script>
 *     <script src="/kfs-strand-live-patch.js" defer></script>
 */

(function () {
  'use strict';

  const FEED_POLL_MS    = 25000;
  const COMMENTS_POLL_MS = 6000;

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  /* ═══════════════════════════════════════════════════════════════════════
     1. FEED — "New posts" pill
     ═══════════════════════════════════════════════════════════════════════ */

  let _feedTopId = null;
  let _feedPollTimer = null;
  let _pillEl = null;

  function feedGridVisible() {
    const grid = document.getElementById('studio-feed');
    return !!grid && !!grid.offsetParent;
  }

  function currentTopIdOnScreen() {
    const grid = document.getElementById('studio-feed');
    const first = grid?.querySelector('[data-project-id]');
    return first?.dataset.projectId || null;
  }

  function ensurePill() {
    if (_pillEl) return _pillEl;
    const grid = document.getElementById('studio-feed');
    if (!grid || !grid.parentNode) return null;
    const pill = document.createElement('button');
    pill.type = 'button';
    pill.id = 'kfs-strand-newposts-pill';
    pill.style.cssText = `
      display:none;position:sticky;top:8px;z-index:5;margin:0 auto 12px;padding:9px 18px;
      background:#0a84ff;color:#fff;border:none;border-radius:999px;font-size:13px;font-weight:600;
      cursor:pointer;box-shadow:0 4px 14px rgba(10,132,255,.35);
    `;
    pill.textContent = '↑ New posts';
    pill.addEventListener('click', () => {
      pill.style.display = 'none';
      if (typeof window.swLoadFeed === 'function') window.swLoadFeed(true);
    });
    grid.parentNode.insertBefore(pill, grid);
    _pillEl = pill;
    return pill;
  }

  function showPill() {
    const pill = ensurePill();
    if (pill) pill.style.display = '';
  }

  async function feedPollTick() {
    if (!feedGridVisible()) return;
    if (window.SW && window.SW.feedLoading) return;
    if (_pillEl && _pillEl.style.display !== 'none') return; // already showing, don't re-check
    try {
      let url = `/api/member/studio/feed?page=1`;
      if (window.SW?.feedTag) url += `&tag=${encodeURIComponent(window.SW.feedTag)}`;
      if (window.SW?.feedSort === 'foryou') url += `&sort=foryou`;
      const resp = await window.api('GET', url);
      const data = resp.feed || resp || [];
      if (!data.length) return;
      const latestId = String(data[0].id);
      const onScreenTop = currentTopIdOnScreen();
      if (!_feedTopId) _feedTopId = onScreenTop; // first tick baseline
      if (latestId !== _feedTopId && latestId !== onScreenTop) {
        showPill();
      }
    } catch {
      // Silent — this is a background nicety, not a user-initiated action.
    }
  }

  function startFeedPoll() {
    stopFeedPoll();
    _feedTopId = currentTopIdOnScreen();
    _feedPollTimer = setInterval(feedPollTick, FEED_POLL_MS);
  }
  function stopFeedPoll() {
    if (_feedPollTimer) { clearInterval(_feedPollTimer); _feedPollTimer = null; }
  }

  function hookSwLoadFeed() {
    if (typeof window.swLoadFeed !== 'function' || window.swLoadFeed.__kfsLiveWrapped) return;
    const orig = window.swLoadFeed;
    const wrapped = async function (reset) {
      const ret = await orig.apply(this, arguments);
      // Any successful load (own post, manual refresh, pill tap, pagination)
      // re-baselines what "top of feed" means and clears the pill.
      _feedTopId = currentTopIdOnScreen();
      if (_pillEl) _pillEl.style.display = 'none';
      if (!_feedPollTimer) startFeedPoll();
      return ret;
    };
    wrapped.__kfsLiveWrapped = true;
    window.swLoadFeed = wrapped;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     2. COMMENTS — live refresh while a post's detail modal is open
     ═══════════════════════════════════════════════════════════════════════ */

  let _commentsPollTimer = null;
  let _lastCommentsSig = null;

  function commentsListFocused() {
    const list = document.getElementById('sw-comments-list');
    return !!(list && document.activeElement && list.contains(document.activeElement));
  }

  function commentsSignature(comments) {
    // Cheap, order-sensitive fingerprint — id + reply count is enough to
    // detect "something changed" without a deep diff.
    const walk = (c) => `${c.id}:${(c.replies || []).map(walk).join(',')}`;
    return (comments || []).map(walk).join('|');
  }

  async function commentsPollTick() {
    const projectId = window.SW?.detailProjectId;
    const overlay = document.getElementById('studio-detail-modal-overlay');
    if (!projectId || !overlay || overlay.style.display !== 'flex') { stopCommentsPoll(); return; }
    if (commentsListFocused()) return; // user is typing a reply — try again next tick
    try {
      const cResp = await window.api('GET', `/api/member/studio/projects/${projectId}/comments`);
      const comments = cResp.comments || cResp || [];
      const sig = commentsSignature(comments);
      if (sig === _lastCommentsSig) return; // nothing new
      _lastCommentsSig = sig;
      const list = document.getElementById('sw-comments-list');
      if (list && typeof window.swRenderComments === 'function') {
        list.innerHTML = window.swRenderComments(comments, projectId);
      }
      // Keep the visible comment count in the meta row in sync too.
      const countEl = overlay.querySelector('.studio-detail-stat:last-child');
      if (countEl) {
        const flat = (arr) => arr.reduce((n, c) => n + 1 + flat(c.replies || []), 0);
        countEl.innerHTML = countEl.innerHTML.replace(/[\d.,km]+$/i, String(flat(comments)));
      }
    } catch {
      // Silent — background nicety.
    }
  }

  function startCommentsPoll() {
    stopCommentsPoll();
    _lastCommentsSig = null;
    _commentsPollTimer = setInterval(commentsPollTick, COMMENTS_POLL_MS);
  }
  function stopCommentsPoll() {
    if (_commentsPollTimer) { clearInterval(_commentsPollTimer); _commentsPollTimer = null; }
  }

  function hookDetailModal() {
    if (typeof window.swOpenDetail === 'function' && !window.swOpenDetail.__kfsLiveWrapped) {
      const orig = window.swOpenDetail;
      const wrapped = async function (projectId) {
        const ret = await orig.apply(this, arguments);
        _lastCommentsSig = null; // force first comparison to pass on next tick
        startCommentsPoll();
        return ret;
      };
      wrapped.__kfsLiveWrapped = true;
      window.swOpenDetail = wrapped;
    }
    if (typeof window.swCloseDetailModal === 'function' && !window.swCloseDetailModal.__kfsLiveWrapped) {
      const orig = window.swCloseDetailModal;
      const wrapped = function () {
        stopCommentsPoll();
        return orig.apply(this, arguments);
      };
      wrapped.__kfsLiveWrapped = true;
      window.swCloseDetailModal = wrapped;
    }
  }

  /* ── Boot ──────────────────────────────────────────────────────────────── */

  function init() {
    // These globals (swLoadFeed, swOpenDetail, swCloseDetailModal, api, SW)
    // are all defined in membersaccess.js. Poll briefly for readiness rather
    // than assuming exact script execution order.
    let tries = 0;
    const tryHook = () => {
      tries++;
      const haveCore = typeof window.api === 'function' && typeof window.swLoadFeed === 'function';
      if (haveCore) {
        hookSwLoadFeed();
        hookDetailModal();
        if (feedGridVisible()) startFeedPoll();
        document.addEventListener('visibilitychange', () => {
          // Timers already no-op appropriately via their own visibility/open
          // checks each tick; nothing extra needed here.
        });
        return;
      }
      if (tries < 40) setTimeout(tryHook, 250); // give membersaccess.js up to ~10s to finish defining globals
    };
    tryHook();
  }

  ready(init);
})();

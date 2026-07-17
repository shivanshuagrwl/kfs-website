/**
 * kfs-patch8.js — Tour polish, emoji → SVG cleanup, dedup timestamps,
 *                 merge My Movies + My Works, fix broken "Request Edit"
 * =====================================================================
 * Load this LAST, after kfs-patch7.js:
 *   <script src="/kfs-patch7.js" defer></script>
 *   <script src="/kfs-patch8.js" defer></script>
 *
 * Fixes five separate things, each in its own IIFE below so they can be
 * lifted out independently later if needed:
 *
 *   1. #work-edit-modal-overlay never actually appeared. The element has
 *      an inline `style="display:none"` in the HTML, and openWorkEditModal()
 *      only ever did `overlay.classList.add('open')`. Inline styles beat
 *      stylesheet rules regardless of selector specificity, so the
 *      `#work-edit-modal-overlay.open { display:flex }` rule never won —
 *      the "Request Edit" button on My Works looked completely dead. Fix:
 *      drive it with the same direct style.display toggle every other
 *      modal in this app already uses (see openCollabEditModal).
 *
 *   2. Tour spotlight/card alignment. The highlight ring used a fixed
 *      16px border-radius and fixed 8px padding regardless of what it was
 *      actually wrapping, so pill buttons (Submit Movie, Suggestion tab)
 *      got a spotlight that didn't match their real shape, and the card
 *      sat close enough to visually collide with it. Fix: read the
 *      target's own computed border-radius so the ring hugs its actual
 *      shape, and widen/clean up the clearance so the card never overlaps
 *      the ring.
 *
 *   3. Emoji cleanup. Swaps decorative/system emoji (🔒 📷 🎬 🤝 💡 🚨 💬 👋
 *      🔗 🗑 📌) for small inline Apple-style line-icon SVGs, sitewide,
 *      via a text-node sweep with a MutationObserver for anything rendered
 *      later. Scoped to a whitelist of exact/known system strings — it
 *      does NOT touch the reaction emoji picker (❤ 😂 😮 😢 😡 👏 🔥 😍 👍
 *      🙂 😊), since those are the actual reaction choices, not chrome.
 *      Also strips emoji out of the tour copy itself (KFS_TOUR_STEPS is
 *      rendered via textContent, so it needs a plain-text fix rather than
 *      an icon swap).
 *
 *   4. Duplicate "time ago" on feed posts. Both regular and collab post
 *      cards render swRelTime(p.created_at) twice — once in the header
 *      next to the author name, once again at the very bottom of the
 *      card. Fix: hide the redundant bottom one.
 *
 *   5. Merge My Movies + My Works into one panel with an in-panel tab
 *      switcher ("Submissions" / "My Works"), since they're two flavors
 *      of the same "manage your film credits with KFS" task. Removes the
 *      separate "My Works" sidebar/settings-sheet entry, keeps the "My
 *      Movies" entry pointing at both.
 */

(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function pollFor(check, run, { tries = 40, delay = 250 } = {}) {
    let n = 0;
    (function tick() {
      n++;
      if (check()) { run(); return; }
      if (n < tries) setTimeout(tick, delay);
    })();
  }

  /* ═══════════════════════════════════════════════════════════════════
     1. FIX: "Request Edit" modal never opened
     ═══════════════════════════════════════════════════════════════════ */
  (function fixWorkEditModal() {
    function patch() {
      if (typeof window.openWorkEditModal !== 'function' || window.openWorkEditModal.__kfsPatched) return false;

      const origOpen = window.openWorkEditModal;
      window.openWorkEditModal = function (movieId, movieTitle) {
        const ret = origOpen(movieId, movieTitle);
        const overlay = document.getElementById('work-edit-modal-overlay');
        if (overlay) overlay.style.display = 'flex'; // the fix — classList alone never worked
        return ret;
      };
      window.openWorkEditModal.__kfsPatched = true;

      const origClose = window.closeWorkEditModal;
      if (typeof origClose === 'function' && !origClose.__kfsPatched) {
        window.closeWorkEditModal = function () {
          const ret = origClose();
          const overlay = document.getElementById('work-edit-modal-overlay');
          if (overlay) overlay.style.display = 'none';
          return ret;
        };
        window.closeWorkEditModal.__kfsPatched = true;
      }
      return true;
    }
    pollFor(() => typeof window.openWorkEditModal === 'function', patch);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     2. FIX: tour spotlight/card alignment
     ═══════════════════════════════════════════════════════════════════ */
  (function fixTourAlignment() {
    function patch() {
      if (typeof window._tourPositionSpot !== 'function' || window._tourPositionSpot.__kfsPatched) return false;
      if (typeof window.KFS_TOUR_STEPS === 'undefined' || typeof window._tourStep === 'undefined') return false;

      window._tourPositionSpot = function () {
        const step = window.KFS_TOUR_STEPS[window._tourStep];
        const spot = document.getElementById('kfs-tour-spot');
        const card = document.getElementById('kfs-tour-card');
        const backdrop = document.getElementById('kfs-tour-backdrop');
        if (!spot || !card || !step) return;

        const target = typeof window._tourFindTarget === 'function' ? window._tourFindTarget(step.selectors) : null;
        if (!target) {
          if (step.selectors) {
            if (window._tourStep < window.KFS_TOUR_STEPS.length - 1) { window._tourStep++; window._tourRenderStep(); }
            else if (typeof window._tourEnd === 'function') window._tourEnd();
            return;
          }
          // No spotlight this step (a centered/intro-style card) — the
          // backdrop is the only thing dimming the page, so keep its tint.
          if (backdrop) backdrop.style.background = 'rgba(0,0,0,0.6)';
          spot.style.display = 'none';
          card.style.top = '50%';
          card.style.left = '50%';
          card.style.transform = 'translate(-50%, -50%)';
          return;
        }

        // The spot's own box-shadow (0 0 0 9999px) already paints the dim
        // everywhere outside the ring. Leaving the backdrop's tint on top
        // stacked a second dark layer over the highlighted target itself,
        // which is why it looked washed-out gray instead of its real color.
        if (backdrop) backdrop.style.background = 'transparent';

        const r = target.getBoundingClientRect();

        // Hug the target's real shape instead of a fixed 16px ring, so a
        // pill button (Submit Movie, the Suggestion tab) gets a pill
        // highlight and a rectangular panel gets a rectangular one.
        const targetRadius = parseFloat(getComputedStyle(target).borderRadius) || 0;
        const pad = 6;
        const isPill = targetRadius >= r.height / 2 - 1;
        const spotRadius = isPill ? (r.height / 2 + pad) : Math.max(targetRadius + pad, 10);

        spot.style.display = 'block';
        spot.style.borderRadius = `${spotRadius}px`;
        spot.style.top = `${r.top - pad}px`;
        spot.style.left = `${r.left - pad}px`;
        spot.style.width = `${r.width + pad * 2}px`;
        spot.style.height = `${r.height + pad * 2}px`;

        // Card sizing/placement — clamped so it can never overlap the ring
        // and never run off any edge of the viewport.
        const GAP = 20;
        const cardW = Math.min(320, window.innerWidth - 32);
        card.style.width = `${cardW}px`;
        card.style.transform = 'none';

        const spotTop    = r.top - pad;
        const spotBottom = r.bottom + pad;
        const roomBelow = window.innerHeight - spotBottom;
        const roomAbove = spotTop;

        // Rough card height estimate for placement decisions (measured
        // after layout below, but we need a first guess to pick a side).
        const estH = card.offsetHeight || 180;

        let top;
        if (roomBelow >= estH + GAP) {
          top = spotBottom + GAP;
        } else if (roomAbove >= estH + GAP) {
          top = spotTop - GAP - estH;
        } else {
          // Neither side has room (small viewport / big target) — pin to
          // whichever side has more space and let it clip the padding
          // rather than overlap the spotlight ring.
          top = roomBelow >= roomAbove
            ? Math.max(spotBottom + GAP, window.innerHeight - estH - 16)
            : Math.min(spotTop - GAP - estH, 16);
        }
        top = Math.max(16, Math.min(top, window.innerHeight - 16 - estH));

        let left = Math.min(Math.max(r.left, 16), window.innerWidth - cardW - 16);

        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
      };
      window._tourPositionSpot.__kfsPatched = true;
      return true;
    }
    pollFor(() => typeof window._tourPositionSpot === 'function', patch);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     3. Emoji → clean SVG icons
     ═══════════════════════════════════════════════════════════════════ */
  (function emojiCleanup() {
    const ICONS = {
      lock: '<path d="M6 11V7a6 6 0 0 1 12 0v4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><rect x="4" y="11" width="16" height="10" rx="2.2" fill="none" stroke="currentColor" stroke-width="2"/>',
      camera: '<path d="M22 18a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h3.2l1.6-2.2h6.4L16.8 7H20a2 2 0 0 1 2 2z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="13" r="3.6" fill="none" stroke="currentColor" stroke-width="1.8"/>',
      film: '<rect x="2.5" y="3.5" width="19" height="17" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><line x1="7.5" y1="3.5" x2="7.5" y2="20.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="3.5" x2="16.5" y2="20.5" stroke="currentColor" stroke-width="1.8"/><line x1="2.5" y1="8.5" x2="7.5" y2="8.5" stroke="currentColor" stroke-width="1.8"/><line x1="2.5" y1="15.5" x2="7.5" y2="15.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="8.5" x2="21.5" y2="8.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="15.5" x2="21.5" y2="15.5" stroke="currentColor" stroke-width="1.8"/>',
      people: '<circle cx="8.5" cy="7.5" r="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M2 20c0-3.6 2.9-6.3 6.5-6.3S15 16.4 15 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="17" cy="8.5" r="2.8" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M15.3 13.9c2.7.4 4.7 2.7 4.7 5.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
      lightbulb: '<path d="M9 18.5h6M10 21.5h4M12 2.5a6.7 6.7 0 0 0-3.8 12.2c.6.45.9 1.1.9 1.9v.4h5.8v-.4c0-.8.3-1.45.9-1.9A6.7 6.7 0 0 0 12 2.5z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      alert: '<path d="M10.3 4.1L2.1 18.3a1.9 1.9 0 0 0 1.7 2.9h16.4a1.9 1.9 0 0 0 1.7-2.9L13.7 4.1a1.9 1.9 0 0 0-3.4 0z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="9.5" x2="12" y2="13.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="16.7" r="0.9" fill="currentColor" stroke="none"/>',
      message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      wave: '<path d="M7 12.3V6.2a1.8 1.8 0 0 1 3.6 0V11M10.6 10.6V4.8a1.8 1.8 0 0 1 3.6 0v6M14.2 11V6.4a1.8 1.8 0 0 1 3.6 0v8.1" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.4 13.6v-1.9a1.8 1.8 0 0 1 3.6 0v2.4a7.3 7.3 0 0 0 7.3 7.3h.6a7.3 7.3 0 0 0 7.3-7.3v-3.6a1.8 1.8 0 0 0-3.6 0" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
      link: '<path d="M9.5 12.8a4.3 4.3 0 0 0 6.5.5l2.6-2.6a4.3 4.3 0 0 0-6.1-6.1L11 6.1" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M14.5 11.2a4.3 4.3 0 0 0-6.5-.5L5.4 13.3a4.3 4.3 0 0 0 6.1 6.1L13 17.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
      trash: '<polyline points="3.5 6 5.5 6 20.5 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M18.3 6l-.9 13a2 2 0 0 1-2 1.9H8.6a2 2 0 0 1-2-1.9L5.7 6m3.5 0V3.8a1.8 1.8 0 0 1 1.8-1.8h2a1.8 1.8 0 0 1 1.8 1.8V6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      pin: '<path d="M12 2.3a5.3 5.3 0 0 0-5.3 5.3c0 3.9 5.3 11.1 5.3 11.1s5.3-7.2 5.3-11.1A5.3 5.3 0 0 0 12 2.3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="7.6" r="2" fill="none" stroke="currentColor" stroke-width="1.8"/>',
    };

    function iconSpan(name, size = 14) {
      const span = document.createElement('span');
      span.className = 'kfs-icon-swap';
      span.style.cssText = `display:inline-flex;align-items:center;justify-content:center;width:${size}px;height:${size}px;vertical-align:-2px;flex:none;`;
      span.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 24 24">${ICONS[name]}</svg>`;
      return span;
    }

    // Curated whitelist only — never touches the reaction-emoji picker
    // (❤ 😂 😮 😢 😡 👏 🔥 😍 👍 🙂 😊), which isn't in this list at all.
    const RULES = [
      { test: t => t.startsWith('🔒'), icon: 'lock', stripLen: 2 },
      { test: t => t === '📷 Photo', icon: 'camera', stripLen: 2 },
      { test: t => t === '🎬', icon: 'film', stripLen: 2 },
      { test: t => t === '🤝', icon: 'people', stripLen: 2 },
      { test: t => t === '💡 Suggestion', icon: 'lightbulb', stripLen: 2 },
      { test: t => t === '🚨 Grievance', icon: 'alert', stripLen: 2 },
      { test: t => t === '💬 General', icon: 'message', stripLen: 2 },
      { test: t => t === '💬', icon: 'message', stripLen: 2 },
      { test: t => t === '👋', icon: 'wave', stripLen: 2 },
      { test: t => t.startsWith('🔗 Copy link'), icon: 'link', stripLen: 2 },
      { test: t => t.startsWith('🗑 Delete post'), icon: 'trash', stripLen: 2 },
      { test: t => t.startsWith('📌'), icon: 'pin', stripLen: 2 },
    ];

    const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT']);

    function shouldSkipContainer(el) {
      while (el) {
        if (SKIP_TAGS.has(el.tagName)) return true;
        if (el.isContentEditable) return true;
        el = el.parentElement;
      }
      return false;
    }

    function processTextNode(node) {
      const raw = node.nodeValue;
      if (!raw || raw.indexOf('\u200b') !== -1) return; // already processed marker
      const trimmed = raw.trim();
      if (!trimmed) return;
      const rule = RULES.find(r => r.test(trimmed));
      if (!rule) return;
      const parent = node.parentNode;
      if (!parent || shouldSkipContainer(parent)) return;

      const leadWs = raw.match(/^\s*/)[0];
      const trailWs = raw.match(/\s*$/)[0];
      const rest = trimmed.slice(rule.stripLen).replace(/^\s+/, '');

      const frag = document.createDocumentFragment();
      if (leadWs) frag.appendChild(document.createTextNode(leadWs));
      frag.appendChild(iconSpan(rule.icon));
      frag.appendChild(document.createTextNode((rest ? ' ' + rest : '') + trailWs || '\u200b'));
      parent.replaceChild(frag, node);
    }

    function sweep(root) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode(n) {
          if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          return shouldSkipContainer(n.parentNode) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        }
      });
      const nodes = [];
      let n;
      while ((n = walker.nextNode())) nodes.push(n);
      nodes.forEach(processTextNode);
    }

    let pending = false;
    function scheduleSweep(root) {
      if (pending) return;
      pending = true;
      setTimeout(() => { pending = false; sweep(root); }, 150);
    }

    function stripEmojiFromTourCopy() {
      if (typeof window.KFS_TOUR_STEPS === 'undefined' || !Array.isArray(window.KFS_TOUR_STEPS)) return false;
      const EMOJI_RE = /\s?[\u{1F300}-\u{1FAFF}\u2600-\u27BF\uFE0F]\s?/gu;
      window.KFS_TOUR_STEPS.forEach(step => {
        if (step.title) step.title = step.title.replace(EMOJI_RE, ' ').replace(/\s+/g, ' ').trim();
        if (step.body)  step.body  = step.body.replace(EMOJI_RE, ' ').replace(/\s+/g, ' ').trim();
      });
      return true;
    }

    ready(() => {
      sweep(document.body);
      const mo = new MutationObserver(() => scheduleSweep(document.body));
      mo.observe(document.body, { childList: true, subtree: true, characterData: true });
      pollFor(() => typeof window.KFS_TOUR_STEPS !== 'undefined', stripEmojiFromTourCopy);
    });
  })();

  /* ═══════════════════════════════════════════════════════════════════
     4. Hide the duplicate "time ago" at the bottom of feed post cards
     ═══════════════════════════════════════════════════════════════════ */
  (function dedupTimestamps() {
    const style = document.createElement('style');
    style.textContent = `.ig-post-timestamp { display: none !important; }`;
    document.head.appendChild(style);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     5. Merge "My Movies" + "My Works" into one panel with tabs
     ═══════════════════════════════════════════════════════════════════ */
  (function mergeMoviesAndWorks() {
    const style = document.createElement('style');
    style.textContent = `
      .nav-item[data-panel="works"],
      .settings-sheet-item[onclick="settingsSheetGo('works')"] { display: none !important; }
      .kfs-mw-tabs { display:flex; gap:6px; margin: 2px 0 20px; }
    `;
    document.head.appendChild(style);

    function setTrailingText(el, oldText, newText) {
      if (!el) return;
      for (const node of el.childNodes) {
        if (node.nodeType === 3 && node.nodeValue.trim() === oldText) {
          node.nodeValue = newText;
          return;
        }
      }
    }

    function patch() {
      const moviesPanel = document.getElementById('panel-movies');
      const worksPanel = document.getElementById('panel-works');
      if (!moviesPanel || !worksPanel || moviesPanel.dataset.kfsMerged) return false;
      moviesPanel.dataset.kfsMerged = '1';

      const titleEl = moviesPanel.querySelector('.panel-title');
      const subEl = moviesPanel.querySelector('.panel-sub');
      if (titleEl) titleEl.textContent = 'My Movies & Works';
      if (subEl) subEl.textContent = 'Submit films for admin review, or request an edit to your existing credits.';

      // Everything in #panel-movies besides the title/sub becomes the
      // "Submissions" tab content.
      const submissionsTab = document.createElement('div');
      submissionsTab.id = 'kfs-mw-submissions-tab';
      Array.from(moviesPanel.children).forEach(child => {
        if (child !== titleEl && child !== subEl) submissionsTab.appendChild(child);
      });
      moviesPanel.appendChild(submissionsTab);

      // #panel-works's content (minus its own title/sub) becomes the
      // "My Works" tab content, hidden by default.
      const worksTab = document.createElement('div');
      worksTab.id = 'kfs-mw-works-tab';
      worksTab.style.display = 'none';
      Array.from(worksPanel.children).forEach(child => {
        if (!child.classList.contains('panel-title') && !child.classList.contains('panel-sub')) {
          worksTab.appendChild(child);
        }
      });
      worksPanel.remove();
      moviesPanel.appendChild(worksTab);

      // Tab switcher — reuses the app's existing pill-tab visual style.
      const tabs = document.createElement('div');
      tabs.className = 'kfs-mw-tabs';
      tabs.innerHTML = `
        <button type="button" class="strand-sort-pill kfs-mw-tab active" data-tab="submissions">Submissions</button>
        <button type="button" class="strand-sort-pill kfs-mw-tab" data-tab="works">My Works</button>`;
      subEl ? subEl.insertAdjacentElement('afterend', tabs) : moviesPanel.insertBefore(tabs, submissionsTab);

      tabs.querySelectorAll('.kfs-mw-tab').forEach(btn => {
        btn.addEventListener('click', () => {
          tabs.querySelectorAll('.kfs-mw-tab').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          const showWorks = btn.dataset.tab === 'works';
          submissionsTab.style.display = showWorks ? 'none' : '';
          worksTab.style.display = showWorks ? '' : 'none';
          if (showWorks && typeof window.loadMyWorks === 'function') window.loadMyWorks();
          else if (typeof window.loadMovies === 'function') window.loadMovies();
        });
      });

      // Rename the remaining sidebar/settings-sheet "My Movies" entries.
      setTrailingText(document.querySelector('.nav-item[data-panel="movies"]'), 'My Movies', 'My Movies & Works');
      const sheetLabel = document.querySelector(".settings-sheet-item[onclick=\"settingsSheetGo('movies')\"] .settings-sheet-label");
      if (sheetLabel) sheetLabel.textContent = 'My Movies & Works';

      // Old deep links / the tour still ask for panel "works" — send them
      // to the merged panel with the My Works tab pre-selected instead of
      // silently landing on nothing.
      if (typeof window.switchPanel === 'function' && !window.switchPanel.__kfsMergePatched) {
        const origSwitchPanel = window.switchPanel;
        window.switchPanel = function (el) {
          if (el && el.dataset && el.dataset.panel === 'works') {
            const moviesNav = document.querySelector('.nav-item[data-panel="movies"]') || { dataset: { panel: 'movies' } };
            const ret = origSwitchPanel(moviesNav);
            tabs.querySelector('.kfs-mw-tab[data-tab="works"]')?.click();
            return ret;
          }
          return origSwitchPanel(el);
        };
        window.switchPanel.__kfsMergePatched = true;
      }

      // Keep the tour's "My Movies" step and closing summary accurate now
      // that My Works lives in the same place.
      if (Array.isArray(window.KFS_TOUR_STEPS)) {
        window.KFS_TOUR_STEPS.forEach(step => {
          if (step.title === 'My Movies — submissions & change requests') {
            step.title = 'My Movies & Works';
            step.body = "Submit a finished film here for admin review and publication on /films, or switch to the My Works tab to request an edit to a credit you already have. Every submission gets a status: Pending, Approved, Rejected, or Changes Requested — if you see Changes Requested, click Edit on that same submission to update and resubmit.";
          }
          if (step.body && step.body.includes('My Movies, My Works')) {
            step.body = step.body.replace('My Movies, My Works,', 'My Movies & Works,');
          }
        });
      }
      return true;
    }

    ready(() => pollFor(() => document.getElementById('panel-movies') && document.getElementById('panel-works'), patch));
  })();

})();

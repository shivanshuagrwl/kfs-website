/**
 * kfs-patch7.js — Restore Bubble Opacity + Read Receipts in Customization
 * =====================================================================
 * Load this LAST, after kfs-patch6.js:
 *   <script src="/kfs-patch7.js" defer></script>
 *
 * PROBLEM
 * -------
 * membersaccess.js originally defines window.loadCustomization /
 * window.applyCustomization with FOUR sections: Chat Wallpaper, Message
 * Color, Bubble Opacity (sliders for "your" / "received" bubbles), and
 * Privacy (Read Receipts on/off toggle).
 *
 * kfs-patch4.js (loaded after membersaccess.js) REPLACES both of those
 * globals wholesale to add an "App Background" section and a nicer
 * gradient builder. Its replacement only re-implements Chat Wallpaper,
 * App Background, and Message Bubble Color — Bubble Opacity and Read
 * Receipts were dropped in that rewrite, which is why they're missing
 * from the live panel even though the base file still has all the CSS
 * (.cust-opacity-row, .cust-slider, .cust-switch, etc.) for them.
 *
 * FIX
 * ---
 * Rather than re-editing kfs-patch4.js (and risking another silent
 * regression next time someone patches the panel again), this file wraps
 * whatever loadCustomization/applyCustomization currently exist at the
 * time it runs and appends the two missing sections after them. It reuses
 * the exact same localStorage keys and markup/classes the original
 * membersaccess.js used, so nothing about existing saved preferences
 * changes for people who already had this working before patch4.
 */

(function () {
  'use strict';

  const OPACITY_KEY       = 'kfs-cust-bubble-opacity';   // { mine: 0-1, theirs: 0-1 }
  const READ_RECEIPTS_KEY = 'kfs-cust-read-receipts';    // true/false, default true

  function _load(key) {
    try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; }
  }
  function _save(key, val) {
    try {
      val === null ? localStorage.removeItem(key) : localStorage.setItem(key, JSON.stringify(val));
      return true;
    } catch { return false; }
  }

  function _readReceiptsEnabled() {
    const v = _load(READ_RECEIPTS_KEY);
    return v === null ? true : !!v;
  }
  window._kfsReadReceiptsEnabled = _readReceiptsEnabled;

  // ── Apply --bubble-mine-opacity / --bubble-theirs-opacity directly ─────
  // IMPORTANT: this does NOT go through window.applyCustomization. Earlier
  // versions of this patch wrapped window.applyCustomization once and
  // relied on that wrapper staying in place — but kfs-patch4.js can (and,
  // in practice, does) reassign window.applyCustomization again later,
  // silently dropping our wrapper and leaving the opacity CSS vars frozen
  // even though the slider still saves the right value to localStorage.
  // Setting the vars ourselves, independent of whatever applyCustomization
  // currently is, means the slider works no matter what patch4 does or
  // when it does it.
  function _applyOpacityVars() {
    const op = _load(OPACITY_KEY);
    document.documentElement.style.setProperty('--bubble-mine-opacity', String(op?.mine ?? 1));
    document.documentElement.style.setProperty('--bubble-theirs-opacity', String(op?.theirs ?? 1));
  }

  // Still nice to have: if window.applyCustomization exists, wrap it too so
  // opacity stays correct through its own re-renders. But this is now a
  // bonus, not the mechanism the slider depends on — and we re-check on
  // every poll tick (not just once) so a later patch4 reassignment gets
  // caught instead of silently winning.
  function wrapApplyCustomization() {
    if (typeof window.applyCustomization !== 'function') return false;
    if (window.applyCustomization.__kfsOpacityWrapped) return true;
    const orig = window.applyCustomization;
    const wrapped = function () {
      const ret = orig.apply(this, arguments);
      _applyOpacityVars();
      return ret;
    };
    wrapped.__kfsOpacityWrapped = true;
    window.applyCustomization = wrapped;
    return true;
  }

  let _opacityContentEl = null;

  function _renderOpacitySection() {
    const section = _opacityContentEl;
    if (!section) return;
    const op = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mineVal = op.mine ?? 1, theirsVal = op.theirs ?? 1;
    section.innerHTML = `
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Your bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-mine" min="0.3" max="1" step="0.05" value="${mineVal}">
        <span class="cust-opacity-value" id="cust-opacity-mine-val">${Math.round(mineVal * 100)}%</span>
      </div>
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Received bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-theirs" min="0.3" max="1" step="0.05" value="${theirsVal}">
        <span class="cust-opacity-value" id="cust-opacity-theirs-val">${Math.round(theirsVal * 100)}%</span>
      </div>
      <div class="cust-hint">Make chat bubbles more see-through. Applies to both DMs and group chats on this device.</div>`;

    const mineInput   = section.querySelector('#cust-opacity-mine');
    const theirsInput = section.querySelector('#cust-opacity-theirs');
    const mineValEl   = section.querySelector('#cust-opacity-mine-val');
    const theirsValEl = section.querySelector('#cust-opacity-theirs-val');

    mineInput?.addEventListener('input', () => {
      const cur = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.mine = parseFloat(mineInput.value);
      _save(OPACITY_KEY, cur);
      mineValEl.textContent = `${Math.round(cur.mine * 100)}%`;
      _applyOpacityVars();
      window.applyCustomization?.();
      _updatePreviewOpacity();
    });
    theirsInput?.addEventListener('input', () => {
      const cur = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.theirs = parseFloat(theirsInput.value);
      _save(OPACITY_KEY, cur);
      theirsValEl.textContent = `${Math.round(cur.theirs * 100)}%`;
      _applyOpacityVars();
      window.applyCustomization?.();
      _updatePreviewOpacity();
    });
  }

  function _updatePreviewOpacity() {
    const op = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mineBubble = document.getElementById('cust-preview-mine-bubble');
    if (mineBubble) mineBubble.style.setProperty('--preview-mine-opacity', String(op.mine ?? 1));
    const theirsBubble = document.querySelector('#cust-preview-chat .cust-preview-bubble.theirs');
    if (theirsBubble) theirsBubble.style.setProperty('--preview-theirs-opacity', String(op.theirs ?? 1));
  }

  let _receiptsContentEl = null;

  function _renderReadReceiptsSection() {
    const section = _receiptsContentEl;
    if (!section) return;
    const on = _readReceiptsEnabled();
    section.innerHTML = `
      <div class="cust-switch-row">
        <div class="cust-switch-text">
          <span class="cust-switch-title">Read Receipts</span>
          <span class="cust-switch-desc">Show the blue "Seen" double-tick on messages you've sent, on this device.</span>
        </div>
        <label class="cust-switch">
          <input type="checkbox" id="cust-read-receipts-toggle" ${on ? 'checked' : ''}>
          <span class="cust-switch-track"></span>
        </label>
      </div>`;
    section.querySelector('#cust-read-receipts-toggle')?.addEventListener('change', (e) => {
      _save(READ_RECEIPTS_KEY, !!e.target.checked);
      // Re-render any ticks already on screen immediately, from data already
      // held locally — no need to wait for the next server poll.
      try {
        const msgs = (typeof DM !== 'undefined' && DM?.msgs) ? DM.msgs : [];
        msgs.forEach(msg => {
          const metaRow = document.querySelector(`.dm-meta[data-meta-for="${msg.id}"]`);
          const oldTick = metaRow?.querySelector('.dm-ticks');
          if (oldTick && typeof _dmTickSpanHTML === 'function') oldTick.outerHTML = _dmTickSpanHTML(msg);
        });
      } catch { /* non-fatal */ }
    });
  }

  // Injects the two missing cards into #cust-root, matching the visual
  // style of the cards kfs-patch4.js already builds (dark card, 12px
  // radius, small "Reset" link top-right for the opacity one).
  function _injectSections() {
    const root = document.getElementById('cust-root');
    if (!root) return;

    const resetAllBtn = document.getElementById('cust-reset-all-btn');

    const opacityCard = document.createElement('div');
    opacityCard.style.cssText = 'background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px';
    opacityCard.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em">Bubble Opacity</div>
        <button id="cust-opacity-reset-btn" style="background:transparent;border:none;font-size:11px;font-weight:600;color:#666;cursor:pointer;padding:0">Reset</button>
      </div>
      <div id="cust-opacity-content"></div>`;

    const privacyCard = document.createElement('div');
    privacyCard.style.cssText = 'background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px';
    privacyCard.innerHTML = `
      <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em;margin-bottom:12px">Privacy</div>
      <div id="cust-read-receipts-content"></div>`;

    if (resetAllBtn) {
      root.insertBefore(opacityCard, resetAllBtn);
      root.insertBefore(privacyCard, resetAllBtn);
    } else {
      root.appendChild(opacityCard);
      root.appendChild(privacyCard);
    }

    _opacityContentEl  = opacityCard.querySelector('#cust-opacity-content');
    _receiptsContentEl = privacyCard.querySelector('#cust-read-receipts-content');

    _renderOpacitySection();
    _renderReadReceiptsSection();
    _updatePreviewOpacity();

    opacityCard.querySelector('#cust-opacity-reset-btn')?.addEventListener('click', () => {
      _save(OPACITY_KEY, null);
      _applyOpacityVars();
      window.applyCustomization?.();
      _renderOpacitySection();
      _updatePreviewOpacity();
    });

    // If a "Reset All" button exists (added by kfs-patch4.js), make it also
    // reset opacity back to 100/100 so it really does reset everything.
    if (resetAllBtn && !resetAllBtn.__kfsOpacityHooked) {
      resetAllBtn.__kfsOpacityHooked = true;
      resetAllBtn.addEventListener('click', () => {
        _save(OPACITY_KEY, null);
        _applyOpacityVars();
        window.applyCustomization?.();
        _renderOpacitySection();
        _updatePreviewOpacity();
      });
    }
  }

  function wrapLoadCustomization() {
    if (typeof window.loadCustomization !== 'function') return false;
    if (window.loadCustomization.__kfsOpacityWrapped) return true;
    const orig = window.loadCustomization;
    const wrapped = function () {
      const ret = orig.apply(this, arguments);
      _injectSections();
      return ret;
    };
    wrapped.__kfsOpacityWrapped = true;
    window.loadCustomization = wrapped;
    return true;
  }

  function init() {
    // Apply immediately so the vars exist even before any customization
    // script has loaded/run, and again on every tick below — cheap, and it
    // means the bubble opacity can never end up depending on winning a
    // one-shot race against kfs-patch4.js.
    _applyOpacityVars();

    // Poll for readiness rather than assuming exact script order —
    // loadCustomization/applyCustomization are defined in membersaccess.js
    // and then possibly re-defined by kfs-patch4.js. We keep polling
    // indefinitely (not just until the first success) specifically because
    // kfs-patch4.js has been observed to reassign window.applyCustomization
    // again after our first wrap succeeds, which would otherwise silently
    // undo it. Re-applying the vars ourselves every tick means that even if
    // the wrap gets clobbered, the slider still visibly works.
    let tries = 0;
    const tryWrap = () => {
      tries++;
      wrapApplyCustomization();
      wrapLoadCustomization();
      _applyOpacityVars();
      // Fast polling for the first ~10s to catch initial script load order,
      // then settle into a slow background check so a late/dynamic
      // reassignment of applyCustomization still gets caught eventually.
      setTimeout(tryWrap, tries < 40 ? 250 : 2000);
    };
    tryWrap();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

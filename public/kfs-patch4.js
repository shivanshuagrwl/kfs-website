// ═══════════════════════════════════════════════════════════════════════════
// KFS PATCH v4.0
// 1. Fix bottom tab bar showing on PC (touchscreen laptops / narrow windows)
// 2. Enhance Customization panel — more solid colors, more gradients,
//    custom gradient builder, app background color option, reset all button
// ═══════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // ── 1. BOTTOM BAR PC FIX ────────────────────────────────────────────────
  // The CSS uses `@media (max-width:768px) and (pointer:coarse)` — but
  // touchscreen laptops have pointer:coarse AND may be wide enough, or the
  // window might be narrow. Add a hard override: force hide at ≥769px
  // regardless of pointer type.
  const _btbStyle = document.createElement('style');
  _btbStyle.id = 'kfs-btb-pc-fix';
  _btbStyle.textContent = `
    @media (min-width: 769px) {
      .bottom-tab-bar { display: none !important; }
    }
  `;
  document.head.appendChild(_btbStyle);

  // ── 2. ENHANCED CUSTOMIZATION PANEL ─────────────────────────────────────

  const WALL_KEY        = 'kfs-cust-wallpaper';
  const APP_BG_KEY      = 'kfs-cust-app-bg';
  const BUBBLE_KEY      = 'kfs-cust-bubble';

  // Expanded palette
  const WALLPAPER_SOLIDS = [
    '#0a0a0a', '#0d0d0d', '#111111', '#141414',
    '#14141c', '#1a1a2e', '#16213e', '#1b262c',
    '#2d2d2d', '#222831', '#264653', '#2a3d45',
    '#3a2e39', '#1a1015', '#1c1c0f', '#0f1f0f',
  ];
  const WALLPAPER_GRADIENTS = [
    'linear-gradient(135deg,#1a1a2e,#16213e)',
    'linear-gradient(135deg,#0f2027,#203a43,#2c5364)',
    'linear-gradient(135deg,#232526,#414345)',
    'linear-gradient(135deg,#1d2671,#c33764)',
    'linear-gradient(135deg,#134e5e,#71b280)',
    'linear-gradient(135deg,#4b134f,#c94b4b)',
    'linear-gradient(135deg,#0f0c29,#302b63,#24243e)',
    'linear-gradient(135deg,#200122,#6f0000)',
    'linear-gradient(135deg,#0a3d62,#1e3799)',
    'linear-gradient(135deg,#1c1c1c,#2c2c54)',
    'linear-gradient(160deg,#0d0d0d 0%,#1a2a1a 100%)',
    'linear-gradient(160deg,#1a0a00 0%,#2d1b00 100%)',
  ];

  const APP_BG_SOLIDS = [
    '#0a0a0a', '#080808', '#050505', '#0d0d10',
    '#0a0a14', '#10050a', '#050a05', '#0a0808',
    '#1a1a1a', '#141414',
  ];

  const BUBBLE_PRESETS = [
    { bg: '#f0f0f0', text: '#0a0a0a' },
    { bg: '#0a84ff', text: '#ffffff' },
    { bg: '#34c759', text: '#ffffff' },
    { bg: '#ff375f', text: '#ffffff' },
    { bg: '#bf5af2', text: '#ffffff' },
    { bg: '#ff9f0a', text: '#0a0a0a' },
    { bg: '#30d158', text: '#0a0a0a' },
    { bg: '#5ac8fa', text: '#0a0a0a' },
  ];

  function _load(key)     { try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; } }
  function _save(key,val) {
    try {
      val===null ? localStorage.removeItem(key) : localStorage.setItem(key,JSON.stringify(val));
      return true;
    } catch {
      // Storage full/blocked — most commonly an uncompressed photo wallpaper
      // pushing past the ~5-10MB localStorage quota. Callers now check this
      // instead of assuming the save always worked.
      return false;
    }
  }
  function _isDark(hex)   {
    const c=(hex||'').replace('#','');
    if(c.length!==6) return true;
    return (0.299*parseInt(c.slice(0,2),16)+0.587*parseInt(c.slice(2,4),16)+0.114*parseInt(c.slice(4,6),16)) < 140;
  }
  function _esc(s) { return (s||'').replace(/"/g,'&quot;'); }

  // Downscales + re-encodes an uploaded photo as a compressed JPEG data URL
  // before it goes anywhere near localStorage. A raw phone photo is often
  // 4-8MB, and base64 inflates that ~33% on top — comfortably enough to blow
  // through the origin's ~5-10MB localStorage quota on its own. When that
  // happened, the quota error was swallowed silently and the wallpaper just
  // never changed (with whatever was previously saved — a solid color, or
  // nothing — staying in place). Capping the long edge at 1280px and
  // re-encoding at quality 0.78 keeps this to a few hundred KB.
  function _resizeImageFile(file, maxDim, quality) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => {
          let { width, height } = img;
          if (width > maxDim || height > maxDim) {
            if (width >= height) { height = Math.round(height * (maxDim / width)); width = maxDim; }
            else { width = Math.round(width * (maxDim / height)); height = maxDim; }
          }
          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, width, height);
          try { resolve(canvas.toDataURL('image/jpeg', quality)); }
          catch (e) { reject(e); }
        };
        img.onerror = () => reject(new Error('Could not read that image.'));
        img.src = reader.result;
      };
      reader.onerror = () => reject(new Error('Could not read that file.'));
      reader.readAsDataURL(file);
    });
  }

  // Apply saved customization to CSS vars
  function applyCustomizationV2() {
    const root = document.documentElement.style;
    // Chat wallpaper
    const wall = _load(WALL_KEY);
    if (!wall || wall.type === 'default')  root.setProperty('--chat-wallpaper-bg','transparent');
    else if (wall.type === 'solid')        root.setProperty('--chat-wallpaper-bg', wall.value);
    else if (wall.type === 'gradient')     root.setProperty('--chat-wallpaper-bg', wall.value);
    else if (wall.type === 'photo')        root.setProperty('--chat-wallpaper-bg', `url("${wall.value}")`);
    // App background
    const appBg = _load(APP_BG_KEY);
    if (appBg && appBg.value) {
      root.setProperty('--bg', appBg.value);
      root.setProperty('--surface', _lighten(appBg.value, 10));
    } else {
      root.setProperty('--bg', '#0a0a0a');
      root.setProperty('--surface', '#111111');
    }
    // Bubble
    const bub = _load(BUBBLE_KEY);
    root.setProperty('--bubble-mine-bg',   bub?.bg   || '#f0f0f0');
    root.setProperty('--bubble-mine-text', bub?.text || '#0a0a0a');
  }

  // Lighten a hex color by N (0-255)
  function _lighten(hex, n) {
    const c = (hex||'#0a0a0a').replace('#','');
    if (c.length !== 6) return '#111111';
    const r = Math.min(255, parseInt(c.slice(0,2),16)+n);
    const g = Math.min(255, parseInt(c.slice(2,4),16)+n);
    const b = Math.min(255, parseInt(c.slice(4,6),16)+n);
    return `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`;
  }

  // Override the global applyCustomization with our enhanced version
  window.applyCustomization = applyCustomizationV2;
  try { applyCustomizationV2(); } catch {}

  // ── 3. OVERRIDE loadCustomization ───────────────────────────────────────
  let _activeSeg = 'solid';
  let _custInited = false;

  function _previewBg() {
    const wall = _load(WALL_KEY) || { type: 'default' };
    if (wall.type === 'solid' || wall.type === 'gradient') return wall.value;
    if (wall.type === 'photo') return `url("${wall.value}") center/cover no-repeat`;
    return 'var(--bg)';
  }

  function _updatePreview() {
    const prev = document.getElementById('cust-preview-chat');
    if (prev) prev.style.background = _previewBg();
    const mine = document.getElementById('cust-preview-mine-bubble');
    if (mine) {
      const bub = _load(BUBBLE_KEY) || { bg: '#f0f0f0', text: '#0a0a0a' };
      mine.style.background = bub.bg;
      mine.style.color = bub.text;
    }
  }

  function _swatchHtml(colors, loadedVal, loadedType, typeAttr) {
    return colors.map(c => {
      const active = loadedType === typeAttr.replace('data-','').replace('-solid','solid').replace('-gradient','gradient') && loadedVal === c;
      const isGrad = typeAttr === 'data-wall-gradient';
      const cls = isGrad ? 'cust-gradient-swatch' : 'cust-swatch';
      return `<div class="${cls}${active ? ' active' : ''}" style="background:${c}" ${typeAttr}="${_esc(c)}" title="${c}"></div>`;
    }).join('');
  }

  function _renderWall() {
    const section = document.getElementById('cust-wall-content');
    if (!section) return;
    const wall = _load(WALL_KEY) || { type: 'default' };

    if (_activeSeg === 'solid') {
      const customActive = wall.type === 'solid' && !WALLPAPER_SOLIDS.includes(wall.value);
      section.innerHTML = `
        <div class="cust-swatch-row">
          ${WALLPAPER_SOLIDS.map(c => `<div class="cust-swatch${wall.type==='solid'&&wall.value===c?' active':''}" style="background:${c}" data-wall-solid="${c}" title="${c}"></div>`).join('')}
          <div class="cust-swatch-custom${customActive?' active':''}" title="Custom color">
            ${customActive?`<span style="width:100%;height:100%;border-radius:50%;display:block;background:${_esc(wall.value)}"></span>`:'＋'}
            <input type="color" id="cust-wall-color-input" value="${customActive?wall.value:'#222222'}">
          </div>
        </div>
        <div class="cust-hint">Tap a color, or use the dashed swatch to pick any custom color.</div>`;
      section.querySelectorAll('[data-wall-solid]').forEach(el => {
        el.addEventListener('click', () => { _save(WALL_KEY,{type:'solid',value:el.dataset.wallSolid}); applyCustomizationV2(); _renderWall(); _updatePreview(); });
      });
      const ci = document.getElementById('cust-wall-color-input');
      if (ci) {
        ci.addEventListener('input', () => { _save(WALL_KEY,{type:'solid',value:ci.value}); applyCustomizationV2(); _updatePreview(); });
        ci.addEventListener('change', () => _renderWall());
      }

    } else if (_activeSeg === 'gradient') {
      const customActive = wall.type === 'gradient' && !WALLPAPER_GRADIENTS.includes(wall.value);
      section.innerHTML = `
        <div class="cust-swatch-row">
          ${WALLPAPER_GRADIENTS.map(g => `<div class="cust-gradient-swatch${wall.type==='gradient'&&wall.value===g?' active':''}" style="background:${g}" data-wall-gradient="${_esc(g)}"></div>`).join('')}
        </div>
        <div class="cust-hint" style="margin-bottom:12px">Tap a gradient preset, or build a custom one below.</div>
        <div style="background:#161616;border:1px solid #1e1e1e;border-radius:10px;padding:14px 16px;margin-bottom:8px">
          <div style="font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Custom Gradient</div>
          <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
            <div style="display:flex;flex-direction:column;gap:4px;align-items:center">
              <div style="font-size:11px;color:#666">From</div>
              <input type="color" id="cust-grad-from" value="${customActive ? wall.value.match(/#[0-9a-fA-F]{6}/g)?.[0] || '#1a1a2e' : '#1a1a2e'}" style="width:44px;height:44px;border-radius:8px;border:1px solid #2a2a2a;background:transparent;cursor:pointer;padding:2px">
            </div>
            <div style="display:flex;flex-direction:column;gap:4px;align-items:center">
              <div style="font-size:11px;color:#666">To</div>
              <input type="color" id="cust-grad-to" value="${customActive ? wall.value.match(/#[0-9a-fA-F]{6}/g)?.[1] || '#16213e' : '#16213e'}" style="width:44px;height:44px;border-radius:8px;border:1px solid #2a2a2a;background:transparent;cursor:pointer;padding:2px">
            </div>
            <div style="display:flex;flex-direction:column;gap:4px;align-items:center">
              <div style="font-size:11px;color:#666">Angle</div>
              <input type="range" id="cust-grad-angle" min="0" max="360" value="135" style="width:90px;accent-color:#fff">
              <div id="cust-grad-angle-val" style="font-size:11px;color:#666">135°</div>
            </div>
            <div id="cust-grad-preview" style="flex:1;min-width:60px;height:44px;border-radius:8px;background:linear-gradient(135deg,#1a1a2e,#16213e);min-width:80px"></div>
            <button id="cust-grad-apply" style="background:#fff;color:#000;border:none;border-radius:7px;font-size:12px;font-weight:700;padding:8px 14px;cursor:pointer;white-space:nowrap">Apply</button>
          </div>
        </div>`;

      // Preset swatches
      section.querySelectorAll('[data-wall-gradient]').forEach(el => {
        el.addEventListener('click', () => { _save(WALL_KEY,{type:'gradient',value:el.dataset.wallGradient}); applyCustomizationV2(); _renderWall(); _updatePreview(); });
      });

      // Custom gradient builder
      function _rebuildCustomGrad() {
        const from  = (document.getElementById('cust-grad-from')?.value || '#1a1a2e');
        const to    = (document.getElementById('cust-grad-to')?.value   || '#16213e');
        const angle = (document.getElementById('cust-grad-angle')?.value || 135);
        const grad  = `linear-gradient(${angle}deg,${from},${to})`;
        const prev  = document.getElementById('cust-grad-preview');
        const label = document.getElementById('cust-grad-angle-val');
        if (prev)  prev.style.background = grad;
        if (label) label.textContent = `${angle}°`;
        return grad;
      }
      ['cust-grad-from','cust-grad-to','cust-grad-angle'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', _rebuildCustomGrad);
      });
      document.getElementById('cust-grad-apply')?.addEventListener('click', () => {
        const grad = _rebuildCustomGrad();
        _save(WALL_KEY,{type:'gradient',value:grad}); applyCustomizationV2(); _renderWall(); _updatePreview();
      });

    } else {
      // Photo
      const hasPhoto = wall.type === 'photo' && wall.value;
      section.innerHTML = `
        <div class="cust-photo-row">
          <div class="cust-photo-thumb">${hasPhoto?`<img src="${wall.value}">`:`<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>`}</div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="cust-upload-btn" id="cust-photo-upload-btn">Upload Photo</button>
            ${hasPhoto?`<button class="cust-photo-remove" id="cust-photo-remove-btn">Remove photo</button>`:''}
          </div>
          <input type="file" id="cust-photo-input" accept="image/*" style="display:none">
        </div>
        <div class="cust-hint">Best with a photo at least 800px wide. Stored only on this device.</div>`;
      document.getElementById('cust-photo-upload-btn')?.addEventListener('click', () => document.getElementById('cust-photo-input')?.click());
      document.getElementById('cust-photo-input')?.addEventListener('change', e => {
        const file = e.target.files?.[0];
        if (!file) return;
        if (file.size > 8*1024*1024) { try { swShowToast('Please choose an image under 8MB.'); } catch {} e.target.value = ''; return; }
        const btn = document.getElementById('cust-photo-upload-btn');
        const prevLabel = btn ? btn.textContent : null;
        if (btn) { btn.disabled = true; btn.textContent = 'Processing…'; }
        _resizeImageFile(file, 1280, 0.78)
          .then(dataUrl => {
            const ok = _save(WALL_KEY,{type:'photo',value:dataUrl});
            if (!ok) {
              try { swShowToast("Couldn't save that photo — try a smaller image."); } catch {}
              if (btn) { btn.disabled = false; btn.textContent = prevLabel; }
              return;
            }
            applyCustomizationV2(); _renderWall(); _updatePreview();
          })
          .catch(() => {
            try { swShowToast('Could not process that image.'); } catch {}
            if (btn) { btn.disabled = false; btn.textContent = prevLabel; }
          })
          .finally(() => { e.target.value = ''; });
      });
      section.querySelector('#cust-photo-remove-btn')?.addEventListener('click', () => {
        _save(WALL_KEY,{type:'default'}); applyCustomizationV2(); _renderWall(); _updatePreview();
      });
    }
  }

  function _renderAppBg() {
    const section = document.getElementById('cust-app-bg-content');
    if (!section) return;
    const appBg = _load(APP_BG_KEY);
    const cur = appBg?.value || '#0a0a0a';
    const customActive = appBg && !APP_BG_SOLIDS.includes(cur);
    section.innerHTML = `
      <div class="cust-swatch-row">
        ${APP_BG_SOLIDS.map(c=>`<div class="cust-swatch${cur===c?' active':''}" style="background:${c};box-shadow:inset 0 0 0 1px rgba(255,255,255,${c==='#0a0a0a'?.12:.06})" data-appbg="${c}" title="${c}"></div>`).join('')}
        <div class="cust-swatch-custom${customActive?' active':''}" title="Custom color">
          ${customActive?`<span style="width:100%;height:100%;border-radius:50%;display:block;background:${_esc(cur)}"></span>`:'＋'}
          <input type="color" id="cust-appbg-color-input" value="${customActive?cur:'#0a0a0a'}">
        </div>
      </div>
      <div class="cust-hint">Changes the app background and sidebar tone. Darker is recommended for the film aesthetic.</div>`;
    section.querySelectorAll('[data-appbg]').forEach(el => {
      el.addEventListener('click', () => { _save(APP_BG_KEY,{value:el.dataset.appbg}); applyCustomizationV2(); _renderAppBg(); });
    });
    const ci = document.getElementById('cust-appbg-color-input');
    if (ci) {
      ci.addEventListener('input', () => { _save(APP_BG_KEY,{value:ci.value}); applyCustomizationV2(); });
      ci.addEventListener('change', () => _renderAppBg());
    }
  }

  function _renderBubble() {
    const section = document.getElementById('cust-bubble-content');
    if (!section) return;
    const bub = _load(BUBBLE_KEY) || { bg: '#f0f0f0', text: '#0a0a0a' };
    const customActive = !BUBBLE_PRESETS.some(p => p.bg === bub.bg);
    section.innerHTML = `
      <div class="cust-swatch-row">
        ${BUBBLE_PRESETS.map(p=>`<div class="cust-swatch${bub.bg===p.bg?' active':''}" style="background:${p.bg}" data-bubble-bg="${p.bg}" data-bubble-text="${p.text}" title="${p.bg}"></div>`).join('')}
        <div class="cust-swatch-custom${customActive?' active':''}" title="Custom color">
          ${customActive?`<span style="width:100%;height:100%;border-radius:50%;display:block;background:${_esc(bub.bg)}"></span>`:'＋'}
          <input type="color" id="cust-bubble-color-input" value="${customActive?bub.bg:'#f0f0f0'}">
        </div>
      </div>
      <div class="cust-hint">Color of your own message bubbles — visible to whoever you're chatting with.</div>`;
    section.querySelectorAll('[data-bubble-bg]').forEach(el => {
      el.addEventListener('click', () => { _save(BUBBLE_KEY,{bg:el.dataset.bubbleBg,text:el.dataset.bubbleText}); applyCustomizationV2(); _renderBubble(); _updatePreview(); });
    });
    const ci = document.getElementById('cust-bubble-color-input');
    if (ci) {
      ci.addEventListener('input', () => { const t=_isDark(ci.value)?'#ffffff':'#0a0a0a'; _save(BUBBLE_KEY,{bg:ci.value,text:t}); applyCustomizationV2(); _updatePreview(); });
      ci.addEventListener('change', () => _renderBubble());
    }
  }

  function _setSeg(seg) {
    _activeSeg = seg;
    document.querySelectorAll('.cust-seg-btn').forEach(b => b.classList.toggle('active', b.dataset.seg === seg));
    _renderWall();
  }

  // Override the global loadCustomization
  window.loadCustomization = function loadCustomization() {
    const root = document.getElementById('cust-root');
    if (!root) return;

    root.innerHTML = `
      <!-- Live preview -->
      <div class="cust-preview">
        <div class="cust-preview-chat" id="cust-preview-chat">
          <div class="cust-preview-bubble theirs">hey, you around tonight?</div>
          <div class="cust-preview-bubble mine" id="cust-preview-mine-bubble">yeah I'm down 👍</div>
        </div>
      </div>

      <!-- Section: App Background -->
      <div style="background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em">App Background</div>
          <button id="cust-appbg-reset-btn" style="background:transparent;border:none;font-size:11px;font-weight:600;color:#666;cursor:pointer;padding:0">Reset</button>
        </div>
        <div id="cust-app-bg-content"></div>
      </div>

      <!-- Section: Chat Wallpaper -->
      <div style="background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em">Chat Wallpaper</div>
          <button id="cust-wall-reset-btn" style="background:transparent;border:none;font-size:11px;font-weight:600;color:#666;cursor:pointer;padding:0">Reset</button>
        </div>
        <div class="cust-seg" style="margin-bottom:14px">
          <div class="cust-seg-btn active" data-seg="solid">Solid</div>
          <div class="cust-seg-btn" data-seg="gradient">Gradient</div>
          <div class="cust-seg-btn" data-seg="photo">Photo</div>
        </div>
        <div id="cust-wall-content"></div>
      </div>

      <!-- Section: Message Bubble Color -->
      <div style="background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em">Message Bubble Color</div>
          <button id="cust-bubble-reset-btn" style="background:transparent;border:none;font-size:11px;font-weight:600;color:#666;cursor:pointer;padding:0">Reset</button>
        </div>
        <div id="cust-bubble-content"></div>
      </div>

      <!-- Reset All -->
      <button id="cust-reset-all-btn" style="width:100%;background:transparent;border:1px solid #2a2a2a;color:#888;font-size:13px;font-weight:600;padding:12px;border-radius:10px;cursor:pointer;transition:all .12s">
        Reset All to Default
      </button>
    `;

    // Segment switcher
    document.querySelectorAll('.cust-seg-btn').forEach(btn => {
      btn.addEventListener('click', () => _setSeg(btn.dataset.seg));
    });

    // Reset buttons
    document.getElementById('cust-wall-reset-btn')?.addEventListener('click', () => {
      _save(WALL_KEY,{type:'default'}); applyCustomizationV2(); _renderWall(); _updatePreview();
    });
    document.getElementById('cust-appbg-reset-btn')?.addEventListener('click', () => {
      _save(APP_BG_KEY,null); applyCustomizationV2(); _renderAppBg();
    });
    document.getElementById('cust-bubble-reset-btn')?.addEventListener('click', () => {
      _save(BUBBLE_KEY,null); applyCustomizationV2(); _renderBubble(); _updatePreview();
    });
    document.getElementById('cust-reset-all-btn')?.addEventListener('click', () => {
      _save(WALL_KEY,{type:'default'}); _save(APP_BG_KEY,null); _save(BUBBLE_KEY,null);
      applyCustomizationV2(); _renderWall(); _renderAppBg(); _renderBubble(); _updatePreview();
      try { swShowToast('All customization reset to default.'); } catch {}
    });
    document.getElementById('cust-reset-all-btn')?.addEventListener('mouseenter', function(){ this.style.background='#1a1a1a'; this.style.color='#f5f5f5'; });
    document.getElementById('cust-reset-all-btn')?.addEventListener('mouseleave', function(){ this.style.background='transparent'; this.style.color='#888'; });

    // Initial render
    _setSeg('solid');
    _renderAppBg();
    _renderBubble();
    _updatePreview();

    _custInited = true;
  };

})();

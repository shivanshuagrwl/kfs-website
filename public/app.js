// app.js — KFS Frontend (extracted from inline scripts)
// Blocks: theme-applier, main-app, search, member-import, form-builder, collab, donations

// Apply banner + hero overrides from theme loaded in <head>
(function() {
  var t = window.__kfsEventTheme;
  if (!t) return;
  // Banner
  if (t.banner_message) {
    var b = document.getElementById('event-banner');
    b.textContent = t.banner_message;
    b.style.background = t.banner_bg || 'var(--accent)';
    b.style.color = t.banner_text_color || 'var(--black)';
    b.classList.add('visible');
  }
  // Logo swap
  if (t.logo_url) {
    var img = document.querySelector('.nav-logo-img');
    if (img) img.src = t.logo_url;
  }
  // Hero title/tagline overrides — applied after DOM ready
  if (t.hero_title || t.hero_tagline) {
    document.addEventListener('DOMContentLoaded', function() {
      if (t.hero_title) {
        var el = document.querySelector('.hero-title, .glow-word, h1');
        if (el) el.textContent = t.hero_title;
      }
      if (t.hero_tagline) {
        var el2 = document.querySelector('.hero-tagline');
        if (el2) el2.textContent = t.hero_tagline;
      }
    });
  }
})();

let currentPage = 'home';
// ── SECURITY: adminToken lives in memory only — never written to localStorage.
// XSS cannot steal it. Session persistence is handled by the httpOnly refresh
// cookie (kfs_refresh) which the server issues on login and rotates on every
// /api/admin/refresh call. On a hard reload the token is re-hydrated from the
// cookie via the immediate refresh call in autoRefreshToken() below.
let adminToken = null;
let _csrfToken = null;

// Fetch CSRF token once on page load
(async function initCsrf() {
  try {
    const r = await fetch('/api/csrf-token');
    const d = await r.json();
    _csrfToken = d.csrf_token;
  } catch(e) {}
})();

// role/name/permissions: safe to keep in localStorage — not secrets, not tokens
let currentAdminRole = localStorage.getItem('kfs_role') || 'admin';
let currentAdminName = localStorage.getItem('kfs_admin_name') || '';
let currentAdminPermissions = (() => { try { return JSON.parse(localStorage.getItem('kfs_permissions') || '[]'); } catch { return []; } })();
const ALL_SECTIONS = ['dashboard','blogs','events','members','movies','chitra-vichitra','testimonials','achievements','settings','analytics','review-analytics','reg-analytics','payment-analytics','wrapped','comments','broadcast','themes','change-password','easter-eggs','scanner'];
function hasPermission(section) {
  if (currentAdminRole === 'master') return true;
  // change-password and two-factor are always accessible (not section-gated)
  if (['change-password','two-factor'].includes(section)) return true;
  // Empty permissions = no access (mirrors server-side requireSection fix)
  if (!currentAdminPermissions || currentAdminPermissions.length === 0) return false;
  // 'scanner' is gated by 'events' permission — same role, different UI section
  const effectiveSection = section === 'scanner' ? 'events' : section;
  return currentAdminPermissions.includes(effectiveSection);
}
let allEvents = [];

// ── AUTO-REFRESH TOKEN — every 12 min (token is 15-min short-lived) ──────────
// On every page load this fires immediately to re-hydrate adminToken from the
// httpOnly refresh cookie — no localStorage read needed.
(function autoRefreshToken() {
  // Immediate refresh on page load — always attempt, cookie presence determines success
  fetch('/api/admin/refresh', {
    method: 'POST',
    credentials: 'include' // send httpOnly refresh cookie
  }).then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (!data || !data.token) return;
      adminToken = data.token; // memory only — never localStorage
      currentAdminRole = data.role || 'admin';
      currentAdminName = data.name || '';
      currentAdminPermissions = data.permissions || [];
      localStorage.setItem('kfs_role', data.role);
      localStorage.setItem('kfs_admin_name', data.name || '');
      localStorage.setItem('kfs_permissions', JSON.stringify(currentAdminPermissions));
      var panel = document.getElementById('admin-panel');
      if (panel && panel.classList.contains('active')) { showAdminPanel(); }
    }).catch(function() {});
  // Then every 12 minutes proactively
  setInterval(async function() {
    if (!adminToken) return;
    try {
      const r = await fetch('/api/admin/refresh', { method: 'POST', credentials: 'include' });
      if (r.ok) {
        const d = await r.json();
        adminToken = d.token; // memory only — never localStorage
        currentAdminRole = d.role || 'admin';
        currentAdminName = d.name || '';
        currentAdminPermissions = d.permissions || [];
        localStorage.setItem('kfs_role', d.role);
        localStorage.setItem('kfs_admin_name', d.name || '');
        localStorage.setItem('kfs_permissions', JSON.stringify(currentAdminPermissions));
        // FIX: refresh CSRF token alongside JWT so it never expires mid-session
        try {
          const cr = await fetch('/api/csrf-token');
          if (cr.ok) { const cd = await cr.json(); _csrfToken = cd.csrf_token; }
        } catch(ce) {}
      } else {
        // Refresh failed — force re-login
        adminToken = null;
        ['kfs_role','kfs_admin_name','kfs_permissions'].forEach(k => localStorage.removeItem(k));
        navigate('admin');
      }
    } catch(e) {}
  }, 12 * 60 * 1000);
})();


// ── HERO WORD GLOW ON SCROLL — locks once lit per visit, resets on re-navigation ──
(function(){
  var ids=['glow-lights','glow-camera','glow-kfs'];
  var thresh=[0.06,0.18,0.32];
  var locked=[false,false,false];
  function update(){
    var sy=window.scrollY, vh=window.innerHeight;
    ids.forEach(function(id,i){
      if(locked[i])return;
      var el=document.getElementById(id);
      if(!el)return;
      if(sy>=thresh[i]*vh){el.classList.add('lit');locked[i]=true;}
    });
    if(locked[0]&&locked[1]&&locked[2])window.removeEventListener('scroll',update);
  }
  window.addEventListener('scroll',update,{passive:true});
  // Called by theme re-render and by navigation back to home
  window.glowUpdate=function(){
    locked=[false,false,false];
    // Remove 'lit' from all glow words so animation re-fires
    ids.forEach(function(id){
      var el=document.getElementById(id);
      if(el) el.classList.remove('lit');
    });
    // Re-attach scroll listener (safe to add multiple times — deduplicated by identity)
    window.removeEventListener('scroll',update);
    window.addEventListener('scroll',update,{passive:true});
    update(); // fire once in case already scrolled
  };
})();

// ── NAVIGATION ──
function _doNavigate(page, pushState=true) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('blog-detail').classList.remove('active');
  document.getElementById('movie-detail').classList.remove('active');
  document.getElementById('admin-login').classList.remove('active');
  document.getElementById('admin-panel').classList.remove('active');
  hideScrollProgress();
  if (page === 'admin') {
    if (adminToken) { showAdminPanel(); return; }
    document.getElementById('admin-login').classList.add('active');
    if (pushState) history.pushState({page}, '', '/admin');
    return;
  }
  if (page === 'wrapped' && _wrappedConfig && _wrappedConfig.enabled === false) {
    // Wrapped is disabled — redirect to home
    page = 'home';
  }
  const pageEl = document.getElementById('page-'+page);
  if (pageEl) {
    // Clear any inline display style (e.g. page-wrapped starts with display:none)
    pageEl.style.display = '';
    pageEl.classList.add('active');
    currentPage = page;
    // When landing on wrapped always restore the hero so refresh/nav starts cleanly
    if (page === 'wrapped') {
      const hero = document.getElementById('wrapped-hero');
      const deck = document.getElementById('wrapped-deck-wrap');
      const restartRow = document.getElementById('wrapped-restart-row');
      if (restartRow) restartRow.remove();
      if (hero) { hero.style.opacity = '1'; hero.style.transform = ''; hero.style.display = ''; hero.style.transition = ''; }
      if (deck)  { deck.classList.remove('visible'); deck.style.display = 'none'; }
    }
  }
  else {
    // Unknown route — show 404
    const p404 = document.getElementById('page-404');
    if (p404) { p404.classList.add('active'); currentPage = '404'; }
    if (pushState) history.pushState({page:'404'}, '', window.location.pathname);
    return;
  }
  document.querySelectorAll('.nav-links a').forEach(a=>{
    a.classList.toggle('active', a.dataset.page === page);
  });
  window.scrollTo({top:0,behavior:'instant'});
  if (pushState) history.pushState({page}, '', '/'+page);
  // Reset meta tags to site defaults on section navigation
  if (page === 'home' || page === 'films' || page === 'events' || page === 'blog' || page === 'about' || page === 'team') {
    updateMetaTags({
      title: 'KIIT Film Society',
      description: 'Official KIIT Film Society — a student-run collective passionate about cinema, filmmaking, storytelling, screenings, and creative collaboration.',
      image: '/images/og-banner.png',
      url: page === 'home' ? '/' : '/' + page,
    });
    removePageSchema(); // clear any film/blog schema from previous detail view
  }
  loadPageData(page);
}

let _wipeInProgress = false;
function navigate(page, pushState=true) {
  // No wipe for first load or same page
  if (!_wipeInProgress && document.body.classList.contains('loaded')) {
    _wipeInProgress = true;
    const wipe = document.getElementById('page-wipe');
    wipe.className = 'wipe-in';
    setTimeout(() => {
      _doNavigate(page, pushState);
      wipe.className = 'wipe-out';
      setTimeout(() => { wipe.className = ''; _wipeInProgress = false; }, 400);
    }, 380);
  } else {
    _doNavigate(page, pushState);
  }
}

window.addEventListener('popstate', e => {
  const state = e.state;
  if (!state) { navigate('home', false); return; }
  if (state.page === 'blog-detail') { openBlog(state.id); return; }
  if (state.page === 'movie-detail') { openMovie(state.id); return; }
  navigate(state.page || 'home', false);
});

// init from URL path - handled inside checkRoute below

function loadPageData(page) {
  if (page==='home') { loadHomeData(); if(window.glowUpdate) window.glowUpdate(); }
  else if (page==='events') loadEvents();
  else if (page==='blog') loadBlog();
  else if (page==='members') loadMembers();
  else if (page==='movies') loadMovies();
  else if (page==='wrapped') loadWrapped();
  else if (page==='collaborate') loadCollaborate();
  else if (page==='donations') loadDonationsPage();
}

function toggleMenu() {
  const open = document.getElementById('nav-links').classList.toggle('open');
  const hb = document.getElementById('hamburger');
  const bd = document.getElementById('nav-backdrop');
  if (hb) hb.classList.toggle('open', open);
  if (bd) bd.classList.toggle('open', open);
}
function closeMenu() {
  document.getElementById('nav-links').classList.remove('open');
  const hb = document.getElementById('hamburger');
  const bd = document.getElementById('nav-backdrop');
  if (hb) hb.classList.remove('open');
  if (bd) bd.classList.remove('open');
}

function _setThemeUI(isLight) {
  const moon = document.getElementById('nav-icon-moon');
  const sun  = document.getElementById('nav-icon-sun');
  const lbl  = document.getElementById('admin-theme-label');
  if (moon) moon.style.display = isLight ? 'none'  : 'block';
  if (sun)  sun.style.display  = isLight ? 'block' : 'none';
  if (lbl)  lbl.textContent    = isLight ? 'ON' : 'OFF';
}
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-mode');
  localStorage.setItem('kfs_theme', isLight ? 'light' : 'dark');
  _setThemeUI(isLight);
}
(function initTheme(){
  const isLight = localStorage.getItem('kfs_theme') === 'light';
  if (isLight) document.body.classList.add('light-mode');
  setTimeout(function(){ _setThemeUI(isLight); }, 0);
})();

// Pre-load members so linked member lookups work on any page.
// Deferred 2s so it doesn't compete with loadHomeData's parallel fetch burst on first paint.
setTimeout(async function prefetchMembers(){
  if (allMembers && allMembers.length) return; // already loaded by a page section
  const data = await apiFetch('/api/members').catch(() => null);
  if (data) {
    allMembers = data;
    if (!window._memberRegistry) window._memberRegistry = [];
    data.forEach(m => {
      if (!window._memberRegistry.find(r => r.id === m.id))
        window._memberRegistry.push(m);
    });
  }
}, 2000);

function animateCounters() {
  document.querySelectorAll('.counter').forEach(el=>{
    const target = parseInt(el.dataset.target);
    if (!target) return;
    // Don't re-animate if already showing the correct value
    if (el.textContent === target + '+') return;
    el.textContent = '0+';
    let current = 0;
    const step = target / 60;
    const timer = setInterval(()=>{
      current = Math.min(current+step, target);
      el.textContent = Math.floor(current) + '+';
      if (current >= target) clearInterval(timer);
    }, 20);
  });
}

async function loadHomeData() {
  // Fetch everything in parallel — no more sequential awaits causing content
  // to pop in one section at a time (the "numbers/links coming and going" bug).
  const [settings, achievements, events, blogs, testimonials, movies, allReviews] = await Promise.all([
    apiFetch('/api/settings').catch(() => null),
    apiFetch('/api/achievements').catch(() => []),
    apiFetch('/api/events').catch(() => []),
    apiFetch('/api/blogs').catch(() => []),
    apiFetch('/api/testimonials').catch(() => []),
    apiFetch('/api/movies').catch(() => []),
    fetch('/api/reviews/all').then(r => r.ok ? r.json() : []).catch(() => [])
  ]);

  // ── Settings / hero / footer ──────────────────────────────────────────────
  if (settings) {
    const tagEl = document.getElementById('hero-tagline');
    if (settings.site_tagline) {
      const _esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
      var parts = settings.site_tagline.match(/([^.]+\.)[\s]*([^.]+\.)[\s]*(.+)/);
      if (parts) {
        tagEl.innerHTML =
          '<span class="glow-word" id="glow-lights">'+_esc(parts[1].trim())+'<\/span><br>'+
          '<em><span class="glow-word" id="glow-camera">'+_esc(parts[2].trim())+'<\/span><\/em><br>'+
          '<span class="glow-word" id="glow-kfs">'+_esc(parts[3].trim())+'<\/span>';
      } else {
        tagEl.innerHTML = '<span class="glow-word" id="glow-lights">'+_esc(settings.site_tagline)+'<\/span>';
      }
      if(window.glowUpdate) window.glowUpdate();
    }
    document.getElementById('about-text').textContent = settings.about_text || '';
    if (settings.team_photo) {
      const tp = document.getElementById('about-team-photo');
      const lb = document.getElementById('about-logo-fallback');
      if (tp) { tp.src = settings.team_photo; tp.style.display = 'block'; }
      if (lb) lb.style.display = 'none';
      const vb = document.getElementById('about-visual-box');
      if (vb) vb.classList.add('has-photo');
    }
    const ig = document.getElementById('footer-instagram');
    const yt = document.getElementById('footer-youtube');
    const em = document.getElementById('footer-email');
    if (settings.instagram) { ig.href=settings.instagram; ig.style.display='block'; }
    if (settings.youtube) { yt.href=settings.youtube; yt.style.display='block'; }
    if (settings.email) em.href='mailto:'+settings.email;
    // update stat counters from settings — set data-target BEFORE animateCounters runs
    if (settings.stat_members) document.querySelector('[data-target="500"]')?.setAttribute('data-target', settings.stat_members);
    if (settings.stat_events) document.querySelector('[data-target="50"]')?.setAttribute('data-target', settings.stat_events);
    if (settings.stat_films) document.querySelector('[data-target="30"]')?.setAttribute('data-target', settings.stat_films);
    if (settings.stat_years) document.querySelector('[data-target="5"]')?.setAttribute('data-target', settings.stat_years);

    // Update structured data sameAs links from settings
    try {
      const ldEl = document.querySelector('script[type="application/ld+json"]');
      if (ldEl) {
        const ld = JSON.parse(ldEl.textContent);
        const sameAs = [];
        if (settings.instagram) sameAs.push(settings.instagram);
        if (settings.youtube) sameAs.push(settings.youtube);
        ld.sameAs = sameAs;
        if (settings.email) ld.email = settings.email;
        ldEl.textContent = JSON.stringify(ld);
      }
    } catch(e) {}

    // Member Spotlight
    if (settings.spotlight_name) {
      const sec = document.getElementById('spotlight-section');
      const div = document.getElementById('spotlight-divider');
      const wrap = document.getElementById('spotlight-wrap');
      sec.style.display = 'block';
      div.style.display = 'block';
      wrap.innerHTML = `
        <div>
          ${settings.spotlight_photo
            ? `<img class="spotlight-photo" src="${settings.spotlight_photo}" alt="${settings.spotlight_name}">`
            : `<div class="spotlight-photo-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/div>`}
        <\/div>
        <div>
          <div class="spotlight-label">Member Spotlight<\/div>
          <p class="spotlight-quote">${settings.spotlight_quote || ''}<\/p>
          <div class="spotlight-name">${settings.spotlight_name}<\/div>
          <div class="spotlight-role">${settings.spotlight_role || ''}<\/div>
        <\/div>`;
    }
  }
  document.getElementById('footer-year').textContent = new Date().getFullYear();

  // ── Achievements ──────────────────────────────────────────────────────────
  const ag = document.getElementById('achievements-grid');
  if (achievements && achievements.length) {
    ag.innerHTML = achievements.map(a=>{ const aJson=JSON.stringify(a).replace(/"/g,'&quot;'); return `
      <div class="achievement-card">
        <div class="achievement-icon">${a.image ? `<img src="${a.image}" alt="" style="width:56px;height:56px;object-fit:cover;border-radius:8px">` : (a.icon||`<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="8 17 12 21 16 17"/><line x1="12" y1="6" x2="12" y2="21"/><path d="M20 4H4l2 10h12z"/><path d="M5 4V2h14v2"/></svg>`)}<\/div>
        <div class="achievement-title">${a.title}<\/div>
        <div class="achievement-year">${a.year||''}<\/div>
        <div class="achievement-desc">${a.description||''}<\/div>
      <\/div>`; }).join('');
  } else {
    ag.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><p>No achievements yet.<\/p><\/div>`;
  }

  // ── Events ────────────────────────────────────────────────────────────────
  const homeEvents = document.getElementById('home-events');
  const upcoming = (events||[]).filter(e=>e.is_upcoming).slice(0,3);
  if (upcoming.length) {
    homeEvents.innerHTML = upcoming.map(e=>renderEventItem(e,true)).join('');
  } else {
    homeEvents.innerHTML = `<div class="empty-state"><p>No upcoming events. Check back soon.<\/p><\/div>`;
  }

  // ── Blog ──────────────────────────────────────────────────────────────────
  const hbg = document.getElementById('home-blog-grid');
  if (blogs && blogs.length) {
    window._allBlogs = blogs;
    const _hrs = getBlogReadState();
    const _hsorted = [...blogs].sort((a,b)=>{
      const av=!!_hrs[a.id], bv=!!_hrs[b.id];
      if(av!==bv) return av?1:-1; return 0;
    });
    hbg.innerHTML = _hsorted.slice(0,6).map(b=>{
      const isViewed = !!_hrs[b.id];
      const badge = isViewed ? `<span class="hc-read-badge"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><\/svg> Viewed<\/span>` : `<span class="hc-read-badge">New<\/span>`;
      const imgHtml = b.cover_image
        ? `<div class="hc-blog-img-wrap">${badge}<img class="hc-blog-img" src="${b.cover_image}" alt="" loading="lazy"><\/div>`
        : `<div class="hc-blog-placeholder" style="position:relative">${badge}<\/div>`;
      return `<div class="hc-blog-card ${isViewed?'hc-viewed':'hc-unread'}" onclick="openBlog('${b.id}')">
        ${imgHtml}
        <div class="hc-blog-body">
          <div class="hc-blog-date">${new Date(b.created_at).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})}<\/div>
          <div class="hc-blog-title">${b.title}<\/div>
          <div class="hc-blog-excerpt">${b.excerpt||''}<\/div>
        <\/div>
      <\/div>`;
    }).join('');
  } else {
    hbg.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><p>No posts yet.<\/p><\/div>`;
  }

  // ── Testimonials ──────────────────────────────────────────────────────────
  renderTestimonials(testimonials||[]);

  // ── Movies + Reviews ──────────────────────────────────────────────────────
  window._allMoviesCache = movies || [];
  window._movieRatings = {};
  if (Array.isArray(allReviews)) {
    const grouped = {};
    allReviews.forEach(r => {
      if (!grouped[r.movie_id]) grouped[r.movie_id] = [];
      grouped[r.movie_id].push(r.overall);
    });
    Object.keys(grouped).forEach(id => {
      const vals = grouped[id].filter(Boolean);
      window._movieRatings[id] = { avg: vals.reduce((a,b)=>a+b,0)/vals.length, count: vals.length };
    });
  }
  const hmg = document.getElementById('home-movies-grid');
  if (movies && movies.length) {
    _allHomeMovies = movies;
    hmg.innerHTML = movies.slice(0,8).map(m=>{
      const rt = window._movieRatings && window._movieRatings[m.id];
      const ratingHtml = rt
        ? `<div class="hc-film-rating"><svg width="10" height="10" viewBox="0 0 24 24" fill="#f59e0b"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/><\/svg>${rt.avg.toFixed(1)}<span class="hc-film-rating-count">(${rt.count})<\/span><\/div>`
        : '';
      const posterHtml = m.poster_image
        ? `<div class="hc-film-poster-wrap"><img class="hc-film-poster" src="${m.poster_image}" alt="" loading="lazy"><\/div>`
        : `<div class="hc-film-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity=".3"><rect x="2" y="2" width="20" height="20" rx="2"><\/rect><path d="M7 2v20M17 2v20M2 12h20M2 7h5M17 7h5M2 17h5M17 17h5"><\/path><\/svg><\/div>`;
      return `<div class="hc-film-card" onclick="openMovie('${m.id}')">
        ${posterHtml}
        <div class="hc-film-info">
          <div class="hc-film-title">${m.title}<\/div>
          <div class="hc-film-meta">${[m.release_year, (Array.isArray(m.genre)?m.genre:(m.genre?[m.genre]:[])).join(', ')].filter(Boolean).join(' · ')}<\/div>
          ${ratingHtml}
        <\/div>
      <\/div>`;
    }).join('');
  } else {
    hmg.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><p>No films yet.<\/p><\/div>`;
  }

  // Counters animate after all data-target values are set
  animateCounters();
}

async function loadEvents() {
  const list = document.getElementById('events-list');
  if (list) list.innerHTML = '<div class="empty-state"><p>Loading events…</p></div>';
  allEvents = await apiFetch('/api/events') || [];
  filterEvents('upcoming', document.querySelector('#page-events .events-tab'));
}

function filterEvents(type, tabEl) {
  document.querySelectorAll('#page-events .events-tab').forEach(t=>t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  const filtered = allEvents.filter(e=> type==='upcoming' ? e.is_upcoming : !e.is_upcoming);
  const list = document.getElementById('events-list');
  if (filtered.length) {
    list.innerHTML = filtered.map(e=>renderEventItem(e,true)).join('');
  } else {
    list.innerHTML = `<div class="empty-state"><p>No ${type} events.<\/p><\/div>`;
  }
  const cvWrap = document.getElementById('cv-section-wrap');
  if (cvWrap) {
    if (type === 'past') { cvWrap.style.display = 'block'; loadCVCards(); }
    else { cvWrap.style.display = 'none'; }
  }
}

function renderEventItem(e, full=false) {
  // Parse date as IST (UTC+5:30)
  const d = e.event_date ? new Date(e.event_date + 'T00:00:00+05:30') : null;
  const day = d ? d.getDate() : '--';
  const month = d ? d.toLocaleString('default',{month:'short'}).toUpperCase() : '';
  // Format time with AM/PM
  const fmtTime = (t) => {
    if (!t) return '';
    const m = t.trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?(\s*[AP]M)?$/i);
    if (!m) return t;
    let h = parseInt(m[1]), mn = m[2], ap = m[4] ? m[4].trim().toUpperCase() : null;
    if (!ap) { ap = h < 12 ? 'AM' : 'PM'; if (h === 0) h = 12; else if (h > 12) h -= 12; }
    return h + ':' + mn + ' ' + ap;
  };
  // Countdown — count down to exact event time (IST)
  let countdownHtml = '';
  if (e.is_upcoming && d) {
    let eventMs = d.getTime();
    if (e.event_time) {
      const tm = e.event_time.trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?(\s*[AP]M)?$/i);
      if (tm) {
        let h = parseInt(tm[1]), mn = parseInt(tm[2]), ap = tm[4] ? tm[4].trim().toUpperCase() : null;
        if (ap === 'PM' && h !== 12) h += 12;
        else if (ap === 'AM' && h === 12) h = 0;
        const pad = n => String(n).padStart(2,'0');
        eventMs = new Date(e.event_date + `T${pad(h)}:${pad(mn)}:00+05:30`).getTime();
      }
    }
    const diff = eventMs - Date.now();
    if (diff > 0) {
      const days = Math.floor(diff / (1000*60*60*24));
      const hrs  = Math.floor((diff % (1000*60*60*24)) / (1000*60*60));
      const mins = Math.floor((diff % (1000*60*60)) / (1000*60));
      const label = days > 0 ? `${days}d ${hrs}h left` : hrs > 0 ? `${hrs}h ${mins}m left` : `${mins}m left`;
      countdownHtml = `<div class="event-countdown"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${label}<\/div>`;
    }
  }
  // Store event in registry so onclick handlers don't break on apostrophes/special chars
  if (!window._eventRegistry) window._eventRegistry = {};
  window._eventRegistry[e.id] = e;
  // Share
  const shareHtml = `<button class="event-share-btn" onclick="event.stopPropagation();shareEventById('${e.id}')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/><\/svg>Share<\/button>`;
  // Image column — always show if cover_image exists
  const imgCol = e.cover_image
    ? `<div class="event-cover-col"><img src="${e.cover_image}" alt="${e.title}"><\/div>`
    : `<div class="event-cover-col" style="display:none"><\/div>`;
  return `<div class="event-item${e.cover_image ? '' : ' event-item-no-img'}" data-event-id="${e.id}">
    <div class="event-date-block">
      <span class="event-day">${day}<\/span>
      <span class="event-month">${month}<\/span>
    <\/div>
    <div class="event-info">
      <span class="tag ${e.is_upcoming?'upcoming':''}">${e.is_upcoming?'Upcoming':'Past'}<\/span>
      <h3>${e.title}<\/h3>
      <p>${e.description||''}<\/p>
      ${countdownHtml}
    <\/div>
    ${imgCol}
    <div class="event-action-row">
      ${e.is_upcoming ? `<button class="event-register-btn" onclick="openEventFormById('${e.id}')">Register →<\/button>` : ''}
      ${shareHtml}
    <\/div>
    <div class="event-location">${e.location||''}<br><span class="event-time-display">${fmtTime(e.event_time||'')}<\/span><\/div>
  <\/div>`;
}

async function loadBlog() {
  const wrap = document.getElementById('blog-sections-wrap');
  if (wrap) wrap.innerHTML = '<div style="padding:60px 80px"><div class="empty-state"><p>Loading posts…</p></div></div>';
  const blogs = await apiFetch('/api/blogs');
  const filterWrap = document.getElementById('blog-filter-wrap');
  if (!blogs || !blogs.length) {
    if (filterWrap) filterWrap.style.display = 'none';
    wrap.innerHTML = `<div style="padding:60px 80px"><div class="empty-state"><p>No posts yet.<\/p><\/div><\/div>`;
    return;
  }
  window._allBlogs = blogs;

  // Collect unique section types
  const sectionTypes = [];
  blogs.forEach(b => {
    let secs = [];
    try { secs = b.sections ? JSON.parse(b.sections) : []; } catch(e){}
    secs.forEach(s => {
      if (s && s.id && s.label && !sectionTypes.find(t=>t.id===s.id))
        sectionTypes.push({id:s.id, label:s.label});
    });
  });
  window._blogSectionTypes = sectionTypes;

  // Show/hide filter button
  if (sectionTypes.length && filterWrap) {
    filterWrap.style.display = 'inline-block';
    _buildBlogFilterDropdown(sectionTypes);
    // Reset to "All" state
    const btn = document.getElementById('blog-filter-btn');
    if (btn) {
      const textNode = Array.from(btn.childNodes).find(n=>n.nodeType===3 && n.textContent.trim());
      if (textNode) textNode.textContent = ' Filter ';
    }
    const badge = document.getElementById('blog-filter-badge');
    if (badge) badge.style.display = 'none';
  } else if (filterWrap) {
    filterWrap.style.display = 'none';
  }

  _renderBlogSections(blogs, sectionTypes, null);
}

function _buildBlogFilterDropdown(sectionTypes) {
  const dd = document.getElementById('blog-filter-dropdown');
  if (!dd) return;
  const allItem = `<button class="blog-filter-item active" id="bfi-all" onclick="applyBlogFilter(null,this)">
    <span class="blog-filter-item-dot"></span>All Posts
  <\/button>`;
  const secItems = sectionTypes.map(st =>
    `<button class="blog-filter-item" id="bfi-${st.id}" onclick="applyBlogFilter('${st.id}',this)">
      <span class="blog-filter-item-dot"></span>${st.label}
    <\/button>`
  ).join('');
  dd.innerHTML = allItem + (sectionTypes.length ? '<div class="blog-filter-divider-line"><\/div>' + secItems : '');
}

function toggleBlogFilter(btn) {
  const dd = document.getElementById('blog-filter-dropdown');
  const isOpen = dd.classList.contains('open');
  dd.classList.toggle('open', !isOpen);
  btn.classList.toggle('open', !isOpen);
  if (!isOpen) {
    const close = e => {
      if (!btn.closest('.blog-filter-wrap').contains(e.target)) {
        dd.classList.remove('open'); btn.classList.remove('open');
        document.removeEventListener('click', close);
      }
    };
    setTimeout(() => document.addEventListener('click', close), 0);
  }
}

function applyBlogFilter(sectionId, btn) {
  document.querySelectorAll('.blog-filter-item').forEach(b=>b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('blog-filter-dropdown').classList.remove('open');
  document.getElementById('blog-filter-btn')?.classList.remove('open');
  // Update button label text
  const filterBtn = document.getElementById('blog-filter-btn');
  if (filterBtn) {
    const st = (window._blogSectionTypes||[]).find(s=>s.id===sectionId);
    const textNode = Array.from(filterBtn.childNodes).find(n=>n.nodeType===3 && n.textContent.trim());
    if (textNode) textNode.textContent = st ? ` ${st.label} ` : ' Filter ';
  }
  _renderBlogSections(window._allBlogs || [], window._blogSectionTypes || [], sectionId);
}

function _renderBlogSections(blogs, sectionTypes, activeSection) {
  const wrap = document.getElementById('blog-sections-wrap');
  const _rs = getBlogReadState();
  const sorted = [...blogs].sort((a,b) => { const av=!!_rs[a.id],bv=!!_rs[b.id]; return av===bv?0:av?1:-1; });

  let html = '';
  if (!activeSection) {
    html += `<div class="blog-page-section" id="blog-all">
      <div class="blog-grid">${sorted.map(b=>renderBlogCard(b)).join('')}<\/div>
    <\/div>`;
    sectionTypes.forEach(st => {
      const tagged = sorted.filter(b => {
        let secs=[]; try{secs=b.sections?JSON.parse(b.sections):[]}catch(e){}
        return secs.some(s=>s.id===st.id);
      });
      if (!tagged.length) return;
      html += `<div class="blog-page-divider"><\/div>
      <div class="blog-page-section" id="blog-sec-${st.id}">
        <div class="blog-page-section-header">
          <p class="blog-page-section-label">Category<\/p>
          <h3 class="blog-page-section-title">${st.label}<\/h3>
        <\/div>
        <div class="blog-grid">${tagged.map(b=>renderBlogCard(b)).join('')}<\/div>
      <\/div>`;
    });
  } else {
    const st = sectionTypes.find(s=>s.id===activeSection);
    const tagged = sorted.filter(b => {
      let secs=[]; try{secs=b.sections?JSON.parse(b.sections):[]}catch(e){}
      return secs.some(s=>s.id===activeSection);
    });
    html += `<div class="blog-page-section" id="blog-sec-${activeSection}">
      <div class="blog-page-section-header">
        <p class="blog-page-section-label">Category<\/p>
        <h3 class="blog-page-section-title">${st ? st.label : activeSection}<\/h3>
      <\/div>
      ${tagged.length
        ? `<div class="blog-grid">${tagged.map(b=>renderBlogCard(b)).join('')}<\/div>`
        : `<div class="empty-state"><p>No posts in this category yet.<\/p><\/div>`}
    <\/div>`;
  }
  wrap.innerHTML = html;
}

function getBlogReadState() {
  try { return JSON.parse(localStorage.getItem('kfs_read_blogs') || '{}'); } catch { return {}; }
}
function markBlogRead(id) {
  const state = getBlogReadState();
  state[id] = Date.now();
  localStorage.setItem('kfs_read_blogs', JSON.stringify(state));
}
function getBlogHistory() {
  const state = getBlogReadState();
  return Object.entries(state).map(([id,ts])=>({id,ts})).sort((a,b)=>b.ts-a.ts);
}

function renderBlogCard(b) {
  const readState = getBlogReadState();
  const isViewed = !!readState[b.id];
  const cls = isViewed ? 'viewed' : 'unread';
  const badge = isViewed ? 'Viewed' : 'Unread';
  // Parse section tags to show as pills on card
  let secs = [];
  try { secs = b.sections ? JSON.parse(b.sections) : []; } catch(e){}
  const tagPills = secs.length
    ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">${secs.map(s=>`<span style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:3px 9px;border-radius:20px;border:1px solid var(--border);color:var(--grey)">${s.label}<\/span>`).join('')}<\/div>`
    : '';
  return `<div class="blog-card ${cls}" onclick="openBlog('${b.id}')" data-blog-id="${b.id}">
    <div class="blog-card-img-wrap">
      <span class="blog-read-badge">${badge}<\/span>
      ${b.cover_image
        ? `<img class="blog-card-img" src="${b.cover_image}" alt="${b.title}">`
        : `<div class="blog-card-img-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg><\/div>`}
    <\/div>
    <div class="blog-card-body">
      <p class="blog-card-date">${b.created_at ? new Date(b.created_at).toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'}) : ''}<\/p>
      ${tagPills}
      <h3 class="blog-card-title">${b.title}<\/h3>
      ${b.author ? `<p class="blog-card-author" style="font-size:11px;color:var(--grey);margin:4px 0 6px;letter-spacing:.04em">${b.author.split(';;').map(a=>{const p=a.indexOf('||');return p!==-1?a.slice(0,p).trim():a.trim();}).join(', ')}<\/p>` : ''}
      <p class="blog-card-excerpt">${b.excerpt||''}<\/p>
    <\/div>
  <\/div>`;
}

async function openBlog(id) {
  const blog = await apiFetch('/api/blogs/'+id);
  if (!blog) return;
  // Ensure members are loaded for author linking
  if (!allMembers || !allMembers.length) {
    const mdata = await apiFetch('/api/members');
    if (mdata) allMembers = mdata;
  }
  // Mark as viewed and update card live
  markBlogRead(id);
  // Update all blog page cards (post may appear in All + section block)
  document.querySelectorAll('[data-blog-id="'+id+'"]').forEach(card => {
    card.classList.remove('unread'); card.classList.add('viewed');
    const badge = card.querySelector('.blog-read-badge');
    if (badge) badge.textContent = 'Viewed';
  });
  // Update home carousel card
  const hcCard = document.querySelector('.hc-blog-card[onclick*="\''+id+'\'"]');
  if (hcCard) {
    hcCard.classList.remove('hc-unread'); hcCard.classList.add('hc-viewed');
    const hcBadge = hcCard.querySelector('.hc-read-badge');
    if (hcBadge) hcBadge.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Viewed';
  }
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('blog-detail').classList.add('active');
  const img = document.getElementById('blog-detail-img');
  if (blog.cover_image) { img.src=blog.cover_image; img.style.display='block'; }
  else img.style.display='none';
  document.getElementById('blog-detail-date').textContent = blog.created_at
    ? new Date(blog.created_at).toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'}) : '';
  document.getElementById('blog-detail-title').textContent = blog.title;
  // Author(s) — supports multiple authors separated by ;;
  const authorEl = document.getElementById('blog-detail-author');
  if (blog.author) {
    const _authorParts = blog.author.split(';;').map(s => s.trim()).filter(Boolean);
    window._blogAuthorMembers = [];
    const _resolvedSpans = _authorParts.map((_authorRaw, _idx) => {
      const _pipeIdx = _authorRaw.indexOf('||');
      let _displayName = _authorRaw;
      let _linkedMember = null;
      if (_pipeIdx !== -1) {
        _displayName = _authorRaw.slice(0, _pipeIdx).trim();
        const _memberId = _authorRaw.slice(_pipeIdx + 2).trim();
        _linkedMember = allMembers && allMembers.find(m => String(m.id) === _memberId);
      }
      if (!_linkedMember) {
        _linkedMember = allMembers && allMembers.find(
          m => m.name && m.name.trim().toLowerCase() === _displayName.toLowerCase()
        );
      }
      window._blogAuthorMembers[_idx] = _linkedMember || null;
      if (_linkedMember) {
        window._blogAuthorMember = _linkedMember; // legacy single-author compat
        return `<span class="blog-author-link" style="cursor:pointer;border-bottom:1px solid rgba(245,245,245,.3);padding-bottom:1px" onclick="openMemberProfile(window._blogAuthorMembers[${_idx}])">${_displayName}</span>`;
      }
      return `<span>${_displayName}</span>`;
    });
    const _joined = _resolvedSpans.length > 1
      ? _resolvedSpans.slice(0,-1).join(', ') + ' &amp; ' + _resolvedSpans[_resolvedSpans.length-1]
      : _resolvedSpans[0];
    authorEl.innerHTML = `By ${_joined}`;
    authorEl.style.display = 'block';
  } else {
    authorEl.style.display = 'none';
  }
  // Render content: clean up contenteditable editor artifacts into proper paragraphs
  let content = blog.content || '';
  // Step 1: extract plain text from whatever HTML the editor produced
  const tmp = document.createElement('div');
  tmp.innerHTML = content;
  // Treat block-level elements as paragraph separators
  tmp.querySelectorAll('p,div,br,h1,h2,h3,h4,h5,h6,li').forEach(el => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'br') { el.replaceWith(' '); }
    else {
      const txt = el.innerText || el.textContent || '';
      el.replaceWith(txt.trim() + '\n\n');
    }
  });
  let plainText = (tmp.textContent || tmp.innerText || '')
    .replace(/\u00a0/g, ' ')       // &nbsp; → space
    .replace(/[ \t]+/g, ' ')       // collapse inline spaces
    .replace(/\n[ \t]+/g, '\n')    // trim leading space per line
    .replace(/[ \t]+\n/g, '\n')    // trim trailing space per line
    .replace(/\n{3,}/g, '\n\n')    // max 2 newlines
    .trim();
  // Step 2: split into paragraphs on double newlines, then rejoin fragments
  // that don't end a sentence (no . ! ? at end) with the next fragment
  const rawBlocks = plainText.split(/\n\n+/).map(b => b.replace(/\n/g, ' ').trim()).filter(Boolean);
  const paragraphs = [];
  let current = '';
  for (const block of rawBlocks) {
    current = current ? current + ' ' + block : block;
    // If this block ends with sentence-closing punctuation, commit it
    if (/[.!?'"\u2019\u201d]\s*$/.test(current)) {
      paragraphs.push(current);
      current = '';
    }
  }
  if (current) paragraphs.push(current); // flush remainder
  content = paragraphs.map(p => `<p>${p}</p>`).join('');
  document.getElementById('blog-detail-body').innerHTML = (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(content) : content;
  // Show section tags as pills below the title (tags only, no content switching)
  const navWrap = document.getElementById('blog-section-nav-wrap');
  let parsedSections = [];
  try { parsedSections = blog.sections ? JSON.parse(blog.sections) : []; } catch(e){}
  if (parsedSections && parsedSections.length) {
    const sanitize = (s) => (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(s, { ALLOWED_TAGS: [] }) : s.replace(/[<>"'&]/g, '');
    navWrap.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:28px">`
      + parsedSections.map(s=>`<span style="font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
          padding:4px 12px;border-radius:20px;border:1px solid var(--border);color:var(--grey)">${sanitize(s.label)}</span>`).join('')
      + `</div>`;
  } else {
    navWrap.innerHTML = '';
  }
  // Inject Recently Viewed below content
  renderRecentlyViewed(id);
  window.scrollTo({top:0,behavior:'instant'});
  // Use slug URL — no UUID exposed
  const slug = (blog.title ? blog.title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') : '') + '-' + id;
  history.pushState({page:'blog-detail', id}, '', '/blog/'+slug);
  window._currentBlogId = id;
  window._currentBlogExcerpt = blog.excerpt || '';
  window._currentBlogCover = blog.cover_image || '';
  const blogDesc = blog.excerpt
    ? blog.excerpt.slice(0, 155)
    : (blog.content ? blog.content.replace(/<[^>]+>/g,'').slice(0,155) : `Read "${blog.title}" on KFS — KIIT Film Society.`);
  updateMetaTags({
    title: blog.title,
    description: blogDesc,
    image: `/og/blog/${id}`,
    url: '/blog/' + slug,
  });

  // BlogPosting schema — helps Google show rich results (author, date, image)
  injectPageSchema({
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "headline": blog.title,
    "description": blogDesc,
    "image": `https://kiitfilmsociety.in/og/blog/${id}`,
    "url": `https://kiitfilmsociety.in/blog/${slug}`,
    "datePublished": blog.created_at || undefined,
    "dateModified": blog.updated_at || blog.created_at || undefined,
    "author": {
      "@type": "Organization",
      "name": "KFS — KIIT Film Society",
      "url": "https://kiitfilmsociety.in"
    },
    "publisher": {
      "@type": "Organization",
      "name": "KFS — KIIT Film Society",
      "logo": {
        "@type": "ImageObject",
        "url": "https://kiitfilmsociety.in/images/kfs-logo.png"
      }
    },
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": `https://kiitfilmsociety.in/blog/${slug}`
    }
  });
  hideScrollProgress();
  setTimeout(updateScrollProgress, 100);
}

function switchBlogSection(btn, sectionId) {
  const navWrap = document.getElementById('blog-section-nav-wrap');
  navWrap.querySelectorAll('.blog-section-btn').forEach(b=>b.classList.remove('active'));
  navWrap.querySelectorAll('.blog-content-section').forEach(s=>s.classList.remove('active'));
  btn.classList.add('active');
  const sec = document.getElementById(sectionId);
  if (sec) sec.classList.add('active');
}

function renderRecentlyViewed(currentId) {
  // Remove any existing section
  const existing = document.getElementById('recently-viewed-section');
  if (existing) existing.remove();
  const history = getBlogHistory().filter(h => String(h.id) !== String(currentId)).slice(0, 5);
  if (!history.length) return;
  const allBlogs = window._allBlogs || [];
  const items = history.map(h => allBlogs.find(b => String(b.id) === String(h.id))).filter(Boolean);
  if (!items.length) return;
  const section = document.createElement('div');
  section.id = 'recently-viewed-section';
  section.className = 'recently-viewed';
  section.innerHTML = '<div class="recently-viewed-label">Recently Viewed<\/div>'
    + '<div class="recently-viewed-list">'
    + items.map(b => `
      <div class="rv-item" onclick="openBlog('${b.id}')">
        <div class="rv-thumb-wrap">
          ${b.cover_image
            ? `<img src="${b.cover_image}" alt="${b.title}">`
            : `<div class="rv-thumb-placeholder"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg><\/div>`}
        <\/div>
        <div class="rv-item-info">
          <div class="rv-item-title">${b.title}<\/div>
          <div class="rv-item-date">${b.created_at ? new Date(b.created_at).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'}) : ''}<\/div>
        <\/div>
      <\/div>`).join('')
    + '<\/div>';
  document.getElementById('blog-detail-body').after(section);
}

let allMembers = [];

async function loadMembers() {
  const container = document.getElementById('members-content');
  container.innerHTML = '<div class="loading">Loading members...<\/div>';
  const data = await apiFetch('/api/members');
  allMembers = data || [];
  // reset tabs
  document.querySelectorAll('#page-members .events-tab').forEach((t,i)=>{
    t.classList.toggle('active', i===0);
  });
  renderMemberSections('current');
}

function filterMembers(type, tabEl) {
  document.querySelectorAll('#page-members .events-tab').forEach(t=>t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  renderMemberSections(type);
}

function renderMemberSections(type) {
  const container = document.getElementById('members-content');
  const members = allMembers.filter(m => type === 'past' ? m.is_past === true : m.is_past !== true);

  if (!members.length) {
    container.innerHTML = `<div class="empty-state"><p>No ${type === 'past' ? 'alumni' : 'current members'} yet.<\/p><\/div>`;
    return;
  }

  const roleOrder = ['President','Vice President','Lead','Core Member','Member'];
  const sections = {};
  roleOrder.forEach(r => sections[r] = []);
  members.forEach(m => {
    const key = roleOrder.includes(m.role) ? m.role : 'Member';
    sections[key].push(m);
  });

  // Photo groups: square cards with image
  const photoGroups = [
    { label: 'President',       roles: ['President'] },
    { label: 'Vice Presidents', roles: ['Vice President'] },
    { label: 'Core & Leads',    roles: ['Lead', 'Core Member'] },
  ];
  // Members: split by whether they have a photo
  const membersWithPhoto = (sections['Member']||[]).filter(m=>m.photo);
  const membersNoPhoto   = (sections['Member']||[]).filter(m=>!m.photo);
  if (membersWithPhoto.length) sections['MemberPhoto'] = membersWithPhoto;
  if (membersNoPhoto.length)   sections['MemberPlain'] = membersNoPhoto;
  if (membersWithPhoto.length) photoGroups.push({ label: 'Members', roles: ['MemberPhoto'] });
  const plainGroups = membersNoPhoto.length ? [{ label: 'General Members', roles: ['MemberPlain'] }] : [];

  function photoCard(m) {
    const subtitle = m.domain ? m.domain : (m.role === 'Member' ? '' : (m.role||''));
    const idx = _memberIdx(m);
    return `<div class="member-card-photo" data-member-idx="${idx}" style="cursor:pointer">
      ${m.photo
        ? `<img class="member-photo-sq" src="${m.photo}" alt="${m.name}">`
        : `<div class="member-photo-sq-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/div>`}
      <div class="member-info-sq">
        <div class="member-name-sq">${m.name}<\/div>
        ${m.special_tag ? `<div class="member-special-tag tag-${m.special_tag}">${m.special_tag === 'admin-developer' ? '</> Admin-Dev' : '</> Developer'}<\/div>` : ''}
        ${subtitle ? `<div class="member-role-sq">${subtitle}<\/div>` : ''}
        ${m.batch ? `<div class="member-batch-sq">${m.batch}<\/div>` : ''}
      <\/div>
    <\/div>`;
  }

  function plainRow(m) {
    return `<div class="member-row" data-member-idx="${_memberIdx(m)}">
      <div class="member-row-name">${m.name}<\/div>
      ${m.batch ? `<div class="member-row-batch">${m.batch}<\/div>` : ''}
    <\/div>`;
  }

  let html = '';
  function tagRank(m){return m.special_tag==='admin-developer'?0:m.special_tag==='developer'?1:2;}
  function sortByTag(arr){return [...arr].sort((a,b)=>tagRank(a)-tagRank(b));}

  photoGroups.forEach(group => {
    const combined = sortByTag(group.roles.flatMap(r => sections[r] || []));
    if (!combined.length) return;
    html += `<div class="members-section">
      <div class="members-section-title">${group.label}<\/div>
      <div class="members-grid-photo">${combined.map(photoCard).join('')}<\/div>
    <\/div>`;
  });
  plainGroups.forEach(group => {
    const combined = sortByTag(group.roles.flatMap(r => sections[r] || []));
    if (!combined.length) return;
    html += `<div class="members-section">
      <div class="members-section-title">${group.label}<\/div>
      <div class="members-list-plain">${combined.map(plainRow).join('')}<\/div>
    <\/div>`;
  });

  container.innerHTML = html || `<div class="empty-state"><p>No members yet.<\/p><\/div>`;
}

function autoMemberSort() {
  const role = document.getElementById('member-role').value;
  const map = {'President':1,'Vice President':2,'Lead':3,'Core Member':3,'Member':5};
  document.getElementById('member-sort').value = map[role] || 5;
}
function toggleDomainField() {
  const role = document.getElementById('member-role').value;
  const group = document.getElementById('domain-group');
  const label = document.getElementById('domain-label');
  if (!group) return;
  const show = role === 'Lead' || role === 'Member';
  group.style.display = show ? 'block' : 'none';
  if (label) label.textContent = role === 'Member' ? 'Domain (optional)' : 'Domain';
}

async function loadMovies() {
  const grid = document.getElementById('movies-grid');
  if (grid) grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><p>Loading films…</p></div>';
  const [movies, allReviews] = await Promise.all([
    apiFetch('/api/movies'),
    fetch('/api/reviews/all').then(r=>r.ok?r.json():[]).catch(()=>[])
  ]);
  window._allMoviesCache = movies || [];
  // Build rating averages keyed by movie id
  window._movieRatings = {};
  if (Array.isArray(allReviews)) {
    const grouped = {};
    allReviews.forEach(r => {
      if (!grouped[r.movie_id]) grouped[r.movie_id] = [];
      grouped[r.movie_id].push(r.overall);
    });
    Object.keys(grouped).forEach(id => {
      const vals = grouped[id].filter(Boolean);
      window._movieRatings[id] = { avg: vals.reduce((a,b)=>a+b,0)/vals.length, count: vals.length };
    });
  }

  // Build genre filter dropdown (matching blog filter style)
  window._activeGenreFilter = null;
  // Deduplicate genres case-insensitively, preserving the first-seen casing
  const genreMap = new Map(); // lowercase key → original casing
  (movies||[]).flatMap(m => Array.isArray(m.genre) ? m.genre : []).filter(Boolean).forEach(g => {
    const key = g.toLowerCase().trim();
    if (!genreMap.has(key)) genreMap.set(key, g.trim());
  });
  const allGenres = [...genreMap.values()].sort((a,b) => a.localeCompare(b));
  const filterBar = document.getElementById('movie-genre-filter-bar');
  const dd = document.getElementById('movie-genre-dropdown');
  if (allGenres.length > 1 && filterBar && dd) {
    filterBar.style.display = 'inline-block';
    const allItem = `<button class="blog-filter-item active" id="mgfi-all" onclick="applyMovieGenreFilter(null,this)"><span class="blog-filter-item-dot"></span>All Films</button>`;
    const genreItems = allGenres.map(g => `<button class="blog-filter-item" id="mgfi-${g.replace(/\s+/g,'-')}" onclick="applyMovieGenreFilter('${g}',this)"><span class="blog-filter-item-dot"></span>${g}</button>`).join('');
    dd.innerHTML = allItem + '<div class="blog-filter-divider-line"></div>' + genreItems;
  } else if (filterBar) { filterBar.style.display = 'none'; }

  renderMoviesGrid(movies || []);
}

function toggleMovieGenreFilter(btn) {
  const dd = document.getElementById('movie-genre-dropdown');
  const isOpen = dd.classList.contains('open');
  dd.classList.toggle('open', !isOpen);
  btn.classList.toggle('open', !isOpen);
  if (!isOpen) {
    setTimeout(() => {
      document.addEventListener('click', function _close(e) {
        if (!btn.closest('.blog-filter-wrap').contains(e.target)) {
          dd.classList.remove('open');
          btn.classList.remove('open');
          document.removeEventListener('click', _close);
        }
      });
    }, 0);
  }
}

function applyMovieGenreFilter(genre, btn) {
  document.querySelectorAll('#movie-genre-dropdown .blog-filter-item').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('movie-genre-dropdown').classList.remove('open');
  document.getElementById('movie-filter-btn')?.classList.remove('open');
  window._activeGenreFilter = genre;
  const badge = document.getElementById('movie-filter-badge');
  if (genre) {
    if (badge) { badge.textContent = genre; badge.style.display = 'inline'; }
  } else {
    if (badge) badge.style.display = 'none';
  }
  const movies = window._allMoviesCache || [];
  const filtered = genre
    ? movies.filter(m => (Array.isArray(m.genre) ? m.genre : []).map(g=>g.toLowerCase()).includes(genre.toLowerCase()))
    : movies;
  renderMoviesGrid(filtered);
}

function renderMoviesGrid(movies) {
  const grid = document.getElementById('movies-grid');
  if (movies && movies.length) {
    grid.innerHTML = movies.map(m=>renderMovieCard(m,true)).join('');
  } else {
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><p>No films yet.<\/p><\/div>`;
  }
}

function renderMovieCard(m, clickable=false) {
  const watched = isMovieWatched(m.id);
  const rating = window._movieRatings && window._movieRatings[m.id];
  const ratingBadge = rating
    ? `<div class="movie-rating-badge"><span class="rb-star">★<\/span>${rating.avg.toFixed(1)}<span class="rb-count">(${rating.count})<\/span><\/div>`
    : '';
  return `<div class="movie-card${watched?' watched':''}" ${clickable?`onclick="openMovie('${m.id}')"`:''}> 
    <div style="position:relative">
      ${m.poster_image
        ? `<img class="movie-poster" src="${m.poster_image}" alt="${m.title}">`
        : `<div class="movie-poster-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg><\/div>`}
      ${ratingBadge}
      ${clickable ? `<div class="movie-watch-badge${watched?' movie-watch-badge--done':''}" onclick="event.stopPropagation();toggleWatchStatusCard('${m.id}',this.closest('.movie-card'))" title="${watched?'Watched':'Mark as Watched'}">
        ${watched ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><\/svg> Watched' : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/><\/svg> Watchlist'}
      <\/div>` : ''}
    <\/div>
    <div class="movie-info">
      <div class="movie-title">${m.title}<\/div>
      <div class="movie-year">${m.release_year||''}<\/div>
      ${(Array.isArray(m.genre)?m.genre:(m.genre?[m.genre]:[])).length ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:5px">${(Array.isArray(m.genre)?m.genre:[m.genre]).map(g=>`<span style="font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:2px 8px;border-radius:20px;border:1px solid var(--border);color:var(--grey)">${g}<\/span>`).join('')}<\/div>` : ''}
      <div class="movie-director">${m.director ? 'Dir. '+splitCrew(m.director).map(p=>p.split('||')[0].trim()).join(', ') : ''}<\/div>
      ${m.description ? `<div class="movie-desc-snip">${m.description}<\/div>` : ''}
    <\/div>
  <\/div>`;
}

async function openMovie(id) {
  // Ensure members are loaded before rendering crew links
  if (!allMembers || !allMembers.length) {
    const data = await apiFetch('/api/members');
    if (data) allMembers = data;
  }
  const m = await apiFetch('/api/movies/'+id);
  if (!m) return;
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('movie-detail').classList.add('active');
  const img = document.getElementById('movie-detail-poster-img');
  const ph = document.getElementById('movie-detail-poster-placeholder');
  if (m.poster_image) {
    img.src=m.poster_image;
    img.style.display='block';
    img.style.filter='grayscale(0%)'; // vivid in detail view
    ph.style.display='none';
  } else { img.style.display='none'; ph.style.display='flex'; }
  document.getElementById('movie-detail-title').textContent = m.title;
  document.getElementById('movie-detail-year').textContent = m.release_year||'';

  // Runtime & Language
  const runtimeEl = document.getElementById('movie-detail-runtime');
  const languageEl = document.getElementById('movie-detail-language');
  const metaRowEl = document.getElementById('movie-detail-meta-row');
  if (m.runtime) {
    const mins = parseInt(m.runtime, 10);
    const dur = mins >= 60 ? Math.floor(mins/60)+'h '+(mins%60)+'m' : mins+'m';
    runtimeEl.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' + dur;
    runtimeEl.style.display = 'inline-flex';
  } else { runtimeEl.style.display = 'none'; }
  if (m.language) {
    languageEl.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>' + m.language;
    languageEl.style.display = 'inline-flex';
  } else { languageEl.style.display = 'none'; }
  metaRowEl.style.display = (m.runtime || m.language) ? 'flex' : 'none';

  // Genre
  const genreWrap = document.getElementById('movie-detail-genre-wrap');
  const genres = Array.isArray(m.genre) ? m.genre : (m.genre ? [m.genre] : []);
  if (genres.length) {
    genreWrap.style.display = 'flex';
    genreWrap.innerHTML = genres.map(g =>
      `<span class="genre-tag" onclick="filterMoviesByGenre('${g}');navigate('movies')" title="Filter by ${g}">${g}<\/span>`
    ).join('');
  } else { genreWrap.style.display = 'none'; genreWrap.innerHTML = ''; }

  // Description
  const descWrap = document.getElementById('movie-detail-description-wrap');
  const descEl = document.getElementById('movie-detail-description');
  if (m.description) { descEl.textContent = m.description; descWrap.style.display = 'block'; }
  else descWrap.style.display = 'none';

  // Watch status
  window._currentMovieId = id;
  updateDetailWatchBtn(id);

  // Trailer / Watch Now buttons
  window._currentTrailerUrl = m.trailer_url || null;
  const actionBtns = document.getElementById('movie-action-btns');
  const posterOverlay = document.getElementById('poster-play-overlay');
  if (m.trailer_url || m.watch_url) {
    actionBtns.style.display = 'flex';
    actionBtns.innerHTML = [
      m.watch_url && /^https:\/\//i.test(m.watch_url) ? `<a class="movie-watch-btn" href="${m.watch_url}" target="_blank" rel="noopener">▶ Watch Now<\/a>` : '',
      m.trailer_url ? `<button class="movie-trailer-btn" onclick="openTrailer()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points='5 3 19 12 5 21 5 3'/><\/svg> Trailer<\/button>` : '',
    ].join('');
  } else {
    actionBtns.style.display = 'none';
    actionBtns.innerHTML = '';
  }
  if (posterOverlay) posterOverlay.style.display = m.trailer_url ? 'flex' : 'none';
  const crewFields = [
    {label:'Director', val:m.director},
    {label:'Producer', val:m.producer},
    {label:'DOP', val:m.dop},
    {label:'Script Writer', val:m.screenwriter},
    {label:'Video Editor', val:m.video_editor},
    {label:'Sound Design', val:m.sound_design},
    {label:'Management', val:m.management},
    {label:'Graphic Design', val:m.graphic_design},
  ].filter(f=>f.val);
  document.getElementById('movie-detail-crew').innerHTML = crewFields.map(f=>`
    <div class="movie-crew-item">
      <div class="movie-crew-label">${f.label}<\/div>
      <div class="movie-crew-value">${renderCrewNames(f.val)}<\/div>
    <\/div>`).join('');
  const actorsSec = document.getElementById('movie-detail-actors-section');
  const actorsEl = document.getElementById('movie-detail-actors');
  if (m.actors) {
    actorsSec.style.display='block';
    actorsEl.innerHTML = splitCrew(m.actors).map(a=>crewNameTag(a.trim())).join('');
  } else actorsSec.style.display='none';
  const supportSec = document.getElementById('movie-detail-support-section');
  const supportEl = document.getElementById('movie-detail-support');
  if (m.support_crew) {
    supportSec.style.display='block';
    supportEl.innerHTML = splitCrew(m.support_crew).map(s=>crewNameTag(s.trim())).join('');
  } else supportSec.style.display='none';
  const spotifySec = document.getElementById('movie-detail-spotify-section');
  const spotifyEmbed = document.getElementById('movie-detail-spotify-embed');
  const soundtrackToggle = document.getElementById('soundtrack-toggle');
  const toggleSpotifyBtn = document.getElementById('toggle-spotify');
  const toggleAppleBtn = document.getElementById('toggle-apple');

  // Store current movie soundtrack URLs for toggle switching
  window._currentSoundtrack = { spotify: m.spotify_url || null, apple: m.apple_music_url || null };

  const hasSpotify = !!m.spotify_url;
  const hasApple = !!m.apple_music_url;

  if (hasSpotify || hasApple) {
    spotifySec.style.display = 'block';

    // Show/hide toggle based on whether both platforms available
    if (hasSpotify && hasApple) {
      soundtrackToggle.style.display = 'flex';
    } else {
      soundtrackToggle.style.display = 'none';
    }

    // Determine default platform: detect OS/platform
    function detectDefaultPlatform() {
      const saved = localStorage.getItem('kfs_music_platform');
      if (saved === 'spotify' || saved === 'apple') return saved;
      const ua = navigator.userAgent || '';
      const platform = navigator.platform || '';
      // Apple platforms: Mac, iPhone, iPad, iPod
      if (/iPhone|iPad|iPod/i.test(ua) || /Mac/i.test(platform)) return 'apple';
      return 'spotify';
    }

    const defaultPlatform = detectDefaultPlatform();
    // If preferred platform not available, fall back
    let activePlatform = defaultPlatform;
    if (activePlatform === 'apple' && !hasApple) activePlatform = 'spotify';
    if (activePlatform === 'spotify' && !hasSpotify) activePlatform = 'apple';

    window.setSoundtrackPlatform = function(platform) {
      activePlatform = platform;
      localStorage.setItem('kfs_music_platform', platform);
      renderSoundtrackEmbed();
      // Re-derive color from the newly active platform's artwork
      fetchAlbumColorAndApply();
    };

    // -- Dynamic color extraction from album art --
    function extractColorFromImg(src, callback) {
      const tmp = new Image();
      tmp.crossOrigin = 'anonymous';
      tmp.onload = () => {
        try {
          const SIZE = 80;
          const canvas = document.createElement('canvas');
          canvas.width = SIZE; canvas.height = SIZE;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(tmp, 0, 0, SIZE, SIZE);
          const data = ctx.getImageData(0, 0, SIZE, SIZE).data;
          const buckets = {};
          for (let i = 0; i < data.length; i += 4) {
            const r = data[i], g = data[i+1], b = data[i+2], a = data[i+3];
            if (a < 128) continue;
            const rf = r/255, gf = g/255, bf = b/255;
            const max = Math.max(rf,gf,bf), min = Math.min(rf,gf,bf);
            const l = (max+min)/2;
            if (l < 0.08 || l > 0.92) continue;
            const d = max - min;
            if (d < 0.1) continue;
            const s = l > 0.5 ? d/(2-max-min) : d/(max+min);
            if (s < 0.2) continue;
            let h;
            if (max===rf) h = ((gf-bf)/d + (gf<bf?6:0))/6;
            else if (max===gf) h = ((bf-rf)/d + 2)/6;
            else h = ((rf-gf)/d + 4)/6;
            const bucket = Math.floor(h * 24);
            if (!buckets[bucket]) buckets[bucket] = {count:0, r:0, g:0, b:0, s:0};
            const bk = buckets[bucket];
            bk.count++; bk.r+=r; bk.g+=g; bk.b+=b; bk.s+=s;
          }
          let topBucket = null, topScore = -1;
          for (const key in buckets) {
            const bk = buckets[key];
            const score = bk.count * (bk.s / bk.count);
            if (score > topScore) { topScore = score; topBucket = bk; }
          }
          if (topBucket) {
            const c = topBucket.count;
            callback({ r: Math.round(topBucket.r/c), g: Math.round(topBucket.g/c), b: Math.round(topBucket.b/c) });
          } else { callback(null); }
        } catch(e) { callback(null); }
      };
      tmp.onerror = () => callback(null);
      tmp.src = src;
    }

    async function fetchAlbumColorAndApply() {
      // 1. Try Spotify oEmbed thumbnail (most reliable — album art exact match)
      if (hasSpotify && m.spotify_url) {
        try {
          const oembedUrl = 'https://open.spotify.com/oembed?url=' + encodeURIComponent(m.spotify_url.trim());
          const res = await fetch(oembedUrl);
          if (res.ok) {
            const json = await res.json();
            if (json.thumbnail_url) {
              extractColorFromImg(json.thumbnail_url, rgb => {
                if (rgb) { applySoundtrackColor(rgb); return; }
                _tryAppleArtwork();
              });
              return;
            }
          }
        } catch(e) {}
      }
      // 2. Try Apple Music oEmbed artwork
      _tryAppleArtwork();
    }

    async function _tryAppleArtwork() {
      // Apple Music exposes artwork via their oEmbed endpoint — no API key needed.
      // The returned thumbnail_url is the album cover at a usable resolution.
      if (hasApple && m.apple_music_url) {
        try {
          const oembedUrl = 'https://music.apple.com/oembed?url=' + encodeURIComponent(m.apple_music_url.trim());
          const res = await fetch(oembedUrl);
          if (res.ok) {
            const json = await res.json();
            // Apple returns artwork_url_100 or thumbnail_url
            const artUrl = json.artwork_url_100 || json.thumbnail_url;
            if (artUrl) {
              // Scale up for better color sample (100px → 300px)
              const largerArt = artUrl.replace('/100x100bb', '/300x300bb');
              extractColorFromImg(largerArt, rgb => {
                if (rgb) { applySoundtrackColor(rgb); return; }
                _fallbackColor();
              });
              return;
            }
          }
        } catch(e) {}
      }
      _fallbackColor();
    }

    function _fallbackColor() {
      // Fall back to movie poster color
      const posterImg = document.getElementById('movie-detail-poster-img');
      if (!posterImg || !posterImg.src || posterImg.style.display === 'none') {
        applySoundtrackColor(null); return;
      }
      const src = posterImg.src + (posterImg.src.includes('?') ? '&' : '?') + '_cb=' + Date.now();
      extractColorFromImg(src, applySoundtrackColor);
    }

    function applySoundtrackColor(rgb) {
      const sec = document.getElementById('movie-detail-spotify-section');
      const titleEl = sec ? sec.querySelector('.movie-detail-section-title') : null;
      if (!sec) return;
      if (!rgb) {
        sec.style.background = 'transparent';
        sec.style.border = '';
        sec.style.boxShadow = 'none';
        if (titleEl) { titleEl.style.color = ''; titleEl.style.borderBottomColor = ''; }
        if (soundtrackToggle) { soundtrackToggle.style.borderColor = ''; soundtrackToggle.style.background = ''; }
        return;
      }
      const {r,g,b} = rgb;
      // Stronger opacity in light mode so color is visible against white bg
      const isLight = document.body.classList.contains('light-mode');
      const bgA1    = isLight ? 0.22 : 0.20;
      const bgA2    = isLight ? 0.10 : 0.08;
      const borderA = isLight ? 0.50 : 0.35;
      const glowA   = isLight ? 0.10 : 0.22;
      const labelA  = isLight ? 0.85 : 0.90;
      sec.style.background  = `linear-gradient(135deg, rgba(${r},${g},${b},${bgA1}) 0%, rgba(${r},${g},${b},${bgA2}) 100%)`;
      sec.style.border      = `1px solid rgba(${r},${g},${b},${borderA})`;
      sec.style.boxShadow   = `0 4px 28px rgba(${r},${g},${b},${glowA}), inset 0 1px 0 rgba(255,255,255,0.06)`;
      if (titleEl) {
        titleEl.style.color = `rgba(${r},${g},${b},${labelA})`;
        titleEl.style.borderBottomColor = `rgba(${r},${g},${b},${borderA})`;
      }
      if (soundtrackToggle) {
        soundtrackToggle.style.borderColor = `rgba(${r},${g},${b},${borderA})`;
        soundtrackToggle.style.background  = `rgba(${r},${g},${b},0.12)`;
      }
    }

    // Kick off color extraction from album art (async)
    fetchAlbumColorAndApply();

    function renderSoundtrackEmbed() {
      // Icon-only toggle: active = platform brand color background, inactive = ghost
      if (toggleSpotifyBtn && toggleAppleBtn) {
        if (activePlatform === 'spotify') {
          toggleSpotifyBtn.style.background = '#1DB954';
          toggleSpotifyBtn.style.color = '#fff';
          toggleSpotifyBtn.style.boxShadow = '0 1px 6px rgba(29,185,84,.35)';
          toggleAppleBtn.style.background = 'transparent';
          toggleAppleBtn.style.color = 'rgba(245,245,245,.4)';
          toggleAppleBtn.style.boxShadow = 'none';
        } else {
          toggleAppleBtn.style.background = '#FC3C44';
          toggleAppleBtn.style.color = '#fff';
          toggleAppleBtn.style.boxShadow = '0 1px 6px rgba(252,60,68,.35)';
          toggleSpotifyBtn.style.background = 'transparent';
          toggleSpotifyBtn.style.color = 'rgba(245,245,245,.4)';
          toggleSpotifyBtn.style.boxShadow = 'none';
        }
      }

      // Clear embed before re-rendering so switching works cleanly
      spotifyEmbed.innerHTML = '';

      if (activePlatform === 'spotify' && hasSpotify) {
        const url = m.spotify_url.trim();
        const spotifyMatch = url.match(/spotify\.com\/(track|album|playlist|episode)\/([a-zA-Z0-9]+)/);
        if (spotifyMatch) {
          const [, type, sid] = spotifyMatch;
          const embedUrl = `https://open.spotify.com/embed/${type}/${sid}?utm_source=generator`;
          const height = type === 'track' ? '152' : '352';
          spotifyEmbed.innerHTML = `<iframe src="${embedUrl}" width="100%" height="${height}" frameborder="0" allowtransparency="true" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" loading="lazy" style="border-radius:12px;display:block"></iframe>`;
        } else {
          spotifyEmbed.innerHTML = `<a href="${url}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border:1px solid rgba(29,185,84,.3);border-radius:24px;font-size:13px;color:#1DB954;text-decoration:none;transition:border-color .2s">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
            Listen on Spotify →</a>`;
        }
      } else if (activePlatform === 'apple' && hasApple) {
        const url = m.apple_music_url.trim();
        const embedUrl = url.replace('music.apple.com', 'embed.music.apple.com');
        spotifyEmbed.innerHTML = `<iframe src="${embedUrl}" width="100%" height="450" frameborder="0" allow="autoplay *; encrypted-media *; fullscreen *; clipboard-write" loading="lazy" style="border-radius:12px;display:block;overflow:hidden"></iframe>`;
      } else if (!hasSpotify && !hasApple) {
        spotifyEmbed.innerHTML = '';
      }
    }

    renderSoundtrackEmbed();
  } else {
    spotifySec.style.display = 'none';
    spotifyEmbed.innerHTML = '';
    if (soundtrackToggle) soundtrackToggle.style.display = 'none';
    // Reset dynamic color
    spotifySec.style.background = 'transparent';
    spotifySec.style.border = '';
    spotifySec.style.boxShadow = 'none';
    const _stTitle = spotifySec.querySelector('.movie-detail-section-title');
    if (_stTitle) { _stTitle.style.color = ''; _stTitle.style.borderBottomColor = ''; }
  }
  window.scrollTo({top:0,behavior:'smooth'});
  const mslug = (m.title ? m.title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') : '') + '-' + id;
  history.pushState({page:'movie-detail', id}, '', '/films/'+mslug);
  window._currentMovieId = id;
  const filmDesc = m.description
    ? m.description.slice(0, 155)
    : `Watch "${m.title}"${m.release_year ? ' ('+m.release_year+')' : ''} — a film by KIIT Film Society.`;
  updateMetaTags({
    title: m.title,
    description: filmDesc,
    image: `/og/film/${id}`,
    url: '/films/' + mslug,
  });

  // VideoObject schema — helps Google show the film in video rich results
  const filmGenres = Array.isArray(m.genre) ? m.genre : (m.genre ? [m.genre] : []);
  const filmSchema = {
    "@context": "https://schema.org",
    "@type": "Movie",
    "name": m.title,
    "description": filmDesc,
    "image": `https://kiitfilmsociety.in/og/film/${id}`,
    "url": `https://kiitfilmsociety.in/films/${mslug}`,
    "dateCreated": m.release_year ? String(m.release_year) : undefined,
    "director": m.director ? {
      "@type": "Person",
      "name": m.director
    } : undefined,
    "productionCompany": {
      "@type": "Organization",
      "name": "KFS — KIIT Film Society",
      "url": "https://kiitfilmsociety.in"
    },
    "genre": filmGenres,
    "inLanguage": "hi-IN"
  };
  if (m.trailer_url) {
    filmSchema.trailer = {
      "@type": "VideoObject",
      "name": `${m.title} — Trailer`,
      "embedUrl": m.trailer_url,
      "thumbnailUrl": `https://kiitfilmsociety.in/og/film/${id}`,
      "uploadDate": m.release_year ? `${m.release_year}-01-01` : undefined
    };
  }
  // Remove undefined keys before injecting
  injectPageSchema(JSON.parse(JSON.stringify(filmSchema)));
  loadReviews(id);
  loadFilmComments(id);
  resetReviewForm();
}

// ── STAR PICKERS ──
const starRatings = {};
function initStarPickers() {
  ['overall','direction','sound','cinematography','script'].forEach(cat => {
    starRatings[cat] = 0;
    const el = document.getElementById('star-'+cat);
    if (!el) return;
    el.innerHTML = '';
    for (let i = 1; i <= 5; i++) {
      const s = document.createElement('span');
      s.textContent = '★';
      s.dataset.val = i;
      s.addEventListener('mouseover', () => highlightStars(el, i));
      s.addEventListener('mouseout', () => highlightStars(el, starRatings[cat]));
      s.addEventListener('click', () => {
        starRatings[cat] = i;
        highlightStars(el, i);
      });
      el.appendChild(s);
    }
  });
}
function highlightStars(el, val) {
  el.querySelectorAll('span').forEach((s,i) => {
    s.classList.toggle('active', i < val);
  });
}
function resetReviewForm() {
  initStarPickers();
  const nameEl = document.getElementById('review-name');
  const msgEl = document.getElementById('review-submit-msg');
  if (nameEl) nameEl.value = '';
  if (msgEl) msgEl.textContent = '';
}

let currentMovieId = null;
async function loadReviews(movieId) {
  currentMovieId = movieId;
  try {
    const res = await fetch('/api/reviews/'+movieId);
    const reviews = await res.json();
    renderReviews(reviews || []);
  } catch(e) { renderReviews([]); }
}

function renderReviews(reviews) {
  const summaryEl = document.getElementById('review-summary');
  const listEl = document.getElementById('reviews-list');
  const catBarsEl = document.getElementById('review-cat-bars');
  if (!listEl) return;

  if (!reviews.length) {
    summaryEl.style.display = 'none';
    listEl.innerHTML = '<p style="color:var(--grey);font-size:13px;padding:16px 0">No reviews yet. Be the first!<\/p>';
    return;
  }

  // Summary
  const avg = reviews.reduce((s,r)=>s+r.overall,0)/reviews.length;
  document.getElementById('review-avg-score').textContent = avg.toFixed(1);
  document.getElementById('review-count').textContent = reviews.length;
  summaryEl.style.display = 'grid';

  // Category bars
  const cats = ['direction','sound','cinematography','script'];
  const catLabels = {direction:'Direction',sound:'Sound',cinematography:'Cinemato.',script:'Script'};
  catBarsEl.innerHTML = cats.map(c => {
    const vals = reviews.map(r=>r[c]).filter(Boolean);
    const avg = vals.length ? vals.reduce((a,b)=>a+b,0)/vals.length : null;
    return `<div class="review-cat-row">
      <div class="review-cat-name">${catLabels[c]}<\/div>
      <div class="review-cat-bar"><div class="review-cat-fill" style="width:${avg ? avg/5*100 : 0}%"><\/div><\/div>
      <div class="review-cat-val">${avg ? avg.toFixed(1) : '—'}<\/div>
    <\/div>`;
  }).join('');

  // Review cards
  listEl.innerHTML = reviews.map(r => {
    const stars = '★'.repeat(r.overall) + '☆'.repeat(5-r.overall);
    const subs = ['direction','sound','cinematography','script']
      .filter(c => r[c])
      .map(c => `<span class="review-sub-score">${catLabels[c]}: <span>${r[c]}/5<\/span><\/span>`).join('');
    const date = r.created_at ? new Date(r.created_at).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'}) : '';
    return `<div class="review-card">
      <div class="review-card-header">
        <div class="review-card-name">${r.reviewer_name||'Anonymous'}<\/div>
        <div class="review-card-date">${date}<\/div>
      <\/div>
      <div class="review-stars-display">${stars}<\/div>
      ${subs ? `<div class="review-sub-scores">${subs}<\/div>` : ''}
      ${r.review_text ? `<div class="review-card-text">${r.review_text}<\/div>` : ''}
    <\/div>`;
  }).join('');
}

async function submitReview() {
  if (!currentMovieId) return;
  if (!starRatings.overall) {
    document.getElementById('review-submit-msg').textContent = 'Please give an overall star rating.';
    return;
  }
  const body = {
    movie_id: currentMovieId,
    reviewer_name: document.getElementById('review-name').value.trim() || 'Anonymous',
    overall: starRatings.overall,
    direction: starRatings.direction || null,
    sound: starRatings.sound || null,
    cinematography: starRatings.cinematography || null,
    script: starRatings.script || null,
  };
  try {
    const res = await fetch('/api/reviews', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type':'application/json','X-CSRF-Token':_csrfToken||''},
      body: JSON.stringify(body)
    });
    if (res.ok) {
      document.getElementById('review-submit-msg').textContent = 'Thanks for your review!';
      resetReviewForm();
      loadReviews(currentMovieId);
      launchKonfetti();
      // Refresh ratings cache so poster badge updates instantly
      fetch('/api/reviews/all').then(r=>r.ok?r.json():[]).then(allReviews => {
        window._movieRatings = {};
        const grouped = {};
        allReviews.forEach(r => { if (!grouped[r.movie_id]) grouped[r.movie_id]=[]; grouped[r.movie_id].push(r.overall); });
        Object.keys(grouped).forEach(id => {
          const vals = grouped[id].filter(Boolean);
          window._movieRatings[id] = { avg: vals.reduce((a,b)=>a+b,0)/vals.length, count: vals.length };
        });
      }).catch(()=>{});
    } else {
      document.getElementById('review-submit-msg').textContent = 'Error submitting review. Try again.';
    }
  } catch(e) {
    document.getElementById('review-submit-msg').textContent = 'Network error. Try again.';
  }
}

// Init star pickers on page load
initStarPickers();


function renderTestimonials(testimonials) {
  const track = document.getElementById('testimonials-track');
  const inner = document.getElementById('testimonials-inner');
  if (!testimonials || !testimonials.length) {
    inner.innerHTML = `<div class="testimonial-card"><p style="color:var(--grey)">No testimonials yet.<\/p><\/div>`;
    return;
  }
  function cardHTML(t) {
    return `<div class="testimonial-card">
      <p class="testimonial-quote">"${t.quote}"<\/p>
      <div class="testimonial-author">
        ${t.photo ? `<img class="testimonial-avatar" src="${t.photo}" alt="${t.name}">` : `<div class="testimonial-avatar-placeholder"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/div>`}
        <div>
          <div class="testimonial-name">${t.name}<\/div>
          <div class="testimonial-role">${t.role||''} ${t.batch?'· '+t.batch:''}<\/div>
        <\/div>
      <\/div>
    <\/div>`;
  }
  inner.innerHTML = testimonials.map(cardHTML).join('') + testimonials.map(cardHTML).join('');
  let pos=0, autoSpeed=0.8, paused=false, isDragging=false;
  let dragStartX=0, dragStartPos=0, momentum=0;
  function loopW(){ return inner.scrollWidth/2; }
  function wrap(v){ var lw=loopW(); if(lw<=0)return v; if(v>=lw)v-=lw; if(v<0)v+=lw; return v; }
  function frame(){
    if(!isDragging){
      if(!paused) pos+=autoSpeed;
      if(Math.abs(momentum)>0.05){pos+=momentum;momentum*=0.9;}
      pos=wrap(pos);
    }
    inner.style.transform=`translateX(${-pos}px)`;
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  track.addEventListener('mouseenter',()=>paused=true);
  track.addEventListener('mouseleave',()=>{paused=false;momentum=0;});
  track.addEventListener('wheel',e=>{
    e.preventDefault(); paused=true;
    pos=wrap(pos+e.deltaY*0.7+e.deltaX*0.7);
    clearTimeout(track._wt); track._wt=setTimeout(()=>paused=false,900);
  },{passive:false});
  track.addEventListener('mousedown',e=>{isDragging=true;paused=true;dragStartX=e.clientX;dragStartPos=pos;momentum=0;e.preventDefault();});
  window.addEventListener('mousemove',e=>{if(!isDragging)return;var dx=dragStartX-e.clientX;momentum=(pos-(dragStartPos+dx))*0.3;pos=wrap(dragStartPos+dx);});
  window.addEventListener('mouseup',()=>{if(!isDragging)return;isDragging=false;setTimeout(()=>paused=false,700);});
  track.addEventListener('touchstart',e=>{isDragging=true;paused=true;dragStartX=e.touches[0].clientX;dragStartPos=pos;momentum=0;},{passive:true});
  track.addEventListener('touchmove',e=>{if(!isDragging)return;var dx=dragStartX-e.touches[0].clientX;momentum=(pos-(dragStartPos+dx))*0.2;pos=wrap(dragStartPos+dx);},{passive:true});
  track.addEventListener('touchend',()=>{isDragging=false;setTimeout(()=>paused=false,700);});
}

// ── ADMIN ──
async function adminLogin() {
  const username = document.getElementById('admin-username').value.trim();
  const password = document.getElementById('admin-password').value;
  const err = document.getElementById('login-error');
  const totpStep = document.getElementById('totp-step');
  const totpVal = document.getElementById('admin-totp')?.value?.replace(/\s/g,'');
  if (!username || !password) { err.textContent = 'Enter username and password.'; return; }
  const body = { username, password };
  if (totpVal) body.totp_code = totpVal;
  const res = await fetch('/api/admin/login',{
    method:'POST', credentials:'include', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (data.require_totp) {
    // Password OK but 2FA needed — show TOTP input
    if (totpStep) totpStep.style.display = 'block';
    err.textContent = 'Enter your 6-digit authenticator code.';
    document.getElementById('admin-totp')?.focus();
    return;
  }
  if (data.token) {
    adminToken = data.token; // memory only — never localStorage, not XSS-stealable
    currentAdminRole = data.role || 'admin';
    currentAdminName = data.name || username;
    currentAdminPermissions = data.permissions || [];
    // role/name/permissions are non-sensitive — safe in localStorage for UI state
    localStorage.setItem('kfs_role', currentAdminRole);
    localStorage.setItem('kfs_admin_name', currentAdminName);
    localStorage.setItem('kfs_permissions', JSON.stringify(currentAdminPermissions));
    localStorage.setItem('kfs_last_login', new Date().toISOString());
    // Store full admin info for 2FA section
    window._currentAdmin = { totp_enabled: !!data.totp_enabled, role: data.role };
    err.textContent = '';
    if (totpStep) { totpStep.style.display = 'none'; }
    if (document.getElementById('admin-totp')) document.getElementById('admin-totp').value = '';
    // Refresh CSRF token after login
    try { const r = await fetch('/api/csrf-token'); const d = await r.json(); _csrfToken = d.csrf_token; } catch(e) {}
    showAdminPanel();
  } else {
    err.textContent = data.error || 'Invalid credentials.';
  }
}

function adminLogout() {
  // Tell server to revoke current JTI and refresh cookie
  if (adminToken) {
    fetch('/api/admin/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'X-CSRF-Token': _csrfToken || '' }
    }).catch(()=>{});
  }
  adminToken = null;
  currentAdminRole = 'admin';
  currentAdminName = '';
  currentAdminPermissions = [];
  // kfs_token was never in localStorage — only clear UI state keys
  ['kfs_role','kfs_admin_name','kfs_permissions'].forEach(k => localStorage.removeItem(k));
  document.body.classList.remove('kfs-admin-view');
  navigate('home');
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const loading = document.getElementById('dashboard-loading');
  if (loading) loading.style.display = 'block';

  // Greeting
  const hour = new Date().getHours();
  const greet = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  const greetEl = document.getElementById('dashboard-greeting');
  const subEl   = document.getElementById('dashboard-subtitle');
  if (greetEl) greetEl.textContent = greet + (currentAdminName ? ', ' + currentAdminName.split(' ')[0] : '');
  if (subEl)   subEl.textContent   = "Here's what's happening at KFS";

  // Hide cards the sub-admin can't access
  const cardMap = { blogs:'db-stat-blogs', events:'db-stat-events', members:'db-stat-members', movies:'db-stat-films', analytics:'db-stat-traffic', collaborate:'db-stat-collabs' };
  Object.entries(cardMap).forEach(([sec, cardId]) => {
    const el = document.getElementById(cardId);
    if (el) el.style.display = hasPermission(sec) ? '' : 'none';
  });

  const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };

  try {
    const results = await Promise.allSettled([
      hasPermission('blogs')       ? apiFetch('/api/admin/blogs')            : Promise.resolve(null),
      hasPermission('events')      ? apiFetch('/api/events')                 : Promise.resolve(null),
      hasPermission('members')     ? apiFetch('/api/members')                : Promise.resolve(null),
      hasPermission('movies')      ? apiFetch('/api/admin/movies')           : Promise.resolve(null),
      hasPermission('analytics')   ? apiFetch('/api/admin/analytics/traffic?range=7d') : Promise.resolve(null),
      hasPermission('collaborate') ? fetch('/api/collaborate').then(r=>r.json()).catch(()=>null) : Promise.resolve(null),
    ]);
    const [blogsR, eventsR, membersR, filmsR, trafficR, collabsR] = results.map(r => r.status === 'fulfilled' ? r.value : null);

    if (blogsR)   setVal('db-val-blogs',   blogsR.length   ?? '—');
    if (eventsR)  setVal('db-val-events',  eventsR.length  ?? '—');
    if (membersR) setVal('db-val-members', membersR.length ?? '—');
    if (filmsR)   setVal('db-val-films',   filmsR.length   ?? '—');
    if (trafficR) setVal('db-val-traffic', (trafficR.today ?? 0).toLocaleString());
    if (collabsR) {
      const collabCard = document.getElementById('db-stat-collabs');
      if (collabCard && hasPermission('collaborate')) {
        collabCard.style.display = '';
        setVal('db-val-collabs', (Array.isArray(collabsR) ? collabsR.length : 0));
      }
    }
  } catch(e) {
    if (subEl) subEl.textContent = 'Some stats could not be loaded.';
  }
  if (loading) loading.style.display = 'none';
}
window.loadDashboard = loadDashboard;

// ── STYLED CONFIRMATION MODAL (replaces browser confirm()) ────────────────────
// Usage: const ok = await kfsConfirm({ title, msg, okLabel? })
function kfsConfirm({ title='Delete item?', msg='', okLabel='Delete' } = {}) {
  return new Promise(resolve => {
    const modal  = document.getElementById('kfs-confirm-modal');
    const titleEl = document.getElementById('kfs-confirm-title');
    const msgEl  = document.getElementById('kfs-confirm-msg');
    const okBtn  = document.getElementById('kfs-confirm-ok');
    const cancelBtn = document.getElementById('kfs-confirm-cancel');
    if (!modal) { resolve(window.confirm(msg || title)); return; }
    if (titleEl) titleEl.textContent = title;
    if (msgEl)   msgEl.innerHTML     = msg;
    if (okBtn)   okBtn.textContent   = okLabel;
    modal.classList.add('open');
    function cleanup(result) {
      modal.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      resolve(result);
    }
    const onOk     = () => cleanup(true);
    const onCancel = () => cleanup(false);
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
  });
}
window.kfsConfirm = kfsConfirm;

// ── CONFIRM MODAL (member portal actions) ─────────────────────────────────────
// showConfirmModal(msg, onConfirm, onCancel?, okLabel?, cancelLabel?)
// Reuses kfs-confirm-modal DOM with a neutral OK button for non-destructive confirms.
// showConfirmModal(msg, onConfirm, onCancel?, okLabel?, cancelLabel?, okStyle?)
// okStyle: 'danger' for red destructive actions, default is indigo accent
function showConfirmModal(msg, onConfirm, onCancel, okLabel = 'Confirm', cancelLabel = 'Cancel', okStyle = 'accent') {
  return new Promise(resolve => {
    const modal     = document.getElementById('kfs-confirm-modal');
    const titleEl   = document.getElementById('kfs-confirm-title');
    const msgEl     = document.getElementById('kfs-confirm-msg');
    const okBtn     = document.getElementById('kfs-confirm-ok');
    const cancelBtn = document.getElementById('kfs-confirm-cancel');
    const iconEl    = document.getElementById('kfs-confirm-icon');
    if (!modal) {
      const confirmed = window.confirm(msg);
      if (confirmed && onConfirm) onConfirm();
      else if (!confirmed && onCancel) onCancel();
      resolve(confirmed);
      return;
    }
    const isDanger = okStyle === 'danger';
    const btnBg    = isDanger ? '#f85149' : 'var(--accent,#6366f1)';
    const iconBg   = isDanger ? 'rgba(248,81,73,.12)' : 'rgba(99,102,241,.15)';
    const iconClr  = isDanger ? '#f85149' : '#818cf8';
    const iconSvg  = isDanger
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${iconClr}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${iconClr}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

    if (titleEl) titleEl.textContent = '';
    if (msgEl)   msgEl.innerHTML = msg;
    if (okBtn)   { okBtn.textContent = okLabel; okBtn.style.background = btnBg; okBtn.style.color = '#fff'; }
    if (cancelBtn) cancelBtn.textContent = cancelLabel;
    if (iconEl)  { iconEl.style.background = iconBg; iconEl.innerHTML = iconSvg; }
    modal.classList.add('open');
    function cleanup(confirmed) {
      modal.classList.remove('open');
      // Reset to default (indigo/info) state
      if (okBtn)   { okBtn.textContent = 'Confirm'; okBtn.style.background = '#6366f1'; okBtn.style.color = '#fff'; }
      if (cancelBtn) cancelBtn.textContent = 'Cancel';
      if (titleEl)  titleEl.textContent = 'Are you sure?';
      if (iconEl)  {
        iconEl.style.background = 'rgba(99,102,241,.15)';
        iconEl.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
      }
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onNo);
      if (confirmed && onConfirm) onConfirm();
      else if (!confirmed && onCancel) onCancel();
      resolve(confirmed);
    }
    const onOk = () => cleanup(true);
    const onNo = () => cleanup(false);
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onNo);
  });
}
window.showConfirmModal = showConfirmModal;

// ── UNSAVED CHANGES GUARD ─────────────────────────────────────────────────────
// Usage: const discard = await kfsUnsavedGuard()
function kfsUnsavedGuard() {
  return new Promise(resolve => {
    const modal   = document.getElementById('kfs-unsaved-modal');
    const stay    = document.getElementById('kfs-unsaved-stay');
    const discard = document.getElementById('kfs-unsaved-discard');
    if (!modal) { resolve(true); return; }
    modal.classList.add('open');
    function cleanup(result) {
      modal.classList.remove('open');
      stay.removeEventListener('click', onStay);
      discard.removeEventListener('click', onDiscard);
      resolve(result);
    }
    const onStay    = () => cleanup(false);
    const onDiscard = () => cleanup(true);
    stay.addEventListener('click', onStay);
    discard.addEventListener('click', onDiscard);
  });
}
window.kfsUnsavedGuard = kfsUnsavedGuard;

// ── INLINE EDIT HELPER ────────────────────────────────────────────────────────
// makeInlineEditable(cell, { onSave(newVal) })
// Call from the row-render helpers — just wrap the display cell.
function makeInlineEditable(cell, { onSave, type='text', validate } = {}) {
  cell.classList.add('inline-editable');
  cell.title = 'Click to edit';
  cell.addEventListener('click', function startEdit(e) {
    if (cell.querySelector('.inline-edit-input')) return; // already editing
    const originalText = cell.textContent.trim();
    cell.removeEventListener('click', startEdit);
    const input = document.createElement('input');
    input.className = 'inline-edit-input';
    input.type  = type;
    input.value = originalText;
    cell.textContent = '';
    cell.appendChild(input);
    input.focus();
    input.select();
    async function commit() {
      const newVal = input.value.trim();
      if (newVal === originalText) { cell.textContent = originalText; cell.addEventListener('click', startEdit); return; }
      if (validate && !validate(newVal)) { input.classList.add('error'); input.focus(); return; }
      cell.textContent = newVal + ' …';
      try {
        await onSave(newVal);
        cell.textContent = newVal;
      } catch(err) {
        cell.textContent = originalText;
        console.error('[inline-edit] save failed', err);
      }
      cell.addEventListener('click', startEdit);
    }
    input.addEventListener('blur',  commit);
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); commit(); }
      if (e.key === 'Escape') { cell.textContent = originalText; cell.addEventListener('click', startEdit); }
    });
  });
}
window.makeInlineEditable = makeInlineEditable;

// Attaches inline-edit to the relevant cells in a rendered tbody
function _attachInlineEdits(section, tbody) {
  if (!tbody) return;
  if (section === 'blogs') {
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      const id = row.dataset.id;
      // Col index 2 = title (0=checkbox, 1=cover, 2=title)
      const titleCell = row.cells[2];
      if (titleCell) {
        makeInlineEditable(titleCell, {
          onSave: async (val) => {
            const fd = new FormData();
            fd.append('title', val);
            const res = await fetch('/api/admin/blogs/'+id, { method:'PUT', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd });
            if (!res.ok) throw new Error('save failed');
            window._allBlogsCache = null;
          }
        });
      }
    });
  }
  if (section === 'events') {
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      const id = row.dataset.id;
      // Col 0=title, col 1=date, col 3=location
      const titleCell = row.cells[0];
      const dateCell  = row.cells[1];
      if (titleCell) {
        makeInlineEditable(titleCell, {
          onSave: async (val) => {
            const fd = new FormData(); fd.append('title', val);
            const res = await fetch('/api/admin/events/'+id, { method:'PUT', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd });
            if (!res.ok) throw new Error('save failed');
          }
        });
      }
      if (dateCell) {
        makeInlineEditable(dateCell, {
          type: 'date',
          onSave: async (val) => {
            const fd = new FormData(); fd.append('event_date', val);
            const res = await fetch('/api/admin/events/'+id, { method:'PUT', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd });
            if (!res.ok) throw new Error('save failed');
          }
        });
      }
    });
  }
}

function showAdminPanel() {
  currentAdminRole = localStorage.getItem('kfs_role') || 'admin';
  currentAdminName = localStorage.getItem('kfs_admin_name') || '';
  try { currentAdminPermissions = JSON.parse(localStorage.getItem('kfs_permissions') || '[]'); } catch { currentAdminPermissions = []; }
  document.body.classList.add('kfs-admin-view');

  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('admin-login').classList.remove('active');
  document.getElementById('admin-panel').classList.add('active');

  // Update URL to /admin so the address bar reflects the admin panel
  if (window.location.pathname !== '/admin') {
    history.pushState({ page: 'admin' }, '', '/admin');
  }

  const nameEl = document.getElementById('sidebar-admin-name');
  const roleEl = document.getElementById('sidebar-admin-role');
  const lastEl = document.getElementById('sidebar-last-login');
  if (nameEl) nameEl.textContent = currentAdminName || 'Admin';
  if (roleEl) roleEl.textContent = currentAdminRole === 'master' ? 'Master' : 'Admin';
  if (lastEl) {
    const raw = localStorage.getItem('kfs_last_login');
    if (raw) {
      try {
        const d = new Date(raw);
        const fmt = d.toLocaleString('en-IN', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit', hour12:true });
        lastEl.textContent = 'Last login: ' + fmt;
      } catch { lastEl.textContent = ''; }
    } else {
      lastEl.textContent = '';
    }
  }

  // Show/hide each sidebar item based on permissions
  document.querySelectorAll('.admin-sidebar-item[data-section]').forEach(el => {
    const sec = el.dataset.section;
    const masterOnly = ['admins','activity'].includes(sec);
    const alwaysVisible = ['change-password','two-factor'].includes(sec);
    if (masterOnly) {
      el.style.display = currentAdminRole === 'master' ? 'flex' : 'none';
    } else if (alwaysVisible) {
      el.style.display = 'flex'; // always show, regardless of permissions
    } else {
      el.style.display = hasPermission(sec) ? 'flex' : 'none';
    }
  });

  // Navigate to dashboard (if permitted) or first allowed section
  const firstAllowed = hasPermission('dashboard') ? 'dashboard' : (ALL_SECTIONS.filter(s => s !== 'change-password').find(s => hasPermission(s)) || 'blogs');
  loadAdminData(firstAllowed);
  document.querySelectorAll('.admin-section').forEach(s=>s.classList.remove('active'));
  const secEl = document.getElementById('section-'+firstAllowed);
  if (secEl) secEl.classList.add('active');
  document.querySelectorAll('.admin-sidebar-item').forEach(i=>i.classList.remove('active'));
  const sideEl = document.querySelector(`[data-section="${firstAllowed}"]`);
  if (sideEl) sideEl.classList.add('active');
}

// ══════════════════════════════════════════════════════════
// GLOBAL ADMIN SEARCH
// ══════════════════════════════════════════════════════════
let _searchDebounce = null;
let _searchActiveIndex = -1;
let _searchFlatItems = [];

const ADMIN_SEARCH_ICONS = {
  section: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
  member: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  event: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>',
  blog: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
  movie: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/></svg>',
  donor: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>',
  admin: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
};

const ADMIN_SEARCH_TYPE_LABELS = {
  section: 'Go to',
  member: 'Members',
  event: 'Events',
  blog: 'Blog Posts',
  movie: 'Films',
  donor: 'Donors',
  admin: 'Admin Accounts',
};

function openAdminSearch() {
  const modal = document.getElementById('admin-search-modal');
  modal.classList.add('open');
  const input = document.getElementById('admin-search-input');
  input.value = '';
  document.getElementById('admin-search-results').innerHTML = `
    <div style="padding:32px 16px;text-align:center;color:var(--grey);font-size:13px">Start typing to search across the admin panel</div>`;
  _searchActiveIndex = -1;
  _searchFlatItems = [];
  setTimeout(() => input.focus(), 50);
}

function closeAdminSearch() {
  document.getElementById('admin-search-modal').classList.remove('open');
}

function _adminSearchInputHandler(e) {
  const q = e.target.value.trim();
  clearTimeout(_searchDebounce);
  if (q.length < 2) {
    document.getElementById('admin-search-results').innerHTML = `
      <div style="padding:32px 16px;text-align:center;color:var(--grey);font-size:13px">Start typing to search across the admin panel</div>`;
    _searchFlatItems = [];
    _searchActiveIndex = -1;
    return;
  }
  _searchDebounce = setTimeout(() => _runAdminSearch(q), 200);
}

async function _runAdminSearch(q) {
  const resultsEl = document.getElementById('admin-search-results');
  resultsEl.innerHTML = `<div style="padding:32px 16px;text-align:center;color:var(--grey);font-size:13px">Searching&hellip;</div>`;
  let data;
  try {
    data = await apiFetch('/api/admin/search?q=' + encodeURIComponent(q));
  } catch (e) {
    resultsEl.innerHTML = `<div style="padding:32px 16px;text-align:center;color:var(--grey);font-size:13px">Search failed. Try again.</div>`;
    return;
  }
  if (!data || (!data.sections.length && !data.results.length)) {
    resultsEl.innerHTML = `<div style="padding:32px 16px;text-align:center;color:var(--grey);font-size:13px">No matches for "${q.replace(/</g,'&lt;')}"</div>`;
    _searchFlatItems = [];
    _searchActiveIndex = -1;
    return;
  }

  const groups = {};
  data.sections.forEach(s => { (groups['section'] = groups['section'] || []).push(s); });
  data.results.forEach(r => { (groups[r.type] = groups[r.type] || []).push(r); });

  const order = ['section', 'member', 'event', 'blog', 'movie', 'donor', 'admin'];
  _searchFlatItems = [];
  let html = '';
  order.forEach(type => {
    const items = groups[type];
    if (!items || !items.length) return;
    html += `<div style="font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#555;padding:10px 12px 4px">${ADMIN_SEARCH_TYPE_LABELS[type]}</div>`;
    items.forEach(item => {
      const idx = _searchFlatItems.length;
      _searchFlatItems.push(item);
      const icon = item.image
        ? `<img src="${item.image}" alt="" style="width:28px;height:28px;border-radius:6px;object-fit:cover;flex-shrink:0">`
        : `<div style="width:28px;height:28px;border-radius:6px;background:rgba(255,255,255,.05);display:flex;align-items:center;justify-content:center;color:var(--grey);flex-shrink:0">${ADMIN_SEARCH_ICONS[item.type] || ADMIN_SEARCH_ICONS.section}</div>`;
      const title = (item.title || item.label || '').toString();
      const subtitle = item.subtitle ? `<div style="font-size:11.5px;color:var(--grey);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${subtitle_escape(item.subtitle)}</div>` : '';
      html += `<div class="admin-search-row" data-idx="${idx}" onclick="_adminSearchSelect(${idx})" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;cursor:pointer;transition:background .1s">
        ${icon}
        <div style="flex:1;min-width:0">
          <div style="font-size:13.5px;font-weight:500;color:var(--white);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${subtitle_escape(title)}</div>
          ${subtitle}
        </div>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#555;flex-shrink:0"><polyline points="9 18 15 12 9 6"/></svg>
      </div>`;
    });
  });

  resultsEl.innerHTML = html;
  _searchActiveIndex = -1;
}

function subtitle_escape(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function _adminSearchKeyHandler(e) {
  if (e.key === 'Escape') { closeAdminSearch(); return; }
  if (!_searchFlatItems.length) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _searchActiveIndex = Math.min(_searchActiveIndex + 1, _searchFlatItems.length - 1);
    _highlightSearchRow();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _searchActiveIndex = Math.max(_searchActiveIndex - 1, 0);
    _highlightSearchRow();
  } else if (e.key === 'Enter') {
    e.preventDefault();
    if (_searchActiveIndex >= 0) _adminSearchSelect(_searchActiveIndex);
    else if (_searchFlatItems.length) _adminSearchSelect(0);
  }
}

function _highlightSearchRow() {
  document.querySelectorAll('.admin-search-row').forEach(el => {
    const isActive = Number(el.dataset.idx) === _searchActiveIndex;
    el.style.background = isActive ? 'rgba(255,255,255,.06)' : '';
    if (isActive) el.scrollIntoView({ block: 'nearest' });
  });
}

function _adminSearchSelect(idx) {
  const item = _searchFlatItems[idx];
  if (!item) return;
  closeAdminSearch();
  if (item.type === 'section') {
    showAdminSection(item.id);
    return;
  }
  goToAdminRecord(item.type, item.id);
}

// Navigates to the right section and scrolls/highlights the matching row.
const ADMIN_RECORD_MAP = {
  member: { section: 'members', tbody: 'admin-members-tbody' },
  event:  { section: 'events',  tbody: 'admin-events-tbody' },
  blog:   { section: 'blogs',   tbody: 'admin-blogs-tbody' },
  movie:  { section: 'movies',  tbody: 'admin-movies-tbody' },
  donor:  { section: 'payment-analytics', tbody: null },
  admin:  { section: 'admins',  tbody: 'admins-tbody' },
};

function goToAdminRecord(type, id) {
  const map = ADMIN_RECORD_MAP[type];
  if (!map) return;
  showAdminSection(map.section);
  if (!map.tbody) return;
  setTimeout(() => {
    const row = document.querySelector(`#${map.tbody} tr[data-id="${id}"]`);
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      row.style.outline = '2px solid #4ade80';
      row.style.outlineOffset = '-1px';
      setTimeout(() => { row.style.outline = ''; }, 2000);
    }
  }, 400);
}

document.addEventListener('keydown', (e) => {
  const isK = e.key === 'k' || e.key === 'K';
  if ((e.metaKey || e.ctrlKey) && isK) {
    e.preventDefault();
    const modal = document.getElementById('admin-search-modal');
    if (modal) {
      if (modal.classList.contains('open')) closeAdminSearch();
      else openAdminSearch();
    }
  }
});

function showAdminSection(name) {
  document.querySelectorAll('.admin-section').forEach(s=>s.classList.remove('active'));
  document.getElementById('section-'+name).classList.add('active');
  document.querySelectorAll('.admin-sidebar-item').forEach(i=>i.classList.remove('active'));
  document.querySelector(`[data-section="${name}"]`)?.classList.add('active');
  loadAdminData(name);
}

async function loadAdminData(name) {
  if (name==='themes') { loadThemes(); return; }
  if (name==='scanner') { loadScannerSection(); return; }
  if (name==='two-factor') { tfa_initSection(); return; }
  if (name==='dashboard') { loadDashboard(); return; }
  if (name==='blogs') {
    const [blogs, analytics] = await Promise.all([
      apiFetch('/api/admin/blogs'),
      apiFetch('/api/admin/blogs/analytics'),
    ]);

    // ── Populate analytics strip ──
    if (analytics) {
      const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
      el('stat-total-views',   analytics.total_views ?? 0);
      el('stat-published',     analytics.published_count ?? 0);
      el('stat-drafts',        analytics.draft_count ?? 0);
      el('stat-top-post',      analytics.top_post ? analytics.top_post.title : '—');
      el('stat-top-post-views', analytics.top_post ? `${analytics.top_post.view_count || 0} views` : '');
    }

    const tbody = document.getElementById('admin-blogs-tbody');
    if (blogs === null) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:#e74c3c">Failed to load — check the error bar above.<\/td><\/tr>`; return; }
    if (!blogs.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No posts yet. Create your first post!<\/td><\/tr>`; return; }

    // Build a view_count map from analytics (more up-to-date, sorted by views)
    const viewMap = {};
    if (analytics && analytics.blogs) analytics.blogs.forEach(b => { viewMap[b.id] = b.view_count || 0; });

    tbody.innerHTML = blogs.map(b=>{ const bJson=JSON.stringify(b).replace(/"/g,'&quot;'); return `<tr data-id="${b.id}">
      <td><input type="checkbox" class="bulk-cb" data-id="${b.id}" onchange="updateBulkBar('blogs')"><\/td>
      <td>${b.cover_image?`<img src="${b.cover_image}" alt="">`:'—'}<\/td>
      <td style="font-weight:500">${b.title}<\/td>
      <td><span class="tag ${b.published?'upcoming':''}">${b.published?'Published':'Draft'}<\/span><\/td>
      <td style="color:var(--grey);font-variant-numeric:tabular-nums">${(viewMap[b.id] ?? b.view_count ?? 0).toLocaleString()}<\/td>
      <td style="color:var(--grey)">${b.created_at?new Date(b.created_at).toLocaleDateString():''}<\/td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editBlog(${bJson})">Edit<\/button>
        <button class="btn-sm" onclick="toggleBlogPublished('${b.id}',${b.published})" title="${b.published?'Unpublish':'Publish'}" style="${b.published?'background:rgba(245,158,11,.12);color:#f59e0b;border-color:rgba(245,158,11,.25)':'background:rgba(34,197,94,.1);color:#22c55e;border-color:rgba(34,197,94,.25)'}">${b.published?'Unpublish':'Publish'}<\/button>
        <button class="btn-sm danger" onclick="deleteBlog('${b.id}')">Delete<\/button>
      <\/div><\/td>
    <\/tr>`; }).join('');
    _attachInlineEdits('blogs', tbody);
  }
  else if (name==='events') {
    loadEventsWithRegs();
  }
  else if (name==='members') {
    const members = await apiFetch('/api/admin/members');
    const tbody = document.getElementById('admin-members-tbody');
    // Reset search + filters
    const searchEl = document.getElementById('member-admin-search');
    if (searchEl) searchEl.value = '';
    const clearBtn = document.getElementById('member-search-clear-btn');
    if (clearBtn) clearBtn.classList.remove('visible');
    ['mf-batch','mf-role','mf-status','mf-portal'].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
      if (el) el.classList.remove('active');
    });
    const resetBtn = document.getElementById('mf-reset-btn');
    if (resetBtn) resetBtn.classList.remove('visible');
    if (!members || !members.length) { tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--grey)">No members yet.<\/td><\/tr>`; return; }
    // Cache for client-side filtering
    window._allAdminMembers = members;
    // Populate batch dropdown with unique non-empty batches
    const batchSel = document.getElementById('mf-batch');
    if (batchSel) {
      const batches = [...new Set(members.map(m => m.batch).filter(Boolean))].sort();
      batchSel.innerHTML = `<option value="">All Batches<\/option>` + batches.map(b => `<option value="${b}">${b}<\/option>`).join('');
    }
    renderAdminMembersTable(members);
  }
  else if (name==='testimonials') {
    const testimonials = await apiFetch('/api/testimonials');
    const tbody = document.getElementById('admin-testimonials-tbody');
    if (!testimonials || !testimonials.length) { tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--grey)">No testimonials yet.<\/td><\/tr>`; return; }
    tbody.innerHTML = testimonials.map(t=>{ const tJson=JSON.stringify(t).replace(/"/g,'&quot;'); return `<tr>
      <td>${t.photo?`<img src="${t.photo}" alt="" style="border-radius:50%">`:svgPerson(16)}<\/td>
      <td style="font-weight:500">${t.name}<\/td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--grey)">"${t.quote}"<\/td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editTestimonial(${tJson})">Edit<\/button>
        <button class="btn-sm danger" onclick="deleteTestimonial('${t.id}')">Delete<\/button>
      <\/div><\/td>
    <\/tr>`; }).join('');
  }
  else if (name==='achievements') {
    const achievements = await apiFetch('/api/achievements');
    const tbody = document.getElementById('admin-achievements-tbody');
    if (!achievements || !achievements.length) { tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--grey)">No achievements yet.<\/td><\/tr>`; return; }
    tbody.innerHTML = achievements.map(a=>{ const aJson=JSON.stringify(a).replace(/"/g,'&quot;'); return `<tr>
      
      <td style="font-weight:500">${a.title}<\/td>
      <td style="color:var(--grey)">${a.year||'—'}<\/td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editAchievement(${aJson})">Edit<\/button>
        <button class="btn-sm danger" onclick="deleteAchievement('${a.id}')">Delete<\/button>
      <\/div><\/td>
    <\/tr>`; }).join('');
  }
  else if (name==='movies') {
    const movies = await apiFetch('/api/movies');
    const tbody = document.getElementById('admin-movies-tbody');
    if (movies === null) { tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:#e74c3c">Failed to load — check the error bar above.<\/td><\/tr>`; return; }
    if (!movies.length) { tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">No films yet.<\/td><\/tr>`; return; }
    tbody.innerHTML = movies.map(m=>{ const mJson=JSON.stringify(m).replace(/"/g,'&quot;'); return `<tr data-id="${m.id}">
      <td><input type="checkbox" class="bulk-cb" data-id="${m.id}" onchange="updateBulkBar('movies')"><\/td>
      <td>${m.poster_image?`<img src="${m.poster_image}" alt="" style="aspect-ratio:2/3;width:36px;object-fit:cover">`:svgFilm(18)}<\/td>
      <td style="font-weight:500">${m.title}<\/td>
      <td style="color:var(--grey)">${m.release_year||'—'}<\/td>
      <td style="color:var(--grey)">${m.director ? splitCrew(m.director).map(p=>p.split('||')[0].trim()).join(', ') : '—'}<\/td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editMovie(${mJson})">Edit<\/button>
        <button class="btn-sm danger" onclick="deleteMovie('${m.id}')">Delete<\/button>
      <\/div><\/td>
    <\/tr>`; }).join('');
  }
  else if (name==='chitra-vichitra') {
    loadAdminCV();
  }
  else if (name==='analytics') {
    loadTrafficAnalytics(currentAnalyticsRange);
  }
  else if (name==='review-analytics') {
    loadReviewAnalytics();
  }
  else if (name==='reg-analytics') {
    loadRegAnalytics();
  }
  else if (name==='payment-analytics') {
    loadPaymentAnalytics();
  }
  else if (name==='notifications') {
    renderNotifTable();
  }
  else if (name==='easter-eggs') {
    const settings = await apiFetch('/api/settings');
    if (settings) {
      if (settings.easter_egg_img) {
        document.getElementById('set-egg-img-url').value = settings.easter_egg_img;
        document.getElementById('egg-img-thumb').src = settings.easter_egg_img;
        document.getElementById('egg-img-preview').style.display = 'block';
        document.getElementById('egg-img-clear-btn').style.display = 'inline-flex';
        document.getElementById('egg-img-filename').textContent = 'Current image';
        window._easterEggImg = settings.easter_egg_img;
      }
      document.getElementById('set-egg-shorts-heading').value = settings.easter_egg_shorts_heading || '';
      document.getElementById('set-egg-shorts-sub').value = settings.easter_egg_shorts_sub || '';
      document.getElementById('set-egg-noshorts-fallback').value = settings.easter_egg_noshorts_fallback || '';
      loadCustomEggsUI();
    }
  }
  else if (name==='settings') {
    const settings = await apiFetch('/api/settings');
    if (settings) {
      document.getElementById('set-tagline').value = settings.site_tagline||'';
      document.getElementById('set-about').value = settings.about_text||'';
      if (settings.team_photo) {
        document.getElementById('set-team-photo-url').value = settings.team_photo;
        document.getElementById('team-photo-img').src = settings.team_photo;
        document.getElementById('team-photo-preview').style.display = 'block';
        document.getElementById('team-photo-clear-btn').style.display = 'inline-flex';
        document.getElementById('team-photo-filename').textContent = 'Current photo';
      }
      document.getElementById('set-stat-members').value = settings.stat_members||'';
      document.getElementById('set-stat-events').value = settings.stat_events||'';
      document.getElementById('set-stat-films').value = settings.stat_films||'';
      document.getElementById('set-stat-years').value = settings.stat_years||'';
      document.getElementById('set-spotlight-name').value = settings.spotlight_name||'';
      document.getElementById('set-spotlight-role').value = settings.spotlight_role||'';
      document.getElementById('set-spotlight-quote').value = settings.spotlight_quote||'';
      document.getElementById('set-spotlight-photo').value = settings.spotlight_photo||'';
      document.getElementById('set-instagram').value = settings.instagram||'';
      document.getElementById('set-youtube').value = settings.youtube||'';
      document.getElementById('set-email').value = settings.email||'';
      // Email confirmation
      if (settings.brevo_api_key) document.getElementById('set-brevo-api-key').placeholder = '(saved — enter new to change)';
      document.getElementById('set-smtp-from-name').value = settings.smtp_from_name || '';
      document.getElementById('set-email-body').value     = settings.email_confirmation_body || '';
      updateEmailPreview();
      // Load custom tags
      loadTagsUI(settings);
    }
  }
  else if (name==='admins') {
    if (currentAdminRole !== 'master') return;
    const admins = await apiFetch('/api/master/admins');
    const tbody = document.getElementById('admins-tbody');
    if (!admins || !admins.length) { tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--grey)">No admins found.<\/td><\/tr>`; return; }
    const SECTION_LABELS = {'blogs':'Blogs','events':'Events','members':'Members','movies':'Films','chitra-vichitra':'CV','testimonials':'Testimonials','achievements':'Achievements','settings':'Settings','analytics':'Analytics','review-analytics':'Rev. Analytics','wrapped':'Wrapped','collaborate':'Collaborate','easter-eggs':'Easter Eggs'};
    window._adminPermsMap = {};
    admins.forEach(a => { window._adminPermsMap[a.id] = Array.isArray(a.permissions) ? a.permissions : []; });
    tbody.innerHTML = admins.map(a => {
      const perms = window._adminPermsMap[a.id];
      const isFullAccess = perms.length === 0;
      const permsDisplay = a.role === 'master'
        ? '<span class="perm-badge master-badge">All Sections<\/span>'
        : isFullAccess
          ? '<span class="perm-badge full-badge">Full Access<\/span>'
          : perms.map(p => `<span class="perm-badge">${SECTION_LABELS[p]||p}<\/span>`).join('');
      const twoFaBadge = a.totp_enabled
        ? `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.04em;background:rgba(80,200,120,.1);border:1px solid rgba(80,200,120,.25);color:#50c878"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"\/><\/svg>On<\/span>`
        : `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.04em;background:rgba(245,245,245,.05);border:1px solid var(--border);color:var(--grey)">Off<\/span>`;
      // 2FA deadline cell — only for non-master admins who haven't enabled 2FA
      let deadlineCell = '<span style="color:var(--grey);font-size:12px">—<\/span>';
      if (a.role !== 'master' && !a.totp_enabled && a.created_at) {
        const deadline = new Date(new Date(a.created_at).getTime() + 48 * 60 * 60 * 1000);
        const msLeft   = deadline - Date.now();
        if (msLeft <= 0) {
          deadlineCell = `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(255,60,60,.12);border:1px solid rgba(255,60,60,.3);color:#ff6060">Overdue<\/span>`;
        } else {
          const hLeft = Math.floor(msLeft / 3600000);
          const mLeft = Math.floor((msLeft % 3600000) / 60000);
          const urgent = msLeft < 6 * 3600000; // less than 6h
          const color  = urgent ? '#f59e0b' : 'var(--grey)';
          const bg     = urgent ? 'rgba(245,158,11,.1)'  : 'rgba(245,245,245,.05)';
          const border = urgent ? 'rgba(245,158,11,.3)'  : 'var(--border)';
          deadlineCell = `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:${bg};border:1px solid ${border};color:${color};white-space:nowrap">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"\/><polyline points="12 6 12 12 16 14"\/><\/svg>
            ${hLeft}h ${mLeft}m left<\/span>`;
        }
      } else if (a.role !== 'master' && a.totp_enabled) {
        deadlineCell = `<span style="color:#50c878;font-size:12px;font-weight:600">Secured<\/span>`;
      }
      const twoFaDisableBtn = (a.role !== 'master' && a.totp_enabled)
        ? `<button class="admin-action-btn" onclick="masterDisable2FA('${a.id}','${a.name.replace(/'/g,"\\'")}')" style="color:#ff8080;border-color:rgba(255,80,80,.2)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"\/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"\/><\/svg> Disable 2FA<\/button>`
        : '';
      const actions = a.role === 'master'
        ? `<span style="color:var(--grey);font-size:12px">Protected<\/span>`
        : `<button class="admin-action-btn perm-btn" onclick="openEditPermsModal('${a.id}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"\/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"\/><\/svg> Permissions<\/button>${twoFaDisableBtn}<button class="admin-action-btn" onclick="openResetPasswordModal('${a.id}','${a.name.replace(/'/g,"\\'")}')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"\/><path d="M7 11V7a5 5 0 0 1 10 0v4"\/><\/svg> Reset PW<\/button><button class="admin-action-btn del-btn" onclick="deleteAdmin('${a.id}','${a.name.replace(/'/g,"\\'")}')">Remove<\/button>`;
      return `<tr>
        <td style="font-weight:500">${a.name}<\/td>
        <td style="color:var(--grey);font-family:monospace;font-size:13px">${a.username}<\/td>
        <td><span class="tag ${a.role==='master'?'upcoming':''}">${a.role==='master'?'Master':'Admin'}<\/span><\/td>
        <td style="max-width:220px">${permsDisplay}<\/td>
        <td>${twoFaBadge}<\/td>
        <td>${deadlineCell}<\/td>
        <td style="color:var(--grey);font-size:12px">${a.created_at ? new Date(a.created_at).toLocaleDateString() : '—'}<\/td>
        <td>${actions}<\/td>
      <\/tr>`;
    }).join('');
  }
  else if (name==='activity') {
    if (currentAdminRole !== 'master') return;
    const logs = await apiFetch('/api/master/activity');
    const tbody = document.getElementById('activity-tbody');
    if (!logs || !logs.length) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No activity yet.<\/td><\/tr>`; return; }
    const actionColors = { create:'#22c55e', update:'#f59e0b', delete:'#ef4444' };
    const UNDOABLE = { member:1, event:1, blog:1, movie:1 };
    tbody.innerHTML = logs.map(l => {
      let undoCell = '<span style="color:var(--grey);font-size:12px">—<\/span>';
      if (l.action === 'delete' && UNDOABLE[l.entity] && l.entity_id) {
        const createdMs = l.created_at ? new Date(l.created_at).getTime() : 0;
        const ageMs = Date.now() - createdMs;
        const remainingMs = (30*60*1000) - ageMs;
        if (l.undone_at) {
          undoCell = `<span style="color:var(--grey);font-size:12px">Restored<\/span>`;
        } else if (remainingMs > 0) {
          const mins = Math.max(1, Math.ceil(remainingMs / 60000));
          undoCell = `<button class="admin-action-btn" onclick="undoActivity('${l.id}')">&#8617; Undo (${mins} min left)<\/button>`;
        } else {
          undoCell = `<span style="color:var(--grey);font-size:12px">Expired<\/span>`;
        }
      }
      return `<tr>
      <td style="font-weight:500">${l.admin_name||'—'}<\/td>
      <td><span style="color:${actionColors[l.action]||'#888'};font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em">${l.action}<\/span><\/td>
      <td style="color:var(--grey);text-transform:capitalize">${l.entity||'—'}<\/td>
      <td style="color:var(--white)">${l.entity_name||'—'}<\/td>
      <td style="color:var(--grey);font-size:12px">${l.created_at ? new Date(l.created_at).toLocaleString() : '—'}<\/td>
      <td>${undoCell}<\/td>
    <\/tr>`;
    }).join('');
  }
  else if (name==='wrapped') { loadWrappedAdminSection(); }
  else if (name==='collaborate') { loadAdminCollaborate(); }
  else if (name==='comments') { loadAdminComments(); }
  else if (name==='broadcast') { loadBroadcastHistory(); previewBroadcastRecipients(); }
  else if (name==='member-portal') { loadMemberAccounts(); }
  else if (name==='member-profile-changes') { loadMemberProfileChanges('pending'); }
  else if (name==='member-movie-submissions') { loadMemberMovieSubmissions('pending'); }
  else if (name==='work-edit-requests') { loadWorkEditRequests('pending'); }
}

function openBlogModal(blog=null) {
  window._blogModalDirty = false;
  document.getElementById('blog-modal').classList.add('open');
  // Mark dirty when user edits any field
  setTimeout(() => {
    const modal = document.getElementById('blog-modal');
    if (modal && !modal._dirtyListenerAdded) {
      modal._dirtyListenerAdded = true;
      modal.addEventListener('input', () => { window._blogModalDirty = true; });
      modal.addEventListener('change', () => { window._blogModalDirty = true; });
    }
  }, 50);
  document.getElementById('blog-modal-title').textContent = blog ? 'Edit Post' : 'New Blog Post';
  document.getElementById('blog-edit-id').value = blog?.id||'';
  document.getElementById('blog-title').value = blog?.title||'';
  document.getElementById('blog-excerpt').value = blog?.excerpt||'';
  document.getElementById('blog-editor-content').innerHTML = blog?.content||'';
  document.getElementById('blog-published').value = blog?.published ? 'true':'false';
  document.getElementById('blog-cover').value='';
  // Init author picker (multi-select member picker — supports multiple authors)
  if (!window._blogAuthorPicker) {
    window._blogAuthorPicker = new MemberPicker('blog-author-picker', true);
  } else {
    window._blogAuthorPicker.selected = [];
    window._blogAuthorPicker._renderTags();
  }
  if (blog?.author) window._blogAuthorPicker.setValue(blog.author);
  // Clear inline new-tag field
  const inlineEl = document.getElementById('blog-new-tag-inline');
  if (inlineEl) inlineEl.value = '';
  // Populate sections (tags only — id + label)
  let secs = [];
  try { secs = blog?.sections ? JSON.parse(blog.sections) : []; } catch(e){}
  window._blogSections = secs.map(s=>({id:s.id, label:s.label}));
  renderBlogSectionsList();
  // Populate tag dropdown from custom tags
  _populateBlogTagDropdown();
}
function editBlog(blog) { openBlogModal(blog); }
async function closeBlogModal() {
  if (window._blogModalDirty) {
    const discard = await kfsUnsavedGuard();
    if (!discard) return;
  }
  window._blogModalDirty = false;
  document.getElementById('blog-modal').classList.remove('open');
}

function _populateBlogTagDropdown() {
  const sel = document.getElementById('blog-section-type');
  if (!sel) return;
  const tags = window._customBlogTags || [];
  sel.innerHTML = '<option value="">— Select a tag —<\/option>'
    + tags.map(t => `<option value="${t.label}">${t.label}<\/option>`).join('');
}

function renderBlogSectionsList() {
  const wrap = document.getElementById('blog-sections-list');
  if (!wrap) return;
  const secs = window._blogSections || [];
  if (!secs.length) {
    wrap.innerHTML = '<p style="font-size:12px;color:var(--grey);margin:0">No tags added yet.</p>';
    return;
  }
  wrap.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px">`
    + secs.map((s,i) => `
      <span style="display:inline-flex;align-items:center;gap:6px;background:var(--card);
        border:1px solid var(--border);border-radius:20px;padding:5px 12px;font-size:12px;font-weight:600;
        letter-spacing:.05em">
        ${s.label}
        <button onclick="removeBlogSection(${i})" style="background:none;border:none;color:var(--grey);
          cursor:pointer;font-size:14px;line-height:1;padding:0;display:flex;align-items:center"
          title="Remove">×<\/button>
      <\/span>`).join('')
    + `<\/div>`;
}

function addBlogSection() {
  const sel = document.getElementById('blog-section-type');
  if (!sel || !sel.value) return;
  const label = sel.value;
  const id = label.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  if (!window._blogSections) window._blogSections = [];
  if (window._blogSections.find(s=>s.id===id)) { sel.value=''; return; }
  window._blogSections.push({id, label});
  renderBlogSectionsList();
  sel.value = '';
}

function addBlogSectionInline() {
  const input = document.getElementById('blog-new-tag-inline');
  if (!input || !input.value.trim()) return;
  const label = input.value.trim();
  const id = label.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  if (!window._blogSections) window._blogSections = [];
  if (window._blogSections.find(s=>s.id===id)) { input.value=''; return; }
  window._blogSections.push({id, label});
  renderBlogSectionsList();
  input.value = '';
  // Also save this as a custom tag globally so others can reuse it
  if (!window._customBlogTags) window._customBlogTags = [];
  if (!window._customBlogTags.find(t=>t.id===id)) {
    window._customBlogTags.push({id, label});
    saveCustomTagsToServer();
    _populateBlogTagDropdown();
  }
}

function removeBlogSection(i) {
  window._blogSections.splice(i,1);
  renderBlogSectionsList();
}

// ── CUSTOM TAG MANAGEMENT ────────────────────────────────────────────────────
async function loadCustomTags() {
  try {
    const settings = await apiFetch('/api/settings');
    const raw = settings && settings.blog_tags;
    window._customBlogTags = raw ? JSON.parse(raw) : _defaultTags();
  } catch(e) {
    window._customBlogTags = _defaultTags();
  }
}
function _defaultTags() {
  return [
    {id:'review', label:'Review'},
    {id:'our-take', label:'Our Take'},
    {id:'industry-insider', label:'Industry Insider'},
    {id:'behind-the-scenes', label:'Behind the Scenes'},
    {id:'interview', label:'Interview'},
    {id:'analysis', label:'Analysis'},
  ];
}
async function saveCustomTagsToServer() {
  await fetch('/api/admin/settings', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+(adminToken||''),'X-CSRF-Token':_csrfToken||''},
    body: JSON.stringify({ blog_tags: JSON.stringify(window._customBlogTags||[]) })
  }).catch(()=>{});
}
function loadTagsUI(settings) {
  const raw = settings && settings.blog_tags;
  window._customBlogTags = raw ? JSON.parse(raw) : _defaultTags();
  renderTagsAdminList();
}
function renderTagsAdminList() {
  const list = document.getElementById('tags-list');
  if (!list) return;
  const tags = window._customBlogTags || [];
  if (!tags.length) {
    list.innerHTML = '<span style="font-size:12px;color:var(--grey)">No tags yet. Add one above.</span>';
    return;
  }
  list.innerHTML = tags.map((t,i) => `
    <span style="display:inline-flex;align-items:center;gap:6px;background:var(--card);
      border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:12px;font-weight:600;letter-spacing:.05em">
      ${t.label}
      <button onclick="deleteCustomTag(${i})" title="Delete tag"
        style="background:none;border:none;cursor:pointer;color:#888;font-size:14px;line-height:1;padding:0;
        display:flex;align-items:center;margin-left:2px;transition:color .15s"
        onmouseover="this.style.color='#e74c3c'" onmouseout="this.style.color='#888'">×<\/button>
    <\/span>`).join('');
}
async function saveNewTag() {
  const input = document.getElementById('new-tag-input');
  const msg = document.getElementById('tags-msg');
  if (!input || !input.value.trim()) return;
  const label = input.value.trim();
  const id = label.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  if (!window._customBlogTags) window._customBlogTags = _defaultTags();
  if (window._customBlogTags.find(t=>t.id===id)) {
    msg.textContent = `"${label}" already exists.`; setTimeout(()=>msg.textContent='',2000); input.value=''; return;
  }
  window._customBlogTags.push({id, label});
  await saveCustomTagsToServer();
  renderTagsAdminList();
  input.value='';
  msg.style.color = 'var(--grey)';
  msg.textContent = `Tag "${label}" added.`;
  setTimeout(()=>msg.textContent='',2500);
}
async function deleteCustomTag(i) {
  const tag = window._customBlogTags[i];
  if (!tag) return;
  if (!confirm(`Delete the tag "${tag.label}"?\n\nThis removes it from the tag manager but does NOT remove it from posts that already use it.`)) return;
  window._customBlogTags.splice(i,1);
  await saveCustomTagsToServer();
  renderTagsAdminList();
  const msg = document.getElementById('tags-msg');
  if (msg) { msg.textContent = `Tag "${tag.label}" deleted.`; setTimeout(()=>msg.textContent='',2500); }
}
// Load tags on init so they're ready when blog modal opens
loadCustomTags();

async function saveBlog() {
  const id = document.getElementById('blog-edit-id').value;
  const btn = document.querySelector('button[data-action="saveBlog"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('title', document.getElementById('blog-title').value);
  const authorVal = window._blogAuthorPicker ? window._blogAuthorPicker.getValue() : '';
  fd.append('author', authorVal);
  fd.append('excerpt', document.getElementById('blog-excerpt').value);
  fd.append('content', document.getElementById('blog-editor-content').innerHTML);
  fd.append('published', document.getElementById('blog-published').value);
  fd.append('sections', JSON.stringify(window._blogSections||[]));
  const cover = document.getElementById('blog-cover').files[0];
  if (cover) fd.append('cover', cover);
  const url = id ? '/api/admin/blogs/'+id : '/api/admin/blogs';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd});
    if (!res.ok) { alert('Error saving post'); return; }
    const saved = await res.json();
    window._allBlogsCache = null;
    window._blogModalDirty = false;
    closeBlogModal();
    // Instant DOM update
    const tbody = document.getElementById('admin-blogs-tbody');
    const bJson = JSON.stringify(saved).replace(/"/g,'&quot;');
    const viewCount = saved.view_count || 0;
    const newRow = `<tr data-id="${saved.id}">
      <td><input type="checkbox" class="bulk-cb" data-id="${saved.id}" onchange="updateBulkBar('blogs')"></td>
      <td>${saved.cover_image?`<img src="${saved.cover_image}" alt="">`:'—'}</td>
      <td style="font-weight:500">${saved.title}</td>
      <td><span class="tag ${saved.published?'upcoming':''}">${saved.published?'Published':'Draft'}</span></td>
      <td style="color:var(--grey);font-variant-numeric:tabular-nums">${viewCount.toLocaleString()}</td>
      <td style="color:var(--grey)">${saved.created_at?new Date(saved.created_at).toLocaleDateString():''}</td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editBlog(${bJson})">Edit</button>
        <button class="btn-sm danger" onclick="deleteBlog('${saved.id}')">Delete</button>
      </div></td>
    </tr>`;
    if (id) {
      const existing = tbody.querySelector(`tr[data-id="${id}"]`);
      if (existing) { existing.outerHTML = newRow; } else { loadAdminData('blogs'); }
    } else {
      tbody.insertAdjacentHTML('afterbegin', newRow);
      tbody.querySelectorAll('tr td[colspan]').forEach(td => td.closest('tr').remove());
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Post'; }
  }
}

async function toggleBlogPublished(id, currentlyPublished) {
  const newState = !currentlyPublished;
  const row = document.querySelector(`#admin-blogs-tbody tr[data-id="${id}"]`);
  // Optimistic UI — flip badge and button immediately
  const badge = row?.querySelector('td:nth-child(4) .tag');
  const toggleBtn = row?.querySelectorAll('.action-btns .btn-sm')?.[1];
  if (badge) {
    badge.className = `tag ${newState ? 'upcoming' : ''}`;
    badge.textContent = newState ? 'Published' : 'Draft';
  }
  if (toggleBtn) {
    toggleBtn.textContent = newState ? 'Unpublish' : 'Publish';
    toggleBtn.style.cssText = newState
      ? 'background:rgba(245,158,11,.12);color:#f59e0b;border-color:rgba(245,158,11,.25)'
      : 'background:rgba(34,197,94,.1);color:#22c55e;border-color:rgba(34,197,94,.25)';
    toggleBtn.setAttribute('onclick', `toggleBlogPublished('${id}',${newState})`);
  }
  // The blog PUT route uses multer, so send as FormData even for just the published field
  const fd = new FormData();
  fd.append('published', String(newState));
  const result = await apiFetch(`/api/admin/blogs/${id}`, 'PUT', fd);
  if (!result) {
    // Revert on failure
    if (badge) {
      badge.className = `tag ${currentlyPublished ? 'upcoming' : ''}`;
      badge.textContent = currentlyPublished ? 'Published' : 'Draft';
    }
    if (toggleBtn) {
      toggleBtn.textContent = currentlyPublished ? 'Unpublish' : 'Publish';
      toggleBtn.style.cssText = currentlyPublished
        ? 'background:rgba(245,158,11,.12);color:#f59e0b;border-color:rgba(245,158,11,.25)'
        : 'background:rgba(34,197,94,.1);color:#22c55e;border-color:rgba(34,197,94,.25)';
      toggleBtn.setAttribute('onclick', `toggleBlogPublished('${id}',${currentlyPublished})`);
    }
    showError('Failed to update publish status.');
  }
  window._allBlogsCache = null;
}

async function deleteBlog(id) {
  let row = document.querySelector(`#admin-blogs-tbody tr[data-id="${id}"]`);
  const title = row ? row.querySelector('td:nth-child(3)')?.textContent?.trim() : 'this post';
  const ok = await kfsConfirm({ title: `Delete post?`, msg: `<strong style="color:var(--white)">"${title}"</strong> will be permanently removed. This can't be undone.`, okLabel: 'Delete Post' });
  if (!ok) return;
  await apiFetch('/api/admin/blogs/'+id,'DELETE');
  window._allBlogsCache = null;
  row = document.querySelector(`#admin-blogs-tbody tr[data-id="${id}"]`);
  if (row) {
    row.style.transition = 'opacity .2s'; row.style.opacity = '0';
    setTimeout(() => {
      row.remove();
      const tbody = document.getElementById('admin-blogs-tbody');
      if (!tbody.querySelector('tr[data-id]')) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No posts yet. Create your first post!</td></tr>`;
    }, 200);
  }
}

function openEventModal(ev=null) {
  document.getElementById('event-modal').classList.add('open');
  document.getElementById('event-modal-title').textContent = ev ? 'Edit Event' : 'New Event';
  document.getElementById('event-edit-id').value = ev?.id||'';
  document.getElementById('event-title').value = ev?.title||'';
  document.getElementById('event-description').value = ev?.description||'';
  document.getElementById('event-date').value = ev?.event_date||'';
  document.getElementById('event-time').value = ev?.event_time||'';
  document.getElementById('event-location').value = ev?.location||'';
  document.getElementById('event-upcoming').value = ev?.is_upcoming ? 'true':'false';
  document.getElementById('event-cover').value='';
}
function editEvent(ev) { openEventModal(ev); }
function closeEventModal() { document.getElementById('event-modal').classList.remove('open'); }

async function saveEvent() {
  const id = document.getElementById('event-edit-id').value;
  const btn = document.querySelector('#event-modal .btn-success') || document.querySelector('#event-modal button[data-action="saveEvent"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('title', document.getElementById('event-title').value);
  fd.append('description', document.getElementById('event-description').value);
  fd.append('event_date', document.getElementById('event-date').value);
  fd.append('event_time', document.getElementById('event-time').value);
  fd.append('location', document.getElementById('event-location').value);
  fd.append('is_upcoming', document.getElementById('event-upcoming').value);
  const cover = document.getElementById('event-cover').files[0];
  if (cover) fd.append('cover', cover);
  const url = id ? '/api/admin/events/'+id : '/api/admin/events';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd});
    if (!res.ok) { let msg='Error saving event'; try{const e=await res.json();msg=e.error||msg;}catch(_){} alert(msg); return; }
    const saved = await res.json();
    closeEventModal();
    // Instant DOM update — no re-fetch needed
    const tbody = document.getElementById('admin-events-tbody');
    const eJson = JSON.stringify(saved).replace(/"/g,'&quot;');
    const newRow = `<tr data-id="${saved.id}">
      <td style="font-weight:500">${saved.title}</td>
      <td style="color:var(--grey)">${saved.event_date||'—'}</td>
      <td><span class="tag ${saved.is_upcoming?'upcoming':''}">${saved.is_upcoming?'Upcoming':'Past'}</span></td>
      <td style="color:var(--grey)">${saved.location||'—'}</td>
      <td></td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editEvent(${eJson})">Edit</button>
        <button class="btn-sm" style="background:rgba(88,166,255,.12);color:#58a6ff;border-color:rgba(88,166,255,.25)" onclick="openFormBuilder('${saved.id}','${saved.title.replace(/'/g,'\\x27')}')">Form</button>
        <button class="btn-sm" style="background:rgba(34,197,94,.1);color:#22c55e;border-color:rgba(34,197,94,.25)" onclick="openEventRegistrations('${saved.id}')">Regs</button>
        <button class="btn-sm danger" onclick="deleteEvent('${saved.id}')">Delete</button>
      </div></td>
    </tr>`;
    if (id) {
      const existing = tbody.querySelector(`tr[data-id="${id}"]`);
      if (existing) { existing.outerHTML = newRow; } else { loadAdminData('events'); }
    } else {
      // New event — prepend to top
      tbody.insertAdjacentHTML('afterbegin', newRow);
      // Remove "no events" placeholder if present
      tbody.querySelectorAll('tr td[colspan]').forEach(td => td.closest('tr').remove());
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Event'; }
  }
}

async function deleteEvent(id) {
  let row = document.querySelector(`#admin-events-tbody tr[data-id="${id}"]`);
  const title = row ? row.querySelector('td:nth-child(1)')?.textContent?.trim() : 'this event';
  const ok = await kfsConfirm({ title: `Delete event?`, msg: `<strong style="color:var(--white)">"${title}"</strong> will be permanently removed. This can't be undone.`, okLabel: 'Delete Event' });
  if (!ok) return;
  await apiFetch('/api/admin/events/'+id,'DELETE');
  // Instant DOM removal
  row = document.querySelector(`#admin-events-tbody tr[data-id="${id}"]`);
  if (row) {
    row.style.transition = 'opacity .2s';
    row.style.opacity = '0';
    setTimeout(() => {
      row.remove();
      const tbody = document.getElementById('admin-events-tbody');
      if (!tbody.querySelector('tr[data-id]')) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">No events yet.</td></tr>`;
      }
    }, 200);
  }
}

function openMemberModal(m=null) {
  document.getElementById('member-modal').classList.add('open');
  document.getElementById('member-modal-title').textContent = m ? 'Edit Member' : 'Add Member';
  document.getElementById('member-edit-id').value = m?.id||'';
  document.getElementById('member-name').value = m?.name||'';
  document.getElementById('member-role').value = m?.role||'President';
  document.getElementById('member-batch').value = m?.batch||'';
  document.getElementById('member-bio').value = m?.bio||'';
  document.getElementById('member-special-tag').value = m?.special_tag||'';
  document.getElementById('member-is-past').checked = m?.is_past||false;
  document.getElementById('member-domain').value = m?.domain||'';
  autoMemberSort();
  toggleDomainField();
  document.getElementById('member-photo').value='';
}
function editMember(m) { openMemberModal(m); }
function closeMemberModal() { document.getElementById('member-modal').classList.remove('open'); }

async function saveMember() {
  const id = document.getElementById('member-edit-id').value;
  const btn = document.querySelector('#member-modal button[data-action="saveMember"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('name', document.getElementById('member-name').value);
  fd.append('role', document.getElementById('member-role').value);
  const _role = document.getElementById('member-role').value;
  fd.append('domain', (_role === 'Lead' || _role === 'Member') ? (document.getElementById('member-domain').value||'') : '');
  fd.append('batch', document.getElementById('member-batch').value);
  fd.append('bio', document.getElementById('member-bio').value);
  fd.append('special_tag', document.getElementById('member-special-tag').value);
  fd.append('sort_order', document.getElementById('member-sort').value);
  fd.append('is_past', document.getElementById('member-is-past').checked ? 'true' : 'false');
  const photo = document.getElementById('member-photo').files[0];
  if (photo) fd.append('photo', photo);
  const url = id ? '/api/admin/members/'+id : '/api/admin/members';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd});
    if (!res.ok) { let msg='Error saving member'; try{const e=await res.json();msg=e.error||msg;}catch(_){} alert(msg); return; }
    const saved = await res.json();
    closeMemberModal();
    localStorage.setItem('kfs_admin_data_change', Date.now().toString()); // signal portal
    // Update cache
    if (window._allAdminMembers) {
      const idx = window._allAdminMembers.findIndex(m => m.id === saved.id);
      if (idx >= 0) window._allAdminMembers[idx] = { ...window._allAdminMembers[idx], ...saved };
      else window._allAdminMembers.unshift(saved);
      // Refresh batch dropdown
      const batchSel = document.getElementById('mf-batch');
      if (batchSel) {
        const batches = [...new Set(window._allAdminMembers.map(m => m.batch).filter(Boolean))].sort();
        const cur = batchSel.value;
        batchSel.innerHTML = `<option value="">All Batches<\/option>` + batches.map(b=>`<option value="${b}" ${b===cur?'selected':''}>${b}<\/option>`).join('');
      }
      filterAdminMembers(); // re-render with active filters
    } else {
      loadAdminData('members');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Member'; }
  }
}

async function deleteMember(id) {
  let row = document.querySelector(`#admin-members-tbody tr[data-id="${id}"]`);
  const name = row ? row.querySelector('td:nth-child(3)')?.textContent?.trim() : 'this member';
  const ok = await kfsConfirm({ title: `Remove member?`, msg: `<strong style="color:var(--white)">"${name}"</strong> will be permanently removed. This can't be undone.`, okLabel: 'Remove Member' });
  if (!ok) return;
  await apiFetch('/api/admin/members/'+id,'DELETE');
  localStorage.setItem('kfs_admin_data_change', Date.now().toString());
  // Remove from cache and re-render
  if (window._allAdminMembers) window._allAdminMembers = window._allAdminMembers.filter(m => m.id !== id);
  row = document.querySelector(`#admin-members-tbody tr[data-id="${id}"]`);
  if (row) { row.style.transition='opacity .2s'; row.style.opacity='0'; setTimeout(()=>{ row.remove(); filterAdminMembers(); }, 200); }
}

// ── GENRE TAG-PILL INPUT ──────────────────────────────────────────────────────
function initGenreTagInput(initialTags = []) {
  const wrap = document.getElementById('movie-genre-wrap');
  const hidden = document.getElementById('movie-genre');
  const input = document.getElementById('movie-genre-input');
  if (!wrap || !hidden || !input) return;

  let tags = [...initialTags.map(t => t.trim()).filter(Boolean)];

  function syncHidden() { hidden.value = JSON.stringify(tags); }
  function renderPills() {
    wrap.querySelectorAll('.tag-pill').forEach(p => p.remove());
    tags.forEach((tag, i) => {
      const pill = document.createElement('span');
      pill.className = 'tag-pill';
      pill.innerHTML = `${tag} <button type="button" onclick="removeGenreTag(${i})" title="Remove">×</button>`;
      wrap.insertBefore(pill, input);
    });
    syncHidden();
  }

  window._genreTags = tags;
  window.removeGenreTag = function(i) { tags.splice(i, 1); renderPills(); };

  input.value = '';
  input.onkeydown = function(e) {
    if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
      e.preventDefault();
      const val = input.value.replace(/,/g,'').trim();
      if (val && !tags.map(t=>t.toLowerCase()).includes(val.toLowerCase())) { tags.push(val); renderPills(); }
      input.value = '';
    } else if (e.key === 'Backspace' && !input.value && tags.length) {
      tags.pop(); renderPills();
    }
  };
  input.onblur = function() {
    const val = input.value.replace(/,/g,'').trim();
    if (val && !tags.map(t=>t.toLowerCase()).includes(val.toLowerCase())) { tags.push(val); renderPills(); }
    input.value = '';
  };
  renderPills();
}

function openMovieModal(m=null) {
  window._movieModalDirty = false;
  document.getElementById('movie-modal').classList.add('open');
  setTimeout(() => {
    const modal = document.getElementById('movie-modal');
    if (modal && !modal._dirtyListenerAdded) {
      modal._dirtyListenerAdded = true;
      modal.addEventListener('input',  () => { window._movieModalDirty = true; });
      modal.addEventListener('change', () => { window._movieModalDirty = true; });
    }
  }, 50);
  document.getElementById('movie-modal-title').textContent = m ? 'Edit Film' : 'Add Film';
  document.getElementById('movie-edit-id').value = m?.id||'';
  document.getElementById('movie-title').value = m?.title||'';
  document.getElementById('movie-year').value = m?.release_year||'';
  document.getElementById('movie-runtime').value = m?.runtime||'';
  document.getElementById('movie-language').value = m?.language||'';
  // Init genre tag-pill input
  const existingGenres = Array.isArray(m?.genre) ? m.genre : (m?.genre ? [m.genre] : []);
  initGenreTagInput(existingGenres);
  document.getElementById('movie-description').value = m?.description||'';
  document.getElementById('movie-trailer').value = m?.trailer_url||'';
  document.getElementById('movie-watch').value = m?.watch_url||'';
  document.getElementById('movie-spotify').value = m?.spotify_url||'';
  document.getElementById('movie-apple-music').value = m?.apple_music_url||'';
  document.getElementById('movie-poster').value='';
  // init pickers (always re-init to reset state)
  initMoviePickers();
  if (m) {
    _moviePickers['director'].setValue(m.director||'');
    _moviePickers['producer'].setValue(m.producer||'');
    _moviePickers['dop'].setValue(m.dop||'');
    _moviePickers['screenwriter'].setValue(m.screenwriter||'');
    _moviePickers['editor'].setValue(m.video_editor||'');
    _moviePickers['sound'].setValue(m.sound_design||'');
    _moviePickers['management'].setValue(m.management||'');
    _moviePickers['gd'].setValue(m.graphic_design||'');
    _moviePickers['actors'].setValue(m.actors||'');
    _moviePickers['support'].setValue(m.support_crew||'');
  }
}
function editMovie(m) { openMovieModal(m); }
async function closeMovieModal() {
  if (window._movieModalDirty) {
    const discard = await kfsUnsavedGuard();
    if (!discard) return;
  }
  window._movieModalDirty = false;
  document.getElementById('movie-modal').classList.remove('open');
}

// Auto-fetch YouTube video duration when Watch URL is pasted
var _ytRuntimeFetchTimer = null;
async function fetchYTRuntime(videoId, force) {
  const runtimeEl = document.getElementById('movie-runtime');
  const btn = document.getElementById('yt-fetch-btn');
  if (!runtimeEl) return;
  if (runtimeEl.value && !force) return; // don't overwrite unless forced
  if (btn) { btn.textContent = '⏳'; btn.disabled = true; }
  try {
    const r = await fetch('/api/yt-duration?v=' + videoId);
    if (!r.ok) { if (btn) { btn.textContent = '✗'; btn.disabled = false; } return; }
    const d = await r.json();
    if (d.minutes) {
      runtimeEl.value = d.minutes;
      runtimeEl.style.outline = '2px solid rgba(52,199,89,.6)';
      setTimeout(() => { runtimeEl.style.outline = ''; }, 2000);
      if (btn) { btn.textContent = '✓'; setTimeout(() => { btn.textContent = '↺ Fetch'; btn.disabled = false; }, 1500); }
    } else {
      if (btn) { btn.textContent = '✗ Not found'; setTimeout(() => { btn.textContent = '↺ Fetch'; btn.disabled = false; }, 2000); }
    }
  } catch(e) {
    if (btn) { btn.textContent = '✗ Error'; setTimeout(() => { btn.textContent = '↺ Fetch'; btn.disabled = false; }, 2000); }
  }
}

function tryAutoFetchYTRuntime(url) {
  clearTimeout(_ytRuntimeFetchTimer);
  const btn = document.getElementById('yt-fetch-btn');
  if (!url) { if (btn) btn.style.display = 'none'; return; }
  const match = url.match(/(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  if (!match) { if (btn) btn.style.display = 'none'; return; }
  const videoId = match[1];
  if (btn) { btn.style.display = 'inline-flex'; btn.onclick = () => fetchYTRuntime(videoId, true); }
  _ytRuntimeFetchTimer = setTimeout(() => fetchYTRuntime(videoId, false), 700);
}

async function saveMovie() {
  const id = document.getElementById('movie-edit-id').value;
  const btn = document.querySelector('#movie-modal button[data-action="saveMovie"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('title', document.getElementById('movie-title').value);
  fd.append('release_year', document.getElementById('movie-year').value);
  fd.append('runtime', document.getElementById('movie-runtime').value.trim());
  fd.append('language', document.getElementById('movie-language').value.trim());
  fd.append('genre', document.getElementById('movie-genre').value);
  fd.append('description', document.getElementById('movie-description').value);
  fd.append('director', _moviePickers['director'].getValue());
  fd.append('producer', _moviePickers['producer'].getValue());
  fd.append('dop', _moviePickers['dop'].getValue());
  fd.append('screenwriter', _moviePickers['screenwriter'].getValue());
  fd.append('video_editor', _moviePickers['editor'].getValue());
  fd.append('sound_design', _moviePickers['sound'].getValue());
  fd.append('management', _moviePickers['management'].getValue());
  fd.append('graphic_design', _moviePickers['gd'].getValue());
  fd.append('actors', _moviePickers['actors'].getValue());
  fd.append('support_crew', _moviePickers['support'].getValue());
  fd.append('trailer_url', document.getElementById('movie-trailer').value.trim());
  fd.append('watch_url', document.getElementById('movie-watch').value.trim());
  // Client-side URL validation — mirrors the server rule (https:// only)
  const trailerVal = document.getElementById('movie-trailer').value.trim();
  const watchVal   = document.getElementById('movie-watch').value.trim();
  if (trailerVal && !/^https:\/\//i.test(trailerVal)) {
    alert('Trailer URL must start with https://');
    return;
  }
  if (watchVal && !/^https:\/\//i.test(watchVal)) {
    alert('Watch Now URL must start with https://');
    return;
  }
  fd.append('spotify_url', document.getElementById('movie-spotify').value.trim());
  fd.append('apple_music_url', document.getElementById('movie-apple-music').value.trim());
  const poster = document.getElementById('movie-poster').files[0];
  if (poster) fd.append('poster', poster);
  const url = id ? '/api/admin/movies/'+id : '/api/admin/movies';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd});
    if (!res.ok) { let msg='Error saving film'; try{const e=await res.json();msg=e.error||msg;}catch(_){} alert(msg); return; }
    const saved = await res.json();
    window._movieModalDirty = false;
    closeMovieModal();
    localStorage.setItem('kfs_admin_data_change', Date.now().toString()); // signal portal
    // Instant DOM update
    const tbody = document.getElementById('admin-movies-tbody');
    const mJson = JSON.stringify(saved).replace(/"/g,'&quot;');
    const dirDisplay = saved.director ? splitCrew(saved.director).map(p=>p.split('||')[0].trim()).join(', ') : '—';
    const newRow = `<tr data-id="${saved.id}">
      <td><input type="checkbox" class="bulk-cb" data-id="${saved.id}" onchange="updateBulkBar('movies')"></td>
      <td>${saved.poster_image?`<img src="${saved.poster_image}" alt="" style="aspect-ratio:2/3;width:36px;object-fit:cover">`:svgFilm(18)}</td>
      <td style="font-weight:500">${saved.title}</td>
      <td style="color:var(--grey)">${saved.release_year||'—'}</td>
      <td style="color:var(--grey)">${dirDisplay}</td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editMovie(${mJson})">Edit</button>
        <button class="btn-sm danger" onclick="deleteMovie('${saved.id}')">Delete</button>
      </div></td>
    </tr>`;
    if (id) {
      const existing = tbody.querySelector(`tr[data-id="${id}"]`);
      if (existing) { existing.outerHTML = newRow; } else { loadAdminData('movies'); }
    } else {
      tbody.insertAdjacentHTML('afterbegin', newRow);
      tbody.querySelectorAll('tr td[colspan]').forEach(td => td.closest('tr').remove());
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Film'; }
  }
}

async function deleteMovie(id) {
  let row = document.querySelector(`#admin-movies-tbody tr[data-id="${id}"]`);
  const title = row ? row.querySelector('td:nth-child(2)')?.textContent?.trim() : 'this film';
  const ok = await kfsConfirm({ title: `Delete film?`, msg: `<strong style="color:var(--white)">"${title}"</strong> will be permanently removed. This can't be undone.`, okLabel: 'Delete Film' });
  if (!ok) return;
  await apiFetch('/api/admin/movies/'+id,'DELETE');
  localStorage.setItem('kfs_admin_data_change', Date.now().toString()); // signal portal
  row = document.querySelector(`#admin-movies-tbody tr[data-id="${id}"]`);
  if (row) {
    row.style.transition = 'opacity .2s'; row.style.opacity = '0';
    setTimeout(() => {
      row.remove();
      const tbody = document.getElementById('admin-movies-tbody');
      if (!tbody.querySelector('tr[data-id]')) tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">No films yet.</td></tr>`;
    }, 200);
  }
}

function openTestimonialModal(t=null) {
  document.getElementById('testimonial-modal').classList.add('open');
  document.getElementById('testimonial-modal-title').textContent = t ? 'Edit Testimonial' : 'Add Testimonial';
  document.getElementById('testimonial-edit-id').value = t?.id||'';
  document.getElementById('testimonial-name').value = t?.name||'';
  document.getElementById('testimonial-role').value = t?.role||'';
  document.getElementById('testimonial-batch').value = t?.batch||'';
  document.getElementById('testimonial-quote').value = t?.quote||'';
  document.getElementById('testimonial-photo').value='';
}
function editTestimonial(t) { openTestimonialModal(t); }
function closeTestimonialModal() { document.getElementById('testimonial-modal').classList.remove('open'); }

async function saveTestimonial() {
  const id = document.getElementById('testimonial-edit-id').value;
  const btn = document.querySelector('button[data-action="saveTestimonial"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('name', document.getElementById('testimonial-name').value);
  fd.append('role', document.getElementById('testimonial-role').value);
  fd.append('batch', document.getElementById('testimonial-batch').value);
  fd.append('quote', document.getElementById('testimonial-quote').value);
  const photo = document.getElementById('testimonial-photo').files[0];
  if (photo) fd.append('photo', photo);
  const url = id ? '/api/admin/testimonials/'+id : '/api/admin/testimonials';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd});
    if (!res.ok) { alert('Error saving testimonial'); return; }
    const saved = await res.json();
    closeTestimonialModal();
    const tbody = document.getElementById('admin-testimonials-tbody');
    const tJson = JSON.stringify(saved).replace(/"/g,'&quot;');
    const newRow = `<tr data-id="${saved.id}">
      <td>${saved.photo?`<img src="${saved.photo}" alt="" style="border-radius:50%">`:svgPerson(16)}</td>
      <td style="font-weight:500">${saved.name}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--grey)">"${saved.quote}"</td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editTestimonial(${tJson})">Edit</button>
        <button class="btn-sm danger" onclick="deleteTestimonial('${saved.id}')">Delete</button>
      </div></td>
    </tr>`;
    if (id) {
      const existing = tbody.querySelector(`tr[data-id="${id}"]`);
      if (existing) { existing.outerHTML = newRow; } else { loadAdminData('testimonials'); }
    } else {
      tbody.insertAdjacentHTML('afterbegin', newRow);
      tbody.querySelectorAll('tr td[colspan]').forEach(td => td.closest('tr').remove());
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Testimonial'; }
  }
}

async function deleteTestimonial(id) {
  if (!confirm('Delete this testimonial?')) return;
  await apiFetch('/api/admin/testimonials/'+id,'DELETE');
  const row = document.querySelector(`#admin-testimonials-tbody tr[data-id="${id}"]`);
  if (row) {
    row.style.transition = 'opacity .2s'; row.style.opacity = '0';
    setTimeout(() => { row.remove(); }, 200);
  }
}

function openAchievementModal(a=null) {
  document.getElementById('achievement-modal').classList.add('open');
  document.getElementById('achievement-modal-title').textContent = a ? 'Edit Achievement' : 'Add Achievement';
  document.getElementById('achievement-edit-id').value = a?.id||'';
  
  document.getElementById('achievement-title').value = a?.title||'';
  document.getElementById('achievement-year').value = a?.year||'';
  document.getElementById('achievement-description').value = a?.description||'';
  document.getElementById('achievement-sort').value = a?.sort_order||99;
}
function editAchievement(a) { openAchievementModal(a); }
function closeAchievementModal() { document.getElementById('achievement-modal').classList.remove('open'); }

async function saveAchievement() {
  const id = document.getElementById('achievement-edit-id').value;
  const btn = document.querySelector('button[data-action="saveAchievement"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const body = {
    title: document.getElementById('achievement-title').value,
    year: document.getElementById('achievement-year').value,
    description: document.getElementById('achievement-description').value,
    sort_order: document.getElementById('achievement-sort').value,
  };
  const url = id ? '/api/admin/achievements/'+id : '/api/admin/achievements';
  try {
    const res = await fetch(url,{method:id?'PUT':'POST', credentials:'include',
      headers:{'Authorization':'Bearer '+adminToken,'Content-Type':'application/json','X-CSRF-Token':_csrfToken||''},
      body:JSON.stringify(body)});
    if (!res.ok) { alert('Error saving achievement'); return; }
    const saved = await res.json();
    closeAchievementModal();
    const tbody = document.getElementById('admin-achievements-tbody');
    const aJson = JSON.stringify(saved).replace(/"/g,'&quot;');
    const newRow = `<tr data-id="${saved.id}">
      <td style="font-weight:500">${saved.title}</td>
      <td style="color:var(--grey)">${saved.year||'—'}</td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editAchievement(${aJson})">Edit</button>
        <button class="btn-sm danger" onclick="deleteAchievement('${saved.id}')">Delete</button>
      </div></td>
    </tr>`;
    if (id) {
      const existing = tbody.querySelector(`tr[data-id="${id}"]`);
      if (existing) { existing.outerHTML = newRow; } else { loadAdminData('achievements'); }
    } else {
      tbody.insertAdjacentHTML('afterbegin', newRow);
      tbody.querySelectorAll('tr td[colspan]').forEach(td => td.closest('tr').remove());
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
  }
}

async function deleteAchievement(id) {
  if (!confirm('Delete this achievement?')) return;
  await apiFetch('/api/admin/achievements/'+id,'DELETE');
  const row = document.querySelector(`#admin-achievements-tbody tr[data-id="${id}"]`);
  if (row) {
    row.style.transition = 'opacity .2s'; row.style.opacity = '0';
    setTimeout(() => { row.remove(); }, 200);
  }
}

async function saveSettings() {
  const saveBtn = document.getElementById('save-settings-btn');
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving...'; }
  try {
    const fd = new FormData();
    // Text fields
    fd.append('site_tagline', document.getElementById('set-tagline').value);
    fd.append('about_text', document.getElementById('set-about').value);
    fd.append('stat_members', document.getElementById('set-stat-members').value);
    fd.append('stat_events', document.getElementById('set-stat-events').value);
    fd.append('stat_films', document.getElementById('set-stat-films').value);
    fd.append('stat_years', document.getElementById('set-stat-years').value);
    fd.append('spotlight_name', document.getElementById('set-spotlight-name').value);
    fd.append('spotlight_role', document.getElementById('set-spotlight-role').value);
    fd.append('spotlight_quote', document.getElementById('set-spotlight-quote').value);
    fd.append('spotlight_photo', document.getElementById('set-spotlight-photo').value);
    fd.append('instagram', document.getElementById('set-instagram').value);
    fd.append('youtube', document.getElementById('set-youtube').value);
    fd.append('email', document.getElementById('set-email').value);
    // Team photo file (if a new one was chosen)
    const photoFile = document.getElementById('set-team-photo-file').files[0];
    if (photoFile) fd.append('team_photo', photoFile);
    const res = await fetch('/api/admin/settings', {
      method: 'POST', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'X-CSRF-Token': _csrfToken || '' },
      body: fd
    });
    if (res.ok) {
      alert('Settings saved!');
      // Refresh preview if photo was uploaded
      if (photoFile) {
        const d = await res.json().catch(() => ({}));
        // Reload settings to get the new photo URL
        const fresh = await apiFetch('/api/settings');
        if (fresh && fresh.team_photo) {
          document.getElementById('set-team-photo-url').value = fresh.team_photo;
          document.getElementById('team-photo-img').src = fresh.team_photo;
          document.getElementById('team-photo-preview').style.display = 'block';
        }
      }
    } else {
      const err = await res.json().catch(() => ({}));
      alert('Save failed: ' + (err.error || res.status));
    }
  } catch(e) {
    alert('Save failed: ' + e.message);
  } finally {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save Settings'; }
  }
}

function insertEmailVar(variable) {
  const ta = document.getElementById('set-email-body');
  if (!ta) return;
  const start = ta.selectionStart ?? ta.value.length;
  const end = ta.selectionEnd ?? ta.value.length;
  ta.value = ta.value.slice(0, start) + variable + ta.value.slice(end);
  ta.focus();
  ta.selectionStart = ta.selectionEnd = start + variable.length;
  updateEmailPreview();
}

let _emailPreviewDebounce = null;
async function updateEmailPreview() {
  clearTimeout(_emailPreviewDebounce);
  _emailPreviewDebounce = setTimeout(async () => {
    const ta = document.getElementById('set-email-body');
    const frame = document.getElementById('email-preview-frame');
    if (!ta || !frame) return;
    try {
      const res = await apiFetch('/api/admin/settings/email-preview', 'POST', { body: ta.value });
      if (res && res.html) frame.srcdoc = res.html;
    } catch (e) { /* non-fatal */ }
  }, 250);
}

async function saveEmailSettings() {
  const btn = document.querySelector('[data-action="saveEmailSettings"]');
  const msg = document.getElementById('email-settings-msg');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }
  try {
    const fd = new FormData();
    const apiKey = document.getElementById('set-brevo-api-key').value.trim();
    if (apiKey) fd.append('brevo_api_key', apiKey);
    fd.append('smtp_from_name', document.getElementById('set-smtp-from-name').value.trim());
    fd.append('email_confirmation_body', document.getElementById('set-email-body').value);
    const res = await fetch('/api/admin/settings', {
      method: 'POST', credentials: 'include', headers: { 'Authorization': 'Bearer ' + adminToken, 'x-csrf-token': _csrfToken || '' }, body: fd
    });
    if (res.ok) {
      if (msg) { msg.style.color='#4caf50'; msg.textContent = '✓ Email settings saved!'; setTimeout(()=>{ msg.textContent=''; }, 4000); }
      document.getElementById('set-brevo-api-key').value = '';
      document.getElementById('set-brevo-api-key').placeholder = '(saved — enter new to change)';
    } else {
      const err = await res.json().catch(()=>({}));
      if (msg) { msg.style.color='#ff453a'; msg.textContent = 'Save failed: ' + (err.error || res.status); }
    }
  } catch(e) {
    if (msg) { msg.style.color='#ff453a'; msg.textContent = 'Error: ' + e.message; }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Email Settings'; }
  }
}

async function sendTestEmail() {
  const btn = document.querySelector('[data-action="sendTestEmail"]');
  const msg = document.getElementById('email-settings-msg');
  const to = prompt('Send test confirmation email to which address?');
  if (!to || !to.includes('@')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }
  try {
    const res = await fetch('/api/admin/email/test', {
      method: 'POST', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'Content-Type': 'application/json', 'x-csrf-token': _csrfToken || '' },
      body: JSON.stringify({ to })
    });
    const d = await res.json().catch(()=>({}));
    if (res.ok) {
      if (msg) { msg.style.color='#4caf50'; msg.textContent = '✓ Test email sent to ' + to; setTimeout(()=>{ msg.textContent=''; }, 6000); }
    } else {
      if (msg) { msg.style.color='#ff453a'; msg.textContent = 'Failed: ' + (d.error || res.status); }
    }
  } catch(e) {
    if (msg) { msg.style.color='#ff453a'; msg.textContent = 'Error: ' + e.message; }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send Test Email'; }
  }
}

async function saveNoShortsEgg() {
  const btn = document.querySelector('[data-action="saveNoShortsEgg"]');
  const msg = document.getElementById('noshorts-egg-msg');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }
  try {
    const fd = new FormData();
    const eggFile = document.getElementById('set-egg-img-file').files[0];
    if (eggFile) fd.append('easter_egg_img', eggFile);
    if (!eggFile && !document.getElementById('set-egg-img-url').value)
      fd.append('easter_egg_img_clear', '1');
    fd.append('easter_egg_shorts_heading', document.getElementById('set-egg-shorts-heading').value);
    fd.append('easter_egg_shorts_sub', document.getElementById('set-egg-shorts-sub').value);
    fd.append('easter_egg_noshorts_fallback', document.getElementById('set-egg-noshorts-fallback').value);
    const res = await fetch('/api/admin/settings', {
      method: 'POST', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'X-CSRF-Token': _csrfToken || '' },
      body: fd
    });
    if (res.ok) {
      if (msg) { msg.style.color='#4caf50'; msg.textContent = '✓ No Shorts Easter Egg saved!'; setTimeout(()=>{ msg.textContent=''; msg.style.color=''; }, 4000); }
      else alert('Easter Egg saved!');
      // Refresh egg image preview if a new one was uploaded
      if (eggFile) {
        const fresh = await apiFetch('/api/settings');
        if (fresh && fresh.easter_egg_img) {
          document.getElementById('set-egg-img-url').value = fresh.easter_egg_img;
          document.getElementById('egg-img-thumb').src = fresh.easter_egg_img;
          document.getElementById('egg-img-preview').style.display = 'block';
          window._easterEggImg = fresh.easter_egg_img;
        }
      }
    } else {
      const err = await res.json().catch(() => ({}));
      if (msg) { msg.style.color='#e74c3c'; msg.textContent = 'Save failed: ' + (err.error || res.status); }
      else alert('Save failed: ' + (err.error || res.status));
    }
  } catch(e) {
    if (msg) { msg.style.color='#e74c3c'; msg.textContent = 'Save failed: ' + e.message; }
    else alert('Save failed: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save No Shorts Easter Egg'; }
  }
}

async function changePassword() {
  const curr = document.getElementById('current-password').value;
  const np   = document.getElementById('new-password').value;
  const cp   = document.getElementById('confirm-password').value;
  const msg  = document.getElementById('change-pw-msg');
  if (!curr) { if(msg) msg.textContent = 'Please enter your current password'; else alert('Please enter your current password'); return; }
  if (np !== cp) { if(msg) msg.textContent = 'Passwords do not match'; else alert('Passwords do not match'); return; }
  if (np.length < 8) { if(msg) msg.textContent = 'Password must be at least 8 characters'; else alert('Password must be at least 8 characters'); return; }
  const res = await fetch('/api/admin/change-password',{method:'POST', credentials:'include',
    headers:{'Authorization':'Bearer '+adminToken,'Content-Type':'application/json','x-csrf-token': _csrfToken || ''},
    body:JSON.stringify({currentPassword:curr, newPassword:np})});
  if (res.ok) {
    document.getElementById('current-password').value='';
    document.getElementById('new-password').value='';
    document.getElementById('confirm-password').value='';
    if(msg) { msg.style.color='#4caf50'; msg.textContent = '✓ Password changed successfully!'; setTimeout(()=>{ msg.textContent=''; msg.style.color=''; }, 4000); }
    else alert('Password changed!');
  } else {
    const err = await res.json().catch(()=>({}));
    if(msg) { msg.style.color='#e74c3c'; msg.textContent = (err.error || 'Failed to change password'); }
    else alert('Failed: ' + (err.error || 'Unknown error'));
  }
}

// ── TWO-FACTOR AUTH ────────────────────────────────────────────────────────────
function tfa_updateStatusCard(enabled) {
  const label = document.getElementById('tfa-status-label');
  const desc  = document.getElementById('tfa-status-desc');
  const badge = document.getElementById('tfa-status-badge');
  const iconWrap = document.getElementById('tfa-status-icon');
  if (enabled) {
    label.textContent = '2FA is enabled';
    desc.textContent  = 'Your account is protected with a second factor.';
    badge.textContent = 'ON';
    badge.style.background = 'rgba(80,200,120,.12)';
    badge.style.borderColor = 'rgba(80,200,120,.3)';
    badge.style.color = '#50c878';
    iconWrap.style.background = 'rgba(80,200,120,.1)';
    iconWrap.style.borderColor = 'rgba(80,200,120,.25)';
  } else {
    label.textContent = '2FA is disabled';
    desc.textContent  = 'Add a second layer of security to your account.';
    badge.textContent = 'OFF';
    badge.style.background = 'rgba(245,245,245,.07)';
    badge.style.borderColor = 'var(--border)';
    badge.style.color = 'var(--grey)';
    iconWrap.style.background = 'rgba(245,245,245,.06)';
    iconWrap.style.borderColor = 'var(--border)';
  }
}

function tfa_showBlocks(state) {
  // state: 'setup' | 'qr' | 'enabled'
  document.getElementById('tfa-setup-block').style.display   = state === 'setup'   ? '' : 'none';
  document.getElementById('tfa-qr-block').style.display      = state === 'qr'      ? '' : 'none';
  document.getElementById('tfa-enabled-block').style.display = state === 'enabled' ? '' : 'none';
}

function tfa_initSection() {
  // Read current 2FA status from login response stored in window
  const enabled = !!(window._currentAdmin && window._currentAdmin.totp_enabled);
  tfa_updateStatusCard(enabled);
  tfa_showBlocks(enabled ? 'enabled' : 'setup');
  document.getElementById('tfa-verify-msg').textContent = '';
  document.getElementById('tfa-disable-msg') && (document.getElementById('tfa-disable-msg').textContent = '');
}

async function tfa_startSetup() {
  const btn = document.getElementById('tfa-start-btn');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  try {
    const data = await apiFetch('/api/admin/2fa/setup');
    if (!data || !data.qr_code) throw new Error('Setup failed');
    document.getElementById('tfa-qr-img').src = data.qr_code;
    document.getElementById('tfa-secret-text').textContent = data.secret || '';
    document.getElementById('tfa-verify-input').value = '';
    document.getElementById('tfa-verify-msg').textContent = '';
    tfa_showBlocks('qr');
    setTimeout(() => document.getElementById('tfa-verify-input').focus(), 200);
  } catch(e) {
    alert('Could not start 2FA setup. Please try again.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:middle;margin-right:6px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Enable Two-Factor Auth';
  }
}

function tfa_cancelSetup() {
  tfa_showBlocks('setup');
  document.getElementById('tfa-verify-input').value = '';
  document.getElementById('tfa-verify-msg').textContent = '';
}

async function tfa_verifyCode() {
  const code = (document.getElementById('tfa-verify-input').value || '').replace(/\s/g,'');
  const msg  = document.getElementById('tfa-verify-msg');
  const btn  = document.getElementById('tfa-verify-btn');
  if (!code || code.length < 6) { msg.style.color='#e74c3c'; msg.textContent='Enter the 6-digit code from your authenticator app.'; return; }
  btn.disabled = true; btn.textContent = 'Verifying…';
  msg.style.color = 'var(--grey)'; msg.textContent = '';
  try {
    const res = await apiFetch('/api/admin/2fa/verify','POST',{ code });
    if (res && res.success) {
      if (window._currentAdmin) window._currentAdmin.totp_enabled = true;
      tfa_updateStatusCard(true);
      tfa_showBlocks('enabled');
    } else {
      msg.style.color = '#e74c3c';
      msg.textContent = (res && res.error) || 'Invalid code. Try again.';
    }
  } catch(e) {
    msg.style.color = '#e74c3c';
    msg.textContent = 'Verification failed. Check your connection.';
  } finally {
    btn.disabled = false; btn.textContent = 'Verify & Activate';
  }
}

async function tfa_disableSelf() {
  const msg = document.getElementById('tfa-disable-msg');
  if (!confirm('Disable Two-Factor Authentication?\n\nYou will no longer need a code to log in. This reduces your account security.')) return;
  msg.style.color = 'var(--grey)'; msg.textContent = 'Disabling…';
  try {
    const res = await apiFetch('/api/admin/2fa/disable','POST',{});
    if (res && res.success) {
      if (window._currentAdmin) window._currentAdmin.totp_enabled = false;
      tfa_updateStatusCard(false);
      tfa_showBlocks('setup');
      msg.textContent = '';
    } else {
      msg.style.color = '#e74c3c'; msg.textContent = (res && res.error) || 'Failed to disable 2FA.';
    }
  } catch(e) {
    msg.style.color = '#e74c3c'; msg.textContent = 'Network error. Please try again.';
  }
}

async function masterDisable2FA(adminId, adminName) {
  if (!confirm(`Disable 2FA for "${adminName}"?\n\nThey will be able to log in without an authenticator code until they re-enable it.`)) return;
  try {
    const res = await apiFetch('/api/admin/2fa/disable','POST',{ admin_id: adminId });
    if (res && res.success) {
      loadAdminData('admins');
    } else {
      alert((res && res.error) || 'Failed to disable 2FA.');
    }
  } catch(e) {
    alert('Network error. Please try again.');
  }
}

function execCmd(cmd, val=null) {
  document.getElementById('blog-editor-content').focus();
  document.execCommand(cmd, false, val);
}
function insertLink() {
  const url = prompt('Enter URL:');
  if (url) execCmd('createLink', url);
}

function previewTeamPhoto(input) {
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  if (file.size > 20 * 1024 * 1024) {
    alert('Photo is too large (' + (file.size/1024/1024).toFixed(1) + 'MB). Please use an image under 20MB.');
    input.value = '';
    return;
  }
  document.getElementById('team-photo-filename').textContent = file.name;
  const reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById('team-photo-img').src = e.target.result;
    document.getElementById('team-photo-preview').style.display = 'block';
    document.getElementById('team-photo-clear-btn').style.display = 'inline-flex';
  };
  reader.readAsDataURL(file);
}

function clearTeamPhoto() {
  document.getElementById('set-team-photo-file').value = '';
  document.getElementById('set-team-photo-url').value = '';
  document.getElementById('team-photo-img').src = '';
  document.getElementById('team-photo-preview').style.display = 'none';
  document.getElementById('team-photo-clear-btn').style.display = 'none';
  document.getElementById('team-photo-filename').textContent = 'No file chosen';
}

function previewEggImg(input) {
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  document.getElementById('egg-img-filename').textContent = file.name;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('egg-img-thumb').src = e.target.result;
    document.getElementById('egg-img-preview').style.display = 'block';
    document.getElementById('egg-img-clear-btn').style.display = 'inline-flex';
  };
  reader.readAsDataURL(file);
}
function clearEggImg() {
  document.getElementById('set-egg-img-file').value = '';
  document.getElementById('set-egg-img-url').value = '';
  document.getElementById('egg-img-thumb').src = '';
  document.getElementById('egg-img-preview').style.display = 'none';
  document.getElementById('egg-img-clear-btn').style.display = 'none';
  document.getElementById('egg-img-filename').textContent = 'No file chosen';
  window._easterEggImg = '';
}

// ── CUSTOM SEARCH EASTER EGGS ────────────────────────────────────────────────
window._customSearchEggs = [];

async function loadCustomEggsUI() {
  const list = document.getElementById('cegg-list');
  if (!list) return;
  try {
    const eggs = await apiFetch('/api/settings/custom-eggs');
    window._customSearchEggs = Array.isArray(eggs) ? eggs : [];
  } catch(e) { window._customSearchEggs = []; }
  renderCustomEggsUI();
}

function renderCustomEggsUI() {
  const list = document.getElementById('cegg-list');
  if (!list) return;
  const eggs = window._customSearchEggs || [];
  if (!eggs.length) {
    list.innerHTML = '<span style="font-size:12px;color:var(--grey)">No custom easter eggs yet.</span>';
    return;
  }
  list.innerHTML = eggs.map((e, i) => `
    <div class="cegg-item">
      <span class="cegg-kw">"${e.keyword}"</span>
      <span class="cegg-text">${e.heading||''}${e.subtext ? ' — '+e.subtext : ''}${e.image_url ? '<span class="cegg-has-img" style="margin-left:4px"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></span>' : ''}</span>
      <button class="cegg-del" onclick="deleteCustomEgg(${i})" title="Delete">×</button>
    </div>
  `).join('');
}

async function addCustomEgg() {
  const kw = document.getElementById('cegg-kw').value.trim().toLowerCase();
  const head = document.getElementById('cegg-head').value.trim();
  const sub = document.getElementById('cegg-sub').value.trim();
  const imgFile = document.getElementById('cegg-img-file').files[0];
  const msg = document.getElementById('cegg-msg');

  if (!kw) { msg.textContent = 'Keyword is required.'; return; }
  if (!head && !imgFile) { msg.textContent = 'Heading or an image is required.'; return; }
  if (window._customSearchEggs.some(e => e.keyword === kw)) {
    msg.textContent = `Keyword "${kw}" already exists. Delete the old one first.`; return;
  }

  msg.textContent = 'Saving…';
  let image_url = null;
  if (imgFile) {
    // Upload via a dedicated endpoint that does NOT touch the No Shorts easter_egg_img setting
    const fd = new FormData();
    fd.append('image', imgFile);
    try {
      const r = await apiFetch('/api/admin/settings/custom-egg-upload', 'POST', fd);
      if (!r || !r.url) { msg.textContent = 'Image upload failed.'; return; }
      image_url = r.url;
    } catch(e) { msg.textContent = 'Image upload failed: ' + e.message; return; }
  }

  const newEgg = { keyword: kw, heading: head, subtext: sub, image_url };
  const eggs = [...(window._customSearchEggs || []), newEgg];
  try {
    await apiFetch('/api/admin/settings/custom-eggs', 'POST', { eggs });
    window._customSearchEggs = eggs;
    renderCustomEggsUI();
    document.getElementById('cegg-kw').value = '';
    document.getElementById('cegg-head').value = '';
    document.getElementById('cegg-sub').value = '';
    document.getElementById('cegg-img-file').value = '';
    document.getElementById('cegg-img-name').textContent = 'No file';
    msg.textContent = 'Easter egg added!';
    setTimeout(() => { msg.textContent = ''; }, 2000);
  } catch(e) { msg.textContent = 'Save failed: ' + e.message; }
}

async function deleteCustomEgg(idx) {
  const eggs = (window._customSearchEggs || []).filter((_, i) => i !== idx);
  try {
    await apiFetch('/api/admin/settings/custom-eggs', 'POST', { eggs });
    window._customSearchEggs = eggs;
    renderCustomEggsUI();
  } catch(e) { alert('Delete failed: ' + e.message); }
}
// ─────────────────────────────────────────────────────────────────────────────



async function apiFetch(url, method='GET', body=null) {
  const opts = { method, headers:{}, credentials: 'include' };
  if (adminToken) opts.headers['Authorization'] = 'Bearer '+adminToken;
  // Include CSRF token on all write requests
  if (_csrfToken && !['GET','HEAD'].includes(method)) {
    opts.headers['X-CSRF-Token'] = _csrfToken;
  }
  if (body) {
    if (body instanceof FormData) {
      opts.body = body;
    } else if (typeof body === 'string') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = body;
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
  }
  try {
    const res = await fetch(url, opts);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      const msg = 'Server returned non-JSON for ' + url + ' (status ' + res.status + '). Redeploy may be needed.';
      console.error('apiFetch:', msg);
      showAdminError(msg);
      return null;
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      console.warn('apiFetch error:', method, url, res.status, data?.error || data);
      if (res.status === 401) showAdminError('Session expired — please log out and log back in.');
      else if (res.status === 403) showAdminError('Access denied: ' + (data?.error || 'insufficient permissions'));
      else if (res.status >= 500) showAdminError('Server error on ' + url + ': ' + (data?.error || res.status));
    }
    return data;
  } catch(e) {
    console.error('apiFetch network error:', url, e);
    showAdminError('Network error: could not reach ' + url);
    return null;
  }
}

function showAdminError(msg) {
  const isAdmin = document.getElementById('admin-panel')?.classList.contains('active');
  let bar = document.getElementById('admin-error-bar');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'admin-error-bar';
    document.body.appendChild(bar);
  }
  if (isAdmin) {
    bar.style.cssText = 'position:fixed;top:0;left:220px;right:0;z-index:9999;background:#c0392b;color:#fff;padding:10px 20px;font-size:13px;display:flex;align-items:center;justify-content:space-between;gap:16px;font-family:inherit';
  } else {
    bar.style.cssText = 'position:fixed;top:70px;left:50%;transform:translateX(-50%);z-index:9999;background:#c0392b;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;display:flex;align-items:center;gap:16px;font-family:inherit;box-shadow:0 4px 20px rgba(0,0,0,.4);max-width:90vw';
  }
  const close = document.createElement('button');
  close.textContent = '×';
  close.style.cssText = 'background:none;border:none;color:#fff;cursor:pointer;font-size:16px;opacity:.8;font-family:inherit;flex-shrink:0';
  close.onclick = () => bar.remove();
  bar.innerHTML = '';
  bar.appendChild(document.createTextNode(msg));
  bar.appendChild(close);
  clearTimeout(bar._t);
  bar._t = setTimeout(() => bar?.remove(), 8000);
}

async function checkRoute() {
  // Wait for wrapped config to resolve before routing, so we never
  // briefly flash the wrapped page if it is disabled.
  await _wrappedNavReady;
  // Now safe to restore the wrapped page element — only if config says it is enabled.
  // Guarding here (in addition to the CSS rule below) prevents any JS-timing flash.
  const wp = document.getElementById('page-wrapped');
  if (wp && _wrappedConfig?.enabled !== false) wp.style.display = '';

  const path = window.location.pathname.replace(/^\//, '');
  if (!path || path === 'home') { navigate('home', false); return; }
  if (path === 'admin') { navigate('admin', false); return; }

  const blogMatch  = path.match(/^blog\/(.+)/);
  const filmMatch  = path.match(/^films\/(.+)/);
  const eventMatch = path.match(/^events\/(.+)/);
  // legacy /movies/ URLs redirect to films
  const movieLegacy = path.match(/^movies\/(.+)/);
  // collaborate edit link
  const collabEditMatch = path.match(/^collaborate\/edit\/(.+)/);
  if (collabEditMatch) {
    loadCollabEditToken(collabEditMatch[1]);
    return;
  }

  // Extract ID from the tail of a slug: "my-post-title-42" → "42"
  // Works for both numeric IDs and UUIDs.
  function idFromSlug(slug) {
    if (!slug) return null;
    const uuidM = slug.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i);
    if (uuidM) return uuidM[1];
    const numM = slug.match(/-([^-]+)$/);
    if (numM) return numM[1];
    return slug;
  }

  if (filmMatch || movieLegacy) {
    const slug = (filmMatch || movieLegacy)[1];
    const id   = idFromSlug(slug);
    if (id) {
      try {
        const movie = await apiFetch('/api/movies/' + id);
        if (movie && movie.id) { openMovie(movie.id); return; }
      } catch(e) {}
    }
    navigate('movies', false);
    return;
  }

  if (blogMatch) {
    const slug = blogMatch[1];
    const id   = idFromSlug(slug);
    if (id) {
      try {
        const blog = await apiFetch('/api/blogs/' + id);
        if (blog && blog.id) { openBlog(blog.id); return; }
      } catch(e) {}
    }
    navigate('blog', false);
    return;
  }

  if (eventMatch) {
    // Events have no dedicated detail page — navigate to the events list.
    // Then scroll to & highlight the matching event card.
    const slug = eventMatch[1];
    const id   = idFromSlug(slug);
    navigate('events', false);
    if (id) {
      setTimeout(() => {
        const card = document.querySelector(`[data-event-id="${id}"]`);
        if (card) {
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
          card.classList.add('event-highlight');
          setTimeout(() => card.classList.remove('event-highlight'), 2000);
        }
      }, 800);
    }
    return;
  }

  navigate(path, false);
}

document.querySelectorAll('.modal-overlay').forEach(overlay=>{
  overlay.addEventListener('click', e=>{
    if (e.target === overlay) overlay.classList.remove('open');
  });
});

// ── DELEGATED CLICK HANDLER — no UUIDs in HTML ───────────────────────────
document.addEventListener('click', function(e) {
  // Member profile open (crew names, cast tags, member cards, member rows)
  const memberEl = e.target.closest('[data-member-idx]');
  if (memberEl) {
    const idx = parseInt(memberEl.dataset.memberIdx, 10);
    const member = window._memberRegistry && window._memberRegistry[idx];
    if (member) openMemberProfile(member);
    return;
  }
  // Movie open from member profile film grid
  const filmEl = e.target.closest('[data-open-movie]');
  if (filmEl) {
    const id = filmEl.dataset.openMovie;
    closeMemberProfile();
    openMovie(id);
    return;
  }
  // Movie card click (films grid)
  const movieCard = e.target.closest('[data-movie-id]');
  if (movieCard && !e.target.closest('[data-watch-id]')) {
    openMovie(movieCard.dataset.movieId);
    return;
  }
  // Watchlist badge click
  const watchEl = e.target.closest('[data-watch-id]');
  if (watchEl) {
    e.stopPropagation();
    const id = watchEl.dataset.watchId;
    const card = watchEl.closest('.movie-card');
    toggleWatchStatusCard(id, card);
    return;
  }
});

// Fetch wrapped config early so the nav link is hidden/shown on every page,
// not just when the user visits the Wrapped section.
// Store the promise so checkRoute can await it before deciding whether to show wrapped.
const _wrappedNavReady = (async function initWrappedNav() {
  try {
    const config = await apiFetch('/api/wrapped/config').catch(() => null);
    if (config) _wrappedConfig = config;
    const wrappedNavLink = document.querySelector('[data-page="wrapped"]')?.parentElement;
    if (wrappedNavLink) {
      wrappedNavLink.style.display = (_wrappedConfig.enabled === false) ? 'none' : '';
    }
  } catch(e) { /* silently ignore — nav defaults to visible */ }
})();

// The wrapped page is hidden via display:none in HTML and revealed by checkRoute after config loads.

checkRoute();
setTimeout(() => document.body.classList.add('loaded'), 600);

// ── EVENT COUNTDOWN POPUP ──


// ── NOTIFICATIONS ──────────────────────────────────────────────────────
let allNotifications = [];

async function loadNotifications() {
  try {
    const res = await fetch('/api/settings');
    const data = await res.json();
    // /api/settings returns a plain object {key: value, ...}
    const raw = data && data.notifications;
    allNotifications = raw ? JSON.parse(raw) : [];
  } catch(e) { allNotifications = []; }
  renderNotifTable();

}

function renderNotifTable() {
  const tbody = document.getElementById('notif-tbody');
  if (!tbody) return;
  if (!allNotifications.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:40px">No notifications yet.<\/td><\/tr>';
    return;
  }
  const typeLabels = {announcement:'Announcement',achievement:'Achievement',film:'Film',event:'Event'};
  tbody.innerHTML = allNotifications.map((n,i) => `
    <tr>
      <td style="font-weight:600">${n.title}<\/td>
      <td>${typeLabels[n.type]||n.type}<\/td>
      <td style="color:var(--grey);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${n.message||''}<\/td>
      <td><span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.06em;background:${n.active?'rgba(255,255,255,.12)':'rgba(255,255,255,.04)'};color:${n.active?'#f5f5f5':'#888'}">${n.active?'ACTIVE':'OFF'}<\/span><\/td>
      <td><div class="action-btns">
        <button class="btn-edit" onclick="openNotifModal(${i})">Edit<\/button>
        <button class="btn-delete" onclick="deleteNotif(${i})">Delete<\/button>
      <\/div><\/td>
    <\/tr>`).join('');
}

function openNotifModal(idx) {
  const modal = document.getElementById('notif-modal-overlay');
  modal.classList.add('open');
  if (idx !== undefined) {
    const n = allNotifications[idx];
    document.getElementById('notif-modal-title').textContent = 'Edit Notification';
    document.getElementById('notif-id').value = idx;
    document.getElementById('notif-title').value = n.title||'';
    document.getElementById('notif-type').value = n.type||'announcement';
    document.getElementById('notif-message').value = n.message||'';
    document.getElementById('notif-btn-text').value = n.btnText||'';
    document.getElementById('notif-btn-page').value = n.btnPage||'';
    document.getElementById('notif-active').checked = !!n.active;
  } else {
    document.getElementById('notif-modal-title').textContent = 'New Notification';
    document.getElementById('notif-id').value = '';
    document.getElementById('notif-title').value = '';
    document.getElementById('notif-type').value = 'announcement';
    document.getElementById('notif-message').value = '';
    document.getElementById('notif-btn-text').value = '';
    document.getElementById('notif-btn-page').value = '';
    document.getElementById('notif-active').checked = true;
  }
}
function closeNotifModal() {
  document.getElementById('notif-modal-overlay').classList.remove('open');
}
async function saveNotif() {
  const idx = document.getElementById('notif-id').value;
  const notif = {
    title: document.getElementById('notif-title').value.trim(),
    type: document.getElementById('notif-type').value,
    message: document.getElementById('notif-message').value.trim(),
    btnText: document.getElementById('notif-btn-text').value.trim(),
    btnPage: document.getElementById('notif-btn-page').value,
    active: document.getElementById('notif-active').checked,
  };
  if (!notif.title) { alert('Title is required'); return; }
  if (idx !== '') allNotifications[parseInt(idx)] = notif;
  else allNotifications.push(notif);
  await saveNotifToServer();
  closeNotifModal();
  renderNotifTable();
  // Show a live preview popup so admin can see it immediately
  if (notif.active) {
    const typeIcons = {announcement:'',achievement:'',film:'',event:''};
    const overlay = document.createElement('div');
    overlay.className = 'notif-popup-overlay';
    overlay.innerHTML = `
      <div class="notif-popup-box">
        <div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:#666;margin-bottom:8px">PREVIEW<\/div>
        <div class="ep-label">${(notif.type||'').charAt(0).toUpperCase()+(notif.type||'').slice(1)}<\/div>
        <div class="ep-title" style="font-size:20px;margin-bottom:10px;line-height:1.3">${notif.title}<\/div>
        ${notif.message ? `<div style="font-size:13px;color:#888;line-height:1.6;margin-bottom:20px">${notif.message}<\/div>` : ''}
        <div class="ep-actions">
          ${notif.btnText ? `<button class="ep-btn-primary">${notif.btnText}<\/button>` : ''}
          <button class="ep-btn-close" onclick="this.closest('.notif-popup-overlay').classList.remove('visible');setTimeout(()=>this.closest('.notif-popup-overlay').remove(),400)">Dismiss<\/button>
        <\/div>
        <button class="ep-x" onclick="this.closest('.notif-popup-overlay').classList.remove('visible');setTimeout(()=>this.closest('.notif-popup-overlay').remove(),400)">✕<\/button>
      <\/div>`;
    overlay.addEventListener('click', e => { if(e.target===overlay){overlay.classList.remove('visible');setTimeout(()=>overlay.remove(),400);} });
    document.body.appendChild(overlay);
    setTimeout(() => overlay.classList.add('visible'), 100);
  }
}
async function deleteNotif(idx) {
  if (!confirm('Delete this notification?')) return;
  allNotifications.splice(idx, 1);
  await saveNotifToServer();
  renderNotifTable();
}
async function saveNotifToServer() {
  await fetch('/api/admin/settings', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json','Authorization':'Bearer ' + (adminToken||''),'X-CSRF-Token':_csrfToken||''},
    body: JSON.stringify({ notifications: JSON.stringify(allNotifications) })
  });
}

loadNotifications();

// ── SCROLL PROGRESS BAR ──────────────────────────────────────────────
let _currentBlogId = null;
let _currentMovieShareId = null;

function updateScrollProgress() {
  const el = document.getElementById('scroll-progress');
  const blogDetail = document.getElementById('blog-detail');
  if (!blogDetail.classList.contains('active')) { hideScrollProgress(); return; }
  const scrollTop = window.scrollY;
  const docHeight = document.documentElement.scrollHeight - window.innerHeight;
  const pct = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
  el.style.width = pct + '%';
  el.classList.add('visible');
}
function hideScrollProgress() {
  const el = document.getElementById('scroll-progress');
  el.classList.remove('visible');
  el.style.width = '0%';
}
window.addEventListener('scroll', updateScrollProgress, { passive: true });

// ── SHARE BUTTON ─────────────────────────────────────────────────────
// ── DYNAMIC META TAGS (SEO + share) ─────────────────────────────────────────
// Call whenever the URL changes so og: / twitter: tags reflect the current page.
// ── Dynamic JSON-LD schema injection ─────────────────────────────────────────
// Injects/replaces a page-level schema block so Google sees the right structured
// data for each film, blog post, or section — not just the static Organization schema.
function injectPageSchema(schemaObj) {
  const SCHEMA_ID = 'kfs-page-schema';
  let el = document.getElementById(SCHEMA_ID);
  if (!el) {
    el = document.createElement('script');
    el.type = 'application/ld+json';
    el.id = SCHEMA_ID;
    document.head.appendChild(el);
  }
  el.textContent = JSON.stringify(schemaObj);
}

function removePageSchema() {
  const el = document.getElementById('kfs-page-schema');
  if (el) el.remove();
}

function updateMetaTags({ title, description, image, url }) {
  const BASE = 'https://kiitfilmsociety.in';
  const fullUrl = url.startsWith('http') ? url : BASE + url;
  const fullImg = image ? (image.startsWith('http') ? image : BASE + image) : BASE + '/images/og-banner.png';

  // <title>
  document.title = title + ' — KFS | KIIT Film Society';

  // canonical
  let canon = document.querySelector('link[rel="canonical"]');
  if (!canon) { canon = document.createElement('link'); canon.rel = 'canonical'; document.head.appendChild(canon); }
  canon.href = fullUrl;

  // og tags — also update og:type (article for blogs/films, website for sections)
  const ogType = (url.includes('/blog/') || url.includes('/films/')) ? 'article' : 'website';
  const ogMeta = {
    'og:title': title,
    'og:description': description,
    'og:image': fullImg,
    'og:image:width': '1200',
    'og:image:height': '630',
    'og:url': fullUrl,
    'og:type': ogType,
  };
  for (const [prop, content] of Object.entries(ogMeta)) {
    let el = document.querySelector(`meta[property="${prop}"]`);
    if (!el) { el = document.createElement('meta'); el.setAttribute('property', prop); document.head.appendChild(el); }
    el.setAttribute('content', content);
  }

  // twitter tags
  const twMeta = { 'twitter:title': title, 'twitter:description': description, 'twitter:image': fullImg, 'twitter:url': fullUrl };
  for (const [name, content] of Object.entries(twMeta)) {
    let el = document.querySelector(`meta[name="${name}"]`);
    if (!el) { el = document.createElement('meta'); el.setAttribute('name', name); document.head.appendChild(el); }
    el.setAttribute('content', content);
  }

  // description
  let desc = document.querySelector('meta[name="description"]');
  if (!desc) { desc = document.createElement('meta'); desc.setAttribute('name', 'description'); document.head.appendChild(desc); }
  desc.setAttribute('content', description);
}

async function shareContent(type) {
  if (type === 'blog') {
    const id      = window._currentBlogId;
    const title   = document.getElementById('blog-detail-title')?.textContent || 'KFS Blog';
    const excerpt = window._currentBlogExcerpt || '';
    const cover   = window._currentBlogCover || document.getElementById('blog-detail-img')?.src || '';
    if (id) { shareBlogCard(id, title, excerpt, cover); return; }
    _copyShareFallback(window.location.href);
  } else {
    const id    = window._currentMovieId;
    const title = document.getElementById('movie-detail-title')?.textContent || 'KFS Film';
    const desc  = document.getElementById('movie-detail-description')?.textContent || '';
    if (!id) { _copyShareFallback(window.location.href); return; }

    const movieData = _gatherCurrentMovieData();
    const pageUrl   = movieData.pageUrl;
    const shareText = desc
      ? `"${title}" — a film by KFS | KIIT Film Society\n${desc.slice(0,120)}${desc.length>120?'…':''}`
      : `"${title}" — a film by KFS | KIIT Film Society`;

    // Try to share with the story card image (so the recipient sees a rich preview)
    if (navigator.share && navigator.canShare) {
      try {
        const blob = await _renderStoryCardBlob(movieData);
        const slug = title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
        const file = new File([blob], `kfs-${slug}.png`, { type: 'image/png' });
        if (navigator.canShare({ files: [file] })) {
          await navigator.share({ title: title + ' — KFS', text: shareText, url: pageUrl, files: [file] });
          return;
        }
      } catch(e) { /* fall through to text-only share */ }
    }
    // Text-only share (desktop or unsupported)
    if (navigator.share) {
      navigator.share({ title: title + ' — KFS', text: shareText, url: pageUrl }).catch(()=>{});
    } else {
      _copyShareFallback(pageUrl);
    }
  }
}

// ── KONFETTI ─────────────────────────────────────────────────────────
function launchKonfetti() {
  const colors = ['#ffffff','#cccccc','#888888','#f5f5f5','#444444','#aaaaaa'];
  const count = 80;
  for (let i = 0; i < count; i++) {
    const el = document.createElement('div');
    el.className = 'konfetti-particle';
    const size = 6 + Math.random() * 8;
    el.style.cssText = [
      'left:' + (Math.random() * 100) + 'vw',
      'top:-20px',
      'width:' + size + 'px',
      'height:' + (size * (Math.random() < 0.5 ? 1 : 2.5)) + 'px',
      'background:' + colors[Math.floor(Math.random() * colors.length)],
      'border-radius:' + (Math.random() < 0.4 ? '50%' : '1px'),
      'animation-duration:' + (1.2 + Math.random() * 1.8) + 's',
      'animation-delay:' + (Math.random() * 0.5) + 's',
    ].join(';');
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }
}

// ── TRAILER FUNCTIONS ────────────────────────────────────────────────
function openTrailer() {
  const url = window._currentTrailerUrl;
  if (!url) return;
  let embedUrl = url;
  const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  if (ytMatch) embedUrl = 'https://www.youtube.com/embed/' + ytMatch[1] + '?autoplay=1&rel=0';
  document.getElementById('trailer-iframe').src = embedUrl;
  document.getElementById('trailer-modal-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeTrailer() {
  document.getElementById('trailer-modal-overlay').classList.remove('open');
  document.getElementById('trailer-iframe').src = '';
  document.body.style.overflow = '';
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('trailer-modal-overlay').classList.contains('open')) closeTrailer();
});

// ── ADMIN MEMBER SEARCH ──────────────────────────────────────────────

// ── MEMBER FILTER + SEARCH ────────────────────────────────────────────────────

function renderAdminMembersTable(members) {
  const tbody = document.getElementById('admin-members-tbody');
  if (!tbody) return;
  if (!members || !members.length) {
    tbody.innerHTML = `<tr id="member-search-empty"><td colspan="7" style="text-align:center;padding:40px;color:var(--grey)">No members match your filters<\/td><\/tr>`;
    document.getElementById('mf-result-count').textContent = '';
    return;
  }
  tbody.innerHTML = members.map(m => {
    const mJson = JSON.stringify(m).replace(/"/g,'&quot;');
    const portalStatus = m.portal_status || 'none'; // 'active' | 'disabled' | 'none'
    return `<tr data-id="${m.id}" data-batch="${(m.batch||'').toLowerCase()}" data-role="${(m.role||'').toLowerCase()}" data-status="${m.is_past?'alumni':'current'}" data-portal="${portalStatus}">
      <td><input type="checkbox" class="bulk-cb" data-id="${m.id}" onchange="updateBulkBar('members')"><\/td>
      <td>${m.photo?`<img src="${m.photo}" alt="" style="border-radius:50%">`:svgPerson(16)}<\/td>
      <td style="font-weight:500">${m.name}<\/td>
      <td style="color:var(--grey)">${m.role||'—'}<\/td>
      <td style="color:var(--grey)">${m.batch||'—'}<\/td>
      <td><span class="tag ${m.is_past?'':'upcoming'}">${m.is_past?'Alumni':'Current'}<\/span><\/td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editMember(${mJson})">Edit<\/button>
        <button class="btn-sm" onclick="openMemberPortalModal(${mJson})" style="background:rgba(99,102,241,.15);color:#818cf8;border-color:#4f46e533">Portal<\/button>
        <button class="btn-sm danger" onclick="deleteMember('${m.id}')">Delete<\/button>
      <\/div><\/td>
    <\/tr>`;
  }).join('');
  clearBulkSelect('members');
}

function filterAdminMembers() {
  const q        = (document.getElementById('member-admin-search')?.value || '').trim().toLowerCase();
  const batch    = (document.getElementById('mf-batch')?.value || '').toLowerCase();
  const role     = (document.getElementById('mf-role')?.value || '').toLowerCase();
  const status   = document.getElementById('mf-status')?.value || '';
  const portal   = document.getElementById('mf-portal')?.value || '';

  // Update clear button visibility
  const clearBtn = document.getElementById('member-search-clear-btn');
  if (clearBtn) clearBtn.classList.toggle('visible', q.length > 0);

  // Mark dropdowns as active
  ['mf-batch','mf-role','mf-status','mf-portal'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('active', !!el.value);
  });

  // Show/hide reset button
  const hasFilters = q || batch || role || status || portal;
  const resetBtn = document.getElementById('mf-reset-btn');
  if (resetBtn) resetBtn.classList.toggle('visible', !!hasFilters);

  const all = window._allAdminMembers || [];
  if (!all.length) return;

  const filtered = all.filter(m => {
    if (q) {
      const haystack = [m.name, m.role, m.batch, m.domain, m.bio, m.special_tag].filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    if (batch && (m.batch||'').toLowerCase() !== batch) return false;
    if (role  && (m.role||'').toLowerCase()  !== role)  return false;
    if (status === 'current' &&  m.is_past) return false;
    if (status === 'alumni'  && !m.is_past) return false;
    if (portal) {
      const ps = m.portal_status || 'none';
      if (ps !== portal) return false;
    }
    return true;
  });

  renderAdminMembersTable(filtered);

  // Update result count
  const countEl = document.getElementById('mf-result-count');
  if (countEl) {
    countEl.textContent = hasFilters ? `${filtered.length} of ${all.length}` : '';
  }
}

function clearMemberSearch() {
  const searchEl = document.getElementById('member-admin-search');
  if (searchEl) searchEl.value = '';
  filterAdminMembers();
  searchEl?.focus();
}

function resetMemberFilters() {
  const searchEl = document.getElementById('member-admin-search');
  if (searchEl) searchEl.value = '';
  ['mf-batch','mf-role','mf-status','mf-portal'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.value = ''; el.classList.remove('active'); }
  });
  const resetBtn = document.getElementById('mf-reset-btn');
  if (resetBtn) resetBtn.classList.remove('visible');
  const clearBtn = document.getElementById('member-search-clear-btn');
  if (clearBtn) clearBtn.classList.remove('visible');
  const countEl = document.getElementById('mf-result-count');
  if (countEl) countEl.textContent = '';
  renderAdminMembersTable(window._allAdminMembers || []);
}

// ── BULK MEMBER ACTIONS ───────────────────────────────────────────────────────

async function bulkMemberPortalAction(action) {
  const checked = [...document.querySelectorAll('#section-members .bulk-cb:checked')];
  if (!checked.length) return;
  const ids = checked.map(cb => cb.dataset.id);
  const label = action === 'enable' ? 'Enable' : 'Disable';
  const confirmed = await showConfirmModal(
    `${label} portal access for ${ids.length} member${ids.length>1?'s':''}?`,
    null, null, label, 'Cancel', action === 'disable' ? 'danger' : 'accent'
  );
  if (!confirmed) return;
  let done = 0, failed = 0;
  await Promise.all(ids.map(async id => {
    try {
      // Fetch current status then toggle only if needed
      const acc = await apiFetch(`/api/admin/members/${id}/account`);
      const currentStatus = acc?.account_status;
      const needsToggle = (action === 'enable' && currentStatus !== 'active') ||
                          (action === 'disable' && currentStatus === 'active');
      if (acc && needsToggle) {
        await apiFetch(`/api/admin/members/${id}/account/toggle-status`, 'POST');
      }
      // Update the cached portal_status
      const m = window._allAdminMembers?.find(x => x.id === id);
      if (m) m.portal_status = acc ? (action === 'enable' ? 'active' : 'disabled') : 'none';
      done++;
    } catch { failed++; }
  }));
  clearBulkSelect('members');
  filterAdminMembers();
  localStorage.setItem('kfs_admin_data_change', Date.now().toString());
  if (typeof showToast === 'function') showToast(`${done} portal${done>1?'s':''} ${action}d${failed?' ('+failed+' failed)':''}`, done > 0 ? 'success' : 'error');
}

async function bulkAssignBatch() {
  const checked = [...document.querySelectorAll('#section-members .bulk-cb:checked')];
  if (!checked.length) return;
  const ids = checked.map(cb => cb.dataset.id);

  // Build a small inline prompt modal for the batch value
  const existing = document.getElementById('kfs-batch-assign-modal');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'kfs-batch-assign-modal';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:10000';
  overlay.innerHTML = `
    <div style="background:#111;border:1px solid #222;border-radius:16px;padding:28px;width:340px;box-shadow:0 24px 60px rgba(0,0,0,.5)">
      <div style="font-size:16px;font-weight:700;color:#f5f5f5;margin-bottom:6px">Assign Batch</div>
      <div style="font-size:13px;color:#666;margin-bottom:20px">Assign a batch to ${ids.length} selected member${ids.length>1?'s':''}</div>
      <input id="batch-assign-input" type="text" placeholder="e.g. 2024–28" style="width:100%;background:#0d0d0d;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 13px;border-radius:10px;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box;margin-bottom:16px" />
      <div style="display:flex;gap:8px">
        <button onclick="document.getElementById('kfs-batch-assign-modal').remove()" style="flex:1;background:transparent;border:1px solid #222;color:#888;border-radius:10px;padding:10px;font-size:13px;font-family:inherit;cursor:pointer">Cancel</button>
        <button id="batch-assign-confirm-btn" style="flex:1;background:#f5f5f5;color:#0a0a0a;border:none;border-radius:10px;padding:10px;font-size:13px;font-weight:700;font-family:inherit;cursor:pointer">Assign</button>
      </div>
      <div id="batch-assign-err" style="font-size:12px;color:#ef4444;margin-top:10px;display:none"></div>
    </div>`;
  document.body.appendChild(overlay);
  const input = document.getElementById('batch-assign-input');
  input.focus();

  document.getElementById('batch-assign-confirm-btn').onclick = async () => {
    const batch = input.value.trim();
    if (!batch) { const e=document.getElementById('batch-assign-err'); e.textContent='Please enter a batch'; e.style.display='block'; return; }
    overlay.remove();
    let done = 0;
    await Promise.all(ids.map(async id => {
      try {
        const fd = new FormData();
        const m = window._allAdminMembers?.find(x => x.id === id);
        if (m) { Object.entries(m).forEach(([k,v]) => { if (v !== null && v !== undefined && k !== 'id') fd.append(k, v); }); }
        fd.set('batch', batch);
        await fetch(`/api/admin/members/${id}`, { method:'PUT', credentials:'include',
          headers:{ 'Authorization':'Bearer '+adminToken, 'X-CSRF-Token':_csrfToken||'' }, body:fd });
        // Update cache
        const cached = window._allAdminMembers?.find(x => x.id === id);
        if (cached) cached.batch = batch;
        done++;
      } catch {}
    }));
    clearBulkSelect('members');
    filterAdminMembers();
    if (typeof showToast === 'function') showToast(`Batch assigned to ${done} member${done>1?'s':''}`, 'success');
  };
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  input.addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('batch-assign-confirm-btn').click(); if (e.key === 'Escape') overlay.remove(); });
}

// ── ADMIN MANAGEMENT (master only) ───────────────────────────────────
function openAddAdminModal() {
  document.getElementById('new-admin-name').value = '';
  document.getElementById('new-admin-username').value = '';
  document.getElementById('new-admin-password').value = '';
  document.getElementById('add-admin-error').textContent = '';
  document.querySelectorAll('.new-admin-perm').forEach(cb => cb.checked = true);
  document.getElementById('add-admin-modal').classList.add('open');
}

function closeAddAdminModal() {
  document.getElementById('add-admin-modal').classList.remove('open');
}

async function saveNewAdmin() {
  const name = document.getElementById('new-admin-name').value.trim();
  const username = document.getElementById('new-admin-username').value.trim().toLowerCase();
  const password = document.getElementById('new-admin-password').value;
  const permissions = Array.from(document.querySelectorAll('.new-admin-perm:checked')).map(cb => cb.value);
  const errEl = document.getElementById('add-admin-error');
  const btn = document.querySelector('#add-admin-modal .btn-primary');
  if (!name || !username || !password) { errEl.textContent = 'All fields are required.'; return; }
  if (password.length < 6) { errEl.textContent = 'Password must be at least 6 characters.'; return; }
  errEl.textContent = '';
  if (btn) { btn.disabled = true; btn.textContent = 'Creating...'; }
  try {
    // Use a direct fetch so we always get the response body even on 4xx
    const rawRes = await fetch('/api/master/admins', {
      method: 'POST', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify({ name, username, password, permissions })
    });
    const data = await rawRes.json().catch(() => ({}));
    if (rawRes.ok && data.id) {
      closeAddAdminModal();
      loadAdminData('admins');
    } else if (rawRes.status === 401) {
      // Access token expired — refresh and retry once
      const refreshRes = await fetch('/api/admin/refresh', {
        method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': _csrfToken || '' }
      });
      const refreshData = await refreshRes.json().catch(() => ({}));
      if (refreshData.token && refreshData.role === 'master') {
        adminToken = refreshData.token; // memory only
        currentAdminRole = 'master';
        localStorage.setItem('kfs_role', 'master');
        // Retry with fresh token
        const retry = await fetch('/api/master/admins', {
          method: 'POST', credentials: 'include',
          headers: { 'Authorization': 'Bearer ' + adminToken, 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
          body: JSON.stringify({ name, username, password, permissions })
        });
        const retryData = await retry.json().catch(() => ({}));
        if (retry.ok && retryData.id) {
          closeAddAdminModal();
          loadAdminData('admins');
        } else {
          errEl.textContent = retryData.error || 'Failed to create admin after token refresh.';
        }
      } else {
        errEl.textContent = 'Session expired. Please log out and log back in.';
      }
    } else {
      errEl.textContent = data.error || 'Failed to create admin.';
    }
  } catch(e) {
    errEl.textContent = 'Network error: ' + e.message;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Create Admin'; }
  }
}

function openEditPermsModal(id) {
  const allAdminRows = document.querySelectorAll('#admins-tbody tr');
  // Get admin name from the table row
  let adminName = '';
  allAdminRows.forEach(row => {
    const btn = row.querySelector('.perm-btn');
    if (btn && btn.getAttribute('onclick').includes("'" + id + "'")) {
      adminName = row.cells[0].textContent;
    }
  });
  document.getElementById('edit-perms-admin-id').value = id;
  document.getElementById('edit-perms-admin-name').textContent = adminName;
  document.getElementById('edit-perms-error').textContent = '';
  const permsArr = (window._adminPermsMap && window._adminPermsMap[id]) || [];
  document.querySelectorAll('.edit-perm-cb').forEach(cb => {
    cb.checked = permsArr.length === 0 || permsArr.includes(cb.value);
  });
  document.getElementById('edit-perms-modal').classList.add('open');
}

function closeEditPermsModal() {
  document.getElementById('edit-perms-modal').classList.remove('open');
}

async function savePermissions() {
  const id = document.getElementById('edit-perms-admin-id').value;
  const permissions = Array.from(document.querySelectorAll('.edit-perm-cb:checked')).map(cb => cb.value);
  const errEl = document.getElementById('edit-perms-error');
  const btn = document.getElementById('save-perms-btn');
  errEl.textContent = '';
  btn.disabled = true; btn.textContent = 'Saving...';
  try {
    const res = await fetch('/api/master/admins/' + id + '/permissions', {
      method: 'PUT', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify({ permissions })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      closeEditPermsModal();
      loadAdminData('admins');
      if (typeof showToast === 'function') showToast('Permissions updated', 'success');
    } else {
      errEl.textContent = data.error || 'Failed to update permissions.';
    }
  } catch(e) {
    errEl.textContent = 'Network error: ' + e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'Save Permissions';
  }
}

async function deleteAdmin(id, name) {
  if (!confirm(`Remove admin "${name}"? They will no longer be able to log in.`)) return;
  const res = await apiFetch('/api/master/admins/' + id, 'DELETE');
  if (res && res.success) {
    loadAdminData('admins');
    if (typeof showToast === 'function') showToast(`Admin "${name}" removed`, 'success');
  } else {
    if (typeof showToast === 'function') showToast('Failed to remove admin', 'error');
  }
}

async function undoActivity(activityId) {
  const res = await apiFetch(`/api/master/activity/${activityId}/undo`, 'POST');
  if (res && res.success) {
    if (typeof showToast === 'function') showToast('Restored successfully', 'success');
    loadAdminData('activity');
  } else {
    if (typeof showToast === 'function') showToast(res?.error || 'Could not undo', 'error');
  }
}

function openResetPasswordModal(adminId, adminName) {
  document.getElementById('reset-pw-admin-id').value = adminId;
  document.getElementById('reset-pw-admin-name').textContent = adminName;
  document.getElementById('reset-pw-input').value = '';
  document.getElementById('reset-pw-error').textContent = '';
  document.getElementById('reset-password-modal').classList.add('open');
  setTimeout(() => document.getElementById('reset-pw-input').focus(), 80);
}

async function submitResetPassword() {
  const id = document.getElementById('reset-pw-admin-id').value;
  const pw = document.getElementById('reset-pw-input').value;
  const errEl = document.getElementById('reset-pw-error');
  errEl.textContent = '';
  if (!pw) { errEl.textContent = 'Enter a new password.'; return; }
  const res = await apiFetch(`/api/master/admins/${id}/reset-password`, 'PUT', { password: pw });
  if (res && res.success) {
    document.getElementById('reset-password-modal').classList.remove('open');
    if (typeof showToast === 'function') showToast('Password reset — admin will need to log in again.', 'success');
  } else {
    errEl.textContent = res?.error || 'Failed to reset password.';
  }
}

// ── BULK DELETE ──────────────────────────────────────────────────────
function updateBulkBar(section) {
  const checked = document.querySelectorAll(`#section-${section} .bulk-cb:checked`);
  const bar = document.getElementById(`bulk-bar-${section}`);
  const countEl = document.getElementById(`bulk-count-${section}`);
  if (!bar) return;
  if (checked.length > 0) {
    bar.style.display = 'flex';
    countEl.textContent = checked.length + ' selected';
  } else {
    bar.style.display = 'none';
  }
}

function selectAllBulk(section, checked) {
  document.querySelectorAll(`#section-${section} .bulk-cb`).forEach(cb => cb.checked = checked);
  updateBulkBar(section);
}

function clearBulkSelect(section) {
  document.querySelectorAll(`#section-${section} .bulk-cb`).forEach(cb => cb.checked = false);
  const masterCb = document.getElementById(`bulk-select-all-${section}`);
  if (masterCb) masterCb.checked = false;
  updateBulkBar(section);
}

async function bulkDelete(section) {
  const checked = [...document.querySelectorAll(`#section-${section} .bulk-cb:checked`)];
  if (!checked.length) return;
  if (!confirm(`Delete ${checked.length} item(s)? This cannot be undone.`)) return;
  const apiMap = { blogs: '/api/admin/blogs/', movies: '/api/admin/movies/', members: '/api/admin/members/' };
  const base = apiMap[section];
  if (!base) return;
  const ids = checked.map(cb => cb.dataset.id);
  await Promise.all(ids.map(id => apiFetch(base + id, 'DELETE')));
  clearBulkSelect(section);
  loadAdminData(section);
  // Show toast if available
  if (typeof showToast === 'function') showToast(`${ids.length} item(s) deleted`, 'success');
}
// ── EVENT THEMES ADMIN ───────────────────────────────────────────────

async function loadThemes() {
  const themes = await apiFetch('/api/admin/themes');
  const grid = document.getElementById('themes-list-grid');
  if (!grid) return;
  if (!themes || !themes.length) {
    grid.innerHTML = '<p style="color:var(--grey);padding:40px 0;text-align:center">No themes yet. Create your first event theme.</p>';
    return;
  }
  const now = new Date();
  grid.innerHTML = themes.map(t => { const tJson=JSON.stringify(t).replace(/"/g,'&quot;');
    const isLive = t.is_active && (!t.active_until || new Date(t.active_until) > now);
    const isScheduled = !t.is_active && t.active_from && new Date(t.active_from) > now;
    const badge = isLive
      ? `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#22c55e;font-size:10px;font-weight:700;letter-spacing:.08em"><span style="width:6px;height:6px;border-radius:50%;background:#22c55e;box-shadow:0 0 6px #22c55e"></span>LIVE</span>`
      : isScheduled
      ? `<span style="padding:3px 10px;border-radius:20px;background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.3);color:#fbbf24;font-size:10px;font-weight:700;letter-spacing:.08em">SCHEDULED</span>`
      : `<span style="padding:3px 10px;border-radius:20px;background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--grey);font-size:10px;font-weight:700;letter-spacing:.08em">INACTIVE</span>`;
    const swatches = [t.bg_color, t.accent_color, t.card_color, t.border_color, t.text_color].map(c =>
      `<span title="${c||'default'}" style="display:inline-block;width:18px;height:18px;border-radius:50%;background:${c||'var(--border)'};border:1px solid rgba(255,255,255,.15);flex-shrink:0"></span>`
    ).join('');
    const dates = (t.active_from || t.active_until)
      ? `<div style="font-size:11px;color:var(--grey);margin-top:6px">${t.active_from?'From '+new Date(t.active_from).toLocaleDateString('en-IN'):''} ${t.active_until?'→ Until '+new Date(t.active_until).toLocaleDateString('en-IN'):''}</div>`
      : '';
    return `<div style="background:var(--card);border:1px solid ${isLive?'rgba(34,197,94,.3)':'var(--border)'};border-radius:14px;padding:18px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div style="flex:1;min-width:180px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="font-size:15px;font-weight:700">${t.name}</span>
          ${badge}
        </div>
        <div style="display:flex;gap:5px;align-items:center;margin-bottom:4px">${swatches}</div>
        ${t.font_family?`<div style="font-size:11px;color:var(--grey)">Font: ${t.font_family}</div>`:''}
        ${dates}
      </div>
      <div style="display:flex;gap:8px;flex-shrink:0;flex-wrap:wrap">
        <button class="btn-sm" onclick="toggleThemeActive('${t.id}',${!t.is_active})" style="${isLive?'background:rgba(231,76,60,.1);border-color:#e74c3c;color:#e74c3c':''}">${isLive?'Deactivate':'Activate'}</button>
        <button class="btn-sm" onclick="openThemeEditor(${tJson})">Edit</button>
        <button class="btn-sm btn-danger" onclick="deleteTheme('${t.id}','${t.name.replace(/'/g,'\\x27')}')">Delete</button>
      </div>
    </div>`;
  }).join('');
}

async function toggleThemeActive(id, activate) {
  const ok = await apiFetch(`/api/admin/themes/${id}`, 'PUT', { is_active: activate });
  if (ok) {
    if (!activate) removeActiveThemeFromPage();
    loadThemes();
  }
}

async function deleteTheme(id, name) {
  if (!confirm(`Delete theme "${name}"?`)) return;
  const res = await apiFetch(`/api/admin/themes/${id}`, 'DELETE');
  if (res && res.success) {
    removeActiveThemeFromPage();
    loadThemes();
  }
}

function removeActiveThemeFromPage() {
  const el = document.getElementById('event-theme-vars');
  if (el) el.remove();
  // Remove dynamically injected font override styles
  document.querySelectorAll('head style:not([id])').forEach(s => {
    if (s.textContent.includes('font-family') && s.textContent.includes('!important')) s.remove();
  });
  // Remove dynamically injected font links (not the static preconnect ones)
  document.querySelectorAll('head link[rel=stylesheet][href*="fonts.googleapis"]').forEach(l => {
    if (!l.dataset.static) l.remove();
  });
  window.__kfsEventTheme = null;
}

function openThemeEditor(theme) {
  document.getElementById('themes-list-view').style.display = 'none';
  document.getElementById('themes-editor-view').style.display = 'block';
  document.getElementById('theme-editor-title').textContent = theme ? 'Edit Theme' : 'New Theme';
  document.getElementById('te-id').value = theme ? theme.id : '';
  document.getElementById('te-name').value = theme ? theme.name : '';
  setColorField('te-bg', theme ? theme.bg_color : '#0a0a0a');
  setColorField('te-text', theme ? theme.text_color : '#f5f5f5');
  setColorField('te-accent', theme ? theme.accent_color : '#f5f5f5');
  setColorField('te-card', theme ? theme.card_color : '#111111');
  setColorField('te-border', theme ? theme.border_color : '#1e1e1e');
  setColorField('te-grey', theme ? theme.grey_color : '#888888');
  setColorField('te-banner-bg', theme ? theme.banner_bg : '#e63946');
  setColorField('te-banner-text', theme ? theme.banner_text_color : '#ffffff');
  document.getElementById('te-font').value = theme ? (theme.font_family || '') : '';
  document.getElementById('te-hero-title').value = theme ? (theme.hero_title || '') : '';
  document.getElementById('te-hero-tagline').value = theme ? (theme.hero_tagline || '') : '';
  document.getElementById('te-banner-msg').value = theme ? (theme.banner_message || '') : '';
  document.getElementById('te-logo-url').value = theme ? (theme.logo_url || '') : '';
  document.getElementById('te-from').value = theme && theme.active_from ? theme.active_from.slice(0,16) : '';
  document.getElementById('te-until').value = theme && theme.active_until ? theme.active_until.slice(0,16) : '';
  document.getElementById('te-activate-now').checked = theme ? !!theme.is_active : false;
  const err = document.getElementById('te-error');
  if (err) { err.textContent = ''; err.style.display = 'none'; }
  updateThemePreview();
}

function setColorField(id, value) {
  const picker = document.getElementById(id);
  const hex = document.getElementById(id + '-hex');
  if (picker) picker.value = value || '#000000';
  if (hex) hex.value = value || '';
}

function syncColorFromHex(pickerId, hexId) {
  const hex = document.getElementById(hexId).value.trim();
  if (/^#[0-9a-fA-F]{6}$/.test(hex)) {
    document.getElementById(pickerId).value = hex;
    updateThemePreview();
  }
}

function updateThemePreview() {
  const g = id => document.getElementById(id)?.value || '';
  const bg = g('te-bg') || '#0a0a0a';
  const text = g('te-text') || '#f5f5f5';
  const accent = g('te-accent') || '#f5f5f5';
  const card = g('te-card') || '#111111';
  const border = g('te-border') || '#1e1e1e';
  const grey = g('te-grey') || '#888888';
  const bannerMsg = g('te-banner-msg');
  const bannerBg = g('te-banner-bg') || '#e63946';
  const bannerText = g('te-banner-text') || '#ffffff';
  // Also sync hex inputs from pickers
  ['te-bg','te-text','te-accent','te-card','te-border','te-grey','te-banner-bg','te-banner-text'].forEach(id => {
    const picker = document.getElementById(id);
    const hexEl = document.getElementById(id + '-hex');
    if (picker && hexEl && document.activeElement !== hexEl) hexEl.value = picker.value;
  });
  const box = document.getElementById('theme-preview-box');
  if (!box) return;
  box.style.background = bg;
  box.style.borderColor = border;
  const nav = document.getElementById('tp-nav');
  if (nav) { nav.style.background = bg; nav.style.borderColor = border; nav.style.color = text; nav.querySelector('div').style.color = text; }
  ['tp-nav-link1','tp-nav-link2','tp-nav-link3'].forEach(id => { const el = document.getElementById(id); if (el) el.style.color = grey; });
  const heroTitle = document.getElementById('tp-hero-title');
  if (heroTitle) { heroTitle.style.color = text; heroTitle.textContent = g('te-hero-title') || 'KIIT Film Society'; }
  const heroSub = document.getElementById('tp-hero-sub');
  if (heroSub) { heroSub.style.color = grey; heroSub.textContent = g('te-hero-tagline') || 'Lights. Camera. KFS.'; }
  const cardEl = document.getElementById('tp-card');
  if (cardEl) { cardEl.style.background = card; cardEl.style.borderColor = border; cardEl.style.color = text; }
  const cardSub = document.getElementById('tp-card-sub');
  if (cardSub) cardSub.style.color = grey;
  const btn = document.getElementById('tp-btn');
  if (btn) { btn.style.background = accent; btn.style.borderColor = accent; btn.style.color = bg; }
  const btn2 = document.getElementById('tp-btn2');
  if (btn2) { btn2.style.background = 'transparent'; btn2.style.borderColor = border; btn2.style.color = text; }
  const banner = document.getElementById('tp-banner');
  if (banner) { banner.style.display = bannerMsg ? 'block' : 'none'; banner.style.background = bannerBg; banner.style.color = bannerText; banner.textContent = bannerMsg || ''; }
}

function closeThemeEditor() {
  document.getElementById('themes-list-view').style.display = 'block';
  document.getElementById('themes-editor-view').style.display = 'none';
}

async function saveTheme(activate) {
  const id = document.getElementById('te-id').value;
  const name = document.getElementById('te-name').value.trim();
  const errEl = document.getElementById('te-error');
  if (!name) { errEl.textContent = 'Theme name is required.'; errEl.style.display = 'block'; return; }
  errEl.style.display = 'none';
  const forceActivate = activate || document.getElementById('te-activate-now').checked;
  const payload = {
    name,
    is_active: forceActivate,
    bg_color: document.getElementById('te-bg').value || null,
    text_color: document.getElementById('te-text').value || null,
    accent_color: document.getElementById('te-accent').value || null,
    card_color: document.getElementById('te-card').value || null,
    border_color: document.getElementById('te-border').value || null,
    grey_color: document.getElementById('te-grey').value || null,
    font_family: document.getElementById('te-font').value.trim() || null,
    hero_title: document.getElementById('te-hero-title').value.trim() || null,
    hero_tagline: document.getElementById('te-hero-tagline').value.trim() || null,
    banner_message: document.getElementById('te-banner-msg').value.trim() || null,
    banner_bg: document.getElementById('te-banner-bg').value || null,
    banner_text_color: document.getElementById('te-banner-text').value || null,
    logo_url: document.getElementById('te-logo-url').value.trim() || null,
    active_from: document.getElementById('te-from').value || null,
    active_until: document.getElementById('te-until').value || null,
  };
  const method = id ? 'PUT' : 'POST';
  const url = id ? `/api/admin/themes/${id}` : '/api/admin/themes';
  const res = await apiFetch(url, method, payload);
  if (res && !res.error) {
    closeThemeEditor();
    loadThemes();
  } else {
    errEl.textContent = (res && res.error) || 'Save failed.';
    errEl.style.display = 'block';
  }
}

// ══════════════════════════════════════════════════════════
// GLOBAL SEARCH
// ══════════════════════════════════════════════════════════
let searchData = { movies:[], blogs:[], events:[], members:[] };
let searchLoaded = false;

async function loadSearchData() {
  if (searchLoaded) return;
  const [movies, blogs, events, members, settings] = await Promise.all([
    apiFetch('/api/movies'), apiFetch('/api/blogs'),
    apiFetch('/api/events'), apiFetch('/api/members'),
    apiFetch('/api/settings')
  ]);
  searchData = { movies: movies||[], blogs: blogs||[], events: events||[], members: members||[] };
  if (settings && settings.easter_egg_img) window._easterEggImg = settings.easter_egg_img;
  if (settings) {
    window._eggShortsHeading  = settings.easter_egg_shorts_heading  || 'No Shorts.';
    window._eggShortsSub      = settings.easter_egg_shorts_sub      || 'we only make films that last';
    window._eggNoShortsFallback = settings.easter_egg_noshorts_fallback || "that's the spirit";
  }
  // Load custom search easter eggs
  try {
    const eggs = await apiFetch('/api/settings/custom-eggs');
    window._customSearchEggs = Array.isArray(eggs) ? eggs : [];
  } catch(e) { window._customSearchEggs = []; }
  searchLoaded = true;
}

function openSearch() {
  document.getElementById('search-overlay').classList.add('open');
  document.getElementById('search-input').value = '';
  document.getElementById('search-results').innerHTML = '';
  document.getElementById('search-input').focus();
  loadSearchData();
}

function closeSearch() {
  document.getElementById('search-overlay').classList.remove('open');
}

// ══════════════════════════════════════════════════════════
// CREW NAME HELPERS — parse "Name||memberId" format
// ══════════════════════════════════════════════════════════
function splitCrew(val) {
  // Support both new separator (;;) and legacy comma-separated data
  if (!val) return [];
  return val.includes(';;') ? val.split(';;').map(s=>s.trim()).filter(Boolean)
                             : val.split(',').map(s=>s.trim()).filter(Boolean);
}
function _memberIdx(member) {
  // Store member in a global registry and return a clean integer index
  if (!window._memberRegistry) window._memberRegistry = [];
  let idx = window._memberRegistry.findIndex(m => m.id === member.id);
  if (idx === -1) { idx = window._memberRegistry.length; window._memberRegistry.push(member); }
  return idx;
}
function renderCrewNames(val) {
  if (!val) return '';
  return splitCrew(val).map(p => {
    const [name, id] = p.trim().split('||');
    const member = id && allMembers ? allMembers.find(m=>String(m.id)===id.trim()) : null;
    if (member) {
      const idx = _memberIdx(member);
      return `<span data-member-idx="${idx}" style="cursor:pointer;text-decoration:underline;text-underline-offset:3px;text-decoration-color:#555">${name.trim()}<\/span>`;
    }
    return name.trim();
  }).join(', ');
}
function crewNameTag(part) {
  const [name, id] = part.split('||');
  const member = id && allMembers ? allMembers.find(m=>String(m.id)===id.trim()) : null;
  if (member) {
    const idx = _memberIdx(member);
    return `<span class="movie-cast-tag" data-member-idx="${idx}" style="cursor:pointer">${name.trim()}<\/span>`;
  }
  return `<span class="movie-cast-tag">${name.trim()}<\/span>`;
}

// ══════════════════════════════════════════════════════════
// MEMBER PICKER
// ══════════════════════════════════════════════════════════
class MemberPicker {
  constructor(containerId, multi=false) {
    this.container = document.getElementById(containerId);
    this.multi = multi;
    this.selected = []; // [{id, name, photo, role}]  id=null for free text
    this.render();
  }
  render() {
    this.container.innerHTML = `
      <input class="mpicker-input" placeholder="Type a name or search members…" autocomplete="off">
      <div class="mpicker-dropdown" style="display:none"><\/div>
      <div class="mpicker-tags"><\/div>`;
    this.input = this.container.querySelector('.mpicker-input');
    this.dropdown = this.container.querySelector('.mpicker-dropdown');
    this.tagsEl = this.container.querySelector('.mpicker-tags');
    this.input.addEventListener('input', ()=>this._onInput());
    this.input.addEventListener('keydown', e=>{
      if (e.key==='Enter'){ e.preventDefault(); this._addFreeText(); }
      if (e.key==='Escape') this._hideDropdown();
    });
    this.input.addEventListener('blur', ()=>setTimeout(()=>this._hideDropdown(),150));
    this._renderTags();
  }
  _onInput() {
    const q = this.input.value.trim().toLowerCase();
    if (!q) { this._hideDropdown(); return; }
    const members = allMembers || [];
    const matches = members.filter(m=>m.name.toLowerCase().includes(q)).slice(0,8);
    if (!matches.length) { this._hideDropdown(); return; }
    this.dropdown.innerHTML = matches.map(m=>`
      <div class="mpicker-opt" data-id="${m.id}">
        ${m.photo ? `<img src="${m.photo}" alt="">` : '<div class="mpicker-opt-placeholder"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/div>'}
        <span class="mpicker-opt-name">${m.name}<\/span>
        <span class="mpicker-opt-role">${m.role||''}<\/span>
      <\/div>`).join('');
    this.dropdown.querySelectorAll('.mpicker-opt').forEach(el=>{
      el.addEventListener('mousedown', e=>{ e.preventDefault(); const m=members.find(x=>x.id==el.dataset.id); if(m) this._select({id:m.id,name:m.name,photo:m.photo,role:m.role}); });
    });
    this.dropdown.style.display='block';
  }
  _addFreeText() {
    const v = this.input.value.trim();
    if (!v) return;
    this._select({id:null,name:v,photo:null,role:''});
  }
  _select(item) {
    if (!this.multi) this.selected = [];
    if (!this.selected.find(s=>s.name===item.name)) this.selected.push(item);
    this.input.value='';
    this._hideDropdown();
    this._renderTags();
  }
  _remove(name) {
    this.selected = this.selected.filter(s=>s.name!==name);
    this._renderTags();
  }
  _renderTags() {
    this.tagsEl.innerHTML = this.selected.map(s=>`
      <span class="mpicker-tag">
        ${s.photo ? `<img src="${s.photo}" alt="">` : '<span class="mpicker-tag-placeholder"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/span>'}
        <span class="mpicker-tag-name">${s.name}<\/span>
        <span class="mpicker-tag-remove" data-name="${s.name}">×<\/span>
      <\/span>`).join('');
    this.tagsEl.querySelectorAll('.mpicker-tag-remove').forEach(el=>{
      el.addEventListener('click',()=>this._remove(el.dataset.name));
    });
  }
  _hideDropdown() { this.dropdown.style.display='none'; }
  getValue() {
    // returns comma-separated names (with id suffix for linked members)
    return this.selected.map(s=>s.id ? `${s.name}||${s.id}` : s.name).join(';;');
  }
  setValue(str) {
    this.selected = [];
    if (!str) return;
    splitCrew(str).forEach(part=>{
      const [name, id] = part.split('||');
      const member = id && allMembers ? allMembers.find(m=>m.id==id) : null;
      this.selected.push(member ? {id:member.id,name:member.name,photo:member.photo,role:member.role} : {id:null,name:name.trim(),photo:null,role:''});
    });
    this._renderTags();
  }
}

// ── Collab Member Picker — members-only, no free text ─────────────────────────
class CollabMemberPicker {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.selected = null; // { id, name, photo, role }
    this._render();
  }
  _render() {
    this.container.innerHTML = `
      <div style="position:relative">
        <input class="mpicker-input" placeholder="Search KFS members…" autocomplete="off"
          style="width:100%;box-sizing:border-box">
        <div class="mpicker-dropdown" style="display:none"></div>
      </div>
      <div class="mpicker-tags" style="margin-top:6px"></div>`;
    this._input = this.container.querySelector('.mpicker-input');
    this._dd    = this.container.querySelector('.mpicker-dropdown');
    this._tags  = this.container.querySelector('.mpicker-tags');
    this._input.addEventListener('input', () => this._onInput());
    this._input.addEventListener('keydown', e => { if (e.key === 'Escape') this._hideDd(); });
    this._input.addEventListener('blur', () => setTimeout(() => this._hideDd(), 150));
    this._renderTag();
  }
  reset() { this.selected = null; this._render(); }
  _onInput() {
    const q = this._input.value.trim().toLowerCase();
    if (!q) { this._hideDd(); return; }
    const members = (allMembers || []).filter(m => !m.is_past);
    const matches = members.filter(m => m.name.toLowerCase().includes(q)).slice(0, 8);
    if (!matches.length) { this._hideDd(); return; }
    this._dd.innerHTML = matches.map(m => `
      <div class="mpicker-opt" data-id="${m.id}">
        ${m.photo ? `<img src="${m.photo}" alt="">` : '<div class="mpicker-opt-placeholder"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg></div>'}
        <span class="mpicker-opt-name">${m.name}</span>
        <span class="mpicker-opt-role">${m.role || ''}</span>
      </div>`).join('');
    this._dd.querySelectorAll('.mpicker-opt').forEach(el => {
      el.addEventListener('mousedown', e => {
        e.preventDefault();
        const m = members.find(x => x.id == el.dataset.id);
        if (m) { this.selected = { id: m.id, name: m.name, photo: m.photo, role: m.role }; this._input.value = ''; this._hideDd(); this._renderTag(); }
      });
    });
    this._dd.style.display = 'block';
  }
  _hideDd() { this._dd.style.display = 'none'; }
  _renderTag() {
    if (!this.selected) { this._tags.innerHTML = ''; return; }
    const s = this.selected;
    this._tags.innerHTML = `<span class="mpicker-tag">
      ${s.photo ? `<img src="${s.photo}" alt="">` : '<span class="mpicker-tag-placeholder"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg></span>'}
      <span class="mpicker-tag-name">${s.name}</span>
      <span class="mpicker-tag-remove" style="cursor:pointer">×</span>
    </span>`;
    this._tags.querySelector('.mpicker-tag-remove').addEventListener('click', () => {
      this.selected = null; this._renderTag();
    });
    // Show domain auto-fill hint
    if (s.role) {
      const domainSel = document.getElementById('collab-domain');
      if (domainSel && !domainSel.value && s.domain) domainSel.value = s.domain;
    }
  }
  getValue() {
    if (!this.selected) return '';
    return this.selected.id ? `${this.selected.name}||${this.selected.id}` : this.selected.name;
  }
  isValid() { return !!this.selected; }
}

let _moviePickers = {};
function initMoviePickers() {
  const fields = ['director','producer','dop','screenwriter','editor','sound','management','gd','actors','support'];
  const multi = ['director','producer','dop','screenwriter','editor','sound','management','gd','actors','support'];
  fields.forEach(f=>{
    _moviePickers[f] = new MemberPicker('mpick-'+f, multi.includes(f));
  });
}

// ══════════════════════════════════════════════════════════
// MEMBER PROFILE MODAL
// ══════════════════════════════════════════════════════════
async function openMemberProfile(member) {
  window._currentProfileMember = member;  // store for passport download
  const modal = document.getElementById('member-profile-modal');
  document.getElementById('mprofile-name').textContent = member.name;
  document.getElementById('mprofile-role').textContent = [member.role, member.domain].filter(Boolean).join(' · ');
  document.getElementById('mprofile-batch').textContent = member.batch ? 'Batch of '+member.batch : '';
  document.getElementById('mprofile-bio').textContent = member.bio || '';

  // ── Social Links ──────────────────────────────────────────────────────────
  const socialsEl = document.getElementById('mprofile-socials');
  if (socialsEl) {
    // Platform-specific SVG icons — 15×15, consistent weight
    const icons = {
      github:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 2C6.477 2 2 6.484 2 12.021c0 4.428 2.865 8.184 6.839 9.504.5.092.682-.217.682-.482 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.342-3.369-1.342-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.021C22 6.484 17.522 2 12 2z"/></svg>`,
      linkedin:  `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>`,
      instagram: `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 1 0 0 12.324 6.162 6.162 0 0 0 0-12.324zM12 16a4 4 0 1 1 0-8 4 4 0 0 1 0 8zm6.406-11.845a1.44 1.44 0 1 0 0 2.881 1.44 1.44 0 0 0 0-2.881z"/></svg>`,
      twitter:   `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.734l7.73-8.835L2.054 2.25H8.08l4.253 5.622 5.911-5.622zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>`,
      youtube:   `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>`,
      website:   `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10A15.3 15.3 0 0 1 12 2z"/></svg>`,
    };
    const labels  = { github:'GitHub', linkedin:'LinkedIn', instagram:'Instagram', twitter:'X', youtube:'YouTube', website:'Portfolio' };
    const classes = { github:'btn-github', linkedin:'btn-linkedin', instagram:'btn-instagram', twitter:'btn-twitter', youtube:'btn-youtube', website:'btn-website' };
    const links = [];

    // Helper: only allow http/https URLs (strip dangerous schemes)
    function _safeSocialUrl(url) {
      if (!url) return '';
      try {
        const u = new URL(url);
        return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : '';
      } catch { return ''; }
    }

    ['github','linkedin','instagram','twitter','youtube','website'].forEach(key => {
      let val = member[key];
      if (!val) return;
      val = val.trim();
      if (!val) return;
      // Normalise bare usernames to full URLs
      if (key === 'instagram' && !val.startsWith('http')) val = `https://instagram.com/${val.replace(/^@+/,'')}`;
      if (key === 'github'    && !val.startsWith('http')) val = `https://github.com/${val.replace(/^@+/,'')}`;
      if (key === 'twitter'   && !val.startsWith('http')) val = `https://x.com/${val.replace(/^@+/,'')}`;
      const safeUrl = _safeSocialUrl(val);
      if (!safeUrl) return;
      links.push(`<a class="mprofile-social-btn ${classes[key]}" href="${safeUrl}" target="_blank" rel="noopener noreferrer">${icons[key]} ${labels[key]}</a>`);
    });
    // Custom links
    if (member.custom_links) {
      try {
        const cl = typeof member.custom_links === 'string' ? JSON.parse(member.custom_links) : member.custom_links;
        (Array.isArray(cl) ? cl : []).forEach(l => {
          if (l.url && l.label) links.push(`<a class="mprofile-social-btn btn-website" href="${_safeSocialUrl(l.url)}" target="_blank" rel="noopener noreferrer">${icons.website} ${l.label}</a>`);
        });
      } catch {}
    }
    if (links.length) {
      socialsEl.innerHTML = links.join('');
      socialsEl.style.display = 'flex';
    } else {
      socialsEl.style.display = 'none';
    }
  }
  const photoWrap = document.getElementById('mprofile-photo-wrap');
  photoWrap.innerHTML = member.photo
    ? `<img class="member-profile-photo" src="${member.photo}" alt="${member.name}">`
    : `<div class="member-profile-photo-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg><\/div>`;

  // find films this member is linked to — fetch if cache empty (e.g. direct /members visit)
  if (!window._allMoviesCache || !window._allMoviesCache.length) {
    const [mv, allReviews] = await Promise.all([
      apiFetch('/api/movies'),
      fetch('/api/reviews/all').then(r=>r.ok?r.json():[]).catch(()=>[])
    ]);
    window._allMoviesCache = mv || [];
    window._movieRatings = window._movieRatings || {};
  }
  const allMovies = window._allMoviesCache || [];
  const crewFields = ['director','producer','dop','screenwriter','video_editor','sound_design','management','graphic_design','actors','support_crew'];
  const memberFilms = [];
  allMovies.forEach(m=>{
    let roleLabel = '';
    crewFields.forEach(f=>{
      const val = m[f]||'';
      const parts = splitCrew(val);
      parts.forEach(p=>{
        const [name, id] = p.split('||');
        if ((id && id.trim()==String(member.id)) || name.trim().toLowerCase()===member.name.toLowerCase()) {
          const labels = {director:'Director',producer:'Producer',dop:'DOP',screenwriter:'Script Writer',video_editor:'Editor',sound_design:'Sound',management:'Management',graphic_design:'Graphic Design',actors:'Actor',support_crew:'Crew'};
          if (!roleLabel) roleLabel = labels[f]||f;
        }
      });
    });
    if (roleLabel) memberFilms.push({movie:m, role:roleLabel});
  });
  // Sort by release year (newest first); films with no year go to the end
  memberFilms.sort((a,b) => {
    const ya = parseInt(a.movie.release_year)||0;
    const yb = parseInt(b.movie.release_year)||0;
    return yb - ya;
  });

  const filmsWrap = document.getElementById('mprofile-films-wrap');
  const filmsGrid = document.getElementById('mprofile-films-grid');
  if (memberFilms.length) {
    filmsWrap.style.display='block';
    filmsGrid.innerHTML = memberFilms.map(({movie:mv, role})=>`
      <div class="member-film-card" data-open-movie="${mv.id}" style="cursor:pointer">
        ${mv.poster_image ? `<img class="member-film-poster" src="${mv.poster_image}" alt="${mv.title}">` : `<div class="member-film-poster-ph"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg><\/div>`}
        <div class="member-film-info">
          <div class="member-film-title">${mv.title}<\/div>
          <div class="member-film-role-label">${role}${mv.release_year ? ' · '+mv.release_year : ''}<\/div>
        <\/div>
      <\/div>`).join('');
  } else {
    filmsWrap.style.display='none';
  }

  // ── Blogs authored by this member ──────────────────────────────────────────
  const blogsWrap = document.getElementById('mprofile-blogs-wrap');
  const blogsList = document.getElementById('mprofile-blogs-list');
  // Use cached blogs if available; fetch otherwise
  const getBlogs = async () => {
    if (window._allBlogsCache) return window._allBlogsCache;
    const data = await apiFetch('/api/blogs').catch(()=>[]);
    window._allBlogsCache = data || [];
    return window._allBlogsCache;
  };
  getBlogs().then(allBlogs => {
    const memberId = String(member.id);
    const memberName = member.name.trim().toLowerCase();
    const authored = allBlogs.filter(b => {
      if (!b.author) return false;
      // Support multiple authors separated by ;;
      return b.author.split(';;').some(part => {
        const raw = part.trim();
        const pipeIdx = raw.indexOf('||');
        if (pipeIdx !== -1) {
          const id = raw.slice(pipeIdx + 2).trim();
          const name = raw.slice(0, pipeIdx).trim().toLowerCase();
          return id === memberId || name === memberName;
        }
        return raw.toLowerCase() === memberName;
      });
    });
    if (authored.length) {
      blogsWrap.style.display = 'block';
      blogsList.innerHTML = authored.map(b => `
        <div class="mprofile-blog-item" onclick="closeMemberProfile();openBlog(${b.id})">
          ${b.cover_image
            ? `<img class="mprofile-blog-thumb" src="${b.cover_image}" alt="">`
            : `<div class="mprofile-blog-thumb-ph"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/><\/svg><\/div>`}
          <span class="mprofile-blog-title">${b.title}<\/span>
        <\/div>`).join('');
    } else {
      blogsWrap.style.display = 'none';
    }
  });

  modal.classList.add('open');
}
function closeMemberProfile() {
  document.getElementById('member-profile-modal').classList.remove('open');
}
document.getElementById('member-profile-modal').addEventListener('click', function(e){
  if (e.target===this) closeMemberProfile();
});

function doSearch(q) {
  q = q.trim().toLowerCase();
  const out = document.getElementById('search-results');
  if (!q) { out.innerHTML = ''; return; }

  // ── CUSTOM EASTER EGGS (admin-configurable) ───────────────────────────
  const customEggs = window._customSearchEggs || [];
  const matched = customEggs.find(e => e.keyword && e.keyword.toLowerCase() === q);
  if (matched) {
    if (matched.image_url) {
      out.innerHTML = `${matched.heading||matched.subtext ? `<div class="search-egg-noshorts"><strong>${matched.heading||''}</strong>${matched.subtext||''}</div>` : ''}<div style="padding:12px"><img class="search-egg-img" src="${matched.image_url}" alt="${matched.heading||''}"></div>`;
    } else {
      out.innerHTML = `<div class="search-egg-noshorts"><strong>${matched.heading||''}</strong>${matched.subtext||''}</div>`;
    }
    return;
  }

  // ── EASTER EGG: "shorts" → "No Shorts." ──────────────────────────────
  if (q === 'shorts') {
    const h = window._eggShortsHeading || 'No Shorts.';
    const s = window._eggShortsSub || 'we only make films that last';
    out.innerHTML = `<div class="search-egg-noshorts"><strong>${h}</strong>${s}</div>`;
    return;
  }

  // ── EASTER EGG: "no shorts" → reveal the image ───────────────────────
  if (q === 'no shorts') {
    const imgUrl = window._easterEggImg || '';
    const fallback = window._eggNoShortsFallback || "that's the spirit";
    const h = window._eggShortsHeading || 'No Shorts.';
    const s = window._eggShortsSub || 'we only make films that last';
    out.innerHTML = imgUrl
      ? `<div style="padding:12px"><img class="search-egg-img" src="${imgUrl}" alt="No Shorts"></div>`
      : `<div class="search-egg-noshorts"><strong>${h}</strong>${fallback}</div>`;
    return;
  }

  const results = [];
  const crewFields = ['director','producer','dop','screenwriter','video_editor','sound_design','management','graphic_design','actors','support_crew'];

  searchData.movies.filter(m => {
    if (m.title?.toLowerCase().includes(q)) return true;
    // Genre tag search
    const genres = Array.isArray(m.genre) ? m.genre : (m.genre ? [m.genre] : []);
    if (genres.some(g => g.toLowerCase().includes(q))) return true;
    return crewFields.some(f => {
      const val = m[f]||'';
      return splitCrew(val).some(p=>p.split('||')[0].trim().toLowerCase().includes(q));
    });
  }).forEach(m => {
    const matchedCrew = [];
    const genres = Array.isArray(m.genre) ? m.genre : (m.genre ? [m.genre] : []);
    const matchedGenres = genres.filter(g => g.toLowerCase().includes(q));
    crewFields.forEach(f=>{
      splitCrew(m[f]||'').forEach(p=>{
        const name = p.split('||')[0].trim();
        if (name.toLowerCase().includes(q) && !m.title?.toLowerCase().includes(q)) matchedCrew.push(name);
      });
    });
    const sub = matchedGenres.length && !m.title?.toLowerCase().includes(q)
      ? 'Genre: '+matchedGenres.join(', ')+(m.director ? ' · Dir. '+m.director.split('||')[0].trim() : '')
      : matchedCrew.length ? 'Crew: '+matchedCrew.slice(0,3).join(', ') : (m.director ? 'Dir. '+m.director.split('||')[0].trim() : m.release_year||'');
    results.push({ type:'film', icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg>`, title: m.title, sub, action: ()=>{ closeSearch(); openMovie(m.id); } });
  });
  searchData.blogs.filter(b => {
    if (b.title?.toLowerCase().includes(q) || b.excerpt?.toLowerCase().includes(q)) return true;
    let secs = [];
    try { secs = b.sections ? JSON.parse(b.sections) : []; } catch(e){}
    return secs.some(s => s.label.toLowerCase().includes(q));
  }).forEach(b => {
    let secs = [];
    try { secs = b.sections ? JSON.parse(b.sections) : []; } catch(e){}
    const matchedSecs = secs.filter(s => s.label.toLowerCase().includes(q));
    let sub = '';
    if (matchedSecs.length) {
      // Tag match — show tags prominently then excerpt
      sub = matchedSecs.map(s=>s.label).join(' · ') + (b.excerpt ? '  —  ' + b.excerpt : '');
    } else {
      // Title/excerpt match — show all tags as context
      const allTags = secs.map(s=>s.label).join(' · ');
      sub = (allTags ? allTags + '  —  ' : '') + (b.excerpt || '');
    }
    results.push({ type:'blog', icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/><\/svg>`, title: b.title, sub, action: ()=>{ closeSearch(); openBlog(b.id); } });
  });
  searchData.events.filter(e => e.title?.toLowerCase().includes(q) || e.description?.toLowerCase().includes(q)).forEach(e =>
    results.push({ type:'event', icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><\/svg>`, title: e.title, sub: e.event_date ? new Date(e.event_date).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'}) : '', action: ()=>{ closeSearch(); navigate('events'); } })
  );
  searchData.members.filter(m => m.name?.toLowerCase().includes(q) || m.role?.toLowerCase().includes(q) || m.domain?.toLowerCase().includes(q)).forEach(m => {
    const allMovies = window._allMoviesCache || [];
    const filmCount = allMovies.filter(mv=>crewFields.some(f=>splitCrew(mv[f]||'').some(p=>{ const [nm,id]=p.split('||'); return (id&&id.trim()==String(m.id))||nm.trim().toLowerCase()===m.name.toLowerCase(); }))).length;
    const sub = [m.role, m.domain, filmCount ? filmCount+' film'+(filmCount>1?'s':'') : ''].filter(Boolean).join(' · ');
    results.push({ type:'member', icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg>`, title: m.name, sub, action: ()=>{ closeSearch(); navigate('members'); setTimeout(()=>openMemberProfile(m),300); } });
  });

  if (!results.length) { out.innerHTML = '<div class="search-empty">No results for "'+q+'"<\/div>'; return; }

  const groups = ['film','blog','event','member'];
  const labels = { film:'Films', blog:'Blog', event:'Events', member:'Members' };
  let html = '';
  groups.forEach(g => {
    const items = results.filter(r=>r.type===g);
    if (!items.length) return;
    html += `<div class="search-result-group">${labels[g]}<\/div>`;
    items.slice(0,5).forEach(item => {
      html += `<div class="search-result-item" data-idx="${results.indexOf(item)}">
        <span class="search-result-icon">${item.icon}<\/span>
        <div><div class="search-result-title">${item.title}<\/div>${item.sub?`<div class="search-result-sub">${item.sub}<\/div>`:''}<\/div>
      <\/div>`;
    });
  });
  out.innerHTML = html;
  out.querySelectorAll('.search-result-item').forEach(el => {
    const idx = parseInt(el.dataset.idx);
    el.addEventListener('click', () => results[idx].action());
  });
}

// ══════════════════════════════════════════════════════════
// CHITRA VICHITRA — PUBLIC
// ══════════════════════════════════════════════════════════
let _cvData = [];

async function loadCVCards() {
  _cvData = await apiFetch('/api/chitra-vichitra') || [];
  const row = document.getElementById('cv-cards-row');
  if (!row) return;
  if (!_cvData.length) {
    row.innerHTML = `<div style="grid-column:1/-1;padding:40px;text-align:center;background:var(--card);color:var(--grey);font-size:13px">No editions yet.<\/div>`;
    return;
  }
  row.innerHTML = _cvData.map(cv => {
    const movieCount = cv.movie_count || 0;
    return `<div class="cv-year-card" onclick="openCVDetail('${cv.id}','${cv.year}')">
      ${cv.cover_image
        ? `<img class="cv-year-card-img" src="${cv.cover_image}" alt="CV ${cv.year}">`
        : `<div class="cv-year-card-placeholder"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.82 2H4.18A2.18 2.18 0 0 0 2 4.18v15.64A2.18 2.18 0 0 0 4.18 22h15.64A2.18 2.18 0 0 0 22 19.82V4.18A2.18 2.18 0 0 0 19.82 2z"/><circle cx="7" cy="7" r="1.5"/><circle cx="12" cy="7" r="1.5"/><circle cx="17" cy="7" r="1.5"/><circle cx="7" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="17" cy="12" r="1.5"/><circle cx="7" cy="17" r="1.5"/><circle cx="12" cy="17" r="1.5"/><circle cx="17" cy="17" r="1.5"/><\/svg><\/div>`}
      <div class="cv-year-card-overlay"><\/div>
      <div class="cv-year-card-info">
        <div class="cv-year-badge">Chitra Vichitra<\/div>
        <div class="cv-year-num">${cv.year}<\/div>
        <div class="cv-year-meta">${movieCount} film${movieCount!==1?'s':''} screened<\/div>
        <div class="cv-year-arrow">View Films →<\/div>
      <\/div>
    <\/div>`;
  }).join('');
}

async function openCVDetail(cvId, year) {
  const mainView = document.getElementById('events-main-view');
  const detailView = document.getElementById('cv-detail-view');
  mainView.style.display = 'none';
  detailView.style.display = 'block';
  document.getElementById('cv-detail-year-title').textContent = `Chitra Vichitra ${year}`;
  const grid = document.getElementById('cv-movies-grid');
  grid.innerHTML = `<div class="loading" style="grid-column:1/-1;padding:40px;text-align:center">Loading...<\/div>`;
  const data = await apiFetch(`/api/chitra-vichitra/${cvId}/movies`);
  if (!data || !data.length) {
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><p>No films added to CV ${year} yet.<\/p><\/div>`;
    return;
  }
  grid.innerHTML = data.map(m => renderMovieCard(m, true)).join('');
}

function closeCVDetail() {
  document.getElementById('events-main-view').style.display = 'block';
  document.getElementById('cv-detail-view').style.display = 'none';
}

// ══════════════════════════════════════════════════════════
// CHITRA VICHITRA — ADMIN
// ══════════════════════════════════════════════════════════
let _cvEditId = null;
let _cvMoviesEditId = null;
let _cvMoviesEditYear = null;
let _allMoviesForDropdown = [];

async function loadAdminCV() {
  const list = document.getElementById('cv-admin-list');
  const editions = await apiFetch('/api/chitra-vichitra') || [];
  if (!editions.length) {
    list.innerHTML = `<div class="empty-state" style="padding:40px;text-align:center"><p>No CV editions yet. Add one to get started.<\/p><\/div>`;
    return;
  }
  list.innerHTML = editions.map(cv => { const cvJson=JSON.stringify(cv).replace(/"/g,'&quot;'); return `
    <div class="admin-card" style="margin-bottom:12px;display:grid;grid-template-columns:auto 1fr auto;gap:20px;align-items:center;padding:16px 20px">
      <div>
        ${cv.cover_image
          ? `<img src="${cv.cover_image}" alt="${cv.year}" style="width:80px;height:52px;object-fit:cover;border-radius:3px;border:1px solid var(--border)">`
          : `<div style="width:80px;height:52px;background:var(--border);border-radius:3px;display:flex;align-items:center;justify-content:center"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.82 2H4.18A2.18 2.18 0 0 0 2 4.18v15.64A2.18 2.18 0 0 0 4.18 22h15.64A2.18 2.18 0 0 0 22 19.82V4.18A2.18 2.18 0 0 0 19.82 2z"/><circle cx="7" cy="7" r="1.5"/><circle cx="12" cy="7" r="1.5"/><circle cx="17" cy="7" r="1.5"/><circle cx="7" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="17" cy="12" r="1.5"/><circle cx="7" cy="17" r="1.5"/><circle cx="12" cy="17" r="1.5"/><circle cx="17" cy="17" r="1.5"/><\/svg><\/div>`}
      <\/div>
      <div>
        <div style="font-weight:700;font-size:16px">Chitra Vichitra ${cv.year}<\/div>
        <div style="font-size:12px;color:var(--grey);margin-top:3px">${cv.movie_count || 0} film${(cv.movie_count||0)!==1?'s':''} screened<\/div>
      <\/div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
        <button class="btn-sm" onclick="openCVMoviesModal('${cv.id}','${cv.year}')"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg> Manage Films<\/button>
        <button class="btn-sm" onclick="editCV(${cvJson})">Edit<\/button>
        <button class="btn-sm danger" onclick="deleteCV('${cv.id}','${cv.year}')">Delete<\/button>
      <\/div>
    <\/div>`; }).join('');
}

function openCVModal(cv=null) {
  _cvEditId = cv ? cv.id : null;
  document.getElementById('cv-modal-title').textContent = cv ? `Edit CV ${cv.year}` : 'Add CV Edition';
  document.getElementById('cv-edit-id').value = cv ? cv.id : '';
  document.getElementById('cv-year').value = cv ? cv.year : '';
  document.getElementById('cv-sort').value = cv ? cv.sort_order : 99;
  const prev = document.getElementById('cv-cover-preview');
  const wrap = document.getElementById('cv-cover-preview-wrap');
  if (cv && cv.cover_image) { prev.src=cv.cover_image; wrap.style.display='block'; }
  else { prev.src=''; wrap.style.display='none'; }
  document.getElementById('cv-cover').value = '';
  document.getElementById('cv-modal').style.display = 'flex';
}

function editCV(cv) { openCVModal(cv); }
function closeCVModal() { document.getElementById('cv-modal').style.display = 'none'; }

async function saveCV() {
  const year = document.getElementById('cv-year').value.trim();
  const sort = document.getElementById('cv-sort').value;
  const file = document.getElementById('cv-cover').files[0];
  if (!year) { alert('Year is required'); return; }

  const fd = new FormData();
  fd.append('year', year);
  fd.append('sort_order', sort);
  if (file) fd.append('cover', file);

  const method = _cvEditId ? 'PUT' : 'POST';
  const url = _cvEditId ? `/api/admin/chitra-vichitra/${_cvEditId}` : '/api/admin/chitra-vichitra';
  const res = await fetch(url, { method, credentials:'include', headers:{'Authorization':'Bearer '+adminToken,'X-CSRF-Token':_csrfToken||''}, body:fd });
  if (!res.ok) { const e=await res.json(); alert(e.error||'Error'); return; }
  closeCVModal();
  loadAdminCV();
}

async function deleteCV(id, year) {
  if (!confirm(`Delete Chitra Vichitra ${year}? This will also remove all film associations.`)) return;
  await apiFetch(`/api/admin/chitra-vichitra/${id}`, 'DELETE');
  loadAdminCV();
}

async function openCVMoviesModal(cvId, year) {
  _cvMoviesEditId = cvId;
  _cvMoviesEditYear = year;
  document.getElementById('cv-movies-modal-year').textContent = year;
  document.getElementById('cv-movies-modal').style.display = 'flex';

  // Load all movies for dropdown
  _allMoviesForDropdown = await apiFetch('/api/movies') || [];
  const sel = document.getElementById('cv-movie-dropdown');
  sel.innerHTML = '<option value="">— Select a film —<\/option>' +
    _allMoviesForDropdown.map(m=>`<option value="${m.id}">${m.title}${m.release_year?' ('+m.release_year+')':''}<\/option>`).join('');

  await refreshCVMoviesList();
}

async function refreshCVMoviesList() {
  const container = document.getElementById('cv-current-movies-list');
  const data = await apiFetch(`/api/chitra-vichitra/${_cvMoviesEditId}/movies`);
  if (!data || !data.length) {
    container.innerHTML = `<div style="font-size:13px;color:var(--grey);padding:16px">No films added yet.<\/div>`;
    return;
  }
  container.innerHTML = data.map(m => `
    <div style="display:grid;grid-template-columns:44px 1fr auto;align-items:center;gap:12px;padding:10px 12px;background:var(--card);border:1px solid var(--border)">
      ${m.poster_image
        ? `<img src="${m.poster_image}" alt="${m.title}" style="width:44px;height:60px;object-fit:cover;border-radius:2px">`
        : `<div style="width:44px;height:60px;background:var(--border);border-radius:2px;display:flex;align-items:center;justify-content:center;><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><\/svg><\/div>`}
      <div>
        <div style="font-size:13px;font-weight:600">${m.title}<\/div>
        <div style="font-size:11px;color:var(--grey)">${m.release_year||''}<\/div>
      <\/div>
      <button class="btn-sm danger" style="font-size:11px;padding:4px 10px" onclick="removeMovieFromCV('${m.cv_movie_id}')">Remove<\/button>
    <\/div>`).join('');
}

async function addMovieToCV() {
  const movieId = document.getElementById('cv-movie-dropdown').value;
  if (!movieId) { alert('Select a film first'); return; }
  const res = await apiFetch(`/api/admin/chitra-vichitra/${_cvMoviesEditId}/movies`, 'POST', { movie_id: movieId });
  if (res && res.error) { alert(res.error); return; }
  await refreshCVMoviesList();
  loadAdminCV();
}

async function removeMovieFromCV(cvMovieId) {
  await apiFetch(`/api/admin/chitra-vichitra/movies/${cvMovieId}`, 'DELETE');
  await refreshCVMoviesList();
  loadAdminCV();
}

function closeCVMoviesModal() { document.getElementById('cv-movies-modal').style.display = 'none'; }

// Hook cv cover preview
document.getElementById('cv-cover').addEventListener('change', function() {
  const f = this.files[0]; if (!f) return;
  const url = URL.createObjectURL(f);
  document.getElementById('cv-cover-preview').src = url;
  document.getElementById('cv-cover-preview-wrap').style.display = 'block';
});

// ══════════════════════════════════════════════════════════
// Keyboard shortcuts
// ══════════════════════════════════════════════════════════
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); openSearch(); }
  // Press / to open search (skip if typing in an input)
  if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
    e.preventDefault();
    openSearch();
  }
  if (e.key === 'Escape') closeSearch();
});
document.getElementById('search-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('search-overlay')) closeSearch();
});
// Show ⌘K hint on desktop
if (!navigator.maxTouchPoints) document.getElementById('search-kbd').style.display = 'inline';


// ══════════════════════════════════════════════════════════
// TRAFFIC TRACKING — fire on every page view
// ══════════════════════════════════════════════════════════
(function trackPageView() {
  const page = window.location.pathname.replace('/','') || 'home';
  fetch('/api/track', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ page, hour: new Date().getHours() })
  }).catch(()=>{});
})();


// ══════════════════════════════════════════════════════════
// ANALYTICS — TRAFFIC
// ══════════════════════════════════════════════════════════
let currentAnalyticsRange = '7d';

function switchAnalyticsTab(type, range, el) {
  document.querySelectorAll('.analytics-tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  currentAnalyticsRange = range;
  loadTrafficAnalytics(range);
}

async function loadTrafficAnalytics(range='7d') {
  const data = await apiFetch('/api/admin/analytics/traffic?range='+range);
  if (!data) return;

  document.getElementById('stat-traffic-total-views').textContent = fmtNum(data.total);
  document.getElementById('stat-today-views').textContent = fmtNum(data.today);
  document.getElementById('stat-peak-day').textContent = data.peak_day || '—';

  const topPage = data.by_page?.[0];
  document.getElementById('stat-top-page').textContent = topPage ? '/'+topPage.page : '—';
  document.getElementById('stat-top-page-views').textContent = topPage ? fmtNum(topPage.views)+' views' : '';

  // Line chart
  renderLineChart('traffic-line-chart', 'traffic-line-labels', data.by_date || []);

  // Page leaderboard
  const maxViews = Math.max(...(data.by_page||[]).map(p=>p.views), 1);
  document.getElementById('page-leaderboard').innerHTML = (data.by_page||[]).slice(0,8).map((p,i)=>`
    <div class="leaderboard-row">
      <span class="leaderboard-rank">${i+1}<\/span>
      <span style="font-size:13px;flex:1">/${p.page||'home'}<\/span>
      <div class="leaderboard-bar-wrap"><div class="leaderboard-bar-fill" style="width:${p.views/maxViews*100}%"><\/div><\/div>
      <span class="leaderboard-score">${fmtNum(p.views)}<\/span>
    <\/div>`).join('');

  // Hours bar chart
  const hoursEl = document.getElementById('hours-bar-chart');
  const maxHour = Math.max(...(data.by_hour||Array(24).fill(0)), 1);
  hoursEl.innerHTML = (data.by_hour||Array(24).fill(0)).map((v,h)=>`
    <div class="bar-chart-col" style="flex:1">
      <div class="bar-chart-bar" style="height:${Math.max(v/maxHour*90,2)}px;opacity:${h===new Date().getHours()?1:.5}"><\/div>
    <\/div>`).join('');
}

function renderLineChart(svgId, labelsId, byDate) {
  const svg = document.getElementById(svgId);
  const labelsEl = document.getElementById(labelsId);
  if (!byDate.length) { svg.innerHTML = ''; return; }
  const W=600, H=160, pad=10;
  const vals = byDate.map(d=>d.views);
  const maxV = Math.max(...vals, 1);
  const pts = byDate.map((d,i)=>{
    const x = pad + (i/(byDate.length-1||1))*(W-pad*2);
    const y = H - pad - (d.views/maxV)*(H-pad*2);
    return `${x},${y}`;
  });
  svg.innerHTML = `
    <style>
      .chart-line { stroke: var(--white); }
      .chart-dot  { fill:   var(--white); }
      .chart-grad-stop { stop-color: var(--white); }
    <\/style>
    <polyline class="chart-line" points="${pts.join(' ')}" fill="none" stroke-width="1.5" stroke-linejoin="round"/>
    ${byDate.map((d,i)=>{
      const x=pad+(i/(byDate.length-1||1))*(W-pad*2);
      const y=H-pad-(d.views/maxV)*(H-pad*2);
      return `<circle class="chart-dot" cx="${x}" cy="${y}" r="3"/>`;
    }).join('')}
    <defs><linearGradient id="fadeG" x1="0" y1="0" x2="0" y2="1"><stop class="chart-grad-stop" offset="0%" stop-opacity=".15"/><stop class="chart-grad-stop" offset="100%" stop-opacity="0"/><\/linearGradient><\/defs>
    <polygon points="${pts.join(' ')} ${W-pad},${H} ${pad},${H}" fill="url(#fadeG)"/>`;
  // Labels — show first, middle, last
  const show = [0, Math.floor(byDate.length/2), byDate.length-1].filter((v,i,a)=>a.indexOf(v)===i);
  labelsEl.innerHTML = byDate.map((d,i)=> show.includes(i)
    ? `<span style="font-size:10px;color:var(--grey)">${new Date(d.date).toLocaleDateString('en-IN',{day:'numeric',month:'short'})}<\/span>`
    : `<span><\/span>`).join('');
}

function fmtNum(n) { return n >= 1000 ? (n/1000).toFixed(1)+'k' : (n||0).toString(); }


// ══════════════════════════════════════════════════════════
// ANALYTICS — REVIEWS
// ══════════════════════════════════════════════════════════
async function loadReviewAnalytics() {
  const data = await apiFetch('/api/admin/analytics/reviews');
  if (!data) return;

  document.getElementById('ra-total').textContent = data.total || '0';
  document.getElementById('ra-avg').textContent = data.overall_avg ? data.overall_avg.toFixed(1) : '—';
  document.getElementById('ra-top-film').textContent = data.top_rated?.title || '—';
  document.getElementById('ra-most-reviewed').textContent = data.most_reviewed?.title || '—';

  // Film scores bar chart
  const films = data.by_film || [];
  const maxScore = 5;
  const chartEl = document.getElementById('film-scores-chart');
  const labelsEl = document.getElementById('film-scores-labels');
  chartEl.style.height = '120px';
  chartEl.innerHTML = films.map(f=>`
    <div class="bar-chart-col">
      <div class="bar-chart-val">${f.avg.toFixed(1)}<\/div>
      <div class="bar-chart-bar" style="height:${f.avg/maxScore*100}px"><\/div>
    <\/div>`).join('');
  labelsEl.innerHTML = films.map(f=>`<span style="flex:1;font-size:9px;color:var(--grey);text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.title}<\/span>`).join('');

  // Category breakdown
  const cats = ['direction','sound','cinematography','script'];
  const catLabels = { direction:'Direction', sound:'Sound', cinematography:'Cinemato.', script:'Script' };
  document.getElementById('category-breakdown').innerHTML = cats.map(c=>`
    <div class="leaderboard-row">
      <span style="font-size:12px;flex:1;color:var(--grey);text-transform:uppercase;letter-spacing:.08em;font-size:10px">${catLabels[c]}<\/span>
      <div class="leaderboard-bar-wrap"><div class="leaderboard-bar-fill" style="width:${(data.cat_avgs?.[c]||0)/5*100}%"><\/div><\/div>
      <span class="leaderboard-score">${data.cat_avgs?.[c]?.toFixed(1)||'—'}<\/span>
    <\/div>`).join('');

  // Film leaderboard
  const maxR = Math.max(...films.map(f=>f.count),1);
  document.getElementById('film-leaderboard').innerHTML = films.map((f,i)=>`
    <div class="leaderboard-row">
      <span class="leaderboard-rank">${i+1}<\/span>
      <span style="font-size:13px;flex:1">${f.title}<\/span>
      <span style="font-size:11px;color:var(--grey);margin-right:8px">${f.count} review${f.count!==1?'s':''}<\/span>
      <div class="leaderboard-bar-wrap"><div class="leaderboard-bar-fill" style="width:${f.avg/5*100}%"><\/div><\/div>
      <span class="leaderboard-score">${f.avg.toFixed(1)}<\/span>
    <\/div>`).join('');
}

// ══════════════════════════════════════════════════════════
// ANALYTICS — REGISTRATIONS
// ══════════════════════════════════════════════════════════
async function loadRegAnalytics() {
  const tbody = document.getElementById('reg-analytics-tbody');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:40px">Loading…</td></tr>';

  // Fetch all events
  const events = await apiFetch('/api/events');
  if (!events || !events.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:40px">No events found.</td></tr>';
    return;
  }

  // Fetch registration counts for each event in parallel
  const results = await Promise.all(events.map(async ev => {
    const responses = await apiFetch('/api/admin/events/' + ev.id + '/form/responses').catch(() => null);
    const count = Array.isArray(responses) ? responses.length : 0;
    // Check if form exists
    const form = await apiFetch('/api/events/' + ev.id + '/form').catch(() => null);
    return { ...ev, count, hasForm: !!form, formOpen: form?.is_open };
  }));

  // Only show events that have forms
  const withForms = results.filter(r => r.hasForm);
  if (!withForms.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:40px">No registration forms found.</td></tr>';
    document.getElementById('reg-total').textContent = '0';
    document.getElementById('reg-events-count').textContent = '0';
    document.getElementById('reg-top-event-count').textContent = '—';
    document.getElementById('reg-avg').textContent = '—';
    document.getElementById('reg-bar-chart').innerHTML = '';
    return;
  }

  // Sort by count desc for chart
  const sorted = [...withForms].sort((a,b) => b.count - a.count);
  const totalRegs = withForms.reduce((s,r) => s + r.count, 0);
  const topEvent = sorted[0];

  document.getElementById('reg-total').textContent = totalRegs;
  document.getElementById('reg-events-count').textContent = withForms.length;
  document.getElementById('reg-top-event-count').textContent = topEvent?.count ?? '—';
  document.getElementById('reg-top-event-name').textContent = topEvent?.title ?? '';
  document.getElementById('reg-avg').textContent = withForms.length ? Math.round(totalRegs / withForms.length) : '—';

  // Bar chart
  const maxCount = Math.max(...sorted.map(r => r.count), 1);
  const chartEl = document.getElementById('reg-bar-chart');
  const labelsEl = document.getElementById('reg-bar-labels');
  const barH = 180;
  chartEl.innerHTML = sorted.map(r => {
    const pct = r.count / maxCount;
    const h = Math.max(Math.round(pct * (barH - 30)), 4);
    return `<div style="flex:1;min-width:32px;max-width:80px;display:flex;flex-direction:column;align-items:center;gap:4px">
      <span style="font-size:11px;font-weight:700;color:var(--white)">${r.count}</span>
      <div style="width:100%;height:${h}px;background:var(--white);border-radius:3px 3px 0 0;opacity:${0.4 + pct * 0.6};transition:height .6s"></div>
    </div>`;
  }).join('');
  labelsEl.innerHTML = sorted.map(r =>
    `<span style="flex:1;min-width:32px;max-width:80px;font-size:9px;color:var(--grey);text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.title}">${r.title}</span>`
  ).join('');

  // Table
  tbody.innerHTML = withForms.map((r, i) => `<tr>
    <td style="color:var(--grey)">${i + 1}</td>
    <td style="font-weight:500">${r.title}</td>
    <td style="color:var(--grey)">${r.event_date || '—'}</td>
    <td><span class="tag ${r.formOpen ? 'upcoming' : ''}">${r.formOpen ? 'Open' : 'Closed'}</span></td>
    <td style="font-weight:700;font-size:16px">${r.count}</td>
  </tr>`).join('');
}

// ══════════════════════════════════════════════════════════
// ANALYTICS — PAYMENTS / DONATIONS
// ══════════════════════════════════════════════════════════
async function loadPaymentAnalytics() {
  // Reset to loading state
  ['pa-total-collected','pa-total-donors','pa-avg-donation','pa-top-donor'].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = '…';
  });
  const tbodyEl = document.getElementById('pa-top-donors-tbody');
  if (tbodyEl) tbodyEl.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--grey);padding:40px">Loading…</td></tr>';

  const data = await apiFetch('/api/admin/donation/analytics');
  if (!data) {
    if (tbodyEl) tbodyEl.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--grey);padding:40px">Could not load analytics.</td></tr>';
    return;
  }

  const { totals, bySemester, dailyTrend, buckets, topDonors } = data;

  // ── KPI Cards ──────────────────────────────────────────────────────────────
  const fmt = paise => '₹' + Math.round(paise / 100).toLocaleString('en-IN');
  document.getElementById('pa-total-collected').textContent = fmt(totals.totalCollected || 0);
  document.getElementById('pa-total-donors').textContent   = totals.totalDonors || 0;
  document.getElementById('pa-avg-donation').textContent   = fmt(totals.avgDonation || 0);
  document.getElementById('pa-top-donor').textContent      = totals.maxDonor?.name || '—';
  const subEl = document.getElementById('pa-top-donor-sub');
  if (subEl) subEl.textContent = totals.maxDonor ? fmt(totals.maxDonor.amount_paise) : '';

  // ── Daily Trend Line Chart ─────────────────────────────────────────────────
  const chartSvg  = document.getElementById('pa-daily-chart');
  const labelsDiv = document.getElementById('pa-daily-labels');
  if (chartSvg && dailyTrend && dailyTrend.length) {
    const W = 600, H = 160, pad = 20;
    const maxAmt = Math.max(...dailyTrend.map(d => d.total_paise), 1);
    const xs = dailyTrend.map((d, i) => pad + i * (W - 2 * pad) / Math.max(dailyTrend.length - 1, 1));
    const ys = dailyTrend.map(d => H - pad - (d.total_paise / maxAmt) * (H - 2 * pad));
    const pts = xs.map((x, i) => `${x},${ys[i]}`);
    const pathD = pts.reduce((acc, p, i) => acc + (i === 0 ? `M${p}` : ` L${p}`), '');
    chartSvg.innerHTML = `<defs>
      <linearGradient id="paFade" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--white)" stop-opacity="0.25"/>
        <stop offset="100%" stop-color="var(--white)" stop-opacity="0"/>
      </linearGradient></defs>
      <path d="${pathD}" fill="none" stroke="var(--white)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <polygon points="${pts.join(' ')} ${W-pad},${H} ${pad},${H}" fill="url(#paFade)"/>`;
    const show = [0, Math.floor(dailyTrend.length / 2), dailyTrend.length - 1].filter((v, i, a) => a.indexOf(v) === i);
    labelsDiv.innerHTML = dailyTrend.map((d, i) => show.includes(i)
      ? `<span style="font-size:10px;color:var(--grey)">${new Date(d.date).toLocaleDateString('en-IN',{day:'numeric',month:'short'})}<\/span>`
      : `<span><\/span>`).join('');
  } else if (chartSvg) {
    chartSvg.innerHTML = `<text x="300" y="90" text-anchor="middle" fill="var(--grey)" font-size="13">No data in last 60 days</text>`;
    if (labelsDiv) labelsDiv.innerHTML = '';
  }

  // ── Revenue by Semester Bar Chart ─────────────────────────────────────────
  const semChartEl  = document.getElementById('pa-semester-chart');
  const semLabelsEl = document.getElementById('pa-semester-labels');
  if (semChartEl && bySemester && bySemester.length) {
    const maxSem = Math.max(...bySemester.map(s => s.total_paise), 1);
    semChartEl.innerHTML = bySemester.map(s => {
      const pct = s.total_paise / maxSem;
      const h   = Math.max(Math.round(pct * 90), 4);
      return `<div style="flex:1;min-width:40px;display:flex;flex-direction:column;align-items:center;gap:4px">
        <span style="font-size:10px;font-weight:700;color:var(--white)">${fmt(s.total_paise)}<\/span>
        <div style="width:100%;height:${h}px;background:var(--white);border-radius:3px 3px 0 0;opacity:${0.35 + pct * 0.65}"><\/div>
      <\/div>`;
    }).join('');
    semLabelsEl.innerHTML = bySemester.map(s =>
      `<span style="flex:1;min-width:40px;font-size:9px;color:var(--grey);text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${s.label}">${s.label} (${s.count})<\/span>`
    ).join('');
  }

  // ── Donation Size Breakdown ────────────────────────────────────────────────
  const bucketEl = document.getElementById('pa-bucket-breakdown');
  if (bucketEl && buckets) {
    const total = Object.values(buckets).reduce((a, b) => a + b, 0) || 1;
    bucketEl.innerHTML = Object.entries(buckets).map(([label, count]) => {
      const pct = count / total;
      return `<div class="leaderboard-row">
        <span style="font-size:12px;flex:1;color:var(--grey)">${label}<\/span>
        <div class="leaderboard-bar-wrap"><div class="leaderboard-bar-fill" style="width:${Math.round(pct*100)}%"><\/div><\/div>
        <span class="leaderboard-score">${count}<\/span>
      <\/div>`;
    }).join('');
  }

  // ── Top Donors Table ───────────────────────────────────────────────────────
  if (tbodyEl) {
    if (!topDonors || !topDonors.length) {
      tbodyEl.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--grey);padding:40px">No donation data yet.</td></tr>';
    } else {
      tbodyEl.innerHTML = topDonors.map((d, i) => {
        const safeName   = escHtml(d.name   || '—');
        const safeEmail  = escHtml(d.email  || '—');
        const safeRoll   = escHtml(d.roll_no|| '—');
        const safeSem    = escHtml(d.semester|| '—');
        const safeDate   = escHtml(d.date   || '—');
        const safePid    = escHtml(d.payment_id || '—');
        const safeId     = escHtml(String(d.id || ''));
        const nameForBtn = escHtml((d.name || 'this donor').replace(/'/g, ''));
        return `<tr data-donor-id="${safeId}">
          <td style="color:var(--grey);font-weight:600">${i + 1}<\/td>
          <td style="font-weight:500">${safeName}<\/td>
          <td style="color:var(--grey);font-size:12px">${safeEmail}<\/td>
          <td style="color:var(--grey);font-size:12px">${safeRoll}<\/td>
          <td style="font-weight:700;font-size:15px;color:var(--accent)">${fmt(d.amount_paise)}<\/td>
          <td style="font-size:12px;color:var(--grey)">${safeSem}<\/td>
          <td style="font-size:12px;color:var(--grey)">${safeDate}<\/td>
          <td style="font-size:11px;color:var(--grey);font-family:monospace">${safePid}<\/td>
          <td><div class="action-btns">${safeId ? `
            <button class="admin-action-btn" title="Download receipt as PDF" onclick="adminDownloadReceipt(${JSON.stringify({id:d.id,name:d.name,email:d.email,amount_paise:d.amount_paise,payment_id:d.payment_id,order_id:d.order_id||'',date:d.date,is_anonymous:d.is_anonymous}).replace(/"/g,'&quot;')})">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/><\/svg>
              Receipt<\/button>
            <button class="admin-action-btn admin-action-btn--danger" title="Delete this record" onclick="adminDeleteDonor('${safeId}','${nameForBtn}',this)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/><\/svg>
            Delete<\/button>` : '<span style="color:var(--grey);font-size:11px">—<\/span>'}<\/div><\/td>
        <\/tr>`;
      }).join('');
    }
  }
}

// ── Admin: Delete a donor/payment record ──────────────────────────────────────
async function adminDeleteDonor(donorId, donorName, btn) {
  if (!donorId) return;
  const displayName = donorName || 'this donor';
  if (!confirm(`Delete payment record for "${displayName}"?\n\nThis permanently removes them from the donors list and cannot be undone.`)) return;

  if (btn) { btn.disabled = true; btn.textContent = 'Deleting…'; }

  try {
    const res = await apiFetch(`/api/admin/donation/donors/${encodeURIComponent(donorId)}`, 'DELETE');
    if (res && res.success) {
      // Remove the row from the table
      const row = document.querySelector(`tr[data-donor-id="${donorId}"]`);
      if (row) row.remove();
      // Reload analytics to refresh counts
      loadPaymentAnalytics();
    } else {
      alert(res?.error || 'Failed to delete. Please try again.');
      if (btn) { btn.disabled = false; btn.textContent = 'Delete'; }
    }
  } catch (e) {
    alert('Network error. Please try again.');
    if (btn) { btn.disabled = false; btn.textContent = 'Delete'; }
  }
}

// ── Admin: Download receipt as printable HTML (opens in new tab → Save as PDF) ─
function adminDownloadReceipt(donor) {
  if (!donor) return;

  const amountRs    = Math.round((donor.amount_paise || 0) / 100);
  const displayName = donor.is_anonymous ? 'Anonymous' : (donor.name || '—');
  const displayEmail = donor.email || '—';
  const paymentId   = donor.payment_id || '—';
  const orderId     = donor.order_id   || '—';
  const year        = donor.date ? new Date(donor.date).getFullYear() : new Date().getFullYear();
  const rand        = String(Math.floor(Math.random() * 90000) + 10000);
  const invoiceNo   = `KFS-${year}-${rand}`;

  // Format date nicely
  let dtStr = '—';
  if (donor.date) {
    try {
      dtStr = new Date(donor.date).toLocaleDateString('en-IN', {
        day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata'
      }) + ' IST';
    } catch(e) { dtStr = donor.date; }
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KFS Receipt — ${invoiceNo}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  @page{size:A4;margin:20mm}
  body{background:#0d0d0d;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#e8e8e8;padding:40px 20px;min-height:100vh}
  .wrap{max-width:640px;margin:0 auto;background:#111;border:1px solid #222;border-radius:8px;overflow:hidden}
  .header{background:#111;border-bottom:1px solid #1f1f1f;padding:28px 36px;display:flex;align-items:center;gap:16px}
  .logo-text{font-size:22px;font-weight:800;color:#fff;letter-spacing:-.02em}
  .header-title{font-size:16px;font-weight:300;letter-spacing:1.5px;color:#aaa}
  .meta-bar{display:flex;justify-content:space-between;padding:16px 36px;border-bottom:1px solid #1a1a1a}
  .meta-item{font-size:10px;letter-spacing:.8px;color:#666;text-transform:uppercase}
  .meta-val{font-size:13px;font-weight:600;color:#e8e8e8;margin-top:3px}
  .badge{display:inline-block;padding:3px 10px;border-radius:3px;font-size:11px;letter-spacing:1px;background:#1a2a3a;color:#4ea8de;border:1px solid #2a5a8a}
  .info-card{margin:24px 36px;background:#161616;border:1px solid #1f1f1f;border-radius:6px;padding:20px 24px}
  .info-row{display:flex;gap:32px;flex-wrap:wrap}
  .field-label{font-size:9px;letter-spacing:1.2px;color:#555;text-transform:uppercase;margin-bottom:4px}
  .field-val{font-size:14px;font-weight:600;color:#e8e8e8}
  .section-title{font-size:9px;letter-spacing:2px;color:#444;text-transform:uppercase;padding:0 36px;margin:24px 0 12px}
  .details-table{margin:0 36px;border:1px solid #1a1a1a;border-radius:6px;overflow:hidden}
  .dt-row{display:flex;justify-content:space-between;align-items:center;padding:12px 18px;border-bottom:1px solid #161616}
  .dt-row:last-child{border-bottom:none}
  .dt-label{font-size:12px;color:#666}
  .dt-val{font-size:12px;font-weight:500;color:#e0e0e0;text-align:right;font-family:monospace}
  .dt-val.status{color:#4ade80;font-weight:700;font-family:inherit;font-size:13px}
  .amount-bar{margin:24px 36px;background:#1a1a1a;border:1px solid #252525;border-radius:6px;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}
  .amount-label{font-size:13px;font-weight:600;letter-spacing:1px;color:#e8e8e8;text-transform:uppercase}
  .amount-value{font-size:28px;font-weight:700;color:#fff}
  .footer{padding:18px 36px;border-top:1px solid #191919;text-align:center}
  .footer-note{font-size:10px;color:#3a3a3a}
  .footer-links{font-size:11px;color:#444;margin-top:4px}
  .print-btn{position:fixed;bottom:24px;right:24px;background:#fff;color:#000;border:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 4px 20px rgba(0,0,0,.4);z-index:999}
  .print-btn:hover{background:#eee}
  @media print{.print-btn{display:none}body{background:#0d0d0d!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">⬇ Save as PDF</button>
<div class="wrap">
  <div class="header">
    <div style="width:44px;height:44px;border-radius:50%;overflow:hidden;flex-shrink:0">
      <img src="https://kiitfilmsociety.in/images/kfs-logo.png" alt="KFS" width="44" height="44" style="display:block;width:44px;height:44px;object-fit:cover" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'" />
      <div style="display:none;width:44px;height:44px;border-radius:50%;background:#fff;align-items:center;justify-content:center"><span style="font-size:13px;font-weight:800;color:#000;letter-spacing:-.02em">KFS</span></div>
    </div>
    <div>
      <div class="logo-text">KIIT Film Society</div>
      <div class="header-title">PAYMENT RECEIPT</div>
    </div>
  </div>

  <div class="meta-bar">
    <div class="meta-item">Invoice No.<div class="meta-val">${invoiceNo}</div></div>
    <div class="meta-item" style="text-align:right">Type<div class="meta-val"><span class="badge">DONATION</span></div></div>
  </div>

  <div class="info-card">
    <div class="info-row">
      <div style="min-width:140px">
        <div class="field-label">Name</div>
        <div class="field-val">${displayName}</div>
      </div>
      <div style="min-width:140px">
        <div class="field-label">Email</div>
        <div class="field-val" style="font-size:13px">${displayEmail}</div>
      </div>
    </div>
    <div style="margin-top:16px">
      <div class="field-label">Cause</div>
      <div class="field-val">KIIT Film Society</div>
    </div>
  </div>

  <div class="section-title">Payment Details</div>
  <div class="details-table">
    <div class="dt-row"><span class="dt-label">Payment ID</span><span class="dt-val">${paymentId}</span></div>
    <div class="dt-row"><span class="dt-label">Order ID</span><span class="dt-val">${orderId}</span></div>
    <div class="dt-row"><span class="dt-label">Date</span><span class="dt-val" style="font-family:inherit">${dtStr}</span></div>
    <div class="dt-row"><span class="dt-label">Method</span><span class="dt-val" style="font-family:inherit">Razorpay (UPI / Card / Net Banking)</span></div>
    <div class="dt-row"><span class="dt-label">Status</span><span class="dt-val status">PAID <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polyline points="20 6 9 17 4 12"/></svg></span></div>
  </div>

  <div class="amount-bar">
    <div class="amount-label">Total Amount Paid</div>
    <div class="amount-value">Rs. ${amountRs}</div>
  </div>

  <div class="footer">
    <div class="footer-note">Computer-generated receipt — no signature required. &nbsp;|&nbsp; ${donor._isDonorCopy ? 'Donor copy.' : 'Admin copy.'}</div>
    <div class="footer-links">kiitfilmsociety.in &nbsp;·&nbsp; filmsocietykiit@gmail.com &nbsp;·&nbsp; KIIT University, Bhubaneswar</div>
  </div>
</div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url  = URL.createObjectURL(blob);
  const win  = window.open(url, '_blank');
  if (!win) {
    // Fallback: direct download
    const a = document.createElement('a');
    a.href = url;
    a.download = `KFS-Receipt-${invoiceNo}.html`;
    a.click();
  }
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// ── Donor-facing: Download receipt from the success card ──────────────────────
// Called via data-action="donorDownloadReceipt" on #don-rec-dl-btn.
// Receipt data is stored on the button element as _receiptData by submitDonation().
function donorDownloadReceipt() {
  const btn = document.getElementById('don-rec-dl-btn');
  if (!btn || !btn._receiptData) return;
  // Reuse the admin receipt renderer — same format, donor copy label is swapped inside.
  const data = { ...btn._receiptData, _isDonorCopy: true };
  adminDownloadReceipt(data);
}

// ── Admin: Backfill all existing payments to Google Sheet ─────────────────────
async function sheetBackfill(btn) {
  if (!confirm('This will sync ALL existing payment records to Google Sheet.\n\nOnly run this once — it will add duplicate rows if run again.\n\nProceed?')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
  try {
    const res = await apiFetch('/api/admin/donation/sheet-backfill', 'POST');
    if (res && res.success) {
      alert(`Sync complete!\n\nSynced: ${res.synced}\nFailed: ${res.failed}\nTotal: ${res.total}\n\nOpen Google Sheet to see all records.`);
    } else {
      alert('Sync failed: ' + (res?.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Network error during sync. Check server logs.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sync Old Payments'; }
  }
}

// ── Admin: Send a test donation thank-you email ────────────────────────────────
async function testDonationEmail(btn) {
  const email = prompt('Enter email address to send the test to:');
  if (!email || !email.includes('@')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  try {
    const res = await apiFetch('/api/admin/donation/test-email', 'POST', { email });
    if (res && res.success) {
      alert(`Test email sent to ${email}!\nCheck your inbox (and spam folder).\nMessageId: ${res.messageId || '—'}`);
    } else {
      alert('Failed: ' + (res?.error || 'Unknown error — check server logs for [bill] lines'));
    }
  } catch (e) {
    alert('Network error. Check server logs.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Test Email'; }
  }
}

// ── WATCH STATUS (localStorage) ──────────────────────────────────────
function getWatchedMovies() {
  try { return JSON.parse(localStorage.getItem('kfs_watched_movies') || '{}'); } catch { return {}; }
}
function svgFilm(size=18){return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>';}
function svgPerson(size=16){return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg>';}
function isMovieWatched(id) { return !!getWatchedMovies()[id]; }
function setMovieWatched(id, val) {
  const w = getWatchedMovies();
  if (val) w[id] = Date.now(); else delete w[id];
  localStorage.setItem('kfs_watched_movies', JSON.stringify(w));
}

function toggleWatchStatus() {
  const id = window._currentMovieId;
  if (!id) return;
  const nowWatched = !isMovieWatched(id);
  setMovieWatched(id, nowWatched);
  updateDetailWatchBtn(id);
  // Also update any card in the grid
  document.querySelectorAll('.movie-card').forEach(card => {
    const badge = card.querySelector('.movie-watch-badge');
    if (!badge) return;
    const onclick = card.getAttribute('onclick') || '';
    if (!onclick.includes(id)) return;
    badge.innerHTML = nowWatched ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Watched' : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Watchlist';
    badge.classList.toggle('movie-watch-badge--done', nowWatched);
    card.classList.toggle('watched', nowWatched);
  });
}

function updateDetailWatchBtn(id) {
  const btn = document.getElementById('movie-watch-status-btn');
  if (!btn) return;
  const watched = isMovieWatched(id);
  btn.innerHTML = watched
    ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polyline points="20 6 9 17 4 12"/><\/svg> Watched'
    : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><rect x="3" y="3" width="18" height="18" rx="2"/><\/svg> Mark as Watched';
  btn.classList.toggle('is-watched', watched);
  btn.style.cssText = ''; // clear any previously set inline styles
}

function toggleWatchStatusCard(id, cardEl) {
  const nowWatched = !isMovieWatched(id);
  setMovieWatched(id, nowWatched);
  const badge = cardEl.querySelector('.movie-watch-badge');
  if (badge) {
    badge.innerHTML = nowWatched ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Watched' : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Watchlist';
    badge.classList.toggle('movie-watch-badge--done', nowWatched);
  }
  cardEl.classList.toggle('watched', nowWatched);
  // Sync detail btn if same film is open
  if (window._currentMovieId === id) updateDetailWatchBtn(id);
}

// Analytics auto-load is handled inside loadAdminData()

// ── Hero Camera Parallax — removed for performance ──

// ── Member Excel Import ──────────────────────────────────────
let _memberImportNames = [];

function previewMemberImport(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  const reader = new FileReader();
  reader.onload = e => {
    let names = [];
    if (file.name.endsWith('.csv')) {
      // CSV: one name per line
      names = e.target.result.split(/\r?\n/).map(l => l.split(',')[0].trim()).filter(Boolean);
    } else {
      const wb = XLSX.read(e.target.result, { type: 'array' });
      const ws = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(ws, { header: 1 });
      // Use first column, skip header row if it looks like a label
      rows.forEach((row, i) => {
        const val = row[0] ? String(row[0]).trim() : '';
        if (!val) return;
        // Skip obvious header row
        if (i === 0 && /name|member|sl\.?|no\.|s\.no/i.test(val)) return;
        names.push(val);
      });
    }
    _memberImportNames = names;
    const tbody = document.getElementById('member-import-tbody');
    tbody.innerHTML = names.map((n, i) => `
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:9px 14px;color:var(--grey)">${i + 1}</td>
        <td style="padding:9px 14px;font-weight:500">${n}</td>
        <td id="import-status-${i}" style="padding:9px 14px;color:var(--grey)">—</td>
      </tr>`).join('');
    document.getElementById('member-import-summary').textContent = `${names.length} name${names.length !== 1 ? 's' : ''} found — review and click Import All.`;
    document.getElementById('member-import-btn').textContent = `Import ${names.length}`;
    document.getElementById('member-import-modal').style.display = 'flex';
  };
  file.name.endsWith('.csv') ? reader.readAsText(file) : reader.readAsArrayBuffer(file);
}

function closeMemberImport() {
  document.getElementById('member-import-modal').style.display = 'none';
  _memberImportNames = [];
}

async function runMemberImport() {
  if (!_memberImportNames.length) return;
  const btn = document.getElementById('member-import-btn');
  btn.disabled = true;
  btn.textContent = 'Checking…';

  // Fetch all existing member names upfront to detect duplicates before sending
  let existingNames = new Set();
  try {
    const chkRes = await fetch('/api/members', { headers: { Authorization: 'Bearer ' + adminToken } });
    const existing = await chkRes.json();
    existingNames = new Set((existing || []).map(m => m.name.trim().toLowerCase()));
  } catch { /* if fetch fails, fall through — server-side guard still protects */ }

  btn.textContent = 'Importing…';
  let ok = 0, skipped = 0, fail = 0;
  for (let i = 0; i < _memberImportNames.length; i++) {
    const name = _memberImportNames[i];
    const statusEl = document.getElementById(`import-status-${i}`);

    // ── Client-side duplicate check (also catches dupes within the same sheet) ──
    if (existingNames.has(name.trim().toLowerCase())) {
      skipped++;
      statusEl.innerHTML = '<span style="color:#ff9800">Duplicate</span>';
      continue;
    }

    try {
      const fd = new FormData();
      fd.append('name', name);
      fd.append('role', 'Member');
      fd.append('batch', '');
      fd.append('domain', '');
      fd.append('bio', '');
      fd.append('sort_order', '99');
      fd.append('is_past', 'false');
      const res = await fetch('/api/admin/members', {
        method: 'POST', credentials: 'include',
        headers: { Authorization: 'Bearer ' + adminToken, 'X-CSRF-Token': _csrfToken || '' },
        body: fd
      });
      if (res.ok) {
        ok++;
        existingNames.add(name.trim().toLowerCase()); // prevent within-sheet dupes
        statusEl.innerHTML = '<span style="color:#4caf50">✓ Added</span>';
      } else {
        const json = await res.json().catch(() => ({}));
        if (res.status === 409) {
          skipped++;
          statusEl.innerHTML = '<span style="color:#ff9800">Duplicate</span>';
        } else {
          fail++;
          statusEl.innerHTML = `<span style="color:#f44" title="${json.error || ''}">Error</span>`;
        }
      }
    } catch {
      fail++;
      statusEl.innerHTML = '<span style="color:#f44">Error</span>';
    }
  }

  let summary = `Done — ${ok} imported`;
  if (skipped) summary += `, ${skipped} skipped (already exists)`;
  if (fail) summary += `, ${fail} failed`;
  document.getElementById('member-import-summary').textContent = summary + '.';
  btn.textContent = 'Done';
  if (ok > 0) loadAdminSection('members');
}


// ════════════════════════════════════════════════════════════════════════════
// FORM BUILDER (Admin)
// ════════════════════════════════════════════════════════════════════════════
let _fbEventId = null;
let _fbEventTitle = '';
let _fbQuestions = [];
let _fbResponseCount = 0;

async function openFormBuilder(eventId, eventTitle) {
  _fbEventId = eventId;
  _fbEventTitle = eventTitle;
  _fbQuestions = [];
  document.getElementById('fb-event-label').textContent = eventTitle;
  document.getElementById('fb-title').textContent = 'Registration Form';
  document.getElementById('fb-form-title').value = '';
  document.getElementById('fb-form-desc').value = '';
  document.getElementById('fb-is-open').checked = true;
  document.getElementById('fb-open-label').textContent = 'Form is Open';
  document.getElementById('fb-response-count').textContent = '0 responses';
  document.getElementById('fb-questions').innerHTML = '';

  // Try to load existing form
  try {
    const res = await fetch('/api/events/' + eventId + '/form');
    if (res.ok) {
      const form = await res.json();
      document.getElementById('fb-form-title').value = form.title || '';
      document.getElementById('fb-form-desc').value = form.description || '';
      document.getElementById('fb-is-open').checked = form.is_open !== false;
      document.getElementById('fb-open-label').textContent = form.is_open !== false ? 'Form is Open' : 'Form is Closed';
      try { _fbQuestions = JSON.parse(form.questions || '[]'); } catch(e){ _fbQuestions = []; }
      // Load response count
      try {
        const rRes = await fetch('/api/admin/events/' + eventId + '/form/responses', {
          headers: { 'Authorization': 'Bearer ' + adminToken }
        });
        if (rRes.ok) {
          const rs = await rRes.json();
          _fbResponseCount = rs.length;
          document.getElementById('fb-response-count').textContent = rs.length + (rs.length === 1 ? ' response' : ' responses');
        }
      } catch(e){}
    }
  } catch(e){}

  renderFBQuestions();
  const isOpenEl = document.getElementById('fb-is-open');
  isOpenEl.onchange = function() {
    document.getElementById('fb-open-label').textContent = this.checked ? 'Form is Open' : 'Form is Closed';
  };
  document.getElementById('form-builder-overlay').classList.add('open');
}

function closeFormBuilder() {
  document.getElementById('form-builder-overlay').classList.remove('open');
}

function addFBQuestion(q=null) {
  const id = 'q_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
  _fbQuestions.push(q || { id, label: '', type: 'text', required: false, options: [] });
  renderFBQuestions();
  // Scroll to new question
  setTimeout(() => {
    const cards = document.querySelectorAll('.fb-question-card');
    if (cards.length) cards[cards.length-1].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 60);
}

function removeFBQuestion(idx) {
  _fbQuestions.splice(idx, 1);
  renderFBQuestions();
}

function fbQuestionTypeChange(idx, val) {
  _fbQuestions[idx].type = val;
  if ((val === 'radio' || val === 'checkbox') && !_fbQuestions[idx].options.length) {
    _fbQuestions[idx].options = ['Option 1', 'Option 2'];
  }
  renderFBQuestions();
}

function addFBOption(idx) {
  _fbQuestions[idx].options.push('');
  renderFBQuestions();
}

function removeFBOption(qIdx, oIdx) {
  _fbQuestions[qIdx].options.splice(oIdx, 1);
  renderFBQuestions();
}

function syncFBState() {
  // Sync all live input values back to _fbQuestions before re-render
  document.querySelectorAll('.fb-question-card').forEach((card, i) => {
    if (!_fbQuestions[i]) return;
    const labelEl = card.querySelector('.fb-q-label');
    const typeEl = card.querySelector('.fb-q-type');
    const reqEl = card.querySelector('.fb-q-req');
    if (labelEl) _fbQuestions[i].label = labelEl.value;
    if (typeEl) _fbQuestions[i].type = typeEl.value;
    if (reqEl) _fbQuestions[i].required = reqEl.checked;
    const optInputs = card.querySelectorAll('.fb-option-input');
    optInputs.forEach((inp, j) => {
      if (_fbQuestions[i].options && _fbQuestions[i].options[j] !== undefined)
        _fbQuestions[i].options[j] = inp.value;
    });
  });
}

function renderFBQuestions() {
  const wrap = document.getElementById('fb-questions');
  const TYPE_LABELS = { text:'Short Text', email:'Email', phone:'Phone Number', textarea:'Long Text', radio:'Multiple Choice', checkbox:'Checkboxes', image:'Image Upload' };

  wrap.innerHTML = _fbQuestions.map((q, i) => `
    <div class="fb-question-card" data-idx="${i}">
      <div class="fb-q-row">
        <input class="fb-q-label" placeholder="Question label..." value="${(q.label||'').replace(/"/g,'&quot;')}"
          oninput="syncFBFieldLabel(${i},this.value)">
        <select class="fb-q-type" onchange="fbQuestionTypeChange(${i},this.value)">
          ${Object.entries(TYPE_LABELS).map(([v,l])=>`<option value="${v}" ${q.type===v?'selected':''}>${l}</option>`).join('')}
        </select>
        <label class="fb-q-required"><input type="checkbox" class="fb-q-req" ${q.required?'checked':''} onchange="syncFBFieldReq(${i},this.checked)"> Required</label>
        <button class="fb-q-delete" onclick="syncFBState();removeFBQuestion(${i})" title="Remove">✕</button>
      </div>
      ${(q.type === 'radio' || q.type === 'checkbox') ? `
        <div class="fb-options-wrap">
          ${(q.options||[]).map((opt,j) => `
            <div class="fb-option-row">
              <span style="color:var(--grey);font-size:12px;width:16px;text-align:center">${q.type==='radio'?'◯':'☐'}</span>
              <input class="fb-option-input" placeholder="Option ${j+1}" value="${(opt||'').replace(/"/g,'&quot;')}"
                oninput="syncFBOptionVal(${i},${j},this.value)">
              <button class="fb-option-del" onclick="syncFBState();removeFBOption(${i},${j})">✕</button>
            </div>
          `).join('')}
          <button class="fb-add-option" onclick="syncFBState();addFBOption(${i})">+ Add option</button>
        </div>` : ''}
      ${q.type === 'image' ? `<div class="fb-image-hint">Respondents will upload an image file (JPEG, PNG, max 10MB)</div>` : ''}
    </div>
  `).join('');
}

function syncFBFieldLabel(idx, val) { _fbQuestions[idx].label = val; }
function syncFBFieldReq(idx, val) { _fbQuestions[idx].required = val; }
function syncFBOptionVal(idx, oIdx, val) {
  if (_fbQuestions[idx].options) _fbQuestions[idx].options[oIdx] = val;
}

async function saveFormBuilder() {
  syncFBState();
  const title = document.getElementById('fb-form-title').value.trim() || _fbEventTitle + ' Registration';
  const desc = document.getElementById('fb-form-desc').value.trim();
  const is_open = document.getElementById('fb-is-open').checked;
  const btn = document.getElementById('fb-save-btn');
  btn.textContent = 'Saving…'; btn.disabled = true;
  try {
    const token = adminToken;
    const res = await fetch('/api/admin/events/' + _fbEventId + '/form', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify({ title, description: desc, questions: _fbQuestions, is_open })
    });
    if (res.ok) {
      btn.textContent = '✓ Saved'; btn.disabled = false;
      setTimeout(() => btn.textContent = 'Save Form', 2000);
    } else {
      const err = await res.json().catch(() => ({}));
      alert('Error saving form: ' + (err.error || res.status));
      btn.textContent = 'Save Form'; btn.disabled = false;
    }
  } catch(e) {
    alert('Error saving form: ' + e.message);
    btn.textContent = 'Save Form'; btn.disabled = false;
  }
}

async function clearFormResponses() {
  if (!_fbEventId) return;
  if (!confirm(`Clear ALL responses for "${_fbEventTitle}"?\n\nThis frees up Supabase storage but cannot be undone. The form schema will be kept.`)) return;
  const btn = document.getElementById('fb-clear-btn');
  const origHtml = btn.innerHTML;
  btn.textContent = 'Clearing…'; btn.disabled = true;
  try {
    const token = adminToken;
    const res = await fetch('/api/admin/events/' + _fbEventId + '/form/responses', {
      method: 'DELETE', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + token, 'X-CSRF-Token': _csrfToken || '' }
    });
    if (res.ok) {
      _fbResponseCount = 0;
      document.getElementById('fb-response-count').textContent = '0 responses';
      btn.textContent = '✓ Cleared';
      setTimeout(() => { btn.innerHTML = origHtml; btn.disabled = false; }, 2000);
    } else {
      const err = await res.json().catch(() => ({}));
      alert('Failed to clear responses: ' + (err.error || res.status));
      btn.innerHTML = origHtml; btn.disabled = false;
    }
  } catch(e) {
    alert('Error: ' + e.message);
    btn.innerHTML = origHtml; btn.disabled = false;
  }
}

async function deleteEntireForm() {
  if (!_fbEventId) return;
  if (!confirm(`Delete the ENTIRE form for "${_fbEventTitle}"?\n\nThis removes the form schema AND all responses permanently. This frees up Supabase space and cannot be undone.`)) return;
  const btn = document.getElementById('fb-del-form-btn');
  const origHtml = btn.innerHTML;
  btn.textContent = 'Deleting…'; btn.disabled = true;
  try {
    const token = adminToken;
    const res = await fetch('/api/admin/events/' + _fbEventId + '/form', {
      method: 'DELETE', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + token, 'X-CSRF-Token': _csrfToken || '' }
    });
    if (res.ok) {
      btn.textContent = '✓ Deleted';
      setTimeout(() => {
        closeFormBuilder();
        // Reset form builder state
        _fbQuestions = [];
        _fbResponseCount = 0;
      }, 1200);
    } else {
      const err = await res.json().catch(() => ({}));
      alert('Failed to delete form: ' + (err.error || res.status));
      btn.innerHTML = origHtml; btn.disabled = false;
    }
  } catch(e) {
    alert('Error: ' + e.message);
    btn.innerHTML = origHtml; btn.disabled = false;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// RESPONSE VIEWER
// ════════════════════════════════════════════════════════════════════════════
let _fbResponsesCache = null; // cache fetched responses for download

async function openResponseViewer() {
  const viewer = document.getElementById('fb-resp-viewer');
  const body = document.getElementById('fb-rv-body');
  const countEl = document.getElementById('fb-rv-count');
  viewer.classList.add('open');
  body.innerHTML = '<div class="fb-rv-loading">Loading responses…</div>';
  countEl.textContent = '';

  try {
    const token = adminToken;
    const [formRes, respRes] = await Promise.all([
      fetch('/api/events/' + _fbEventId + '/form'),
      fetch('/api/admin/events/' + _fbEventId + '/form/responses', {
        headers: { 'Authorization': 'Bearer ' + token }
      })
    ]);

    if (!respRes.ok) {
      body.innerHTML = '<div class="fb-rv-empty"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>Failed to load responses.</span></div>';
      return;
    }

    const responses = await respRes.json();
    _fbResponsesCache = responses;

    let questions = _fbQuestions;
    if (formRes.ok) {
      const form = await formRes.json();
      try { questions = JSON.parse(form.questions || '[]'); } catch(e) {}
    }

    countEl.textContent = responses.length + ' response' + (responses.length !== 1 ? 's' : '');

    if (!responses.length) {
      body.innerHTML = `<div class="fb-rv-empty">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="13" y2="13"/></svg>
        <span>No responses yet</span>
      </div>`;
      return;
    }

    body.innerHTML = responses.map((r, i) => {
      let answers = {};
      try { answers = JSON.parse(r.answers || '{}'); } catch(e) {}
      const time = r.submitted_at ? new Date(r.submitted_at).toLocaleString('en-GB', { day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }) : '';
      const answerRows = questions.map(q => {
        const val = answers[q.id] || answers[q.label] || '';
        const display = Array.isArray(val) ? val.join(', ') : String(val);
        if (!display) return '';
        return `<div class="fb-rv-answer">
          <div class="fb-rv-q">${q.label || q.id}</div>
          <div class="fb-rv-a">${display.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
        </div>`;
      }).filter(Boolean).join('');

      return `<div class="fb-rv-row">
        <div class="fb-rv-row-header">
          <div class="fb-rv-num">${i + 1}</div>
          <div class="fb-rv-time">${time}</div>
        </div>
        <div class="fb-rv-answers">${answerRows || '<div class="fb-rv-a" style="opacity:.4">No text answers</div>'}</div>
      </div>`;
    }).join('');

  } catch(e) {
    body.innerHTML = '<div class="fb-rv-empty"><span>Error: ' + e.message + '</span></div>';
  }
}

function closeResponseViewer() {
  document.getElementById('fb-resp-viewer').classList.remove('open');
}

async function downloadFormResponsesFromViewer() {
  const btn = document.getElementById('fb-rv-dl-btn');
  const origHtml = btn.innerHTML;
  btn.textContent = 'Loading…'; btn.disabled = true;
  try {
    await downloadFormResponses();
  } finally {
    btn.innerHTML = origHtml; btn.disabled = false;
  }
}

async function downloadFormResponses() {
  if (!_fbEventId) return;
  const btn = document.getElementById('fb-dl-btn');
  btn.textContent = 'Loading…'; btn.disabled = true;

  try {
    const [formRes, respRes] = await Promise.all([
      fetch('/api/events/' + _fbEventId + '/form'),
      fetch('/api/admin/events/' + _fbEventId + '/form/responses', {
        headers: { 'Authorization': 'Bearer ' + adminToken }
      })
    ]);

    if (!respRes.ok) { alert('Failed to load responses'); return; }
    const responses = await respRes.json();

    if (!responses.length) { alert('No responses yet.'); return; }

    // Parse form questions for headers
    let questions = _fbQuestions;
    if (formRes.ok) {
      const form = await formRes.json();
      try { questions = JSON.parse(form.questions || '[]'); } catch(e){}
    }

    // Build CSV
    const headers = ['#', 'Submitted At', ...questions.map(q => q.label || q.id)];
    const rows = responses.map((r, i) => {
      let answers = {};
      try { answers = JSON.parse(r.answers || '{}'); } catch(e){}
      return [
        i + 1,
        new Date(r.submitted_at).toLocaleString(),
        ...questions.map(q => {
          const val = answers[q.id] || answers[q.label] || '';
          if (Array.isArray(val)) return val.join(', ');
          return String(val);
        })
      ];
    });

    // Generate XLSX using SheetJS if available, otherwise CSV
    if (window.XLSX) {
      const wsData = [headers, ...rows];
      const ws = XLSX.utils.aoa_to_sheet(wsData);
      // Column widths
      ws['!cols'] = headers.map((h,i) => ({ wch: i===0?5:i===1?20:Math.max(h.length+4, 16) }));
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Responses');
      XLSX.writeFile(wb, (_fbEventTitle||'event').replace(/[^a-z0-9]/gi,'_') + '_responses.xlsx');
    } else {
      // Fallback to CSV
      const escape = v => `"${String(v).replace(/"/g,'""')}"`;
      const csv = [headers, ...rows].map(row => row.map(escape).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = (_fbEventTitle||'event').replace(/[^a-z0-9]/gi,'_') + '_responses.csv';
      a.click(); URL.revokeObjectURL(url);
    }
  } catch(e) {
    alert('Download failed: ' + e.message);
  } finally {
    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Responses`;
    btn.disabled = false;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// REGISTRATION FORM (Public)
// ════════════════════════════════════════════════════════════════════════════
let _rfEventId = null;
let _rfEventTitle = '';
let _rfEventDate = '';
let _rfEventTime = '';
let _rfEventLocation = '';
let _rfForm = null;
let _rfImageFiles = {};

// Safe wrappers — look up event from registry to avoid apostrophe/quote issues in onclick
function openEventFormById(eventId) {
  const e = (window._eventRegistry || {})[eventId];
  if (!e) return;
  openEventForm(e.id, e.title, e.event_date || '', e.event_time || '', e.location || '');
}
function shareEventById(eventId) {
  const e = (window._eventRegistry || {})[eventId];
  if (!e) return;
  const dateStr = e.event_date
    ? new Date(e.event_date).toLocaleDateString('en-IN', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
    : '';
  shareEventCard(e.id, e.title, dateStr, e.venue || e.location || '');
}

async function openEventForm(eventId, eventTitle, eventDate='', eventTime='', eventLocation='') {
  _rfEventId = eventId;
  _rfEventTitle = eventTitle;
  _rfEventDate = eventDate;
  _rfEventTime = eventTime;
  _rfEventLocation = eventLocation;
  _rfForm = null;
  _rfImageFiles = {};

  document.getElementById('rf-event-label').textContent = eventTitle;
  document.getElementById('rf-title').textContent = 'Registration';
  document.getElementById('rf-desc').textContent = '';
  document.getElementById('rf-body').innerHTML = '<div style="padding:40px;text-align:center;color:var(--grey);font-size:14px">Loading form…</div>';
  document.getElementById('rf-submit-row').style.display = 'flex';
  document.getElementById('reg-form-overlay').classList.add('open');

  const res = await fetch('/api/events/' + eventId + '/form');
  if (!res.ok) {
    document.getElementById('rf-body').innerHTML = '<div style="padding:40px;text-align:center;color:var(--grey)">No registration form available for this event.</div>';
    document.getElementById('rf-submit-row').style.display = 'none';
    return;
  }
  const form = await res.json();
  if (!form.is_open) {
    document.getElementById('rf-body').innerHTML = '<div style="padding:40px;text-align:center;color:var(--grey)">Registrations are currently closed.</div>';
    document.getElementById('rf-submit-row').style.display = 'none';
    return;
  }

  _rfForm = form;
  let questions = [];
  try { questions = JSON.parse(form.questions || '[]'); } catch(e){}

  document.getElementById('rf-title').textContent = form.title || eventTitle + ' Registration';
  document.getElementById('rf-desc').textContent = form.description || '';

  document.getElementById('rf-body').innerHTML = questions.map(q => buildRegField(q)).join('');
}

function buildRegField(q) {
  const req = q.required ? `<span class="req-dot">*</span>` : '';
  const label = `<div class="reg-field-label">${q.label || 'Question'}${req}</div>`;

  if (q.type === 'text' || q.type === 'email' || q.type === 'phone') {
    const t = q.type === 'email' ? 'email' : q.type === 'phone' ? 'tel' : 'text';
    const ph = q.type === 'email' ? 'you@example.com' : q.type === 'phone' ? '+91 XXXXX XXXXX' : 'Your answer';
    return `<div class="reg-field" data-qid="${q.id}">
      ${label}
      <input class="reg-input" type="${t}" placeholder="${ph}" data-qid="${q.id}" ${q.required?'required':''} oninput="(function(){var e=document.getElementById('rf-submit-error');if(e)e.style.display='none';})()">
    </div>`;
  }
  if (q.type === 'textarea') {
    return `<div class="reg-field" data-qid="${q.id}">
      ${label}
      <textarea class="reg-textarea" placeholder="Your answer…" data-qid="${q.id}" ${q.required?'required':''}></textarea>
    </div>`;
  }
  if (q.type === 'radio') {
    const opts = (q.options || []).map((opt, i) => `
      <label class="reg-radio-item" onclick="selectRadioItem(this)">
        <input type="radio" name="q_${q.id}" value="${(opt||'').replace(/"/g,'&quot;')}" data-qid="${q.id}">
        ${opt}
      </label>`).join('');
    return `<div class="reg-field" data-qid="${q.id}">${label}<div class="reg-radio-group">${opts}</div></div>`;
  }
  if (q.type === 'checkbox') {
    const opts = (q.options || []).map((opt, i) => `
      <label class="reg-check-item" onclick="toggleCheckItem(this)">
        <input type="checkbox" value="${(opt||'').replace(/"/g,'&quot;')}" data-qid="${q.id}">
        ${opt}
      </label>`).join('');
    return `<div class="reg-field" data-qid="${q.id}">${label}<div class="reg-check-group">${opts}</div></div>`;
  }
  if (q.type === 'image') {
    return `<div class="reg-field" data-qid="${q.id}">
      ${label}
      <div class="reg-image-upload" id="img-upload-${q.id}">
        <input type="file" accept="image/*" data-qid="${q.id}" onchange="previewRegImage(this,'${q.id}')">
        <div class="reg-image-upload-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>
        <div class="reg-image-upload-text">Click to upload image<br><span style="font-size:11px;opacity:.6">JPEG, PNG — max 10MB</span></div>
        <img class="reg-image-preview" id="img-preview-${q.id}" src="" alt="">
      </div>
    </div>`;
  }
  return `<div class="reg-field" data-qid="${q.id}">${label}<input class="reg-input" type="text" placeholder="Your answer" data-qid="${q.id}"></div>`;
}

function selectRadioItem(label) {
  const name = label.querySelector('input').name;
  document.querySelectorAll(`input[name="${name}"]`).forEach(inp => {
    inp.closest('.reg-radio-item').classList.remove('selected');
  });
  label.classList.add('selected');
}

function toggleCheckItem(label) {
  const inp = label.querySelector('input[type=checkbox]');
  // toggled after click, so check current state
  setTimeout(() => label.classList.toggle('selected', inp.checked), 0);
}

function previewRegImage(input, qid) {
  const file = input.files[0];
  if (!file) return;
  _rfImageFiles[qid] = file;
  const prev = document.getElementById('img-preview-' + qid);
  if (prev) {
    prev.src = URL.createObjectURL(file);
    prev.style.display = 'block';
  }
  const hint = input.closest('.reg-image-upload').querySelector('.reg-image-upload-text');
  if (hint) hint.textContent = file.name;
}

async function submitRegForm() {
  if (!_rfForm || !_rfEventId) return;
  let questions = [];
  try { questions = JSON.parse(_rfForm.questions || '[]'); } catch(e){}

  // Collect answers
  const answers = {};
  let valid = true;
  let firstInvalid = null;
  for (const q of questions) {
    if (q.type === 'text' || q.type === 'email' || q.type === 'phone' || q.type === 'textarea') {
      // Target the actual input/textarea, NOT the wrapper div
      const el = document.querySelector(`input[data-qid="${q.id}"], textarea[data-qid="${q.id}"]`);
      const val = el ? el.value.trim() : '';
      if (q.required && !val) { firstInvalid = el; valid = false; break; }
      answers[q.id] = val;
    } else if (q.type === 'radio') {
      const checked = document.querySelector(`input[name="q_${q.id}"]:checked`);
      if (q.required && !checked) { valid = false; break; }
      answers[q.id] = checked ? checked.value : '';
    } else if (q.type === 'checkbox') {
      const checked = [...document.querySelectorAll(`input[data-qid="${q.id}"]:checked`)].map(i => i.value);
      if (q.required && !checked.length) { valid = false; break; }
      answers[q.id] = checked;
    } else if (q.type === 'image') {
      if (q.required && !_rfImageFiles[q.id]) { valid = false; break; }
    }
  }

  if (!valid) {
    if (firstInvalid) firstInvalid.focus();
    const btn = document.getElementById('rf-submit-btn');
    const orig = btn.innerHTML;
    btn.innerHTML = 'Please fill all required fields';
    btn.style.background = '#ff453a';
    setTimeout(() => { btn.innerHTML = orig; btn.style.background = ''; }, 2500);
    return;
  }

  const btn = document.getElementById('rf-submit-btn');
  btn.disabled = true;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.2-8.6"/></svg> Submitting…';

  // Clear any previous duplicate/error message before each attempt
  const prevErr = document.getElementById('rf-submit-error');
  if (prevErr) prevErr.style.display = 'none';

  try {
    const fd = new FormData();
    fd.append('answers', JSON.stringify(answers));
    for (const [qid, file] of Object.entries(_rfImageFiles)) {
      fd.append(qid, file);
    }

    const res = await fetch('/api/events/' + _rfEventId + '/form/submit', { method: 'POST', credentials: 'include', body: fd });

    if (res.ok) {
      document.querySelector('.reg-form-header').style.display = 'none';
      document.getElementById('rf-submit-row').style.display = 'none';
      const errEl2 = document.getElementById('rf-submit-error');
      if (errEl2) errEl2.style.display = 'none';

      // ── Track event registration in localStorage for Wrapped ──
      try {
        const evts = JSON.parse(localStorage.getItem('kfs_registered_events') || '{}');
        evts[_rfEventId] = { title: _rfEventTitle, ts: Date.now() };
        localStorage.setItem('kfs_registered_events', JSON.stringify(evts));
      } catch(e) {}

      // Build Google Calendar URL from stored event variables
      const _gcTitle = encodeURIComponent(_rfEventTitle);
      const _gcLoc   = encodeURIComponent(_rfEventLocation || '');
      let _gcDates = '';
      if (_rfEventDate) {
        const base = _rfEventDate.replace(/-/g, '');
        if (_rfEventTime) {
          const t = _rfEventTime.trim();
          let h = 0, m = 0;
          const ampm = t.match(/(\d{1,2}):(\d{2})\s*(AM|PM)/i);
          const h24  = t.match(/^(\d{1,2}):(\d{2})$/);
          if (ampm) {
            h = parseInt(ampm[1]); m = parseInt(ampm[2]);
            if (/PM/i.test(ampm[3]) && h !== 12) h += 12;
            if (/AM/i.test(ampm[3]) && h === 12) h = 0;
          } else if (h24) { h = parseInt(h24[1]); m = parseInt(h24[2]); }
          const pad = n => String(n).padStart(2,'0');
          const eh = Math.min(h + 2, 23);
          _gcDates = base + 'T' + pad(h) + pad(m) + '00/' + base + 'T' + pad(eh) + pad(m) + '00';
        } else {
          _gcDates = base + '/' + base;
        }
      }
      const _gcUrl = 'https://calendar.google.com/calendar/render?action=TEMPLATE&text=' + _gcTitle + '&dates=' + _gcDates + '&location=' + _gcLoc + '&details=' + encodeURIComponent('Registered via KFS — KIIT Film Society');

      document.getElementById('rf-body').innerHTML = `
        <div class="reg-success">
          <div class="reg-success-icon">
            <svg width="52" height="52" viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="26" cy="26" r="25" stroke="rgba(245,245,245,0.15)" stroke-width="1.5"/>
              <rect x="12" y="17" width="28" height="20" rx="3" stroke="currentColor" stroke-width="1.8" fill="none"/>
              <path d="M12 21h28M12 29h28M20 17v20M32 17v20" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
              <circle cx="38" cy="14" r="6" fill="#34c759"/>
              <path d="M35.5 14l1.8 1.8 3-3" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div class="reg-success-title">You\'re registered!</div>
          <div class="reg-success-sub">We\'ll see you at <strong>${_rfEventTitle}</strong>. Stay tuned for updates.</div>
          <div style="display:flex;gap:10px;margin-top:24px;flex-wrap:wrap;justify-content:center">
            ${_rfEventDate ? `<a href="${_gcUrl}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:8px;padding:11px 22px;background:rgba(255,255,255,.1);color:var(--white);border:1px solid rgba(255,255,255,.2);border-radius:50px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none" onmouseover="this.style.background=\'rgba(255,255,255,.18)\'" onmouseout="this.style.background=\'rgba(255,255,255,.1)\'"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><path d="M8 14h.01M12 14h.01M16 14h.01M8 18h.01M12 18h.01"/></svg>Add to Google Calendar</a>` : ''}
            <a href="https://wa.me/?text=${encodeURIComponent('I just registered for ' + _rfEventTitle + ' by KFS — KIIT Film Society! Join me: https://kiitfilmsociety.in/events')}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:8px;padding:11px 22px;background:rgba(37,211,102,.12);color:#25d366;border:1px solid rgba(37,211,102,.3);border-radius:50px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none" onmouseover="this.style.background=\'rgba(37,211,102,.2)\'" onmouseout="this.style.background=\'rgba(37,211,102,.12)\'"><svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>Share on WhatsApp</a>
            <button onclick="closeRegForm()" style="padding:11px 28px;background:var(--white);color:var(--black);border:none;border-radius:50px;font:inherit;font-size:13px;font-weight:600;cursor:pointer">Close</button>
          </div>
        </div>`;
    } else {
      const err = await res.json().catch(() => ({}));
      console.error('Form submit failed:', res.status, err);
      const errMsg = err.error || `Submission failed (${res.status}). Please try again.`;
      let errEl = document.getElementById('rf-submit-error');
      if (!errEl) {
        errEl = document.createElement('div');
        errEl.id = 'rf-submit-error';
        errEl.style.cssText = 'color:#ff453a;font-size:13px;text-align:center;margin-top:10px;padding:10px 16px;background:rgba(255,69,58,.1);border-radius:10px;border:1px solid rgba(255,69,58,.25)';
        document.getElementById('rf-submit-row').after(errEl);
      }
      errEl.textContent = errMsg;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.innerHTML = 'Submit <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>';
    }
  } catch(err) {
    console.error('Form submit error:', err);
    alert('Network error. Please check your connection and try again.');
    btn.disabled = false;
    btn.innerHTML = 'Submit <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>';
  }
}

// ── SHARE EVENT ──────────────────────────────────────────────────────────────
function shareEvent(id, title) {
  const url = 'https://kiitfilmsociety.in/events';
  const text = `Check out "${title}" by KFS — KIIT Film Society!`;
  if (navigator.share) {
    navigator.share({ title, text, url }).catch(()=>{});
  } else {
    const waUrl = `https://wa.me/?text=${encodeURIComponent(text + '\n' + url)}`;
    window.open(waUrl, '_blank');
  }
}

// ── SHARE WITH DYNAMIC OG ─────────────────────────────────────────────────────
// Updates OG/twitter meta tags to the dynamic image before sharing so that
// WhatsApp / Telegram / iMessage previews show the right card.
function _setOGImage(imageUrl, width=1200, height=630) {
  const set = (attr, prop, val) => {
    let el = document.querySelector(`meta[${attr}="${prop}"]`);
    if (!el) { el = document.createElement('meta'); el.setAttribute(attr, prop); document.head.appendChild(el); }
    el.setAttribute('content', val);
  };
  set('property', 'og:image',        imageUrl);
  set('property', 'og:image:width',  String(width));
  set('property', 'og:image:height', String(height));
  set('name',     'twitter:image',   imageUrl);
}

function shareFilmCard(id, title, description, posterUrl) {
  const slug    = (title || '').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  const pageUrl = `https://kiitfilmsociety.in/films/${slug}-${id}`;
  // Server injects real OG tags at /films/:slug for crawlers — no JS meta mutation needed.
  // NOTE: do NOT include pageUrl in `text` — navigator.share appends `url` automatically.
  const text = description ? `"${title}" — a film by KFS | KIIT Film Society\n${description}` : `"${title}" — a film by KFS | KIIT Film Society`;
  if (navigator.share) {
    navigator.share({ title: title + ' — KFS', text, url: pageUrl }).catch(()=>{});
  } else {
    _copyShareFallback(pageUrl);
  }
}

function shareBlogCard(id, title, excerpt, coverUrl) {
  const slug    = (title || '').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  const pageUrl = `https://kiitfilmsociety.in/blog/${slug}-${id}`;
  // Server injects real OG tags at /blog/:slug for crawlers — no JS meta mutation needed.
  // NOTE: do NOT include pageUrl in `text` — navigator.share appends `url` automatically,
  // which would cause the link to appear twice in the share sheet.
  const text = excerpt ? `"${title}" — KFS Blog\n${excerpt}` : `"${title}" — KFS Blog`;
  if (navigator.share) {
    navigator.share({ title: title + ' — KFS Blog', text, url: pageUrl }).catch(()=>{});
  } else {
    _copyShareFallback(pageUrl);
  }
}

function shareEventCard(id, title, date, venue) {
  const slug    = (title || '').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  const pageUrl = `https://kiitfilmsociety.in/events/${slug}-${id}`;
  // Server injects real OG tags at /events/:slug for crawlers — no JS meta mutation needed.
  // NOTE: do NOT include pageUrl in `text` — navigator.share appends `url` automatically.
  const lines = [`"${title}" — KFS Event`];
  if (date)  lines.push('\u{1F4C5} ' + date);
  if (venue) lines.push('\u{1F4CD} ' + venue);
  const text = lines.join('\n');
  if (navigator.share) {
    navigator.share({ title: title + ' — KFS', text, url: pageUrl }).catch(()=>{});
  } else {
    _copyShareFallback(pageUrl);
  }
}

function _copyShareFallback(url) {
  // Show a brief "Copied!" toast instead of a WhatsApp fallback
  navigator.clipboard?.writeText(url).then(() => {
    _showShareToast('Link copied!');
  }).catch(() => {
    const waUrl = `https://wa.me/?text=${encodeURIComponent(url)}`;
    window.open(waUrl, '_blank');
  });
}

function _showShareToast(msg) {
  let t = document.getElementById('_share_toast');
  if (!t) {
    t = document.createElement('div');
    t.id = '_share_toast';
    t.style.cssText = [
      'position:fixed','bottom:28px','left:50%','transform:translateX(-50%) translateY(20px)',
      'background:#f5f5f5','color:#0a0a0a','font-size:13px','font-weight:600',
      'padding:10px 22px','border-radius:999px','pointer-events:none',
      'opacity:0','transition:opacity .2s,transform .2s','z-index:9999',
    ].join(';');
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = '1';
  t.style.transform = 'translateX(-50%) translateY(0)';
  clearTimeout(t._tid);
  t._tid = setTimeout(() => {
    t.style.opacity = '0';
    t.style.transform = 'translateX(-50%) translateY(20px)';
  }, 2200);
}

// ── SORT HOME FILMS ───────────────────────────────────────────────────────────
let _allHomeMovies = [];
function sortHomeFilms(type, btn) {
  document.querySelectorAll('.film-sort-pill').forEach(p=>p.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (!_allHomeMovies.length) return;
  let sorted = [..._allHomeMovies];
  if (type === 'top') {
    sorted.sort((a,b) => {
      const ra = window._movieRatings?.[a.id]?.avg || 0;
      const rb = window._movieRatings?.[b.id]?.avg || 0;
      return rb - ra;
    });
  } else if (type === 'loved') {
    sorted.sort((a,b) => {
      const ca = window._movieRatings?.[a.id]?.count || 0;
      const cb = window._movieRatings?.[b.id]?.count || 0;
      return cb - ca;
    });
  } else {
    sorted.sort((a,b) => (b.release_year||0) - (a.release_year||0));
  }
  const hmg = document.getElementById('home-movies-grid');
  if (!hmg) return;
  hmg.innerHTML = sorted.slice(0,8).map(m => {
    const rt = window._movieRatings && window._movieRatings[m.id];
    const ratingHtml = rt
      ? `<div class="hc-film-rating"><svg width="10" height="10" viewBox="0 0 24 24" fill="#f59e0b"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>${rt.avg.toFixed(1)}<span class="hc-film-rating-count">(${rt.count})</span></div>`
      : '';
    const posterHtml = m.poster_image
      ? `<div class="hc-film-poster-wrap"><img class="hc-film-poster" src="${m.poster_image}" alt="${m.title}" loading="lazy"></div>`
      : `<div class="hc-film-placeholder"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity=".3"><rect x="2" y="2" width="20" height="20" rx="2"></rect><path d="M7 2v20M17 2v20M2 12h20M2 7h5M17 7h5M2 17h5M17 17h5"></path></svg></div>`;
    return `<div class="hc-film-card" onclick="openMovie('${m.id}')">
      ${posterHtml}
      <div class="hc-film-info">
        <div class="hc-film-title">${m.title}</div>
        <div class="hc-film-meta">${[m.release_year,(Array.isArray(m.genre)?m.genre:(m.genre?[m.genre]:[])).join(', ')].filter(Boolean).join(' · ')}</div>
        ${ratingHtml}
      </div>
    </div>`;
  }).join('');
}

function closeRegForm() {
  document.getElementById('reg-form-overlay').classList.remove('open');
  // Reset header visibility for next open
  const hdr = document.querySelector('.reg-form-header');
  if (hdr) hdr.style.display = '';
}

// Load SheetJS for Excel export
(function() {
  const s = document.createElement('script');
  s.src = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
  document.head.appendChild(s);
})();

// ══════════════════════════════════════════════════════════════════════════════
// SMART RECOMMENDATIONS — tag/genre/director-based engine
// Injected into movie-detail after every film page view.
// ══════════════════════════════════════════════════════════════════════════════

const _recsFilmIcon = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="17" y1="7" x2="22" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/></svg>`;
const _recsDirIcon  = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`;
const _recsGenreIcon = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`;

async function loadFilmRecommendations(movieId, movieTitle) {
  const sec   = document.getElementById('film-recs-section');
  const grid  = document.getElementById('film-recs-grid');
  const titleRef = document.getElementById('film-recs-title-ref');
  if (!sec || !grid) return;
  sec.style.display = 'none';
  grid.innerHTML = '';
  try {
    const recs = await apiFetch('/api/recommendations/' + movieId);
    if (!recs || !recs.length) return;
    if (titleRef) titleRef.textContent = movieTitle || 'this film';
    grid.innerHTML = recs.map(m => {
      const genres = Array.isArray(m.genre) ? m.genre : [];
      // Determine the match reason
      const isDir = m._reason === 'director';
      const reasonHtml = isDir
        ? `<div class="film-rec-reason">${_recsDirIcon} Same director</div>`
        : genres.length
          ? `<div class="film-rec-reason">${_recsGenreIcon} ${genres.slice(0,2).join(' · ')}</div>`
          : '';
      return `<div class="film-rec-card" onclick="openMovie('${m.id}')">
        ${m.poster_image
          ? `<img class="film-rec-poster" src="${m.poster_image}" alt="${m.title}" loading="lazy">`
          : `<div class="film-rec-poster-ph">${_recsFilmIcon}</div>`}
        <div class="film-rec-info">
          <div class="film-rec-title">${m.title}</div>
          <div class="film-rec-meta">${m.release_year || ''}</div>
          ${reasonHtml}
        </div>
      </div>`;
    }).join('');
    sec.style.display = 'block';
  } catch(e) { /* silent */ }
}

// Patch openMovie once on load to always inject recommendations
let _recsPatchApplied = false;
function _ensureRecsPatch() {
  if (_recsPatchApplied || typeof openMovie !== 'function') return;
  _recsPatchApplied = true;
  const _orig = openMovie;
  openMovie = async function(id) {
    await _orig(id);
    const m = window._allMoviesCache ? window._allMoviesCache.find(x => String(x.id) === String(id)) : null;
    setTimeout(() => loadFilmRecommendations(id, m ? m.title : ''), 100);
  };
}
window.addEventListener('load', _ensureRecsPatch);


// ══════════════════════════════════════════════════════════════════════════════
// KFS WRAPPED — Spotify-style annual recap
// Data sources: localStorage (watched films, read blogs) + /api/wrapped/stats
// ══════════════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════════════
// KFS WRAPPED — Spotify-style annual recap
// Data sources: localStorage (watched films, events registered, read blogs) + /api/wrapped/stats
// No emojis — all icons are inline SVG themed to match the UI.
// ══════════════════════════════════════════════════════════════════════════════

let _wrappedCards = [];
let _wrappedIndex = 0;
let _wrappedStats = null;
let _wrappedConfig = {};

// ── SVG icon library for cards ────────────────────────────────────────────────
const W_ICONS = {
  film:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="17" y1="7" x2="22" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/></svg>`,
  play:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8" fill="currentColor" stroke="none" opacity=".7"/></svg>`,
  star:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  book:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>`,
  event:  `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
  chart:  `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>`,
  globe:  `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  heart:  `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  lens:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  sun:    `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  tape:   `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15.5 2H8.5A6.5 6.5 0 0 0 2 8.5v7A6.5 6.5 0 0 0 8.5 22h7A6.5 6.5 0 0 0 22 15.5v-7A6.5 6.5 0 0 0 15.5 2z"/><circle cx="12" cy="12" r="3"/><circle cx="6.5" cy="6.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="17.5" cy="6.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="17.5" cy="17.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="6.5" cy="17.5" r="1.2" fill="currentColor" stroke="none"/></svg>`,
  award:  `<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="6"/><path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11"/></svg>`,
  broadcast:`<svg class="wrapped-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11l19-9-9 19-2-8-8-2z"/></svg>`,
};

// Fun-card icon options for admin picker
const W_FUN_ICONS = ['film','play','star','book','event','chart','globe','heart','lens','sun','tape','award'];

// Card colour themes — cinematic palettes with accent glow colours
const WRAPPED_THEMES = [
  { bg: 'linear-gradient(150deg,#0a0a0a 0%,#141414 100%)', fg: '#f5f5f5', glow: 'rgba(245,245,245,.12)' },
  { bg: 'linear-gradient(150deg,#08080f 0%,#0e0e22 100%)', fg: '#c8c8ff', glow: 'rgba(120,120,255,.25)' },
  { bg: 'linear-gradient(150deg,#070f07 0%,#0b1c0b 100%)', fg: '#b8f0b8', glow: 'rgba(80,200,80,.22)' },
  { bg: 'linear-gradient(150deg,#120606 0%,#200b0b 100%)', fg: '#ffb8b8', glow: 'rgba(255,80,80,.22)' },
  { bg: 'linear-gradient(150deg,#0f0c05 0%,#1c1605 100%)', fg: '#f5e8b0', glow: 'rgba(240,200,60,.22)' },
  { bg: 'linear-gradient(150deg,#06060f 0%,#0c0c28 100%)', fg: '#b0c8ff', glow: 'rgba(80,120,255,.25)' },
  { bg: 'linear-gradient(150deg,#0a0808 0%,#1a1010 100%)', fg: '#f0c8a0', glow: 'rgba(220,140,60,.22)' },
  { bg: 'linear-gradient(150deg,#080a0f 0%,#0e1420 100%)', fg: '#a0e0ff', glow: 'rgba(60,180,255,.22)' },
];

const BROADCAST_THEMES = {
  dark:    'linear-gradient(150deg,#0a0a0a 0%,#1a1a1a 100%)',
  slate:   'linear-gradient(150deg,#08090f 0%,#0c1020 100%)',
  forest:  'linear-gradient(150deg,#060f06 0%,#0b1a0b 100%)',
  crimson: 'linear-gradient(150deg,#120606 0%,#200b0b 100%)',
  gold:    'linear-gradient(150deg,#100c03 0%,#1c1603 100%)',
};

function _wrappedTheme(i) { return WRAPPED_THEMES[i % WRAPPED_THEMES.length]; }

// ── Noise overlay for card depth (pure CSS, no image) ─────────────────────────
function _noiseStyle() {
  return `radial-gradient(circle at 20% 80%, rgba(255,255,255,.03) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(255,255,255,.02) 0%, transparent 50%)`;
}

// ── Get registered events from localStorage ───────────────────────────────────
function getRegisteredEvents() {
  try { return JSON.parse(localStorage.getItem('kfs_registered_events') || '{}'); } catch { return {}; }
}

// ── Build the set of cards based on user data + server stats ──────────────────
function buildWrappedCards(stats, config) {
  const cards = [];
  const watchedMovies    = getWatchedMovies();    // {id: timestamp}
  const readBlogs        = getBlogReadState();    // {id: timestamp}
  const registeredEvents = getRegisteredEvents(); // {id: {title,ts}}

  const watchedIds   = Object.keys(watchedMovies);
  const readIds      = Object.keys(readBlogs);
  const eventIds     = Object.keys(registeredEvents);
  const watchedCount = watchedIds.length;
  const readCount    = readIds.length;
  const eventCount   = eventIds.length;

  const allMovies = (stats && stats.allMovies) || [];
  const myMovies  = watchedIds.map(id => allMovies.find(m => String(m.id) === String(id))).filter(Boolean);

  // My genre breakdown
  const myGenreCount = {};
  myMovies.forEach(m => {
    const genres = Array.isArray(m.genre) ? m.genre : [];
    genres.forEach(g => { if (g) myGenreCount[g] = (myGenreCount[g] || 0) + 1; });
  });
  const myTopGenres = Object.entries(myGenreCount).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([g])=>g);

  // ── Most-liked movie: highest community average rating among watched movies ──
  // Falls back to most recently watched if no ratings
  let myFavouriteMovie = null;
  if (myMovies.length > 0) {
    const allReviewStats = (stats && stats.movieRatings) || {}; // {id: {avg, count}}
    // Find watched movie with highest community avg (min 1 review); fallback to most recent
    let bestAvg = -1;
    myMovies.forEach(m => {
      const r = allReviewStats[String(m.id)];
      if (r && r.avg > bestAvg) { bestAvg = r.avg; myFavouriteMovie = m; }
    });
    if (!myFavouriteMovie) {
      // No rating data — pick most recently watched
      myFavouriteMovie = [...myMovies].sort((a,b)=>(watchedMovies[b.id]||0)-(watchedMovies[a.id]||0))[0];
    }
  }

  // Most recently watched films (up to 3 for poster row), excluding favourite
  const recentMovies = [...myMovies]
    .sort((a,b)=>(watchedMovies[b.id]||0)-(watchedMovies[a.id]||0))
    .filter(m => !myFavouriteMovie || String(m.id) !== String(myFavouriteMovie.id))
    .slice(0, 3);

  // Registered event titles
  const myEventTitles = eventIds.map(id => registeredEvents[id]?.title).filter(Boolean).slice(0,4);

  const year = (config.year || new Date().getFullYear()).toString();

  // ── 0: Broadcast (admin message) ─────────────────────────────────────────
  if (config.broadcast && config.broadcast.trim()) {
    const themeName = config.broadcast_theme || 'dark';
    const bg = BROADCAST_THEMES[themeName] || BROADCAST_THEMES.dark;
    cards.push({
      id: 'broadcast',
      theme: { bg, fg: '#f5f5f5', glow: 'rgba(245,245,245,.15)' },
      render: () => `
        ${W_ICONS.broadcast}
        <div class="wrapped-card-eyebrow">From KFS</div>
        <div class="wrapped-card-headline" style="font-size:clamp(20px,4.5vw,30px);line-height:1.15">${config.broadcast}</div>
      `,
    });
  }

  // ── 1: Intro ──────────────────────────────────────────────────────────────
  cards.push({
    id: 'intro',
    theme: _wrappedTheme(0),
    render: () => `
      ${W_ICONS.tape}
      <div class="wrapped-card-eyebrow">KFS · ${year}</div>
      <div class="wrapped-card-headline">Your Year<br>in Cinema</div>
      <div class="wrapped-card-sub">Tap or swipe to reveal how your KFS year unfolded — one card at a time.</div>
    `,
  });

  // ── 2: Your Most-Liked Movie (auto: highest community rating among watched) ─
  if (myFavouriteMovie) {
    const fav = myFavouriteMovie;
    const allReviewStats = (stats && stats.movieRatings) || {};
    const favRating = allReviewStats[String(fav.id)];
    cards.push({
      id: 'my-fav-movie',
      theme: _wrappedTheme(1),
      render: () => `
        ${W_ICONS.award}
        <div class="wrapped-card-eyebrow">Your most-loved film</div>
        ${fav.poster_image ? `<img class="wrapped-card-film-poster" src="${fav.poster_image}" alt="${fav.title}" loading="lazy" style="width:80px;height:120px;margin-bottom:10px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.5)">` : ''}
        <div class="wrapped-card-headline" style="font-size:clamp(18px,4vw,26px)">${fav.title}</div>
        <div class="wrapped-card-sub">${[fav.release_year, fav.director ? fav.director.split(/[,|]+/)[0].trim() : null].filter(Boolean).join(' · ')}</div>
        ${favRating ? `<div class="wrapped-card-stat" style="font-size:clamp(22px,5vw,36px);margin-top:8px">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:middle;margin-right:3px;margin-top:-3px;display:inline"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>${favRating.avg.toFixed(1)}
          <span class="wrapped-card-sub" style="font-size:13px;margin-left:4px;display:inline">/5 · ${favRating.count} ${favRating.count===1?'review':'reviews'}</span>
        </div>` : `<div class="wrapped-card-sub" style="margin-top:6px;opacity:.6">The one that stayed with you.</div>`}
      `,
    });
  }

  // ── 3: Films watched count ─────────────────────────────────────────────────
  cards.push({
    id: 'films-watched',
    theme: _wrappedTheme(2),
    render: () => `
      ${W_ICONS.film}
      <div class="wrapped-card-eyebrow">Films on your list</div>
      <div class="wrapped-card-stat">${watchedCount}</div>
      <div class="wrapped-card-stat-label">${watchedCount === 1 ? 'film' : 'films'} watched</div>
      ${watchedCount === 0
        ? `<div class="wrapped-card-sub" style="margin-top:14px">Start exploring the KFS library — mark films as watched to track your journey.</div>`
        : watchedCount >= 20
          ? `<div class="wrapped-card-sub" style="margin-top:14px">Seriously cinematic. You live here.</div>`
          : watchedCount >= 10
            ? `<div class="wrapped-card-sub" style="margin-top:14px">Incredible dedication to the craft.</div>`
            : watchedCount >= 5
              ? `<div class="wrapped-card-sub" style="margin-top:14px">You're building a real filmography.</div>`
              : `<div class="wrapped-card-sub" style="margin-top:14px">Every film is a new perspective.</div>`}
      ${myMovies.length > 0 ? `<div class="wrapped-card-events-row" style="margin-top:10px">
        ${myMovies.slice(0,4).map(m=>`<div class="wrapped-card-event-item">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          ${m.title}${m.release_year?' · '+m.release_year:''}
        </div>`).join('')}
        ${myMovies.length > 4 ? `<div class="wrapped-card-sub" style="margin-top:4px">+${myMovies.length-4} more</div>` : ''}
      </div>` : ''}
    `,
  });

  // ── 4: Other films poster row (recently watched, excl. favourite) ──────────
  if (recentMovies.length > 0) {
    cards.push({
      id: 'my-films',
      theme: _wrappedTheme(3),
      render: () => `
        <div class="wrapped-card-eyebrow">More from your watchlist</div>
        <div class="wrapped-card-film-row">
          ${recentMovies.map(m => m.poster_image
            ? `<img class="wrapped-card-film-poster" src="${m.poster_image}" alt="${m.title}" loading="lazy">`
            : '').join('')}
        </div>
        <div class="wrapped-card-headline" style="font-size:clamp(18px,4vw,24px);margin-top:12px">${recentMovies[0].title}</div>
        <div class="wrapped-card-sub">${recentMovies[0].release_year || ''}${recentMovies[0].director ? ' · ' + recentMovies[0].director.split(/[,|]+/)[0].trim() : ''}</div>
        ${recentMovies.length > 1 ? `<div class="wrapped-card-sub" style="margin-top:4px">+${recentMovies.length - 1} more on your list</div>` : ''}
      `,
    });
  }

  // ── 5: Top genre ─────────────────────────────────────────────────────────
  if (myTopGenres.length > 0) {
    cards.push({
      id: 'top-genre',
      theme: _wrappedTheme(4),
      render: () => `
        ${W_ICONS.chart}
        <div class="wrapped-card-eyebrow">Your top genre</div>
        <div class="wrapped-card-headline">${myTopGenres[0]}</div>
        <div class="wrapped-card-sub">You gravitate towards ${myTopGenres[0].toLowerCase()} films.</div>
        ${myTopGenres.length > 1
          ? `<div class="wrapped-card-genres">${myTopGenres.map(g=>`<span class="wrapped-card-genre-pill">${g}</span>`).join('')}</div>`
          : ''}
      `,
    });
  } else if (stats && stats.topGenres && stats.topGenres.length) {
    cards.push({
      id: 'top-genre-kfs',
      theme: _wrappedTheme(4),
      render: () => `
        ${W_ICONS.chart}
        <div class="wrapped-card-eyebrow">KFS's most made genre</div>
        <div class="wrapped-card-headline">${stats.topGenres[0].genre}</div>
        <div class="wrapped-card-sub">KFS has made <strong>${stats.topGenres[0].count}</strong> ${stats.topGenres[0].genre.toLowerCase()} films.</div>
        <div class="wrapped-card-genres">${stats.topGenres.slice(0,4).map(g=>`<span class="wrapped-card-genre-pill">${g.genre}</span>`).join('')}</div>
      `,
    });
  }

  // ── 6: Events attended ───────────────────────────────────────────────────
  cards.push({
    id: 'events-attended',
    theme: _wrappedTheme(5),
    render: () => `
      ${W_ICONS.event}
      <div class="wrapped-card-eyebrow">Events attended</div>
      <div class="wrapped-card-stat">${eventCount}</div>
      <div class="wrapped-card-stat-label">${eventCount === 1 ? 'event' : 'events'} this year</div>
      ${myEventTitles.length > 0
        ? `<div class="wrapped-card-events-row">
            ${myEventTitles.map(t => `<div class="wrapped-card-event-item">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              ${t}
            </div>`).join('')}
          </div>`
        : eventCount === 0
          ? `<div class="wrapped-card-sub" style="margin-top:14px">Register for KFS events to see them here.</div>`
          : ''}
    `,
  });

  // ── 7: Blogs read ─────────────────────────────────────────────────────────
  const allBlogs = (stats && stats.allBlogs) || [];
  const myBlogs = readIds.map(id => allBlogs.find(b => String(b.id) === String(id))).filter(Boolean);

  cards.push({
    id: 'blogs-read',
    theme: _wrappedTheme(6),
    render: () => `
      ${W_ICONS.book}
      <div class="wrapped-card-eyebrow">Blog posts read</div>
      <div class="wrapped-card-stat">${readCount}</div>
      <div class="wrapped-card-stat-label">${readCount === 1 ? 'article' : 'articles'} explored</div>
      ${readCount === 0
        ? `<div class="wrapped-card-sub" style="margin-top:14px">The KFS blog is full of film essays and behind-the-scenes stories.</div>`
        : `<div class="wrapped-card-sub" style="margin-top:14px">Curiosity looks good on you.</div>`}
      ${myBlogs.length > 0 ? `<div class="wrapped-card-events-row" style="margin-top:10px">
        ${myBlogs.slice(0,4).map(b=>`<div class="wrapped-card-event-item">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          ${b.title}
        </div>`).join('')}
        ${myBlogs.length > 4 ? `<div class="wrapped-card-sub" style="margin-top:4px">+${myBlogs.length-4} more</div>` : ''}
      </div>` : ''}
    `,
  });

  // ── 8: Year Highlight Cards (admin-curated: what KFS did this year) ────────
  if (config.blog_highlights && Array.isArray(config.blog_highlights)) {
    config.blog_highlights.forEach((bh, i) => {
      if (!bh.headline) return;
      cards.push({
        id: 'year-highlight-' + i,
        theme: _wrappedTheme(i + 2),
        render: () => `
          <div class="wrapped-card-blog-highlight">
            ${bh.image_url
              ? `<img class="wrapped-card-blog-img" src="${bh.image_url}" alt="${bh.headline}" loading="lazy" style="border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.4)">`
              : `<div style="margin-bottom:12px;opacity:.4"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg></div>`}
            <div class="wrapped-card-blog-title">${bh.headline}</div>
            ${bh.sub ? `<div class="wrapped-card-blog-sub" style="white-space:pre-line">${bh.sub}</div>` : ''}
          </div>
        `,
      });
    });
  }

  // ── 9: KFS by the numbers ─────────────────────────────────────────────────
  if (stats) {
    const listIconSvg = `<svg class="wrapped-card-list-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
    cards.push({
      id: 'kfs-numbers',
      theme: _wrappedTheme(7),
      render: () => `
        ${W_ICONS.globe}
        <div class="wrapped-card-eyebrow">KFS · All Time</div>
        <div class="wrapped-card-headline">By the<br>Numbers</div>
        <ul class="wrapped-card-list">
          <li>${listIconSvg}<strong>${stats.totalMovies}</strong>&nbsp;films in the library</li>
          <li>${listIconSvg}<strong>${stats.totalEvents}</strong>&nbsp;events hosted</li>
          <li>${listIconSvg}<strong>${stats.totalBlogs}</strong>&nbsp;blog posts published</li>
          <li>${listIconSvg}<strong>${stats.totalReviews}</strong>&nbsp;community reviews</li>
        </ul>
      `,
    });
  }

  // ── 10: Community top-rated / admin-featured film ──────────────────────────
  let featuredMovie = null;
  if (config.featured_movie_id && allMovies.length) {
    featuredMovie = allMovies.find(m => String(m.id) === String(config.featured_movie_id));
  }
  if (!featuredMovie && stats && stats.topRatedMovie) {
    featuredMovie = stats.topRatedMovie;
  }
  if (featuredMovie) {
    const t = featuredMovie;
    const isAdminPicked = !!config.featured_movie_id;
    cards.push({
      id: 'top-rated',
      theme: _wrappedTheme(1),
      render: () => `
        ${W_ICONS.award}
        <div class="wrapped-card-eyebrow">${isAdminPicked ? "KFS Film of the Year" : "Community's top-rated film"}</div>
        ${t.poster_image ? `<img class="wrapped-card-film-poster" src="${t.poster_image}" alt="${t.title}" loading="lazy" style="width:80px;height:120px;margin-bottom:8px">` : ''}
        <div class="wrapped-card-headline" style="font-size:clamp(18px,4vw,26px)">${t.title}</div>
        ${t.score ? `<div class="wrapped-card-stat" style="font-size:clamp(28px,6vw,44px)">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:middle;margin-right:4px;margin-top:-3px;display:inline"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>${t.score}
        </div>` : ''}
        ${t.release_year || t.director ? `<div class="wrapped-card-sub">${[t.release_year, t.director ? t.director.split(/[,|]+/)[0].trim() : null].filter(Boolean).join(' · ')}</div>` : ''}
      `,
    });
  }

  // ── 11: Genre personality ─────────────────────────────────────────────────
  const personalities = {
    'Drama':       { title: 'The Empath',       sub: 'You feel every scene.', icon: W_ICONS.heart },
    'Comedy':      { title: 'The Laughtrack',   sub: "Life's too short to be serious.", icon: W_ICONS.sun },
    'Horror':      { title: 'The Brave Soul',   sub: 'You watch what others fear.', icon: W_ICONS.lens },
    'Thriller':    { title: 'The Edge-Sitter',  sub: 'You never blink.', icon: W_ICONS.play },
    'Documentary': { title: 'The Truth-Seeker', sub: 'Facts hit harder than fiction.', icon: W_ICONS.globe },
    'Romance':     { title: 'The Hopeful',      sub: 'You believe in the happy ending.', icon: W_ICONS.heart },
    'Action':      { title: 'The Adrenaline',   sub: 'Still counting the explosions.', icon: W_ICONS.star },
  };
  if (myTopGenres.length > 0) {
    const p = personalities[myTopGenres[0]];
    if (p) {
      cards.push({
        id: 'personality',
        theme: _wrappedTheme(2),
        render: () => `
          ${p.icon}
          <div class="wrapped-card-eyebrow">Your film personality</div>
          <div class="wrapped-card-headline">${p.title}</div>
          <div class="wrapped-card-sub">${p.sub}</div>
        `,
      });
    }
  }

  // ── 12: Admin fun cards ──────────────────────────────────────────────────
  if (config.fun_cards && Array.isArray(config.fun_cards)) {
    config.fun_cards.forEach((fc, i) => {
      if (!fc.text) return;
      const iconKey = fc.icon && W_ICONS[fc.icon] ? fc.icon : 'film';
      cards.push({
        id: 'fun-' + i,
        theme: _wrappedTheme(i + 2),
        render: () => `
          ${W_ICONS[iconKey]}
          <div class="wrapped-card-headline" style="font-size:clamp(18px,4vw,26px)">${fc.text}</div>
          ${fc.sub ? `<div class="wrapped-card-sub">${fc.sub}</div>` : ''}
        `,
      });
    });
  }

  // ── 11: Outro ────────────────────────────────────────────────────────────
  const outroText = config.outro || `Thanks for being part of KFS ${year}.\nSee you at the next screening.`;
  cards.push({
    id: 'outro',
    theme: _wrappedTheme(0),
    render: () => `
      ${W_ICONS.award}
      <div class="wrapped-card-eyebrow">KFS · ${year}</div>
      <div class="wrapped-card-headline" style="font-size:clamp(40px,9vw,64px)">That's a<br>Wrap.</div>
      <div class="wrapped-card-sub" style="white-space:pre-line;margin-top:14px;font-size:14px;opacity:.7">${outroText}</div>
      <div style="margin-top:20px">
        <button class="wrapped-start-btn" style="font-size:12px;padding:12px 24px" onclick="event.stopPropagation();shareWrappedCard()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
          Share your Wrapped
        </button>
      </div>
    `,
  });

  return cards;
}

function renderWrappedDeck() {
  const deck = document.getElementById('wrapped-deck');
  if (!deck) return;
  deck.innerHTML = '';

  _wrappedCards.forEach((card, i) => {
    const t = card.theme;
    const div = document.createElement('div');
    div.className = 'wrapped-card';
    if      (i === _wrappedIndex)     div.classList.add('is-active');
    else if (i === _wrappedIndex + 1) div.classList.add('is-behind');
    else if (i === _wrappedIndex + 2) div.classList.add('is-behind-2');
    else div.style.opacity = '0';

    // Progress bars keyed to _wrappedIndex (not i)
    const progressHtml = _wrappedCards.map((_,j) =>
      `<div class="wrapped-progress-bar ${j < _wrappedIndex ? 'done' : j === _wrappedIndex ? 'active' : ''}"></div>`
    ).join('');

    div.innerHTML = `
      <div class="wrapped-card-inner">
        <div class="wrapped-card-bg" style="background:${t.bg};"></div>
        <div class="wrapped-card-grain"></div>
        ${t.glow ? `<div class="wrapped-card-glow" style="background:${t.glow}"></div>` : ''}
        <div class="wrapped-card-content" style="color:${t.fg}">
          <div class="wrapped-progress">${progressHtml}</div>
          ${card.render()}
        </div>
      </div>`;

    // Click: right half → next, left half → prev (intuitive story UX)
    div.addEventListener('click', e => {
      if (!div.classList.contains('is-active')) return;
      const rect = div.getBoundingClientRect();
      const x = e.clientX - rect.left;
      if (x < rect.width * 0.25) wrappedPrev();
      else wrappedNext();
    });

    deck.appendChild(div);
  });

  // Swipe support
  _attachWrappedSwipe(deck);
}

let _wSwipeStartX = 0, _wSwipeStartY = 0, _wSwiping = false;
function _attachWrappedSwipe(deck) {
  deck.addEventListener('touchstart', e => {
    _wSwipeStartX = e.touches[0].clientX;
    _wSwipeStartY = e.touches[0].clientY;
    _wSwiping = true;
  }, { passive: true });
  deck.addEventListener('touchend', e => {
    if (!_wSwiping) return;
    _wSwiping = false;
    const dx = e.changedTouches[0].clientX - _wSwipeStartX;
    const dy = e.changedTouches[0].clientY - _wSwipeStartY;
    if (Math.abs(dx) > Math.abs(dy) && Math.abs(dx) > 40) {
      if (dx < 0) wrappedNext(); else wrappedPrev();
    }
  }, { passive: true });
  // Keyboard
  if (!deck._keyHandlerAttached) {
    deck._keyHandlerAttached = true;
    document.addEventListener('keydown', e => {
      if (document.getElementById('page-wrapped')?.classList.contains('active')) {
        if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); wrappedNext(); }
        if (e.key === 'ArrowLeft') { e.preventDefault(); wrappedPrev(); }
      }
    });
  }
}

async function loadWrapped() {
  // Avoid double-loading
  if (_wrappedStats !== null) return;
  try {
    const [stats, config] = await Promise.all([
      apiFetch('/api/wrapped/stats').catch(() => null),
      apiFetch('/api/wrapped/config').catch(() => null),
    ]);
    _wrappedStats  = stats  || {};
    _wrappedConfig = config || {};

    // Show/hide wrapped nav link based on enabled flag (default true)
    const wrappedNavLink = document.querySelector('[data-page="wrapped"]')?.parentElement;
    if (wrappedNavLink) {
      wrappedNavLink.style.display = (_wrappedConfig.enabled === false) ? 'none' : '';
    }

    const yearEl = document.getElementById('wrapped-year-label');
    const subEl  = document.getElementById('wrapped-hero-sub');
    const statsEl = document.getElementById('wrapped-hero-stats');
    if (yearEl && _wrappedConfig.year) yearEl.textContent = `KFS · ${_wrappedConfig.year}`;
    if (subEl  && _wrappedConfig.sub)  subEl.textContent  = _wrappedConfig.sub;

    // Populate hero stats from localStorage counts
    const watchedCount = Object.keys(getWatchedMovies()).length;
    const readCount    = Object.keys(getBlogReadState()).length;
    const eventCount   = Object.keys(getRegisteredEvents()).length;
    if (statsEl && (watchedCount + readCount + eventCount) > 0) {
      document.getElementById('whero-films').textContent  = watchedCount;
      document.getElementById('whero-events').textContent = eventCount;
      document.getElementById('whero-blogs').textContent  = readCount;
      statsEl.style.display = 'flex';
    }
  } catch(e) {
    _wrappedStats = {}; _wrappedConfig = {};
  }
}

async function startWrapped() {
  // Ensure data loaded (loadWrapped guards against double-loading)
  _wrappedStats = null; // force fresh load each time Start is clicked
  await loadWrapped();
  _wrappedCards = buildWrappedCards(_wrappedStats, _wrappedConfig);
  _wrappedIndex = 0;

  // Hide hero, reveal deck with animation
  const hero = document.getElementById('wrapped-hero');
  const deck = document.getElementById('wrapped-deck-wrap');
  const restartRow = document.getElementById('wrapped-restart-row');
  if (restartRow) restartRow.remove();
  if (hero) { hero.style.transition = 'opacity .35s ease, transform .35s ease'; hero.style.opacity = '0'; hero.style.transform = 'translateY(-16px)'; setTimeout(() => { hero.style.display = 'none'; }, 360); }
  deck.style.display = 'flex';
  deck.classList.remove('visible');
  renderWrappedDeck();
  requestAnimationFrame(() => requestAnimationFrame(() => { deck.classList.add('visible'); }));
}

function wrappedNext() {
  if (!_wrappedCards.length) return;
  if (_wrappedIndex >= _wrappedCards.length - 1) {
    let restartRow = document.getElementById('wrapped-restart-row');
    if (!restartRow) {
      restartRow = document.createElement('div');
      restartRow.id = 'wrapped-restart-row';
      restartRow.className = 'wrapped-restart-row';
      restartRow.innerHTML = `<button class="wrapped-start-btn" style="margin-top:16px" onclick="restartWrapped()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.5"/></svg>
        Replay
      </button>`;
      document.getElementById('wrapped-deck-wrap').appendChild(restartRow);
    }
    return;
  }
  // Animate exit-left before advancing
  const activeCard = document.querySelector('.wrapped-card.is-active');
  if (activeCard) {
    activeCard.classList.remove('is-active');
    activeCard.classList.add('is-exit-left');
  }
  _wrappedIndex++;
  setTimeout(() => renderWrappedDeck(), 40);
}

function wrappedPrev() {
  if (_wrappedIndex <= 0) return;
  const activeCard = document.querySelector('.wrapped-card.is-active');
  if (activeCard) {
    activeCard.classList.remove('is-active');
    activeCard.classList.add('is-exit-right');
  }
  _wrappedIndex--;
  setTimeout(() => renderWrappedDeck(), 40);
}

function restartWrapped() {
  _wrappedIndex = 0;
  const restartRow = document.getElementById('wrapped-restart-row');
  if (restartRow) restartRow.remove();
  renderWrappedDeck();
}

function showWrappedHero() {
  const hero = document.getElementById('wrapped-hero');
  const deck = document.getElementById('wrapped-deck-wrap');
  deck.classList.remove('visible');
  setTimeout(() => { deck.style.display = 'none'; }, 400);
  if (hero) {
    hero.style.display = '';
    hero.style.opacity = '0';
    hero.style.transform = 'translateY(-16px)';
    setTimeout(() => { hero.style.opacity = '1'; hero.style.transform = 'translateY(0)'; }, 20);
  }
}

// Share current wrapped card as image using Canvas
async function shareWrappedCard() {
  if (!_wrappedCards.length) return;
  const card = _wrappedCards[_wrappedIndex];
  if (!card) return;
  const t = card.theme;
  const canvas = document.getElementById('wrapped-share-canvas');
  if (!canvas) { _copyShareFallback('https://kiitfilmsociety.in/wrapped'); return; }

  const W = 1080, H = 1080;
  canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext('2d');

  // Background gradient
  const grd = ctx.createLinearGradient(0, 0, W, H);
  const bgColors = t.bg.match(/#[0-9a-f]{3,8}/gi) || ['#0a0a0a', '#181818'];
  grd.addColorStop(0, bgColors[0]);
  grd.addColorStop(1, bgColors[1] || bgColors[0]);
  ctx.fillStyle = grd;
  ctx.fillRect(0, 0, W, H);

  // Subtle radial overlay
  const r = ctx.createRadialGradient(W*.2, H*.8, 0, W*.2, H*.8, W*.6);
  r.addColorStop(0, 'rgba(255,255,255,.03)');
  r.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = r;
  ctx.fillRect(0, 0, W, H);

  // KFS wordmark
  ctx.fillStyle = t.fg;
  ctx.globalAlpha = 0.38;
  ctx.font = '600 26px system-ui,sans-serif';
  ctx.fillText('KFS — KIIT FILM SOCIETY', 72, 80);
  ctx.globalAlpha = 1;

  // Progress bars
  const barW = (W - 144) / _wrappedCards.length - 4;
  _wrappedCards.forEach((_, i) => {
    ctx.globalAlpha = i < _wrappedIndex ? 0.8 : i === _wrappedIndex ? 1 : 0.2;
    ctx.fillStyle = t.fg;
    ctx.beginPath();
    ctx.roundRect(72 + i * (barW + 4), 108, barW, 5, 2);
    ctx.fill();
  });
  ctx.globalAlpha = 1;

  // Card text content
  ctx.fillStyle = t.fg;
  const year = (_wrappedConfig.year || new Date().getFullYear()).toString();
  const watched = watchedIds_share();
  const read = readIds_share();
  const events = eventIds_share();
  const lines = [];
  if      (card.id === 'films-watched')    { lines.push([String(watched), 96, 900]); lines.push(['films watched', 28, 400]); }
  else if (card.id === 'events-attended')  { lines.push([String(events), 96, 900]); lines.push(['events attended', 28, 400]); }
  else if (card.id === 'blogs-read')       { lines.push([String(read), 96, 900]); lines.push(['articles read', 28, 400]); }
  else if (card.id === 'outro')            { lines.push(["That's a", 60, 800]); lines.push(['Wrap.', 96, 900]); }
  else if (card.id === 'intro')            { lines.push(['Your Year', 60, 800]); lines.push(['in Cinema', 60, 400]); }
  else if (card.id === 'top-genre' || card.id === 'top-genre-kfs') {
    const g = _wrappedStats?.topGenres?.[0]?.genre || 'Cinema';
    lines.push([g, 72, 900]);
  }
  else { lines.push(['KFS', 96, 900]); lines.push([year, 48, 400]); }

  let y = H / 2 - 40;
  lines.forEach(([text, size, weight]) => {
    ctx.font = `${weight} ${size}px system-ui,sans-serif`;
    ctx.fillText(text, 72, y);
    y += size + 16;
  });

  // Bottom URL
  ctx.globalAlpha = 0.32;
  ctx.font = '400 22px system-ui,sans-serif';
  ctx.fillText('kiitfilmsociety.in/wrapped', 72, H - 56);
  ctx.globalAlpha = 1;

  canvas.toBlob(async blob => {
    const url = 'https://kiitfilmsociety.in/wrapped';
    const yearStr = (_wrappedConfig.year || new Date().getFullYear()).toString();
    if (navigator.share && blob) {
      try {
        await navigator.share({
          title: `My KFS Wrapped ${yearStr}`,
          text: `My KFS Wrapped ${yearStr} — kiitfilmsociety.in/wrapped`,
          url,
          files: [new File([blob], `kfs-wrapped-${yearStr}.png`, { type: 'image/png' })],
        });
        return;
      } catch(e) { /* fall through */ }
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `kfs-wrapped-${yearStr}.png`;
    a.click();
    _showShareToast('Card downloaded!');
  }, 'image/png');
}

// Helper shims for share canvas (avoid closure over changing vars)
function watchedIds_share() { return Object.keys(getWatchedMovies()).length; }
function readIds_share()    { return Object.keys(getBlogReadState()).length; }
function eventIds_share()   { return Object.keys(getRegisteredEvents()).length; }

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN — Wrapped Config Editor
// ══════════════════════════════════════════════════════════════════════════════

let _wrappedAdminFunCards = [];
let _wrappedAdminBlogHighlights = [];
let _wrappedAdminAllMovies = [];

async function loadWrappedAdminSection() {
  try {
    const [config, movies] = await Promise.all([
      apiFetch('/api/wrapped/config'),
      apiFetch('/api/movies'),
    ]);
    if (!config) return;
    _wrappedConfig = config;
    _wrappedAdminAllMovies = movies || [];

    const yearEl    = document.getElementById('wrapped-cfg-year');
    const subEl     = document.getElementById('wrapped-cfg-sub');
    const outroEl   = document.getElementById('wrapped-cfg-outro');
    const bcEl      = document.getElementById('wrapped-cfg-broadcast');
    const bcThemeEl = document.getElementById('wrapped-cfg-broadcast-theme');
    if (yearEl)    yearEl.value    = config.year  || '';
    if (subEl)     subEl.value     = config.sub   || '';
    if (outroEl)   outroEl.value   = config.outro || '';
    if (bcEl)      bcEl.value      = config.broadcast || '';
    if (bcThemeEl) bcThemeEl.value = config.broadcast_theme || 'dark';

    // Enabled toggle (default true if not set)
    const toggleEl = document.getElementById('wrapped-enabled-toggle');
    if (toggleEl) {
      toggleEl.checked = config.enabled !== false;
      updateWrappedToggleLabel(toggleEl);
    }

    _wrappedAdminFunCards = Array.isArray(config.fun_cards) ? [...config.fun_cards] : [];
    _wrappedAdminBlogHighlights = Array.isArray(config.blog_highlights) ? [...config.blog_highlights] : [];
    renderWrappedFunCardsList();
    renderWrappedBlogHighlightsList();

    // Populate movie dropdown
    const sel = document.getElementById('wrapped-cfg-featured-movie');
    if (sel && _wrappedAdminAllMovies.length) {
      sel.innerHTML = '<option value="">— Auto (highest-rated by community) —</option>'
        + _wrappedAdminAllMovies.map(m => `<option value="${m.id}" data-poster="${m.poster_image||''}" data-year="${m.release_year||''}" data-dir="${(m.director||'').split(/[,|]+/)[0].trim()}">${m.title}${m.release_year?' ('+m.release_year+')':''}</option>`).join('');
      if (config.featured_movie_id) {
        sel.value = config.featured_movie_id;
        wrappedFeaturedMoviePreview();
      }
    }
  } catch(e) { console.error('[wrapped admin load]', e); }
}

function updateWrappedToggleLabel(el) {
  const label = document.getElementById('wrapped-toggle-label');
  const notice = document.getElementById('wrapped-disabled-notice');
  if (label) {
    label.textContent = el.checked ? 'On' : 'Off';
    label.style.color = el.checked ? '#34c759' : 'var(--grey)';
  }
  if (notice) notice.style.display = el.checked ? 'none' : 'block';
}

function wrappedFeaturedMoviePreview() {
  const sel = document.getElementById('wrapped-cfg-featured-movie');
  const preview = document.getElementById('wrapped-featured-movie-preview');
  const thumb = document.getElementById('wrapped-featured-movie-thumb');
  const titleEl = document.getElementById('wrapped-featured-movie-title');
  const metaEl = document.getElementById('wrapped-featured-movie-meta');
  if (!sel || !preview) return;
  const opt = sel.options[sel.selectedIndex];
  if (!sel.value || !opt) { preview.style.display = 'none'; return; }
  const poster = opt.dataset.poster;
  const year = opt.dataset.year;
  const dir = opt.dataset.dir;
  thumb.src = poster || '';
  thumb.style.display = poster ? 'block' : 'none';
  titleEl.textContent = opt.text.replace(/ \(\d{4}\)$/, '');
  metaEl.textContent = [year, dir].filter(Boolean).join(' · ');
  preview.style.display = 'flex';
}

function _iconPickerHtml(selectedIcon, rowIndex) {
  return W_FUN_ICONS.map(key => {
    const svg = W_ICONS[key].replace('class="wrapped-card-icon"', 'width="16" height="16"');
    return `<span class="wrapped-admin-fun-icon-opt${selectedIcon===key?' sel':''}" title="${key}" onclick="wrappedFunCardUpdateIcon(${rowIndex},'${key}',this)">${svg}</span>`;
  }).join('');
}

function renderWrappedBlogHighlightsList() {
  const list = document.getElementById('wrapped-blog-highlights-list');
  if (!list) return;
  if (!_wrappedAdminBlogHighlights.length) {
    list.innerHTML = '<p style="font-size:12px;color:var(--grey);margin:0">No highlight cards yet. Add one below to showcase what KFS did this year.</p>';
    return;
  }
  list.innerHTML = _wrappedAdminBlogHighlights.map((bh, i) => `
    <div class="wrapped-admin-highlight-row" style="flex-direction:column;align-items:stretch;gap:12px;padding:16px;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,.02);margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:12px">
        ${bh.image_url
          ? `<img class="wrapped-admin-highlight-thumb" src="${bh.image_url.replace(/"/g,'&quot;')}" alt="" onerror="this.style.display='none'" style="width:64px;height:64px;object-fit:cover;border-radius:8px;flex-shrink:0">`
          : `<div style="width:64px;height:64px;border-radius:8px;background:var(--card);border:1px dashed var(--border);display:flex;align-items:center;justify-content:center;color:var(--grey);flex-shrink:0"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg></div>`}
        <div style="flex:1;min-width:0">
          <div style="font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--grey);margin-bottom:4px">Card ${i+1}</div>
          <div style="font-size:13px;font-weight:600;color:var(--white);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${bh.headline || '(no headline yet)'}</div>
        </div>
        <button class="btn-sm danger" style="flex-shrink:0" onclick="wrappedBlogHighlightRemove(${i})">Remove</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px">
        <div>
          <div style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--grey);margin-bottom:5px">Headline *</div>
          <input type="text" value="${(bh.headline||'').replace(/"/g,'&quot;')}" placeholder="e.g. Chitra Vichitra 2025 was a hit!" style="width:100%;border-radius:8px" oninput="wrappedBlogHighlightUpdate(${i},'headline',this.value)">
        </div>
        <div>
          <div style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--grey);margin-bottom:5px">Description (optional)</div>
          <textarea placeholder="Add more context — what happened, why it was special…" style="width:100%;border-radius:8px;min-height:64px;resize:vertical;font-family:inherit;font-size:13px;padding:10px 12px;background:var(--black);border:1px solid var(--border);color:var(--white);outline:none" oninput="wrappedBlogHighlightUpdate(${i},'sub',this.value)">${(bh.sub||'').replace(/</g,'&lt;')}</textarea>
        </div>
        <div>
          <div style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--grey);margin-bottom:5px">Image URL</div>
          <input type="text" value="${(bh.image_url||'').replace(/"/g,'&quot;')}" placeholder="Paste Supabase / CDN image URL…" style="width:100%;border-radius:8px" oninput="wrappedBlogHighlightUpdate(${i},'image_url',this.value)">
          <div style="font-size:11px;color:var(--grey);margin-top:4px;opacity:.7">Upload to Supabase Storage first, then paste the public URL here</div>
        </div>
      </div>
    </div>`).join('');
}

function wrappedBlogHighlightUpdate(i, key, val) {
  if (!_wrappedAdminBlogHighlights[i]) return;
  _wrappedAdminBlogHighlights[i][key] = val;
  if (key === 'image_url' || key === 'headline') renderWrappedBlogHighlightsList();
}
function wrappedBlogHighlightRemove(i) {
  _wrappedAdminBlogHighlights.splice(i, 1);
  renderWrappedBlogHighlightsList();
}
function addWrappedBlogHighlight() {
  _wrappedAdminBlogHighlights.push({ headline: '', sub: '', image_url: '' });
  renderWrappedBlogHighlightsList();
}

function renderWrappedFunCardsList() {
  const list = document.getElementById('wrapped-fun-cards-list');
  if (!list) return;
  if (!_wrappedAdminFunCards.length) {
    list.innerHTML = '<p style="font-size:12px;color:var(--grey);margin:0">No fun cards yet. Add one below.</p>';
    return;
  }
  list.innerHTML = _wrappedAdminFunCards.map((fc, i) => `
    <div class="wrapped-admin-fun-row">
      <div style="flex:1">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
          <input type="text" value="${(fc.text||'').replace(/"/g,'&quot;')}" placeholder="Card headline…" style="flex:1" oninput="wrappedFunCardUpdate(${i},'text',this.value)">
          <button class="btn-sm danger" style="flex-shrink:0" onclick="wrappedFunCardRemove(${i})">Remove</button>
        </div>
        <input type="text" value="${(fc.sub||'').replace(/"/g,'&quot;')}" placeholder="Subtext (optional)…" style="width:100%;margin-bottom:8px" oninput="wrappedFunCardUpdate(${i},'sub',this.value)">
        <div style="font-size:10px;color:var(--grey);margin-bottom:5px;letter-spacing:.1em;text-transform:uppercase">Icon</div>
        <div class="wrapped-admin-fun-icon-picker" id="icon-picker-${i}">${_iconPickerHtml(fc.icon||'film', i)}</div>
      </div>
    </div>`).join('');
}

function wrappedFunCardUpdate(i, key, val) {
  if (!_wrappedAdminFunCards[i]) return;
  _wrappedAdminFunCards[i][key] = val;
}
function wrappedFunCardUpdateIcon(i, iconKey, el) {
  if (!_wrappedAdminFunCards[i]) return;
  _wrappedAdminFunCards[i].icon = iconKey;
  // Update selected state visually
  const picker = document.getElementById('icon-picker-' + i);
  if (picker) picker.querySelectorAll('.wrapped-admin-fun-icon-opt').forEach(opt => opt.classList.remove('sel'));
  if (el) el.classList.add('sel');
}
function wrappedFunCardRemove(i) {
  _wrappedAdminFunCards.splice(i, 1);
  renderWrappedFunCardsList();
}
function addWrappedFunCard() {
  _wrappedAdminFunCards.push({ icon: 'film', text: '', sub: '' });
  renderWrappedFunCardsList();
}

async function saveWrappedConfig() {
  const saveBtn = document.querySelector('#section-wrapped .btn-primary');
  const origText = saveBtn ? saveBtn.textContent : '';
  if (saveBtn) { saveBtn.textContent = 'Saving…'; saveBtn.disabled = true; }

  const config = {
    enabled:          document.getElementById('wrapped-enabled-toggle')?.checked !== false,
    year:             (document.getElementById('wrapped-cfg-year')?.value     || '').trim(),
    sub:              (document.getElementById('wrapped-cfg-sub')?.value      || '').trim(),
    outro:            (document.getElementById('wrapped-cfg-outro')?.value    || '').trim(),
    broadcast:        (document.getElementById('wrapped-cfg-broadcast')?.value || '').trim(),
    broadcast_theme:  (document.getElementById('wrapped-cfg-broadcast-theme')?.value || 'dark').trim(),
    featured_movie_id: (document.getElementById('wrapped-cfg-featured-movie')?.value || '').trim() || null,
    fun_cards:        _wrappedAdminFunCards.filter(fc => fc.text),
    blog_highlights:  _wrappedAdminBlogHighlights.filter(bh => bh.headline),
  };
  const token = adminToken;
  try {
    const res = await fetch('/api/admin/wrapped/config', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      const err = await res.json().catch(()=>({}));
      throw new Error(err.error || 'Save failed (' + res.status + ')');
    }
    _wrappedConfig = config;
    // Immediately reflect enabled/disabled in the public nav
    const _wNavLink = document.querySelector('[data-page="wrapped"]')?.parentElement;
    if (_wNavLink) _wNavLink.style.display = (config.enabled === false) ? 'none' : '';
    _showShareToast('Wrapped config saved!');
  } catch(e) {
    showAdminError('Wrapped save failed: ' + e.message);
  } finally {
    if (saveBtn) { saveBtn.textContent = origText; saveBtn.disabled = false; }
  }
}

function _kfsRoundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x+r,y); ctx.lineTo(x+w-r,y);
  ctx.arcTo(x+w,y,x+w,y+r,r); ctx.lineTo(x+w,y+h-r);
  ctx.arcTo(x+w,y+h,x+w-r,y+h,r); ctx.lineTo(x+r,y+h);
  ctx.arcTo(x,y+h,x,y+h-r,r); ctx.lineTo(x,y+r);
  ctx.arcTo(x,y,x+r,y,r); ctx.closePath();
}

// ── PASSPORT CARD ─────────────────────────────────────────────────────────────
// data = { name, role, domain, batch, bio, photo, special_tag, filmPosters[] }
async function downloadPassportCard(data) {
  data = data || {};
  var W = 1080, H = 1620;
  var PAD = 64;
  var name       = data.name       || 'Your Name';
  var role       = data.role       || '';
  var domain     = data.domain     || '';
  var batch      = data.batch      || '';
  var bio        = data.bio        || '';
  var specialTag = data.special_tag|| '';   // 'admin-developer' | 'developer' | ''
  var filmPosters= data.filmPosters|| [];    // array of poster URLs (up to 3)
  var photoUrl   = data.photo      || '';
  var yr         = new Date().getFullYear();

  var cv = document.createElement('canvas');
  cv.width = W; cv.height = H;
  var ctx = cv.getContext('2d');

  // ── Background ──────────────────────────────────────────────
  ctx.fillStyle = '#0d0d0d';
  ctx.fillRect(0, 0, W, H);

  // Subtle top gradient wash
  var topGrad = ctx.createLinearGradient(0, 0, 0, 500);
  topGrad.addColorStop(0, 'rgba(255,255,255,0.04)');
  topGrad.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = topGrad;
  ctx.fillRect(0, 0, W, 500);

  // ── Header row: KFS left, badge right ──────────────────────
  ctx.font = '600 28px monospace';
  ctx.fillStyle = '#4a4a4a';
  ctx.fillText('K F S', PAD, 88);

  // MEMBER badge
  var badgeLabel = 'MEMBER';
  ctx.font = '600 20px monospace';
  var bw = ctx.measureText(badgeLabel).width + 48;
  var bh = 40, bx = W - PAD - bw, by = 62;
  ctx.strokeStyle = '#2e2e2e'; ctx.lineWidth = 1.5;
  _kfsRoundRect(ctx, bx, by, bw, bh, 6); ctx.stroke();
  ctx.fillStyle = '#3a3a3a';
  ctx.fillText(badgeLabel, bx + 24, by + 26);

  // Special tag (if any) — right of header, below badge
  if (specialTag) {
    var tagLabel = specialTag === 'admin-developer' ? '</> ADMIN-DEV' : '</> DEV';
    ctx.font = '600 18px monospace';
    var tw2 = ctx.measureText(tagLabel).width + 40;
    var ty2 = by + bh + 10;
    if (specialTag === 'admin-developer') {
      ctx.strokeStyle = '#8b5cf640'; ctx.fillStyle = '#8b5cf6';
    } else {
      ctx.strokeStyle = '#3b82f640'; ctx.fillStyle = '#60a5fa';
    }
    _kfsRoundRect(ctx, W - PAD - tw2, ty2, tw2, 36, 6);
    ctx.globalAlpha = 0.18; ctx.fill(); ctx.globalAlpha = 1;
    ctx.lineWidth = 1.2; ctx.stroke();
    ctx.fillStyle = specialTag === 'admin-developer' ? '#c4b5fd' : '#93c5fd';
    ctx.fillText(tagLabel, W - PAD - tw2 + 20, ty2 + 24);
  }

  // ── Photo circle ────────────────────────────────────────────
  var photoSize = 200, photoX = PAD, photoY = 136;
  // Draw placeholder circle first
  ctx.save();
  ctx.beginPath(); ctx.arc(photoX + photoSize/2, photoY + photoSize/2, photoSize/2, 0, Math.PI*2);
  ctx.fillStyle = '#1e1e1e'; ctx.fill();
  ctx.strokeStyle = '#2a2a2a'; ctx.lineWidth = 2; ctx.stroke();
  ctx.restore();

  // Load and clip photo if available
  var photoLoaded = false;
  if (photoUrl) {
    try {
      var photoImg = await _kfsLoadImage(photoUrl);
      ctx.save();
      ctx.beginPath();
      ctx.arc(photoX + photoSize/2, photoY + photoSize/2, photoSize/2 - 2, 0, Math.PI*2);
      ctx.clip();
      // cover-fit: draw centered square crop
      var ps = photoSize - 4;
      var iw = photoImg.naturalWidth, ih = photoImg.naturalHeight;
      var scale = Math.max(ps/iw, ps/ih);
      var dw = iw*scale, dh = ih*scale;
      ctx.drawImage(photoImg, photoX+2 + (ps-dw)/2, photoY+2 + (ps-dh)/2, dw, dh);
      ctx.restore();
      photoLoaded = true;
    } catch(e) { /* keep placeholder */ }
  }
  if (!photoLoaded) {
    // Silhouette icon
    ctx.save();
    ctx.fillStyle = '#333';
    ctx.beginPath(); ctx.arc(photoX+photoSize/2, photoY+68, 36, 0, Math.PI*2); ctx.fill();
    ctx.beginPath();
    ctx.ellipse(photoX+photoSize/2, photoY+photoSize/2+30, 56, 44, 0, Math.PI, 0);
    ctx.fill();
    ctx.restore();
  }

  // ── Name block ──────────────────────────────────────────────
  var nameX = photoX + photoSize + 40;
  var nameMaxW = W - nameX - PAD;

  // Name — auto-shrink font to fit
  var nameFontSize = 72;
  ctx.font = `bold ${nameFontSize}px serif`;
  while (ctx.measureText(name).width > nameMaxW && nameFontSize > 36) {
    nameFontSize -= 4;
    ctx.font = `bold ${nameFontSize}px serif`;
  }
  ctx.fillStyle = '#e8e8e2';
  ctx.fillText(name, nameX, photoY + 74);

  // Role
  ctx.font = '600 26px monospace';
  ctx.fillStyle = '#606060';
  ctx.fillText(role.toUpperCase(), nameX, photoY + 74 + 46);

  // Domain (if different from role)
  if (domain && domain.toLowerCase() !== role.toLowerCase()) {
    ctx.font = '500 22px monospace';
    ctx.fillStyle = '#424242';
    ctx.fillText(domain.toUpperCase(), nameX, photoY + 74 + 46 + 34);
  }

  // Batch pill
  if (batch) {
    ctx.font = '500 20px monospace';
    ctx.fillStyle = '#3a3a3a';
    var batchText = 'BATCH ' + batch;
    var bpw = ctx.measureText(batchText).width + 32;
    var bpy = photoY + photoSize - 38;
    _kfsRoundRect(ctx, nameX, bpy, bpw, 32, 16);
    ctx.strokeStyle = '#2a2a2a'; ctx.lineWidth = 1; ctx.stroke();
    ctx.fillStyle = '#505050';
    ctx.fillText(batchText, nameX + 16, bpy + 21);
  }

  // ── Divider line ────────────────────────────────────────────
  var divY = photoY + photoSize + 48;
  ctx.strokeStyle = '#1e1e1e'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(PAD, divY); ctx.lineTo(W-PAD, divY); ctx.stroke();

  // ── Bio ─────────────────────────────────────────────────────
  var bioY = divY + 48;
  if (bio) {
    ctx.font = 'italic 400 30px serif';
    ctx.fillStyle = '#4a4a4a';
    // wrap bio
    var bioMaxW = W - PAD*2;
    var bioLines = _kfsWrapTextLines(ctx, bio, bioMaxW, 3); // max 3 lines
    bioLines.forEach(function(line, i) {
      ctx.fillText(line, PAD, bioY + i * 44);
    });
    bioY += bioLines.length * 44 + 32;
  }

  // ── Data fields ─────────────────────────────────────────────
  var numFilms = filmPosters.length || data.filmCount || 0;
  var fieldRows = [];
  if (numFilms) fieldRows.push(['FILMS',   String(numFilms) + (numFilms === 1 ? ' film' : ' films')]);
  if (batch)    fieldRows.push(['BATCH',   batch]);
  if (domain)   fieldRows.push(['DOMAIN',  domain]);

  var fy = bioY;
  fieldRows.forEach(function(pair) {
    ctx.font = '600 20px monospace'; ctx.fillStyle = '#383838';
    ctx.fillText(pair[0], PAD, fy);
    ctx.font = '400 28px sans-serif'; ctx.fillStyle = '#888880';
    ctx.fillText(pair[1], PAD, fy + 38);
    fy += 96;
  });

  // ── Film posters strip ──────────────────────────────────────
  var postersY = Math.max(fy + 16, H - 380);
  if (filmPosters.length) {
    // Section label
    ctx.font = '600 20px monospace'; ctx.fillStyle = '#2e2e2e';
    ctx.fillText('FILMS', PAD, postersY);
    postersY += 28;

    var maxPosters = Math.min(filmPosters.length, 4);
    var posterH = 200, posterW = Math.round(posterH * 2/3); // 2:3 ratio
    var posterGap = 20;
    var totalW = maxPosters * posterW + (maxPosters-1) * posterGap;
    var startX = PAD;

    for (var pi = 0; pi < maxPosters; pi++) {
      var px = startX + pi * (posterW + posterGap);
      var py = postersY;
      // Placeholder
      ctx.fillStyle = '#191919';
      _kfsRoundRect(ctx, px, py, posterW, posterH, 8);
      ctx.fill();
      try {
        var pImg = await _kfsLoadImage(filmPosters[pi]);
        ctx.save();
        _kfsRoundRect(ctx, px, py, posterW, posterH, 8);
        ctx.clip();
        var sc = Math.max(posterW/pImg.naturalWidth, posterH/pImg.naturalHeight);
        var dw2 = pImg.naturalWidth*sc, dh2 = pImg.naturalHeight*sc;
        ctx.drawImage(pImg, px+(posterW-dw2)/2, py+(posterH-dh2)/2, dw2, dh2);
        ctx.restore();
      } catch(e) {
        // film icon fallback
        ctx.fillStyle = '#2a2a2a';
        ctx.font = '32px monospace';
        ctx.fillText('▶', px + posterW/2 - 12, py + posterH/2 + 10);
      }
    }
  }

  // ── Footer band ─────────────────────────────────────────────
  ctx.fillStyle = '#090909';
  ctx.fillRect(0, H-100, W, 100);
  ctx.strokeStyle = '#1a1a1a'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, H-100); ctx.lineTo(W, H-100); ctx.stroke();

  ctx.font = '500 22px monospace'; ctx.fillStyle = '#2e2e2e';
  ctx.fillText('kiitfilmsociety.in', PAD, H-38);
  ctx.fillText('KFS · ' + yr, W-PAD - ctx.measureText('KFS · '+yr).width, H-38);

  // ── Download ─────────────────────────────────────────────────
  var lnk = document.createElement('a');
  lnk.download = 'kfs-passport-' + name.toLowerCase().replace(/\s+/g,'-') + '.png';
  lnk.href = cv.toDataURL('image/png');
  lnk.click();
}

// Load an image cross-origin, returning a promise<HTMLImageElement>
function _kfsLoadImage(url) {
  return new Promise(function(resolve, reject) {
    var img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload  = function() { resolve(img); };
    img.onerror = function() { reject(new Error('img load failed: ' + url)); };
    img.src = url;
  });
}

// Wrap text and return array of line strings (max maxLines)
function _kfsWrapTextLines(ctx, text, maxW, maxLines) {
  var words = text.split(' '), lines = [], line = '';
  for (var n = 0; n < words.length; n++) {
    var test = line + (line ? ' ' : '') + words[n];
    if (ctx.measureText(test).width > maxW && line) {
      lines.push(line);
      if (lines.length >= maxLines) {
        // Truncate last line with ellipsis
        var last = lines[lines.length-1];
        while (ctx.measureText(last + '…').width > maxW && last.length > 0) last = last.slice(0,-1);
        lines[lines.length-1] = last + '…';
        return lines;
      }
      line = words[n];
    } else { line = test; }
  }
  if (line) lines.push(line);
  return lines;
}

// Download passport pre-filled from the currently open member profile
async function downloadPassportFromProfile() {
  var name     = document.getElementById('mprofile-name')?.textContent?.trim() || '';
  var roleEl   = document.getElementById('mprofile-role')?.textContent || '';
  // role text is "Role · Domain"
  var parts    = roleEl.split('·');
  var role     = parts[0]?.trim() || '';
  var domain   = parts[1]?.trim() || '';
  var batchEl  = document.getElementById('mprofile-batch')?.textContent || '';
  var batch    = batchEl.replace(/^Batch of\s*/i,'').trim();
  var bio      = document.getElementById('mprofile-bio')?.textContent?.trim() || '';

  // Photo from the img tag inside mprofile-photo-wrap
  var photoImg = document.querySelector('#mprofile-photo-wrap img');
  var photo    = photoImg ? photoImg.src : '';

  // Special tag — read from window._currentProfileMember set by openMemberProfile
  var special_tag = window._currentProfileMember?.special_tag || '';

  // Film posters from the films grid
  var filmPosters = [];
  document.querySelectorAll('#mprofile-films-grid .member-film-card').forEach(function(card) {
    var img = card.querySelector('img.member-film-poster');
    if (img && img.src) filmPosters.push(img.src);
  });

  await downloadPassportCard({ name, role, domain, batch, bio, photo, special_tag, filmPosters });
}

function _kfsWrapText(ctx, text, x, y, maxW, lineH) {
  var words = text.split(' '), line = '';
  for(var n=0;n<words.length;n++){
    var tl = line + words[n] + ' ';
    if(ctx.measureText(tl).width > maxW && n > 0){ ctx.fillText(line, x, y); line = words[n] + ' '; y += lineH; }
    else { line = tl; }
  }
  ctx.fillText(line, x, y);
}

// ── STORY CARD ─────────────────────────────────────────────────────────────────
// data = { type, title, year, description, genres[], crew[], posterUrl, pageUrl }
async function downloadStoryCard(data) {
  var blob = await _renderStoryCardBlob(data);
  if (!blob) return;
  var url = URL.createObjectURL(blob);
  var lnk = document.createElement('a');
  var slug = (data.title||'film').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  lnk.download = 'kfs-story-' + slug + '.png';
  lnk.href = url;
  lnk.click();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 3000);
}

// Download story card for the currently open movie
async function downloadMovieStoryCard() {
  var data = _gatherCurrentMovieData();
  await downloadStoryCard(data);
}

// Gather all current movie data from the DOM + window state
function _gatherCurrentMovieData() {
  var title   = document.getElementById('movie-detail-title')?.textContent?.trim() || '';
  var year    = document.getElementById('movie-detail-year')?.textContent?.trim()  || '';
  var desc    = document.getElementById('movie-detail-description')?.textContent?.trim() || '';
  var posterEl= document.getElementById('movie-detail-poster-img');
  var posterUrl = (posterEl && posterEl.style.display !== 'none') ? posterEl.src : '';
  var id      = window._currentMovieId || '';
  var slug    = title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  var pageUrl = id ? ('https://kiitfilmsociety.in/films/' + slug + '-' + id) : 'https://kiitfilmsociety.in';

  // Genre tags
  var genreTags = [];
  document.querySelectorAll('#movie-detail-genre-wrap .genre-tag').forEach(function(el){
    genreTags.push(el.textContent.trim());
  });

  // Crew — read from the rendered crew items
  var crew = [];
  document.querySelectorAll('#movie-detail-crew .movie-crew-item').forEach(function(item){
    var label = item.querySelector('.movie-crew-label')?.textContent?.trim() || '';
    var value = item.querySelector('.movie-crew-value')?.textContent?.replace(/\s+/g,' ')?.trim() || '';
    if (label && value) crew.push({ label: label, value: value });
  });

  return { type: 'FILM', title: title, year: year, description: desc,
           genres: genreTags, crew: crew, posterUrl: posterUrl, pageUrl: pageUrl };
}

// Render story card to a Blob (PNG). Returns null on failure.
async function _renderStoryCardBlob(data) {
  data = data || {};
  var W = 1080, H = 1920, PAD = 64;
  var type   = (data.type  || 'FILM').toUpperCase();
  var title  = data.title  || 'Untitled';
  var year   = data.year   || '';
  var desc   = data.description || '';
  var genres = data.genres || [];
  var crew   = (data.crew  || []).slice(0, 4); // max 4 crew rows
  var poster = data.posterUrl || '';
  var pageUrl= data.pageUrl || 'kiitfilmsociety.in';
  var displayUrl = pageUrl.replace(/^https?:\/\//,'');

  var cv  = document.createElement('canvas');
  cv.width = W; cv.height = H;
  var ctx = cv.getContext('2d');

  // ── Background ──────────────────────────────────────────────
  ctx.fillStyle = '#0a0a0a';
  ctx.fillRect(0, 0, W, H);

  // ── Poster image (top ~55% of card) ─────────────────────────
  var imgZoneH = 1060;
  if (poster) {
    try {
      var pImg = await _kfsLoadImage(poster);
      // Cover-fill the image zone
      var sc = Math.max(W / pImg.naturalWidth, imgZoneH / pImg.naturalHeight);
      var dw = pImg.naturalWidth * sc, dh = pImg.naturalHeight * sc;
      ctx.drawImage(pImg, (W - dw) / 2, (imgZoneH - dh) / 2, dw, dh);
    } catch(e) { /* no poster — leave dark bg */ }
  }

  // Gradient overlay on poster — dark vignette bottom
  var grad = ctx.createLinearGradient(0, imgZoneH * 0.3, 0, imgZoneH);
  grad.addColorStop(0, 'rgba(10,10,10,0)');
  grad.addColorStop(0.6, 'rgba(10,10,10,0.55)');
  grad.addColorStop(1,   'rgba(10,10,10,0.95)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, imgZoneH);

  // Top gradient (for KFS label legibility)
  var topGrad = ctx.createLinearGradient(0, 0, 0, 180);
  topGrad.addColorStop(0, 'rgba(10,10,10,0.7)');
  topGrad.addColorStop(1, 'rgba(10,10,10,0)');
  ctx.fillStyle = topGrad;
  ctx.fillRect(0, 0, W, 180);

  // ── KFS wordmark top-left ────────────────────────────────────
  ctx.font = '600 28px monospace';
  ctx.fillStyle = 'rgba(255,255,255,0.55)';
  ctx.fillText('K F S', PAD, 80);

  // ── Type badge top-right ─────────────────────────────────────
  ctx.font = '600 22px monospace';
  var bw = ctx.measureText(type).width + 44;
  _kfsRoundRect(ctx, W - PAD - bw, 48, bw, 42, 6);
  ctx.strokeStyle = 'rgba(255,255,255,0.25)'; ctx.lineWidth = 1.5; ctx.stroke();
  ctx.fillStyle = 'rgba(255,255,255,0.5)';
  ctx.fillText(type, W - PAD - bw + 22, 76);

  // ── Content panel (bottom of card) ──────────────────────────
  var panelY = imgZoneH;  // where text panel starts
  ctx.fillStyle = '#0a0a0a';
  ctx.fillRect(0, panelY, W, H - panelY);

  var cy = panelY + 64;

  // Year + genres row
  var metaParts = [];
  if (year) metaParts.push(year);
  genres.slice(0, 3).forEach(function(g){ metaParts.push(g); });
  if (metaParts.length) {
    ctx.font = '500 26px monospace';
    ctx.fillStyle = '#505050';
    ctx.fillText(metaParts.join('  ·  '), PAD, cy);
    cy += 52;
  }

  // Title — large, auto-wraps at 2 lines max
  var titleFontSize = 96;
  ctx.font = 'bold ' + titleFontSize + 'px serif';
  while (ctx.measureText(title).width > W - PAD*2 - 20 && titleFontSize > 52) {
    titleFontSize -= 4;
    ctx.font = 'bold ' + titleFontSize + 'px serif';
  }
  // Wrap to 2 lines if still needed
  var titleLines = _kfsWrapTextLines(ctx, title, W - PAD*2, 2);
  ctx.fillStyle = '#ebebE5';
  titleLines.forEach(function(line, i){ ctx.fillText(line, PAD, cy + i * (titleFontSize + 12)); });
  cy += titleLines.length * (titleFontSize + 12) + 32;

  // Thin divider
  ctx.strokeStyle = '#1e1e1e'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(PAD, cy); ctx.lineTo(W - PAD, cy); ctx.stroke();
  cy += 36;

  // Crew rows
  if (crew.length) {
    crew.forEach(function(c) {
      ctx.font = '600 22px monospace'; ctx.fillStyle = '#383838';
      ctx.fillText(c.label.toUpperCase(), PAD, cy);
      ctx.font = '400 28px sans-serif'; ctx.fillStyle = '#787870';
      // truncate long crew strings
      var crewVal = c.value;
      ctx.font = '400 28px sans-serif';
      while (ctx.measureText(crewVal).width > W - PAD*2 - 10 && crewVal.length > 4) {
        crewVal = crewVal.slice(0, -4) + '…';
      }
      ctx.fillText(crewVal, PAD, cy + 36);
      cy += 84;
    });
    cy += 8;
  }

  // Description (italic, capped to 3 lines)
  if (desc) {
    ctx.font = 'italic 400 32px serif'; ctx.fillStyle = '#3e3e3a';
    // quote bar
    ctx.fillStyle = '#222'; ctx.fillRect(PAD, cy, 3, 100);
    ctx.font = 'italic 400 32px serif'; ctx.fillStyle = '#484844';
    var descLines = _kfsWrapTextLines(ctx, desc, W - PAD*2 - 20, 3);
    descLines.forEach(function(line, i){ ctx.fillText(line, PAD + 20, cy + 36 + i * 46); });
    cy += 100 + descLines.length * 4;
  }

  // ── Footer ───────────────────────────────────────────────────
  var footerY = H - 80;
  ctx.fillStyle = '#141414';
  ctx.fillRect(0, footerY - 1, W, H - footerY + 1);

  // URL with subtle arrow — acts as the deep link hint
  ctx.font = '500 24px monospace'; ctx.fillStyle = '#303030';
  ctx.fillText(displayUrl, PAD, H - 32);

  // Small arrow indicator
  ctx.font = '500 24px monospace'; ctx.fillStyle = '#282828';
  ctx.fillText('↗', W - PAD - ctx.measureText('↗').width, H - 32);

  return new Promise(function(resolve) {
    cv.toBlob(function(blob){ resolve(blob); }, 'image/png');
  });
}

// ── SCREENSAVER ────────────────────────────────────────────────────────────
var _ssFilms = [];
var _ssIdx = 0, _ssTimer = null, _ssActive = false, _ssIdleTimer = null;
var _SS_IDLE_MS = 3 * 60 * 1000; // 3 minutes

function _ssGetFilms() {
  // Use real movies from cache; fall back to placeholder only if nothing loaded yet
  var movies = window._allMoviesCache || [];
  if (movies.length > 0) {
    // Shuffle so order varies each screensaver session
    var shuffled = movies.slice().sort(function() { return Math.random() - 0.5; });
    return shuffled.map(function(m) {
      return { title: m.title, year: m.release_year ? String(m.release_year) : '' };
    });
  }
  return [{ title: 'KFS', year: '' }];
}

function _resetIdleTimer() {
  clearTimeout(_ssIdleTimer);
  if (_ssActive) return;
  _ssIdleTimer = setTimeout(function() {
    // Don't trigger on admin panel or admin login
    var ap = document.getElementById('admin-panel');
    var al = document.getElementById('admin-login');
    if ((ap && ap.classList.contains('active')) || (al && al.classList.contains('active'))) return;
    launchKFSScreensaver();
  }, _SS_IDLE_MS);
}

(function initIdleWatcher() {
  ['mousemove','keydown','scroll','click','touchstart'].forEach(function(ev) {
    document.addEventListener(ev, _resetIdleTimer, { passive: true });
  });
  _resetIdleTimer();
})();

function launchKFSScreensaver() {
  var el = document.getElementById('kfs-screensaver');
  if (!el || _ssActive) return;
  _ssActive = true;
  el.style.display = 'flex';
  requestAnimationFrame(function(){ requestAnimationFrame(function(){ el.style.opacity = '1'; }); });

  // Load real films — fetch from API if cache is empty
  var doLaunch = function() {
    _ssFilms = _ssGetFilms();
    _ssIdx = 0;
    _ssCycleFilm();
    _ssTimer = setInterval(_ssCycleFilm, 3200);
  };

  if (!window._allMoviesCache || !window._allMoviesCache.length) {
    fetch('/api/movies').then(function(r){ return r.ok ? r.json() : []; })
      .then(function(movies){ window._allMoviesCache = movies || []; doLaunch(); })
      .catch(function(){ doLaunch(); });
  } else {
    doLaunch();
  }

  document.addEventListener('keydown', exitKFSScreensaver, { once: true });
}

function _ssCycleFilm() {
  if (!_ssFilms.length) _ssFilms = _ssGetFilms();
  var f = _ssFilms[_ssIdx % _ssFilms.length];
  var titleEl = document.getElementById('kfs-ss-title');
  var yearEl = document.getElementById('kfs-ss-year');
  if (!titleEl || !yearEl) return;
  titleEl.style.opacity = '0'; yearEl.style.opacity = '0';
  setTimeout(function() {
    titleEl.textContent = f.title;
    yearEl.textContent = f.year || '';
    titleEl.style.opacity = '1';
    yearEl.style.opacity = f.year ? '1' : '0';
  }, 500);
  _ssIdx++;
}

function exitKFSScreensaver() {
  var el = document.getElementById('kfs-screensaver');
  if (!el) return;
  _ssActive = false;
  el.style.opacity = '0';
  clearInterval(_ssTimer);
  setTimeout(function(){ el.style.display = 'none'; }, 1200);
  _resetIdleTimer();
}
// Allow clicking inside screensaver to not double-fire via bubbled events
document.getElementById('kfs-screensaver') && document.getElementById('kfs-screensaver').addEventListener('click', function(e){ e.stopPropagation(); exitKFSScreensaver(); });

// ── COLLABORATE ────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
}

function openMemberProfileById(uuid) {
  const allMembers = window._memberRegistry || [];
  const member = allMembers.find(m => String(m.id) === String(uuid));
  if (member) openMemberProfile(member);
}

async function loadCollaborate() {
  const list = document.getElementById('collab-list');
  if (!list) return;
  list.innerHTML = '<div class="loading">Loading open calls…</div>';

  let posts;
  try {
    const res = await fetch('/api/collaborate');
    posts = await res.json();
  } catch(e) {
    list.innerHTML = '<div class="admin-empty"><p>Could not load listings.</p></div>';
    return;
  }

  window._allCollabPosts = posts || [];

  // Build domain filter
  const filterWrap = document.getElementById('collab-filter-wrap');
  const domains = [...new Set((posts || []).map(p => p.domain).filter(Boolean))].sort();
  if (domains.length && filterWrap) {
    filterWrap.style.display = 'inline-block';
    _buildCollabFilterDropdown(domains);
    const btn = document.getElementById('collab-filter-btn');
    if (btn) {
      const textNode = Array.from(btn.childNodes).find(n=>n.nodeType===3 && n.textContent.trim());
      if (textNode) textNode.textContent = ' Filter ';
    }
  } else if (filterWrap) {
    filterWrap.style.display = 'none';
  }

  _renderCollabPosts(posts || [], null);
}

function _buildCollabFilterDropdown(domains) {
  const dd = document.getElementById('collab-filter-dropdown');
  if (!dd) return;
  const allItem = `<button class="blog-filter-item active" id="cfi-all" onclick="applyCollabFilter(null,this)"><span class="blog-filter-item-dot"></span>All Domains<\/button>`;
  const items = domains.map(d =>
    `<button class="blog-filter-item" id="cfi-${d.replace(/\s+/g,'-')}" onclick="applyCollabFilter('${d}',this)"><span class="blog-filter-item-dot"></span>${d}<\/button>`
  ).join('');
  dd.innerHTML = allItem + '<div class="blog-filter-divider-line"><\/div>' + items;
}

function toggleCollabFilter(btn) {
  const dd = document.getElementById('collab-filter-dropdown');
  const isOpen = dd.classList.contains('open');
  dd.classList.toggle('open', !isOpen);
  btn.classList.toggle('open', !isOpen);
  if (!isOpen) {
    const close = e => {
      if (!btn.closest('.blog-filter-wrap').contains(e.target)) {
        dd.classList.remove('open'); btn.classList.remove('open');
        document.removeEventListener('click', close);
      }
    };
    setTimeout(() => document.addEventListener('click', close), 0);
  }
}

function applyCollabFilter(domain, btn) {
  document.querySelectorAll('#collab-filter-dropdown .blog-filter-item').forEach(b=>b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('collab-filter-dropdown').classList.remove('open');
  document.getElementById('collab-filter-btn')?.classList.remove('open');
  const filterBtn = document.getElementById('collab-filter-btn');
  if (filterBtn) {
    const textNode = Array.from(filterBtn.childNodes).find(n=>n.nodeType===3 && n.textContent.trim());
    if (textNode) textNode.textContent = domain ? ` ${domain} ` : ' Filter ';
  }
  _renderCollabPosts(window._allCollabPosts || [], domain);
}

function _renderCollabPosts(posts, activeDomain) {
  const list = document.getElementById('collab-list');
  if (!list) return;
  const filtered = activeDomain ? posts.filter(p => p.domain === activeDomain) : posts;

  if (!filtered.length) {
    list.innerHTML = '<div class="admin-empty" style="text-align:center;padding:48px 24px"><p style="color:var(--grey);font-size:15px">' +
      (activeDomain ? `No open calls for "${activeDomain}" right now.` : 'No open calls right now. Be the first to post one!') +
      '</p></div>';
    return;
  }

  list.innerHTML = filtered.map(p => {
    const rawName = p.contact_name || '';
    const nameParts = rawName.split('||');
    const displayName = nameParts[0].trim();
    const memberUuid  = nameParts[1] ? nameParts[1].trim() : null;

    const memberBadge = memberUuid
      ? `<span onclick="openMemberProfileById('${memberUuid}')" style="color:var(--accent);cursor:pointer;text-decoration:underline;text-underline-offset:3px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:3px"><polyline points="20 6 9 17 4 12"/></svg>KFS Member</span>`
      : `<span style="color:var(--accent)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:3px"><polyline points="20 6 9 17 4 12"/></svg>KFS Member</span>`;

    const domainFlair = p.domain
      ? `<span style="display:inline-flex;align-items:center;padding:3px 10px;background:rgba(255,255,255,.07);border:1px solid var(--border);border-radius:20px;font-size:11px;font-weight:600;color:var(--grey);letter-spacing:.04em">${escapeHtml(p.domain)}</span>`
      : '';

    const contactParts = [];
    if (displayName)     contactParts.push(`<span>${escapeHtml(displayName)}</span>`);
    if (p.contact_email) contactParts.push(`<a href="mailto:${escapeHtml(p.contact_email)}" style="color:var(--white);text-decoration:underline;text-underline-offset:3px">${escapeHtml(p.contact_email)}</a>`);
    if (p.contact_phone) contactParts.push(`<a href="tel:${escapeHtml(p.contact_phone)}" style="color:var(--white);text-decoration:underline;text-underline-offset:3px">${escapeHtml(p.contact_phone)}</a>`);

    return `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px 26px;margin-bottom:14px;transition:border-color .2s">
      <div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:10px">
        <div style="flex:1;min-width:0">
          <h3 style="font-size:18px;font-weight:700;margin-bottom:5px;color:var(--white);letter-spacing:-.02em">${escapeHtml(p.title)}</h3>
          <p style="color:var(--grey);font-size:13px;margin:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <span>${escapeHtml(p.role)}</span>
            <span style="opacity:.35">·</span>
            ${memberBadge}
            ${p.domain ? `<span style="opacity:.35">·</span>${domainFlair}` : ''}
          </p>
        </div>
        <span class="tag upcoming" style="flex-shrink:0;font-size:11px">Until ${new Date(p.fulfillment_date + 'T00:00:00').toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'})}</span>
      </div>
      <p style="color:var(--white);line-height:1.7;margin-bottom:14px;font-size:14.5px">${escapeHtml(p.description)}</p>
      ${p.skills   ? `<p style="color:var(--grey);font-size:13px;margin-bottom:5px"><strong style="color:var(--white);font-weight:600">Skills needed:</strong> ${escapeHtml(p.skills)}</p>` : ''}
      ${p.timeline ? `<p style="color:var(--grey);font-size:13px;margin-bottom:5px"><strong style="color:var(--white);font-weight:600">Timeline:</strong> ${escapeHtml(p.timeline)}</p>` : ''}
      ${contactParts.length ? `
      <p style="color:var(--grey);font-size:13px;margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <strong style="color:var(--white);font-weight:600">Contact:</strong>
        ${contactParts.join('<span style="opacity:.3">·</span>')}
      </p>` : ''}
    </div>`;
  }).join('');
}

// ── COLLAB: KIIT email gate ────────────────────────────────────────────────────
let _collabVerifiedMember = null; // { id, name, role, domain, email }

function collabGateEmailInput() {
  const err = document.getElementById('collab-gate-error');
  if (err) { err.style.display = 'none'; err.textContent = ''; }
}

function _isKiitEmail(email) {
  const e = email.toLowerCase();
  return e.endsWith('@kiit.ac.in') ||
         e.includes('.kiit.ac.in') ||
         e.endsWith('@ksom.ac.in') ||
         e.endsWith('@kiitbiotech.ac.in');
}

async function verifyCollabMember() {
  const emailInput = document.getElementById('collab-kiit-email');
  const errEl = document.getElementById('collab-gate-error');
  const btn = document.getElementById('collab-gate-btn');
  const email = (emailInput?.value || '').trim();

  errEl.style.display = 'none'; errEl.textContent = '';

  if (!email) {
    errEl.textContent = 'Please enter your KIIT email.';
    errEl.style.display = 'block'; return;
  }
  if (!_isKiitEmail(email)) {
    errEl.textContent = 'This feature is exclusive to KFS members only. Contact us at filmsocietykiit@gmail.com for external support.';
    errEl.style.display = 'block'; return;
  }

  // Valid KIIT domain — unlock form, no server call needed
  _collabVerifiedMember = { email };
  document.getElementById('collab-gate').style.display = 'none';
  document.getElementById('collab-form-body').style.display = 'block';
  document.getElementById('collab-verified-name').textContent = '✓ ' + email + ' — KIIT verified';
  document.getElementById('collab-email').value = email;

  // Init member-only name picker (no free text)
  if (!window._collabNamePicker) {
    window._collabNamePicker = new CollabMemberPicker('collab-name-picker');
  } else {
    window._collabNamePicker.reset();
  }
}

function resetCollabGate() {
  _collabVerifiedMember = null;
  document.getElementById('collab-gate').style.display = 'block';
  document.getElementById('collab-form-body').style.display = 'none';
  document.getElementById('collab-gate-error').style.display = 'none';
  document.getElementById('collab-kiit-email').value = '';
}

function openCollabForm(post) {
  document.getElementById('collab-modal').classList.add('open');
  document.getElementById('collab-modal-title').textContent = post ? 'Edit Open Call' : 'Post Open Call';
  document.getElementById('collab-token').value = post?.edit_token || '';
  document.getElementById('collab-error').textContent = '';
  document.getElementById('collab-delete-own').style.display = post ? 'inline-flex' : 'none';

  if (post) {
    // Editing — skip the gate, show form directly
    document.getElementById('collab-gate').style.display = 'none';
    document.getElementById('collab-form-body').style.display = 'block';
    document.getElementById('collab-verified-badge').style.display = 'none';

    document.getElementById('collab-title').value = post.title || '';
    document.getElementById('collab-role').value = post.role || '';
    document.getElementById('collab-skills').value = post.skills || '';
    document.getElementById('collab-timeline').value = post.timeline || '';
    document.getElementById('collab-description').value = post.description || '';
    document.getElementById('collab-domain').value = post.domain || '';
    document.getElementById('collab-email').value = post.contact_email || '';
    document.getElementById('collab-email').readOnly = false;
    document.getElementById('collab-email').style.opacity = '1';
    document.getElementById('collab-email').style.cursor = 'auto';
    document.getElementById('collab-phone').value = post.contact_phone || '';
    document.getElementById('collab-date').value = post.fulfillment_date || '';

    if (!window._collabNamePicker) {
      window._collabNamePicker = new MemberPicker('collab-name-picker', false);
    } else {
      window._collabNamePicker.render();
    }
    window._collabNamePicker.setValue(post.contact_name || '');
  } else {
    // Check for portal member token — bypass gate entirely
    const memberToken = localStorage.getItem('kfs-member-token');
    // Profile (with email/mobile) stored by membersaccess.js on loadProfile()
    const memberProfileLS = (() => { try { return JSON.parse(localStorage.getItem('kfs-member-profile') || 'null'); } catch { return null; } })();
    const memberDataLS    = (() => { try { return JSON.parse(localStorage.getItem('kfs-member-data')    || 'null'); } catch { return null; } })();
    // Prefer in-memory (same-tab), fall back to localStorage (cross-tab)
    const memberProfile   = window._memberProfile || memberProfileLS;
    const memberData      = window._member        || memberDataLS;

    if (memberToken && (memberProfile || memberData)) {
      // Portal member: skip gate, auto-fill locked fields
      document.getElementById('collab-gate').style.display = 'none';
      document.getElementById('collab-form-body').style.display = 'block';

      const memberName  = memberProfile?.name  || memberData?.name  || '';
      const memberEmail = memberProfile?.email || memberData?.email || '';
      const memberPhone = memberProfile?.mobile || memberData?.mobile || '';

      // Show member badge instead of verified badge
      const badge = document.getElementById('collab-verified-badge');
      if (badge) {
        badge.style.display = 'flex';
        badge.style.background = 'rgba(255,255,255,.03)';
        badge.style.borderColor = 'rgba(255,255,255,.1)';
        // Swap check → lock icon
        const checkIcon = document.getElementById('collab-badge-check-icon');
        const lockIcon  = document.getElementById('collab-badge-lock-icon');
        if (checkIcon) checkIcon.style.display = 'none';
        if (lockIcon)  lockIcon.style.display  = 'block';
        const nameEl = document.getElementById('collab-verified-name');
        if (nameEl) {
          nameEl.style.color = '#e0e0e0';
          nameEl.innerHTML = `<span style="font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#555;font-weight:600;display:block;margin-bottom:1px">Logged in as</span><span style="font-size:13px;font-weight:600;color:#f0f0f0">${memberName}</span>`;
        }
        // Hide the "Change" span — member can't change identity
        const changeEl = badge.querySelector('[data-action="resetCollabGate"]');
        if (changeEl) changeEl.style.display = 'none';
      }
      // Update labels to reflect locked/pre-filled state
      const nameLabelEl = document.getElementById('collab-name-label');
      if (nameLabelEl) nameLabelEl.innerHTML = 'Your Name <span style="font-size:10px;color:#555;text-transform:none;font-weight:400;letter-spacing:0">· from your portal profile</span>';
      const phoneLabelEl = document.getElementById('collab-phone-label');
      if (phoneLabelEl) phoneLabelEl.innerHTML = 'Phone <span style="font-size:10px;color:#555;text-transform:none;font-weight:400;letter-spacing:0">· from your portal profile</span>';

      _collabVerifiedMember = { email: memberEmail, name: memberName, fromPortal: true };

      // Lock name field — show locked read-only display
      const namePickerWrap = document.getElementById('collab-name-picker');
      if (namePickerWrap) {
        namePickerWrap.innerHTML = `<div style="padding:10px 14px;background:#111;border:1px solid #1e1e1e;border-radius:8px;font-size:14px;color:#e0e0e0;display:flex;align-items:center;gap:8px">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <span>${memberName}</span>
        </div>`;
      }

      // Lock email — read-only
      const emailEl = document.getElementById('collab-email');
      if (emailEl) {
        emailEl.value = memberEmail;
        emailEl.readOnly = true;
        emailEl.style.opacity = '.5';
        emailEl.style.cursor = 'not-allowed';
      }

      // Lock phone — read-only (pre-filled from member profile)
      const phoneEl = document.getElementById('collab-phone');
      if (phoneEl) {
        phoneEl.value = memberPhone || '';
        if (memberPhone) {
          phoneEl.readOnly = true;
          phoneEl.style.opacity = '.5';
          phoneEl.style.cursor = 'not-allowed';
        }
      }

      // Reset other fields
      ['collab-title','collab-role','collab-skills','collab-timeline','collab-description','collab-date'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      document.getElementById('collab-domain').value = '';
      return;
    }

    // Non-member — show gate as normal
    document.getElementById('collab-gate').style.display = 'block';
    document.getElementById('collab-form-body').style.display = 'none';
    document.getElementById('collab-gate-error').style.display = 'none';
    document.getElementById('collab-kiit-email').value = '';
    document.getElementById('collab-gate-btn').disabled = false;
    document.getElementById('collab-gate-btn').textContent = 'Verify & Continue';
    // Restore default labels and badge icons
    const checkIcon = document.getElementById('collab-badge-check-icon');
    const lockIcon  = document.getElementById('collab-badge-lock-icon');
    if (checkIcon) checkIcon.style.display = '';
    if (lockIcon)  lockIcon.style.display  = 'none';
    const nameLabelEl = document.getElementById('collab-name-label');
    if (nameLabelEl) nameLabelEl.textContent = 'Your Name';
    const phoneLabelEl = document.getElementById('collab-phone-label');
    if (phoneLabelEl) phoneLabelEl.textContent = 'Phone (optional)';
    const phoneEl = document.getElementById('collab-phone');
    if (phoneEl) { phoneEl.readOnly = false; phoneEl.style.opacity = ''; phoneEl.style.cursor = ''; }

    // Reset form fields
    ['collab-title','collab-role','collab-skills','collab-timeline','collab-description','collab-phone','collab-date'].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    document.getElementById('collab-domain').value = '';
    document.getElementById('collab-email').value = '';
    _collabVerifiedMember = null;
  }
}

function closeCollabForm() {
  document.getElementById('collab-modal').classList.remove('open');
  // Restore default labels on close
  const checkIcon = document.getElementById('collab-badge-check-icon');
  const lockIcon  = document.getElementById('collab-badge-lock-icon');
  if (checkIcon) checkIcon.style.display = '';
  if (lockIcon)  lockIcon.style.display  = 'none';
  const nameLabelEl = document.getElementById('collab-name-label');
  if (nameLabelEl) nameLabelEl.textContent = 'Your Name';
  const phoneLabelEl = document.getElementById('collab-phone-label');
  if (phoneLabelEl) phoneLabelEl.textContent = 'Phone (optional)';
  const phoneEl = document.getElementById('collab-phone');
  if (phoneEl) { phoneEl.readOnly = false; phoneEl.style.opacity = ''; phoneEl.style.cursor = ''; }
}

function collabPayload() {
  const nameVal = window._collabNamePicker ? window._collabNamePicker.getValue() : (document.getElementById('collab-contact-name')?.value || '');
  return {
    title:            document.getElementById('collab-title').value,
    role:             document.getElementById('collab-role').value,
    domain:           document.getElementById('collab-domain').value,
    skills:           document.getElementById('collab-skills').value,
    timeline:         document.getElementById('collab-timeline').value,
    description:      document.getElementById('collab-description').value,
    contact_name:     nameVal,
    is_kfs_member:    true,
    contact_email:    document.getElementById('collab-email').value,
    contact_phone:    document.getElementById('collab-phone').value,
    fulfillment_date: document.getElementById('collab-date').value,
  };
}

async function saveCollabPost() {
  const token = document.getElementById('collab-token').value;
  const isPortalMember = !!(localStorage.getItem('kfs-member-token') && _collabVerifiedMember?.fromPortal);

  // Validate member picker — must select an existing KFS member (skip for portal members: name is locked)
  if (!token && !isPortalMember && window._collabNamePicker && !window._collabNamePicker.isValid()) {
    document.getElementById('collab-error').textContent = 'Please select your name from the KFS members list.';
    return;
  }
  let res, data;
  try {
    // Portal members use the authenticated endpoint — server overwrites name/email/phone from DB
    const url    = token ? '/api/collaborate/' + token
                  : isPortalMember ? '/api/collaborate/member'
                  : '/api/collaborate';
    const method = token ? 'PUT' : 'POST';
    const headers = { 'Content-Type': 'application/json', 'x-csrf-token': _csrfToken || '' };
    if (isPortalMember && !token) {
      // Authenticated portal request — send Bearer token, no CSRF needed (JWT is the auth)
      headers['Authorization'] = `Bearer ${localStorage.getItem('kfs-member-token')}`;
      delete headers['x-csrf-token'];
    }
    res = await fetch(url, {
      method,
      credentials: 'include',
      headers,
      body: JSON.stringify(collabPayload()),
    });
    data = await res.json();
  } catch(e) {
    document.getElementById('collab-error').textContent = 'Network error — please try again.';
    return;
  }

  if (!res.ok) {
    document.getElementById('collab-error').textContent = data.error || 'Could not save listing.';
    return;
  }

  closeCollabForm();
  loadCollaborate();

  if (data.edit_url) {
    const full = location.origin + data.edit_url;
    const successEl = document.getElementById('collab-success');
    if (successEl) {
      successEl.style.display = 'block';
      document.getElementById('collab-edit-link').value = full;
      setTimeout(() => {
        const input = document.getElementById('collab-edit-link');
        if (input) { input.focus(); input.select(); }
      }, 100);
    }
  }
}

async function loadCollabEditToken(token) {
  try {
    navigate('collaborate', false);
    const res = await fetch('/api/collaborate/edit/' + token);
    const post = await res.json();
    if (!res.ok) {
      alert(post.error || 'Invalid or expired edit link.');
      return;
    }
    // Wait for page to render then open modal
    await loadCollaborate();
    openCollabForm(post);
  } catch(e) {
    alert('Could not load listing.');
  }
}

async function deleteOwnCollabPost() {
  const token = document.getElementById('collab-token').value;
  if (!token || !confirm('Delete this listing? This cannot be undone.')) return;
  try {
    await fetch('/api/collaborate/' + token, { method: 'DELETE', credentials: 'include', headers: { 'X-CSRF-Token': _csrfToken || '' } });
  } catch(e) {}
  closeCollabForm();
  loadCollaborate();
}

// ── ADMIN: Collaboration Board ─────────────────────────────────────────────────

async function loadAdminCollaborate() {
  let posts;
  try {
    const res = await fetch('/api/collaborate', { headers: { 'Authorization': 'Bearer ' + (adminToken || '') } });
    posts = await res.json();
  } catch(e) { posts = []; }

  const tbody = document.getElementById('admin-collab-tbody');
  if (!tbody) return;

  if (!posts || !posts.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No active listings.</td></tr>';
    return;
  }

  tbody.innerHTML = posts.map(p => `
    <tr>
      <td style="font-weight:500">${escapeHtml(p.title)}</td>
      <td style="color:var(--grey)">${escapeHtml(p.role)}</td>
      <td style="color:var(--grey)">${escapeHtml(p.domain || '—')}</td>
      <td><span class="tag upcoming">KFS Member</span></td>
      <td style="color:var(--grey)">${p.fulfillment_date || '—'}</td>
      <td style="color:var(--grey)">${escapeHtml(p.contact_email || p.contact_phone || '—')}</td>
      <td><button class="btn-sm danger" onclick="deleteAdminCollab('${p.id}')">Delete</button></td>
    </tr>
  `).join('');
}

async function deleteAdminCollab(id) {
  if (!confirm('Delete this collaboration listing?')) return;
  await apiFetch('/api/admin/collaborate/' + id, 'DELETE');
  loadAdminCollaborate();
}


function openCollabMailModal(){document.getElementById('collab-mail-modal').classList.add('open');}
function closeCollabMailModal(){document.getElementById('collab-mail-modal').classList.remove('open');}
function copyCollabEmail(){
  navigator.clipboard.writeText('filmsocietykiit@gmail.com').then(()=>{
    const btn=document.getElementById('collab-copy-btn');
    btn.textContent='Copied!';btn.style.color='#34c759';btn.style.borderColor='#34c759';
    setTimeout(()=>{btn.textContent='Copy';btn.style.color='';btn.style.borderColor='';},2000);
  });
}
function openGmailCompose(e){
  e.preventDefault();
  const subject=encodeURIComponent('Collaboration Enquiry — External Collaborator');
  const body=encodeURIComponent('Hi KFS Team,\n\nI am interested in collaborating with KIIT Film Society.\n\n--- My Details ---\n\nName: \nInstitution / Organisation: \nRole / Skill I can offer: \nProject idea: \nTimeline / Availability: \nContact number: \nWhat I Require: \n\nAdditional details:\n\n---');
  window.open('https://mail.google.com/mail/?view=cm&to=filmsocietykiit@gmail.com&su='+subject+'&body='+body,'_blank');
}

// ══════════════════════════════════════════════════════════
// FILM COMMENTS — PUBLIC
// ══════════════════════════════════════════════════════════
let _fcMovieId = null;
let _fcAllComments = [];
let _fcShowing = 10;
const FC_PAGE = 10;

function timeAgo(dateStr) {
  const d = new Date(dateStr);
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  if (s < 604800) return Math.floor(s/86400) + 'd ago';
  return d.toLocaleDateString('en-IN', { day:'numeric', month:'short' });
}

function initials(name) {
  const parts = (name || '?').trim().split(/\s+/);
  return (parts[0][0] + (parts[1]?.[0] || '')).toUpperCase();
}

async function loadFilmComments(movieId) {
  _fcMovieId = movieId;
  _fcAllComments = [];
  _fcShowing = FC_PAGE;
  document.getElementById('fc-list').innerHTML = '<div class="fc-empty">Loading…</div>';
  document.getElementById('fc-form-msg').textContent = '';
  try {
    const data = await fetch('/api/films/' + movieId + '/comments').then(r => r.json());
    _fcAllComments = Array.isArray(data) ? data : [];
    renderFilmComments();
  } catch(e) {
    document.getElementById('fc-list').innerHTML = '<div class="fc-empty">Could not load comments.</div>';
  }
}

function renderFilmComments() {
  const list = document.getElementById('fc-list');
  const countEl = document.getElementById('fc-count');
  const moreBtn = document.getElementById('fc-load-more');
  const total = _fcAllComments.length;
  countEl.textContent = total;
  if (!total) {
    list.innerHTML = '<div class="fc-empty">Be the first to share your thoughts.</div>';
    moreBtn.style.display = 'none';
    return;
  }
  const slice = _fcAllComments.slice(0, _fcShowing);
  list.innerHTML = slice.map(c => renderComment(c)).join('');
  moreBtn.style.display = _fcShowing < total ? 'block' : 'none';
}

function renderComment(c) {
  const av = c.is_kfs_reply
    ? `<div class="fc-avatar is-kfs">K</div>`
    : `<div class="fc-avatar">${initials(c.author_name)}</div>`;

  const badges = [];
  if (c.is_kfs_reply) badges.push('<span class="fc-badge kfs">KFS Team</span>');
  if (c.is_pinned && !c.is_kfs_reply) badges.push('<span class="fc-badge pinned">Pinned</span>');

  const bodyClass = c.is_spoiler ? 'fc-body is-blurred' : 'fc-body';
  const spoilerLabel = c.is_spoiler
    ? '<div class="fc-spoiler-label"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> Spoiler</div>'
    : '';

  return `<div class="fc-item${c.is_pinned?' is-pinned':''}" data-id="${c.id}">
    <div class="fc-item-top">
      ${av}
      <div class="fc-meta">
        <div class="fc-meta-row">
          <span class="fc-author">${escHtml(c.author_name)}</span>
          ${badges.join('')}
          <span class="fc-time">${timeAgo(c.created_at)}</span>
        </div>
        <div class="${bodyClass}" id="fc-body-${c.id}">
          ${spoilerLabel}
          <div class="fc-body-text">${escHtml(c.body)}</div>
          ${c.is_spoiler ? `<button class="fc-spoiler-reveal" onclick="revealSpoiler('${c.id}')"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Reveal spoiler</button>` : ''}
        </div>
      </div>
    </div>
  </div>`;
}

function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function revealSpoiler(id) {
  const el = document.getElementById('fc-body-' + id);
  if (el) el.classList.remove('is-blurred');
}

function loadMoreComments() {
  _fcShowing += FC_PAGE;
  renderFilmComments();
}

async function submitFilmComment() {
  const nameEl = document.getElementById('fc-name');
  const bodyEl = document.getElementById('fc-body');
  const spoilerEl = document.getElementById('fc-spoiler');
  const msgEl = document.getElementById('fc-form-msg');
  const btn = document.getElementById('fc-submit-btn');

  const name = (nameEl.value || '').trim();
  const body = (bodyEl.value || '').trim();
  const is_spoiler = spoilerEl.checked;

  msgEl.className = 'fc-form-msg';
  if (!name) { msgEl.textContent = 'Please enter your name.'; msgEl.classList.add('error'); return; }
  if (!body) { msgEl.textContent = 'Comment cannot be empty.'; msgEl.classList.add('error'); return; }
  if (!_fcMovieId) return;

  btn.disabled = true;
  btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Posting…';
  msgEl.textContent = '';

  try {
    const res = await fetch('/api/films/' + _fcMovieId + '/comments', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify({ author_name: name, body, is_spoiler }),
    });
    const data = await res.json();
    if (!res.ok) {
      msgEl.textContent = data.error || 'Failed to post comment.';
      msgEl.classList.add('error');
    } else {
      bodyEl.value = '';
      spoilerEl.checked = false;
      // Insert at top of list (after any pinned items)
      const firstUnpinned = _fcAllComments.findIndex(c => !c.is_pinned);
      if (firstUnpinned === -1) _fcAllComments.push(data);
      else _fcAllComments.splice(firstUnpinned, 0, data);
      _fcShowing = Math.max(_fcShowing, _fcAllComments.length);
      renderFilmComments();
      msgEl.textContent = 'Comment posted!';
      setTimeout(() => { msgEl.textContent = ''; }, 3000);
    }
  } catch(e) {
    msgEl.textContent = 'Network error. Please try again.';
    msgEl.classList.add('error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Post';
  }
}

// ══════════════════════════════════════════════════════════
// FILM COMMENTS — ADMIN MODERATION
// ══════════════════════════════════════════════════════════
let _adminAllComments = [];
let _adminCommentFilter = 'all';
let _kfsReplyTargetMovieId = null;

async function loadAdminComments() {
  const listEl = document.getElementById('admin-comments-list');
  listEl.innerHTML = '<div class="bc-loading">Loading…</div>';
  try {
    const data = await apiFetch('/api/admin/comments');
    _adminAllComments = Array.isArray(data) ? data : [];
    renderAdminComments();
  } catch(e) {
    listEl.innerHTML = '<div class="bc-loading">Failed to load comments.</div>';
  }
}

function filterAdminComments(filter, btn) {
  _adminCommentFilter = filter;
  document.querySelectorAll('.admin-comment-filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderAdminComments();
}

function renderAdminComments() {
  const listEl = document.getElementById('admin-comments-list');
  let comments = _adminAllComments;
  if (_adminCommentFilter === 'pinned') comments = comments.filter(c => c.is_pinned);
  else if (_adminCommentFilter === 'spoiler') comments = comments.filter(c => c.is_spoiler);
  else if (_adminCommentFilter === 'kfs') comments = comments.filter(c => c.is_kfs_reply);

  if (!comments.length) {
    listEl.innerHTML = '<div class="bc-loading">No comments match this filter.</div>';
    return;
  }
  listEl.innerHTML = comments.map(c => `
    <div class="admin-comment-row" data-id="${c.id}">
      <div class="admin-comment-meta">
        <span class="admin-comment-film">${escHtml(c.movies?.title || 'Unknown Film')}</span>
        <span class="admin-comment-author">${escHtml(c.author_name)}</span>
        ${c.is_kfs_reply ? '<span class="fc-badge kfs" style="font-size:9px">KFS Team</span>' : ''}
        ${c.is_pinned ? '<span class="fc-badge pinned" style="font-size:9px">Pinned</span>' : ''}
        ${c.is_spoiler ? '<span class="fc-badge pinned" style="font-size:9px">Spoiler</span>' : ''}
        <span class="admin-comment-time">${timeAgo(c.created_at)}</span>
      </div>
      <div class="admin-comment-body">${escHtml(c.body)}</div>
      <div class="admin-comment-actions">
        <button class="admin-comment-action${c.is_pinned?' pinned':''}" onclick="adminTogglePin('${c.id}',${!c.is_pinned})">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
          ${c.is_pinned ? 'Unpin' : 'Pin'}
        </button>
        <button class="admin-comment-action" onclick="openKfsReplyModal('${c.movie_id}')">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          Reply as KFS
        </button>
        <button class="admin-comment-action danger" onclick="adminDeleteComment('${c.id}')">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          Delete
        </button>
      </div>
    </div>`).join('');
}

async function adminTogglePin(commentId, pin) {
  const res = await apiFetch('/api/admin/comments/' + commentId + '/pin', 'PATCH', { is_pinned: pin });
  if (res) {
    const idx = _adminAllComments.findIndex(c => c.id === commentId);
    if (idx !== -1) _adminAllComments[idx].is_pinned = pin;
    renderAdminComments();
  }
}

async function adminDeleteComment(commentId) {
  if (!confirm('Delete this comment? This cannot be undone.')) return;
  const res = await apiFetch('/api/admin/comments/' + commentId, 'DELETE');
  if (res) {
    _adminAllComments = _adminAllComments.filter(c => c.id !== commentId);
    renderAdminComments();
  }
}

// KFS Team reply modal
function openKfsReplyModal(movieId) {
  _kfsReplyTargetMovieId = movieId || null;
  const overlay = document.getElementById('fc-reply-modal-overlay');
  const select = document.getElementById('kfs-reply-movie-select');
  // Populate movie dropdown if no movieId pre-selected
  if (!movieId && select) {
    apiFetch('/api/movies').then(movies => {
      if (!movies) return;
      select.innerHTML = movies.map(m => `<option value="${m.id}">${escHtml(m.title)}</option>`).join('');
    });
    document.getElementById('kfs-reply-movie-wrap').style.display = 'block';
  } else {
    if (document.getElementById('kfs-reply-movie-wrap')) document.getElementById('kfs-reply-movie-wrap').style.display = 'none';
  }
  document.getElementById('kfs-reply-body').value = '';
  document.getElementById('kfs-reply-msg').textContent = '';
  overlay.classList.add('open');
}

function closeKfsReplyModal() {
  document.getElementById('fc-reply-modal-overlay').classList.remove('open');
  _kfsReplyTargetMovieId = null;
}

async function submitKfsReply() {
  const body = (document.getElementById('kfs-reply-body').value || '').trim();
  const msgEl = document.getElementById('kfs-reply-msg');
  const movieId = _kfsReplyTargetMovieId || document.getElementById('kfs-reply-movie-select')?.value;
  if (!body) { msgEl.textContent = 'Reply cannot be empty.'; return; }
  if (!movieId) { msgEl.textContent = 'Please select a film.'; return; }
  msgEl.textContent = '';
  const btn = document.getElementById('kfs-reply-send-btn');
  btn.disabled = true;
  try {
    const res = await apiFetch('/api/admin/films/' + movieId + '/comments/reply', 'POST', { body });
    if (res) {
      closeKfsReplyModal();
      loadAdminComments();
    } else {
      msgEl.textContent = 'Failed to post reply.';
    }
  } catch(e) {
    msgEl.textContent = 'Network error.';
  } finally {
    btn.disabled = false;
  }
}

// ══════════════════════════════════════════════════════════
// BROADCAST — ADMIN
// ══════════════════════════════════════════════════════════
let _bcAudienceType = 'all_registrants';

function selectBcAudience(type) {
  _bcAudienceType = type;
  document.getElementById('bc-aud-all').classList.toggle('selected', type === 'all_registrants');
  document.getElementById('bc-aud-event').classList.toggle('selected', type === 'event');
  document.getElementById('bc-event-picker').style.display = type === 'event' ? 'block' : 'none';
  document.getElementById('bc-recipient-count').textContent = '—';
}

async function loadBcEvents() {
  const sel = document.getElementById('bc-event-select');
  if (!sel) return;
  try {
    const events = await apiFetch('/api/admin/broadcast/events-with-registrants');
    if (!events || !events.length) {
      sel.innerHTML = '<option value="">No events with registrants yet</option>';
      return;
    }
    sel.innerHTML = events.map(e =>
      `<option value="${e.id}">${escHtml(e.title)}${e.event_date ? ' — ' + e.event_date : ''}</option>`
    ).join('');
  } catch(e) {}
}

async function previewBroadcastRecipients() {
  const countEl = document.getElementById('bc-recipient-count');
  countEl.textContent = '…';
  const eventId = _bcAudienceType === 'event' ? (document.getElementById('bc-event-select')?.value || null) : null;
  try {
    const res = await apiFetch('/api/admin/broadcast/preview', 'POST', { audience_type: _bcAudienceType, event_id: eventId });
    countEl.textContent = res?.count ?? '—';
  } catch(e) {
    countEl.textContent = '—';
  }
}

async function sendBroadcast() {
  const subject = (document.getElementById('bc-subject').value || '').trim();
  const bodyText = (document.getElementById('bc-body').value || '').trim();
  const msgEl = document.getElementById('bc-send-msg');
  const btn = document.getElementById('bc-send-btn');

  msgEl.style.display = 'none';
  if (!subject) { showBcMsg('Subject is required.', 'error'); return; }
  if (!bodyText) { showBcMsg('Message body is required.', 'error'); return; }

  const recipientCount = parseInt(document.getElementById('bc-recipient-count').textContent) || 0;
  if (!recipientCount) {
    const go = confirm('Recipient count not checked — send anyway?');
    if (!go) return;
  } else {
    const go = confirm(`Send to ${recipientCount} recipient${recipientCount !== 1 ? 's' : ''}?`);
    if (!go) return;
  }

  btn.disabled = true;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Sending…';

  const eventId = _bcAudienceType === 'event' ? (document.getElementById('bc-event-select')?.value || null) : null;

  // Build minimal HTML from plain text
  const bodyHtml = `<!DOCTYPE html>
<!-- KFS Frontend v1.17.9 — SRI attributes added for CDN scripts, unsafe-inline removed --><html><body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#111;border-radius:16px;border:1px solid #1e1e1e;overflow:hidden;max-width:560px">
  <tr><td style="background:#0a0a0a;padding:28px 36px;border-bottom:1px solid #1e1e1e">
    <span style="font-size:18px;font-weight:700;color:#f5f5f5;letter-spacing:-.02em">KFS — KIIT Film Society</span>
  </td></tr>
  <tr><td style="padding:32px 36px">
    <div style="font-size:15px;line-height:1.7;color:#aaa;white-space:pre-line">${bodyText.replace(/</g,'&lt;').replace(/>/g,'&gt;').split('\n').join('<br>')}</div>
  </td></tr>
  <tr><td style="padding:20px 36px 28px;border-top:1px solid #1e1e1e">
    <p style="font-size:12px;color:#444;margin:0">This message was sent by KFS — KIIT Film Society. <a href="https://kiitfilmsociety.in" style="color:#666;text-decoration:none">kiitfilmsociety.in</a></p>
  </td></tr>
</table>
</td></tr></table></body></html>`;

  try {
    const res = await apiFetch('/api/admin/broadcast/send', 'POST', { subject, body_html: bodyHtml, body_text: bodyText, audience_type: _bcAudienceType, event_id: eventId });
    if (res && res.success) {
      showBcMsg(`Sent to ${res.sent} recipient${res.sent !== 1 ? 's' : ''}${res.failed ? ` (${res.failed} failed)` : ''}.`, 'success');
      document.getElementById('bc-subject').value = '';
      document.getElementById('bc-body').value = '';
      document.getElementById('bc-recipient-count').textContent = '—';
      loadBroadcastHistory();
    } else {
      showBcMsg(res?.error || 'Send failed.', 'error');
    }
  } catch(e) {
    showBcMsg('Network error. Please try again.', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Send Broadcast';
  }
}

function showBcMsg(text, type) {
  const el = document.getElementById('bc-send-msg');
  el.textContent = text;
  el.className = 'bc-send-msg ' + type;
  el.style.display = 'block';
}

async function loadBroadcastHistory() {
  const tbody = document.getElementById('bc-history-tbody');
  try {
    const data = await apiFetch('/api/admin/broadcasts');
    if (!data || !data.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:32px">No broadcasts sent yet.</td></tr>';
      return;
    }
    // Fetch stats for each broadcast (parallel, capped at 20)
    const slice = data.slice(0, 20);
    const stats = await Promise.all(slice.map(b =>
      apiFetch('/api/admin/broadcasts/' + b.id + '/stats').catch(() => null)
    ));
    tbody.innerHTML = slice.map((b, i) => {
      const st = stats[i] || {};
      const opens = st.opens ?? '—';
      const rate = st.open_rate != null ? st.open_rate + '%' : '—';
      const fillW = st.open_rate ? Math.min(st.open_rate, 100) : 0;
      const audLabel = b.audience_type === 'all_registrants'
        ? 'All Registrants'
        : (b.events?.title ? escHtml(b.events.title) : 'Event');
      return `<tr>
        <td style="font-weight:500;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(b.subject)}</td>
        <td style="color:var(--grey);font-size:12px">${audLabel}</td>
        <td style="color:var(--grey);font-size:12px;white-space:nowrap">${b.sent_at ? new Date(b.sent_at).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'}) : '—'}</td>
        <td style="color:var(--grey);font-variant-numeric:tabular-nums">${b.recipient_count ?? '—'}</td>
        <td>
          <span style="font-size:13px;font-weight:600;color:var(--white)">${rate}</span>
          <div class="bc-open-bar"><div class="bc-open-bar-fill" style="width:${fillW}%"></div></div>
          <span style="font-size:10px;color:var(--grey)">${opens !== '—' ? opens + ' opens' : ''}</span>
        </td>
      </tr>`;
    }).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--grey);padding:32px">Failed to load history.</td></tr>';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// DONATIONS PAGE
// ══════════════════════════════════════════════════════════════════════════════

let _donSelectedAmount = 250; // default preset
let _donIsAnon = false;

// ── Mark body as admin-view so amount is visible in donor cards ──────────────
function _syncAdminAmountVisibility() {
  if (adminToken) {
    document.body.classList.add('kfs-admin-view');
  } else {
    document.body.classList.remove('kfs-admin-view');
  }
}

// ── Called by loadPageData when navigating to donations ─────────────────────
async function loadDonationsPage() {
  _syncAdminAmountVisibility();
  resetDonForm();
  await Promise.all([loadDonStats(), loadDonors()]);
}

// ── Amount preset buttons ────────────────────────────────────────────────────
function selectDonAmount(amount, btn) {
  _donSelectedAmount = amount;
  document.querySelectorAll('.don-amount-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  // Clear custom input
  const custom = document.getElementById('don-custom-amount');
  if (custom) custom.value = '';
  updateDonSubmit();
}

// ── Custom amount input ──────────────────────────────────────────────────────
function onDonCustomAmount(input) {
  const val = parseInt(input.value, 10);
  // Deselect presets
  document.querySelectorAll('.don-amount-btn').forEach(b => b.classList.remove('active'));
  if (!isNaN(val) && val >= 10 && val <= 500) {
    _donSelectedAmount = val;
  } else {
    _donSelectedAmount = null;
  }
  updateDonSubmit();
}

// ── T&C modal toggle ─────────────────────────────────────────────────────────
function toggleDonTC(e) {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  const overlay = document.getElementById('don-tc-overlay');
  if (!overlay) return;
  const opening = !overlay.classList.contains('open');
  overlay.classList.toggle('open', opening);
  document.body.style.overflow = opening ? 'hidden' : '';
}
function handleDonTCOverlayClick(e) {
  // close on backdrop click (not on modal itself)
  if (e.target === e.currentTarget || e.target.classList.contains('don-tc-backdrop')) toggleDonTC(e);
}
// Escape key closes modal
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('don-tc-overlay');
    if (overlay && overlay.classList.contains('open')) toggleDonTC(null);
  }
});

// ── Anonymous toggle ─────────────────────────────────────────────────────────
function toggleDonAnon() {
  _donIsAnon = !_donIsAnon;
  const toggle = document.getElementById('don-anon-toggle');
  if (toggle) toggle.classList.toggle('active', _donIsAnon);
}

// ── Enable/disable submit button based on T&C + amount validity ──────────────
function updateDonSubmit() {
  const tandcChecked = document.getElementById('don-tandc')?.checked;
  const amountOk = _donSelectedAmount && _donSelectedAmount >= 10 && _donSelectedAmount <= 500;
  const btn = document.getElementById('don-submit-btn');
  if (btn) btn.disabled = !(tandcChecked && amountOk);
}

// ── Show/hide error ──────────────────────────────────────────────────────────
function _donShowError(msg) {
  const el = document.getElementById('don-error');
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('show', !!msg);
}

// ── Reset form to initial state ──────────────────────────────────────────────
function resetDonForm() {
  _donIsAnon = false;
  _donSelectedAmount = 250;
  const toggle = document.getElementById('don-anon-toggle');
  if (toggle) toggle.classList.remove('active');

  // Reset preset buttons — highlight ₹250
  document.querySelectorAll('.don-amount-btn').forEach(b => {
    b.classList.toggle('active', b.textContent.includes('250'));
  });

  const ids = ['don-name', 'don-email', 'don-rollno', 'don-bio', 'don-custom-amount'];
  ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  const tandc = document.getElementById('don-tandc');
  if (tandc) tandc.checked = false;
  const tcCard = document.getElementById('don-tc-overlay');
  if (tcCard) { tcCard.classList.remove('open'); document.body.style.overflow = ''; }

  _donShowError('');
  const formBody = document.getElementById('don-form-body');
  const success  = document.getElementById('don-success');
  if (formBody) formBody.style.display = '';
  if (success)  success.classList.remove('show');

  updateDonSubmit();
}

// ── Main donation flow ───────────────────────────────────────────────────────
async function submitDonation() {
  _donShowError('');

  // Guard: T&C
  if (!document.getElementById('don-tandc')?.checked) {
    _donShowError('Please agree to the Terms & Conditions before donating.');
    return;
  }

  // Guard: amount — must be whole integer between 10 and 500 (guide Section 3.2)
  if (!_donSelectedAmount || !Number.isInteger(_donSelectedAmount) || _donSelectedAmount < 10 || _donSelectedAmount > 500) {
    _donShowError('Please choose a valid whole-number amount between ₹10 and ₹500.');
    return;
  }

  // Razorpay SDK loaded statically in <head> — no lazy load needed

  // Guard: email required
  const email = (document.getElementById('don-email')?.value || '').trim();
  if (!email || !email.includes('@')) {
    _donShowError('A valid email is required for your receipt.');
    return;
  }

  const name    = (document.getElementById('don-name')?.value    || '').trim();
  const rollNo  = (document.getElementById('don-rollno')?.value  || '').trim();
  const bio     = (document.getElementById('don-bio')?.value     || '').trim();

  const btn = document.getElementById('don-submit-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Opening payment…'; }

  try {
    // Step 1 — Create order on our backend (amount enforced server-side)
    const orderRes = await fetch('/api/donation/create-order', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
      body: JSON.stringify({
        amount: _donSelectedAmount,
        email,
        tandc_acknowledged: true,
        is_anonymous: _donIsAnon,
        ...(_donIsAnon ? {} : { name, roll_no: rollNo, bio }),
      }),
    });

    const orderData = await orderRes.json();
    if (!orderRes.ok) {
      _donShowError(orderData.error || 'Could not initiate payment. Please try again.');
      return;
    }

    const { order_id, key_id, amount_paise } = orderData;

    // Show TEST MODE banner if using test keys
    const existingBanner = document.getElementById('don-test-mode-banner');
    if (existingBanner) existingBanner.remove();
    if (key_id && key_id.startsWith('rzp_test_')) {
      const banner = document.createElement('div');
      banner.id = 'don-test-mode-banner';
      banner.style.cssText = 'background:rgba(255,193,7,.15);border:1px solid rgba(255,193,7,.4);color:#ffc107;border-radius:8px;padding:10px 14px;font-size:12px;font-weight:600;margin-bottom:12px;text-align:center;letter-spacing:.04em';
      banner.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> TEST MODE — No real money will be charged. Use Razorpay test card: 4111 1111 1111 1111';
      const submitBtn = document.getElementById('don-submit-btn');
      if (submitBtn && submitBtn.parentNode) submitBtn.parentNode.insertBefore(banner, submitBtn);
    }

    // Step 2 — Open Razorpay Checkout
    const rzp = new Razorpay({
      key:         key_id,
      amount:      amount_paise,
      currency:    'INR',
      name:        'KFS — KIIT Film Society',
      description: 'Donation to KFS',
      order_id:    order_id,
      prefill: {
        name:  _donIsAnon ? '' : name,
        email: email,
      },
      theme: { color: '#f5f5f5' },
      modal: {
        ondismiss: () => {
          if (btn) { btn.disabled = false; btn.textContent = 'Donate with Razorpay'; }
        },
      },
      handler: async (response) => {
        // Step 3 — Verify payment signature on backend
        if (btn) btn.textContent = 'Verifying…';
        try {
          const verifyRes = await fetch('/api/donation/verify', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
            body: JSON.stringify({
              razorpay_order_id:   response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature:  response.razorpay_signature,
              donor: {
                email,
                tandc_acknowledged: true,
                is_anonymous: _donIsAnon,
                ...(_donIsAnon ? {} : { name, roll_no: rollNo, bio }),
              },
            }),
          });
          const verifyData = await verifyRes.json();
          if (!verifyRes.ok) {
            _donShowError(verifyData.error || 'Payment verification failed. Contact support if amount was deducted.');
            if (btn) { btn.disabled = false; btn.textContent = 'Donate with Razorpay'; }
            return;
          }
          // Success
          const formBody = document.getElementById('don-form-body');
          const success  = document.getElementById('don-success');
          if (formBody) formBody.style.display = 'none';
          if (success)  success.classList.add('show');

          // ── Populate receipt card ───────────────────────────────────────
          const recCard   = document.getElementById('don-receipt-card');
          const recDlBtn  = document.getElementById('don-rec-dl-btn');
          if (recCard) {
            const recAmtRs = Math.round((verifyData.amount_paise || amount_paise || 0) / 100);
            const recDate  = verifyData.date
              ? new Date(verifyData.date).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric', timeZone:'Asia/Kolkata' }) + ' IST'
              : new Date().toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric', timeZone:'Asia/Kolkata' }) + ' IST';
            const setRec = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val || '—'; };
            setRec('don-rec-name',       _donIsAnon ? 'Anonymous' : (name || '—'));
            setRec('don-rec-email',      email);
            setRec('don-rec-amount',     `₹${recAmtRs.toLocaleString('en-IN')}`);
            setRec('don-rec-payment-id', response.razorpay_payment_id || verifyData.payment_id || '—');
            setRec('don-rec-order-id',   response.razorpay_order_id   || order_id || '—');
            setRec('don-rec-date',       recDate);
            recCard.style.display = 'block';
            // Store receipt data on the button for donorDownloadReceipt()
            if (recDlBtn) {
              recDlBtn._receiptData = {
                name:        _donIsAnon ? null : name,
                email:       email,
                amount_paise: verifyData.amount_paise || amount_paise,
                payment_id:  response.razorpay_payment_id || verifyData.payment_id,
                order_id:    response.razorpay_order_id   || order_id,
                date:        verifyData.date || new Date().toISOString(),
                is_anonymous: _donIsAnon,
              };
              recDlBtn.style.display = 'flex';
            }
          }
          // Refresh donors list
          loadDonors();
          loadDonStats();
        } catch(e) {
          _donShowError('Network error during verification. Contact us if your amount was deducted.');
          if (btn) { btn.disabled = false; btn.textContent = 'Donate with Razorpay'; }
        }
      },
    });

    rzp.open();

  } catch(e) {
    _donShowError('Something went wrong. Please try again.');
    if (btn) { btn.disabled = false; btn.textContent = 'Donate with Razorpay'; }
  }
}

// ── Load impact stats ─────────────────────────────────────────────────────────
async function loadDonStats() {
  try {
    const data = await fetch('/api/donation/stats').then(r => r.ok ? r.json() : null);
    if (!data) return;

    const donorsEl = document.getElementById('don-stat-donors');
    const filmsEl  = document.getElementById('don-stat-films');
    if (donorsEl) donorsEl.textContent = data.active_donors ?? '—';
    if (filmsEl)  filmsEl.textContent  = data.films_supported ?? '—';
  } catch(e) {}
}

// ── Load & render donors list ─────────────────────────────────────────────────
async function loadDonors() {
  const container = document.getElementById('don-donors-container');
  if (!container) return;
  container.innerHTML = '<div class="don-donors-empty">Loading…</div>';

  try {
    // Use admin endpoint (includes amount) if logged in, else public endpoint
    const endpoint = adminToken ? '/api/admin/donation/donors' : '/api/donation/donors';
    const donors = await fetch(endpoint, {
      headers: adminToken ? { Authorization: 'Bearer ' + adminToken } : {},
    }).then(r => r.ok ? r.json() : []);

    if (!donors || !donors.length) {
      container.innerHTML = '<div class="don-donors-empty">No donors yet this semester. Be the first!</div>';
      return;
    }

    container.innerHTML = '<div class="don-donors-grid">' +
      donors.map(d => renderDonorCard(d)).join('') +
    '</div>';

  } catch(e) {
    container.innerHTML = '<div class="don-donors-empty">Could not load donors.</div>';
  }
}

function renderDonorCard(d) {
  const name    = d.is_anonymous ? 'Anonymous Donor' : escHtml(d.display_name || d.name || 'Donor');
  const rollNo  = d.is_anonymous ? null : (d.roll_no || null);
  const photo   = d.is_anonymous ? null : (d.photo_path  || null);
  const bio     = d.is_anonymous ? null : (d.bio         || null);
  const semester = escHtml(d.semester_label || '');

  const nameHtml = `<div class="don-donor-name">${name}</div>`;

  const rollHtml = rollNo
    ? `<div style="font-size:10px;color:var(--grey);letter-spacing:.06em;text-transform:uppercase;margin-top:2px">${escHtml(rollNo)}</div>`
    : '';

  const photoHtml = photo
    ? `<img src="${escHtml(photo)}" alt="${name}" style="width:32px;height:32px;border-radius:50%;object-fit:cover;margin-bottom:8px;display:block">`
    : '';

  const bioHtml = bio ? `<div style="font-size:11px;color:var(--grey);margin-top:4px;line-height:1.5;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${escHtml(bio)}</div>` : '';

  // Amount — only rendered if server sent it (admin endpoint) and kfs-admin-view is active
  const amtHtml = d.amount_paise != null
    ? `<div class="don-donor-amt">₹${Math.round(d.amount_paise / 100).toLocaleString('en-IN')}</div>`
    : '';

  // Download Receipt button — only for admins (amount_paise present = admin endpoint response)
  const receiptBtnHtml = (d.amount_paise != null && d.payment_id)
    ? `<button class="don-donor-receipt-btn" title="Download receipt"
         onclick="event.stopPropagation();adminDownloadReceipt(${JSON.stringify({
           id:           d.id,
           name:         d.name,
           email:        d.email,
           amount_paise: d.amount_paise,
           payment_id:   d.payment_id,
           order_id:     d.order_id || '',
           date:         d.date,
           is_anonymous: d.is_anonymous,
         }).replace(/"/g,'&quot;')})">
         <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
         Receipt
       </button>`
    : '';

  const donorIdSafe = escHtml(String(d.id || ''));

  return `<div class="don-donor-card" data-donor-id="${donorIdSafe}" style="position:relative">
    ${photoHtml}
    ${nameHtml}
    ${rollHtml}
    <div class="don-donor-meta">${semester}</div>
    ${bioHtml}
    ${amtHtml}
    ${receiptBtnHtml}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
// EVENT DELEGATION — replaces all inline onclick=/onchange=/oninput=/onkeydown=
// One listener per event type on document handles every data-action element.
// ══════════════════════════════════════════════════════════════════════════════

// ── Helper stubs for elements that used complex inline expressions ────────────
function scrollTo_don_form_wrap()      { document.getElementById('don-form-wrap')?.scrollIntoView({behavior:'smooth',block:'center'}); }
function scrollTo_don_donors_section() { document.getElementById('don-donors-section')?.scrollIntoView({behavior:'smooth',block:'start'}); }
function triggerClick_member_xlsx_input()  { document.getElementById('member-xlsx-input')?.click(); }
function triggerClick_set_team_photo_file(){ document.getElementById('set-team-photo-file')?.click(); }
function triggerClick_set_egg_img_file()   { document.getElementById('set-egg-img-file')?.click(); }
function triggerClick_cegg_img_file()      { document.getElementById('cegg-img-file')?.click(); }
function focusEl_movie_genre_input()       { document.getElementById('movie-genre-input')?.focus(); }
function togglePasswordVisibility() {
  const i = document.getElementById('admin-password');
  if (!i) return;
  const open = i.type === 'password';
  i.type = open ? 'text' : 'password';
  const eo = document.getElementById('eye-open');
  const ec = document.getElementById('eye-closed');
  if (eo) eo.style.display = open ? 'none' : 'block';
  if (ec) ec.style.display = open ? 'block' : 'none';
}

// ── Core dispatcher ───────────────────────────────────────────────────────────
function _dispatch(el, eventObj) {
  const action = el.dataset.action;
  if (!action) return;
  const fn = window[action];
  if (typeof fn !== 'function') {
    console.warn('[dispatch] Unknown action:', action);
    return;
  }
  let args = [];
  if (el.dataset.args) {
    try {
      args = JSON.parse(el.dataset.args).map(a =>
        a === '__this__' ? el : a === '__event__' ? eventObj : a
      );
    } catch(e) { console.warn('[dispatch] Bad data-args on', action, e); }
  }
  fn(...args);
}

// ── Click delegation ──────────────────────────────────────────────────────────
document.addEventListener('click', function(e) {
  // data-action (regular buttons/links)
  const actionEl = e.target.closest('[data-action]');
  if (actionEl) {
    // Backdrop: only fire if click landed directly on this element
    if (actionEl.dataset.backdrop === 'true' && e.target !== actionEl) return;
    e.preventDefault();
    _dispatch(actionEl, e);
    return;
  }

  // data-nav-page (nav links + any element navigating to a page)
  const navEl = e.target.closest('[data-nav-page]');
  if (navEl) {
    e.preventDefault();
    const page = navEl.dataset.navPage;
    if (typeof navigate === 'function') navigate(page);
    if (typeof closeMenu === 'function') closeMenu();
    return;
  }
}, { capture: false });

// ── Change delegation (onchange) ──────────────────────────────────────────────
document.addEventListener('change', function(e) {
  const el = e.target.closest('[data-onchange]');
  if (!el) return;
  const expr = el.dataset.onchange;
  // Map known expressions to function calls
  _evalDataHandler(el, expr, e);
});

// ── Input delegation (oninput) ────────────────────────────────────────────────
document.addEventListener('input', function(e) {
  const el = e.target.closest('[data-oninput]');
  if (!el) return;
  _evalDataHandler(el, el.dataset.oninput, e);
});

// ── Keydown delegation (onkeydown) ────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  const el = e.target.closest('[data-onkeydown]');
  if (!el) return;
  _evalDataHandler(el, el.dataset.onkeydown, e);
});

// ── Handler expression evaluator ─────────────────────────────────────────────
// Handles the small set of expression patterns found in the codebase.
// This is NOT eval() — it's a whitelist matcher.
const _HANDLER_RE = /^(?:if\(event\.key===(['"])([^'"]+)\1\))?([a-zA-Z_$][a-zA-Z0-9_$]*)(?:\(([^)]*)\))?(?:;([a-zA-Z_$][a-zA-Z0-9_$]*)(?:\(([^)]*)\))?)?$/;

function _evalDataHandler(el, expr, eventObj) {
  if (!expr) return;

  // Handle paired expressions like "autoMemberSort();toggleDomainField()"
  const parts = expr.split(';').map(s => s.trim()).filter(Boolean);
  for (const part of parts) {
    // "if(event.key==='X')fn()" pattern
    const keyMatch = part.match(/^if\s*\(event\.key===(['"])([^'"]+)\1\)\s*(?:\{event\.preventDefault\(\);\s*\})?([a-zA-Z_$][a-zA-Z0-9_$]*)\(([^)]*)\)$/);
    if (keyMatch) {
      if (eventObj.key === keyMatch[2]) {
        if (part.includes('event.preventDefault()')) eventObj.preventDefault();
        const fn = window[keyMatch[3]];
        if (typeof fn === 'function') fn();
      }
      continue;
    }

    // Simple "fn()" or "fn(this)" or "fn(this.value)"
    const simpleMatch = part.match(/^([a-zA-Z_$][a-zA-Z0-9_$]*)\(([^)]*)\)$/);
    if (simpleMatch) {
      const fn = window[simpleMatch[1]];
      if (typeof fn !== 'function') { console.warn('[handler] Unknown fn:', simpleMatch[1]); continue; }
      const argStr = simpleMatch[2].trim();
      if (!argStr)              { fn(); continue; }
      if (argStr === 'this')    { fn(el); continue; }
      if (argStr === 'this.value') { fn(el.value); continue; }
      if (argStr === 'this.checked') { fn(el.checked); continue; }
      if (argStr === 'this.files[0]?.name||\'No file\'') {
        // onchange="document.getElementById('cegg-img-name').textContent=this.files[0]?.name||'No file'"
        // handled below
        continue;
      }
      // Try JSON parse for literal args
      try {
        const safe = argStr.replace(/'/g, '"');
        const args = JSON.parse('[' + safe + ']');
        fn(...args);
      } catch { fn(); }
      continue;
    }

    // Special: update a textContent from file input
    const fileNameMatch = part.match(/^document\.getElementById\('([^']+)'\)\.textContent=this\.files\[0\]\?\.name\|\|'([^']+)'$/);
    if (fileNameMatch) {
      const target = document.getElementById(fileNameMatch[1]);
      if (target) target.textContent = el.files?.[0]?.name || fileNameMatch[2];
      continue;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// KFS QR REGISTRATION SYSTEM — additions
// ══════════════════════════════════════════════════════════════════════════════

async function loadScannerSection() {
  const events = await apiFetch('/api/events');
  const scanEvSel = document.getElementById('scan-event-select');
  const dataEvSel = document.getElementById('scan-data-event-select');

  if (events && events.length) {
    const sorted = [...events].sort((a, b) => {
      if (a.is_upcoming !== b.is_upcoming) return a.is_upcoming ? -1 : 1;
      return new Date(b.event_date || 0) - new Date(a.event_date || 0);
    });
    const opts = sorted.map(e =>
      `<option value="${e.id}">${e.is_upcoming ? '▶' : '●'} ${e.title}${e.event_date ? ' — ' + new Date(e.event_date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }) : ''}</option>`
    ).join('');
    if (scanEvSel) scanEvSel.innerHTML = '<option value="">— Select event —</option>' + opts;
    if (dataEvSel) dataEvSel.innerHTML = '<option value="">— Select event —</option>' + opts;
  }
}

async function loadEventsWithRegs() {
  const events = await apiFetch('/api/events');
  const tbody = document.getElementById('admin-events-tbody');
  if (!tbody) return;
  if (events === null) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:#e74c3c">Failed to load — check the error bar above.</td></tr>`;
    return;
  }
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No events yet.</td></tr>`;
    return;
  }

  const statsMap = {};
  await Promise.allSettled(
    events.map(async e => {
      try {
        const s = await apiFetch(`/api/admin/events/${e.id}/registrations/stats`);
        if (s) statsMap[e.id] = s;
      } catch {}
    })
  );

  tbody.innerHTML = events.map(e => {
    const eJson = JSON.stringify(e).replace(/"/g, '&quot;');
    const stats = statsMap[e.id];
    const regBadge = stats
      ? `<span style="font-size:11px;color:var(--grey)">${stats.checked_in}/${stats.total} present</span>`
      : '';
    return `<tr data-id="${e.id}">
      <td style="font-weight:500">${e.title}</td>
      <td style="color:var(--grey)">${e.event_date || '—'}</td>
      <td><span class="tag ${e.is_upcoming ? 'upcoming' : ''}">${e.is_upcoming ? 'Upcoming' : 'Past'}</span></td>
      <td style="color:var(--grey)">${e.location || '—'}</td>
      <td>${regBadge}</td>
      <td><div class="action-btns">
        <button class="btn-sm" onclick="editEvent(${eJson})">Edit</button>
        <button class="btn-sm" style="background:rgba(88,166,255,.12);color:#58a6ff;border-color:rgba(88,166,255,.25)" onclick="openFormBuilder('${e.id}','${e.title.replace(/'/g,"\\x27")}')">Form</button>
        <button class="btn-sm" style="background:rgba(34,197,94,.1);color:#22c55e;border-color:rgba(34,197,94,.25)" onclick="openEventRegistrations('${e.id}')">Regs</button>
        <button class="btn-sm danger" onclick="deleteEvent('${e.id}')">Delete</button>
      </div></td>
    </tr>`;
  }).join('');
  _attachInlineEdits('events', tbody);
}

let _regEventId = null;
let _regsList = [];

async function openEventRegistrations(eventId) {
  _regEventId = eventId;
  const events = await apiFetch('/api/events');
  const ev = (events || []).find(e => String(e.id) === String(eventId));

  const modalHtml = `
    <div class="modal-header" style="padding:24px 28px;border-bottom:1px solid var(--border-subtle)">
      <h2 style="font-size:18px;font-weight:700;margin:0">Registrations — ${ev ? ev.title : 'Event'}</h2>
    </div>
    <div style="padding:20px 28px">
      <div id="reg-stats-strip" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px">
        <div style="background:#1a1a1a;border:1px solid var(--border-subtle);border-radius:10px;padding:14px;text-align:center">
          <div id="rstat-total" style="font-size:24px;font-weight:800;letter-spacing:-.03em">—</div>
          <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Total</div>
        </div>
        <div style="background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:10px;padding:14px;text-align:center">
          <div id="rstat-checked" style="font-size:24px;font-weight:800;letter-spacing:-.03em;color:#22c55e">—</div>
          <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Present</div>
        </div>
        <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.15);border-radius:10px;padding:14px;text-align:center">
          <div id="rstat-pending" style="font-size:24px;font-weight:800;letter-spacing:-.03em;color:#f59e0b">—</div>
          <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Pending</div>
        </div>
      </div>
      <div style="display:flex;gap:10px;margin-bottom:14px">
        <input id="reg-search-input" type="text" placeholder="Search by name, email, roll no…"
          style="flex:1;background:#0d0d0d;border:1px solid var(--border-subtle);border-radius:8px;padding:10px 12px;font-size:13px;color:var(--text);outline:none"
          oninput="filterModalRegs(this.value)">
        <button class="btn-sm" style="background:rgba(88,166,255,.1);color:#58a6ff;border:1px solid rgba(88,166,255,.2);padding:10px 14px" onclick="downloadRegsExport('${eventId}')">↓ Export</button>
      </div>
      <div id="regs-modal-list" style="max-height:380px;overflow-y:auto;display:flex;flex-direction:column;gap:6px">
        <div style="text-align:center;padding:24px;color:var(--grey);font-size:13px">Loading…</div>
      </div>
    </div>
  `;

  showModal(modalHtml, '680px');

  const data = await apiFetch(`/api/admin/events/${eventId}/registrations`);
  _regsList = data || [];
  updateRegStats();
  renderModalRegs(_regsList);
}

function updateRegStats() {
  const total = _regsList.length;
  const checked = _regsList.filter(r => r.checked_in).length;
  const pending = total - checked;
  const el = id => document.getElementById(id);
  if (el('rstat-total'))   el('rstat-total').textContent = total;
  if (el('rstat-checked')) el('rstat-checked').textContent = checked;
  if (el('rstat-pending')) el('rstat-pending').textContent = pending;
}

function filterModalRegs(q) {
  const ql = q.toLowerCase();
  const filtered = _regsList.filter(r =>
    (r.name || '').toLowerCase().includes(ql) ||
    (r.email || '').toLowerCase().includes(ql) ||
    (r.roll_no || '').toLowerCase().includes(ql)
  );
  renderModalRegs(filtered);
}

function renderModalRegs(list) {
  const el = document.getElementById('regs-modal-list');
  if (!el) return;
  if (!list.length) {
    el.innerHTML = `<div style="text-align:center;padding:24px;color:var(--grey);font-size:13px">No registrations found</div>`;
    return;
  }
  el.innerHTML = list.map(r => `
    <div style="background:#111;border:1px solid ${r.checked_in ? 'rgba(34,197,94,.2)' : 'var(--border-subtle)'};border-radius:8px;padding:12px 14px;display:flex;align-items:center;gap:12px">
      <div style="width:7px;height:7px;border-radius:50%;background:${r.checked_in ? '#22c55e' : '#333'};flex-shrink:0"></div>
      <div style="flex:1;min-width:0">
        <div style="font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.name}</div>
        <div style="font-size:11px;color:var(--grey);margin-top:2px">${r.email}${r.roll_no ? ' · ' + r.roll_no : ''}</div>
      </div>
      <div style="text-align:right;flex-shrink:0">
        ${r.checked_in
          ? `<div style="font-size:11px;color:#22c55e;font-weight:600">✓ ${r.checked_in_at ? new Date(r.checked_in_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : 'Present'}</div>`
          : `<div style="font-size:11px;color:var(--grey)">${r.created_at ? new Date(r.created_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : ''}</div>`
        }
        <button class="btn-sm danger" style="margin-top:4px;font-size:10px;padding:3px 8px" onclick="deleteRegFromModal(${r.id})">Remove</button>
      </div>
    </div>
  `).join('');
}

async function deleteRegFromModal(id) {
  if (!confirm('Remove this registration?')) return;
  // apiFetch returns null on error (and shows admin error banner automatically)
  const res = await apiFetch(`/api/admin/events/${_regEventId}/registrations/${id}`, 'DELETE');
  if (res === null) return; // apiFetch already showed the error
  if (typeof showToast === 'function') showToast('Registration removed', 'success');
  _regsList = _regsList.filter(r => r.id !== id);
  updateRegStats();
  renderModalRegs(_regsList);
}

async function downloadRegsExport(eventId) {
  try {
    const r = await fetch(`/api/admin/events/${eventId}/registrations/export`, {
      headers: { 'Authorization': `Bearer ${adminToken}`, 'x-csrf-token': _csrfToken || '' },
    });
    if (!r.ok) { showAdminError('Export failed'); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kfs-registrations-event-${eventId}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    showAdminError('Export failed');
  }
}

async function downloadRegsExportFromSection() {
  const sel = document.getElementById('scan-data-event-select');
  if (!sel || !sel.value) return;
  await downloadRegsExport(sel.value);
}

let _scanSectionRegs = [];
let _scanSectionEventId = null;

async function loadScanDataSection() {
  const sel = document.getElementById('scan-data-event-select');
  const content = document.getElementById('scan-data-content');
  const exportBtn = document.getElementById('scan-export-btn');
  if (!sel || !sel.value) return;
  _scanSectionEventId = sel.value;
  if (exportBtn) exportBtn.style.display = 'inline-flex';
  if (content) content.innerHTML = `<div style="text-align:center;padding:24px;color:var(--grey);font-size:13px">Loading…</div>`;

  const data = await apiFetch(`/api/admin/events/${_scanSectionEventId}/registrations`);
  _scanSectionRegs = data || [];
  if (!content) return;
  renderScanDataSection();
}

function renderScanDataSection() {
  const content = document.getElementById('scan-data-content');
  if (!content) return;
  const total   = _scanSectionRegs.length;
  const checked = _scanSectionRegs.filter(r => r.checked_in).length;
  const searchVal = document.getElementById('scan-search-input')?.value || '';

  if (!total) {
    content.innerHTML = `<div style="text-align:center;padding:32px;color:var(--grey);font-size:13px">No registrations yet for this event.</div>`;
    return;
  }

  const filtered = searchVal
    ? _scanSectionRegs.filter(r =>
        (r.name||'').toLowerCase().includes(searchVal.toLowerCase()) ||
        (r.email||'').toLowerCase().includes(searchVal.toLowerCase()) ||
        (r.roll_no||'').toLowerCase().includes(searchVal.toLowerCase())
      )
    : _scanSectionRegs;

  content.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
      <div style="background:#1a1a1a;border:1px solid var(--border-subtle);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800">${total}</div>
        <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Total</div>
      </div>
      <div style="background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#22c55e">${checked}</div>
        <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Present</div>
      </div>
      <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.15);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#f59e0b">${total - checked}</div>
        <div style="font-size:10px;color:var(--grey);text-transform:uppercase;letter-spacing:.07em;margin-top:2px">Pending</div>
      </div>
    </div>
    <input id="scan-search-input" type="text" placeholder="Search name, email, roll no…" value="${searchVal}"
      oninput="renderScanDataSection()"
      style="width:100%;background:#0d0d0d;border:1px solid var(--border-subtle);border-radius:8px;padding:10px 12px;font-size:13px;color:var(--text);outline:none;margin-bottom:12px">
    <div style="display:flex;flex-direction:column;gap:6px">
      ${filtered.length ? filtered.map(r => `
        <div style="background:#111;border:1px solid ${r.checked_in ? 'rgba(34,197,94,.2)' : 'var(--border-subtle)'};border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px">
          <div style="width:7px;height:7px;border-radius:50%;background:${r.checked_in ? '#22c55e' : '#333'};flex-shrink:0"></div>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.name}</div>
            <div style="font-size:11px;color:var(--grey);margin-top:1px">${r.email}${r.roll_no ? ' · ' + r.roll_no : ''}</div>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:11px;${r.checked_in ? 'color:#22c55e;font-weight:600' : 'color:var(--grey)'}">
              ${r.checked_in ? ('\u2713 ' + (r.checked_in_at ? new Date(r.checked_in_at).toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit' }) : 'Present')) : (r.created_at ? new Date(r.created_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' }) : 'Pending')}
            </div>
            <button class="btn-sm danger" style="margin-top:5px;font-size:10px;padding:3px 8px" onclick="deleteScanSectionReg(${r.id})">Remove</button>
          </div>
        </div>
      `).join('') : '<div style="text-align:center;padding:24px;color:var(--grey);font-size:13px">No matches</div>'}
    </div>
  `;
}

async function deleteScanSectionReg(id) {
  if (!confirm('Remove this registration?')) return;
  const res = await apiFetch(`/api/admin/events/${_scanSectionEventId}/registrations/${id}`, 'DELETE');
  if (res === null) return;
  if (typeof showToast === 'function') showToast('Registration removed', 'success');
  _scanSectionRegs = _scanSectionRegs.filter(r => r.id !== id);
  renderScanDataSection();
}

async function submitEventRegistration(eventId) {
  const btn = document.getElementById('reg-submit-btn');
  const errEl = document.getElementById('reg-form-error');
  const successEl = document.getElementById('reg-form-success');
  errEl.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'Registering…';

  const name    = document.getElementById('reg-name').value.trim();
  const email   = document.getElementById('reg-email').value.trim();
  const roll_no = document.getElementById('reg-rollno').value.trim();
  const phone   = document.getElementById('reg-phone').value.trim();

  if (!name || !email) {
    errEl.textContent = 'Name and email are required.';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Register & Get QR Ticket';
    return;
  }

  try {
    const r = await fetch(`/api/events/${eventId}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, roll_no, phone }),
    });
    const data = await r.json();
    if (!r.ok) {
      errEl.textContent = data.error || 'Registration failed.';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Register & Get QR Ticket';
    } else {
      document.getElementById('reg-form-fields').style.display = 'none';
      successEl.style.display = 'block';
    }
  } catch {
    errEl.textContent = 'Network error — please try again.';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Register & Get QR Ticket';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// END QR REGISTRATION SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// MEMBER PORTAL — Admin Functions
// ═══════════════════════════════════════════════════════════════════════════════

// ── Member Accounts ──────────────────────────────────────────────────────────

async function loadMemberAccounts() {
  const tbody = document.getElementById('admin-member-accounts-tbody');
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">Loading…</td></tr>`;
  const members = await apiFetch('/api/admin/members');
  if (!members || !members.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No members found.</td></tr>`;
    return;
  }
  // Fetch account status for each member in parallel
  const accounts = await Promise.all(
    members.map(m => apiFetch(`/api/admin/members/${m.id}/account`).catch(() => null))
  );
  tbody.innerHTML = members.map((m, i) => {
    const acc = accounts[i];
    const hasAccount = acc && acc.username;
    const status = hasAccount ? acc.account_status : '—';
    const statusTag = hasAccount
      ? `<span class="tag ${status === 'active' ? 'upcoming' : ''}">${status}</span>`
      : `<span style="color:var(--grey);font-size:12px">No account</span>`;
    const twoFA = hasAccount ? (acc.totp_enabled ? '✓' : '✗') : '—';
    const lastLogin = hasAccount && acc.last_login
      ? new Date(acc.last_login).toLocaleDateString('en-IN')
      : '—';
    const actionBtns = hasAccount
      ? `<div class="action-btns">
          <button class="btn-sm" onclick="toggleMemberAccountStatus('${m.id}','${acc.account_status}')">${acc.account_status === 'active' ? 'Disable' : 'Enable'}</button>
          <button class="btn-sm" onclick="resetMemberPassword('${m.id}')">Reset PW</button>
          <button class="btn-sm danger" onclick="forceMember2FAReset('${m.id}')">Clear 2FA</button>
        </div>`
      : `<div class="action-btns">
          <button class="btn-sm" style="background:rgba(99,102,241,.15);color:#818cf8;border-color:#4f46e533" onclick="openCreateMemberAccount('${m.id}','${m.name}')">Create Account</button>
        </div>`;
    return `<tr>
      <td style="font-weight:500">${m.name}</td>
      <td style="color:var(--grey);font-size:12px">${hasAccount ? acc.username : '—'}</td>
      <td>${statusTag}</td>
      <td style="text-align:center;color:${hasAccount && acc.totp_enabled ? '#4ade80' : '#f87171'}">${twoFA}</td>
      <td style="color:var(--grey);font-size:12px">${lastLogin}</td>
      <td>${actionBtns}</td>
    </tr>`;
  }).join('');
}

function openCreateMemberAccount(memberId, memberName) {
  showConfirmModal(
    `Create portal account for <strong>${memberName}</strong>?<br><br>A username and temporary password will be generated automatically.`,
    async () => {
      const res = await apiFetch(`/api/admin/members/${memberId}/create-account`, 'POST');
      if (!res) return;
      loadMemberAccounts();

      // Show account details and ask whether to send email
      const confirmed = await showConfirmModal(
        `Account created!<br><br>` +
        `<strong>Username:</strong> ${res.username}<br>` +
        `<strong>Temp Password:</strong> <code style="background:#1a1a1a;padding:2px 6px;border-radius:4px">${res.tempPassword}</code>` +
        `<br><br>Send credentials to member via email?`,
        null, null, 'Send Email', 'Skip'
      );
      if (!confirmed) return;

      // Ask for the email address to send to
      const prefill = res.email || '';
      const emailToSend = await new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:9999';
        overlay.innerHTML = `
          <div style="background:#111;border:1px solid #2a2a2a;border-radius:16px;padding:28px 32px;width:420px;max-width:90vw">
            <p style="margin:0 0 6px;font-size:15px;font-weight:600;color:#f0f0f0">Send credentials to</p>
            <p style="margin:0 0 18px;font-size:13px;color:#888">Enter the email address to send the login details to.</p>
            <input id="send-creds-email-input" type="email" placeholder="member@example.com"
              value="${prefill}"
              style="width:100%;box-sizing:border-box;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;padding:10px 12px;font-size:14px;color:#f0f0f0;outline:none;margin-bottom:16px">
            <div style="display:flex;gap:10px;justify-content:flex-end">
              <button id="send-creds-cancel" style="background:transparent;border:1px solid #2a2a2a;color:#888;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px">Cancel</button>
              <button id="send-creds-ok" style="background:#6366f1;border:none;color:#fff;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px;font-weight:500">Send</button>
            </div>
          </div>`;
        document.body.appendChild(overlay);
        const input = overlay.querySelector('#send-creds-email-input');
        const okBtn = overlay.querySelector('#send-creds-ok');
        const cancelBtn = overlay.querySelector('#send-creds-cancel');
        // Focus and select prefilled value
        setTimeout(() => { input.focus(); input.select(); }, 50);
        const done = (val) => { document.body.removeChild(overlay); resolve(val); };
        okBtn.onclick = () => { const v = input.value.trim(); if (v) done(v); else input.focus(); };
        cancelBtn.onclick = () => done(null);
        input.onkeydown = (e) => { if (e.key === 'Enter') okBtn.click(); if (e.key === 'Escape') cancelBtn.click(); };
      });

      if (!emailToSend) return;
      const sent = await apiFetch(`/api/admin/members/${memberId}/send-credentials`, 'POST', { toEmail: emailToSend, customPassword: res.tempPassword });
      if (sent) showToast(`Credentials sent to ${emailToSend}`);
    }
  );
}

async function sendTestCredentialsEmail() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:9999';
  overlay.innerHTML = `
    <div style="background:#111;border:1px solid #2a2a2a;border-radius:16px;padding:28px 32px;width:420px;max-width:90vw">
      <p style="margin:0 0 6px;font-size:15px;font-weight:600;color:#f0f0f0">Send Test Credentials Email</p>
      <p style="margin:0 0 18px;font-size:13px;color:#888">Sends a sample credentials email so you can verify your Brevo setup is working.</p>
      <input id="test-creds-email-input" type="email" placeholder="your@email.com"
        style="width:100%;box-sizing:border-box;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;padding:10px 12px;font-size:14px;color:#f0f0f0;outline:none;margin-bottom:16px">
      <div id="test-creds-msg" style="font-size:12px;margin-bottom:12px;min-height:16px"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="test-creds-cancel" style="background:transparent;border:1px solid #2a2a2a;color:#888;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px">Cancel</button>
        <button id="test-creds-send" style="background:#6366f1;border:none;color:#fff;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px;font-weight:500">Send Test</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const input   = overlay.querySelector('#test-creds-email-input');
  const sendBtn = overlay.querySelector('#test-creds-send');
  const cancelBtn = overlay.querySelector('#test-creds-cancel');
  const msgEl   = overlay.querySelector('#test-creds-msg');
  setTimeout(() => input.focus(), 50);
  const close = () => document.body.removeChild(overlay);
  cancelBtn.onclick = close;
  input.onkeydown = (e) => { if (e.key === 'Escape') close(); if (e.key === 'Enter') sendBtn.click(); };
  sendBtn.onclick = async () => {
    const email = input.value.trim();
    if (!email || !email.includes('@')) { input.focus(); return; }
    sendBtn.disabled = true; sendBtn.textContent = 'Sending…';
    msgEl.style.color = '#888'; msgEl.textContent = '';
    try {
      const res = await apiFetch('/api/admin/members/test-credentials-email', 'POST', { toEmail: email });
      if (res && res.success) {
        msgEl.style.color = '#4ade80'; msgEl.textContent = '✓ Test email sent! Check your inbox.';
        sendBtn.textContent = 'Sent ✓';
        setTimeout(close, 2500);
      } else {
        msgEl.style.color = '#f87171'; msgEl.textContent = res?.error || 'Failed to send';
        sendBtn.disabled = false; sendBtn.textContent = 'Send Test';
      }
    } catch (e) {
      msgEl.style.color = '#f87171'; msgEl.textContent = 'Error: ' + e.message;
      sendBtn.disabled = false; sendBtn.textContent = 'Send Test';
    }
  };
}

async function exportMemberData() {
  try {
    const r = await fetch('/api/admin/members/export', {
      headers: { 'Authorization': `Bearer ${adminToken}`, 'x-csrf-token': _csrfToken || '' },
    });
    if (!r.ok) { showAdminError('Export failed'); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const date = new Date().toISOString().slice(0, 10);
    a.download = `kfs-members-${date}.xlsx`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    showAdminError('Export failed');
  }
}

// ── Member Portal Modal (opened from Members list "Portal" button) ────────────

async function openMemberPortalModal(member) {
  // Build overlay immediately with a loading state
  const existing = document.getElementById('kfs-member-portal-modal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'kfs-member-portal-modal';
  overlay.style.cssText = `
    position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(6px);
    display:flex;align-items:center;justify-content:center;z-index:9999;
    padding:24px;animation:kfsMFadeIn .18s ease`;
  overlay.innerHTML = `
    <style>
      @keyframes kfsMFadeIn{from{opacity:0;transform:scale(.97)}to{opacity:1;transform:scale(1)}}
      #kfs-member-portal-modal .mpm-card{
        background:#111;border:1px solid #1e1e1e;border-radius:20px;
        width:100%;max-width:560px;max-height:90vh;overflow-y:auto;
        box-shadow:0 32px 80px rgba(0,0,0,.6);
      }
      #kfs-member-portal-modal .mpm-header{
        display:flex;align-items:center;gap:16px;
        padding:28px 28px 20px;border-bottom:1px solid #1a1a1a;
      }
      #kfs-member-portal-modal .mpm-avatar{
        width:56px;height:56px;border-radius:50%;object-fit:cover;
        background:#1e1e1e;flex-shrink:0;display:flex;align-items:center;
        justify-content:center;font-size:22px;font-weight:700;color:#888;overflow:hidden;
      }
      #kfs-member-portal-modal .mpm-avatar img{width:100%;height:100%;object-fit:cover}
      #kfs-member-portal-modal .mpm-name{font-size:18px;font-weight:700;letter-spacing:-.02em;color:#f5f5f5}
      #kfs-member-portal-modal .mpm-role-badge{
        display:inline-block;margin-top:4px;padding:3px 10px;border-radius:20px;
        font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
        background:rgba(99,102,241,.15);color:#818cf8;border:1px solid rgba(99,102,241,.3)
      }
      #kfs-member-portal-modal .mpm-close{
        margin-left:auto;background:transparent;border:none;color:#666;
        font-size:22px;cursor:pointer;padding:4px 8px;border-radius:8px;transition:color .12s;line-height:1
      }
      #kfs-member-portal-modal .mpm-close:hover{color:#f5f5f5}
      #kfs-member-portal-modal .mpm-body{padding:24px 28px}
      #kfs-member-portal-modal .mpm-section-label{
        font-size:11px;font-weight:700;color:#555;text-transform:uppercase;
        letter-spacing:.08em;margin:20px 0 10px
      }
      #kfs-member-portal-modal .mpm-section-label:first-child{margin-top:0}
      #kfs-member-portal-modal .mpm-field{margin-bottom:14px}
      #kfs-member-portal-modal .mpm-field label{
        display:block;font-size:11px;color:#666;text-transform:uppercase;
        letter-spacing:.07em;margin-bottom:5px
      }
      #kfs-member-portal-modal .mpm-field input,
      #kfs-member-portal-modal .mpm-field select,
      #kfs-member-portal-modal .mpm-field textarea{
        width:100%;background:#0d0d0d;border:1px solid #222;border-radius:10px;
        color:#f5f5f5;font-size:14px;padding:10px 13px;outline:none;
        transition:border-color .15s;font-family:inherit;resize:none;box-sizing:border-box
      }
      #kfs-member-portal-modal .mpm-field input:focus,
      #kfs-member-portal-modal .mpm-field select:focus,
      #kfs-member-portal-modal .mpm-field textarea:focus{border-color:#3a3a3a}
      #kfs-member-portal-modal .mpm-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      #kfs-member-portal-modal .mpm-account-row{
        display:flex;align-items:center;justify-content:space-between;
        background:#0d0d0d;border:1px solid #1a1a1a;border-radius:12px;
        padding:14px 16px;margin-bottom:10px
      }
      #kfs-member-portal-modal .mpm-account-label{font-size:13px;color:#f0f0f0;font-weight:500}
      #kfs-member-portal-modal .mpm-account-sub{font-size:11px;color:#555;margin-top:2px}
      #kfs-member-portal-modal .mpm-toggle{
        position:relative;width:44px;height:26px;cursor:pointer;flex-shrink:0
      }
      #kfs-member-portal-modal .mpm-toggle input{opacity:0;position:absolute;width:0;height:0}
      #kfs-member-portal-modal .mpm-toggle-track{
        position:absolute;inset:0;background:#2a2a2a;border-radius:13px;
        transition:background .2s;border:1px solid #333
      }
      #kfs-member-portal-modal .mpm-toggle input:checked+.mpm-toggle-track{background:#6366f1;border-color:#6366f1}
      #kfs-member-portal-modal .mpm-toggle-thumb{
        position:absolute;top:3px;left:3px;width:18px;height:18px;
        background:#fff;border-radius:50%;transition:transform .2s;
        box-shadow:0 1px 3px rgba(0,0,0,.4)
      }
      #kfs-member-portal-modal .mpm-toggle input:checked~.mpm-toggle-thumb{transform:translateX(18px)}
      #kfs-member-portal-modal .mpm-actions{
        display:flex;gap:10px;padding:20px 28px 24px;
        border-top:1px solid #1a1a1a;margin-top:4px
      }
      #kfs-member-portal-modal .mpm-btn-save{
        flex:1;background:#f5f5f5;color:#0a0a0a;border:none;
        border-radius:10px;padding:11px 18px;font-size:14px;
        font-weight:700;cursor:pointer;transition:opacity .15s;font-family:inherit
      }
      #kfs-member-portal-modal .mpm-btn-save:hover{opacity:.85}
      #kfs-member-portal-modal .mpm-btn-save:disabled{opacity:.4;cursor:default}
      #kfs-member-portal-modal .mpm-btn-secondary{
        background:transparent;border:1px solid #222;color:#888;
        border-radius:10px;padding:11px 18px;font-size:14px;
        font-weight:600;cursor:pointer;transition:all .15s;font-family:inherit
      }
      #kfs-member-portal-modal .mpm-btn-secondary:hover{border-color:#444;color:#f5f5f5}
      #kfs-member-portal-modal .mpm-status-tag{
        display:inline-flex;align-items:center;gap:6px;
        padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;
        text-transform:uppercase;letter-spacing:.06em
      }
      #kfs-member-portal-modal .mpm-status-active{background:#0d1f0d;color:#22c55e;border:1px solid #1a3a1a}
      #kfs-member-portal-modal .mpm-status-disabled{background:#1f1010;color:#ef4444;border:1px solid #3a1a1a}
      #kfs-member-portal-modal .mpm-status-none{background:#1a1a1a;color:#888;border:1px solid #2a2a2a}
      #kfs-member-portal-modal .mpm-msg{
        font-size:13px;padding:10px 14px;border-radius:8px;margin-top:12px;display:none
      }
      #kfs-member-portal-modal .mpm-msg.ok{background:#0d1f0d;color:#4ade80;border:1px solid #1a3a1a}
      #kfs-member-portal-modal .mpm-msg.err{background:#1f0d0d;color:#ef4444;border:1px solid #3a1a1a}
      #kfs-member-portal-modal .spinner-sm{
        display:inline-block;width:16px;height:16px;border:2px solid #333;
        border-top-color:#888;border-radius:50%;animation:kfsSpin .7s linear infinite;vertical-align:middle;margin-right:6px
      }
      @keyframes kfsSpin{to{transform:rotate(360deg)}}
    </style>
    <div class="mpm-card">
      <div id="mpm-inner"><div style="padding:60px;text-align:center;color:#444"><span class="spinner-sm"></span> Loading…</div></div>
    </div>`;

  overlay.addEventListener('click', e => { if (e.target === overlay) closeMemberPortalModal(); });
  document.addEventListener('keydown', _mpmEscListener = e => { if (e.key === 'Escape') closeMemberPortalModal(); });
  document.body.appendChild(overlay);

  // Fetch account data only — member data passed in directly
  let account = null;
  const memberId = member.id;
  try {
    account = await apiFetch(`/api/admin/members/${memberId}/account`);
  } catch(e) {}

  const hasAccount = account && account.username;
  const accStatus  = hasAccount ? account.account_status : null;
  const avatarEl   = member.photo
    ? `<div class="mpm-avatar"><img src="${member.photo}" alt="" /></div>`
    : `<div class="mpm-avatar">${(member.name||'?')[0].toUpperCase()}</div>`;

  const statusBadge = !hasAccount
    ? `<span class="mpm-status-tag mpm-status-none">No Account</span>`
    : accStatus === 'active'
      ? `<span class="mpm-status-tag mpm-status-active">● Active</span>`
      : `<span class="mpm-status-tag mpm-status-disabled">● Disabled</span>`;

  const roleOptions = ['President','Vice President','Core','Lead','Member','Advisor','Collaborator'].map(r =>
    `<option value="${r}" ${member.role===r?'selected':''}>${r}</option>`).join('');

  document.getElementById('mpm-inner').innerHTML = `
    <div class="mpm-header">
      ${avatarEl}
      <div>
        <div class="mpm-name">${member.name}</div>
        <div style="margin-top:6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span class="mpm-role-badge">${member.role||'Member'}</span>
          ${statusBadge}
        </div>
      </div>
      <button class="mpm-close" onclick="closeMemberPortalModal()">×</button>
    </div>
    <div class="mpm-body">

      <div class="mpm-section-label">Profile Info</div>
      <div class="mpm-grid">
        <div class="mpm-field">
          <label>Full Name</label>
          <input id="mpm-name" type="text" value="${(member.name||'').replace(/"/g,'&quot;')}" />
        </div>
        <div class="mpm-field">
          <label>Role</label>
          <select id="mpm-role">${roleOptions}</select>
        </div>
        <div class="mpm-field">
          <label>Batch</label>
          <input id="mpm-batch" type="text" value="${(member.batch||'').replace(/"/g,'&quot;')}" placeholder="e.g. 2024–28" />
        </div>
        <div class="mpm-field">
          <label>Domain</label>
          <input id="mpm-domain" type="text" value="${(member.domain||'').replace(/"/g,'&quot;')}" placeholder="e.g. Direction" />
        </div>
      </div>
      <div class="mpm-field">
        <label>Bio</label>
        <textarea id="mpm-bio" rows="3">${(member.bio||'').replace(/</g,'&lt;')}</textarea>
      </div>
      <div class="mpm-field">
        <label>Special Tag</label>
        <input id="mpm-special-tag" type="text" value="${(member.special_tag||'').replace(/"/g,'&quot;')}" placeholder="e.g. Founder" />
      </div>

      <div class="mpm-section-label">Portal Account</div>

      ${hasAccount ? `
      <div class="mpm-account-row">
        <div>
          <div class="mpm-account-label">Portal Access</div>
          <div class="mpm-account-sub">Username: <strong style="color:#ccc">${account.username}</strong> · 2FA: ${account.totp_enabled ? '<span style="color:#4ade80">On</span>' : '<span style="color:#f87171">Off</span>'}</div>
        </div>
        <label class="mpm-toggle" title="${accStatus==='active'?'Disable portal access':'Enable portal access'}">
          <input type="checkbox" id="mpm-portal-toggle" ${accStatus==='active'?'checked':''} />
          <div class="mpm-toggle-track"></div>
          <div class="mpm-toggle-thumb"></div>
        </label>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="mpm-btn-secondary" style="font-size:12px;padding:8px 14px" onclick="mpmResetPassword('${memberId}')">Reset Password</button>
        <button class="mpm-btn-secondary" style="font-size:12px;padding:8px 14px;color:#f87171;border-color:rgba(239,68,68,.3)" onclick="mpmClear2FA('${memberId}')">Clear 2FA</button>
      </div>` : `
      <div class="mpm-account-row">
        <div>
          <div class="mpm-account-label">No portal account yet</div>
          <div class="mpm-account-sub">Create one to give this member portal access</div>
        </div>
        <button class="mpm-btn-secondary" style="font-size:12px;padding:8px 16px;background:rgba(99,102,241,.12);border-color:rgba(99,102,241,.3);color:#818cf8" onclick="mpmCreateAccount('${memberId}','${(member.name||'').replace(/'/g,"\\'")}')">Create Account</button>
      </div>`}

      <div id="mpm-msg" class="mpm-msg"></div>
    </div>
    <div class="mpm-actions">
      <button class="mpm-btn-secondary" onclick="closeMemberPortalModal()">Cancel</button>
      <button class="mpm-btn-save" id="mpm-save-btn" onclick="mpmSave('${memberId}')">Save Changes</button>
    </div>`;

  // Wire portal toggle change
  const toggle = document.getElementById('mpm-portal-toggle');
  if (toggle) {
    toggle.addEventListener('change', async () => {
      toggle.disabled = true;
      try {
        await apiFetch(`/api/admin/members/${memberId}/account/toggle-status`, 'POST');
        // Update status badge
        const newStatus = toggle.checked ? 'active' : 'disabled';
        const badgeEl = overlay.querySelector('.mpm-status-tag');
        if (badgeEl) {
          badgeEl.className = `mpm-status-tag ${toggle.checked ? 'mpm-status-active' : 'mpm-status-disabled'}`;
          badgeEl.textContent = toggle.checked ? '● Active' : '● Disabled';
        }
        mpmShowMsg('Portal access ' + (toggle.checked ? 'enabled' : 'disabled'), true);
        loadMemberAccounts(); // refresh accounts table in background
      } catch(e) {
        toggle.checked = !toggle.checked; // revert
        mpmShowMsg(e.message || 'Failed to toggle access', false);
      } finally { toggle.disabled = false; }
    });
  }
}

let _mpmEscListener = null;

function closeMemberPortalModal() {
  const el = document.getElementById('kfs-member-portal-modal');
  if (el) { el.style.opacity='0'; el.style.transform='scale(.97)'; el.style.transition='all .15s'; setTimeout(()=>el.remove(),150); }
  if (_mpmEscListener) { document.removeEventListener('keydown', _mpmEscListener); _mpmEscListener = null; }
}

function mpmShowMsg(msg, ok) {
  const el = document.getElementById('mpm-msg');
  if (!el) return;
  el.textContent = msg;
  el.className = 'mpm-msg ' + (ok ? 'ok' : 'err');
  el.style.display = 'block';
  if (ok) setTimeout(() => { el.style.display = 'none'; }, 3500);
}

async function mpmSave(memberId) {
  const btn = document.getElementById('mpm-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  const fd = new FormData();
  fd.append('name',        document.getElementById('mpm-name')?.value || '');
  fd.append('role',        document.getElementById('mpm-role')?.value || '');
  fd.append('batch',       document.getElementById('mpm-batch')?.value || '');
  fd.append('domain',      document.getElementById('mpm-domain')?.value || '');
  fd.append('bio',         document.getElementById('mpm-bio')?.value || '');
  fd.append('special_tag', document.getElementById('mpm-special-tag')?.value || '');
  try {
    const res = await fetch(`/api/admin/members/${memberId}`, {
      method: 'PUT', credentials: 'include',
      headers: { 'Authorization': 'Bearer ' + adminToken, 'X-CSRF-Token': _csrfToken || '' },
      body: fd,
    });
    if (!res.ok) { const e = await res.json().catch(()=>{}); throw new Error(e?.error || 'Save failed'); }
    const saved = await res.json();
    mpmShowMsg('Changes saved successfully', true);
    // Update cache + re-render with filters
    if (window._allAdminMembers) {
      const idx = window._allAdminMembers.findIndex(m => m.id === memberId);
      if (idx >= 0) window._allAdminMembers[idx] = { ...window._allAdminMembers[idx], ...saved };
      filterAdminMembers();
    }
    // Signal member portal to refresh
    localStorage.setItem('kfs_admin_data_change', Date.now().toString());
  } catch(e) {
    mpmShowMsg(e.message, false);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Changes'; }
  }
}

async function mpmResetPassword(memberId) {
  if (!await kfsConfirm({ title: 'Reset Password?', msg: 'Member will need to set a new password on next login.', okLabel: 'Reset' })) return;
  try {
    await apiFetch(`/api/admin/members/${memberId}/account/reset-password`, 'POST');
    mpmShowMsg('Password reset — member must change on next login', true);
  } catch(e) { mpmShowMsg(e.message, false); }
}

async function mpmClear2FA(memberId) {
  if (!await kfsConfirm({ title: 'Clear 2FA?', msg: 'Member will need to set up 2FA again on next login.', okLabel: 'Clear 2FA' })) return;
  try {
    await apiFetch(`/api/admin/members/${memberId}/account/force-2fa-reset`, 'POST');
    mpmShowMsg('2FA cleared', true);
    loadMemberAccounts();
  } catch(e) { mpmShowMsg(e.message, false); }
}

async function mpmCreateAccount(memberId, memberName) {
  const res = await apiFetch(`/api/admin/members/${memberId}/create-account`, 'POST');
  if (!res) return;
  closeMemberPortalModal();
  loadMemberAccounts();
  openCreateMemberAccount(memberId, memberName);
}

async function toggleMemberAccountStatus(memberId, currentStatus) {
  const action = currentStatus === 'active' ? 'Disable' : 'Enable';
  const isDanger = currentStatus === 'active';
  const confirmed = await showConfirmModal(
    `${action} this member's portal account?`,
    null, null, action, 'Cancel', isDanger ? 'danger' : 'accent'
  );
  if (!confirmed) return;
  const result = await apiFetch(`/api/admin/members/${memberId}/account/toggle-status`, 'POST');
  if (result !== null) { loadMemberAccounts(); localStorage.setItem('kfs_admin_data_change', Date.now().toString()); }
}

async function resetMemberPassword(memberId) {
  showConfirmModal('Force a password reset for this member? They will be required to set a new password on next login.', async () => {
    const res = await apiFetch(`/api/admin/members/${memberId}/account/reset-password`, 'POST');
    if (res) showToast('Password reset — member must change password on next login');
    loadMemberAccounts();
  });
}

async function forceMember2FAReset(memberId) {
  showConfirmModal('Clear 2FA for this member? They will be required to set up 2FA again on next login.', async () => {
    await apiFetch(`/api/admin/members/${memberId}/account/force-2fa-reset`, 'POST');
    showToast('2FA cleared');
    loadMemberAccounts();
  });
}

// ── Profile Changes ──────────────────────────────────────────────────────────

async function loadMemberProfileChanges(status = 'pending') {
  const tbody = document.getElementById('admin-member-profile-changes-tbody');
  tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">Loading…</td></tr>`;

  // Update filter button styles
  ['pending','approved','rejected'].forEach(s => {
    const btn = document.getElementById(`mp-filter-${s}`);
    if (!btn) return;
    if (s === status) {
      btn.className = 'btn btn-primary';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px';
    } else {
      btn.className = 'btn';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)';
    }
  });

  const data = await apiFetch(`/api/admin/member-profile-changes?status=${status}`);
  if (!data || !data.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">No ${status} profile changes.</td></tr>`;
    return;
  }
  tbody.innerHTML = data.map(r => {
    const changes = r.new_values ? Object.keys(r.new_values).join(', ') : '—';
    const date = new Date(r.created_at).toLocaleDateString('en-IN');
    const actions = status === 'pending'
      ? `<div class="action-btns">
          <button class="btn-sm" style="background:rgba(74,222,128,.1);color:#4ade80;border-color:#4ade8033" onclick="reviewMemberProfileChange(${r.id},'approved')">Approve</button>
          <button class="btn-sm" onclick="reviewMemberProfileChange(${r.id},'changes_requested')">Request Changes</button>
          <button class="btn-sm danger" onclick="reviewMemberProfileChange(${r.id},'rejected')">Reject</button>
        </div>`
      : `<span style="font-size:12px;color:var(--grey)">${r.reviewed_by || '—'}</span>`;
    return `<tr>
      <td style="font-weight:500">${r.members?.name || r.member_id}</td>
      <td style="color:var(--grey);font-size:12px">${date}</td>
      <td style="font-size:12px;color:var(--grey)">${changes}</td>
      <td><span class="tag ${r.status === 'approved' ? 'upcoming' : ''}">${r.status}</span></td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
}

async function reviewMemberProfileChange(changeId, decision) {
  let notes = '';
  if (decision === 'rejected' || decision === 'changes_requested') {
    notes = prompt(decision === 'rejected' ? 'Reason for rejection (optional):' : 'What changes are needed?') || '';
  }
  const actionMap = { approved: 'approve', rejected: 'reject', changes_requested: 'request_changes' };
  const action = actionMap[decision] || decision;
  await apiFetch(`/api/admin/member-profile-changes/${changeId}/review`, 'POST', { action, notes });
  loadMemberProfileChanges('pending');
}

// ── Movie Submissions ────────────────────────────────────────────────────────

async function loadMemberMovieSubmissions(status = 'pending') {
  const tbody = document.getElementById('admin-member-movie-submissions-tbody');
  tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">Loading…</td></tr>`;

  // Update filter button styles
  ['pending','approved','rejected'].forEach(s => {
    const btn = document.getElementById(`ms-filter-${s}`);
    if (!btn) return;
    if (s === status) {
      btn.className = 'btn btn-primary';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px';
    } else {
      btn.className = 'btn';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)';
    }
  });

  const data = await apiFetch(`/api/admin/member-movie-submissions?status=${status}`);
  if (!data || !data.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--grey)">No ${status} movie submissions.</td></tr>`;
    return;
  }
  tbody.innerHTML = data.map(r => {
    const title = r.movie_data?.title || '—';
    const date = new Date(r.created_at).toLocaleDateString('en-IN');
    const actions = status === 'pending'
      ? `<div class="action-btns">
          <button class="btn-sm" style="background:rgba(74,222,128,.1);color:#4ade80;border-color:#4ade8033" onclick="reviewMemberMovieSubmission(${r.id},'approved')">Approve</button>
          <button class="btn-sm" onclick="reviewMemberMovieSubmission(${r.id},'changes_requested')">Request Changes</button>
          <button class="btn-sm danger" onclick="reviewMemberMovieSubmission(${r.id},'rejected')">Reject</button>
        </div>`
      : status === 'approved' && r.published_movie_id
      ? `<div class="action-btns"><button class="btn-sm" onclick="showAdminSection('movies');setTimeout(()=>{const row=document.querySelector('#admin-movies-tbody tr[data-id=\\'${r.published_movie_id}\\']');if(row){row.scrollIntoView({behavior:'smooth',block:'center'});row.style.outline='2px solid #4ade80';setTimeout(()=>row.style.outline='',2000);}},400)">Edit in Films →</button></div>`
      : `<span style="font-size:12px;color:var(--grey)">${r.reviewed_by || '—'}</span>`;
    return `<tr>
      <td style="font-weight:500">${r.members?.name || r.member_id}</td>
      <td style="font-weight:500">${title}</td>
      <td style="color:var(--grey);font-size:12px">${date}</td>
      <td><span class="tag ${r.status === 'approved' ? 'upcoming' : ''}">${r.status}</span></td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
}

async function reviewMemberMovieSubmission(submissionId, decision) {
  let notes = '';
  if (decision === 'rejected' || decision === 'changes_requested') {
    notes = prompt(decision === 'rejected' ? 'Reason for rejection (optional):' : 'What changes are needed?') || '';
  }
  const actionMap = { approved: 'approve', rejected: 'reject', changes_requested: 'request_changes' };
  const action = actionMap[decision] || decision;
  const result = await apiFetch(`/api/admin/member-movie-submissions/${submissionId}/review`, 'POST', { action, notes });
  localStorage.setItem('kfs_admin_data_change', Date.now().toString()); // signal portal
  loadMemberMovieSubmissions('pending');
  // If approved, navigate to Films section and highlight the new film row
  if (action === 'approve') {
    const publishedId = result?.publishedMovieId;
    showAdminSection('movies');
    await loadAdminData('movies');
    if (publishedId) {
      setTimeout(() => {
        const row = document.querySelector(`#admin-movies-tbody tr[data-id="${publishedId}"]`);
        if (row) {
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          row.style.outline = '2px solid #4ade80';
          row.style.background = 'rgba(74,222,128,0.06)';
          setTimeout(() => { row.style.outline = ''; row.style.background = ''; }, 3000);
        }
      }, 300);
    }
  }
}

// ── Work Edit Requests ────────────────────────────────────────────────────────

async function loadWorkEditRequests(status = 'pending') {
  const tbody = document.getElementById('admin-work-edit-requests-tbody');
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">Loading…</td></tr>`;

  ['pending','approved','rejected'].forEach(s => {
    const btn = document.getElementById(`wer-filter-${s}`);
    if (!btn) return;
    if (s === status) {
      btn.className = 'btn btn-primary';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px';
    } else {
      btn.className = 'btn';
      btn.style.cssText = 'font-size:12px;padding:8px 16px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)';
    }
  });

  const data = await apiFetch(`/api/admin/work-edit-requests?status=${status}`);
  if (!data || !data.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--grey)">No ${status} work edit requests.</td></tr>`;
    return;
  }
  tbody.innerHTML = data.map(r => {
    const date = new Date(r.created_at).toLocaleDateString('en-IN');
    const desc = r.description ? (r.description.length > 80 ? r.description.slice(0,80)+'…' : r.description) : '—';
    const actions = status === 'pending'
      ? `<div class="action-btns">
          <button class="btn-sm" style="background:rgba(74,222,128,.1);color:#4ade80;border-color:#4ade8033" onclick="reviewWorkEditRequest(${r.id},'approve')">Approve</button>
          <button class="btn-sm danger" onclick="reviewWorkEditRequest(${r.id},'reject')">Reject</button>
        </div>`
      : `<span style="font-size:12px;color:var(--grey)">${r.reviewed_by || '—'}</span>`;
    return `<tr>
      <td style="font-weight:500">${r.members?.name || r.member_id}</td>
      <td style="font-size:13px">${r.movie_title || r.movie_id}</td>
      <td style="font-size:12px;color:var(--grey);max-width:220px">${desc}</td>
      <td style="color:var(--grey);font-size:12px">${date}</td>
      <td><span class="tag ${r.status === 'approved' ? 'upcoming' : ''}">${r.status}</span></td>
      <td>${actions}</td>
    </tr>`;
  }).join('');
}

async function reviewWorkEditRequest(requestId, action) {
  let notes = '';
  if (action === 'reject') notes = prompt('Reason for rejection (optional):') || '';
  await apiFetch(`/api/admin/work-edit-requests/${requestId}/review`, 'POST', { action, notes });
  loadWorkEditRequests('pending');
}

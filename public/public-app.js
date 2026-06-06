// app.js — KFS Frontend (extracted from inline scripts)
// Blocks: theme-applier, main-app, search, member-import, form-builder, collab, donations

// ── CSRF token (fetched once on load) ─────────────────────────────────────────
let _csrfToken = '';
(async function fetchCsrf() {
  try {
    const r = await fetch('/api/csrf-token');
    if (r.ok) { const d = await r.json(); _csrfToken = d.csrf_token || d.token || ''; }
  } catch(e) {}
})();

// ── apiFetch — central fetch wrapper used by all public data loaders ──────────
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (!res.ok) return null;
    return await res.json();
  } catch(e) {
    console.error('[apiFetch] Error fetching', url, e);
    return null;
  }
}

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
  hideScrollProgress();
  if (page === 'admin') {
    // P1: Admin panel is now a separate auth-gated page — redirect the browser there.
    // The inline admin HTML no longer exists in this bundle.
    window.location.href = '/admin';
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
        <div class="achievement-icon">${a.image ? `<img src="${a.image}" alt="" style="width:56px;height:56px;object-fit:cover;border-radius:8px">` : (a.icon||'🏆')}<\/div>
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
      const badge = isViewed ? `<span class="hc-read-badge">✓ Viewed<\/span>` : `<span class="hc-read-badge">New<\/span>`;
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
    if (hcBadge) hcBadge.textContent = '✓ Viewed';
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
        ${watched ? '✓ Watched' : '+ Watchlist'}
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

// ── ROUTE CHECK — reads URL on first load and navigates to the right page ─────
function checkRoute() {
  const raw = window.location.pathname.replace(/^\//, '') || 'home';

  // Films deep link: /films/some-title-123
  const filmMatch = raw.match(/^films\/[^/]+-(\d+)$/);
  if (filmMatch) { openMovie(filmMatch[1]); return; }

  // Blog deep link: /blog/some-title-123
  const blogMatch = raw.match(/^blog\/[^/]+-(\d+)$/);
  if (blogMatch) { openBlog(blogMatch[1]); return; }

  // Named pages
  const knownPages = [
    'home','events','blog','movies','members',
    'wrapped','collaborate','donations','about','team'
  ];
  const page = knownPages.includes(raw) ? raw : 'home';
  _doNavigate(page, false);
}

// ── APP BOOTSTRAP ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  document.body.classList.add('loaded');
  checkRoute();
});

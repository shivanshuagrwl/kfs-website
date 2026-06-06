// app.js — KFS Frontend
// ── CSRF token ────────────────────────────────────────────────────────────────
let _csrfToken = '';
(async function fetchCsrf() {
  try {
    const r = await fetch('/api/csrf-token');
    if (r.ok) { const d = await r.json(); _csrfToken = d.csrf_token || d.token || ''; }
  } catch(e) {}
})();

// ── apiFetch ──────────────────────────────────────────────────────────────────
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
// ── ALL PUBLIC FUNCTIONS (extracted from admin.js) ───────────────────────────

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
    const fallback = window._eggNoShortsFallback || "that's the spirit 🎬";
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

function splitCrew(val) {
  // Support both new separator (;;) and legacy comma-separated data
  if (!val) return [];
  return val.includes(';;') ? val.split(';;').map(s=>s.trim()).filter(Boolean)
                             : val.split(',').map(s=>s.trim()).filter(Boolean);
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

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
}

function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function openMemberProfile(member) {
  window._currentProfileMember = member;  // store for passport download
  const modal = document.getElementById('member-profile-modal');
  document.getElementById('mprofile-name').textContent = member.name;
  document.getElementById('mprofile-role').textContent = [member.role, member.domain].filter(Boolean).join(' · ');
  document.getElementById('mprofile-batch').textContent = member.batch ? 'Batch of '+member.batch : '';
  document.getElementById('mprofile-bio').textContent = member.bio || '';
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

function openMemberProfileById(uuid) {
  const allMembers = window._memberRegistry || [];
  const member = allMembers.find(m => String(m.id) === String(uuid));
  if (member) openMemberProfile(member);
}

function getWatchedMovies() {
  try { return JSON.parse(localStorage.getItem('kfs_watched_movies') || '{}'); } catch { return {}; }
}

function setMovieWatched(id, val) {
  const w = getWatchedMovies();
  if (val) w[id] = Date.now(); else delete w[id];
  localStorage.setItem('kfs_watched_movies', JSON.stringify(w));
}

function isMovieWatched(id) { return !!getWatchedMovies()[id]; }

function updateDetailWatchBtn(id) {
  const btn = document.getElementById('movie-watch-status-btn');
  if (!btn) return;
  const watched = isMovieWatched(id);
  btn.innerHTML = watched
    ? '<span>✓<\/span> Watched'
    : '<span>☐<\/span> Mark as Watched';
  btn.classList.toggle('is-watched', watched);
  btn.style.cssText = ''; // clear any previously set inline styles
}

function toggleWatchStatusCard(id, cardEl) {
  const nowWatched = !isMovieWatched(id);
  setMovieWatched(id, nowWatched);
  const badge = cardEl.querySelector('.movie-watch-badge');
  if (badge) {
    badge.textContent = nowWatched ? '✓ Watched' : '+ Watchlist';
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
    badge.textContent = nowWatched ? '✓ Watched' : '+ Watchlist';
    badge.classList.toggle('movie-watch-badge--done', nowWatched);
    card.classList.toggle('watched', nowWatched);
  });
}

function svgFilm(size=18){return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>';}

function svgPerson(size=16){return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><\/svg>';}

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

function openEventFormById(eventId) {
  const e = (window._eventRegistry || {})[eventId];
  if (!e) return;
  openEventForm(e.id, e.title, e.event_date || '', e.event_time || '', e.location || '');
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

    const res = await fetch('/api/events/' + _rfEventId + '/form/submit', { method: 'POST', body: fd });

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

function shareEventById(eventId) {
  const e = (window._eventRegistry || {})[eventId];
  if (!e) return;
  const dateStr = e.event_date
    ? new Date(e.event_date).toLocaleDateString('en-IN', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
    : '';
  shareEventCard(e.id, e.title, dateStr, e.venue || e.location || '');
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
      ? `<span onclick="openMemberProfileById('${memberUuid}')" style="color:var(--accent);cursor:pointer;text-decoration:underline;text-underline-offset:3px">✓ KFS Member</span>`
      : `<span style="color:var(--accent)">✓ KFS Member</span>`;

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
    // New post — show gate
    document.getElementById('collab-gate').style.display = 'block';
    document.getElementById('collab-form-body').style.display = 'none';
    document.getElementById('collab-gate-error').style.display = 'none';
    document.getElementById('collab-kiit-email').value = '';
    document.getElementById('collab-gate-btn').disabled = false;
    document.getElementById('collab-gate-btn').textContent = 'Verify & Continue';

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
  // Validate member picker — must select an existing KFS member
  if (!token && window._collabNamePicker && !window._collabNamePicker.isValid()) {
    document.getElementById('collab-error').textContent = 'Please select your name from the KFS members list.';
    return;
  }
  let res, data;
  try {
    res = await fetch(token ? '/api/collaborate/' + token : '/api/collaborate', {
      method: token ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken || '' },
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
    await fetch('/api/collaborate/' + token, { method: 'DELETE', headers: { 'X-CSRF-Token': _csrfToken || '' } });
  } catch(e) {}
  closeCollabForm();
  loadCollaborate();
}

// ── ADMIN: Collaboration Board ─────────────────────────────────────────────────

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

function revealSpoiler(id) {
  const el = document.getElementById('fc-body-' + id);
  if (el) el.classList.remove('is-blurred');
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
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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

function loadMoreComments() {
  _fcShowing += FC_PAGE;
  renderFilmComments();
}

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
      method: 'POST',
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
      banner.textContent = '⚠️ TEST MODE — No real money will be charged. Use Razorpay test card: 4111 1111 1111 1111';
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
            method: 'POST',
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

  const donorIdSafe = escHtml(String(d.id || ''));

  return `<div class="don-donor-card" data-donor-id="${donorIdSafe}" style="position:relative">
    ${photoHtml}
    ${nameHtml}
    ${rollHtml}
    <div class="don-donor-meta">${semester}</div>
    ${bioHtml}
    ${amtHtml}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
// EVENT DELEGATION — replaces all inline onclick=/onchange=/oninput=/onkeydown=

// EVENT DELEGATION — replaces all inline onclick=/onchange=/oninput=/onkeydown=
// One listener per event type on document handles every data-action element.
// ══════════════════════════════════════════════════════════════════════════════

// ── Helper stubs for elements that used complex inline expressions ────────────

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


// ── filterMoviesByGenre — called from genre tags on movie detail page ─────────
function filterMoviesByGenre(genre) {
  window._activeGenreFilter = genre;
  document.querySelectorAll('.blog-filter-item[id^="mgfi-"]').forEach(b => {
    b.classList.toggle('active', b.id === 'mgfi-' + (genre ? genre.replace(/\s+/g, '-') : 'all'));
  });
  if (typeof renderMoviesGrid === 'function' && window._allMovies) {
    renderMoviesGrid(window._allMovies);
  }
}

// ── ROUTE CHECK ───────────────────────────────────────────────────────────────
function checkRoute() {
  const raw = window.location.pathname.replace(/^\//, '') || 'home';
  const filmMatch = raw.match(/^films\/[^/]+-(\d+)$/);
  if (filmMatch) { openMovie(filmMatch[1]); return; }
  const blogMatch = raw.match(/^blog\/[^/]+-(\d+)$/);
  if (blogMatch) { openBlog(blogMatch[1]); return; }
  const knownPages = ['home','events','blog','movies','members','wrapped','collaborate','donations','about','team'];
  const page = knownPages.includes(raw) ? raw : 'home';
  _doNavigate(page, false);
}

// ── APP BOOTSTRAP ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  document.body.classList.add('loaded');
  checkRoute();
});

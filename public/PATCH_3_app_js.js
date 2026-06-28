/*
 ╔══════════════════════════════════════════════════════════════════════
 ║  SOCIAL STRAND — JS Redesign (Public / Guest view)
 ║  Replaces functions from ~line 13060 onwards in app.js:
 ║    - pswEsc, pswFmt, pswTime, pswAvatar, pswEmbedUrl
 ║    - PSW_ICONS, PSW_REACTIONS constants
 ║    - pswFeedCard
 ║    - loadStudio, pswLoadMoreInner
 ║    - pswOpenDetail
 ║    - pswRenderComments
 ║    - pswCloseDetail
 ║    - pswShowAuthNudge → pswShowAuthNudge + pswHideAuthNudge
 ║
 ║  All API endpoints and data shapes remain unchanged.
 ╚══════════════════════════════════════════════════════════════════════
*/

// ── Shared state (unchanged) ──────────────────────────────────────────
const _PSW = {
  feedPage:      1,
  feedTag:       null,
  feedExhausted: false,
  feedLoading:   false,
  tagTimer:      null,
};

// ── Utilities ─────────────────────────────────────────────────────────

function pswEsc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function pswFmt(n) {
  const v = Number(n) || 0;
  if (v >= 1_000_000) return (v/1_000_000).toFixed(1).replace(/\.0$/,'')+'M';
  if (v >= 1000)      return (v/1000).toFixed(1).replace(/\.0$/,'')+'k';
  return String(v);
}

function pswTime(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff/60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m`;
  const h = Math.floor(m/60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h/24);
  if (d < 7)  return `${d}d`;
  return new Date(ts).toLocaleDateString('en-GB', { month:'short', day:'numeric' });
}

function pswTimeFull(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleDateString('en-GB', { month:'long', day:'numeric', year:'numeric' });
}

function pswAvatar(name, photo, size = 32) {
  if (photo) {
    return `<img src="${pswEsc(photo)}" alt="${pswEsc(name)}" width="${size}" height="${size}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;flex-shrink:0;background:#1a1a1a;display:block;">`;
  }
  const initials = (name || '?').split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();
  const bg = [
    '#2d2d2d','#2a2a3a','#2a3a2a','#3a2a2a','#2a3a3a','#3a3a2a'
  ][Math.abs((name||'').charCodeAt(0)) % 6];
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:${bg};border:1px solid rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.36)}px;font-weight:700;color:rgba(255,255,255,.55);flex-shrink:0;letter-spacing:-.01em">${pswEsc(initials)}</div>`;
}

function pswEmbedUrl(url, provider) {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (provider === 'youtube' || u.hostname.includes('youtube') || u.hostname.includes('youtu.be')) {
      const vid = u.searchParams.get('v') || u.pathname.split('/').pop();
      return `https://www.youtube.com/embed/${vid}?rel=0&modestbranding=1`;
    }
    if (provider === 'vimeo' || u.hostname.includes('vimeo')) {
      return `https://player.vimeo.com/video/${u.pathname.split('/').pop()}?title=0&byline=0&portrait=0`;
    }
  } catch {}
  return null;
}

// ── Icon set (inline SVG — no emoji) ─────────────────────────────────

const PSW_ICONS = {
  eye:     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  heart:   `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  comment: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  share:   `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
  bookmark:`<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>`,
  play:    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  pin:     `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
  user:    `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
  dots:    `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>`,
  detailShare: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
};

// Reactions with purposeful film-world labels
const PSW_REACTIONS = [
  { type: 'wow',        label: 'Wow',         icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>` },
  { type: 'inspiring',  label: 'Inspiring',   icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>` },
  { type: 'fire',       label: 'Fire',         icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0011 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 01-7 7 7 7 0 01-4.5-1.5c1-.5 1.5-1 1-2z"/></svg>` },
  { type: 'mind_blown', label: 'Mind Blown',   icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>` },
];

// ── Premium feed card ──────────────────────────────────────────────────

function pswFeedCard(p) {
  const author   = p.members || {};
  const hasImage = !!p.cover_image;
  const hasVideo = !!p.video_url;
  const postType = p.post_type || (hasImage ? 'image' : hasVideo ? 'video' : 'text');

  // Avatar
  const avatarHtml = author.photo
    ? `<img src="${pswEsc(author.photo)}" alt="" width="40" height="40" style="width:100%;height:100%;border-radius:50%;object-fit:cover;display:block" loading="lazy">`
    : `<div style="width:100%;height:100%;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:rgba(255,255,255,.5)">${pswEsc((author.name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase())}</div>`;

  // Domain chip
  const domainHtml = p.domain
    ? `<span class="psw-domain-chip">${pswEsc(p.domain)}</span>` : '';

  // Media
  let mediaHtml = '';
  if (hasImage) {
    mediaHtml = `<div class="psw-media-wrap"><img src="${pswEsc(p.cover_image)}" alt="" class="psw-media-img" loading="lazy"></div>`;
  } else if (hasVideo) {
    const embedUrl = pswEmbedUrl(p.video_url, p.video_provider);
    if (embedUrl) {
      mediaHtml = `<div class="psw-media-wrap psw-video-wrap" style="position:relative;padding-bottom:56.25%"><iframe src="${pswEsc(embedUrl)}" allowfullscreen loading="lazy" style="position:absolute;inset:0;width:100%;height:100%;border:none"></iframe></div>`;
    } else {
      mediaHtml = `<div class="psw-media-wrap" style="aspect-ratio:16/9;display:flex;align-items:center;justify-content:center;background:#0d0d0d">${PSW_ICONS.play}</div>`;
    }
  } else if (postType === 'text' && p.description) {
    mediaHtml = `<div class="psw-text-body"><div class="psw-text-content">${pswEsc(p.description)}</div></div>`;
  }

  // Caption / title
  const hasCaption = hasImage || hasVideo;
  let captionHtml = '';
  if (hasCaption) {
    const captionBody = [p.title, p.description].filter(Boolean).join(' — ');
    if (captionBody) captionHtml = `<div class="psw-caption"><span class="psw-caption-author">${pswEsc(author.name||'Member')}</span> <span class="psw-caption-text">${pswEsc(captionBody)}</span></div>`;
  } else if (postType !== 'text' && p.title) {
    captionHtml = `<div class="psw-post-title">${pswEsc(p.title)}</div>`;
  }

  // Tags
  const tagsHtml = p.tags?.length
    ? `<div class="psw-tag-row">${p.tags.map(t=>`<span class="psw-tag-chip">#${pswEsc(t)}</span>`).join('')}</div>` : '';

  // Comments link
  const commentsHtml = (p.comments_count||0) > 0
    ? `<div class="psw-comments-link" onclick="pswOpenDetail('${pswEsc(p.id)}')">${p.comments_count===1?'View 1 comment':`View all ${pswFmt(p.comments_count)} comments`}</div>` : '';

  // Likes
  const likesHtml = (p.reactions_count||0) > 0
    ? `<div class="psw-likes">${pswFmt(p.reactions_count)} like${p.reactions_count!==1?'s':''}</div>` : '';

  return `<article class="psw-post" data-project-id="${pswEsc(p.id)}" aria-label="${pswEsc(p.title||'Post by '+author.name)}">

    <!-- Header -->
    <div class="psw-post-header">
      <div class="psw-avatar-ring">
        <div class="psw-avatar-inner">${avatarHtml}</div>
      </div>
      <div class="psw-post-meta">
        <div class="psw-post-author">${pswEsc(author.name||'Member')}${domainHtml}</div>
        <div class="psw-post-time">${pswTime(p.created_at)}</div>
      </div>
      <button class="psw-post-options" onclick="pswOpenDetail('${pswEsc(p.id)}')" title="View post" aria-label="View full post">
        ${PSW_ICONS.dots}
      </button>
    </div>

    <!-- Media / content -->
    ${mediaHtml}

    <!-- Action row -->
    <div class="psw-actions">
      <button class="psw-action-btn" onclick="pswShowAuthNudge()" title="Like" aria-label="Like post">
        ${PSW_ICONS.heart}
      </button>
      <button class="psw-action-btn" onclick="pswOpenDetail('${pswEsc(p.id)}')" title="Comment" aria-label="Comment">
        ${PSW_ICONS.comment}
      </button>
      <button class="psw-action-btn" onclick="pswSharePost('${pswEsc(p.id)}','${pswEsc(p.title||'')}','${pswEsc(author.name||'')}',this)" title="Share" aria-label="Share">
        ${PSW_ICONS.share}
      </button>
      <button class="psw-action-btn psw-save" onclick="pswShowAuthNudge()" title="Save" aria-label="Save post">
        ${PSW_ICONS.bookmark}
      </button>
      <div class="psw-views-pill">
        ${PSW_ICONS.eye.replace('width="13" height="13"','width="12" height="12"')}&nbsp;${pswFmt(p.views_count||0)}
      </div>
    </div>

    <!-- Post body -->
    <div class="psw-post-body">
      ${likesHtml}
      ${captionHtml}
      ${tagsHtml}
      ${commentsHtml}
      <div class="psw-signin-nudge"><a href="/Social-Strand">Sign in</a> to like and comment.</div>
      <div class="psw-timestamp">${pswTimeFull(p.created_at)}</div>
    </div>
  </article>`;
}

// ── Feed load ──────────────────────────────────────────────────────────

async function loadStudio() {
  // Show skeleton, hide real feed
  const skeletons = document.getElementById('psw-skeletons');
  const feed = document.getElementById('psw-feed');
  if (skeletons) { skeletons.style.display = 'flex'; }
  if (feed) { feed.style.display = 'none'; feed.innerHTML = ''; }

  _PSW.feedPage = 1;
  _PSW.feedExhausted = false;

  await pswLoadMoreInner(true);

  // Hide skeleton, show feed
  if (skeletons) { skeletons.style.display = 'none'; }
  if (feed) { feed.style.display = 'flex'; }

  // Tag filter wire-up
  const tagInput = document.getElementById('psw-tag-filter');
  if (tagInput && !tagInput._wired) {
    tagInput._wired = true;
    tagInput.addEventListener('input', () => {
      clearTimeout(_PSW.tagTimer);
      _PSW.tagTimer = setTimeout(() => {
        _PSW.feedTag = tagInput.value.trim().replace(/^#/, '') || null;
        loadStudio();
      }, 380);
    });
  }
}

async function pswLoadMoreInner(reset = false) {
  if (_PSW.feedLoading) return;
  if (!reset && _PSW.feedExhausted) return;
  if (reset) { _PSW.feedPage = 1; _PSW.feedExhausted = false; }

  _PSW.feedLoading = true;
  const feed = document.getElementById('psw-feed');
  const moreBtn = document.getElementById('psw-load-more-btn');

  try {
    let url = `/api/strand/feed?page=${_PSW.feedPage}`;
    if (_PSW.feedTag) url += `&tag=${encodeURIComponent(_PSW.feedTag)}`;

    const resp  = await fetch(url);
    const data  = await resp.json();
    const posts = data.feed || data || [];
    const hasMore = data.has_more ?? (posts.length === 20);

    if (!feed) return;
    if (reset) feed.innerHTML = '';

    if (!posts.length && _PSW.feedPage === 1) {
      feed.innerHTML = `<div class="psw-empty">
        <div class="psw-empty-icon">${PSW_ICONS.heart}</div>
        <div class="psw-empty-title">Nothing here yet</div>
        <div class="psw-empty-sub">Members haven't shared any work yet. Check back soon.</div>
      </div>`;
      if (moreBtn) moreBtn.style.display = 'none';
      return;
    }

    feed.insertAdjacentHTML('beforeend', posts.map(pswFeedCard).join(''));
    _PSW.feedPage++;

    if (!hasMore) {
      _PSW.feedExhausted = true;
      if (moreBtn) moreBtn.style.display = 'none';
    } else {
      if (moreBtn) moreBtn.style.display = '';
    }
  } catch (e) {
    if (feed && _PSW.feedPage === 1) {
      feed.innerHTML = `<div class="psw-empty">
        <div class="psw-empty-title">Couldn't load posts</div>
        <div class="psw-empty-sub" style="margin-bottom:20px">Check your connection and try again.</div>
        <button class="psw-load-more-btn" onclick="loadStudio()">Retry</button>
      </div>`;
    }
  } finally {
    _PSW.feedLoading = false;
  }
}

function pswLoadMore() {
  pswLoadMoreInner(false);
}

// ── Share utility ──────────────────────────────────────────────────────

async function pswSharePost(postId, title, authorName, btn) {
  const usernameSlug = (authorName||'member').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
  const url = `https://kiitfilmsociety.in/social-strand/${usernameSlug}/${postId}`;
  try {
    if (navigator.share) {
      await navigator.share({ title, url });
    } else {
      await navigator.clipboard.writeText(url);
      if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
        setTimeout(() => { btn.innerHTML = orig; }, 1800);
      }
    }
  } catch {}
}

// ── Detail modal ───────────────────────────────────────────────────────

async function pswOpenDetail(projectId) {
  const overlay = document.getElementById('psw-detail-overlay');
  const body    = document.getElementById('psw-detail-body');
  if (!overlay || !body) return;

  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';

  body.innerHTML = `<div style="padding:80px 28px;text-align:center">
    <div style="width:32px;height:32px;border:2px solid rgba(255,255,255,.1);border-top-color:rgba(255,255,255,.6);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto"></div>
    <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
  </div>`;

  try {
    const resp = await fetch(`/api/strand/post/${projectId}`);
    if (!resp.ok) throw new Error(`${resp.status}`);
    const { post: p, comments } = await resp.json();
    const author = p.members || {};
    const collabs = p.project_collaborators?.map(c => c.members).filter(Boolean) || [];
    const embedUrl = pswEmbedUrl(p.video_url, p.video_provider);

    // Domain
    const domainHtml = p.domain
      ? `<span class="psw-detail-domain">${pswEsc(p.domain)}</span>` : '';

    // Tags
    const tagsHtml = p.tags?.length
      ? `<div class="psw-detail-tags">${p.tags.map(t=>`<span class="psw-tag">#${pswEsc(t)}</span>`).join('')}</div>` : '';

    // Collabs
    const collabsHtml = collabs.length
      ? `<div class="psw-detail-collabs">
          <span class="psw-detail-collab-label">${PSW_ICONS.user}&nbsp;With</span>
          ${collabs.map(c=>`<span class="psw-detail-collab-chip">${pswAvatar(c.name,c.photo,20)}&nbsp;${pswEsc(c.name)}</span>`).join('')}
        </div>` : '';

    body.innerHTML = `
      ${p.cover_image && !embedUrl ? `<img src="${pswEsc(p.cover_image)}" alt="${pswEsc(p.title)}" class="psw-detail-cover">` : ''}
      ${embedUrl ? `<div class="psw-detail-video-wrap"><iframe src="${pswEsc(embedUrl)}" allowfullscreen loading="lazy"></iframe></div>` : ''}

      <div class="psw-detail-content">
        <!-- Author row -->
        <div class="psw-detail-author-row">
          ${pswAvatar(author.name, author.photo, 38)}
          <div class="psw-detail-author-info">
            <div class="psw-detail-author-name">${pswEsc(author.name||'Member')}</div>
            ${author.role ? `<div class="psw-detail-author-role">${pswEsc(author.role)}</div>` : ''}
          </div>
          ${domainHtml}
        </div>

        <!-- Title -->
        <div class="psw-detail-title">${pswEsc(p.title)}</div>

        <!-- Description -->
        ${p.description ? `<div class="psw-detail-desc">${pswEsc(p.description)}</div>` : ''}

        <!-- Meta: views, reactions, comments, share -->
        <div class="psw-detail-meta">
          <span class="psw-detail-stat">${PSW_ICONS.eye}&nbsp;${pswFmt(p.views_count)}</span>
          <span class="psw-detail-stat">${PSW_ICONS.heart.replace('width="22" height="22"','width="12" height="12"')}&nbsp;${pswFmt(p.reactions_count)}</span>
          <span class="psw-detail-stat">${PSW_ICONS.comment.replace('width="22" height="22"','width="12" height="12"')}&nbsp;${pswFmt(p.comments_count)}</span>
          <button class="psw-share-btn" id="psw-detail-share-btn">
            ${PSW_ICONS.detailShare} Share
          </button>
        </div>

        <!-- Tags -->
        ${tagsHtml}

        <!-- Collaborators -->
        ${collabsHtml}

        <!-- Reaction gate (locked for guests) -->
        <div class="psw-rxn-section">
          <div class="psw-rxn-label">React to this post</div>
          <div class="psw-rxn-btns">
            ${PSW_REACTIONS.map(r=>`<button class="psw-rxn-ghost" onclick="pswShowAuthNudge()" aria-label="${pswEsc(r.label)}">${r.icon}<span>${pswEsc(r.label)}</span></button>`).join('')}
          </div>
        </div>

        <!-- Comments -->
        <div class="psw-comments-section">
          <div class="psw-comments-header">Comments · ${p.comments_count||0}</div>
          <div class="psw-comment-gate">
            <a href="/Social-Strand">Join Social Strand</a> to leave a comment.
          </div>
          <div id="psw-comments-list">${pswRenderComments(comments||[])}</div>
        </div>
      </div>`;

    // URL + OG meta
    const usernameSlug = (author.name||'member').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
    const shareUrl = `/social-strand/${usernameSlug}/${p.id}`;
    history.pushState({ page:'strand-detail', id:p.id }, '', shareUrl);
    window._currentStudioProjectId = p.id;
    updateMetaTags({
      title: p.title,
      description: p.description?.slice(0,155) || `${p.title} — work by ${author.name||'a KFS member'} on the KFS Social Strand.`,
      image: `/og/studio/${p.id}`,
      url: shareUrl,
    });

    // Wire share button
    const shareBtn = document.getElementById('psw-detail-share-btn');
    if (shareBtn) {
      shareBtn.addEventListener('click', async () => {
        const fullUrl = `https://kiitfilmsociety.in${shareUrl}`;
        try {
          if (navigator.share) {
            await navigator.share({ title: p.title, url: fullUrl });
          } else {
            await navigator.clipboard.writeText(fullUrl);
            shareBtn.textContent = 'Link copied!';
            setTimeout(() => { shareBtn.innerHTML = `${PSW_ICONS.detailShare} Share`; }, 1800);
          }
        } catch {}
      });
    }

  } catch (e) {
    body.innerHTML = `<div style="padding:56px 28px;text-align:center;color:var(--grey);font-size:14px">
      <div style="margin-bottom:12px">Couldn't load this post.</div>
      <button class="psw-load-more-btn" onclick="pswOpenDetail('${pswEsc(projectId)}')">Retry</button>
    </div>`;
  }
}

// ── Comments render (read-only, guests) ───────────────────────────────

function pswRenderComments(comments) {
  if (!comments.length) {
    return `<div style="color:var(--grey);font-size:13px;padding:8px 0 4px;line-height:1.6">No comments yet. Be the first to join the conversation.</div>`;
  }

  function renderOne(c, nested = false) {
    const a = c.members || {};
    return `<div class="psw-comment${nested?' psw-comment-nested':''}">
      <div class="psw-comment-header">
        ${pswAvatar(a.name, a.photo, nested ? 20 : 24)}
        <span class="psw-comment-author">${pswEsc(a.name||'Member')}</span>
        <span class="psw-comment-time">${pswTime(c.created_at)}</span>
        ${c.is_pinned ? `<span class="psw-pin-badge">${PSW_ICONS.pin} Pinned</span>` : ''}
      </div>
      <div class="psw-comment-body">${pswEsc(c.body)}</div>
      ${(c.replies||[]).map(r=>renderOne(r,true)).join('')}
    </div>`;
  }

  return comments.map(c => renderOne(c, false)).join('');
}

// ── Close detail ──────────────────────────────────────────────────────

function pswCloseDetail() {
  const overlay = document.getElementById('psw-detail-overlay');
  if (overlay) {
    overlay.classList.remove('open');
    // Small delay so close animation can run before display:none
    setTimeout(() => { overlay.style.display = ''; }, 0);
  }
  document.body.style.overflow = '';

  if (window._currentStudioProjectId) {
    window._currentStudioProjectId = null;
    history.pushState({ page:'strand' }, '', '/social-strand');
    updateMetaTags({
      title: 'KIIT Film Society',
      description: 'Official KIIT Film Society — a student-run collective passionate about cinema.',
      image: '/images/og-banner.png',
      url: '/social-strand',
    });
    removePageSchema?.();
  }
}

// Keyboard close
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('psw-detail-overlay');
    const authModal = document.getElementById('psw-auth-nudge');
    if (overlay && overlay.classList.contains('open')) pswCloseDetail();
    if (authModal && authModal.classList.contains('open')) pswHideAuthNudge();
  }
});

// ── Auth gate modal ────────────────────────────────────────────────────

function pswShowAuthNudge() {
  const m = document.getElementById('psw-auth-nudge');
  if (m) { m.classList.add('open'); document.body.style.overflow = 'hidden'; }
}

function pswHideAuthNudge() {
  const m = document.getElementById('psw-auth-nudge');
  if (m) { m.classList.remove('open'); document.body.style.overflow = ''; }
}

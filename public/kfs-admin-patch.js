/**
 * kfs-admin-patch.js  — KFS Admin Panel Enhancement v1.1
 * =========================================================
 * Adds to index.html / app.js without touching either file:
 *
 *  1. Dashboard  — "Pending Reports" summary card (red badge, links to Moderation)
 *  2. Moderation — Full inline content preview, reporter name link,
 *                  alongside existing Suspend / Delete actions
 *
 * v1.1 changes:
 *  - FIXED: requests now go through app.js's apiFetch() instead of reading
 *    window.adminToken (which app.js never sets — adminToken is a local
 *    variable there). The old code sent "Authorization: Bearer undefined"
 *    on every request, which 401'd unconditionally.
 *  - REMOVED: the standalone "Messaging" sidebar section (Broadcast DM /
 *    Targeted DM / Member Conversations) and the "Warn Member" button.
 *    These called /api/admin/messaging/send, /api/admin/messaging/broadcast,
 *    /api/admin/members/:id/conversations, and /api/admin/members/:id/account/warn
 *    — none of which exist on the server. The native DM & Messaging panel
 *    already in app.js covers broadcast/targeted DMs and works correctly.
 *
 * HOW TO DEPLOY:
 *   Add this line anywhere in index.html (before </body>), AFTER app.js:
 *     <script src="/app.js" defer></script>
 *     <script src="/kfs-admin-patch.js" defer></script>
 *
 * All functions are namespaced under window.KFSAdminPatch to avoid clashes.
 */

(function () {
  'use strict';

  /* ── Helpers ──────────────────────────────────────────────────────────── */

  async function adminFetch(url, method = 'GET', body = null) {
    if (typeof window.apiFetch !== 'function') {
      throw new Error('Admin session not ready yet — please wait a moment and retry.');
    }
    // app.js's apiFetch always attaches the live, auto-refreshed adminToken
    // internally — this is the fix for the old "Bearer undefined" 401 bug.
    const data = await window.apiFetch(url, method, body);
    if (data === null) {
      // apiFetch already surfaced a non-JSON / fatal error via showAdminError
      throw new Error('Request failed for ' + url);
    }
    if (data && data.error) throw new Error(data.error);
    return data;
  }

  function esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmtDate(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     1.  DASHBOARD — Pending Reports stat card
     ═══════════════════════════════════════════════════════════════════════ */

  function injectDashboardReportsCard() {
    const grid = document.getElementById('dashboard-stats-grid');
    if (!grid || document.getElementById('db-stat-reports')) return;

    const card = document.createElement('div');
    card.className = 'db-stat-card';
    card.id = 'db-stat-reports';
    card.style.cursor = 'pointer';
    card.setAttribute('data-action', 'showAdminSection');
    card.setAttribute('data-args', '["moderation"]');
    card.innerHTML = `
      <div class="db-stat-icon" style="background:rgba(229,62,62,.12);color:#e53e3e">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <div class="db-stat-val" id="db-val-reports">—</div>
      <div class="db-stat-label">Pending Reports</div>`;
    grid.appendChild(card);

    // Wire click via existing delegated event system
    card.addEventListener('click', () => {
      if (typeof window.showAdminSection === 'function') window.showAdminSection('moderation');
    });
  }

  async function refreshDashboardReportsCard() {
    const el = document.getElementById('db-val-reports');
    if (!el) return;
    try {
      const data = await adminFetch('/api/admin/reports/count');
      const n = data?.count ?? 0;
      el.textContent = n;
      el.style.color = n > 0 ? '#e53e3e' : '';
    } catch {
      el.textContent = '—';
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     2.  MODERATION — Enhanced reports table
         • Full inline content preview (expandable)
         • Reporter + affected member profile links
         • "Warn Member" action button
     ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Replaces the stock loadModReports with an enhanced version.
   * Called once, after DOMContentLoaded.
   */
  function patchLoadModReports() {
    // We override the global; the original is still callable as _origLoadModReports
    if (typeof window.loadModReports === 'function') {
      window._origLoadModReports = window.loadModReports;
    }

    window.loadModReports = async function enhancedLoadModReports() {
      const status = document.getElementById('mod-report-status')?.value || 'pending';
      const type   = document.getElementById('mod-report-type')?.value   || '';
      const tbody  = document.getElementById('mod-reports-tbody');
      if (!tbody) return;

      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--grey)">Loading…</td></tr>`;

      try {
        const url  = `/api/admin/reports?status=${status}${type ? '&type=' + type : ''}`;
        const data = await adminFetch(url);

        if (!Array.isArray(data) || !data.length) {
          tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--grey)">No reports found.</td></tr>`;
          return;
        }

        tbody.innerHTML = data.map(rep => {
          const date       = fmtDate(rep.created_at);
          const typeBadge  = { post: '📝 Post', dm: '💬 DM', comment: '🗨️ Comment' }[rep.content_type] || rep.content_type;
          const reporterId = rep.reporter?.id;
          const reporterName = esc(rep.reporter?.name || 'Unknown');
          const reporterLink = reporterId
            ? `<a href="javascript:void(0)" onclick="KFSAdminPatch.openMemberProfile('${reporterId}')"
                style="color:inherit;text-decoration:underline;text-underline-offset:3px">${reporterName}</a>`
            : reporterName;

          // Inline content preview — full text, collapsible
          const fullPreview = _buildFullPreview(rep);
          const shortPreview = fullPreview.slice(0, 60) + (fullPreview.length > 60 ? '…' : '');
          const previewId = `rep-preview-${rep.id}`;
          const previewCell = `
            <div id="${previewId}-short" style="font-size:12px;color:var(--grey)">${esc(shortPreview)}
              ${fullPreview.length > 60
                ? `<button onclick="KFSAdminPatch.expandPreview('${previewId}')"
                     style="background:none;border:none;color:#58a6ff;font-size:11px;cursor:pointer;padding:0;margin-left:4px">more</button>`
                : ''}
            </div>
            <div id="${previewId}-full" style="display:none;font-size:12px;color:var(--grey);white-space:pre-wrap;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;padding:10px;margin-top:6px;max-height:160px;overflow-y:auto">
              ${esc(fullPreview)}
              <button onclick="KFSAdminPatch.collapsePreview('${previewId}')"
                style="display:block;background:none;border:none;color:#58a6ff;font-size:11px;cursor:pointer;padding:4px 0 0;margin:0">less</button>
            </div>`;

          // Affected member (from snapshot) — shape differs per content_type, mirrors
          // server.js's enrichment: post/comment/group_message embed members{id,name};
          // dm embeds actor_id/actor_name (the sender); member reports embed id/name directly.
          let affectedMemberId = null, affectedMemberName = '—';
          if (rep.snapshot) {
            if (['post', 'comment', 'group_message'].includes(rep.content_type) && rep.snapshot.members) {
              affectedMemberId   = rep.snapshot.members.id;
              affectedMemberName = rep.snapshot.members.name || 'Member';
            } else if (rep.content_type === 'dm') {
              affectedMemberId   = rep.snapshot.actor_id || rep.snapshot.member_id;
              affectedMemberName = rep.snapshot.actor_name || 'Member';
            } else if (rep.content_type === 'member') {
              affectedMemberId   = rep.snapshot.id;
              affectedMemberName = rep.snapshot.name || 'Member';
            }
          }
          affectedMemberName = esc(affectedMemberName);
          const memberLink = affectedMemberId
            ? `<a href="javascript:void(0)" onclick="KFSAdminPatch.openMemberProfile('${affectedMemberId}')"
                style="font-size:11px;color:#58a6ff;text-decoration:none"
                title="View member profile">👤 ${affectedMemberName}</a>`
            : `<span style="font-size:11px;color:var(--grey)">—</span>`;

          // Actions
          let actions = '';
          if (status === 'pending') {
            actions = `
              <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
                <button onclick="openModResolveModal('${rep.id}','${rep.content_type}','${rep.content_id}',${JSON.stringify(_buildFullPreview(rep)).replace(/"/g,'&quot;')}${affectedMemberId ? `,'${affectedMemberId}',${JSON.stringify(affectedMemberName).replace(/"/g,'&quot;')}` : ',null,null'})"
                  class="btn-sm btn-success" style="font-size:11px;padding:4px 10px">Review</button>
                <button onclick="quickDismissReport('${rep.id}')"
                  class="btn-sm" style="font-size:11px;padding:4px 10px;background:transparent;border:1px solid var(--border);color:var(--grey)">Dismiss</button>
                ${affectedMemberId
                  ? `<button onclick="openSuspendModal('${affectedMemberId}')"
                       class="btn-sm" style="font-size:11px;padding:4px 10px;background:rgba(229,62,62,.1);border:1px solid rgba(229,62,62,.3);color:#e53e3e">Suspend</button>`
                  : ''}
                ${rep.content_type === 'dm' && rep.snapshot?.link_id
                  ? `<button onclick="viewDmConv('${rep.snapshot.link_id}')"
                       class="btn-sm" style="font-size:11px;padding:4px 10px;background:transparent;border:1px solid var(--border);color:var(--grey)">View DM</button>`
                  : ''}
              </div>`;
          } else {
            actions = `<span style="font-size:11px;color:var(--grey)">${esc(rep.reviewed_by || '—')} · ${fmtDate(rep.reviewed_at)}</span>`;
          }

          return `<tr>
            <td style="white-space:nowrap;font-size:12px">${date}</td>
            <td style="font-size:13px">${reporterLink}</td>
            <td>${typeBadge}</td>
            <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--grey)"
                title="${esc(rep.reason)}">${esc(rep.reason)}</td>
            <td style="max-width:220px">${previewCell}</td>
            <td>${memberLink}</td>
            <td>${actions}</td>
          </tr>`;
        }).join('');

        // Update column header to 7 cols
        const thead = tbody.closest('table')?.querySelector('thead tr');
        if (thead && thead.children.length < 7) {
          thead.innerHTML = '<th>Date</th><th>Reporter</th><th>Type</th><th>Reason</th><th>Content Preview</th><th>Member</th><th>Actions</th>';
        }

      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:#e53e3e">Failed to load reports: ${esc(e.message)}</td></tr>`;
      }
    };
  }

  function _buildFullPreview(rep) {
    if (!rep.snapshot) return '(content unavailable)';
    if (rep.content_type === 'post') {
      if (rep.snapshot.deleted_at) return '[deleted]';
      const title = rep.snapshot.title ? 'Title: ' + rep.snapshot.title + '\n' : '';
      const desc  = rep.snapshot.description || '';
      return (title + desc).trim() || '(no preview)';
    }
    if (rep.content_type === 'dm')      return rep.snapshot.body || '(empty message)';
    if (rep.content_type === 'comment') return rep.snapshot.body || '(empty comment)';
    return '(no preview)';
  }

  /* ═══════════════════════════════════════════════════════════════════════
     MEMBER PROFILE LINK from reports
     ═══════════════════════════════════════════════════════════════════════ */
  function openMemberProfile(memberId) {
    // Re-use the existing admin member modal if available (openMemberPortalModal)
    // Otherwise fall back to navigating to the Members section
    if (typeof window.openMemberPortalModal === 'function') {
      adminFetch(`/api/admin/members/${memberId}`)
        .then(member => window.openMemberPortalModal(member))
        .catch(() => {
          if (typeof window.showAdminSection === 'function') window.showAdminSection('members');
        });
    } else if (typeof window.showAdminSection === 'function') {
      window.showAdminSection('members');
    }
  }

  /* ── Preview expand/collapse ────────────────────────────────────────── */
  function expandPreview(id) {
    const shortEl = document.getElementById(id + '-short');
    const fullEl  = document.getElementById(id + '-full');
    if (shortEl) shortEl.style.display = 'none';
    if (fullEl)  fullEl.style.display  = '';
  }

  function collapsePreview(id) {
    const shortEl = document.getElementById(id + '-short');
    const fullEl  = document.getElementById(id + '-full');
    if (shortEl) shortEl.style.display = '';
    if (fullEl)  fullEl.style.display  = 'none';
  }

  /* ═══════════════════════════════════════════════════════════════════════
     BOOT — wire everything up after DOM is ready
     ═══════════════════════════════════════════════════════════════════════ */

  function init() {
    injectDashboardReportsCard();
    patchLoadModReports();

    // Hook into loadDashboard to also fetch reports count
    const _origLoadDashboard = window.loadDashboard;
    if (typeof _origLoadDashboard === 'function') {
      window.loadDashboard = async function () {
        await _origLoadDashboard.call(this, ...arguments);
        refreshDashboardReportsCard();
      };
    }

    // Belt-and-suspenders: app.js dispatches this once the admin token has
    // hydrated from the refresh cookie. If the dashboard is already on
    // screen at that point, refresh the card instead of leaving it on "—".
    document.addEventListener('adminTokenReady', refreshDashboardReportsCard, { once: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ── Public API ─────────────────────────────────────────────────────── */
  window.KFSAdminPatch = {
    /* moderation */
    openMemberProfile,
    expandPreview,
    collapsePreview,
  };
})();

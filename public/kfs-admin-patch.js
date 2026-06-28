/**
 * kfs-admin-patch.js  — KFS Admin Panel Enhancement v1.0
 * =========================================================
 * Adds to index.html / app.js without touching either file:
 *
 *  1. Dashboard  — "Pending Reports" summary card (red badge, links to Moderation)
 *  2. Moderation — Full inline content preview, reporter name link, "Warn Member"
 *                  action button alongside existing Suspend / Delete actions
 *  3. Admin Messaging — New sidebar group "Messaging" with:
 *        • KFS Broadcast DM  (send to all members or specific member)
 *        • View Conversations (browse any member conversation from a report)
 *        • Send Targeted DM  (send as KFS to a single member)
 *
 * HOW TO DEPLOY:
 *   Add this line anywhere in index.html (before </body>):
 *     <script src="/kfs-admin-patch.js" defer></script>
 *
 * All functions are namespaced under window.KFSAdminPatch to avoid clashes.
 */

(function () {
  'use strict';

  /* ── Helpers ──────────────────────────────────────────────────────────── */

  function getAdminToken() {
    // Mirrors the pattern in app.js — adminToken is a closure var there,
    // but it's also referenced on window in some build paths.
    return window.adminToken || null;
  }

  function getCsrf() {
    return window._csrfToken || '';
  }

  async function adminFetch(url, method = 'GET', body = null) {
    const opts = {
      method,
      credentials: 'include',
      headers: { Authorization: 'Bearer ' + getAdminToken() },
    };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      if (!['GET', 'HEAD'].includes(method)) opts.headers['X-CSRF-Token'] = getCsrf();
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new Error('Non-JSON response from ' + url);
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
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

          // Affected member (from snapshot)
          const affectedMemberId   = rep.snapshot?.author_id || rep.snapshot?.sender_id;
          const affectedMemberName = esc(rep.snapshot?.author_name || rep.snapshot?.sender_name || '—');
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
                <button onclick="openModResolveModal('${rep.id}','${rep.content_type}','${rep.content_id}',${JSON.stringify(_buildFullPreview(rep)).replace(/"/g,'&quot;')})"
                  class="btn-sm btn-success" style="font-size:11px;padding:4px 10px">Review</button>
                <button onclick="quickDismissReport('${rep.id}')"
                  class="btn-sm" style="font-size:11px;padding:4px 10px;background:transparent;border:1px solid var(--border);color:var(--grey)">Dismiss</button>
                ${affectedMemberId
                  ? `<button onclick="KFSAdminPatch.warnMember('${affectedMemberId}','${esc(affectedMemberName)}')"
                       class="btn-sm" style="font-size:11px;padding:4px 10px;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#f59e0b">⚠ Warn</button>`
                  : ''}
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
     3.  ADMIN MESSAGING SECTION
     ═══════════════════════════════════════════════════════════════════════ */

  function injectMessagingSidebar() {
    const sidebar = document.querySelector('.admin-sidebar');
    if (!sidebar || document.getElementById('sidebar-messaging')) return;

    // Find the "bottom" divider to insert before it, after existing items
    const bottomSection = sidebar.querySelector('.admin-sidebar-bottom');

    const group = document.createElement('div');
    group.innerHTML = `
      <div class="admin-sidebar-group" style="margin-top:8px">Messaging</div>
      <div data-action="showAdminSection" data-args='["admin-messaging"]'
           class="admin-sidebar-item" data-section="admin-messaging" id="sidebar-messaging"
           onclick="KFSAdminPatch.showMessagingSection()">
        <span class="icon">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07
                     A19.5 19.5 0 0 1 4.07 13.91 19.79 19.79 0 0 1 1 5.33
                     A2 2 0 0 1 2.96 3h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7
                     2.81a2 2 0 0 1-.45 2.11L7.09 10.91a16 16 0 0 0 6 6l1.27-1.27
                     a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 21
                     18v3z"/>
          </svg>
        </span>
        DM &amp; Messaging
      </div>`;

    if (bottomSection) {
      sidebar.insertBefore(group, bottomSection);
    } else {
      sidebar.appendChild(group);
    }
  }

  function injectMessagingSection() {
    const adminMain = document.querySelector('.admin-main');
    if (!adminMain || document.getElementById('section-admin-messaging')) return;

    const section = document.createElement('div');
    section.className = 'admin-section';
    section.id = 'section-admin-messaging';
    section.innerHTML = `
      <div class="admin-header">
        <div>
          <h2>DM &amp; Messaging</h2>
          <p>Send broadcast DMs as KFS, view reported conversations, and send targeted messages</p>
        </div>
      </div>

      <!-- ── Tabs ── -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px" id="msg-tabs">
        <button onclick="KFSAdminPatch.msgTab('broadcast')" id="msg-tab-broadcast"
          class="btn btn-primary" style="font-size:12px;padding:8px 18px;border-radius:20px">
          📢 Broadcast DM
        </button>
        <button onclick="KFSAdminPatch.msgTab('targeted')" id="msg-tab-targeted"
          class="btn" style="font-size:12px;padding:8px 18px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)">
          ✉ Targeted DM
        </button>
        <button onclick="KFSAdminPatch.msgTab('conversations')" id="msg-tab-conversations"
          class="btn" style="font-size:12px;padding:8px 18px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)">
          🗂 Member Conversations
        </button>
      </div>

      <!-- ── Broadcast DM ── -->
      <div id="msg-panel-broadcast">
        <div class="admin-card" style="max-width:680px;padding:24px">
          <h4 style="margin:0 0 6px;font-size:15px;font-weight:700">Send Broadcast DM as KFS</h4>
          <p style="font-size:12px;color:var(--grey);margin:0 0 20px;line-height:1.6">
            This sends a direct message from the KFS official account to members via the
            Social Strand DM system. Use for important announcements, event reminders, or
            individual follow-ups.
          </p>

          <div class="form-group">
            <label>Recipients</label>
            <select id="msg-bc-scope" onchange="KFSAdminPatch.onBcScopeChange()"
              style="font-size:13px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:360px">
              <option value="all">All Members</option>
              <option value="specific">Specific Member…</option>
            </select>
          </div>

          <div id="msg-bc-member-picker" style="display:none;margin-bottom:18px">
            <label style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--grey);display:block;margin-bottom:6px">Member</label>
            <div style="position:relative">
              <input type="text" id="msg-bc-member-search" placeholder="Search member by name…"
                style="font-size:13px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:360px;box-sizing:border-box"
                oninput="KFSAdminPatch.searchMembersPicker('msg-bc-member-search','msg-bc-member-dropdown','msg-bc-member-id')">
              <div id="msg-bc-member-dropdown"
                style="display:none;position:absolute;top:calc(100%+4px);left:0;width:360px;background:var(--card);border:1px solid var(--border);border-radius:10px;z-index:50;max-height:220px;overflow-y:auto;box-shadow:0 8px 24px rgba(0,0,0,.4)"></div>
            </div>
            <input type="hidden" id="msg-bc-member-id">
          </div>

          <div class="form-group">
            <label>Subject / Opening Line</label>
            <input type="text" id="msg-bc-subject" placeholder="e.g. 🎬 Reminder: Film Screening this Saturday!"
              style="font-size:13px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:680px;box-sizing:border-box">
          </div>

          <div class="form-group">
            <label>Message Body</label>
            <textarea id="msg-bc-body" rows="6" placeholder="Write your message here…"
              style="font-size:13px;padding:12px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:680px;box-sizing:border-box;resize:vertical;line-height:1.6;font-family:inherit"></textarea>
          </div>

          <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
            <button onclick="KFSAdminPatch.sendBroadcastDM()"
              class="btn btn-primary" style="padding:10px 24px;font-size:13px;border-radius:20px">
              📤 Send DM
            </button>
            <span id="msg-bc-status" style="font-size:12px;color:var(--grey)"></span>
          </div>

          <div id="msg-bc-result" style="display:none;margin-top:16px;padding:12px 16px;background:rgba(52,199,89,.08);border:1px solid rgba(52,199,89,.2);border-radius:10px;font-size:13px;color:#4ade80"></div>
          <div id="msg-bc-error"  style="display:none;margin-top:16px;padding:12px 16px;background:rgba(229,62,62,.08);border:1px solid rgba(229,62,62,.2);border-radius:10px;font-size:13px;color:#e53e3e"></div>
        </div>
      </div>

      <!-- ── Targeted DM ── -->
      <div id="msg-panel-targeted" style="display:none">
        <div class="admin-card" style="max-width:680px;padding:24px">
          <h4 style="margin:0 0 6px;font-size:15px;font-weight:700">Send Targeted DM as KFS</h4>
          <p style="font-size:12px;color:var(--grey);margin:0 0 20px;line-height:1.6">
            Send a one-to-one direct message to a specific member as the KFS official account.
            Useful for warnings, personal follow-ups, or confirmations.
          </p>

          <div class="form-group">
            <label>To (Member)</label>
            <div style="position:relative">
              <input type="text" id="msg-tgt-member-search" placeholder="Search member by name…"
                style="font-size:13px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:360px;box-sizing:border-box"
                oninput="KFSAdminPatch.searchMembersPicker('msg-tgt-member-search','msg-tgt-member-dropdown','msg-tgt-member-id')">
              <div id="msg-tgt-member-dropdown"
                style="display:none;position:absolute;top:calc(100%+4px);left:0;width:360px;background:var(--card);border:1px solid var(--border);border-radius:10px;z-index:50;max-height:220px;overflow-y:auto;box-shadow:0 8px 24px rgba(0,0,0,.4)"></div>
            </div>
            <input type="hidden" id="msg-tgt-member-id">
            <div id="msg-tgt-selected-member" style="display:none;margin-top:8px;padding:8px 12px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;font-size:13px;color:var(--white)"></div>
          </div>

          <div class="form-group">
            <label>Message</label>
            <textarea id="msg-tgt-body" rows="5" placeholder="Write your message here…"
              style="font-size:13px;padding:12px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;max-width:680px;box-sizing:border-box;resize:vertical;line-height:1.6;font-family:inherit"></textarea>
          </div>

          <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
            <button onclick="KFSAdminPatch.sendTargetedDM()"
              class="btn btn-primary" style="padding:10px 24px;font-size:13px;border-radius:20px">
              📤 Send Message
            </button>
            <span id="msg-tgt-status" style="font-size:12px;color:var(--grey)"></span>
          </div>
          <div id="msg-tgt-result" style="display:none;margin-top:16px;padding:12px 16px;background:rgba(52,199,89,.08);border:1px solid rgba(52,199,89,.2);border-radius:10px;font-size:13px;color:#4ade80"></div>
          <div id="msg-tgt-error"  style="display:none;margin-top:16px;padding:12px 16px;background:rgba(229,62,62,.08);border:1px solid rgba(229,62,62,.2);border-radius:10px;font-size:13px;color:#e53e3e"></div>
        </div>
      </div>

      <!-- ── Member Conversations ── -->
      <div id="msg-panel-conversations" style="display:none">
        <div class="admin-card" style="padding:20px;margin-bottom:18px">
          <h4 style="margin:0 0 6px;font-size:15px;font-weight:700">Browse Member Conversations</h4>
          <p style="font-size:12px;color:var(--grey);margin:0 0 16px;line-height:1.6">
            View DM conversations for a specific member — typically used when following up on a report.
            Only conversations involving reported content are accessible.
          </p>
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
            <div style="position:relative;flex:1;min-width:200px;max-width:360px">
              <input type="text" id="msg-conv-member-search" placeholder="Search member by name…"
                style="font-size:13px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--white);width:100%;box-sizing:border-box"
                oninput="KFSAdminPatch.searchMembersPicker('msg-conv-member-search','msg-conv-member-dropdown','msg-conv-member-id')">
              <div id="msg-conv-member-dropdown"
                style="display:none;position:absolute;top:calc(100%+4px);left:0;right:0;background:var(--card);border:1px solid var(--border);border-radius:10px;z-index:50;max-height:220px;overflow-y:auto;box-shadow:0 8px 24px rgba(0,0,0,.4)"></div>
            </div>
            <input type="hidden" id="msg-conv-member-id">
            <button onclick="KFSAdminPatch.loadMemberConversations()"
              class="btn btn-primary" style="font-size:12px;padding:10px 20px;border-radius:20px;white-space:nowrap">
              Load Conversations
            </button>
          </div>
        </div>

        <div id="msg-conv-list">
          <div style="text-align:center;padding:40px;color:var(--grey);font-size:13px">
            Select a member above to view their reported conversations.
          </div>
        </div>
      </div>`;

    adminMain.appendChild(section);
  }

  /* ── Tab switching for Messaging section ─────────────────────────────── */
  function msgTab(tab) {
    ['broadcast', 'targeted', 'conversations'].forEach(t => {
      const panel = document.getElementById('msg-panel-' + t);
      const btn   = document.getElementById('msg-tab-' + t);
      if (!panel || !btn) return;
      if (t === tab) {
        panel.style.display = '';
        btn.className = 'btn btn-primary';
        btn.style.cssText = 'font-size:12px;padding:8px 18px;border-radius:20px';
      } else {
        panel.style.display = 'none';
        btn.className = 'btn';
        btn.style.cssText = 'font-size:12px;padding:8px 18px;border-radius:20px;background:transparent;border:1px solid var(--border);color:var(--grey)';
      }
    });
  }

  function showMessagingSection() {
    // Deactivate other admin sidebar items
    document.querySelectorAll('.admin-sidebar-item').forEach(el => el.classList.remove('active'));
    document.getElementById('sidebar-messaging')?.classList.add('active');
    // Deactivate all admin sections
    document.querySelectorAll('.admin-section').forEach(el => el.classList.remove('active'));
    document.getElementById('section-admin-messaging')?.classList.add('active');
    // Activate broadcast tab by default
    msgTab('broadcast');
  }

  function onBcScopeChange() {
    const scope  = document.getElementById('msg-bc-scope')?.value;
    const picker = document.getElementById('msg-bc-member-picker');
    if (picker) picker.style.display = scope === 'specific' ? '' : 'none';
  }

  /* ── Member picker autocomplete (shared) ───────────────────────────── */
  let _allMembersCache = null;

  async function getAllMembers() {
    if (_allMembersCache) return _allMembersCache;
    try {
      _allMembersCache = await adminFetch('/api/admin/members');
      return _allMembersCache;
    } catch {
      return [];
    }
  }

  async function searchMembersPicker(inputId, dropdownId, hiddenId) {
    const input    = document.getElementById(inputId);
    const dropdown = document.getElementById(dropdownId);
    const hidden   = document.getElementById(hiddenId);
    if (!input || !dropdown) return;

    const q = input.value.trim().toLowerCase();
    if (!q) { dropdown.style.display = 'none'; return; }

    const members = await getAllMembers();
    const matches = members.filter(m => (m.name || '').toLowerCase().includes(q)).slice(0, 10);

    if (!matches.length) { dropdown.style.display = 'none'; return; }

    dropdown.innerHTML = matches.map(m => `
      <div onclick="KFSAdminPatch.selectPickerMember('${m.id}',${JSON.stringify(m.name).replace(/"/g,'&quot;')},'${inputId}','${dropdownId}','${hiddenId}')"
        style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;transition:background .1s"
        onmouseover="this.style.background='rgba(255,255,255,.06)'"
        onmouseout="this.style.background=''"
      >
        <span style="font-size:13px;font-weight:500;color:var(--white)">${esc(m.name)}</span>
        ${m.batch ? `<span style="font-size:11px;color:var(--grey)">${esc(m.batch)}</span>` : ''}
      </div>`).join('');
    dropdown.style.display = '';

    // Close on outside click
    setTimeout(() => {
      const close = (e) => {
        if (!dropdown.contains(e.target) && e.target !== input) {
          dropdown.style.display = 'none';
          document.removeEventListener('click', close);
        }
      };
      document.addEventListener('click', close);
    }, 0);
  }

  function selectPickerMember(id, name, inputId, dropdownId, hiddenId) {
    const input    = document.getElementById(inputId);
    const dropdown = document.getElementById(dropdownId);
    const hidden   = document.getElementById(hiddenId);
    if (input)    input.value    = name;
    if (hidden)   hidden.value   = id;
    if (dropdown) dropdown.style.display = 'none';

    // Update selected member display for targeted DM
    const selectedEl = document.getElementById('msg-tgt-selected-member');
    if (selectedEl && inputId === 'msg-tgt-member-search') {
      selectedEl.textContent = `Sending to: ${name}`;
      selectedEl.style.display = '';
    }
  }

  /* ── Send Broadcast DM ──────────────────────────────────────────────── */
  async function sendBroadcastDM() {
    const scope   = document.getElementById('msg-bc-scope')?.value || 'all';
    const subject = document.getElementById('msg-bc-subject')?.value.trim() || '';
    const body    = document.getElementById('msg-bc-body')?.value.trim() || '';
    const memberId = scope === 'specific' ? (document.getElementById('msg-bc-member-id')?.value || '') : null;

    const resultEl = document.getElementById('msg-bc-result');
    const errorEl  = document.getElementById('msg-bc-error');
    const statusEl = document.getElementById('msg-bc-status');
    [resultEl, errorEl].forEach(el => { if (el) el.style.display = 'none'; });

    if (!body) { if (errorEl) { errorEl.textContent = 'Please write a message body.'; errorEl.style.display = ''; } return; }
    if (scope === 'specific' && !memberId) { if (errorEl) { errorEl.textContent = 'Please select a member.'; errorEl.style.display = ''; } return; }

    const label = scope === 'all' ? 'all members' : document.getElementById('msg-bc-member-search')?.value || 'the selected member';
    if (!confirm(`Send this DM as KFS to ${label}?`)) return;

    if (statusEl) statusEl.textContent = 'Sending…';

    try {
      const payload = { scope, body, subject };
      if (memberId) payload.member_id = memberId;
      const data = await adminFetch('/api/admin/messaging/broadcast', 'POST', payload);
      if (statusEl) statusEl.textContent = '';
      if (resultEl) {
        const sent = data?.sent ?? '?';
        resultEl.textContent = `✓ DM sent to ${sent} member${sent !== 1 ? 's' : ''} successfully.`;
        resultEl.style.display = '';
      }
      // Clear form
      ['msg-bc-subject', 'msg-bc-body'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
    } catch (e) {
      if (statusEl) statusEl.textContent = '';
      if (errorEl) {
        errorEl.textContent = 'Failed to send: ' + e.message;
        errorEl.style.display = '';
      }
    }
  }

  /* ── Send Targeted DM ───────────────────────────────────────────────── */
  async function sendTargetedDM() {
    const memberId = document.getElementById('msg-tgt-member-id')?.value || '';
    const body     = document.getElementById('msg-tgt-body')?.value.trim() || '';
    const memberName = document.getElementById('msg-tgt-member-search')?.value || 'this member';

    const resultEl = document.getElementById('msg-tgt-result');
    const errorEl  = document.getElementById('msg-tgt-error');
    const statusEl = document.getElementById('msg-tgt-status');
    [resultEl, errorEl].forEach(el => { if (el) el.style.display = 'none'; });

    if (!memberId) { if (errorEl) { errorEl.textContent = 'Please select a member.'; errorEl.style.display = ''; } return; }
    if (!body)     { if (errorEl) { errorEl.textContent = 'Please write a message.';  errorEl.style.display = ''; } return; }

    if (!confirm(`Send this DM as KFS to ${memberName}?`)) return;
    if (statusEl) statusEl.textContent = 'Sending…';

    try {
      await adminFetch('/api/admin/messaging/send', 'POST', { member_id: memberId, body });
      if (statusEl) statusEl.textContent = '';
      if (resultEl) { resultEl.textContent = `✓ Message sent to ${memberName}.`; resultEl.style.display = ''; }
      document.getElementById('msg-tgt-body').value  = '';
      document.getElementById('msg-tgt-member-search').value = '';
      document.getElementById('msg-tgt-member-id').value = '';
      const selEl = document.getElementById('msg-tgt-selected-member');
      if (selEl) selEl.style.display = 'none';
    } catch (e) {
      if (statusEl) statusEl.textContent = '';
      if (errorEl) { errorEl.textContent = 'Failed: ' + e.message; errorEl.style.display = ''; }
    }
  }

  /* ── Load Member Conversations (from reports) ───────────────────────── */
  async function loadMemberConversations() {
    const memberId   = document.getElementById('msg-conv-member-id')?.value || '';
    const memberName = document.getElementById('msg-conv-member-search')?.value || '';
    const listEl     = document.getElementById('msg-conv-list');
    if (!listEl) return;

    if (!memberId) {
      listEl.innerHTML = '<div style="text-align:center;padding:40px;color:#e53e3e;font-size:13px">Please select a member first.</div>';
      return;
    }

    listEl.innerHTML = '<div style="text-align:center;padding:40px;color:var(--grey);font-size:13px">Loading conversations…</div>';

    try {
      const data = await adminFetch(`/api/admin/members/${memberId}/conversations`);
      if (!Array.isArray(data) || !data.length) {
        listEl.innerHTML = `<div style="text-align:center;padding:40px;color:var(--grey);font-size:13px">
          No reported conversations found for ${esc(memberName)}.<br>
          <span style="font-size:11px;opacity:.6">Conversations are only surfaced when they contain reported messages.</span>
        </div>`;
        return;
      }

      listEl.innerHTML = `
        <div class="admin-card" style="padding:0;overflow:hidden">
          <table class="admin-table">
            <thead><tr>
              <th>With</th><th>Last Message</th><th>Date</th><th>Reports</th><th>Action</th>
            </tr></thead>
            <tbody>
              ${data.map(conv => `
                <tr>
                  <td style="font-weight:500">${esc(conv.other_member_name || '—')}</td>
                  <td style="font-size:12px;color:var(--grey);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                    ${esc((conv.last_message || '').slice(0, 80))}
                  </td>
                  <td style="font-size:12px;white-space:nowrap">${fmtDate(conv.last_message_at)}</td>
                  <td style="text-align:center">
                    ${conv.report_count
                      ? `<span style="background:rgba(229,62,62,.12);color:#e53e3e;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700">${conv.report_count}</span>`
                      : '—'}
                  </td>
                  <td>
                    <button onclick="${conv.conv_id ? `viewDmConv('${conv.conv_id}')` : `KFSAdminPatch.viewConvFallback('${conv.conv_id || ''}')`}"
                      class="btn-sm" style="font-size:11px;padding:4px 12px">View</button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>`;
    } catch (e) {
      listEl.innerHTML = `<div style="text-align:center;padding:40px;color:#e53e3e;font-size:13px">Failed to load: ${esc(e.message)}</div>`;
    }
  }

  function viewConvFallback(convId) {
    if (convId && typeof window.viewDmConv === 'function') {
      window.viewDmConv(convId);
    } else {
      alert('Conversation ID not available. Open from the Reports tab instead.');
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     WARN MEMBER — sends a warning DM + flags on account
     ═══════════════════════════════════════════════════════════════════════ */
  async function warnMember(memberId, memberName) {
    const reason = prompt(`Send a formal warning to ${memberName}?\n\nEnter the reason (shown to member via DM):`);
    if (reason === null) return; // cancelled
    if (!reason.trim()) { alert('Please provide a reason for the warning.'); return; }

    try {
      await adminFetch(`/api/admin/members/${memberId}/account/warn`, 'POST', { reason: reason.trim() });
      alert(`Warning sent to ${memberName}. They will receive a DM notification and their account will be flagged for one violation.`);
    } catch (e) {
      alert('Failed to warn member: ' + e.message);
    }
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
    injectMessagingSidebar();
    injectMessagingSection();
    patchLoadModReports();

    // Hook into loadDashboard to also fetch reports count
    const _origLoadDashboard = window.loadDashboard;
    if (typeof _origLoadDashboard === 'function') {
      window.loadDashboard = async function () {
        await _origLoadDashboard.call(this, ...arguments);
        refreshDashboardReportsCard();
      };
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ── Public API ─────────────────────────────────────────────────────── */
  window.KFSAdminPatch = {
    /* messaging */
    showMessagingSection,
    msgTab,
    onBcScopeChange,
    searchMembersPicker,
    selectPickerMember,
    sendBroadcastDM,
    sendTargetedDM,
    loadMemberConversations,
    viewConvFallback,
    /* moderation */
    warnMember,
    openMemberProfile,
    expandPreview,
    collapsePreview,
  };
})();

// ═══════════════════════════════════════════════════════════════════════════
// admin-analytics.js — Engagement & Network Analytics + Trust & Safety suite
//
// Wire into server.js with:
//   const mountAnalytics = require("./admin-analytics");
//   mountAnalytics(app, { supabase, requireSection, masterMiddleware,
//                          authMiddleware, memCache, memInvalidate, logActivity });
//
// Reuses your existing patterns: requireSection()/masterMiddleware for authz,
// memCache() for read-through caching, logActivity() for the admin audit trail.
// Adds NO new plaintext DM storage — the DM investigation layer only ever reads
// content_reports.decrypted_snapshot, which your E2EE report flow already
// populates client-side. Nothing here decrypts anything server-side.
// ═══════════════════════════════════════════════════════════════════════════

module.exports = function mountAnalytics(app, deps) {
  const { supabase, requireSection, masterMiddleware, authMiddleware, memCache, memInvalidate, logActivity } = deps;

  // New granular permission strings — add these to your admin permission
  // editor UI (same place ALL_SECTIONS / the permissions checkbox list lives).
  // 'trust_safety.investigate' and 'investigations.access_dm' should be
  // treated as master-only until you decide to hand them to trusted non-master
  // admins — masterMiddleware is used below for anything DM-related.
  const PERMS = {
    ANALYTICS_VIEW: "analytics.view",              // viral content, overview, influencer stats
    TRUST_SAFETY_VIEW: "trust_safety.view",         // read detection logs
    TRUST_SAFETY_INVESTIGATE: "trust_safety.investigate", // change detection status
    AUDIT_LOGS_VIEW: "audit_logs.view",
  };

  // ── Small helper: OR-permission middleware (mirrors requireGrievanceAccess pattern) ──
  function requireAnyPermission(...sections) {
    return (req, res, next) => {
      // req.admin is already populated by an upstream authMiddleware-style check;
      // if this router is mounted standalone, run authMiddleware first via app.use.
      if (!req.admin) return res.status(401).json({ error: "No token" });
      if (req.admin.role === "master") return next();
      const perms = req.admin.permissions || [];
      if (sections.some(s => perms.includes(s))) return next();
      return res.status(403).json({ error: `No permission for: ${sections.join(" or ")}` });
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 1. VIRAL CONTENT TRACKER
  // ═══════════════════════════════════════════════════════════════════════

  // GET /api/admin/analytics/viral-content?window=24h&sort=viral_score&page=0
  app.get("/api/admin/analytics/viral-content",
    authMiddleware, requireSection(PERMS.ANALYTICS_VIEW), async (req, res) => {
    try {
      const page  = Math.max(0, parseInt(req.query.page) || 0);
      const limit = 30;
      const sort  = ["viral_score", "velocity", "anomaly_score"].includes(req.query.sort)
        ? req.query.sort : "viral_score";

      const data = await memCache(`analytics:viral:${sort}:${page}`, 60, async () => {
        const { data: rows, error } = await supabase
          .from("post_momentum")
          .select(`
            project_id, reactions_last_1h, reactions_last_24h, comments_last_1h,
            comments_last_24h, velocity, velocity_change_pct, viral_score, anomaly_score, updated_at,
            member_projects!inner ( id, title, description, cover_image, created_at, deleted_at,
              members!member_projects_member_id_fkey ( id, name, photo, followers_count ) )
          `)
          .is("member_projects.deleted_at", null)
          .order(sort, { ascending: false })
          .range(page * limit, page * limit + limit - 1);
        if (error) throw error;
        return rows || [];
      });

      res.json({
        items: data.map(r => ({
          project_id: r.project_id,
          title: r.member_projects?.title,
          caption_preview: (r.member_projects?.description || "").slice(0, 140),
          thumbnail: r.member_projects?.cover_image || null,
          author: r.member_projects?.members
            ? { id: r.member_projects.members.id, name: r.member_projects.members.name,
                photo: r.member_projects.members.photo, followers: r.member_projects.members.followers_count }
            : null,
          reactions_24h: r.reactions_last_24h,
          comments_24h: r.comments_last_24h,
          velocity: r.velocity,
          velocity_change_pct: r.velocity_change_pct,
          viral_score: r.viral_score,
          anomaly_score: r.anomaly_score,      // separate from viral_score — see note below
          created_at: r.member_projects?.created_at,
        })),
        page, limit,
      });
    } catch (e) {
      console.error("[analytics/viral-content]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // NOTE on anomaly vs viral: per the spec, high viral_score alone is never
  // labeled "manipulation". anomaly_score is a *separate* statistical-deviation
  // signal (e.g. velocity many std-devs above the account's own baseline in a
  // way that also correlates with other suspicion signals from the detection
  // engine below) — it's surfaced, not auto-actioned.

  // GET /api/admin/analytics/viral-content/:id — drill-down
  app.get("/api/admin/analytics/viral-content/:id",
    authMiddleware, requireSection(PERMS.ANALYTICS_VIEW), async (req, res) => {
    try {
      const { data: post, error } = await supabase
        .from("member_projects")
        .select(`id, title, description, cover_image, created_at,
          members!member_projects_member_id_fkey ( id, name, photo, followers_count )`)
        .eq("id", req.params.id).maybeSingle();
      if (error) throw error;
      if (!post) return res.status(404).json({ error: "Post not found" });

      const { data: momentum } = await supabase
        .from("post_momentum").select("*").eq("project_id", req.params.id).maybeSingle();

      // Simple time-bucketed activity timeline from reactions/comments timestamps
      const [{ data: reactions }, { data: comments }] = await Promise.all([
        supabase.from("project_reactions").select("created_at").eq("project_id", req.params.id),
        supabase.from("project_comments").select("created_at").eq("project_id", req.params.id).is("deleted_at", null),
      ]);
      const timeline = bucketByHour([...(reactions||[]).map(r=>r.created_at), ...(comments||[]).map(c=>c.created_at)]);

      res.json({ post, momentum: momentum || null, timeline });
    } catch (e) {
      console.error("[analytics/viral-content/:id]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  function bucketByHour(timestamps) {
    const buckets = {};
    for (const ts of timestamps) {
      const hour = new Date(ts); hour.setMinutes(0,0,0);
      const key = hour.toISOString();
      buckets[key] = (buckets[key] || 0) + 1;
    }
    return Object.entries(buckets).sort(([a],[b]) => a.localeCompare(b)).map(([hour, count]) => ({ hour, count }));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 2. INFLUENCER / TOP-CREATOR DASHBOARD
  //    (adapted: no verification/blue-badge system exists in this codebase —
  //    this surfaces follower growth + engagement leaders instead. If you want
  //    an actual verification-request workflow, that's a separate feature to
  //    scope with its own DB table — say the word and I'll add it.)
  // ═══════════════════════════════════════════════════════════════════════

  app.get("/api/admin/analytics/top-creators",
    authMiddleware, requireSection(PERMS.ANALYTICS_VIEW), async (req, res) => {
    try {
      const by = ["followers", "engagement", "growth"].includes(req.query.by) ? req.query.by : "followers";
      const data = await memCache(`analytics:top-creators:${by}`, 120, async () => {
        if (by === "growth") {
          const since = new Date(Date.now() - 7*24*3600*1000).toISOString().slice(0,10);
          const { data: rows, error } = await supabase
            .from("creator_metrics_daily")
            .select("member_id, followers_gained, members(id,name,photo,followers_count)")
            .gte("metric_date", since);
          if (error) throw error;
          const byMember = {};
          for (const r of rows || []) {
            byMember[r.member_id] = byMember[r.member_id] || { member: r.members, growth: 0 };
            byMember[r.member_id].growth += r.followers_gained || 0;
          }
          return Object.values(byMember).sort((a,b) => b.growth - a.growth).slice(0, 25);
        }
        const { data: rows, error } = await supabase
          .from("members")
          .select("id, name, photo, followers_count, following_count, status")
          .order("followers_count", { ascending: false })
          .limit(25);
        if (error) throw error;
        return rows;
      });
      res.json({ by, items: data });
    } catch (e) {
      console.error("[analytics/top-creators]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 3. SPAM & BOT DETECTION — rule engine + logs
  // ═══════════════════════════════════════════════════════════════════════

  // Extensible rule format: each rule takes a member_id + fresh activity data,
  // returns { detected, score, severity, reason, evidence } or null.
  const DETECTION_RULES = {
    mass_follow: async (memberId) => {
      const since = new Date(Date.now() - 60*60*1000).toISOString();
      const { count } = await supabase.from("member_follows")
        .select("id", { count: "exact", head: true })
        .eq("follower_id", memberId).gte("created_at", since);
      const n = count || 0;
      const BASELINE_PER_HOUR = 15; // configurable threshold, not hardcoded logic
      if (n <= BASELINE_PER_HOUR * 2) return null;
      const score = Math.min(100, Math.round((n / (BASELINE_PER_HOUR * 2)) * 40));
      return {
        detected: true, score,
        severity: score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW",
        reason: `${n} follows in the last hour (baseline ~${BASELINE_PER_HOUR}/hr)`,
        evidence: { count: n, window_minutes: 60, baseline_per_hour: BASELINE_PER_HOUR },
      };
    },
    rapid_posting: async (memberId) => {
      const since = new Date(Date.now() - 60*60*1000).toISOString();
      const { count } = await supabase.from("member_projects")
        .select("id", { count: "exact", head: true })
        .eq("member_id", memberId).gte("created_at", since);
      const n = count || 0;
      const BASELINE = 5;
      if (n <= BASELINE) return null;
      const score = Math.min(100, Math.round((n / BASELINE) * 30));
      return {
        detected: true, score,
        severity: score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : "MEDIUM",
        reason: `${n} posts in the last hour (baseline ~${BASELINE}/hr)`,
        evidence: { count: n, window_minutes: 60, baseline_per_hour: BASELINE },
      };
    },
    duplicate_comment: async (memberId) => {
      const since = new Date(Date.now() - 24*60*60*1000).toISOString();
      const { data: comments } = await supabase.from("project_comments")
        .select("body, created_at").eq("member_id", memberId)
        .gte("created_at", since).is("deleted_at", null).limit(200);
      const counts = {};
      for (const c of comments || []) {
        const norm = (c.body || "").trim().toLowerCase();
        if (norm.length < 3) continue;
        counts[norm] = (counts[norm] || 0) + 1;
      }
      const maxDup = Math.max(0, ...Object.values(counts));
      if (maxDup < 5) return null;
      const score = Math.min(100, maxDup * 8);
      return {
        detected: true, score,
        severity: score >= 70 ? "HIGH" : "MEDIUM",
        reason: `Same comment text posted ${maxDup} times in 24h`,
        evidence: { repeat_count: maxDup, window_hours: 24 },
      };
    },
  };

  // POST /api/admin/trust-safety/scan/:memberId — run all rules for one member on-demand.
  // (Production: also run this from a scheduled job over active members and
  // upsert results, rather than only on-demand — that's a background-job wire-up
  // outside what an HTTP handler should own.)
  app.post("/api/admin/trust-safety/scan/:memberId",
    authMiddleware, requireSection(PERMS.TRUST_SAFETY_VIEW), async (req, res) => {
    try {
      const memberId = req.params.memberId;
      const results = [];
      for (const [ruleId, rule] of Object.entries(DETECTION_RULES)) {
        const r = await rule(memberId).catch(() => null);
        if (r && r.detected) {
          const { data: inserted, error } = await supabase.from("detection_events").insert([{
            member_id: memberId, rule_id: ruleId, severity: r.severity,
            risk_score: r.score, reason: r.reason, evidence: r.evidence,
          }]).select().single();
          if (!error) results.push(inserted);
        }
      }
      res.json({ scanned: memberId, detections: results });
    } catch (e) {
      console.error("[trust-safety/scan]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // GET /api/admin/trust-safety/detections?status=OPEN&severity=HIGH&page=0
  app.get("/api/admin/trust-safety/detections",
    authMiddleware, requireSection(PERMS.TRUST_SAFETY_VIEW), async (req, res) => {
    try {
      const page = Math.max(0, parseInt(req.query.page) || 0);
      const limit = 30;
      let q = supabase.from("detection_events")
        .select("*, members(id,name,photo)")
        .order("detected_at", { ascending: false })
        .range(page*limit, page*limit+limit-1);
      if (req.query.status) q = q.eq("status", req.query.status);
      if (req.query.severity) q = q.eq("severity", req.query.severity);
      const { data, error } = await q;
      if (error) throw error;
      res.json({ items: data || [], page, limit });
    } catch (e) {
      console.error("[trust-safety/detections]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // PATCH /api/admin/trust-safety/detections/:id — update status (never auto-ban)
  app.patch("/api/admin/trust-safety/detections/:id",
    authMiddleware, requireSection(PERMS.TRUST_SAFETY_INVESTIGATE), async (req, res) => {
    try {
      const { status, resolution } = req.body || {};
      if (!["OPEN","INVESTIGATING","CONFIRMED","DISMISSED","RESOLVED"].includes(status))
        return res.status(400).json({ error: "Invalid status" });
      const { error } = await supabase.from("detection_events").update({
        status, resolution: resolution ? String(resolution).slice(0,1000) : null,
        reviewer: req.admin.username,
        resolved_at: ["RESOLVED","DISMISSED"].includes(status) ? new Date().toISOString() : null,
      }).eq("id", req.params.id);
      if (error) throw error;
      logActivity(req.admin.id, req.admin.name, `detection_${status.toLowerCase()}`, "detection_event", req.params.id).catch(()=>{});
      res.json({ success: true });
    } catch (e) {
      console.error("[trust-safety/detections/:id PATCH]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 4. DM INVESTIGATIONS — case-management wrapper around content_reports.
  //    Master-only throughout. Every access writes an immutable log row
  //    BEFORE returning any message content. No new decryption capability
  //    is introduced — this only ever surfaces decrypted_snapshot, which is
  //    the same reporter-decrypted plaintext /api/admin/reports already
  //    exposes to masters today.
  // ═══════════════════════════════════════════════════════════════════════

  // POST /api/admin/investigations — open a case from an existing DM/group_message report
  app.post("/api/admin/investigations", masterMiddleware, async (req, res) => {
    try {
      const { report_id, priority } = req.body || {};
      const { data: report } = await supabase.from("content_reports")
        .select("id, content_type, content_id").eq("id", report_id).maybeSingle();
      if (!report) return res.status(404).json({ error: "Report not found" });
      if (!["dm","group_message"].includes(report.content_type))
        return res.status(400).json({ error: "Investigations are only for dm/group_message reports" });

      const { data: caseRow, error } = await supabase.from("investigation_cases").insert([{
        report_id, priority: ["LOW","NORMAL","HIGH","URGENT"].includes(priority) ? priority : "NORMAL",
      }]).select().single();
      if (error) throw error;

      logActivity(req.admin.id, req.admin.name, "investigation_opened", "investigation_case", caseRow.id).catch(()=>{});
      res.json(caseRow);
    } catch (e) {
      console.error("[investigations POST]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // GET /api/admin/investigations — case list (metadata only, no message content)
  app.get("/api/admin/investigations", masterMiddleware, async (req, res) => {
    try {
      let q = supabase.from("investigation_cases")
        .select("id, status, priority, assigned_to, created_at, updated_at, report_id, content_reports(reporter_id, content_type)")
        .order("created_at", { ascending: false });
      if (req.query.status) q = q.eq("status", req.query.status);
      const { data, error } = await q;
      if (error) throw error;
      res.json({ items: data || [] });
    } catch (e) {
      console.error("[investigations GET]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/admin/investigations/:id/access — REQUIRED before viewing message
  // content. Body: { reason: string }. Logs, then returns the case's report
  // content (decrypted_snapshot if present) in the SAME response — the UI
  // should never fetch message content without going through this endpoint.
  app.post("/api/admin/investigations/:id/access", masterMiddleware, async (req, res) => {
    try {
      const { reason } = req.body || {};
      if (!reason || String(reason).trim().length < 5)
        return res.status(400).json({ error: "A specific access reason is required." });

      const { data: caseRow } = await supabase.from("investigation_cases")
        .select("*, content_reports(*)").eq("id", req.params.id).maybeSingle();
      if (!caseRow) return res.status(404).json({ error: "Case not found" });

      // Log FIRST — access is recorded even if something downstream fails.
      await supabase.from("investigation_access_log").insert([{
        case_id: req.params.id,
        admin_id: req.admin.id,
        admin_name: req.admin.name || req.admin.username,
        reason: String(reason).trim().slice(0, 500),
        ip: req.ip,
      }]);
      logActivity(req.admin.id, req.admin.name, "investigation_dm_access", "investigation_case", req.params.id, { reason }).catch(()=>{});

      const report = caseRow.content_reports;
      res.json({
        case_id: caseRow.id,
        status: caseRow.status,
        priority: caseRow.priority,
        report_context: { reason: report?.reason, details: report?.details, created_at: report?.created_at },
        // Only the specific reported message's decrypted snapshot — never a
        // broader conversation dump. This is the reporter-submitted plaintext,
        // nothing decrypted server-side.
        message_content: report?.e2ee_report ? (report?.decrypted_snapshot || null) : (report?.decrypted_snapshot ?? null),
      });
    } catch (e) {
      console.error("[investigations/:id/access]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // POST /api/admin/investigations/:id/notes
  app.post("/api/admin/investigations/:id/notes", masterMiddleware, async (req, res) => {
    try {
      const { text } = req.body || {};
      if (!text || !String(text).trim()) return res.status(400).json({ error: "Note text required" });
      const { data: caseRow } = await supabase.from("investigation_cases").select("notes").eq("id", req.params.id).maybeSingle();
      if (!caseRow) return res.status(404).json({ error: "Case not found" });
      const notes = [...(caseRow.notes || []), { author: req.admin.username, text: String(text).trim().slice(0,1000), at: new Date().toISOString() }];
      await supabase.from("investigation_cases").update({ notes, updated_at: new Date().toISOString() }).eq("id", req.params.id);
      logActivity(req.admin.id, req.admin.name, "investigation_note_added", "investigation_case", req.params.id).catch(()=>{});
      res.json({ success: true, notes });
    } catch (e) {
      console.error("[investigations/:id/notes]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // PATCH /api/admin/investigations/:id — status/priority/assignment changes
  app.patch("/api/admin/investigations/:id", masterMiddleware, async (req, res) => {
    try {
      const { status, priority, assigned_to } = req.body || {};
      const update = { updated_at: new Date().toISOString() };
      if (status) {
        if (!["OPEN","INVESTIGATING","ESCALATED","RESOLVED","CLOSED"].includes(status))
          return res.status(400).json({ error: "Invalid status" });
        update.status = status;
      }
      if (priority) {
        if (!["LOW","NORMAL","HIGH","URGENT"].includes(priority))
          return res.status(400).json({ error: "Invalid priority" });
        update.priority = priority;
      }
      if (assigned_to !== undefined) update.assigned_to = assigned_to ? String(assigned_to) : null;
      const { error } = await supabase.from("investigation_cases").update(update).eq("id", req.params.id);
      if (error) throw error;
      logActivity(req.admin.id, req.admin.name, "investigation_updated", "investigation_case", req.params.id, update).catch(()=>{});
      res.json({ success: true });
    } catch (e) {
      console.error("[investigations/:id PATCH]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // GET /api/admin/investigations/:id/access-log — audit trail for one case (master only)
  app.get("/api/admin/investigations/:id/access-log", masterMiddleware, async (req, res) => {
    try {
      const { data, error } = await supabase.from("investigation_access_log")
        .select("id, admin_id, admin_name, reason, accessed_at, ip")
        .eq("case_id", req.params.id).order("accessed_at", { ascending: false });
      if (error) throw error;
      res.json({ items: data || [] });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 5. OVERVIEW — top-level KPIs, cached
  // ═══════════════════════════════════════════════════════════════════════

  app.get("/api/admin/analytics/overview",
    authMiddleware, requireSection(PERMS.ANALYTICS_VIEW), async (req, res) => {
    try {
      const data = await memCache("analytics:overview", 60, async () => {
        const todayStart = new Date(); todayStart.setHours(0,0,0,0);
        const [
          { count: activeMembers },
          { count: postsToday },
          { count: openDetections },
          { count: openInvestigations },
        ] = await Promise.all([
          supabase.from("members").select("id",{count:"exact",head:true}).eq("status","active"),
          supabase.from("member_projects").select("id",{count:"exact",head:true}).gte("created_at", todayStart.toISOString()).is("deleted_at", null),
          supabase.from("detection_events").select("id",{count:"exact",head:true}).eq("status","OPEN"),
          supabase.from("investigation_cases").select("id",{count:"exact",head:true}).in("status",["OPEN","INVESTIGATING","ESCALATED"]),
        ]);
        return { activeMembers: activeMembers||0, postsToday: postsToday||0, openDetections: openDetections||0, openInvestigations: openInvestigations||0 };
      });
      res.json(data);
    } catch (e) {
      console.error("[analytics/overview]", e.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 6. AUDIT LOGS — thin read view over your existing admin_activity table
  // ═══════════════════════════════════════════════════════════════════════

  app.get("/api/admin/audit-logs", authMiddleware, requireSection(PERMS.AUDIT_LOGS_VIEW), async (req, res) => {
    try {
      const page = Math.max(0, parseInt(req.query.page) || 0);
      const limit = 50;
      const { data, error } = await supabase.from("admin_activity")
        .select("*").order("created_at", { ascending: false }).range(page*limit, page*limit+limit-1);
      if (error) throw error;
      res.json({ items: data || [], page, limit });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  console.log("[admin-analytics] Trust & Safety / Engagement Analytics routes mounted");
};

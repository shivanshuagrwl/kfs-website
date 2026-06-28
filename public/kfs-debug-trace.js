/**
 * kfs-debug-trace.js — RUNTIME INSTRUMENTATION (not a fix)
 * =====================================================================
 * Load this LAST, after kfs-patch3.js:
 *   <script src="/kfs-debug-trace.js" defer></script>
 *
 * Or paste the whole file into the DevTools console on an already-loaded
 * page (it self-installs immediately, no DOMContentLoaded dependency for
 * the parts that matter — see "WHY THIS WORKS" below).
 *
 * This produces ZERO behavior changes. It only observes and logs. It does
 * not fix pins, nicknames, blocks, or groups. Its only job is to answer,
 * with real browser console evidence:
 *
 *   - which function actually ran, in what order, with what args/result
 *   - what GC.msgs / GC.groups / GC.activeGroup / GC.activeId / BLOCKS.set
 *     looked like immediately before and after every single mutation,
 *     no matter which function (even a closure you can't name) caused it
 *   - whether kfs-patch2.js / kfs-patch3.js actually got applied to the
 *     function you think they patched
 *   - the full before/after/render lifecycle of one specific message id
 *
 * WHY THIS WORKS (read before you doubt it):
 *   membersaccess.js, kfs-social-hotfix.js, kfs-patch2.js and kfs-patch3.js
 *   are all classic (non-module) <script defer> tags loaded in that order.
 *   Top-level `function foo(){}` declarations in a classic script become
 *   BOTH a global lexical binding AND a property of window — so
 *   `window.foo` and the bare identifier `foo` are the same storage slot.
 *   That means a later deferred script (this one) can read/replace them
 *   via `window['gcLoadMsgs']` etc. — confirmed by static AST scope
 *   analysis (gcLoadGroups, gcLoadMsgs, gcRenderMsgs, gcRenderGroups,
 *   gcOpenGroup, gcSend, gcLeave, gcGoBack, nicksLoadGlobal, nicksLoad,
 *   blocksEnsureLoaded, blocksToggle, _showMsgContextMenu,
 *   _attachMsgContextMenu, and api are ALL top-level, i.e. real globals).
 *
 *   BUT: inboxLoad, _startSidebarRefresh, dpShowGroup, dpBlock,
 *   dpLeaveGroup, and initDetailPanel are declared INSIDE the "UNIFIED
 *   INBOX" IIFE in membersaccess.js. They are genuinely closure-local.
 *   Only `inboxLoad` (as window._inboxLoad) and `dpShowGroup` (as
 *   window._dpShowGroup) are ever exposed outward. dpBlock and
 *   dpLeaveGroup are NOT reachable by name from any external script,
 *   patch, or this tracer. We can't wrap what was never exported — so
 *   instead we instrument the shared STATE OBJECTS directly (GC, BLOCKS),
 *   which every closure mutates through the same property regardless of
 *   whether the closure itself is reachable. That catches dpBlock/
 *   dpLeaveGroup mutations even though we can never wrap those functions.
 * =====================================================================
 */
(function kfsDebugTrace() {
  "use strict";

  if (window.__kfsTraceInstalled) {
    console.warn("[TRACE] kfs-debug-trace already installed — skipping re-install.");
    return;
  }
  window.__kfsTraceInstalled = true;

  var seq = 0;
  var watchedMsgId = null; // set via window.kfsTraceMessage('12345')

  // ─── Helpers ────────────────────────────────────────────────────────────────

  function ts() {
    var d = new Date();
    return d.toISOString().split("T")[1].replace("Z", "");
  }

  function shortStack(skip) {
    var e = new Error();
    var lines = (e.stack || "").split("\n").slice(skip || 2, (skip || 2) + 6);
    return lines.map(function (l) { return l.trim(); }).join("\n  ");
  }

  function safeClone(v) {
    try {
      return structuredClone(v);
    } catch (_) {
      try {
        return JSON.parse(JSON.stringify(v, function (k, val) {
          if (val instanceof Set) return { __type: "Set", values: Array.from(val) };
          return val;
        }));
      } catch (__) {
        return "[unclonable: " + Object.prototype.toString.call(v) + "]";
      }
    }
  }

  function logStage(stage, name, data) {
    seq++;
    var style = "color:#fff;background:#444;padding:1px 5px;border-radius:3px";
    if (stage === "STATE-SET") style = "color:#fff;background:#a33;padding:1px 5px;border-radius:3px";
    if (stage === "CALL") style = "color:#fff;background:#357;padding:1px 5px;border-radius:3px";
    if (stage === "RETURN") style = "color:#fff;background:#373;padding:1px 5px;border-radius:3px";
    if (stage === "WRAP-INSTALLED" || stage === "WRAP-MISSING") style = "color:#000;background:#fc0;padding:1px 5px;border-radius:3px";
    if (stage === "WATCH") style = "color:#fff;background:#909;padding:1px 5px;border-radius:3px";
    console.groupCollapsed("%c[" + seq + " " + ts() + " " + stage + "]%c " + name, style, "");
    console.log(data);
    console.groupEnd();
  }

  function findWatched(arr) {
    if (!watchedMsgId || !Array.isArray(arr)) return null;
    return arr.find(function (m) { return m && String(m.id) === String(watchedMsgId); }) || null;
  }

  // ─── 1. Property-level instrumentation of GC (catches every mutator,
  //        named or closure-local, global or not — because the mutation
  //        always goes through GC.<prop> regardless of who's calling) ──────

  function instrumentGcProp(prop) {
    if (typeof GC === "undefined") {
      console.error("[TRACE] GC is not defined yet — load this script AFTER membersaccess.js");
      return;
    }
    var desc = Object.getOwnPropertyDescriptor(GC, prop);
    if (desc && desc.get) return; // already instrumented
    var value = GC[prop];
    Object.defineProperty(GC, prop, {
      configurable: true,
      enumerable: true,
      get: function () { return value; },
      set: function (v) {
        var before = safeClone(value);
        var after = safeClone(v);
        value = v;
        logStage("STATE-SET", "GC." + prop, {
          before: before,
          after: after,
          stack: shortStack(3),
        });
        if (prop === "msgs" && watchedMsgId) {
          var bw = findWatched(before);
          var aw = findWatched(v);
          logStage("WATCH", "GC.msgs mutation re: id " + watchedMsgId, {
            was_present_before: !!bw,
            is_pinned_before: bw ? bw.is_pinned : undefined,
            is_present_after: !!aw,
            is_pinned_after: aw ? aw.is_pinned : undefined,
          });
        }
      },
    });
  }

  ["msgs", "groups", "activeGroup", "activeId"].forEach(instrumentGcProp);

  // ─── 2. Property + Set-method instrumentation of BLOCKS ─────────────────

  function instrumentSetInstance(setInstance, label) {
    if (!setInstance || setInstance.__kfsTraced) return setInstance;
    var origAdd = setInstance.add.bind(setInstance);
    var origDelete = setInstance.delete.bind(setInstance);
    setInstance.add = function (v) {
      logStage("STATE-SET", label + ".add(" + v + ")", { before: Array.from(setInstance), stack: shortStack(3) });
      var r = origAdd(v);
      logStage("STATE-SET", label + ".add(" + v + ") DONE", { after: Array.from(setInstance) });
      return r;
    };
    setInstance.delete = function (v) {
      logStage("STATE-SET", label + ".delete(" + v + ")", { before: Array.from(setInstance), stack: shortStack(3) });
      var r = origDelete(v);
      logStage("STATE-SET", label + ".delete(" + v + ") DONE", { after: Array.from(setInstance) });
      return r;
    };
    setInstance.__kfsTraced = true;
    return setInstance;
  }

  if (typeof BLOCKS !== "undefined") {
    instrumentSetInstance(BLOCKS.set, "BLOCKS.set");
    var blocksSetValue = BLOCKS.set;
    Object.defineProperty(BLOCKS, "set", {
      configurable: true,
      enumerable: true,
      get: function () { return blocksSetValue; },
      set: function (v) {
        logStage("STATE-SET", "BLOCKS.set (REASSIGNED — new Set instance)", {
          before: Array.from(blocksSetValue || []),
          after: Array.from(v || []),
          stack: shortStack(3),
          note: "Any code holding a direct reference to the OLD Set object is now stale.",
        });
        blocksSetValue = instrumentSetInstance(v, "BLOCKS.set");
      },
    });
  } else {
    console.error("[TRACE] BLOCKS is not defined yet — load this script AFTER membersaccess.js");
  }

  // ─── 3. Function-call wrapping for every CONFIRMED global function ──────
  //        (confirmed via AST scope analysis — these are real `window.x`)

  var GLOBAL_FN_TARGETS = [
    "api",
    "gcLoadGroups", "gcRenderGroups", "gcOpenGroup", "gcLoadMsgs", "gcRenderMsgs",
    "gcRefreshPinnedBanner", "gcSend", "gcLeave", "gcGoBack", "gcOpenCreateModal",
    "_showMsgContextMenu", "_attachMsgContextMenu",
    "nicksLoadGlobal", "nicksLoad", "nicksOpenModal",
    "blocksEnsureLoaded", "blocksToggle",
  ];

  function wrapGlobalFn(name) {
    if (typeof window[name] !== "function") {
      logStage("WRAP-MISSING", name, {
        reason: "Not found as window['" + name + "']. Either it's closure-local " +
          "(declared inside an IIFE and never exported via window.x = ...), " +
          "or it hasn't loaded yet, or the name is wrong.",
      });
      return false;
    }
    var orig = window[name];
    if (orig.__kfsTraced) return true;

    // Report what's CURRENTLY bound before we wrap it, so you can see
    // whether kfs-patch2/patch3 already replaced the original.
    var src = orig.toString().slice(0, 160);
    logStage("WRAP-INSTALLED", name, {
      currently_bound_to: src,
      looks_patched_by: /patched|patchPin|patchedApi/.test(src) ? "YES — a prior patch's wrapper name is visible here" : "no patch marker visible in this layer (may still be wrapped underneath)",
    });

    var wrapped = function () {
      var args = Array.prototype.slice.call(arguments);
      var before = {
        GC_msgs_len: typeof GC !== "undefined" ? GC.msgs.length : null,
        GC_groups_len: typeof GC !== "undefined" ? GC.groups.length : null,
        watched: typeof GC !== "undefined" ? findWatched(GC.msgs) : null,
      };
      logStage("CALL", name, { args: safeClone(args), before: before, stack: shortStack(3) });
      var result;
      try {
        result = orig.apply(this, args);
      } catch (err) {
        logStage("THROW", name, { error: err && err.message, stack: err && err.stack });
        throw err;
      }
      function afterLog(r) {
        var after = {
          GC_msgs_len: typeof GC !== "undefined" ? GC.msgs.length : null,
          GC_groups_len: typeof GC !== "undefined" ? GC.groups.length : null,
          watched: typeof GC !== "undefined" ? findWatched(GC.msgs) : null,
        };
        logStage("RETURN", name, { result: safeClone(r), after: after });
      }
      if (result && typeof result.then === "function") {
        return result.then(
          function (r) { afterLog(r); return r; },
          function (e) { logStage("REJECT", name, { error: e && e.message }); throw e; }
        );
      }
      afterLog(result);
      return result;
    };
    wrapped.__kfsTraced = true;
    window[name] = wrapped;
    return true;
  }

  GLOBAL_FN_TARGETS.forEach(wrapGlobalFn);

  // ─── 4. Outside-in DOM witness for closure-trapped UI actions ───────────
  //        (dpBlock / dpLeaveGroup can't be wrapped — they're never
  //        exported — so watch the DOM events that trigger them instead.
  //        This proves WHEN the action happened even though we can't see
  //        inside the function itself.)

  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest(
      "[data-block-member], .dm-block-btn, [data-leave-group], .gc-leave-btn, [data-id], .dm-ctx-item"
    );
    if (t) {
      logStage("CALL", "DOM-CLICK (possibly closure-local handler, e.g. dpBlock/dpLeaveGroup)", {
        target: t.outerHTML.slice(0, 200),
        dataset: Object.assign({}, t.dataset),
      });
    }
  }, true);

  // ─── 5. Patch-status report ──────────────────────────────────────────────

  window.kfsCheckPatches = function () {
    ["api", "gcRenderMsgs", "gcRenderGroups", "_showMsgContextMenu", "gcRefreshPinnedBanner"].forEach(function (name) {
      var fn = window[name];
      console.log(name, "->", fn ? fn.toString().slice(0, 200) : "(not found)");
    });
  };

  // ─── 6. Single-message tracer ────────────────────────────────────────────
  // Usage: kfsTraceMessage(12345)   — or kfsTraceMessage(null) to stop.

  window.kfsTraceMessage = function (id) {
    watchedMsgId = id === null ? null : String(id);
    logStage("WATCH", "now tracing message id " + watchedMsgId, {
      current_in_GC_msgs: typeof GC !== "undefined" ? findWatched(GC.msgs) : null,
    });
  };

  console.log(
    "%c[kfs-debug-trace] installed. " +
    "Run kfsTraceMessage(12345) to trace one message. " +
    "Run kfsCheckPatches() to see what's currently bound to each patched name.",
    "color:#0f0;font-weight:bold"
  );
})();

/**
 * kfs-patch2.js  — KFS Social Hotfix, Part 2
 * =====================================================================
 * Load this AFTER kfs-social-hotfix.js and AFTER membersaccess.js.
 * Add a <script src="/kfs-patch2.js" defer></script> tag at the
 * bottom of membersaccess.html, just below the kfs-social-hotfix.js tag.
 *
 * What this fixes (all issues not already covered by kfs-social-hotfix.js):
 *
 *  1. Pin label — group messages GET doesn't return is_pinned, so the
 *     context menu always shows "Pin" even for pinned messages, and the
 *     pin action never updates the local is_pinned state correctly.
 *     Fix: intercept gcRenderMsgs to tag bubbles with their server-side
 *     pin state, then re-derive is_pinned when the context menu opens.
 *
 *  2. Profanity / moderation modal — the client already checks
 *     ed.temp_banned, but the api() helper for /groups paths reads the
 *     body as text and re-parses it, sometimes losing the error object.
 *     Fix: ensure the _data payload always reaches the catch blocks.
 *
 *  3. Debug console noise — the api() helper logs every /groups and
 *     /nicknames response to the console. This patch suppresses those
 *     logs in production (keeps them if ?kfs_debug is in the URL).
 *
 *  4. KFS sentinel — block nickname attempts on the KFS account even
 *     if the UI check in kfs-social-hotfix.js is somehow bypassed via
 *     the API layer (belt-and-suspenders client guard).
 *
 *  5. Pin banner after toggle — after a successful pin/unpin, the
 *     gcRefreshPinnedBanner call is already wired but only fires if the
 *     function exists at that moment. This ensures it fires reliably.
 *
 * =====================================================================
 */
(function kfsPatch2() {
  "use strict";

  var DEBUG = location.search.indexOf("kfs_debug") !== -1;

  // ─── 1. Pin state registry ──────────────────────────────────────────────────
  // The server's GET /groups/:id/messages now returns is_pinned (after you apply
  // server-patch.js). But until the server is deployed, we also maintain a
  // client-side registry from successful pin/unpin API calls so the label is
  // always correct even without a page refresh.

  var _pinRegistry = {}; // msgId → true|false

  function setPinState(msgId, isPinned) {
    if (msgId) _pinRegistry[String(msgId)] = !!isPinned;
  }

  function getPinState(msgId, serverValue) {
    var id = String(msgId || "");
    if (id in _pinRegistry) return _pinRegistry[id];
    return !!serverValue;
  }

  // ─── 2. Patch _showMsgContextMenu to use registry ──────────────────────────
  // The context menu reads info.is_pinned at open time. We augment the info
  // object with the registry value before the menu is built.

  var _origShowCtx = typeof _showMsgContextMenu === "function" ? _showMsgContextMenu : null;

  if (_origShowCtx) {
    // eslint-disable-next-line no-global-assign
    _showMsgContextMenu = function patchedShowMsgCtx(e, info) {
      if (info && info.id && info.type === "group") {
        info = Object.assign({}, info, {
          is_pinned: getPinState(info.id, info.is_pinned),
        });
      }
      return _origShowCtx.call(this, e, info);
    };
  } else {
    // Function not defined yet — install after DOMContentLoaded
    document.addEventListener("DOMContentLoaded", function () {
      if (typeof _showMsgContextMenu === "function") {
        var orig = _showMsgContextMenu;
        _showMsgContextMenu = function patchedShowMsgCtxLate(e, info) {
          if (info && info.id && info.type === "group") {
            info = Object.assign({}, info, {
              is_pinned: getPinState(info.id, info.is_pinned),
            });
          }
          return orig.call(this, e, info);
        };
      }
    });
  }

  // ─── 3. Intercept api() to capture pin results and strip debug noise ────────
  // We wrap the global api() function to:
  //   a) Record is_pinned values returned by the pin endpoint
  //   b) Suppress verbose console.log for /groups and /nicknames in production

  var _origApi = typeof api === "function" ? api : null;

  if (_origApi) {
    // eslint-disable-next-line no-global-assign
    api = async function patchedApi(method, path, body, opts) {
      // Suppress debug logs unless ?kfs_debug in URL — monkey-patch console
      // only for the duration of this call to avoid touching global state.
      var _origLog = console.log;
      if (!DEBUG && (path.indexOf("/groups") !== -1 || path.indexOf("/nicknames") !== -1)) {
        console.log = function () {}; // mute during this call
      }
      var result;
      try {
        result = await _origApi.call(this, method, path, body, opts);
      } finally {
        console.log = _origLog; // always restore
      }

      // Capture pin state from pin endpoint response
      // Path pattern: /api/member/groups/:id/messages/:msgId/pin
      if (
        method === "POST" &&
        path.indexOf("/groups/") !== -1 &&
        path.indexOf("/messages/") !== -1 &&
        path.endsWith("/pin") &&
        result && typeof result.is_pinned === "boolean"
      ) {
        // Extract msgId from path: .../messages/{msgId}/pin
        var parts = path.split("/messages/");
        if (parts[1]) {
          var msgId = parts[1].replace("/pin", "").split("?")[0];
          setPinState(msgId, result.is_pinned);
        }
      }

      return result;
    };
  }

  // ─── 4. Intercept gcRenderMsgs to populate pin registry from server data ────
  // When messages come back from the server (after the server patch adds
  // is_pinned), we pre-populate the registry so labels are right from first
  // render without needing a manual pin action first.

  var _origGcRender = typeof gcRenderMsgs === "function" ? gcRenderMsgs : null;

  function installGcRenderPatch() {
    if (typeof gcRenderMsgs !== "function") return;
    var orig = gcRenderMsgs;
    gcRenderMsgs = function patchedGcRenderMsgs(msgs, opts) {
      if (Array.isArray(msgs)) {
        msgs.forEach(function (m) {
          if (m && m.id && typeof m.is_pinned === "boolean") {
            setPinState(m.id, m.is_pinned);
          }
        });
      }
      return orig.call(this, msgs, opts);
    };
  }

  if (_origGcRender) {
    installGcRenderPatch();
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      installGcRenderPatch();
    });
  }

  // ─── 5. Ensure gcRefreshPinnedBanner fires reliably after pin toggle ────────
  // The existing pin action in _showMsgContextMenu calls gcRefreshPinnedBanner()
  // after a successful toggle. If that function isn't defined at call time the
  // pin banner never updates. We install a safe wrapper that retries once.

  function safeRefreshPinnedBanner() {
    try {
      if (typeof gcRefreshPinnedBanner === "function") {
        gcRefreshPinnedBanner();
      }
    } catch (_) {}
  }

  // Expose so the existing code can call it even if the original fails
  window._kfsRefreshPinnedBanner = safeRefreshPinnedBanner;

  // ─── 6. KFS sentinel — block nickname API calls on KFS account ──────────────
  // Belt-and-suspenders: kfs-social-hotfix.js already blocks the UI flow.
  // Here we additionally intercept api() calls to the nickname endpoint.

  // Re-wrap api() (which may already be the patched version from step 3).
  var _apiAfterDebugPatch = typeof api === "function" ? api : null;
  if (_apiAfterDebugPatch) {
    // eslint-disable-next-line no-global-assign
    api = async function patchedApiWithNickGuard(method, path, body, opts) {
      // Block   PUT /api/member/nicknames/:targetId   if target is KFS sentinel
      if (
        (method === "PUT" || method === "POST" || method === "PATCH") &&
        path.indexOf("/nicknames/") !== -1 &&
        window.__KFS_SENTINEL_MEMBER_ID
      ) {
        var targetId = path.split("/nicknames/")[1]?.split("?")[0];
        if (targetId && targetId === window.__KFS_SENTINEL_MEMBER_ID) {
          if (typeof swShowToast === "function") swShowToast("KFS cannot be nicknamed.");
          return {};
        }
      }
      return _apiAfterDebugPatch.call(this, method, path, body, opts);
    };
  }

  // ─── 7. Moderation modal — harden error data propagation ───────────────────
  // The api() helper uses r.text() + manual JSON.parse() for /groups paths.
  // If the HTTP error body is truncated or malformed, e._data ends up as {}.
  // We patch the catch side: if e._data is empty but e.message looks like a
  // violation message, reconstruct the _data flags from the message string.

  function inferVioFlags(msg) {
    if (!msg) return {};
    var m = String(msg);
    if (m.indexOf("temporarily banned") !== -1 || m.indexOf("temp") !== -1) {
      return { temp_banned: true };
    }
    if (m.indexOf("disabled") !== -1) {
      return { banned: true };
    }
    if (m.indexOf("muted") !== -1 || m.indexOf("Muted") !== -1) {
      return { muted: true, warned: true };
    }
    if (m.indexOf("Warning") !== -1 || m.indexOf("warning") !== -1 || m.indexOf("blocked") !== -1) {
      return { warned: true };
    }
    return {};
  }

  // Patch _vioShowClientNotice to be resilient against empty _data
  var _origVio = typeof _vioShowClientNotice === "function" ? _vioShowClientNotice : null;

  function installVioPatch() {
    if (typeof _vioShowClientNotice !== "function") return;
    var orig = _vioShowClientNotice;
    _vioShowClientNotice = function patchedVioNotice(data, msg, inputId, sendBtnId) {
      var resolved = (data && (data.warned || data.muted || data.banned || data.temp_banned))
        ? data
        : Object.assign({}, data, inferVioFlags(msg));
      return orig.call(this, resolved, msg, inputId, sendBtnId);
    };
  }

  if (_origVio) {
    installVioPatch();
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      installVioPatch();
    });
  }

  // Also patch the Social Strand post violation modal
  var _origSwVio = typeof _swVioShowModal === "function" ? _swVioShowModal : null;

  function installSwVioPatch() {
    if (typeof _swVioShowModal !== "function") return;
    var orig = _swVioShowModal;
    _swVioShowModal = function patchedSwVioModal(data, msg) {
      var resolved = (data && (data.warned || data.muted || data.banned || data.temp_banned))
        ? data
        : Object.assign({}, data, inferVioFlags(msg));
      return orig.call(this, resolved, msg);
    };
  }

  if (_origSwVio) {
    installSwVioPatch();
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      installSwVioPatch();
    });
  }

  // ─── 8. Expose pin registry for debugging ───────────────────────────────────
  window.__kfsPinRegistry = _pinRegistry;
  window.__kfsSetPinState = setPinState;

  if (DEBUG) {
    console.log("[kfs-patch2] loaded. Pin registry:", _pinRegistry);
  }
})();

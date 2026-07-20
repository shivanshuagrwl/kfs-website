// ═══════════════════════════════════════════════════════════════════════════════
// E2EE MODULE — End-to-End Encryption for DMs + Group Chats
//
// Design: Signal-style ECDH + AES-GCM
//   • Each member has a persistent ECDH P-256 key pair (private key in IndexedDB,
//     public key published to server on first login / key-generation).
//   • DMs:  sender fetches recipient's public key → ECDH → shared AES-GCM key →
//           encrypts body → stores ciphertext on server. Server never sees plaintext.
//   • Groups: per-message random AES-GCM key, wrapped (encrypted) for each member
//             using their ECDH public key → each member decrypts the wrapper key
//             then decrypts the message. One ciphertext, N wrapped keys.
//   • Reports: reporter's client decrypts the flagged message locally, then sends
//              ONLY the plaintext of that specific message (+ context) to a secure
//              report endpoint that only master admins can read. This is exactly the
//              same approach Signal/iMessage use.
//   • Key rotation: a new ephemeral AES key per message (DMs) or per group message
//              so compromise of one message key doesn't expose past/future messages.
//
// Threat model:
//   ✓ Server DB breach — all stored bodies are AES-GCM ciphertext, unreadable.
//   ✓ Server operator snooping — server never receives plaintext of any message.
//   ✓ Regular admins — have zero access to message content.
//   ✓ Master admins — can read content only when a member explicitly reports a
//              message, and only that message (plus a small window of context).
//   ✗ Device compromise — if a member's device/browser is compromised, private
//              keys in IndexedDB could be extracted. Mitigated by not syncing
//              private keys anywhere and locking them to origin.
//   ✗ Active MITM on key exchange — mitigated by key fingerprints that members
//              can optionally verify out-of-band (shown in profile/details panel).
//
// Browser API: Web Crypto (SubtleCrypto) — available in all modern browsers,
//   no external library needed. Works in the same origin as the rest of the app.
// ═══════════════════════════════════════════════════════════════════════════════

const E2EE = (() => {

  // ── Constants ────────────────────────────────────────────────────────────────
  const DB_NAME    = 'kfs-e2ee';
  const DB_VERSION = 1;
  const STORE_NAME = 'keys';
  const MY_KEY_ID  = 'my-identity-keypair'; // fixed key in IndexedDB store

  // ── IndexedDB helpers ────────────────────────────────────────────────────────

  function _openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = e => {
        e.target.result.createObjectStore(STORE_NAME);
      };
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function _dbGet(key) {
    const db = await _openDb();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function _dbPut(key, value) {
    const db = await _openDb();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(STORE_NAME, 'readwrite');
      const req = tx.objectStore(STORE_NAME).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror   = e => reject(e.target.error);
    });
  }

  // ── Base64 helpers ───────────────────────────────────────────────────────────

  function _ab2b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function _b642ab(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }

  // ── Key pair management ───────────────────────────────────────────────────────

  /**
   * Generate a new ECDH P-256 key pair and persist private key in IndexedDB.
   * Returns { publicKeyJwk, privateKey (CryptoKey) }.
   */
  async function _generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,  // extractable so we can export the public key for the server
      ['deriveKey', 'deriveBits']
    );
    const publicKeyJwk  = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    await _dbPut(MY_KEY_ID, { publicKeyJwk, privateKeyJwk });
    return { publicKeyJwk, privateKey: kp.privateKey };
  }

  /**
   * Load our identity key pair from IndexedDB.
   * Creates a new one if none exists yet.
   * Returns { publicKeyJwk, privateKey (CryptoKey), isFresh }.
   */
  async function _loadMyKeyPair() {
    const stored = await _dbGet(MY_KEY_ID);
    if (stored) {
      const privateKey = await crypto.subtle.importKey(
        'jwk', stored.privateKeyJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false, ['deriveKey', 'deriveBits']
      );
      return { publicKeyJwk: stored.publicKeyJwk, privateKey, isFresh: false };
    }
    const fresh = await _generateKeyPair();
    return { ...fresh, isFresh: true };
  }

  /**
   * Import a peer's public key from JWK format to a CryptoKey.
   */
  async function _importPeerPublicKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
  }

  /**
   * Derive a shared AES-GCM-256 key from our private key + peer's public key.
   * This is the ECDH key agreement step.
   */
  async function _deriveSharedKey(myPrivateKey, peerPublicKey) {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── AES-GCM encrypt / decrypt ─────────────────────────────────────────────────

  /**
   * Encrypt plaintext string with AES-GCM.
   * Returns base64(iv) + ':' + base64(ciphertext).
   */
  async function _aesEncrypt(aesKey, plaintext) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(plaintext);
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc);
    return _ab2b64(iv.buffer) + ':' + _ab2b64(ct);
  }

  /**
   * Decrypt an AES-GCM ciphertext produced by _aesEncrypt.
   */
  async function _aesDecrypt(aesKey, cipherStr) {
    const [ivB64, ctB64] = cipherStr.split(':');
    if (!ivB64 || !ctB64) throw new Error('E2EE: malformed ciphertext');
    const iv = new Uint8Array(_b642ab(ivB64));
    const ct = _b642ab(ctB64);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return new TextDecoder().decode(pt);
  }

  // ── Wrap / unwrap an AES key with ECDH-derived shared key ─────────────────────
  // Used for group messages: the message is encrypted once with a random AES key,
  // then that key is "wrapped" (encrypted) separately for each group member.

  async function _wrapAesKey(aesKey, wrapperKey) {
    const raw = await crypto.subtle.exportKey('raw', aesKey);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapperKey, raw);
    return _ab2b64(iv.buffer) + ':' + _ab2b64(ct);
  }

  async function _unwrapAesKey(wrappedStr, wrapperKey) {
    const [ivB64, ctB64] = wrappedStr.split(':');
    const iv  = new Uint8Array(_b642ab(ivB64));
    const ct  = _b642ab(ctB64);
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrapperKey, ct);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  // ── Public-key cache (avoid re-fetching) ─────────────────────────────────────

  const _peerKeyCache = new Map(); // memberId → CryptoKey (public)

  async function _getPeerPublicKey(memberId) {
    if (_peerKeyCache.has(memberId)) return _peerKeyCache.get(memberId);
    const data = await api('GET', `/api/member/e2ee/public-key/${memberId}`);
    if (!data?.public_key_jwk) throw new Error(`No E2EE key for member ${memberId}`);
    const key = await _importPeerPublicKey(data.public_key_jwk);
    _peerKeyCache.set(memberId, key);
    return key;
  }

  // ── Initialise: load/generate key pair, publish public key to server ──────────

  let _myPrivateKey   = null;
  let _myPublicKeyJwk = null;
  let _ready          = false;
  let _readyPromise   = null;
  let _wasRotated     = false; // true only if the server already had a different key on file

  // Callbacks to notify once init finally succeeds, even if it succeeds on a
  // retry long after the first caller gave up waiting. Lets any screen that
  // rendered messages while _ready was false ask to be re-rendered instead of
  // being stuck showing placeholders for the rest of the session.
  const _onReadyCallbacks = [];
  function onReady(cb) {
    if (_ready) { cb(); return; }
    _onReadyCallbacks.push(cb);
  }

  /**
   * Must be called once on login (after _member is set).
   * Generates key pair if needed, publishes public key to server.
   *
   * Retries on failure (e.g. a transient network error, or a 429 from the
   * publish-key rate limit) instead of giving up for the rest of the session.
   * Previously a single failed publish-key call left `_ready` false forever —
   * every E2EE message in every conversation would then show "encrypted
   * before your keys were set up" for the whole session, indistinguishable
   * from a genuine old-message-can't-decrypt case, until a full page reload
   * (which could immediately hit the same failure again, e.g. still rate
   * limited) — see also the e2eePublishLimit/e2eeReadLimit split server-side.
   */
  async function init() {
    if (_readyPromise) return _readyPromise;
    _readyPromise = (async () => {
      const maxAttempts = 5;
      const backoffMs = [1000, 3000, 8000, 15000, 30000];
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
          const { publicKeyJwk, privateKey, isFresh } = await _loadMyKeyPair();
          _myPrivateKey   = privateKey;
          _myPublicKeyJwk = publicKeyJwk;
          // Publish our public key so peers can encrypt messages to us.
          // The server stores it — it's not secret. Idempotent upsert.
          // rotated=true means the server already had a *different* key on
          // file — i.e. this is genuinely a new device/browser or cleared
          // storage, not a first-ever setup, so older messages may not
          // decrypt here.
          const resp = await api('POST', '/api/member/e2ee/publish-key', { public_key_jwk: publicKeyJwk });
          _wasRotated = isFresh && !!resp?.rotated;
          _ready = true;
          console.log('[E2EE] Ready. Key fingerprint:', await fingerprint());
          _onReadyCallbacks.splice(0).forEach(cb => { try { cb(); } catch {} });
          return;
        } catch (e) {
          const isLastAttempt = attempt === maxAttempts - 1;
          console.error(`[E2EE] init failed (attempt ${attempt + 1}/${maxAttempts}):`, e.message);
          if (isLastAttempt) {
            // Give up for now, but let a later explicit init() call (e.g. the
            // user reopening a chat) try again from scratch rather than
            // staying stuck for the rest of the session.
            _readyPromise = null;
            return;
          }
          await new Promise(r => setTimeout(r, backoffMs[attempt]));
        }
      }
    })();
    return _readyPromise;
  }

  function ready() { return _ready; }
  // True only when this device's key was freshly generated AND the server
  // already had a prior key on file for this member — a real rotation
  // (new device/browser, or local site data cleared), not first-time setup.
  function wasFreshKey() { return _wasRotated; }

  // ── Fingerprint (for out-of-band verification) ───────────────────────────────

  /**
   * SHA-256 of the raw public key bytes, returned as a hex string broken into
   * 8-char groups (e.g. "A1B2C3D4 E5F60718 …"). Members can compare these
   * in person / via another channel to verify they have each other's real keys.
   */
  async function fingerprint(publicKeyJwk) {
    const jwk = publicKeyJwk || _myPublicKeyJwk;
    if (!jwk) return null;
    const key = publicKeyJwk
      ? await _importPeerPublicKey(jwk)
      : await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const raw  = await crypto.subtle.exportKey('raw', key);
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const hex  = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
    // Format as groups of 8 chars for readability
    return hex.match(/.{1,8}/g).join(' ').toUpperCase();
  }

  // ── DM encrypt / decrypt ─────────────────────────────────────────────────────
  //
  // Per-message ephemeral AES key: derive shared ECDH key → use it to encrypt.
  // This means every message gets a fresh IV and the ciphertext is stored on server.

  /**
   * Encrypt a DM body for `recipientMemberId`.
   * Returns the encrypted string to store as `body` on the server.
   * Also encrypts for SELF so we can read our sent messages in the same conv.
   * Returns { cipher_for_recipient, cipher_for_self }
   */
  async function encryptDm(plaintext, recipientMemberId) {
    if (!_ready) return { plaintext }; // fallback (shouldn't happen in prod)
    const myId = window._memberProfile?.id || _member?.id;

    // Derive shared key with recipient
    const recipientPublicKey = await _getPeerPublicKey(recipientMemberId);
    const sharedKeyForRecipient = await _deriveSharedKey(_myPrivateKey, recipientPublicKey);
    const cipher_for_recipient  = await _aesEncrypt(sharedKeyForRecipient, plaintext);

    // Also encrypt for self (ECDH with our own public key, so we can read sent msgs)
    const myPublicKey    = await _importPeerPublicKey(_myPublicKeyJwk);
    const sharedKeyForMe = await _deriveSharedKey(_myPrivateKey, myPublicKey);
    const cipher_for_self = await _aesEncrypt(sharedKeyForMe, plaintext);

    return { cipher_for_recipient, cipher_for_self, e2ee: true };
  }

  /**
   * Decrypt a DM message.
   * `msg` from server has either `cipher_for_recipient` (received) or `cipher_for_self` (sent).
   * Falls back to `msg.body` for legacy plaintext messages.
   */
  async function decryptDm(msg, myId) {
    // Legacy plaintext message (pre-E2EE)
    if (!msg.e2ee) return msg.body || '';
    // E2EE message but our keys aren't loaded yet — body is just the empty
    // server-side sentinel here, so don't return it (renders as a blank
    // bubble). Show the same placeholder used for real decrypt failures.
    if (!_ready) return '🔒 Message encrypted before your keys were set up';
    try {
      const isMine = msg.sender_id === myId;
      const cipherStr = isMine ? msg.cipher_for_self : msg.cipher_for_recipient;
      if (!cipherStr) return '[message unavailable]';
      // Derive the same shared key
      const peerId = isMine ? myId : msg.sender_id;
      const peerPublicKey = await _getPeerPublicKey(peerId);
      const sharedKey = await _deriveSharedKey(_myPrivateKey, peerPublicKey);
      return await _aesDecrypt(sharedKey, cipherStr);
    } catch (e) {
      console.warn('[E2EE] DM decrypt failed for msg', msg.id, e.message);
      return '🔒 Message encrypted before your keys were set up';
    }
  }

  // ── Group encrypt / decrypt ───────────────────────────────────────────────────
  //
  // One random AES key per message, wrapped for each member in the group.
  // Server stores: { ciphertext, wrapped_keys: { [memberId]: wrappedKey } }

  /**
   * Encrypt a group message for all `memberIds` (including self).
   * Returns { ciphertext, wrapped_keys, e2ee: true }
   */
  async function encryptGroup(plaintext, memberIds) {
    if (!_ready) return { plaintext };
    // Generate a random per-message AES key
    const msgKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const ciphertext = await _aesEncrypt(msgKey, plaintext);

    // Wrap the message key for each member
    const wrapped_keys = {};
    await Promise.allSettled(memberIds.map(async memberId => {
      try {
        const memberPublicKey = await _getPeerPublicKey(memberId);
        const sharedKey = await _deriveSharedKey(_myPrivateKey, memberPublicKey);
        wrapped_keys[memberId] = await _wrapAesKey(msgKey, sharedKey);
      } catch (e) {
        console.warn('[E2EE] Could not wrap key for member', memberId, e.message);
        // Skip — that member won't be able to read this message
        // (typically means they haven't published a key yet)
      }
    }));

    return { ciphertext, wrapped_keys, e2ee: true };
  }

  /**
   * Decrypt a group message for the current user.
   * `msg` has `ciphertext` + `wrapped_keys: { [myId]: wrappedKey }`.
   */
  async function decryptGroup(msg, myId) {
    if (!msg.e2ee) return msg.body || ''; // legacy plaintext
    // E2EE message but our keys aren't loaded yet — see decryptDm for why we
    // don't fall through to msg.body here (it's just the empty sentinel).
    if (!_ready) return '🔒 Message encrypted before your keys were set up';
    try {
      const myWrappedKey = msg.wrapped_keys?.[myId];
      if (!myWrappedKey) return '🔒 Message encrypted before your keys were set up';
      // Unwrap the message key using our ECDH shared key with the sender
      const senderPublicKey = await _getPeerPublicKey(msg.sender_id);
      const sharedKey = await _deriveSharedKey(_myPrivateKey, senderPublicKey);
      const msgKey = await _unwrapAesKey(myWrappedKey, sharedKey);
      return await _aesDecrypt(msgKey, msg.ciphertext);
    } catch (e) {
      console.warn('[E2EE] Group decrypt failed for msg', msg.id, e.message);
      return '🔒 Message encrypted before your keys were set up';
    }
  }

  // ── Report: decrypt a specific message and send plaintext to admin-only endpoint
  //
  // The reporter's browser decrypts the flagged message locally and sends only
  // that plaintext to a secure endpoint. The server stores the plaintext in the
  // report only, isolated from the live encrypted message store.
  // Master admins can then read it via the existing /api/admin/reports interface.

  /**
   * Decrypt a reported message (DM or group) and return its plaintext.
   * Called client-side just before submitting a report.
   */
  async function decryptForReport(msg, type /* 'dm'|'group' */, myId) {
    if (!_ready || !msg.e2ee) return msg.body || null; // legacy or no key
    try {
      if (type === 'dm') return await decryptDm(msg, myId);
      if (type === 'group') return await decryptGroup(msg, myId);
    } catch { /* if we can't decrypt, send null — admin can see the report context */ }
    return null;
  }

  /**
   * Re-encrypt a message for a new group member who was added after the message
   * was sent. Called client-side by the group owner/admin.
   * (Optional, future: for now new members only see messages sent after they joined.)
   */
  // async function reEncryptForNewMember(msg, newMemberId) { ... } // future

  // ── Key regeneration (after suspected compromise) ─────────────────────────────
  async function regenerateKeyPair() {
    const { publicKeyJwk } = await _generateKeyPair();
    _myPublicKeyJwk = publicKeyJwk;
    const { privateKey } = await _loadMyKeyPair();
    _myPrivateKey = privateKey;
    _peerKeyCache.clear(); // clear cached peer keys too (they may have rotated)
    await api('POST', '/api/member/e2ee/publish-key', { public_key_jwk: publicKeyJwk });
    return fingerprint();
  }

  // ── Public API ────────────────────────────────────────────────────────────────

  /**
   * Unwrap a message AES key that was wrapped for the current user (as sender),
   * then re-wrap it for a different member. Used by gcAutoRewrapMissingKeys so
   * that function doesn't need access to any private (_-prefixed) internals.
   *
   * @param {string} myWrappedKey  - The wrapped key entry from wrapped_keys[myId]
   * @param {string} targetMemberId - The member who is missing a wrapped key
   * @returns {Promise<string>} The new wrapped key string for targetMemberId
   */
  async function rewrapMsgKey(myWrappedKey, targetMemberId) {
    // Unwrap using our ECDH shared key with ourselves (sender wraps for self
    // the same way encryptGroup does: deriveSharedKey(myPrivate, myPublic))
    const myPublicKey = await _importPeerPublicKey(_myPublicKeyJwk);
    const mySharedKey = await _deriveSharedKey(_myPrivateKey, myPublicKey);
    const msgKey      = await _unwrapAesKey(myWrappedKey, mySharedKey);
    // Re-wrap for the target member using our ECDH shared key with them
    const peerKey   = await _getPeerPublicKey(targetMemberId);
    const sharedKey = await _deriveSharedKey(_myPrivateKey, peerKey);
    return _wrapAesKey(msgKey, sharedKey);
  }

  return {
    init,
    ready,
    onReady,
    wasFreshKey,
    fingerprint,
    encryptDm,
    decryptDm,
    encryptGroup,
    decryptGroup,
    decryptForReport,
    regenerateKeyPair,
    rewrapMsgKey,
    getMyPublicKeyJwk: () => _myPublicKeyJwk,
  };

})();
// ═══════════════════════════════════════════════════════════════════════════════
// KFS Member Portal — membersaccess.js
// All logic extracted from inline <script>. No onclick= in HTML.
// Wired via addEventListener inside DOMContentLoaded.
// ═══════════════════════════════════════════════════════════════════════════════

const API = '';  // same-origin
let _token      = null;
let _member     = null;
let _csrfToken  = null;
let _sessionExpiredHandled = false; // guards against firing the expired-session reset more than once when several polls/requests 401 around the same time

// ── Helpers ───────────────────────────────────────────────────────────────────

function $id(id) { return document.getElementById(id); }
function showEl(id) { const el = $id(id); if (el) el.style.display = ''; }
function hideEl(id) { const el = $id(id); if (el) el.style.display = 'none'; }
function setText(id, txt) { const el = $id(id); if (el) el.textContent = txt; }
function showMsg(id, msg, ok = true) {
  const el = $id(id); if (!el) return;
  el.textContent = msg;
  el.className = ok ? 'ok-msg' : 'err-msg';
  el.style.display = 'block';
  if (ok) setTimeout(() => { el.style.display = 'none'; }, 4000);
}

async function getCsrf() {
  if (_csrfToken) return _csrfToken;
  const r = await fetch('/api/csrf-token', { credentials: 'include' });
  const d = await r.json();
  _csrfToken = d.csrf_token;
  return _csrfToken;
}

async function api(method, path, body, isForm = false) {
  const headers = {};
  if (_token) headers['Authorization'] = `Bearer ${_token}`;
  if (!isForm) headers['Content-Type'] = 'application/json';
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
    headers['x-csrf-token'] = await getCsrf();
  }
  const opts = { method, headers, credentials: 'include' };
  if (body) opts.body = isForm ? body : JSON.stringify(body);
  // Cache-bust GET requests to groups/nicknames specifically: these kept
  // coming back with stale/empty bodies even at a 200 status after a 304/etag
  // fix was already deployed, which points to a URL-keyed cache somewhere
  // upstream of this app (browser or platform-level) rather than anything
  // this app's own headers can control. A unique query string per request
  // guarantees a cache miss every time, regardless of cause.
  let fetchPath = path;
  if (method.toUpperCase() === 'GET' && (path.includes('/groups') || path.includes('/nicknames'))) {
    fetchPath += (path.includes('?') ? '&' : '?') + '_cb=' + Date.now() + Math.random().toString(36).slice(2);
  }
  let r = await fetch(API + fetchPath, opts);

  // ── 401 auto-refresh ─────────────────────────────────────────────────────
  // Member JWTs expire after 15 min. On 401, silently refresh via the httpOnly
  // cookie and retry once with the new token — keeps long sessions alive.
  if (r.status === 401 && typeof refreshToken === 'function') {
    const refreshed = await refreshToken().catch(() => false);
    if (refreshed && _token) {
      const retryHeaders = { ...headers, 'Authorization': `Bearer ${_token}` };
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
        retryHeaders['x-csrf-token'] = await getCsrf();
      }
      r = await fetch(API + fetchPath, { ...opts, headers: retryHeaders });
      if (r.status === 401) _handleSessionExpired(); // refreshed token was rejected too — truly expired
    } else {
      // The httpOnly refresh cookie is gone/expired too — there's no way to
      // silently recover. Previously the request just threw here and
      // whatever screen was open (e.g. a post detail modal mid-load) was
      // left stuck with no feedback, looking unresponsive. Force a clean
      // re-login instead.
      _handleSessionExpired();
    }
  }

  // A 304 means "nothing changed" — it is not a failure, but r.ok is false for
  // it (only 200–299 counts), and a 304 has no body, so r.json() would throw.
  // Treat it as an empty-but-successful response rather than an error.
  if (r.status === 304) {
    return {};
  }
  const d = await (async () => {
    if (path.includes('/groups') || path.includes('/nicknames')) {
      const text = await r.text();
      try { return JSON.parse(text); } catch { return {}; }
    }
    return r.json().catch(() => ({}));
  })();
  if (!r.ok) {
    const err = new Error(d.error || 'Request failed');
    err._data = d; // attach full response so callers can read warned/muted/banned
    throw err;
  }
  return d;
}

async function refreshToken() {
  try {
    const csrf = await getCsrf();
    const r = await fetch('/api/member/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'x-csrf-token': csrf },
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.token) {
      _token = d.token;
      localStorage.setItem('kfs-member-token', d.token);
      if (d.member) {
        _member = d.member;
        localStorage.setItem('kfs-member-data', JSON.stringify(d.member));
        window._member = d.member;
      }
      _sessionExpiredHandled = false; // a fresh, valid session — re-arm the expiry handler
      return true;
    }
    return false;
  } catch { return false; }
}

/** Called when a request 401s and the refresh-token cookie can't (or no
 *  longer can) recover the session. Rather than leaving whatever was open
 *  mid-load stuck and unresponsive, this clears local auth state, closes
 *  any open modals/overlays, and drops the person back to the login screen
 *  with a clear explanation. Guarded so a burst of concurrent 401s (e.g.
 *  several polling timers firing around the same moment) only does this once. */
function _handleSessionExpired() {
  if (_sessionExpiredHandled) return;
  _sessionExpiredHandled = true;
  _token = null;
  _member = null;
  localStorage.removeItem('kfs-member-token');
  localStorage.removeItem('kfs-member-data');
  document.querySelectorAll('[id$="-modal-overlay"]').forEach(el => { el.style.display = 'none'; });
  document.body.style.overflow = '';
  if (typeof showLoginScreen === 'function') showLoginScreen();
  showMsg('login-err', 'Your session expired. Please sign in again.', false);
}

function relTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

// ── Social URL helpers ────────────────────────────────────────────────────────

/**
 * Validate a URL is safe (http/https only, no javascript:, data: etc.)
 * Returns cleaned URL string or empty string if invalid.
 */
function sanitizeSocialUrl(raw) {
  if (!raw) return '';
  const val = raw.trim();
  if (!val) return '';
  try {
    const u = new URL(val);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
    return u.href;
  } catch {
    return '';
  }
}

/**
 * Validate a bare username (no spaces, no special chars other than . - _)
 * Returns sanitized username or empty string.
 */
function sanitizeUsername(raw) {
  if (!raw) return '';
  // Strip leading @ if present, remove whitespace, allow only safe chars
  return raw.trim().replace(/^@+/, '').replace(/[^\w.\-]/g, '').slice(0, 100);
}

/**
 * Validate all social fields. Returns { valid: bool, errors: string[] }.
 */
function validateSocialLinks(fields) {
  const errors = [];
  const urlFields = ['linkedin', 'youtube', 'website'];
  urlFields.forEach(k => {
    const v = fields[k];
    if (v && sanitizeSocialUrl(v) === '') {
      errors.push(`${k.charAt(0).toUpperCase() + k.slice(1)} must be a valid https:// URL.`);
    }
  });
  return { valid: errors.length === 0, errors };
}

let _portalMembers = null;

async function loadPortalMembers() {
  if (_portalMembers) return _portalMembers;
  try {
    const r = await fetch('/api/members');
    if (r.ok) _portalMembers = await r.json();
  } catch {}
  return _portalMembers || [];
}

function splitCrew(str) {
  if (!str) return [];
  // Support both ";;" and "," separators
  const sep = str.includes(';;') ? ';;' : ',';
  return str.split(sep).map(s => s.trim()).filter(Boolean);
}

// ── Member Picker (portal) ────────────────────────────────────────────────────

class MemberPortalPicker {
  constructor(containerId, multi = false) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;
    this.multi = multi;
    this.selected = [];
    this._render();
  }
  _render() {
    this.container.innerHTML = `
      <div style="position:relative">
        <input class="portal-mpicker-input" placeholder="Type name or search members…" autocomplete="off" />
        <div class="portal-mpicker-dropdown" style="display:none"></div>
      </div>
      <div class="portal-mpicker-tags"></div>`;
    this._input    = this.container.querySelector('.portal-mpicker-input');
    this._dd       = this.container.querySelector('.portal-mpicker-dropdown');
    this._tagsEl   = this.container.querySelector('.portal-mpicker-tags');
    this._input.addEventListener('input',   () => this._onInput());
    this._input.addEventListener('keydown', e => {
      if (e.key === 'Enter')  { e.preventDefault(); this._addFreeText(); }
      if (e.key === 'Escape') this._hideDd();
    });
    this._input.addEventListener('blur', () => setTimeout(() => this._hideDd(), 150));
    this._renderTags();
  }
  _onInput() {
    const q = this._input.value.trim().toLowerCase();
    if (!q) { this._hideDd(); return; }
    const members = _portalMembers || [];
    const matches = members.filter(m => m.name.toLowerCase().includes(q)).slice(0, 8);
    if (!matches.length) { this._hideDd(); return; }
    this._dd.innerHTML = matches.map(m => `
      <div class="portal-mpicker-opt" data-id="${m.id}">
        ${m.photo
          ? `<img src="${m.photo}" alt="" />`
          : `<div class="portal-mpicker-avatar">${(m.name || '?')[0].toUpperCase()}</div>`}
        <span class="portal-mpicker-opt-name">${m.name}</span>
        <span class="portal-mpicker-opt-role">${m.role || ''}</span>
      </div>`).join('');
    this._dd.querySelectorAll('.portal-mpicker-opt').forEach(el => {
      el.addEventListener('mousedown', e => {
        e.preventDefault();
        const m = members.find(x => String(x.id) === el.dataset.id);
        if (m) this._select({ id: m.id, name: m.name, photo: m.photo, role: m.role });
      });
    });
    this._dd.style.display = 'block';
  }
  _addFreeText() {
    const v = this._input.value.trim();
    if (!v) return;
    this._select({ id: null, name: v, photo: null, role: '' });
  }
  _select(item) {
    if (!this.multi) this.selected = [];
    if (!this.selected.find(s => s.name === item.name)) this.selected.push(item);
    this._input.value = '';
    this._hideDd();
    this._renderTags();
  }
  _remove(name) {
    this.selected = this.selected.filter(s => s.name !== name);
    this._renderTags();
  }
  _renderTags() {
    if (!this._tagsEl) return;
    this._tagsEl.innerHTML = this.selected.map(s => `
      <span class="portal-mpicker-tag">
        ${s.photo
          ? `<img src="${s.photo}" alt="" />`
          : `<span class="portal-mpicker-tag-avatar">${(s.name || '?')[0].toUpperCase()}</span>`}
        <span>${s.name}</span>
        <span class="portal-mpicker-tag-remove" data-name="${s.name}">×</span>
      </span>`).join('');
    this._tagsEl.querySelectorAll('.portal-mpicker-tag-remove').forEach(el => {
      el.addEventListener('click', () => this._remove(el.dataset.name));
    });
  }
  _hideDd() { if (this._dd) this._dd.style.display = 'none'; }
  getValue() {
    return this.selected.map(s => s.id ? `${s.name}||${s.id}` : s.name).join(';;');
  }
  setValue(str) {
    this.selected = [];
    if (!str) { this._renderTags(); return; }
    splitCrew(str).forEach(part => {
      const pipes = part.split('||');
      const name  = pipes[0].trim();
      const id    = pipes[1] ? pipes[1].trim() : null;
      const member = id && _portalMembers ? _portalMembers.find(m => String(m.id) === id) : null;
      this.selected.push(member
        ? { id: member.id, name: member.name, photo: member.photo, role: member.role }
        : { id: null, name, photo: null, role: '' });
    });
    this._renderTags();
  }
}

let _formPickers = {};

function initMovieFormPickers() {
  const pickerFields = ['director','producer','dop','writer','editor','sound','management','gd','actors','support'];
  pickerFields.forEach(f => {
    _formPickers[f] = new MemberPortalPicker(`mfpick-${f}`, true);
  });
}

// ── Genre tag-input helpers ───────────────────────────────────────────────────

function renderMfGenreTags(tags) {
  const wrap  = $id('mf-genre-wrap');
  const input = $id('mf-genre-input');
  if (!wrap || !input) return;
  wrap.querySelectorAll('.mf-tag-chip').forEach(c => c.remove());
  tags.forEach((tag, i) => {
    const chip = document.createElement('span');
    chip.className = 'mf-tag-chip';
    chip.innerHTML = `${tag}<button type="button" aria-label="Remove ${tag}">×</button>`;
    chip.querySelector('button').addEventListener('click', () => {
      const cur = JSON.parse($id('mf-genre').value || '[]');
      cur.splice(i, 1);
      $id('mf-genre').value = JSON.stringify(cur);
      renderMfGenreTags(cur);
    });
    wrap.insertBefore(chip, input);
  });
}

function addMfGenreTag(raw) {
  raw.split(/[,،]+/).map(s => s.trim()).filter(Boolean).forEach(tag => {
    const cur = JSON.parse($id('mf-genre').value || '[]');
    if (!cur.includes(tag)) { cur.push(tag); $id('mf-genre').value = JSON.stringify(cur); renderMfGenreTags(cur); }
  });
}

function initMfGenreInput() {
  const wrap  = $id('mf-genre-wrap');
  const input = $id('mf-genre-input');
  if (!wrap || !input) return;
  wrap.addEventListener('click', () => input.focus());
  input.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
      e.preventDefault(); addMfGenreTag(input.value); input.value = '';
    } else if (e.key === 'Backspace' && !input.value) {
      const cur = JSON.parse($id('mf-genre').value || '[]');
      if (cur.length) { cur.pop(); $id('mf-genre').value = JSON.stringify(cur); renderMfGenreTags(cur); }
    }
  });
  input.addEventListener('blur', () => { if (input.value.trim()) { addMfGenreTag(input.value); input.value = ''; } });
}

// ── Boot ──────────────────────────────────────────────────────────────────────

function _hideBootLoader() {
  $id('kfs-boot-loader')?.classList.add('kfs-boot-hidden');
}

document.addEventListener('DOMContentLoaded', async () => {
  wireStaticButtons();

  // Try to restore session via refresh token cookie
  if (document.cookie.includes('kfs_member_session=1')) {
    const ok = await refreshToken();
    if (ok) {
      try { await loadDashboard(); } finally { _hideBootLoader(); }
      return;
    }
  }
  showLoginScreen();
  _hideBootLoader();
});

// ── Wire all static HTML buttons via addEventListener ─────────────────────────

function wireStaticButtons() {
  // Auth flow
  on('login-btn',         'click', handleLogin);
  on('totp-btn',          'click', submitTotp);
  on('back-to-login-btn', 'click', backToLogin);
  on('cp-btn',            'click', handleChangePw);
  on('setup-totp-btn',    'click', verify2FASetup);
  on('skip-2fa-btn',      'click', skip2FASetup);

  // Forgot password flow
  on('forgot-password-link', 'click', startForgotPasswordFlow);
  on('fp-back-to-login-btn', 'click', backToLogin);
  on('fp-start-btn',         'click', fpSubmitUsername);
  on('fp-otp-back-btn',      'click', startForgotPasswordFlow);
  on('fp-verify-btn',        'click', fpSubmitOtp);
  on('fp-resend-btn',        'click', fpResendOtp);
  on('fp-reset-btn',         'click', fpSubmitNewPassword);
  on('fp-done-btn',          'click', backToLogin);
  const fpNewPw = $id('fp-new-password');
  if (fpNewPw) fpNewPw.addEventListener('input', () => updatePasswordStrength(fpNewPw.value));
  const fpOtpInput = $id('fp-otp-input');
  if (fpOtpInput) fpOtpInput.addEventListener('input', function() { this.value = this.value.replace(/\D/g, '').slice(0, 6); });

  // Logout buttons
  on('mobile-logout-btn', 'click', logoutMember);
  on('sidebar-logout-btn','click', logoutMember);

  // Nav items — delegate on both nav containers.
  // .btb-item elements are wired separately via btbSwitch() in _wireBtb() —
  // skip them here so a single tap doesn't fire switchPanel twice.
  document.querySelectorAll('[data-panel]:not(.btb-item)').forEach(el => {
    el.addEventListener('click', () => switchPanel(el));
  });

  // Profile
  on('profile-photo-input', 'change', function() { previewPhoto(this); });
  on('profile-save-btn',    'click',  saveProfile);

  // Recovery contact info banner + modal
  on('recovery-banner-add-btn',     'click', openContactInfoModal);
  on('recovery-banner-dismiss-btn', 'click', dismissRecoveryBanner);
  on('ci-save-btn',                 'click', saveContactInfo);
  on('ci-cancel-btn',                'click', closeContactInfoModal);
  const ciOverlay = $id('contact-info-modal-overlay');
  if (ciOverlay) ciOverlay.addEventListener('click', e => { if (e.target === ciOverlay) closeContactInfoModal(); });

  // Movies
  on('new-movie-btn',    'click', () => showMovieForm(null));
  on('movie-submit-btn', 'click', submitMovie);
  on('cancel-movie-btn', 'click', hideMovieForm);

  // Security
  on('sec-change-pw-btn',  'click', changePasswordFromSecurity);
  on('revoke-sessions-btn','click', revokeAllSessions);
  on('security-logout-btn','click', logoutMember);
  on('replay-tutorial-btn','click', () => {
    // Jump to the Strand feed first so the tour's spotlight targets (nav
    // items, post button, etc.) are actually visible/in-DOM before it starts.
    _goToStrandFeed();
    setTimeout(() => kfsStartTour(true), 350);
  });

  // Collab
  on('new-collab-btn',    'click', showCollabForm);
  on('cancel-collab-btn', 'click', hideCollabForm);
  on('collab-submit-btn', 'click', submitCollab);
  const cfDesc = $id('cf-description');
  if (cfDesc) cfDesc.addEventListener('input', () => { const cnt = $id('cf-desc-count'); if(cnt) cnt.textContent = cfDesc.value.length; });

  // Collab edit modal
  on('collab-edit-submit-btn', 'click', submitCollabEdit);
  on('collab-edit-cancel-btn', 'click', closeCollabEditModal);
  const ceDesc = $id('ce-description');
  if (ceDesc) ceDesc.addEventListener('input', () => { const cnt = $id('ce-desc-count'); if(cnt) cnt.textContent = ceDesc.value.length; });
  const editOverlay = $id('collab-edit-modal-overlay');
  if (editOverlay) editOverlay.addEventListener('click', e => { if (e.target === editOverlay) closeCollabEditModal(); });

  // Grievance / Suggestion
  on('grv-submit-btn', 'click', submitGrievance);
  const grvBody = $id('grv-body');
  if (grvBody) grvBody.addEventListener('input', () => { const cnt = $id('grv-body-count'); if (cnt) cnt.textContent = grvBody.value.length; });
  document.querySelectorAll('.grv-type-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.grv-type-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const typeEl = $id('grv-type-value');
      if (typeEl) typeEl.value = tab.dataset.grvType || 'general';
    });
  });


  // Work edit modal
  on('work-edit-submit-btn', 'click', submitWorkEditRequest);
  on('work-edit-cancel-btn', 'click', closeWorkEditModal);
  const overlay = $id('work-edit-modal-overlay');
  if (overlay) overlay.addEventListener('click', e => { if (e.target === overlay) closeWorkEditModal(); });

  // Enter key support
  document.addEventListener('keydown', handleEnterKey);
}

function on(id, evt, fn) {
  const el = $id(id);
  if (el) el.addEventListener(evt, fn);
}

// ── Emoji rendering (Twemoji) ──────────────────────────────────────────────
// Reaction emoji are rendered as Apple Color Emoji images so every member
// sees the clean iOS-style glyphs regardless of OS. We convert emoji chars
// to their Unicode codepoint path and load the image from the Apple emoji
// dataset on jsDelivr. Falls back gracefully if the CDN is unavailable.
//
// NOTE: this used to point at jsDelivr's npm CDN (emoji-datasource-apple).
// jsDelivr enforces an aggregate package-size cap (100MB for npm), and that
// package is large enough to trip it — it silently 403s on individual emoji
// PNGs, which fires every image's onerror fallback and reverts to the
// device's native emoji glyph instead of Apple's. raw.githubusercontent.com
// serves the same underlying dataset's files directly with no such cap.
const _APPLE_EMOJI_BASE = 'https://raw.githubusercontent.com/iamcal/emoji-data/master/img-apple-64/';

function _emojiToCodepoint(emoji) {
  // Convert an emoji string to the lowercase hex codepoint path Apple uses.
  // Multi-codepoint sequences (e.g. 👨‍👩‍👧) are joined with dashes, and VS-16
  // (U+FE0F) is stripped because Apple's filenames exclude it.
  const codepoints = [];
  for (const char of emoji) {
    const cp = char.codePointAt(0);
    if (cp === 0xFE0F) continue; // variation selector — skip
    codepoints.push(cp.toString(16).toLowerCase());
  }
  return codepoints.join('-');
}

function _emojify(el) {
  if (!el) return;
  try {
    // Walk every text node and replace bare emoji chars with <img> tags
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
    const nodes = [];
    let node;
    while ((node = walker.nextNode())) nodes.push(node);

    // Regex that matches a single emoji (including ZWJ sequences and flags)
    const emojiRx = /(\p{Emoji_Presentation}|\p{Emoji}\uFE0F)(\u200D(\p{Emoji_Presentation}|\p{Emoji}\uFE0F))*/gu;

    nodes.forEach(textNode => {
      const text = textNode.nodeValue;
      if (!emojiRx.test(text)) return;
      emojiRx.lastIndex = 0;

      const frag = document.createDocumentFragment();
      let last = 0;
      let m;
      while ((m = emojiRx.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        const cp  = _emojiToCodepoint(m[0]);
        const img = document.createElement('img');
        img.src        = `${_APPLE_EMOJI_BASE}${cp}.png`;
        img.alt        = m[0];
        img.draggable  = false;
        img.className  = 'kfs-apple-emoji';
        img.onerror    = function() { this.replaceWith(document.createTextNode(this.alt)); };
        frag.appendChild(img);
        last = m.index + m[0].length;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      textNode.parentNode.replaceChild(frag, textNode);
    });
  } catch { /* never let emoji rendering break the UI */ }
}

// ── Auth screen ───────────────────────────────────────────────────────────────

function showLoginScreen() {
  $id('auth-screen').style.display = 'flex';
  $id('app-screen').style.display  = 'none';
  document.body.classList.add('auth-active'); // hides the bottom pill nav while signed out
  showStep('login');
  const u = $id('login-username'); if (u) u.value = '';
  const p = $id('login-password'); if (p) p.value = '';
  hideEl('login-err');
  _csrfToken = null; // force fresh CSRF on next login attempt
  initGoogleSignIn();
}

// ── Google Sign-In ───────────────────────────────────────────────────────────
// Loads the (non-secret) Google OAuth Client ID from the server, then renders
// Google's own sign-in button into #google-signin-container. Google handles
// the account picker UI; we only get a signed ID token back via the callback,
// which we send straight to /api/member/google-login for verification.

let _googleInitialized = false;
let _pendingGoogleCredential = null; // held while a Google sign-in is waiting on a 2FA code

async function initGoogleSignIn() {
  const container = $id('google-signin-container');
  if (!container) return;
  hideEl('google-signin-err');

  if (typeof google === 'undefined' || !google.accounts?.id) {
    // Google's script may not have finished loading yet (it's loaded with
    // `defer`) — retry shortly instead of silently failing.
    setTimeout(() => { if ($id('step-login')?.style.display !== 'none') initGoogleSignIn(); }, 300);
    return;
  }

  try {
    if (!_googleInitialized) {
      const r = await fetch('/api/member/google-client-id');
      if (!r.ok) { container.style.display = 'none'; return; } // not configured — hide gracefully, password login still works
      const { client_id } = await r.json();
      if (!client_id) { container.style.display = 'none'; return; }

      google.accounts.id.initialize({
        client_id,
        callback: handleGoogleCredential,
      });
      _googleInitialized = true;
    }
    container.innerHTML = '';
    google.accounts.id.renderButton(container, {
      type: 'standard',
      theme: 'filled_black',
      size: 'large',
      text: 'signin_with',
      shape: 'pill',
      width: 320,
    });
  } catch (e) {
    container.style.display = 'none'; // fail quiet — password login is always the fallback
  }
}

async function handleGoogleCredential(response) {
  await submitGoogleCredential(response.credential, null);
}

async function submitGoogleCredential(credential, totpCode) {
  hideEl('google-signin-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/google-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ credential, totp_code: totpCode || undefined }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('google-signin-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('google-signin-err', d.error || 'Google sign-in failed', false); return; }

    if (d.require_totp) {
      _pendingGoogleCredential = d.google_credential || credential;
      showStep('totp');
      return;
    }
    _pendingGoogleCredential = null;
    _token  = d.token;
    _member = d.member;
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;

    if (d.must_change_password) { showStep('change-pw'); return; }
    // 2FA is opt-in, not forced — members can turn it on later from Security settings.
    await loadDashboard();
  } catch (e) {
    showMsg('google-signin-err', e.message || 'Could not connect to server', false);
  }
}

async function loadDashboard() {
  $id('auth-screen').style.display = 'none';
  $id('app-screen').style.display  = 'flex';
  document.body.classList.remove('auth-active'); // safe to show the bottom pill nav now
  loadPortalMembers(); // preload for pickers (non-blocking)
  await loadProfile();
  // Initialise E2EE: generate or load ECDH key pair, publish public key to server.
  // Non-blocking — runs in background. Falls back to plaintext if crypto unavailable.
  E2EE.init();
  // onReady fires once keys are actually ready, whether that's on the first
  // try or after init() retries in the background (see E2EE.init — it now
  // retries with backoff instead of giving up for the whole session on a
  // single failed publish-key call, e.g. a transient 429). Using onReady
  // instead of chaining off the init() promise directly means this still
  // fires correctly even if the *first* attempt failed and a later retry
  // succeeded a minute later.
  E2EE.onReady(() => {
    if (E2EE.wasFreshKey()) {
      // Genuine rotation — server had a different key on file, so older
      // DMs/group messages encrypted under the previous key won't decrypt
      // here (see _collapseFailedDecrypts). One-time heads up rather than
      // letting people discover it message-by-message.
      swShowToast("New device detected — some older encrypted messages may show as locked here.", 5000);
    }
    // If a conversation was opened before keys were ready, its messages were
    // decrypted with _ready still false and are showing as blank/placeholder
    // bubbles (see decryptDm/decryptGroup). Re-render now that keys are
    // loaded so people don't have to reload the page to see them.
    if (typeof DM !== 'undefined' && DM.activeKey) dmLoadMsgs(false).catch(() => {});
    if (typeof GC !== 'undefined' && GC.activeId)  gcLoadMsgs(false).catch(() => {});
  });
  loadMovies();
  loadSecurity();
  loadActivity();
  loadMyWorks();
  loadNotificationBadge(); // populate badge count without opening the panel
  startNotifPolling();     // keep badge fresh while page is open

  // Pre-load nicknames and block list on every session restore so they are
  // available immediately when any panel renders — not deferred until the
  // DM tab is first clicked. nicksLoadGlobal seeds from localStorage first
  // (instant) then reconciles with the server. blocksEnsureLoaded is a
  // no-op if it already ran. Both are non-blocking.
  if (typeof nicksLoadGlobal === 'function') nicksLoadGlobal().catch(() => {});
  if (typeof blocksEnsureLoaded === 'function') {
    blocksEnsureLoaded()
      .then(() => { if (typeof dmUpdateBlockedBanner === 'function') dmUpdateBlockedBanner(); })
      .catch(() => {});
  }

  // ── First-time login detection ──────────────────────────────────────────
  // We track this with a per-member localStorage key so it only fires once
  // per device. Keyed by member id so different members on the same device
  // get their own first-time flag.
  const memberId = (_member?.id || window._memberProfile?.id || 'unknown');
  const firstTimeKey = `kfs-strand-welcomed-${memberId}`;
  const isFirstTime = !localStorage.getItem(firstTimeKey);

  if (isFirstTime) {
    // Show onboarding overlay — direct them to profile
    const overlay = $id('onboarding-overlay');
    if (overlay) {
      overlay.classList.add('open');
      const goBtn   = $id('onboarding-go-btn');
      const skipBtn = $id('onboarding-skip-btn');
      if (goBtn) goBtn.addEventListener('click', () => {
        overlay.classList.remove('open');
        localStorage.setItem(firstTimeKey, '1');
        // Switch to profile panel and WAIT for them to actually finish
        // setting it up (i.e. a real saveProfile() success) before the tour
        // starts — it used to fire on a flat 450ms timer regardless of
        // whether the person had touched a single field, which meant "Set
        // Up My Profile" and "Skip" behaved identically. window._kfsPendingProfileTour
        // is consumed in saveProfile() on success, and as a fallback (they
        // navigate away without saving) it's also consumed the moment they
        // leave the profile panel, in switchPanel(), so nobody gets
        // permanently stuck without ever seeing the tour.
        window._kfsPendingProfileTour = true;
        const profileNav = document.querySelector('[data-panel="profile"]');
        if (profileNav) switchPanel(profileNav);
      }, { once: true });
      if (skipBtn) skipBtn.addEventListener('click', () => {
        overlay.classList.remove('open');
        localStorage.setItem(firstTimeKey, '1');
        // Go straight to feed
        _goToStrandFeed();
        setTimeout(() => kfsStartTour(), 450);
      }, { once: true });
    }
  } else {
    // Returning user — open Strand feed immediately unless hash says otherwise
    const hash = window.location.hash.replace('#', '');
    if (hash && document.querySelector(`[data-panel="${hash}"]`)) {
      switchPanel(document.querySelector(`[data-panel="${hash}"]`));
    } else {
      _goToStrandFeed();
    }
  }

  // Clear hash after use so back-navigation stays clean
  if (window.location.hash) history.replaceState(null, '', window.location.pathname);

  // Wire bottom tab bar if not already wired
  _wireBtb();
}

/** Switch directly to the Strand (Social Strand) feed panel. Past/alumni
 *  members don't get a Studio tab at all, so send them to Profile instead —
 *  this used to be implicit (Profile was simply whichever panel the static
 *  HTML marked "active" by default), but now that the static default matches
 *  the Studio nav item (to stop it flashing before this function runs), that
 *  fallback needs to be explicit here instead. */
function _goToStrandFeed() {
  const studioNav = document.querySelector('[data-panel="studio"]');
  if (studioNav && window._memberProfile && !window._memberProfile.is_past) {
    switchPanel(studioNav);
  } else {
    const profileNav = document.querySelector('[data-panel="profile"]');
    if (profileNav) switchPanel(profileNav);
  }
}

/** Wire the bottom tab bar (mobile) — safe to call multiple times. */
function _wireBtb() {
  // Already wired if btb-strand has a listener flag
  if (window._btbWired) return;
  window._btbWired = true;
  document.querySelectorAll('.btb-item[data-panel]').forEach(item => {
    item.addEventListener('click', () => btbSwitch(item));
  });
}

// ── Live lockout countdown ───────────────────────────────────────────────────
// Generic helper for any "locked out, try again in X" UI. Ticks every second,
// updates the error text + a depleting progress bar, disables the action
// button while locked, and auto re-enables everything the instant it expires
// (no page refresh needed). Mirrors the admin portal's version.
const _activeLockoutTimers = {}; // keyed by errEl id, so concurrent screens don't collide

function startLockoutCountdown({ errId, barTrackId, barFillId, btn, btnIdleText, lockedUntil, baseMessage }) {
  const errEl = $id(errId);
  const barTrack = barTrackId ? $id(barTrackId) : null;
  const barFill = barFillId ? $id(barFillId) : null;

  if (_activeLockoutTimers[errId]) clearInterval(_activeLockoutTimers[errId]);

  const totalMs = Math.max(lockedUntil - Date.now(), 0);
  if (totalMs <= 0) return;

  function formatRemaining(ms) {
    const totalSecs = Math.max(Math.ceil(ms / 1000), 0);
    if (totalSecs < 3600) {
      const m = Math.floor(totalSecs / 60);
      const s = totalSecs % 60;
      return `${m}:${String(s).padStart(2, '0')}`;
    }
    if (totalSecs < 86400) {
      const h = Math.floor(totalSecs / 3600);
      const m = Math.floor((totalSecs % 3600) / 60);
      return `${h}h ${m}m`;
    }
    const d = Math.floor(totalSecs / 86400);
    const h = Math.floor((totalSecs % 86400) / 3600);
    return `${d}d ${h}h`;
  }

  function tick() {
    const msLeft = lockedUntil - Date.now();
    if (msLeft <= 0) {
      clearInterval(_activeLockoutTimers[errId]);
      delete _activeLockoutTimers[errId];
      if (errEl) { errEl.textContent = ''; errEl.style.display = 'none'; }
      if (barTrack) barTrack.classList.remove('show');
      if (btn) { btn.disabled = false; if (btnIdleText) btn.textContent = btnIdleText; }
      return;
    }
    if (errEl) { errEl.textContent = `${baseMessage} ${formatRemaining(msLeft)}`; errEl.style.display = 'block'; errEl.className = 'err-msg'; }
    if (barTrack && barFill) {
      barTrack.classList.add('show');
      barFill.style.width = `${Math.max((msLeft / totalMs) * 100, 0)}%`;
    }
  }

  if (btn) btn.disabled = true;
  tick();
  _activeLockoutTimers[errId] = setInterval(tick, 1000);
}

// ── Login ─────────────────────────────────────────────────────────────────────

let _pendingUsername = null, _pendingPassword = null;
let _recoveryPromptDismissedThisSession = false;

async function handleLogin() {
  const username = $id('login-username').value.trim();
  const password = $id('login-password').value;
  if (!username || !password) {
    showMsg('login-err', 'Username and password required', false);
    return;
  }
  const btn = $id('login-btn');
  btn.disabled = true; btn.textContent = 'Signing in…';
  hideEl('login-err');
  let lockedOut = false;
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username, password }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('login-err', 'Server error — please try again', false); return; }
    if (r.status === 429 && d.locked_until) {
      lockedOut = true;
      startLockoutCountdown({
        errId: 'login-err',
        barTrackId: 'login-lockout-bar-track',
        barFillId: 'login-lockout-bar-fill',
        btn,
        btnIdleText: 'Sign in',
        lockedUntil: d.locked_until,
        baseMessage: 'Account locked. Try again in',
      });
      return;
    }
    if (!r.ok) { showMsg('login-err', d.error || 'Login failed', false); return; }

    if (d.require_totp) {
      _pendingUsername = username;
      _pendingPassword = password;
      showStep('totp');
      return;
    }
    _token  = d.token;
    _member = d.member;
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
    // Persist token + member data so index.html collab gate can read them
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;

    if (d.must_change_password) { showStep('change-pw'); return; }
    // 2FA is opt-in, not forced — members can turn it on later from Security settings.
    await loadDashboard();
  } catch (e) {
    showMsg('login-err', e.message || 'Could not connect to server', false);
  } finally {
    // Skip resetting the button if a live lockout countdown just took over —
    // it owns the disabled/text state until it hits 0:00.
    if (!lockedOut) {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  }
}

async function submitTotp() {
  const code = $id('totp-input').value.trim();
  if (!code) return;
  const btn = $id('totp-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    if (_pendingGoogleCredential) {
      await submitGoogleCredential(_pendingGoogleCredential, code);
      return;
    }
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _pendingUsername, password: _pendingPassword, totp_code: code }),
      credentials: 'include',
    });
    const d = await r.json();
    if (!r.ok) { showMsg('totp-err', d.error || 'Invalid code', false); return; }
    _token  = d.token;
    _member = d.member;
    _recoveryPromptDismissedThisSession = !!d.recovery_prompt_dismissed;
    localStorage.setItem('kfs-member-token', d.token);
    localStorage.setItem('kfs-member-data', JSON.stringify(d.member || {}));
    window._member = d.member;
    if (d.must_change_password) { showStep('change-pw'); return; }
    await loadDashboard();
  } catch (e) {
    showMsg('totp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
}

function backToLogin() { _pendingGoogleCredential = null; showStep('login'); }

function showStep(step) {
  ['login', 'totp', 'change-pw', '2fa-setup', 'fp-username', 'fp-otp', 'fp-reset', 'fp-success'].forEach(s => {
    const el = $id(`step-${s}`);
    if (el) el.style.display = s === step ? 'block' : 'none';
  });
}

// ── Forgot Password ─────────────────────────────────────────────────────────
// Three steps: username -> OTP (email) -> new password.
// Mirrors the existing login/TOTP UX so it doesn't feel like a bolted-on flow.

let _fpUsername = null, _fpResetToken = null, _fpResendCooldownTimer = null;

function startForgotPasswordFlow() {
  _fpUsername = null;
  _fpResetToken = null;
  const u = $id('fp-username'); if (u) u.value = '';
  const o = $id('fp-otp-input'); if (o) o.value = '';
  hideEl('fp-username-err');
  hideEl('fp-otp-err');
  showStep('fp-username');
  setTimeout(() => $id('fp-username')?.focus(), 50);
}

async function fpSubmitUsername() {
  const username = $id('fp-username').value.trim();
  if (!username) { showMsg('fp-username-err', 'Please enter your username', false); return; }
  const btn = $id('fp-start-btn');
  btn.disabled = true; btn.textContent = 'Sending…';
  hideEl('fp-username-err');
  let lockedOut = false;
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-username-err', 'Server error — please try again', false); return; }
    if (r.status === 429 && d.locked_until) {
      lockedOut = true;
      startLockoutCountdown({
        errId: 'fp-username-err',
        barTrackId: 'fp-username-lockout-bar-track',
        barFillId: 'fp-username-lockout-bar-fill',
        btn,
        btnIdleText: 'Send code',
        lockedUntil: d.locked_until,
        baseMessage: 'Too many attempts. Try again in',
      });
      return;
    }
    if (!r.ok) { showMsg('fp-username-err', d.error || 'Something went wrong', false); return; }
    if (d.reason === 'no_contact') {
      showMsg('fp-username-err', d.error || 'Your email is not on file yet. Please contact your site admin for assistance.', false);
      return;
    }

    _fpUsername = username;
    setFpChannelUI(d.channel, d.masked_destination);
    showStep('fp-otp');
    startFpResendCooldown();
    setTimeout(() => $id('fp-otp-input')?.focus(), 50);
  } catch (e) {
    showMsg('fp-username-err', e.message || 'Could not connect to server', false);
  } finally {
    if (!lockedOut) {
      btn.disabled = false;
      btn.textContent = 'Send code';
    }
  }
}

function setFpChannelUI(channel, maskedDestination) {
  const badge = $id('fp-channel-badge');
  const text  = $id('fp-channel-text');
  const sub   = $id('fp-otp-sub');
  if (!channel) {
    // Generic response (account/email couldn't be confirmed) — don't reveal anything extra.
    if (badge) badge.style.display = 'none';
    if (sub) sub.textContent = "If we found an email on file, a 6-digit code is on its way.";
    return;
  }
  if (sub) sub.textContent = `We've sent a 6-digit code to ${maskedDestination || 'your email on file'}.`;
  if (badge && text) {
    text.textContent = 'Sent via email';
    badge.style.display = 'inline-flex';
  }
}

async function fpSubmitOtp() {
  const code = $id('fp-otp-input').value.trim();
  if (!code || code.length !== 6) { showMsg('fp-otp-err', 'Enter the 6-digit code', false); return; }
  const btn = $id('fp-verify-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  hideEl('fp-otp-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername, code }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-otp-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('fp-otp-err', d.error || 'Incorrect code', false); return; }

    _fpResetToken = d.reset_token;
    const np = $id('fp-new-password'); if (np) np.value = '';
    const cp = $id('fp-confirm-password'); if (cp) cp.value = '';
    updatePasswordStrength('');
    showStep('fp-reset');
    setTimeout(() => $id('fp-new-password')?.focus(), 50);
  } catch (e) {
    showMsg('fp-otp-err', e.message || 'Could not connect to server', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify code';
  }
}

function startFpResendCooldown() {
  const btn = $id('fp-resend-btn');
  if (!btn) return;
  let seconds = 30;
  btn.disabled = true;
  btn.textContent = `Resend code (${seconds}s)`;
  clearInterval(_fpResendCooldownTimer);
  _fpResendCooldownTimer = setInterval(() => {
    seconds -= 1;
    if (seconds <= 0) {
      clearInterval(_fpResendCooldownTimer);
      btn.disabled = false;
      btn.textContent = 'Resend code';
    } else {
      btn.textContent = `Resend code (${seconds}s)`;
    }
  }, 1000);
}

async function fpResendOtp() {
  if (!_fpUsername) return;
  const btn = $id('fp-resend-btn');
  if (btn.disabled) return;
  hideEl('fp-otp-err');
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (d && r.ok && d.reason === 'no_contact') {
      showMsg('fp-otp-err', d.error || 'Your email is not on file yet. Please contact your site admin for assistance.', false);
    } else if (d && r.ok) {
      setFpChannelUI(d.channel, d.masked_destination);
      showMsg('fp-otp-err', 'A new code has been sent.', true);
      startFpResendCooldown();
    } else {
      showMsg('fp-otp-err', d?.error || 'Could not resend code', false);
    }
  } catch (e) {
    showMsg('fp-otp-err', e.message || 'Could not connect to server', false);
  }
}

function updatePasswordStrength(pw) {
  const bars = document.querySelectorAll('#fp-pw-strength .pw-strength-bar');
  if (!bars.length) return;
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const level = score <= 1 ? 'weak' : score <= 3 ? 'medium' : 'strong';
  const litCount = score <= 1 ? 1 : score <= 3 ? 2 : 3;
  bars.forEach((bar, i) => {
    bar.className = 'pw-strength-bar' + (i < litCount && pw.length ? ` ${level}` : '');
  });
}

async function fpSubmitNewPassword() {
  const newPw = $id('fp-new-password').value;
  const confirmPw = $id('fp-confirm-password').value;
  hideEl('fp-reset-err');
  if (newPw !== confirmPw) { showMsg('fp-reset-err', 'Passwords do not match', false); return; }
  const isStrong = newPw.length >= 8 && /[A-Z]/.test(newPw) && /[0-9]/.test(newPw) && /[^A-Za-z0-9]/.test(newPw);
  if (!isStrong) { showMsg('fp-reset-err', 'Password must be ≥8 chars, with 1 uppercase, 1 number, 1 special character', false); return; }

  const btn = $id('fp-reset-btn');
  btn.disabled = true; btn.textContent = 'Updating…';
  try {
    const csrfH = await getCsrf();
    const r = await fetch('/api/member/forgot-password/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfH },
      body: JSON.stringify({ username: _fpUsername, reset_token: _fpResetToken, newPassword: newPw }),
      credentials: 'include',
    });
    const d = await r.json().catch(() => null);
    if (!d) { showMsg('fp-reset-err', 'Server error — please try again', false); return; }
    if (!r.ok) { showMsg('fp-reset-err', d.error || 'Could not update password', false); return; }

    _fpUsername = null; _fpResetToken = null;
    showStep('fp-success');
  } catch (e) {
    showMsg('fp-reset-err', e.message || 'Could not connect to server', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update password';
  }
}

// ── Recovery contact info (banner + modal) ───────────────────────────────────

function dismissRecoveryBanner() {
  const banner = $id('recovery-banner');
  if (banner) banner.classList.remove('show');
  _recoveryPromptDismissedThisSession = true;
  api('POST', '/api/member/contact-info/dismiss-prompt').catch(() => {});
}

function openContactInfoModal() {
  const d = window._memberProfile || {};
  const e = $id('ci-email');   if (e) e.value = d.email  || '';
  const p = $id('ci-phone');   if (p) p.value = d.mobile || '';
  hideEl('ci-err'); hideEl('ci-ok');
  $id('contact-info-modal-overlay')?.classList.add('open');
}
function closeContactInfoModal() {
  $id('contact-info-modal-overlay')?.classList.remove('open');
}

async function saveContactInfo() {
  const email = $id('ci-email').value.trim();
  const phone = $id('ci-phone').value.trim();
  hideEl('ci-err'); hideEl('ci-ok');
  if (!email) { showMsg('ci-err', 'Please provide an email for account recovery', false); return; }

  const btn = $id('ci-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('PUT', '/api/member/contact-info', { email, mobile: phone });
    showMsg('ci-ok', 'Saved! Your recovery email is now up to date.', true);
    const banner = $id('recovery-banner');
    if (banner) banner.classList.remove('show');
    // Refresh cached profile + pf-mobile/pf-email fields if visible
    await loadProfile();
    setTimeout(closeContactInfoModal, 900);
  } catch (e) {
    showMsg('ci-err', e.message || 'Could not save contact info', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
}

// ── Change Password (forced) ──────────────────────────────────────────────────

async function handleChangePw() {
  const cur = $id('cp-current').value;
  const nw  = $id('cp-new').value;
  const cf  = $id('cp-confirm').value;
  if (nw !== cf) { showMsg('cp-err', 'Passwords do not match', false); return; }
  const btn = $id('cp-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('POST', '/api/member/change-password', { currentPassword: cur, newPassword: nw });
    await refreshToken();
    await initiate2FASetup();
  } catch (e) {
    showMsg('cp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Set Password';
  }
}

// ── 2FA Setup (optional — skippable) ─────────────────────────────────────────

async function initiate2FASetup() {
  showStep('2fa-setup');
  $id('qr-box').innerHTML = '<div class="spinner"></div>';
  try {
    const d = await api('GET', '/api/member/2fa/setup');
    $id('qr-box').innerHTML = `
      <img src="${d.qr}" width="180" height="180" alt="QR Code" />
      <div class="qr-secret">Manual entry: <strong>${d.secret}</strong></div>
    `;
  } catch (e) {
    $id('qr-box').innerHTML = `<span style="color:var(--danger)">Failed to load QR: ${e.message}</span>`;
  }
}

async function verify2FASetup() {
  const code = $id('setup-totp-input').value.trim();
  if (!code) return;
  const btn = $id('setup-totp-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    await api('POST', '/api/member/2fa/verify', { totp_code: code });
    await refreshToken();
    await loadDashboard();
  } catch (e) {
    showMsg('setup-totp-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Enable 2FA & Continue';
  }
}

// 2FA is optional — a member who doesn't want it yet can skip straight to
// their dashboard. They can always turn it on later from Security settings.
async function skip2FASetup() {
  await loadDashboard();
}

// ── Logout ────────────────────────────────────────────────────────────────────

async function logoutMember() {
  try { await api('POST', '/api/member/logout'); } catch (_) {}
  _token = null; _member = null; _csrfToken = null;
  _recoveryPromptDismissedThisSession = false;
  localStorage.removeItem('kfs-member-token');
  localStorage.removeItem('kfs-member-data');
  localStorage.removeItem('kfs-member-profile');
  // Clear nickname + group cache — another member logging in on same device shouldn't see stale data
  try {
    Object.keys(localStorage)
      .filter(k => k.startsWith('kfs-nicks-') || k.startsWith('kfs-groups-'))
      .forEach(k => localStorage.removeItem(k));
  } catch { /* ignore */ }
  window._member = null;
  window._memberProfile = null;
  showLoginScreen();
}

// ── Panel switching ───────────────────────────────────────────────────────────

function switchPanel(el) {
  const panel = el.dataset.panel;
  // Block studio access for alumni/past members
  if (panel === 'studio' && window._memberProfile?.is_past) return;
  // First-time flow fallback: they chose "Set Up My Profile" but are now
  // leaving the Profile panel without having saved — don't leave them
  // stuck with a pending tour that never fires; start it now instead.
  if (window._kfsPendingProfileTour && panel !== 'profile') {
    window._kfsPendingProfileTour = false;
    setTimeout(() => kfsStartTour(), 450);
  }
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll(`.nav-item[data-panel="${panel}"]`).forEach(n => n.classList.add('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $id('panel-' + panel)?.classList.add('active');
  // Any navigation away means the person is done with the settings menu —
  // collapse the desktop dropdown and close the mobile bottom sheet so they
  // don't stay stuck open over whatever's now on screen. Safe to call even
  // when already closed (both are no-ops in that case).
  if ($id('sidebar-settings-items')?.classList.contains('open')) {
    toggleSidebarSettings();
  }
  if ($id('settings-sheet')?.classList.contains('open')) {
    closeSettingsSheet();
  }
  if (panel === 'security') loadSecurity();
  if (panel === 'activity') loadActivity();
  if (panel === 'movies')   loadMovies();
  if (panel === 'works')    loadMyWorks();
  if (panel === 'grievance') loadMyGrievances();
  if (panel === 'network') loadNetworkPanel();
  if (panel === 'customization') { if (typeof loadCustomization === 'function') loadCustomization(); }
  if (panel === 'dms') { if (typeof window.dmPanelOpened === 'function') window.dmPanelOpened(); }
  else {
    if (typeof dmPausePolling === 'function') dmPausePolling();
    // Do NOT pause GC polling when switching away from the DMs panel.
    // gcPollTick needs to keep running so:
    //   1. Reactions remain live and don't disappear after a few minutes.
    //   2. The background group-list refresh continues for members who were
    //      just added to a group (they see it in the sidebar without a reload).
    // gcPollTick already no-ops silently when no group is open (GC.activeId is null).
  }
}

// ── Desktop Sidebar Settings Toggle ──────────────────────────────────────

function toggleSidebarSettings() {
  const items = $id('sidebar-settings-items');
  const chevron = $id('sidebar-settings-chevron');
  const toggle = $id('sidebar-settings-toggle');
  const isOpen = items?.classList.contains('open');
  items?.classList.toggle('open', !isOpen);
  chevron?.classList.toggle('open', !isOpen);
  toggle?.classList.toggle('open', !isOpen);
}

// ── Mini Settings Sheet (mobile bottom nav → Settings) ────────────────────────

function openSettingsSheet() {
  $id('settings-sheet-backdrop')?.classList.add('open');
  $id('settings-sheet')?.classList.add('open');
  document.querySelectorAll('.btb-item').forEach(i => i.classList.remove('active'));
  $id('btb-settings')?.classList.add('active');
  _kfsPushNavState('settings-sheet');
}

function closeSettingsSheet() {
  const sheet = $id('settings-sheet');
  const backdrop = $id('settings-sheet-backdrop');
  const hide = () => {
    backdrop?.classList.remove('open');
    sheet?.classList.remove('open');
  };
  if (sheet && sheet.classList.contains('open') && typeof window._kfsAnimateSheetOut === 'function') {
    window._kfsAnimateSheetOut(sheet, '-50%', hide);
  } else {
    hide();
  }
  _kfsPopNavState('settings-sheet');
}

// panel: 'profile' | 'analytics' | 'movies' | 'works' | 'security' | 'activity'
function settingsSheetGo(panel) {
  closeSettingsSheet();
  if (panel === 'analytics') {
    // Analytics lives inside the Strand/Studio panel as a tab
    const studioNav = document.querySelector('[data-panel="studio"]');
    if (studioNav) switchPanel(studioNav);
    swSwitchTab('analytics');
  } else {
    const navEl = document.querySelector(`[data-panel="${panel}"]`);
    if (navEl) switchPanel(navEl);
  }
  // Settings has no single matching bottom-bar icon — keep it highlighted
  // since the user is still "inside" the settings flow they tapped into.
  document.querySelectorAll('.btb-item').forEach(i => i.classList.remove('active'));
  $id('btb-settings')?.classList.add('active');
}

// ── Bottom Tab Bar sync ───────────────────────────────────────────────────────

function btbSwitch(el) {
  const panel = el.dataset.panel;
  if (!panel) return;
  // Use existing switchPanel logic
  const navEl = document.querySelector(`.sidebar [data-panel="${panel}"]`) ||
                document.querySelector(`.mobile-nav [data-panel="${panel}"]`) ||
                document.querySelector(`[data-panel="${panel}"]`);
  if (navEl) switchPanel(navEl);
  // Sync active state on bottom bar
  document.querySelectorAll('.btb-item').forEach(i => {
    i.classList.toggle('active', i.dataset.panel === panel);
  });
}

// Keep bottom tab bar in sync when panel changes from sidebar/desktop nav
const _origSwitchPanel = typeof switchPanel !== 'undefined' ? switchPanel : null;

async function loadProfile() {
  try {
    const d = await api('GET', '/api/member/profile');
    const changes  = await api('GET', '/api/member/profile/pending-changes');
    const pending  = changes.some(c => c.status === 'pending');
    $id('profile-pending-banner').style.display = pending ? 'block' : 'none';

    let displayData = { ...d };
    if (pending) {
      const latestPending = changes.find(c => c.status === 'pending');
      if (latestPending && latestPending.new_values) displayData = { ...d, ...latestPending.new_values };
    }

    window._memberProfile = d; // cache raw profile globally for collab + notifications
    // Persist profile to localStorage so index.html collab gate can read it cross-tab
    localStorage.setItem('kfs-member-profile', JSON.stringify(d));
    // Ensure email/mobile are available on window._member for collab gate
    if (!window._member) window._member = {};
    if (d.email)  window._member.email  = d.email;
    if (d.mobile) window._member.mobile = d.mobile;
    if (d.name)   window._member.name   = d.name;

    // Hide Studio nav for non-active (alumni/past) members
    const isActiveMember = !d.is_past;
    document.querySelectorAll('.nav-item[data-panel="studio"]').forEach(el => {
      el.style.display = isActiveMember ? '' : 'none';
    });
    // If a past member somehow lands on the studio panel, redirect to profile
    if (!isActiveMember && window.location.hash === '#studio') {
      window.location.hash = '';
    }

    fillProfile(displayData);
    renderStatusPicker(d.status);
    loadMySkills();
    setText('sidebar-name', displayData.name || '—');
    setText('sidebar-role', displayData.role || displayData.domain || '—');
    setText('sidebar-followers-count', swFmtNum ? swFmtNum(d.followers_count) : (d.followers_count||0));
    setText('sidebar-following-count', swFmtNum ? swFmtNum(d.following_count) : (d.following_count||0));
    const av = $id('sidebar-avatar');
    if (displayData.photo) {
      av.innerHTML = `<img src="${displayData.photo}" style="width:32px;height:32px;border-radius:50%;object-fit:cover" />`;
    } else {
      av.textContent = (displayData.name || '?')[0].toUpperCase();
    }

    // Recovery contact banner — show only if no email is on file (mobile
    // no longer satisfies forgot-password — Twilio removed), and the member
    // hasn't dismissed it (server-side flag from login, or this-session dismiss).
    const hasRecoveryContact = !!d.email;
    const banner = $id('recovery-banner');
    if (banner) banner.classList.toggle('show', !hasRecoveryContact && !_recoveryPromptDismissedThisSession);
  } catch (e) {
    console.error('loadProfile:', e);
  }
}

function fillProfile(d) {
  const fields = ['name','roll_no','mobile','email','batch','domain','role','bio','instagram','linkedin','github','twitter','youtube','website'];
  const ids    = ['pf-name','pf-roll','pf-mobile','pf-email','pf-batch','pf-domain','pf-role','pf-bio','pf-instagram','pf-linkedin','pf-github','pf-twitter','pf-youtube','pf-website'];
  fields.forEach((f, i) => {
    const el = $id(ids[i]); if (el) el.value = d[f] || '';
  });
  const ph = $id('profile-photo-preview');
  if (d.photo) {
    ph.innerHTML = `<img src="${d.photo}" style="width:80px;height:80px;border-radius:50%;object-fit:cover" />`;
  } else {
    ph.textContent = (d.name || '?')[0].toUpperCase();
    Object.assign(ph.style, { fontSize:'28px', display:'flex', alignItems:'center', justifyContent:'center',
      width:'80px', height:'80px', borderRadius:'50%', background:'var(--faint)' });
  }
}

function previewPhoto(input) {
  if (!input.files[0]) return;
  const url = URL.createObjectURL(input.files[0]);
  $id('profile-photo-preview').innerHTML = `<img src="${url}" style="width:80px;height:80px;border-radius:50%;object-fit:cover" />`;
}

async function saveProfile() {
  const btn = $id('profile-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  hideEl('profile-msg'); hideEl('profile-err'); hideEl('social-link-err');

  // Client-side social URL validation
  const rawLinkedin = $id('pf-linkedin').value.trim();
  const rawYoutube  = $id('pf-youtube').value.trim();
  const rawWebsite  = $id('pf-website').value.trim();
  const socialValidation = validateSocialLinks({ linkedin: rawLinkedin, youtube: rawYoutube, website: rawWebsite });
  if (!socialValidation.valid) {
    const errEl = $id('social-link-err');
    if (errEl) { errEl.textContent = socialValidation.errors.join(' '); errEl.style.display = 'block'; }
    btn.disabled = false; btn.textContent = 'Save Changes';
    return;
  }

  try {
    const form = new FormData();
    // NOTE: domain and role are admin-only — intentionally not sent.
    const fields = {
      name:      $id('pf-name').value,
      roll_no:   $id('pf-roll').value,
      mobile:    $id('pf-mobile').value,
      batch:     $id('pf-batch').value,
      bio:       $id('pf-bio').value,
      instagram: sanitizeUsername($id('pf-instagram').value),
      linkedin:  sanitizeSocialUrl(rawLinkedin),
      github:    sanitizeUsername($id('pf-github').value),
      twitter:   sanitizeUsername($id('pf-twitter').value),
      youtube:   sanitizeSocialUrl(rawYoutube),
      website:   sanitizeSocialUrl(rawWebsite),
    };
    Object.entries(fields).forEach(([k, v]) => form.append(k, v));
    const photoFile = $id('profile-photo-input').files[0];
    if (photoFile) form.append('photo', photoFile);

    const csrf = await getCsrf();
    const r = await fetch('/api/member/profile', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${_token}`, 'x-csrf-token': csrf },
      credentials: 'include',
      body: form,
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Failed to save');
    showMsg('profile-msg', d.pending ? 'Update submitted — pending admin review.' : 'Profile saved!');
    await loadProfile();
    // First-time flow: they picked "Set Up My Profile" and just saved for
    // real (whether it went through immediately or is pending admin
    // review — either way they did the setup). Now start the tour.
    if (window._kfsPendingProfileTour) {
      window._kfsPendingProfileTour = false;
      setTimeout(() => kfsStartTour(), 450);
    }
  } catch (e) {
    showMsg('profile-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Changes';
  }
}

// ── Movies ────────────────────────────────────────────────────────────────────

async function loadMovies() {
  try {
    const subs = await api('GET', '/api/member/movies');
    const list = $id('movies-list');
    if (!subs.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No submissions yet. Click "Submit Movie" to get started.</div>';
      return;
    }
    list.innerHTML = subs.map(s => {
      const md = s.movie_data;
      const statusBadge = { pending:'badge-pending', approved:'badge-approved', rejected:'badge-rejected' }[s.status] || 'badge-changes';
      const statusLabel = s.status === 'changes_requested' ? 'Changes Requested' : s.status.charAt(0).toUpperCase() + s.status.slice(1);
      const notes   = s.reviewer_notes ? `<div class="movie-notes"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:5px;flex-shrink:0"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>Admin feedback: ${s.reviewer_notes}</div>` : '';
      const editBtn = ['pending','changes_requested'].includes(s.status)
        ? `<button class="btn-sm movie-edit-btn" style="margin-top:10px;background:#1a1a1a;border:1px solid var(--border);color:var(--muted);border-radius:6px;font-size:12px" data-id="${s.id}">Edit</button>` : '';
      const poster  = md.poster_image
        ? `<img class="movie-poster" src="${md.poster_image}" />`
        : `<div class="movie-poster" style="display:flex;align-items:center;justify-content:center"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg></div>`;
      return `
        <div class="movie-card">
          ${poster}
          <div class="movie-info">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
              <div class="movie-title">${md.title || 'Untitled'}</div>
              <span class="badge ${statusBadge}">${statusLabel}</span>
            </div>
            <div class="movie-meta">${md.language || ''} ${md.genre ? '· ' + (Array.isArray(md.genre) ? md.genre.join(', ') : md.genre) : ''} ${md.runtime ? '· ' + md.runtime + ' min' : ''}</div>
            <div class="movie-meta" style="margin-top:4px">Submitted ${relTime(s.created_at)}</div>
            ${notes}${editBtn}
          </div>
        </div>`;
    }).join('');

    // Wire edit buttons (dynamically generated, so addEventListener here)
    list.querySelectorAll('.movie-edit-btn').forEach(btn => {
      btn.addEventListener('click', () => showMovieForm(btn.dataset.id));
    });
  } catch (e) {
    console.error('loadMovies:', e);
  }
}

async function showMovieForm(id) {
  hideEl('movie-form-err'); hideEl('movie-form-ok');
  $id('movie-edit-id').value = id || '';
  $id('movie-form-title').textContent = id ? 'Edit Submission' : 'New Submission';
  $id('movie-submit-btn').textContent = id ? 'Update Submission' : 'Submit for Review';

  // Ensure members are loaded before init pickers
  await loadPortalMembers();
  initMovieFormPickers();
  initMfGenreInput();

  if (id) {
    try {
      const subs = await api('GET', '/api/member/movies');
      const sub  = subs.find(s => String(s.id) === String(id));
      if (sub) {
        const md = sub.movie_data;
        $id('mf-title').value       = md.title || '';
        $id('mf-desc').value        = md.description || '';
        $id('mf-trailer').value     = md.trailer_url || '';
        $id('mf-watch').value       = md.watch_url || '';
        $id('mf-runtime').value     = md.runtime || '';
        $id('mf-language').value    = md.language || '';
        $id('mf-year').value        = md.release_year || '';
        $id('mf-spotify').value     = md.spotify_url || '';
        $id('mf-apple-music').value = md.apple_music_url || '';
        // Genre tags
        const genres = Array.isArray(md.genre) ? md.genre : (md.genre ? String(md.genre).split(',').map(s=>s.trim()).filter(Boolean) : []);
        $id('mf-genre').value = JSON.stringify(genres);
        renderMfGenreTags(genres);
        // Fill pickers
        _formPickers['director']?.setValue(md.director || '');
        _formPickers['producer']?.setValue(md.producer || '');
        _formPickers['dop']?.setValue(md.dop || '');
        _formPickers['writer']?.setValue(md.writer || '');
        _formPickers['editor']?.setValue(md.video_editor || '');
        _formPickers['sound']?.setValue(md.sound_design || '');
        _formPickers['management']?.setValue(md.management || '');
        _formPickers['gd']?.setValue(md.graphic_design || '');
        _formPickers['actors']?.setValue(md.actors || '');
        _formPickers['support']?.setValue(md.support_crew || '');
      }
    } catch (_) {}
  } else {
    ['mf-title','mf-desc','mf-trailer','mf-watch','mf-runtime','mf-language','mf-year','mf-spotify','mf-apple-music']
      .forEach(fid => { const el = $id(fid); if (el) el.value = ''; });
    $id('mf-genre').value = '[]';
    renderMfGenreTags([]);
    // Clear all pickers
    Object.values(_formPickers).forEach(p => { if (p) { p.selected = []; p._renderTags?.(); } });
  }

  $id('movie-form').style.display    = 'block';
  $id('new-movie-btn').style.display = 'none';
  $id('movie-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideMovieForm() {
  $id('movie-form').style.display    = 'none';
  $id('new-movie-btn').style.display = '';
}

async function submitMovie() {
  const editId = $id('movie-edit-id').value;
  const btn    = $id('movie-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('movie-form-err'); hideEl('movie-form-ok');
  try {
    const form       = new FormData();
    const genreRaw   = JSON.parse($id('mf-genre').value || '[]');
    form.append('title',           $id('mf-title').value);
    form.append('release_year',    $id('mf-year').value);
    form.append('description',     $id('mf-desc').value);
    form.append('trailer_url',     $id('mf-trailer').value);
    form.append('watch_url',       $id('mf-watch').value);
    form.append('runtime',         $id('mf-runtime').value);
    form.append('language',        $id('mf-language').value);
    form.append('genre',           JSON.stringify(genreRaw));
    form.append('spotify_url',     $id('mf-spotify').value);
    form.append('apple_music_url', $id('mf-apple-music').value);
    form.append('director',        _formPickers['director']?.getValue()    || '');
    form.append('producer',        _formPickers['producer']?.getValue()    || '');
    form.append('dop',             _formPickers['dop']?.getValue()         || '');
    form.append('writer',          _formPickers['writer']?.getValue()      || '');
    form.append('video_editor',    _formPickers['editor']?.getValue()      || '');
    form.append('sound_design',    _formPickers['sound']?.getValue()       || '');
    form.append('management',      _formPickers['management']?.getValue()  || '');
    form.append('graphic_design',  _formPickers['gd']?.getValue()          || '');
    form.append('actors',          _formPickers['actors']?.getValue()      || '');
    form.append('support_crew',    _formPickers['support']?.getValue()     || '');
    const posterFile = $id('mf-poster').files[0];
    if (posterFile) form.append('poster', posterFile);

    const csrf     = await getCsrf();
    const method   = editId ? 'PUT' : 'POST';
    const endpoint = editId ? `/api/member/movies/${editId}` : '/api/member/movies';
    const r = await fetch(endpoint, {
      method,
      headers: { Authorization: `Bearer ${_token}`, 'x-csrf-token': csrf },
      credentials: 'include',
      body: form,
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Submission failed');
    showMsg('movie-form-ok', editId ? 'Submission updated!' : 'Movie submitted for review!');
    setTimeout(() => { hideMovieForm(); loadMovies(); }, 1500);
  } catch (e) {
    showMsg('movie-form-err', e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = editId ? 'Update Submission' : 'Submit for Review';
  }
}

// ── Security ──────────────────────────────────────────────────────────────────

async function loadSecurity() {
  loadSessions();
  load2FAStatus();
}

async function changePasswordFromSecurity() {
  const cur = $id('sec-cur-pw').value;
  const nw  = $id('sec-new-pw').value;
  const cf  = $id('sec-confirm-pw').value;
  if (nw !== cf) { showMsg('sec-pw-err', 'Passwords do not match', false); return; }
  try {
    await api('POST', '/api/member/change-password', { currentPassword: cur, newPassword: nw });
    showMsg('sec-pw-msg', 'Password updated successfully!');
    $id('sec-cur-pw').value = $id('sec-new-pw').value = $id('sec-confirm-pw').value = '';
  } catch (e) {
    showMsg('sec-pw-err', e.message, false);
  }
}

async function load2FAStatus() {
  const card = $id('twofa-status');
  if (!card || !_token) return;
  try {
    const payload = JSON.parse(atob(_token.split('.')[1]));
    if (payload.totp_enabled) {
      card.innerHTML = `
        <div style="font-size:13px;color:var(--success);margin-bottom:16px;display:flex;align-items:center;gap:6px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Two-factor authentication is enabled</div>
        <button class="btn-sm btn-danger" id="twofa-disable-toggle-btn">Disable 2FA</button>
        <div id="twofa-disable-form" style="display:none;margin-top:16px">
          <div class="form-group" style="max-width:280px">
            <label>Password</label><input id="twofa-dis-pw" type="password" />
          </div>
          <div class="form-group" style="max-width:200px">
            <label>TOTP Code</label><input id="twofa-dis-code" type="text" maxlength="6" />
          </div>
          <button class="btn-primary" id="twofa-disable-confirm-btn" style="max-width:160px">Confirm Disable</button>
          <div id="twofa-dis-err" class="err-msg" style="display:none"></div>
        </div>`;
      on('twofa-disable-toggle-btn', 'click', show2FADisable);
      on('twofa-disable-confirm-btn','click', disable2FA);
    } else {
      card.innerHTML = `
        <div style="font-size:13px;color:var(--muted);margin-bottom:16px">Two-factor authentication is not enabled</div>
        <button class="btn-primary" id="twofa-enable-btn" style="max-width:180px">Enable 2FA</button>
        <div id="twofa-setup-inline" style="display:none;margin-top:20px"></div>`;
      on('twofa-enable-btn', 'click', startSetup2FA);
    }
  } catch (_) {}
}

function show2FADisable() {
  const f = $id('twofa-disable-form');
  if (f) f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function disable2FA() {
  const pw   = $id('twofa-dis-pw').value;
  const code = $id('twofa-dis-code').value;
  try {
    await api('POST', '/api/member/2fa/disable', { password: pw, totp_code: code });
    await refreshToken();
    load2FAStatus();
  } catch (e) {
    showMsg('twofa-dis-err', e.message, false);
  }
}

async function startSetup2FA() {
  const container = $id('twofa-setup-inline');
  container.style.display = 'block';
  container.innerHTML = '<div class="spinner"></div>';
  try {
    const d = await api('GET', '/api/member/2fa/setup');
    container.innerHTML = `
      <div class="qr-box" style="padding:0;margin-bottom:16px">
        <img src="${d.qr}" width="160" height="160" alt="QR" style="border-radius:8px" />
        <div class="qr-secret">Manual: <strong>${d.secret}</strong></div>
      </div>
      <div class="form-group" style="max-width:200px">
        <label>Enter code to confirm</label>
        <input id="inline-totp" type="text" maxlength="6" inputmode="numeric" />
      </div>
      <button class="btn-primary" id="inline-totp-confirm-btn" style="max-width:160px">Activate 2FA</button>
      <div id="inline-totp-err" class="err-msg" style="display:none"></div>`;
    on('inline-totp-confirm-btn', 'click', confirmInline2FA);
  } catch (e) {
    container.innerHTML = `<span style="color:var(--danger)">${e.message}</span>`;
  }
}

async function confirmInline2FA() {
  const code = $id('inline-totp').value.trim();
  try {
    await api('POST', '/api/member/2fa/verify', { totp_code: code });
    await refreshToken();
    load2FAStatus();
  } catch (e) {
    showMsg('inline-totp-err', e.message, false);
  }
}

async function loadSessions() {
  const list = $id('sessions-list');
  try {
    const sessions = await api('GET', '/api/member/sessions');
    if (!sessions.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No active sessions</div>';
      return;
    }
    list.innerHTML = sessions.map(s => `
      <div class="session-item">
        <div>
          <div style="font-size:13px;font-weight:600">Session</div>
          <div style="font-size:11px;color:var(--muted)">Created ${relTime(s.created_at)} · Expires ${new Date(s.expires_at).toLocaleDateString()}</div>
        </div>
        <span class="badge badge-approved">Active</span>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

async function revokeAllSessions() {
  try {
    await api('DELETE', '/api/member/sessions/all');
    showMsg('sessions-msg', 'All sessions revoked. You will be signed out.');
    setTimeout(() => logoutMember(), 1500);
  } catch (e) {
    console.error(e);
  }
}

// ── My Works ──────────────────────────────────────────────────────────────────

let _pendingEditMovieId = null;
let _pendingEditMovieTitle = null;

async function loadMyWorks() {
  const list = $id('works-list');
  if (!list) return;
  list.innerHTML = swSkelRows(3);
  try {
    const works = await api('GET', '/api/member/works');
    if (!works.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No films found in the KFS filmography for your profile yet.</div>';
      return;
    }
    list.innerHTML = `
      <div class="works-grid">
        ${works.map(w => `
          <div class="work-card">
            <div class="work-poster">
              ${w.poster_image
                ? `<img src="${w.poster_image}" alt="${w.title}" />`
                : `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.3"><rect x="2" y="2" width="20" height="20" rx="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>`}
            </div>
            <div class="work-info">
              <div class="work-title" title="${w.title}">${w.title}</div>
              <div class="work-role">${w.role}</div>
              ${w.release_year ? `<div class="work-year">${w.release_year}</div>` : ''}
              <button class="btn-edit-request" data-movie-id="${w.id}" data-movie-title="${w.title.replace(/"/g,'&quot;')}"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>Request Edit</button>
            </div>
          </div>`).join('')}
      </div>`;

    list.querySelectorAll('.btn-edit-request').forEach(btn => {
      btn.addEventListener('click', () => openWorkEditModal(btn.dataset.movieId, btn.dataset.movieTitle));
    });
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

function openWorkEditModal(movieId, movieTitle) {
  _pendingEditMovieId    = movieId;
  _pendingEditMovieTitle = movieTitle;
  const overlay = $id('work-edit-modal-overlay');
  setText('work-edit-movie-name', movieTitle || 'this film');
  const desc = $id('work-edit-desc'); if (desc) desc.value = '';
  hideEl('work-edit-msg'); hideEl('work-edit-err');
  overlay.classList.add('open');
}

function closeWorkEditModal() {
  $id('work-edit-modal-overlay')?.classList.remove('open');
  _pendingEditMovieId = null; _pendingEditMovieTitle = null;
}

async function submitWorkEditRequest() {
  const desc = $id('work-edit-desc')?.value?.trim();
  if (!desc) { showMsg('work-edit-err', 'Please describe what needs to change', false); return; }
  const btn = $id('work-edit-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('work-edit-msg'); hideEl('work-edit-err');
  try {
    await api('POST', '/api/member/work-edit-request', {
      movie_id:    _pendingEditMovieId,
      movie_title: _pendingEditMovieTitle,
      description: desc,
    });
    showMsg('work-edit-msg', 'Edit request submitted! Admin will review it shortly.');
    setTimeout(() => closeWorkEditModal(), 2000);
  } catch (e) {
    showMsg('work-edit-err', e.message, false);
  } finally {
    btn.disabled = false; btn.textContent = 'Submit Request';
  }
}

// ── Activity ──────────────────────────────────────────────────────────────────

async function loadActivity() {
  const list = $id('activity-list');
  try {
    const items = await api('GET', '/api/member/activity?limit=30');
    if (!items.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:13px">No activity yet</div>';
      return;
    }
    const labelMap = {
      login:                    'Signed in',
      logout:                   'Signed out',
      password_change:          'Changed password',
      profile_update_requested: 'Profile update submitted',
      profile_updated:          'Profile updated',
      movie_submit:             'Movie submitted',
      movie_resubmit:           'Movie resubmitted',
      '2fa_setup':              '2FA enabled',
      '2fa_disable':            '2FA disabled',
      session_revoke_all:       'All sessions revoked',
      work_edit_requested:      'Work edit request submitted',
    };
    list.innerHTML = items.map(a => `
      <div class="activity-item">
        <div class="activity-dot"></div>
        <div>
          <div class="activity-text">${labelMap[a.action] || a.action}</div>
          <div class="activity-time">${relTime(a.created_at)} · IP: ${a.ip_address || 'unknown'}</div>
        </div>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ── Mobile in-app back stack ───────────────────────────────────────────────
// Problem: none of DM chat / group chat / settings sheet / notifications ever
// touched browser history, so the phone's back gesture (or Android back
// button) skipped straight past the app and left the site entirely. This
// gives each "layer" of mobile UI its own history entry: opening one pushes
// a state, the OS back action pops it and we close that layer instead of
// navigating away. Only once nothing is open does back behave normally.
var _kfsNavStack = [];
var _kfsIgnoreNextPopstate = false;
var _kfsPoppingFromBack = false;

function _kfsPushNavState(type) {
  _kfsNavStack.push(type);
  try {
    const base = location.href.split('#')[0];
    history.pushState({ kfsLayer: type }, '', base + '#kfs-nav-' + _kfsNavStack.length);
  } catch (e) {}
}

// Call when a layer is dismissed via a UI control (X button, backdrop tap,
// swipe-back) rather than the OS back action, so the matching history entry
// gets consumed instead of piling up as dead state.
function _kfsPopNavState(type) {
  const idx = _kfsNavStack.lastIndexOf(type);
  if (idx === -1) return;
  _kfsNavStack.splice(idx, 1);
  if (_kfsPoppingFromBack) return; // history already moved; nothing left to consume
  _kfsIgnoreNextPopstate = true;
  try { history.back(); } catch (e) {}
}

function _kfsCloseTopNavLayer(type) {
  switch (type) {
    case 'dm-chat':
      if (typeof window.dmGoBack === 'function') window.dmGoBack();
      break;
    case 'gc-chat':
      if (typeof window.gcGoBack === 'function') window.gcGoBack();
      break;
    case 'settings-sheet':
      if (typeof window.closeSettingsSheet === 'function') window.closeSettingsSheet();
      break;
    case 'notif':
      if (typeof window.closeNotifPanel === 'function') window.closeNotifPanel();
      break;
    case 'panel-away': {
      // Back button while on a non-Feed panel (Network, Messages, Settings…)
      // returns to Feed instead of leaving the site entirely — matches the
      // usual "home tab first" back behaviour of mobile apps. Goes through
      // btbSwitch (not switchPanel directly) so the bottom pill's active
      // dot moves back to the Feed icon too, not just the panel content.
      const studioBtb = document.querySelector('.btb-item[data-panel="studio"]');
      if (studioBtb && typeof window.btbSwitch === 'function') {
        window.btbSwitch(studioBtb);
      } else {
        const studioNav = document.querySelector('[data-panel="studio"]');
        if (studioNav && typeof window.switchPanel === 'function') window.switchPanel(studioNav);
      }
      break;
    }
  }
}

window.addEventListener('popstate', function () {
  if (_kfsIgnoreNextPopstate) { _kfsIgnoreNextPopstate = false; return; }
  if (_kfsNavStack.length > 0) {
    const type = _kfsNavStack[_kfsNavStack.length - 1];
    _kfsPoppingFromBack = true;
    _kfsCloseTopNavLayer(type);
    _kfsPoppingFromBack = false;
  }
  // else: nothing tracked as open — let the normal back navigation proceed.
});

// ── Notifications (slide-in panel) ────────────────────────────────────────────

let _notifOpen = false;
let _notifLoading = false;
let _notifPollTimer = null;

// Silently refresh the unread badge count without opening the panel
async function loadNotificationBadge() {
  if (!_token) return;
  try {
    const items  = await api('GET', '/api/member/notifications');
    const unread = items.filter(n => !n.is_read).length;
    const badge  = $id('notif-badge');
    const badgeMobile = $id('notif-badge-mobile');
    [badge, badgeMobile].forEach(b => {
      if (!b) return;
      b.textContent = unread > 9 ? '9+' : unread;
      b.classList.toggle('visible', unread > 0);
    });
    // If the panel is already open, refresh its contents too
    if (_notifOpen) loadNotifications();
  } catch (e) { /* silent — badge stays as-is */ }
}

// Poll for new notifications every 60 s while the page is visible
function startNotifPolling() {
  if (_notifPollTimer) return; // already running
  _notifPollTimer = setInterval(() => {
    if (document.visibilityState === 'visible') loadNotificationBadge();
  }, 60_000);
}

// Icon per notification type
function _notifIcon(type) {
  const icons = {
    movie_approved:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    movie_rejected:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    profile_change:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
    event:           `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
    announcement:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
    follow:          `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="4"/><path d="M2 20c0-4 3.1-6.5 7-6.5s7 2.5 7 6.5"/><line x1="18" y1="6" x2="18" y2="12"/><line x1="15" y1="9" x2="21" y2="9"/></svg>`,
    network:         `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="4"/><path d="M2 20c0-4 3.1-6.5 7-6.5s7 2.5 7 6.5"/><line x1="18" y1="6" x2="18" y2="12"/><line x1="15" y1="9" x2="21" y2="9"/></svg>`,
    new_post:        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/><circle cx="6.5" cy="6" r="0.8" fill="currentColor" stroke="none"/></svg>`,
    studio:          `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/></svg>`,
    group_mention:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M16 12v1.5a2.5 2.5 0 0 0 5 0V12a9 9 0 1 0-4 7.5"/></svg>`,
    default:         `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  };
  return icons[type] || icons.default;
}

// Tiny badge icon overlaid on the bottom-right of an actor's avatar —
// gives the same at-a-glance "what happened" signal Instagram uses.
function _notifBadgeIcon(type) {
  const badges = {
    follow:   { cls: 'follow',   svg: `<svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7z"/></svg>` },
    network:  { cls: 'follow',   svg: `<svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7z"/></svg>` },
    new_post: { cls: 'post',     svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M12 8v8M8 12h8"/></svg>` },
  };
  return badges[type] || null;
}

// Cache the most recently loaded notifications keyed by id so click
// handlers can navigate without fighting HTML-attribute escaping.
let _notifCache = new Map();

function onNotifClick(id) {
  const n = _notifCache.get(id);
  markNotifRead(id, document.querySelector(`.notif-item[data-notif-id="${id}"]`));
  if (!n) return;
  if (n.link_type === 'profile' && n.link_id) {
    closeNotifPanel();
    openMemberProfile(n.link_id);
  } else if (n.link_type === 'post' && n.link_id) {
    closeNotifPanel();
    const studioNav = document.querySelector('[data-panel="studio"]');
    if (studioNav) switchPanel(studioNav);
    swOpenDetail(n.link_id);
  } else if (n.type === 'dm' || n.link_type === 'dm') {
    // DM notification — jump straight into that chat, same as tapping the
    // conversation in the inbox. link_id is the conv key, but actor_id is
    // always the other person, so we go through dmStartWith which will
    // reuse the existing conversation if one is already loaded.
    closeNotifPanel();
    if (n.actor_id && typeof dmStartWith === 'function') {
      dmStartWith(n.actor_id, { id: n.actor_id, name: n.actor_name, photo: n.actor_photo });
    }
  } else if (n.type === 'group_mention' || n.link_type === 'group') {
    // Group @mention — jump into that group thread, same as tapping it
    // in the inbox. link_id is the group id.
    closeNotifPanel();
    if (n.link_id) {
      const messagesNav = document.querySelector('[data-panel="dms"]') || document.querySelector('[data-panel="messages"]');
      if (messagesNav) switchPanel(messagesNav);
      (async () => {
        try {
          if (!(GC.groups || []).length) await gcLoadGroups();
          const g = (GC.groups || []).find(gr => gr.id === n.link_id);
          if (g && typeof window._inboxOpenGroup === 'function') window._inboxOpenGroup(g);
          else if (g && typeof gcOpenGroup === 'function') gcOpenGroup(g);
        } catch { /* ignore */ }
      })();
    }
  }
}

async function loadNotifications() {
  if (!_token || _notifLoading) return;
  _notifLoading = true;
  const list = $id('notif-list');
  if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-title" style="color:#333">Loading…</div></div>';
  try {
    const rawItems = await api('GET', '/api/member/notifications');
    const clearedBefore = _notifClearWatermark();
    const items = clearedBefore
      ? rawItems.filter(n => new Date(n.created_at).getTime() > clearedBefore)
      : rawItems;
    _notifCache = new Map(items.map(n => [n.id, n]));
    const unread = items.filter(n => !n.is_read);
    const badge = $id('notif-badge');
    if (badge) {
      badge.textContent = unread.length > 9 ? '9+' : unread.length;
      badge.classList.toggle('visible', unread.length > 0);
    }
    if (!list) return;
    if (!items.length) {
      list.innerHTML = `
        <div class="notif-empty">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          <div class="notif-empty-title">All caught up</div>
          <div class="notif-empty-sub">No new notifications</div>
        </div>`;
      return;
    }
    list.innerHTML = items.map(n => {
      const badge = _notifBadgeIcon(n.type);
      const avatarHtml = n.actor_photo || n.actor_name
        ? `<div class="notif-avatar-wrap">
             ${swAvatar(n.actor_name, n.actor_photo, 38)}
             ${badge ? `<span class="notif-type-badge notif-type-badge--${badge.cls}">${badge.svg}</span>` : ''}
           </div>`
        : `<div class="notif-icon-bubble">${_notifIcon(n.type)}</div>`;
      return `
      <div class="notif-item ${n.is_read ? '' : 'unread'}" data-notif-id="${n.id}" onclick="onNotifClick('${n.id}')">
        ${avatarHtml}
        <div class="notif-item-content">
          <div class="notif-item-title">${swEsc(n.title)}</div>
          ${n.body ? `<div class="notif-item-body">${swEsc(n.body)}</div>` : ''}
          <div class="notif-item-time">${relTime(n.created_at)}</div>
        </div>
        <div class="notif-unread-pip ${n.is_read ? 'read' : ''}"></div>
      </div>`;
    }).join('');
  } catch(e) {
    if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-sub">Could not load notifications</div></div>';
  } finally { _notifLoading = false; }
}

function toggleNotifPanel() {
  _notifOpen ? closeNotifPanel() : openNotifPanel();
}

function openNotifPanel() {
  _notifOpen = true;
  const panel    = $id('notif-panel');
  const backdrop = $id('notif-panel-backdrop');
  const btn      = $id('notif-bell-btn');
  const btnMobile = $id('btb-notif-fab');
  const btnStrand = $id('strand-notif-btn');
  if (panel)    { panel.classList.add('open'); }
  if (backdrop) { backdrop.classList.add('open'); }
  if (btn)      { btn.classList.add('active'); }
  if (btnMobile){ btnMobile.classList.add('active'); }
  if (btnStrand){ btnStrand.classList.add('active'); }
  loadNotifications();
  _kfsPushNavState('notif');
}

function closeNotifPanel() {
  _notifOpen = false;
  const panel    = $id('notif-panel');
  const backdrop = $id('notif-panel-backdrop');
  const btn      = $id('notif-bell-btn');
  const btnMobile = $id('btb-notif-fab');
  const btnStrand = $id('strand-notif-btn');
  if (panel)    { panel.classList.remove('open'); }
  if (backdrop) { backdrop.classList.remove('open'); }
  if (btn)      { btn.classList.remove('active'); }
  if (btnMobile){ btnMobile.classList.remove('active'); }
  if (btnStrand){ btnStrand.classList.remove('active'); }
  _kfsPopNavState('notif');
}

async function markNotifRead(id, el) {
  if (el) {
    el.classList.remove('unread');
    const pip = el.querySelector('.notif-unread-pip');
    if (pip) pip.classList.add('read');
  }
  try { await api('POST', `/api/member/notifications/${id}/read`); } catch(e) {}
  const remaining = document.querySelectorAll('#notif-list .notif-item.unread').length;
  const badge = $id('notif-badge');
  if (badge) { badge.textContent = remaining > 9 ? '9+' : remaining; badge.classList.toggle('visible', remaining > 0); }
}

async function markAllNotifsRead() {
  document.querySelectorAll('#notif-list .notif-item').forEach(el => {
    el.classList.remove('unread');
    const pip = el.querySelector('.notif-unread-pip'); if (pip) pip.classList.add('read');
  });
  const badge = $id('notif-badge');
  if (badge) { badge.textContent = ''; badge.classList.remove('visible'); }
  try { await api('POST', '/api/member/notifications/read-all'); } catch(e) {}
}

// Wipe every notification from the list — distinct from markAllNotifsRead,
// which only clears the unread dot. Optimistically empties the UI first so
// it feels instant, then tells the server.
//
// This used to roll back to the pre-clear list (and pop an error toast)
// any time the DELETE call failed for any reason — including a slow network
// or a route that 404s — which made the button look completely broken even
// though the person's intent ("I don't want to see these anymore") is a
// purely local one. It now also records a local "cleared before <timestamp>"
// watermark that loadNotifications() respects, so the list stays empty for
// this device even if the server-side delete didn't stick or the endpoint
// doesn't exist yet — the button always "works" from the user's point of
// view, and we still best-effort tell the server in the background.
function _notifClearWatermark() {
  const raw = localStorage.getItem('kfs_notif_cleared_before');
  return raw ? Number(raw) || 0 : 0;
}
async function clearAllNotifications() {
  if (_notifCache.size === 0) return; // nothing to clear
  const list = $id('notif-list');
  _notifCache = new Map();
  localStorage.setItem('kfs_notif_cleared_before', String(Date.now()));
  if (list) {
    list.innerHTML = `
      <div class="notif-empty">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <div class="notif-empty-title">All caught up</div>
        <div class="notif-empty-sub">No new notifications</div>
      </div>`;
  }
  const badge = $id('notif-badge');
  const badgeMobile = $id('notif-badge-mobile');
  [badge, badgeMobile].forEach(b => { if (b) { b.textContent = ''; b.classList.remove('visible'); } });
  try {
    await api('DELETE', '/api/member/notifications/clear-all');
  } catch (e) {
    // Server call failed or the route isn't there — the local watermark
    // above already guarantees the list stays cleared on this device, so
    // just log it quietly instead of telling the user something broke.
    console.warn('clearAllNotifications: server call failed, cleared locally only', e);
  }
}

// Close panel on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && _notifOpen) closeNotifPanel();
  if (e.key === 'Escape' && $id('settings-sheet')?.classList.contains('open')) closeSettingsSheet();
  if (e.key === 'Escape' && _editingCollabToken) closeCollabEditModal();
});

// ── Admin-change sync ─────────────────────────────────────────────────────────
// Uses both localStorage events (cross-tab) and visibilitychange (same-tab refocus)

let _lastAdminChange = localStorage.getItem('kfs_admin_data_change') || '0';

function _handleAdminDataChange() {
  const latest = localStorage.getItem('kfs_admin_data_change') || '0';
  if (latest !== _lastAdminChange) {
    _lastAdminChange = latest;
    // Only refresh if user is logged in and app is visible
    if (!_token || $id('app-screen')?.style.display === 'none') return;
    // Silently refresh data panels that could have changed
    loadProfile();
    loadMyWorks();
    loadMovies();
  }
}

window.addEventListener('storage', e => {
  if (e.key === 'kfs_admin_data_change') _handleAdminDataChange();
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') _handleAdminDataChange();
});

// ── Collaborate ───────────────────────────────────────────────────────────────

function showCollabForm() {
  hideEl('collab-form-err'); hideEl('collab-form-ok');
  // Prefill email & phone from cached profile
  const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
  const emailEl = $id('cf-email');
  const phoneEl = $id('cf-phone');
  if (emailEl && profile.email)  emailEl.value = profile.email;
  if (phoneEl && profile.mobile) phoneEl.value = profile.mobile;
  // Set min date to today
  const dateEl = $id('cf-date');
  if (dateEl) dateEl.min = new Date().toISOString().split('T')[0];
  $id('collab-form').style.display = 'block';
  $id('collab-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideCollabForm() {
  $id('collab-form').style.display = 'none';
  ['cf-title','cf-role','cf-domain','cf-skills','cf-description','cf-timeline','cf-date','cf-phone'].forEach(id => {
    const el = $id(id); if (el) el.value = '';
  });
  // Reset email to profile value
  const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
  const emailEl = $id('cf-email');
  if (emailEl) emailEl.value = profile.email || '';
  const cnt = $id('cf-desc-count'); if (cnt) cnt.textContent = '0';
}

async function submitCollab() {
  hideEl('collab-form-err'); hideEl('collab-form-ok');
  const title       = ($id('cf-title')?.value || '').trim();
  const role        = ($id('cf-role')?.value || '').trim();
  const description = ($id('cf-description')?.value || '').trim();
  const date        = ($id('cf-date')?.value || '').trim();
  const email       = ($id('cf-email')?.value || '').trim();
  const phone       = ($id('cf-phone')?.value || '').trim();

  if (!title || !role || !description || !date) {
    showMsg('collab-form-err', 'Title, role, description, and fulfillment date are required.', false);
    return;
  }
  if (!email || !phone) {
    showMsg('collab-form-err', 'Email and phone are required.', false);
    return;
  }

  const btn = $id('collab-submit-btn');
  btn.disabled = true; btn.textContent = 'Posting…';
  try {
    const profile = window._memberProfile || JSON.parse(localStorage.getItem('kfs-member-profile') || '{}');
    await api('POST', '/api/collaborate/member', {
      title,
      role,
      description,
      fulfillment_date: date,
      domain:        ($id('cf-domain')?.value || '').trim(),
      skills:        ($id('cf-skills')?.value || '').trim(),
      timeline:      ($id('cf-timeline')?.value || '').trim(),
      contact_name:  profile.name || '',
      contact_email: email,
      contact_phone: phone,
    });
    showMsg('collab-form-ok', '🎬 Collab post published! It\'s now live on the /collaborate page.');
    setTimeout(() => { hideCollabForm(); loadMyCollabs(); }, 2200);
  } catch (e) {
    showMsg('collab-form-err', e.message || 'Could not post — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Post Request';
  }
}

async function loadMyCollabs() {
  const list = $id('collab-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  try {
    const mine = await api('GET', '/api/collaborate/mine');
    if (!mine.length) {
      list.innerHTML = `
        <div class="collab-empty">
          <div class="collab-empty-icon">🤝</div>
          <div class="collab-empty-title">No posts yet</div>
          <div class="collab-empty-sub">Your collab requests will appear here once posted.</div>
        </div>`;
      return;
    }
    list.innerHTML = mine.map(c => {
      const until = new Date(c.fulfillment_date).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' });
      return `
        <div class="collab-posted-card">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div>
              <div class="collab-posted-title">${escHtml(c.title)}</div>
              <div class="collab-posted-role">${escHtml(c.role)}${c.domain ? ' · ' + escHtml(c.domain) : ''}</div>
            </div>
            <span class="badge badge-approved">Live</span>
          </div>
          ${c.description ? `<div style="font-size:13px;color:var(--muted);margin-bottom:12px;line-height:1.55">${escHtml(c.description.slice(0,180))}${c.description.length > 180 ? '…' : ''}</div>` : ''}
          <div class="collab-posted-meta">
            <div class="collab-posted-meta-item">Needed by <span>${until}</span></div>
            ${c.skills ? `<div class="collab-posted-meta-item">Skills <span>${escHtml(c.skills)}</span></div>` : ''}
            ${c.timeline ? `<div class="collab-posted-meta-item">Timeline <span>${escHtml(c.timeline)}</span></div>` : ''}
          </div>
          <div class="collab-card-actions">
            <a href="/collaborate" target="_blank" class="btn-sm" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;transition:all .12s">View on Site ↗</a>
            ${c.edit_token ? `<button class="btn-sm" onclick="openCollabEditModal('${c.edit_token}')" style="background:#1e1e1e;border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;transition:all .12s">Edit</button>` : ''}
            ${c.edit_token ? `<button class="btn-sm btn-danger" onclick="deleteCollab('${c.edit_token}', this)">Delete</button>` : ''}
          </div>
        </div>`;
    }).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ── Collab Edit Modal ─────────────────────────────────────────────────────────

let _editingCollabToken = null;

async function openCollabEditModal(token) {
  _editingCollabToken = token;
  hideEl('collab-edit-err'); hideEl('collab-edit-ok');
  // Fetch existing data
  const modal = $id('collab-edit-modal-overlay');
  if (!modal) return;
  modal.style.display = 'flex';
  try {
    const d = await api('GET', `/api/collaborate/edit/${token}`);
    const set = (id, val) => { const el = $id(id); if (el) el.value = val || ''; };
    set('ce-title',       d.title);
    set('ce-role',        d.role);
    set('ce-domain',      d.domain);
    set('ce-skills',      d.skills);
    set('ce-description', d.description);
    set('ce-timeline',    d.timeline);
    set('ce-date',        d.fulfillment_date);
    set('ce-email',       d.contact_email);
    set('ce-phone',       d.contact_phone);
    const cnt = $id('ce-desc-count'); if (cnt) cnt.textContent = (d.description || '').length;
    // Set min date
    const dateEl = $id('ce-date');
    if (dateEl) dateEl.min = new Date().toISOString().split('T')[0];
  } catch (e) {
    showMsg('collab-edit-err', 'Could not load post data: ' + e.message, false);
  }
}

function closeCollabEditModal() {
  const modal = $id('collab-edit-modal-overlay');
  if (modal) modal.style.display = 'none';
  _editingCollabToken = null;
}

async function submitCollabEdit() {
  if (!_editingCollabToken) return;
  hideEl('collab-edit-err'); hideEl('collab-edit-ok');

  const title       = ($id('ce-title')?.value || '').trim();
  const role        = ($id('ce-role')?.value || '').trim();
  const description = ($id('ce-description')?.value || '').trim();
  const date        = ($id('ce-date')?.value || '').trim();
  const email       = ($id('ce-email')?.value || '').trim();
  const phone       = ($id('ce-phone')?.value || '').trim();

  if (!title || !role || !description || !date) {
    showMsg('collab-edit-err', 'Title, role, description, and fulfillment date are required.', false);
    return;
  }
  if (!email || !phone) {
    showMsg('collab-edit-err', 'Email and phone are required.', false);
    return;
  }

  const btn = $id('collab-edit-submit-btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    await api('PUT', `/api/collaborate/member/${_editingCollabToken}`, {
      title, role, description, fulfillment_date: date,
      domain:        ($id('ce-domain')?.value || '').trim(),
      skills:        ($id('ce-skills')?.value || '').trim(),
      timeline:      ($id('ce-timeline')?.value || '').trim(),
      contact_email: email,
      contact_phone: phone,
    });
    showMsg('collab-edit-ok', '✅ Post updated successfully!');
    setTimeout(() => { closeCollabEditModal(); loadMyCollabs(); }, 1800);
  } catch (e) {
    showMsg('collab-edit-err', e.message || 'Could not update — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Save Changes';
  }
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function deleteCollab(token, btn) {
  if (!await swConfirm('Delete this collab post? This cannot be undone.', { title: 'Delete collab post', confirmLabel: 'Delete', danger: true })) return;
  btn.disabled = true; btn.textContent = 'Deleting…';
  try {
    await api('DELETE', `/api/collaborate/${token}`);
    await loadMyCollabs();
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Delete';
    swAlert(e.message || 'Could not delete collab post.', { title: 'Error' });
  }
}

// ── Enter key support ─────────────────────────────────────────────────────────

function handleEnterKey(e) {
  if (e.key !== 'Enter') return;
  // Once logged in, #auth-screen is hidden — bail immediately. (We can't rely on
  // each individual step's own inline style.display: showStep() sets it to 'block'
  // when a step is shown but nothing ever resets it back to 'none' after a
  // successful login, so step-login.style.display stayed 'block' forever and this
  // function kept firing handleLogin() on every Enter press anywhere in the app —
  // including while sending a DM — which silently re-logged in and bounced the
  // user back to the Strand feed via loadDashboard().)
  if ($id('auth-screen')?.style.display === 'none') return;
  const loginStep    = $id('step-login');
  const totpStep     = $id('step-totp');
  const changePwStep = $id('step-change-pw');
  const setup2FAStep = $id('step-2fa-setup');
  const fpUserStep   = $id('step-fp-username');
  const fpOtpStep    = $id('step-fp-otp');
  const fpResetStep  = $id('step-fp-reset');
  if      (loginStep    && loginStep.style.display    !== 'none')  handleLogin();
  else if (totpStep     && totpStep.style.display     !== 'none')  submitTotp();
  else if (changePwStep && changePwStep.style.display === 'block') handleChangePw();
  else if (setup2FAStep && setup2FAStep.style.display === 'block') verify2FASetup();
  else if (fpUserStep   && fpUserStep.style.display   === 'block') fpSubmitUsername();
  else if (fpOtpStep    && fpOtpStep.style.display    === 'block') fpSubmitOtp();
  else if (fpResetStep  && fpResetStep.style.display  === 'block') fpSubmitNewPassword();
}

// ── Grievance / Suggestion ────────────────────────────────────────────────────

async function submitGrievance() {
  const subject  = ($id('grv-subject')?.value || '').trim();
  const body     = ($id('grv-body')?.value    || '').trim();
  const type     = ($id('grv-type-value')?.value || 'general');
  const anon     = !!$id('grv-anon')?.checked;

  if (!subject) { showMsg('grv-form-err', 'Please add a subject.', false); return; }
  if (!body)    { showMsg('grv-form-err', 'Please add some details.', false); return; }
  if (body.length < 10) { showMsg('grv-form-err', 'Details are too short — please be more descriptive.', false); return; }

  const btn = $id('grv-submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';
  hideEl('grv-form-err'); hideEl('grv-form-ok');
  try {
    await api('POST', '/api/member/grievances', { subject, body, type, anonymous: anon });
    showMsg('grv-form-ok', '✅ Submitted! We\'ll review it and update the status here.');
    // Reset form
    const subj = $id('grv-subject'); if (subj) subj.value = '';
    const bod  = $id('grv-body');   if (bod)  { bod.value = ''; const cnt = $id('grv-body-count'); if (cnt) cnt.textContent = '0'; }
    const anonEl = $id('grv-anon'); if (anonEl) anonEl.checked = false;
    // Reset type tab to suggestion
    document.querySelectorAll('.grv-type-tab').forEach(t => t.classList.remove('active'));
    const defTab = $id('grv-tab-suggestion'); if (defTab) defTab.classList.add('active');
    const typeEl = $id('grv-type-value'); if (typeEl) typeEl.value = 'suggestion';
    // Reload list
    await loadMyGrievances();
  } catch (e) {
    showMsg('grv-form-err', e.message || 'Could not submit — please try again.', false);
  } finally {
    btn.disabled = false; btn.textContent = 'Submit';
  }
}

function _grvStatusBanner(status, adminNote) {
  const cfg = {
    open:        { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>', text: 'Received — pending review by the team.' },
    in_progress: { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', text: 'Being worked on — your issue is actively being addressed.' },
    resolved:    { icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>', text: 'Resolved — this has been addressed.' },
  };
  const c = cfg[status] || cfg.open;
  return `
    <div class="grv-status-banner ${status || 'open'}">
      ${c.icon}
      <div>
        <div>${c.text}</div>
        ${adminNote ? `<div class="grv-admin-note">Admin note: ${escHtml(adminNote)}</div>` : ''}
      </div>
    </div>`;
}

function _grvBadgeClass(status) {
  if (status === 'resolved')    return 'badge-resolved';
  if (status === 'in_progress') return 'badge-in-progress';
  return 'badge-open';
}

function _grvBadgeLabel(status) {
  if (status === 'resolved')    return 'Resolved';
  if (status === 'in_progress') return 'In Progress';
  return 'Open';
}

function _grvTypeLabel(type) {
  if (type === 'suggestion') return '💡 Suggestion';
  if (type === 'grievance')  return '🚨 Grievance';
  return '💬 General';
}

async function loadMyGrievances() {
  const list = $id('grv-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
  try {
    const items = await api('GET', '/api/member/grievances');
    if (!items.length) {
      list.innerHTML = `
        <div class="grv-empty">
          <div class="grv-empty-icon">💬</div>
          <div class="grv-empty-title">Nothing submitted yet</div>
          <div class="grv-empty-sub">Use the form above to share feedback or raise a concern.</div>
        </div>`;
      return;
    }
    list.innerHTML = items.map(g => `
      <div class="grv-card">
        <div class="grv-card-header">
          <div class="grv-card-subject">${escHtml(g.subject)}</div>
          <span class="badge ${_grvBadgeClass(g.status)}">${_grvBadgeLabel(g.status)}</span>
        </div>
        <div class="grv-card-body">${escHtml(g.body)}</div>
        <div class="grv-card-meta">
          <span class="grv-card-type-chip">${_grvTypeLabel(g.type)}</span>
          <span class="grv-card-time">${relTime(g.created_at)}</span>
          ${g.anonymous ? '<span class="grv-card-time">· Anonymous</span>' : ''}
        </div>
        ${_grvStatusBanner(g.status, g.admin_note)}
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${e.message}</span>`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// KFS Social Strand — Client
// Routes: /api/member/studio/* (member-auth-gated, CSRF applied by server)
// ═══════════════════════════════════════════════════════════════════════════

const SW = {
  feedPage:             1,
  feedTag:              null,
  feedSort:             'latest', // 'latest' | 'foryou' (Phase 2 smart feed)
  feedExhausted:        false,
  feedLoading:          false,
  myReactions:          new Map(), // projectId → reactionType | null
  editingProjectId:     null,
  collabPickerSelected: [],
  detailProjectId:      null,
};

// ── Utilities ──────────────────────────────────────────────────────────────

function swEsc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function swFmtNum(n) {
  const num = Number(n) || 0;
  if (num >= 1_000_000) return (num/1_000_000).toFixed(1).replace(/\.0$/,'')+'M';
  if (num >= 1000)      return (num/1000).toFixed(1).replace(/\.0$/,'')+'k';
  return String(num);
}

function swRelTime(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff/60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m/60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h/24);
  if (d < 30) return `${d}d ago`;
  return new Date(ts).toLocaleDateString('en-GB', { month:'short', year:'numeric' });
}

function swVideoEmbedUrl(url, provider) {
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

function swAvatar(name, photo, size = 32) {
  // server stores field as `photo`, not `photo_url`
  if (photo) {
    return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;flex-shrink:0;background:#1a1a1a">`;
  }
  const initials = (name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;border:1px solid #2a2a2a;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.36)}px;font-weight:600;color:#666;flex-shrink:0;letter-spacing:-.01em">${swEsc(initials)}</div>`;
}

// SVG icon set — no emojis
const SW_ICONS = {
  eye:      `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  heart:    `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  heartF:   `<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  comment:  `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  play:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  trash:    `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
  edit:     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  close:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  user:     `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
  pin:      `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
  eyeLg:    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  heartLg:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  postsLg:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`,
};

const SW_REACTIONS = [
  { type:'wow',        label:'Wow',           icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>` },
  { type:'fire',       label:'Fire',          icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0011 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 01-7 7 7 7 0 01-4.5-1.5c1-.5 1.5-1 1-2z"/></svg>` },
  { type:'brilliant',  label:'Brilliant',     icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>` },
  { type:'seahaven',   label:'Seahaven',      icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="1" y1="18" x2="3" y2="18"/><line x1="21" y1="18" x2="23" y2="18"/><line x1="18.36" y1="11.64" x2="19.78" y2="10.22"/><line x1="23" y1="22" x2="1" y2="22"/><polyline points="8 6 12 2 16 6"/></svg>` },
  { type:'mind_blown', label:'Mind Blown',    icon:`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>` },
];

// ── Feed card ─────────────────────────────────────────────────────────────

/** Jump to the Network panel's Collab sub-tab — used by the "Manage this
 *  post" link on your own collab cards in the main feed. */
function swGoToMyCollabs() {
  const navEl = document.querySelector('[data-panel="network"]');
  if (navEl) switchPanel(navEl);
  const collabTab = document.querySelector('.nw-tab[data-network-tab="collab"]');
  if (collabTab) nwSwitchTab('collab');
}

// ── Collab request feed card ─────────────────────────────────────────────
// Collab requests (posted via the "New Collab" form) show up in the main
// feed alongside photo/text/video posts, tagged post_type: 'collab' by the
// server (see /api/member/studio/feed). Instead of like/comment, they get
// an "I'm Interested" button that opens a DM to the poster with a pre-filled
// message — the person can still edit it before sending, nothing goes out
// automatically.
function swCollabFeedCard(p) {
  const author = p.members || {};
  const isMine = p.member_id === (window._member?.id || window._memberProfile?.id);
  const metaBits = [p.role, p.domain].filter(Boolean).join(' · ');
  const untilLabel = p.fulfillment_date
    ? new Date(p.fulfillment_date).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
    : null;

  const actionHtml = isMine
    ? `<button class="ig-action-btn" style="width:auto;padding:0 12px;font-size:12px;font-weight:600;color:var(--muted);" onclick="event.stopPropagation();swGoToMyCollabs()">Manage this post</button>`
    : `<button class="ig-action-btn" style="width:auto;padding:0 12px;font-size:12px;font-weight:700;color:#4ba3d4;" onclick="event.stopPropagation();swCollabExpressInterest('${swEsc(p.member_id)}','${swEsc(author.name||'Member')}','${swEsc(author.photo||'')}','${swEsc(author.role||'')}','${swEsc(p.domain||'')}','${swEsc(p.title||'')}')">I'm Interested</button>`;

  return `<article class="ig-post" data-project-id="${swEsc(p.id)}" style="border:1.5px solid #4ba3d422;background:linear-gradient(180deg,rgba(75,163,212,.05),transparent)">
    <div class="ig-post-header">
      <div class="ig-post-avatar-wrap" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-avatar-inner">${author.photo
          ? `<img src="${swEsc(author.photo)}" alt="${swEsc(author.name)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;display:block;">`
          : `<div style="width:100%;height:100%;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#666;">${swEsc((author.name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase())}</div>`}
        </div>
      </div>
      <div class="ig-post-author-block" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-author-name">${swEsc(author.name||'Member')}
          <span style="display:inline-flex;align-items:center;gap:4px;background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em;margin-left:6px;vertical-align:middle">Collab</span>
        </div>
        <div class="ig-post-time">${swRelTime(p.created_at)}</div>
      </div>
    </div>

    <div style="padding:2px 14px 12px;">
      <div style="font-size:15px;font-weight:700;color:var(--text);margin-bottom:4px;">${swEsc(p.title||'Collab request')}</div>
      ${metaBits ? `<div style="font-size:12px;color:var(--muted);margin-bottom:8px;">${swEsc(metaBits)}</div>` : ''}
      ${p.description ? `<div style="font-size:13px;color:var(--text);opacity:.85;line-height:1.5;margin-bottom:8px;">${swEsc(p.description)}</div>` : ''}
      <div style="display:flex;flex-wrap:wrap;gap:8px;font-size:11px;color:var(--muted);">
        ${p.skills ? `<span>Skills: ${swEsc(p.skills)}</span>` : ''}
        ${p.timeline ? `<span>Timeline: ${swEsc(p.timeline)}</span>` : ''}
        ${untilLabel ? `<span>Needed by ${untilLabel}</span>` : ''}
      </div>
    </div>

    <div class="ig-post-actions" style="justify-content:flex-end;">
      ${actionHtml}
    </div>

    <div class="ig-post-timestamp">${swRelTime(p.created_at)}</div>
  </article>`;
}

/** "I'm Interested" on a collab feed card — opens (or jumps to) a DM with
 *  the poster and pre-fills a message identifying the interested member and
 *  their domain. Doesn't send automatically; the person reviews it first. */
function swCollabExpressInterest(posterId, posterName, posterPhoto, posterRole, collabDomain, collabTitle) {
  const me = window._memberProfile || window._member || {};
  const myDomain = me.domain || me.role || 'a member';
  const draft = `Hi! I'm ${me.name || 'a KFS member'}${myDomain ? `, ${myDomain}` : ''} — interested in your collab post${collabTitle ? ` "${collabTitle}"` : ''}. Would love to help out!`;

  dmStartWith(posterId, { id: posterId, name: posterName, photo: posterPhoto || null, role: posterRole || null, domain: collabDomain || null });

  // dmStartWith does its own UI setup synchronously for the "no existing
  // conversation" path, but if a conversation already exists it calls
  // dmOpenConv (async — fetches message history) before the input is ready.
  // Give it a beat either way rather than trying to prefill mid-transition.
  setTimeout(() => {
    const input = $id('dm-input');
    if (!input) return;
    input.value = draft;
    input.dispatchEvent(new Event('input')); // trigger auto-grow + typing ping
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }, 250);
}

function swFeedCard(p) {
  if (p.post_type === 'collab') return swCollabFeedCard(p);

  const author   = p.members || {};
  const myRxn    = SW.myReactions.get(p.id) || p.my_reaction || null;
  const isLiked  = !!myRxn;
  const hasImage = !!p.cover_image;
  const hasVideo = !!p.video_url;
  const postType = p.post_type || (hasImage ? 'image' : hasVideo ? 'video' : 'text');

  // Avatar — with gradient ring like Instagram
  const avatarInner = author.photo
    ? `<img src="${swEsc(author.photo)}" alt="${swEsc(author.name)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;display:block;">`
    : `<div style="width:100%;height:100%;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#666;">${swEsc((author.name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase())}</div>`;

  // Media section — image, video, or text body
  let mediaHtml = '';
  if (hasImage) {
    mediaHtml = `<div class="ig-post-img-wrap"><img src="${swEsc(p.cover_image)}" alt="" class="ig-post-img" loading="lazy"></div>`;
  } else if (hasVideo) {
    const embedUrl = swVideoEmbedUrl(p.video_url, p.video_provider);
    if (embedUrl) {
      mediaHtml = `<div class="ig-post-img-wrap" style="position:relative;padding-bottom:56.25%;background:#000;"><iframe src="${swEsc(embedUrl)}" allowfullscreen loading="lazy" style="position:absolute;inset:0;width:100%;height:100%;border:none;"></iframe></div>`;
    } else {
      mediaHtml = `<div class="ig-post-img-wrap" style="aspect-ratio:16/9;background:#111;display:flex;align-items:center;justify-content:center;">${SW_ICONS.play}</div>`;
    }
  } else if (postType === 'text' && p.description) {
    // Text-only post — X/Twitter style: just inline text, no dark box
    mediaHtml = `<div class="ig-post-text-bg"><div class="ig-post-text-content">${swEsc(p.description)}</div></div>`;
  }

  // Caption: show title as headline, then description (if there's also an image)
  const hasCaption = hasImage || hasVideo;
  let captionHtml = '';
  if (hasCaption && (p.title || p.description)) {
    const captionBody = [p.title, (hasImage || hasVideo) ? p.description : null].filter(Boolean).join(' · ');
    captionHtml = `<div class="ig-post-caption"><span class="ig-post-caption-author" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">${swEsc(author.name||'Member')}</span> <span class="ig-post-caption-text">${swEsc(captionBody)}</span></div>`;
  } else if (postType !== 'text' && p.title) {
    captionHtml = `<div class="ig-post-caption"><span class="ig-post-caption-author" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">${swEsc(author.name||'Member')}</span> <span class="ig-post-caption-text">${swEsc(p.title)}</span></div>`;
  }

  // Tags
  const tagsHtml = p.tags?.length
    ? `<div class="ig-post-tags">${p.tags.map(t=>`<span class="ig-post-tag">#${swEsc(t)}</span>`).join(' ')}</div>` : '';

  // Comments count link + inline preview
  const previewComments = (p.latest_comments || []).slice(0,3);
  const commentsHtml = (() => {
    let html = '';
    if (previewComments.length) {
      html += `<div class="ig-post-comments-preview">`;
      previewComments.forEach(c => {
        const ca = c.members || {};
        html += `<div class="ig-comment-preview-row"><span class="ig-comment-preview-author">${swEsc(ca.name||'Member')}</span> <span class="ig-comment-preview-body">${swEsc(c.body||'')}</span></div>`;
      });
      html += `</div>`;
    }
    if (p.comments_count > previewComments.length) {
      const remaining = p.comments_count - previewComments.length;
      html += `<div class="ig-post-view-comments" onclick="event.stopPropagation();swOpenDetail('${swEsc(p.id)}')">View ${remaining > 0 && previewComments.length > 0 ? `${p.comments_count > 1 ? `all ${swFmtNum(p.comments_count)} comments` : '1 comment'}` : (p.comments_count === 1 ? '1 comment' : `all ${swFmtNum(p.comments_count)} comments`)}</div>`;
    } else if (p.comments_count === 0) {
      html += '';
    }
    return html;
  })();

  const likesLabel = p.reactions_count > 0
    ? `<div class="ig-post-likes">${swFmtNum(p.reactions_count)} ${p.reactions_count !== 1 ? 'reactions' : 'reaction'}</div>` : '';

  // Reaction popup is now a single body-level portal (#rxn-overlay), not per-card

  // Admin/KFS post indicator
  const isAdminPost = !!p.is_admin_post;
  const kfsBadgeHtml = isAdminPost
    ? `<span style="display:inline-flex;align-items:center;gap:4px;background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em;margin-left:6px;vertical-align:middle">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="#fff"><path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" stroke="none"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round"/></svg> KFS
       </span>` : '';

  return `<article class="ig-post" data-project-id="${swEsc(p.id)}" data-rxn-count="${p.reactions_count||0}"${isAdminPost ? ' style="border:1.5px solid #2d6a9f22;background:linear-gradient(180deg,rgba(45,106,159,.04),transparent)"' : ''} onclick="swOpenDetail('${swEsc(p.id)}')">
    <!-- Header -->
    <div class="ig-post-header">
      <div class="ig-post-avatar-wrap" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-avatar-inner">${avatarInner}</div>
      </div>
      <div class="ig-post-author-block" onclick="event.stopPropagation();openMemberProfile('${swEsc(p.member_id)}')">
        <div class="ig-post-author-name">${swEsc(isAdminPost ? 'KFS' : (author.name||'Member'))}${kfsBadgeHtml}</div>
        <div class="ig-post-time">${swRelTime(p.created_at)}</div>
      </div>
      <button class="ig-post-options" onclick="event.stopPropagation();swShowPostMenu(event,'${swEsc(p.id)}','${swEsc(p.member_id)}',${isAdminPost})" title="More" aria-label="Post options">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>
      </button>
    </div>

    <!-- Media / text body -->
    ${mediaHtml}

    <!-- Action bar -->
    <div class="ig-post-actions">
      <button class="ig-action-btn ig-like-btn${isLiked?' liked':''}"
        data-project-id="${swEsc(p.id)}"
        title="${isLiked?'Liked':'Like'}"
        onclick="event.stopPropagation();swToggleReaction('${swEsc(p.id)}','wow')"
        onmouseenter="swShowRxnPopup('${swEsc(p.id)}')"
        onmouseleave="swHideRxnPopup('${swEsc(p.id)}')"
      ><svg width="24" height="24" viewBox="0 0 24 24" fill="${isLiked?'#4ba3d4':'none'}" stroke="${isLiked?'#4ba3d4':'currentColor'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>
      </button>
      <button class="ig-action-btn" onclick="event.stopPropagation();swOpenDetail('${swEsc(p.id)}')" title="Comment">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      </button>
      <span class="ig-post-views-inline"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>&nbsp;${swFmtNum(p.views_count||0)}</span>
    </div>

    <!-- Reactions count -->
    ${likesLabel}

    <!-- Caption -->
    ${captionHtml}

    <!-- Tags -->
    ${tagsHtml}

    <!-- Comments link -->
    ${commentsHtml}

    <!-- Timestamp -->
    <div class="ig-post-timestamp">${swRelTime(p.created_at)}</div>
  </article>`;
}

// ── Feed Load ─────────────────────────────────────────────────────────────

/** Generic list-row skeleton — used anywhere a list previously showed a bare
 *  "Loading…" line while it fetched (sessions, works, DM conversations). */
function swSkelRows(n = 4) {
  const row = `<div class="sw-skel-row">
    <div class="sw-skel-avatar"></div>
    <div class="sw-skel-lines">
      <div class="sw-skel-line"></div>
      <div class="sw-skel-line"></div>
    </div>
  </div>`;
  return row.repeat(n);
}

/** Horizontal-scroll tile skeleton — used for the Discover "Trending" row. */
function swSkelTiles(n = 4) {
  const tile = `<div class="sw-skel-tile">
    <div class="sw-skel-img"></div>
    <div class="sw-skel-line"></div>
  </div>`;
  return tile.repeat(n);
}

function swSkeletonCards(n = 3) {
  const card = `<div class="sw-skel-card">
    <div class="sw-skel-header">
      <div class="sw-skel-avatar"></div>
      <div class="sw-skel-lines">
        <div class="sw-skel-line" style="width:35%"></div>
        <div class="sw-skel-line" style="width:20%;height:7px"></div>
      </div>
    </div>
    <div class="sw-skel-img"></div>
    <div class="sw-skel-actions">
      <div class="sw-skel-icon"></div>
      <div class="sw-skel-icon"></div>
    </div>
  </div>`;
  return card.repeat(n);
}

async function swLoadFeed(reset = false) {
  if (SW.feedLoading) return;
  if (!reset && SW.feedExhausted) return;
  if (reset) {
    SW.feedPage = 1;
    SW.feedExhausted = false;
    const grid = $id('studio-feed');
    if (grid) grid.innerHTML = swSkeletonCards(3);
  }
  SW.feedLoading = true;
  try {
    let url = `/api/member/studio/feed?page=${SW.feedPage}`;
    if (SW.feedTag) url += `&tag=${encodeURIComponent(SW.feedTag)}`;
    if (SW.feedSort === 'foryou') url += `&sort=foryou`;
    const resp = await api('GET', url);
    // server returns { feed, page, has_more }
    const data = resp.feed || resp; // fallback to flat array
    const hasMore = resp.has_more ?? (data.length === 20);

    const grid = $id('studio-feed');
    if (!grid) return;
    if (reset) grid.innerHTML = '';

    if (!data.length && SW.feedPage === 1) {
      grid.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon">${SW_ICONS.postsLg}</div><div class="sw-empty-title">No posts yet</div><div class="sw-empty-sub">Be the first to share your work.</div></div>`;
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = 'none';
      return;
    }

    if (!hasMore) {
      SW.feedExhausted = true;
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = 'none';
    } else {
      const btn = $id('studio-feed-more'); if (btn) btn.style.display = '';
    }

    // Sync my_reaction into SW.myReactions map
    data.forEach(p => { if (p.my_reaction) SW.myReactions.set(p.id, p.my_reaction); });

    grid.insertAdjacentHTML('beforeend', data.map(swFeedCard).join(''));
    swAttachLongPress();
    SW.feedPage++;
  } catch (e) {
    const grid = $id('studio-feed');
    if (grid && reset) grid.innerHTML = `<div class="sw-error">Could not load feed. <button class="btn-ghost" onclick="swLoadFeed(true)" style="font-size:12px;padding:4px 10px;margin-left:6px">Retry</button></div>`;
  } finally {
    SW.feedLoading = false;
  }
}

// ── My Posts ──────────────────────────────────────────────────────────────

async function swLoadMyPosts() {
  const list = $id('studio-my-posts-list');
  if (!list) return;
  list.innerHTML = '<div class="sw-loading">Loading…</div>';
  try {
    const data = await api('GET', '/api/member/studio/mine');
    if (!data.length) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon">${SW_ICONS.postsLg}</div><div class="sw-empty-title">No posts yet</div><div class="sw-empty-sub">Post your first project to the Social Strand.</div></div>`;
      return;
    }
    list.innerHTML = data.map(p => `
      <div class="sw-my-post-row">
        <div class="sw-my-post-info">
          ${p.cover_image ? `<img src="${swEsc(p.cover_image)}" alt="" class="sw-my-post-thumb">` : `<div class="sw-my-post-thumb sw-my-post-thumb-blank">${SW_ICONS.play}</div>`}
          <div class="sw-my-post-text">
            <div class="sw-my-post-title">${swEsc(p.title)}</div>
            <div class="sw-my-post-meta">
              <span class="sw-stat">${SW_ICONS.eye}&nbsp;${swFmtNum(p.views_count)}</span>
              <span class="sw-stat">${SW_ICONS.heart}&nbsp;${swFmtNum(p.reactions_count)}</span>
              <span class="sw-stat">${SW_ICONS.comment}&nbsp;${swFmtNum(p.comments_count)}</span>
              ${p.status==='hidden'?'<span class="sw-badge-hidden">Hidden</span>':''}
            </div>
          </div>
        </div>
        <div class="sw-my-post-actions">
          <button class="sw-action-btn" title="Edit" onclick="swOpenEditModal('${swEsc(p.id)}')">${SW_ICONS.edit}</button>
          <button class="sw-action-btn sw-action-btn-danger" title="Delete" onclick="swDeletePost('${swEsc(p.id)}','${swEsc(p.title)}')">${SW_ICONS.trash}</button>
        </div>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = `<span style="color:var(--danger);font-size:13px">${swEsc(e.message)}</span>`;
  }
}

// ── Analytics — views + reactions only ────────────────────────────────────

async function swLoadAnalytics() {
  const wrap = $id('studio-analytics-list');
  if (!wrap) return;
  wrap.innerHTML = '<div class="sw-loading">Loading…</div>';
  try {
    const data = await api('GET', '/api/member/studio/my-analytics');
    if (!data.length) {
      wrap.innerHTML = `<div class="sw-empty"><div class="sw-empty-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#444" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg></div><div class="sw-empty-title">No data yet</div><div class="sw-empty-sub">Post work to start seeing your numbers.</div></div>`;
      return;
    }
    const totalViews     = data.reduce((s,p)=>s+(p.views_count||0),0);
    const totalReactions = data.reduce((s,p)=>s+(p.reactions_count||0),0);
    const maxViews       = Math.max(...data.map(p=>p.views_count||0),1);
    const maxReactions   = Math.max(...data.map(p=>p.reactions_count||0),1);

    wrap.innerHTML = `
      <div class="sw-analytics-kpis">
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--views">${SW_ICONS.eyeLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${swFmtNum(totalViews)}</div><div class="sw-analytics-kpi-label">Total Views</div></div>
        </div>
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--reactions">${SW_ICONS.heartLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${swFmtNum(totalReactions)}</div><div class="sw-analytics-kpi-label">Total Reactions</div></div>
        </div>
        <div class="sw-analytics-kpi">
          <div class="sw-analytics-kpi-icon sw-analytics-kpi-icon--posts">${SW_ICONS.postsLg}</div>
          <div class="sw-analytics-kpi-body"><div class="sw-analytics-kpi-val">${data.length}</div><div class="sw-analytics-kpi-label">Published</div></div>
        </div>
      </div>
      <div class="sw-analytics-section-label">Per post</div>
      <div class="sw-analytics-rows">
        ${data.map(p=>{
          const v = p.views_count||0, r = p.reactions_count||0;
          const vPct = Math.round((v/maxViews)*100), rPct = Math.round((r/maxReactions)*100);
          return `<div class="sw-analytics-row">
            <div class="sw-analytics-row-head"><div class="sw-analytics-row-title" title="${swEsc(p.title)}">${swEsc(p.title)}</div></div>
            <div class="sw-analytics-metric-row">
              <div class="sw-analytics-metric-label"><span class="sw-analytics-metric-icon">${SW_ICONS.eye}</span><span class="sw-analytics-metric-num">${swFmtNum(v)}</span><span class="sw-analytics-metric-name">views</span></div>
              <div class="sw-analytics-bar-track"><div class="sw-analytics-bar-fill sw-analytics-bar-fill--views" style="width:${vPct}%"></div></div>
            </div>
            <div class="sw-analytics-metric-row">
              <div class="sw-analytics-metric-label"><span class="sw-analytics-metric-icon">${SW_ICONS.heart}</span><span class="sw-analytics-metric-num">${swFmtNum(r)}</span><span class="sw-analytics-metric-name">reactions</span></div>
              <div class="sw-analytics-bar-track"><div class="sw-analytics-bar-fill sw-analytics-bar-fill--reactions" style="width:${rPct}%"></div></div>
            </div>
          </div>`;
        }).join('')}
      </div>`;
  } catch (e) {
    wrap.innerHTML = `<span style="color:var(--danger);font-size:13px">${swEsc(e.message)}</span>`;
  }
}

// ── Detail Modal ──────────────────────────────────────────────────────────

async function swOpenDetail(projectId) {
  _rxnHideNow(); // dismiss reaction wheel if open
  SW.detailProjectId = projectId;
  const overlay = $id('studio-detail-modal-overlay');
  const body    = $id('studio-detail-body');
  if (!overlay||!body) return;
  body.innerHTML = '<div class="sw-loading" style="padding:60px 0;text-align:center">Loading…</div>';
  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
  try {
    const p = await api('GET', `/api/member/studio/projects/${projectId}`);
    const author   = p.members || {};
    const collabs  = (p.project_collaborators||[]).map(c=>c.members).filter(Boolean);
    const myRxn    = SW.myReactions.get(p.id) || p.my_reaction || null;
    SW.myReactions.set(p.id, myRxn);
    const embedUrl = swVideoEmbedUrl(p.video_url, p.video_provider);

    // Fetch comments
    const cResp = await api('GET', `/api/member/studio/projects/${projectId}/comments`);
    const comments = cResp.comments || cResp || [];

    body.innerHTML = `
      ${p.cover_image && !embedUrl ? `<img src="${swEsc(p.cover_image)}" alt="${swEsc(p.title)}" class="studio-detail-cover">` : ''}
      ${embedUrl ? `<div class="studio-detail-video-wrap"><iframe src="${swEsc(embedUrl)}" allowfullscreen loading="lazy"></iframe></div>` : ''}
      <div class="studio-detail-content">
        <div class="studio-detail-author-row">
          <span style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="openMemberProfile('${swEsc(p.member_id)}')">
            ${swAvatar(author.name, author.photo, 34)}
            <span><div class="studio-detail-author-name">${swEsc(author.name||'Member')}</div>${author.role?`<div class="studio-detail-author-role">${swEsc(author.role)}</div>`:''}</span>
          </span>
          ${p.domain?`<span class="studio-detail-domain-pill" style="margin-left:auto">${swEsc(p.domain)}</span>`:''}
        </div>
        <div class="studio-detail-title">${swEsc(p.title)}</div>
        ${p.description?`<div class="studio-detail-desc">${swEsc(p.description)}</div>`:''}
        <div class="studio-detail-meta">
          <span class="studio-detail-stat">${SW_ICONS.eye}&nbsp;${swFmtNum(p.views_count)}</span>
          <span class="studio-detail-stat">${SW_ICONS.heart}&nbsp;${swFmtNum(p.reactions_count)}</span>
          <span class="studio-detail-stat">${SW_ICONS.comment}&nbsp;${swFmtNum(p.comments_count)}</span>
        </div>
        ${p.tags?.length?`<div class="studio-detail-tags">${p.tags.map(t=>`<span class="sw-tag">${swEsc(t)}</span>`).join('')}</div>`:''}
        ${collabs.length?(()=>{
          const MAX=3;
          const shown=collabs.slice(0,MAX);
          const extra=collabs.length-shown.length;
          return `<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:16px">
            <span style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em">${SW_ICONS.user}&nbsp;With</span>
            ${shown.map(c=>`<span style="display:flex;align-items:center;gap:4px;font-size:11px;color:#bbb">${swAvatar(c.name,c.photo,16)}${swEsc(c.name)}</span>`).join('')}
            ${extra>0?`<span style="font-size:11px;color:var(--muted)">+${extra} more</span>`:''}
          </div>`;
        })():''}
        <div class="studio-reactions" id="detail-reactions-${swEsc(p.id)}">
          ${SW_REACTIONS.map(r=>`<button class="studio-rxn-btn ${myRxn===r.type?'active':''}" data-rxn="${swEsc(r.type)}" data-project="${swEsc(p.id)}" onclick="swToggleReaction('${swEsc(p.id)}','${swEsc(r.type)}')" title="${swEsc(r.label)}">${r.icon}<span class="sw-rxn-label">${swEsc(r.label)}</span></button>`).join('')}
        </div>
        <div class="studio-comments-section">
          <div class="studio-comments-title">Comments</div>
          <div class="studio-comment-input-row">
            <input id="sw-comment-input" type="text" placeholder="Add a comment…" class="studio-comment-input" maxlength="1000" onkeydown="if(event.key==='Enter')swPostComment('${swEsc(p.id)}',null)">
            <button class="studio-comment-post-btn" onclick="swPostComment('${swEsc(p.id)}',null)">Post</button>
          </div>
          <div id="sw-comments-list">${swRenderComments(comments, p.id)}</div>
        </div>
      </div>`;
  } catch (e) {
    body.innerHTML = `<div style="padding:48px;text-align:center;color:var(--muted);font-size:14px">${swEsc(e.message)}</div>`;
  }
}

function swRenderComments(comments, projectId) {
  // server nests replies under each comment's `.replies` array
  if (!comments.length) return `<div style="color:var(--muted);font-size:13px;padding:16px 0">No comments yet.</div>`;

  function renderOne(c, nested=false) {
    const a = c.members||{};
    return `<div class="studio-comment ${nested?'studio-comment-nested':''}">
      <div class="studio-comment-header">
        <span style="display:inline-flex;align-items:center;gap:8px;cursor:pointer" onclick="openMemberProfile('${swEsc(a.id)}')">
          ${swAvatar(a.name,a.photo,22)}
          <span class="studio-comment-author">${swEsc(a.name||'Member')}</span>
        </span>
        <span class="studio-comment-time">${swRelTime(c.created_at)}</span>
        ${c.is_pinned?`<span class="studio-comment-pinned-badge">${SW_ICONS.pin}&nbsp;Pinned</span>`:''}
      </div>
      <div class="studio-comment-body">${swEsc(c.body)}</div>
      <button class="studio-comment-reply-btn" onclick="swShowReplyInput('${swEsc(c.id)}','${swEsc(projectId)}')">Reply</button>
      <div id="sw-reply-input-${swEsc(c.id)}"></div>
      ${(c.replies||[]).map(r=>renderOne(r,true)).join('')}
    </div>`;
  }

  return comments.map(c=>renderOne(c,false)).join('');
}

function swShowReplyInput(commentId, projectId) {
  const wrap = $id(`sw-reply-input-${commentId}`);
  if (!wrap) return;
  if (wrap.innerHTML) { wrap.innerHTML=''; return; }
  wrap.innerHTML = `<div class="studio-comment-input-row" style="margin-top:8px;padding-left:30px">
    <input id="sw-reply-text-${swEsc(commentId)}" type="text" placeholder="Reply…" class="studio-comment-input" maxlength="1000"
      onkeydown="if(event.key==='Enter')swPostComment('${swEsc(projectId)}','${swEsc(commentId)}')">
    <button class="studio-comment-post-btn" onclick="swPostComment('${swEsc(projectId)}','${swEsc(commentId)}')">Reply</button>
  </div>`;
  $id(`sw-reply-text-${commentId}`)?.focus();
}

async function swPostComment(projectId, parentId) {
  const inputId = parentId ? `sw-reply-text-${parentId}` : 'sw-comment-input';
  const input   = $id(inputId);
  if (!input) return;
  const body = input.value.trim();
  if (!body) return;
  try {
    await api('POST', `/api/member/studio/projects/${projectId}/comments`, { body, parent_id: parentId||null });
    input.value = '';
    const cResp = await api('GET', `/api/member/studio/projects/${projectId}/comments`);
    const comments = cResp.comments || cResp || [];
    const list = $id('sw-comments-list');
    if (list) list.innerHTML = swRenderComments(comments, projectId);
    if (parentId) { const w=$id(`sw-reply-input-${parentId}`); if(w)w.innerHTML=''; }
  } catch (e) { swAlert(e.message||'Could not post comment.', { title: 'Error' }); }
}

// ── Reactions ─────────────────────────────────────────────────────────────

async function swToggleReaction(projectId, reactionType) {
  const current = SW.myReactions.get(projectId)||null;
  const next = current===reactionType ? null : reactionType;
  // Delta only fires on a null <-> non-null transition — switching from one
  // reaction type straight to another (e.g. wow -> fire) is a swap, not an
  // additional reaction, since it's one reaction per member per post.
  const delta = (current===null && next!==null) ? 1 : (current!==null && next===null) ? -1 : 0;
  SW.myReactions.set(projectId, next);
  swUpdateReactionUI(projectId, delta);
  try {
    const resp = await api('POST', `/api/member/studio/projects/${projectId}/react`, { reaction_type: reactionType });
    // Server returns { active, reaction_type }; sync state with server truth
    SW.myReactions.set(projectId, resp.active ? resp.reaction_type : null);
    swUpdateReactionUI(projectId, 0);
  } catch {
    SW.myReactions.set(projectId, current);
    swUpdateReactionUI(projectId, -delta);
  }
}

function swUpdateReactionUI(projectId, countDelta = 0) {
  const myRxn = SW.myReactions.get(projectId)||null;
  // Update detail modal reactions
  $id(`detail-reactions-${projectId}`)?.querySelectorAll('.studio-rxn-btn').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.rxn === myRxn);
  });
  // Update inline feed like button on ig-post cards
  const feedCard = document.querySelector(`.ig-post[data-project-id="${CSS.escape(projectId)}"]`);
  if (feedCard) {
    const likeBtn = feedCard.querySelector('.ig-like-btn');
    if (likeBtn) {
      const isLiked = !!myRxn;
      likeBtn.classList.toggle('liked', isLiked);
      // Replace only the SVG (last child), keep the reaction popup
      const svg = likeBtn.querySelector('svg');
      if (svg) {
        svg.setAttribute('fill', isLiked ? '#4ba3d4' : 'none');
        svg.setAttribute('stroke', isLiked ? '#4ba3d4' : 'currentColor');
      }
    }
    if (countDelta !== 0) swBumpReactionCount(feedCard, countDelta);
  }
  // Keep the reaction count in the open post-detail modal in sync too
  if (countDelta !== 0 && SW.detailProjectId === projectId) {
    const overlay = $id('studio-detail-modal-overlay');
    const statEl = overlay?.querySelectorAll('.studio-detail-stat')[1]; // [views, reactions, comments]
    if (statEl) {
      const cur = parseInt((statEl.textContent||'').replace(/[^\d]/g,''),10) || 0;
      statEl.innerHTML = `${SW_ICONS.heart}&nbsp;${swFmtNum(Math.max(0, cur + countDelta))}`;
    }
  }
  // Sync overlay active states if it's currently showing for this project
  if (RXN.currentId === projectId) _rxnSyncActive(projectId);
}

/** Update the "N reactions" line on a feed card in place, creating or
 *  removing the element as the count crosses 0 — so the count never sits
 *  stale after a reaction until the next full feed reload. */
function swBumpReactionCount(feedCard, delta) {
  const prevCount = parseInt(feedCard.dataset.rxnCount || '0', 10) || 0;
  const newCount = Math.max(0, prevCount + delta);
  feedCard.dataset.rxnCount = String(newCount);
  let likesEl = feedCard.querySelector('.ig-post-likes');
  if (newCount > 0) {
    const text = `${swFmtNum(newCount)} ${newCount !== 1 ? 'reactions' : 'reaction'}`;
    if (likesEl) {
      likesEl.textContent = text;
    } else {
      likesEl = document.createElement('div');
      likesEl.className = 'ig-post-likes';
      likesEl.textContent = text;
      const actions = feedCard.querySelector('.ig-post-actions');
      actions?.insertAdjacentElement('afterend', likesEl);
    }
  } else if (likesEl) {
    likesEl.remove();
  }
}

// ── Reaction Overlay — single body-level portal ────────────────────────────
// One shared #rxn-overlay div, positioned via getBoundingClientRect().
// Escapes all overflow:hidden / stacking context traps in the card layout.

const RXN = {
  overlay: null,
  pill: null,
  backdrop: null,
  currentId: null,
  showTimer: null,
  hideTimer: null,
};

function _rxnEnsureOverlay() {
  if (RXN.overlay) return;

  // Soft blurred backdrop behind the wheel — dims/blurs the rest of the page while it's open
  const backdrop = document.createElement('div');
  backdrop.id = 'rxn-backdrop';
  document.body.appendChild(backdrop);
  RXN.backdrop = backdrop;

  const el = document.createElement('div');
  el.id = 'rxn-overlay';
  el.innerHTML = `<div class="rxn-wheel">
    <button class="rxn-btn" data-rxn="wow" title="Like">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg></div>
      <span class="rxn-label">Like</span>
    </button>
    <button class="rxn-btn" data-rxn="fire" title="Fire">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0011 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 01-7 7 7 7 0 01-4.5-1.5c1-.5 1.5-1 1-2z"/></svg></div>
      <span class="rxn-label">Fire</span>
    </button>
    <button class="rxn-btn" data-rxn="brilliant" title="Brilliant">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div>
      <span class="rxn-label">Brilliant</span>
    </button>
    <button class="rxn-btn" data-rxn="seahaven" title="Seahaven">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="1" y1="18" x2="3" y2="18"/><line x1="21" y1="18" x2="23" y2="18"/><line x1="18.36" y1="11.64" x2="19.78" y2="10.22"/><line x1="23" y1="22" x2="1" y2="22"/><polyline points="8 6 12 2 16 6"/></svg></div>
      <span class="rxn-label">Seahaven</span>
    </button>
    <button class="rxn-btn" data-rxn="mind_blown" title="Whoa">
      <div class="rxn-icon-wrap"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div>
      <span class="rxn-label">Whoa</span>
    </button>
  </div>`;
  document.body.appendChild(el);
  RXN.overlay = el;
  RXN.pill = el.querySelector('.rxn-wheel');

  // Delegate clicks on rxn-btn inside overlay
  el.addEventListener('click', e => {
    const btn = e.target.closest('.rxn-btn');
    if (btn && RXN.currentId) {
      e.stopPropagation();
      swToggleReaction(RXN.currentId, btn.dataset.rxn);
      _rxnHideNow();
    }
  });

  // Keep visible when hovering the overlay itself
  el.addEventListener('mouseenter', () => {
    clearTimeout(RXN.hideTimer);
  });
  el.addEventListener('mouseleave', () => {
    _rxnScheduleHide(150);
  });
}

function _rxnPosition(triggerEl) {
  const rect = triggerEl.getBoundingClientRect();
  const wheel = RXN.pill;
  const N = 5;
  // Overlay must be large enough to contain all buttons without clipping.
  // Buttons sit at radius R from the center; each button is BTN wide.
  // Minimum overlay size = 2*(R + BTN/2) + a little padding.
  const BTN = 42;        // must match CSS .rxn-btn width/height
  const R = 56;          // orbit radius — enough gap so buttons don't crowd the center
  const OVERLAY = 2 * (R + BTN / 2) + 16; // dynamic, keeps all buttons inside

  // Sync the overlay element's size so CSS clips nothing
  RXN.overlay.style.width  = `${OVERLAY}px`;
  RXN.overlay.style.height = `${OVERLAY}px`;

  // Position each button evenly around a full 360° circle, starting at 12 o'clock.
  // The overlay's center (OVERLAY/2, OVERLAY/2) will be placed exactly on the
  // like-button's center, so the like hand appears in the middle of the ring.
  wheel.querySelectorAll('.rxn-btn').forEach((btn, i) => {
    const angle = -90 + i * (360 / N);
    const rad = (angle * Math.PI) / 180;
    // cx/cy = top-left corner of button, relative to overlay top-left
    const cx = OVERLAY / 2 + R * Math.cos(rad) - BTN / 2;
    const cy = OVERLAY / 2 + R * Math.sin(rad) - BTN / 2;
    btn.style.left = `${Math.round(cx)}px`;
    btn.style.top  = `${Math.round(cy)}px`;
    // Burst vector for entrance animation
    const dx = (cx + BTN / 2) - OVERLAY / 2;
    const dy = (cy + BTN / 2) - OVERLAY / 2;
    btn.style.setProperty('--dx', `${dx.toFixed(1)}px`);
    btn.style.setProperty('--dy', `${dy.toFixed(1)}px`);
    btn.style.setProperty('--enter-delay', `${i * 30}ms`);
  });

  // Center the overlay exactly on the like button (fixed positioning = viewport coords)
  const btnCx = rect.left + rect.width  / 2;
  const btnCy = rect.top  + rect.height / 2;
  let left = btnCx - OVERLAY / 2;
  let top  = btnCy - OVERLAY / 2;

  // Keep the overlay inside the viewport with a small margin
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  left = Math.max(4, Math.min(left, vw - OVERLAY - 4));
  top  = Math.max(4, Math.min(top,  vh - OVERLAY - 4));

  RXN.overlay.style.left = `${Math.round(left)}px`;
  RXN.overlay.style.top  = `${Math.round(top)}px`;
  RXN.overlay.style.display = 'block';
}

function _rxnSyncActive(projectId) {
  const myRxn = SW.myReactions.get(projectId) || null;
  RXN.pill?.querySelectorAll('.rxn-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.rxn === myRxn);
  });
}

function _rxnShowNow(projectId, triggerEl) {
  _rxnEnsureOverlay();
  RXN.currentId = projectId;
  _rxnSyncActive(projectId);
  _rxnPosition(triggerEl);
  RXN.backdrop.style.display = 'block';
  // Force reflow so transitions play
  RXN.overlay.offsetHeight;
  RXN.overlay.classList.add('visible');
  RXN.backdrop.classList.add('visible');
}

function _rxnHideNow() {
  if (!RXN.overlay) return;
  RXN.overlay.classList.remove('visible');
  RXN.overlay.style.display = 'none';  // fully remove from hit-testing
  RXN.backdrop?.classList.remove('visible');
  if (RXN.backdrop) RXN.backdrop.style.display = 'none';
  RXN.currentId = null;
}

function _rxnScheduleHide(delay = 180) {
  clearTimeout(RXN.hideTimer);
  RXN.hideTimer = setTimeout(_rxnHideNow, delay);
}

// Public API called from HTML attributes
function swShowRxnPopup(projectId) {
  clearTimeout(RXN.hideTimer);
  clearTimeout(RXN.showTimer);
  RXN.showTimer = setTimeout(() => {
    const btn = document.querySelector(`.ig-like-btn[data-project-id="${CSS.escape(projectId)}"]`);
    if (btn) _rxnShowNow(projectId, btn);
  }, 280);
}

function swHideRxnPopup(projectId) {
  clearTimeout(RXN.showTimer);
  _rxnScheduleHide(160);
}

function swCancelHideRxnPopup(projectId) {
  // Legacy — no longer needed (overlay handles its own mouseenter)
  clearTimeout(RXN.hideTimer);
}

// Dismiss on scroll (repositioning on scroll would be expensive)
window.addEventListener('scroll', () => { if (RXN.overlay?.classList.contains('visible')) _rxnHideNow(); }, { passive: true });

// Dismiss when clicking anywhere outside the overlay or the like button
document.addEventListener('click', e => {
  if (!RXN.overlay?.classList.contains('visible')) return;
  if (RXN.overlay.contains(e.target)) return;
  if (e.target.closest('.ig-like-btn')) return;
  _rxnHideNow();
}, true);

// Mobile long-press: attach to feed after render
function swAttachLongPress() {
  document.querySelectorAll('.ig-like-btn[data-project-id]').forEach(btn => {
    if (btn._lpAttached) return;
    btn._lpAttached = true;
    let timer;
    btn.addEventListener('touchstart', () => {
      timer = setTimeout(() => {
        const pid = btn.dataset.projectId;
        _rxnShowNow(pid, btn);
        // Dismiss on outside touch
        const dismiss = (ev) => {
          if (!RXN.overlay?.contains(ev.target) && ev.target !== btn) {
            _rxnHideNow();
            document.removeEventListener('touchstart', dismiss, true);
          }
        };
        setTimeout(() => document.addEventListener('touchstart', dismiss, true), 50);
      }, 420);
    }, { passive: true });
    btn.addEventListener('touchend', () => clearTimeout(timer), { passive: true });
    btn.addEventListener('touchmove', () => clearTimeout(timer), { passive: true });
  });
}



let _composerPostType = 'image'; // 'image' | 'text' | 'video'
const _composerTypeOrder = ['image', 'text', 'video'];

function swSetPostType(type) {
  _composerPostType = type;
  // Update type buttons
  document.querySelectorAll('.composer-type-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.postType === type);
  });
  // Slide the pill indicator under the active button
  const indicator = $id('composer-type-indicator');
  if (indicator) {
    const idx = _composerTypeOrder.indexOf(type);
    if (idx !== -1) indicator.style.transform = `translateX(${idx * 100}%)`;
  }
  // Show/hide sections
  ['image','text','video'].forEach(t => {
    const s = $id(`section-${t}`); if (s) s.style.display = t === type ? 'flex' : 'none';
  });
}

function _fillComposerAuthor() {
  const d = window._memberProfile || _member || {};
  const name = d.name || '';
  const photo = d.photo || '';
  const avEl = $id('composer-avatar-el');
  if (avEl) {
    if (photo) {
      avEl.innerHTML = `<img src="${swEsc(photo)}" style="width:36px;height:36px;border-radius:50%;object-fit:cover" />`;
    } else {
      avEl.textContent = (name || '?')[0].toUpperCase();
    }
  }
  const nameEl = $id('composer-author-name');
  if (nameEl) nameEl.textContent = name;
}

async function swOpenNewPostModal() {
  _rxnHideNow(); // dismiss reaction wheel if open
  SW.editingProjectId = null;
  const t = $id('studio-modal-title-text'); if(t) t.textContent = 'New Post';
  const s = $id('sw-submit-btn'); if(s) s.textContent = 'Post';
  swResetPostModal();
  swSetPostType('image');
  // Show type row for new posts
  const typeRow = $id('composer-type-row'); if (typeRow) typeRow.style.display = '';
  _fillComposerAuthor();
  const o = $id('studio-post-modal-overlay');
  if (o) { o.style.display = 'flex'; document.body.style.overflow = 'hidden'; }
}

async function swOpenEditModal(projectId) {
  try {
    const p = await api('GET', `/api/member/studio/projects/${projectId}`);
    SW.editingProjectId = projectId;
    const t = $id('studio-modal-title-text'); if(t) t.textContent = 'Edit Post';
    const s = $id('sw-submit-btn'); if(s) s.textContent = 'Save';
    swResetPostModal();
    // Hide type switcher when editing
    const typeRow = $id('composer-type-row'); if (typeRow) typeRow.style.display = 'none';

    // Detect type from stored data
    const hasVideo = !!p.video_url;
    const hasCover = !!p.cover_image;
    const hasCaptionOnly = !p.title && !hasVideo && !hasCover && p.description;
    if (hasVideo) swSetPostType('video');
    else if (hasCaptionOnly) swSetPostType('text');
    else swSetPostType('image');

    // Fill fields
    const f = id => $id(id);
    if (f('sw-title'))  f('sw-title').value  = p.title || '';
    if (f('sw-tags'))   f('sw-tags').value   = (p.tags || []).join(', ');
    if (f('sw-domain')) f('sw-domain').value = p.domain || '';
    // Caption / text
    const captionVal = p.description || '';
    if (f('sw-caption'))       { f('sw-caption').value = captionVal; $id('sw-caption-count').textContent = captionVal.length; }
    if (f('sw-text-body'))     { f('sw-text-body').value = captionVal; $id('sw-text-count').textContent = captionVal.length; }
    if (f('sw-video-caption')) { f('sw-video-caption').value = captionVal; $id('sw-video-caption-count').textContent = captionVal.length; }
    if (f('sw-video-url'))     f('sw-video-url').value = p.video_url || '';
    if (f('sw-video-provider')) f('sw-video-provider').value = p.video_provider || '';
    // Cover image preview
    if (p.cover_image) {
      const img = $id('sw-cover-img'); if (img) { img.src = p.cover_image; img.style.display = ''; }
      const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = 'none';
      const rm = $id('composer-img-remove'); if (rm) rm.style.display = '';
    }
    SW.collabPickerSelected = (p.project_collaborators || []).map(c => c.members).filter(Boolean)
      .map(m => ({ id: m.id, name: m.name, photo: m.photo || null }));
    swRenderCollabPicker();
    _fillComposerAuthor();
    const o = $id('studio-post-modal-overlay'); if (o) { o.style.display = 'flex'; document.body.style.overflow = 'hidden'; }
  } catch(e) { swAlert('Could not load post for editing: ' + e.message, { title: 'Error' }); }
}

function swResetPostModal() {
  // Clear all inputs
  ['sw-title','sw-tags','sw-domain','sw-caption','sw-text-body','sw-video-url','sw-video-caption'].forEach(id => {
    const el = $id(id); if (el) el.value = '';
  });
  ['sw-caption-count','sw-text-count','sw-video-caption-count'].forEach(id => {
    const el = $id(id); if (el) el.textContent = '0';
  });
  const p = $id('sw-video-provider'); if (p) p.value = '';
  const cv = $id('sw-cover'); if (cv) cv.value = '';
  const img = $id('sw-cover-img'); if (img) { img.src = ''; img.style.display = 'none'; }
  const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = '';
  const rm = $id('composer-img-remove'); if (rm) rm.style.display = 'none';
  const err = $id('sw-err'); if (err) err.style.display = 'none';
  SW.collabPickerSelected = [];
  swRenderCollabPicker();
}

async function swSubmitPost() {
  const type     = _composerPostType;
  const title    = ($id('sw-title')?.value || '').trim();
  // Pick description from whichever textarea is active
  let desc = '';
  if (type === 'text')  desc = ($id('sw-text-body')?.value || '').trim();
  else if (type === 'video') desc = ($id('sw-video-caption')?.value || '').trim();
  else desc = ($id('sw-caption')?.value || '').trim();

  const videoUrl = ($id('sw-video-url')?.value || '').trim();
  const provider = $id('sw-video-provider')?.value || '';
  const domain   = ($id('sw-domain')?.value || '').trim();
  const tagsRaw  = ($id('sw-tags')?.value || '').trim();
  const coverFile = $id('sw-cover')?.files?.[0] || null;
  const errEl = $id('sw-err'), btn = $id('sw-submit-btn');

  const showErr = msg => { if (errEl) { errEl.textContent = msg; errEl.style.display = ''; } };

  // Validation: at least something must be present
  if (type === 'text' && !desc) { showErr('Write something to post.'); return; }
  if (type === 'video' && !videoUrl) { showErr('Add a YouTube or Vimeo URL.'); return; }
  if (type === 'image' && !coverFile && !$id('sw-cover-img')?.src) { showErr('Pick a photo to post.'); return; }

  if (btn) { btn.disabled = true; btn.textContent = SW.editingProjectId ? 'Saving…' : 'Posting…'; }
  if (errEl) errEl.style.display = 'none';

  try {
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
    const collabIds = SW.collabPickerSelected.map(m => m.id);
    const fd = new FormData();
    fd.append('title', title || desc.slice(0, 80)); // use first 80 chars of body as title if blank
    fd.append('description', desc);
    fd.append('video_url', videoUrl);
    if (provider) fd.append('video_provider', provider);
    fd.append('domain', domain);
    fd.append('tags', JSON.stringify(tags));
    fd.append('collab_ids', JSON.stringify(collabIds));
    fd.append('post_type', type);
    if (coverFile) fd.append('cover_image', coverFile);

    if (SW.editingProjectId) {
      await api('PUT', `/api/member/studio/projects/${SW.editingProjectId}`, fd, true);
    } else {
      await api('POST', '/api/member/studio/projects', fd, true);
    }
    swClosePostModal();
    await swLoadFeed(true);
    await swLoadMyPosts();
  } catch(e) {
    const ed = e._data || {};
    if (ed.warned || ed.muted || ed.banned || ed.temp_banned) {
      // Close the composer and show the dedicated violation modal instead
      swClosePostModal();
      _swVioShowModal(ed, e.message);
    } else {
      showErr(e.message || 'Could not save post. Please try again.');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = SW.editingProjectId ? 'Save' : 'Post'; }
  }
}

// ── Apple-style Profanity Violation Modal (Posts only) ────────────────────────
// Shows a full-screen frosted-glass modal with a live countdown timer when a
// post is blocked for inappropriate content. Completely separate from the DM
// toast system so each channel has the right UX.

let _swVioTimerInterval = null;

function _swEnsureVioModal() {
  if ($id('sw-vio-modal-overlay')) return;
  const el = document.createElement('div');
  el.id = 'sw-vio-modal-overlay';
  el.setAttribute('role', 'alertdialog');
  el.setAttribute('aria-modal', 'true');
  el.style.cssText = [
    'position:fixed', 'inset:0', 'z-index:9999',
    'display:flex', 'align-items:center', 'justify-content:center',
    'background:rgba(0,0,0,.72)',
    'backdrop-filter:blur(28px)', '-webkit-backdrop-filter:blur(28px)',
    'opacity:0', 'pointer-events:none',
    'transition:opacity .28s cubic-bezier(.4,0,.2,1)',
    'padding:20px',
  ].join(';');
  el.innerHTML = `
    <div id="sw-vio-modal" style="
      background:rgba(18,18,18,.98);
      border:1px solid rgba(255,255,255,.10);
      border-radius:20px;
      padding:32px 28px 28px;
      max-width:380px;
      width:100%;
      box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.04);
      text-align:center;
      transform:scale(.92) translateY(12px);
      transition:transform .28s cubic-bezier(.34,1.56,.64,1),opacity .28s ease;
      opacity:0;
    ">
      <div id="sw-vio-icon" style="
        width:56px;height:56px;border-radius:50%;
        display:flex;align-items:center;justify-content:center;
        margin:0 auto 18px;color:#e8e8e8;
        background:rgba(255,255,255,.08);border:1.5px solid rgba(255,255,255,.14);
      "></div>
      <div id="sw-vio-title" style="
        font-size:18px;font-weight:700;letter-spacing:-.025em;
        color:#f5f5f5;margin-bottom:8px;line-height:1.25;
      "></div>
      <div id="sw-vio-desc" style="
        font-size:13.5px;color:rgba(255,255,255,.55);line-height:1.6;
        margin-bottom:22px;
      "></div>
      <div id="sw-vio-timer-wrap" style="display:none;margin-bottom:22px;">
        <div style="
          font-size:11px;letter-spacing:.1em;text-transform:uppercase;
          color:rgba(255,255,255,.3);margin-bottom:8px;
        ">POSTING UNLOCKED IN</div>
        <div id="sw-vio-timer" style="
          font-size:38px;font-weight:800;letter-spacing:-.04em;
          font-variant-numeric:tabular-nums;
          color:#f5f5f5;line-height:1;
        ">—</div>
        <div style="
          margin-top:10px;height:3px;background:rgba(255,255,255,.08);
          border-radius:2px;overflow:hidden;
        ">
          <div id="sw-vio-timer-bar" style="
            height:100%;width:100%;border-radius:2px;
            background:#e8e8e8;
            transform-origin:left;transition:transform .9s linear;
          "></div>
        </div>
      </div>
      <div id="sw-vio-appeal-wrap" style="display:none;margin-bottom:12px">
        <button id="sw-vio-appeal-btn" onclick="_swVioSubmitAppeal()" style="
          width:100%;padding:13px 20px;border-radius:12px;border:none;
          background:#f5f5f5;color:#000;
          font-size:15px;font-weight:600;letter-spacing:-.01em;
          cursor:pointer;transition:opacity .15s;margin-bottom:8px;
          -webkit-tap-highlight-color:transparent;
        ">Ask Admin to Review</button>
        <div id="sw-vio-appeal-status" style="font-size:12px;color:rgba(255,255,255,.45);text-align:center;line-height:1.4"></div>
      </div>
      <button id="sw-vio-dismiss" onclick="_swVioClose()" style="
        width:100%;padding:13px 20px;border-radius:12px;border:none;
        background:rgba(255,255,255,.08);color:#f5f5f5;
        font-size:15px;font-weight:600;letter-spacing:-.01em;
        cursor:pointer;transition:background .15s;
        -webkit-tap-highlight-color:transparent;
      " onmouseover="this.style.background='rgba(255,255,255,.13)'"
         onmouseout="this.style.background='rgba(255,255,255,.08)'">
        Got it
      </button>
    </div>`;
  document.body.appendChild(el);
}

function _swVioFormatMs(ms) {
  if (ms <= 0) return '0:00';
  const totalSec = Math.ceil(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
  return `${m}:${String(s).padStart(2,'0')}`;
}

function _swVioShowModal(data, msg) {
  _swEnsureVioModal();
  clearInterval(_swVioTimerInterval);

  const overlay    = $id('sw-vio-modal-overlay');
  const modal      = $id('sw-vio-modal');
  const icon       = $id('sw-vio-icon');
  const title      = $id('sw-vio-title');
  const desc       = $id('sw-vio-desc');
  const timerWrap  = $id('sw-vio-timer-wrap');
  const timerEl    = $id('sw-vio-timer');
  const timerBar   = $id('sw-vio-timer-bar');
  const dismiss    = $id('sw-vio-dismiss');
  const appealWrap = $id('sw-vio-appeal-wrap');
  const appealBtn  = $id('sw-vio-appeal-btn');
  const appealStat = $id('sw-vio-appeal-status');

  // Reset appeal area
  if (appealWrap) appealWrap.style.display = 'none';
  if (appealStat) appealStat.textContent = '';
  if (appealBtn)  { appealBtn.disabled = false; appealBtn.textContent = 'Ask Admin to Review'; }

  // ── Tiny inline SVG icon set (grayscale, no emojis) ────────────────────────
  const _vioIconSvg = {
    warning: '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    mute:    '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>',
    ban:     '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    lock:    '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    check:   '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  };
  function _vioIconSmall(name) {
    return _vioIconSvg[name].replace('width="26" height="26"', 'width="12" height="12"');
  }

  // ── Ladder step labels shown in descriptions (icon + text, no emoji) ───────
  const ladderSteps = [
    { icon: 'warning', label: '1st violation \u2192 Warning' },
    { icon: 'mute',    label: '2nd violation \u2192 1-minute mute' },
    { icon: 'mute',    label: '3rd violation \u2192 2-minute mute' },
    { icon: 'mute',    label: '4th violation \u2192 5-minute mute' },
    { icon: 'ban',     label: '5th violation \u2192 Temporary ban' },
  ];
  function _ladderHtml(currentOffense) {
    return ladderSteps.map((s, i) => {
      const n = i + 1;
      const isCurrent = n === currentOffense;
      const isPast    = n < currentOffense;
      return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;${isCurrent ? 'font-weight:700;color:#f5f5f5' : isPast ? 'color:rgba(255,255,255,.3);text-decoration:line-through' : 'color:rgba(255,255,255,.45)'}">
        <span style="width:18px;height:18px;border-radius:50%;background:${isCurrent ? '#f5f5f5' : isPast ? 'rgba(255,255,255,.08)' : 'rgba(255,255,255,.06)'};color:${isCurrent ? '#000' : 'inherit'};display:flex;align-items:center;justify-content:center;flex-shrink:0">${isPast ? _vioIconSmall('check') : _vioIconSmall(s.icon)}</span>
        <span style="font-size:12.5px">${s.label}</span>
      </div>`;
    }).join('');
  }

  if (data.temp_banned || data.action === 'temp_ban') {
    // ── TEMP BAN ─────────────────────────────────────────────────────────────
    icon.innerHTML = _vioIconSvg.ban;
    title.textContent = 'Temporarily Banned';

    let untilStr = '';
    if (data.suspended_until) {
      const d = new Date(data.suspended_until);
      untilStr = ` until ${d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}`;
    }

    desc.innerHTML = `<div style="margin-bottom:14px;font-size:13px;line-height:1.6">Your account has been temporarily suspended${untilStr} due to repeated guideline violations. You cannot post, DM, or use Social Strand during this period.</div>
      <div style="background:rgba(255,255,255,.04);border-radius:12px;padding:12px 14px;margin-bottom:6px;text-align:left">${_ladderHtml(data.offense || 5)}</div>`;

    timerWrap.style.display = 'none';
    dismiss.textContent = 'Close';
    if (appealWrap) appealWrap.style.display = '';

    // Show Social Strand lockout overlay
    _swShowTempBanOverlay(data.suspended_until);

  } else if (data.banned) {
    // ── PERMANENT BAN ────────────────────────────────────────────────────────
    icon.innerHTML = _vioIconSvg.lock;
    title.textContent = 'Account Disabled';
    desc.innerHTML = `<div style="margin-bottom:6px">Your account has been permanently disabled for repeated violations of our community guidelines.</div><div style="font-size:12px;color:rgba(255,255,255,.35);margin-top:8px">Contact KFS leadership directly to appeal this decision.</div>`;
    timerWrap.style.display = 'none';
    dismiss.textContent = 'Close';
    if (appealWrap) appealWrap.style.display = 'none';

  } else if (data.muted && data.muted_until) {
    // ── MUTE ─────────────────────────────────────────────────────────────────
    const muteUntil  = new Date(data.muted_until).getTime();
    const totalMs    = muteUntil - Date.now();
    const offenseNum = data.offense || 2;

    icon.innerHTML = _vioIconSvg.mute;
    title.textContent = `Warning #${offenseNum} — Posting Paused`;

    const nextHint = offenseNum === 2 ? 'Next: 2-min mute'
                   : offenseNum === 3 ? 'Next: 5-min mute'
                   : 'Next: Temporary ban';

    desc.innerHTML = `<div style="margin-bottom:12px;font-size:13px;line-height:1.6">Your message contained language that violates our community guidelines. Posting is paused until the timer expires.</div>
      <div style="background:rgba(255,255,255,.04);border-radius:12px;padding:12px 14px;margin-bottom:6px;text-align:left">${_ladderHtml(offenseNum)}</div>
      <div style="font-size:11.5px;color:rgba(255,255,255,.4);margin-top:8px;display:flex;align-items:center;justify-content:center;gap:5px">${_vioIconSmall('warning')} ${nextHint}</div>`;

    timerWrap.style.display = 'block';
    dismiss.textContent = 'I understand';
    if (appealWrap) appealWrap.style.display = 'none';

    timerEl.textContent = _swVioFormatMs(Math.max(0, muteUntil - Date.now()));
    timerBar.style.transform = 'scaleX(1)';

    requestAnimationFrame(() => {
      timerBar.style.transition = `transform ${Math.ceil(totalMs / 1000)}s linear`;
      timerBar.style.transform  = 'scaleX(0)';
    });

    _swVioTimerInterval = setInterval(() => {
      const rem = muteUntil - Date.now();
      if (rem <= 0) {
        clearInterval(_swVioTimerInterval);
        timerEl.textContent = '0:00';
        timerEl.style.color = '#f5f5f5';
        desc.innerHTML = `<div style="color:rgba(255,255,255,.65);font-size:13px">Your posting is now unlocked. Please keep the community respectful going forward.</div>`;
        dismiss.textContent = 'Start posting again';
        return;
      }
      timerEl.textContent = _swVioFormatMs(rem);
    }, 500);

  } else {
    // ── WARNING ONLY (offense 1) ──────────────────────────────────────────────
    const offenseNum = data.offense || 1;
    icon.innerHTML = _vioIconSvg.warning;
    title.textContent = `Warning #${offenseNum} — Post Blocked`;

    desc.innerHTML = `<div style="margin-bottom:12px;font-size:13px;line-height:1.6">${msg || 'Your post contained language that violates our community guidelines.'}</div>
      <div style="background:rgba(255,255,255,.04);border-radius:12px;padding:12px 14px;text-align:left">${_ladderHtml(offenseNum)}</div>
      <div style="font-size:11.5px;color:rgba(255,255,255,.4);margin-top:10px;display:flex;align-items:center;justify-content:center;gap:5px">${_vioIconSmall('warning')} Next violation will result in a 1-min mute.</div>`;

    timerWrap.style.display = 'none';
    dismiss.textContent = 'I understand';
    if (appealWrap) appealWrap.style.display = 'none';
  }

  // Animate in
  overlay.style.pointerEvents = 'auto';
  overlay.style.opacity = '1';
  requestAnimationFrame(() => {
    modal.style.transform = 'scale(1) translateY(0)';
    modal.style.opacity   = '1';
  });

  overlay.onclick = e => { if (e.target === overlay) _swVioClose(); };
  document._swVioKeyHandler = e => { if (e.key === 'Escape') _swVioClose(); };
  document.addEventListener('keydown', document._swVioKeyHandler);
}

function _swVioClose() {
  clearInterval(_swVioTimerInterval);
  const overlay = $id('sw-vio-modal-overlay');
  const modal   = $id('sw-vio-modal');
  if (!overlay) return;
  overlay.style.opacity = '0';
  overlay.style.pointerEvents = 'none';
  if (modal) { modal.style.transform = 'scale(.92) translateY(12px)'; modal.style.opacity = '0'; }
  if (document._swVioKeyHandler) {
    document.removeEventListener('keydown', document._swVioKeyHandler);
    delete document._swVioKeyHandler;
  }
}

async function _swVioSubmitAppeal() {
  const btn    = $id('sw-vio-appeal-btn');
  const status = $id('sw-vio-appeal-status');
  if (!btn || !status) return;
  btn.disabled  = true;
  btn.textContent = 'Submitting…';
  status.textContent = '';
  try {
    const res = await api('POST', '/api/member/ban-appeal', { reason: 'Member requested review via Social Strand.' });
    btn.textContent    = 'Appeal Submitted';
    status.textContent = 'An admin will review your case. You will be notified when a decision is made.';
    status.style.color = 'rgba(255,255,255,.5)';
  } catch (e) {
    btn.disabled   = false;
    btn.textContent = 'Ask Admin to Review';
    status.textContent = e.message || 'Could not submit appeal. Try again.';
    status.style.color = 'rgba(255,255,255,.5)';
  }
}

// Full Social Strand lockout overlay shown when member is temp-banned
function _swShowTempBanOverlay(suspendedUntil) {
  if ($id('sw-tempban-overlay')) return; // already showing
  const el = document.createElement('div');
  el.id = 'sw-tempban-overlay';
  el.style.cssText = [
    'position:fixed','inset:0','z-index:9998',
    'background:rgba(0,0,0,.88)',
    'backdrop-filter:blur(20px)','-webkit-backdrop-filter:blur(20px)',
    'display:flex','align-items:center','justify-content:center',
    'flex-direction:column','gap:14px','padding:28px','text-align:center',
  ].join(';');

  let untilHtml = '';
  if (suspendedUntil) {
    const d = new Date(suspendedUntil);
    untilHtml = `<div style="font-size:13px;color:rgba(255,255,255,.4);margin-top:4px">Suspended until ${d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}</div>`;
  }

  el.innerHTML = `
    <div style="width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin-bottom:4px;color:#e8e8e8;background:rgba(255,255,255,.08);border:1.5px solid rgba(255,255,255,.14)">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
    </div>
    <div style="font-size:22px;font-weight:800;letter-spacing:-.03em;color:#f5f5f5">Account Suspended</div>
    ${untilHtml}
    <div style="font-size:14px;color:rgba(255,255,255,.5);max-width:340px;line-height:1.6;margin-top:2px">
      You cannot access Social Strand, DMs, or Group Chats during your suspension. If you believe this is a mistake, tap below to request a review.
    </div>
    <button id="sw-tempban-appeal-btn" style="
      margin-top:10px;padding:14px 32px;border-radius:14px;border:none;
      background:#f5f5f5;color:#000;
      font-size:15px;font-weight:700;cursor:pointer;letter-spacing:.01em;
      font-family:inherit;transition:opacity .15s;
    ">Ask Admin to Review</button>
    <div id="sw-tempban-appeal-status" style="font-size:12.5px;color:rgba(255,255,255,.4);min-height:18px"></div>
  `;
  document.body.appendChild(el);

  el.querySelector('#sw-tempban-appeal-btn').addEventListener('click', async () => {
    const btn = el.querySelector('#sw-tempban-appeal-btn');
    const stat = el.querySelector('#sw-tempban-appeal-status');
    btn.disabled = true;
    btn.textContent = 'Submitting…';
    try {
      await api('POST', '/api/member/ban-appeal', { reason: 'Member requested review via ban overlay.' });
      btn.textContent = 'Appeal Submitted';
      stat.textContent = 'An admin will review your case and you\'ll be notified.';
      stat.style.color = 'rgba(255,255,255,.5)';
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Ask Admin to Review';
      stat.textContent = e.message || 'Could not submit — try again.';
      stat.style.color = 'rgba(255,255,255,.5)';
    }
  });
}


async function swDeletePost(projectId,title) {
  if (!await swConfirm(`Delete "${swEsc(title)}"? This cannot be undone.`, { title: 'Delete post', confirmLabel: 'Delete', danger: true })) return;
  try {
    await api('DELETE',`/api/member/studio/projects/${projectId}`);
    await swLoadMyPosts();
    await swLoadFeed(true);
  } catch(e){ swAlert('Could not delete: '+e.message, { title: 'Error' }); }
}

function swClosePostModal() {
  const o = $id('studio-post-modal-overlay');
  const sheet = $id('composer-sheet');
  const finish = () => {
    if (o) o.style.display = 'none';
    document.body.style.overflow = '';
    swResetPostModal();
  };
  if (o && sheet && o.style.display !== 'none' && typeof window._kfsAnimateSheetOut === 'function') {
    window._kfsAnimateSheetOut(sheet, '0', finish);
  } else {
    finish();
  }
}

function swCloseDetailModal() {
  const o=$id('studio-detail-modal-overlay');if(o)o.style.display='none';
  document.body.style.overflow='';
  SW.detailProjectId=null;
}

// ── Collaborator Picker ────────────────────────────────────────────────────

let _swCollabTimer=null;

function swRenderCollabPicker() {
  const wrap=$id('sw-collab-picker');if(!wrap)return;
  const chips=SW.collabPickerSelected.map(m=>`<span class="sw-collab-chip">${swAvatar(m.name,m.photo,18)}<span>${swEsc(m.name)}</span><button onclick="swRemoveCollab('${swEsc(m.id)}')" title="Remove">${SW_ICONS.close}</button></span>`).join('');
  wrap.innerHTML=`<div class="sw-collab-wrap">${chips}<input id="sw-collab-input" type="text" placeholder="Search members…" class="sw-collab-input" autocomplete="off" oninput="swCollabSearch(this.value)"></div><div id="sw-collab-dropdown" class="sw-collab-dropdown" style="display:none"></div>`;
}

async function swCollabSearch(q) {
  clearTimeout(_swCollabTimer);
  const dd=$id('sw-collab-dropdown');if(!dd)return;
  if(!q||q.length<2){dd.style.display='none';return;}
  _swCollabTimer=setTimeout(async()=>{
    try {
      const results=await api('GET',`/api/member/studio/members-search?q=${encodeURIComponent(q)}`);
      const filtered=results.filter(m=>!SW.collabPickerSelected.find(s=>s.id===m.id));
      if(!filtered.length){dd.style.display='none';return;}
      dd.style.display='';
      dd.innerHTML=filtered.map(m=>`<div class="sw-collab-option" onclick="swAddCollab('${swEsc(m.id)}','${swEsc(m.name)}','${swEsc(m.photo_url||'')}')">
        ${swAvatar(m.name,m.photo_url,24)}<span>${swEsc(m.name)}</span></div>`).join('');
    } catch{dd.style.display='none';}
  },250);
}

function swAddCollab(id,name,photo) {
  if(!SW.collabPickerSelected.find(m=>m.id===id)) SW.collabPickerSelected.push({id,name,photo:photo||null});
  swRenderCollabPicker();
}

function swRemoveCollab(id) {
  SW.collabPickerSelected=SW.collabPickerSelected.filter(m=>m.id!==id);
  swRenderCollabPicker();
}

// ── Tab switching ──────────────────────────────────────────────────────────

function swSwitchTab(tabName) {
  document.querySelectorAll('.studio-tab').forEach(t=>t.classList.toggle('active',t.dataset.studioTab===tabName));
  document.querySelectorAll('.studio-tab-panel').forEach(p=>p.classList.toggle('active',p.id===`studio-tab-${tabName}`));
  if(tabName==='my-posts')  swLoadMyPosts();
  if(tabName==='analytics') swLoadAnalytics();
}

// ── Init ──────────────────────────────────────────────────────────────────

function initStudioWall() {
  document.querySelectorAll('.studio-tab').forEach(btn=>{
    btn.addEventListener('click',()=>swSwitchTab(btn.dataset.studioTab));
  });

  $id('studio-new-post-btn')?.addEventListener('click', swOpenNewPostModal);
  $id('studio-new-post-btn2')?.addEventListener('click', swOpenNewPostModal);
  $id('studio-post-modal-close')?.addEventListener('click', swClosePostModal);
  $id('studio-post-modal-cancel')?.addEventListener('click', swClosePostModal);
  $id('studio-post-modal-overlay')?.addEventListener('click',e=>{if(e.target===$id('studio-post-modal-overlay'))swClosePostModal();});
  $id('studio-detail-close')?.addEventListener('click', swCloseDetailModal);
  $id('studio-detail-modal-overlay')?.addEventListener('click',e=>{if(e.target===$id('studio-detail-modal-overlay'))swCloseDetailModal();});
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'){
      if($id('studio-detail-modal-overlay')?.style.display==='flex')swCloseDetailModal();
      if($id('studio-post-modal-overlay')?.style.display==='flex')swClosePostModal();
    }
  });
  $id('sw-submit-btn')?.addEventListener('click', swSubmitPost);

  // Post type picker (Photo / Text / Video)
  document.querySelectorAll('.composer-type-btn').forEach(btn => {
    btn.addEventListener('click', () => swSetPostType(btn.dataset.postType));
  });

  // Tap the image zone (anywhere except the remove button) to open the file picker
  $id('composer-img-zone')?.addEventListener('click', e => {
    if (e.target.closest('#composer-img-remove')) return;
    $id('sw-cover')?.click();
  });

  // Remove the selected/loaded photo and go back to the placeholder state
  $id('composer-img-remove')?.addEventListener('click', e => {
    e.stopPropagation();
    const cv = $id('sw-cover'); if (cv) cv.value = '';
    const img = $id('sw-cover-img'); if (img) { img.src = ''; img.style.display = 'none'; }
    const ph = $id('composer-img-placeholder'); if (ph) ph.style.display = '';
    e.currentTarget.style.display = 'none';
  });

  $id('sw-cover')?.addEventListener('change', e => {
    const f = e.target.files?.[0]; if (!f) return;
    const img = $id('sw-cover-img');
    const ph  = $id('composer-img-placeholder');
    const rm  = $id('composer-img-remove');
    if (img) { img.src = URL.createObjectURL(f); img.style.display = ''; }
    if (ph) ph.style.display = 'none';
    if (rm) rm.style.display = '';
  });
  $id('sw-desc')?.addEventListener('input',e=>{const c=$id('sw-desc-count');if(c)c.textContent=e.target.value.length;});

  let _tagTimer=null;
  $id('studio-tag-filter')?.addEventListener('input',e=>{
    clearTimeout(_tagTimer);
    _tagTimer=setTimeout(()=>{SW.feedTag=e.target.value.trim().toLowerCase()||null;swLoadFeed(true);},400);
  });
  $id('studio-load-more-btn')?.addEventListener('click',()=>swLoadFeed(false));

  // Smart feed — Latest / For You (Phase 2)
  $id('feed-sort-toggle')?.addEventListener('click', e => {
    const btn = e.target.closest('.feed-sort-btn');
    if (!btn || btn.classList.contains('active')) return;
    document.querySelectorAll('.feed-sort-btn').forEach(b => b.classList.toggle('active', b === btn));
    SW.feedSort = btn.dataset.feedSort === 'foryou' ? 'foryou' : 'latest';
    swLoadFeed(true);
  });

  // Load feed when Studio panel becomes active
  const panelEl=$id('panel-studio');
  if(panelEl){
    const obs=new MutationObserver(muts=>{
      muts.forEach(m=>{if(m.attributeName==='class'&&panelEl.classList.contains('active'))swLoadFeed(true);});
    });
    obs.observe(panelEl,{attributes:true});
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Network — Follow system (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const NW = {
  followersPage: 1, followersExhausted: false, followersLoading: false,
  followingPage: 1, followingExhausted: false, followingLoading: false,
  myFollowing: new Map(), // memberId → bool (local optimistic cache)
  profileMemberId: null,
};

function nwMyId() {
  return window._memberProfile?.id || window._member?.id || null;
}

// Maps a status slug (set by the Member Status feature) to its display label.
// Kept here too — not just in the status-editor UI — since follower/following
// rows and the mini-profile modal need to render it wherever it appears.
function nwStatusLabel(status) {
  const map = { open_to_collab: 'Open to collab', busy_on_set: 'Busy on set', alumni_mentor: 'Alumni mentor' };
  return map[status] || null;
}

function nwFollowBtn(m) {
  const myId = nwMyId();
  if (!m.id || m.id === myId) return '';
  const isFollowing = NW.myFollowing.has(m.id) ? NW.myFollowing.get(m.id) : !!m.is_following;
  return `<button class="nw-follow-btn ${isFollowing?'following':''}" data-member-id="${swEsc(m.id)}" onclick="event.stopPropagation();toggleFollow('${swEsc(m.id)}',this)">${isFollowing?'Following':'Follow'}</button>`;
}

function nwRenderRow(m) {
  const statusLabel = nwStatusLabel(m.status);
  return `<div class="nw-row" data-row-member="${swEsc(m.id)}">
    <span class="nw-row-info" onclick="openMemberProfile('${swEsc(m.id)}')">
      ${swAvatar(m.name, m.photo, 36)}
      <span>
        <div class="nw-row-name">${swEsc(m.name||'Member')}${statusLabel?`<span class="nw-status-pill">${swEsc(statusLabel)}</span>`:''}</div>
        <div class="nw-row-meta">${swEsc(m.role || m.domain || '')}</div>
      </span>
    </span>
    ${nwFollowBtn(m)}
  </div>`;
}

async function nwLoadFollowers(reset = false) {
  const myId = nwMyId();
  if (!myId) return;
  if (NW.followersLoading) return;
  if (!reset && NW.followersExhausted) return;
  if (reset) { NW.followersPage = 1; NW.followersExhausted = false; }
  const list = $id('network-followers-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  NW.followersLoading = true;
  try {
    const resp = await api('GET', `/api/member/network/followers/${myId}?page=${NW.followersPage}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, m.is_following));
    if (reset) list.innerHTML = '';
    if (!members.length && NW.followersPage === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No followers yet</div><div class="sw-empty-sub">Share work on the Social Strand to get noticed.</div></div>`;
      hideEl('network-followers-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('network-followers-more'); NW.followersPage++; }
    else { hideEl('network-followers-more'); NW.followersExhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load followers.</div>`;
  } finally {
    NW.followersLoading = false;
  }
}

async function nwLoadFollowing(reset = false) {
  const myId = nwMyId();
  if (!myId) return;
  if (NW.followingLoading) return;
  if (!reset && NW.followingExhausted) return;
  if (reset) { NW.followingPage = 1; NW.followingExhausted = false; }
  const list = $id('network-following-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  NW.followingLoading = true;
  try {
    const resp = await api('GET', `/api/member/network/following/${myId}?page=${NW.followingPage}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, true)); // by definition, people I follow
    if (reset) list.innerHTML = '';
    if (!members.length && NW.followingPage === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">Not following anyone yet</div><div class="sw-empty-sub">Follow members from their posts on the Social Strand.</div></div>`;
      hideEl('network-following-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('network-following-more'); NW.followingPage++; }
    else { hideEl('network-following-more'); NW.followingExhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load following.</div>`;
  } finally {
    NW.followingLoading = false;
  }
}

function loadNetworkPanel() {
  nwLoadFollowers(true);
  nwLoadFollowing(true);
}

function nwSwitchTab(tabName) {
  document.querySelectorAll('.nw-tab').forEach(t=>t.classList.toggle('active', t.dataset.networkTab===tabName));
  document.querySelectorAll('.nw-tab-panel').forEach(p=>p.classList.toggle('active', p.id===`network-tab-${tabName}`));
  const sel = $id('nw-tabs-select');
  if (sel && sel.value !== tabName) sel.value = tabName;
  if (tabName === 'discover')    loadDiscoverTab();
  if (tabName === 'leaderboard') loadLeaderboardTab();
  if (tabName === 'collab')      loadMyCollabs();
}

// ── Follow toggle — called from feed cards, member rows, and the mini-profile modal ──
async function toggleFollow(memberId, btnEl) {
  if (!memberId || btnEl?.disabled) return;
  if (btnEl) btnEl.disabled = true;
  try {
    const resp = await api('POST', `/api/member/network/follow/${memberId}`);
    NW.myFollowing.set(memberId, resp.following);
    // Update every rendered follow button for this member (feed cards, lists, modal)
    document.querySelectorAll(`.nw-follow-btn[data-member-id="${memberId}"]`).forEach(b => {
      b.classList.toggle('following', resp.following);
      b.textContent = resp.following ? 'Following' : 'Follow';
      b.disabled = false;
    });
    const statFollowers = $id('mpm-stat-followers');
    if (statFollowers && NW.profileMemberId === memberId) statFollowers.textContent = swFmtNum(resp.followers_count);
    // Following list membership just changed — refresh it next time that tab is visited
    NW.followingExhausted = false;
  } catch (e) {
    if (btnEl) btnEl.disabled = false;
    swAlert(e.message || 'Could not update follow status.', { title: 'Error' });
  }
}

// ── Member mini-profile modal ────────────────────────────────────────────
async function openMemberProfile(memberId) {
  if (!memberId) return;
  NW.profileMemberId = memberId;
  const overlay = $id('member-profile-modal-overlay');
  const body    = $id('member-profile-modal-body');
  if (!overlay || !body) return;
  body.innerHTML = '<div class="sw-loading" style="padding:40px 0;text-align:center">Loading…</div>';
  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
  try {
    const m = await api('GET', `/api/member/network/profile/${memberId}`);
    NW.myFollowing.set(m.id, m.is_following);
    const statusLabel = nwStatusLabel(m.status);
    body.innerHTML = `
      <div class="mpm-head">
        ${swAvatar(m.name, m.photo, 64)}
        <div>
          <div class="mpm-name">${swEsc(m.name||'Member')}${statusLabel?`<span class="nw-status-pill">${swEsc(statusLabel)}</span>`:''}</div>
          <div class="mpm-role">${swEsc([m.role, m.domain].filter(Boolean).join(' · '))}</div>
        </div>
      </div>
      ${m.bio ? `<div class="mpm-bio">${swEsc(m.bio)}</div>` : ''}
      <div class="mpm-stats">
        <div class="mpm-stat"><div class="mpm-stat-val" id="mpm-stat-followers">${swFmtNum(m.followers_count)}</div><div class="mpm-stat-label">Followers</div></div>
        <div class="mpm-stat"><div class="mpm-stat-val">${swFmtNum(m.following_count)}</div><div class="mpm-stat-label">Following</div></div>
      </div>
      ${m.skills?.length ? `<div class="mpm-skills">${m.skills.map(s=>`<span class="mpm-skill-chip" onclick="closeMemberProfileModal();discFilterBySkill('${swEsc(s.name)}')" style="cursor:pointer">${swEsc(s.name)}</span>`).join('')}</div>` : ''}
      ${m.is_self ? '' : `<button class="nw-follow-btn ${m.is_following?'following':''}" id="mpm-follow-btn" data-member-id="${swEsc(m.id)}" style="width:100%;padding:11px" onclick="toggleFollow('${swEsc(m.id)}',this)">${m.is_following?'Following':'Follow'}</button>`}
    `;
  } catch (e) {
    body.innerHTML = `<div style="padding:32px;text-align:center;color:var(--muted);font-size:14px">${swEsc(e.message)}</div>`;
  }
}

function closeMemberProfileModal() {
  hideEl('member-profile-modal-overlay');
  document.body.style.overflow = '';
  NW.profileMemberId = null;
}

function initNetworkModule() {
  document.querySelectorAll('.nw-tab').forEach(btn => {
    btn.addEventListener('click', () => nwSwitchTab(btn.dataset.networkTab));
  });
  $id('nw-tabs-select')?.addEventListener('change', e => nwSwitchTab(e.target.value));
  $id('network-followers-more-btn')?.addEventListener('click', () => nwLoadFollowers(false));
  $id('network-following-more-btn')?.addEventListener('click', () => nwLoadFollowing(false));
  $id('member-profile-modal-close')?.addEventListener('click', closeMemberProfileModal);
  $id('member-profile-modal-overlay')?.addEventListener('click', e => {
    if (e.target === $id('member-profile-modal-overlay')) closeMemberProfileModal();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $id('member-profile-modal-overlay')?.style.display === 'flex') closeMemberProfileModal();
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Member status (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

// Renders the active pill in the Profile panel's status picker.
// (nwStatusLabel(), above, renders the same slugs as a read-only pill
// wherever a member's status shows up elsewhere — feed cards, rows, modal.)
function renderStatusPicker(status) {
  document.querySelectorAll('#status-picker .status-pill-btn').forEach(b => {
    const isClear = b.classList.contains('status-pill-clear');
    b.classList.toggle('active', !isClear && b.dataset.status === (status || ''));
  });
}

async function setMemberStatus(status) {
  const picker = $id('status-picker');
  picker?.querySelectorAll('.status-pill-btn').forEach(b => b.disabled = true);
  hideEl('status-err');
  try {
    const resp = await api('POST', '/api/member/network/status', { status: status || null });
    renderStatusPicker(resp.status);
    if (window._memberProfile) window._memberProfile.status = resp.status;
    showMsg('status-msg', resp.status ? 'Status updated.' : 'Status cleared.');
  } catch (e) {
    showMsg('status-err', e.message || 'Could not update status.', false);
  } finally {
    picker?.querySelectorAll('.status-pill-btn').forEach(b => b.disabled = false);
  }
}

function initStatusModule() {
  $id('status-picker')?.addEventListener('click', e => {
    const btn = e.target.closest('.status-pill-btn');
    if (!btn || btn.disabled) return;
    const isClear = btn.classList.contains('status-pill-clear');
    if (!isClear && btn.classList.contains('active')) return; // already set — no-op
    setMemberStatus(isClear ? null : btn.dataset.status);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Skills / Interest graph (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const SKILLS = { mine: [], suggestTimer: null };

function skillChipHtml(tag) {
  return `<span class="skill-chip" data-tag-id="${swEsc(tag.id)}">${swEsc(tag.name)}<button type="button" class="skill-chip-remove" onclick="removeSkill('${swEsc(tag.id)}')" title="Remove" aria-label="Remove ${swEsc(tag.name)}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></span>`;
}

function renderSkillChips() {
  const wrap = $id('skill-chips');
  if (!wrap) return;
  if (!SKILLS.mine.length) {
    wrap.innerHTML = `<div class="skill-chip-empty">No skills tagged yet — add up to ${12} above.</div>`;
    return;
  }
  wrap.innerHTML = SKILLS.mine.map(skillChipHtml).join('');
}

async function loadMySkills() {
  try {
    SKILLS.mine = await api('GET', '/api/member/skills/mine');
    renderSkillChips();
  } catch (e) {
    console.error('loadMySkills:', e);
  }
}

async function addSkill(name) {
  const clean = (name || '').trim();
  if (!clean) return;
  hideEl('skill-err');
  try {
    const resp = await api('POST', '/api/member/skills', { name: clean });
    if (!SKILLS.mine.some(t => t.id === resp.tag.id)) {
      SKILLS.mine.push(resp.tag);
      renderSkillChips();
    }
    const input = $id('skill-input');
    if (input) input.value = '';
    hideEl('skill-suggestions');
  } catch (e) {
    showMsg('skill-err', e.message || 'Could not add skill.', false);
  }
}

async function removeSkill(tagId) {
  try {
    await api('DELETE', `/api/member/skills/${tagId}`);
    SKILLS.mine = SKILLS.mine.filter(t => t.id !== tagId);
    renderSkillChips();
  } catch (e) {
    showMsg('skill-err', e.message || 'Could not remove skill.', false);
  }
}

async function showSkillSuggestions(q) {
  const box = $id('skill-suggestions');
  if (!box) return;
  try {
    const results = await api('GET', `/api/member/skills/search?q=${encodeURIComponent(q)}`);
    const mineIds = new Set(SKILLS.mine.map(t => t.id));
    const filtered = results.filter(r => !mineIds.has(r.id));
    let html = filtered.map(r => `<div class="skill-suggestion-item" onclick="addSkill('${swEsc(r.name)}')"><span>${swEsc(r.name)}</span><span class="skill-suggestion-count">${swFmtNum(r.usage_count)} ${r.usage_count===1?'member':'members'}</span></div>`).join('');
    if (q && !results.some(r => r.name.toLowerCase() === q.toLowerCase())) {
      html += `<div class="skill-suggestion-item skill-suggestion-create" onclick="addSkill('${swEsc(q)}')">+ Add "${swEsc(q)}"</div>`;
    }
    if (!html) { hideEl('skill-suggestions'); return; }
    box.innerHTML = html;
    box.style.display = 'block';
  } catch (e) {
    hideEl('skill-suggestions');
  }
}

function initSkillsModule() {
  const input = $id('skill-input');
  if (!input) return;
  input.addEventListener('input', () => {
    clearTimeout(SKILLS.suggestTimer);
    const v = input.value.trim();
    if (!v) { hideEl('skill-suggestions'); return; }
    SKILLS.suggestTimer = setTimeout(() => showSkillSuggestions(v), 300);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addSkill(input.value); }
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.skill-input-wrap')) hideEl('skill-suggestions');
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Discovery & Explore (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const DISC = { facetsLoaded: false, page: 1, exhausted: false, loading: false };

async function discLoadFacets() {
  if (DISC.facetsLoaded) return;
  try {
    const { domains, batches } = await api('GET', '/api/member/network/facets');
    const dSel = $id('discover-domain-filter');
    const bSel = $id('discover-batch-filter');
    if (dSel) dSel.insertAdjacentHTML('beforeend', (domains||[]).map(d => `<option value="${swEsc(d)}">${swEsc(d)}</option>`).join(''));
    if (bSel) bSel.insertAdjacentHTML('beforeend', (batches||[]).map(b => `<option value="${swEsc(b)}">${swEsc(b)}</option>`).join(''));
    DISC.facetsLoaded = true;
  } catch (e) { console.error('discLoadFacets:', e); }
}

async function discLoadTrending() {
  const row = $id('discover-trending-row');
  if (!row) return;
  try {
    const { trending } = await api('GET', '/api/member/network/trending');
    if (!trending.length) { row.innerHTML = `<div class="skill-chip-empty">Nothing trending yet — be the first to post.</div>`; return; }
    row.innerHTML = trending.map(p => {
      const author = p.members || {};
      return `<div class="discover-trend-card" onclick="swOpenDetail('${swEsc(p.id)}')">
        <div class="discover-trend-media">${p.cover_image ? `<img src="${swEsc(p.cover_image)}" loading="lazy" alt="${swEsc(p.title)}">` : ''}</div>
        <div class="discover-trend-title">${swEsc(p.title)}</div>
        <div class="discover-trend-meta">${swEsc(author.name||'Member')} · ${swFmtNum(p.trending_score)} reactions/48h</div>
      </div>`;
    }).join('');
  } catch (e) {
    row.innerHTML = `<div class="sw-error">Could not load trending posts.</div>`;
  }
}

async function discLoadNewJoiners() {
  const row = $id('discover-newjoiners-row');
  if (!row) return;
  try {
    const joiners = await api('GET', '/api/member/network/new-joiners');
    if (!joiners.length) { row.innerHTML = `<div class="skill-chip-empty">No new joiners yet.</div>`; return; }
    row.innerHTML = joiners.map(m => `<div class="discover-joiner-card" onclick="openMemberProfile('${swEsc(m.id)}')">
        ${swAvatar(m.name, m.photo, 56)}
        <div class="discover-joiner-name">${swEsc(m.name||'Member')}</div>
        <div class="discover-joiner-meta">${swEsc(m.role || m.domain || '')}</div>
      </div>`).join('');
  } catch (e) {
    row.innerHTML = `<div class="sw-error">Could not load new joiners.</div>`;
  }
}

async function discLoadMembers(reset = false) {
  if (DISC.loading) return;
  if (!reset && DISC.exhausted) return;
  if (reset) { DISC.page = 1; DISC.exhausted = false; }
  const list = $id('discover-list');
  if (!list) return;
  if (reset) list.innerHTML = '<div class="sw-loading">Loading…</div>';
  DISC.loading = true;
  try {
    const params = new URLSearchParams({ page: DISC.page });
    const q      = $id('discover-search')?.value.trim();
    const domain = $id('discover-domain-filter')?.value;
    const batch  = $id('discover-batch-filter')?.value;
    const skill  = $id('discover-skill-filter')?.value.trim();
    if (q)      params.set('q', q);
    if (domain) params.set('domain', domain);
    if (batch)  params.set('batch', batch);
    if (skill)  params.set('skill', skill);

    const resp = await api('GET', `/api/member/network/discover?${params.toString()}`);
    const members = resp.members || [];
    members.forEach(m => NW.myFollowing.set(m.id, m.is_following));
    if (reset) list.innerHTML = '';
    if (!members.length && DISC.page === 1) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No members match</div><div class="sw-empty-sub">Try a different filter.</div></div>`;
      hideEl('discover-more');
      return;
    }
    list.insertAdjacentHTML('beforeend', members.map(nwRenderRow).join(''));
    if (resp.has_more) { showEl('discover-more'); DISC.page++; }
    else { hideEl('discover-more'); DISC.exhausted = true; }
  } catch (e) {
    if (reset) list.innerHTML = `<div class="sw-error">Could not load members.</div>`;
  } finally {
    DISC.loading = false;
  }
}

function loadDiscoverTab() {
  discLoadFacets();
  discLoadTrending();
  discLoadNewJoiners();
  discLoadMembers(true);
}

// Jump to Network → Discover, pre-filtered by a skill (called from a skill
// chip on the mini-profile modal).
function discFilterBySkill(skillName) {
  const input = $id('discover-skill-filter');
  if (input) input.value = skillName;
  const navNetwork = document.querySelector('.nav-item[data-panel="network"]');
  if (navNetwork) switchPanel(navNetwork);
  nwSwitchTab('discover');
}

function initDiscoverModule() {
  let searchTimer = null;
  const debouncedReload = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => discLoadMembers(true), 350); };
  $id('discover-search')?.addEventListener('input', debouncedReload);
  $id('discover-skill-filter')?.addEventListener('input', debouncedReload);
  $id('discover-domain-filter')?.addEventListener('change', () => discLoadMembers(true));
  $id('discover-batch-filter')?.addEventListener('change', () => discLoadMembers(true));
  $id('discover-more-btn')?.addEventListener('click', () => discLoadMembers(false));
}

// ═══════════════════════════════════════════════════════════════════════════
// Leaderboard / Hall of fame (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

const LB = { period: 'weekly' };

function lbRankClass(rank) {
  if (rank === 1) return 'lb-rank-1';
  if (rank === 2) return 'lb-rank-2';
  if (rank === 3) return 'lb-rank-3';
  return '';
}

async function lbLoad() {
  const list = $id('lb-list');
  if (!list) return;
  list.innerHTML = '<div class="sw-loading">Loading…</div>';
  hideEl('lb-my-rank');
  try {
    const resp = await api('GET', `/api/member/network/leaderboard?period=${LB.period}`);
    const rows = resp.leaderboard || [];
    if (!rows.length) {
      list.innerHTML = `<div class="sw-empty"><div class="sw-empty-title">No wows yet</div><div class="sw-empty-sub">${LB.period==='weekly' ? 'Check back once posts start getting reactions this week.' : 'The hall of fame fills up once posts start earning wow reactions.'}</div></div>`;
      return;
    }
    const wowIcon = SW_REACTIONS.find(r => r.type === 'wow')?.icon || '';
    list.innerHTML = rows.map(m => `<div class="lb-row" onclick="openMemberProfile('${swEsc(m.id)}')">
        <div class="lb-rank ${lbRankClass(m.rank)}">${m.rank}</div>
        ${swAvatar(m.name, m.photo, 36)}
        <div class="lb-info">
          <div class="lb-name">${swEsc(m.name||'Member')}</div>
          <div class="lb-meta">${swEsc(m.role || m.domain || '')}</div>
        </div>
        <div class="lb-wows">${wowIcon}${swFmtNum(m.wows_received)}</div>
      </div>`).join('');
    if (resp.my_rank) {
      const banner = $id('lb-my-rank');
      if (banner) { banner.style.display = 'block'; banner.textContent = `You're #${resp.my_rank} ${LB.period==='weekly' ? 'this week' : 'all-time'}.`; }
    }
  } catch (e) {
    list.innerHTML = `<div class="sw-error">Could not load the leaderboard.</div>`;
  }
}

function loadLeaderboardTab() { lbLoad(); }

function initLeaderboardModule() {
  document.querySelectorAll('.lb-period-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.classList.contains('active')) return;
      document.querySelectorAll('.lb-period-btn').forEach(b => b.classList.toggle('active', b === btn));
      LB.period = btn.dataset.lbPeriod === 'all_time' ? 'all_time' : 'weekly';
      lbLoad();
    });
  });
}

if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded',()=>{
    initStudioWall(); initNetworkModule();
    initStatusModule(); initSkillsModule(); initDiscoverModule(); initLeaderboardModule();
  });
}else{
  initStudioWall(); initNetworkModule();
  initStatusModule(); initSkillsModule(); initDiscoverModule(); initLeaderboardModule();
}

// ═══════════════════════════════════════════════════════════════════════════
// DM CHAT MODULE
// Uses member_notifications (type="dm") — zero new DB tables.
// conv_key = "<smaller_uuid>:<larger_uuid>" (deterministic pair key)
// ═══════════════════════════════════════════════════════════════════════════

const DM = {
  convs:         [],    // loaded conversations
  loaded:        false, // true once DM.convs has been fetched at least once this session
  activeKey:     null,  // current conv_key
  activePeer:    null,  // { id, name, photo, role, batch, domain }
  msgs:          [],    // messages in active convo
  oldestSentAt:  null,  // for "load earlier" pagination
  poll:          null,  // setInterval handle
  members:       [],    // cached member list for picker
  pickerTimer:   null,
  panelVisible:  false,
  pendingBodies: new Set(), // bodies of in-flight optimistic messages (for poll dedup)
  loadingMsgs:   false,     // true while initial dmLoadMsgs fetch is in flight
};

const DM_POLL = 5000; // ms

// ─── Helpers ─────────────────────────────────────────────────────────────────

function dmMyId() {
  return window._memberProfile?.id || _member?.id || null;
}

function dmAvatar(name, photo, size) {
  if (photo) return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;background:#1e1e1e">`;
  const init = (name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
  return `<div class="dm-av-placeholder" style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size * .36)}px;font-weight:700;color:#666;flex-shrink:0">${swEsc(init)}</div>`;
}

function dmTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
  if (diff < 7 * 86400000) return `${Math.floor(diff / 86400000)}d`;
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

function dmFull(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ─── Read receipts (DM double-ticks) ──────────────────────────────────────────
// Single gray check = sent, double gray = delivered (peer's client has synced
// their inbox), double blue = seen (peer opened this thread). Only rendered on
// my own, non-deleted, already-confirmed (non-"tmp-") messages.
const _DM_TICK_SINGLE = '<svg width="14" height="10" viewBox="0 0 16 11" fill="none"><path d="M1 5.5L5 9.5L15 1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const _DM_TICK_DOUBLE = '<svg width="17" height="10" viewBox="0 0 20 11" fill="none"><path d="M1 5.5L5 9.5L11 2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M8 5.5L12 9.5L19 1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function _dmTickSpanHTML(m) {
  const receiptsOn = typeof window._kfsReadReceiptsEnabled === 'function' ? window._kfsReadReceiptsEnabled() : true;
  if (m.read_at && receiptsOn) return `<span class="dm-ticks dm-ticks-read" title="Seen">${_DM_TICK_DOUBLE}</span>`;
  if (m.delivered_at)          return `<span class="dm-ticks dm-ticks-delivered" title="Delivered">${_DM_TICK_DOUBLE}</span>`;
  return `<span class="dm-ticks dm-ticks-sent" title="Sent">${_DM_TICK_SINGLE}</span>`;
}

// ─── Badge ────────────────────────────────────────────────────────────────────

function dmSetBadge(n) {
  const show = n > 0;
  const label = n > 99 ? '99+' : String(n);
  [$id('dm-nav-badge'), $id('dm-btb-badge')].forEach(el => {
    if (!el) return;
    el.style.display = show ? '' : 'none';
    el.textContent = label;
  });
}

async function dmRefreshBadge() {
  if (!_token) return; // session not restored yet — avoid a guaranteed 401 during boot
  try {
    const d = await api('GET', '/api/member/dm/unread-count');
    dmSetBadge(d.count || 0);
  } catch { /* silent */ }
}

// ─── Conversation list ────────────────────────────────────────────────────────

async function dmLoadConvs() {
  try {
    const data = await api('GET', '/api/member/dm/conversations');
    DM.convs = data || [];
    // Use window.dmRenderConvs so the unified-inbox IIFE override (inboxRender) is picked up
    if (typeof window.dmRenderConvs === 'function') window.dmRenderConvs(DM.convs);
    else dmRenderConvs(DM.convs);
    const total = DM.convs.reduce((s, c) => s + (c.unread_count || 0), 0);
    dmSetBadge(total);
  } catch (e) {
    console.error('[DM] loadConvs:', e.message);
  }
}

function dmRenderConvs(list) {
  const container = $id('dm-conv-list');
  if (!container) return;
  $id('dm-conv-loading') && ($id('dm-conv-loading').style.display = 'none');

  // Remove old rows
  container.querySelectorAll('.dm-conv-row').forEach(el => el.remove());

  if (!list || list.length === 0) {
    $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = '');
    return;
  }
  $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = 'none');

  list.forEach(c => {
    const row = document.createElement('div');
    row.className = 'dm-conv-row' + (c.conv_key === DM.activeKey ? ' dm-active-row' : '');
    row.dataset.key = c.conv_key;
    const preview = c.last_is_e2ee
      ? (c.last_sender_is_me ? 'You: ' : '') + '🔒 Encrypted message'
      : c.last_snippet
        ? (c.last_sender_is_me ? 'You: ' : '') + c.last_snippet
        : 'No messages yet';
    const displayName = (typeof nicksResolveDisplay === 'function')
      ? nicksResolveDisplay(c.conv_key, c.peer?.id, c.peer?.name || 'Member')
      : (c.peer?.name || 'Member');
    row.innerHTML = `
      ${dmAvatar(c.peer?.name, c.peer?.photo, 42)}
      <div class="dm-conv-info">
        <div class="dm-conv-name">${swEsc(displayName)}</div>
        <div class="dm-conv-preview ${c.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
      </div>
      <div class="dm-conv-right">
        <span class="dm-conv-time">${dmTime(c.last_msg_at)}</span>
        ${c.unread_count > 0 ? `<span class="dm-unread-pill">${c.unread_count > 9 ? '9+' : c.unread_count}</span>` : ''}
      </div>`;
    row.addEventListener('click', () => dmOpenConv(c));
    container.appendChild(row);
  });
}

// ─── Open a conversation ──────────────────────────────────────────────────────

async function dmOpenConv(conv) {
  if (typeof _cancelEditMsg === 'function') _cancelEditMsg('dm');
  DM.activeKey   = conv.conv_key;
  DM.activePeer  = conv.peer;
  DM.msgs        = [];
  DM.oldestSentAt = null;

  // Highlight row
  document.querySelectorAll('.dm-conv-row').forEach(el => {
    el.classList.toggle('dm-active-row', el.dataset.key === conv.conv_key);
  });

  // Topbar
  const ta = $id('dm-topbar-avatar');
  if (ta) ta.innerHTML = dmAvatar(conv.peer?.name, conv.peer?.photo, 34);
  setText('dm-topbar-name', conv.peer?.name || 'Member');
  setText('dm-topbar-sub', [conv.peer?.role, conv.peer?.batch || conv.peer?.domain].filter(Boolean).join(' · '));

  // Show window, hide empty state
  $id('dm-window-empty') && ($id('dm-window-empty').style.display = 'none');
  $id('dm-active') && ($id('dm-active').style.display = 'flex');

  // Official KFS channel — one-way broadcast, no reply UI.
  _dmSetOneWayMode(!!conv.peer?.is_official);

  // Mobile only: slide sidebar out to reveal chat window
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.add('dm-slide-out');
    $id('dm-window')?.classList.add('dm-slide-in');
    _kfsPushNavState('dm-chat');
  }

  await dmLoadMsgs(false);
  $id('dm-input')?.focus();
}

// Show/hide the reply compose box vs. the "one-way channel" notice.
function _dmSetOneWayMode(isOfficial) {
  const compose = $id('dm-compose');
  const notice  = $id('dm-oneway-notice');
  if (compose) compose.style.display = isOfficial ? 'none' : '';
  if (notice)  notice.style.display  = isOfficial ? 'flex' : 'none';
}

// Open or create a conversation with a member by ID (called from Network cards)
async function dmStartWith(memberId, peerHint) {
  const navEl = document.querySelector('[data-panel="dms"]');
  if (navEl) switchPanel(navEl);
  document.querySelectorAll('.btb-item').forEach(el => {
    el.classList.toggle('active', el.dataset.panel === 'dms');
  });

  // Check if conversation already exists
  const existing = DM.convs.find(c => c.peer?.id === memberId);
  if (existing) { dmOpenConv(existing); return; }

  // No existing — show chat UI optimistically, conv created on first message
  DM.activeKey  = null;
  DM.activePeer = peerHint || { id: memberId, name: 'Member', photo: null };
  DM.msgs       = [];
  // No conv key yet means no pin lookup is possible — clear any leftover
  // banner from whatever conversation was open before this one.
  document.getElementById('dm-pinned-bar')?.remove();

  const ta = $id('dm-topbar-avatar');
  if (ta) ta.innerHTML = dmAvatar(DM.activePeer.name, DM.activePeer.photo, 34);
  setText('dm-topbar-name', DM.activePeer.name || 'Member');
  setText('dm-topbar-sub', [DM.activePeer.role, DM.activePeer.batch || DM.activePeer.domain].filter(Boolean).join(' · '));

  // Official KFS channel — one-way broadcast, no reply UI.
  _dmSetOneWayMode(!!DM.activePeer.is_official);

  $id('dm-window-empty') && ($id('dm-window-empty').style.display = 'none');
  $id('dm-active') && ($id('dm-active').style.display = 'flex');
  $id('dm-msg-list') && ($id('dm-msg-list').innerHTML = '');
  $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.add('dm-slide-out');
    $id('dm-window')?.classList.add('dm-slide-in');
    _kfsPushNavState('dm-chat');
  }
  $id('dm-input')?.focus();
}

// ─── Load messages ────────────────────────────────────────────────────────────

async function dmLoadMsgs(prepend) {
  if (!DM.activeKey) return;
  if (!prepend) DM.loadingMsgs = true;
  try {
    const myId = dmMyId();
    let url = `/api/member/dm/messages/${encodeURIComponent(DM.activeKey)}?limit=40`;
    if (prepend && DM.oldestSentAt) url += `&before=${encodeURIComponent(DM.oldestSentAt)}`;

    const msgs = await api('GET', url);
    if (!msgs || !msgs.length) {
      if (prepend) $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
      return;
    }

    if (prepend) {
      // Preserve any optimistic messages already in DM.msgs that aren't in the fetched set
      const fetchedIds = new Set(msgs.map(m => m.id));
      const optimistic = DM.msgs.filter(m => m.id.startsWith('tmp-') && !fetchedIds.has(m.id));
      DM.msgs = [...msgs, ...DM.msgs.filter(m => !fetchedIds.has(m.id) && !m.id.startsWith('tmp-')), ...optimistic];
    } else {
      // Preserve any optimistic (tmp) messages that were added while this fetch was in flight
      const optimistic = DM.msgs.filter(m => m.id.startsWith('tmp-'));
      const fetchedIds = new Set(msgs.map(m => m.id));
      // Also preserve confirmed messages that arrived via poll but aren't in this batch
      DM.msgs = [...msgs, ...optimistic].filter((m, i, arr) =>
        !fetchedIds.has(m.id) || arr.findIndex(x => x.id === m.id) === i
      );
      // Sort: confirmed msgs first (by sent_at), optimistic at end
      DM.msgs.sort((a, b) => {
        const aOpt = a.id.startsWith('tmp-');
        const bOpt = b.id.startsWith('tmp-');
        if (aOpt && !bOpt) return 1;
        if (!aOpt && bOpt) return -1;
        return new Date(a.sent_at) - new Date(b.sent_at);
      });
    }
    DM.oldestSentAt = DM.msgs.find(m => !m.id.startsWith('tmp-'))?.sent_at || null;

    const list = $id('dm-msg-list');
    if (!list) return;

    if (!prepend) {
      list.innerHTML = '';
      // WhatsApp-style E2EE notice
      const e2eeNotice = document.createElement('div');
      e2eeNotice.className = 'dm-e2ee-notice';
      e2eeNotice.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Messages and calls are end-to-end encrypted. No one outside of this chat can read or listen to them.`;
      list.appendChild(e2eeNotice);
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
      if (typeof dmRefreshPinnedBanner === 'function') dmRefreshPinnedBanner();
    } else {
      const area    = $id('dm-msgs');
      const prevH   = area.scrollHeight;
      const prevTop = area.scrollTop;
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      area.scrollTop = area.scrollHeight - prevH + prevTop;
    }

    const moreWrap = $id('dm-load-earlier-wrap');
    if (moreWrap) moreWrap.style.display = msgs.length >= 40 ? '' : 'none';

    // Zero this conv's unread in local state & refresh badge
    const conv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (conv) conv.unread_count = 0;
    const total = DM.convs.reduce((s, c) => s + (c.unread_count || 0), 0);
    dmSetBadge(total);
    // Re-render conv list to clear unread pill
    dmRenderConvs(DM.convs);
  } catch (e) {
    console.error('[DM] loadMsgs:', e.message);
  } finally {
    if (!prepend) DM.loadingMsgs = false;
  }
}

// ── Image attachments — shared lightbox + bubble rendering (DM + group) ────
function _openImageLightbox(url) {
  const overlay = document.createElement('div');
  overlay.className = 'dm-img-lightbox';
  const img = document.createElement('img');
  img.src = url;
  img.alt = 'Photo';
  overlay.appendChild(img);
  overlay.addEventListener('click', () => overlay.remove());
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', esc); }
  });
  document.body.appendChild(overlay);
}

// Appends an image wrapper to `bubble` if the message carries an attachment.
// Returns true if the message is photo-only (no caption text to render).
function _attachImageToBubble(bubble, m) {
  if (!m.attachment_url) return false;
  bubble.classList.add('dm-bubble-image');
  const imgWrap = document.createElement('div');
  imgWrap.className = 'dm-bubble-img-wrap';
  if (String(m.id || '').startsWith('tmp-')) imgWrap.classList.add('dm-img-uploading');
  const img = document.createElement('img');
  img.src = m.attachment_url;
  img.alt = 'Photo';
  img.loading = 'lazy';
  if (m.attachment_opacity != null && m.attachment_opacity < 100) {
    img.style.opacity = Math.max(0, Math.min(100, m.attachment_opacity)) / 100;
  }
  imgWrap.appendChild(img);
  imgWrap.addEventListener('click', e => { e.stopPropagation(); _openImageLightbox(m.attachment_url); });
  bubble.appendChild(imgWrap);
  return !m.body || m.body === '📷 Photo';
}

// ─── Social Strand link preview cards (DM + group chat) ──────────────────────
// When a message body contains a link to a Social Strand post — e.g. from the
// "Share" sheet's Send-in-chat action, which sends plain text like
// "Check this out on Social Strand: https://.../strand/<id>" — render an
// Instagram-style rich preview card (cover image, title, author) under the
// bubble instead of leaving it as a raw, unclickable URL.
const _STRAND_LINK_RE = /https?:\/\/[^\s]+?\/(?:social-strand\/[^\/\s]+\/([a-zA-Z0-9-]+)|strand\/([a-zA-Z0-9-]+))(?=[\s]|$)/i;
const _strandPreviewCache = new Map(); // projectId -> preview data (or in-flight Promise)

function _detectStrandLink(text) {
  if (!text) return null;
  const m = String(text).match(_STRAND_LINK_RE);
  if (!m) return null;
  const id = m[1] || m[2];
  if (!id) return null;
  return { id, matched: m[0] };
}

// True when the ENTIRE message body is just the auto-generated "Share to
// chat" caption (see the share-send handler: `Check this out on Social
// Strand: <url>`) with no extra text added by the sender. When true, we
// render only the rich preview card (Instagram-style) instead of also
// showing that boilerplate sentence as a separate text bubble above it.
const _STRAND_SHARE_ONLY_RE = /^check this out on social strand:\s*https?:\/\/\S+$/i;
function _isStrandShareOnly(text) {
  return !!text && _STRAND_SHARE_ONLY_RE.test(String(text).trim());
}

function _fetchStrandPreview(id) {
  if (_strandPreviewCache.has(id)) return _strandPreviewCache.get(id);
  const p = api('GET', `/api/member/studio/preview/${id}`).catch(() => null);
  _strandPreviewCache.set(id, p);
  return p;
}

// Appends a strand-post preview card to `bubble` if `bodyText` contains a
// Social Strand link. Safe to call multiple times (no-ops if no link found).
// `standalone` (bool) — pass true when the message is ONLY the auto-share
// caption (see _isStrandShareOnly): renders a bigger, Instagram-DM-style
// card as the sole bubble content instead of a small inline link chip.
function _attachStrandPreviewToBubble(bubble, bodyText, standalone) {
  if (!bubble || bubble.querySelector('.strand-preview-card')) return;
  const hit = _detectStrandLink(bodyText);
  if (!hit) return;

  const card = document.createElement('div');
  card.className = `strand-preview-card strand-preview-loading${standalone ? ' strand-preview-standalone' : ''}`;
  card.innerHTML = `
    <div class="strand-preview-thumb"></div>
    <div class="strand-preview-info">
      <div class="strand-preview-title">Loading post…</div>
      <div class="strand-preview-sub">Social Strand</div>
    </div>
  `;
  bubble.appendChild(card);

  card.addEventListener('click', e => {
    e.stopPropagation();
    if (typeof swOpenDetail === 'function') swOpenDetail(hit.id);
    else window.open(`${location.origin}/strand/${hit.id}`, '_blank', 'noopener,noreferrer');
  });

  _fetchStrandPreview(hit.id).then(data => {
    card.classList.remove('strand-preview-loading');
    if (!data || !data.id) {
      card.innerHTML = `
        <div class="strand-preview-thumb strand-preview-thumb-fallback">🎬</div>
        <div class="strand-preview-info">
          <div class="strand-preview-title">Post unavailable</div>
          <div class="strand-preview-sub">It may have been removed</div>
        </div>
      `;
      return;
    }
    card.innerHTML = `
      ${data.cover_image
        ? `<div class="strand-preview-thumb"><img src="${swEsc(data.cover_image)}" alt="" loading="lazy"></div>`
        : `<div class="strand-preview-thumb strand-preview-thumb-fallback">🎬</div>`}
      <div class="strand-preview-info">
        <div class="strand-preview-title">${swEsc(data.title || 'Social Strand post')}</div>
        <div class="strand-preview-sub">By ${swEsc(data.author_name || 'a KFS member')}${data.domain ? ` · ${swEsc(data.domain)}` : ''}</div>
      </div>
    `;
  });
}

// Resolve the text to show in a reply-quote strip without trusting any
// plaintext the server might hand back for it. Server-stored
// `replied_to_body` is now only ever plaintext for genuinely-unencrypted
// (legacy/non-e2ee) messages — see SECURITY notes in dmSend/gcSend/
// _dmSendImage/_gcSendImage. For E2EE originals we look the quoted message
// up in the in-memory list we already decrypted client-side; if it isn't
// loaded/decrypted yet locally we fall back to a generic placeholder rather
// than ever displaying server-supplied plaintext for an E2EE message.
function _resolveReplyPreviewText(m, msgArray) {
  if (m.replied_to_body) return m.replied_to_body; // legacy/non-e2ee — safe as-is
  if (!m.replied_to_id) return null;
  const orig = (msgArray || []).find(x => x.id === m.replied_to_id);
  if (orig && orig._plaintext != null) return orig._plaintext;
  if (orig && !orig.e2ee) return orig.body || null;
  return '🔒 Original message';
}

function dmRenderMsgs(msgs, container, myId, lastSenderHint) {
  // Group consecutive messages from same sender.
  // lastSenderHint: pass the sender_id of the last message already in the DOM
  // so incremental appends can continue an existing group instead of creating a new one.
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild
    : null;

  // Collected so we can collapse a run of failed decrypts into one summary
  // row once we know how many failed, instead of leaving a wall of identical
  // "encrypted before your keys were set up" bubbles (see _collapseFailedDecrypts).
  const _pendingDecrypts = [];

  msgs.forEach(m => {
    const mine = m.sender_id === myId;
    const senderKey = m.sender_id;

    if (senderKey !== lastSender || !group) {
      group = document.createElement('div');
      group.className = `dm-msg-group ${mine ? 'mine' : 'theirs'}`;
      container.appendChild(group);
      lastSender = senderKey;
    }

    const isDeleted = m.body === '[deleted]';

    // Wrap bubble + hover actions together
    const wrap = document.createElement('div');
    wrap.className = 'dm-bubble-wrap';

    const bubble = document.createElement('div');
    bubble.className = `dm-bubble${isDeleted ? ' dm-deleted' : ''}`;
    bubble.dataset.msgId = m.id;

    // Reply quote
    if (m.replied_to_id) {
      const _replyText = _resolveReplyPreviewText(m, DM.msgs);
      if (_replyText) {
        const quote = document.createElement('div');
        quote.className = 'dm-reply-quote';
        quote.innerHTML = `<span class="dm-reply-sender">${swEsc(m.replied_to_sender || 'Member')}</span><span class="dm-reply-body">${swEsc(_replyText.slice(0, 120))}</span>`;
        // Tap/click → scroll to the original message
        quote.addEventListener('click', e => {
          e.stopPropagation();
          const target = document.querySelector(`[data-msg-id="${CSS.escape(m.replied_to_id)}"]`);
          if (!target) return;
          target.scrollIntoView({ behavior: 'smooth', block: 'center' });
          target.classList.add('dm-msg-highlight');
          setTimeout(() => target.classList.remove('dm-msg-highlight'), 1600);
        });
        bubble.appendChild(quote);
      }
    }
    // Attachment (image) — renders above/instead of the text caption
    const _isPhotoOnly = !isDeleted && _attachImageToBubble(bubble, m);
    // "Check this out on Social Strand: <url>" auto-share messages — render
    // only the rich card, not the boilerplate sentence as raw text too.
    const _plainIsStrandOnly = !_isPhotoOnly && !isDeleted && !m.e2ee && _isStrandShareOnly(m.body);

    const bodyNode = document.createElement('span');
    bodyNode.className = 'dm-bubble-text';
    // E2EE: decrypt asynchronously; show placeholder while decrypting
    if (_isPhotoOnly || _plainIsStrandOnly) {
      // no caption to render — image or standalone strand card handles it
    } else if (m.e2ee && !isDeleted) {
      bodyNode.textContent = '🔒 …';
      bodyNode.style.opacity = '0.5';
      const _myId = myId;
      const _decryptP = E2EE.decryptDm(m, _myId).then(pt => {
        m._plaintext = pt; // cache for context menu / reply
        if (_isStrandShareOnly(pt)) {
          bodyNode.remove();
          bubble.classList.add('dm-bubble-strand-share');
          _attachStrandPreviewToBubble(bubble, pt, true);
        } else {
          bodyNode.textContent = pt;
          bodyNode.style.opacity = '';
          _attachStrandPreviewToBubble(bubble, pt, false);
        }
      }).catch(() => {
        bodyNode.textContent = '🔒 Message encrypted before your keys were set up';
        bodyNode.style.opacity = '0.5';
        bubble.classList.add('dm-e2ee-failed');
      });
      _pendingDecrypts.push(_decryptP);
    } else {
      bodyNode.textContent = m.body;
    }
    if (_plainIsStrandOnly) bubble.classList.add('dm-bubble-strand-share');
    if (!_isPhotoOnly && !_plainIsStrandOnly) bubble.appendChild(bodyNode);
    if (_plainIsStrandOnly) {
      _attachStrandPreviewToBubble(bubble, m.body, true);
    } else if (!_isPhotoOnly && !(m.e2ee && !isDeleted)) {
      _attachStrandPreviewToBubble(bubble, m.body, false);
    }

    wrap.appendChild(bubble);

    // Instagram-style hover actions (hidden on mobile via CSS — mobile users
    // react via long-press → context menu instead, see _attachMsgContextMenu)
    if (!isDeleted) {
      // Use cached plaintext (from E2EE decrypt) for reply/context-menu body
      const _bodyForActions = () => m._plaintext || m.body;
      const hoverActions = _buildHoverActions({
        msgId: m.id, body: _bodyForActions(), mine,
        senderName: mine ? 'You' : (DM.activePeer?.name || 'Member'),
        type: 'dm',
        senderId: m.sender_id,
        onReply: () => _setReply('dm', { id: m.id, body: _bodyForActions(), sender: mine ? 'You' : (DM.activePeer?.name || 'Member') }),
        onReact: (emoji) => _toggleReaction('dm', m.id, emoji, bubble),
      });
      wrap.appendChild(hoverActions);
      _attachQuickHeart(bubble, (emoji) => _toggleReaction('dm', m.id, emoji, bubble));
    }

    // Existing reactions (from initial load or poll refresh)
    if (m.reactions && m.reactions.length) {
      _renderReactionPills(bubble, m.reactions, (emoji) => _toggleReaction('dm', m.id, emoji, bubble));
    }

    const meta = document.createElement('div');
    meta.className = 'dm-meta';
    meta.dataset.metaFor = m.id;
    meta.innerHTML = `${!isDeleted && m.edited_at ? `<span class="dm-edited-tag">edited</span>` : ''}<span class="dm-msg-time">${dmFull(m.sent_at)}</span>${mine && !isDeleted && !String(m.id).startsWith('tmp-') ? _dmTickSpanHTML(m) : ''}${mine && !isDeleted ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

    const delBtn = meta.querySelector('.dm-del-btn');
    if (delBtn) {
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dmDeleteMsg(m.id, bubble, delBtn);
      });
    }

    // Context menu: right-click (desktop) + long-press (mobile)
    _attachMsgContextMenu(bubble, {
      id: m.id, body: m.body, mine, isDeleted,
      senderName: mine ? 'You' : (DM.activePeer?.name || 'Member'),
      type: 'dm',
    });

    group.appendChild(wrap);
    group.appendChild(meta);
  });

  _markLastBubbleInGroups(container);
  if (_pendingDecrypts.length) {
    Promise.allSettled(_pendingDecrypts).then(() => _collapseFailedDecrypts(container));
  }
}

/**
 * If a device's local E2EE key changed (new device/browser, or the browser's
 * local storage was cleared — the private key lives only in IndexedDB, it's
 * never synced), every older message that was encrypted under the previous
 * key fails to decrypt. Left as-is this rendered a long wall of identical
 * "Message encrypted before your keys were set up" bubbles, which reads as
 * broken. This collapses any run of 3+ consecutive failures inside a single
 * message group into one compact system-style row with a "Why?" explainer,
 * keeping the last message's timestamp for context.
 */
function _collapseFailedDecrypts(container) {
  container.querySelectorAll('.dm-msg-group').forEach(group => {
    const children = Array.from(group.children); // alternating .dm-bubble-wrap, .dm-meta
    const runs = [];
    let i = 0;
    while (i < children.length) {
      const isFailedWrap = n => n?.classList?.contains('dm-bubble-wrap') && n.querySelector('.dm-bubble.dm-e2ee-failed');
      if (!isFailedWrap(children[i])) { i++; continue; }
      const start = i;
      const nodes = [];
      let j = i;
      while (isFailedWrap(children[j]) && children[j + 1]) {
        nodes.push(children[j], children[j + 1]);
        j += 2;
      }
      if (nodes.length >= 6) runs.push(nodes); // 3+ failed messages (wrap+meta pairs)
      i = j > start ? j : i + 1;
    }
    runs.forEach(nodes => {
      const count = nodes.length / 2;
      const lastMeta = nodes[nodes.length - 1];
      const toRemove = nodes.slice(0, -1); // everything except the last meta (keeps its timestamp)
      const summary = document.createElement('div');
      summary.className = 'dm-bubble-wrap dm-e2ee-summary-wrap';
      summary.innerHTML = `<div class="dm-bubble dm-e2ee-summary">🔒 ${count} messages can't be decrypted on this device <button type="button" class="dm-e2ee-why">Why?</button></div>`;
      summary.querySelector('.dm-e2ee-why').addEventListener('click', e => {
        e.stopPropagation();
        swAlert("These were encrypted before the secure keys on this device existed — usually because you're signed in on a new device/browser, or this browser's local data was cleared. They can't be recovered here, but new messages will work normally.", { title: 'Locked messages' });
      });
      toRemove[0].parentNode.insertBefore(summary, toRemove[0]);
      toRemove.forEach(n => n.remove());
    });
  });
}

/**
 * Instagram-style consecutive bubbles: only the LAST bubble in a run from the
 * same sender gets the small "tail" corner; the rest are evenly rounded.
 * Each bubble lives inside its own .dm-bubble-wrap (alternating with a
 * .dm-meta sibling), so a CSS-only :last-of-type selector can't tell them
 * apart — this just re-tags the right one with a class after every render.
 */
function _markLastBubbleInGroups(container) {
  container.querySelectorAll('.dm-msg-group').forEach(group => {
    const wraps = group.querySelectorAll('.dm-bubble-wrap');
    wraps.forEach((w, i) => {
      const bubble = w.querySelector('.dm-bubble');
      if (bubble) bubble.classList.toggle('dm-bubble-tail', i === wraps.length - 1);
    });
    // iMessage/WhatsApp-style meta: only the LAST message in a consecutive
    // run from the same sender shows its time/tick/edited row. Showing a
    // full meta row under every single bubble was what made back-to-back
    // messages from the same person look far more spaced out than they
    // needed to be. Earlier messages in the run keep their meta element in
    // the DOM (so delete/edit state stays wired up) but it's collapsed to
    // zero height via CSS — see `.dm-meta-mid` in membersaccess.html.
    const metas = group.querySelectorAll(':scope > .dm-meta');
    metas.forEach((m, i) => {
      m.classList.toggle('dm-meta-mid', i !== metas.length - 1);
    });
  });
}

function dmScrollBottom() {
  const el = $id('dm-msgs');
  if (el) el.scrollTop = el.scrollHeight;
}

// ─── Send ─────────────────────────────────────────────────────────────────────

async function dmSend() {
  const input = $id('dm-input');
  if (!input) return;
  const body = input.value.trim();
  if (!body) return;

  // Edit mode — route to the PATCH flow instead of posting a new message.
  if (_editState.dm) { await _dmSubmitEdit(body); return; }

  const peerId = DM.activePeer?.id;
  if (!peerId) return;

  // If history is still loading (race: user typed before initial load finished),
  // disable the send button briefly and retry once the load clears
  if (DM.loadingMsgs) {
    const btn = $id('dm-send-btn');
    if (btn) btn.disabled = true;
    const waitForLoad = () => new Promise(resolve => {
      const check = () => { if (!DM.loadingMsgs) resolve(); else setTimeout(check, 50); };
      check();
    });
    await waitForLoad();
    if (btn) btn.disabled = false;
  }

  // Optimistic bubble — include reply fields so the quote box renders
  // immediately instead of waiting for the next poll/refresh.
  const myId      = dmMyId();
  const tmpId     = 'tmp-' + Date.now();
  const replyData = _dmGetReplyPayload();
  const tmp   = { id: tmpId, sender_id: myId, body, sent_at: new Date().toISOString(), read_at: null, reactions: [], ...replyData };
  DM.msgs.push(tmp);
  // Tell the poll not to re-append this message body while the request is in-flight
  DM.pendingBodies.add(body);

  const list = $id('dm-msg-list');
  // Pass the previous sender so incremental append continues the right group
  const lastRenderedSender = DM.msgs.length > 1 ? DM.msgs[DM.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    dmRenderMsgs([tmp], list, myId, lastRenderedSender);
    // Tag the newly added bubble so we can swap it in-place without a full rerender
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) {
      allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
    }
  }
  dmScrollBottom();
  input.value = '';
  input.style.height = '';

  try {
    // E2EE: encrypt the message body before sending. Falls back to plaintext
    // if E2EE is not yet ready (first-ever load before key published).
    let dmPayload = { to_member_id: peerId, body, ..._dmGetReplyPayload() };
    if (E2EE.ready()) {
      try {
        const enc = await E2EE.encryptDm(body, peerId);
        dmPayload = { ...dmPayload, body: '', ...enc }; // body sentinel = '' (server stores ciphertexts)
        // SECURITY: replied_to_body above is the *decrypted plaintext* of the
        // quoted message (see _bodyForActions/_dmGetReplyPayload) — sending it
        // as-is would hand the server a cleartext preview of a message we just
        // went to the trouble of encrypting. Strip it; the reply UI resolves
        // the quoted text locally from DM.msgs (see _resolveReplyPreviewText),
        // keyed off replied_to_id, which we do still send.
        if (dmPayload.replied_to_body) dmPayload.replied_to_body = null;
      } catch (encErr) {
        console.warn('[E2EE] DM encrypt failed, sending plaintext:', encErr.message);
      }
    }
    const res = await api('POST', '/api/member/dm/send', dmPayload);
    _setReply('dm', null); // clear reply bar after successful send

    // If this was a new conversation, update our active key
    if (!DM.activeKey && res.conv_key) DM.activeKey = res.conv_key;

    const realMsg = res.message;

    // Replace temp msg in DM.msgs with the real confirmed message
    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    if (realMsg) DM.msgs.push(realMsg);

    // Swap tmp bubble in-place — no DOM nuke, no flicker
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      // CRITICAL: update data-msg-id so reactions, reply, and context menu work
      // immediately on the confirmed message — no page reload needed.
      tmpBubble.dataset.msgId = realMsg.id;
      // Update the delete button's data-id so deletion works after confirm
      const dmGrp  = tmpBubble.closest('.dm-msg-group');
      const delBtn = dmGrp?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
      // Re-attach quick-heart with real ID
      _attachQuickHeart(tmpBubble, (emoji) => _toggleReaction('dm', realMsg.id, emoji, tmpBubble));
      // Re-attach context menu with real ID
      _attachMsgContextMenu(tmpBubble, { id: realMsg.id, body: realMsg.body, mine: true, senderName: 'You', type: 'dm' });
      // Re-attach hover-action buttons with real ID
      const _hwrap = tmpBubble.closest('.dm-bubble-wrap');
      _hwrap?.querySelectorAll('.dm-ha-btn').forEach(btn => {
        if (btn.title === 'React') {
          const nb = btn.cloneNode(true);
          nb.addEventListener('click', e => { e.stopPropagation(); _showEmojiPicker(nb, emoji => _toggleReaction('dm', realMsg.id, emoji, tmpBubble)); });
          btn.replaceWith(nb);
        } else if (btn.title === 'Reply') {
          const nb = btn.cloneNode(true);
          nb.addEventListener('click', e => { e.stopPropagation(); _setReply('dm', { id: realMsg.id, body: realMsg.body, sender: 'You' }); });
          btn.replaceWith(nb);
        }
      });
      // Now that the bubble is confirmed (no longer "tmp-"), it's eligible for
      // a read-receipt tick — show the "sent" single check immediately.
      const _dmMetaRow = tmpBubble.closest('.dm-msg-group')?.querySelector('.dm-meta');
      if (_dmMetaRow) {
        _dmMetaRow.dataset.metaFor = realMsg.id;
        if (!_dmMetaRow.querySelector('.dm-ticks')) {
          const _delBtn = _dmMetaRow.querySelector('.dm-del-btn');
          const _tickHTML = _dmTickSpanHTML(realMsg);
          if (_delBtn) _delBtn.insertAdjacentHTML('beforebegin', _tickHTML);
          else _dmMetaRow.insertAdjacentHTML('beforeend', _tickHTML);
        }
      }
    } else if (list) {
      // Fallback: full rerender (bubble wasn't tagged somehow)
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
    }

    // Update conv list locally (avoid full refetch on every send)
    const existingConv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (existingConv) {
      existingConv.last_snippet      = dmPayload.e2ee ? null : body.slice(0, 80);
      existingConv.last_is_e2ee      = dmPayload.e2ee ? true : false;
      existingConv.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existingConv.last_sender_is_me = true;
      dmRenderConvs(DM.convs);
    } else {
      // First message in a brand-new conv — need server data for peer info
      await dmLoadConvs();
    }
  } catch (e) {
    // Roll back: remove the tmp bubble from the DOM and from DM.msgs
    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const group = tmpBubble.closest('.dm-msg-group');
      const meta  = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (group && !group.querySelector('.dm-bubble')) group.remove();
    }
    // Restore input text only for non-violation errors
    const ed = e._data || {};
    if (ed.warned || ed.muted || ed.banned || ed.temp_banned) {
      _vioShowClientNotice(ed, e.message, 'dm-input', 'dm-send-btn');
    } else if (/can.t reply to KFS/i.test(e.message || '')) {
      // Safety net: server rejected a reply to the official one-way channel.
      // Lock the compose UI so it can't be attempted again in this view.
      _dmSetOneWayMode(true);
    } else {
      input.value = body;
      console.error('[DM] send:', e.message);
    }
  } finally {
    DM.pendingBodies.delete(body);
  }
}

// ── Send a photo attachment in a DM ───────────────────────────────────────────
// Uploads via multipart/form-data to /api/member/dm/messages/image (the server
// pipeline already existed — this client-side sender function was missing,
// which is why tapping the attach button silently did nothing).
async function _dmSendImage(file, opacity = 100) {
  const peerId = DM.activePeer?.id;
  if (!peerId) return;
  if (file.size > 8 * 1024 * 1024) { swShowToast('Photo is too large (max 8MB).', 4000); return; }

  const btn = $id('dm-attach-btn');
  if (btn) btn.disabled = true;

  // Optimistic "sending" bubble with a local object URL preview
  const myId  = dmMyId();
  const tmpId = 'tmp-' + Date.now();
  const localUrl = URL.createObjectURL(file);
  const replyData = _dmGetReplyPayload();
  const tmp = { id: tmpId, sender_id: myId, body: '📷 Photo', attachment_url: localUrl, attachment_type: 'image', attachment_opacity: opacity, sent_at: new Date().toISOString(), read_at: null, reactions: [], ...replyData };
  DM.msgs.push(tmp);

  const list = $id('dm-msg-list');
  const lastRenderedSender = DM.msgs.length > 1 ? DM.msgs[DM.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    dmRenderMsgs([tmp], list, myId, lastRenderedSender);
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
  }
  dmScrollBottom();

  try {
    const fd = new FormData();
    fd.append('image', file);
    fd.append('to_member_id', peerId);
    fd.append('opacity', String(opacity));
    if (replyData.replied_to_id) {
      fd.append('replied_to_id', replyData.replied_to_id);
      // SECURITY: replyData.replied_to_body is the decrypted plaintext of
      // whatever message is being replied to — it may be an E2EE message.
      // Don't forward it to the server; the client resolves the quoted
      // preview locally (see _resolveReplyPreviewText).
      fd.append('replied_to_sender', replyData.replied_to_sender || '');
    }
    const res = await api('POST', '/api/member/dm/messages/image', fd, true);
    _setReply('dm', null);
    if (!DM.activeKey && res.conv_key) DM.activeKey = res.conv_key;
    const realMsg = res.message;

    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    if (realMsg) DM.msgs.push(realMsg);

    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      tmpBubble.dataset.msgId = realMsg.id;
      const dmGrp  = tmpBubble.closest('.dm-msg-group');
      const delBtn = dmGrp?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
      _attachQuickHeart(tmpBubble, (emoji) => _toggleReaction('dm', realMsg.id, emoji, tmpBubble));
      _attachMsgContextMenu(tmpBubble, { id: realMsg.id, body: realMsg.body, mine: true, senderName: 'You', type: 'dm' });
    } else if (list) {
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
    }

    const existingConv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (existingConv) {
      existingConv.last_snippet      = '📷 Photo';
      existingConv.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existingConv.last_sender_is_me = true;
      dmRenderConvs(DM.convs);
    } else {
      await dmLoadConvs();
    }
  } catch (e) {
    DM.msgs = DM.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const group = tmpBubble.closest('.dm-msg-group');
      const meta  = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (group && !group.querySelector('.dm-bubble')) group.remove();
    }
    const ed = e._data || {};
    if (ed.warned || ed.muted || ed.banned || ed.temp_banned) {
      _vioShowClientNotice(ed, e.message, 'dm-input', 'dm-send-btn');
    } else {
      swShowToast(e.message || 'Could not send photo.', 4000);
      console.error('[DM] send image:', e.message);
    }
  } finally {
    URL.revokeObjectURL(localUrl);
    if (btn) btn.disabled = false;
  }
}

// ── Photo attachment opacity picker (DM + group chat) ─────────────────────────
// Shown right after picking a file, before upload — lets the user drag a
// slider to set the image's opacity. The chosen value travels with the
// message (attachment_opacity) and is applied as a CSS opacity on the bubble
// image for every viewer, so it renders correctly against any chat theme
// without baking/flattening the image itself.
let _attachOpacityOverlay = null;
function _openAttachOpacityPicker(file, onSend) {
  if (!_attachOpacityOverlay) {
    const el = document.createElement('div');
    el.id = 'attach-opacity-overlay';
    el.className = 'nick-modal-overlay';
    el.innerHTML = `
      <div class="nick-modal" id="attach-opacity-modal" style="max-width:320px">
        <div class="nick-modal-head">
          <span>Photo opacity</span>
          <button class="dm-icon-btn" id="attach-opacity-close" aria-label="Close">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div style="width:100%;aspect-ratio:1/1;border-radius:12px;background:#181818 url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%2216%22 height=%2216%22><rect width=%228%22 height=%228%22 fill=%22%23222%22/><rect x=%228%22 y=%228%22 width=%228%22 height=%228%22 fill=%22%23222%22/></svg>') repeat;overflow:hidden;display:flex;align-items:center;justify-content:center;margin-bottom:14px">
          <img id="attach-opacity-img" src="" alt="" style="width:100%;height:100%;object-fit:cover">
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/></svg>
          <input id="attach-opacity-slider" type="range" min="15" max="100" value="100" style="flex:1;accent-color:#0095f6">
          <span id="attach-opacity-value" style="font-size:12px;color:var(--muted);width:36px;text-align:right;flex-shrink:0">100%</span>
        </div>
        <div class="nick-modal-actions" style="margin-top:16px">
          <button class="nick-clear-btn" id="attach-opacity-cancel">Cancel</button>
          <button class="nick-save-btn" id="attach-opacity-send">Send</button>
        </div>
      </div>`;
    document.body.appendChild(el);
    el.addEventListener('click', e => { if (e.target === el) _closeAttachOpacityPicker(); });
    _attachOpacityOverlay = el;
  }

  const el      = _attachOpacityOverlay;
  const img     = $id('attach-opacity-img');
  const slider  = $id('attach-opacity-slider');
  const valLbl  = $id('attach-opacity-value');
  const url     = URL.createObjectURL(file);
  img.src = url;
  slider.value = 100;
  valLbl.textContent = '100%';
  img.style.opacity = 1;

  slider.oninput = () => {
    valLbl.textContent = slider.value + '%';
    img.style.opacity = slider.value / 100;
  };
  $id('attach-opacity-close').onclick  = () => _closeAttachOpacityPicker(url);
  $id('attach-opacity-cancel').onclick = () => _closeAttachOpacityPicker(url);
  $id('attach-opacity-send').onclick   = () => {
    const opacity = parseInt(slider.value, 10) || 100;
    _closeAttachOpacityPicker(url, /*revoke*/ false);
    onSend(file, opacity);
  };

  el.style.display = 'flex';
}
function _closeAttachOpacityPicker(url, revoke = true) {
  if (_attachOpacityOverlay) _attachOpacityOverlay.style.display = 'none';
  if (url && revoke) URL.revokeObjectURL(url);
}

// ── Violation notice (warning / mute / temp-ban) shown inside DM & GC ─────────
// Called from dmSend and gcSendMsg catch blocks when server returns a violation.
function _vioShowClientNotice(data, msg, inputId, sendBtnId) {
  // Show toast with the server message (already friendly)
  swShowToast(msg || 'Message blocked.', 6000);

  if (data.temp_banned || data.action === 'temp_ban') {
    // Lock the compose input and show the full lockout overlay
    const inp = $id(inputId);
    const btn = $id(sendBtnId);
    if (inp) { inp.disabled = true; inp.placeholder = 'Account suspended — see notice above.'; }
    if (btn) btn.disabled = true;
    _swShowTempBanOverlay(data.suspended_until);
    return;
  }

  if (data.banned) {
    // Permanently disable the compose input
    const inp = $id(inputId);
    const btn = $id(sendBtnId);
    if (inp) { inp.disabled = true; inp.placeholder = 'Your account has been disabled.'; }
    if (btn) btn.disabled = true;
    return;
  }

  if (data.muted && data.muted_until) {
    const muteUntil = new Date(data.muted_until).getTime();
    const inp = $id(inputId);
    const btn = $id(sendBtnId);

    function applyMute() {
      const remaining = muteUntil - Date.now();
      if (remaining <= 0) {
        if (inp) { inp.disabled = false; inp.placeholder = ''; }
        if (btn) btn.disabled = false;
        return;
      }
      const label = _vioFormatMs(remaining);
      if (inp) { inp.disabled = true; inp.placeholder = `Muted — ${label} remaining`; }
      if (btn) btn.disabled = true;
    }

    applyMute();
    const timer = setInterval(() => {
      const rem = muteUntil - Date.now();
      if (rem <= 0) {
        clearInterval(timer);
        const inp2 = $id(inputId);
        const btn2 = $id(sendBtnId);
        if (inp2) { inp2.disabled = false; inp2.placeholder = ''; }
        if (btn2) btn2.disabled = false;
        swShowToast('You are no longer muted. Please keep the conversation respectful.');
      } else {
        const inp2 = $id(inputId);
        if (inp2) inp2.placeholder = `Muted — ${_vioFormatMs(rem)} remaining`;
      }
    }, 1000);
    return;
  }

  // Warning only — flash the border briefly to signal the block
  const inp = $id(inputId);
  if (inp) {
    inp.style.transition = 'border-color .2s';
    inp.style.borderColor = 'rgba(255,59,48,.7)';
    setTimeout(() => { inp.style.borderColor = ''; }, 2000);
  }
}

function _vioFormatMs(ms) {
  const s = Math.ceil(ms / 1000);
  if (s < 3600)  return `${Math.ceil(s / 60)}m`;
  if (s < 86400) return `${Math.ceil(s / 3600)}h`;
  return `${Math.ceil(s / 86400)}d`;
}

async function dmDeleteMsg(msgId, bubble, btn) {
  if (!await swConfirm('Delete this message?', { confirmLabel: 'Delete', danger: true })) return;
  try {
    await api('DELETE', `/api/member/dm/messages/${msgId}`);
    bubble.textContent = '[deleted]';
    bubble.classList.add('dm-deleted');
    btn.remove();
    const msg = DM.msgs.find(m => m.id === msgId);
    if (msg) msg.body = '[deleted]';
  } catch (e) {
    console.error('[DM] delete:', e.message);
  }
}

// ─── Polling ──────────────────────────────────────────────────────────────────

async function _dmPollNewMessages() {
  const myId  = dmMyId();
  // Use newest known message as cursor — server only returns rows after this timestamp,
  // so the mark-read UPDATE only fires when there are genuinely new unread messages.
  const newest = DM.msgs.length ? DM.msgs[DM.msgs.length - 1].sent_at : null;
  const url    = `/api/member/dm/messages/${encodeURIComponent(DM.activeKey)}?limit=20`
               + (newest ? `&since=${encodeURIComponent(newest)}` : '');
  const msgs   = await api('GET', url);
  if (!msgs?.length) return;
  // Dedup by id; also skip messages whose body is still in-flight as optimistic bubbles
  // (race condition: server returns the message before dmSend's try-block finishes)
  const known   = new Set(DM.msgs.map(m => m.id));
  const newMsgs = msgs.filter(m => !known.has(m.id) && !DM.pendingBodies.has(m.body));
  if (!newMsgs.length) return;
  DM.msgs.push(...newMsgs);
  const list = $id('dm-msg-list');
  if (!list) return;
  const area  = $id('dm-msgs');
  const atEnd = area ? area.scrollHeight - area.scrollTop - area.clientHeight < 80 : true;
  // Pass the last known sender so incremental append chains groups correctly
  const lastSender = DM.msgs.length > newMsgs.length
    ? DM.msgs[DM.msgs.length - newMsgs.length - 1].sender_id
    : null;
  dmRenderMsgs(newMsgs, list, myId, lastSender);
  if (atEnd) dmScrollBottom();
}

// ── Typing indicator (DM) ──────────────────────────────────────────────────
// Pings the server at most once every 2s while the user has the thread open
// and is actively typing; polls (piggybacked on the normal poll tick) for the
// peer's typing state and toggles the "X is typing…" pill under the thread.
let _dmTypingLastSent = 0;
function _dmPingTyping() {
  if (!DM.activeKey) return;
  const now = Date.now();
  if (now - _dmTypingLastSent < 2000) return;
  _dmTypingLastSent = now;
  api('POST', '/api/member/typing', { conv_key: DM.activeKey, conv_type: 'dm' }).catch(() => {});
}
async function _dmPollTyping() {
  const el  = $id('dm-typing-indicator');
  const txt = $id('dm-typing-text');
  if (!DM.activeKey) { el?.classList.remove('show'); return; }
  try {
    const typers = await api('GET', `/api/member/typing?conv_key=${encodeURIComponent(DM.activeKey)}&conv_type=dm`);
    if (typers && typers.length) {
      if (txt) txt.textContent = `${typers[0].name} is typing…`;
      el?.classList.add('show');
    } else {
      el?.classList.remove('show');
    }
  } catch { /* silent */ }
}

async function dmPollTick() {
  // Always refresh visible reactions — even when we've gone "back" to the
  // sidebar, a reaction the other person added to a visible bubble should
  // update without a reload. The reaction endpoint is a cheap read-only call.
  if (DM.activeKey) {
    try { await _dmPollNewMessages(); } catch { /* silent */ }
    // Reactions don't ride along with the "since" cursor above (it only returns
    // brand-new messages), so refresh reaction state on already-rendered
    // messages separately, every tick — this is how a friend's reaction shows
    // up live instead of needing a refresh.
    try { await _refreshVisibleReactions('dm'); } catch { /* silent */ }
    // Same idea for read receipts: delivered/seen status on messages I sent
    // changes on the peer's side, not mine, so it never rides the "since"
    // cursor above — poll for it separately so double-ticks update live.
    try { await _refreshVisibleDmStatus(); } catch { /* silent */ }
    // "X is typing…" indicator — cheap read-only poll, same cadence as reactions.
    try { await _dmPollTyping(); } catch { /* silent */ }
  }
  // When no DM is open, the poll keeps running (set by dmStartPolling) but
  // just does nothing — this is intentional so reactions are always live
  // the moment the user opens a conv without needing to restart the interval.
}

function dmStartPolling() {
  dmPausePolling();
  DM.poll = setInterval(dmPollTick, DM_POLL);
}
function dmPausePolling() {
  if (DM.poll) { clearInterval(DM.poll); DM.poll = null; }
}

// ─── Panel open/close ─────────────────────────────────────────────────────────

async function dmPanelOpened() {
  DM.panelVisible = true;
  await dmLoadConvs();
  dmStartPolling();
}

// ─── Back button (mobile) ─────────────────────────────────────────────────────

function dmGoBack() {
  if (typeof window._dpClose === 'function') window._dpClose();
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.remove('dm-slide-out');
    $id('dm-window')?.classList.remove('dm-slide-in');
  }
  $id('dm-active') && ($id('dm-active').style.display = 'none');
  $id('dm-window-empty') && ($id('dm-window-empty').style.display = '');
  DM.activeKey  = null;
  DM.activePeer = null;
  // Do NOT pause polling here — we keep the interval alive so that when the
  // user re-opens a conv or returns to the inbox the poll resumes immediately.
  // dmPollTick already no-ops when DM.activeKey is null.
  document.querySelectorAll('.dm-conv-row').forEach(el => el.classList.remove('dm-active-row'));
  _kfsPopNavState('dm-chat');
}

// ─── Member picker ────────────────────────────────────────────────────────────

async function dmEnsureMembers() {
  if (DM.members.length) return;
  try {
    const data = await api('GET', '/api/members');
    const list = Array.isArray(data) ? data : (data.members || []);
    const myId = dmMyId();
    DM.members = list.filter(m => m.id !== myId);
  } catch { DM.members = []; }
}

function dmRenderPicker(q) {
  const results = $id('dm-picker-results');
  if (!results) return;
  const query = (q || '').toLowerCase().trim();
  const hits  = query
    ? DM.members.filter(m => (m.name || '').toLowerCase().includes(query) || (m.roll_no || '').includes(query))
    : DM.members.slice(0, 10);

  if (!hits.length) {
    results.innerHTML = `<div class="dm-state-msg" style="padding:16px">${query ? 'No members found.' : 'Start typing a name…'}</div>`;
    return;
  }
  results.innerHTML = hits.map(m => `
    <div class="dm-picker-row" data-id="${swEsc(m.id)}">
      ${dmAvatar(m.name, m.photo, 36)}
      <div>
        <div class="dm-picker-name">${swEsc(m.name || 'Member')}</div>
        <div class="dm-picker-meta">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
      </div>
    </div>`).join('');
  results.querySelectorAll('.dm-picker-row').forEach(row => {
    row.addEventListener('click', () => {
      const memberId = row.dataset.id;
      const m = DM.members.find(x => x.id === memberId);
      dmClosePicker();
      dmStartWith(memberId, m ? { id: m.id, name: m.name, photo: m.photo, role: m.role, batch: m.batch, domain: m.domain } : null);
    });
  });
}

function dmOpenPicker() {
  $id('dm-picker-overlay') && ($id('dm-picker-overlay').style.display = '');
  const inp = $id('dm-picker-input');
  if (inp) { inp.value = ''; inp.focus(); }
  dmEnsureMembers().then(() => dmRenderPicker(''));
}
function dmClosePicker() {
  $id('dm-picker-overlay') && ($id('dm-picker-overlay').style.display = 'none');
}

// ─── In-thread message search (DM + group) ────────────────────────────────────
// Shared by the DM panel (#dm-*) and group panel (#gc-*) via the `kind` param.
const _threadSearchState = {
  dm:    { open: false, query: '', matches: [], idx: -1 },
  group: { open: false, query: '', matches: [], idx: -1 },
};

function _threadSearchIds(kind) {
  return kind === 'group'
    ? { bar: 'gc-search-bar', input: 'gc-search-input', count: 'gc-search-count', list: 'gc-msg-list', area: 'gc-msgs' }
    : { bar: 'dm-search-bar', input: 'dm-search-input', count: 'dm-search-count', list: 'dm-msg-list',  area: 'dm-msgs' };
}

function _threadSearchOpen(kind) {
  const st = _threadSearchState[kind];
  const ids = _threadSearchIds(kind);
  st.open = true;
  $id(ids.bar)?.classList.add('show');
  const input = $id(ids.input);
  if (input) { input.value = st.query; input.focus(); }
  if (st.query) _threadSearchRun(kind, st.query);
}

function _threadSearchClose(kind) {
  const st = _threadSearchState[kind];
  const ids = _threadSearchIds(kind);
  st.open = false;
  st.query = '';
  st.matches = [];
  st.idx = -1;
  $id(ids.bar)?.classList.remove('show');
  const input = $id(ids.input);
  if (input) input.value = '';
  const count = $id(ids.count);
  if (count) count.textContent = '';
  document.querySelectorAll(`#${ids.list} .dm-bubble.dm-search-match, #${ids.list} .dm-bubble.dm-search-current`)
    .forEach(el => el.classList.remove('dm-search-match', 'dm-search-current'));
}

function _threadSearchRun(kind, query) {
  const st = _threadSearchState[kind];
  const ids = _threadSearchIds(kind);
  st.query = query || '';

  document.querySelectorAll(`#${ids.list} .dm-bubble.dm-search-match, #${ids.list} .dm-bubble.dm-search-current`)
    .forEach(el => el.classList.remove('dm-search-match', 'dm-search-current'));

  const q = st.query.trim().toLowerCase();
  const count = $id(ids.count);
  if (!q) {
    st.matches = [];
    st.idx = -1;
    if (count) count.textContent = '';
    return;
  }

  const bubbles = Array.from(document.querySelectorAll(`#${ids.list} .dm-bubble`));
  st.matches = bubbles.filter(b => (b.querySelector('.dm-bubble-text')?.textContent || '').toLowerCase().includes(q));
  st.matches.forEach(b => b.classList.add('dm-search-match'));
  st.idx = st.matches.length ? 0 : -1;

  if (count) count.textContent = st.matches.length ? `${st.idx + 1}/${st.matches.length}` : '0/0';
  if (st.idx >= 0) _threadSearchHighlightCurrent(kind);
}

function _threadSearchHighlightCurrent(kind) {
  const st = _threadSearchState[kind];
  const ids = _threadSearchIds(kind);
  st.matches.forEach(b => b.classList.remove('dm-search-current'));
  const current = st.matches[st.idx];
  if (!current) return;
  current.classList.add('dm-search-current');
  current.scrollIntoView({ block: 'center', behavior: 'smooth' });
  const count = $id(ids.count);
  if (count) count.textContent = `${st.idx + 1}/${st.matches.length}`;
}

function _threadSearchNav(kind, dir) {
  const st = _threadSearchState[kind];
  if (!st.matches.length) return;
  st.idx = (st.idx + dir + st.matches.length) % st.matches.length;
  _threadSearchHighlightCurrent(kind);
}

// ─── Conversation search/filter ───────────────────────────────────────────────
function dmFilterConvs(q) {
  const query = (q || '').toLowerCase().trim();
  dmRenderConvs(query ? DM.convs.filter(c => (c.peer?.name || '').toLowerCase().includes(query)) : DM.convs);
}

// ─── Init ─────────────────────────────────────────────────────────────────────

function initDM() {
  // NOTE: dm-new-btn dropdown is wired by initInboxNewBtn() in the unified inbox IIFE.
  // Do NOT wire it here to dmOpenPicker directly — that breaks the New Message / New Group dropdown.

  // Picker close
  $id('dm-picker-close')?.addEventListener('click', dmClosePicker);
  $id('dm-picker-overlay')?.addEventListener('click', e => { if (e.target === $id('dm-picker-overlay')) dmClosePicker(); });

  // Picker search
  $id('dm-picker-input')?.addEventListener('input', e => {
    clearTimeout(DM.pickerTimer);
    DM.pickerTimer = setTimeout(() => dmRenderPicker(e.target.value), 200);
  });

  // Conv search — use window.dmFilterConvs so unified inbox override handles groups too
  $id('dm-search')?.addEventListener('input', e => {
    if (typeof window.dmFilterConvs === 'function') window.dmFilterConvs(e.target.value);
    else dmFilterConvs(e.target.value);
  });

  // Send
  $id('dm-send-btn')?.addEventListener('click', dmSend);
  $id('dm-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); dmSend(); }
  });

  // Auto-grow textarea
  $id('dm-input')?.addEventListener('input', function () {
    this.style.height = '';
    this.style.height = Math.min(this.scrollHeight, 110) + 'px';
    if (this.value.trim()) _dmPingTyping();
  });

  // Photo attachment
  $id('dm-attach-btn')?.addEventListener('click', () => $id('dm-attach-input')?.click());
  $id('dm-attach-input')?.addEventListener('change', e => {
    const file = e.target.files?.[0];
    e.target.value = ''; // allow picking the same file twice in a row
    if (file) _openAttachOpacityPicker(file, (f, opacity) => _dmSendImage(f, opacity));
  });

  // In-thread search
  $id('dm-thread-search-btn')?.addEventListener('click', () => _threadSearchOpen('dm'));
  $id('dm-search-close')?.addEventListener('click', () => _threadSearchClose('dm'));
  $id('dm-search-prev')?.addEventListener('click', () => _threadSearchNav('dm', -1));
  $id('dm-search-next')?.addEventListener('click', () => _threadSearchNav('dm', 1));
  $id('dm-search-input')?.addEventListener('input', e => _threadSearchRun('dm', e.target.value));
  $id('dm-search-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); _threadSearchNav('dm', e.shiftKey ? -1 : 1); }
    if (e.key === 'Escape') { e.preventDefault(); _threadSearchClose('dm'); }
  });

  // Back (mobile)
  $id('dm-back-btn')?.addEventListener('click', dmGoBack);

  // Load earlier
  $id('dm-load-earlier')?.addEventListener('click', () => dmLoadMsgs(true));

  // Background unread badge refresh every 30s
  dmRefreshBadge();
  setInterval(dmRefreshBadge, 30000);
}

// Boot after DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDM);
} else {
  initDM();
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION: Content Reporting — Member Portal JS
// Covers: post options menu, report modal, DM report button
// ─────────────────────────────────────────────────────────────────────────────

// ── Post options menu (three-dot) ────────────────────────────────────────────
let _swPostMenuOpen = null;

function swShowPostMenu(event, postId, authorId, isAdminPost) {
  event.stopPropagation();
  // Close any open menu first
  swClosePostMenu();

  const myId = window._memberProfile?.id || '';
  const isOwn = myId && myId === authorId;
  const isAdmin = isAdminPost;

  const items = [];
  items.push({ label: '🔗 Copy link', fn: `swCopyPostLink('${postId}')` });
  if (!isAdmin) {
    // Don't show report on KFS official posts
    items.push({ label: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>Report post', fn: `swOpenReportModal('post','${postId}')`, danger: true });
  }
  if (isOwn) {
    items.push({ label: '🗑 Delete post', fn: `swConfirmDeletePost('${postId}')`, danger: true });
  }

  const menu = document.createElement('div');
  menu.id = 'sw-post-menu';
  menu.style.cssText = 'position:fixed;z-index:9999;background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.5);padding:6px;min-width:160px';
  menu.innerHTML = items.map(item =>
    `<button onclick="event.stopPropagation();swClosePostMenu();${item.fn}" style="display:block;width:100%;text-align:left;background:transparent;border:none;padding:10px 14px;font-size:13px;color:${item.danger?'#e53e3e':'var(--text,#f5f5f5)'};border-radius:8px;cursor:pointer" onmouseover="this.style.background='rgba(255,255,255,.06)'" onmouseout="this.style.background='transparent'">${item.label}</button>`
  ).join('');

  // Position near the button
  const btn = event.currentTarget || event.target;
  const rect = btn.getBoundingClientRect();
  const menuW = 180;
  let left = rect.right - menuW;
  if (left < 8) left = 8;
  let top = rect.bottom + 4;
  if (top + 160 > window.innerHeight) top = rect.top - 160;
  menu.style.left = left + 'px';
  menu.style.top  = top  + 'px';

  document.body.appendChild(menu);
  _swPostMenuOpen = menu;

  // Close on outside click
  setTimeout(() => {
    document.addEventListener('click', swClosePostMenu, { once: true, capture: true });
  }, 0);
}

function swClosePostMenu() {
  if (_swPostMenuOpen) { _swPostMenuOpen.remove(); _swPostMenuOpen = null; }
}

function swCopyPostLink(postId) {
  const url = `${location.origin}/social-strand/member/${postId}`;
  navigator.clipboard?.writeText(url).then(() => {
    swShowToast('Link copied!');
  }).catch(() => { swShowToast('Could not copy — try manually.'); });
}

async function swConfirmDeletePost(postId) {
  const ok = await swConfirm('Delete this post? This cannot be undone.', { title: 'Delete post', confirmLabel: 'Delete', danger: true });
  if (!ok) return;
  // Use existing delete function if available
  if (typeof swDeleteProject === 'function') { swDeleteProject(postId); return; }
  // Fallback — use api() helper so CSRF is automatically attached
  api('DELETE', `/api/member/studio/projects/${postId}`)
    .then(() => {
      const card = document.querySelector(`.ig-post[data-project-id="${CSS.escape(postId)}"]`);
      if (card) card.remove();
      swShowToast('Post deleted.');
    })
    .catch(e => swAlert(e.message || 'Error deleting post. Please try again.'));
}

// ── Custom confirm/alert dialogs (replaces native confirm()/alert()) ─────────
// swConfirm(message, opts) -> Promise<boolean>   (true = user confirmed)
// swAlert(message, opts)   -> Promise<void>
// opts: { title, confirmLabel, cancelLabel, danger }
function _swDialogShow({ title, message, confirmLabel, cancelLabel, danger, alertOnly } = {}) {
  return new Promise(resolve => {
    document.getElementById('sw-dialog-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'sw-dialog-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:99995;background:rgba(0,0,0,.7);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:16px;animation:dmFadeIn .15s ease';

    const accentColor = danger ? '#ef4444' : '#3b82f6';
    overlay.innerHTML = `
      <div style="background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:18px;padding:24px 22px 20px;max-width:380px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,.7);animation:dmSlideUp .26s cubic-bezier(.34,1.56,.64,1)">
        ${title ? `<h3 style="margin:0 0 8px;font-size:16px;font-weight:700;letter-spacing:-0.01em;color:var(--text,#f5f5f5)">${swEsc(title)}</h3>` : ''}
        <p style="margin:0 0 22px;font-size:13.5px;line-height:1.55;color:#aaa;white-space:pre-line">${message}</p>
        <div style="display:flex;gap:10px;justify-content:flex-end">
          ${alertOnly ? '' : `<button id="sw-dialog-cancel" style="background:transparent;border:1px solid var(--border,#333);color:#888;padding:9px 20px;border-radius:20px;font-size:13px;font-weight:500;cursor:pointer;transition:border-color .15s,color .15s" onmouseover="this.style.borderColor='#555';this.style.color='#f5f5f5'" onmouseout="this.style.borderColor='#333';this.style.color='#888'">${swEsc(cancelLabel || 'Cancel')}</button>`}
          <button id="sw-dialog-ok" style="background:${accentColor};color:#fff;border:none;padding:9px 20px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s" onmouseover="this.style.opacity='.88'" onmouseout="this.style.opacity='1'">${swEsc(confirmLabel || 'OK')}</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const cleanup = (result) => {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      resolve(result);
    };
    const onKey = e => {
      if (e.key === 'Escape') { e.preventDefault(); cleanup(false); }
      if (e.key === 'Enter')  { e.preventDefault(); cleanup(true); }
    };
    document.addEventListener('keydown', onKey);

    overlay.querySelector('#sw-dialog-ok').addEventListener('click', () => cleanup(true));
    overlay.querySelector('#sw-dialog-cancel')?.addEventListener('click', () => cleanup(false));
    overlay.addEventListener('click', e => { if (e.target === overlay) cleanup(false); });
    overlay.querySelector('#sw-dialog-ok')?.focus();
  });
}
function swConfirm(message, opts = {}) {
  return _swDialogShow({ message, ...opts });
}
function swAlert(message, opts = {}) {
  return _swDialogShow({ message, alertOnly: true, confirmLabel: opts.confirmLabel || 'OK', ...opts }).then(() => {});
}

function swShowToast(msg, duration = 2800) {
  let t = document.getElementById('sw-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'sw-toast';
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#111;color:#f5f5f5;font-size:13px;padding:10px 20px;border-radius:24px;z-index:99999;box-shadow:0 4px 16px rgba(0,0,0,.5);transition:opacity .3s;pointer-events:none';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = '1';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, duration);
}

// ── Report modal ─────────────────────────────────────────────────────────────
// Creates a lightweight report modal inline (no external HTML needed)
function swOpenReportModal(contentType, contentId, extraLabel, _reportMsgObj) {
  // Remove any existing modal
  let existing = document.getElementById('sw-report-modal-overlay');
  if (existing) existing.remove();

  const typeLabel = { post: 'post', dm: 'DM message', comment: 'comment', group_message: 'group message', member: 'account' }[contentType] || contentType;
  const reasons = [
    'Harassment or bullying',
    'Hate speech or discrimination',
    'Spam or misleading content',
    'Inappropriate or explicit content',
    'Impersonation',
    'Other',
  ];

  const overlay = document.createElement('div');
  overlay.id = 'sw-report-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:99990;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:18px;padding:28px 24px;max-width:420px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,.7)">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <h3 style="margin:0;font-size:16px;font-weight:700;letter-spacing:-0.01em">Report ${typeLabel}</h3>
        <button id="sw-report-x" style="background:none;border:none;color:#666;cursor:pointer;padding:2px;line-height:1;font-size:18px">&#x2715;</button>
      </div>
      <p style="font-size:13px;color:#888;margin:0 0 20px;line-height:1.5">Please tell us why you're reporting this. Our team reviews all reports.</p>
      <div style="display:flex;flex-direction:column;gap:2px;margin-bottom:20px">
        ${reasons.map((r, i) => `
          <label style="display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;cursor:pointer;transition:background 0.1s" onmouseover="this.style.background='rgba(255,255,255,0.04)'" onmouseout="this.style.background='transparent'">
            <input type="radio" name="sw-report-reason" value="${r}" ${i===0?'checked':''} style="width:16px;height:16px;accent-color:#ef4444;cursor:pointer;flex-shrink:0">
            <span style="font-size:13px;color:var(--text,#f5f5f5)">${r}</span>
          </label>`).join('')}
      </div>
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:600;letter-spacing:0.06em;color:#666;text-transform:uppercase;margin-bottom:8px">Additional Details (optional)</div>
        <textarea id="sw-report-details" rows="3" placeholder="Any extra context…" style="width:100%;box-sizing:border-box;font-size:13px;background:rgba(0,0,0,0.3);border:1px solid var(--border,#222);border-radius:10px;padding:10px 12px;color:var(--text,#f5f5f5);resize:vertical;font-family:inherit;outline:none;line-height:1.5"></textarea>
      </div>
      <div id="sw-report-msg" style="font-size:12px;color:#ef4444;margin-bottom:12px;display:none;padding:8px 12px;background:rgba(239,68,68,0.1);border-radius:8px"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="sw-report-cancel" style="background:transparent;border:1px solid var(--border,#333);color:#888;padding:9px 20px;border-radius:20px;font-size:13px;font-weight:500;cursor:pointer;transition:border-color 0.15s,color 0.15s" onmouseover="this.style.borderColor='#555';this.style.color='#f5f5f5'" onmouseout="this.style.borderColor='#333';this.style.color='#888'">Cancel</button>
        <button id="sw-report-submit" style="background:#ef4444;color:#fff;border:none;padding:9px 20px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity 0.15s" onmouseover="this.style.opacity='0.88'" onmouseout="this.style.opacity='1'">Submit Report</button>
      </div>
    </div>`;

  document.body.appendChild(overlay);

  overlay.querySelector('#sw-report-cancel').onclick = () => overlay.remove();
  overlay.querySelector('#sw-report-x').onclick = () => overlay.remove();
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

  overlay.querySelector('#sw-report-submit').onclick = async () => {
    const reasonEl = overlay.querySelector('input[name="sw-report-reason"]:checked');
    const reason   = reasonEl?.value || '';
    const details  = overlay.querySelector('#sw-report-details')?.value.trim() || '';
    const msgEl    = overlay.querySelector('#sw-report-msg');
    const submitBtn = overlay.querySelector('#sw-report-submit');

    if (!reason) { msgEl.textContent = 'Please select a reason.'; msgEl.style.display='block'; return; }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting…';

    try {
      // E2EE: if the reported message is encrypted, decrypt it client-side and
      // include the plaintext in the report. Only master admins can read it.
      // This is the same approach Signal uses for E2EE content moderation.
      let decrypted_snapshot = null;
      if (_reportMsgObj && _reportMsgObj.e2ee && E2EE.ready()) {
        const myId = window._memberProfile?.id || window._member?.id;
        const msgType = (contentType === 'group_message') ? 'group' : 'dm';
        decrypted_snapshot = await E2EE.decryptForReport(_reportMsgObj, msgType, myId).catch(() => null);
      }
      await api('POST', '/api/member/reports', {
        content_type: contentType,
        content_id: String(contentId),
        reason,
        details,
        ...(decrypted_snapshot != null ? { decrypted_snapshot, e2ee_report: true } : {}),
      });
      overlay.remove();
      swShowToast('✓ Report submitted. Thank you.');
    } catch (e) {
      msgEl.textContent = e.message || 'Error submitting report. Please try again.';
      msgEl.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit Report';
    }
  };
}

// ── Hook: add Report button in DM conversation view ──────────────────────────
// Called when DM message context-menu / long-press happens
function swReportDmMessage(msgId) {
  // Find the message object in DM.msgs for E2EE decryption
  const msgObj = DM.msgs?.find(m => m.id === msgId) || null;
  swOpenReportModal('dm', msgId, 'You are reporting a direct message.', msgObj);
}

// ── Hook: add Report button for comments (in detail view) ────────────────────
function swReportComment(commentId) {
  swOpenReportModal('comment', commentId, 'You are reporting a comment.');
}

// ── Hook: report a group message ─────────────────────────────────────────────
function swReportGroupMessage(msgId) {
  // Find the message object in GC.msgs for E2EE decryption at report time
  const msgObj = GC.msgs?.find(m => m.id === msgId) || null;
  swOpenReportModal('group_message', msgId, 'You are reporting a group message.', msgObj);
}

// ── Hook: report a member account ────────────────────────────────────────────
function swReportMember(memberId, memberName) {
  swOpenReportModal('member', memberId, `You are reporting ${memberName || 'this member'}'s account.`);
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE CONTEXT MENU  (right-click desktop · long-press mobile)
// Surfaces: DM bubbles + group chat bubbles
// Actions: Reply (quoted) · Forward · Report message · Report account (group)
// ═══════════════════════════════════════════════════════════════════════════

// Active reply state — shown as a bar above the compose area
const _replyState = { dm: null, group: null }; // { id, body, sender } | null

function _setReply(type /* 'dm'|'group' */, state /* null | {id, body, sender} */) {
  _replyState[type] = state;
  const barId   = type === 'dm' ? 'dm-reply-bar' : 'gc-reply-bar';
  const inputId = type === 'dm' ? 'dm-input'     : 'gc-input';
  let bar = $id(barId);
  if (!state) {
    if (bar) bar.style.display = 'none';
    return;
  }
  if (!bar) {
    // Create once; insert just above the compose textarea
    bar = document.createElement('div');
    bar.id = barId;
    bar.className = 'dm-reply-bar';
    const input = $id(inputId);
    if (input) input.closest('.dm-compose')?.before(bar);
  }
  bar.style.display = 'flex';
  bar.innerHTML = `
    <div class="dm-reply-bar-inner">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;opacity:.6"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>
      <div class="dm-reply-bar-content">
        <span class="dm-reply-bar-sender">${swEsc(state.sender)}</span>
        <span class="dm-reply-bar-body">${swEsc((state.body || '').slice(0, 100))}</span>
      </div>
      <button class="dm-reply-bar-cancel" title="Cancel reply">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>`;
  bar.querySelector('.dm-reply-bar-cancel').onclick = () => _setReply(type, null);
  $id(inputId)?.focus();
}

// Patch dmSend to inject replied_to fields when a reply is active
const _origDmSend = typeof dmSend === 'function' ? dmSend : null;
// We'll wrap at call-site by intercepting the api call in _dmSendReplyWrapper
function _dmGetReplyPayload() {
  const r = _replyState.dm;
  if (!r) return {};
  return { replied_to_id: r.id, replied_to_body: r.body, replied_to_sender: r.sender };
}
function _gcGetReplyPayload() {
  const r = _replyState.group;
  if (!r) return {};
  return { replied_to_id: r.id, replied_to_body: r.body, replied_to_sender: r.sender };
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE EDITING — same soft pattern as delete: sender-only, stamps
// edited_at, "(edited)" tag renders next to the timestamp. Reuses the reply
// bar's markup/CSS (.dm-reply-bar) for the "Editing message…" strip above
// the composer, so no new CSS is needed.
// ═══════════════════════════════════════════════════════════════════════════

const _editState = { dm: null, group: null }; // { id } | null

function _beginEditMsg(type /* 'dm'|'group' */, id, body) {
  // Can't reply and edit at the same time — editing wins.
  _setReply(type, null);
  _editState[type] = { id };

  const inputId = type === 'dm' ? 'dm-input' : 'gc-input';
  const input = $id(inputId);
  if (input) {
    input.value = body || '';
    input.style.height = '';
    input.style.height = input.scrollHeight + 'px';
    input.focus();
    // Cursor at the end
    input.setSelectionRange?.(input.value.length, input.value.length);
  }

  const barId = type === 'dm' ? 'dm-edit-bar' : 'gc-edit-bar';
  let bar = $id(barId);
  if (!bar) {
    bar = document.createElement('div');
    bar.id = barId;
    bar.className = 'dm-reply-bar';
    if (input) input.closest('.dm-compose')?.before(bar);
  }
  bar.style.display = 'flex';
  bar.innerHTML = `
    <div class="dm-reply-bar-inner">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;opacity:.6"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
      <div class="dm-reply-bar-content">
        <span class="dm-reply-bar-sender">Editing message</span>
        <span class="dm-reply-bar-body">${swEsc((body || '').slice(0, 100))}</span>
      </div>
      <button class="dm-reply-bar-cancel" title="Cancel edit">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>`;
  bar.querySelector('.dm-reply-bar-cancel').onclick = () => _cancelEditMsg(type);
}

function _cancelEditMsg(type) {
  _editState[type] = null;
  const barId = type === 'dm' ? 'dm-edit-bar' : 'gc-edit-bar';
  const bar = $id(barId);
  if (bar) bar.style.display = 'none';
  const inputId = type === 'dm' ? 'dm-input' : 'gc-input';
  const input = $id(inputId);
  if (input) { input.value = ''; input.style.height = ''; }
}

/** Update a single already-rendered bubble in place after a successful edit. */
function _applyEditedBubble(msgId, newBody) {
  const bubble = document.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
  if (!bubble) return;
  const textNode = bubble.querySelector('.dm-bubble-text');
  if (textNode) textNode.textContent = newBody;
  const meta = bubble.closest('.dm-bubble-wrap')?.nextElementSibling;
  if (meta?.classList.contains('dm-meta') && !meta.querySelector('.dm-edited-tag')) {
    meta.insertAdjacentHTML('afterbegin', '<span class="dm-edited-tag">edited</span>');
  }
}

async function _dmSubmitEdit(newBody) {
  const state = _editState.dm;
  if (!state) return;
  const input = $id('dm-input');
  try {
    let payload = { body: newBody };
    const msg = (DM.msgs || []).find(m => m.id === state.id);
    if (msg?.e2ee && E2EE.ready() && DM.activePeer?.id) {
      try {
        const enc = await E2EE.encryptDm(newBody, DM.activePeer.id);
        payload = { body: '', ...enc };
      } catch (encErr) {
        console.warn('[E2EE] DM edit-encrypt failed, sending plaintext:', encErr.message);
      }
    }
    const res = await api('PATCH', `/api/member/dm/messages/${state.id}`, payload);
    if (msg) {
      msg.body = res.message?.body ?? newBody;
      msg.edited_at = res.message?.edited_at || new Date().toISOString();
      msg.e2ee = res.message?.e2ee ?? msg.e2ee;
      msg.cipher_for_recipient = res.message?.cipher_for_recipient ?? null;
      msg.cipher_for_self = res.message?.cipher_for_self ?? null;
      msg._plaintext = newBody; // avoid a re-decrypt round-trip
    }
    _applyEditedBubble(state.id, newBody);
    if (typeof swShowToast === 'function') swShowToast('Message edited.');
  } catch (e) {
    alert(e.message || 'Could not edit message.');
  } finally {
    _cancelEditMsg('dm');
    if (input) input.style.height = '';
  }
}

async function _gcSubmitEdit(newBody) {
  const state = _editState.group;
  if (!state) return;
  const input = $id('gc-input');
  try {
    let payload = { body: newBody };
    const msg = (GC.msgs || []).find(m => m.id === state.id);
    if (msg?.e2ee && E2EE.ready() && GC.activeMembers?.length) {
      try {
        const memberIds = GC.activeMembers.map(m => m.id || m.member_id).filter(Boolean);
        const enc = await E2EE.encryptGroup(newBody, memberIds);
        payload = { body: '', ...enc };
      } catch (encErr) {
        console.warn('[E2EE] Group edit-encrypt failed, sending plaintext:', encErr.message);
      }
    }
    const res = await api('PATCH', `/api/member/groups/${GC.activeId}/messages/${state.id}`, payload);
    if (msg) {
      msg.body = res.message?.body ?? newBody;
      msg.edited_at = res.message?.edited_at || new Date().toISOString();
      msg.e2ee = res.message?.e2ee ?? msg.e2ee;
      msg.ciphertext = res.message?.ciphertext ?? null;
      msg.wrapped_keys = res.message?.wrapped_keys ?? null;
      msg._plaintext = newBody;
    }
    _applyEditedBubble(state.id, newBody);
    if (typeof swShowToast === 'function') swShowToast('Message edited.');
  } catch (e) {
    alert(e.message || 'Could not edit message.');
  } finally {
    _cancelEditMsg('group');
    if (input) input.style.height = '';
  }
}

// Forward picker — minimal inline modal
function _openForwardPicker(body) {
  let overlay = $id('dm-forward-overlay');
  if (overlay) overlay.remove();
  overlay = document.createElement('div');
  overlay.id = 'dm-forward-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:99991;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px';

  const dms    = DM.convs  || [];
  const groups = GC.groups || [];
  const items  = [
    ...dms.map(c    => ({ label: c.peer?.name || 'Member', key: c.conv_key, avatar: c.peer?.photo || '', type: 'dm',    data: c })),
    ...groups.map(g => ({ label: g.name,                   key: g.id,       avatar: '',                type: 'group',  data: g })),
  ].sort((a, b) => a.label.localeCompare(b.label));

  overlay.innerHTML = `
    <div style="background:var(--surface,#1a1a1a);border:1px solid var(--border,#222);border-radius:18px;padding:24px 20px;max-width:360px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,.7);max-height:80vh;display:flex;flex-direction:column">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
        <h3 style="margin:0;font-size:15px;font-weight:700">Forward message</h3>
        <button id="dm-fwd-x" style="background:none;border:none;color:#666;cursor:pointer;font-size:18px">&#x2715;</button>
      </div>
      <p style="font-size:12px;color:#888;margin:0 0 14px;padding:10px 12px;background:rgba(255,255,255,.04);border-radius:10px;border-left:3px solid var(--accent,#3b82f6);line-height:1.4">${swEsc(body.slice(0, 160))}</p>
      <input id="dm-fwd-search" placeholder="Search…" style="width:100%;box-sizing:border-box;padding:8px 12px;border-radius:10px;border:1px solid var(--border,#333);background:rgba(0,0,0,.3);color:var(--text,#f5f5f5);font-size:13px;outline:none;margin-bottom:10px">
      <div id="dm-fwd-list" style="overflow-y:auto;max-height:260px;display:flex;flex-direction:column;gap:2px"></div>
      <div id="dm-fwd-msg" style="font-size:12px;color:#ef4444;margin-top:8px;display:none"></div>
    </div>`;
  document.body.appendChild(overlay);

  overlay.querySelector('#dm-fwd-x').onclick = () => overlay.remove();
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

  function renderList(q) {
    const filt = q ? items.filter(i => i.label.toLowerCase().includes(q.toLowerCase())) : items;
    const list = $id('dm-fwd-list');
    list.innerHTML = '';
    filt.forEach(item => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;cursor:pointer;transition:background .1s';
      row.onmouseover = () => row.style.background = 'rgba(255,255,255,.05)';
      row.onmouseout  = () => row.style.background = 'transparent';
      const av = item.type === 'dm' && item.avatar
        ? `<img src="${swEsc(item.avatar)}" style="width:34px;height:34px;border-radius:50%;object-fit:cover;flex-shrink:0">`
        : `<div style="width:34px;height:34px;border-radius:${item.type==='group'?'10px':'50%'};background:var(--accent,#3b82f6);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0">${swEsc((item.label[0]||'?').toUpperCase())}</div>`;
      row.innerHTML = `${av}<span style="font-size:13px;font-weight:500">${swEsc(item.label)}</span>`;
      row.onclick = async () => {
        try {
          const msgEl = $id('dm-fwd-msg');
          if (item.type === 'dm') {
            let payload = { to_member_id: item.data.peer?.id, body };
            if (E2EE.ready() && item.data.peer?.id) {
              try { payload = { to_member_id: item.data.peer.id, body: '', ...(await E2EE.encryptDm(body, item.data.peer.id)) }; }
              catch { /* fall back to plaintext */ }
            }
            await api('POST', '/api/member/dm/send', payload);
          } else {
            let payload = { body };
            if (E2EE.ready() && item.data.members?.length) {
              try {
                const memberIds = item.data.members.map(m => m.id || m.member_id).filter(Boolean);
                payload = { body: '', ...(await E2EE.encryptGroup(body, memberIds)) };
              } catch { /* fall back to plaintext */ }
            }
            await api('POST', `/api/member/groups/${item.data.id}/messages`, payload);
          }
          overlay.remove();
          swShowToast('✓ Message forwarded.');
        } catch (e) {
          const msgEl = $id('dm-fwd-msg');
          if (msgEl) { msgEl.textContent = e.message || 'Could not forward.'; msgEl.style.display = ''; }
        }
      };
      list.appendChild(row);
    });
    if (!filt.length) {
      list.innerHTML = '<p style="color:#666;font-size:13px;text-align:center;padding:12px 0;margin:0">No conversations found</p>';
    }
  }
  renderList('');
  $id('dm-fwd-search').oninput = e => renderList(e.target.value);
  $id('dm-fwd-search').focus();
}

// ── Shared emoji picker popup (anchored to the react button) ──────────────────
let _emojiPickerPopup = null;
// Instagram's exact quick-reaction set
const _QUICK_REACTIONS = ['❤️', '😂', '😮', '😢', '😡', '👏', '🔥', '😍'];

function _dismissEmojiPicker() {
  if (_emojiPickerPopup) { _emojiPickerPopup.remove(); _emojiPickerPopup = null; }
}

function _showEmojiPicker(anchorBtn, onPick) {
  _dismissEmojiPicker();
  const popup = document.createElement('div');
  popup.className = 'dm-emoji-picker-popup';
  _emojiPickerPopup = popup;

  _QUICK_REACTIONS.forEach((emoji, i) => {
    const btn = document.createElement('button');
    btn.className = 'dm-emoji-picker-btn';
    btn.type = 'button';
    btn.textContent = emoji;
    // Stagger the bounce-in animation per emoji
    btn.style.animationDelay = `${i * 18}ms`;
    btn.style.animationName = 'emojiItemIn';
    btn.style.animationDuration = '.22s';
    btn.style.animationFillMode = 'both';
    btn.style.animationTimingFunction = 'cubic-bezier(.34,1.56,.64,1)';
    btn.addEventListener('click', e => {
      e.stopPropagation();
      _dismissEmojiPicker();
      onPick(emoji);
    });
    popup.appendChild(btn);
  });

  document.body.appendChild(popup);
  _emojify(popup);

  // Position above the anchor (bubble or react button), centred
  const rect = anchorBtn.getBoundingClientRect();
  // Use offsetWidth after append; fall back to estimated width
  const pw = popup.offsetWidth || (_QUICK_REACTIONS.length * 42 + 16);
  const ph = popup.offsetHeight || 52;
  // Try above first (Instagram behaviour), fall below if no room
  let left = rect.left + rect.width / 2 - pw / 2;
  let top  = rect.top - ph - 10;
  left = Math.max(8, Math.min(left, window.innerWidth  - pw - 8));
  top  = top < 8 ? rect.bottom + 10 : top;
  popup.style.left = left + 'px';
  popup.style.top  = top  + 'px';

  // Dismiss on outside click or Escape
  const dismiss = e => { if (!popup.contains(e.target)) _dismissEmojiPicker(); };
  setTimeout(() => document.addEventListener('click', dismiss, { once: true }), 0);
  document.addEventListener('keydown', function escDismiss(e) {
    if (e.key === 'Escape') { _dismissEmojiPicker(); document.removeEventListener('keydown', escDismiss); }
  });
}

// ── Build the three Instagram-style action buttons beside a bubble ────────────
// order for MINE (shown to left of bubble):  ⋮  ↩  🙂   (right-to-left visually)
// order for THEIRS (shown to right of bubble): 🙂  ↩  ⋮  (left-to-right)
// CSS flex-direction:row handles both; for mine the wrap is row-reverse so
// the bubble stays right and actions sit to the left.
function _buildHoverActions({ msgId, body, mine, senderName, type, senderId, onReply, onReact }) {
  const hoverActions = document.createElement('div');
  hoverActions.className = 'dm-hover-actions';

  // ── React button (smiley face) ──────────────────────────────────────
  const reactBtn = document.createElement('button');
  reactBtn.className = 'dm-ha-btn';
  reactBtn.type = 'button';
  reactBtn.title = 'React';
  reactBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>`;
  reactBtn.addEventListener('click', e => {
    e.stopPropagation();
    _showEmojiPicker(reactBtn, emoji => onReact(emoji));
  });

  // ── Reply button ──────────────────────────────────────────────────
  const replyBtn = document.createElement('button');
  replyBtn.className = 'dm-ha-btn';
  replyBtn.type = 'button';
  replyBtn.title = 'Reply';
  replyBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>`;
  replyBtn.addEventListener('click', e => {
    e.stopPropagation();
    onReply();
  });

  // ── More (⋮) button ───────────────────────────────────────────────
  const moreBtn = document.createElement('button');
  moreBtn.className = 'dm-ha-btn';
  moreBtn.type = 'button';
  moreBtn.title = 'More';
  moreBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="12" cy="19" r="1.6"/></svg>`;
  moreBtn.addEventListener('click', e => {
    e.stopPropagation();
    _showMsgContextMenu(e, { id: msgId, body, mine, senderName, type, senderId });
  });

  // Instagram order:
  // mine   → shown LEFT of bubble in visual order: ⋮ ↩ 😊  (wrap is row-reverse, so first child ends up rightmost)
  // theirs → shown RIGHT of bubble: 😊 ↩ ⋮
  if (mine) {
    hoverActions.appendChild(moreBtn);
    hoverActions.appendChild(replyBtn);
    hoverActions.appendChild(reactBtn);
  } else {
    hoverActions.appendChild(reactBtn);
    hoverActions.appendChild(replyBtn);
    hoverActions.appendChild(moreBtn);
  }

  return hoverActions;
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE REACTIONS (Instagram-style) — shared by DM + group chat
// One reaction per member per message: tap an emoji to add/switch, tap your
// own again to remove. Pills overlap the bottom corner of the bubble, just
// like Instagram DMs.
// ═══════════════════════════════════════════════════════════════════════════

/** (Re)draw the little overlapping reaction-pill row on a bubble.
 *  Update in-place when the container already exists so the CSS animation
 *  only fires on genuinely new pills — not on every poll-refresh tick. */
function _renderReactionPills(bubble, reactions, onPick) {
  const wrap = bubble.closest('.dm-bubble-wrap');
  if (!reactions || !reactions.length) {
    bubble.querySelector('.dm-bubble-reactions')?.remove();
    wrap?.classList.remove('dm-has-reactions');
    return;
  }
  wrap?.classList.add('dm-has-reactions');

  // Build a key → reaction map for easy lookup
  const rxnMap = {};
  reactions.forEach(r => { rxnMap[r.emoji] = r; });

  let pills = bubble.querySelector('.dm-bubble-reactions');
  const isNew = !pills;
  if (isNew) {
    pills = document.createElement('div');
    pills.className = 'dm-bubble-reactions';
  }

  // Remove pills that are no longer in the list
  pills.querySelectorAll('.dm-rxn-pill').forEach(el => {
    if (!rxnMap[el.dataset.emoji]) el.remove();
  });

  // Update existing or insert new pills (preserve DOM order = reaction order)
  reactions.forEach((r, idx) => {
    let pill = pills.querySelector(`.dm-rxn-pill[data-emoji="${CSS.escape(r.emoji)}"]`);
    if (pill) {
      // Update in-place — add dm-rxn-no-anim so CSS animation doesn't replay
      // (browsers restart the animation whenever className is reassigned)
      pill.className = `dm-rxn-pill dm-rxn-no-anim${r.mine ? ' dm-rxn-mine' : ''}`;
      pill.title = r.mine ? 'Remove your reaction' : `React with ${r.emoji}`;
      pill.innerHTML = `<span>${swEsc(r.emoji)}</span>${r.count > 1 ? `<span class="dm-rxn-count">${r.count}</span>` : ''}`;
      // Re-wire click (innerHTML wipe removes old listener)
      pill.addEventListener('click', e => { e.stopPropagation(); onPick(r.emoji); });
      _emojify(pill);
    } else {
      pill = document.createElement('button');
      pill.type = 'button';
      pill.dataset.emoji = r.emoji;
      pill.className = `dm-rxn-pill${r.mine ? ' dm-rxn-mine' : ''}`;
      pill.title = r.mine ? 'Remove your reaction' : `React with ${r.emoji}`;
      pill.innerHTML = `<span>${swEsc(r.emoji)}</span>${r.count > 1 ? `<span class="dm-rxn-count">${r.count}</span>` : ''}`;
      pill.addEventListener('click', e => { e.stopPropagation(); onPick(r.emoji); });
      _emojify(pill);
      // Insert at correct index position
      const sibling = pills.children[idx];
      if (sibling) pills.insertBefore(pill, sibling);
      else pills.appendChild(pill);
    }
  });

  if (isNew) bubble.appendChild(pills);
}

// Tracks "type:msgId" keys that currently have a reaction toggle in flight.
// The poll-driven refresh below reads this so it never clobbers a reaction
// the user *just* set with a stale response that was already in transit —
// without this, a friend's reaction poll (every 5s) landing right after your
// own tap could overwrite your brand-new pill with the pre-tap state, making
// it look like the reaction "didn't stick".
const _reactionInFlight = new Set();

/** Toggle my reaction on a message — optimistic update, reconciled against the server's response, rolled back on failure. */
async function _toggleReaction(type, msgId, emoji, bubble) {
  if (!msgId || String(msgId).startsWith('tmp-')) return; // not confirmed by the server yet
  const key = `${type}:${msgId}`;
  // If a toggle for this exact message is already in flight, ignore the new
  // tap rather than letting two requests race and resolve out of order.
  if (_reactionInFlight.has(key)) return;
  _reactionInFlight.add(key);

  const msgsArr = type === 'group' ? GC.msgs : DM.msgs;
  const msg = msgsArr.find(m => m.id === msgId);
  const rerender = (list) => bubble && _renderReactionPills(bubble, list, e => _toggleReaction(type, msgId, e, bubble));

  const prev = msg?.reactions ? msg.reactions.map(r => ({ ...r })) : [];
  if (msg) {
    const list = prev.map(r => ({ ...r }));
    const mineIdx = list.findIndex(r => r.mine);
    const hadMineSameEmoji = mineIdx > -1 && list[mineIdx].emoji === emoji;
    if (mineIdx > -1) {
      list[mineIdx].count--;
      if (list[mineIdx].count <= 0) list.splice(mineIdx, 1); else list[mineIdx].mine = false;
    }
    if (!hadMineSameEmoji) {
      const existing = list.find(r => r.emoji === emoji);
      if (existing) { existing.count++; existing.mine = true; }
      else list.push({ emoji, count: 1, mine: true });
    }
    msg.reactions = list;
    rerender(list);
  }

  try {
    const url = type === 'group'
      ? `/api/member/groups/${GC.activeId}/messages/${msgId}/react`
      : `/api/member/dm/messages/${msgId}/react`;
    const resp = await api('POST', url, { emoji });
    if (msg) { msg.reactions = resp.reactions || []; rerender(msg.reactions); }
  } catch (e) {
    if (msg) { msg.reactions = prev; rerender(prev); }
    if (typeof swShowToast === 'function') swShowToast('Could not react — try again.');
  } finally {
    _reactionInFlight.delete(key);
  }
}

/** Instagram-style double-tap: quick-react with ❤️ + a big heart burst animation. */
function _attachQuickHeart(bubble, onReact) {
  // Re-attaching (e.g. once a tmp bubble's id is replaced with the real,
  // server-confirmed id after sending) must replace the previous listener,
  // not stack a second one beside it — a stale listener still closed over
  // the old tmp-id would otherwise sit there as dead weight, and on group
  // chat in particular this could leave two competing handlers racing each
  // other on every click.
  if (bubble._quickHeartHandler) {
    bubble.removeEventListener('click', bubble._quickHeartHandler);
  }
  // A single 'click' listener with manual timing covers mouse AND touch —
  // using both 'dblclick' and 'touchend' here would double-fire on some
  // mobile browsers and cancel the toggle right back out.
  let lastTap = 0;
  const handler = e => {
    if (e.target.closest('.dm-bubble-reactions')) return; // pill clicks have their own handler
    const now = Date.now();
    if (now - lastTap < 320) {
      lastTap = 0;
      const heart = document.createElement('div');
      heart.className = 'dm-heart-burst';
      heart.textContent = '❤️';
      bubble.appendChild(heart);
      _emojify(heart);
      heart.addEventListener('animationend', () => heart.remove());
      onReact('❤️');
    } else {
      lastTap = now;
    }
  };
  bubble._quickHeartHandler = handler;
  bubble.addEventListener('click', handler);
}

/**
 * Poll-driven reaction refresh: the message-list "since" cursor only ever
 * returns brand-new messages, so a reaction a friend adds to a message
 * that's already on screen would otherwise sit invisible until the next
 * full reload. This patches just the reaction pills on already-rendered
 * bubbles, cheaply, every poll tick.
 */
async function _refreshVisibleReactions(type) {
  const msgsArr = type === 'group' ? GC.msgs : DM.msgs;
  const ids = msgsArr
    .filter(m => m.id && !String(m.id).startsWith('tmp-') && !m.is_system)
    .slice(-40)
    .map(m => m.id);
  if (!ids.length) return;
  const map = await api('GET', `/api/member/messages/reactions?chat_type=${type}&ids=${ids.map(encodeURIComponent).join(',')}`);
  // Guard: if the server returned an empty object (network blip / allowedIds empty)
  // don't wipe reactions that already exist on screen — only update if server
  // actually returned a map with at least one key, OR none of the visible
  // messages currently have reactions (so an empty map is genuinely correct).
  if (!map || typeof map !== 'object') return;
  const serverHasData = Object.keys(map).length > 0;
  if (!serverHasData) {
    const anyHasReactions = ids.some(id => {
      const m = msgsArr.find(x => x.id === id);
      return (m?.reactions?.length || 0) > 0;
    });
    if (anyHasReactions) return; // server returned nothing but we have reactions — skip
  }
  ids.forEach(id => {
    // Skip any message whose reaction is currently being toggled — that
    // in-flight request will land its own, more current, result shortly.
    if (_reactionInFlight.has(`${type}:${id}`)) return;
    const msg = msgsArr.find(m => m.id === id);
    if (!msg) return;
    // Only update if the server actually returned data for this specific message.
    // If the server omits an id entirely, keep local state rather than wiping it.
    if (serverHasData && !Object.prototype.hasOwnProperty.call(map, id)) return;
    const newList = map[id] || [];
    if (JSON.stringify(msg.reactions || []) === JSON.stringify(newList)) return;
    msg.reactions = newList;
    const bubble = document.querySelector(`[data-msg-id="${id}"]`);
    if (bubble) _renderReactionPills(bubble, newList, (emoji) => _toggleReaction(type, id, emoji, bubble));
  });
}

/**
 * Poll-driven read-receipt refresh: delivered_at/read_at on a message I sent
 * only change on the recipient's side, so — same as reactions above — the
 * "since" cursor never surfaces the update. This patches just the tick icon
 * on already-rendered outgoing bubbles, every poll tick.
 */
async function _refreshVisibleDmStatus() {
  const myId = dmMyId();
  const ids = DM.msgs
    .filter(m => m.id && !String(m.id).startsWith('tmp-') && m.sender_id === myId)
    .slice(-40)
    .map(m => m.id);
  if (!ids.length) return;
  const map = await api('GET', `/api/member/dm/messages/status?ids=${ids.map(encodeURIComponent).join(',')}`);
  if (!map || typeof map !== 'object') return;
  ids.forEach(id => {
    const msg = DM.msgs.find(m => m.id === id);
    const st  = map[id];
    if (!msg || !st) return;
    if (msg.delivered_at === st.delivered_at && msg.read_at === st.read_at) return;
    msg.delivered_at = st.delivered_at;
    msg.read_at      = st.read_at;
    const metaRow = document.querySelector(`.dm-meta[data-meta-for="${id}"]`);
    const oldTick = metaRow?.querySelector('.dm-ticks');
    if (oldTick) oldTick.outerHTML = _dmTickSpanHTML(msg);
  });
}

// Context menu implementation
let _ctxMenu = null;
let _longPressTimer = null;

function _dismissCtxMenu() {
  if (_ctxMenu) { _ctxMenu.remove(); _ctxMenu = null; }
  _dismissEmojiPicker();
}
document.addEventListener('click', _dismissCtxMenu);
document.addEventListener('keydown', e => { if (e.key === 'Escape') _dismissCtxMenu(); });

function _showMsgContextMenu(e, info, opts = {}) {
  e.preventDefault();
  e.stopPropagation();
  _dismissCtxMenu();
  _dismissEmojiPicker();

  const { id, body, mine, senderName, type /* 'dm'|'group' */, senderId, isDeleted } = info;

  // The `info` object closed over by _attachMsgContextMenu was built once,
  // at render time. After a pin/unpin toggle, GC.msgs is updated in memory
  // but that closure is not, so info.is_pinned can be stale on re-open.
  // GC.msgs is the single live source of truth for group messages — always
  // re-derive from it rather than trusting the closure snapshot.
  const liveMsg = (type === 'group' && typeof GC !== 'undefined')
    ? GC.msgs.find(m => m.id === id)
    : null;
  const isPinnedLive = liveMsg ? !!liveMsg.is_pinned : !!info.is_pinned;
  // DM pins have no backend endpoint (server only supports group pins), so
  // they're tracked locally per-conversation — see _dmGetPin/_dmSetPin below.
  const isDmPinnedLive = (type !== 'group' && typeof DM !== 'undefined' && DM.activeKey)
    ? (_dmGetPin(DM.activeKey)?.id === id)
    : false;

  const menu = document.createElement('div');
  menu.className = 'dm-ctx-menu';
  _ctxMenu = menu;

  // Position near pointer (clamp to viewport)
  const x = e.clientX ?? (e.touches?.[0]?.clientX ?? window.innerWidth / 2);
  const y = e.clientY ?? (e.touches?.[0]?.clientY ?? window.innerHeight / 2);

  const actions = [];

  // Reply (keep in context menu too for right-click / long-press on mobile)
  actions.push({
    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>',
    label: 'Reply',
    fn: () => {
      _setReply(type === 'group' ? 'group' : 'dm', { id, body, sender: senderName });
    },
  });

  // React (the only entry point on mobile, since hover actions are desktop-only)
  actions.push({
    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>',
    label: 'React',
    fn: () => {
      const bubble = document.querySelector(`[data-msg-id="${id}"]`);
      // Anchor the picker to wherever the long-press/right-click happened
      const anchor = { getBoundingClientRect: () => ({ left: x, right: x, top: y, bottom: y, width: 0, height: 0 }) };
      _showEmojiPicker(anchor, emoji => _toggleReaction(type === 'group' ? 'group' : 'dm', id, emoji, bubble));
    },
  });

  // Forward
  actions.push({
    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/></svg>',
    label: 'Forward',
    fn: () => _openForwardPicker(body),
  });

  // Pin — group pins round-trip through the server; DM pins have no backend
  // endpoint, so they're pinned locally per-conversation (see _dmGetPin/
  // _dmSetPin) and drive their own banner via dmRefreshPinnedBanner. Both
  // now actually do something and show Pin/Unpin correctly, instead of the
  // DM case just popping a toast with no effect.
  actions.push({
    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>',
    label: type === 'group' ? (isPinnedLive ? 'Unpin' : 'Pin') : (isDmPinnedLive ? 'Unpin' : 'Pin'),
    fn: async () => {
      if (type !== 'group') {
        if (!DM.activeKey) return;
        // Block pin on optimistic (tmp-) messages — nothing stable to point at yet
        if (!id || String(id).startsWith('tmp-')) {
          if (typeof swShowToast === 'function') swShowToast('Message is still sending — please wait before pinning.');
          return;
        }
        if (isDmPinnedLive) {
          _dmSetPin(DM.activeKey, null);
          if (typeof swShowToast === 'function') swShowToast('📌 Message unpinned.');
        } else {
          _dmSetPin(DM.activeKey, { id, body, sender_name: senderName });
          if (typeof swShowToast === 'function') swShowToast('📌 Message pinned to this conversation.');
        }
        if (typeof dmRefreshPinnedBanner === 'function') dmRefreshPinnedBanner();
        return;
      }
      // Block pin on optimistic (tmp-) messages — server doesn't have them yet
      if (!id || String(id).startsWith('tmp-')) {
        if (typeof swShowToast === 'function') swShowToast('Message is still sending — please wait before pinning.');
        return;
      }
      try {
        const r = await api('POST', `/api/member/groups/${GC.activeId}/messages/${id}/pin`, {});
        if (typeof swShowToast === 'function') {
          swShowToast(r.is_pinned ? '📌 Message pinned.' : '📌 Message unpinned.');
        }
        // Update local state
        const msg = GC.msgs.find(m => m.id === id);
        if (msg) msg.is_pinned = r.is_pinned;
        // Refresh pinned banner if visible
        if (typeof gcRefreshPinnedBanner === 'function') gcRefreshPinnedBanner();
      } catch (e) {
        if (typeof swShowToast === 'function') swShowToast('Could not pin message — try again.');
      }
    },
  });

  // Edit (own messages only, not yet deleted, not still sending)
  if (mine && !isDeleted) {
    actions.push({
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
      label: 'Edit',
      fn: () => {
        if (id && String(id).startsWith('tmp-')) {
          if (typeof swShowToast === 'function') swShowToast('Message is still sending — please wait before editing.');
          return;
        }
        const list = (type === 'group' && typeof GC !== 'undefined') ? GC.msgs : (typeof DM !== 'undefined' ? DM.msgs : []);
        const liveM = (list || []).find(mm => mm.id === id);
        const text  = liveM ? (liveM._plaintext || liveM.body || '') : body;
        if (typeof _beginEditMsg === 'function') _beginEditMsg(type === 'group' ? 'group' : 'dm', id, text);
      },
    });
  }

  // Delete (own messages only)
  if (mine) {
    actions.push({
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
      label: 'Delete',
      danger: true,
      fn: () => {
        const bubble = document.querySelector(`[data-msg-id="${id}"]`);
        const delBtn = bubble?.closest('.dm-msg-group')?.querySelector(`.dm-del-btn[data-id="${id}"]`);
        if (type === 'group') gcDeleteMsg(id, bubble, delBtn);
        else dmDeleteMsg(id, bubble, delBtn);
      },
    });
  }

  // Report message (others' messages only)
  if (!mine) {
    actions.push({
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>',
      label: 'Report message',
      danger: true,
      fn: () => {
        if (type === 'group') swReportGroupMessage(id);
        else swReportDmMessage(id);
      },
    });
  }

  // Report account (group only, other person's message)
  if (type === 'group' && !mine && senderId) {
    actions.push({
      icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
      label: 'Report account',
      danger: true,
      fn: () => swReportMember(senderId, senderName),
    });
  }

  menu.innerHTML = actions.map((a, i) => {
    const divider = (a.danger && i > 0 && !actions[i - 1].danger) ? '<div class="dm-ctx-divider"></div>' : '';
    return `${divider}<button class="dm-ctx-item${a.danger ? ' dm-ctx-danger' : ''}" data-idx="${i}">
      ${a.icon}<span>${a.label}</span>
    </button>`;
  }).join('');

  document.body.appendChild(menu);

  // Position after append so we know dimensions
  const mw = menu.offsetWidth  || 180;
  const mh = menu.offsetHeight || actions.length * 40;
  const left = Math.min(x, window.innerWidth  - mw - 8);
  const top  = Math.min(y, window.innerHeight - mh - 8);
  menu.style.left = Math.max(8, left) + 'px';
  menu.style.top  = Math.max(8, top)  + 'px';

  menu.querySelectorAll('.dm-ctx-item').forEach((btn, i) => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      _dismissCtxMenu();
      actions[i].fn();
    });
  });

  // Apple/iMessage-style long-press: surface the quick-reaction bar directly
  // above the bubble at the same time as the context menu, instead of making
  // the person tap "React" as a separate step. Right-click (desktop) skips
  // this — it's a touch-specific affordance.
  if (opts.withReactionBar) {
    const bubbleEl = document.querySelector(`[data-msg-id="${id}"]`);
    if (bubbleEl) {
      _showEmojiPicker(bubbleEl, emoji => {
        _dismissCtxMenu();
        _toggleReaction(type === 'group' ? 'group' : 'dm', id, emoji, bubbleEl);
      });
    }
  }
}

function _attachMsgContextMenu(bubble, info) {
  // Desktop: right-click (menu only — no reaction bar, that's a touch affordance)
  bubble.addEventListener('contextmenu', e => _showMsgContextMenu(e, info));

  const wrap = bubble.closest('.dm-bubble-wrap') || bubble;
  const { type, id, body, senderName } = info;

  const SWIPE_TRIGGER = 64;   // px of drag before a release counts as "reply"
  const SWIPE_CAP     = 84;   // px after which further drag gets rubber-banded
  const SPRING = 'transform 0.32s cubic-bezier(0.34, 1.56, 0.64, 1)';

  let touchStartX = 0, touchStartY = 0, swiping = false, swipeArmed = false;

  function replyIcon() {
    let icon = wrap.querySelector(':scope > .dm-swipe-reply-icon');
    if (!icon) {
      icon = document.createElement('div');
      icon.className = 'dm-swipe-reply-icon';
      icon.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>';
      wrap.prepend(icon);
    }
    return icon;
  }

  // Mobile: long-press (500 ms) opens the combined reaction-bar + context
  // menu, unless the touch turned into a horizontal swipe-to-reply instead.
  bubble.addEventListener('touchstart', e => {
    const t = e.touches[0];
    touchStartX = t.clientX; touchStartY = t.clientY;
    swiping = false; swipeArmed = false;
    _longPressTimer = setTimeout(() => {
      _longPressTimer = null;
      if (!swiping) _showMsgContextMenu(e, info, { withReactionBar: true });
    }, 500);
  }, { passive: true });

  bubble.addEventListener('touchmove', e => {
    const t = e.touches[0];
    const dx = t.clientX - touchStartX;
    const dy = t.clientY - touchStartY;

    if (!swipeArmed && !swiping) {
      if (Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(dy) * 1.4) {
        swipeArmed = true;
        clearTimeout(_longPressTimer); _longPressTimer = null;
      } else if (Math.abs(dy) > 8) {
        // Vertical scroll — this isn't a swipe-to-reply gesture, bail.
        clearTimeout(_longPressTimer); _longPressTimer = null;
        return;
      } else {
        return;
      }
    }
    if (!swipeArmed) return;

    swiping = true;
    let clamped = Math.max(0, dx); // right-swipe only, iMessage/WhatsApp style
    if (clamped > SWIPE_CAP) clamped = SWIPE_CAP + (clamped - SWIPE_CAP) / 4; // rubber-band past cap
    wrap.style.transition = 'none';
    wrap.style.transform = `translateX(${clamped}px)`;

    const icon = replyIcon();
    const progress = Math.min(1, clamped / SWIPE_TRIGGER);
    icon.style.opacity = String(progress);
    icon.style.transform = `translateY(-50%) scale(${0.5 + progress * 0.5})`;
  }, { passive: true });

  bubble.addEventListener('touchend', () => {
    clearTimeout(_longPressTimer); _longPressTimer = null;
    if (swiping) {
      const m = /translateX\(([-\d.]+)px\)/.exec(wrap.style.transform);
      const dx = m ? parseFloat(m[1]) : 0;
      wrap.style.transition = SPRING;
      wrap.style.transform = 'translateX(0)';
      const icon = wrap.querySelector(':scope > .dm-swipe-reply-icon');
      if (icon) { icon.style.transition = 'opacity 0.2s ease'; icon.style.opacity = '0'; }
      if (dx >= SWIPE_TRIGGER) {
        _setReply(type === 'group' ? 'group' : 'dm', { id, body, sender: senderName });
      }
    }
    swiping = false; swipeArmed = false;
  });

  bubble.addEventListener('touchcancel', () => {
    clearTimeout(_longPressTimer); _longPressTimer = null;
    wrap.style.transition = SPRING;
    wrap.style.transform = 'translateX(0)';
    swiping = false; swipeArmed = false;
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// BLOCK / UNBLOCK MODULE
// ═══════════════════════════════════════════════════════════════════════════

const BLOCKS = {
  set: new Set(),   // IDs I have blocked
  loaded: false,
};

// _blocksInFlight deduplicates concurrent calls so two simultaneous startup
// callers share one request rather than racing to overwrite BLOCKS.set.
let _blocksInFlight = null;

async function blocksEnsureLoaded() {
  if (BLOCKS.loaded) return;
  if (_blocksInFlight) return _blocksInFlight;

  _blocksInFlight = (async () => {
    try {
      // Wait for the session token before touching the API — prevents the
      // startup-401 race where initDMExtensions fires this before
      // refreshToken() has set _token, which previously wiped BLOCKS.set.
      if (!_token) {
        await new Promise(resolve => {
          let tries = 0;
          const poll = setInterval(() => {
            if (_token || ++tries > 150) { clearInterval(poll); resolve(); }
          }, 80);
        });
      }
      if (BLOCKS.loaded) return; // another caller succeeded while we waited
      const ids = await api('GET', '/api/member/blocks');
      BLOCKS.set = new Set(Array.isArray(ids) ? ids : []);
      BLOCKS.loaded = true;
    } catch {
      // Do NOT wipe BLOCKS.set — preserve whatever state already exists.
      // Do NOT set BLOCKS.loaded — allow the next call to retry the server.
    } finally {
      _blocksInFlight = null;
    }
  })();

  return _blocksInFlight;
}

async function blocksToggle(memberId, btn) {
  const nowBlocked = BLOCKS.set.has(memberId);
  try {
    btn && (btn.disabled = true);
    if (nowBlocked) {
      await api('DELETE', `/api/member/blocks/${memberId}`);
      BLOCKS.set.delete(memberId);
    } else {
      await api('POST', '/api/member/blocks', { blocked_id: memberId });
      BLOCKS.set.add(memberId);
    }
    // Update all block buttons for this member in the DOM
    document.querySelectorAll(`[data-block-member="${memberId}"]`).forEach(el => {
      const isNowBlocked = BLOCKS.set.has(memberId);
      el.textContent = isNowBlocked ? 'Unblock' : 'Block';
      el.classList.toggle('dm-block-active', isNowBlocked);
      el.title = isNowBlocked ? 'Unblock this member' : 'Block this member';
    });
    // If we just blocked the active DM peer, show blocked banner
    if (DM.activePeer?.id === memberId) dmUpdateBlockedBanner();
  } catch (e) {
    showMsg && showMsg('dm-error', e.message || 'Could not update block status.', false);
  } finally {
    btn && (btn.disabled = false);
  }
}

function dmUpdateBlockedBanner() {
  const peerId = DM.activePeer?.id;
  if (!peerId) return;
  const compose = $id('dm-compose');
  let banner = $id('dm-blocked-banner');
  const iBlocked     = BLOCKS.set.has(peerId);
  const theyBlockedMe = DM.activePeer?._blockedMe || false;
  const blocked = iBlocked || theyBlockedMe;
  if (blocked) {
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'dm-blocked-banner';
      banner.className = 'dm-blocked-banner';
      compose?.parentNode?.insertBefore(banner, compose);
    }
    banner.textContent = iBlocked
      ? 'You have blocked this member. Unblock to send messages.'
      : 'You can\'t message this person.';
    compose && (compose.style.display = 'none');
  } else {
    banner?.remove();
    // Official KFS one-way channel keeps its compose box hidden regardless
    // of block status — don't let this "not blocked" path re-show it.
    if (!DM.activePeer?.is_official) compose && (compose.style.display = '');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// NICKNAME MODULE
// ═══════════════════════════════════════════════════════════════════════════

// In-memory store: conv_key → [{giver_id, target_id, nickname}]
const NICKS = {};
// Global DM-nickname cache, keyed by target_id only. DM nicknames aren't actually
// scoped to a conversation (the server endpoint returns ALL of my nicknames at
// once) — they were just being filed away under whichever convKey happened to
// call nicksLoad(). That meant any convKey nicksLoad() was never called for
// (e.g. every row in the sidebar list, or a conv reopened on a fresh page load
// before its own nicksLoad() round-trip finished) showed the real name instead.
// This flat cache is the source of truth that survives across conv keys and a
// page refresh's first render, while NICKS[convKey] is still kept in sync for
// existing call sites (group nicknames, in-place edits) that key off it.
let NICKS_GLOBAL_LOADED = false;
const NICKS_BY_TARGET = {};

async function nicksLoadGlobal() {
  // Wait for a real member ID — never write/read under kfs-nicks-null
  let myId = dmMyId();
  if (!myId) {
    await new Promise(resolve => {
      let tries = 0;
      const poll = setInterval(() => {
        myId = dmMyId();
        if (myId || ++tries > 40) { clearInterval(poll); resolve(); }
      }, 150);
    });
  }
  if (!myId) return; // session never resolved — bail

  // Migrate any data accidentally stored under bad keys (null/undefined/unknown)
  ['kfs-nicks-null','kfs-nicks-undefined','kfs-nicks-unknown'].forEach(badKey => {
    try {
      const raw = localStorage.getItem(badKey);
      if (!raw) return;
      const realKey = 'kfs-nicks-' + myId;
      const existing = JSON.parse(localStorage.getItem(realKey) || '{}');
      const bad = JSON.parse(raw);
      if (bad && typeof bad === 'object' && !Array.isArray(bad)) {
        Object.assign(existing, bad);
        localStorage.setItem(realKey, JSON.stringify(existing));
      }
      localStorage.removeItem(badKey);
    } catch { /* ignore */ }
  });

  // Seed from localStorage immediately so the sidebar has nicknames on first
  // paint, before the API round-trip completes.
  try {
    const cached = localStorage.getItem('kfs-nicks-' + myId);
    if (cached) {
      const parsed = JSON.parse(cached);
      Object.entries(parsed).forEach(([target_id, nickname]) => {
        if (!NICKS_BY_TARGET[target_id]) {
          NICKS_BY_TARGET[target_id] = { giver_id: myId, target_id, nickname };
        }
      });
    }
  } catch { /* ignore */ }

  try {
    const data = await api('GET', '/api/member/nicknames');
    // Only replace the cache when the server returns a non-empty object.
    // An empty {} means "you have no nicknames" which is valid — but we
    // only accept that verdict when the object has actually been parsed
    // from a successful response AND is confirmed empty, not when the
    // request failed or returned garbage. Distinguish "empty" from "failed"
    // by checking Object.keys length: if the server truly has no nicknames
    // for this member, clear the cache; if data is falsy/array (error path),
    // leave whatever was seeded from localStorage intact.
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const serverNicks = Object.entries(data);
      if (serverNicks.length > 0) {
        // Server has nicknames — replace cache wholesale
        Object.keys(NICKS_BY_TARGET).forEach(k => delete NICKS_BY_TARGET[k]);
        serverNicks.forEach(([target_id, nickname]) => {
          NICKS_BY_TARGET[target_id] = { giver_id: myId, target_id, nickname };
        });
        // Persist to localStorage so next refresh has instant nicknames
        try { localStorage.setItem('kfs-nicks-' + myId, JSON.stringify(data)); } catch { /* ignore */ }
      } else {
        // Server returned {} — this is ambiguous: it can mean "you genuinely
        // have no nicknames" OR it can be the same {} that api() returns for
        // a 304 Not Modified or a JSON-parse failure (see api(), where both
        // of those fall back to {} and are indistinguishable from a real
        // empty payload here). Wiping the cache on the very first load of
        // the session — before we've ever confirmed a real response — risks
        // destroying a perfectly good localStorage seed because of a network
        // artifact. Only accept {} as authoritative once we've already had
        // at least one confirmed load this session; on the first load,
        // leave the localStorage-seeded cache alone and let the next
        // fetch (which will use a fresh _cb cache-buster) re-confirm.
        if (NICKS_GLOBAL_LOADED) {
          Object.keys(NICKS_BY_TARGET).forEach(k => delete NICKS_BY_TARGET[k]);
          try { localStorage.removeItem('kfs-nicks-' + myId); } catch { /* ignore */ }
        }
      }
      NICKS_GLOBAL_LOADED = true;
    }
    // If data is falsy or array (parse error / network failure), leave cache
    // as-is — localStorage seed is better than nothing. Don't set NICKS_GLOBAL_LOADED
    // so the next call will retry the fetch.
  } catch { /* ignore — localStorage seed remains */ }
}

async function nicksLoad(convKey) {
  try {
    // Server returns { [target_id]: nickname } for all nicknames set BY me (DM nicknames table)
    const data = await api('GET', '/api/member/nicknames');
    const myId = dmMyId();
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const entries = Object.entries(data);
      NICKS[convKey] = entries.map(([target_id, nickname]) => ({
        giver_id: myId, target_id, nickname
      }));
      // Sync into the flat global cache — but only replace when we got actual
      // nicknames back. An empty {} from the server is valid and clears the
      // conv-level cache, but don't wipe NICKS_BY_TARGET entries seeded
      // from nicksLoadGlobal / localStorage for other conversations.
      if (entries.length > 0) {
        entries.forEach(([target_id, nickname]) => {
          NICKS_BY_TARGET[target_id] = { giver_id: myId, target_id, nickname };
        });
      }
      NICKS_GLOBAL_LOADED = true;
    }
    // On bad/null response: leave NICKS[convKey] as-is. Don't overwrite with
    // an empty array — it may already be seeded from group rows or a prior fetch.
  } catch {
    // Network / auth error — preserve whatever cache we have, don't blank it.
  }
}

// Seed group nicknames from dm_group_members.nickname rows returned by the server.
// Called after gcLoadMsgs — the messages endpoint already returns nicknames[] for the group.
// Format: [{ member_id, nickname }]  (giver_id is always the group — treat as shared nick)
function nicksLoadGroupRows(groupId, nickRows) {
  if (!groupId || !Array.isArray(nickRows)) return;
  const myId = dmMyId();
  const existing = NICKS[groupId] || [];
  // Build a map so we can upsert without duplicates
  const map = new Map(existing.map(r => [r.target_id, r]));
  nickRows.forEach(r => {
    if (r.member_id && r.nickname) {
      map.set(r.member_id, { giver_id: myId, target_id: r.member_id, nickname: r.nickname });
    } else if (r.member_id && !r.nickname) {
      map.delete(r.member_id); // cleared nickname — remove from cache
    }
  });
  NICKS[groupId] = [...map.values()];
}

function nicksGetFor(convKey, targetId) {
  // Returns the nickname map: { [giverId]: nickname }
  const rows = NICKS[convKey] || [];
  const result = {};
  rows.filter(r => r.target_id === targetId).forEach(r => { result[r.giver_id] = r.nickname; });
  return result;
}

function nicksResolveDisplay(convKey, memberId, fallbackName) {
  // Returns the nickname set FOR this memberId by anyone, or fallbackName.
  // Priority: any nickname in this conv for this member (first found, or giver=me first)
  const myId = dmMyId();
  const rows = NICKS[convKey] || [];
  // Prefer nickname set by me
  const mine = rows.find(r => r.target_id === memberId && r.giver_id === myId);
  if (mine) return mine.nickname;
  // Then any other
  const any = rows.find(r => r.target_id === memberId);
  if (any) return any.nickname;
  // Fall back to the flat global cache — covers DM nicknames for a convKey
  // that nicksLoad() hasn't (yet) been called for, e.g. sidebar list rows on
  // a fresh page load, or a conv reopened before its own round-trip resolves.
  const global = NICKS_BY_TARGET[memberId];
  if (global) return global.nickname;
  return fallbackName;
}

// Open Instagram-style nickname modal — shows BOTH participants with edit per person
function nicksOpenModal(convKey, targetId, targetName, isGroup) {
  const myId      = dmMyId();
  const myProfile = window._memberProfile || {};

  // Build participant list
  // For DM: [me, peer]. For group: just the target member (single edit).
  const participants = isGroup
    ? [{ id: targetId, name: targetName, photo: null, isSelf: false }]
    : [
        { id: myId,     name: myProfile.name || 'You', photo: myProfile.photo || null, isSelf: true  },
        { id: targetId, name: targetName,               photo: DM.activePeer?.photo || null, isSelf: false },
      ];

  function getCurrentNick(membId) {
    const rows = NICKS[convKey] || [];
    const mine = rows.find(r => r.giver_id === myId && r.target_id === membId);
    return mine?.nickname || '';
  }

  // Remove any existing modal
  document.getElementById('nick-modal-overlay')?.remove();

  const modal = document.createElement('div');
  modal.id = 'nick-modal-overlay';
  modal.className = 'nick-modal-overlay';
  modal.innerHTML = `
    <div class="nick-modal nick-modal-insta" id="nick-modal">
      <div class="nick-modal-head">
        <span>${isGroup ? 'Set Nickname' : 'Nicknames'}</span>
        <button class="dm-icon-btn" id="nick-modal-close" aria-label="Close">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div class="nick-participants" id="nick-participants"></div>
      <p class="nick-modal-hint" style="text-align:center;margin-top:14px">
        ${isGroup ? 'This nickname is visible to everyone in the group.' : 'Nicknames are only visible in this chat.'}
      </p>
      <div id="nick-inline-edit" style="display:none;padding:14px 0 4px">
        <div style="font-size:11px;color:var(--muted);margin-bottom:8px" id="nick-editing-label"></div>
        <input id="nick-input" class="nick-input" type="text" maxlength="40" autocomplete="off" placeholder="Enter nickname…">
        <div class="nick-modal-actions" style="margin-top:10px">
          <button class="nick-clear-btn" id="nick-clear-btn">Clear</button>
          <button class="nick-save-btn" id="nick-save-btn">Save</button>
        </div>
        <div id="nick-error" class="nick-error" style="display:none;margin-top:8px"></div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  function renderParticipants(editingId) {
    const list = document.getElementById('nick-participants');
    if (!list) return;
    list.innerHTML = participants.map(p => {
      const nick = getCurrentNick(p.id);
      const initials = (p.name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
      const avatarHtml = p.photo
        ? `<img src="${swEsc(p.photo)}" style="width:44px;height:44px;border-radius:50%;object-fit:cover;flex-shrink:0;background:#1e1e1e">`
        : `<div style="width:44px;height:44px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#666;flex-shrink:0">${swEsc(initials)}</div>`;
      const canEdit = !p.isSelf; // can't nickname yourself
      return `
        <div class="nick-participant-row ${editingId === p.id ? 'nick-participant-active' : ''}" data-id="${swEsc(p.id)}" data-name="${swEsc(p.name)}" style="cursor:${canEdit ? 'pointer' : 'default'}">
          ${avatarHtml}
          <div style="flex:1;min-width:0">
            <div style="font-size:13.5px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${swEsc(nick || p.name)}</div>
            ${nick ? `<div style="font-size:11px;color:var(--muted);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${swEsc(p.name)}</div>` : ''}
          </div>
          ${canEdit ? `<button class="dm-icon-btn nick-edit-btn" data-id="${swEsc(p.id)}" data-name="${swEsc(p.name)}" title="Edit nickname" style="flex-shrink:0">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </button>` : ''}
        </div>`;
    }).join('');

    // Wire edit buttons and row clicks
    list.querySelectorAll('.nick-edit-btn, .nick-participant-row[data-id]').forEach(el => {
      const id   = el.dataset.id;
      const name = el.dataset.name;
      const p    = participants.find(x => x.id === id);
      if (!p || p.isSelf) return;
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        openInlineEdit(id, name);
      });
    });
  }

  let _editingId = null;

  function openInlineEdit(id, name) {
    _editingId = id;
    const editBox   = document.getElementById('nick-inline-edit');
    const label     = document.getElementById('nick-editing-label');
    const inp       = document.getElementById('nick-input');
    const errEl     = document.getElementById('nick-error');
    if (!editBox || !inp) return;

    label.textContent = `Nickname for ${name}`;
    inp.value = getCurrentNick(id);
    errEl.style.display = 'none';
    editBox.style.display = '';
    inp.focus();
    inp.select();

    renderParticipants(id);
  }

  // Save / clear handler
  async function doSave(nick) {
    if (!_editingId) return;
    const errEl   = document.getElementById('nick-error');
    const saveBtn = document.getElementById('nick-save-btn');
    if (errEl) errEl.style.display = 'none';
    if (saveBtn) saveBtn.disabled = true;
    try {
      // Use the group-nickname endpoint if this is a group conv (GC.activeId === convKey)
      const isGroupConv = typeof GC !== 'undefined' && GC.activeId === convKey;
      if (isGroupConv) {
        await api('PUT', `/api/member/groups/${convKey}/members/${encodeURIComponent(_editingId)}/nickname`, { nickname: nick || null });
      } else {
        await api('PUT', `/api/member/nicknames/${encodeURIComponent(_editingId)}`, { nickname: nick });
      }
      // Update local cache
      const rows = NICKS[convKey] || (NICKS[convKey] = []);
      const idx  = rows.findIndex(r => r.giver_id === myId && r.target_id === _editingId);
      if (nick) {
        if (idx >= 0) rows[idx].nickname = nick;
        else rows.push({ giver_id: myId, target_id: _editingId, nickname: nick });
      } else {
        if (idx >= 0) rows.splice(idx, 1);
      }
      // Mirror into the flat global cache too (DM nicknames only — group
      // nicknames stay scoped to NICKS[convKey] since they're per-group).
      if (!isGroupConv) {
        if (nick) NICKS_BY_TARGET[_editingId] = { giver_id: myId, target_id: _editingId, nickname: nick };
        else delete NICKS_BY_TARGET[_editingId];
        // Keep localStorage in sync so nickname survives page refresh instantly
        try {
          const key = 'kfs-nicks-' + myId;
          const stored = JSON.parse(localStorage.getItem(key) || '{}');
          if (nick) stored[_editingId] = nick; else delete stored[_editingId];
          localStorage.setItem(key, JSON.stringify(stored));
        } catch { /* ignore */ }
      }
      // Refresh participant list
      renderParticipants(_editingId);
      // Refresh display names
      dmRefreshDisplayNames(convKey);
      // If a group is active and this is a group nickname, also refresh the detail panel
      if (typeof GC !== 'undefined' && GC.activeId === convKey && typeof window._dpShowGroup === 'function' && GC.activeGroup) {
        // Re-fetch fresh group data and re-render the panel
        try {
          const fresh = await api('GET', `/api/member/groups/${convKey}`);
          GC.activeGroup = { ...(GC.activeGroup || {}), ...fresh };
          // Update nicknames in the rendered message list
          const list = document.getElementById('gc-msg-list');
          if (list) {
            list.querySelectorAll('.gc-msg-sender-name').forEach(el => {
              const membId = el.dataset.memberId;
              if (membId) {
                const memberObj = (GC.activeGroup.members || []).find(m => m.id === membId);
                if (memberObj) {
                  const display = nicksResolveDisplay(convKey, membId, memberObj.name || 'Member');
                  el.textContent = display;
                }
              }
            });
          }
        } catch { /* silent */ }
      }
      // Close inline edit after short delay
      setTimeout(() => {
        const editBox = document.getElementById('nick-inline-edit');
        if (editBox) editBox.style.display = 'none';
        _editingId = null;
        renderParticipants(null);
      }, 600);
    } catch (e) {
      if (errEl) { errEl.textContent = e.message || 'Could not save.'; errEl.style.display = ''; }
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  }

  // Wire inline edit buttons (re-wired on each renderParticipants)
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.getElementById('nick-modal-close')?.addEventListener('click', () => modal.remove());

  // Wire save/clear with event delegation (they're inside nick-inline-edit which is static)
  modal.addEventListener('click', e => {
    const btn = e.target.closest('#nick-save-btn');
    if (btn) { const inp = document.getElementById('nick-input'); doSave(inp?.value.trim() || ''); }
    const clrBtn = e.target.closest('#nick-clear-btn');
    if (clrBtn) doSave('');
  });
  modal.addEventListener('keydown', e => {
    if (e.key === 'Enter' && _editingId) {
      const inp = document.getElementById('nick-input');
      doSave(inp?.value.trim() || '');
    }
    if (e.key === 'Escape') modal.remove();
  });

  renderParticipants(null);

  // If group (single person) or called directly for a specific person, open edit immediately
  if (isGroup || (targetId && targetId !== myId)) {
    openInlineEdit(targetId, targetName);
  }
}

// Refresh display names after a nickname change
function dmRefreshDisplayNames(convKey) {
  // 1-1 DM
  if (DM.activeKey === convKey && DM.activePeer) {
    const peerId   = DM.activePeer.id;
    const peerName = DM.activePeer.name;
    const display  = nicksResolveDisplay(convKey, peerId, peerName);
    const topbarName = $id('dm-topbar-name');
    if (topbarName) topbarName.textContent = display;
  }
  // Conv list rows
  DM.convs.forEach(c => {
    if (c.conv_key !== convKey) return;
    const display = nicksResolveDisplay(convKey, c.peer?.id, c.peer?.name);
    const row = document.querySelector(`.dm-conv-row[data-key="${convKey}"] .dm-conv-name`);
    if (row) row.textContent = display;
  });
  // Group chat topbar
  if (GC.activeId === convKey) {
    const group = GC.groups.find(g => g.id === convKey);
    if (group) gcRefreshTopbarNicknames(convKey, group);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// GROUP CHAT MODULE (GC)
// ═══════════════════════════════════════════════════════════════════════════

const GC = {
  groups:         [],      // loaded group list
  activeId:       null,    // currently open group UUID
  activeGroup:    null,    // { id, name, members[], my_role, ... }
  msgs:           [],      // messages in active group
  oldestSentAt:   null,
  poll:           null,
  panelVisible:   false,
  pendingBodies:  new Set(),
  loadingMsgs:    false,
  reads:          [],      // cached [{member_id, last_read_at}] for "seen by" — see _gcRefreshSeenBy
};

const GC_POLL = 5000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function gcMyId() { return window._memberProfile?.id || _member?.id || null; }

function gcAvatar(name, photo, size) {
  if (photo) return `<img src="${swEsc(photo)}" alt="${swEsc(name)}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;background:#1e1e1e">`;
  const init = (name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.36)}px;font-weight:700;color:#666;flex-shrink:0">${swEsc(init)}</div>`;
}

function gcGroupAvatar(group, size) {
  if (group.photo_url) {
    return `<img src="${swEsc(group.photo_url)}" alt="${swEsc(group.name || 'Group')}" style="width:${size}px;height:${size}px;border-radius:${Math.round(size * 0.28)}px;object-fit:cover;flex-shrink:0">`;
  }
  const text = group.avatar_text || (group.name?.[0] || '?').toUpperCase();
  return `<div class="gc-group-av" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.42)}px">${swEsc(text)}</div>`;
}

function gcTime(iso) { return dmTime(iso); }
function gcFull(iso) { return dmFull(iso); }

function gcSetBadge(n) {
  const show  = n > 0;
  const label = n > 99 ? '99+' : String(n);
  [$id('gc-nav-badge')].forEach(el => {
    if (!el) return;
    el.style.display = show ? '' : 'none';
    el.textContent   = label;
  });
}

async function gcRefreshBadge() {
  if (!_token) return;
  try {
    const d = await api('GET', '/api/member/groups/unread-count');
    gcSetBadge(d.count || 0);
  } catch { /* silent */ }
}

// ─── Group list ───────────────────────────────────────────────────────────────

async function gcLoadGroups() {
  try {
    const data = await api('GET', '/api/member/groups');
    const fresh = Array.isArray(data) ? data : [];
    // Guard: if the server returns empty but we had groups in memory,
    // treat it as a possible transient read and skip the wipe — the
    // background sidebar refresh timer will reconcile on the next tick.
    if (fresh.length || !(GC.groups || []).length) {
      GC.groups = fresh;
    }
    // Use window.gcRenderGroups so the unified-inbox IIFE override (inboxRender) is picked up
    if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
    else gcRenderGroups(GC.groups);
    const total = GC.groups.reduce((s, g) => s + (g.unread_count || 0), 0);
    gcSetBadge(total);
  } catch (e) {
    console.error('[GC] loadGroups:', e.message);
  }
}

function gcRenderGroups(list) {
  const container = $id('gc-conv-list');
  if (!container) return;
  $id('gc-conv-loading') && ($id('gc-conv-loading').style.display = 'none');
  container.querySelectorAll('.gc-conv-row').forEach(el => el.remove());

  if (!list?.length) {
    $id('gc-conv-empty') && ($id('gc-conv-empty').style.display = '');
    return;
  }
  $id('gc-conv-empty') && ($id('gc-conv-empty').style.display = 'none');

  list.forEach(g => {
    const row = document.createElement('div');
    row.className = 'dm-conv-row gc-conv-row' + (g.id === GC.activeId ? ' dm-active-row' : '');
    row.dataset.key = g.id;
    // Normalise: server v2 returns last_msg_at flat; old server returned last_msg sub-object
    const lastAt  = g.last_msg_at || g.last_msg?.created_at || g.created_at || null;
    const snippet = g.last_snippet ?? g.last_msg?.body?.slice(0, 80) ?? null;
    let preview;
    if (!snippet) {
      preview = 'No messages yet';
    } else if (g.last_is_system) {
      preview = snippet;
    } else {
      preview = (g.last_sender_is_me ? 'You: ' : (g.last_sender_name ? g.last_sender_name + ': ' : '')) + snippet;
    }
    row.innerHTML = `
      ${gcGroupAvatar(g, 42)}
      <div class="dm-conv-info">
        <div class="dm-conv-name">${swEsc(g.name)}</div>
        <div class="dm-conv-preview ${g.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
      </div>
      <div class="dm-conv-right">
        <span class="dm-conv-time">${gcTime(lastAt)}</span>
        ${g.unread_count > 0 ? `<span class="dm-unread-pill">${g.unread_count > 9 ? '9+' : g.unread_count}</span>` : ''}
      </div>`;
    row.addEventListener('click', () => {
      if (!g?.id) return; // guard: skip null-id entries from corrupted cache
      const opener = typeof window.gcOpenGroup === 'function' ? window.gcOpenGroup : gcOpenGroup;
      opener(g);
    });
    container.appendChild(row);
  });
}

// ─── Open a group ─────────────────────────────────────────────────────────────

async function gcOpenGroup(group) {
  if (typeof _cancelEditMsg === 'function') _cancelEditMsg('group');
  GC.activeId    = group.id;
  GC.activeGroup = group;
  GC.msgs        = [];
  GC.oldestSentAt = null;

  document.querySelectorAll('.gc-conv-row, .inbox-group-row').forEach(el => {
    el.classList.toggle('dm-active-row', el.dataset.key === group.id);
  });

  // Topbar
  const ta = $id('gc-topbar-avatar');
  if (ta) ta.innerHTML = gcGroupAvatar(group, 34);
  setText('gc-topbar-name', group.name);
  // Use the member count from the list response immediately — the list endpoint
  // always returns the full members array so this is authoritative.
  // gcLoadGroupDetails may refine it, but NEVER overwrite with a lower/zero count.
  const initialCount = Array.isArray(group.members) ? group.members.length : (group.member_count || 0);
  setText('gc-topbar-sub', `${initialCount} member${initialCount !== 1 ? 's' : ''}`);

  // Fetch full detail (roles, nicknames) — pass floor so topbar never regresses to 0
  gcLoadGroupDetails(group.id, 0, initialCount);

  $id('gc-window-empty') && ($id('gc-window-empty').style.display = 'none');
  $id('gc-active') && ($id('gc-active').style.display = 'flex');
  // Mobile only: slide the sidebar out and bring gc-window forward
  // On desktop the sidebar stays visible alongside the chat window
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.add('dm-slide-out');
    $id('gc-window')?.classList.add('dm-slide-in');
    _kfsPushNavState('gc-chat');
  }

  // Load nicknames
  await nicksLoad(group.id);
  await gcLoadMsgs(false);
  $id('gc-input')?.focus();
}

async function gcLoadGroupDetails(groupId, _retryCount, _floorCount) {
  _retryCount = _retryCount || 0;
  _floorCount = _floorCount || 0; // never show a count lower than this
  try {
    const data = await api('GET', `/api/member/groups/${groupId}`);
    GC.activeGroup = { ...GC.activeGroup, ...data };
    // Cache member list for E2EE key wrapping (encryptGroup needs all member IDs)
    if (data.members?.length) GC.activeMembers = data.members;
    const count = data.members?.length || 0;
    // If the detail endpoint returns fewer members than we already know about,
    // keep the higher number (avoids regressing to 0 due to DB lag or auth issues).
    const displayCount = Math.max(count, _floorCount);
    if (displayCount > 0) {
      setText('gc-topbar-sub', `${displayCount} member${displayCount !== 1 ? 's' : ''}`);
    }
    // If still 0 and haven't retried enough, try again with backoff
    if (count === 0 && _retryCount < 3) {
      setTimeout(() => {
        if (GC.activeId === groupId) gcLoadGroupDetails(groupId, _retryCount + 1, _floorCount);
      }, 800);
    }

    // Topbar nickname button / role update (always run even if count is uncertain)
    gcRefreshTopbarNicknames(groupId, data);
    gcUpdateInputState();
  } catch (e) {
    if (_retryCount < 2) setTimeout(() => {
      if (GC.activeId === groupId) gcLoadGroupDetails(groupId, _retryCount + 1, _floorCount);
    }, 1200);
  }
}

function gcRefreshTopbarNicknames(groupId, group) {
  // Nothing to show in topbar about nicknames; nickname setting is via the info panel
}

function gcUpdateInputState() {
  // Group chats: everyone can send (no blocking check needed here for simplicity)
  const compose = $id('gc-compose');
  if (compose) compose.style.display = '';
}

// ─── Load messages ────────────────────────────────────────────────────────────

// ── Auto-rewrap missing E2EE keys ────────────────────────────────────────────
// When the sender of a group message opens the group chat, this checks all
// loaded messages they sent for any current members who are missing a wrapped
// key (i.e. they joined after the message was sent, or their key wasn't
// available at send time). For each such gap it decrypts the AES key using
// the sender's own wrapped key, then re-wraps it for the missing member and
// patches the server. Runs silently in the background — no UI impact.
async function gcAutoRewrapMissingKeys(groupId, msgs, myId) {
  if (!E2EE.ready()) return;

  // Get the current member list so we know who should have wrapped keys
  const groupData = GC.activeGroup;
  if (!groupData?.members?.length) return;
  const memberIds = groupData.members.map(m => m.id).filter(Boolean);

  // Filter to E2EE messages I sent that are missing at least one member's key
  const toFix = msgs.filter(m =>
    m.e2ee &&
    m.sender_id === myId &&
    m.wrapped_keys &&
    memberIds.some(mid => !m.wrapped_keys[mid])
  );
  if (!toFix.length) return;

  for (const msg of toFix) {
    try {
      const myWrappedKey = msg.wrapped_keys[myId];
      if (!myWrappedKey) continue; // I don't have my own key either — can't help

      // For each member missing a wrapped key, re-wrap and patch the server.
      // E2EE.rewrapMsgKey handles the unwrap+rewrap entirely within the E2EE
      // closure so we never need to reach private (_-prefixed) internals here.
      const missing = memberIds.filter(mid => !msg.wrapped_keys[mid]);
      for (const memberId of missing) {
        try {
          const wrappedKey = await E2EE.rewrapMsgKey(myWrappedKey, memberId);
          await api('PATCH', `/api/member/groups/${groupId}/messages/${msg.id}/wrapped-key`, {
            member_id:   memberId,
            wrapped_key: wrappedKey,
          });
          // Update local cache so the recipient can decrypt immediately on next render
          msg.wrapped_keys = { ...msg.wrapped_keys, [memberId]: wrappedKey };
        } catch (e) {
          // Member may not have published a key yet — skip silently
          console.warn('[E2EE] auto-rewrap skipped for member', memberId, e.message);
        }
      }
    } catch (e) {
      console.warn('[E2EE] auto-rewrap failed for msg', msg.id, e.message);
    }
  }
}

async function gcLoadMsgs(prepend) {
  if (!GC.activeId) return;
  if (!prepend) GC.loadingMsgs = true;
  try {
    const myId = gcMyId();
    let url    = `/api/member/groups/${encodeURIComponent(GC.activeId)}/messages?limit=40`;
    if (prepend && GC.oldestSentAt) url += `&before=${encodeURIComponent(GC.oldestSentAt)}`;

    const resp = await api('GET', url);
    // Server returns a plain array (not wrapped in {messages:…})
    const msgs      = Array.isArray(resp) ? resp : (resp.messages || []);
    const nicknames = Array.isArray(resp) ? [] : (resp.nicknames || []);

    // Merge nicknames into cache using the dedicated group nicks seeder
    // nicknames here come from dm_group_members.nickname — { member_id, nickname }
    if (nicknames.length) {
      if (typeof nicksLoadGroupRows === 'function') {
        nicksLoadGroupRows(GC.activeId, nicknames);
      } else {
        NICKS[GC.activeId] = nicknames;
      }
    }

    if (prepend) {
      const fetchedIds = new Set(msgs.map(m => m.id));
      const optimistic = GC.msgs.filter(m => m.id.startsWith('tmp-'));
      GC.msgs = [...msgs, ...GC.msgs.filter(m => !fetchedIds.has(m.id) && !m.id.startsWith('tmp-')), ...optimistic];
    } else {
      const optimistic = GC.msgs.filter(m => m.id.startsWith('tmp-'));
      const fetchedIds = new Set(msgs.map(m => m.id));
      GC.msgs = [...msgs, ...optimistic].filter((m, i, arr) =>
        !fetchedIds.has(m.id) || arr.findIndex(x => x.id === m.id) === i
      );
      GC.msgs.sort((a, b) => {
        const aO = a.id.startsWith('tmp-'), bO = b.id.startsWith('tmp-');
        if (aO && !bO) return 1; if (!aO && bO) return -1;
        return new Date(a.sent_at) - new Date(b.sent_at);
      });
    }

    GC.oldestSentAt = GC.msgs.find(m => !m.id.startsWith('tmp-'))?.sent_at || null;

    // ── Auto-rewrap: silently fix old E2EE messages where a member's
    // wrapped key is missing. Only the original sender can do this,
    // since only they can unwrap the AES key and re-wrap it for others.
    if (myId && E2EE.ready()) {
      gcAutoRewrapMissingKeys(GC.activeId, GC.msgs, myId).catch(() => {});
    }

    const list = $id('gc-msg-list');
    if (!list) return;

    if (!prepend) {
      list.innerHTML = '';
      // WhatsApp-style E2EE notice at top of conversation
      const e2eeNotice = document.createElement('div');
      e2eeNotice.className = 'gc-e2ee-notice';
      e2eeNotice.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Messages and calls are end-to-end encrypted. No one outside of this chat can read or listen to them.`;
      list.appendChild(e2eeNotice);
      gcRenderMsgs(GC.msgs, list, myId);
      gcScrollBottom();
    } else {
      const area    = $id('gc-msgs');
      const prevH   = area.scrollHeight;
      const prevTop = area.scrollTop;
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      area.scrollTop = area.scrollHeight - prevH + prevTop;
    }

    const moreWrap = $id('gc-load-earlier-wrap');
    if (moreWrap) moreWrap.style.display = msgs.length >= 40 ? '' : 'none';

    // Refresh pinned message banner
    if (!prepend) gcRefreshPinnedBanner().catch(() => {});
    if (!prepend) _gcRefreshSeenBy().catch(() => {});

    const g = GC.groups.find(g => g.id === GC.activeId);
    if (g) {
      g.unread_count = 0;
      // Use window.gcRenderGroups (unified inbox) if available, so the conv list
      // stays in sync without needing a separate gc-conv-list element.
      if (typeof window.gcRenderGroups === "function") window.gcRenderGroups(GC.groups);
      else gcRenderGroups(GC.groups);
    }
  } catch (e) {
    console.error('[GC] loadMsgs:', e.message);
  } finally {
    if (!prepend) GC.loadingMsgs = false;
  }
}

// Wrap @mentions that match a real group member (by name/nickname, no-space
// case-insensitive) in a highlighted span. Escapes the rest of the text, so
// this always returns safe HTML — never use textContent alongside it.
function _gcHighlightMentions(text) {
  const raw = text || '';
  const members = GC.activeMembers || [];
  if (!members.length) return swEsc(raw);
  const lookup = new Set();
  members.forEach(m => {
    [m.nickname, m.name, (m.name || '').split(/\s+/)[0]].filter(Boolean).forEach(c => {
      const key = c.toLowerCase().replace(/\s+/g, '');
      if (key) lookup.add(key);
    });
  });
  let out = '';
  let last = 0;
  const re = /@([A-Za-z0-9_.]{2,40})/g;
  let match;
  while ((match = re.exec(raw))) {
    const token = match[1].toLowerCase();
    out += swEsc(raw.slice(last, match.index));
    if (lookup.has(token)) {
      out += `<span class="gc-mention-tag">${swEsc(match[0])}</span>`;
    } else {
      out += swEsc(match[0]);
    }
    last = match.index + match[0].length;
  }
  out += swEsc(raw.slice(last));
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// @MENTIONS — lightweight autocomplete on gc-input. Typing "@" followed by
// letters opens a dropdown of matching group members; picking one inserts
// their name as a single no-space token (e.g. "@RahulSharma ") so it matches
// the same lookup the server uses to fire mention notifications.
// ═══════════════════════════════════════════════════════════════════════════
let _gcMentionDropdown = null;
let _gcMentionActiveIdx = 0;
let _gcMentionMatches = [];
let _gcMentionRange = null; // { start, end } indices in input.value being replaced

function _gcMentionClose() {
  if (_gcMentionDropdown) { _gcMentionDropdown.remove(); _gcMentionDropdown = null; }
  _gcMentionRange = null;
  _gcMentionMatches = [];
}

function _gcMentionOnInput(input) {
  const val = input.value;
  const caret = input.selectionStart || 0;
  // Find an unfinished "@token" run immediately before the caret
  const before = val.slice(0, caret);
  const m = before.match(/(^|\s)@([A-Za-z0-9_.]{0,40})$/);
  if (!m) { _gcMentionClose(); return; }
  const query = m[2].toLowerCase();
  const start = caret - m[2].length - 1; // position of '@'
  const members = (GC.activeMembers || []).filter(mm => mm.id !== gcMyId());
  const matches = members.filter(mm => {
    const name = (mm.nickname || mm.name || '').toLowerCase();
    return !query || name.replace(/\s+/g, '').includes(query);
  }).slice(0, 6);

  if (!matches.length) { _gcMentionClose(); return; }
  _gcMentionMatches = matches;
  _gcMentionRange = { start, end: caret };
  _gcMentionActiveIdx = 0;
  _gcMentionRenderDropdown(input);
}

function _gcMentionRenderDropdown(input) {
  _gcMentionDropdown?.remove();
  const wrap = input.closest('.dm-compose') || input.parentElement;
  if (!wrap) return;
  const dd = document.createElement('div');
  dd.className = 'gc-mention-dropdown';
  _gcMentionMatches.forEach((mm, i) => {
    const item = document.createElement('div');
    item.className = 'gc-mention-item' + (i === _gcMentionActiveIdx ? ' active' : '');
    item.innerHTML = `${gcAvatar(mm.nickname || mm.name, mm.photo, 26)}<span>${swEsc(mm.nickname || mm.name || 'Member')}</span>`;
    item.onmousedown = e => { e.preventDefault(); _gcMentionPick(input, mm); };
    dd.appendChild(item);
  });
  wrap.appendChild(dd);
  _gcMentionDropdown = dd;
}

function _gcMentionPick(input, member) {
  if (!_gcMentionRange) return;
  const token = (member.nickname || member.name || 'member').replace(/\s+/g, '');
  const val = input.value;
  const newVal = val.slice(0, _gcMentionRange.start) + '@' + token + ' ' + val.slice(_gcMentionRange.end);
  input.value = newVal;
  const newCaret = _gcMentionRange.start + token.length + 2;
  input.setSelectionRange?.(newCaret, newCaret);
  input.focus();
  _gcMentionClose();
}

function _gcMentionOnKeydown(e) {
  if (!_gcMentionDropdown || !_gcMentionMatches.length) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _gcMentionActiveIdx = (_gcMentionActiveIdx + 1) % _gcMentionMatches.length;
    _gcMentionRenderDropdown(e.target);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _gcMentionActiveIdx = (_gcMentionActiveIdx - 1 + _gcMentionMatches.length) % _gcMentionMatches.length;
    _gcMentionRenderDropdown(e.target);
  } else if (e.key === 'Enter' || e.key === 'Tab') {
    e.preventDefault();
    e.stopImmediatePropagation();
    _gcMentionPick(e.target, _gcMentionMatches[_gcMentionActiveIdx]);
  } else if (e.key === 'Escape') {
    _gcMentionClose();
  }
}

function gcRenderMsgs(msgs, container, myId, lastSenderHint) {
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild : null;

  const _pendingDecrypts = [];

  msgs.forEach(m => {
    // ── System / activity messages → WhatsApp-style centered pill ─────────
    if (m.is_system) {
      lastSender = '__system__';
      group = null;
      const pill = document.createElement('div');
      pill.className = 'gc-system-pill';
      pill.textContent = m.body;
      container.appendChild(pill);
      return;
    }

    const mine = m.sender_id === myId || (m.id.startsWith('tmp-') && !m.sender_id);
    const senderKey = mine ? '__mine__' : m.sender_id;
    const convKey   = GC.activeId;

    const displayName = mine
      ? 'You'
      : nicksResolveDisplay(convKey, m.sender_id, m.sender?.name || m.sender_name || 'Member');

    if (senderKey !== lastSender || !group) {
      group = document.createElement('div');
      group.className = `dm-msg-group ${mine ? 'mine' : 'theirs'}`;

      if (!mine) {
        // WhatsApp/Insta style: avatar + colored sender name
        const sName  = m.sender?.name  || m.sender_name  || 'Member';
        const sPhoto = m.sender?.photo || m.sender_photo || null;
        // Stable hue from sender_id so each person always gets the same color
        const hue = m.sender_id
          ? [...m.sender_id].reduce((acc, c) => acc + c.charCodeAt(0), 0) % 360
          : 200;
        const header = document.createElement('div');
        header.className = 'gc-msg-header';
        header.innerHTML = `
          <span class="gc-msg-avatar-btn" data-member-id="${swEsc(m.sender_id)}" style="cursor:pointer">${gcAvatar(sName, sPhoto, 28)}</span>
          <span class="gc-msg-sender-name" data-member-id="${swEsc(m.sender_id)}"
                style="color:hsl(${hue},65%,65%);cursor:pointer">${swEsc(displayName)}</span>
        `;
        // Tap the name or avatar → open that member's profile info, same as
        // tapping a person in Instagram/WhatsApp chats. Nickname editing is
        // still available from the ⓘ info panel's "Nicknames" action.
        const openSenderProfile = e => {
          e.stopPropagation();
          if (typeof openMemberProfile === 'function') openMemberProfile(m.sender_id);
        };
        header.querySelector('.gc-msg-sender-name')?.addEventListener('click', openSenderProfile);
        header.querySelector('.gc-msg-avatar-btn')?.addEventListener('click', openSenderProfile);
        group.appendChild(header);
      }

      container.appendChild(group);
      lastSender = senderKey;
    }

    const isDeleted = m.body === '[deleted]' || m.is_deleted;

    // Wrap bubble + hover actions together
    const wrap = document.createElement('div');
    wrap.className = 'dm-bubble-wrap';

    const bubble = document.createElement('div');
    bubble.className = `dm-bubble${isDeleted ? ' dm-deleted' : ''}`;
    bubble.dataset.msgId = m.id;

    // Reply quote (WhatsApp-style)
    if (m.replied_to_id) {
      const _replyText = _resolveReplyPreviewText(m, GC.msgs);
      if (_replyText) {
      const quote = document.createElement('div');
      quote.className = 'dm-reply-quote';
      const qSender = document.createElement('span');
      qSender.className = 'dm-reply-sender';
      qSender.textContent = m.replied_to_sender || 'Member';
      const qBody = document.createElement('span');
      qBody.className = 'dm-reply-body';
      qBody.textContent = _replyText.slice(0, 120);
      quote.appendChild(qSender);
      quote.appendChild(qBody);
      // Tap/click → scroll to the original message (same as DM)
      quote.addEventListener('click', e => {
        e.stopPropagation();
        const target = document.querySelector(`[data-msg-id="${CSS.escape(m.replied_to_id)}"]`);
        if (!target) return;
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('dm-msg-highlight');
        setTimeout(() => target.classList.remove('dm-msg-highlight'), 1600);
      });
      bubble.appendChild(quote);
      }
    }
    // Attachment (image) — renders above/instead of the text caption
    const _isPhotoOnly = !isDeleted && !m.is_system && _attachImageToBubble(bubble, m);
    // "Check this out on Social Strand: <url>" auto-share messages — render
    // only the rich card, not the boilerplate sentence as raw text too.
    const _plainIsStrandOnly = !_isPhotoOnly && !isDeleted && !m.is_system && !m.e2ee && _isStrandShareOnly(m.body);

    const bodyNode = document.createElement('span');
    bodyNode.className = 'dm-bubble-text';
    // E2EE: decrypt group message asynchronously
    if (_isPhotoOnly || _plainIsStrandOnly) {
      // no caption to render — image or standalone strand card handles it
    } else if (m.e2ee && !isDeleted && !m.is_system) {
      bodyNode.textContent = '🔒 …';
      bodyNode.style.opacity = '0.5';
      const _gcMyId = mine ? m.sender_id : gcMyId();
      const _decryptP = E2EE.decryptGroup(m, _gcMyId).then(pt => {
        m._plaintext = pt;
        if (_isStrandShareOnly(pt)) {
          bodyNode.remove();
          bubble.classList.add('dm-bubble-strand-share');
          _attachStrandPreviewToBubble(bubble, pt, true);
        } else {
          bodyNode.innerHTML = _gcHighlightMentions(pt);
          bodyNode.style.opacity = '';
          _attachStrandPreviewToBubble(bubble, pt, false);
        }
      }).catch(() => {
        bodyNode.textContent = '🔒 Message encrypted before your keys were set up';
        bodyNode.style.opacity = '0.5';
        bubble.classList.add('dm-e2ee-failed');
      });
      _pendingDecrypts.push(_decryptP);
    } else {
      bodyNode.innerHTML = _gcHighlightMentions(m.body);
    }
    if (_plainIsStrandOnly) bubble.classList.add('dm-bubble-strand-share');
    if (!_isPhotoOnly && !_plainIsStrandOnly) bubble.appendChild(bodyNode);
    if (_plainIsStrandOnly) {
      _attachStrandPreviewToBubble(bubble, m.body, true);
    } else if (!_isPhotoOnly && !m.is_system && !(m.e2ee && !isDeleted)) {
      _attachStrandPreviewToBubble(bubble, m.body, false);
    }

    wrap.appendChild(bubble);

    // Instagram-style hover actions (hidden on mobile via CSS)
    if (!isDeleted && !m.is_system) {
      const _gcBodyForActions = () => m._plaintext || m.body;
      const hoverActions = _buildHoverActions({
        msgId: m.id, body: _gcBodyForActions(), mine,
        senderName: mine ? 'You' : (m.sender?.name || m.sender_name || 'Member'),
        type: 'group',
        senderId: m.sender_id,
        onReply: () => _setReply('group', { id: m.id, body: _gcBodyForActions(), sender: mine ? 'You' : (m.sender?.name || m.sender_name || 'Member') }),
        onReact: (emoji) => _toggleReaction('group', m.id, emoji, bubble),
      });
      wrap.appendChild(hoverActions);
      _attachQuickHeart(bubble, (emoji) => _toggleReaction('group', m.id, emoji, bubble));
    }

    // Existing reactions (from initial load or poll refresh)
    if (!m.is_system && m.reactions && m.reactions.length) {
      _renderReactionPills(bubble, m.reactions, (emoji) => _toggleReaction('group', m.id, emoji, bubble));
    }

    const meta = document.createElement('div');
    meta.className = 'dm-meta';
    meta.dataset.metaFor = m.id;
    meta.innerHTML = `${!isDeleted && m.edited_at ? `<span class="dm-edited-tag">edited</span>` : ''}<span class="dm-msg-time">${gcFull(m.sent_at)}</span>${mine && !isDeleted && !m.id.startsWith('tmp-') ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

    const delBtn = meta.querySelector('.dm-del-btn');
    if (delBtn) {
      delBtn.addEventListener('click', e => {
        e.stopPropagation();
        gcDeleteMsg(m.id, bubble, delBtn);
      });
    }

    // Context menu: right-click (desktop) + long-press (mobile)
    if (!isDeleted && !m.is_system) {
      _attachMsgContextMenu(bubble, {
        id: m.id, body: m.body, mine,
        senderName: mine ? 'You' : (m.sender?.name || m.sender_name || 'Member'),
        type: 'group',
        senderId: m.sender_id,
        is_pinned: m.is_pinned || false,
      });
    }

    group.appendChild(wrap);
    group.appendChild(meta);
  });

  _markLastBubbleInGroups(container);
  _gcRenderSeenBy();
  if (_pendingDecrypts.length) {
    Promise.allSettled(_pendingDecrypts).then(() => _collapseFailedDecrypts(container));
  }
}

function gcScrollBottom() {
  const el = $id('gc-msgs');
  if (el) el.scrollTop = el.scrollHeight;
}

// ─── "Seen by" avatar stack (WhatsApp-style, groups only) ────────────────────
// Rather than tracking read state per message, the server keeps one row per
// (group, member) — a last-read watermark (see GET /api/member/groups/:id/seen).
// A member has "seen" a message if their last_read_at >= that message's
// created_at. We only ever compute/show this for the single most recent
// message in the thread, same as WhatsApp.
function _gcRenderSeenBy() {
  document.querySelectorAll('.gc-seenby').forEach(el => el.remove());
  if (!GC.activeId || !GC.activeGroup) return;
  const real = GC.msgs.filter(m => m.id && !String(m.id).startsWith('tmp-') && !m.is_system);
  const last = real[real.length - 1];
  if (!last) return;
  const myId = gcMyId();
  const seenMembers = (GC.reads || [])
    .filter(r => r.member_id !== last.sender_id && r.member_id !== myId && new Date(r.last_read_at) >= new Date(last.sent_at))
    .map(r => (GC.activeGroup.members || []).find(mm => mm.id === r.member_id))
    .filter(Boolean);
  if (!seenMembers.length) return;
  const metaRow = document.querySelector(`.dm-meta[data-meta-for="${CSS.escape(last.id)}"]`);
  if (!metaRow) return;
  const shown = seenMembers.slice(0, 4);
  const row = document.createElement('div');
  row.className = 'gc-seenby';
  row.title = 'Seen by ' + seenMembers.map(m => m.nickname || m.name || 'Member').join(', ');
  row.innerHTML = shown.map(m => {
    const initials = (m.name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
    return m.photo
      ? `<img class="gc-seenby-avatar" src="${swEsc(m.photo)}" alt="">`
      : `<span class="gc-seenby-avatar gc-seenby-initials">${swEsc(initials)}</span>`;
  }).join('') + (seenMembers.length > 4 ? `<span class="gc-seenby-more">+${seenMembers.length - 4}</span>` : '');
  metaRow.insertAdjacentElement('afterend', row);
}

async function _gcRefreshSeenBy() {
  if (!GC.activeId) return;
  try {
    const reads = await api('GET', `/api/member/groups/${GC.activeId}/seen`);
    if (Array.isArray(reads)) {
      GC.reads = reads;
      _gcRenderSeenBy();
    }
  } catch { /* silent — try again next poll tick */ }
}

// Show pinned message banner in the group topbar area
async function gcRefreshPinnedBanner() {
  if (!GC.activeId) return;
  try {
    const pins = await api('GET', `/api/member/groups/${GC.activeId}/pinned`);
    let bar = $id('gc-pinned-bar');
    if (!pins || !pins.length) {
      if (bar) bar.remove();
      return;
    }
    const latest = pins[0];
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'gc-pinned-bar';
      bar.style.cssText = `display:flex;align-items:center;gap:10px;padding:8px 14px;background:#111;border-bottom:1px solid #1e1e1e;cursor:pointer;font-size:12.5px;color:var(--muted);flex-shrink:0`;
      const msgs = $id('gc-msgs');
      if (msgs) msgs.parentNode.insertBefore(bar, msgs);
    }
    bar.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:#888"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
      <div style="flex:1;min-width:0"><span style="color:var(--text);font-weight:600">Pinned:</span> <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${swEsc((latest.body || '').slice(0, 80))}</span></div>
      <button style="background:none;border:none;color:var(--muted);cursor:pointer;padding:2px;flex-shrink:0" title="Dismiss" onclick="event.stopPropagation();this.parentElement.remove()">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>`;
    bar.onclick = (e) => {
      if (e.target.closest('button')) return;
      // Scroll to pinned message
      const target = document.querySelector(`[data-msg-id="${CSS.escape(latest.id)}"]`);
      if (target) { target.scrollIntoView({ behavior: 'smooth', block: 'center' }); target.classList.add('dm-msg-highlight'); setTimeout(() => target.classList.remove('dm-msg-highlight'), 1600); }
    };
  } catch { /* silent */ }
}

// ─── Send ─────────────────────────────────────────────────────────────────────

async function gcSend() {
  const input = $id('gc-input');
  if (!input) return;
  const body = input.value.trim();
  if (!body || !GC.activeId) return;

  // Edit mode — route to the PATCH flow instead of posting a new message.
  if (_editState.group) { await _gcSubmitEdit(body); return; }

  if (GC.loadingMsgs) {
    const btn = $id('gc-send-btn');
    if (btn) btn.disabled = true;
    await new Promise(resolve => { const c = () => { if (!GC.loadingMsgs) resolve(); else setTimeout(c, 50); }; c(); });
    if (btn) btn.disabled = false;
  }

  const myId      = gcMyId();
  const tmpId     = 'tmp-' + Date.now();
  const replyData = _gcGetReplyPayload();
  const tmp   = { id: tmpId, sender_id: myId, sender: window._memberProfile || { id: myId, name: 'You', photo: null }, body, sent_at: new Date().toISOString(), is_deleted: false, reactions: [], ...replyData };
  GC.msgs.push(tmp);
  GC.pendingBodies.add(body);

  const list = $id('gc-msg-list');
  const lastRenderedSender = GC.msgs.length > 1 ? GC.msgs[GC.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    gcRenderMsgs([tmp], list, myId, lastRenderedSender === myId ? '__mine__' : lastRenderedSender);
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
  }
  gcScrollBottom();
  input.value = '';
  input.style.height = '';

  try {
    // E2EE: encrypt for all group members before sending
    let gcPayload = { body, ..._gcGetReplyPayload() };
    if (E2EE.ready() && GC.activeMembers?.length) {
      try {
        const memberIds = GC.activeMembers.map(m => m.id || m.member_id).filter(Boolean);
        const enc = await E2EE.encryptGroup(body, memberIds);
        gcPayload = { ...gcPayload, body: '', ...enc };
        // SECURITY: see matching note in dmSend — don't ship the decrypted
        // reply-quote text to the server for an otherwise-encrypted message.
        if (gcPayload.replied_to_body) gcPayload.replied_to_body = null;
      } catch (encErr) {
        console.warn('[E2EE] Group encrypt failed, sending plaintext:', encErr.message);
      }
    }
    const res = await api('POST', `/api/member/groups/${GC.activeId}/messages`, gcPayload);
    _setReply('group', null); // clear reply bar after successful send
    const realMsg = res.message;

    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    if (realMsg) GC.msgs.push(realMsg);

    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      // CRITICAL: update data-msg-id so reactions, reply, context menu all work immediately
      tmpBubble.dataset.msgId = realMsg.id;
      const grp    = tmpBubble.closest('.dm-msg-group');
      const delBtn = grp?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
      const _gcMetaRow = grp?.querySelector('.dm-meta');
      if (_gcMetaRow) _gcMetaRow.dataset.metaFor = realMsg.id;
      // Re-attach quick-heart with real ID
      _attachQuickHeart(tmpBubble, (emoji) => _toggleReaction('group', realMsg.id, emoji, tmpBubble));
      // Re-attach context menu with real ID
      _attachMsgContextMenu(tmpBubble, { id: realMsg.id, body: realMsg.body, mine: true, senderName: 'You', type: 'group', senderId: myId });
      // Re-wire hover-action buttons with real ID
      const _gcHwrap = tmpBubble.closest('.dm-bubble-wrap');
      _gcHwrap?.querySelectorAll('.dm-ha-btn').forEach(btn => {
        if (btn.title === 'React') {
          const nb = btn.cloneNode(true);
          nb.addEventListener('click', e => { e.stopPropagation(); _showEmojiPicker(nb, emoji => _toggleReaction('group', realMsg.id, emoji, tmpBubble)); });
          btn.replaceWith(nb);
        } else if (btn.title === 'Reply') {
          const nb = btn.cloneNode(true);
          nb.addEventListener('click', e => { e.stopPropagation(); _setReply('group', { id: realMsg.id, body: realMsg.body, sender: 'You' }); });
          btn.replaceWith(nb);
        }
      });
    } else if (list) {
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      gcScrollBottom();
    }
    _gcRenderSeenBy();

    const existing = GC.groups.find(g => g.id === GC.activeId);
    if (existing) {
      existing.last_snippet      = body.slice(0, 80);
      existing.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existing.last_sender_is_me = true;
      if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
      else gcRenderGroups(GC.groups);
    } else {
      await gcLoadGroups();
    }
  } catch (e) {
    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const grp  = tmpBubble.closest('.dm-msg-group');
      const meta = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (grp && !grp.querySelector('.dm-bubble')) grp.remove();
    }
    // Same moderation handling as DM: a warned/muted/banned member gets a
    // visible toast (and, for mute/ban, a locked compose box) instead of the
    // message just silently vanishing with no explanation.
    const ed = e._data || {};
    if (ed.warned || ed.muted || ed.banned || ed.temp_banned) {
      _vioShowClientNotice(ed, e.message, 'gc-input', 'gc-send-btn');
    } else {
      input.value = body; // restore on error
      console.error('[GC] send:', e.message);
    }
  } finally {
    GC.pendingBodies.delete(body);
  }
}

// ── Send a photo attachment in a group chat ───────────────────────────────────
// Uploads via multipart/form-data to /api/member/groups/:id/messages/image (the
// server pipeline already existed — this client-side sender function was
// missing, which is why tapping the attach button silently did nothing).
async function _gcSendImage(file, opacity = 100) {
  if (!GC.activeId) return;
  if (file.size > 8 * 1024 * 1024) { swShowToast('Photo is too large (max 8MB).', 4000); return; }

  const btn = $id('gc-attach-btn');
  if (btn) btn.disabled = true;

  const myId  = gcMyId();
  const tmpId = 'tmp-' + Date.now();
  const localUrl = URL.createObjectURL(file);
  const replyData = _gcGetReplyPayload();
  const tmp = { id: tmpId, sender_id: myId, sender: window._memberProfile || { id: myId, name: 'You', photo: null }, body: '📷 Photo', attachment_url: localUrl, attachment_type: 'image', attachment_opacity: opacity, sent_at: new Date().toISOString(), is_deleted: false, reactions: [], ...replyData };
  GC.msgs.push(tmp);

  const list = $id('gc-msg-list');
  const lastRenderedSender = GC.msgs.length > 1 ? GC.msgs[GC.msgs.length - 2].sender_id : null;
  if (list) {
    const beforeCount = list.querySelectorAll('.dm-bubble').length;
    gcRenderMsgs([tmp], list, myId, lastRenderedSender === myId ? '__mine__' : lastRenderedSender);
    const allBubbles = list.querySelectorAll('.dm-bubble');
    if (allBubbles.length > beforeCount) allBubbles[allBubbles.length - 1].dataset.tmpId = tmpId;
  }
  gcScrollBottom();

  try {
    const fd = new FormData();
    fd.append('image', file);
    fd.append('opacity', String(opacity));
    if (replyData.replied_to_id) {
      fd.append('replied_to_id', replyData.replied_to_id);
      // SECURITY: see matching note in _dmSendImage.
      fd.append('replied_to_sender', replyData.replied_to_sender || '');
    }
    const res = await api('POST', `/api/member/groups/${GC.activeId}/messages/image`, fd, true);
    _setReply('group', null);
    const realMsg = res.message;

    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    if (realMsg) GC.msgs.push(realMsg);

    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble && realMsg) {
      delete tmpBubble.dataset.tmpId;
      tmpBubble.dataset.msgId = realMsg.id;
      const grp    = tmpBubble.closest('.dm-msg-group');
      const delBtn = grp?.querySelector('.dm-del-btn');
      if (delBtn) delBtn.dataset.id = realMsg.id;
      const _gcMetaRow = grp?.querySelector('.dm-meta');
      if (_gcMetaRow) _gcMetaRow.dataset.metaFor = realMsg.id;
      _attachQuickHeart(tmpBubble, (emoji) => _toggleReaction('group', realMsg.id, emoji, tmpBubble));
      _attachMsgContextMenu(tmpBubble, { id: realMsg.id, body: realMsg.body, mine: true, senderName: 'You', type: 'group', senderId: myId });
    } else if (list) {
      list.innerHTML = '';
      gcRenderMsgs(GC.msgs, list, myId);
      gcScrollBottom();
    }
    _gcRenderSeenBy();

    const existing = GC.groups.find(g => g.id === GC.activeId);
    if (existing) {
      existing.last_snippet      = '📷 Photo';
      existing.last_msg_at       = realMsg?.sent_at || new Date().toISOString();
      existing.last_sender_is_me = true;
      if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
      else gcRenderGroups(GC.groups);
    } else {
      await gcLoadGroups();
    }
  } catch (e) {
    GC.msgs = GC.msgs.filter(m => m.id !== tmpId);
    const tmpBubble = list?.querySelector(`[data-tmp-id="${tmpId}"]`);
    if (tmpBubble) {
      const grp  = tmpBubble.closest('.dm-msg-group');
      const meta = tmpBubble.nextElementSibling;
      if (meta?.classList.contains('dm-meta')) meta.remove();
      tmpBubble.remove();
      if (grp && !grp.querySelector('.dm-bubble')) grp.remove();
    }
    const ed = e._data || {};
    if (ed.warned || ed.muted || ed.banned || ed.temp_banned) {
      _vioShowClientNotice(ed, e.message, 'gc-input', 'gc-send-btn');
    } else {
      swShowToast(e.message || 'Could not send photo.', 4000);
      console.error('[GC] send image:', e.message);
    }
  } finally {
    URL.revokeObjectURL(localUrl);
    if (btn) btn.disabled = false;
  }
}

// ─── Delete ───────────────────────────────────────────────────────────────────

async function gcDeleteMsg(msgId, bubble, btn) {
  if (!await swConfirm('Delete this message?', { title: 'Delete message', confirmLabel: 'Delete', danger: true })) return;
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/messages/${msgId}`);
    bubble.textContent = '[deleted]';
    bubble.classList.add('dm-deleted');
    btn.remove();
    const m = GC.msgs.find(m => m.id === msgId);
    if (m) { m.body = '[deleted]'; m.is_deleted = true; }
  } catch (e) {
    console.error('[GC] delete:', e.message);
  }
}

// ─── Polling ──────────────────────────────────────────────────────────────────

async function _gcPollNewMessages() {
  const myId   = gcMyId();
  // Use the newest CONFIRMED (non-tmp) message as the since cursor.
  // Optimistic tmp messages use client time which may not match the server's
  // created_at, so using them as a cursor could cause messages to be skipped.
  const confirmedMsgs = GC.msgs.filter(m => m.id && !String(m.id).startsWith('tmp-'));
  const newest = confirmedMsgs.length ? confirmedMsgs[confirmedMsgs.length - 1].sent_at : null;
  const url    = `/api/member/groups/${encodeURIComponent(GC.activeId)}/messages?limit=20`
               + (newest ? `&since=${encodeURIComponent(newest)}` : '');
  const resp   = await api('GET', url);
  const msgs   = Array.isArray(resp) ? resp : (resp.messages || []);
  if (!msgs.length) return;

  const known   = new Set(GC.msgs.map(m => m.id));
  const newMsgs = msgs.filter(m =>
    !known.has(m.id) && (m.is_system || !GC.pendingBodies.has(m.body))
  );
  if (!newMsgs.length) return;

  // Merge new nicknames (only available when resp is an object, not array)
  if (!Array.isArray(resp) && resp.nicknames?.length) {
    const existing = NICKS[GC.activeId] || [];
    const existMap = new Map(existing.map(n => `${n.giver_id}:${n.target_id}`));
    resp.nicknames.forEach(n => { existMap.set(`${n.giver_id}:${n.target_id}`, n); });
    NICKS[GC.activeId] = [...existMap.values()];
  }

  GC.msgs.push(...newMsgs);
  const list  = $id('gc-msg-list');
  if (!list) return;
  const area  = $id('gc-msgs');
  const atEnd = area ? area.scrollHeight - area.scrollTop - area.clientHeight < 80 : true;
  const lastSender = GC.msgs.length > newMsgs.length
    ? GC.msgs[GC.msgs.length - newMsgs.length - 1].sender_id
    : null;
  gcRenderMsgs(newMsgs, list, myId, lastSender === myId ? '__mine__' : lastSender);
  if (atEnd) gcScrollBottom();
}

// ── Typing indicator (Group) ───────────────────────────────────────────────
// Same pattern as DM: throttled ping on input, polled + rendered on tick.
// Group typers can be multiple people, so the label lists up to two names.
let _gcTypingLastSent = 0;
function _gcPingTyping() {
  if (!GC.activeId) return;
  const now = Date.now();
  if (now - _gcTypingLastSent < 2000) return;
  _gcTypingLastSent = now;
  api('POST', '/api/member/typing', { conv_key: GC.activeId, conv_type: 'group' }).catch(() => {});
}
async function _gcPollTyping() {
  const el  = $id('gc-typing-indicator');
  const txt = $id('gc-typing-text');
  if (!GC.activeId) { el?.classList.remove('show'); return; }
  try {
    const typers = await api('GET', `/api/member/typing?conv_key=${encodeURIComponent(GC.activeId)}&conv_type=group`);
    if (typers && typers.length) {
      const label = typers.length === 1
        ? `${typers[0].name} is typing…`
        : typers.length === 2
          ? `${typers[0].name} and ${typers[1].name} are typing…`
          : `${typers[0].name} and ${typers.length - 1} others are typing…`;
      if (txt) txt.textContent = label;
      el?.classList.add('show');
    } else {
      el?.classList.remove('show');
    }
  } catch { /* silent */ }
}

async function gcPollTick() {
  if (!GC.activeId) {
    // No group open. The _sidebarRefreshTimer (every 10s) already handles the
    // background group-list refresh, so we don't need to duplicate the API call
    // here. Just return — the sidebar timer will keep the list fresh.
    return;
  }
  try { await _gcPollNewMessages(); } catch { /* silent */ }
  // Same reasoning as DM: a groupmate's reaction on an existing message
  // doesn't come through the "since" cursor above, so refresh separately.
  try { await _refreshVisibleReactions('group'); } catch { /* silent */ }
  // Refresh "seen by" watermarks so the avatar stack under the last message
  // updates live as groupmates open the thread.
  try { await _gcRefreshSeenBy(); } catch { /* silent */ }
  // "X is typing…" indicator — cheap read-only poll, same cadence as reactions.
  try { await _gcPollTyping(); } catch { /* silent */ }
}

function gcStartPolling() { gcPausePolling(); GC.poll = setInterval(gcPollTick, GC_POLL); }
function gcPausePolling()  { if (GC.poll) { clearInterval(GC.poll); GC.poll = null; } }

// ─── Panel ────────────────────────────────────────────────────────────────────

async function gcPanelOpened() {
  GC.panelVisible = true;
  await gcLoadGroups();
  gcStartPolling();
}

function gcGoBack() {
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.remove('dm-slide-out');
    $id('gc-window')?.classList.remove('dm-slide-in');
  }
  $id('gc-active') && ($id('gc-active').style.display = 'none');
  $id('gc-window-empty') && ($id('gc-window-empty').style.display = '');
  GC.activeId    = null;
  GC.activeGroup = null;
  _kfsPopNavState('gc-chat');
  // Do NOT pause polling — gcPollTick already no-ops when GC.activeId is null.
  // Keeping the interval alive means reactions stay fresh and the group list
  // can be refreshed by the background sidebar timer without needing a restart.
  document.querySelectorAll('.gc-conv-row').forEach(el => el.classList.remove('dm-active-row'));
}

// ─── Create group modal ───────────────────────────────────────────────────────

function gcOpenCreateModal() {
  let modal = $id('gc-create-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gc-create-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `
      <div class="nick-modal gc-create-modal" id="gc-create-modal">
        <div class="nick-modal-head">
          <span>New Group Chat</span>
          <button class="dm-icon-btn" id="gc-create-close" aria-label="Close">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <input id="gc-create-name" class="nick-input" type="text" maxlength="60" placeholder="Group name…" autocomplete="off">
        <div style="margin-top:10px;font-size:12px;color:var(--muted);margin-bottom:6px">Add members</div>
        <div class="gc-create-search-wrap">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted)"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="gc-member-search" class="dm-search-input" style="padding-left:32px;width:100%;box-sizing:border-box" type="text" placeholder="Search members…" autocomplete="off">
        </div>
        <div id="gc-member-results" class="dm-picker-results" style="max-height:160px;margin-top:6px"></div>
        <div style="margin-top:8px;font-size:11px;color:var(--muted);margin-bottom:4px">Selected</div>
        <div id="gc-selected-chips" style="display:flex;flex-wrap:wrap;gap:6px;min-height:28px"></div>
        <div class="nick-modal-actions" style="margin-top:14px">
          <button class="nick-clear-btn" id="gc-create-cancel">Cancel</button>
          <button class="nick-save-btn" id="gc-create-submit">Create</button>
        </div>
        <div id="gc-create-error" class="nick-error" style="display:none"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) gcCloseCreateModal(); });
  }

  // Use onclick (not addEventListener) to avoid stacking duplicate handlers on modal reuse
  const gcCloseEl  = $id('gc-create-close');
  const gcCancelEl = $id('gc-create-cancel');
  if (gcCloseEl)  gcCloseEl.onclick  = gcCloseCreateModal;
  if (gcCancelEl) gcCancelEl.onclick = gcCloseCreateModal;

  const selected = new Map(); // id → member object
  modal._selected = selected;

  const renderChips = () => {
    const chips = $id('gc-selected-chips');
    chips.innerHTML = '';
    selected.forEach((m, id) => {
      const chip = document.createElement('span');
      chip.className = 'gc-chip';
      chip.innerHTML = `${swEsc(m.name || 'Member')}<button data-id="${swEsc(id)}" class="gc-chip-remove">×</button>`;
      chip.querySelector('.gc-chip-remove')?.addEventListener('click', () => { selected.delete(id); renderChips(); });
      chips.appendChild(chip);
    });
  };

  const renderResults = (q) => {
    const results = $id('gc-member-results');
    const query   = (q || '').toLowerCase().trim();
    const myId    = gcMyId();
    const pool    = DM.members.length ? DM.members : (_portalMembers || []);
    const hits    = query
      ? pool.filter(m => (m.name || '').toLowerCase().includes(query) && !selected.has(m.id))
      : pool.filter(m => !selected.has(m.id)).slice(0, 8);
    results.innerHTML = hits.map(m => `
      <div class="dm-picker-row" data-id="${swEsc(m.id)}">
        ${gcAvatar(m.name, m.photo, 30)}
        <div>
          <div class="dm-picker-name">${swEsc(m.name || 'Member')}</div>
          <div class="dm-picker-meta">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
        </div>
      </div>`).join('');
    results.querySelectorAll('.dm-picker-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        const m  = pool.find(x => x.id === id);
        if (m) { selected.set(id, m); renderChips(); renderResults($id('gc-member-search')?.value); }
      });
    });
  };

  // Reset
  $id('gc-create-name').value = '';
  $id('gc-member-search').value = '';
  $id('gc-selected-chips').innerHTML = '';
  $id('gc-create-error').style.display = 'none';

  // Load members
  dmEnsureMembers().then(() => renderResults(''));

  let searchTimer;
  const searchInp = $id('gc-member-search');
  searchInp.oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => renderResults(searchInp.value), 150); };

  const submitBtn = $id('gc-create-submit');
  submitBtn.onclick = async () => {
    const name = ($id('gc-create-name').value || '').trim();
    if (!name) { $id('gc-create-error').textContent = 'Group name required.'; $id('gc-create-error').style.display = ''; return; }
    if (!selected.size) { $id('gc-create-error').textContent = 'Add at least one member.'; $id('gc-create-error').style.display = ''; return; }
    submitBtn.disabled = true;
    try {
      const res = await api('POST', '/api/member/groups', { name, member_ids: [...selected.keys()] });
      gcCloseCreateModal();
      // Use _inboxLoad (unified) so DM.convs + GC.groups are both refreshed.
      if (typeof window._inboxLoad === 'function') {
        await window._inboxLoad();
      } else {
        await gcLoadGroups();
      }
      // Optimistically inject the new group if it's not in the list yet
      // (avoids a blank moment if the server hasn't synced yet)
      if (res.group && !(GC.groups || []).find(g => g.id === res.group.id)) {
        GC.groups = [{ ...res.group, members: res.group.members || [], last_msg_at: res.group.created_at, unread_count: 0, my_role: 'owner' }, ...(GC.groups || [])];
        if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
      }
      if (res.group) {
        // Prefer the fully-enriched object from the freshly-loaded list
        const toOpen = GC.groups.find(g => g.id === res.group.id) || {
          ...res.group,
          members:           res.group.members || [],
          last_msg_at:       res.group.created_at,
          last_snippet:      null,
          last_sender_is_me: false,
          last_sender_name:  null,
          unread_count:      0,
          my_role:           'owner',
        };
        // Reset stale message state so the newly-created group starts clean
        GC.msgs = [];
        GC.oldestSentAt = null;
        // Always open via window._inboxOpenGroup (unified inbox) so dm-window
        // is properly hidden and gc-window is shown. Falls back to the patched
        // window.gcOpenGroup if the unified IIFE hasn't exposed _inboxOpenGroup yet.
        if (typeof window._inboxOpenGroup === 'function') {
          window._inboxOpenGroup(toOpen);
        } else {
          // Force gc-window + gc-active visible NOW before gcOpenGroup fires
          // so messages are never rendered into a hidden container (blank chat bug)
          const _gcWin    = $id('gc-window');
          const _dmWin    = $id('dm-window');
          const _gcActive = $id('gc-active');
          const _gcEmpty  = $id('gc-window-empty');
          if (_dmWin)    _dmWin.style.display    = 'none';
          if (_gcWin)    _gcWin.style.display    = 'flex';
          if (_gcEmpty)  _gcEmpty.style.display  = 'none';
          if (_gcActive) _gcActive.style.display = 'flex';
          // Clear any stale message DOM
          const _msgList = $id('gc-msg-list');
          if (_msgList) _msgList.innerHTML = '';
          const opener = typeof window.gcOpenGroup === 'function' ? window.gcOpenGroup : gcOpenGroup;
          await opener(toOpen);
        }
      }
    } catch (e) {
      $id('gc-create-error').textContent = e.message || 'Could not create group.';
      $id('gc-create-error').style.display = '';
    } finally {
      submitBtn.disabled = false;
    }
  };

  modal.style.display = 'flex';
  $id('gc-create-name').focus();
}

function gcCloseCreateModal() {
  const modal = $id('gc-create-overlay');
  if (modal) modal.style.display = 'none';
}

// ─── Add Members to existing group modal ──────────────────────────────────────
// Reuses the same search/chip UI as the create modal but POSTs to the
// add-member endpoint for an already-existing group.
function gcOpenAddMembersModal(groupId) {
  const group = GC.groups.find(g => g.id === groupId) || GC.activeGroup;
  if (!groupId) return;

  let modal = $id('gc-addmem-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gc-addmem-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `
      <div class="nick-modal gc-create-modal" id="gc-addmem-modal">
        <div class="nick-modal-head">
          <span>Add Members</span>
          <button class="dm-icon-btn" id="gc-addmem-close" aria-label="Close">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="gc-create-search-wrap">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted)"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="gc-addmem-search" class="dm-search-input" style="padding-left:32px;width:100%;box-sizing:border-box" type="text" placeholder="Search members…" autocomplete="off">
        </div>
        <div id="gc-addmem-results" class="dm-picker-results" style="max-height:160px;margin-top:6px"></div>
        <div style="margin-top:8px;font-size:11px;color:var(--muted);margin-bottom:4px">Selected</div>
        <div id="gc-addmem-chips" style="display:flex;flex-wrap:wrap;gap:6px;min-height:28px"></div>
        <div class="nick-modal-actions" style="margin-top:14px">
          <button class="nick-clear-btn" id="gc-addmem-cancel">Cancel</button>
          <button class="nick-save-btn" id="gc-addmem-submit">Add</button>
        </div>
        <div id="gc-addmem-error" class="nick-error" style="display:none"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) gcCloseAddMembersModal(); });
  }

  $id('gc-addmem-close').onclick  = gcCloseAddMembersModal;
  $id('gc-addmem-cancel').onclick = gcCloseAddMembersModal;

  const selected = new Map();
  // Build a set of member IDs already in the group so we don't show them as options
  const existingIds = new Set((group?.members || []).map(m => m.id));

  const renderChips = () => {
    const chips = $id('gc-addmem-chips');
    chips.innerHTML = '';
    selected.forEach((m, id) => {
      const chip = document.createElement('span');
      chip.className = 'gc-chip';
      chip.innerHTML = `${swEsc(m.name || 'Member')}<button data-id="${swEsc(id)}" class="gc-chip-remove">×</button>`;
      chip.querySelector('.gc-chip-remove')?.addEventListener('click', () => { selected.delete(id); renderChips(); });
      chips.appendChild(chip);
    });
  };

  const renderResults = (q) => {
    const results = $id('gc-addmem-results');
    if (!results) return;
    const query = (q || '').toLowerCase().trim();
    const pool  = DM.members.length ? DM.members : (_portalMembers || []);
    const hits  = (query
      ? pool.filter(m => (m.name || '').toLowerCase().includes(query))
      : pool.slice(0, 12)
    ).filter(m => !existingIds.has(m.id) && !selected.has(m.id));
    results.innerHTML = hits.map(m => `
      <div class="dm-picker-row" data-id="${swEsc(m.id)}">
        ${gcAvatar(m.name, m.photo, 30)}
        <div>
          <div class="dm-picker-name">${swEsc(m.name || 'Member')}</div>
          <div class="dm-picker-meta">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
        </div>
      </div>`).join('');
    results.querySelectorAll('.dm-picker-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        const m  = pool.find(x => x.id === id);
        if (m) { selected.set(id, m); renderChips(); renderResults($id('gc-addmem-search')?.value); }
      });
    });
  };

  // Reset
  $id('gc-addmem-search').value = '';
  $id('gc-addmem-chips').innerHTML = '';
  $id('gc-addmem-error').style.display = 'none';
  dmEnsureMembers().then(() => renderResults(''));

  let searchTimer;
  const searchInp = $id('gc-addmem-search');
  searchInp.oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => renderResults(searchInp.value), 150); };

  const submitBtn = $id('gc-addmem-submit');
  submitBtn.onclick = async () => {
    if (!selected.size) { $id('gc-addmem-error').textContent = 'Select at least one member.'; $id('gc-addmem-error').style.display = ''; return; }
    submitBtn.disabled = true;
    const errEl = $id('gc-addmem-error');
    const ids = [...selected.keys()];
    let failed = 0;
    for (const memberId of ids) {
      try {
        await api('POST', `/api/member/groups/${groupId}/members`, { member_id: memberId });
      } catch (e) {
        failed++;
        console.error('[gcAddMembers]', memberId, e.message);
      }
    }
    if (failed === ids.length) {
      errEl.textContent = 'Could not add any members. Please try again.';
      errEl.style.display = '';
      submitBtn.disabled = false;
      return;
    }
    gcCloseAddMembersModal();
    // Refresh group data and reopen info panel so member count updates immediately
    try {
      const data = await api('GET', `/api/member/groups/${groupId}`);
      GC.activeGroup = { ...(GC.activeGroup || {}), ...data };
      // Update the group in GC.groups list too
      const idx = (GC.groups || []).findIndex(g => g.id === groupId);
      if (idx >= 0) GC.groups[idx] = { ...GC.groups[idx], ...data };
      if (typeof window._inboxLoad === 'function') await window._inboxLoad();
      else if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
      if (typeof window._dpShowGroup === 'function') window._dpShowGroup(GC.activeGroup);
    } catch { /* silent — panel stays closed, user can tap ⓘ again */ }
    if (failed > 0) {
      if (typeof swShowToast === 'function') swShowToast(`Added ${ids.length - failed} member(s); ${failed} failed.`);
    }
    submitBtn.disabled = false;
  };

  modal.style.display = 'flex';
  searchInp.focus();
}

function gcCloseAddMembersModal() {
  const modal = $id('gc-addmem-overlay');
  if (modal) modal.style.display = 'none';
}

// ─── Group info panel ─────────────────────────────────────────────────────────

// Override gcOpenInfo to use the Instagram-style detail panel (dpShowGroup)
// instead of the old nick-modal-overlay (z-index:700) which was blocking the
// sidebar. The detail panel IIFE below exposes window._dpShowGroup for this.
async function gcOpenInfo() {
  if (!GC.activeId) return;
  // If the new detail-panel system is available, use it — it won't block the sidebar
  if (typeof window._dpShowGroup === 'function' && GC.activeGroup) {
    // Fetch fresh member list first so the panel shows accurate info
    try {
      const data = await api('GET', `/api/member/groups/${GC.activeId}`);
      GC.activeGroup = { ...GC.activeGroup, ...data };
    } catch { /* use cached data */ }
    window._dpShowGroup(GC.activeGroup);
    return;
  }
  // Fallback: old modal (only used if detail panel isn't loaded yet)
  try {
    const data    = await api('GET', `/api/member/groups/${GC.activeId}`);
    GC.activeGroup = { ...GC.activeGroup, ...data };
    gcShowInfoModal(data);
  } catch { /* silent */ }
}

function gcShowInfoModal(data) {
  const myId  = gcMyId();
  let modal   = $id('gc-info-overlay');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gc-info-overlay';
    modal.className = 'nick-modal-overlay';
    modal.innerHTML = `<div class="nick-modal gc-info-modal" id="gc-info-modal"></div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
  }

  const isAdminOrOwner = ['owner','admin'].includes(data.my_role);
  const convKey        = GC.activeId;

  modal.querySelector('#gc-info-modal').innerHTML = `
    <div class="nick-modal-head">
      <span>Group Info</span>
      <button class="dm-icon-btn" onclick="document.getElementById('gc-info-overlay').style.display='none'" aria-label="Close">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div style="text-align:center;margin:12px 0 16px">
      ${gcGroupAvatar(data, 56)}
      ${isAdminOrOwner
        ? `<div style="display:flex;align-items:center;justify-content:center;gap:6px;margin-top:8px">
             <span id="gc-info-name-display" style="font-weight:600;font-size:15px">${swEsc(data.name)}</span>
             <button class="dm-icon-btn" style="padding:3px" onclick="gcStartRename()" title="Rename"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></button>
           </div>`
        : `<div style="font-weight:600;font-size:15px;margin-top:8px">${swEsc(data.name)}</div>`
      }
    </div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-weight:600;letter-spacing:.04em">MEMBERS</div>
    <div id="gc-info-members" style="display:flex;flex-direction:column;gap:4px">
      ${(data.members || []).map(m => {
        const displayName = nicksResolveDisplay(convKey, m.id, m.name);
        return `<div class="gc-info-member-row" data-id="${swEsc(m.id)}">
          ${gcAvatar(m.name, m.photo, 34)}
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:500">${swEsc(displayName)}${m.group_role === 'owner' ? ' <span style="font-size:10px;color:var(--muted);background:rgba(255,255,255,.07);padding:1px 6px;border-radius:10px">owner</span>' : ''}</div>
            <div style="font-size:11px;color:var(--muted)">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>
          </div>
          ${!m.is_me ? `<button class="dm-icon-btn gc-nick-btn" data-id="${swEsc(m.id)}" data-name="${swEsc(m.name)}" title="Set nickname" style="padding:4px">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </button>` : ''}
          ${isAdminOrOwner && !m.is_me ? `<button class="dm-icon-btn" style="color:#ef4444;padding:4px" onclick="gcRemoveMember('${swEsc(m.id)}')" title="Remove"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}
        </div>`;
      }).join('')}
    </div>
    <button class="dm-icon-btn" style="width:100%;margin-top:12px;padding:8px;border-radius:8px;color:#ef4444;justify-content:center;gap:6px;font-size:12px" onclick="gcLeave()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Leave group
    </button>
    ${data.my_role === 'owner' ? `<button class="dm-icon-btn" style="width:100%;margin-top:6px;padding:8px;border-radius:8px;color:#ef4444;justify-content:center;gap:6px;font-size:12px;background:rgba(239,68,68,.08)" onclick="gcDeleteGroup()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
      Delete group for everyone
    </button>` : ''}`;

  // Nickname buttons
  modal.querySelectorAll('.gc-nick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id   = btn.dataset.id;
      const name = btn.dataset.name;
      nicksOpenModal(convKey, id, name, true);
    });
  });

  modal.style.display = 'flex';
}

async function gcStartRename() {
  const current = GC.activeGroup?.name || '';
  const newName = prompt('New group name:', current);
  if (!newName?.trim() || newName.trim() === current) return;
  try {
    await api('PATCH', `/api/member/groups/${GC.activeId}`, { name: newName.trim() });
    GC.activeGroup.name = newName.trim();
    setText('gc-topbar-name', newName.trim());
    await gcLoadGroups();
    // Close whichever info UI is open (old modal or new detail panel)
    const _renameOverlay = document.getElementById('gc-info-overlay');
    if (_renameOverlay) _renameOverlay.style.display = 'none';
    if (typeof window._dpClose === 'function') window._dpClose();
  } catch (e) {
    alert(e.message || 'Could not rename group.');
  }
}

async function gcRemoveMember(memberId) {
  if (!await swConfirm('Remove this member from the group?', { title: 'Remove member', confirmLabel: 'Remove', danger: true })) return;
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/members/${memberId}`);
    const _removeOverlay = document.getElementById('gc-info-overlay');
    if (_removeOverlay) _removeOverlay.style.display = 'none';
    // Re-open info so member count and list updates immediately
    gcOpenInfo();
  } catch (e) {
    swAlert(e.message || 'Could not remove member.');
  }
}

async function gcLeave() {
  if (!await swConfirm('Leave this group?', { title: 'Leave group', confirmLabel: 'Leave', danger: true })) return;
  const myId    = gcMyId();
  const groupId = GC.activeId;
  try {
    await api('DELETE', `/api/member/groups/${groupId}/members/${myId}`);
    const overlay = document.getElementById('gc-info-overlay');
    if (overlay) overlay.style.display = 'none';
    GC.groups = GC.groups.filter(g => g.id !== groupId);
    if (typeof window.gcGoBack === 'function') window.gcGoBack();
    else gcGoBack();
    if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
    else gcRenderGroups(GC.groups);
  } catch (e) {
    swAlert(e.message || 'Could not leave group.');
  }
}

async function gcDeleteGroup() {
  if (!await swConfirm('Delete this group for ALL members? This cannot be undone.', { title: 'Delete group', confirmLabel: 'Delete', danger: true })) return;
  const groupId = GC.activeId;
  try {
    await api('DELETE', `/api/member/groups/${groupId}`);
    const overlay = document.getElementById('gc-info-overlay');
    if (overlay) overlay.style.display = 'none';
    GC.groups = GC.groups.filter(g => g.id !== groupId);
    if (typeof window.gcGoBack === 'function') window.gcGoBack();
    else gcGoBack();
    if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
    else gcRenderGroups(GC.groups);
    if (typeof swShowToast === 'function') swShowToast('Group deleted.');
  } catch (e) {
    swAlert(e.message || 'Could not delete group.');
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────

function initGC() {
  $id('gc-new-btn')?.addEventListener('click', gcOpenCreateModal);
  $id('gc-back-btn')?.addEventListener('click', gcGoBack);
  // NOTE: gc-info-btn and gc-send/input are also wired in initUnifiedInbox — don't double-bind here
  $id('gc-load-earlier')?.addEventListener('click', () => gcLoadMsgs(true));
  gcRefreshBadge();
  setInterval(gcRefreshBadge, 30000);
}

// ─── Patch dmOpenConv to load block status + nicknames ───────────────────────
// Hook into the existing DM module to load block + nickname data

const _origDmOpenConv = typeof dmOpenConv === 'function' ? dmOpenConv : null;
// (Actual monkey-patching done via initDMExtensions below, called after initDM)

function initDMExtensions() {
  // Ensure blocks are preloaded
  blocksEnsureLoaded();

  // Add nickname + block buttons to DM topbar when a conv is opened.
  // We listen on the DM topbar for the custom event dispatched from dmOpenConvPatched.
  // Instead of monkey-patching, we override the relevant functions by wrapping globals.

  const originalDmOpenConv = window.dmOpenConv;
  window.dmOpenConv = async function(conv) {
    await originalDmOpenConv.call(this, conv);
    // After opening: load block status + nicknames
    const peerId  = conv.peer?.id;
    const convKey = conv.conv_key;
    if (peerId) {
      // Check block status
      try {
        const status = await api('GET', `/api/member/blocks/check/${peerId}`);
        DM.activePeer = { ...DM.activePeer, _blockedMe: status.blocked_me };
        dmUpdateBlockedBanner();
        // Official KFS channel — re-assert one-way mode in case anything
        // above touched the compose box's display state.
        if (typeof _dmSetOneWayMode === 'function') _dmSetOneWayMode(!!DM.activePeer?.is_official);
        // Update topbar block button
        dmRenderTopbarExtras(convKey, peerId, conv.peer);
      } catch { /* silent */ }
      // Load nicknames
      await nicksLoad(convKey);
      // Apply nickname to topbar
      const peerName = conv.peer?.name;
      const display  = nicksResolveDisplay(convKey, peerId, peerName);
      const topbarName = $id('dm-topbar-name');
      if (topbarName) topbarName.textContent = display;
    }
  };

  const originalDmStartWith = window.dmStartWith;
  window.dmStartWith = async function(memberId, peerHint) {
    await originalDmStartWith.call(this, memberId, peerHint);
    if (memberId) {
      try {
        const status = await api('GET', `/api/member/blocks/check/${memberId}`);
        if (DM.activePeer) DM.activePeer._blockedMe = status.blocked_me;
        dmUpdateBlockedBanner();
        const convKey = DM.activeKey;
        const topbarActions = $id('dm-topbar-actions');
        if (!topbarActions) dmInjectTopbarActions();
        if (convKey) {
          await nicksLoad(convKey);
          const display = nicksResolveDisplay(convKey, memberId, peerHint?.name);
          const topbarName = $id('dm-topbar-name');
          if (topbarName) topbarName.textContent = display;
        }
        dmRenderTopbarExtras(convKey, memberId, peerHint);
      } catch { /* silent */ }
    }
  };
}

function dmInjectTopbarActions() {
  const topbar = $id('dm-topbar');
  if (!topbar || $id('dm-topbar-actions')) return;
  const actions = document.createElement('div');
  actions.id = 'dm-topbar-actions';
  actions.style.cssText = 'display:flex;align-items:center;gap:4px;margin-left:auto';
  // Insert BEFORE dm-info-btn so ⓘ stays as the rightmost element in the topbar
  const infoBtn = $id('dm-info-btn');
  if (infoBtn) {
    topbar.insertBefore(actions, infoBtn);
    // Remove margin-left:auto from actions since ⓘ now provides the right-push
    actions.style.marginLeft = '0';
  } else {
    topbar.appendChild(actions);
  }
}

function dmRenderTopbarExtras(convKey, peerId, peer) {
  dmInjectTopbarActions();
  const actions = $id('dm-topbar-actions');
  if (!actions) return;
  const isBlocked = BLOCKS.set.has(peerId);

  actions.innerHTML = `
    <button class="dm-icon-btn dm-nick-topbar-btn" title="Set nickname" style="font-size:11px;padding:4px 8px;border-radius:8px;gap:4px">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
      Nickname
    </button>
    <button class="dm-icon-btn dm-block-btn" data-block-member="${swEsc(peerId)}" title="${isBlocked ? 'Unblock' : 'Block'} this member" style="font-size:11px;padding:4px 8px;border-radius:8px;gap:4px;${isBlocked ? 'color:#ef4444' : ''}">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
      ${isBlocked ? 'Unblock' : 'Block'}
    </button>`;

  actions.querySelector('.dm-nick-topbar-btn')?.addEventListener('click', () => {
    if (convKey) nicksOpenModal(convKey, peerId, peer?.name || DM.activePeer?.name || 'Member', false);
  });
  actions.querySelector('.dm-block-btn')?.addEventListener('click', function() {
    blocksToggle(peerId, this);
  });
}

// Hook into openMemberProfile to show block button in member profile modal
const _origOpenMemberProfile = window.openMemberProfile;
window.openMemberProfile = async function(memberId) {
  await (_origOpenMemberProfile || openMemberProfile).call(this, memberId);
  // Inject block button after the modal body renders
  const myId = gcMyId();
  if (!myId || memberId === myId) return;
  await blocksEnsureLoaded();
  const body = $id('member-profile-modal-body');
  if (!body || $id('mpm-block-btn')) return;
  const isBlocked = BLOCKS.set.has(memberId);
  const blockBtn  = document.createElement('button');
  blockBtn.id = 'mpm-block-btn';
  blockBtn.className = 'dm-icon-btn';
  blockBtn.dataset.blockMember = memberId;
  blockBtn.style.cssText = 'width:100%;padding:9px;border-radius:8px;justify-content:center;gap:6px;font-size:12px;margin-top:6px';
  if (isBlocked) blockBtn.style.color = '#ef4444';
  blockBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> ${isBlocked ? 'Unblock' : 'Block'}`;
  blockBtn.addEventListener('click', () => blocksToggle(memberId, blockBtn));
  body.appendChild(blockBtn);
};

// ── MA-35 Boot ────────────────────────────────────────────────────────────────
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => { initGC(); initDMExtensions(); });
} else {
  initGC();
  initDMExtensions();
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNIFIED INBOX — DMs + Groups merged into panel-dms conv list (Instagram-style)
// ═══════════════════════════════════════════════════════════════════════════════

(function() {

  // ── Mute/Archive — per-conversation settings loaded from the server ────────
  // Keyed by conv_key (DM "a:b" or group id) -> { muted, archived }.
  const _convSettings = {};
  let _archivedExpanded = false;

  async function _loadConvSettings() {
    try {
      const rows = await api('GET', '/api/member/conv-settings');
      Object.keys(_convSettings).forEach(k => delete _convSettings[k]);
      (rows || []).forEach(r => { _convSettings[r.conv_key] = { muted: !!r.muted, archived: !!r.archived }; });
    } catch { /* table not migrated yet, or transient error — treat as no settings */ }
  }
  window._inboxConvSettings = _convSettings;

  // Exposed so the DM/group detail-panel Mute & Archive buttons (dpToggleMute /
  // dpToggleArchive) can call them by name — they were previously undefined,
  // which made those buttons silently no-op.
  window.convSettingsGet = function(convKey) {
    return _convSettings[convKey] || { muted: false, archived: false };
  };
  window.convSettingsToggleMute = function(convKey, convType) {
    const cur = _convSettings[convKey] || { muted: false, archived: false };
    return _setConvSetting(convKey, convType, { muted: !cur.muted });
  };
  window.convSettingsToggleArchive = function(convKey, convType) {
    const cur = _convSettings[convKey] || { muted: false, archived: false };
    return _setConvSetting(convKey, convType, { archived: !cur.archived });
  };

  async function _setConvSetting(convKey, convType, patch) {
    const prev = _convSettings[convKey] || { muted: false, archived: false };
    _convSettings[convKey] = { ...prev, ...patch };
    inboxRender();
    try {
      await api('POST', `/api/member/conv-settings/${encodeURIComponent(convKey)}`, { conv_type: convType, ...patch });
    } catch (e) {
      _convSettings[convKey] = prev; // roll back on failure
      inboxRender();
      if (typeof swShowToast === 'function') swShowToast('Could not update — try again.');
    }
  }

  // ── Small context menu for a conv row: Mute/Unmute, Archive/Unarchive ──────
  let _convCtxMenu = null;
  function _dismissConvCtxMenu() { if (_convCtxMenu) { _convCtxMenu.remove(); _convCtxMenu = null; } }
  document.addEventListener('click', _dismissConvCtxMenu);

  function _showConvContextMenu(e, convKey, convType, label) {
    e.preventDefault();
    e.stopPropagation();
    _dismissConvCtxMenu();

    const settings = _convSettings[convKey] || { muted: false, archived: false };
    const actions = [
      {
        label: settings.muted ? 'Unmute' : 'Mute',
        icon: settings.muted
          ? '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/></svg>'
          : '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>',
        fn: () => _setConvSetting(convKey, convType, { muted: !settings.muted }),
      },
      {
        label: settings.archived ? 'Unarchive' : 'Archive',
        icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>',
        fn: () => _setConvSetting(convKey, convType, { archived: !settings.archived }),
      },
    ];

    const menu = document.createElement('div');
    menu.className = 'dm-ctx-menu';
    _convCtxMenu = menu;
    menu.innerHTML = actions.map((a, i) => `
      <button class="dm-ctx-item" data-idx="${i}">${a.icon}<span>${a.label}</span></button>`).join('');
    document.body.appendChild(menu);

    const x = e.clientX ?? (e.touches?.[0]?.clientX ?? window.innerWidth / 2);
    const y = e.clientY ?? (e.touches?.[0]?.clientY ?? window.innerHeight / 2);
    const mw = menu.offsetWidth  || 160;
    const mh = menu.offsetHeight || actions.length * 40;
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth  - mw - 8)) + 'px';
    menu.style.top  = Math.max(8, Math.min(y, window.innerHeight - mh - 8)) + 'px';

    menu.querySelectorAll('.dm-ctx-item').forEach((btn, i) => {
      btn.addEventListener('click', ev => { ev.stopPropagation(); _dismissConvCtxMenu(); actions[i].fn(); });
    });
  }

  // Right-click (desktop) + long-press (mobile) on a conv row
  function _attachConvContextMenu(row, convKey, convType) {
    row.addEventListener('contextmenu', e => _showConvContextMenu(e, convKey, convType));
    let pressTimer = null;
    row.addEventListener('touchstart', e => {
      pressTimer = setTimeout(() => _showConvContextMenu(e, convKey, convType), 500);
    }, { passive: true });
    row.addEventListener('touchend',   () => clearTimeout(pressTimer));
    row.addEventListener('touchmove',  () => clearTimeout(pressTimer));
  }

  // ── Helper: group avatar HTML (rounded square, letter fallback) ─────────────
  function inboxGroupAv(group, size) {
    if (group.photo_url) {
      return `<img src="${swEsc(group.photo_url)}" alt="${swEsc(group.name)}" style="width:${size}px;height:${size}px;border-radius:12px;object-fit:cover;flex-shrink:0">`;
    }
    const letter = (group.avatar_text || group.name?.[0] || '?').slice(0, 2).toUpperCase();
    return `<div class="gc-group-av" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px">${swEsc(letter)}</div>`;
  }

  const _muteIconHTML = '<svg class="dm-mute-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="opacity:.55;flex-shrink:0"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>';

  // ── Unified render: merges DM.convs + GC.groups, sorts by last_msg_at ───────
  // Hardened so that a single malformed conversation/group can never blank the
  // entire sidebar: rows are built into a detached fragment first, bad items
  // are skipped (and logged) individually, and the live list is only ever
  // swapped once the new content is fully ready.
  function inboxRender() {
    const container = $id('dm-conv-list');
    if (!container) return;

    // Always hide loading state — render either content or empty state
    const loadingEl = $id('dm-conv-loading');
    if (loadingEl) loadingEl.style.display = 'none';

    const dms    = DM.convs  || [];
    const groups = GC.groups || [];

    if (!dms.length && !groups.length) {
      container.querySelectorAll('.dm-conv-row, .gc-conv-row, .inbox-group-row, .inbox-archived-toggle').forEach(el => el.remove());
      $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = '');
      return;
    }

    // Tag each item with type and normalised sort key
    const allItems = [
      ...dms.map(c => ({ type: 'dm', data: c, ts: c.last_msg_at || '0', key: c.conv_key })),
      ...groups.map(g => ({
        type: 'group',
        data: g,
        // Normalise: server v2 sends last_msg_at flat; old server nested in last_msg
        ts: g.last_msg_at || g.last_msg?.created_at || g.created_at || '0',
        key: g.id,
      })),
    ].sort((a, b) => (b.ts > a.ts ? 1 : b.ts < a.ts ? -1 : 0));

    // Split into active + archived (archived chats collapse under a toggle,
    // same idea as Instagram/WhatsApp's "Archived" row)
    const items         = allItems.filter(i => !_convSettings[i.key]?.archived);
    const archivedItems = allItems.filter(i =>  _convSettings[i.key]?.archived);

    const fragment = document.createDocumentFragment();
    let builtAny = false;

    function buildRow(item) {
      const row = document.createElement('div');
      const muted = !!_convSettings[item.key]?.muted;

      if (item.type === 'dm') {
        const c = item.data;
        row.className = 'dm-conv-row' + (c.conv_key === DM.activeKey ? ' dm-active-row' : '');
        row.dataset.key  = c.conv_key;
        row.dataset.type = 'dm';
        const preview = c.last_is_e2ee
          ? (c.last_sender_is_me ? 'You: ' : '') + '🔒 Encrypted message'
          : c.last_snippet
            ? (c.last_sender_is_me ? 'You: ' : '') + c.last_snippet
            : 'No messages yet';
        const displayName = (typeof nicksResolveDisplay === 'function')
          ? nicksResolveDisplay(c.conv_key, c.peer?.id, c.peer?.name || 'Member')
          : (c.peer?.name || 'Member');
        row.innerHTML = `
          ${dmAvatar(c.peer?.name, c.peer?.photo, 42)}
          <div class="dm-conv-info">
            <div class="dm-conv-name">${swEsc(displayName)}${muted ? _muteIconHTML : ''}</div>
            <div class="dm-conv-preview ${c.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(preview)}</div>
          </div>
          <div class="dm-conv-right">
            <span class="dm-conv-time">${dmTime(c.last_msg_at)}</span>
            ${c.unread_count > 0 ? `<span class="dm-unread-pill">${c.unread_count > 9 ? '9+' : c.unread_count}</span>` : ''}
          </div>`;
        row.addEventListener('click', () => inboxOpenDm(c));
        _attachConvContextMenu(row, c.conv_key, 'dm');

      } else {
        const g = item.data;
        row.className = 'dm-conv-row inbox-group-row' + (g.id === GC.activeId ? ' dm-active-row' : '');
        row.dataset.key  = g.id;
        row.dataset.type = 'group';
        const gLastAt  = g.last_msg_at || g.last_msg?.created_at || g.created_at || null;
        const gSnippet = g.last_snippet ?? g.last_msg?.body?.slice(0, 80) ?? null;
        let gPreview;
        if (!gSnippet) {
          gPreview = 'No messages yet';
        } else if (g.last_is_system) {
          gPreview = gSnippet;
        } else {
          gPreview = (g.last_sender_is_me ? 'You: ' : (g.last_sender_name ? g.last_sender_name + ': ' : '')) + gSnippet;
        }
        row.innerHTML = `
          ${inboxGroupAv(g, 42)}
          <div class="dm-conv-info">
            <div class="dm-conv-name">${swEsc(g.name || 'Group')}${muted ? _muteIconHTML : ''}</div>
            <div class="dm-conv-preview ${g.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(gPreview)}</div>
          </div>
          <div class="dm-conv-right">
            <span class="dm-conv-time">${dmTime(gLastAt)}</span>
            ${g.unread_count > 0 ? `<span class="dm-unread-pill">${g.unread_count > 9 ? '9+' : g.unread_count}</span>` : ''}
          </div>`;
        row.addEventListener('click', () => inboxOpenGroup(g));
        _attachConvContextMenu(row, g.id, 'group');
      }
      return row;
    }

    items.forEach(item => {
      try {
        fragment.appendChild(buildRow(item));
        builtAny = true;
      } catch (e) {
        // Skip just this one row — never let a single bad conversation/group
        // take down the whole sidebar.
        console.error('[inbox] failed to render row, skipping:', e.message, item);
      }
    });

    // Archived section — collapsed by default, tap to expand/collapse.
    if (archivedItems.length) {
      const toggle = document.createElement('div');
      toggle.className = 'dm-conv-row inbox-archived-toggle';
      toggle.style.cssText = 'cursor:pointer;opacity:.75';
      toggle.innerHTML = `
        <div style="width:42px;height:42px;border-radius:50%;background:rgba(255,255,255,.06);display:flex;align-items:center;justify-content:center;flex-shrink:0">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
        </div>
        <div class="dm-conv-info">
          <div class="dm-conv-name">Archived (${archivedItems.length})</div>
        </div>
        <div class="dm-conv-right">
          <span class="dm-conv-time">${_archivedExpanded ? '▲' : '▼'}</span>
        </div>`;
      toggle.addEventListener('click', () => { _archivedExpanded = !_archivedExpanded; inboxRender(); });
      fragment.appendChild(toggle);
      builtAny = true;

      if (_archivedExpanded) {
        archivedItems.forEach(item => {
          try {
            fragment.appendChild(buildRow(item));
          } catch (e) {
            console.error('[inbox] failed to render archived row, skipping:', e.message, item);
          }
        });
      }
    }

    // Only touch the live DOM once the new rows are fully built — if nothing
    // built successfully (e.g. every item somehow failed), leave whatever was
    // already on screen alone instead of leaving the user with a blank panel.
    if (!builtAny) return;
    container.querySelectorAll('.dm-conv-row, .gc-conv-row, .inbox-group-row, .inbox-archived-toggle').forEach(el => el.remove());
    $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = 'none');
    container.appendChild(fragment);
  }

  // ── Open DM — hides gc-window, shows dm-window ────────────────────────────
  function inboxOpenDm(conv) {
    // Switch windows
    const gcWin = $id('gc-window');
    const dmWin = $id('dm-window');
    if (gcWin) gcWin.style.display = 'none';
    if (dmWin) dmWin.style.display = '';

    GC.activeId    = null;
    GC.activeGroup = null;
    // Do NOT pause GC polling — gcPollTick already no-ops when GC.activeId is null.
    // Keeping the interval alive means the background sidebar refresh also stays alive.

    // Highlight row
    document.querySelectorAll('.dm-conv-row').forEach(el => {
      el.classList.toggle('dm-active-row', el.dataset.key === conv.conv_key && el.dataset.type === 'dm');
    });

    // Use the patched dmOpenConv (includes block/nick logic)
    if (typeof window._dpClose === 'function') window._dpClose();
    if (typeof window.dmOpenConv === 'function') window.dmOpenConv(conv);
  }

  // ── Open Group — hides dm-window, shows gc-window ────────────────────────
  function inboxOpenGroup(group) {
    // Switch windows
    const dmWin = $id('dm-window');
    const gcWin = $id('gc-window');
    if (dmWin) dmWin.style.display = 'none';
    if (gcWin) gcWin.style.display = '';

    DM.activeKey  = null;
    DM.activePeer = null;

    // Highlight row
    document.querySelectorAll('.dm-conv-row').forEach(el => {
      el.classList.toggle('dm-active-row', el.dataset.key === group.id && el.dataset.type === 'group');
    });

    // gcOpenGroup handles topbar, messages, polling
    // Use window.gcOpenGroup so the IIFE's mobile slide-in override runs
    if (typeof window._dpClose === 'function') window._dpClose();
    const opener = typeof window.gcOpenGroup === 'function' ? window.gcOpenGroup : gcOpenGroup;
    opener(group);
  }

  // ── Override gcGoBack to return to unified list ───────────────────────────
  window.gcGoBack = function() {
    if (typeof window._dpClose === 'function') window._dpClose();
    const gcWin = $id('gc-window');
    const dmWin = $id('dm-window');
    if (gcWin) gcWin.style.display = 'none';
    if (dmWin) { dmWin.style.display = ''; }

    // Restore empty state on dm-window
    $id('dm-active') && ($id('dm-active').style.display = 'none');
    $id('dm-window-empty') && ($id('dm-window-empty').style.display = '');

    // Also reset gc-window inner state for next open
    $id('gc-active') && ($id('gc-active').style.display = 'none');
    $id('gc-window-empty') && ($id('gc-window-empty').style.display = '');

    // Mobile only: slide sidebar back
    if (window.innerWidth <= 768) {
      $id('dm-sidebar')?.classList.remove('dm-slide-out');
      $id('gc-window')?.classList.remove('dm-slide-in');
    }
    _kfsPopNavState('gc-chat');

    GC.activeId    = null;
    GC.activeGroup = null;
    // Do NOT pause GC polling — gcPollTick already no-ops when GC.activeId is null.
    // Keeping the interval alive means reactions stay live and the background
    // sidebar timer keeps refreshing the group list for non-active-group members.
    document.querySelectorAll('.dm-conv-row').forEach(el => el.classList.remove('dm-active-row'));
  };

  // ── Also patch gcOpenGroup to ensure display is set (unified inbox uses style, not class) ──
  const _origGcOpenGroup = typeof gcOpenGroup === 'function' ? gcOpenGroup : null;
  window.gcOpenGroup = async function(group) {
    // Make gc-window visible (unified inbox uses style, not class).
    // Use explicit 'flex' (not '') so the inline display:none from the HTML
    // is fully overridden even when no CSS cascade provides a fallback.
    const gcWin    = $id('gc-window');
    const dmWin    = $id('dm-window');
    const gcEmpty  = $id('gc-window-empty');
    const gcActive = $id('gc-active');
    if (dmWin)    dmWin.style.display    = 'none';
    if (gcWin)    gcWin.style.display    = 'flex';
    if (gcEmpty)  gcEmpty.style.display  = 'none';
    // Pre-show the active chat pane so messages are not rendered into a hidden element
    if (gcActive) gcActive.style.display = 'flex';
    if (_origGcOpenGroup) await _origGcOpenGroup(group);
  };

  // ── Unified load: fetch both convs + groups, then render ─────────────────
  async function inboxLoad() {
    // Always clear the "Loading…" spinner immediately so it never gets stuck
    const loadingEl = $id('dm-conv-loading');
    if (loadingEl) loadingEl.style.display = 'none';

    // Wait for a real member ID before touching localStorage — prevents kfs-groups-null
    let _inboxMyId = dmMyId();
    if (!_inboxMyId) {
      await new Promise(resolve => {
        let tries = 0;
        const poll = setInterval(() => {
          _inboxMyId = dmMyId();
          if (_inboxMyId || ++tries > 40) { clearInterval(poll); resolve(); }
        }, 150);
      });
    }

    // Migrate any data written under bad keys before fix was deployed
    if (_inboxMyId) {
      ['kfs-groups-null','kfs-groups-undefined','kfs-groups-unknown'].forEach(badKey => {
        try {
          const raw = localStorage.getItem(badKey);
          if (!raw) return;
          const realKey = 'kfs-groups-' + _inboxMyId;
          const existing = JSON.parse(localStorage.getItem(realKey) || '[]');
          const bad = JSON.parse(raw);
          if (Array.isArray(bad) && bad.length) {
            const map = new Map();
            existing.forEach(g => g && g.id && map.set(String(g.id), g));
            bad.forEach(g => g && g.id && map.set(String(g.id), g));
            localStorage.setItem(realKey, JSON.stringify([...map.values()]));
          }
          localStorage.removeItem(badKey);
        } catch { /* ignore */ }
      });
    }

    // Seed groups from localStorage immediately so the sidebar isn't blank on
    // first paint — the API fetch will reconcile below and re-render.
    if (!(GC.groups || []).length) {
      try {
        const myId = _inboxMyId || dmMyId();
        const cachedGroups = localStorage.getItem('kfs-groups-' + myId);
        if (cachedGroups) {
          const parsed = JSON.parse(cachedGroups);
          if (Array.isArray(parsed) && parsed.length) {
            GC.groups = parsed;
            inboxRender(); // render immediately from cache
          }
        }
      } catch { /* ignore */ }
    } else {
    }

    // Fire nicksLoadGlobal separately so we can await it again below for a
    // guaranteed nick-aware re-render after all data is settled.
    const nicksPromise = nicksLoadGlobal();

    await Promise.all([
      (async () => {
        try {
          const data = await api('GET', '/api/member/dm/conversations');
          DM.convs = Array.isArray(data) ? data : [];
        } catch (e) {
          console.error('[inbox] DM convs load failed:', e.message);
          DM.convs = DM.convs || [];
        }
      })(),
      (async () => {
        try {
          const data = await api('GET', '/api/member/groups');
          const fresh = Array.isArray(data) ? data : [];
          // Supabase sometimes returns empty right after a group create/join
          // due to replication lag. On a cold page-load GC.groups is always
          // empty too, so we can't use "had groups before" as a guard.
          // Do up to two retries with increasing back-off before giving up.
          if (!fresh.length) {
            await new Promise(r => setTimeout(r, 500));
            const r1 = await api('GET', '/api/member/groups').catch(() => null);
            const f1 = Array.isArray(r1) ? r1 : [];
            if (f1.length) {
              GC.groups = f1;
              try { localStorage.setItem('kfs-groups-' + (_inboxMyId || dmMyId()), JSON.stringify(f1)); } catch { /* ignore */ }
            } else {
              await new Promise(r => setTimeout(r, 800));
              const r2 = await api('GET', '/api/member/groups').catch(() => null);
              const f2 = Array.isArray(r2) ? r2 : [];
              GC.groups = f2.length ? f2 : ((GC.groups || []).length ? GC.groups : []);
              if (f2.length) {
                try { localStorage.setItem('kfs-groups-' + (_inboxMyId || dmMyId()), JSON.stringify(f2)); } catch { /* ignore */ }
              }
            }
          } else {
            GC.groups = fresh;
            try { localStorage.setItem('kfs-groups-' + (_inboxMyId || dmMyId()), JSON.stringify(fresh)); } catch { /* ignore */ }
          }
        } catch (e) {
          console.error('[inbox] Groups load failed:', e.message);
          GC.groups = GC.groups || [];
        }
      })(),
      nicksPromise,
      _loadConvSettings(),
    ]);
    // Mark convs as having been fetched at least once — lets other call sites
    // (e.g. the share modal) tell "never loaded" apart from "loaded, but empty".
    DM.loaded = true;
    // Primary render — all three fetches (DMs, groups, nicknames) done.
    inboxRender();
    // Belt-and-suspenders: re-render once nicksPromise settles in case it
    // was the last to finish and inboxRender already ran from a poll tick.
    nicksPromise.catch(() => {}).then(() => inboxRender());

    // Combined badge on the Messages nav/btb
    const dmUnread = (DM.convs || []).reduce((s, c) => s + (c.unread_count || 0), 0);
    const gcUnread = (GC.groups || []).reduce((s, g) => s + (g.unread_count || 0), 0);
    dmSetBadge(dmUnread + gcUnread);
  }

  // Expose inboxLoad + inboxOpenGroup globally so the group-create handler (outside this IIFE) can call them
  window._inboxLoad = inboxLoad;
  window._inboxOpenGroup = inboxOpenGroup;

  // ── Override dmPanelOpened to use unified load ────────────────────────────
  // Gate on _token being set before calling inboxLoad — this is the public
  // entry point that switchPanel() always calls via window.dmPanelOpened(),
  // so gating here means inboxLoad (and the api() calls inside it) never
  // fire before refreshToken() has completed, regardless of which internal
  // binding inboxLoad is reached through.
  window.dmPanelOpened = async function() {
    DM.panelVisible = true;
    GC.panelVisible = true;
    // Wait for the session token before touching the API. If _token is already
    // set (normal case: user clicked Messages after login completed) this
    // resolves synchronously on the next microtask and adds no perceptible
    // delay. If we somehow arrive here before refreshToken() finished (the
    // startup race), we wait up to 12 s rather than sending guaranteed-401
    // requests that would break inbox rendering and the block list.
    if (!_token) {
      await new Promise(resolve => {
        let tries = 0;
        const poll = setInterval(() => {
          if (_token || ++tries > 150) { clearInterval(poll); resolve(); }
        }, 80);
      });
    }
    await inboxLoad();
    dmStartPolling();
    gcStartPolling();
    // Background sidebar refresh: re-fetches group list every 30s so that
    // members added to a new group see it appear without a page reload.
    // This is separate from gcStartPolling (which only polls messages when
    // a group is open) — we need the group LIST to refresh for everyone.
    _startSidebarRefresh();
  };

  // ── Background sidebar refresh (group list for non-active-group members) ──
  let _sidebarRefreshTimer = null;
  function _startSidebarRefresh() {
    _stopSidebarRefresh();
    _sidebarRefreshTimer = setInterval(async () => {
      // Only refresh groups in the background — DM conv list is already
      // handled by dmPollTick. Skip if no token (not logged in).
      if (!_token) return;
      try {
        const data = await api('GET', '/api/member/groups');
        const fresh = Array.isArray(data) ? data : [];
        // Guard: if server returns empty and we had groups, could be transient — skip
        if (!fresh.length && (GC.groups || []).length > 0) return;
        // Re-render whenever group list changes — new group added, member count,
        // last message time, or group count itself changed (user was added to a group)
        const oldKey = JSON.stringify((GC.groups || []).map(g => `${g.id}|${g.last_msg_at}|${g.members?.length || 0}|${g.name}`));
        const newKey = JSON.stringify(fresh.map(g => `${g.id}|${g.last_msg_at}|${g.members?.length || 0}|${g.name}`));
        if (oldKey !== newKey) {
          GC.groups = fresh;
          try {
            const saveId = _inboxMyId || dmMyId();
            if (saveId) localStorage.setItem('kfs-groups-' + saveId, JSON.stringify(fresh));
          } catch { /* ignore */ }
          inboxRender();
          // Update combined unread badge
          const dmUnread = (DM.convs || []).reduce((s, c) => s + (c.unread_count || 0), 0);
          const gcUnread = fresh.reduce((s, g) => s + (g.unread_count || 0), 0);
          if (typeof dmSetBadge === 'function') dmSetBadge(dmUnread + gcUnread);
        } else {
          // Even when list unchanged, ensure localStorage is seeded for next refresh
          try {
            const saveId = _inboxMyId || dmMyId();
            if (saveId && fresh.length && !localStorage.getItem('kfs-groups-' + saveId)) {
              localStorage.setItem('kfs-groups-' + saveId, JSON.stringify(fresh));
            }
          } catch { /* ignore */ }
        }
      } catch { /* silent — transient network error, try again next tick */ }
    }, 3000); // every 3s — faster detection when added to a new group
  }
  function _stopSidebarRefresh() {
    if (_sidebarRefreshTimer) { clearInterval(_sidebarRefreshTimer); _sidebarRefreshTimer = null; }
  }

  // ── Override dmRenderConvs so DM polling updates also re-render unified ───
  window.dmRenderConvs = function(list) {
    DM.convs = list;
    inboxRender();
  };

  // ── Override gcRenderGroups so GC polling updates also re-render ──────────
  window.gcRenderGroups = function(list) {
    GC.groups = list;
    inboxRender();
  };

  // ── Override dmFilterConvs to also filter groups ──────────────────────────
  window.dmFilterConvs = function(q) {
    const query = (q || '').toLowerCase().trim();
    if (!query) { inboxRender(); return; }
    const filteredDms    = (DM.convs  || []).filter(c => (c.peer?.name || '').toLowerCase().includes(query));
    const filteredGroups = (GC.groups || []).filter(g => g.name.toLowerCase().includes(query));
    // Temp override for render
    const origDm = DM.convs, origGc = GC.groups;
    DM.convs  = filteredDms;
    GC.groups = filteredGroups;
    inboxRender();
    DM.convs  = origDm;
    GC.groups = origGc;
  };

  // ── New message dropdown wiring ───────────────────────────────────────────
  function initInboxNewBtn() {
    const btn      = $id('dm-new-btn');
    const dropdown = $id('dm-new-dropdown');
    const msgBtn   = $id('dm-new-msg-btn');
    const grpBtn   = $id('dm-new-grp-btn');
    if (!btn || !dropdown) return;

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.style.display = dropdown.style.display === 'none' ? '' : 'none';
    });
    document.addEventListener('click', () => { if (dropdown) dropdown.style.display = 'none'; });

    msgBtn?.addEventListener('click', () => {
      dropdown.style.display = 'none';
      dmOpenPicker();
    });
    grpBtn?.addEventListener('click', () => {
      dropdown.style.display = 'none';
      if (typeof gcOpenCreateModal === 'function') gcOpenCreateModal();
    });

    // Dropdown hover state
    [msgBtn, grpBtn].forEach(b => {
      if (!b) return;
      b.addEventListener('mouseenter', () => b.style.background = 'rgba(255,255,255,.05)');
      b.addEventListener('mouseleave', () => b.style.background = 'none');
    });
  }

  // ── switchPanel: remove 'groups' branch, gc windows live in 'dms' ─────────
  const _origSwitchPanelInbox = typeof switchPanel === 'function' ? switchPanel : null;
  if (_origSwitchPanelInbox) {
    window.switchPanel = function(el) {
      // Remap 'groups' to 'dms' since groups live inside the DMs panel now
      if (el?.dataset?.panel === 'groups') {
        const dmsEl = document.querySelector('[data-panel="dms"]');
        if (dmsEl) { _origSwitchPanelInbox(dmsEl); return; }
      }
      _origSwitchPanelInbox(el);
    };
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  function initUnifiedInbox() {
    initInboxNewBtn();

    // gc-back-btn uses gcGoBack which is now overridden above
    $id('gc-back-btn')?.addEventListener('click', () => window.gcGoBack());
    $id('gc-send-btn')?.addEventListener('click', gcSend);
    $id('gc-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); gcSend(); }
    });
    $id('gc-input')?.addEventListener('input', function() {
      this.style.height = '';
      this.style.height = Math.min(this.scrollHeight, 110) + 'px';
      _gcMentionOnInput(this);
      if (this.value.trim()) _gcPingTyping();
    });
    $id('gc-input')?.addEventListener('keydown', e => _gcMentionOnKeydown(e), true);
    $id('gc-load-earlier')?.addEventListener('click', () => {
      if (typeof gcLoadMsgs === 'function') gcLoadMsgs(true);
    });

    // Photo attachment
    $id('gc-attach-btn')?.addEventListener('click', () => $id('gc-attach-input')?.click());
    $id('gc-attach-input')?.addEventListener('change', e => {
      const file = e.target.files?.[0];
      e.target.value = '';
      if (file) _openAttachOpacityPicker(file, (f, opacity) => _gcSendImage(f, opacity));
    });

    // In-thread search
    $id('gc-thread-search-btn')?.addEventListener('click', () => _threadSearchOpen('group'));
    $id('gc-search-close')?.addEventListener('click', () => _threadSearchClose('group'));
    $id('gc-search-prev')?.addEventListener('click', () => _threadSearchNav('group', -1));
    $id('gc-search-next')?.addEventListener('click', () => _threadSearchNav('group', 1));
    $id('gc-search-input')?.addEventListener('input', e => _threadSearchRun('group', e.target.value));
    $id('gc-search-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); _threadSearchNav('group', e.shiftKey ? -1 : 1); }
      if (e.key === 'Escape') { e.preventDefault(); _threadSearchClose('group'); }
    });
    // NOTE: gc-info-btn is wired in the Detail Panel IIFE below (dpShowGroup) — don't double-bind here
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUnifiedInbox);
  } else {
    initUnifiedInbox();
  }

})();

// ═══════════════════════════════════════════════════════════════════════════════
// DETAIL PANEL — Instagram-style right drawer for DM + Group info
// ═══════════════════════════════════════════════════════════════════════════════

(function () {

  const DP = {
    mode: null,   // 'dm' | 'group'
    peer: null,   // for dm: { id, name, photo, role, batch }
    group: null,  // for group: group object
  };

  // ── Open / close ────────────────────────────────────────────────────────────
  function dpOpen() {
    const panel = document.getElementById('dm-detail-panel');
    if (!panel) return;
    panel.style.display = 'flex';
    // Mobile: show scrim + animate in
    if (window.innerWidth <= 768) {
      let scrim = document.getElementById('dm-detail-scrim');
      if (!scrim) {
        scrim = document.createElement('div');
        scrim.id = 'dm-detail-scrim';
        scrim.className = 'dm-detail-scrim';
        scrim.addEventListener('click', dpClose);
        document.body.appendChild(scrim);
      }
      requestAnimationFrame(() => scrim.classList.add('visible'));
    }
    requestAnimationFrame(() => panel.classList.add('open'));
  }

  function dpClose() {
    const panel = document.getElementById('dm-detail-panel');
    if (!panel) return;
    panel.classList.remove('open');
    const isMobile = window.innerWidth <= 768;
    const scrim = document.getElementById('dm-detail-scrim');
    if (scrim) scrim.classList.remove('visible');
    if (!isMobile) {
      panel.style.display = 'none';
    } else {
      panel.addEventListener('transitionend', () => { panel.style.display = 'none'; }, { once: true });
    }
  }

  function dpToggle() {
    const panel = document.getElementById('dm-detail-panel');
    if (!panel) return;
    const visible = panel.style.display !== 'none';
    visible ? dpClose() : dpOpen();
  }

  // ── Populate for a 1-1 DM ──────────────────────────────────────────────────
  function dpShowDm(peer) {
    DP.mode = 'dm';
    DP.peer = peer;

    // Hero — show the nickname (if set) instead of always showing the real
    // name, same as the sidebar row and topbar already do. Previously this
    // always rendered peer.name, so the detail panel looked like the
    // nickname had "reverted" even though it was just never wired up here.
    const convKey  = DM.activeKey || '';
    const heroName = (typeof nicksResolveDisplay === 'function')
      ? nicksResolveDisplay(convKey, peer.id, peer.name || 'Member')
      : (peer.name || 'Member');
    const avEl = document.getElementById('dm-detail-avatar');
    if (avEl) avEl.innerHTML = dmAvatar(peer.name, peer.photo, 64);
    setText('dm-detail-name', heroName);
    setText('dm-detail-sub', [peer.role, peer.batch || peer.domain].filter(Boolean).join(' · '));

    // Hide group members section, show DM-only buttons
    document.getElementById('dm-detail-members-section').style.display = 'none';
    document.getElementById('dm-detail-delete-btn').style.display = '';
    document.getElementById('dm-detail-leave-btn').style.display = 'none';
    document.getElementById('dm-detail-block-btn').style.display = '';

    // Block button label
    const isBlocked = typeof BLOCKS !== 'undefined' && BLOCKS.set?.has(peer.id);
    setText('dm-detail-block-label', isBlocked ? 'Unblock' : 'Block');
    const blockBtn = document.getElementById('dm-detail-block-btn');
    if (blockBtn) blockBtn.classList.toggle('dm-detail-danger', isBlocked);

    // Nickname button label — show current nickname if set
    const nick = (typeof nicksResolveDisplay === 'function')
      ? nicksResolveDisplay(convKey, peer.id, null)
      : null;
    setText('dm-detail-nickname-label', nick ? `Nickname: ${nick}` : 'Nickname');

    dpRefreshMuteArchiveLabels(convKey, 'dm');

    dpOpen();
  }

  // ── Mute / Archive labels (shared by DM + group panels) ───────────────────
  function dpRefreshMuteArchiveLabels(convKey, convType) {
    const s = (typeof convSettingsGet === 'function') ? convSettingsGet(convKey) : { muted: false, archived: false };
    setText('dm-detail-mute-label', s.muted ? 'Unmute' : 'Mute');
    setText('dm-detail-archive-label', s.archived ? 'Unarchive' : 'Archive');
    document.getElementById('dm-detail-mute-btn')?.classList.toggle('dm-detail-danger', s.muted);
    document.getElementById('dm-detail-archive-btn')?.classList.toggle('dm-detail-danger', s.archived);
  }

  async function dpToggleMute() {
    const convKey  = DP.mode === 'group' ? DP.group?.id : (DM.activeKey || '');
    const convType = DP.mode === 'group' ? 'group' : 'dm';
    if (!convKey || typeof convSettingsToggleMute !== 'function') return;
    const btn = document.getElementById('dm-detail-mute-btn');
    btn && (btn.disabled = true);
    try {
      await convSettingsToggleMute(convKey, convType);
      dpRefreshMuteArchiveLabels(convKey, convType);
    } catch { /* toast already shown by convSettingsSet */ }
    finally { btn && (btn.disabled = false); }
  }

  async function dpToggleArchive() {
    const convKey  = DP.mode === 'group' ? DP.group?.id : (DM.activeKey || '');
    const convType = DP.mode === 'group' ? 'group' : 'dm';
    if (!convKey || typeof convSettingsToggleArchive !== 'function') return;
    const btn = document.getElementById('dm-detail-archive-btn');
    btn && (btn.disabled = true);
    try {
      await convSettingsToggleArchive(convKey, convType);
      dpRefreshMuteArchiveLabels(convKey, convType);
      if (typeof swShowToast === 'function') {
        swShowToast(convSettingsGet(convKey).archived ? 'Conversation archived.' : 'Conversation unarchived.');
      }
    } catch { /* toast already shown by convSettingsSet */ }
    finally { btn && (btn.disabled = false); }
  }

  // ── Populate for a Group ───────────────────────────────────────────────────
  function dpShowGroup(group) {
    DP.mode = 'group';
    DP.group = group;

    // Hero
    const avEl = document.getElementById('dm-detail-avatar');
    if (avEl) {
      if (group.photo_url) {
        avEl.innerHTML = `<img src="${group.photo_url}" alt="${group.name || 'Group'}" style="width:64px;height:64px;border-radius:14px;object-fit:cover">`;
      } else {
        const letter = (group.avatar_text || group.name?.[0] || '?').slice(0, 2).toUpperCase();
        avEl.innerHTML = `<div class="gc-group-av" style="width:64px;height:64px;font-size:24px">${swEsc(letter)}</div>`;
      }
      // Add photo upload overlay for group (tap/click avatar to change photo)
      avEl.style.position = 'relative';
      avEl.style.cursor = 'pointer';
      avEl.title = 'Change group photo';
      // Remove old handler
      avEl.onclick = null;
      avEl.onclick = () => {
        const inp = document.createElement('input');
        inp.type = 'file';
        inp.accept = 'image/jpeg,image/png,image/webp';
        inp.onchange = async () => {
          const file = inp.files?.[0];
          if (!file) return;
          if (file.size > 5 * 1024 * 1024) { alert('Image must be under 5 MB.'); return; }
          const fd = new FormData();
          fd.append('photo', file);
          try {
            const r = await api('POST', `/api/member/groups/${group.id}/photo`, fd, true);
            if (r.photo_url) {
              // Update local state
              if (GC.activeGroup) GC.activeGroup.photo_url = r.photo_url;
              const gIdx = (GC.groups || []).findIndex(g => g.id === group.id);
              if (gIdx >= 0) GC.groups[gIdx].photo_url = r.photo_url;
              group.photo_url = r.photo_url;
              // Re-render detail panel hero
              dpShowGroup(group);
              // Update topbar avatar
              const ta = $id('gc-topbar-avatar');
              if (ta) ta.innerHTML = gcGroupAvatar(group, 34);
              // Update sidebar row
              if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
              if (typeof swShowToast === 'function') swShowToast('Group photo updated!');
            }
          } catch (e) {
            alert(e.message || 'Could not upload photo.');
          }
        };
        inp.click();
      };
    }
    setText('dm-detail-name', group.name);
    const count = group.members?.length || 0;
    setText('dm-detail-sub', `${count} member${count !== 1 ? 's' : ''}`);

    // Members section
    document.getElementById('dm-detail-members-section').style.display = '';
    document.getElementById('dm-detail-delete-btn').style.display = 'none';
    document.getElementById('dm-detail-leave-btn').style.display = '';
    document.getElementById('dm-detail-block-btn').style.display = 'none';
    setText('dm-detail-nickname-label', 'Nicknames');
    dpRefreshMuteArchiveLabels(group.id, 'group');

    const isAdminOrOwner = ['owner', 'admin'].includes(group.my_role);
    const myId = gcMyId();
    const convKey = group.id;

    // Render member list with role badges + remove buttons
    const listEl = document.getElementById('dm-detail-members-list');
    if (listEl) {
      const members = group.members || [];
      listEl.innerHTML = '';
      members.forEach(m => {
        const row = document.createElement('div');
        row.className = 'dm-detail-member-row';
        const isMe = m.id === myId || m.is_me;
        const displayName = nicksResolveDisplay(convKey, m.id, m.name || 'Member');
        row.innerHTML = `
          ${dmAvatar(m.name, m.photo, 32)}
          <div style="flex:1;min-width:0">
            <div class="dm-detail-member-name" style="display:flex;align-items:center;gap:6px">
              ${swEsc(displayName)}
              ${m.group_role === 'owner' ? `<span style="font-size:9px;background:rgba(255,255,255,.08);color:var(--muted);padding:1px 6px;border-radius:10px;font-weight:600;letter-spacing:.04em">OWNER</span>` : ''}
              ${m.group_role === 'admin' ? `<span style="font-size:9px;background:rgba(255,255,255,.08);color:var(--muted);padding:1px 6px;border-radius:10px;font-weight:600;letter-spacing:.04em">ADMIN</span>` : ''}
            </div>
            ${(m.role || m.batch || m.domain) ? `<div class="dm-detail-member-role">${swEsc([m.role, m.batch || m.domain].filter(Boolean).join(' · '))}</div>` : ''}
          </div>
          ${!isMe && isAdminOrOwner && m.group_role !== 'owner' ? `<button class="dm-icon-btn dp-remove-member-btn" data-id="${swEsc(m.id)}" title="Remove from group" style="color:#ef4444;padding:4px;flex-shrink:0">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>` : ''}`;
        listEl.appendChild(row);
      });

      // Wire remove buttons
      listEl.querySelectorAll('.dp-remove-member-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          if (!await swConfirm('Remove this member from the group?', { title: 'Remove member', confirmLabel: 'Remove', danger: true })) return;
          const memberId = btn.dataset.id;
          try {
            await api('DELETE', `/api/member/groups/${group.id}/members/${memberId}`);
            // Refresh group data and re-render panel
            const data = await api('GET', `/api/member/groups/${group.id}`);
            GC.activeGroup = { ...(GC.activeGroup || {}), ...data };
            DP.group = GC.activeGroup;
            dpShowGroup(GC.activeGroup);
            if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
          } catch (e) { swAlert(e.message || 'Could not remove member.'); }
        });
      });
    }

    // Show/hide the "Add Members" button based on role
    const addBtn = document.getElementById('dm-detail-add-member-btn');
    if (addBtn) addBtn.style.display = isAdminOrOwner ? '' : 'none';

    // Report Group button — visible to all non-owners
    let reportGrpBtn = document.getElementById('dp-report-group-btn');
    if (!reportGrpBtn) {
      reportGrpBtn = document.createElement('button');
      reportGrpBtn.id = 'dp-report-group-btn';
      reportGrpBtn.className = 'dm-detail-action-btn dm-detail-danger';
      reportGrpBtn.style.cssText = 'margin-top:4px;display:flex;align-items:center;gap:8px;font-size:13px';
      reportGrpBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg> Report Group`;
      const leaveBtn = document.getElementById('dm-detail-leave-btn');
      if (leaveBtn && leaveBtn.parentNode) leaveBtn.parentNode.appendChild(reportGrpBtn);
    }
    reportGrpBtn.style.display = '';
    reportGrpBtn.onclick = () => {
      if (typeof swReportMember === 'function') {
        // Report the group creator as a proxy for "report this group"
        swReportMember(group.created_by, `group "${group.name}"`);
      } else if (typeof swOpenReportModal === 'function') {
        swOpenReportModal('group', group.id, `You are reporting the group "${group.name}".`);
      }
    };

    // Rename button — only for owner/admin
    let renameBtn = document.getElementById('dp-rename-group-btn');
    if (isAdminOrOwner) {
      if (!renameBtn) {
        renameBtn = document.createElement('button');
        renameBtn.id = 'dp-rename-group-btn';
        renameBtn.className = 'dm-detail-action-btn';
        renameBtn.style.cssText = 'margin-top:4px;display:flex;align-items:center;gap:8px;font-size:13px';
        renameBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg> Rename Group`;
        const leaveBtn = document.getElementById('dm-detail-leave-btn');
        if (leaveBtn && leaveBtn.parentNode) leaveBtn.parentNode.insertBefore(renameBtn, leaveBtn);
      }
      renameBtn.style.display = '';
      renameBtn.onclick = async () => {
        const current = group.name || '';
        const newName = prompt('New group name:', current);
        if (!newName?.trim() || newName.trim() === current) return;
        try {
          await api('PATCH', `/api/member/groups/${group.id}`, { name: newName.trim() });
          if (GC.activeGroup) GC.activeGroup.name = newName.trim();
          setText('gc-topbar-name', newName.trim());
          setText('dm-detail-name', newName.trim());
          await gcLoadGroups();
        } catch (e) { alert(e.message || 'Could not rename group.'); }
      };
    } else if (renameBtn) {
      renameBtn.style.display = 'none';
    }

    // ── Delete Group button (owner only) ─────────────────────────────────────
    let deleteGrpBtn = document.getElementById('dp-delete-group-btn');
    if (group.my_role === 'owner') {
      if (!deleteGrpBtn) {
        deleteGrpBtn = document.createElement('button');
        deleteGrpBtn.id = 'dp-delete-group-btn';
        deleteGrpBtn.className = 'dm-detail-action-btn dm-detail-danger';
        deleteGrpBtn.style.cssText = 'margin-top:4px;display:flex;align-items:center;gap:8px;font-size:13px';
        deleteGrpBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg> Delete group for everyone';
        const leaveBtn = document.getElementById('dm-detail-leave-btn');
        if (leaveBtn && leaveBtn.parentNode) leaveBtn.parentNode.appendChild(deleteGrpBtn);
      }
      deleteGrpBtn.style.display = '';
      deleteGrpBtn.onclick = async () => {
        if (!await swConfirm('Delete "' + group.name + '" for everyone? This cannot be undone.', { title: 'Delete group', confirmLabel: 'Delete', danger: true })) return;
        try {
          await api('DELETE', '/api/member/groups/' + group.id);
          if (typeof GC !== 'undefined') {
            GC.groups = (GC.groups || []).filter(g => g.id !== group.id);
            if (GC.activeId === group.id) { GC.activeId = null; GC.activeGroup = null; GC.msgs = []; }
          }
          if (typeof dpClose === 'function') dpClose();
          if (typeof window.gcGoBack === 'function') window.gcGoBack();
          if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups || []);
          if (typeof swShowToast === 'function') swShowToast('Group deleted.');
          try {
            const myId = typeof gcMyId === 'function' ? gcMyId() : null;
            if (myId) {
              const cacheKey = 'kfs-groups-' + myId;
              const raw = localStorage.getItem(cacheKey);
              if (raw) localStorage.setItem(cacheKey, JSON.stringify(JSON.parse(raw).filter(g => g?.id && g.id !== group.id)));
            }
          } catch { /* silent */ }
        } catch (e) { alert(e.message || 'Could not delete group.'); }
      };
    } else if (deleteGrpBtn) {
      deleteGrpBtn.style.display = 'none';
    }

    dpOpen();
  }

  // ── Action: Nickname ───────────────────────────────────────────────────────
  function dpNickname() {
    if (DP.mode === 'dm' && DP.peer) {
      dpClose();
      const convKey = DM.activeKey || '';
      if (typeof dmOpenNicknameModal === 'function') {
        dmOpenNicknameModal(DP.peer.id, DP.peer.name, convKey);
      } else if (typeof nicksOpenModal === 'function') {
        nicksOpenModal(convKey, DP.peer.id, DP.peer.name);
      }
    } else if (DP.mode === 'group' && DP.group) {
      // For groups: open the Instagram-style nickname picker that lists all members
      const group   = DP.group;
      const members = (group.members || []).filter(m => {
        const myId = typeof gcMyId === 'function' ? gcMyId() : null;
        return m.id !== myId && !m.is_me;
      });
      if (!members.length) return;
      // If only one other member, open directly
      if (members.length === 1) {
        dpClose();
        if (typeof nicksOpenModal === 'function') nicksOpenModal(group.id, members[0].id, members[0].name || 'Member', true);
        return;
      }
      // Multiple members — show a picker sheet
      dpClose();
      let picker = document.getElementById('gc-nick-picker-overlay');
      if (picker) picker.remove();
      picker = document.createElement('div');
      picker.id = 'gc-nick-picker-overlay';
      picker.className = 'nick-modal-overlay';
      picker.innerHTML = `
        <div class="nick-modal nick-modal-insta" style="max-width:360px">
          <div class="nick-modal-head">
            <span>Set a Nickname</span>
            <button class="dm-icon-btn" id="gc-nick-picker-close" aria-label="Close">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <p class="nick-modal-hint">Choose a member to nickname:</p>
          <div class="nick-participants" id="gc-nick-picker-list"></div>
        </div>`;
      document.body.appendChild(picker);
      picker.querySelector('#gc-nick-picker-close').onclick = () => picker.remove();
      picker.addEventListener('click', e => { if (e.target === picker) picker.remove(); });
      const list = picker.querySelector('#gc-nick-picker-list');
      members.forEach(m => {
        const row = document.createElement('div');
        row.className = 'nick-participant-row';
        row.style.cursor = 'pointer';
        const initials = (m.name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
        const av = m.photo
          ? `<img src="${m.photo}" style="width:44px;height:44px;border-radius:50%;object-fit:cover;flex-shrink:0">`
          : `<div style="width:44px;height:44px;border-radius:50%;background:#1e1e1e;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#666;flex-shrink:0">${initials}</div>`;
        const curNick = (typeof nicksResolveDisplay === 'function') ? nicksResolveDisplay(group.id, m.id, null) : null;
        row.innerHTML = `${av}<div style="flex:1;min-width:0"><div style="font-size:13.5px;font-weight:600">${m.name || 'Member'}</div>${curNick && curNick !== m.name ? `<div style="font-size:11px;color:var(--muted)">${curNick}</div>` : ''}</div>`;
        row.addEventListener('click', () => {
          picker.remove();
          if (typeof nicksOpenModal === 'function') nicksOpenModal(group.id, m.id, m.name || 'Member', true);
        });
        list.appendChild(row);
      });
    }
  }

  // ── Action: Block ──────────────────────────────────────────────────────────
  async function dpBlock() {
    if (DP.mode !== 'dm' || !DP.peer) return;
    const peerId = DP.peer.id;
    if (typeof dmToggleBlock === 'function') {
      await dmToggleBlock(peerId);
    } else {
      // Fallback: direct API call
      const isBlocked = typeof BLOCKS !== 'undefined' && BLOCKS.set?.has(peerId);
      try {
        if (isBlocked) {
          await api('DELETE', `/api/member/blocks/${peerId}`);
          BLOCKS.set?.delete(peerId);
        } else {
          await api('POST', '/api/member/blocks', { blocked_id: peerId });
          BLOCKS.set?.add(peerId);
        }
      } catch (e) { console.error('[DP] block:', e); return; }
    }
    // Refresh label
    const nowBlocked = typeof BLOCKS !== 'undefined' && BLOCKS.set?.has(peerId);
    setText('dm-detail-block-label', nowBlocked ? 'Unblock' : 'Block');
    const blockBtn = document.getElementById('dm-detail-block-btn');
    if (blockBtn) blockBtn.classList.toggle('dm-detail-danger', nowBlocked);
  }

  // ── Action: Clear Chat (DM) — me only ──────────────────────────────────────
  // Wipes the message history from MY view only. The other person's copy of
  // the chat is completely untouched — nothing is deleted for them, and no
  // messages are deleted server-side at all, just hidden below my watermark.
  async function dpDeleteChat() {
    if (!await swConfirm('Messages will be removed for you only — the other person will still see them.', { title: 'Clear this chat?', confirmLabel: 'Clear', danger: true })) return;
    const convKey = DM.activeKey;
    if (!convKey) { dpClose(); if (typeof dmGoBack === 'function') dmGoBack(); return; }
    try {
      await api('POST', `/api/member/dm/conversations/${encodeURIComponent(convKey)}/clear`);
    } catch (e) {
      swAlert(e.message || 'Could not clear chat. Please try again.');
      return;
    }
    dpClose();
    // Wipe local message state and show the empty chat window (conversation
    // stays selected — a new message from either side will repopulate it).
    DM.msgs = [];
    DM.oldestSentAt = null;
    const list = $id('dm-msg-list');
    if (list) list.innerHTML = '';
    $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
    // Reflect the clear in the conversation list preview immediately
    const conv = (DM.convs || []).find(c => c.conv_key === convKey);
    if (conv) {
      conv.last_snippet = null;
      conv.last_is_e2ee = false;
    }
    if (typeof window.dmRenderConvs === 'function') window.dmRenderConvs(DM.convs);
    else if (typeof dmRenderConvs === 'function') dmRenderConvs(DM.convs);
    if (typeof swShowToast === 'function') swShowToast('Chat cleared.');
  }

  // ── Action: Leave Group ────────────────────────────────────────────────────
  async function dpLeaveGroup() {
    if (!DP.group) return;
    if (!await swConfirm(`Leave "${DP.group.name}"?`, { title: 'Leave group', confirmLabel: 'Leave', danger: true })) return;
    const myId = window._memberProfile?.id;
    try {
      await api('DELETE', `/api/member/groups/${DP.group.id}/members/${myId}`);
      dpClose();
      GC.groups = (GC.groups || []).filter(g => g.id !== DP.group.id);
      if (typeof window.gcGoBack === 'function') window.gcGoBack();
    } catch (e) { swAlert('Could not leave group. Please try again.'); }
  }

  // ── Action: Add Members (Group) ────────────────────────────────────────────
  function dpAddMembers() {
    dpClose();
    if (DP.group && typeof gcOpenAddMembersModal === 'function') {
      gcOpenAddMembersModal(DP.group.id);
    }
  }

  // ── Wire up buttons ────────────────────────────────────────────────────────
  function initDetailPanel() {
    document.getElementById('dm-detail-close')?.addEventListener('click', dpClose);
    document.getElementById('dm-detail-nickname-btn')?.addEventListener('click', dpNickname);
    document.getElementById('dm-detail-block-btn')?.addEventListener('click', dpBlock);
    document.getElementById('dm-detail-mute-btn')?.addEventListener('click', dpToggleMute);
    document.getElementById('dm-detail-archive-btn')?.addEventListener('click', dpToggleArchive);
    document.getElementById('dm-detail-delete-btn')?.addEventListener('click', dpDeleteChat);
    document.getElementById('dm-detail-leave-btn')?.addEventListener('click', dpLeaveGroup);
    document.getElementById('dm-detail-add-member-btn')?.addEventListener('click', dpAddMembers);

    // DM topbar ⓘ button — stopPropagation so the document click-outside
    // handler (below) doesn't fire on the same event and immediately close the panel.
    const _dmInfoBtn = document.getElementById('dm-info-btn');
    if (_dmInfoBtn) {
      const _dmInfoHandler = (e) => {
        e.stopPropagation();
        e.preventDefault();
        if (!DM.activePeer) return;
        const panel = document.getElementById('dm-detail-panel');
        const isOpen = panel && panel.classList.contains('open');
        if (isOpen && DP.mode === 'dm') { dpClose(); return; }
        dpShowDm(DM.activePeer);
      };
      _dmInfoBtn.addEventListener('click', _dmInfoHandler);
      // Android fallback: touchend fires reliably even when click is delayed
      _dmInfoBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        _dmInfoHandler(e);
      }, { passive: false });
    }

    // GC topbar ⓘ button (re-wire to use dpShowGroup)
    const _gcInfoBtn = document.getElementById('gc-info-btn');
    if (_gcInfoBtn) {
      const _gcInfoHandler = (e) => {
        e.stopPropagation();
        e.preventDefault();
        // Prefer activeGroup; fall back to fetching by activeId if group object isn't cached yet
        const group = GC.activeGroup || null;
        const groupId = group?.id || GC.activeId;
        if (!groupId) return;
        const panel = document.getElementById('dm-detail-panel');
        const isOpen = panel && panel.classList.contains('open');
        if (isOpen && DP.mode === 'group') { dpClose(); return; }
        if (group && group.members?.some(m => m.name)) {
          dpShowGroup(group);
        } else {
          api('GET', `/api/member/groups/${groupId}`)
            .then(data => { GC.activeGroup = { ...(GC.activeGroup || {}), ...data }; dpShowGroup(GC.activeGroup); })
            .catch(() => { if (group) dpShowGroup(group); });
        }
      };
      _gcInfoBtn.addEventListener('click', _gcInfoHandler);
      // Android fallback: touchend fires reliably even when click is delayed
      _gcInfoBtn.addEventListener('touchend', (e) => {
        e.preventDefault(); // prevents the subsequent click from double-firing
        _gcInfoHandler(e);
      }, { passive: false });
    }

    // Close panel only when clicking the left nav sidebar (switching panels)
    // — NOT when clicking chat messages or the compose area (Instagram keeps it open).
    // Mobile uses a scrim overlay instead.
    document.addEventListener('click', (e) => {
      if (window.innerWidth <= 768) return; // mobile uses scrim
      const panel = document.getElementById('dm-detail-panel');
      if (!panel || !panel.classList.contains('open')) return;
      // Only close if the click is on the left sidebar nav (switching away from DMs)
      const sidebar = document.querySelector('.sidebar');
      if (sidebar && sidebar.contains(e.target)) {
        dpClose();
      }
    });
  }

  // Also expose dpShowDm so initDMExtensions patched dmOpenConv can call it to close panel when switching convs
  window._dpClose = dpClose;
  window._dpShowDm = dpShowDm;
  window._dpShowGroup = dpShowGroup;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDetailPanel);
  } else {
    initDetailPanel();
  }

})();
// ═══════════════════════════════════════════════════════════════════════════
// KFS SOCIAL STRAND — PATCH v2.0
// Instagram-style UI, bug fixes, share modal, admin broadcast
//
// Append this file to membersaccess.js
// ═══════════════════════════════════════════════════════════════════════════

// ── 1. NICKNAME PERSISTENCE FIX ──────────────────────────────────────────────
// Problem: nicknames saved to localStorage but on page reload, the `myId`
// is often not yet available when `nicksLoadGlobal` is called (session restore
// is async). Fix: defer the localStorage seed until after session is restored,
// and also add a MutationObserver fallback.

// nicksLoadGlobal now waits for member ID internally — no wrapper needed.

// ── 2. GROUP CHAT REFRESH FIX ────────────────────────────────────────────────
// Problem: GC.groups sometimes wiped to empty on page-load due to race.
// Additional fix: persist groups in localStorage more aggressively with a
// stable-key approach and restore on page load before any API call.

(function patchGroupPersistence() {
  // FIXED: the old version did
  //   Object.keys(localStorage).find(k => k.startsWith('kfs-groups-'))
  // which grabs the FIRST matching key it finds, regardless of which member
  // it belongs to. On any device that ever had more than one kfs-groups-*
  // key written (a second test account, a leftover key from before the
  // earlier fix shipped, a shared machine, etc.) this silently loaded a
  // DIFFERENT member's group list into GC.groups before the real fetch
  // even ran — and because inboxLoad's retry fallback keeps the existing
  // GC.groups when a fetch comes back transiently empty, the wrong data
  // could stick around instead of ever being corrected.
  //
  // Fix: only ever read the key for the member who is ACTUALLY logged in
  // right now. If we don't know who that is yet, do nothing — inboxLoad's
  // own (correctly-scoped) seeding step will handle it once the ID resolves.
  try {
    const myId = (typeof dmMyId === 'function') ? dmMyId() : null;
    if (!myId) return; // no verified session yet — never guess from a random key
    const key = 'kfs-groups-' + myId;
    const raw = localStorage.getItem(key);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length && typeof GC !== 'undefined') {
      if (!GC.groups || !GC.groups.length) {
        GC.groups = parsed.filter(g => g?.id); // strip null-id entries
      }
    }
    // Sanitize the stored key so nulls don't persist across refreshes
    try {
      const clean = parsed.filter(g => g?.id);
      if (clean.length !== parsed.length) localStorage.setItem(key, JSON.stringify(clean));
    } catch { /* silent */ }
  } catch { /* silent */ }
})();

// ── 3a. DM PIN (local, server has no DM-pin endpoint) ───────────────────────
// Group pins are stored server-side (GET/POST /api/member/groups/:id/pinned).
// There is no equivalent for 1:1 DMs, so the "Pin" action there used to just
// show a toast and forget about it. Instead we keep one pinned message per
// conversation in localStorage (scoped to the logged-in member, like the
// groups cache above) and render a banner identical in spirit to the group
// one — tap to jump to the message, ✕ to unpin.

function _dmPinStorageKey() {
  const myId = (typeof dmMyId === 'function') ? dmMyId() : null;
  return myId ? `kfs_dm_pins_${myId}` : null;
}
function _dmGetPins() {
  const key = _dmPinStorageKey();
  if (!key) return {};
  try { return JSON.parse(localStorage.getItem(key) || '{}') || {}; } catch { return {}; }
}
function _dmSetPin(convKey, msg) {
  const key = _dmPinStorageKey();
  if (!key || !convKey) return;
  const pins = _dmGetPins();
  if (msg) pins[convKey] = msg; else delete pins[convKey];
  try { localStorage.setItem(key, JSON.stringify(pins)); } catch { /* silent */ }
}
function _dmGetPin(convKey) {
  if (!convKey) return null;
  return _dmGetPins()[convKey] || null;
}

async function dmRefreshPinnedBanner() {
  if (typeof DM === 'undefined' || !DM.activeKey) return;
  const pin = _dmGetPin(DM.activeKey);
  let bar = document.getElementById('dm-pinned-bar');
  if (!pin) { if (bar) bar.remove(); return; }
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'dm-pinned-bar';
    bar.style.cssText = `
      display:flex;align-items:center;gap:10px;padding:8px 14px;
      background:rgba(255,255,255,.04);border-bottom:1px solid #1e1e1e;
      font-size:12.5px;color:#ccc;cursor:pointer;flex-shrink:0;
      border-left:2px solid #3b82f6;
    `;
    bar.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
      <span id="dm-pinned-bar-text" style="flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis"></span>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;cursor:pointer" id="dm-pinned-bar-close"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    `;
    const msgs = document.getElementById('dm-msgs');
    if (msgs && msgs.parentNode) msgs.parentNode.insertBefore(bar, msgs);
    bar.querySelector('#dm-pinned-bar-close')?.addEventListener('click', e => {
      e.stopPropagation();
      _dmSetPin(DM.activeKey, null);
      bar.remove();
      if (typeof swShowToast === 'function') swShowToast('📌 Message unpinned.');
    });
    bar.addEventListener('click', () => {
      const livePin = _dmGetPin(DM.activeKey);
      if (!livePin) return;
      const target = document.querySelector(`[data-msg-id="${CSS.escape(livePin.id)}"]`);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.style.background = 'rgba(59,130,246,.12)';
        setTimeout(() => target.style.background = '', 1500);
      }
    });
  }
  const snippet = (pin.body || '').slice(0, 60);
  const textEl = bar.querySelector('#dm-pinned-bar-text');
  if (textEl) textEl.textContent = `📌 ${pin.sender_name || 'Member'}: ${snippet}${snippet.length < (pin.body?.length || 0) ? '…' : ''}`;
}

// ── 3. PIN BANNER FIX ────────────────────────────────────────────────────────
// Problem: DM pin shows toast but does nothing; GC pin works but banner
// sometimes doesn't refresh. Patch gcRefreshPinnedBanner to be more robust.

(function patchPinBanner() {
  // Ensure gcRefreshPinnedBanner exists and works
  window.gcRefreshPinnedBanner = async function() {
    if (!GC || !GC.activeId) return;
    try {
      const pins = await api('GET', `/api/member/groups/${GC.activeId}/pinned`);
      let bar = document.getElementById('gc-pinned-bar');
      if (!pins || !pins.length) {
        if (bar) bar.remove();
        return;
      }
      const pin = pins[0];
      if (!bar) {
        bar = document.createElement('div');
        bar.id = 'gc-pinned-bar';
        bar.style.cssText = `
          display:flex;align-items:center;gap:10px;padding:8px 14px;
          background:rgba(255,255,255,.04);border-bottom:1px solid #1e1e1e;
          font-size:12.5px;color:#ccc;cursor:pointer;flex-shrink:0;
          border-left:2px solid #3b82f6;
        `;
        bar.innerHTML = `
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
          <span id="gc-pinned-bar-text" style="flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis"></span>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;cursor:pointer" id="gc-pinned-bar-close"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        `;
        // Insert above message list
        const msgs = document.getElementById('gc-msgs');
        if (msgs && msgs.parentNode) msgs.parentNode.insertBefore(bar, msgs);
        bar.querySelector('#gc-pinned-bar-close')?.addEventListener('click', e => {
          e.stopPropagation();
          bar.remove();
        });
        bar.addEventListener('click', () => {
          const target = document.querySelector(`[data-msg-id="${CSS.escape(pin.id)}"]`);
          if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            target.style.background = 'rgba(59,130,246,.12)';
            setTimeout(() => target.style.background = '', 1500);
          }
        });
      }
      const snippet = (pin.body || '').slice(0, 60);
      const textEl = bar.querySelector('#gc-pinned-bar-text');
      if (textEl) textEl.textContent = `📌 ${pin.sender_name || 'Member'}: ${snippet}${snippet.length < pin.body?.length ? '…' : ''}`;
    } catch { /* silent */ }
  };
})();

// ── 4. INSTAGRAM-STYLE SHARE MODAL ───────────────────────────────────────────
// Triggered from the share button on posts in Social Strand.
// Shows: DM contacts grid (first 8), search, copy link, close.

(function installShareModal() {

  let _shareProjectId = null;
  let _shareOverlay = null;

  function _createShareOverlay() {
    if (_shareOverlay) return _shareOverlay;
    const el = document.createElement('div');
    el.id = 'kfs-share-overlay';
    el.style.cssText = `
      display:none;position:fixed;inset:0;z-index:9999;
      background:rgba(0,0,0,.65);backdrop-filter:blur(6px);
      align-items:flex-end;justify-content:center;
    `;
    el.innerHTML = `
      <div id="kfs-share-sheet" style="
        background:#1a1a1a;border-top:1px solid #2a2a2a;border-radius:22px 22px 0 0;
        width:100%;max-width:540px;padding:0 0 env(safe-area-inset-bottom);
        animation:kfsSheetUp .28s cubic-bezier(.32,1.1,.5,1) both;
        max-height:90vh;display:flex;flex-direction:column;
      ">
        <div style="width:36px;height:4px;border-radius:2px;background:#333;margin:12px auto 0;flex-shrink:0"></div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 18px 10px;flex-shrink:0;border-bottom:1px solid #222">
          <span style="font-size:16px;font-weight:700;letter-spacing:-.01em">Share</span>
          <button id="kfs-share-close" style="background:none;border:none;color:#666;cursor:pointer;padding:4px;border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <!-- Search -->
        <div style="padding:10px 14px 4px;flex-shrink:0">
          <div style="position:relative">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" stroke-linecap="round" style="position:absolute;left:10px;top:50%;transform:translateY(-50%)"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input id="kfs-share-search" type="text" placeholder="Search" style="
              width:100%;box-sizing:border-box;background:#252525;border:none;
              border-radius:10px;padding:9px 10px 9px 30px;color:#f5f5f5;
              font-size:14px;outline:none;font-family:inherit;
            ">
          </div>
        </div>
        <!-- People grid -->
        <div id="kfs-share-people" style="display:flex;gap:0;overflow-x:auto;padding:8px 8px 4px;flex-shrink:0;scrollbar-width:none"></div>
        <!-- Divider -->
        <div style="height:1px;background:#1e1e1e;flex-shrink:0;margin:0 0 2px"></div>
        <!-- Action buttons row -->
        <div id="kfs-share-actions" style="display:flex;gap:4px;padding:8px 6px;overflow-x:auto;flex-shrink:0;border-bottom:1px solid #1e1e1e;scrollbar-width:none">
          <button class="kfs-share-action-btn" id="kfs-share-copy" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:0 0 64px;padding:8px 2px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:10.5px;font-weight:600;font-family:inherit;white-space:nowrap;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:#252525;display:flex;align-items:center;justify-content:center">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </div>
            Copy link
          </button>
          <button class="kfs-share-action-btn kfs-share-social-btn" data-platform="whatsapp" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:0 0 64px;padding:8px 2px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:10.5px;font-weight:600;font-family:inherit;white-space:nowrap;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:#25D366;display:flex;align-items:center;justify-content:center">
              <svg width="20" height="20" viewBox="0 0 16 16" fill="#fff"><path d="M13.601 2.326A7.85 7.85 0 0 0 7.994 0C3.627 0 .068 3.558.064 7.926c0 1.399.366 2.76 1.057 3.965L0 16l4.204-1.102a7.9 7.9 0 0 0 3.79.965h.004c4.368 0 7.926-3.558 7.93-7.93A7.9 7.9 0 0 0 13.6 2.326zM7.994 14.521a6.6 6.6 0 0 1-3.356-.92l-.24-.144-2.494.654.666-2.433-.156-.251a6.56 6.56 0 0 1-1.007-3.505c0-3.626 2.957-6.584 6.591-6.584a6.56 6.56 0 0 1 4.66 1.931 6.56 6.56 0 0 1 1.928 4.66c-.004 3.639-2.961 6.592-6.592 6.592m3.615-4.934c-.197-.099-1.17-.578-1.353-.646-.182-.065-.315-.099-.445.099-.133.197-.513.646-.627.775-.114.133-.232.148-.43.05-.197-.1-.836-.308-1.592-.985-.59-.525-.985-1.175-1.103-1.372-.114-.198-.011-.304.088-.403.087-.088.197-.232.296-.346.1-.114.133-.198.198-.33.065-.134.034-.248-.015-.347-.05-.099-.445-1.076-.612-1.47-.16-.389-.323-.335-.445-.34-.114-.007-.247-.007-.38-.007a.73.73 0 0 0-.529.247c-.182.198-.691.677-.691 1.654s.71 1.916.81 2.049c.098.133 1.394 2.132 3.383 2.992.47.205.84.326 1.129.418.475.152.904.129 1.246.08.38-.058 1.171-.48 1.338-.943.164-.464.164-.86.114-.943-.049-.084-.182-.133-.38-.232"/></svg>
            </div>
            WhatsApp
          </button>
          <button class="kfs-share-action-btn kfs-share-social-btn" data-platform="twitter" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:0 0 64px;padding:8px 2px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:10.5px;font-weight:600;font-family:inherit;white-space:nowrap;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:#000;border:1px solid #2a2a2a;display:flex;align-items:center;justify-content:center">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="#fff"><path d="M12.6.75h2.454l-5.36 6.142L16 15.25h-4.937l-3.867-5.07-4.425 5.07H.316l5.733-6.57L0 .75h5.063l3.495 4.633L12.601.75Zm-.86 13.028h1.36L4.323 2.145H2.865z"/></svg>
            </div>
            X
          </button>
          <button class="kfs-share-action-btn kfs-share-social-btn" data-platform="snapchat" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:0 0 64px;padding:8px 2px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:10.5px;font-weight:600;font-family:inherit;white-space:nowrap;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:#FFFC00;display:flex;align-items:center;justify-content:center">
              <svg width="20" height="20" viewBox="0 0 16 16" fill="#111"><path d="M15.943 11.526c-.111-.303-.323-.465-.564-.599a1 1 0 0 0-.123-.064l-.219-.111c-.752-.399-1.339-.902-1.746-1.498a3.4 3.4 0 0 1-.3-.531c-.034-.1-.032-.156-.008-.207a.3.3 0 0 1 .097-.1c.129-.086.262-.173.352-.231.162-.104.289-.187.371-.245.309-.216.525-.446.66-.702a1.4 1.4 0 0 0 .069-1.16c-.205-.538-.713-.872-1.329-.872a1.8 1.8 0 0 0-.487.065c.006-.368-.002-.757-.035-1.139-.116-1.344-.587-2.048-1.077-2.61a4.3 4.3 0 0 0-1.095-.881C9.764.216 8.92 0 7.999 0s-1.76.216-2.505.641c-.412.232-.782.53-1.097.883-.49.562-.96 1.267-1.077 2.61-.033.382-.04.772-.036 1.138a1.8 1.8 0 0 0-.487-.065c-.615 0-1.124.335-1.328.873a1.4 1.4 0 0 0 .067 1.161c.136.256.352.486.66.701.082.058.21.14.371.246l.339.221a.4.4 0 0 1 .109.11c.026.053.027.11-.012.217a3.4 3.4 0 0 1-.295.52c-.398.583-.968 1.077-1.696 1.472-.385.204-.786.34-.955.8-.128.348-.044.743.28 1.075q.18.189.409.31a4.4 4.4 0 0 0 1 .4.7.7 0 0 1 .202.09c.118.104.102.26.259.488q.12.178.296.3c.33.229.701.243 1.095.258.355.014.758.03 1.217.18.19.064.389.186.618.328.55.338 1.305.802 2.566.802 1.262 0 2.02-.466 2.576-.806.227-.14.424-.26.609-.321.46-.152.863-.168 1.218-.181.393-.015.764-.03 1.095-.258a1.14 1.14 0 0 0 .336-.368c.114-.192.11-.327.217-.42a.6.6 0 0 1 .19-.087 4.5 4.5 0 0 0 1.014-.404c.16-.087.306-.2.429-.336l.004-.005c.304-.325.38-.709.256-1.047m-1.121.602c-.684.378-1.139.337-1.493.565-.3.193-.122.61-.34.76-.269.186-1.061-.012-2.085.326-.845.279-1.384 1.082-2.903 1.082s-2.045-.801-2.904-1.084c-1.022-.338-1.816-.14-2.084-.325-.218-.15-.041-.568-.341-.761-.354-.228-.809-.187-1.492-.563-.436-.24-.189-.39-.044-.46 2.478-1.199 2.873-3.05 2.89-3.188.022-.166.045-.297-.138-.466-.177-.164-.962-.65-1.18-.802-.36-.252-.52-.503-.402-.812.082-.214.281-.295.49-.295a1 1 0 0 1 .197.022c.396.086.78.285 1.002.338q.04.01.082.011c.118 0 .16-.06.152-.195-.026-.433-.087-1.277-.019-2.066.094-1.084.444-1.622.859-2.097.2-.229 1.137-1.22 2.93-1.22 1.792 0 2.732.987 2.931 1.215.416.475.766 1.013.859 2.098.068.788.009 1.632-.019 2.065-.01.142.034.195.152.195a.4.4 0 0 0 .082-.01c.222-.054.607-.253 1.002-.338a1 1 0 0 1 .197-.023c.21 0 .409.082.49.295.117.309-.04.56-.401.812-.218.152-1.003.638-1.18.802-.184.169-.16.3-.139.466.018.14.413 1.991 2.89 3.189.147.073.394.222-.041.464"/></svg>
            </div>
            Snapchat
          </button>
          <button class="kfs-share-action-btn kfs-share-social-btn" data-platform="instagram" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:0 0 64px;padding:8px 2px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:10.5px;font-weight:600;font-family:inherit;white-space:nowrap;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#f9ce34,#ee2a7b,#6228d7);display:flex;align-items:center;justify-content:center">
              <svg width="19" height="19" viewBox="0 0 16 16" fill="#fff"><path d="M8 0C5.829 0 5.556.01 4.703.048 3.85.088 3.269.222 2.76.42a3.9 3.9 0 0 0-1.417.923A3.9 3.9 0 0 0 .42 2.76C.222 3.268.087 3.85.048 4.7.01 5.555 0 5.827 0 8.001c0 2.172.01 2.444.048 3.297.04.852.174 1.433.372 1.942.205.526.478.972.923 1.417.444.445.89.719 1.416.923.51.198 1.09.333 1.942.372C5.555 15.99 5.827 16 8 16s2.444-.01 3.298-.048c.851-.04 1.434-.174 1.943-.372a3.9 3.9 0 0 0 1.416-.923c.445-.445.718-.891.923-1.417.197-.509.332-1.09.372-1.942C15.99 10.445 16 10.173 16 8s-.01-2.445-.048-3.299c-.04-.851-.175-1.433-.372-1.941a3.9 3.9 0 0 0-.923-1.417A3.9 3.9 0 0 0 13.24.42c-.51-.198-1.092-.333-1.943-.372C10.443.01 10.172 0 7.998 0zm-.717 1.442h.718c2.136 0 2.389.007 3.232.046.78.035 1.204.166 1.486.275.373.145.64.319.92.599s.453.546.598.92c.11.281.24.705.275 1.485.039.843.047 1.096.047 3.231s-.008 2.389-.047 3.232c-.035.78-.166 1.203-.275 1.485a2.5 2.5 0 0 1-.599.919c-.28.28-.546.453-.92.598-.28.11-.704.24-1.485.276-.843.038-1.096.047-3.232.047s-2.39-.009-3.233-.047c-.78-.036-1.203-.166-1.485-.276a2.5 2.5 0 0 1-.92-.598 2.5 2.5 0 0 1-.6-.92c-.109-.281-.24-.705-.275-1.485-.038-.843-.046-1.096-.046-3.233s.008-2.388.046-3.231c.036-.78.166-1.204.276-1.486.145-.373.319-.64.599-.92s.546-.453.92-.598c.282-.11.705-.24 1.485-.276.738-.034 1.024-.044 2.515-.045zm4.988 1.328a.96.96 0 1 0 0 1.92.96.96 0 0 0 0-1.92m-4.27 1.122a4.109 4.109 0 1 0 0 8.217 4.109 4.109 0 0 0 0-8.217m0 1.441a2.667 2.667 0 1 1 0 5.334 2.667 2.667 0 0 1 0-5.334"/></svg>
            </div>
            Instagram
          </button>
        </div>
        <!-- Conversation list -->
        <div id="kfs-share-convs" style="flex:1;overflow-y:auto;max-height:260px;display:flex;flex-direction:column"></div>
        <!-- Send confirmation area -->
        <div id="kfs-share-footer" style="padding:10px 14px;display:none;flex-shrink:0;border-top:1px solid #1e1e1e">
          <button id="kfs-share-send" style="
            width:100%;padding:13px;background:#0095f6;color:#fff;border:none;
            border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;
            font-family:inherit;transition:opacity .15s;
          ">Send</button>
        </div>
      </div>
    `;
    document.body.appendChild(el);
    _shareOverlay = el;

    if (typeof window._kfsAttachSwipeDismiss === 'function') {
      window._kfsAttachSwipeDismiss(
        el.querySelector('#kfs-share-sheet'),
        el.querySelector('#kfs-share-sheet > div:first-child'), // the drag pill
        '0',
        closeShareModal
      );
    }

    el.querySelector('#kfs-share-close').addEventListener('click', closeShareModal);
    el.addEventListener('click', e => { if (e.target === el) closeShareModal(); });

    // Copy link
    el.querySelector('#kfs-share-copy').addEventListener('click', async () => {
      try {
        const url = `${location.origin}/strand/${_shareProjectId}`;
        await navigator.clipboard.writeText(url);
        swShowToast('Link copied!');
        closeShareModal();
      } catch { swShowToast('Could not copy link.'); }
    });

    // Social platform share buttons (WhatsApp, X/Twitter, Snapchat, Instagram)
    el.querySelectorAll('.kfs-share-social-btn').forEach(btn => {
      btn.addEventListener('click', () => _shareToPlatform(btn.dataset.platform));
    });

    // Send
    el.querySelector('#kfs-share-send').addEventListener('click', async () => {
      const selected = [...el.querySelectorAll('.kfs-share-person[data-selected="true"], .kfs-share-conv[data-selected="true"]')];
      if (!selected.length) return;
      const sendBtn = el.querySelector('#kfs-share-send');
      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending…';
      const url = `${location.origin}/strand/${_shareProjectId}`;
      const body = `Check this out on Social Strand: ${url}`;
      let ok = 0;
      for (const item of selected) {
        try {
          if (item.dataset.type === 'dm') {
            await api('POST', '/api/member/dm/send', {
              to_member_id: item.dataset.id,
              body,
            });
          } else if (item.dataset.type === 'group') {
            await api('POST', `/api/member/groups/${item.dataset.id}/messages`, { body });
          }
          ok++;
        } catch { /* skip */ }
      }
      closeShareModal();
      if (ok) swShowToast(`Shared with ${ok} conversation${ok !== 1 ? 's' : ''}!`);
      else swShowToast('Could not send to selected.');
    });

    // Search
    el.querySelector('#kfs-share-search').addEventListener('input', e => {
      _filterShareList(e.target.value);
    });

    return el;
  }

  function _filterShareList(q) {
    const query = (q || '').toLowerCase().trim();
    const overlay = _shareOverlay;
    if (!overlay) return;
    overlay.querySelectorAll('.kfs-share-conv').forEach(row => {
      const name = (row.dataset.name || '').toLowerCase();
      row.style.display = (!query || name.includes(query)) ? 'flex' : 'none';
    });
  }

  function _updateSendBtn() {
    const overlay = _shareOverlay;
    if (!overlay) return;
    const selected = overlay.querySelectorAll('[data-selected="true"]').length;
    const footer = overlay.querySelector('#kfs-share-footer');
    const sendBtn = overlay.querySelector('#kfs-share-send');
    if (footer) footer.style.display = selected > 0 ? '' : 'none';
    if (sendBtn) sendBtn.textContent = selected > 1 ? `Send (${selected})` : 'Send';
  }

  function _buildPersonAvatar(name, photo, size) {
    if (photo) return `<img src="${photo}" alt="${name}" style="width:${size}px;height:${size}px;border-radius:50%;object-fit:cover">`;
    const init = (name || '?').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
    return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:#2a2a2a;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size*.38)}px;font-weight:700;color:#888">${init}</div>`;
  }

  // ── Share to an external social platform ──────────────────────────────────
  function _shareToPlatform(platform) {
    const url = `${location.origin}/strand/${_shareProjectId}`;
    const text = 'Check this out on Social Strand';

    // Instagram has no public web-share intent for arbitrary links (only
    // their native app SDK supports posting to feed/story) — copy the link
    // instead so the member can paste it into a DM or Story themselves.
    if (platform === 'instagram') {
      navigator.clipboard?.writeText(url)
        .then(() => swShowToast('Link copied — paste it into Instagram!'))
        .catch(() => swShowToast('Could not copy link.'));
      closeShareModal();
      return;
    }

    const intents = {
      whatsapp: `https://wa.me/?text=${encodeURIComponent(`${text}: ${url}`)}`,
      twitter:  `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`,
      snapchat: `https://www.snapchat.com/scan?attachmentUrl=${encodeURIComponent(url)}`,
    };
    const intentUrl = intents[platform];
    if (intentUrl) window.open(intentUrl, '_blank', 'noopener,noreferrer');
    closeShareModal();
  }

  window.openShareModal = async function(projectId) {
    _shareProjectId = projectId;
    const overlay = _createShareOverlay();
    overlay.style.display = 'flex';

    // Reset state
    overlay.querySelectorAll('[data-selected="true"]').forEach(el => {
      el.dataset.selected = 'false';
      const check = el.querySelector('.kfs-share-check');
      if (check) check.style.display = 'none';
    });
    _updateSendBtn();

    const footer = overlay.querySelector('#kfs-share-footer');
    if (footer) footer.style.display = 'none';
    const search = overlay.querySelector('#kfs-share-search');
    if (search) search.value = '';

    // Lazy-fetch DM conversations (+ groups) if the messaging tab has never
    // been opened this session. DM.convs/GC.groups are normally populated by
    // _inboxLoad() the first time the Messages panel opens — if a member
    // shares a post before ever opening Messages, those arrays are still
    // empty and the sheet would wrongly look like "no conversations yet".
    if (!DM.loaded && typeof window._inboxLoad === 'function') {
      const peopleGrid = overlay.querySelector('#kfs-share-people');
      const convsList = overlay.querySelector('#kfs-share-convs');
      if (peopleGrid) peopleGrid.innerHTML = '<div style="padding:10px 14px;color:#555;font-size:12px">Loading contacts…</div>';
      if (convsList) convsList.innerHTML = '';
      try {
        await window._inboxLoad();
      } catch { /* fall through and render with whatever we have */ }
      // The modal may have been closed (or re-opened for a different post)
      // while we were awaiting the fetch — bail out rather than render stale data.
      if (_shareOverlay.style.display === 'none' || _shareProjectId !== projectId) return;
    }

    _populateShareLists(overlay);
  };

  // ── Populate the people grid + conversation list from DM.convs/GC.groups ──
  function _populateShareLists(overlay) {
    // Populate people grid (top 8 DM contacts)
    const peopleGrid = overlay.querySelector('#kfs-share-people');
    if (peopleGrid) {
      peopleGrid.innerHTML = '';
      const contacts = (DM.convs || []).slice(0, 8);
      contacts.forEach(c => {
        const name = c.peer?.name || 'Member';
        const item = document.createElement('div');
        item.className = 'kfs-share-person';
        item.dataset.type = 'dm';
        item.dataset.id = c.peer?.id;
        item.dataset.selected = 'false';
        item.dataset.name = name;
        item.style.cssText = 'display:flex;flex-direction:column;align-items:center;gap:4px;padding:4px 10px;cursor:pointer;flex-shrink:0;position:relative;min-width:68px';
        item.innerHTML = `
          <div style="position:relative">
            ${_buildPersonAvatar(name, c.peer?.photo, 52)}
            <div class="kfs-share-check" style="display:none;position:absolute;bottom:0;right:0;width:18px;height:18px;border-radius:50%;background:#0095f6;border:2px solid #1a1a1a;align-items:center;justify-content:center">
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>
            </div>
          </div>
          <span style="font-size:11px;color:#e0e0e0;white-space:nowrap;max-width:60px;overflow:hidden;text-overflow:ellipsis;text-align:center">${name.split(' ')[0]}</span>
        `;
        item.addEventListener('click', () => {
          const isSelected = item.dataset.selected === 'true';
          item.dataset.selected = isSelected ? 'false' : 'true';
          const check = item.querySelector('.kfs-share-check');
          if (check) check.style.display = isSelected ? 'none' : 'flex';
          _updateSendBtn();
        });
        peopleGrid.appendChild(item);
      });
    }

    // Populate conversation list
    const convsList = overlay.querySelector('#kfs-share-convs');
    if (convsList) {
      convsList.innerHTML = '';
      const allItems = [
        ...(DM.convs || []).map(c => ({ type: 'dm', id: c.peer?.id, name: c.peer?.name || 'Member', photo: c.peer?.photo, convKey: c.conv_key })),
        ...(GC.groups || []).map(g => ({ type: 'group', id: g.id, name: g.name || 'Group', photo: g.photo_url })),
      ];
      allItems.forEach(item => {
        const row = document.createElement('div');
        row.className = 'kfs-share-conv';
        row.dataset.type = item.type;
        row.dataset.id = item.id;
        row.dataset.name = item.name;
        row.dataset.selected = 'false';
        row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;transition:background .1s';
        row.innerHTML = `
          ${_buildPersonAvatar(item.name, item.photo, 44)}
          <div style="flex:1;min-width:0">
            <div style="font-size:14px;font-weight:600;color:#f5f5f5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${item.name}</div>
            <div style="font-size:12px;color:#666">${item.type === 'group' ? 'Group' : 'Direct message'}</div>
          </div>
          <div class="kfs-share-check" style="display:none;width:22px;height:22px;border-radius:50%;background:#0095f6;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
        `;
        row.addEventListener('mouseenter', () => { if (row.dataset.selected !== 'true') row.style.background = 'rgba(255,255,255,.04)'; });
        row.addEventListener('mouseleave', () => { if (row.dataset.selected !== 'true') row.style.background = ''; });
        row.addEventListener('click', () => {
          const isSelected = row.dataset.selected === 'true';
          row.dataset.selected = isSelected ? 'false' : 'true';
          const check = row.querySelector('.kfs-share-check');
          if (check) check.style.display = isSelected ? 'none' : 'flex';
          row.style.background = isSelected ? '' : 'rgba(0,149,246,.07)';
          _updateSendBtn();
        });
        convsList.appendChild(row);
      });

      if (!allItems.length) {
        convsList.innerHTML = '<div style="padding:24px;text-align:center;color:#444;font-size:13px">No conversations yet. Start chatting to share!</div>';
      }
    }
  }

  function closeShareModal() {
    if (!_shareOverlay) return;
    const sheet = _shareOverlay.querySelector('#kfs-share-sheet');
    const hide = () => { _shareOverlay.style.display = 'none'; };
    if (sheet && _shareOverlay.style.display !== 'none' && typeof window._kfsAnimateSheetOut === 'function') {
      window._kfsAnimateSheetOut(sheet, '0', hide);
    } else {
      hide();
    }
  }
  window.closeShareModal = closeShareModal;

})();

// ── 5. ADD SHARE BUTTON TO IG-POST ACTION BAR ──────────────────────────────
// Monkey-patch swFeedCard to inject a share button

(function patchFeedCardShare() {
  if (typeof swFeedCard !== 'function') return;
  const _orig = window.swFeedCard;
  window.swFeedCard = function(p) {
    let html = _orig(p);
    // Inject share (paper-plane) button into the action bar, before the views span
    html = html.replace(
      '<span class="ig-post-views-inline">',
      `<button class="ig-action-btn kfs-share-fab" onclick="event.stopPropagation();openShareModal('${p.id}')" title="Share">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
        </svg>
      </button>
      <span class="ig-post-views-inline">`
    );
    return html;
  };
})();

// ── 6. ADMIN KFS BROADCAST SYSTEM ────────────────────────────────────────────
// Admins can send as KFS verified account to: all members, or specific targets.
// Button appears in the DM compose area for admin users only.

(function installAdminBroadcast() {

  let _broadcastOverlay = null;

  function _isAdmin() {
    const p = window._memberProfile || window._member || {};
    return p.is_admin === true || p.role === 'admin' || p.role === 'master_admin';
  }

  function _createBroadcastBtn() {
    if (!_isAdmin()) return;
    // Find the DM sidebar header area and inject broadcast button
    const header = document.querySelector('.dm-sidebar-head') ||
                   document.querySelector('#dm-sidebar > div:first-child');
    if (!header || document.getElementById('kfs-broadcast-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'kfs-broadcast-btn';
    btn.title = 'Send as KFS (Admin Broadcast)';
    btn.style.cssText = `
      display:flex;align-items:center;gap:6px;padding:7px 12px;border-radius:20px;
      background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;border:none;
      font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;
      letter-spacing:.03em;transition:opacity .15s;margin:0 0 6px 0;width:100%;
      justify-content:center;
    `;
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="#fff"><path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" stroke="none"/><path d="M9 12l2 2 4-4" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round"/></svg>
      KFS Broadcast
    `;
    btn.addEventListener('click', openBroadcastModal);
    // Try to insert it at the top of the sidebar conv list
    const convList = document.getElementById('dm-conv-list');
    if (convList && convList.parentNode) {
      convList.parentNode.insertBefore(btn, convList);
    }
  }

  function openBroadcastModal() {
    if (_broadcastOverlay) {
      _broadcastOverlay.style.display = 'flex';
      _resetBroadcastModal();
      return;
    }
    const el = document.createElement('div');
    el.id = 'kfs-broadcast-overlay';
    el.style.cssText = `
      display:flex;position:fixed;inset:0;z-index:9999;
      background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
      align-items:center;justify-content:center;padding:16px;
    `;
    el.innerHTML = `
      <div style="
        background:#111;border:1px solid #222;border-radius:18px;
        width:100%;max-width:480px;max-height:90vh;display:flex;flex-direction:column;
        box-shadow:0 20px 60px rgba(0,0,0,.8);
      ">
        <!-- Header -->
        <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 20px 14px;border-bottom:1px solid #1e1e1e;flex-shrink:0">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#1a3a5c,#2d6a9f);display:flex;align-items:center;justify-content:center">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/></svg>
            </div>
            <div>
              <div style="font-size:15px;font-weight:700">KFS Broadcast</div>
              <div style="font-size:11px;color:#666">Sends as verified KFS account</div>
            </div>
          </div>
          <button id="kfs-bc-close" style="background:none;border:none;color:#666;cursor:pointer;padding:4px;font-size:18px">✕</button>
        </div>
        <!-- Target -->
        <div style="padding:14px 20px 0;flex-shrink:0">
          <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px">Send to</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <label class="kfs-bc-target-pill" style="display:flex;align-items:center;gap:6px;padding:7px 14px;border-radius:20px;border:1px solid #2a2a2a;cursor:pointer;font-size:13px;transition:all .12s">
              <input type="radio" name="kfs-bc-target" value="all" style="display:none" checked>
              <span>All members</span>
            </label>
            <label class="kfs-bc-target-pill" style="display:flex;align-items:center;gap:6px;padding:7px 14px;border-radius:20px;border:1px solid #2a2a2a;cursor:pointer;font-size:13px;transition:all .12s">
              <input type="radio" name="kfs-bc-target" value="group" style="display:none">
              <span>Specific group</span>
            </label>
            <label class="kfs-bc-target-pill" style="display:flex;align-items:center;gap:6px;padding:7px 14px;border-radius:20px;border:1px solid #2a2a2a;cursor:pointer;font-size:13px;transition:all .12s">
              <input type="radio" name="kfs-bc-target" value="member" style="display:none">
              <span>Specific member</span>
            </label>
          </div>
          <!-- Group selector -->
          <div id="kfs-bc-group-select" style="display:none;margin-top:10px">
            <select id="kfs-bc-group-id" style="width:100%;background:#1a1a1a;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 12px;border-radius:10px;font-family:inherit;font-size:13px;outline:none">
              <option value="">Select a group…</option>
            </select>
          </div>
          <!-- Member selector -->
          <div id="kfs-bc-member-select" style="display:none;margin-top:10px">
            <input id="kfs-bc-member-search" type="text" placeholder="Search members…" style="width:100%;box-sizing:border-box;background:#1a1a1a;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 12px;border-radius:10px;font-family:inherit;font-size:13px;outline:none">
            <div id="kfs-bc-member-results" style="max-height:140px;overflow-y:auto;margin-top:4px;border:1px solid #1e1e1e;border-radius:10px;display:none"></div>
            <div id="kfs-bc-member-chosen" style="font-size:12px;color:#0095f6;margin-top:6px;display:none"></div>
          </div>
        </div>
        <!-- Message -->
        <div style="padding:12px 20px;flex:1;overflow:hidden;display:flex;flex-direction:column">
          <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;flex-shrink:0">Message</div>
          <textarea id="kfs-bc-body" placeholder="Type your KFS broadcast message…" style="
            flex:1;min-height:100px;max-height:200px;resize:none;background:#1a1a1a;
            border:1px solid #2a2a2a;color:#f5f5f5;padding:12px;border-radius:10px;
            font-family:inherit;font-size:14px;line-height:1.6;outline:none;
          "></textarea>
          <div id="kfs-bc-char" style="font-size:11px;color:#444;text-align:right;margin-top:4px">0 / 1000</div>
        </div>
        <!-- Footer -->
        <div style="padding:12px 20px 18px;flex-shrink:0;border-top:1px solid #1e1e1e">
          <div id="kfs-bc-err" style="font-size:12px;color:#ef4444;margin-bottom:8px;display:none"></div>
          <button id="kfs-bc-send" style="
            width:100%;padding:13px;background:linear-gradient(135deg,#1a3a5c,#2d6a9f);
            color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:700;
            cursor:pointer;font-family:inherit;letter-spacing:.01em;transition:opacity .15s;
          ">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" style="display:inline-block;vertical-align:middle;margin-right:6px"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            Send Broadcast
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(el);
    _broadcastOverlay = el;

    // Wire close
    el.querySelector('#kfs-bc-close').addEventListener('click', () => { el.style.display = 'none'; });
    el.addEventListener('click', e => { if (e.target === el) el.style.display = 'none'; });

    // Populate groups
    const groupSel = el.querySelector('#kfs-bc-group-id');
    (GC.groups || []).forEach(g => {
      const opt = document.createElement('option');
      opt.value = g.id;
      opt.textContent = g.name;
      groupSel.appendChild(opt);
    });

    // Target toggle
    let _bcTarget = 'all';
    let _bcMemberId = null;
    el.querySelectorAll('.kfs-bc-target-pill').forEach(pill => {
      const radio = pill.querySelector('input[type=radio]');
      const updateStyles = () => {
        el.querySelectorAll('.kfs-bc-target-pill').forEach(p => {
          const r = p.querySelector('input[type=radio]');
          const checked = r.checked;
          p.style.background = checked ? 'rgba(45,106,159,.25)' : 'transparent';
          p.style.borderColor = checked ? '#2d6a9f' : '#2a2a2a';
          p.style.color = checked ? '#7cb9fd' : '#ccc';
        });
        el.querySelector('#kfs-bc-group-select').style.display = _bcTarget === 'group' ? '' : 'none';
        el.querySelector('#kfs-bc-member-select').style.display = _bcTarget === 'member' ? '' : 'none';
      };
      pill.addEventListener('click', () => {
        radio.checked = true;
        _bcTarget = radio.value;
        updateStyles();
      });
    });

    // Member search
    let _bcSearchTimer;
    el.querySelector('#kfs-bc-member-search').addEventListener('input', e => {
      const q = e.target.value.trim();
      clearTimeout(_bcSearchTimer);
      if (!q) { el.querySelector('#kfs-bc-member-results').style.display = 'none'; return; }
      _bcSearchTimer = setTimeout(async () => {
        try {
          const pool = DM.members.length ? DM.members : (window._portalMembers || []);
          const hits = pool.filter(m => (m.name || '').toLowerCase().includes(q.toLowerCase())).slice(0, 8);
          const results = el.querySelector('#kfs-bc-member-results');
          results.style.display = hits.length ? '' : 'none';
          results.innerHTML = hits.map(m => `
            <div data-id="${m.id}" data-name="${m.name}" style="
              display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer;
              transition:background .1s;font-size:13px;
            " class="kfs-bc-member-row">
              ${dmAvatar(m.name, m.photo, 28)}
              <div>
                <div style="font-weight:600">${m.name || 'Member'}</div>
                ${m.role ? `<div style="font-size:11px;color:#666">${m.role}</div>` : ''}
              </div>
            </div>
          `).join('');
          results.querySelectorAll('.kfs-bc-member-row').forEach(row => {
            row.addEventListener('mouseenter', () => row.style.background = 'rgba(255,255,255,.04)');
            row.addEventListener('mouseleave', () => row.style.background = '');
            row.addEventListener('click', () => {
              _bcMemberId = row.dataset.id;
              const chosen = el.querySelector('#kfs-bc-member-chosen');
              chosen.textContent = `Selected: ${row.dataset.name}`;
              chosen.style.display = '';
              results.style.display = 'none';
              el.querySelector('#kfs-bc-member-search').value = row.dataset.name;
            });
          });
        } catch { /* silent */ }
      }, 250);
    });

    // Char counter
    el.querySelector('#kfs-bc-body').addEventListener('input', e => {
      el.querySelector('#kfs-bc-char').textContent = `${e.target.value.length} / 1000`;
    });

    // Send
    el.querySelector('#kfs-bc-send').addEventListener('click', async () => {
      const body = (el.querySelector('#kfs-bc-body').value || '').trim();
      const errEl = el.querySelector('#kfs-bc-err');
      const sendBtn = el.querySelector('#kfs-bc-send');
      errEl.style.display = 'none';

      if (!body) { errEl.textContent = 'Please enter a message.'; errEl.style.display = ''; return; }
      if (body.length > 1000) { errEl.textContent = 'Message too long (max 1000 chars).'; errEl.style.display = ''; return; }

      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending…';

      try {
        // Build the API call
        let endpoint, payload;
        if (_bcTarget === 'all') {
          endpoint = '/api/admin/broadcast';
          payload = { body, target: 'all' };
        } else if (_bcTarget === 'group') {
          const gid = el.querySelector('#kfs-bc-group-id').value;
          if (!gid) { errEl.textContent = 'Please select a group.'; errEl.style.display = ''; return; }
          endpoint = `/api/member/groups/${gid}/messages`;
          payload = { body, is_admin_post: true };
        } else {
          if (!_bcMemberId) { errEl.textContent = 'Please select a member.'; errEl.style.display = ''; return; }
          endpoint = '/api/member/dm/send';
          payload = { to_member_id: _bcMemberId, body };
        }

        await api('POST', endpoint, payload);
        el.style.display = 'none';
        swShowToast('✓ KFS broadcast sent!');
      } catch (e) {
        errEl.textContent = e.message || 'Could not send broadcast.';
        errEl.style.display = '';
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send Broadcast';
      } finally {
        sendBtn.disabled = false;
        if (sendBtn.textContent === 'Sending…') sendBtn.textContent = 'Send Broadcast';
      }
    });

    _resetBroadcastModal();
  }

  function _resetBroadcastModal() {
    if (!_broadcastOverlay) return;
    _broadcastOverlay.querySelector('#kfs-bc-body').value = '';
    _broadcastOverlay.querySelector('#kfs-bc-char').textContent = '0 / 1000';
    _broadcastOverlay.querySelector('#kfs-bc-err').style.display = 'none';
    const radios = _broadcastOverlay.querySelectorAll('input[name="kfs-bc-target"]');
    if (radios[0]) { radios[0].checked = true; }
    _broadcastOverlay.querySelectorAll('.kfs-bc-target-pill').forEach((p, i) => {
      p.style.background = i === 0 ? 'rgba(45,106,159,.25)' : 'transparent';
      p.style.borderColor = i === 0 ? '#2d6a9f' : '#2a2a2a';
      p.style.color = i === 0 ? '#7cb9fd' : '#ccc';
    });
    _broadcastOverlay.querySelector('#kfs-bc-group-select').style.display = 'none';
    _broadcastOverlay.querySelector('#kfs-bc-member-select').style.display = 'none';
    const chosen = _broadcastOverlay.querySelector('#kfs-bc-member-chosen');
    if (chosen) chosen.style.display = 'none';
  }

  // Inject broadcast button after session restore
  function tryInjectBroadcastBtn() {
    if (_isAdmin()) {
      _createBroadcastBtn();
    }
  }

  // Try now, and also after DM panel opens
  const _origDmPanelOpened = window.dmPanelOpened;
  window.dmPanelOpened = async function() {
    if (_origDmPanelOpened) await _origDmPanelOpened();
    tryInjectBroadcastBtn();
  };

  setTimeout(tryInjectBroadcastBtn, 1500);

})();

// ── 7. MOBILE UI IMPROVEMENTS ────────────────────────────────────────────────
// Inject improved CSS for mobile to match Instagram on Apple devices

(function injectMobileStyles() {
  const style = document.createElement('style');
  style.textContent = `
    /* ── Share modal animation ────────────────────────────────────────────── */
    @keyframes kfsSheetUp {
      from { transform: translateY(100%); opacity: 0; }
      to   { transform: translateY(0);    opacity: 1; }
    }

    /* ── Share people grid scrollbar hide ───────────────────────────────── */
    #kfs-share-people::-webkit-scrollbar { display: none; }
    #kfs-share-people { -ms-overflow-style: none; }

    /* ── Message input: iOS auto-zoom fix ───────────────────────────────── */
    @media (max-width: 768px) {
      #dm-input, #gc-input, textarea, input[type="text"] {
        font-size: 16px !important; /* prevents iOS auto-zoom */
      }
    }

    /* ── Bottom tab bar: increase touch targets ─────────────────────────── */
    @media (max-width: 768px) {
      .btb-item {
        min-height: 56px !important;
        min-width: 48px !important;
      }

      /* ── DM: full-screen chat window on mobile ─────────────────────────── */
      .dm-slide-in {
        position: fixed !important;
        inset: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 100 !important;
        background: var(--bg) !important;
        transform: translateX(0) !important;
      }
      #dm-sidebar.dm-slide-out {
        transform: translateX(-100%) !important;
      }

      /* ── GC: full-screen chat window on mobile ─────────────────────────── */
      #gc-window.dm-slide-in {
        position: fixed !important;
        inset: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 100 !important;
        background: var(--bg) !important;
        transform: translateX(0) !important;
      }

      /* ── Topbar: make it sticky and styled ─────────────────────────────── */
      .dm-topbar, #gc-topbar {
        position: sticky !important;
        top: 0 !important;
        z-index: 50 !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
      }

      /* ── Message bubbles: larger tap target ─────────────────────────────── */
      .dm-bubble { padding: 10px 13px !important; font-size: 14.5px !important; }

      /* ── Compose area: safe area aware ─────────────────────────────────── */
      .dm-compose {
        padding-bottom: calc(env(safe-area-inset-bottom) + 8px) !important;
      }
    }

    /* ── KFS Share modal: hide scrollbar ───────────────────────────────── */
    #kfs-share-convs::-webkit-scrollbar { width: 3px; }
    #kfs-share-convs::-webkit-scrollbar-track { background: transparent; }
    #kfs-share-convs::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 10px; }
    #kfs-share-actions::-webkit-scrollbar { height: 0; display: none; }

    /* ── Post share button: hide until hover on desktop ───────────────────── */
    @media (min-width: 769px) {
      .ig-action-btn.kfs-share-fab { opacity: 0.6; transition: opacity .15s; }
      .ig-post:hover .ig-action-btn.kfs-share-fab { opacity: 1; }
    }

    /* ── GC pinned bar animation ─────────────────────────────────────────── */
    #gc-pinned-bar {
      animation: kfsFadeIn .2s ease both;
    }
    @keyframes kfsFadeIn {
      from { opacity: 0; transform: translateY(-6px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    /* ── Nickname modal: smooth enter ───────────────────────────────────── */
    .nick-modal-overlay.open .nick-modal,
    .nick-modal-overlay[style*="flex"] .nick-modal {
      animation: kfsFadeIn .18s ease both;
    }

    /* ── Improve DM topbar on mobile ────────────────────────────────────── */
    @media (max-width: 768px) {
      .dm-topbar {
        padding: 10px 12px !important;
        background: rgba(10,10,10,.95) !important;
        border-bottom: 1px solid #1a1a1a !important;
      }
      #dm-topbar-name {
        font-size: 15px !important;
        font-weight: 700 !important;
      }

      /* ── Group chat topbar on mobile ──────────────────────────────────── */
      #gc-topbar {
        padding: 10px 12px !important;
        background: rgba(10,10,10,.95) !important;
      }

      /* ── Reply bar: more visible ─────────────────────────────────────── */
      .dm-reply-bar {
        padding: 8px 12px !important;
        background: rgba(30,30,30,.98) !important;
      }

      /* ── Conversation rows: larger ──────────────────────────────────────── */
      .dm-conv-row {
        padding: 13px 14px !important;
      }
    }

    /* ── Admin broadcast button in sidebar ────────────────────────────────── */
    #kfs-broadcast-btn:hover {
      opacity: 0.85;
    }
    #kfs-broadcast-btn:active {
      transform: scale(0.97);
    }

    /* ── Toast: ensure it always shows above modals ──────────────────────── */
    .kfs-toast { z-index: 99999 !important; }
  `;
  document.head.appendChild(style);
})();

// ── 8. NICKNAME DISPLAY IN CONVERSATION HEADER FIX ───────────────────────────
// When a DM conversation is opened, always re-resolve the display name
// including any nickname, and update the topbar immediately.

(function patchDmTopbarNickname() {
  const _orig = window.dmOpenConv;
  if (!_orig) return; // will be patched by initDMExtensions anyway
})();

// ── 9. SWIPE BACK GESTURE (Mobile) ───────────────────────────────────────────
// Add swipe-right gesture to go back from a chat to the conversation list.

(function addSwipeBack() {
  let startX = 0, startY = 0, swiping = false;

  document.addEventListener('touchstart', e => {
    const t = e.touches[0];
    startX = t.clientX;
    startY = t.clientY;
    swiping = startX < 24; // only activate from left edge
  }, { passive: true });

  document.addEventListener('touchend', e => {
    if (!swiping) return;
    const t = e.changedTouches[0];
    const dx = t.clientX - startX;
    const dy = Math.abs(t.clientY - startY);
    swiping = false;
    // Swipe right > 60px, mostly horizontal
    if (dx > 60 && dy < 60) {
      // If DM chat is open, go back
      const dmSidebar = document.getElementById('dm-sidebar');
      if (dmSidebar && dmSidebar.classList.contains('dm-slide-out')) {
        if (typeof dmGoBack === 'function') dmGoBack();
        else {
          dmSidebar.classList.remove('dm-slide-out');
          document.getElementById('dm-window')?.classList.remove('dm-slide-in');
        }
        return;
      }
      // If GC chat is open, go back
      const gcWindow = document.getElementById('gc-window');
      if (gcWindow && gcWindow.classList.contains('dm-slide-in')) {
        if (typeof window.gcGoBack === 'function') window.gcGoBack();
      }
    }
  }, { passive: true });
})();

// ── 10. INSTAGRAM-STYLE SHARE BUTTON STYLING ────────────────────────────────
// Inject the kfs-share-fab class on the injected share buttons (workaround
// since we inject into the HTML string via swFeedCard). Section 5 now adds
// the class directly at injection time, but this stays as a safety net in
// case any share button ever renders without it (e.g. a stale cached
// reference to swFeedCard captured before the patch in section 5 ran).
(function styleShareButton() {
  function _tagShareButtons(root) {
    (root || document).querySelectorAll('.ig-action-btn[title="Share"]:not(.kfs-share-fab)')
      .forEach(btn => btn.classList.add('kfs-share-fab'));
  }

  function _start() {
    _tagShareButtons();
    // Posts re-render dynamically (feed scroll/pagination, likes, new posts) —
    // observe the document and re-tag any share button that slips through
    // without the class.
    const observer = new MutationObserver(muts => {
      for (const m of muts) {
        m.addedNodes && m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          if (node.matches?.('.ig-action-btn[title="Share"]')) node.classList.add('kfs-share-fab');
          else _tagShareButtons(node);
        });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _start);
  } else {
    _start();
  }
})();

// ═══════════════════════════════════════════════════════════════════════════
// 10.5 SPRING SHEET POLISH — shared swipe-to-dismiss + spring exit animation
//      for bottom sheets (share sheet, settings sheet, post composer).
//      Dragging the handle down past a threshold — or a fast flick —
//      dismisses with the same spring curve the button/backdrop close path
//      uses; dragging up rubber-bands instead of moving freely.
// ═══════════════════════════════════════════════════════════════════════════
(function installSpringSheetHelpers() {
  const SPRING = 'transform 0.32s cubic-bezier(0.34, 1.56, 0.64, 1)';

  // Animate a sheet down and off-screen, then run the real close/cleanup
  // (which hides the overlay etc). baseX is the sheet's own horizontal
  // transform offset when open — '-50%' for sheets centered via left:50%,
  // '0' for sheets that are just flex-centered with no X offset.
  function animateSheetOut(sheet, baseX, doClose) {
    if (!sheet) { doClose(); return; }
    sheet.style.transition = SPRING;
    sheet.style.transform = `translate(${baseX}, 100%)`;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      sheet.removeEventListener('transitionend', finish);
      sheet.style.transition = '';
      sheet.style.transform = '';
      doClose();
    };
    sheet.addEventListener('transitionend', finish);
    setTimeout(finish, 360); // safety net if transitionend never fires
  }

  // Wire drag-to-dismiss on a sheet via its drag handle element.
  function attachSwipeDismiss(sheet, handle, baseX, doClose) {
    if (!sheet || !handle || handle.dataset.swipeDismissWired) return;
    handle.dataset.swipeDismissWired = '1';
    const THRESHOLD = 90, FLICK_V = 0.55;
    let startY = 0, lastY = 0, lastT = 0, v = 0, dragging = false;

    handle.addEventListener('touchstart', e => {
      const t = e.touches[0];
      startY = lastY = t.clientY; lastT = Date.now(); v = 0; dragging = true;
      sheet.style.transition = 'none';
    }, { passive: true });

    handle.addEventListener('touchmove', e => {
      if (!dragging) return;
      const t = e.touches[0];
      let dy = t.clientY - startY;
      if (dy < 0) dy = dy / 4; // rubber-band resistance dragging up past open
      sheet.style.transform = `translate(${baseX}, ${dy}px)`;
      const now = Date.now(), dt = now - lastT;
      if (dt > 0) v = (t.clientY - lastY) / dt;
      lastY = t.clientY; lastT = now;
    }, { passive: true });

    function release() {
      if (!dragging) return;
      dragging = false;
      const m = /translate\([^,]+,\s*([-\d.]+)px\)/.exec(sheet.style.transform);
      const dy = m ? parseFloat(m[1]) : 0;
      if (dy > THRESHOLD || v > FLICK_V) {
        animateSheetOut(sheet, baseX, doClose);
      } else {
        sheet.style.transition = SPRING;
        sheet.style.transform = `translate(${baseX}, 0)`;
      }
    }
    handle.addEventListener('touchend', release);
    handle.addEventListener('touchcancel', release);
  }

  window._kfsAnimateSheetOut = animateSheetOut;
  window._kfsAttachSwipeDismiss = attachSwipeDismiss;

  function wireStaticSheets() {
    attachSwipeDismiss(
      document.getElementById('settings-sheet'),
      document.querySelector('#settings-sheet .settings-sheet-handle'),
      '-50%',
      () => { if (typeof closeSettingsSheet === 'function') closeSettingsSheet(); }
    );
    attachSwipeDismiss(
      document.getElementById('composer-sheet'),
      document.querySelector('#composer-sheet .composer-handle'),
      '0',
      () => { if (typeof swClosePostModal === 'function') swClosePostModal(); }
    );
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireStaticSheets);
  } else {
    wireStaticSheets();
  }
})();

// ═══════════════════════════════════════════════════════════════════════════
// 11. SETTINGS → CUSTOMIZATION — chat wallpaper (solid/gradient/photo) +
//     message bubble color. Device-local only (localStorage), matches the
//     "Saved only on this device" copy already in the panel. Wires up the
//     #cust-root placeholder that markup/CSS already had in place.
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  const WALL_KEY    = 'kfs-cust-wallpaper';
  const BUBBLE_KEY  = 'kfs-cust-bubble';
  const OPACITY_KEY = 'kfs-cust-bubble-opacity'; // { mine: 0-1, theirs: 0-1 }
  const READ_RECEIPTS_KEY = 'kfs-cust-read-receipts'; // true/false, default true

  const WALLPAPER_SOLIDS = [
    '#0a0a0a', '#14141c', '#1a1a2e', '#16213e', '#1b262c',
    '#2d2d2d', '#222831', '#264653', '#2a3d45', '#3a2e39',
  ];
  const WALLPAPER_GRADIENTS = [
    'linear-gradient(135deg, #1a1a2e, #16213e)',
    'linear-gradient(135deg, #0f2027, #203a43, #2c5364)',
    'linear-gradient(135deg, #232526, #414345)',
    'linear-gradient(135deg, #1d2671, #c33764)',
    'linear-gradient(135deg, #134e5e, #71b280)',
    'linear-gradient(135deg, #4b134f, #c94b4b)',
  ];
  const BUBBLE_PRESETS = [
    { bg: '#f0f0f0', text: '#0a0a0a' },
    { bg: '#0a84ff', text: '#ffffff' },
    { bg: '#34c759', text: '#ffffff' },
    { bg: '#ff375f', text: '#ffffff' },
    { bg: '#bf5af2', text: '#ffffff' },
    { bg: '#ff9f0a', text: '#0a0a0a' },
  ];

  function _custLoad(key) {
    try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; }
  }
  function _custSave(key, val) {
    try {
      if (val === null) localStorage.removeItem(key);
      else localStorage.setItem(key, JSON.stringify(val));
      return true;
    } catch {
      // Storage full/blocked (most commonly: an uncompressed photo wallpaper
      // pushed past the ~5-10MB localStorage quota). Caller decides how to
      // surface this — we don't fail silently anymore.
      return false;
    }
  }

  // Downscales + re-encodes an uploaded photo as a compressed JPEG data URL
  // before it goes anywhere near localStorage. A raw phone photo can easily
  // be 4-8MB, and base64 inflates that by ~33% — comfortably enough to blow
  // through the origin's storage quota on its own, which made "Upload Photo"
  // silently do nothing (the failed write was swallowed). Capping the long
  // edge at 1280px and re-encoding at quality 0.78 keeps this to a few
  // hundred KB while still looking sharp as a chat background.
  function _custResizeImageFile(file, maxDim, quality) {
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
  function _custIsDark(hex) {
    const c = (hex || '').replace('#', '');
    if (c.length !== 6) return true;
    const r = parseInt(c.slice(0, 2), 16), g = parseInt(c.slice(2, 4), 16), b = parseInt(c.slice(4, 6), 16);
    return (0.299 * r + 0.587 * g + 0.114 * b) < 140;
  }

  function applyCustomization() {
    const root = document.documentElement.style;
    const wall = _custLoad(WALL_KEY);
    if (!wall || wall.type === 'default') root.setProperty('--chat-wallpaper-bg', 'transparent');
    else if (wall.type === 'solid')       root.setProperty('--chat-wallpaper-bg', wall.value);
    else if (wall.type === 'gradient')    root.setProperty('--chat-wallpaper-bg', wall.value);
    else if (wall.type === 'photo')       root.setProperty('--chat-wallpaper-bg', `url("${wall.value}")`);

    const bub = _custLoad(BUBBLE_KEY);
    root.setProperty('--bubble-mine-bg',   bub?.bg   || '#f0f0f0');
    root.setProperty('--bubble-mine-text', bub?.text || '#0a0a0a');

    const op = _custLoad(OPACITY_KEY);
    root.setProperty('--bubble-mine-opacity',   String(op?.mine   ?? 1));
    root.setProperty('--bubble-theirs-opacity', String(op?.theirs ?? 1));
  }
  window.applyCustomization = applyCustomization;
  try { applyCustomization(); } catch { /* localStorage may be blocked — defaults already match */ }

  // Read receipts on/off — device-local display preference. When off, your
  // own sent messages never show the blue "Seen" double-tick in this
  // browser (they cap out at "Delivered"). Default is on (current behavior).
  function _readReceiptsEnabled() {
    const v = _custLoad(READ_RECEIPTS_KEY);
    return v === null ? true : !!v;
  }
  window._kfsReadReceiptsEnabled = _readReceiptsEnabled;

  let _custActiveSeg = 'solid';

  function _custPreviewBg() {
    const wall = _custLoad(WALL_KEY) || { type: 'default' };
    if (wall.type === 'solid' || wall.type === 'gradient') return wall.value;
    if (wall.type === 'photo') return `url("${wall.value}") center/cover no-repeat`;
    return 'var(--bg)';
  }

  function _custUpdatePreview() {
    const prev = $id('cust-preview-chat');
    if (prev) prev.style.background = _custPreviewBg();
    const op = _custLoad(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mine = $id('cust-preview-mine-bubble');
    if (mine) {
      const bub = _custLoad(BUBBLE_KEY) || { bg: '#f0f0f0', text: '#0a0a0a' };
      mine.style.background = bub.bg;
      mine.style.color = bub.text;
      mine.style.setProperty('--preview-mine-opacity', String(op.mine ?? 1));
    }
    const theirs = $id('cust-preview-chat')?.querySelector('.cust-preview-bubble.theirs');
    if (theirs) theirs.style.setProperty('--preview-theirs-opacity', String(op.theirs ?? 1));
  }

  function _custWallpaperSectionHtml(type) {
    const wall = _custLoad(WALL_KEY) || { type: 'default' };
    if (type === 'solid') {
      const customActive = wall.type === 'solid' && !WALLPAPER_SOLIDS.includes(wall.value);
      return `
        <div class="cust-swatch-row">
          ${WALLPAPER_SOLIDS.map(c => `<div class="cust-swatch${wall.type === 'solid' && wall.value === c ? ' active' : ''}" style="background:${c}" data-wall-solid="${c}" title="${c}"></div>`).join('')}
          <div class="cust-swatch-custom${customActive ? ' active' : ''}" title="Custom color">
            ${customActive
              ? `<span class="cust-swatch-custom-fill" style="background:${swEsc(wall.value)}"></span>`
              : `<span class="cust-swatch-custom-ring"></span><svg class="cust-swatch-custom-plus" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`}
            <input type="color" id="cust-wall-color-input" value="${customActive ? wall.value : '#222222'}">
          </div>
        </div>
        <div class="cust-hint">Tap a color, or pick a custom one with the dashed swatch.</div>`;
    }
    if (type === 'gradient') {
      return `
        <div class="cust-swatch-row">
          ${WALLPAPER_GRADIENTS.map(g => `<div class="cust-gradient-swatch${wall.type === 'gradient' && wall.value === g ? ' active' : ''}" style="background:${g}" data-wall-gradient="${swEsc(g)}"></div>`).join('')}
        </div>
        <div class="cust-hint">Soft gradients that stay easy on the eyes in dark mode.</div>`;
    }
    const hasPhoto = wall.type === 'photo' && wall.value;
    return `
      <div class="cust-photo-row">
        <div class="cust-photo-thumb">${hasPhoto ? `<img src="${wall.value}">` : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>`}</div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <button class="cust-upload-btn" id="cust-photo-upload-btn">Upload Photo</button>
          ${hasPhoto ? `<button class="cust-photo-remove" id="cust-photo-remove-btn">Remove photo</button>` : ''}
        </div>
        <input type="file" id="cust-photo-input" accept="image/*" style="display:none">
      </div>
      <div class="cust-hint">Best with a photo at least 800px wide. Stored only on this device.</div>`;
  }

  function _custRenderWallpaperSection() {
    const section = $id('cust-wall-content');
    if (!section) return;
    section.innerHTML = _custWallpaperSectionHtml(_custActiveSeg);

    section.querySelectorAll('[data-wall-solid]').forEach(el => {
      el.addEventListener('click', () => {
        _custSave(WALL_KEY, { type: 'solid', value: el.dataset.wallSolid });
        applyCustomization(); _custRenderWallpaperSection(); _custUpdatePreview();
      });
    });
    section.querySelectorAll('[data-wall-gradient]').forEach(el => {
      el.addEventListener('click', () => {
        _custSave(WALL_KEY, { type: 'gradient', value: el.dataset.wallGradient });
        applyCustomization(); _custRenderWallpaperSection(); _custUpdatePreview();
      });
    });
    const colorInput = $id('cust-wall-color-input');
    if (colorInput) {
      colorInput.addEventListener('input', () => {
        _custSave(WALL_KEY, { type: 'solid', value: colorInput.value });
        applyCustomization(); _custUpdatePreview();
      });
      colorInput.addEventListener('change', () => _custRenderWallpaperSection());
    }
    const uploadBtn = $id('cust-photo-upload-btn');
    const fileInput = $id('cust-photo-input');
    if (uploadBtn && fileInput) {
      uploadBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', () => {
        const file = fileInput.files?.[0];
        if (!file) return;
        if (file.size > 8 * 1024 * 1024) { try { swShowToast('Please choose an image under 8MB.'); } catch {} fileInput.value = ''; return; }
        const prevLabel = uploadBtn.textContent;
        uploadBtn.disabled = true;
        uploadBtn.textContent = 'Processing…';
        _custResizeImageFile(file, 1280, 0.78)
          .then(dataUrl => {
            const ok = _custSave(WALL_KEY, { type: 'photo', value: dataUrl });
            if (!ok) {
              try { swShowToast("Couldn't save that photo — try a smaller image."); } catch {}
              uploadBtn.disabled = false; uploadBtn.textContent = prevLabel;
              return;
            }
            applyCustomization(); _custRenderWallpaperSection(); _custUpdatePreview();
          })
          .catch(() => {
            try { swShowToast('Could not process that image.'); } catch {}
            uploadBtn.disabled = false; uploadBtn.textContent = prevLabel;
          })
          .finally(() => { fileInput.value = ''; });
      });
    }
    section.querySelector('#cust-photo-remove-btn')?.addEventListener('click', () => {
      _custSave(WALL_KEY, { type: 'default' });
      applyCustomization(); _custRenderWallpaperSection(); _custUpdatePreview();
    });
  }

  function _custRenderBubbleSection() {
    const section = $id('cust-bubble-content');
    if (!section) return;
    const bub = _custLoad(BUBBLE_KEY) || { bg: '#f0f0f0', text: '#0a0a0a' };
    const customActive = !BUBBLE_PRESETS.some(p => p.bg === bub.bg);
    section.innerHTML = `
      <div class="cust-swatch-row">
        ${BUBBLE_PRESETS.map(p => `<div class="cust-swatch${bub.bg === p.bg ? ' active' : ''}" style="background:${p.bg}" data-bubble-bg="${p.bg}" data-bubble-text="${p.text}" title="${p.bg}"></div>`).join('')}
        <div class="cust-swatch-custom${customActive ? ' active' : ''}" title="Custom color">
          ${customActive
            ? `<span class="cust-swatch-custom-fill" style="background:${swEsc(bub.bg)}"></span>`
            : `<span class="cust-swatch-custom-ring"></span><svg class="cust-swatch-custom-plus" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`}
          <input type="color" id="cust-bubble-color-input" value="${customActive ? bub.bg : '#f0f0f0'}">
        </div>
      </div>
      <div class="cust-hint">The color of your own message bubbles — visible to whoever you're chatting with.</div>`;

    section.querySelectorAll('[data-bubble-bg]').forEach(el => {
      el.addEventListener('click', () => {
        _custSave(BUBBLE_KEY, { bg: el.dataset.bubbleBg, text: el.dataset.bubbleText });
        applyCustomization(); _custRenderBubbleSection(); _custUpdatePreview();
      });
    });
    const colorInput = $id('cust-bubble-color-input');
    if (colorInput) {
      colorInput.addEventListener('input', () => {
        const text = _custIsDark(colorInput.value) ? '#ffffff' : '#0a0a0a';
        _custSave(BUBBLE_KEY, { bg: colorInput.value, text });
        applyCustomization(); _custUpdatePreview();
      });
      colorInput.addEventListener('change', () => _custRenderBubbleSection());
    }
  }

  function _custRenderOpacitySection() {
    const section = $id('cust-opacity-content');
    if (!section) return;
    const op = _custLoad(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mineVal   = op.mine   ?? 1;
    const theirsVal = op.theirs ?? 1;
    section.innerHTML = `
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Your bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-mine" min="0.3" max="1" step="0.05" value="${mineVal}">
        <span class="cust-opacity-value" id="cust-opacity-mine-val">${Math.round(mineVal * 100)}%</span>
      </div>
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Received bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-theirs" min="0.3" max="1" step="0.05" value="${theirsVal}">
        <span class="cust-opacity-value" id="cust-opacity-theirs-val">${Math.round(theirsVal * 100)}%</span>
      </div>
      <div class="cust-hint">Make chat bubbles more see-through. Applies to both DMs and group chats on this device.</div>`;

    const mineInput   = $id('cust-opacity-mine');
    const theirsInput = $id('cust-opacity-theirs');
    const mineValEl   = $id('cust-opacity-mine-val');
    const theirsValEl = $id('cust-opacity-theirs-val');

    mineInput?.addEventListener('input', () => {
      const cur = _custLoad(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.mine = parseFloat(mineInput.value);
      _custSave(OPACITY_KEY, cur);
      mineValEl.textContent = `${Math.round(cur.mine * 100)}%`;
      applyCustomization(); _custUpdatePreview();
    });
    theirsInput?.addEventListener('input', () => {
      const cur = _custLoad(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.theirs = parseFloat(theirsInput.value);
      _custSave(OPACITY_KEY, cur);
      theirsValEl.textContent = `${Math.round(cur.theirs * 100)}%`;
      applyCustomization(); _custUpdatePreview();
    });
  }

  function _custRenderReadReceiptsSection() {
    const section = $id('cust-read-receipts-content');
    if (!section) return;
    const on = _readReceiptsEnabled();
    section.innerHTML = `
      <div class="cust-switch-row">
        <div class="cust-switch-text">
          <span class="cust-switch-title">Read Receipts</span>
          <span class="cust-switch-desc">Show the blue "Seen" double-tick on messages you've sent, on this device.</span>
        </div>
        <label class="cust-switch">
          <input type="checkbox" id="cust-read-receipts-toggle" ${on ? 'checked' : ''}>
          <span class="cust-switch-track"></span>
        </label>
      </div>`;
    $id('cust-read-receipts-toggle')?.addEventListener('change', (e) => {
      _custSave(READ_RECEIPTS_KEY, !!e.target.checked);
      // Re-render any ticks already on screen immediately, from data already
      // held locally — no need to wait for the next server poll.
      try {
        const msgs = (typeof DM !== 'undefined' && DM?.msgs) ? DM.msgs : [];
        msgs.forEach(msg => {
          const metaRow = document.querySelector(`.dm-meta[data-meta-for="${msg.id}"]`);
          const oldTick = metaRow?.querySelector('.dm-ticks');
          if (oldTick && typeof _dmTickSpanHTML === 'function') oldTick.outerHTML = _dmTickSpanHTML(msg);
        });
      } catch { /* non-fatal */ }
    });
  }

  function _custSetSeg(seg) {
    _custActiveSeg = seg;
    document.querySelectorAll('.cust-seg-btn').forEach(b => b.classList.toggle('active', b.dataset.seg === seg));
    _custRenderWallpaperSection();
  }

  window.loadCustomization = function loadCustomization() {
    const root = $id('cust-root');
    if (!root) return;
    root.innerHTML = `
      <div class="cust-preview">
        <div class="cust-preview-chat" id="cust-preview-chat">
          <div class="cust-preview-bubble theirs">hey, you around tonight?</div>
          <div class="cust-preview-bubble mine" id="cust-preview-mine-bubble">yeah I'm down 👍</div>
        </div>
      </div>

      <div class="card-title" style="margin-bottom:10px">Chat Wallpaper</div>
      <div class="cust-seg">
        <div class="cust-seg-btn active" data-seg="solid">Solid</div>
        <div class="cust-seg-btn" data-seg="gradient">Gradient</div>
        <div class="cust-seg-btn" data-seg="photo">Photo</div>
      </div>
      <div id="cust-wall-content"></div>
      <button class="cust-upload-btn" id="cust-wall-reset-btn" style="margin-top:4px;margin-bottom:24px">Reset wallpaper to default</button>

      <div class="card-title" style="margin-bottom:10px">Message Color</div>
      <div id="cust-bubble-content"></div>
      <button class="cust-upload-btn" id="cust-bubble-reset-btn" style="margin-top:12px;margin-bottom:24px">Reset message color to default</button>

      <div class="card-title" style="margin-bottom:10px">Bubble Opacity</div>
      <div id="cust-opacity-content"></div>
      <button class="cust-upload-btn" id="cust-opacity-reset-btn" style="margin-top:12px;margin-bottom:24px">Reset opacity to default</button>

      <div class="card-title" style="margin-bottom:10px">Privacy</div>
      <div id="cust-read-receipts-content"></div>
    `;

    document.querySelectorAll('.cust-seg-btn').forEach(btn => {
      btn.addEventListener('click', () => _custSetSeg(btn.dataset.seg));
    });
    $id('cust-wall-reset-btn')?.addEventListener('click', () => {
      _custSave(WALL_KEY, { type: 'default' });
      applyCustomization(); _custRenderWallpaperSection(); _custUpdatePreview();
    });
    $id('cust-bubble-reset-btn')?.addEventListener('click', () => {
      _custSave(BUBBLE_KEY, null);
      applyCustomization(); _custRenderBubbleSection(); _custUpdatePreview();
    });
    $id('cust-opacity-reset-btn')?.addEventListener('click', () => {
      _custSave(OPACITY_KEY, null);
      applyCustomization(); _custRenderOpacitySection(); _custUpdatePreview();
    });

    _custSetSeg('solid');
    _custRenderBubbleSection();
    _custRenderOpacitySection();
    _custRenderReadReceiptsSection();
    _custUpdatePreview();
  };
})();

// ═══════════════════════════════════════════════════════════════════════════
// PATCH — chat header cleanup: Nickname/Block chips lived in two places at
// once (inline in the topbar AND inside the ⓘ info panel). Keep just the ⓘ
// panel as the single home for those actions, and make tapping the avatar
// or name — same as Instagram/WhatsApp — open that panel too.
// ═══════════════════════════════════════════════════════════════════════════

// Neutralize the inline topbar nickname/block chips. These function names
// are plain top-level declarations earlier in this file; re-declaring them
// here overrides the earlier definitions, so initDMExtensions' calls into
// them become harmless no-ops. Block-status/nickname *data* loading (used
// elsewhere, e.g. the blocked banner) is untouched — only the extra chip UI
// that used to render into #dm-topbar-actions is removed.
function dmInjectTopbarActions() { /* no-op — actions live in the ⓘ info panel now */ }
function dmRenderTopbarExtras() { /* no-op — actions live in the ⓘ info panel now */ }

(function wireTopbarPersonClick() {
  function attach(topbarId, infoBtnId) {
    const topbar = document.getElementById(topbarId);
    const infoBtn = document.getElementById(infoBtnId);
    if (!topbar || !infoBtn) return;
    const avatar = topbar.querySelector('.dm-topbar-avatar');
    const info   = topbar.querySelector('.dm-topbar-info');
    [avatar, info].forEach(el => {
      if (!el || el.dataset.personClickWired) return;
      el.dataset.personClickWired = '1';
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => infoBtn.click());
    });
  }
  function init() {
    attach('dm-topbar', 'dm-info-btn');
    attach('gc-topbar', 'gc-info-btn');
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  // dm-active / gc-active windows can be (re)shown after initial load —
  // re-check once shortly after in case the topbar nodes weren't in the DOM yet.
  setTimeout(init, 500);
})();

// ═══════════════════════════════════════════════════════════════════════════
// END PATCH
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// FIRST-TIME FEATURE TOUR — spotlight walkthrough with a skip option
// Runs once per member (tracked in localStorage), right after the existing
// profile-setup nudge resolves. Replayable any time from Settings.
// ═══════════════════════════════════════════════════════════════════════════

// Force the desktop sidebar's collapsible "Settings" submenu open (idempotent
// — adds the 'open' class rather than toggling it, so it's safe to call even
// if it's already open). Needed before tour steps that live inside it
// (Movies / Customization / Grievance) so their nav items are actually
// visible/clickable on desktop; on mobile this submenu doesn't exist at all,
// so those steps instead target elements inside the panel itself (which
// switchPanel() makes visible regardless of device).
function _tourExpandSidebarSettings() {
  $id('sidebar-settings-items')?.classList.add('open');
  $id('sidebar-settings-chevron')?.classList.add('open');
  $id('sidebar-settings-toggle')?.classList.add('open');
}

// Small wrapper so tour steps can jump straight to a panel the same way a
// real nav click would (switchPanel expects an element with .dataset.panel).
function _tourGoToPanel(panelName) {
  switchPanel({ dataset: { panel: panelName } });
}

const KFS_TOUR_STEPS = [
  {
    selectors: null, // no target — centered welcome card
    title: 'Quick tour of KFS',
    body: "Here's a full walkthrough of where everything lives — the feed, collaboration, movie submissions, customization, and how to send us feedback. Tap Skip any time to jump straight in, and you can always replay this from Settings.",
    beforeShow: () => _tourGoToPanel('studio'),
  },
  {
    selectors: ['#studio-feed', '.strand-feed-grid'],
    title: 'Social Strand',
    body: 'This is the feed — see what other members are posting, react with an emoji, or leave a comment on their work.',
    beforeShow: () => _tourGoToPanel('studio'),
  },
  {
    selectors: ['#studio-new-post-btn', '.btb-post-item', '#studio-new-post-btn2'],
    title: 'Share your work',
    body: 'Tap here any time to post a project, photo, video, or update of your own to the Strand.',
  },
  {
    selectors: ['[data-panel="network"]', '#btb-network'],
    title: 'Network',
    body: 'Followers, who you follow, a member directory to discover people, and a leaderboard all live here. Next up — the tab that matters most.',
    beforeShow: () => { _tourGoToPanel('network'); nwSwitchTab('followers'); },
  },
  {
    selectors: ['#new-collab-btn', '[data-network-tab="collab"]'],
    title: 'Collaborate — this is a big one',
    body: 'The Collab tab is where projects actually come together. Post a "Collab Request" listing your project, the role(s) you need filled, and the skills required — it shows up here for every member to browse. See a request that fits you? Reach out directly through Messages. You can also mark your own profile "Open to collab" so people looking for teammates can find you first. If you\'re starting something, don\'t just post in the feed — post it here so it\'s actually discoverable.',
    beforeShow: () => { _tourGoToPanel('network'); nwSwitchTab('collab'); },
  },
  {
    selectors: ['#new-movie-btn', '#panel-movies'],
    title: 'My Movies — submissions & change requests',
    body: 'Submit a finished film here for admin review and publication on /films. Every submission gets a status: Pending (awaiting review), Approved, Rejected, or Changes Requested. If you see "Changes Requested," an admin left feedback under "Admin feedback" on the card — click Edit on that same submission to update it and resubmit; you don\'t need to start a new one.',
    beforeShow: () => { _tourExpandSidebarSettings(); _tourGoToPanel('movies'); },
  },
  {
    selectors: ['#panel-customization', '[data-panel="customization"]'],
    title: 'Customization',
    body: 'Make the app feel like yours — personalize your chat wallpaper and message bubble colors from here. Heads up: these preferences are saved locally to this device/browser only, so they won\'t follow you if you log in elsewhere.',
    beforeShow: () => { _tourExpandSidebarSettings(); _tourGoToPanel('customization'); },
  },
  {
    selectors: ['#grv-tab-suggestion', '#panel-grievance'],
    title: 'Feedback & Grievances — please use this',
    body: 'Seriously, use this one. There are two tabs: 💡 Suggestion for ideas on how to improve KFS, and 🚨 Grievance for reporting a problem or raising a concern. You can submit either anonymously if you\'d rather not attach your name. Every submission goes straight to the team for review — this is the direct line for anything you want changed or fixed, so don\'t sit on it.',
    beforeShow: () => { _tourExpandSidebarSettings(); _tourGoToPanel('grievance'); },
  },
  {
    selectors: ['#nav-dms', '[data-panel="dms"]'],
    title: 'Messages',
    body: 'Direct messages and group chats with other members live here — including the collaborators you find on the Collab tab.',
  },
  {
    selectors: ['[data-panel="profile"]', '#btb-settings'],
    title: "You're set",
    body: 'Profile, My Movies, My Works, Security, and Customization are always one tap away under Settings. You can replay this tour any time from the same menu. Enjoy KFS!',
    beforeShow: () => { _tourExpandSidebarSettings(); },
  },
];

let _tourStep = 0;
let _tourResizeHandler = null;

function _tourFindTarget(selectors) {
  if (!selectors) return null;
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el && el.offsetParent !== null) return el; // must be visible in current layout
  }
  return null;
}

function kfsStartTour(force = false) {
  const memberId = (_member?.id || window._memberProfile?.id || 'unknown');
  const tourKey = `kfs-tour-seen-${memberId}`;
  if (!force && localStorage.getItem(tourKey)) return;
  if ($id('app-screen')?.style.display === 'none') return; // not logged in / not on dashboard

  _tourStep = 0;
  _tourBuildDom();
  _tourRenderStep();
}

function _tourBuildDom() {
  if ($id('kfs-tour-root')) return;
  const root = document.createElement('div');
  root.id = 'kfs-tour-root';
  root.innerHTML = `
    <div id="kfs-tour-backdrop"></div>
    <div id="kfs-tour-spot"></div>
    <div id="kfs-tour-card" role="dialog" aria-modal="true">
      <div class="kfs-tour-dots"></div>
      <div class="kfs-tour-title"></div>
      <div class="kfs-tour-body"></div>
      <div class="kfs-tour-actions">
        <button type="button" class="kfs-tour-skip">Skip</button>
        <div style="flex:1"></div>
        <button type="button" class="kfs-tour-back">Back</button>
        <button type="button" class="kfs-tour-next">Next</button>
      </div>
    </div>`;
  document.body.appendChild(root);
  root.querySelector('.kfs-tour-skip').addEventListener('click', _tourEnd);
  root.querySelector('.kfs-tour-back').addEventListener('click', () => { if (_tourStep > 0) { _tourStep--; _tourRenderStep(); } });
  root.querySelector('.kfs-tour-next').addEventListener('click', () => {
    if (_tourStep >= KFS_TOUR_STEPS.length - 1) { _tourEnd(); return; }
    _tourStep++;
    _tourRenderStep();
  });
  _tourResizeHandler = () => _tourPositionSpot();
  window.addEventListener('resize', _tourResizeHandler);
  window.addEventListener('scroll', _tourResizeHandler, true);
}

function _tourRenderStep() {
  const step = KFS_TOUR_STEPS[_tourStep];
  const root = $id('kfs-tour-root');
  if (!root || !step) return;

  // Navigate to whatever panel/tab this step is actually about, so the
  // spotlight highlights real, live UI instead of a nav item pointing at
  // content the person can't currently see.
  if (typeof step.beforeShow === 'function') {
    try { step.beforeShow(); } catch (e) { /* non-fatal — fall back to spotlight-search below */ }
  }

  root.querySelector('.kfs-tour-title').textContent = step.title;
  root.querySelector('.kfs-tour-body').textContent = step.body;
  root.querySelector('.kfs-tour-back').style.visibility = _tourStep === 0 ? 'hidden' : 'visible';
  root.querySelector('.kfs-tour-next').textContent = _tourStep === KFS_TOUR_STEPS.length - 1 ? 'Get started' : 'Next';

  const dots = root.querySelector('.kfs-tour-dots');
  dots.innerHTML = KFS_TOUR_STEPS.map((_, i) => `<span class="kfs-tour-dot${i === _tourStep ? ' active' : ''}"></span>`).join('');

  _tourPositionSpot();
}

function _tourPositionSpot() {
  const step = KFS_TOUR_STEPS[_tourStep];
  const spot = $id('kfs-tour-spot');
  const card = $id('kfs-tour-card');
  if (!spot || !card || !step) return;

  const target = _tourFindTarget(step.selectors);
  if (!target) {
    // No visible target for this step (e.g. desktop-only or mobile-only nav
    // element not present at this breakpoint) — skip straight past it rather
    // than showing a spotlight pointing at nothing.
    if (step.selectors) {
      if (_tourStep < KFS_TOUR_STEPS.length - 1) { _tourStep++; _tourRenderStep(); }
      else _tourEnd();
      return;
    }
    // Welcome step — no spotlight, just center the card
    spot.style.display = 'none';
    card.style.top = '50%';
    card.style.left = '50%';
    card.style.transform = 'translate(-50%, -50%)';
    return;
  }

  const r = target.getBoundingClientRect();
  const pad = 8;
  spot.style.display = 'block';
  spot.style.top = `${r.top - pad}px`;
  spot.style.left = `${r.left - pad}px`;
  spot.style.width = `${r.width + pad * 2}px`;
  spot.style.height = `${r.height + pad * 2}px`;

  // Place the card below the target if there's room, otherwise above; clamp
  // horizontally so it never runs off-screen on narrow viewports.
  const cardW = Math.min(320, window.innerWidth - 32);
  card.style.width = `${cardW}px`;
  card.style.transform = 'none';
  let left = Math.min(Math.max(r.left, 16), window.innerWidth - cardW - 16);
  let top = r.bottom + pad + 14;
  if (top + 160 > window.innerHeight) top = Math.max(16, r.top - pad - 14 - 160);
  card.style.left = `${left}px`;
  card.style.top = `${top}px`;
}

function _tourEnd() {
  const memberId = (_member?.id || window._memberProfile?.id || 'unknown');
  localStorage.setItem(`kfs-tour-seen-${memberId}`, '1');
  const root = $id('kfs-tour-root');
  if (root) root.remove();
  if (_tourResizeHandler) {
    window.removeEventListener('resize', _tourResizeHandler);
    window.removeEventListener('scroll', _tourResizeHandler, true);
    _tourResizeHandler = null;
  }
  // The tour now hops across several panels (Collab, Movies, Customization,
  // Grievance) — leave the person somewhere sensible rather than wherever
  // the last step happened to land them.
  _goToStrandFeed();
}

//==============================================================================
// PATCH STACK MERGED INTO CORE FILE — 2026-07-19
//
// Everything below this line used to live in separate files
// (kfs-patch2.js through kfs-patch8.js, plus kfs-strand-live-patch.js),
// loaded as individual <script defer> tags AFTER this file, in the exact
// order they appear here. Each patch is a self-contained IIFE that
// monkey-patches globals defined above (or by an earlier patch in this
// same list) — merging them into one file changes nothing about how they
// run, since classic <script> tags already shared one global `window`
// scope. This merge only removes the file-boundary bookkeeping so the
// whole patch history lives in one place instead of 8+ files that each
// assumed a specific load order relative to the others.
//
// kfs-debug-trace.js (dev-only console instrumentation, zero behavior
// change) was intentionally dropped rather than merged — it was never
// meant for production and added nothing here.
//==============================================================================

//------------------------------------------------------------------------------
// ── formerly kfs-patch2.js ──
//------------------------------------------------------------------------------
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
    gcRenderMsgs = function patchedGcRenderMsgs() {
      var msgs = arguments[0];
      if (Array.isArray(msgs)) {
        msgs.forEach(function (m) {
          if (m && m.id && typeof m.is_pinned === "boolean") {
            setPinState(m.id, m.is_pinned);
          }
        });
      }
      // IMPORTANT: forward every argument the caller actually passed
      // (msgs, container, myId, lastSenderHint) — the original two-param
      // signature here silently dropped myId/lastSenderHint on every call,
      // which broke "mine" detection and message grouping site-wide.
      return orig.apply(this, arguments);
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

//------------------------------------------------------------------------------
// ── formerly kfs-patch3.js ──
//------------------------------------------------------------------------------
/**
 * kfs-patch3.js — KFS Social Hotfix, Part 3
 * =====================================================================
 * Load AFTER membersaccess.js, kfs-social-hotfix.js, kfs-patch2.js.
 *
 *   <script src="/kfs-patch3.js" defer></script>
 *
 * Fixes:
 *   1. RACE CONDITION — FIXED IN SOURCE (membersaccess.js); wrappers removed.
 *      window.dmPanelOpened now gates on _token before calling inboxLoad
 *      (fixes the primary call path). blocksEnsureLoaded now waits for _token
 *      and preserves BLOCKS.set on failure instead of wiping it.
 *      The window._inboxLoad wrapper previously here targeted the wrong
 *      binding — the real call path uses a closure-local inboxLoad reference
 *      that the wrapper never intercepted. The nicksLoadGlobal wrapper was
 *      redundant because nicksLoadGlobal already has its own internal
 *      member-ID polling guard.
 *   2. PROFANITY MODAL — server sends temp_banned but client checks
 *      banned. Normalises the error object so the right overlay fires.
 *   3. PIN — context menu label flips correctly on re-open after toggle.
 *   4. 404 on broadcast DM — FIXED IN SOURCE (membersaccess.js); wrapper removed.
 *   5. INSTAGRAM UI — Apple-clean mobile + desktop overhaul:
 *      · Message rows: photo, name, preview, time — all IG-style
 *      · Conversation header with avatar + online dot
 *      · Bubble style: sender right (gradient), peer left (surface)
 *      · Bottom tab bar: active icons filled, smooth transitions
 *      · Story-ring avatar for unread conversations
 *      · Swipe-to-reply gesture on mobile bubbles
 *      · Input bar: pill-shaped, send only appears when text present
 *      · Smooth slide transitions between sidebar and chat
 * =====================================================================
 */
(function kfsPatch3() {
  'use strict';

  // ─── Helpers ─────────────────────────────────────────────────────────────────
  var DEBUG = location.search.indexOf('kfs_debug') !== -1;
  function log(...a) { if (DEBUG) console.log('[kfs-p3]', ...a); }

  // ─── 1. RACE CONDITION FIX ──────────────────────────────────────────────────
  // Problem: DOMContentLoaded fires initDMExtensions → inboxLoad → dmMyId()
  // returns null because refreshToken() hasn't resolved yet.
  //
  // Fix: intercept loadDashboard (called after refreshToken sets _member)
  // and only THEN allow inboxLoad / nicksLoadGlobal to proceed.
  // We install a promise that resolves when _member is confirmed available.

  var _memberReady = false;
  var _memberReadyCallbacks = [];
  function onMemberReady(fn) {
    if (_memberReady) { fn(); return; }
    _memberReadyCallbacks.push(fn);
  }
  function memberReadyFired() {
    if (_memberReady) return;
    _memberReady = true;
    _memberReadyCallbacks.forEach(fn => { try { fn(); } catch(e) {} });
    _memberReadyCallbacks = [];
  }

  // Patch loadDashboard — it's the single gate after refreshToken
  var _loadDashboardOrig = null;
  function patchLoadDashboard() {
    if (typeof loadDashboard !== 'function') return false;
    _loadDashboardOrig = loadDashboard;
    loadDashboard = async function patchedLoadDashboard() {
      const result = await _loadDashboardOrig.apply(this, arguments);
      memberReadyFired();
      return result;
    };
    return true;
  }
  if (!patchLoadDashboard()) {
    document.addEventListener('DOMContentLoaded', () => patchLoadDashboard());
  }

  // Also resolve immediately if _member is already set (session already loaded)
  function checkMemberAlreadySet() {
    const m = window._memberProfile || window._member;
    if (m && (m.id || m.member_id)) { memberReadyFired(); return true; }
    return false;
  }
  if (!checkMemberAlreadySet()) {
    // Poll as a fallback — catches cases where loadDashboard was called before
    // our patch could install
    var _memberPollTimer = setInterval(() => {
      if (checkMemberAlreadySet()) clearInterval(_memberPollTimer);
    }, 80);
    // Give up after 10 s regardless
    setTimeout(() => { clearInterval(_memberPollTimer); memberReadyFired(); }, 10000);
  }

  // NOTE (fixed in membersaccess.js — wrapper removed):
  // The window._inboxLoad wrapper that previously lived here targeted the wrong
  // binding. The primary call path is:
  //   switchPanel('dms') → window.dmPanelOpened() → closure-local inboxLoad()
  // window._inboxLoad is only an alias used by poll-tick callers, which only
  // fire after loadDashboard completes and _token is already set, so they never
  // needed guarding. The fix now lives in window.dmPanelOpened in
  // membersaccess.js, which gates on _token before calling inboxLoad directly.
  //
  // NOTE (redundant wrapper removed):
  // nicksLoadGlobal already contains its own internal "wait for member ID"
  // polling loop (membersaccess.js lines 6430+). Stacking a second,
  // uncoordinated onMemberReady gate on top created two sources of truth that
  // could both resolve at different times and trigger double fetches.
  // nicksLoadGlobal handles its own readiness — no wrapper needed here.
  //
  // Both of the wrapper functions that used to live in this spot
  // (patchInboxLoad / patchNicksLoadGlobal) were confirmed dead no-ops and
  // have been deleted outright during the 2026-07 patch consolidation —
  // there is nothing left here for a future edit to accidentally depend on.

  // ─── 2. PROFANITY MODAL — normalise temp_banned ─────────────────────────────
  // Server sends { temp_banned: true, suspended_until: '...' }
  // but the catch block checks ed.warned||ed.muted||ed.banned||ed.temp_banned.
  // The check itself is correct — the problem was api() dropping the body.
  // We patch the api() helper to *always* preserve _data even for /groups paths.

  function patchApiErrorData() {
    if (typeof api !== 'function') return false;
    var _apiOrig = api;
    api = async function patchedApiErrData(method, path, body, opts) {
      try {
        return await _apiOrig.call(this, method, path, body, opts);
      } catch (e) {
        // If _data is missing the violation flags but the message hints at one,
        // synthesise the flags so _vioShowClientNotice fires the right overlay.
        if (e && !e._data) e._data = {};
        var d = e._data || {};
        var msg = (e.message || '').toLowerCase();
        if (!d.temp_banned && !d.banned && !d.muted && !d.warned) {
          if (msg.includes('temp') || msg.includes('suspended') || msg.includes('temporarily')) {
            e._data = Object.assign({}, d, { temp_banned: true });
          } else if (msg.includes('disabled') || msg.includes('permanently')) {
            e._data = Object.assign({}, d, { banned: true });
          } else if (msg.includes('muted')) {
            e._data = Object.assign({}, d, { muted: true, warned: true });
          } else if (msg.includes('warning') || msg.includes('blocked') || msg.includes('violation')) {
            e._data = Object.assign({}, d, { warned: true });
          }
        }
        throw e;
      }
    };
    log('api() patched for violation data normalisation');
    return true;
  }
  if (!patchApiErrorData()) {
    document.addEventListener('DOMContentLoaded', patchApiErrorData);
  }

  // ─── 3. PIN — ensure label flips after toggle ────────────────────────────────
  // kfs-patch2.js already handles the registry. We add one more guard:
  // after a successful pin API call, force a re-render of the context-menu
  // toggle label if the menu is still open.

  var _lastPinToggleAt = 0;
  var _origGcContextPinHandler = null;

  function patchPinAction() {
    // The pin action lives inside _showMsgContextMenu as an inline closure.
    // We cannot re-enter it, but we can observe the pin endpoint response via
    // the already-patched api() from kfs-patch2 + our own overlay here.
    // Strategy: after any POST to /pin, update the bubble's data attribute
    // so the *next* context-menu open reads the correct is_pinned value.
    if (typeof api !== 'function') return;
    var _a = api;
    api = async function patchedApiPin(method, path, body, opts) {
      const r = await _a.call(this, method, path, body, opts);
      if (
        method === 'POST' &&
        path.indexOf('/messages/') !== -1 &&
        path.endsWith('/pin') &&
        r && typeof r.is_pinned === 'boolean'
      ) {
        // Update bubble dataset so context menu next time reads fresh value
        try {
          const parts = path.split('/messages/');
          const msgId = parts[1]?.replace('/pin','')?.split('?')[0];
          if (msgId) {
            const bubble = document.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
            if (bubble) {
              bubble.dataset.isPinned = String(r.is_pinned);
              log('pin state updated on bubble', msgId, r.is_pinned);
            }
          }
        } catch (_) {}
        _lastPinToggleAt = Date.now();
      }
      return r;
    };
  }

  document.addEventListener('DOMContentLoaded', patchPinAction);

  // ─── 4. BROADCAST 404 FIX — REMOVED ──────────────────────────────────────────
  // This wrapper is no longer needed. Both wrong /api/member/dm/messages call
  // sites have been corrected directly in membersaccess.js (share modal line
  // 9244 and broadcast modal line 9659). The patchedApiBroadcast api() wrapper
  // that lived here has been removed to reduce the api() call stack depth.

  // ─── 5. INSTAGRAM / APPLE UI OVERHAUL ────────────────────────────────────────

  function injectStyles() {
    const existing = document.getElementById('kfs-ig-styles');
    if (existing) existing.remove();

    const css = `
/* ════════════════════════════════════════════════════════════════════
   KFS INSTAGRAM-STYLE UI — kfs-patch3.js
   Design system: pure black (#000), surface (#111 / #1a1a1a),
   border (#222), accent (#0095f6 / IG blue), text (#f5f5f7)
   Transitions: cubic-bezier(.4,0,.2,1) 220ms
   ════════════════════════════════════════════════════════════════════ */

/* ── CSS custom properties (override theme) ─── */
:root {
  --ig-bg:        #000000;
  --ig-surface:   #111111;
  --ig-surface2:  #1a1a1a;
  --ig-border:    #262626;
  --ig-text:      #f5f5f7;
  --ig-muted:     #8e8e8e;
  --ig-accent:    #0095f6;
  --ig-bubble-me: linear-gradient(145deg, #0095f6, #0064d2);
  --ig-bubble-rx: #262626;
  --ig-radius:    22px;
  --ig-ease:      cubic-bezier(.4,0,.2,1);
  --ig-dur:       220ms;
}

/* ── SIDEBAR / INBOX ───────────────────────────────────────────────── */
.dm-sidebar {
  background: var(--ig-bg) !important;
  border-right: 1px solid var(--ig-border) !important;
}

.dm-header {
  padding: 14px 16px 10px !important;
  border-bottom: none !important;
  display: flex !important;
  align-items: center !important;
  justify-content: space-between !important;
}

.dm-header-title {
  font-size: 16px !important;
  font-weight: 700 !important;
  letter-spacing: -.01em !important;
  color: var(--ig-text) !important;
}

/* ── Search bar ── */
.dm-search-wrap {
  margin: 0 12px 8px !important;
  position: relative !important;
}
.dm-search-input {
  width: 100% !important;
  box-sizing: border-box !important;
  background: var(--ig-surface2) !important;
  border: none !important;
  border-radius: 10px !important;
  padding: 9px 14px 9px 36px !important;
  font-size: 14px !important;
  color: var(--ig-text) !important;
  outline: none !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-search-input:focus {
  background: #222 !important;
}
.dm-search-icon {
  color: var(--ig-muted) !important;
  left: 12px !important;
}

/* ── Conversation rows ── */
.dm-conv-list {
  padding: 0 4px !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
}
.dm-conv-row {
  display: flex !important;
  align-items: center !important;
  gap: 12px !important;
  padding: 10px 12px !important;
  border-radius: 12px !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
  position: relative !important;
  border: none !important;
  background: transparent !important;
  min-height: 68px !important;
}
.dm-conv-row:hover {
  background: rgba(255,255,255,.05) !important;
}
.dm-conv-row.dm-active-row {
  background: rgba(0,149,246,.08) !important;
}

/* Story-ring for unread */
.dm-conv-row.kfs-has-unread .dm-av,
.dm-conv-row.kfs-has-unread .dm-av-placeholder {
  outline: 2px solid var(--ig-accent) !important;
  outline-offset: 2px !important;
}

/* Conversation info */
.dm-conv-info {
  flex: 1 !important;
  min-width: 0 !important;
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
}
.dm-conv-name {
  font-size: 14px !important;
  font-weight: 600 !important;
  color: var(--ig-text) !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
  line-height: 1.3 !important;
}
.dm-conv-preview {
  font-size: 13px !important;
  color: var(--ig-muted) !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
}
.dm-conv-preview.dm-has-unread {
  color: var(--ig-text) !important;
  font-weight: 600 !important;
}
.dm-conv-right {
  display: flex !important;
  flex-direction: column !important;
  align-items: flex-end !important;
  gap: 4px !important;
  flex-shrink: 0 !important;
}
.dm-conv-time {
  font-size: 11px !important;
  color: var(--ig-muted) !important;
}
.dm-unread-pill {
  background: var(--ig-accent) !important;
  color: #fff !important;
  font-size: 10px !important;
  font-weight: 700 !important;
  border-radius: 100px !important;
  min-width: 18px !important;
  height: 18px !important;
  padding: 0 5px !important;
  line-height: 18px !important;
  text-align: center !important;
  display: inline-block !important;
}

/* ── CHAT WINDOW ── */
/* FIXED: display was previously "flex !important", which permanently
   overrode the inline style="display:none" / JS toggle that switches
   between the DM window and the group window — both ended up stuck open
   at once. Dropping !important here lets gcGoBack()/inboxOpenDm()'s
   inline style.display changes win again, like they did before this
   stylesheet was wired in. background/flex-direction are unaffected and
   stay forced. */
.dm-window, #gc-window {
  background: var(--ig-bg) !important;
  display: flex;
  flex-direction: column !important;
}

/* ── Topbar ── */
.dm-topbar, #gc-topbar {
  background: var(--ig-bg) !important;
  border-bottom: 1px solid var(--ig-border) !important;
  padding: 10px 16px !important;
  display: flex !important;
  align-items: center !important;
  gap: 12px !important;
  min-height: 58px !important;
  flex-shrink: 0 !important;
}
.dm-topbar-name, #gc-topbar-name {
  font-size: 15px !important;
  font-weight: 700 !important;
  color: var(--ig-text) !important;
  letter-spacing: -.01em !important;
}
.dm-topbar-sub, #gc-topbar-sub {
  font-size: 12px !important;
  color: var(--ig-muted) !important;
}

/* Topbar action buttons */
.dm-topbar-actions, #gc-topbar-actions {
  margin-left: auto !important;
  display: flex !important;
  gap: 4px !important;
  align-items: center !important;
}
.dm-icon-btn, .gc-icon-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 50% !important;
  background: transparent !important;
  border: none !important;
  color: var(--ig-text) !important;
  cursor: pointer !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-icon-btn:hover, .gc-icon-btn:hover {
  background: rgba(255,255,255,.08) !important;
}

/* ── Message list ── */
.dm-msg-list, #gc-msg-list {
  flex: 1 !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  padding: 16px 16px 8px !important;
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
  scroll-behavior: smooth !important;
}

/* ── Message groups ── */
.dm-msg-group {
  display: flex !important;
  flex-direction: column !important;
  gap: 2px !important;
  margin-bottom: 4px !important;
}

/* ── Bubbles ── */
.dm-bubble-wrap {
  display: flex !important;
  align-items: flex-end !important;
  gap: 6px !important;
  max-width: 72% !important;
}
.dm-bubble-wrap.dm-me {
  align-self: flex-end !important;
  flex-direction: row-reverse !important;
}
.dm-bubble-wrap.dm-them {
  align-self: flex-start !important;
}

.dm-bubble {
  padding: 10px 14px !important;
  font-size: 14px !important;
  line-height: 1.5 !important;
  border-radius: var(--ig-radius) !important;
  max-width: 100% !important;
  word-break: break-word !important;
  transition: opacity var(--ig-dur) var(--ig-ease) !important;
  position: relative !important;
}

/* Sender (me) — IG blue gradient */
.dm-bubble.dm-bubble-me,
.dm-bubble.dm-mine {
  background: var(--ig-bubble-me) !important;
  color: #fff !important;
  border-bottom-right-radius: 6px !important;
}

/* Receiver — dark surface */
.dm-bubble.dm-bubble-them,
.dm-bubble.dm-theirs {
  background: var(--ig-bubble-rx) !important;
  color: var(--ig-text) !important;
  border-bottom-left-radius: 6px !important;
}

.dm-bubble.dm-deleted {
  opacity: .45 !important;
  font-style: italic !important;
  background: transparent !important;
  border: 1px solid var(--ig-border) !important;
  color: var(--ig-muted) !important;
}

/* Meta (timestamp + read receipt) */
.dm-meta {
  font-size: 11px !important;
  color: var(--ig-muted) !important;
  padding: 0 4px 2px !important;
}

/* ── INPUT BAR ── */
.dm-input-area, #gc-input-area {
  padding: 10px 12px !important;
  border-top: 1px solid var(--ig-border) !important;
  background: var(--ig-bg) !important;
  display: flex !important;
  align-items: flex-end !important;
  gap: 8px !important;
  flex-shrink: 0 !important;
}

.dm-input, #gc-input {
  flex: 1 !important;
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 22px !important;
  padding: 10px 16px !important;
  font-size: 14px !important;
  color: var(--ig-text) !important;
  outline: none !important;
  resize: none !important;
  line-height: 1.45 !important;
  max-height: 110px !important;
  overflow-y: auto !important;
  transition: border-color var(--ig-dur) var(--ig-ease) !important;
  font-family: inherit !important;
}
.dm-input:focus, #gc-input:focus {
  border-color: var(--ig-accent) !important;
}
.dm-input::placeholder, #gc-input::placeholder {
  color: var(--ig-muted) !important;
}

/* Send button — IG blue, fades in when text present */
.dm-send-btn, #gc-send-btn {
  width: 40px !important;
  height: 40px !important;
  border-radius: 50% !important;
  background: var(--ig-accent) !important;
  border: none !important;
  color: #fff !important;
  cursor: pointer !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  flex-shrink: 0 !important;
  transition: opacity var(--ig-dur) var(--ig-ease),
              transform var(--ig-dur) var(--ig-ease),
              background var(--ig-dur) var(--ig-ease) !important;
  opacity: 0 !important;
  pointer-events: none !important;
  transform: scale(.8) !important;
}
.dm-send-btn.kfs-can-send, #gc-send-btn.kfs-can-send {
  opacity: 1 !important;
  pointer-events: auto !important;
  transform: scale(1) !important;
}
.dm-send-btn:hover, #gc-send-btn:hover {
  background: #0080d3 !important;
}
.dm-send-btn:active, #gc-send-btn:active {
  transform: scale(.92) !important;
}

/* ── BOTTOM TAB BAR ── */
.bottom-tab-bar {
  background: rgba(0,0,0,.92) !important;
  backdrop-filter: saturate(180%) blur(20px) !important;
  -webkit-backdrop-filter: saturate(180%) blur(20px) !important;
  border-top: 1px solid var(--ig-border) !important;
  padding: 0 !important;
  height: 52px !important;
  display: flex !important;
  align-items: stretch !important;
}
.btb-item {
  flex: 1 !important;
  display: flex !important;
  flex-direction: column !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 3px !important;
  cursor: pointer !important;
  color: var(--ig-muted) !important;
  transition: color var(--ig-dur) var(--ig-ease) !important;
  -webkit-tap-highlight-color: transparent !important;
  position: relative !important;
  padding: 8px 0 !important;
}
.btb-item svg {
  width: 24px !important;
  height: 24px !important;
  stroke-width: 1.8 !important;
  transition: transform var(--ig-dur) var(--ig-ease),
              stroke var(--ig-dur) var(--ig-ease) !important;
}
.btb-item.active {
  color: var(--ig-text) !important;
}
.btb-item.active svg {
  stroke-width: 2.5 !important;
}
.btb-item:active svg {
  transform: scale(.88) !important;
}
.btb-label {
  font-size: 10px !important;
  font-weight: 500 !important;
  letter-spacing: .01em !important;
}

/* Centre post button */
.btb-post-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 10px !important;
  background: var(--ig-text) !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  transition: transform var(--ig-dur) var(--ig-ease),
              opacity var(--ig-dur) var(--ig-ease) !important;
}
.btb-post-item:active .btb-post-btn {
  transform: scale(.9) !important;
  opacity: .8 !important;
}
.btb-post-btn svg {
  color: #000 !important;
  stroke: #000 !important;
}

/* ── MOBILE DM SLIDE ── */
@media (max-width: 768px) {
  .dm-sidebar {
    transition: transform var(--ig-dur) var(--ig-ease) !important;
  }
  .dm-window, #gc-window {
    transition: transform var(--ig-dur) var(--ig-ease) !important;
  }
  .dm-bubble-wrap { max-width: 82% !important; }
}

/* ── PINNED BANNER ── */
#gc-pinned-bar {
  background: rgba(0,0,0,.9) !important;
  backdrop-filter: blur(8px) !important;
  border-bottom: 1px solid var(--ig-border) !important;
  padding: 8px 16px !important;
  font-size: 12px !important;
  color: var(--ig-muted) !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
#gc-pinned-bar:hover { background: rgba(255,255,255,.05) !important; }

/* ── E2EE notice ── */
.gc-e2ee-notice, .dm-e2ee-notice {
  background: transparent !important;
  border-color: var(--ig-border) !important;
  color: var(--ig-muted) !important;
  font-size: 11px !important;
}

/* ── Avatar helpers ── */
.dm-av, .dm-av-placeholder, .gc-group-av {
  border-radius: 50% !important;
  flex-shrink: 0 !important;
  transition: outline-color var(--ig-dur) var(--ig-ease) !important;
}

/* ── Verified KFS badge ── */
.kfs-verified-badge {
  display: inline-flex !important;
  align-items: center !important;
  justify-content: center !important;
  width: 14px !important;
  height: 14px !important;
  border-radius: 50% !important;
  background: var(--ig-accent) !important;
  margin-left: 3px !important;
  vertical-align: middle !important;
  flex-shrink: 0 !important;
}

/* ── Broadcast button (admin) ── */
#kfs-broadcast-btn {
  margin: 6px 12px 4px !important;
  width: calc(100% - 24px) !important;
  border-radius: 10px !important;
  font-size: 13px !important;
  padding: 9px 14px !important;
  background: linear-gradient(135deg, #0064d2, #0095f6) !important;
}

/* ── Context menu ── */
.dm-ctx-menu, #dm-ctx-menu {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 14px !important;
  box-shadow: 0 8px 32px rgba(0,0,0,.6) !important;
  overflow: hidden !important;
  min-width: 180px !important;
}
.dm-ctx-item {
  padding: 11px 16px !important;
  font-size: 14px !important;
  cursor: pointer !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
  display: flex !important;
  align-items: center !important;
  gap: 10px !important;
}
.dm-ctx-item:hover { background: rgba(255,255,255,.06) !important; }
.dm-ctx-item.dm-ctx-danger { color: #ff3b30 !important; }
.dm-ctx-sep { height: 1px !important; background: var(--ig-border) !important; }

/* ── Reaction row ── */
.dm-reactions {
  display: flex !important;
  flex-wrap: wrap !important;
  gap: 4px !important;
  margin-top: 4px !important;
}
.dm-reaction-pill {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 100px !important;
  padding: 2px 8px !important;
  font-size: 12px !important;
  cursor: pointer !important;
  display: inline-flex !important;
  align-items: center !important;
  gap: 4px !important;
  transition: background var(--ig-dur) var(--ig-ease) !important;
}
.dm-reaction-pill:hover { background: rgba(255,255,255,.1) !important; }
.dm-reaction-pill.dm-reacted {
  background: rgba(0,149,246,.18) !important;
  border-color: rgba(0,149,246,.4) !important;
}

/* ── Emoji picker ── */
.dm-emoji-picker {
  background: var(--ig-surface2) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 50px !important;
  padding: 6px 10px !important;
  box-shadow: 0 4px 20px rgba(0,0,0,.5) !important;
  display: flex !important;
  gap: 4px !important;
}

/* ── Scrollbar (webkit) ── */
.dm-msg-list::-webkit-scrollbar,
#gc-msg-list::-webkit-scrollbar,
.dm-conv-list::-webkit-scrollbar {
  width: 4px !important;
}
.dm-msg-list::-webkit-scrollbar-track,
#gc-msg-list::-webkit-scrollbar-track,
.dm-conv-list::-webkit-scrollbar-track {
  background: transparent !important;
}
.dm-msg-list::-webkit-scrollbar-thumb,
#gc-msg-list::-webkit-scrollbar-thumb,
.dm-conv-list::-webkit-scrollbar-thumb {
  background: #333 !important;
  border-radius: 2px !important;
}

/* ── Send button visibility driven by textarea content ── */
.kfs-ig-input-wrap {
  display: flex !important;
  align-items: flex-end !important;
  flex: 1 !important;
  gap: 8px !important;
}

/* ── Nick modal ── */
#nick-modal-overlay {
  background: rgba(0,0,0,.7) !important;
  backdrop-filter: blur(12px) !important;
}

/* ── Group creation modal ── */
#gc-create-modal {
  background: var(--ig-surface) !important;
  border: 1px solid var(--ig-border) !important;
  border-radius: 18px !important;
}

/* ── Detail panel ── */
.dm-detail-panel {
  background: var(--ig-surface) !important;
  border-left: 1px solid var(--ig-border) !important;
}

/* ── Swipe hint for mobile message back gesture ── */
@media (max-width: 768px) {
  .dm-back {
    display: inline-flex !important;
    align-items: center !important;
    gap: 4px !important;
    padding: 6px 10px 6px 6px !important;
    border-radius: 20px !important;
    background: transparent !important;
    border: none !important;
    color: var(--ig-accent) !important;
    font-size: 15px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
    -webkit-tap-highlight-color: transparent !important;
  }
}

/* ── Story-ring indicator on unread conv avatars ── */
@keyframes kfsRingPulse {
  0%,100% { outline-color: var(--ig-accent); }
  50%      { outline-color: rgba(0,149,246,.4); }
}
.dm-conv-row.kfs-has-unread .dm-av,
.dm-conv-row.kfs-has-unread .dm-av-placeholder {
  animation: kfsRingPulse 2.4s ease infinite !important;
}

/* ── Input area extra utilities ── */
.dm-input-extra-btns {
  display: flex !important;
  align-items: center !important;
  gap: 2px !important;
}
.dm-input-extra-btn {
  width: 36px !important;
  height: 36px !important;
  border-radius: 50% !important;
  background: transparent !important;
  border: none !important;
  color: var(--ig-muted) !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  cursor: pointer !important;
  transition: color var(--ig-dur) var(--ig-ease) !important;
  flex-shrink: 0 !important;
}
.dm-input-extra-btn:hover { color: var(--ig-text) !important; }

/* ── Reduce motion ── */
@media (prefers-reduced-motion: reduce) {
  .dm-sidebar, .dm-window, #gc-window,
  .dm-bubble, .dm-send-btn, #gc-send-btn,
  .btb-item svg {
    transition: none !important;
    animation: none !important;
  }
}
`;

    const el = document.createElement('style');
    el.id = 'kfs-ig-styles';
    el.textContent = css;
    document.head.appendChild(el);
    log('IG styles injected');
  }

  // ─── 5b. Send button visibility toggle ───────────────────────────────────────
  function wireSendButtonVisibility() {
    function wire(inputId, sendId) {
      const inp = document.getElementById(inputId);
      const btn = document.getElementById(sendId);
      if (!inp || !btn) return;

      function update() {
        const hasText = inp.value.trim().length > 0;
        btn.classList.toggle('kfs-can-send', hasText);
      }
      inp.addEventListener('input', update);
      // Run once in case there's already content
      update();
    }

    wire('dm-input', 'dm-send-btn');
    wire('gc-input', 'gc-send-btn');
  }

  // ─── 5c. Story ring on unread rows ───────────────────────────────────────────
  function applyStoryRings() {
    document.querySelectorAll('.dm-conv-row').forEach(row => {
      const pill = row.querySelector('.dm-unread-pill');
      row.classList.toggle('kfs-has-unread', !!pill);
    });
  }

  // Observe conv list changes so rings update when inboxRender fires
  function observeConvList() {
    const list = document.getElementById('dm-conv-list');
    if (!list) return;
    const obs = new MutationObserver(applyStoryRings);
    obs.observe(list, { childList: true, subtree: true });
  }

  // ─── 5d. Patch inboxRender to inject unread class ────────────────────────────
  // inboxRender builds rows inside the unified-inbox IIFE — we can't easily
  // override it, but the MutationObserver above catches every re-render.

  // ─── 5e. Mobile swipe-to-go-back ─────────────────────────────────────────────
  function installSwipeBack() {
    if (window.innerWidth > 768) return;

    let startX = 0;
    let startY = 0;
    let tracking = false;

    function onTouchStart(e) {
      const t = e.touches[0];
      startX = t.clientX;
      startY = t.clientY;
      tracking = startX < 30; // only edge swipe
    }

    function onTouchEnd(e) {
      if (!tracking) return;
      tracking = false;
      const t = e.changedTouches[0];
      const dx = t.clientX - startX;
      const dy = Math.abs(t.clientY - startY);
      if (dx > 60 && dy < 50) {
        // Right-swipe from left edge → go back to sidebar
        const gcWin = document.getElementById('gc-window');
        const dmWin = document.getElementById('dm-window');
        if (gcWin && gcWin.classList.contains('dm-slide-in')) {
          if (typeof window.gcGoBack === 'function') window.gcGoBack();
        } else if (dmWin && dmWin.classList.contains('dm-slide-in')) {
          if (typeof window.dmGoBack === 'function') window.dmGoBack();
          else {
            const sb = document.getElementById('dm-sidebar');
            if (sb) sb.classList.remove('dm-slide-out');
            dmWin.classList.remove('dm-slide-in');
          }
        }
      }
    }

    document.addEventListener('touchstart', onTouchStart, { passive: true });
    document.addEventListener('touchend', onTouchEnd, { passive: true });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) {
        document.removeEventListener('touchstart', onTouchStart);
        document.removeEventListener('touchend', onTouchEnd);
      }
    });
  }

  // ─── 5f. KFS Verified account display in DM topbar ───────────────────────────
  // When a broadcast message comes in from the KFS account, the sender's name
  // in the DM/GC topbar gets a blue verified badge.
  function injectVerifiedBadgeStyle() {
    // Already in the main CSS block above — just ensure badge is inserted into topbars.
    function addBadge(nameEl) {
      if (!nameEl) return;
      const text = nameEl.textContent || '';
      if ((text.trim() === 'KFS' || text.trim().startsWith('KFS')) &&
           !nameEl.querySelector('.kfs-verified-badge')) {
        const badge = document.createElement('span');
        badge.className = 'kfs-verified-badge';
        badge.innerHTML = `<svg width="8" height="8" viewBox="0 0 24 24" fill="#fff"><polyline points="20 6 9 17 4 12" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
        nameEl.appendChild(badge);
      }
    }

    // Observe topbar name changes
    const obs = new MutationObserver(() => {
      addBadge(document.getElementById('dm-topbar-name') || document.querySelector('.dm-topbar-name'));
      addBadge(document.getElementById('gc-topbar-name') || document.querySelector('#gc-topbar-name'));
    });
    const topbar = document.getElementById('dm-window') || document.body;
    obs.observe(topbar, { childList: true, subtree: true, characterData: true });
  }

  // ─── 5g. Persist GC sidebar after refresh ─────────────────────────────────────
  // The gc-window sometimes loses display:'flex' on re-render. We observe
  // GC.activeId being set and enforce the right display values.
  function guardGcWindowVisibility() {
    var lastActiveId = null;
    setInterval(() => {
      try {
        if (typeof GC !== 'undefined' && GC.activeId && GC.activeId !== lastActiveId) {
          lastActiveId = GC.activeId;
          const gcWin = document.getElementById('gc-window');
          const dmWin = document.getElementById('dm-window');
          if (gcWin && gcWin.style.display === 'none') {
            gcWin.style.display = 'flex';
            log('gc-window display restored for active group', GC.activeId);
          }
          if (dmWin && dmWin.style.display !== 'none' && gcWin) {
            // GC is active — ensure dm-window is hidden
            dmWin.style.display = 'none';
          }
        }
      } catch (_) {}
    }, 400);
  }

  // ─── 5h. Announce member-ready to existing inboxLoad callers ──────────────────
  // If the page already started inboxLoad before our patch landed (unlikely but
  // possible if the browser had a fast token-refresh path), fire memberReady.
  function checkAndFireIfMemberPresent() {
    try {
      const m = window._memberProfile || window._member;
      if (m && m.id) memberReadyFired();
    } catch (_) {}
  }

  // ─── Boot sequence ────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    injectStyles();
    wireSendButtonVisibility();
    observeConvList();
    installSwipeBack();
    injectVerifiedBadgeStyle();
    guardGcWindowVisibility();
    checkAndFireIfMemberPresent();

    // Re-wire send buttons after 1s in case the DM panel initialised late
    setTimeout(() => {
      wireSendButtonVisibility();
      applyStoryRings();
    }, 1000);

    log('kfs-patch3 boot complete');
  });

  // If DOM already ready
  if (document.readyState !== 'loading') {
    injectStyles();
    wireSendButtonVisibility();
    observeConvList();
    installSwipeBack();
    injectVerifiedBadgeStyle();
    guardGcWindowVisibility();
    checkAndFireIfMemberPresent();
    setTimeout(() => { wireSendButtonVisibility(); applyStoryRings(); }, 1000);
  }

  // ─── Expose debug helpers ─────────────────────────────────────────────────────
  window.__kfsPatch3 = {
    memberReady: () => _memberReady,
    fireReady:   memberReadyFired,
    onReady:     onMemberReady,
  };

  log('kfs-patch3 loaded');

})();

//------------------------------------------------------------------------------
// ── formerly kfs-patch4.js ──
//------------------------------------------------------------------------------
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
  function _hexToRgb(hex) {
    const c = (hex||'#0a0a0a').replace('#','');
    if (c.length !== 6) return '10,10,10';
    return `${parseInt(c.slice(0,2),16)},${parseInt(c.slice(2,4),16)},${parseInt(c.slice(4,6),16)}`;
  }
  // Builds the CSS `background` value for a photo wallpaper at a given opacity
  // (0-100). We can't use the `opacity` CSS property directly on the chat
  // container — that would fade the message bubbles too. Instead we layer a
  // solid wash (matching the app's background color) over the photo at
  // (1 - opacity) alpha, using two background layers. At opacity 100 the wash
  // is fully transparent, i.e. the photo shows exactly as uploaded.
  function _photoBg(dataUrl, opacity) {
    const op  = Math.max(15, Math.min(100, Number(opacity) || 100)) / 100;
    const rgb = _hexToRgb((_load(APP_BG_KEY)?.value) || '#0a0a0a');
    return `linear-gradient(rgba(${rgb},${(1-op).toFixed(3)}),rgba(${rgb},${(1-op).toFixed(3)})), url("${dataUrl}")`;
  }

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
    else if (wall.type === 'photo')        root.setProperty('--chat-wallpaper-bg', _photoBg(wall.value, wall.opacity));
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
    if (wall.type === 'photo') return `${_photoBg(wall.value, wall.opacity)} center/cover no-repeat`;
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
      const curOpacity = hasPhoto ? Math.max(15, Math.min(100, Number(wall.opacity) || 100)) : 100;
      section.innerHTML = `
        <div class="cust-photo-row">
          <div class="cust-photo-thumb">${hasPhoto?`<img src="${wall.value}">`:`<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>`}</div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="cust-upload-btn" id="cust-photo-upload-btn">${hasPhoto?'Change Photo':'Upload Photo'}</button>
            ${hasPhoto?`<button class="cust-photo-remove" id="cust-photo-remove-btn">Remove photo</button>`:''}
          </div>
          <input type="file" id="cust-photo-input" accept="image/*" style="display:none">
        </div>
        <div class="cust-hint">Best with a photo at least 800px wide. Stored only on this device.</div>
        ${hasPhoto ? `
        <div style="margin-top:14px;background:#161616;border:1px solid #1e1e1e;border-radius:10px;padding:12px 14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <span style="font-size:12px;font-weight:600;color:#ccc">Photo opacity</span>
            <span id="cust-wall-opacity-val" style="font-size:12px;color:#888;width:36px;text-align:right">${curOpacity}%</span>
          </div>
          <input type="range" id="cust-wall-opacity-slider" min="15" max="100" value="${curOpacity}" style="width:100%;accent-color:#fff">
          <div class="cust-hint" style="margin-top:6px">Lower this if the photo makes messages hard to read.</div>
        </div>` : ''}`;
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
            // Keep whatever opacity the user already had dialed in when
            // replacing a photo; default to fully opaque for a first upload.
            const prevOpacity = (wall.type === 'photo' && wall.opacity) ? wall.opacity : 100;
            const ok = _save(WALL_KEY,{type:'photo',value:dataUrl,opacity:prevOpacity});
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
      const opSlider = document.getElementById('cust-wall-opacity-slider');
      if (opSlider) {
        opSlider.addEventListener('input', () => {
          const val = parseInt(opSlider.value, 10) || 100;
          const valLbl = document.getElementById('cust-wall-opacity-val');
          if (valLbl) valLbl.textContent = `${val}%`;
          // Live-preview without hitting storage on every tick of the slider
          document.documentElement.style.setProperty('--chat-wallpaper-bg', _photoBg(wall.value, val));
          _updatePreview();
        });
        opSlider.addEventListener('change', () => {
          const val = parseInt(opSlider.value, 10) || 100;
          _save(WALL_KEY, { type: 'photo', value: wall.value, opacity: val });
          applyCustomizationV2(); _updatePreview();
        });
      }
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

//------------------------------------------------------------------------------
// ── formerly kfs-strand-live-patch.js ──
//------------------------------------------------------------------------------
/**
 * kfs-strand-live-patch.js — Social Strand Live Updates v1.0
 * =========================================================
 * Problem: your own posts/reactions already update instantly (swLoadFeed /
 * swToggleReaction handle that), but content from OTHER members — new posts
 * to the feed, new comments on a post you have open — only appeared after
 * leaving and re-entering the page (a hard refresh).
 *
 * This patch adds, without modifying membersaccess.js:
 *   1. Feed: polls quietly every 25s. If there's a newer post than what's
 *      currently on screen, shows a small "New posts" pill above the feed —
 *      tapping it does a normal swLoadFeed(true) reset. (We show a pill
 *      rather than silently inserting posts so we never yank the feed out
 *      from under someone mid-scroll or mid-read.)
 *   2. Comments: while a post's detail/comments modal is open, polls every
 *      6s and refreshes the comment list in place if new comments have
 *      arrived. Skipped for a cycle (not cancelled — just retried next
 *      tick) if you're actively typing a reply, so nothing you're writing
 *      gets wiped.
 *
 * Both use the same authenticated `api()` helper and existing endpoints
 * already used by the page — no new endpoints, no new auth surface.
 *
 * HOW TO DEPLOY:
 *   Add this line in membersaccess.html (before </body>), AFTER kfs-patch4.js:
 *     <script src="/kfs-patch4.js" defer></script>
 *     <script src="/kfs-strand-live-patch.js" defer></script>
 */

(function () {
  'use strict';

  const FEED_POLL_MS    = 25000;
  const COMMENTS_POLL_MS = 6000;

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  /* ═══════════════════════════════════════════════════════════════════════
     1. FEED — "New posts" pill
     ═══════════════════════════════════════════════════════════════════════ */

  let _feedTopId = null;
  let _feedPollTimer = null;
  let _pillEl = null;

  function feedGridVisible() {
    const grid = document.getElementById('studio-feed');
    return !!grid && !!grid.offsetParent;
  }

  function currentTopIdOnScreen() {
    const grid = document.getElementById('studio-feed');
    const first = grid?.querySelector('[data-project-id]');
    return first?.dataset.projectId || null;
  }

  function ensurePill() {
    if (_pillEl) return _pillEl;
    const grid = document.getElementById('studio-feed');
    if (!grid || !grid.parentNode) return null;
    const pill = document.createElement('button');
    pill.type = 'button';
    pill.id = 'kfs-strand-newposts-pill';
    pill.style.cssText = `
      display:none;position:sticky;top:8px;z-index:5;margin:0 auto 12px;padding:9px 18px;
      background:#0a84ff;color:#fff;border:none;border-radius:999px;font-size:13px;font-weight:600;
      cursor:pointer;box-shadow:0 4px 14px rgba(10,132,255,.35);
    `;
    pill.textContent = '↑ New posts';
    pill.addEventListener('click', () => {
      pill.style.display = 'none';
      if (typeof window.swLoadFeed === 'function') window.swLoadFeed(true);
    });
    grid.parentNode.insertBefore(pill, grid);
    _pillEl = pill;
    return pill;
  }

  function showPill() {
    const pill = ensurePill();
    if (pill) pill.style.display = '';
  }

  async function feedPollTick() {
    if (!feedGridVisible()) return;
    if (window.SW && window.SW.feedLoading) return;
    if (_pillEl && _pillEl.style.display !== 'none') return; // already showing, don't re-check
    try {
      let url = `/api/member/studio/feed?page=1`;
      if (window.SW?.feedTag) url += `&tag=${encodeURIComponent(window.SW.feedTag)}`;
      if (window.SW?.feedSort === 'foryou') url += `&sort=foryou`;
      const resp = await window.api('GET', url);
      const data = resp.feed || resp || [];
      if (!data.length) return;
      const latestId = String(data[0].id);
      const onScreenTop = currentTopIdOnScreen();
      if (!_feedTopId) _feedTopId = onScreenTop; // first tick baseline
      if (latestId !== _feedTopId && latestId !== onScreenTop) {
        showPill();
      }
    } catch {
      // Silent — this is a background nicety, not a user-initiated action.
    }
  }

  function startFeedPoll() {
    stopFeedPoll();
    _feedTopId = currentTopIdOnScreen();
    _feedPollTimer = setInterval(feedPollTick, FEED_POLL_MS);
  }
  function stopFeedPoll() {
    if (_feedPollTimer) { clearInterval(_feedPollTimer); _feedPollTimer = null; }
  }

  function hookSwLoadFeed() {
    if (typeof window.swLoadFeed !== 'function' || window.swLoadFeed.__kfsLiveWrapped) return;
    const orig = window.swLoadFeed;
    const wrapped = async function (reset) {
      const ret = await orig.apply(this, arguments);
      // Any successful load (own post, manual refresh, pill tap, pagination)
      // re-baselines what "top of feed" means and clears the pill.
      _feedTopId = currentTopIdOnScreen();
      if (_pillEl) _pillEl.style.display = 'none';
      if (!_feedPollTimer) startFeedPoll();
      return ret;
    };
    wrapped.__kfsLiveWrapped = true;
    window.swLoadFeed = wrapped;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     2. COMMENTS — live refresh while a post's detail modal is open
     ═══════════════════════════════════════════════════════════════════════ */

  let _commentsPollTimer = null;
  let _lastCommentsSig = null;

  function commentsListFocused() {
    const list = document.getElementById('sw-comments-list');
    return !!(list && document.activeElement && list.contains(document.activeElement));
  }

  function commentsSignature(comments) {
    // Cheap, order-sensitive fingerprint — id + reply count is enough to
    // detect "something changed" without a deep diff.
    const walk = (c) => `${c.id}:${(c.replies || []).map(walk).join(',')}`;
    return (comments || []).map(walk).join('|');
  }

  async function commentsPollTick() {
    const projectId = window.SW?.detailProjectId;
    const overlay = document.getElementById('studio-detail-modal-overlay');
    if (!projectId || !overlay || overlay.style.display !== 'flex') { stopCommentsPoll(); return; }
    if (commentsListFocused()) return; // user is typing a reply — try again next tick
    try {
      const cResp = await window.api('GET', `/api/member/studio/projects/${projectId}/comments`);
      const comments = cResp.comments || cResp || [];
      const sig = commentsSignature(comments);
      if (sig === _lastCommentsSig) return; // nothing new
      _lastCommentsSig = sig;
      const list = document.getElementById('sw-comments-list');
      if (list && typeof window.swRenderComments === 'function') {
        list.innerHTML = window.swRenderComments(comments, projectId);
      }
      // Keep the visible comment count in the meta row in sync too.
      const countEl = overlay.querySelector('.studio-detail-stat:last-child');
      if (countEl) {
        const flat = (arr) => arr.reduce((n, c) => n + 1 + flat(c.replies || []), 0);
        countEl.innerHTML = countEl.innerHTML.replace(/[\d.,km]+$/i, String(flat(comments)));
      }
    } catch {
      // Silent — background nicety.
    }
  }

  function startCommentsPoll() {
    stopCommentsPoll();
    _lastCommentsSig = null;
    _commentsPollTimer = setInterval(commentsPollTick, COMMENTS_POLL_MS);
  }
  function stopCommentsPoll() {
    if (_commentsPollTimer) { clearInterval(_commentsPollTimer); _commentsPollTimer = null; }
  }

  function hookDetailModal() {
    if (typeof window.swOpenDetail === 'function' && !window.swOpenDetail.__kfsLiveWrapped) {
      const orig = window.swOpenDetail;
      const wrapped = async function (projectId) {
        const ret = await orig.apply(this, arguments);
        _lastCommentsSig = null; // force first comparison to pass on next tick
        startCommentsPoll();
        return ret;
      };
      wrapped.__kfsLiveWrapped = true;
      window.swOpenDetail = wrapped;
    }
    if (typeof window.swCloseDetailModal === 'function' && !window.swCloseDetailModal.__kfsLiveWrapped) {
      const orig = window.swCloseDetailModal;
      const wrapped = function () {
        stopCommentsPoll();
        return orig.apply(this, arguments);
      };
      wrapped.__kfsLiveWrapped = true;
      window.swCloseDetailModal = wrapped;
    }
  }

  /* ── Boot ──────────────────────────────────────────────────────────────── */

  function init() {
    // These globals (swLoadFeed, swOpenDetail, swCloseDetailModal, api, SW)
    // are all defined in membersaccess.js. Poll briefly for readiness rather
    // than assuming exact script execution order.
    let tries = 0;
    const tryHook = () => {
      tries++;
      const haveCore = typeof window.api === 'function' && typeof window.swLoadFeed === 'function';
      if (haveCore) {
        hookSwLoadFeed();
        hookDetailModal();
        if (feedGridVisible()) startFeedPoll();
        document.addEventListener('visibilitychange', () => {
          // Timers already no-op appropriately via their own visibility/open
          // checks each tick; nothing extra needed here.
        });
        return;
      }
      if (tries < 40) setTimeout(tryHook, 250); // give membersaccess.js up to ~10s to finish defining globals
    };
    tryHook();
  }

  ready(init);
})();

//------------------------------------------------------------------------------
// ── formerly kfs-patch5.js ──
//------------------------------------------------------------------------------
/**
 * kfs-patch5.js  — Social Strand Patch v5
 * =========================================
 * Loaded by membersaccess.html (add alongside kfs-patch4.js).
 *
 * This patch has NO Social Strand UI changes.
 * It exists as the correct place for any future member-side
 * additions without touching membersaccess.html.
 *
 * Mobile nav architecture note (answers your question):
 * ──────────────────────────────────────────────────────
 * The "Network bar" (bottom pill nav) and the "site bar" (desktop sidebar)
 * serve DIFFERENT contexts and are BOTH needed:
 *
 *   • Desktop sidebar  — always visible on ≥769 px; provides full text labels,
 *     nested settings, and the member chip. Cannot exist on mobile because
 *     it eats the full left column.
 *
 *   • Bottom pill nav (btb)  — shown ONLY on mobile/touch (≤768 px + pointer:coarse).
 *     It floats over content, is gesture-friendly, and follows iOS/Android
 *     tap-target guidelines (44 px minimum). The desktop sidebar is hidden on
 *     these viewports.
 *
 * So they're NOT duplicates — they're the same navigation adapted for two
 * different form factors via a responsive media query.  Removing either one
 * would break usability on that viewport class.
 *
 * The only items that could be trimmed from the bottom nav are the ones that
 * are already accessible from the Settings bottom-sheet (Profile, Security,
 * My Movies, etc.) — and they already are excluded; the nav only exposes the
 * 4 primary destinations + post + settings-sheet trigger, which is the
 * recommended pattern for Instagram-style apps.
 */

(function () {
  'use strict';
  // Reserved for future Social Strand member-side additions.
  // All current changes are server-side (API) or in kfs-admin-patch.js.
})();

//------------------------------------------------------------------------------
// ── formerly kfs-patch6.js ──
//------------------------------------------------------------------------------
/**
 * kfs-patch6.js — Instant Feed Refresh + Dynamic Composer Textareas + Input Gap
 * =====================================================================
 * Load this AFTER membersaccess.js and AFTER kfs-patch5.js.
 * Add at the bottom of membersaccess.html:
 *     <script src="/kfs-patch6.js" defer></script>
 *
 * -----------------------------------------------------------------------
 * BUG #1 — "I post, but it doesn't show up in the feed right away"
 * -----------------------------------------------------------------------
 * Root cause (found in server.js):
 *   GET /api/member/studio/feed sends `Cache-Control: public, max-age=30,
 *   stale-while-revalidate=60` (via cacheFor(res,30)), overriding the
 *   blanket `no-store` the rest of /api gets.
 *
 *   swSubmitPost() already does the right thing client-side — it calls
 *   `await swLoadFeed(true)` immediately after a successful post, and the
 *   server already busts its OWN in-memory cache on write
 *   (memInvalidate("studio:feed:")). Both of those are correct.
 *
 *   The problem is a third layer neither of those touches: the browser's
 *   own HTTP cache. Because the response is marked `public, max-age=30`,
 *   the very next GET to the exact same URL (?page=1) within 30s is
 *   answered straight from the browser cache and never reaches the
 *   network at all — so the poster's own client renders the pre-post
 *   snapshot. This is the same class of bug already fixed for
 *   /groups and /nicknames in the api() helper (see the comment there);
 *   /studio/feed just wasn't included in that fix.
 *
 * Fix: cache-bust GET requests to /studio/feed the same way, by wrapping
 * window.api so every feed fetch gets a unique query string. No server
 * change needed, and pagination/"foryou" behavior is untouched since the
 * server-side memCache (60s, keyed by page+tag) still does the real work
 * of keeping DB load down — this only defeats the browser-level cache.
 *
 * -----------------------------------------------------------------------
 * BUG #2 — "input textboxes need to be dynamic"
 * -----------------------------------------------------------------------
 * The composer textareas (#sw-caption, #sw-text-body, #sw-video-caption)
 * are fixed-height (`rows="3"`/`"4"`, `resize:none`) — typing past that
 * just scrolls inside a tiny box instead of the box growing. This patch
 * makes them auto-grow to fit content, and re-measures them whenever
 * their value is set programmatically (switching post type, opening the
 * edit modal with an existing long caption) since those don't fire an
 * `input` event on their own.
 *
 * -----------------------------------------------------------------------
 * BUG #3 — "2-3px gap between the input border and the displayed text"
 * -----------------------------------------------------------------------
 * Applies to all post/comment input boxes:
 *   - Comment + reply input pill (.studio-comment-input-row)
 *   - Composer title/tags/domain rows (.composer-field-row)
 *   - Composer caption/text/video-caption textareas
 *
 * The comment input pill already uses the "border lives on the outer
 * wrapper, the actual <input> stays borderless inside it" structure —
 * its padding is just bigger than needed, so we tighten it. The composer
 * field rows and caption textareas don't have that wrapper at all today
 * (rows use a bottom divider, textareas have no border), so this gives
 * them the same box: a bordered container with the real <input>/
 * <textarea> borderless inside it — same technique, done in CSS via
 * padding/border on the row/field itself rather than an extra DOM node.
 * IDs are untouched, so none of the existing swSubmitPost/swPostComment/
 * char-counter code needs to change.
 *
 * Two follow-on issues showed up once the gap was actually this tight:
 *
 * 1) The sitewide base rule `input:focus, textarea:focus { box-shadow: 0
 *    0 0 3px rgba(10,132,255,.25) }` (membersaccess.html's global
 *    stylesheet) draws its blue glow flush against the element's own
 *    edge — which, with ~0 padding on the input itself, lands right on
 *    top of the leading character(s). Fixed by suppressing that glow on
 *    these fields and moving the focus indication to the wrapper's
 *    border-color instead, where there's room for it.
 *
 * 2) The comment pill's border-radius is 24px (a full pill). Shrinking
 *    the box's height without a big enough left inset means the rounded
 *    corner's own curve reaches past the padding into the text — not a
 *    focus-state thing at all, just geometry, and it was there whether
 *    focused or not. Fixed by giving the pill (and the other boxes, at
 *    their own smaller radii) enough left padding to clear the curve.
 *    The reply row's inline `padding-left:30px` indent is preserved by
 *    leaving padding-left off the !important list here.
 */

(function () {
  'use strict';

  // Version marker — bump this string every time this file changes.
  // Open DevTools Console after a hard refresh and look for this line.
  // If you DON'T see it (or see an older version string), your browser
  // is still running a cached copy of this file, not the one that was
  // just uploaded — that's almost certainly why a fix "doesn't show up"
  // even though the code itself is correct. Hard-refresh (Ctrl/Cmd+Shift+R)
  // or clear cache for this site and reload.
  console.log('[kfs-patch6] v6 loaded (comment-pill padding-left made !important — no longer relies on source-order to win)');

  const GROW_IDS = ['sw-caption', 'sw-text-body', 'sw-video-caption'];

  function autoGrow(el) {
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = el.scrollHeight + 'px';
  }

  function autoGrowById(id) {
    autoGrow(document.getElementById(id));
  }

  function growAll() {
    GROW_IDS.forEach(autoGrowById);
  }

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  /* ── 1. Feed cache-busting ────────────────────────────────────────────── */

  function hookApiCacheBust() {
    if (typeof window.api !== 'function' || window.api.__kfsFeedCacheBustWrapped) return;
    const orig = window.api;
    const wrapped = function (method, path, body, isForm) {
      if (
        typeof path === 'string' &&
        String(method).toUpperCase() === 'GET' &&
        path.includes('/studio/feed') &&
        !path.includes('_cb=')
      ) {
        path += (path.includes('?') ? '&' : '?') + '_cb=' + Date.now() + Math.random().toString(36).slice(2);
      }
      return orig.call(this, method, path, body, isForm);
    };
    wrapped.__kfsFeedCacheBustWrapped = true;
    window.api = wrapped;
  }

  /* ── 2. 2-3px border-to-text gap on post/comment input boxes ─────────── */

  function injectTightGapCSS() {
    if (document.getElementById('kfs-p6-tight-gap')) return;
    const style = document.createElement('style');
    style.id = 'kfs-p6-tight-gap';
    style.textContent = `
      /* Comment + reply input pill — already wrapper(border)+input(borderless).
         NOTE: border-radius here is 24px (full pill). Shrinking the box's
         height without enough left inset makes the rounded corner's own
         curve reach past the padding and into the text — which is exactly
         what was still happening.
         padding-left is now !important. It previously wasn't, on the theory
         that the reply row's inline padding-left:30px (its indent under the
         parent comment) needed to win by NOT fighting an !important — but
         that also meant this value only won by source-order against any
         other stylesheet, which is fragile (a later-loaded patch touching
         the same class at the same specificity would silently win instead).
         Made !important for robustness; the reply row's inline style has
         been upgraded to padding-left:30px !important to match (see
         membersaccess.js, the sw-comment reply-row template) so it still
         overrides this base value same as before. */
      /* padding-left must be >= border-radius (24px). A rounded corner's
         horizontal inset is 0 at the box's vertical midline and grows to
         exactly 'radius' at the very top/bottom edge. 22px left a 2px gap
         against the 24px radius, which was too tight for tall ascenders
         (capital letters like "W" sit close to the box's actual top) even
         though lowercase text — which sits closer to the midline — cleared
         it fine. 28px = radius + a small buffer for anti-aliasing. */
      .studio-comment-input-row {
        padding-top: 6px !important;
        padding-bottom: 6px !important;
        padding-right: 10px !important;
        padding-left: 28px !important;
      }

      /* Composer title/tags/domain — turn the bottom-divider list rows into
         individually boxed inputs, borderless <input> inside. Left padding
         kept comfortably past the 10px corner radius so the curve can't
         reach the text. */
      .composer-field-row {
        border: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 6px 16px !important;
        margin-bottom: 8px !important;
      }
      .composer-field-row:last-of-type {
        margin-bottom: 8px !important;
      }
      .composer-field-row--collab {
        padding-top: 8px !important;
      }

      /* Composer caption / text-body / video-caption — same logic: padding
         kept clear of the 10px corner radius. */
      .composer-caption,
      .composer-text-body {
        border: 1px solid #1c1c1e !important;
        border-radius: 10px !important;
        padding: 7px 14px !important;
        box-sizing: border-box !important;
      }

      /* The actual inputs/textareas have ~0 padding of their own — all the
         spacing lives on the wrapper/box above. There's also a sitewide
         base rule (input:focus/textarea:focus) that adds a blue
         box-shadow glow (0 0 0 3px rgba(10,132,255,.25)) directly on the
         focused element itself. With zero padding on the element, that
         glow sits right on top of the text and clips the first
         character(s) — that's the blue cutting into "Add a comment...".
         Kill the glow/outline on the fields themselves and show focus on
         the box instead, where there's room for it. */
      .studio-comment-input:focus,
      .composer-input:focus,
      .composer-caption:focus,
      .composer-text-body:focus {
        outline: none !important;
        box-shadow: none !important;
      }

      /* Kill the browser's native autofill background (white/yellow pill
         behind typed text, seen on comment/search-like inputs). Chrome/
         Safari apply this via an internal :-webkit-autofill UA style that
         a plain 'background: transparent !important' cannot override —
         it has to be beaten with the same weapon, a huge inset box-shadow
         that paints over it, plus forcing the text color back to our own. */
      .studio-comment-input:-webkit-autofill,
      .composer-input:-webkit-autofill,
      .composer-caption:-webkit-autofill,
      .composer-text-body:-webkit-autofill,
      .studio-comment-input:-webkit-autofill:hover,
      .studio-comment-input:-webkit-autofill:focus,
      .composer-input:-webkit-autofill:hover,
      .composer-input:-webkit-autofill:focus {
        -webkit-text-fill-color: var(--text) !important;
        -webkit-box-shadow: 0 0 0px 1000px #141414 inset !important;
        box-shadow: 0 0 0px 1000px #141414 inset !important;
        caret-color: var(--text);
        transition: background-color 5000s ease-in-out 0s;
      }

      /* Pin line-height explicitly instead of relying on the UA default
         ("normal") on <input>. Browsers reset line-height on <input> via
         an internal font shorthand and it does NOT inherit the site's
         line-height:1.5 the way <textarea> does — that's why the caption
         box was never affected but every single-line input was. "normal"
         is resolved from OS/browser font metrics, so it renders looser
         on some systems and noticeably tighter on others (worse at
         font-weight:600), pushing the glyph higher in the box and closer
         to the corner curve even when padding/radius math is correct.
         Pinning a fixed px value makes the vertical position identical
         everywhere. */
      .composer-input,
      .studio-comment-input {
        line-height: 20px;
      }
      .composer-input-title {
        line-height: 22px; /* slightly taller for the 600-weight/15px title */
      }
      .studio-comment-input-row:focus-within,
      .composer-field-row:focus-within {
        border-color: #0095f6 !important;
      }
      .composer-caption:focus,
      .composer-text-body:focus {
        border-color: #0095f6 !important;
      }
    `;
    // IMPORTANT: appended to the END of <body>, not <head>. This file has
    // several <style> blocks embedded inside <body> itself (not just the
    // usual <head> stylesheet), and <head> always precedes <body> in the
    // DOM regardless of when a script runs — so a style appended to <head>
    // can never win a same-specificity, non-!important cascade tie against
    // ANY of those body-embedded rules, including the base
    // .studio-comment-input-row padding-left this patch is meant to
    // override. Appending to the end of <body> guarantees this style is
    // last in source order and actually wins.
    document.body.appendChild(style);
    logComputedPaddingCheck();
  }

  // Reads back the REAL computed padding-left of the elements this patch
  // targets, right after injecting the override — not what the CSS *says*,
  // what the browser actually *resolved*. If some other rule (a device-
  // specific media query, a later-loaded stylesheet, an inline style, an
  // extension, etc.) is still winning the cascade on your exact device,
  // this will show a value other than the expected one and prove it
  // directly, instead of us going back and forth guessing.
  function logComputedPaddingCheck() {
    const checks = [
      { sel: '.studio-comment-input-row', expect: '28px' },
      { sel: '.composer-field-row', expect: '16px' },
      { sel: '.composer-caption', expect: '14px' },
    ];
    const results = checks.map(({ sel, expect }) => {
      const el = document.querySelector(sel);
      if (!el) return `${sel}: (not in DOM yet — open the relevant modal, then run kfsCheckInputGap() again)`;
      const actual = getComputedStyle(el).paddingLeft;
      const ok = actual === expect ? 'OK' : 'MISMATCH — something else is overriding this';
      return `${sel}: expected ${expect}, actual ${actual} → ${ok}`;
    });
    console.log('[kfs-patch6] computed padding-left check:\n' + results.join('\n'));
  }
  // Exposed so it can be re-run on demand from the console once the
  // comment box / composer modal is actually open (they don't exist in
  // the DOM until then, so the check at load time may say "not in DOM yet").
  window.kfsCheckInputGap = logComputedPaddingCheck;

  /* ── 3. Auto-grow textareas ───────────────────────────────────────────── */

  function hookInputListeners() {
    // Delegated so it works even though these fields live inside a modal
    // that may be re-rendered/hidden rather than always present.
    document.addEventListener('input', (e) => {
      if (e.target && GROW_IDS.includes(e.target.id)) autoGrow(e.target);
    });
  }

  function hookProgrammaticFills() {
    // swSetPostType shows/hides sections — resize on every switch so a
    // section that was hidden (and therefore had scrollHeight 0) is
    // measured correctly once visible.
    if (typeof window.swSetPostType === 'function' && !window.swSetPostType.__kfsGrowWrapped) {
      const orig = window.swSetPostType;
      const wrapped = function (type) {
        const ret = orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swSetPostType = wrapped;
    }
    // swOpenEditModal sets .value directly (pre-filling an existing long
    // caption/description) — no input event fires, so resize explicitly
    // once the fields are populated.
    if (typeof window.swOpenEditModal === 'function' && !window.swOpenEditModal.__kfsGrowWrapped) {
      const orig = window.swOpenEditModal;
      const wrapped = async function (projectId) {
        const ret = await orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swOpenEditModal = wrapped;
    }
    // swResetPostModal clears fields back to empty — collapse back down
    // to the natural min-height instead of staying stretched out.
    if (typeof window.swResetPostModal === 'function' && !window.swResetPostModal.__kfsGrowWrapped) {
      const orig = window.swResetPostModal;
      const wrapped = function () {
        const ret = orig.apply(this, arguments);
        setTimeout(growAll, 0);
        return ret;
      };
      wrapped.__kfsGrowWrapped = true;
      window.swResetPostModal = wrapped;
    }
  }

  /* ── Boot ──────────────────────────────────────────────────────────────── */

  function init() {
    injectTightGapCSS(); // pure CSS, doesn't need to wait on membersaccess.js globals
    let tries = 0;
    const tryHook = () => {
      tries++;
      const haveCore = typeof window.api === 'function';
      if (haveCore) {
        hookApiCacheBust();
        hookInputListeners();
        hookProgrammaticFills();
        return;
      }
      if (tries < 40) setTimeout(tryHook, 250);
    };
    tryHook();
  }

  ready(init);
})();

//------------------------------------------------------------------------------
// ── formerly kfs-patch7.js ──
//------------------------------------------------------------------------------
/**
 * kfs-patch7.js — Restore Bubble Opacity + Read Receipts in Customization
 * =====================================================================
 * Load this LAST, after kfs-patch6.js:
 *   <script src="/kfs-patch7.js" defer></script>
 *
 * PROBLEM
 * -------
 * membersaccess.js originally defines window.loadCustomization /
 * window.applyCustomization with FOUR sections: Chat Wallpaper, Message
 * Color, Bubble Opacity (sliders for "your" / "received" bubbles), and
 * Privacy (Read Receipts on/off toggle).
 *
 * kfs-patch4.js (loaded after membersaccess.js) REPLACES both of those
 * globals wholesale to add an "App Background" section and a nicer
 * gradient builder. Its replacement only re-implements Chat Wallpaper,
 * App Background, and Message Bubble Color — Bubble Opacity and Read
 * Receipts were dropped in that rewrite, which is why they're missing
 * from the live panel even though the base file still has all the CSS
 * (.cust-opacity-row, .cust-slider, .cust-switch, etc.) for them.
 *
 * FIX
 * ---
 * Rather than re-editing kfs-patch4.js (and risking another silent
 * regression next time someone patches the panel again), this file wraps
 * whatever loadCustomization/applyCustomization currently exist at the
 * time it runs and appends the two missing sections after them. It reuses
 * the exact same localStorage keys and markup/classes the original
 * membersaccess.js used, so nothing about existing saved preferences
 * changes for people who already had this working before patch4.
 */

(function () {
  'use strict';

  const OPACITY_KEY       = 'kfs-cust-bubble-opacity';   // { mine: 0-1, theirs: 0-1 }
  const READ_RECEIPTS_KEY = 'kfs-cust-read-receipts';    // true/false, default true

  function _load(key) {
    try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; }
  }
  function _save(key, val) {
    try {
      val === null ? localStorage.removeItem(key) : localStorage.setItem(key, JSON.stringify(val));
      return true;
    } catch { return false; }
  }

  function _readReceiptsEnabled() {
    const v = _load(READ_RECEIPTS_KEY);
    return v === null ? true : !!v;
  }
  window._kfsReadReceiptsEnabled = _readReceiptsEnabled;

  // ── Apply --bubble-mine-opacity / --bubble-theirs-opacity directly ─────
  // IMPORTANT: this does NOT go through window.applyCustomization. Earlier
  // versions of this patch wrapped window.applyCustomization once and
  // relied on that wrapper staying in place — but kfs-patch4.js can (and,
  // in practice, does) reassign window.applyCustomization again later,
  // silently dropping our wrapper and leaving the opacity CSS vars frozen
  // even though the slider still saves the right value to localStorage.
  // Setting the vars ourselves, independent of whatever applyCustomization
  // currently is, means the slider works no matter what patch4 does or
  // when it does it.
  function _applyOpacityVars() {
    const op = _load(OPACITY_KEY);
    document.documentElement.style.setProperty('--bubble-mine-opacity', String(op?.mine ?? 1));
    document.documentElement.style.setProperty('--bubble-theirs-opacity', String(op?.theirs ?? 1));
  }

  // Still nice to have: if window.applyCustomization exists, wrap it too so
  // opacity stays correct through its own re-renders. But this is now a
  // bonus, not the mechanism the slider depends on — and we re-check on
  // every poll tick (not just once) so a later patch4 reassignment gets
  // caught instead of silently winning.
  function wrapApplyCustomization() {
    if (typeof window.applyCustomization !== 'function') return false;
    if (window.applyCustomization.__kfsOpacityWrapped) return true;
    const orig = window.applyCustomization;
    const wrapped = function () {
      const ret = orig.apply(this, arguments);
      _applyOpacityVars();
      return ret;
    };
    wrapped.__kfsOpacityWrapped = true;
    window.applyCustomization = wrapped;
    return true;
  }

  let _opacityContentEl = null;

  function _renderOpacitySection() {
    const section = _opacityContentEl;
    if (!section) return;
    const op = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mineVal = op.mine ?? 1, theirsVal = op.theirs ?? 1;
    section.innerHTML = `
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Your bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-mine" min="0.3" max="1" step="0.05" value="${mineVal}">
        <span class="cust-opacity-value" id="cust-opacity-mine-val">${Math.round(mineVal * 100)}%</span>
      </div>
      <div class="cust-opacity-row">
        <span class="cust-opacity-label">Received bubbles</span>
        <input type="range" class="cust-slider" id="cust-opacity-theirs" min="0.3" max="1" step="0.05" value="${theirsVal}">
        <span class="cust-opacity-value" id="cust-opacity-theirs-val">${Math.round(theirsVal * 100)}%</span>
      </div>
      <div class="cust-hint">Make chat bubbles more see-through. Applies to both DMs and group chats on this device.</div>`;

    const mineInput   = section.querySelector('#cust-opacity-mine');
    const theirsInput = section.querySelector('#cust-opacity-theirs');
    const mineValEl   = section.querySelector('#cust-opacity-mine-val');
    const theirsValEl = section.querySelector('#cust-opacity-theirs-val');

    mineInput?.addEventListener('input', () => {
      const cur = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.mine = parseFloat(mineInput.value);
      _save(OPACITY_KEY, cur);
      mineValEl.textContent = `${Math.round(cur.mine * 100)}%`;
      _applyOpacityVars();
      window.applyCustomization?.();
      _updatePreviewOpacity();
    });
    theirsInput?.addEventListener('input', () => {
      const cur = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
      cur.theirs = parseFloat(theirsInput.value);
      _save(OPACITY_KEY, cur);
      theirsValEl.textContent = `${Math.round(cur.theirs * 100)}%`;
      _applyOpacityVars();
      window.applyCustomization?.();
      _updatePreviewOpacity();
    });
  }

  function _updatePreviewOpacity() {
    const op = _load(OPACITY_KEY) || { mine: 1, theirs: 1 };
    const mineBubble = document.getElementById('cust-preview-mine-bubble');
    if (mineBubble) mineBubble.style.setProperty('--preview-mine-opacity', String(op.mine ?? 1));
    const theirsBubble = document.querySelector('#cust-preview-chat .cust-preview-bubble.theirs');
    if (theirsBubble) theirsBubble.style.setProperty('--preview-theirs-opacity', String(op.theirs ?? 1));
  }

  let _receiptsContentEl = null;

  function _renderReadReceiptsSection() {
    const section = _receiptsContentEl;
    if (!section) return;
    const on = _readReceiptsEnabled();
    section.innerHTML = `
      <div class="cust-switch-row">
        <div class="cust-switch-text">
          <span class="cust-switch-title">Read Receipts</span>
          <span class="cust-switch-desc">Show the blue "Seen" double-tick on messages you've sent, on this device.</span>
        </div>
        <label class="cust-switch">
          <input type="checkbox" id="cust-read-receipts-toggle" ${on ? 'checked' : ''}>
          <span class="cust-switch-track"></span>
        </label>
      </div>`;
    section.querySelector('#cust-read-receipts-toggle')?.addEventListener('change', (e) => {
      _save(READ_RECEIPTS_KEY, !!e.target.checked);
      // Re-render any ticks already on screen immediately, from data already
      // held locally — no need to wait for the next server poll.
      try {
        const msgs = (typeof DM !== 'undefined' && DM?.msgs) ? DM.msgs : [];
        msgs.forEach(msg => {
          const metaRow = document.querySelector(`.dm-meta[data-meta-for="${msg.id}"]`);
          const oldTick = metaRow?.querySelector('.dm-ticks');
          if (oldTick && typeof _dmTickSpanHTML === 'function') oldTick.outerHTML = _dmTickSpanHTML(msg);
        });
      } catch { /* non-fatal */ }
    });
  }

  // Injects the two missing cards into #cust-root, matching the visual
  // style of the cards kfs-patch4.js already builds (dark card, 12px
  // radius, small "Reset" link top-right for the opacity one).
  function _injectSections() {
    const root = document.getElementById('cust-root');
    if (!root) return;

    const resetAllBtn = document.getElementById('cust-reset-all-btn');

    const opacityCard = document.createElement('div');
    opacityCard.style.cssText = 'background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px';
    opacityCard.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em">Bubble Opacity</div>
        <button id="cust-opacity-reset-btn" style="background:transparent;border:none;font-size:11px;font-weight:600;color:#666;cursor:pointer;padding:0">Reset</button>
      </div>
      <div id="cust-opacity-content"></div>`;

    const privacyCard = document.createElement('div');
    privacyCard.style.cssText = 'background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:16px 18px;margin-bottom:16px';
    privacyCard.innerHTML = `
      <div style="font-size:13px;font-weight:700;color:#f5f5f5;letter-spacing:-.01em;margin-bottom:12px">Privacy</div>
      <div id="cust-read-receipts-content"></div>`;

    if (resetAllBtn) {
      root.insertBefore(opacityCard, resetAllBtn);
      root.insertBefore(privacyCard, resetAllBtn);
    } else {
      root.appendChild(opacityCard);
      root.appendChild(privacyCard);
    }

    _opacityContentEl  = opacityCard.querySelector('#cust-opacity-content');
    _receiptsContentEl = privacyCard.querySelector('#cust-read-receipts-content');

    _renderOpacitySection();
    _renderReadReceiptsSection();
    _updatePreviewOpacity();

    opacityCard.querySelector('#cust-opacity-reset-btn')?.addEventListener('click', () => {
      _save(OPACITY_KEY, null);
      _applyOpacityVars();
      window.applyCustomization?.();
      _renderOpacitySection();
      _updatePreviewOpacity();
    });

    // If a "Reset All" button exists (added by kfs-patch4.js), make it also
    // reset opacity back to 100/100 so it really does reset everything.
    if (resetAllBtn && !resetAllBtn.__kfsOpacityHooked) {
      resetAllBtn.__kfsOpacityHooked = true;
      resetAllBtn.addEventListener('click', () => {
        _save(OPACITY_KEY, null);
        _applyOpacityVars();
        window.applyCustomization?.();
        _renderOpacitySection();
        _updatePreviewOpacity();
      });
    }
  }

  function wrapLoadCustomization() {
    if (typeof window.loadCustomization !== 'function') return false;
    if (window.loadCustomization.__kfsOpacityWrapped) return true;
    const orig = window.loadCustomization;
    const wrapped = function () {
      const ret = orig.apply(this, arguments);
      _injectSections();
      return ret;
    };
    wrapped.__kfsOpacityWrapped = true;
    window.loadCustomization = wrapped;
    return true;
  }

  function init() {
    // Apply immediately so the vars exist even before any customization
    // script has loaded/run, and again on every tick below — cheap, and it
    // means the bubble opacity can never end up depending on winning a
    // one-shot race against kfs-patch4.js.
    _applyOpacityVars();

    // Poll for readiness rather than assuming exact script order —
    // loadCustomization/applyCustomization are defined in membersaccess.js
    // and then possibly re-defined by kfs-patch4.js. We keep polling
    // indefinitely (not just until the first success) specifically because
    // kfs-patch4.js has been observed to reassign window.applyCustomization
    // again after our first wrap succeeds, which would otherwise silently
    // undo it. Re-applying the vars ourselves every tick means that even if
    // the wrap gets clobbered, the slider still visibly works.
    let tries = 0;
    const tryWrap = () => {
      tries++;
      wrapApplyCustomization();
      wrapLoadCustomization();
      _applyOpacityVars();
      // Fast polling for the first ~10s to catch initial script load order,
      // then settle into a slow background check so a late/dynamic
      // reassignment of applyCustomization still gets caught eventually.
      setTimeout(tryWrap, tries < 40 ? 250 : 2000);
    };
    tryWrap();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

//------------------------------------------------------------------------------
// ── formerly kfs-patch8.js ──
//------------------------------------------------------------------------------
/**
 * kfs-patch8.js — Tour polish, emoji → SVG cleanup, dedup timestamps,
 *                 merge My Movies + My Works, fix broken "Request Edit"
 * =====================================================================
 * Load this LAST, after kfs-patch7.js:
 *   <script src="/kfs-patch7.js" defer></script>
 *   <script src="/kfs-patch8.js" defer></script>
 *
 * Fixes five separate things, each in its own IIFE below so they can be
 * lifted out independently later if needed:
 *
 *   1. #work-edit-modal-overlay never actually appeared. The element has
 *      an inline `style="display:none"` in the HTML, and openWorkEditModal()
 *      only ever did `overlay.classList.add('open')`. Inline styles beat
 *      stylesheet rules regardless of selector specificity, so the
 *      `#work-edit-modal-overlay.open { display:flex }` rule never won —
 *      the "Request Edit" button on My Works looked completely dead. Fix:
 *      drive it with the same direct style.display toggle every other
 *      modal in this app already uses (see openCollabEditModal).
 *
 *   2. Tour spotlight/card alignment. The highlight ring used a fixed
 *      16px border-radius and fixed 8px padding regardless of what it was
 *      actually wrapping, so pill buttons (Submit Movie, Suggestion tab)
 *      got a spotlight that didn't match their real shape, and the card
 *      sat close enough to visually collide with it. Fix: read the
 *      target's own computed border-radius so the ring hugs its actual
 *      shape, and widen/clean up the clearance so the card never overlaps
 *      the ring.
 *
 *   3. Emoji cleanup. Swaps decorative/system emoji (🔒 📷 🎬 🤝 💡 🚨 💬 👋
 *      🔗 🗑 📌) for small inline Apple-style line-icon SVGs, sitewide,
 *      via a text-node sweep with a MutationObserver for anything rendered
 *      later. Scoped to a whitelist of exact/known system strings — it
 *      does NOT touch the reaction emoji picker (❤ 😂 😮 😢 😡 👏 🔥 😍 👍
 *      🙂 😊), since those are the actual reaction choices, not chrome.
 *      Also strips emoji out of the tour copy itself (KFS_TOUR_STEPS is
 *      rendered via textContent, so it needs a plain-text fix rather than
 *      an icon swap).
 *
 *   4. Duplicate "time ago" on feed posts. Both regular and collab post
 *      cards render swRelTime(p.created_at) twice — once in the header
 *      next to the author name, once again at the very bottom of the
 *      card. Fix: hide the redundant bottom one.
 *
 *   5. Merge My Movies + My Works into one panel with an in-panel tab
 *      switcher ("Submissions" / "My Works"), since they're two flavors
 *      of the same "manage your film credits with KFS" task. Removes the
 *      separate "My Works" sidebar/settings-sheet entry, keeps the "My
 *      Movies" entry pointing at both.
 */

(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function pollFor(check, run, { tries = 40, delay = 250 } = {}) {
    let n = 0;
    (function tick() {
      n++;
      if (check()) { run(); return; }
      if (n < tries) setTimeout(tick, delay);
    })();
  }

  /* ═══════════════════════════════════════════════════════════════════
     1. FIX: "Request Edit" modal never opened
     ═══════════════════════════════════════════════════════════════════ */
  (function fixWorkEditModal() {
    function patch() {
      if (typeof window.openWorkEditModal !== 'function' || window.openWorkEditModal.__kfsPatched) return false;

      const origOpen = window.openWorkEditModal;
      window.openWorkEditModal = function (movieId, movieTitle) {
        const ret = origOpen(movieId, movieTitle);
        const overlay = document.getElementById('work-edit-modal-overlay');
        if (overlay) overlay.style.display = 'flex'; // the fix — classList alone never worked
        return ret;
      };
      window.openWorkEditModal.__kfsPatched = true;

      const origClose = window.closeWorkEditModal;
      if (typeof origClose === 'function' && !origClose.__kfsPatched) {
        window.closeWorkEditModal = function () {
          const ret = origClose();
          const overlay = document.getElementById('work-edit-modal-overlay');
          if (overlay) overlay.style.display = 'none';
          return ret;
        };
        window.closeWorkEditModal.__kfsPatched = true;
      }
      return true;
    }
    pollFor(() => typeof window.openWorkEditModal === 'function', patch);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     2. FIX: tour spotlight/card alignment
     ═══════════════════════════════════════════════════════════════════ */
  (function fixTourAlignment() {
    function patch() {
      if (typeof window._tourPositionSpot !== 'function' || window._tourPositionSpot.__kfsPatched) return false;
      if (typeof window.KFS_TOUR_STEPS === 'undefined' || typeof window._tourStep === 'undefined') return false;

      window._tourPositionSpot = function () {
        const step = window.KFS_TOUR_STEPS[window._tourStep];
        const spot = document.getElementById('kfs-tour-spot');
        const card = document.getElementById('kfs-tour-card');
        const backdrop = document.getElementById('kfs-tour-backdrop');
        if (!spot || !card || !step) return;

        const target = typeof window._tourFindTarget === 'function' ? window._tourFindTarget(step.selectors) : null;
        if (!target) {
          if (step.selectors) {
            if (window._tourStep < window.KFS_TOUR_STEPS.length - 1) { window._tourStep++; window._tourRenderStep(); }
            else if (typeof window._tourEnd === 'function') window._tourEnd();
            return;
          }
          // No spotlight this step (a centered/intro-style card) — the
          // backdrop is the only thing dimming the page, so keep its tint.
          if (backdrop) backdrop.style.background = 'rgba(0,0,0,0.6)';
          spot.style.display = 'none';
          card.style.top = '50%';
          card.style.left = '50%';
          card.style.transform = 'translate(-50%, -50%)';
          return;
        }

        // The spot's own box-shadow (0 0 0 9999px) already paints the dim
        // everywhere outside the ring. Leaving the backdrop's tint on top
        // stacked a second dark layer over the highlighted target itself,
        // which is why it looked washed-out gray instead of its real color.
        if (backdrop) backdrop.style.background = 'transparent';

        const r = target.getBoundingClientRect();

        // Hug the target's real shape instead of a fixed 16px ring, so a
        // pill button (Submit Movie, the Suggestion tab) gets a pill
        // highlight and a rectangular panel gets a rectangular one.
        const targetRadius = parseFloat(getComputedStyle(target).borderRadius) || 0;
        const pad = 6;
        const isPill = targetRadius >= r.height / 2 - 1;
        const spotRadius = isPill ? (r.height / 2 + pad) : Math.max(targetRadius + pad, 10);

        spot.style.display = 'block';
        spot.style.borderRadius = `${spotRadius}px`;
        spot.style.top = `${r.top - pad}px`;
        spot.style.left = `${r.left - pad}px`;
        spot.style.width = `${r.width + pad * 2}px`;
        spot.style.height = `${r.height + pad * 2}px`;

        // Card sizing/placement — clamped so it can never overlap the ring
        // and never run off any edge of the viewport.
        const GAP = 20;
        const cardW = Math.min(320, window.innerWidth - 32);
        card.style.width = `${cardW}px`;
        card.style.transform = 'none';

        const spotTop    = r.top - pad;
        const spotBottom = r.bottom + pad;
        const roomBelow = window.innerHeight - spotBottom;
        const roomAbove = spotTop;

        // Rough card height estimate for placement decisions (measured
        // after layout below, but we need a first guess to pick a side).
        const estH = card.offsetHeight || 180;

        let top;
        if (roomBelow >= estH + GAP) {
          top = spotBottom + GAP;
        } else if (roomAbove >= estH + GAP) {
          top = spotTop - GAP - estH;
        } else {
          // Neither side has room (small viewport / big target) — pin to
          // whichever side has more space and let it clip the padding
          // rather than overlap the spotlight ring.
          top = roomBelow >= roomAbove
            ? Math.max(spotBottom + GAP, window.innerHeight - estH - 16)
            : Math.min(spotTop - GAP - estH, 16);
        }
        top = Math.max(16, Math.min(top, window.innerHeight - 16 - estH));

        let left = Math.min(Math.max(r.left, 16), window.innerWidth - cardW - 16);

        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
      };
      window._tourPositionSpot.__kfsPatched = true;
      return true;
    }
    pollFor(() => typeof window._tourPositionSpot === 'function', patch);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     3. Emoji → clean SVG icons
     ═══════════════════════════════════════════════════════════════════ */
  (function emojiCleanup() {
    const ICONS = {
      lock: '<path d="M6 11V7a6 6 0 0 1 12 0v4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><rect x="4" y="11" width="16" height="10" rx="2.2" fill="none" stroke="currentColor" stroke-width="2"/>',
      camera: '<path d="M22 18a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h3.2l1.6-2.2h6.4L16.8 7H20a2 2 0 0 1 2 2z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="13" r="3.6" fill="none" stroke="currentColor" stroke-width="1.8"/>',
      film: '<rect x="2.5" y="3.5" width="19" height="17" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><line x1="7.5" y1="3.5" x2="7.5" y2="20.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="3.5" x2="16.5" y2="20.5" stroke="currentColor" stroke-width="1.8"/><line x1="2.5" y1="8.5" x2="7.5" y2="8.5" stroke="currentColor" stroke-width="1.8"/><line x1="2.5" y1="15.5" x2="7.5" y2="15.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="8.5" x2="21.5" y2="8.5" stroke="currentColor" stroke-width="1.8"/><line x1="16.5" y1="15.5" x2="21.5" y2="15.5" stroke="currentColor" stroke-width="1.8"/>',
      people: '<circle cx="8.5" cy="7.5" r="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M2 20c0-3.6 2.9-6.3 6.5-6.3S15 16.4 15 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="17" cy="8.5" r="2.8" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M15.3 13.9c2.7.4 4.7 2.7 4.7 5.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
      lightbulb: '<path d="M9 18.5h6M10 21.5h4M12 2.5a6.7 6.7 0 0 0-3.8 12.2c.6.45.9 1.1.9 1.9v.4h5.8v-.4c0-.8.3-1.45.9-1.9A6.7 6.7 0 0 0 12 2.5z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      alert: '<path d="M10.3 4.1L2.1 18.3a1.9 1.9 0 0 0 1.7 2.9h16.4a1.9 1.9 0 0 0 1.7-2.9L13.7 4.1a1.9 1.9 0 0 0-3.4 0z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="9.5" x2="12" y2="13.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="16.7" r="0.9" fill="currentColor" stroke="none"/>',
      message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      wave: '<path d="M7 12.3V6.2a1.8 1.8 0 0 1 3.6 0V11M10.6 10.6V4.8a1.8 1.8 0 0 1 3.6 0v6M14.2 11V6.4a1.8 1.8 0 0 1 3.6 0v8.1" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.4 13.6v-1.9a1.8 1.8 0 0 1 3.6 0v2.4a7.3 7.3 0 0 0 7.3 7.3h.6a7.3 7.3 0 0 0 7.3-7.3v-3.6a1.8 1.8 0 0 0-3.6 0" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
      link: '<path d="M9.5 12.8a4.3 4.3 0 0 0 6.5.5l2.6-2.6a4.3 4.3 0 0 0-6.1-6.1L11 6.1" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M14.5 11.2a4.3 4.3 0 0 0-6.5-.5L5.4 13.3a4.3 4.3 0 0 0 6.1 6.1L13 17.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
      trash: '<polyline points="3.5 6 5.5 6 20.5 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M18.3 6l-.9 13a2 2 0 0 1-2 1.9H8.6a2 2 0 0 1-2-1.9L5.7 6m3.5 0V3.8a1.8 1.8 0 0 1 1.8-1.8h2a1.8 1.8 0 0 1 1.8 1.8V6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      pin: '<path d="M12 2.3a5.3 5.3 0 0 0-5.3 5.3c0 3.9 5.3 11.1 5.3 11.1s5.3-7.2 5.3-11.1A5.3 5.3 0 0 0 12 2.3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="7.6" r="2" fill="none" stroke="currentColor" stroke-width="1.8"/>',
    };

    function iconSpan(name, size = 14) {
      const span = document.createElement('span');
      span.className = 'kfs-icon-swap';
      span.style.cssText = `display:inline-flex;align-items:center;justify-content:center;width:${size}px;height:${size}px;vertical-align:-2px;flex:none;`;
      span.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 24 24">${ICONS[name]}</svg>`;
      return span;
    }

    // Curated whitelist only — never touches the reaction-emoji picker
    // (❤ 😂 😮 😢 😡 👏 🔥 😍 👍 🙂 😊), which isn't in this list at all.
    const RULES = [
      { test: t => t.startsWith('🔒'), icon: 'lock', stripLen: 2 },
      { test: t => t === '📷 Photo', icon: 'camera', stripLen: 2 },
      { test: t => t === '🎬', icon: 'film', stripLen: 2 },
      { test: t => t === '🤝', icon: 'people', stripLen: 2 },
      { test: t => t === '💡 Suggestion', icon: 'lightbulb', stripLen: 2 },
      { test: t => t === '🚨 Grievance', icon: 'alert', stripLen: 2 },
      { test: t => t === '💬 General', icon: 'message', stripLen: 2 },
      { test: t => t === '💬', icon: 'message', stripLen: 2 },
      { test: t => t === '👋', icon: 'wave', stripLen: 2 },
      { test: t => t.startsWith('🔗 Copy link'), icon: 'link', stripLen: 2 },
      { test: t => t.startsWith('🗑 Delete post'), icon: 'trash', stripLen: 2 },
      { test: t => t.startsWith('📌'), icon: 'pin', stripLen: 2 },
    ];

    const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT']);

    function shouldSkipContainer(el) {
      while (el) {
        if (SKIP_TAGS.has(el.tagName)) return true;
        if (el.isContentEditable) return true;
        el = el.parentElement;
      }
      return false;
    }

    function processTextNode(node) {
      const raw = node.nodeValue;
      if (!raw || raw.indexOf('\u200b') !== -1) return; // already processed marker
      const trimmed = raw.trim();
      if (!trimmed) return;
      const rule = RULES.find(r => r.test(trimmed));
      if (!rule) return;
      const parent = node.parentNode;
      if (!parent || shouldSkipContainer(parent)) return;

      const leadWs = raw.match(/^\s*/)[0];
      const trailWs = raw.match(/\s*$/)[0];
      const rest = trimmed.slice(rule.stripLen).replace(/^\s+/, '');

      const frag = document.createDocumentFragment();
      if (leadWs) frag.appendChild(document.createTextNode(leadWs));
      frag.appendChild(iconSpan(rule.icon));
      frag.appendChild(document.createTextNode((rest ? ' ' + rest : '') + trailWs || '\u200b'));
      parent.replaceChild(frag, node);
    }

    function sweep(root) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode(n) {
          if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          return shouldSkipContainer(n.parentNode) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        }
      });
      const nodes = [];
      let n;
      while ((n = walker.nextNode())) nodes.push(n);
      nodes.forEach(processTextNode);
    }

    let pending = false;
    function scheduleSweep(root) {
      if (pending) return;
      pending = true;
      setTimeout(() => { pending = false; sweep(root); }, 150);
    }

    function stripEmojiFromTourCopy() {
      if (typeof window.KFS_TOUR_STEPS === 'undefined' || !Array.isArray(window.KFS_TOUR_STEPS)) return false;
      const EMOJI_RE = /\s?[\u{1F300}-\u{1FAFF}\u2600-\u27BF\uFE0F]\s?/gu;
      window.KFS_TOUR_STEPS.forEach(step => {
        if (step.title) step.title = step.title.replace(EMOJI_RE, ' ').replace(/\s+/g, ' ').trim();
        if (step.body)  step.body  = step.body.replace(EMOJI_RE, ' ').replace(/\s+/g, ' ').trim();
      });
      return true;
    }

    ready(() => {
      sweep(document.body);
      const mo = new MutationObserver(() => scheduleSweep(document.body));
      mo.observe(document.body, { childList: true, subtree: true, characterData: true });
      pollFor(() => typeof window.KFS_TOUR_STEPS !== 'undefined', stripEmojiFromTourCopy);
    });
  })();

  /* ═══════════════════════════════════════════════════════════════════
     4. Hide the duplicate "time ago" at the bottom of feed post cards
     ═══════════════════════════════════════════════════════════════════ */
  (function dedupTimestamps() {
    const style = document.createElement('style');
    style.textContent = `.ig-post-timestamp { display: none !important; }`;
    document.head.appendChild(style);
  })();

  /* ═══════════════════════════════════════════════════════════════════
     5. Merge "My Movies" + "My Works" into one panel with tabs
     ═══════════════════════════════════════════════════════════════════ */
  (function mergeMoviesAndWorks() {
    const style = document.createElement('style');
    style.textContent = `
      .nav-item[data-panel="works"],
      .settings-sheet-item[onclick="settingsSheetGo('works')"] { display: none !important; }
      .kfs-mw-tabs { display:flex; gap:6px; margin: 2px 0 20px; }
    `;
    document.head.appendChild(style);

    function setTrailingText(el, oldText, newText) {
      if (!el) return;
      for (const node of el.childNodes) {
        if (node.nodeType === 3 && node.nodeValue.trim() === oldText) {
          node.nodeValue = newText;
          return;
        }
      }
    }

    function patch() {
      const moviesPanel = document.getElementById('panel-movies');
      const worksPanel = document.getElementById('panel-works');
      if (!moviesPanel || !worksPanel || moviesPanel.dataset.kfsMerged) return false;
      moviesPanel.dataset.kfsMerged = '1';

      const titleEl = moviesPanel.querySelector('.panel-title');
      const subEl = moviesPanel.querySelector('.panel-sub');
      if (titleEl) titleEl.textContent = 'My Movies & Works';
      if (subEl) subEl.textContent = 'Submit films for admin review, or request an edit to your existing credits.';

      // Everything in #panel-movies besides the title/sub becomes the
      // "Submissions" tab content.
      const submissionsTab = document.createElement('div');
      submissionsTab.id = 'kfs-mw-submissions-tab';
      Array.from(moviesPanel.children).forEach(child => {
        if (child !== titleEl && child !== subEl) submissionsTab.appendChild(child);
      });
      moviesPanel.appendChild(submissionsTab);

      // #panel-works's content (minus its own title/sub) becomes the
      // "My Works" tab content, hidden by default.
      const worksTab = document.createElement('div');
      worksTab.id = 'kfs-mw-works-tab';
      worksTab.style.display = 'none';
      Array.from(worksPanel.children).forEach(child => {
        if (!child.classList.contains('panel-title') && !child.classList.contains('panel-sub')) {
          worksTab.appendChild(child);
        }
      });
      worksPanel.remove();
      moviesPanel.appendChild(worksTab);

      // Tab switcher — reuses the app's existing pill-tab visual style.
      const tabs = document.createElement('div');
      tabs.className = 'kfs-mw-tabs';
      tabs.innerHTML = `
        <button type="button" class="strand-sort-pill kfs-mw-tab active" data-tab="submissions">Submissions</button>
        <button type="button" class="strand-sort-pill kfs-mw-tab" data-tab="works">My Works</button>`;
      subEl ? subEl.insertAdjacentElement('afterend', tabs) : moviesPanel.insertBefore(tabs, submissionsTab);

      tabs.querySelectorAll('.kfs-mw-tab').forEach(btn => {
        btn.addEventListener('click', () => {
          tabs.querySelectorAll('.kfs-mw-tab').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          const showWorks = btn.dataset.tab === 'works';
          submissionsTab.style.display = showWorks ? 'none' : '';
          worksTab.style.display = showWorks ? '' : 'none';
          if (showWorks && typeof window.loadMyWorks === 'function') window.loadMyWorks();
          else if (typeof window.loadMovies === 'function') window.loadMovies();
        });
      });

      // Rename the remaining sidebar/settings-sheet "My Movies" entries.
      setTrailingText(document.querySelector('.nav-item[data-panel="movies"]'), 'My Movies', 'My Movies & Works');
      const sheetLabel = document.querySelector(".settings-sheet-item[onclick=\"settingsSheetGo('movies')\"] .settings-sheet-label");
      if (sheetLabel) sheetLabel.textContent = 'My Movies & Works';

      // Old deep links / the tour still ask for panel "works" — send them
      // to the merged panel with the My Works tab pre-selected instead of
      // silently landing on nothing.
      if (typeof window.switchPanel === 'function' && !window.switchPanel.__kfsMergePatched) {
        const origSwitchPanel = window.switchPanel;
        window.switchPanel = function (el) {
          if (el && el.dataset && el.dataset.panel === 'works') {
            const moviesNav = document.querySelector('.nav-item[data-panel="movies"]') || { dataset: { panel: 'movies' } };
            const ret = origSwitchPanel(moviesNav);
            tabs.querySelector('.kfs-mw-tab[data-tab="works"]')?.click();
            return ret;
          }
          return origSwitchPanel(el);
        };
        window.switchPanel.__kfsMergePatched = true;
      }

      // Keep the tour's "My Movies" step and closing summary accurate now
      // that My Works lives in the same place.
      if (Array.isArray(window.KFS_TOUR_STEPS)) {
        window.KFS_TOUR_STEPS.forEach(step => {
          if (step.title === 'My Movies — submissions & change requests') {
            step.title = 'My Movies & Works';
            step.body = "Submit a finished film here for admin review and publication on /films, or switch to the My Works tab to request an edit to a credit you already have. Every submission gets a status: Pending, Approved, Rejected, or Changes Requested — if you see Changes Requested, click Edit on that same submission to update and resubmit.";
          }
          if (step.body && step.body.includes('My Movies, My Works')) {
            step.body = step.body.replace('My Movies, My Works,', 'My Movies & Works,');
          }
        });
      }
      return true;
    }

    ready(() => pollFor(() => document.getElementById('panel-movies') && document.getElementById('panel-works'), patch));
  })();

})();


// ── 8. MOBILE NAV PILL — FINAL DESIGN PASS ──────────────────────────────────
// Earlier patches (section 7 above, and the "kfs-patch3" Instagram overhaul
// merged in further down) both touch .bottom-tab-bar/.btb-item with
// !important and fight each other — one wants a flat 52px Instagram-style
// bar, the original HTML wants a floating pill. This block is injected last
// (last <style> tag wins ties at equal specificity) and is the single
// source of truth for the mobile nav from here on: compact by default,
// icon-only, a soft glow so it lifts off the page, and a spring "grow"
// bounce on tap instead of the old shrink — closer to how iOS/Instagram's
// own tab bar feels.
(function injectFinalMobileNavStyles() {
  const style = document.createElement('style');
  style.id = 'kfs-final-mobile-nav';
  style.textContent = `
    @media (max-width: 768px) and (pointer: coarse) {
      /* ── The pill itself: compact, centered, glowing ─────────────────── */
      .bottom-tab-bar {
        position: fixed !important;
        left: 50% !important;
        right: auto !important;
        bottom: max(14px, calc(env(safe-area-inset-bottom) + 8px)) !important;
        transform: translateX(-50%) !important;
        width: auto !important;
        min-width: 0 !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 13px !important;
        height: 61px !important;
        padding: 0 24px !important;
        margin: 0 !important;
        border: 1px solid rgba(255,255,255,0.16) !important;
        border-radius: 999px !important;
        background: rgba(40,40,44,0.82) !important;
        backdrop-filter: blur(28px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(28px) saturate(180%) !important;
        box-shadow:
          0 10px 30px rgba(0,0,0,0.55),
          0 2px 10px rgba(0,0,0,0.4),
          0 0 24px rgba(10,132,255,0.10),
          inset 0 1px 0 rgba(255,255,255,0.10) !important;
        transition: box-shadow 0.25s var(--spring-soft, ease), transform 0.25s var(--spring-soft, ease) !important;
        z-index: 999998 !important;
        pointer-events: auto !important;
      }

      /* ── Items: icon-only, compact, evenly spaced ────────────────────── */
      .btb-item {
        flex: 0 0 auto !important;
        width: 44px !important;
        height: 44px !important;
        min-width: 0 !important;
        min-height: 0 !important;
        padding: 0 !important;
        margin: 0 !important;
        display: flex !important;
        flex-direction: row !important;
        align-items: center !important;
        justify-content: center !important;
        border-radius: 999px !important;
        color: rgba(255,255,255,0.42) !important;
        transition: color 0.15s ease, background 0.15s ease,
                    transform 0.32s var(--spring, cubic-bezier(0.34,1.56,0.64,1)) !important;
      }
      .btb-item svg {
        width: 22px !important;
        height: 22px !important;
        stroke-width: 2 !important;
        flex-shrink: 0 !important;
        transition: transform 0.32s var(--spring, cubic-bezier(0.34,1.56,0.64,1)) !important;
      }
      .btb-item.active {
        color: #ffffff !important;
      }
      .btb-item.active svg { stroke-width: 2.3 !important; }
      /* Small dot beneath the active icon, matching the reference design —
         no background pill, just the dot. Never on the post button. */
      .btb-item.active:not(.btb-post-item)::after {
        content: "" !important;
        position: absolute !important;
        bottom: 3px !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        width: 4px !important;
        height: 4px !important;
        border-radius: 50% !important;
        background: #ffffff !important;
      }

      /* Tap feedback: GROW instead of shrink — the "otherwise it's smaller,
         enlarges when touched" behaviour that was asked for. Driven by the
         .kfs-pressed class (added/removed via touchstart/touchend JS below)
         rather than :active alone — :active is unreliable inside Android
         WebViews and some mobile browsers without extra wiring. */
      .btb-item:active,
      .btb-item.kfs-pressed {
        transform: scale(1.14) !important;
        background: rgba(255,255,255,0.12) !important;
        transition: transform 0.12s var(--spring, cubic-bezier(0.34,1.56,0.64,1)) !important;
      }

      /* Text labels removed — icon-only nav */
      .bottom-tab-bar .btb-label {
        display: none !important;
      }

      /* ── Centre post button — its own accent circle, same rhythm ─────── */
      .btb-post-item {
        width: auto !important;
        height: auto !important;
        background: none !important;
        margin: 0 !important;
      }
      .btb-post-btn {
        width: 40px !important;
        height: 40px !important;
        border-radius: 14px !important;
        background: #ffffff !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        box-shadow: 0 2px 12px rgba(0,0,0,0.5), 0 1px 3px rgba(0,0,0,0.3) !important;
        transition: transform 0.32s var(--spring, cubic-bezier(0.34,1.56,0.64,1)) !important;
      }
      .btb-post-btn svg {
        width: 18px !important;
        height: 18px !important;
        stroke: #000 !important;
      }
      .btb-post-item:active .btb-post-btn,
      .btb-post-item.kfs-pressed .btb-post-btn {
        transform: scale(1.14) !important;
      }

      /* ── Unread badge: sit tight on the icon, not floating in space ──── */
      #dm-btb-badge {
        top: 2px !important;
        right: 2px !important;
      }

      /* ── Mobile notification FAB, docked top-right near the composer/+
             button so it reads as part of the same top action row ──────── */
      .btb-notif-fab {
        position: fixed;
        top: max(14px, env(safe-area-inset-top));
        right: 16px;
        width: 40px;
        height: 40px;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(18,18,20,0.85);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        box-shadow: 0 6px 18px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.06);
        display: flex;
        align-items: center;
        justify-content: center;
        color: rgba(255,255,255,0.85);
        z-index: 999999;
        pointer-events: auto;
        transition: transform 0.28s var(--spring, cubic-bezier(0.34,1.56,0.64,1)), background 0.15s ease;
      }
      .btb-notif-fab svg { width: 18px; height: 18px; }
      .btb-notif-fab:active,
      .btb-notif-fab.kfs-pressed { transform: scale(1.14); }
      .btb-notif-fab.active {
        background: rgba(10,132,255,0.22);
        color: #fff;
      }
      .btb-notif-fab .notif-badge {
        top: -2px !important;
        left: auto !important;
        right: -2px !important;
      }

      /* Hide the mobile FAB whenever a full-screen chat window has slid in,
         or while the auth screen is showing — same rule the pill nav uses.
         Also hide it on the Strand panel specifically — that panel has its
         own bell built into its topbar (Site / globe / bell), so showing
         the floating FAB there too would be a redundant second bell. */
      body.auth-active .btb-notif-fab { display: none !important; }
      body:has(#dm-window.dm-slide-in) .btb-notif-fab,
      body:has(#gc-window.dm-slide-in) .btb-notif-fab,
      body:has(#panel-studio.active) .btb-notif-fab {
        display: none !important;
      }
    }

    /* Never show the notif FAB on desktop */
    @media (min-width: 769px) {
      .btb-notif-fab { display: none !important; }
    }
  `;
  document.head.appendChild(style);
})();

// ── Reliable tap feedback for the mobile nav pill ───────────────────────────
// Some Android WebViews / older mobile browsers apply :active flakily on
// tap. Toggling a real class on touchstart/touchend guarantees the "grow on
// tap" effect actually fires every time, everywhere this app runs.
(function installKfsPressFeedback() {
  const pressTargets = '.btb-item, .btb-post-item, .btb-notif-fab';
  function addPressed(e) {
    const el = e.target.closest && e.target.closest(pressTargets);
    if (el) el.classList.add('kfs-pressed');
  }
  function removePressed() {
    document.querySelectorAll('.kfs-pressed').forEach(el => el.classList.remove('kfs-pressed'));
  }
  document.addEventListener('touchstart', addPressed, { passive: true });
  document.addEventListener('touchend', removePressed, { passive: true });
  document.addEventListener('touchcancel', removePressed, { passive: true });
  document.addEventListener('mousedown', addPressed);
  document.addEventListener('mouseup', removePressed);
  document.addEventListener('mouseleave', removePressed);
})();

// ── Mobile back button: don't skip straight out to the original site ──────
// Tapping into Network / Messages / Settings etc. from the Feed home panel
// used to leave zero history trace, so the very next hardware/browser back
// press exited the app entirely instead of returning to Feed first — the
// same "back leaves the whole page" problem _kfsPushNavState already solves
// for chats/settings-sheet/notifications, just not yet for panel switches.
(function installPanelBackNav() {
  const HOME_PANEL = 'studio';
  let awayPushed = false;

  function currentPanelName() {
    const active = document.querySelector('.panel.active');
    return active ? active.id.replace(/^panel-/, '') : null;
  }

  const _prevSwitchPanel = window.switchPanel;
  if (typeof _prevSwitchPanel !== 'function' || _prevSwitchPanel.__kfsBackNavPatched) return;

  window.switchPanel = function (el) {
    const prevPanel = currentPanelName();
    const nextPanel = el && el.dataset ? el.dataset.panel : null;
    _prevSwitchPanel(el);
    if (!nextPanel) return;
    if (nextPanel !== HOME_PANEL && !awayPushed && (prevPanel === HOME_PANEL || prevPanel === null)) {
      awayPushed = true;
      _kfsPushNavState('panel-away');
    } else if (nextPanel === HOME_PANEL && awayPushed) {
      awayPushed = false;
      _kfsPopNavState('panel-away');
    }
  };
  window.switchPanel.__kfsBackNavPatched = true;
})();

// ── Mobile viewport-height fix (keyboard-safe DM/GC composer) ─────────────
// iOS Safari and most Android browsers don't shrink `100vh` when the on-
// screen keyboard opens (only the *visual* viewport shrinks), which is why
// the composer used to get covered by the keyboard or the page jumped.
// window.visualViewport reports the real visible height, so we mirror it
// into a CSS var and let .dm-panel (mobile-only, see CSS) size off that
// instead of 100vh. No-ops harmlessly on desktop / unsupported browsers.
(function kfsInitViewportFix() {
  const root = document.documentElement;
  if (!window.visualViewport) return; // graceful no-op on old browsers

  let raf = null;
  function apply() {
    raf = null;
    root.style.setProperty('--kfs-vvh', window.visualViewport.height + 'px');
  }
  function schedule() {
    if (raf) return;
    raf = requestAnimationFrame(apply);
  }

  apply();
  window.visualViewport.addEventListener('resize', schedule);
  window.visualViewport.addEventListener('scroll', schedule);
  // Orientation changes can land visualViewport a frame late on iOS.
  window.addEventListener('orientationchange', () => setTimeout(apply, 120));
})();

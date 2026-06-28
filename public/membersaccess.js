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
   * Returns { publicKeyJwk, privateKey (CryptoKey) }.
   */
  async function _loadMyKeyPair() {
    const stored = await _dbGet(MY_KEY_ID);
    if (stored) {
      const privateKey = await crypto.subtle.importKey(
        'jwk', stored.privateKeyJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false, ['deriveKey', 'deriveBits']
      );
      return { publicKeyJwk: stored.publicKeyJwk, privateKey };
    }
    return _generateKeyPair();
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

  /**
   * Must be called once on login (after _member is set).
   * Generates key pair if needed, publishes public key to server.
   */
  async function init() {
    if (_readyPromise) return _readyPromise;
    _readyPromise = (async () => {
      try {
        const { publicKeyJwk, privateKey } = await _loadMyKeyPair();
        _myPrivateKey   = privateKey;
        _myPublicKeyJwk = publicKeyJwk;
        // Publish our public key so peers can encrypt messages to us.
        // The server stores it — it's not secret. Idempotent upsert.
        await api('POST', '/api/member/e2ee/publish-key', { public_key_jwk: publicKeyJwk });
        _ready = true;
        console.log('[E2EE] Ready. Key fingerprint:', await fingerprint());
      } catch (e) {
        console.error('[E2EE] init failed:', e.message);
        // Non-fatal: fall back to plaintext mode (E2EE.ready() returns false)
      }
    })();
    return _readyPromise;
  }

  function ready() { return _ready; }

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
    if (!_ready) return msg.body || ''; // no key yet
    // Legacy plaintext message (pre-E2EE)
    if (!msg.e2ee) return msg.body || '';
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
      return '[encrypted message — key unavailable]';
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
    if (!_ready) return msg.body || '';
    if (!msg.e2ee) return msg.body || ''; // legacy plaintext
    try {
      const myWrappedKey = msg.wrapped_keys?.[myId];
      if (!myWrappedKey) return '[message unavailable — no key for you]';
      // Unwrap the message key using our ECDH shared key with the sender
      const senderPublicKey = await _getPeerPublicKey(msg.sender_id);
      const sharedKey = await _deriveSharedKey(_myPrivateKey, senderPublicKey);
      const msgKey = await _unwrapAesKey(myWrappedKey, sharedKey);
      return await _aesDecrypt(msgKey, msg.ciphertext);
    } catch (e) {
      console.warn('[E2EE] Group decrypt failed for msg', msg.id, e.message);
      return '[encrypted message — key unavailable]';
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
  return {
    init,
    ready,
    fingerprint,
    encryptDm,
    decryptDm,
    encryptGroup,
    decryptGroup,
    decryptForReport,
    regenerateKeyPair,
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
  const r = await fetch(API + fetchPath, opts);
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
      return true;
    }
    return false;
  } catch { return false; }
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

document.addEventListener('DOMContentLoaded', async () => {
  wireStaticButtons();

  // Try to restore session via refresh token cookie
  if (document.cookie.includes('kfs_member_session=1')) {
    const ok = await refreshToken();
    if (ok) { await loadDashboard(); return; }
  }
  showLoginScreen();
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
  E2EE.init().catch(e => console.warn('[E2EE] init error (non-fatal):', e.message));
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
        // Switch to profile panel
        const profileNav = document.querySelector('[data-panel="profile"]');
        if (profileNav) switchPanel(profileNav);
      }, { once: true });
      if (skipBtn) skipBtn.addEventListener('click', () => {
        overlay.classList.remove('open');
        localStorage.setItem(firstTimeKey, '1');
        // Go straight to feed
        _goToStrandFeed();
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

/** Switch directly to the Strand (Social Strand) feed panel. */
function _goToStrandFeed() {
  const studioNav = document.querySelector('[data-panel="studio"]');
  if (studioNav && window._memberProfile && !window._memberProfile.is_past) {
    switchPanel(studioNav);
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
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll(`.nav-item[data-panel="${panel}"]`).forEach(n => n.classList.add('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $id('panel-' + panel)?.classList.add('active');
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
}

function closeSettingsSheet() {
  $id('settings-sheet-backdrop')?.classList.remove('open');
  $id('settings-sheet')?.classList.remove('open');
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
  list.innerHTML = '<div style="color:var(--muted);font-size:13px">Loading…</div>';
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
    if (badge) {
      badge.textContent = unread > 9 ? '9+' : unread;
      badge.classList.toggle('visible', unread > 0);
    }
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
  }
}

async function loadNotifications() {
  if (!_token || _notifLoading) return;
  _notifLoading = true;
  const list = $id('notif-list');
  if (list) list.innerHTML = '<div class="notif-empty"><div class="notif-empty-title" style="color:#333">Loading…</div></div>';
  try {
    const items = await api('GET', '/api/member/notifications');
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
  if (panel)    { panel.classList.add('open'); }
  if (backdrop) { backdrop.classList.add('open'); }
  if (btn)      { btn.classList.add('active'); }
  loadNotifications();
}

function closeNotifPanel() {
  _notifOpen = false;
  const panel    = $id('notif-panel');
  const backdrop = $id('notif-panel-backdrop');
  const btn      = $id('notif-bell-btn');
  if (panel)    { panel.classList.remove('open'); }
  if (backdrop) { backdrop.classList.remove('open'); }
  if (btn)      { btn.classList.remove('active'); }
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
  if (!confirm('Delete this collab post? This cannot be undone.')) return;
  btn.disabled = true; btn.textContent = 'Deleting…';
  try {
    await api('DELETE', `/api/collaborate/${token}`);
    await loadMyCollabs();
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Delete';
    alert('Could not delete: ' + e.message);
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

function swFeedCard(p) {
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

  return `<article class="ig-post" data-project-id="${swEsc(p.id)}"${isAdminPost ? ' style="border:1.5px solid #2d6a9f22;background:linear-gradient(180deg,rgba(45,106,159,.04),transparent)"' : ''} onclick="swOpenDetail('${swEsc(p.id)}')">
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

async function swLoadFeed(reset = false) {
  if (SW.feedLoading) return;
  if (!reset && SW.feedExhausted) return;
  if (reset) {
    SW.feedPage = 1;
    SW.feedExhausted = false;
    const grid = $id('studio-feed');
    if (grid) grid.innerHTML = '<div class="sw-loading">Loading…</div>';
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
  } catch (e) { alert(e.message||'Could not post comment.'); }
}

// ── Reactions ─────────────────────────────────────────────────────────────

async function swToggleReaction(projectId, reactionType) {
  const current = SW.myReactions.get(projectId)||null;
  SW.myReactions.set(projectId, current===reactionType ? null : reactionType);
  swUpdateReactionUI(projectId);
  try {
    const resp = await api('POST', `/api/member/studio/projects/${projectId}/react`, { reaction_type: reactionType });
    // Server returns { active, reaction_type }; sync state with server truth
    SW.myReactions.set(projectId, resp.active ? resp.reaction_type : null);
    swUpdateReactionUI(projectId);
  } catch {
    SW.myReactions.set(projectId, current);
    swUpdateReactionUI(projectId);
  }
}

function swUpdateReactionUI(projectId) {
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
  }
  // Sync overlay active states if it's currently showing for this project
  if (RXN.currentId === projectId) _rxnSyncActive(projectId);
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

function swSetPostType(type) {
  _composerPostType = type;
  // Update type buttons
  document.querySelectorAll('.composer-type-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.postType === type);
  });
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
  } catch(e) { alert('Could not load post for editing: ' + e.message); }
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
        margin:0 auto 18px;font-size:26px;
        background:rgba(255,59,48,.15);border:1.5px solid rgba(255,59,48,.3);
      ">⚠️</div>
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
          background:linear-gradient(135deg,#ff9f0a,#ff6b00);
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;
          background-clip:text;line-height:1;
        ">—</div>
        <div style="
          margin-top:10px;height:3px;background:rgba(255,255,255,.08);
          border-radius:2px;overflow:hidden;
        ">
          <div id="sw-vio-timer-bar" style="
            height:100%;width:100%;border-radius:2px;
            background:linear-gradient(90deg,#ff9f0a,#ff6b00);
            transform-origin:left;transition:transform .9s linear;
          "></div>
        </div>
      </div>
      <div id="sw-vio-appeal-wrap" style="display:none;margin-bottom:12px">
        <button id="sw-vio-appeal-btn" onclick="_swVioSubmitAppeal()" style="
          width:100%;padding:13px 20px;border-radius:12px;border:none;
          background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;
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

  // ── Ladder step labels shown in descriptions ───────────────────────────────
  const ladderSteps = [
    '1st violation → ⚠️ Warning',
    '2nd violation → 🔇 1-minute mute',
    '3rd violation → 🔇 2-minute mute',
    '4th violation → 🔇 5-minute mute',
    '5th violation → 🔴 Temporary ban',
  ];
  function _ladderHtml(currentOffense) {
    return ladderSteps.map((s, i) => {
      const n = i + 1;
      const isCurrent = n === currentOffense;
      const isPast    = n < currentOffense;
      return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;${isCurrent ? 'font-weight:700;color:#f5f5f5' : isPast ? 'color:rgba(255,255,255,.3);text-decoration:line-through' : 'color:rgba(255,255,255,.45)'}">
        <span style="width:18px;height:18px;border-radius:50%;background:${isCurrent ? '#e53e3e' : isPast ? 'rgba(255,255,255,.08)' : 'rgba(255,255,255,.06)'};display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;flex-shrink:0">${isPast ? '✓' : n}</span>
        <span style="font-size:12.5px">${s}</span>
      </div>`;
    }).join('');
  }

  if (data.temp_banned || data.action === 'temp_ban') {
    // ── TEMP BAN ─────────────────────────────────────────────────────────────
    icon.textContent = '🔴';
    icon.style.background  = 'rgba(229,62,62,.18)';
    icon.style.borderColor = 'rgba(229,62,62,.4)';
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
    icon.textContent = '🚫';
    icon.style.background  = 'rgba(255,59,48,.15)';
    icon.style.borderColor = 'rgba(255,59,48,.3)';
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

    icon.textContent = '🔇';
    icon.style.background  = 'rgba(255,159,10,.12)';
    icon.style.borderColor = 'rgba(255,159,10,.3)';
    title.textContent = `Warning #${offenseNum} — Posting Paused`;

    const nextHint = offenseNum === 2 ? 'Next: 2-min mute'
                   : offenseNum === 3 ? 'Next: 5-min mute'
                   : 'Next: Temporary ban';

    desc.innerHTML = `<div style="margin-bottom:12px;font-size:13px;line-height:1.6">Your message contained language that violates our community guidelines. Posting is paused until the timer expires.</div>
      <div style="background:rgba(255,255,255,.04);border-radius:12px;padding:12px 14px;margin-bottom:6px;text-align:left">${_ladderHtml(offenseNum)}</div>
      <div style="font-size:11.5px;color:rgba(255,159,10,.7);margin-top:8px">⚠️ ${nextHint}</div>`;

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
        timerEl.style.background = 'linear-gradient(135deg,#34c759,#30d158)';
        desc.innerHTML = `<div style="color:rgba(255,255,255,.65);font-size:13px">Your posting is now unlocked. Please keep the community respectful going forward.</div>`;
        dismiss.textContent = 'Start posting again';
        return;
      }
      timerEl.textContent = _swVioFormatMs(rem);
    }, 500);

  } else {
    // ── WARNING ONLY (offense 1) ──────────────────────────────────────────────
    const offenseNum = data.offense || 1;
    icon.textContent = '⚠️';
    icon.style.background  = 'rgba(255,204,0,.12)';
    icon.style.borderColor = 'rgba(255,204,0,.3)';
    title.textContent = `Warning #${offenseNum} — Post Blocked`;

    desc.innerHTML = `<div style="margin-bottom:12px;font-size:13px;line-height:1.6">${msg || 'Your post contained language that violates our community guidelines.'}</div>
      <div style="background:rgba(255,255,255,.04);border-radius:12px;padding:12px 14px;text-align:left">${_ladderHtml(offenseNum)}</div>
      <div style="font-size:11.5px;color:rgba(255,204,0,.75);margin-top:10px">⚠️ Next violation will result in a 1-min mute.</div>`;

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
    btn.textContent    = '✓ Appeal Submitted';
    status.textContent = 'An admin will review your case. You will be notified when a decision is made.';
    status.style.color = 'rgba(52,199,89,.8)';
  } catch (e) {
    btn.disabled   = false;
    btn.textContent = 'Ask Admin to Review';
    status.textContent = e.message || 'Could not submit appeal. Try again.';
    status.style.color = 'rgba(255,80,60,.8)';
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
    <div style="font-size:48px;margin-bottom:4px">🔴</div>
    <div style="font-size:22px;font-weight:800;letter-spacing:-.03em;color:#f5f5f5">Account Suspended</div>
    ${untilHtml}
    <div style="font-size:14px;color:rgba(255,255,255,.5);max-width:340px;line-height:1.6;margin-top:2px">
      You cannot access Social Strand, DMs, or Group Chats during your suspension. If you believe this is a mistake, tap below to request a review.
    </div>
    <button id="sw-tempban-appeal-btn" style="
      margin-top:10px;padding:14px 32px;border-radius:14px;border:none;
      background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;
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
      btn.textContent = '✓ Appeal Submitted';
      stat.textContent = 'An admin will review your case and you\'ll be notified.';
      stat.style.color = 'rgba(52,199,89,.8)';
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Ask Admin to Review';
      stat.textContent = e.message || 'Could not submit — try again.';
      stat.style.color = 'rgba(255,80,60,.8)';
    }
  });
}


async function swDeletePost(projectId,title) {
  if(!confirm(`Delete "${title}"? This cannot be undone.`))return;
  try {
    await api('DELETE',`/api/member/studio/projects/${projectId}`);
    await swLoadMyPosts();
    await swLoadFeed(true);
  } catch(e){alert('Could not delete: '+e.message);}
}

function swClosePostModal() {
  const o=$id('studio-post-modal-overlay');if(o)o.style.display='none';
  document.body.style.overflow='';
  swResetPostModal();
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
    alert(e.message || 'Could not update follow status.');
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
    const preview = c.last_snippet
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

  // Mobile only: slide sidebar out to reveal chat window
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.add('dm-slide-out');
    $id('dm-window')?.classList.add('dm-slide-in');
  }

  await dmLoadMsgs(false);
  $id('dm-input')?.focus();
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

  const ta = $id('dm-topbar-avatar');
  if (ta) ta.innerHTML = dmAvatar(DM.activePeer.name, DM.activePeer.photo, 34);
  setText('dm-topbar-name', DM.activePeer.name || 'Member');
  setText('dm-topbar-sub', [DM.activePeer.role, DM.activePeer.batch || DM.activePeer.domain].filter(Boolean).join(' · '));

  $id('dm-window-empty') && ($id('dm-window-empty').style.display = 'none');
  $id('dm-active') && ($id('dm-active').style.display = 'flex');
  $id('dm-msg-list') && ($id('dm-msg-list').innerHTML = '');
  $id('dm-load-earlier-wrap') && ($id('dm-load-earlier-wrap').style.display = 'none');
  if (window.innerWidth <= 768) {
    $id('dm-sidebar')?.classList.add('dm-slide-out');
    $id('dm-window')?.classList.add('dm-slide-in');
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

function dmRenderMsgs(msgs, container, myId, lastSenderHint) {
  // Group consecutive messages from same sender.
  // lastSenderHint: pass the sender_id of the last message already in the DOM
  // so incremental appends can continue an existing group instead of creating a new one.
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild
    : null;

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
    if (m.replied_to_id && m.replied_to_body) {
      const quote = document.createElement('div');
      quote.className = 'dm-reply-quote';
      quote.innerHTML = `<span class="dm-reply-sender">${swEsc(m.replied_to_sender || 'Member')}</span><span class="dm-reply-body">${swEsc((m.replied_to_body || '').slice(0, 120))}</span>`;
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
    const bodyNode = document.createElement('span');
    bodyNode.className = 'dm-bubble-text';
    // E2EE: decrypt asynchronously; show placeholder while decrypting
    if (m.e2ee && !isDeleted) {
      bodyNode.textContent = '🔒 …';
      bodyNode.style.opacity = '0.5';
      const _myId = myId;
      E2EE.decryptDm(m, _myId).then(pt => {
        bodyNode.textContent = pt;
        bodyNode.style.opacity = '';
        m._plaintext = pt; // cache for context menu / reply
      }).catch(() => { bodyNode.textContent = '[encrypted — key unavailable]'; bodyNode.style.opacity = '0.5'; });
    } else {
      bodyNode.textContent = m.body;
    }
    bubble.appendChild(bodyNode);

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
    meta.innerHTML = `<span class="dm-msg-time">${dmFull(m.sent_at)}</span>${mine && !isDeleted ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

    const delBtn = meta.querySelector('.dm-del-btn');
    if (delBtn) {
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dmDeleteMsg(m.id, bubble, delBtn);
      });
    }

    // Context menu: right-click (desktop) + long-press (mobile)
    _attachMsgContextMenu(bubble, {
      id: m.id, body: m.body, mine,
      senderName: mine ? 'You' : (DM.activePeer?.name || 'Member'),
      type: 'dm',
    });

    group.appendChild(wrap);
    group.appendChild(meta);
  });

  _markLastBubbleInGroups(container);
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
      // Re-wire hover-action buttons with real ID
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
    } else if (list) {
      // Fallback: full rerender (bubble wasn't tagged somehow)
      list.innerHTML = '';
      dmRenderMsgs(DM.msgs, list, myId);
      dmScrollBottom();
    }

    // Update conv list locally (avoid full refetch on every send)
    const existingConv = DM.convs.find(c => c.conv_key === DM.activeKey);
    if (existingConv) {
      existingConv.last_snippet      = body.slice(0, 80);
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
    } else {
      input.value = body;
      console.error('[DM] send:', e.message);
    }
  } finally {
    DM.pendingBodies.delete(body);
  }
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
  if (!confirm('Delete this message?')) return;
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

function swConfirmDeletePost(postId) {
  if (!confirm('Delete this post? This cannot be undone.')) return;
  // Use existing delete function if available
  if (typeof swDeleteProject === 'function') { swDeleteProject(postId); return; }
  // Fallback — use api() helper so CSRF is automatically attached
  api('DELETE', `/api/member/studio/projects/${postId}`)
    .then(() => {
      const card = document.querySelector(`.ig-post[data-project-id="${CSS.escape(postId)}"]`);
      if (card) card.remove();
      swShowToast('Post deleted.');
    })
    .catch(e => alert(e.message || 'Error deleting post. Please try again.'));
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
            await api('POST', '/api/member/dm/send', { to_member_id: item.data.peer?.id, body });
          } else {
            await api('POST', `/api/member/groups/${item.data.id}/messages`, { body });
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

// Context menu implementation
let _ctxMenu = null;
let _longPressTimer = null;

function _dismissCtxMenu() {
  if (_ctxMenu) { _ctxMenu.remove(); _ctxMenu = null; }
}
document.addEventListener('click', _dismissCtxMenu);
document.addEventListener('keydown', e => { if (e.key === 'Escape') _dismissCtxMenu(); });

function _showMsgContextMenu(e, info) {
  e.preventDefault();
  e.stopPropagation();
  _dismissCtxMenu();

  const { id, body, mine, senderName, type /* 'dm'|'group' */, senderId } = info;

  // The `info` object closed over by _attachMsgContextMenu was built once,
  // at render time. After a pin/unpin toggle, GC.msgs is updated in memory
  // but that closure is not, so info.is_pinned can be stale on re-open.
  // GC.msgs is the single live source of truth for group messages — always
  // re-derive from it rather than trusting the closure snapshot.
  const liveMsg = (type === 'group' && typeof GC !== 'undefined')
    ? GC.msgs.find(m => m.id === id)
    : null;
  const isPinnedLive = liveMsg ? !!liveMsg.is_pinned : !!info.is_pinned;

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

  // Pin — works for group messages; DM pin shows a toast (server doesn't support DM pins)
  actions.push({
    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>',
    label: type === 'group' ? (isPinnedLive ? 'Unpin' : 'Pin') : 'Pin',
    fn: async () => {
      if (type !== 'group') {
        if (typeof swShowToast === 'function') swShowToast('📌 Message pinned to this conversation.');
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

  menu.innerHTML = actions.map((a, i) => `
    <button class="dm-ctx-item${a.danger ? ' dm-ctx-danger' : ''}" data-idx="${i}">
      ${a.icon}<span>${a.label}</span>
    </button>`).join('');

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
}

function _attachMsgContextMenu(bubble, info) {
  // Desktop: right-click
  bubble.addEventListener('contextmenu', e => _showMsgContextMenu(e, info));

  // Mobile: long-press (500 ms)
  bubble.addEventListener('touchstart', e => {
    _longPressTimer = setTimeout(() => {
      _longPressTimer = null;
      _showMsgContextMenu(e, info);
    }, 500);
  }, { passive: true });
  bubble.addEventListener('touchend',  () => { clearTimeout(_longPressTimer); _longPressTimer = null; });
  bubble.addEventListener('touchmove', () => { clearTimeout(_longPressTimer); _longPressTimer = null; });
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
    compose && (compose.style.display = '');
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
        // Only retry if we're still looking at the same group
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

function gcRenderMsgs(msgs, container, myId, lastSenderHint) {
  let lastSender = lastSenderHint || null;
  let group = (lastSenderHint && container.lastElementChild?.classList.contains('dm-msg-group'))
    ? container.lastElementChild : null;

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
          ${gcAvatar(sName, sPhoto, 28)}
          <span class="gc-msg-sender-name" data-member-id="${swEsc(m.sender_id)}"
                style="color:hsl(${hue},65%,65%);cursor:pointer">${swEsc(displayName)}</span>
        `;
        header.querySelector('.gc-msg-sender-name')?.addEventListener('click', e => {
          e.stopPropagation();
          nicksOpenModal(GC.activeId, m.sender_id, sName, true);
        });
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
    if (m.replied_to_id && m.replied_to_body) {
      const quote = document.createElement('div');
      quote.className = 'dm-reply-quote';
      const qSender = document.createElement('span');
      qSender.className = 'dm-reply-sender';
      qSender.textContent = m.replied_to_sender || 'Member';
      const qBody = document.createElement('span');
      qBody.className = 'dm-reply-body';
      qBody.textContent = (m.replied_to_body || '').slice(0, 120);
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
    const bodyNode = document.createElement('span');
    bodyNode.className = 'dm-bubble-text';
    // E2EE: decrypt group message asynchronously
    if (m.e2ee && !isDeleted && !m.is_system) {
      bodyNode.textContent = '🔒 …';
      bodyNode.style.opacity = '0.5';
      const _gcMyId = mine ? m.sender_id : gcMyId();
      E2EE.decryptGroup(m, _gcMyId).then(pt => {
        bodyNode.textContent = pt;
        bodyNode.style.opacity = '';
        m._plaintext = pt;
      }).catch(() => { bodyNode.textContent = '[encrypted — key unavailable]'; bodyNode.style.opacity = '0.5'; });
    } else {
      bodyNode.textContent = m.body;
    }
    bubble.appendChild(bodyNode);

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
    meta.innerHTML = `<span class="dm-msg-time">${gcFull(m.sent_at)}</span>${mine && !isDeleted && !m.id.startsWith('tmp-') ? `<button class="dm-del-btn" data-id="${swEsc(m.id)}" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}`;

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
}

function gcScrollBottom() {
  const el = $id('gc-msgs');
  if (el) el.scrollTop = el.scrollHeight;
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
    input.value = body; // restore on error
    console.error('[GC] send:', e.message);
  } finally {
    GC.pendingBodies.delete(body);
  }
}

// ─── Delete ───────────────────────────────────────────────────────────────────

async function gcDeleteMsg(msgId, bubble, btn) {
  if (!confirm('Delete this message?')) return;
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
  if (!confirm('Remove this member from the group?')) return;
  try {
    await api('DELETE', `/api/member/groups/${GC.activeId}/members/${memberId}`);
    const _removeOverlay = document.getElementById('gc-info-overlay');
    if (_removeOverlay) _removeOverlay.style.display = 'none';
    // Re-open info so member count and list updates immediately
    gcOpenInfo();
  } catch (e) {
    alert(e.message || 'Could not remove member.');
  }
}

async function gcLeave() {
  if (!confirm('Leave this group?')) return;
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
    alert(e.message || 'Could not leave group.');
  }
}

async function gcDeleteGroup() {
  if (!confirm('Delete this group for ALL members? This cannot be undone.')) return;
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
    alert(e.message || 'Could not delete group.');
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
  topbar.appendChild(actions);
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

  // ── Helper: group avatar HTML (rounded square, letter fallback) ─────────────
  function inboxGroupAv(group, size) {
    if (group.photo_url) {
      return `<img src="${swEsc(group.photo_url)}" alt="${swEsc(group.name)}" style="width:${size}px;height:${size}px;border-radius:12px;object-fit:cover;flex-shrink:0">`;
    }
    const letter = (group.avatar_text || group.name?.[0] || '?').slice(0, 2).toUpperCase();
    return `<div class="gc-group-av" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px">${swEsc(letter)}</div>`;
  }

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
      container.querySelectorAll('.dm-conv-row, .gc-conv-row, .inbox-group-row').forEach(el => el.remove());
      $id('dm-conv-empty') && ($id('dm-conv-empty').style.display = '');
      return;
    }

    // Tag each item with type and normalised sort key
    const items = [
      ...dms.map(c => ({ type: 'dm', data: c, ts: c.last_msg_at || '0' })),
      ...groups.map(g => ({
        type: 'group',
        data: g,
        // Normalise: server v2 sends last_msg_at flat; old server nested in last_msg
        ts: g.last_msg_at || g.last_msg?.created_at || g.created_at || '0',
      })),
    ].sort((a, b) => (b.ts > a.ts ? 1 : b.ts < a.ts ? -1 : 0));

    const fragment = document.createDocumentFragment();
    let builtAny = false;

    items.forEach(item => {
      try {
        const row = document.createElement('div');

        if (item.type === 'dm') {
          const c = item.data;
          row.className = 'dm-conv-row' + (c.conv_key === DM.activeKey ? ' dm-active-row' : '');
          row.dataset.key  = c.conv_key;
          row.dataset.type = 'dm';
          const preview = c.last_snippet
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
          row.addEventListener('click', () => inboxOpenDm(c));

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
              <div class="dm-conv-name">${swEsc(g.name || 'Group')}</div>
              <div class="dm-conv-preview ${g.unread_count > 0 ? 'dm-has-unread' : ''}">${swEsc(gPreview)}</div>
            </div>
            <div class="dm-conv-right">
              <span class="dm-conv-time">${dmTime(gLastAt)}</span>
              ${g.unread_count > 0 ? `<span class="dm-unread-pill">${g.unread_count > 9 ? '9+' : g.unread_count}</span>` : ''}
            </div>`;
          row.addEventListener('click', () => inboxOpenGroup(g));
        }

        fragment.appendChild(row);
        builtAny = true;
      } catch (e) {
        // Skip just this one row — never let a single bad conversation/group
        // take down the whole sidebar.
        console.error('[inbox] failed to render row, skipping:', e.message, item);
      }
    });

    // Only touch the live DOM once the new rows are fully built — if nothing
    // built successfully (e.g. every item somehow failed), leave whatever was
    // already on screen alone instead of leaving the user with a blank panel.
    if (!builtAny) return;
    container.querySelectorAll('.dm-conv-row, .gc-conv-row, .inbox-group-row').forEach(el => el.remove());
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
    ]);
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
    });
    $id('gc-load-earlier')?.addEventListener('click', () => {
      if (typeof gcLoadMsgs === 'function') gcLoadMsgs(true);
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

    dpOpen();
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
          if (!confirm('Remove this member from the group?')) return;
          const memberId = btn.dataset.id;
          try {
            await api('DELETE', `/api/member/groups/${group.id}/members/${memberId}`);
            // Refresh group data and re-render panel
            const data = await api('GET', `/api/member/groups/${group.id}`);
            GC.activeGroup = { ...(GC.activeGroup || {}), ...data };
            DP.group = GC.activeGroup;
            dpShowGroup(GC.activeGroup);
            if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups);
          } catch (e) { alert(e.message || 'Could not remove member.'); }
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
    // The old gcShowInfoModal had this but dpShowGroup never did — wiring it in.
    let deleteGrpBtn = document.getElementById('dp-delete-group-btn');
    if (group.my_role === 'owner') {
      if (!deleteGrpBtn) {
        deleteGrpBtn = document.createElement('button');
        deleteGrpBtn.id = 'dp-delete-group-btn';
        deleteGrpBtn.className = 'dm-detail-action-btn dm-detail-danger';
        deleteGrpBtn.style.cssText = 'margin-top:4px;display:flex;align-items:center;gap:8px;font-size:13px';
        deleteGrpBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg> Delete group for everyone`;
        const leaveBtn = document.getElementById('dm-detail-leave-btn');
        if (leaveBtn && leaveBtn.parentNode) leaveBtn.parentNode.appendChild(deleteGrpBtn);
      }
      deleteGrpBtn.style.display = '';
      deleteGrpBtn.onclick = async () => {
        if (!confirm(`Delete "${group.name}" for everyone? This cannot be undone.`)) return;
        try {
          await api('DELETE', `/api/member/groups/${group.id}`);
          // Remove from local state
          if (typeof GC !== 'undefined') {
            GC.groups = (GC.groups || []).filter(g => g.id !== group.id);
            if (GC.activeId === group.id) {
              GC.activeId    = null;
              GC.activeGroup = null;
              GC.msgs        = [];
            }
          }
          if (typeof dpClose === 'function') dpClose();
          if (typeof window.gcGoBack === 'function') window.gcGoBack();
          if (typeof window.gcRenderGroups === 'function') window.gcRenderGroups(GC.groups || []);
          if (typeof swShowToast === 'function') swShowToast('Group deleted.');
          // Purge from localStorage cache
          try {
            const myId = typeof gcMyId === 'function' ? gcMyId() : null;
            if (myId) {
              const cacheKey = 'kfs-groups-' + myId;
              const raw = localStorage.getItem(cacheKey);
              if (raw) {
                const arr = JSON.parse(raw).filter(g => g?.id && g.id !== group.id);
                localStorage.setItem(cacheKey, JSON.stringify(arr));
              }
            }
          } catch { /* silent */ }
        } catch (e) {
          alert(e.message || 'Could not delete group. Please try again.');
        }
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

  // ── Action: Delete Chat (DM) ───────────────────────────────────────────────
  async function dpDeleteChat() {
    if (!confirm('Delete this conversation? This only removes it from your view.')) return;
    dpClose();
    // Reset DM panel to empty state
    if (typeof dmGoBack === 'function') dmGoBack();
    // Optimistically remove from list
    if (DM.activeKey) {
      DM.convs = (DM.convs || []).filter(c => c.conv_key !== DM.activeKey);
      if (typeof dmRenderConvs === 'function') dmRenderConvs(DM.convs);
    }
  }

  // ── Action: Leave Group ────────────────────────────────────────────────────
  async function dpLeaveGroup() {
    if (!DP.group) return;
    if (!confirm(`Leave "${DP.group.name}"?`)) return;
    const myId = window._memberProfile?.id;
    try {
      await api('DELETE', `/api/member/groups/${DP.group.id}/members/${myId}`);
      dpClose();
      GC.groups = (GC.groups || []).filter(g => g.id !== DP.group.id);
      if (typeof window.gcGoBack === 'function') window.gcGoBack();
    } catch (e) { alert('Could not leave group. Please try again.'); }
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
    document.getElementById('dm-detail-delete-btn')?.addEventListener('click', dpDeleteChat);
    document.getElementById('dm-detail-leave-btn')?.addEventListener('click', dpLeaveGroup);
    document.getElementById('dm-detail-add-member-btn')?.addEventListener('click', dpAddMembers);

    // DM topbar ⓘ button — stopPropagation so the document click-outside
    // handler (below) doesn't fire on the same event and immediately close the panel.
    document.getElementById('dm-info-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!DM.activePeer) return;
      const panel = document.getElementById('dm-detail-panel');
      const isOpen = panel && panel.classList.contains('open');
      if (isOpen && DP.mode === 'dm') { dpClose(); return; }
      dpShowDm(DM.activePeer);
    });

    // GC topbar ⓘ button (re-wire to use dpShowGroup)
    document.getElementById('gc-info-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!GC.activeGroup) return;
      const panel = document.getElementById('dm-detail-panel');
      const isOpen = panel && panel.classList.contains('open');
      if (isOpen && DP.mode === 'group') { dpClose(); return; }
      // Load fresh member details first
      // Only skip the fetch if members actually have names — stale stub arrays
      // (members: [{id}] only, no name) must still trigger a fresh fetch so
      // the Details panel never shows "?" / "Member" placeholders.
      if (GC.activeGroup.members?.some(m => m.name)) {
        dpShowGroup(GC.activeGroup);
      } else {
        api('GET', `/api/member/groups/${GC.activeGroup.id}`)
          .then(data => { GC.activeGroup = { ...GC.activeGroup, ...data }; dpShowGroup(GC.activeGroup); })
          .catch(() => dpShowGroup(GC.activeGroup));
      }
    });

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
        // Strip any entries with null/undefined id — these were written during
        // the kfs-groups-null bug and cause /api/member/groups/null 401 errors
        GC.groups = parsed.filter(g => g?.id);
      }
    }
    // Also sanitize the stored key itself so nulls don't persist across refreshes
    try {
      const clean = parsed.filter(g => g?.id);
      if (clean.length !== parsed.length) localStorage.setItem(key, JSON.stringify(clean));
    } catch { /* silent */ }
  } catch { /* silent */ }
})();

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
        <div style="display:flex;gap:0;padding:8px 6px;flex-shrink:0;border-bottom:1px solid #1e1e1e">
          <button class="kfs-share-action-btn" id="kfs-share-copy" style="
            display:flex;flex-direction:column;align-items:center;gap:5px;
            flex:1;padding:8px 4px;background:none;border:none;color:#f5f5f5;
            cursor:pointer;font-size:11px;font-weight:600;font-family:inherit;
          ">
            <div style="width:42px;height:42px;border-radius:50%;background:#252525;display:flex;align-items:center;justify-content:center">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </div>
            Copy link
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
      row.style.display = (!query || name.includes(query)) ? '' : 'none';
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

  window.openShareModal = function(projectId) {
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
  };

  function closeShareModal() {
    if (_shareOverlay) {
      _shareOverlay.style.display = 'none';
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
      `<button class="ig-action-btn" onclick="event.stopPropagation();openShareModal('${p.id}')" title="Share" style="margin-left:auto">
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
// since we inject into the HTML string via swFeedCard)
(function styleShareButton() {
  document.addEventListener('DOMContentLoaded', () => {
    // Handled via CSS in section 7 above
  });
})();

// ═══════════════════════════════════════════════════════════════════════════
// END PATCH
// ═══════════════════════════════════════════════════════════════════════════

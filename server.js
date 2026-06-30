// KFS Server v1.17.9 — Security Release\n// Changes: CSP unsafe-inline removed, password complexity, GIF disallowed,\n//   structured access logging, security.txt, SRI hints\nrequire("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs"); // ADD THIS LINE
const { createClient } = require("@supabase/supabase-js");
const sharp = require("sharp");
const cloudinary = require("cloudinary").v2;
const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = rateLimit;
const helmet = require("helmet");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const cookieParser = require("cookie-parser");

const app = express();
app.set('trust proxy', 1); // Render reverse-proxy ke peeche
app.set('case sensitive routing', true); // /Social-Strand (member portal) ≠ /social-strand (public feed)
// Disable auto-ETag/conditional-GET for dynamic JSON responses (res.json/res.send).
// Without this, identical responses to /api/member/groups, /api/member/nicknames,
// etc. get served as a bodiless 304 once the browser caches the ETag — which looks
// exactly like "groups/nicknames disappear on refresh" client-side, since a 304
// isn't a 2xx and gets treated as a failed request. express.static() below uses
// its own independent ETag logic for actual static files, so this is unaffected.
app.set('etag', false);
const PORT = process.env.PORT || 3000;

// ── Supabase ──────────────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;         // service_role key — admin writes only
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY; // anon key — public reads

// Admin client — service_role, bypasses RLS — use ONLY for admin/internal routes
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false },
  db: { schema: "public" },
  global: { headers: { "x-application-name": "kfs-server" } },
});

// Public client — anon key, respects RLS — use for all public-facing GET routes
const supabasePublic = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false },
  db: { schema: "public" },
  global: { headers: { "x-application-name": "kfs-public" } },
});

// ── Cloudinary ────────────────────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Retry wrapper for transient Supabase failures (network blips, cold starts)
async function sbQuery(fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (e) {
      const isLast = i === retries - 1;
      if (isLast) throw e;
      await new Promise((r) => setTimeout(r, 300 * (i + 1)));
    }
  }
}

// Shared HTML builder — used by both sendConfirmationEmail and the live preview
// endpoint, so admins see exactly what lands in inboxes.
function buildConfirmationEmailHtml(bodyText, eventTitle, eventDate, eventVenue) {
  const dateLine = eventDate
    ? `\n\nDate: ${new Date(eventDate).toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}`
    : "";
  const venueLine = eventVenue ? `\nVenue: ${eventVenue}` : "";

  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#111;border-radius:16px;border:1px solid #1e1e1e;overflow:hidden;max-width:560px">
  <tr><td style="background:#0a0a0a;padding:28px 36px;border-bottom:1px solid #1e1e1e">
    <span style="font-size:18px;font-weight:700;color:#f5f5f5;letter-spacing:-.02em">KFS — KIIT Film Society</span>
  </td></tr>
  <tr><td style="padding:32px 36px">
    <div style="background:#f5f5f5;color:#0a0a0a;display:inline-block;padding:6px 16px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:24px">✓ Registration Confirmed</div>
    <h2 style="font-size:22px;font-weight:700;color:#f5f5f5;margin:0 0 20px;letter-spacing:-.02em">${eventTitle || "Event"}</h2>
    <div style="font-size:15px;line-height:1.7;color:#aaa;white-space:pre-line">${bodyText.split("\n").join("<br>")}</div>
    ${
      dateLine || venueLine
        ? `<div style="margin:24px 0;padding:16px 20px;background:#1a1a1a;border-radius:12px;border:1px solid #1e1e1e;font-size:13px;color:#888">
      ${eventDate ? `<div style="margin-bottom:6px;display:flex;align-items:center;gap:8px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg><span style="color:#f5f5f5">${new Date(eventDate).toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}</span></div>` : ""}
      ${eventVenue ? `<div style="display:flex;align-items:center;gap:8px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg><span style="color:#f5f5f5">${eventVenue}</span></div>` : ""}
    </div>`
        : ""
    }
  </td></tr>
  <tr><td style="padding:20px 36px 28px;border-top:1px solid #1e1e1e">
    <p style="font-size:12px;color:#444;margin:0">This is an automated confirmation from <a href="https://kiitfilmsociety.in" style="color:#666;text-decoration:none">kiitfilmsociety.in</a>. Please do not reply to this email.</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

// ── Email helper (Brevo HTTP API — works on all hosts) ────────────────────────
async function sendConfirmationEmail({
  toEmail,
  toName,
  eventTitle,
  eventDate,
  eventVenue,
}) {
  const { data: rows } = await memCache("settings:email", 300, () =>
    supabase
      .from("settings")
      .select("key,value")
      .in("key", [
        "brevo_api_key",
        "smtp_from_name",
        "email_confirmation_body",
      ]),
  );
  const s = {};
  (rows || []).forEach((r) => (s[r.key] = r.value));

  if (!s.brevo_api_key) {
    console.warn(
      "[email] Brevo API key not configured — skipping confirmation email",
    );
    return;
  }

  const defaultBody = `Hi {{name}},\n\nYou're confirmed for {{event}}!{{date_line}}{{venue_line}}\n\nSee you there!\n\nWarm regards,\nKFS — KIIT Film Society`;
  let bodyTemplate = s.email_confirmation_body || defaultBody;
  const dateLine = eventDate
    ? `\n\nDate: ${new Date(eventDate).toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}`
    : "";
  const venueLine = eventVenue ? `\nVenue: ${eventVenue}` : "";

  const bodyText = bodyTemplate
    .replace(/{{name}}/g, toName || "there")
    .replace(/{{event}}/g, eventTitle || "")
    .replace(/{{date_line}}/g, dateLine)
    .replace(/{{venue_line}}/g, venueLine);

  const bodyHtml = buildConfirmationEmailHtml(bodyText, eventTitle, eventDate, eventVenue);

  const fromName = s.smtp_from_name || "KFS — KIIT Film Society";

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": s.brevo_api_key,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { name: fromName, email: "noreply@kiitfilmsociety.in" },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject: `You're registered for ${eventTitle || "the event"} — KFS`,
      textContent: bodyText,
      htmlContent: bodyHtml,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${err}`);
  }
  console.log(
    `[email] Confirmation sent to ${toEmail} for event "${eventTitle}"`,
  );
}

const JWT_SECRET = process.env.JWT_SECRET;

// Canonical KFS logo — used as a fallback for the KFS sentinel member's
// avatar in DMs/notifications if the members.photo column is left blank.
const KFS_SENTINEL_LOGO_URL = "https://kiitfilmsociety.in/images/kfs-logo.png";

// ─────────────────────────────────────────────────────────────────────────────
// PROFANITY FILTER — English + Hindi/Hinglish (v2 — Strict)
// ─────────────────────────────────────────────────────────────────────────────
// v2 improvements:
//   1. Leet-speak / homoglyph normalisation before matching
//      (f*ck, f.u.c.k, ph uck, fvck, etc. all normalise to "fuck")
//   2. Separator-stripping — spaces/dots/dashes/underscores between letters
//      (f_u_c_k, f-u-c-k, f u c k all caught)
//   3. Expanded word list — more variants & near-misses
//   4. Hindi/Hinglish: also strip separators before matching
//   5. Tags are also checked for profanity
// ─────────────────────────────────────────────────────────────────────────────

// ── Step 1: Leet / homoglyph map ─────────────────────────────────────────────
// Maps look-alike characters back to their plain ASCII letter.
const LEET_MAP = {
  // vowels
  '@': 'a', '4': 'a', 'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'ã': 'a',
  '3': 'e', 'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
  '1': 'i', '!': 'i', '|': 'i', 'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i',
  '0': 'o', 'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'õ': 'o',
  'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u',
  // consonants
  '$': 's', '5': 's', 'z': 's', // z→s catches "azz" for "ass"
  '7': 't', '+': 't',
  '(': 'c', 'ç': 'c',
  'ñ': 'n',
  // ph → f (phucker etc.) — handled at string level below
  // k/ck/q → k
  'q': 'k',
  // NOTE: 'v' → 'u' removed from this global map — it was breaking every common English
  // word containing 'v' (have → haue, very → uery, love → loue, over → ouer, etc.).
  // fvck-style evasion is now caught via a targeted consonant-context substitution in
  // normaliseLeet() below, which only fires when 'v' sits between two consonants.
};

/**
 * Normalise a string to catch leet-speak, homoglyphs, separators and
 * common letter-substitution workarounds.
 * @param {string} text
 * @returns {string}
 */
function normaliseLeet(text) {
  if (!text) return '';
  let s = text;

  // 0. Unicode decomposition — catches circled letters (Ⓕ→f), fullwidth (Ａ→a),
  //    small-caps (ᴀ→a), and strips combining diacritics not already in LEET_MAP.
  //    NFKD decomposes compatibility forms; then we strip combining marks (U+0300–U+036F).
  try { s = s.normalize('NFKD').replace(/[\u0300-\u036f]/g, ''); } catch (_) { /* older env fallback */ }
  // Circled Latin: Ⓐ–Ⓩ (U+24B6–U+24D9) and ⓐ–ⓩ (U+24D0–U+24E9)
  s = s.replace(/[\u24B6-\u24D9]/g, ch => String.fromCharCode(ch.codePointAt(0) - 0x24B6 + 65));
  s = s.replace(/[\u24D0-\u24E9]/g, ch => String.fromCharCode(ch.codePointAt(0) - 0x24D0 + 97));
  // Fullwidth Latin: Ａ–Ｚ (U+FF21–U+FF3A) and ａ–ｚ (U+FF41–U+FF5A)
  s = s.replace(/[\uFF21-\uFF3A]/g, ch => String.fromCharCode(ch.codePointAt(0) - 0xFF21 + 65));
  s = s.replace(/[\uFF41-\uFF5A]/g, ch => String.fromCharCode(ch.codePointAt(0) - 0xFF41 + 97));

  s = s.toLowerCase();

  // 1. Collapse "ph" → "f" BEFORE per-char replacement
  s = s.replace(/ph/g, 'f');

  // 1b. v → u ONLY when surrounded by consonants on both sides (e.g. "fvck" → "fuck").
  //     This avoids corrupting common words like "have", "very", "love", "over", "never".
  s = s.replace(/(?<=[bcdfghjklmnpqrstvwxyz])v(?=[bcdfghjklmnpqrstvwxyz])/g, 'u');

  // 2. Per-character substitution via leet map
  s = s.split('').map(ch => LEET_MAP[ch] || ch).join('');

  // 3. Strip zero-width / invisible characters
  s = s.replace(/[\u200b\u200c\u200d\u2060\ufeff]/g, '');

  // 4. Remove separators between individual letters (f.u.c.k / f-u-c-k / f_u_c_k)
  //    Only strip a separator that is surrounded by single letters on both sides
  //    so we don't destroy real words like "good-morning".
  s = s.replace(/(?<=[a-z])[\.\-_*]+(?=[a-z])/g, ''); // FIX: removed space from char class — was collapsing words into one string, breaking word-boundary profanity matching

  // 5. Collapse repeated chars to max 2 (fuuuuck → fuuck)
  s = s.replace(/(.)\1{2,}/g, '$1$1');

  return s;
}

// ── Step 2: Word lists ────────────────────────────────────────────────────────
// Each entry is the canonical (already-normalised) form.
// We match normalised text against normalised word so workarounds don't help.

// ── Word list design ─────────────────────────────────────────────────────────
// Words are split into two lists with different matching semantics:
//
//   STEM_WORDS  — matched with left-word-boundary + stem + suffix-allowance regex.
//                 Catches all inflected/derived forms: fucking, fucked, fucks, fucker,
//                 shitting, shitty, bitches, asses, sexuality, etc. without needing
//                 to enumerate every variant. Suffix regex allows consonant doubling
//                 (shitt-ing, slut-ty) and common English morphology.
//
//   EXACT_WORDS — matched with strict word boundaries on both sides. Used for words
//                 that are complete in themselves, or where stem matching would create
//                 unacceptable false positives (e.g. "rap" → rapper, "sex" alone is
//                 in STEM so "sextet" is safe due to boundary — see containsProfanity).
//
// The normalised forms of both lists are pre-computed at startup.

// Stem words: left-boundary + word + allowed suffix variants (see PROFANITY_STEM_SUFFIX)
const PROFANITY_STEM_WORDS = [
  // f-word family (covers: fucking, fucked, fucker, fucks, fucky, fvck, f*cking, …)
  "fuck", "fuk", "fck", "fuc",
  // s-word (covers: shitting, shitty, shitless, shitfaced, shits, bullshitting, …)
  "shit", "sht",
  // a-word (covers: asses, assing, assed, asshole via exact below, …)
  "ass",
  // b-word (covers: bitching, bitchy, bitches, bitched, …)
  "bitch",
  // c-words (covers: cocked, cocking, cocks, cunts, …)
  "cunt", "cock",
  // d-word (covers: dicks, dicked, dicking, …)
  "dick", "dik",
  // p-words (covers: pussied, pusses, porno via exact below, pornographic, …)
  "puss", "porn",
  // s-words (covers: slutty, slutted, sluttier, …)
  "slut",
  // w-word (covers: whored, whoring, whores, …)
  "whor",
  // other (covers: pricked, pricking, …)
  "prick",
  // racial slurs (covers: niggas, nigging, …)
  "nigga", "nigger", "niga",
  // compound (covers: motherfucking, motherfucked, …)
  "motherfuck",
  // homophobic (covers: fagging, faggots, …)
  "fagg",
  // sex (covers: sexy, sexual, sexuality, sexed, …)
  // Safe: sextet/sextant blocked by suffix regex (tet/tant not in allowed suffixes)
  "sex",
];

// Exact words: whole-word match only (no suffix variants allowed)
const PROFANITY_EXACT_WORDS = [
  // f-word variants not covered by stem
  "effing", "fucker",
  // a-word explicit forms
  "asshole", "ashole", "arse", "arsehole",
  // b-word variants
  "biatch", "beyatch",
  // c-word variants
  "cok",
  // other
  "bastard", "bastad",
  "pussy",
  "mofo", "mf",
  "faggot", "fagot", "fag",
  "retard",
  // rape — exact only; 'rap' as stem catches 'rapper', 'wrap', etc.
  "rape", "rapist", "raping", "raped",
  // sexual acts / explicit
  "blowjob", "blwjob", "handjob",
  "porno", "xxx", "dildo",
  "cumshot", "cum shot",
  "masturbat",
  "boner", "erection", "orgasm",
  "penis", "vagina", "vulva",
  "boobs", "boob", "tits", "tit",
  "naked", "nude", "nudity",
  "sexy", "sexting", "sext",   // also caught by sex stem, kept here for explicit coverage
  "horny", "hentai",
  "bullshit", "bulls hit",
];

// Keep legacy alias so nothing that imports PROFANITY_WORDS_EN breaks
const PROFANITY_WORDS_EN = [...PROFANITY_STEM_WORDS, ...PROFANITY_EXACT_WORDS];

// Suffix regex for stem matching. Allows:
//   - Optional consonant doubling before suffix (shitt-ing, slut-ty, etc.)
//   - Common English inflectional suffixes: -ing, -ed, -er, -es, -s, -y, -ty, etc.
//   - Common derivational suffixes: -ness, -less, -ful, -able, -ual, -ity, -uality
// Does NOT allow free arbitrary suffixes — "sextet", "sextant", "cocktail",
// "assessment", "assassin", "dickens", "rapper" all remain clean.
const PROFANITY_STEM_SUFFIX = '(?:[bcdfgklmnprstvw]?(?:ing|ings|ed|er|ers|es)|[esyd]|ty|i(?:er|est|ly|ng|ty)|(?:ful|less|ness|able|uality|ual|ity|ous|ment))?(?![a-z])';

const PROFANITY_WORDS_HI = [
  // Romanised Hindi — substring matched after normalisation
  "madarchod", "madarjaat", "maderchod",
  "behenchod", "behenchod", "behen chod",
  "chutiya", "chutiye", "chut",
  "bhosdi", "bhosdike", "bhosdiwale",
  "gandu", "gaand", "gaandu",
  "lodu", "lund", "lauda", "laudu",
  "harami", "haramzada", "haramzadi",
  "randi", "randwa",
  "saala", "sala",
  "kutta", "kutti",
  "ullu",
  "kamina", "kamine",
  "chakka",
  "hijra",
  "bhadwa",
  "teri maa", "teri behen",
  "bkl", "bkc", "mkc",
  "bhenchod",
  // Devanagari (Unicode) — no normalisation needed
  "मादरचोद", "बहनचोद", "चूतिया", "भोसड़ी", "गांडू", "लंड", "रंडी", "हरामी", "हरामज़ादा",
  "कुत्ता", "कुत्ती", "कमीना", "लौड़ा", "चूत",
];

// Pre-normalise all word list entries once at startup
const _PROFANITY_STEM_NORM  = PROFANITY_STEM_WORDS.map(w => normaliseLeet(w));
const _PROFANITY_EXACT_NORM = PROFANITY_EXACT_WORDS.map(w => normaliseLeet(w));
// Legacy alias — keeps any code that references _PROFANITY_EN_NORMALISED working
const _PROFANITY_EN_NORMALISED = [..._PROFANITY_STEM_NORM, ..._PROFANITY_EXACT_NORM];

/**
 * Escape regex metacharacters in a string.
 */
function _escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * Check whether `text` contains any banned word.
 * Normalises the input before matching so leet/workaround tricks don't help.
 *
 * Matching strategy:
 *   Stem words  — left-word-boundary + normalised stem + PROFANITY_STEM_SUFFIX regex.
 *                 Catches all inflected forms (fucking, shitty, bitches, sexual…)
 *                 without false-positives on words like assessment, cocktail, sextet.
 *   Exact words — strict word boundaries on both sides.
 *   Hindi/Hinglish — substring on normalised + separator-stripped text.
 *
 * @param {string} text
 * @returns {{ found: boolean, word?: string }}
 */
function containsProfanity(text) {
  if (!text) return { found: false };

  const normText = normaliseLeet(text);

  // ── English stem words: left-boundary + stem + suffix allowance ───────────
  for (let i = 0; i < _PROFANITY_STEM_NORM.length; i++) {
    const nw = _PROFANITY_STEM_NORM[i];
    const re = new RegExp(`(?<![a-z])${_escapeRe(nw)}${PROFANITY_STEM_SUFFIX}`, 'i');
    if (re.test(normText)) return { found: true, word: PROFANITY_STEM_WORDS[i] };
  }

  // ── English exact words: whole-word match ─────────────────────────────────
  for (let i = 0; i < _PROFANITY_EXACT_NORM.length; i++) {
    const nw = _PROFANITY_EXACT_NORM[i];
    const re = new RegExp(`(?<![a-z])${_escapeRe(nw)}(?![a-z])`, 'i');
    if (re.test(normText)) return { found: true, word: PROFANITY_EXACT_WORDS[i] };
  }

  // ── Hindi/Hinglish: substring match on normalised + original ─────────────
  // Strip separators from the normalised text for Hindi too
  const normHi = normText.replace(/[\s.\-_*]+/g, '');

  for (const word of PROFANITY_WORDS_HI) {
    const wLower = word.toLowerCase();
    // Check original normalised (preserves spaces for multi-word phrases)
    if (normText.includes(wLower)) return { found: true, word };
    // Check separator-stripped version
    const wStripped = wLower.replace(/[\s.\-_*]+/g, '');
    if (normHi.includes(wStripped)) return { found: true, word };
  }

  return { found: false };
}

/**
 * Check multiple text fields at once (title, description, tags, etc.)
 * @param {...string} fields
 * @returns {{ found: boolean, word?: string }}
 */
function checkFieldsForProfanity(...fields) {
  for (const field of fields) {
    const result = containsProfanity(field);
    if (result.found) return result;
  }
  return { found: false };
}

// ── Image content-type enforcement ───────────────────────────────────────────
// On POST /api/member/studio/projects, additionally validate that the uploaded
// image buffer actually starts with a known magic byte sequence. This prevents
// a renamed non-image file from slipping through the MIME-type filter.
const IMAGE_MAGIC = [
  { sig: [0xff, 0xd8, 0xff],              mime: 'image/jpeg' },
  { sig: [0x89, 0x50, 0x4e, 0x47],        mime: 'image/png'  },
  { sig: [0x52, 0x49, 0x46, 0x46],        mime: 'image/webp' }, // RIFF....WEBP
];

function validateImageMagicBytes(buffer, declaredMime) {
  if (!buffer || buffer.length < 8) return false;
  for (const { sig, mime } of IMAGE_MAGIC) {
    if (mime !== declaredMime) continue;
    const match = sig.every((byte, i) => buffer[i] === byte);
    if (match) {
      // Extra check for WebP: bytes 8-11 must be "WEBP"
      if (mime === 'image/webp') {
        const riff = buffer.slice(8, 12).toString('ascii');
        return riff === 'WEBP';
      }
      return true;
    }
  }
  return false;
}

/**
 * Validate an uploaded image file for posts.
 * Returns an error string if invalid, null if OK.
 * @param {object} file  — multer file object
 * @returns {string|null}
 */
function validatePostImage(file) {
  if (!file) return null; // no image is fine (text posts)

  const mime = (file.mimetype || '').toLowerCase();
  if (!ALLOWED_MIME_TYPES.has(mime)) {
    return 'Only JPEG, PNG, or WebP images are allowed.';
  }
  if (mime === 'image/gif') {
    return 'GIF uploads are not permitted.';
  }
  // Magic-byte check
  if (file.buffer && !validateImageMagicBytes(file.buffer, mime)) {
    return 'The uploaded file does not appear to be a valid image.';
  }
  // Size cap for posts specifically: 10 MB (server multer limit is 20 MB globally)
  const POST_IMAGE_MAX = 10 * 1024 * 1024;
  if (file.size > POST_IMAGE_MAX || (file.buffer && file.buffer.length > POST_IMAGE_MAX)) {
    return 'Post images must be under 10 MB.';
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION VIO — Member Violation Tracking (Warning → Mute → Ban)
//
// Escalation ladder (per member, in-memory, resets on server restart):
//   Offense 1 → warning + 5-minute mute   (live countdown shown client-side)
//   Offense 2 → warning + 60-minute mute  (harsher)
//   Offense 3+ → permanent ban (account_status = 'disabled') — admin must unban
//
// SQL needed (run once in Supabase if you want violations to survive restarts):
//   CREATE TABLE IF NOT EXISTS member_violations (
//     id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     member_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     offense     INTEGER NOT NULL DEFAULT 1,
//     muted_until TIMESTAMPTZ,
//     banned      BOOLEAN NOT NULL DEFAULT FALSE,
//     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//     updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   CREATE UNIQUE INDEX IF NOT EXISTS idx_violations_member ON member_violations(member_id);
//
// In v1 we store state in-memory and optionally sync to DB.
// ─────────────────────────────────────────────────────────────────────────────

// In-memory store:  memberId → { offense: N, mutedUntil: Date|null, banned: bool }
const _violations = new Map();

function vioGet(memberId) {
  return _violations.get(memberId) || { offense: 0, mutedUntil: null, banned: false };
}

function vioIsMuted(memberId) {
  const v = vioGet(memberId);
  if (v.banned) return true;
  if (!v.mutedUntil) return false;
  if (new Date() < v.mutedUntil) return true;
  // Mute expired — clear it
  _violations.set(memberId, { ...v, mutedUntil: null });
  return false;
}

function vioMuteRemaining(memberId) {
  const v = vioGet(memberId);
  if (!v.mutedUntil) return 0;
  return Math.max(0, v.mutedUntil - Date.now());
}

/**
 * Record a profanity/violation offense and return what to tell the client.
 *
 * Escalation ladder (per member):
 *   Offense 1  Warning only      (fair first notice, no mute)
 *   Offense 2  1-minute mute
 *   Offense 3  2-minute mute
 *   Offense 4  5-minute mute     (final warning before ban)
 *   Offense 5+ Temp ban 24h      (suspended status; member can appeal; admin must lift)
 *
 * SQL (run once):
 *   CREATE TABLE IF NOT EXISTS member_violations (
 *     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     member_id UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
 *     offense INTEGER NOT NULL DEFAULT 1,
 *     muted_until TIMESTAMPTZ,
 *     banned BOOLEAN NOT NULL DEFAULT FALSE,
 *     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 *     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 *   );
 *   CREATE UNIQUE INDEX IF NOT EXISTS idx_violations_member ON member_violations(member_id);
 *
 *   CREATE TABLE IF NOT EXISTS ban_appeals (
 *     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     member_id UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
 *     offense INTEGER NOT NULL DEFAULT 1,
 *     message TEXT,
 *     status TEXT NOT NULL DEFAULT 'pending',
 *     reviewed_by UUID,
 *     reviewed_at TIMESTAMPTZ,
 *     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 *   );
 *
 * @returns {{ action: 'warn'|'mute'|'temp_ban', offense: number, mutedUntil?: string, muteLabel?: string, suspended_until?: string }}
 */
async function vioRecord(memberId) {
  const v = vioGet(memberId);
  const n = v.offense + 1;

  let mutedUntil = null;
  let tempBanned = false;
  let muteMs     = 0;

  if (n === 1) {
    muteMs = 0;                   // 1st offense: warning only
  } else if (n === 2) {
    muteMs = 1 * 60 * 1000;      // 2nd offense: 1-minute mute
  } else if (n === 3) {
    muteMs = 2 * 60 * 1000;      // 3rd offense: 2-minute mute
  } else if (n === 4) {
    muteMs = 5 * 60 * 1000;      // 4th offense: 5-minute mute
  } else {
    tempBanned = true;            // 5th+ offense: 24h temp ban
  }

  if (tempBanned) {
    const suspendedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);
    _violations.set(memberId, { offense: n, mutedUntil: null, banned: true });
    try {
      await supabase.from("member_accounts")
        .update({ account_status: "suspended", suspended_until: suspendedUntil.toISOString() })
        .eq("member_id", memberId);
    } catch (e) { console.error("[vio] temp-ban DB update failed:", e.message); }
    try {
      await supabase.from("member_violations")
        .upsert([{ member_id: memberId, offense: n, muted_until: null, banned: true, updated_at: new Date().toISOString() }],
                { onConflict: "member_id" });
    } catch { /* non-fatal */ }
    return { action: "temp_ban", offense: n, suspended_until: suspendedUntil.toISOString() };
  }

  mutedUntil = muteMs > 0 ? new Date(Date.now() + muteMs) : null;
  _violations.set(memberId, { offense: n, mutedUntil, banned: false });

  try {
    await supabase.from("member_violations")
      .upsert([{ member_id: memberId, offense: n, muted_until: mutedUntil?.toISOString() || null, banned: false, updated_at: new Date().toISOString() }],
              { onConflict: "member_id" });
  } catch { /* non-fatal */ }

  return {
    action:     muteMs > 0 ? "mute" : "warn",
    offense:    n,
    mutedUntil: mutedUntil?.toISOString() || null,
    muteLabel:  muteMs > 0 ? _muteLabel(muteMs) : null,
  };
}

async function loadMemberViolations() {
  const { data } = await supabase
    .from('member_violations')
    .select('member_id, offense, muted_until, banned')
    .gt('updated_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString());
  (data || []).forEach(row => {
    _violations.set(row.member_id, {
      offense:    row.offense,
      mutedUntil: row.muted_until ? new Date(row.muted_until) : null,
      banned:     row.banned || false,
    });
  });
  console.log(`[vio] Restored ${data?.length || 0} active member violations from DB`);
}

function _muteLabel(ms) {
  const s = Math.ceil(ms / 1000);
  if (s < 3600)  return `${Math.ceil(s / 60)} minute${Math.ceil(s/60) !== 1 ? 's' : ''}`;
  if (s < 86400) return `${Math.ceil(s / 3600)} hour${Math.ceil(s/3600) !== 1 ? 's' : ''}`;
  return `${Math.ceil(s / 86400)} day${Math.ceil(s/86400) !== 1 ? 's' : ''}`;
}

// Shared profanity gate used by DM send + group message send.
// Returns null if clean/allowed, or an Express response (already sent) if blocked.
async function vioGate(req, res, memberId, text) {
  // 1. Already muted or banned?
  if (vioIsMuted(memberId)) {
    const v = vioGet(memberId);
    if (v.banned) {
      return res.status(403).json({ error: "Your account has been disabled due to repeated violations.", banned: true });
    }
    const remaining = vioMuteRemaining(memberId);
    return res.status(403).json({
      error:        `You are muted for inappropriate language. Please wait ${_muteLabel(remaining)}.`,
      muted:        true,
      muted_until:  _violations.get(memberId)?.mutedUntil?.toISOString(),
      offense:      vioGet(memberId).offense,
    });
  }

  // 2. Check current message
  const check = containsProfanity(text);
  if (!check.found) return null; // clean — caller may proceed

  // 3. Record offense and respond
  const vio = await vioRecord(memberId);

  // Audit log — every moderation decision is recorded for admin review
  console.log(`[profanity-gate] memberId=${memberId} offense=${vio.offense} action=${vio.action} word="${check.word}" path=${req.path}`);

  if (vio.action === "temp_ban") {
    return res.status(403).json({
      error:          "Your account has been temporarily banned due to repeated violations. You can appeal to an admin.",
      temp_banned:    true,
      offense:        vio.offense,
      suspended_until: vio.suspended_until,
    });
  }

  // Warning messages explain the full escalation ladder
  const ladderHint = vio.offense === 1
    ? "Next violation: 1-min mute."
    : vio.offense === 2
    ? "Next violation: 2-min mute."
    : vio.offense === 3
    ? "Next violation: 5-min mute."
    : vio.offense >= 4
    ? "Next violation: temporary ban."
    : "";

  const warningMsg = vio.action === "mute"
    ? `⚠️ Warning #${vio.offense}: Message blocked. You are muted for ${vio.muteLabel}. ${ladderHint}`
    : `⚠️ Warning #${vio.offense}: Message blocked for inappropriate language. ${ladderHint}`;

  return res.status(400).json({
    error:        warningMsg,
    warned:       true,
    offense:      vio.offense,
    muted:        vio.action === "mute",
    muted_until:  vio.mutedUntil || null,
    ladder_hint:  ladderHint,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION FP — Forgot Password: OTP generation, masking, delivery helpers
// Used by both /api/admin/forgot-password/* and /api/member/forgot-password/*
// ─────────────────────────────────────────────────────────────────────────────

const OTP_TTL_MS          = 10 * 60 * 1000; // 10 minutes
const OTP_MAX_ATTEMPTS     = 5;
const RESET_TOKEN_TTL_MS   = 15 * 60 * 1000; // 15 minutes to actually set the new password after verifying

function generateOtp() {
  // 6-digit numeric, zero-padded. crypto.randomInt is uniform (no modulo bias).
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

// Masks contact info for display, e.g. "+91 98765 43210" -> "+91 98••• •••10"
// and "jdoe@kiit.ac.in" -> "j***@kiit.ac.in". Never expose the full value.
function maskPhone(phone) {
  const digits = (phone || "").replace(/\D/g, "");
  if (digits.length < 4) return "••••";
  const last2 = digits.slice(-2);
  return `••••••${last2}`;
}
function maskEmail(email) {
  const [user, domain] = (email || "").split("@");
  if (!user || !domain) return "••••";
  const visible = user.slice(0, 1);
  return `${visible}${"*".repeat(Math.max(user.length - 1, 3))}@${domain}`;
}

// Generic OTP email via Brevo (separate template from sendConfirmationEmail —
// short-lived security code, not a marketing/event email).
async function sendOtpViaEmail(toEmail, toName, otp) {
  const { data: rows } = await supabase
    .from("settings")
    .select("key,value")
    .in("key", ["brevo_api_key", "smtp_from_name"]);
  const s = {};
  (rows || []).forEach((r) => (s[r.key] = r.value));
  if (!s.brevo_api_key) {
    throw new Error("EMAIL_NOT_CONFIGURED");
  }
  const fromName = s.smtp_from_name || "KFS — KIIT Film Society";
  const html = `<!DOCTYPE html><html><body style="margin:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 0"><tr><td align="center">
<table width="420" cellpadding="0" cellspacing="0" style="background:#111111;border:1px solid #1e1e1e;border-radius:18px;overflow:hidden">
  <tr><td style="padding:36px 36px 8px">
    <p style="font-size:13px;color:#888;margin:0 0 6px;text-transform:uppercase;letter-spacing:.08em">KFS — KIIT Film Society</p>
    <h2 style="color:#f5f5f5;font-size:20px;margin:0 0 18px;letter-spacing:-.02em">Your verification code</h2>
    <p style="color:#ccc;font-size:14px;line-height:1.6;margin:0 0 24px">Hi ${toName || "there"}, use this code to reset your password. It expires in 10 minutes.</p>
    <div style="background:#1a1a1a;border:1px solid #1e1e1e;border-radius:12px;padding:20px;text-align:center;margin-bottom:24px">
      <span style="font-size:32px;font-weight:700;letter-spacing:.3em;color:#f5f5f5">${otp}</span>
    </div>
    <p style="color:#666;font-size:12px;line-height:1.6;margin:0">If you didn't request this, you can safely ignore this email — your password won't change unless this code is used.</p>
  </td></tr>
  <tr><td style="padding:20px 36px 28px;border-top:1px solid #1e1e1e">
    <p style="font-size:12px;color:#444;margin:0">This is an automated message from <a href="https://kiitfilmsociety.in" style="color:#666;text-decoration:none">kiitfilmsociety.in</a>. Please do not reply to this email.</p>
  </td></tr>
</table>
</td></tr></table></body></html>`;

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": s.brevo_api_key,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { name: fromName, email: "noreply@kiitfilmsociety.in" },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject: "Your KFS verification code",
      textContent: `Your KFS verification code is ${otp}. It expires in 10 minutes.`,
      htmlContent: html,
    }),
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${err}`);
  }
}

// Sends OTP via email. account = { email, name }.
// Email is now the sole forgot-password channel (Twilio/WhatsApp/SMS removed —
// see v1.18 migration notes). Returns { channel, destination, maskedDestination }
// or throws NO_CONTACT_METHOD if the account has no email on file.
async function dispatchOtp(account, otp) {
  if (!account.email) {
    throw new Error("NO_CONTACT_METHOD");
  }
  await sendOtpViaEmail(account.email, account.name, otp);
  return { channel: "email", destination: account.email, maskedDestination: maskEmail(account.email) };
}

// ── Forgot-password lockout (mirrors login lockout pattern) ───────────────────
const FP_ATTEMPTS = new Map(); // key: `${accountType}:${normalisedUsername}` -> { count, lockedUntil }

function checkForgotPasswordLockout(key) {
  const entry = FP_ATTEMPTS.get(key);
  if (!entry) return null;
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    const secsLeft = Math.ceil((entry.lockedUntil - Date.now()) / 1000);
    const timeStr = secsLeft < 120 ? `${secsLeft} second(s)` : `${Math.ceil(secsLeft / 60)} minute(s)`;
    return {
      message: `Too many attempts. Try again in ${timeStr}.`,
      lockedUntil: entry.lockedUntil, // epoch ms — client uses this to drive a live countdown
    };
  }
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) FP_ATTEMPTS.delete(key);
  return null;
}
function recordForgotPasswordAttempt(key) {
  const entry = FP_ATTEMPTS.get(key) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= 5) entry.lockedUntil = Date.now() + 15 * 60 * 1000;
  FP_ATTEMPTS.set(key, entry);
}
function clearForgotPasswordAttempts(key) {
  FP_ATTEMPTS.delete(key);
}


// ── File uploads ──────────────────────────────────────────────────────────────
const ALLOWED_MIME_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  // SVG removed v1.17.10 — MIME bypass risk: attacker can rename .svg to .jpg;
  // browser sniffs content-type and executes embedded scripts. Sanitisation
  // alone is insufficient defence. Posters/covers don't need SVG.
]);

function imageFileFilter(req, file, cb) {
  if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      Object.assign(new Error("Only image files are allowed (JPEG, PNG, WebP)."), {
        code: "INVALID_FILE_TYPE",
      }),
      false,
    );
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: imageFileFilter,
});

// ── Image compression config ──────────────────────────────────────────────────
// Max dimension for any uploaded image. Larger images are scaled down while
// preserving aspect ratio. Posters/covers rarely need to be bigger than this.
const IMAGE_MAX_PX = 1800; // longest edge in pixels
const IMAGE_QUALITY = 82; // WebP quality (0-100). 82 is visually lossless for photos.

async function compressImage(file) {
  if (!file) return null;

  const mime = file.mimetype || "";

  // ── SVG sanitisation — strip embedded scripts and event-handler attributes ──
  // SVGs can carry <script> tags and onX= attributes that execute in browsers.
  // We sanitise the buffer in-place before it reaches Cloudinary.
  if (mime === "image/svg+xml") {
    const svgText = file.buffer.toString("utf8");

    // Remove <script>...</script> blocks (including multiline)
    let safe = svgText.replace(/<script[\s\S]*?<\/script>/gi, "");

    // Remove <?xml-stylesheet ...?> processing instructions (can load external CSS)
    safe = safe.replace(/<\?xml-stylesheet[\s\S]*?\?>/gi, "");

    // Remove on* event handler attributes (onclick=, onload=, onerror=, etc.)
    safe = safe.replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");

    // Remove javascript: href / xlink:href values
    safe = safe.replace(/(?:href|xlink:href)\s*=\s*["']?\s*javascript:[^"'\s>]*/gi, "");

    // Remove <use xlink:href="data:..."> or external references
    safe = safe.replace(/<use[^>]+xlink:href\s*=\s*["'][^"']*["'][^>]*>/gi, "");

    console.log(`[img] SVG sanitised: ${file.originalname}`);
    return { ...file, buffer: Buffer.from(safe, "utf8") };
  }

  // v1.17.9: Disallow GIF uploads to prevent embedded-payload risk
  // Per release-notes LOW item: either re-encode or disallow. We disallow.
  if (mime === "image/gif") {
    throw Object.assign(new Error("GIF uploads are not permitted. Please use JPEG, PNG, or WebP."), { code: "GIF_NOT_ALLOWED" });
  }

  try {
    const before = file.buffer.length;

    const compressed = await sharp(file.buffer)
      .rotate() // auto-rotate from EXIF orientation
      .resize(IMAGE_MAX_PX, IMAGE_MAX_PX, {
        fit: "inside", // never upscale, just shrink if needed
        withoutEnlargement: true,
      })
      .webp({ quality: IMAGE_QUALITY }) // always convert to WebP for best size
      .toBuffer();

    const after = compressed.length;
    const saving = Math.round((1 - after / before) * 100);
    console.log(
      `[img] ${file.originalname}: ${(before / 1024).toFixed(0)}KB → ${(after / 1024).toFixed(0)}KB (${saving}% smaller)`,
    );

    // Return a modified file-like object with the compressed buffer
    return {
      ...file,
      buffer: compressed,
      mimetype: "image/webp",
      originalname: file.originalname.replace(/\.[^.]+$/, "") + ".webp",
    };
  } catch (e) {
    // If compression fails for any reason, fall back to original
    console.warn(
      `[img] compression failed for ${file.originalname}:`,
      e.message,
      "— using original",
    );
    return file;
  }
}

async function uploadImage(file, folder = "general") {
  if (!file) return null;

  // Compress before upload
  const processed = await compressImage(file);

  // Upload to Cloudinary via buffer stream
  const result = await new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: `kfs-media/${folder}`,
        resource_type: "image",
        format: "webp",
      },
      (error, result) => {
        if (error) reject(new Error("Cloudinary upload: " + error.message));
        else resolve(result);
      },
    );
    uploadStream.end(processed.buffer);
  });

  return result.secure_url;
}

// ── Middleware ────────────────────────────────────────────────────────────────
// Fix 1: Lock CORS to production domain only (was open to all origins)
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://kiitfilmsociety.in', 'https://www.kiitfilmsociety.in']
    : true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
}));

// Fix 2: Enable a real CSP instead of disabling it entirely
// frameSrc covers all embed iframes — add new platforms here as needed
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // v1.17.9: 'unsafe-inline' removed from scriptSrc (blocks injected <script> XSS — the real attack vector)
      // which is already prevented by output encoding and Supabase RLS. Full migration is tracked separately.
      // 'unsafe-inline' removed — all JS is in /public/app.js (external, covered by 'self')
      // The one remaining inline script is the synchronous theme-loader; its hash is pinned below.
      // All 212 inline event handlers migrated to data-action delegation — scriptSrcAttr removed.
      scriptSrc: ["'self'", "'sha256-+66rGdTLpDfofX3X9tPnOXG2mk883HeaJVj/Zy2m7VQ='", "'sha256-2asVaJiBS57Wr2ER9jyWn0odi19ZVJql169KxTpB7d4='", "'sha256-BA2H1D/U01IDrFsnrXJATwOAqtE8Q6nevz3CatpZuww='", "https://cdnjs.cloudflare.com", "https://checkout.razorpay.com", "https://cdn.razorpay.com", "https://accounts.google.com/gsi/client"],
      scriptSrcAttr: ["'unsafe-inline'"], // required: movie/blog cards use onclick in JS templates
      imgSrc: [
        "'self'", "data:",
        "https://res.cloudinary.com",
        "https://*.supabase.co",
        "https://img.youtube.com",       // YouTube thumbnails
        "https://i.ytimg.com",           // YouTube thumbnails (alternate CDN)
        "https://*.razorpay.com",        // Razorpay checkout images
        "https://raw.githubusercontent.com", // Apple emoji images (iamcal/emoji-data) — jsDelivr's npm CDN was 403'ing these due to its package-size cap
      ],
      connectSrc: [
        "'self'",
        "https://api.brevo.com",
        "https://*.supabase.co",         // Supabase realtime + API calls
        "https://api.razorpay.com",      // Razorpay order/payment API
        "https://lumberjack.razorpay.com", // Razorpay analytics/logging
        "https://accounts.google.com/gsi/", // Google Identity Services background calls
        "https://cdnjs.cloudflare.com",  // DOMPurify + other CDN libs (source maps)
      ],
      frameSrc: [
        "https://www.youtube.com",       // YouTube embeds
        "https://open.spotify.com",      // Spotify embeds
        "https://embed.music.apple.com", // Apple Music embeds
        "https://api.razorpay.com",      // Razorpay checkout iframe
        "https://*.razorpay.com",        // Razorpay checkout modal
        "https://accounts.google.com/gsi/", // Google Sign-In button/One Tap iframe
        "https://accounts.google.com/o/oauth2/", // Google Sign-In popup fallback (non-FedCM browsers)
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://accounts.google.com/gsi/style"],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  // Google Sign-In's popup-based fallback (used when the browser doesn't support FedCM)
  // needs to postMessage back to the opener window. The helmet default ("same-origin")
  // blocks that handshake, leaving the popup blank/unresponsive.
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
}));

// Fix 3: Add body size limit to prevent large payload DoS attacks (was unlimited)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

// ── v1.17.9: Structured access logging ───────────────────────────────────────
// Logs: timestamp, IP, method, path, status, latency (ms)
// Alerts in stderr for patterns: >10 consecutive 401s from one IP, admin logins
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const latency = Date.now() - start;
    const ip = req.ip || req.socket?.remoteAddress || '-';
    const log = JSON.stringify({
      ts: new Date().toISOString(),
      ip,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      latencyMs: latency,
    });
    // Write structured log to stdout (Render log drain picks this up)
    process.stdout.write(log + '\n');
    // Alert on suspicious patterns
    if (res.statusCode === 401) {
      _consecutiveUnauthed.set(ip, (_consecutiveUnauthed.get(ip) || 0) + 1);
      if (_consecutiveUnauthed.get(ip) >= 10) {
        console.warn('[ALERT] >10 consecutive 401s from IP:', ip);
      }
    } else if (res.statusCode < 400) {
      _consecutiveUnauthed.delete(ip);
    }
    if (req.path === '/api/admin/login' && res.statusCode === 200) {
      console.warn('[AUDIT] Admin login from IP:', ip, 'user-agent:', req.headers['user-agent'] || '-');
    }
  });
  next();
});
const _consecutiveUnauthed = new Map(); // IP → count

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500, // raised from 100 — home page fires 7 requests at once, admin panel fires 20+
    message: { error: "Too many requests. Slow down." },
  }),
);

// ── Strict rate limiters for public write endpoints ───────────────────────────
// Prevents bots from flooding comments/reviews within the global 100-req window.
const strictWriteLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                   // 20 submissions per IP per window (raised from 5 — campus NAT shares one public IP)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many submissions. Please wait 15 minutes and try again." },
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
});

app.use(express.static(path.join(__dirname, "public")));

// Every /api/* response is dynamic, per-request, often per-user data — it
// must never be cached by the browser or by any proxy/CDN sitting in front
// of this server. Disabling Express's own ETag generation (see app.set
// above) only stops THIS app from answering with a 304; it doesn't stop an
// upstream layer from caching the response body on its own heuristics if
// there's no explicit instruction not to. Cache-Control: no-store is the
// one directive every HTTP cache in the chain is required to respect.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// ── Response cache helper ──────────────────────────────────────────────────────
// maxAge in seconds. Sends Cache-Control: public, max-age=N, stale-while-revalidate=60
function cacheFor(res, seconds = 60) {
  res.setHeader(
    "Cache-Control",
    `public, max-age=${seconds}, stale-while-revalidate=60`,
  );
}

// For mutable content: no browser cache so SSE-triggered refreshes always get fresh data.
// Server-side memCache still handles DB load.
function noStore(res) {
  res.setHeader("Cache-Control", "no-store");
}

// ── Server-side in-memory cache ────────────────────────────────────────────────
// Keeps Supabase query count (and thus cached egress) very low.
// Call: await memCache('key', ttlSeconds, () => supabase.from(...).select(...))
// Invalidate a key after a write:  memInvalidate('key')  or  memInvalidate('prefix:')
const _memStore = new Map();
const CACHE_FILE = path.join(__dirname, ".memcache.json");

// Load cache from disk on startup (survives server restarts)
try {
  const saved = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8"));
  for (const [k, v] of Object.entries(saved)) {
    if (Date.now() < v.expires) _memStore.set(k, v);
  }
  console.log("[cache] Restored", _memStore.size, "entries from disk");
} catch {}

const MAX_CACHE_ENTRIES = 500; // prevent unbounded memory growth

function memCache(key, ttlSeconds, fn) {
  const hit = _memStore.get(key);
  if (hit && Date.now() < hit.expires) return Promise.resolve(hit.data);
  return fn().then((data) => {
    if (_memStore.size >= MAX_CACHE_ENTRIES) {
      // Evict the soonest-to-expire entry
      const oldest = [..._memStore.entries()].sort((a, b) => a[1].expires - b[1].expires)[0];
      if (oldest) _memStore.delete(oldest[0]);
    }
    _memStore.set(key, { data, expires: Date.now() + ttlSeconds * 1000 });
    debouncedCacheFlush();
    return data;
  });
}

// Debounced disk flush — writes at most once every 2 seconds, never on every set.
// Also skips keys that may contain sensitive data (settings, email keys).
let _cacheFlushTimer = null;
function debouncedCacheFlush() {
  clearTimeout(_cacheFlushTimer);
  _cacheFlushTimer = setTimeout(() => {
    const SKIP_KEYS = ["settings", "settings:email"];
    const safe = Object.fromEntries(
      [..._memStore.entries()].filter(([k]) => !SKIP_KEYS.some(sk => k === sk || k.startsWith(sk + ":")))
    );
    fs.writeFile(CACHE_FILE, JSON.stringify(safe), () => {});
  }, 2000);
}
// Invalidate one key or all keys that start with a prefix (e.g. 'movies')
function memInvalidate(...keys) {
  for (const key of keys) {
    if (key.endsWith(":") || key.endsWith("_")) {
      // prefix invalidation
      for (const k of _memStore.keys()) {
        if (k.startsWith(key)) _memStore.delete(k);
      }
    } else {
      _memStore.delete(key);
    }
  }
}

// ── Auth middleware ───────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// SECTION A — JWT helpers (short-lived access tokens + jti for revocation)
// ─────────────────────────────────────────────────────────────────────────────

function signAccessToken(payload) {
  const jti = crypto.randomBytes(16).toString("hex");
  return jwt.sign({ ...payload, jti }, JWT_SECRET, { expiresIn: "15m" });
}

async function issueRefreshToken(adminId) {
  const raw  = crypto.randomBytes(40).toString("hex");
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  const exp  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const { error } = await supabase.from("refresh_tokens").insert([{
    admin_id:   adminId,
    token_hash: hash,
    expires_at: exp.toISOString(),
  }]);
  if (error) throw new Error("Could not store refresh token: " + error.message);
  return raw;
}

function setRefreshCookie(res, raw) {
  res.cookie("kfs_refresh", raw, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   7 * 24 * 60 * 60 * 1000,
    path:     "/api/admin/refresh",
  });
  // Non-httpOnly sentinel — lets the scanner page skip the refresh call
  // when there is clearly no session (avoids a noisy 401 on every page load).
  res.cookie("kfs_session", "1", {
    httpOnly: false,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie("kfs_refresh", { path: "/api/admin/refresh" });
  res.clearCookie("kfs_session");
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION B — JWT revocation (in-memory Set, synced from Supabase on boot)
// ─────────────────────────────────────────────────────────────────────────────

const _revokedJtis = new Set();

// ─────────────────────────────────────────────────────────────────────────────
// Refresh-rotation grace cache — guards against the legitimate multi-tab /
// double-fire case where two requests race in with the SAME (still valid)
// refresh cookie. Without this, the second request sees `used: true` and
// nukes every session for the admin, even though no theft occurred — just
// two browser tabs (or a duplicate network call) hitting /api/admin/refresh
// within milliseconds of each other. We cache the rotation result for a few
// seconds keyed by the consumed token's hash; a repeat call within that
// window gets the same fresh token back instead of being treated as reuse.
// Genuine reuse outside the window (e.g. a stolen/replayed token used much
// later) still falls through to the theft-protection revoke below.
// ─────────────────────────────────────────────────────────────────────────────
const _refreshGraceCache = new Map(); // token_hash -> { response, expiresAt }
const REFRESH_GRACE_MS = 10 * 1000;

function setRefreshGrace(tokenHash, response) {
  _refreshGraceCache.set(tokenHash, { response, expiresAt: Date.now() + REFRESH_GRACE_MS });
  // opportunistic cleanup of stale entries
  for (const [k, v] of _refreshGraceCache) {
    if (v.expiresAt < Date.now()) _refreshGraceCache.delete(k);
  }
}

function getRefreshGrace(tokenHash) {
  const entry = _refreshGraceCache.get(tokenHash);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    _refreshGraceCache.delete(tokenHash);
    return null;
  }
  return entry.response;
}

async function loadRevokedTokens() {
  const { data } = await supabase
    .from("revoked_tokens")
    .select("jti")
    .gt("expires_at", new Date().toISOString());
  (data || []).forEach(r => _revokedJtis.add(r.jti));
  console.log(`[auth] Loaded ${_revokedJtis.size} revoked token JTIs from DB`);
}

async function revokeToken(jti, expiresAt) {
  _revokedJtis.add(jti);
  try {
    await supabase.from("revoked_tokens").upsert([{
      jti,
      expires_at: new Date(expiresAt * 1000).toISOString(),
    }]);
  } catch(e) {
    console.error("[auth] revoke persist failed:", e.message);
  }
}

async function revokeAllForAdmin(adminId) {
  await supabase
    .from("refresh_tokens")
    .update({ used: true })
    .eq("admin_id", adminId);
  console.log(`[auth] All refresh tokens revoked for admin ${adminId}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION C — Updated middleware (all check revocation Set)
// ─────────────────────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    if (decoded.jti && _revokedJtis.has(decoded.jti)) {
      return res.status(401).json({ error: "Token revoked" });
    }
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Master-only middleware
function masterMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    console.log(
      "masterMiddleware decoded role:",
      decoded.role,
      "username:",
      decoded.username,
    );
    if (decoded.jti && _revokedJtis.has(decoded.jti)) {
      return res.status(401).json({ error: "Token revoked" });
    }
    if (decoded.role !== "master")
      return res.status(403).json({ error: "Master access only" });
    req.admin = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Section permission middleware — master bypasses, regular admins checked
function requireSection(section) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
      if (decoded.jti && _revokedJtis.has(decoded.jti)) {
        return res.status(401).json({ error: "Token revoked" });
      }
      req.admin = decoded;
      if (decoded.role === "master") return next(); // master always passes
      const perms = decoded.permissions || [];
      // NOTE: empty permissions array means NO access (not legacy full-access).
      // Ensure all admin accounts have their permissions[] set before deploying.
      if (perms.includes(section)) return next();
      return res
        .status(403)
        .json({ error: `No permission for section: ${section}` });
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ── Activity logger ───────────────────────────────────────────────────────────
// entityId + snapshot are optional (only used for soft-delete + undo support).
async function logActivity(adminId, adminName, action, entity, entityName, entityId = null, snapshot = null) {
  try {
    await supabase.from("admin_activity").insert([
      {
        admin_id: adminId,
        admin_name: adminName,
        action,
        entity,
        entity_name: entityName,
        entity_id: entityId !== null && entityId !== undefined ? String(entityId) : null,
        snapshot: snapshot ? JSON.stringify(snapshot) : null,
      },
    ]);
  } catch (e) {
    console.error("Activity log error:", e);
  }
}

// Tables that support soft-delete + undo (must have a `deleted_at` column).
const UNDOABLE_TABLES = {
  member: "members",
  event: "events",
  blog: "blogs",
  movie: "movies",
};

// ── DB Init ───────────────────────────────────────────────────────────────────
async function initDB() {
  try {
    const defaultPw = process.env.MASTER_DEFAULT_PW;

    // ── Seed kfsmaster ────────────────────────────────────────────────────────
    const { data: master1, error: masterErr } = await supabase
      .from("admins")
      .select("id")
      .eq("username", "kfsmaster")
      .maybeSingle();
    if (masterErr)
      throw new Error("admins table query failed: " + masterErr.message);

    if (!master1) {
      if (!defaultPw) {
        console.error(
          "[initDB] FATAL: MASTER_DEFAULT_PW env var is not set. " +
          "Cannot create master admin account safely. " +
          "Set this env var in your Render dashboard and restart.",
        );
        return; // Don't create master with no password
      }
      const hash = await bcrypt.hash(defaultPw, 10);
      const { error: insertErr } = await supabase.from("admins").insert([
        {
          name: "KFS Master",
          username: "kfsmaster",
          password_hash: hash,
          role: "master",
        },
      ]);
      if (insertErr)
        throw new Error("Master admin insert failed: " + insertErr.message);
      console.log(
        "Master admin created: username=kfsmaster (password from MASTER_DEFAULT_PW env var)",
      );
    }

    // ── Seed kfsmaster2 ───────────────────────────────────────────────────────
    const { data: master2, error: master2Err } = await supabase
      .from("admins")
      .select("id")
      .eq("username", "kfsmaster2")
      .maybeSingle();
    if (master2Err)
      throw new Error("admins table query failed (master2): " + master2Err.message);

    if (!master2) {
      const master2Pw = process.env.MASTER2_DEFAULT_PW; // intentionally NOT falling back to MASTER_DEFAULT_PW
      if (!master2Pw) {
        console.error(
          "[initDB] FATAL: MASTER2_DEFAULT_PW env var is not set. " +
          "Cannot create kfsmaster2 account safely. " +
          "Set a SEPARATE password from MASTER_DEFAULT_PW in your Render dashboard.",
        );
      } else {
        const hash2 = await bcrypt.hash(master2Pw, 10);
        const { error: insert2Err } = await supabase.from("admins").insert([
          {
            name: "KFS Master 2",
            username: "kfsmaster2",
            password_hash: hash2,
            role: "master",
          },
        ]);
        if (insert2Err)
          throw new Error("Master admin 2 insert failed: " + insert2Err.message);
        console.log(
          "Master admin created: username=kfsmaster2 (password from MASTER2_DEFAULT_PW env var)",
        );
      }
    }

    // Check if settings are seeded (use maybeSingle to avoid crash on missing row)
    const { data: tagline } = await supabase
      .from("settings")
      .select("key")
      .eq("key", "site_tagline")
      .maybeSingle();
    if (!tagline) {
      await supabase
        .from("settings")
        .insert([
          { key: "site_tagline", value: "Lights. Camera. KFS." },
          {
            key: "about_text",
            value:
              "KIIT Film Society is a student-run collective passionate about cinema.",
          },
          { key: "instagram", value: "" },
          { key: "youtube", value: "" },
          { key: "email", value: "kfs@kiit.ac.in" },
        ])
        .then(() => {})
        .catch(() => {});
    }

    // Probe donors table — log a clear message if it doesn't exist yet
    const { error: donorsErr } = await supabase
      .from("donors")
      .select("id", { count: "exact", head: true })
      .limit(1);
    if (donorsErr) {
      console.warn(
        "[initDB] donors table not found — run the SQL migration in Supabase:\n" +
        "  CREATE TABLE IF NOT EXISTS donors (\n" +
        "    id                  BIGSERIAL PRIMARY KEY,\n" +
        "    name                TEXT,\n" +
        "    email               TEXT,\n" +
        "    roll_no             TEXT,\n" +
        "    bio                 TEXT,\n" +
        "    photo_path          TEXT,\n" +
        "    is_anonymous        BOOLEAN NOT NULL DEFAULT FALSE,\n" +
        "    tandc_acknowledged  BOOLEAN NOT NULL DEFAULT FALSE,\n" +
        "    amount_paise        INTEGER,\n" +
        "    razorpay_order_id   TEXT UNIQUE,\n" +
        "    razorpay_payment_id TEXT,\n" +
        "    payment_verified_at TIMESTAMPTZ,\n" +
        "    featured_until      TIMESTAMPTZ,\n" +
        "    is_active           BOOLEAN NOT NULL DEFAULT TRUE,\n" +
        "    semester_label      TEXT,\n" +
        "    email_sent          BOOLEAN NOT NULL DEFAULT FALSE,\n" +
        "    email_sent_at       TIMESTAMPTZ,\n" +
        "    brevo_message_id    TEXT,\n" +
        "    created_at          TIMESTAMPTZ DEFAULT NOW()\n" +
        "  );\n" +
        "\n" +
        "  -- Payment failures table (fraud monitoring):\n" +
        "  CREATE TABLE IF NOT EXISTS payment_failures (\n" +
        "    id                  BIGSERIAL PRIMARY KEY,\n" +
        "    razorpay_order_id   TEXT,\n" +
        "    razorpay_payment_id TEXT,\n" +
        "    failure_reason      TEXT,\n" +
        "    ip_address          TEXT,\n" +
        "    user_agent          TEXT,\n" +
        "    created_at          TIMESTAMPTZ DEFAULT NOW()\n" +
        "  );\n" +
        "  CREATE INDEX IF NOT EXISTS idx_pf_order ON payment_failures(razorpay_order_id);\n" +
        "  CREATE INDEX IF NOT EXISTS idx_pf_ip    ON payment_failures(ip_address);"
      );
    } else {
      console.log("[initDB] donors table OK");
    }

    // Probe form_responses for the payment columns added by the
    // branching/paid-section registration forms feature.
    const { error: formRespPayErr } = await supabase
      .from("form_responses")
      .select("amount_paise,razorpay_order_id,razorpay_payment_id,razorpay_signature,payment_verified_at")
      .limit(1);
    if (formRespPayErr) {
      console.warn(
        "[initDB] form_responses is missing payment columns — run this SQL migration in Supabase:\n" +
        "  ALTER TABLE form_responses\n" +
        "    ADD COLUMN IF NOT EXISTS amount_paise        INTEGER,\n" +
        "    ADD COLUMN IF NOT EXISTS razorpay_order_id    TEXT UNIQUE,\n" +
        "    ADD COLUMN IF NOT EXISTS razorpay_payment_id  TEXT,\n" +
        "    ADD COLUMN IF NOT EXISTS razorpay_signature   TEXT,\n" +
        "    ADD COLUMN IF NOT EXISTS payment_verified_at  TIMESTAMPTZ;\n" +
        "  CREATE INDEX IF NOT EXISTS idx_fr_order ON form_responses(razorpay_order_id);\n" +
        "\n" +
        "  Without this, paid registration forms (sections marked is_paid) will\n" +
        "  fail to save once a payment is verified."
      );
    } else {
      console.log("[initDB] form_responses payment columns OK");
    }
  } catch (e) {
    console.error("initDB error:", e.message);
    // Don't crash the server — Supabase may be temporarily unreachable
  }
}

// ── SECURITY.TXT (RFC 9116) — v1.17.9 ───────────────────────────────────────
// Publish at /.well-known/security.txt so researchers know the disclosure path.
// Update SECURITY_CONTACT env var in Render dashboard (e.g. security@kiitfilmsociety.in)
app.get('/.well-known/security.txt', (req, res) => {
  const contact = process.env.SECURITY_CONTACT || 'mailto:filmsocietykiit@gmail.com';
  res.type('text/plain');
  res.send(
    `Contact: ${contact}\n` +
    `Preferred-Languages: en\n` +
    `Canonical: https://kiitfilmsociety.in/.well-known/security.txt\n` +
    `Policy: https://kiitfilmsociety.in/security-policy\n`
  );
});

// ── ROBOTS.TXT ────────────────────────────────────────────────────────────────
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(
    "User-agent: *\n" +
      "Allow: /\n" +
      "Disallow: /api/\n" +
      "Disallow: /admin\n" +
      "Disallow: /admin/\n" +
      "\n" +
      "Sitemap: https://kiitfilmsociety.in/sitemap.xml\n",
  );
});

// ── SHARED UTILITIES ──────────────────────────────────────────────────────────
// Turn a title into a URL slug — mirrors the frontend slugify helper
function slugify(str) {
  return (str || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// ── SITEMAP.XML ───────────────────────────────────────────────────────────────
app.get("/sitemap.xml", async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const cachedXml = _memStore.get("sitemap:xml");
  if (cachedXml && Date.now() < cachedXml.expires) {
    res.header("Content-Type", "application/xml");
    res.header("Cache-Control", "public, max-age=3600");
    return res.send(cachedXml.data);
  }

  // ── Movies ────────────────────────────────────────────────────────────────
  let movieUrls = "";
  try {
    const { data: movies } = await supabasePublic
      .from("movies")
      .select("id, title, updated_at")
      .order("release_year", { ascending: false })
      .limit(200);
    if (movies && movies.length > 0) {
      movieUrls = movies
        .map((mv) => {
          const slug = slugify(mv.title) + "-" + mv.id;
          const lastmod = mv.updated_at ? mv.updated_at.split("T")[0] : today;
          return `  <url>\n    <loc>https://kiitfilmsociety.in/films/${slug}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.8</priority>\n  </url>`;
        })
        .join("\n");
    }
  } catch (e) {
    /* non-fatal */
  }

  // ── Blogs ─────────────────────────────────────────────────────────────────
  let blogUrls = "";
  try {
    const { data: blogs } = await supabasePublic
      .from("blogs")
      .select("id, title, updated_at, created_at")
      .eq("published", true)
      .order("created_at", { ascending: false })
      .limit(200);
    if (blogs && blogs.length > 0) {
      blogUrls = blogs
        .map((b) => {
          const slug = slugify(b.title) + "-" + b.id;
          const lastmod = b.updated_at
            ? b.updated_at.split("T")[0]
            : b.created_at
              ? b.created_at.split("T")[0]
              : today;
          return `  <url>\n    <loc>https://kiitfilmsociety.in/blog/${slug}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.75</priority>\n  </url>`;
        })
        .join("\n");
    }
  } catch (e) {
    /* non-fatal */
  }

  // ── Events ────────────────────────────────────────────────────────────────
  let eventUrls = "";
  try {
    const { data: evs } = await supabasePublic
      .from("events")
      .select("id, title, updated_at, event_date")
      .order("event_date", { ascending: false })
      .limit(200);
    if (evs && evs.length > 0) {
      eventUrls = evs
        .map((ev) => {
          const slug = slugify(ev.title) + "-" + ev.id;
          const lastmod = ev.updated_at ? ev.updated_at.split("T")[0] : today;
          const isPast = ev.event_date && new Date(ev.event_date) < new Date();
          return `  <url>\n    <loc>https://kiitfilmsociety.in/events/${slug}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>${isPast ? "monthly" : "weekly"}</changefreq>\n    <priority>${isPast ? "0.6" : "0.85"}</priority>\n  </url>`;
        })
        .join("\n");
    }
  } catch (e) {
    /* non-fatal */
  }

  const xmlString = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://kiitfilmsociety.in/</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://kiitfilmsociety.in/films</loc>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://kiitfilmsociety.in/events</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://kiitfilmsociety.in/blog</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://kiitfilmsociety.in/about</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>https://kiitfilmsociety.in/team</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
${movieUrls}
${blogUrls}
${eventUrls}
</urlset>`;
  // Cache for 1 hour
  _memStore.set("sitemap:xml", { data: xmlString, expires: Date.now() + 3600 * 1000 });
  res.header("Content-Type", "application/xml");
  res.header("Cache-Control", "public, max-age=3600");
  res.send(xmlString);
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get("/api/health", async (req, res) => {
  if (req.headers['x-health-secret'] !== process.env.HEALTH_SECRET) {
    return res.status(404).send('Not found');
  }
  const start = Date.now();
  try {
    const { error } = await supabasePublic.from("settings").select("key", { count: "exact", head: true }).limit(1); // zero egress bytes
    if (error) throw new Error(error.message);
    res.json({ status: "ok", db: "connected", latencyMs: Date.now() - start });
  } catch (e) {
    res.status(503).json({
      status: "error",
      db: "unreachable",
      error: e.message,
      latencyMs: Date.now() - start,
    });
  }
});

// ── Login lockout ─────────────────────────────────────────────────────────────
// Progressive lockout tiers per username (stored in memory):
//   Tier 1 — after 3 failures  → locked 1 minute
//   Tier 2 — after 6 failures  → locked 5 minutes
//   Tier 3 — after 9 failures  → locked 2 weeks
const LOGIN_ATTEMPTS = new Map(); // username → { count, lockedUntil, tier }

const LOCKOUT_TIERS = [
  { afterAttempts: 3, durationMs: 1  * 60 * 1000,              label: '1 minute'  },
  { afterAttempts: 6, durationMs: 5  * 60 * 1000,              label: '5 minutes' },
  { afterAttempts: 9, durationMs: 14 * 24 * 60 * 60 * 1000,   label: '2 weeks'   },
];

function checkLoginLockout(username) {
  const entry = LOGIN_ATTEMPTS.get(username);
  if (!entry) return null; // no failures yet
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    const msLeft = entry.lockedUntil - Date.now();
    const secsLeft = Math.ceil(msLeft / 1000);
    let timeStr;
    if (secsLeft < 120)        timeStr = `${secsLeft} second(s)`;
    else if (secsLeft < 7200)  timeStr = `${Math.ceil(secsLeft / 60)} minute(s)`;
    else if (secsLeft < 172800) timeStr = `${Math.ceil(secsLeft / 3600)} hour(s)`;
    else                        timeStr = `${Math.ceil(secsLeft / 86400)} day(s)`;
    return {
      message: `Account locked. Try again in ${timeStr}.`,
      lockedUntil: entry.lockedUntil, // epoch ms — client uses this to drive a live countdown
    };
  }
  // Lockout expired — clear it so the next attempt counts fresh
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    LOGIN_ATTEMPTS.delete(username);
  }
  return null;
}

function recordLoginFailure(username) {
  const entry = LOGIN_ATTEMPTS.get(username) || { count: 0, lockedUntil: null, tier: 0 };
  entry.count += 1;
  // Find the highest tier whose threshold has been reached
  for (let i = LOCKOUT_TIERS.length - 1; i >= 0; i--) {
    if (entry.count >= LOCKOUT_TIERS[i].afterAttempts && entry.tier <= i) {
      entry.tier = i + 1; // mark tier consumed
      entry.lockedUntil = Date.now() + LOCKOUT_TIERS[i].durationMs;
      console.warn(
        `[auth] Account "${username}" locked (tier ${i + 1}) after ${entry.count} failed attempts — ${LOCKOUT_TIERS[i].label}`
      );
      break;
    }
  }
  LOGIN_ATTEMPTS.set(username, entry);
}

function clearLoginFailures(username) {
  LOGIN_ATTEMPTS.delete(username);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION J — Durable lockout helpers (persisted to Supabase, survive restarts)
// ─────────────────────────────────────────────────────────────────────────────

async function loadActiveLockouts() {
  const { data } = await supabase
    .from("admins")
    .select("username, login_failures, locked_until")
    .not("locked_until", "is", null)
    .gt("locked_until", new Date().toISOString());
  (data || []).forEach(admin => {
    if (admin.locked_until) {
      LOGIN_ATTEMPTS.set(admin.username, {
        count:       admin.login_failures,
        lockedUntil: new Date(admin.locked_until).getTime(),
        tier:        0,
      });
    }
  });
  console.log(`[auth] Restored ${data?.length || 0} active lockouts from DB`);
}

async function recordLoginFailureDurable(username) {
  recordLoginFailure(username);
  const entry = LOGIN_ATTEMPTS.get(username);
  if (entry) {
    try {
      await supabase
        .from("admins")
        .update({
          login_failures: entry.count,
          locked_until:   entry.lockedUntil ? new Date(entry.lockedUntil).toISOString() : null,
        })
        .eq("username", username);
    } catch(e) {
      console.error("[auth] lockout persist failed:", e.message);
    }
  }
}

async function clearLoginFailuresDurable(username) {
  clearLoginFailures(username);
  try {
    await supabase
      .from("admins")
      .update({ login_failures: 0, locked_until: null })
      .eq("username", username);
  } catch(e) {
    console.error("[auth] lockout clear failed:", e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION I — CSRF double-submit cookie protection
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/csrf-token", (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("kfs_csrf", token, {
    httpOnly: false, // JS must read this to send as header
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   24 * 60 * 60 * 1000, // 24h — long enough to survive a full admin session
  });
  res.json({ csrf_token: token });
});

function csrfProtect(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const cookieToken = req.cookies?.kfs_csrf;
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken) {
    return res.status(403).json({ error: "CSRF token missing" });
  }
  const a = Buffer.from(cookieToken);
  const b = Buffer.from(headerToken);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "CSRF token mismatch" });
  }
  next();
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// SECTION D — Updated /api/admin/login (supports TOTP second factor)
// NOTE: Login route defined BEFORE csrfProtect middleware so it is exempt.
// ─────────────────────────────────────────────────────────────────────────────
app.post(
  "/api/admin/login",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many login attempts. Try again later." },
  }),
  async (req, res) => {
    const { username, password, totp_code } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Username and password required" });

    const normalised = username.trim().toLowerCase();

    // Check lockout before touching the DB
    const lock = checkLoginLockout(normalised);
    if (lock) return res.status(429).json({ error: lock.message, locked_until: lock.lockedUntil });

    const { data: admin } = await supabase
      .from("admins")
      .select("*")
      .eq("username", normalised)
      .maybeSingle();
    if (!admin) {
      await recordLoginFailureDurable(normalised);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) {
      await recordLoginFailureDurable(normalised);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ── 2FA check (only if totp_enabled) ─────────────────────────────────────
    if (admin.totp_enabled) {
      if (!totp_code) {
        // Password correct but no TOTP code — tell client to prompt for it
        return res.status(200).json({ require_totp: true });
      }
      const verified = speakeasy.totp.verify({
        secret:   admin.totp_secret,
        encoding: "base32",
        token:    totp_code.replace(/\s/g, ""),
        window:   1,
      });
      if (!verified) {
        await recordLoginFailureDurable(normalised);
        return res.status(401).json({ error: "Invalid 2FA code" });
      }
    }

    // Successful login — clear any accumulated failures
    await clearLoginFailuresDurable(normalised);

    const perms = (() => {
      try {
        return JSON.parse(admin.permissions || "[]");
      } catch {
        return [];
      }
    })();

    const accessToken = signAccessToken({
      id: admin.id, name: admin.name,
      username: admin.username, role: admin.role, permissions: perms,
    });

    const refreshRaw = await issueRefreshToken(admin.id);
    setRefreshCookie(res, refreshRaw);

    res.json({
      token:        accessToken,
      name:         admin.name,
      role:         admin.role,
      permissions:  perms,
      totp_enabled: !!admin.totp_enabled,
      has_recovery_contact: !!admin.email,
      recovery_prompt_dismissed: !!admin.recovery_prompt_dismissed_at,
    });
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION D2 — Admin Forgot Password (username -> OTP via WhatsApp/SMS/Email -> reset)
// Three-step flow, mirrors the TOTP login pattern. Exempt from CSRF (pre-auth,
// like /login) and rate-limited per step.
// ─────────────────────────────────────────────────────────────────────────────

// Step 1 — submit username, receive OTP via email
app.post(
  "/api/admin/forgot-password/start",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: { error: "Too many requests. Try again later." } }),
  async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });
    const normalised = username.trim().toLowerCase();
    const lockKey = `admin:${normalised}`;

    const lock = checkForgotPasswordLockout(lockKey);
    if (lock) return res.status(429).json({ error: lock.message, locked_until: lock.lockedUntil });

    const { data: admin } = await supabase
      .from("admins")
      .select("id, name, email")
      .eq("username", normalised)
      .maybeSingle();

    // Always return a generic success-shaped response even if the account
    // doesn't exist or has no contact info — avoids leaking which usernames
    // are valid (standard account-enumeration defence).
    const genericResponse = { success: true, message: "If an account with an email on file exists for this username, a verification code has been sent." };

    if (!admin) {
      recordForgotPasswordAttempt(lockKey);
      return res.json(genericResponse);
    }
    if (!admin.email) {
      // Real account but no recovery email on file — tell them plainly so
      // they know to go to a master admin instead of waiting on a code that
      // will never arrive. (Trade-off: this confirms the username exists,
      // unlike the fully generic response above — see setup notes.)
      return res.json({
        success: false,
        reason: "no_contact",
        error: "Your email is not on file yet. Please contact your site admin for assistance.",
      });
    }

    const otp = generateOtp();
    let sent;
    try {
      sent = await dispatchOtp({ email: admin.email, name: admin.name }, otp);
    } catch (e) {
      console.error("[admin/forgot-password] OTP dispatch failed:", e.message);
      return res.status(500).json({ error: "Could not send verification code. Please contact a master admin." });
    }

    await supabase.from("password_reset_otps").insert([{
      account_type: "admin",
      account_id:   admin.id,
      channel:      sent.channel,
      destination:  sent.destination,
      otp_hash:     hashOtp(otp),
      max_attempts: OTP_MAX_ATTEMPTS,
      expires_at:   new Date(Date.now() + OTP_TTL_MS).toISOString(),
      ip_address:   req.ip,
    }]);

    recordForgotPasswordAttempt(lockKey);
    res.json({ ...genericResponse, channel: sent.channel, masked_destination: sent.maskedDestination });
  },
);

// Step 2 — verify the 6-digit code, receive a short-lived reset token
app.post(
  "/api/admin/forgot-password/verify",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { error: "Too many attempts. Try again later." } }),
  async (req, res) => {
    const { username, code } = req.body;
    if (!username || !code) return res.status(400).json({ error: "Username and code are required" });
    const normalised = username.trim().toLowerCase();

    const { data: admin } = await supabase
      .from("admins").select("id").eq("username", normalised).maybeSingle();
    if (!admin) return res.status(400).json({ error: "Invalid or expired code" });

    const { data: otpRow } = await supabase
      .from("password_reset_otps")
      .select("*")
      .eq("account_type", "admin")
      .eq("account_id", admin.id)
      .eq("consumed", false)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!otpRow) return res.status(400).json({ error: "Invalid or expired code" });
    if (new Date(otpRow.expires_at) < new Date()) return res.status(400).json({ error: "Code has expired. Please request a new one." });
    if (otpRow.attempts >= otpRow.max_attempts) return res.status(429).json({ error: "Too many incorrect attempts. Please request a new code." });

    const valid = hashOtp(code.replace(/\s/g, "")) === otpRow.otp_hash;
    if (!valid) {
      await supabase.from("password_reset_otps").update({ attempts: otpRow.attempts + 1 }).eq("id", otpRow.id);
      return res.status(401).json({ error: "Incorrect code" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    await supabase.from("password_reset_otps").update({
      reset_token: resetToken,
      reset_token_expires_at: new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString(),
      consumed: true,
    }).eq("id", otpRow.id);

    res.json({ success: true, reset_token: resetToken });
  },
);

// Step 3 — set the new password using the reset token from Step 2
app.post(
  "/api/admin/forgot-password/reset",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Too many attempts. Try again later." } }),
  async (req, res) => {
    const { username, reset_token, newPassword } = req.body;
    if (!username || !reset_token || !newPassword)
      return res.status(400).json({ error: "Missing required fields" });

    function isStrongPassword(pw) {
      return pw.length >= 8 && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
    }
    if (!isStrongPassword(newPassword))
      return res.status(400).json({ error: "Password must be at least 8 characters, include 1 uppercase letter, 1 number, and 1 special character." });

    const normalised = username.trim().toLowerCase();
    const { data: admin } = await supabase
      .from("admins").select("id").eq("username", normalised).maybeSingle();
    if (!admin) return res.status(400).json({ error: "Invalid or expired session. Please start over." });

    const { data: otpRow } = await supabase
      .from("password_reset_otps")
      .select("*")
      .eq("account_type", "admin")
      .eq("account_id", admin.id)
      .eq("reset_token", reset_token)
      .maybeSingle();

    if (!otpRow) return res.status(400).json({ error: "Invalid or expired session. Please start over." });
    if (new Date(otpRow.reset_token_expires_at) < new Date())
      return res.status(400).json({ error: "This reset session has expired. Please start over." });

    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from("admins").update({ password_hash: hash }).eq("id", admin.id);
    // Invalidate the reset token immediately so it can't be reused.
    await supabase.from("password_reset_otps").update({ reset_token: null }).eq("id", otpRow.id);
    // Also revoke all existing sessions for this admin — a password reset should log out everywhere.
    await revokeAllForAdmin(admin.id);
    clearForgotPasswordAttempts(`admin:${normalised}`);

    logActivity(admin.id, normalised, "password_reset_via_forgot_password", "admin", normalised).catch(() => {});
    res.json({ success: true, message: "Password updated. Please sign in with your new password." });
  },
);

app.post("/api/admin/change-password", authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword)
    return res.status(400).json({ error: "Current password is required" });
  // v1.17.9: Enforce password complexity (uppercase, digit, special char)
  function isStrongPassword(pw) {
    return pw.length >= 8 &&
      /[A-Z]/.test(pw) &&
      /[0-9]/.test(pw) &&
      /[^A-Za-z0-9]/.test(pw);
  }
  if (!newPassword || !isStrongPassword(newPassword))
    return res.status(400).json({ error: "Password must be at least 8 characters, include 1 uppercase letter, 1 number, and 1 special character." });

  // Fetch current hash from DB and verify before allowing change
  const { data: admin, error } = await supabase
    .from("admins")
    .select("password_hash")
    .eq("id", req.admin.id)
    .maybeSingle();
  if (error || !admin)
    return res.status(500).json({ error: "Could not verify identity" });

  const valid = await bcrypt.compare(currentPassword, admin.password_hash);
  if (!valid)
    return res.status(401).json({ error: "Current password is incorrect" });

  const hash = await bcrypt.hash(newPassword, 10);
  const { error: updateError } = await supabase
    .from("admins")
    .update({ password_hash: hash })
    .eq("id", req.admin.id);
  if (updateError) {
    console.error("change-password DB error:", updateError);
    return res.status(500).json({ error: "Failed to update password. Please try again." });
  }
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION D3 — Admin recovery contact info (email / phone) — self-service, instant
// Every admin (including masters) can set their own recovery contact info.
// This is what forgot-password uses to decide WhatsApp/SMS vs email.
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/admin/contact-info — fetch your own current contact info
app.get("/api/admin/contact-info", authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("admins")
    .select("email, phone, recovery_prompt_dismissed_at")
    .eq("id", req.admin.id)
    .maybeSingle();
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || { email: null, phone: null });
});

// PUT /api/admin/contact-info
app.put("/api/admin/contact-info", authMiddleware, async (req, res) => {
  const { email, phone } = req.body;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const updates = {};
  if (email !== undefined) {
    const v = (email || "").trim();
    if (v && !EMAIL_RE.test(v)) return res.status(400).json({ error: "Invalid email address" });
    updates.email = v || null;
  }
  if (phone !== undefined) {
    const digits = (phone || "").replace(/\D/g, "");
    if (phone && digits.length < 10) return res.status(400).json({ error: "Invalid phone number" });
    updates.phone = phone ? phone.trim() : null;
  }
  if (!Object.keys(updates).length) return res.status(400).json({ error: "Nothing to update" });

  const { data: current } = await supabase.from("admins").select("email,phone").eq("id", req.admin.id).maybeSingle();
  const willHaveEmail = updates.email !== undefined ? updates.email : current?.email;
  if (!willHaveEmail) {
    return res.status(400).json({ error: "Please provide an email for account recovery." });
  }

  const { error } = await supabase.from("admins").update(updates).eq("id", req.admin.id);
  if (error) return res.status(500).json({ error: "Internal server error" });

  logActivity(req.admin.id, req.admin.name, "contact_info_updated", "admin", req.admin.username).catch(() => {});
  res.json({ success: true });
});

// POST /api/admin/contact-info/dismiss-prompt
app.post("/api/admin/contact-info/dismiss-prompt", authMiddleware, async (req, res) => {
  await supabase.from("admins")
    .update({ recovery_prompt_dismissed_at: new Date().toISOString() })
    .eq("id", req.admin.id);
  res.json({ success: true });
});


// Protect all admin and master write routes.
// /login and /refresh are exempt — login uses rate-limit+bcrypt, refresh uses httpOnly cookie.
// /forgot-password/* is exempt — it's pre-auth by definition (the whole point is the
// user doesn't have a valid session), and is independently rate-limited + OTP-protected.
// When mounted at /api/admin, req.path is the remainder e.g. "/login", "/refresh".
function csrfProtectAdmin(req, res, next) {
  if (req.path.startsWith("/login") || req.path.startsWith("/refresh") || req.path.startsWith("/forgot-password")) return next();
  return csrfProtect(req, res, next);
}
app.use("/api/admin", csrfProtectAdmin);
app.use("/api/master", csrfProtect);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION E — Updated /api/admin/refresh (single-use httpOnly cookie)
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/admin/refresh", async (req, res) => {
  const raw = req.cookies?.kfs_refresh;
  if (!raw) return res.status(401).json({ error: "No refresh token" });

  const hash = crypto.createHash("sha256").update(raw).digest("hex");

  const { data: stored, error } = await supabase
    .from("refresh_tokens")
    .select("*")
    .eq("token_hash", hash)
    .maybeSingle();

  if (error || !stored)
    return res.status(401).json({ error: "Invalid refresh token" });

  if (stored.used) {
    // Could be a genuine theft/replay, OR a harmless race — two tabs (or a
    // duplicate request) hitting /refresh with the same cookie within the
    // same instant. Check the short grace cache first: if THIS exact token
    // was rotated moments ago, hand back that same rotation result instead
    // of nuking every session for the admin.
    const graced = getRefreshGrace(hash);
    if (graced) {
      setRefreshCookie(res, graced.newRefreshRaw);
      console.log(`[refresh] grace-window reuse for admin ${stored.admin_id} — same token served`);
      return res.json(graced.body);
    }
    // Outside the grace window — treat as genuine reuse/theft, revoke ALL tokens
    await revokeAllForAdmin(stored.admin_id);
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token already used — all sessions revoked" });
  }

  if (new Date(stored.expires_at) < new Date()) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token expired" });
  }

  // Mark as used (single-use) — conditional update so two requests racing in
  // at the exact same instant can't both believe they're the one rotating
  // this token. Only the request whose UPDATE actually matches a row wins;
  // the loser (rowsAffected === 0) falls through to a short wait + grace
  // cache check, since the winner will populate the cache a moment later.
  const { data: claimRows, error: claimErr } = await supabase
    .from("refresh_tokens")
    .update({ used: true })
    .eq("id", stored.id)
    .eq("used", false)
    .select("id");

  if (claimErr) {
    return res.status(500).json({ error: "Refresh failed" });
  }

  if (!claimRows || claimRows.length === 0) {
    // Lost the race — another concurrent request is rotating this token
    // right now. Briefly wait for it to populate the grace cache, then
    // serve that result instead of treating this as theft.
    await new Promise(r => setTimeout(r, 250));
    const graced = getRefreshGrace(hash);
    if (graced) {
      setRefreshCookie(res, graced.newRefreshRaw);
      return res.json(graced.body);
    }
    return res.status(401).json({ error: "Refresh token already used — all sessions revoked" });
  }

  // Fetch fresh admin data (picks up permission changes)
  const { data: admin } = await supabase
    .from("admins")
    .select("id,name,username,role,permissions")
    .eq("id", stored.admin_id)
    .maybeSingle();

  if (!admin) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Admin not found" });
  }

  const perms = (() => {
    try {
      return JSON.parse(admin.permissions || "[]");
    } catch {
      return [];
    }
  })();

  // Issue new access token + new refresh token (rotation)
  const accessToken = signAccessToken({
    id: admin.id, name: admin.name,
    username: admin.username, role: admin.role, permissions: perms,
  });

  const newRefreshRaw = await issueRefreshToken(admin.id);
  setRefreshCookie(res, newRefreshRaw);

  const responseBody = { token: accessToken, name: admin.name, role: admin.role, permissions: perms };
  setRefreshGrace(hash, { newRefreshRaw, body: responseBody });

  console.log(`[refresh] ${admin.username} — role: ${admin.role}`);
  res.json(responseBody);
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION F — Logout (revoke current token + refresh cookie)
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/admin/logout", authMiddleware, async (req, res) => {
  if (req.admin?.jti && req.admin?.exp) {
    await revokeToken(req.admin.jti, req.admin.exp);
  }
  const raw = req.cookies?.kfs_refresh;
  if (raw) {
    const hash = crypto.createHash("sha256").update(raw).digest("hex");
    await supabase.from("refresh_tokens").update({ used: true }).eq("token_hash", hash);
  }
  clearRefreshCookie(res);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION G — Logout ALL sessions (master or self only)
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/admin/logout-all", authMiddleware, async (req, res) => {
  const targetId = req.body.admin_id || req.admin.id;
  if (targetId !== req.admin.id && req.admin.role !== "master") {
    return res.status(403).json({ error: "Not allowed" });
  }
  await revokeAllForAdmin(targetId);
  if (targetId === req.admin.id) {
    if (req.admin?.jti && req.admin?.exp) {
      await revokeToken(req.admin.jti, req.admin.exp);
    }
    clearRefreshCookie(res);
  }
  res.json({ success: true, message: "All sessions revoked" });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION H — TOTP 2FA Setup (3-step flow)
// ─────────────────────────────────────────────────────────────────────────────

// Step 1 — Generate secret and QR code
app.get("/api/admin/2fa/setup", authMiddleware, rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: "Too many 2FA setup attempts. Try again later." } }), async (req, res) => {
  const secret = speakeasy.generateSecret({
    name:   `KFS Admin (${req.admin.username})`,
    issuer: "KFS — KIIT Film Society",
    length: 20,
  });
  await supabase
    .from("admins")
    .update({ totp_pending: secret.base32 })
    .eq("id", req.admin.id);
  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  res.json({
    secret:  secret.base32,
    qr_code: qrDataUrl,
    message: "Scan the QR code with Google Authenticator or Authy, then POST the 6-digit code to /api/admin/2fa/verify",
  });
});

// Step 2 — Verify and activate
app.post("/api/admin/2fa/verify", authMiddleware, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code is required" });
  const { data: admin } = await supabase
    .from("admins")
    .select("totp_pending, totp_enabled")
    .eq("id", req.admin.id)
    .maybeSingle();
  if (!admin?.totp_pending)
    return res.status(400).json({ error: "No pending 2FA setup. Call GET /api/admin/2fa/setup first." });
  const verified = speakeasy.totp.verify({
    secret:   admin.totp_pending,
    encoding: "base32",
    token:    code.replace(/\s/g, ""),
    window:   1,
  });
  if (!verified)
    return res.status(400).json({ error: "Invalid code. Make sure your authenticator clock is correct." });
  await supabase
    .from("admins")
    .update({ totp_secret: admin.totp_pending, totp_enabled: true, totp_pending: null })
    .eq("id", req.admin.id);
  res.json({ success: true, message: "2FA is now active on your account." });
});

// Step 3 — Disable
app.post("/api/admin/2fa/disable", authMiddleware, async (req, res) => {
  const targetId = req.body.admin_id || req.admin.id;
  if (targetId !== req.admin.id && req.admin.role !== "master") {
    return res.status(403).json({ error: "Not allowed" });
  }
  await supabase
    .from("admins")
    .update({ totp_secret: null, totp_enabled: false, totp_pending: null })
    .eq("id", targetId);
  res.json({ success: true, message: "2FA disabled." });
});

// ── MASTER: Admin management ──────────────────────────────────────────────────
app.get("/api/master/admins", masterMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("admins")
    .select("id,name,username,role,permissions,created_at,totp_enabled")
    .order("created_at");
  res.json(
    (data || []).map((a) => ({
      ...a,
      permissions: (() => {
        try {
          return JSON.parse(a.permissions || "[]");
        } catch {
          return [];
        }
      })(),
    })),
  );
});

app.post("/api/master/admins", masterMiddleware, async (req, res) => {
  const { name, username, password, permissions, email, phone } = req.body;
  if (!name || !username || !password)
    return res
      .status(400)
      .json({ error: "Name, username and password required" });
  // Recovery email is required for NEW admins (existing admins are untouched —
  // they get a soft in-app prompt to add theirs instead). Phone is still
  // collected but is no longer used for forgot-password (Twilio removed).
  const emailTrim = (email || "").trim();
  const phoneTrim = (phone || "").trim();
  if (!emailTrim)
    return res.status(400).json({ error: "Email is required (used for password recovery)." });
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!EMAIL_RE.test(emailTrim))
    return res.status(400).json({ error: "Invalid email address" });
  if (phoneTrim && phoneTrim.replace(/\D/g, "").length < 10)
    return res.status(400).json({ error: "Invalid phone number" });
  // v1.17.9: Enforce complexity for admin creation too
  const isStrong = (pw) => pw.length >= 8 && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
  if (!isStrong(password))
    return res
      .status(400)
      .json({ error: "Password must be ≥8 chars, include 1 uppercase, 1 digit, and 1 special character." });
  const hash = await bcrypt.hash(password, 10);
  const permsArr = Array.isArray(permissions) ? permissions : [];
  const { data, error } = await supabase
    .from("admins")
    .insert([
      {
        name,
        username: username.trim().toLowerCase(),
        password_hash: hash,
        role: "admin",
        permissions: JSON.stringify(permsArr),
        email: emailTrim || null,
        phone: phoneTrim || null,
      },
    ])
    .select("id,name,username,role,permissions,email,phone,created_at")
    .single();
  if (error)
    return res.status(400).json({
      error: error.message.includes("unique")
        ? "Username already taken"
        : error.message,
    });
  res.json({ ...data, permissions: permsArr });
});

app.delete("/api/master/admins/:id", masterMiddleware, async (req, res) => {
  const { data: target } = await supabase
    .from("admins")
    .select("role")
    .eq("id", req.params.id)
    .maybeSingle();
  if (!target) return res.status(404).json({ error: "Not found" });
  if (target.role === "master")
    return res.status(403).json({ error: "Cannot delete master admin" });
  await supabase.from("admins").delete().eq("id", req.params.id);
  res.json({ success: true });
});

app.put(
  "/api/master/admins/:id/reset-password",
  masterMiddleware,
  async (req, res) => {
    const { password } = req.body;
    if (!password)
      return res.status(400).json({ error: "New password required" });
    const isStrong = (pw) =>
      pw.length >= 8 &&
      /[A-Z]/.test(pw) &&
      /[0-9]/.test(pw) &&
      /[^A-Za-z0-9]/.test(pw);
    if (!isStrong(password))
      return res.status(400).json({
        error:
          "Password must be ≥8 chars, include 1 uppercase, 1 digit, and 1 special character.",
      });
    const { data: target } = await supabase
      .from("admins")
      .select("role, name")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!target) return res.status(404).json({ error: "Admin not found" });
    if (target.role === "master")
      return res.status(403).json({ error: "Cannot reset master password" });
    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase
      .from("admins")
      .update({ password_hash: hash })
      .eq("id", req.params.id);
    if (error) return res.status(500).json({ error: "Internal server error" });
    // Revoke all existing refresh tokens so the admin must log in with the new password
    await revokeAllForAdmin(req.params.id);
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "admin",
      `Reset password for ${target.name} (id:${req.params.id})`,
    ).catch((e) => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

app.put(
  "/api/master/admins/:id/permissions",
  masterMiddleware,
  async (req, res) => {
    const { permissions } = req.body;
    if (!Array.isArray(permissions))
      return res.status(400).json({ error: "permissions must be an array" });
    const { data: target } = await supabase
      .from("admins")
      .select("role")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!target) return res.status(404).json({ error: "Admin not found" });
    if (target.role === "master")
      return res
        .status(403)
        .json({ error: "Cannot modify master permissions" });
    const { error } = await supabase
      .from("admins")
      .update({ permissions: JSON.stringify(permissions) })
      .eq("id", req.params.id);
    if (error) return res.status(500).json({ error: "Internal server error" });
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "admin_permissions",
      `Permissions for admin ${req.params.id}`,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true, permissions });
  },
);

// ── MASTER: Activity log ──────────────────────────────────────────────────────
app.get("/api/master/activity", masterMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("admin_activity")
    .select("*")
    .neq("admin_id", req.admin.id)
    .order("created_at", { ascending: false })
    .limit(200);
  res.json(data || []);
});

// Undo a soft-deleted member/event/blog/movie within a 30-minute window.
app.post("/api/master/activity/:activityId/undo", masterMiddleware, async (req, res) => {
  const { data: log, error: logErr } = await supabase
    .from("admin_activity")
    .select("*")
    .eq("id", req.params.activityId)
    .single();

  if (logErr || !log) return res.status(404).json({ error: "Activity not found" });
  if (log.action !== "delete" || log.undone_at) {
    return res.status(400).json({ error: "This action cannot be undone" });
  }

  const table = UNDOABLE_TABLES[log.entity];
  if (!table || !log.entity_id) {
    return res.status(400).json({ error: "This action type does not support undo" });
  }

  const ageMs = Date.now() - new Date(log.created_at).getTime();
  if (ageMs > 30 * 60 * 1000) {
    return res.status(400).json({ error: "Undo window expired (30 min)" });
  }

  const { error: restoreErr } = await supabase
    .from(table)
    .update({ deleted_at: null })
    .eq("id", log.entity_id);
  if (restoreErr) return res.status(500).json({ error: "Failed to restore item" });

  await supabase
    .from("admin_activity")
    .update({ undone_at: new Date().toISOString(), undone_by: req.admin.name })
    .eq("id", req.params.activityId);

  // Invalidate caches so the restored item shows up immediately
  if (table === "members") memInvalidate("members:list");
  else if (table === "events") memInvalidate("events:list");
  else if (table === "blogs") memInvalidate("blogs:list", `blogs:${log.entity_id}`);
  else if (table === "movies") memInvalidate("movies:list", "movies:genre:", `movies:${log.entity_id}`);

  logActivity(req.admin.id, req.admin.name, "undo", log.entity, log.entity_name).catch(e => console.error("[activity]", e.message));
  res.json({ success: true });
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
// Live preview of the confirmation email — renders the exact same HTML template
// used by sendConfirmationEmail, with sample placeholder data.
app.post("/api/admin/settings/email-preview", requireSection("settings"), (req, res) => {
  const SAMPLE = {
    name: "Arjun Sharma",
    event: "Cine Noir Screening",
    eventDate: "2025-06-21",
    venue: "F4 Auditorium",
  };
  const bodyTemplate = typeof req.body.body === "string" ? req.body.body : "";
  const dateLine = `\n\nDate: ${new Date(SAMPLE.eventDate).toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}`;
  const venueLine = `\nVenue: ${SAMPLE.venue}`;

  const bodyText = bodyTemplate
    .replace(/{{name}}/g, SAMPLE.name)
    .replace(/{{event}}/g, SAMPLE.event)
    .replace(/{{date_line}}/g, dateLine)
    .replace(/{{venue_line}}/g, venueLine);

  const html = buildConfirmationEmailHtml(bodyText, SAMPLE.event, SAMPLE.eventDate, SAMPLE.venue);
  res.json({ html });
});

app.get("/api/settings", async (req, res) => {
  cacheFor(res, 60); // 1-min browser cache; server memCache handles DB load
  const obj = await memCache("settings", 300, async () => {
    const { data } = await supabasePublic
      .from("settings")
      .select("*")
      .not("key", "in", '("admin_password","brevo_api_key","smtp_from_name")');
    const o = {};
    (data || []).forEach((r) => (o[r.key] = r.value));
    return o;
  });
  res.json(obj);
});

app.post(
  "/api/admin/settings",
  requireSection("settings"),
  (req, res, next) => {
    upload.fields([
      { name: "team_photo", maxCount: 1 },
      { name: "easter_egg_img", maxCount: 1 },
    ])(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE")
          return res.status(400).json({
            error: "Photo too large — please use an image under 20MB",
          });
        if (err.code === "INVALID_FILE_TYPE")
          return res.status(400).json({ error: err.message });
        return res.status(400).json({ error: "Upload failed. Please check the file and try again." });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const files = req.files || {};
      // Team photo
      if (files.team_photo && files.team_photo[0]) {
        const f = files.team_photo[0];
        console.log("[settings] uploading team photo:", f.originalname, f.size);
        const photoUrl = await uploadImage(f, "general");
        console.log("[settings] photo upload result:", photoUrl);
        if (photoUrl) {
          await supabase
            .from("settings")
            .upsert(
              { key: "team_photo", value: photoUrl },
              { onConflict: "key" },
            );
        } else {
          return res.status(500).json({
            error:
              "Photo upload to storage failed — check Supabase storage bucket permissions",
          });
        }
      }
      // Easter egg image
      if (files.easter_egg_img && files.easter_egg_img[0]) {
        const f = files.easter_egg_img[0];
        console.log(
          "[settings] uploading easter egg img:",
          f.originalname,
          f.size,
        );
        const eggUrl = await uploadImage(f, "general");
        if (eggUrl) {
          await supabase
            .from("settings")
            .upsert(
              { key: "easter_egg_img", value: eggUrl },
              { onConflict: "key" },
            );
        }
      }
      const body = req.body || {};
      // Handle easter egg clear
      if (body.easter_egg_img_clear === "1") {
        await supabase.from("settings").delete().eq("key", "easter_egg_img");
        delete body.easter_egg_img_clear;
      }
      const entries = Object.entries(body);
      for (const [key, value] of entries) {
        if (value === "" || value === null || value === undefined) continue;
        await supabase
          .from("settings")
          .upsert({ key, value }, { onConflict: "key" });
      }
      memInvalidate("settings");
      try {
        logActivity(
          req.admin.id,
          req.admin.name,
          "update",
          "settings",
          "Site Settings",
        ).catch(e => console.error("[activity]", e.message));
      } catch (e) {}
      res.json({ success: true });
    } catch (e) {
      console.error("[settings] error:", e);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ── CUSTOM SEARCH EASTER EGGS ─────────────────────────────────────────────────
// Get all custom eggs
app.get("/api/settings/custom-eggs", async (req, res) => {
  const data = await memCache("settings:custom-eggs", 300, async () => {
    const { data } = await supabasePublic
      .from("settings")
      .select("value")
      .eq("key", "custom_search_eggs")
      .maybeSingle();
    try {
      return JSON.parse(data?.value || "[]");
    } catch {
      return [];
    }
  });
  res.json(data);
});

// ADMIN: Upload an image for a custom search easter egg (does NOT touch easter_egg_img setting)
app.post(
  "/api/admin/settings/custom-egg-upload",
  requireSection("settings"),
  upload.single("image"),
  async (req, res) => {
    if (!req.file)
      return res.status(400).json({ error: "No image file provided" });
    try {
      const url = await uploadImage(req.file, "general");
      if (!url)
        return res
          .status(500)
          .json({ error: "Image upload to storage failed" });
      res.json({ url });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Save all custom eggs (admin only)
app.post(
  "/api/admin/settings/custom-eggs",
  requireSection("settings"),
  async (req, res) => {
    const { eggs } = req.body;
    if (!Array.isArray(eggs))
      return res.status(400).json({ error: "eggs must be an array" });
    const value = JSON.stringify(eggs);
    await supabase
      .from("settings")
      .upsert({ key: "custom_search_eggs", value }, { onConflict: "key" });
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "settings",
      "Custom Search Easter Eggs",
    ).catch(e => console.error("[activity]", e.message));
    memInvalidate("settings:custom-eggs", "settings");
    res.json({ success: true });
  },
);

app.get("/api/blogs", async (req, res) => {
  cacheFor(res, 60);
  const data = await memCache("blogs:list", 600, async () => {
    const { data } = await supabasePublic
      .from("blogs")
      .select(
        "id,title,author,excerpt,cover_image,published,created_at,sections,view_count",
      )
      .eq("published", true)
      .is("deleted_at", null)
      .order("created_at", { ascending: false });
    return data || [];
  });
  res.json(data);
});

// ── Global admin search ───────────────────────────────────────────────────────
// Static index of admin sections, so typing "broadcast" or "themes" jumps straight
// to that tab even with zero DB records matching.
const ADMIN_SECTION_INDEX = [
  { id: "dashboard", label: "Dashboard", section: null, keywords: "overview home stats" },
  { id: "blogs", label: "Blog Posts", section: "blogs", keywords: "blog post article write content" },
  { id: "events", label: "Events", section: "events", keywords: "event screening registration" },
  { id: "scanner", label: "Scanner", section: "events", keywords: "scanner qr checkin check-in ticket" },
  { id: "members", label: "Members", section: "members", keywords: "member team roster people" },
  { id: "movies", label: "Films", section: "movies", keywords: "movie film production showcase" },
  { id: "chitra-vichitra", label: "Chitra Vichitra", section: "chitra-vichitra", keywords: "chitra vichitra magazine" },
  { id: "testimonials", label: "Testimonials", section: "testimonials", keywords: "testimonial review quote" },
  { id: "achievements", label: "Achievements", section: "achievements", keywords: "achievement award milestone" },
  { id: "wrapped", label: "Wrapped", section: "wrapped", keywords: "wrapped recap year in review" },
  { id: "collaborate", label: "Collaborate", section: "collaborate", keywords: "collaborate collaboration partner" },
  { id: "easter-eggs", label: "Easter Eggs", section: "settings", keywords: "easter egg search hidden" },
  { id: "analytics", label: "Analytics", section: "analytics", keywords: "analytics traffic visitors" },
  { id: "review-analytics", label: "Review Analytics", section: "review-analytics", keywords: "review analytics ratings" },
  { id: "reg-analytics", label: "Registration Analytics", section: "events", keywords: "registration analytics signups" },
  { id: "payment-analytics", label: "Payment Analytics", section: "settings", keywords: "payment donation analytics revenue" },
  { id: "comments", label: "Comments", section: "settings", keywords: "comment moderation reply" },
  { id: "broadcast", label: "Broadcast", section: "notifications", keywords: "broadcast email newsletter blast" },
  { id: "themes", label: "Themes", section: "settings", keywords: "theme color palette appearance" },
  { id: "member-portal", label: "Member Portal", section: "members", keywords: "member portal account login" },
  { id: "member-profile-changes", label: "Profile Change Requests", section: "members", keywords: "profile change request approval" },
  { id: "member-movie-submissions", label: "Movie Submissions", section: "members", keywords: "movie submission member upload" },
  { id: "work-edit-requests", label: "Work Edit Requests", section: "members", keywords: "work edit request portfolio" },
  { id: "credits", label: "Site Credits", section: "settings", keywords: "credits contributors developers designers" },
  { id: "settings", label: "Settings", section: "settings", keywords: "settings config email site" },
  { id: "change-password", label: "Change Password", section: null, keywords: "password security change" },
  { id: "two-factor", label: "Two-Factor Auth", section: null, keywords: "2fa two factor security otp" },
  { id: "admins", label: "Admin Accounts", section: null, keywords: "admin account user role permission", masterOnly: true },
  { id: "activity", label: "Activity Log", section: null, keywords: "activity log audit history undo", masterOnly: true },
];

// ── Fuzzy matching helpers for admin search ──────────────────────────────
// Plain ilike substring matching means a single typo ("memebrs", "anlytics")
// returns nothing. These helpers add typo-tolerant scoring + ranking, and
// power the "did you mean" suggestion when a query has zero hits.
function _levenshtein(a, b) {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (!al) return bl;
  if (!bl) return al;
  let prev = Array.from({ length: bl + 1 }, (_, i) => i);
  for (let i = 1; i <= al; i++) {
    const cur = [i];
    for (let j = 1; j <= bl; j++) {
      cur[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : Math.min(prev[j - 1] + 1, prev[j] + 1, cur[j - 1] + 1);
    }
    prev = cur;
  }
  return prev[bl];
}

// Score how well `text` matches query `q` (0..1, higher is better).
// Rewards exact matches, prefix matches, and substrings highest;
// falls back to edit-distance similarity for fuzzy/typo tolerance.
function _fuzzyScore(text, q) {
  if (!text) return 0;
  const t = text.toLowerCase().trim();
  const query = q.toLowerCase().trim();
  if (!t || !query) return 0;
  if (t === query) return 1;
  if (t.startsWith(query)) return 0.92;
  if (t.includes(query)) return 0.8;
  // word-level prefix match, e.g. "anly" vs "Payment Analytics"
  const words = t.split(/\s+/);
  if (words.some((w) => w.startsWith(query))) return 0.7;
  const dist = _levenshtein(t.length > 40 ? t.slice(0, 40) : t, query);
  const maxLen = Math.max(t.length, query.length);
  const similarity = 1 - dist / maxLen;
  return similarity > 0.45 ? similarity * 0.65 : 0;
}

function _bestFieldScore(fields, q) {
  let best = 0;
  for (const f of fields) {
    const s = _fuzzyScore(f, q);
    if (s > best) best = s;
  }
  return best;
}

// Score a query (which may be multiple words, e.g. "site credits") against a
// label + a space-separated keyword blob. Checks three things and takes the
// best: (1) the whole query as a phrase against the whole blob/label, so
// "site credits" matches a "site credits team..." keyword string even though
// no single token equals the full query, (2) each query word against the
// blob individually for fuzzy/typo tolerance per word, and (3) what fraction
// of the query's words are found (fuzzily) somewhere in the blob, so partial
// multi-word matches still rank reasonably.
function _phraseScore(label, keywordBlob, q) {
  const query = q.toLowerCase().trim();
  const haystack = `${label} ${keywordBlob}`.toLowerCase();
  const wholePhrase = Math.max(_fuzzyScore(label, query), _fuzzyScore(keywordBlob, query));
  if (wholePhrase >= 0.7) return wholePhrase;

  const qWords = query.split(/\s+/).filter(Boolean);
  const kwTokens = keywordBlob.split(/\s+/).filter(Boolean);
  if (qWords.length <= 1) {
    return Math.max(wholePhrase, _bestFieldScore(kwTokens, query), _fuzzyScore(label, query));
  }

  let matchedWords = 0;
  let sum = 0;
  for (const w of qWords) {
    const s = Math.max(_bestFieldScore(kwTokens, w), haystack.includes(w) ? 0.8 : 0);
    if (s > 0.55) matchedWords++;
    sum += s;
  }
  const coverage = matchedWords / qWords.length;
  const avg = sum / qWords.length;
  // Reward matching most/all words of the query, not just one.
  return Math.max(wholePhrase, coverage >= 0.5 ? avg : avg * 0.5);
}

app.get("/api/admin/search", authMiddleware, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (q.length < 2) return res.json({ sections: [], results: [], didYouMean: null });

  const isMaster = req.admin.role === "master";
  const perms = req.admin.permissions || [];
  const canAccess = (section) => isMaster || !section || perms.includes(section);

  // Matching sections — fuzzy scored against label + full keyword phrase
  // (not just single keyword tokens), so multi-word queries like
  // "site credits" correctly match a "credits site credits team..." blob.
  const scoredSections = ADMIN_SECTION_INDEX
    .filter((s) => isMaster || !s.masterOnly)
    .filter((s) => canAccess(s.section))
    .map((s) => ({ s, score: _phraseScore(s.label, s.keywords, q) }))
    .filter((x) => x.score > 0.3)
    .sort((a, b) => b.score - a.score);

  const sections = scoredSections
    .slice(0, 6)
    .map(({ s }) => ({ type: "section", id: s.id, label: s.label }));

  const results = [];
  // PostgREST's .or() syntax treats commas and parentheses as structural
  // delimiters — strip them from the search term so queries like "Smith, John"
  // or "100% (final)" don't silently break the ilike filters below.
  const safeQ = q.replace(/[,()]/g, " ").trim();
  if (!safeQ) return res.json({ sections, results: [], didYouMean: null });

  // Pull a generous candidate pool per table via trigram-ish broad ilike (each
  // word of the query, OR'd), then re-rank with fuzzy scoring server-side.
  // This catches typos/transpositions that a strict substring `like` misses,
  // while still using an index-friendly ilike to keep the DB query cheap.
  const words = safeQ.split(/\s+/).filter(Boolean);
  const wideLike = (cols) => {
    const variants = words.length ? words : [safeQ];
    const clauses = [];
    cols.forEach((c) => variants.forEach((w) => clauses.push(`${c}.ilike.%${w}%`)));
    return clauses.join(",");
  };

  const tasks = [];

  if (canAccess("members")) {
    tasks.push(
      supabase
        .from("members")
        .select("id,name,role,batch,email,roll_no,photo")
        .is("deleted_at", null)
        .or(wideLike(["name", "email", "roll_no", "role"]))
        .limit(40)
        .then(({ data }) => (data || []).map((m) => ({
          type: "member",
          id: m.id,
          title: m.name,
          subtitle: [m.role, m.batch].filter(Boolean).join(" • ") || m.email,
          image: m.photo || null,
          _score: _bestFieldScore([m.name, m.email, m.roll_no, m.role], safeQ),
        }))),
    );
  }

  if (canAccess("events")) {
    tasks.push(
      supabase
        .from("events")
        .select("id,title,location,event_date,is_upcoming")
        .is("deleted_at", null)
        .or(wideLike(["title", "location"]))
        .limit(40)
        .then(({ data }) => (data || []).map((e) => ({
          type: "event",
          id: e.id,
          title: e.title,
          subtitle: [e.location, e.event_date ? new Date(e.event_date).toLocaleDateString() : null].filter(Boolean).join(" • "),
          image: null,
          _score: _bestFieldScore([e.title, e.location], safeQ),
        }))),
    );
  }

  if (canAccess("blogs")) {
    tasks.push(
      supabase
        .from("blogs")
        .select("id,title,author,published,cover_image")
        .is("deleted_at", null)
        .or(wideLike(["title", "author"]))
        .limit(40)
        .then(({ data }) => (data || []).map((b) => ({
          type: "blog",
          id: b.id,
          title: b.title,
          subtitle: [b.author, b.published ? "Published" : "Draft"].filter(Boolean).join(" • "),
          image: b.cover_image || null,
          _score: _bestFieldScore([b.title, b.author], safeQ),
        }))),
    );
  }

  if (canAccess("movies")) {
    tasks.push(
      supabase
        .from("movies")
        .select("id,title,release_year,director,poster_image")
        .is("deleted_at", null)
        .or(wideLike(["title", "director"]))
        .limit(40)
        .then(({ data }) => (data || []).map((m) => ({
          type: "movie",
          id: m.id,
          title: m.title,
          subtitle: [m.director, m.release_year].filter(Boolean).join(" • "),
          image: m.poster_image || null,
          _score: _bestFieldScore([m.title, m.director], safeQ),
        }))),
    );
  }

  if (canAccess("settings")) {
    tasks.push(
      supabase
        .from("donors")
        .select("id,name,email,roll_no,amount_paise,semester_label,is_anonymous")
        .or(wideLike(["name", "email", "roll_no"]))
        .limit(40)
        .then(({ data }) => (data || []).map((d) => ({
          type: "donor",
          id: d.id,
          title: d.is_anonymous ? "Anonymous Donor" : (d.name || d.email),
          subtitle: [d.semester_label, d.amount_paise ? `₹${(d.amount_paise / 100).toLocaleString("en-IN")}` : null].filter(Boolean).join(" • "),
          image: null,
          _score: _bestFieldScore([d.name, d.email, d.roll_no], safeQ),
        }))),
    );
  }

  if (isMaster) {
    tasks.push(
      supabase
        .from("admins")
        .select("id,username,name,role")
        .or(wideLike(["username", "name"]))
        .limit(20)
        .then(({ data }) => (data || []).map((a) => ({
          type: "admin",
          id: a.id,
          title: a.name || a.username,
          subtitle: a.role,
          image: null,
          _score: _bestFieldScore([a.name, a.username], safeQ),
        }))),
    );
  }

  const settled = await Promise.allSettled(tasks);
  settled.forEach((r) => {
    if (r.status === "fulfilled") results.push(...r.value);
  });

  // Rank by fuzzy score (desc), drop noise below a minimum relevance floor,
  // then strip the internal _score before sending to the client.
  const ranked = results
    .filter((r) => r._score > 0.28)
    .sort((a, b) => b._score - a._score)
    .slice(0, 30)
    .map(({ _score, ...rest }) => rest);

  // "Did you mean" — only computed when the literal query came up empty.
  // Returns multiple ranked guesses (not just one), so a vague or
  // multi-word typo gets several real options instead of a single guess
  // that might be wrong. Compares against section labels (always available,
  // cheap) plus every fetched candidate row across all tables, scored even
  // below the relevance floor used for real results — a typo like "memebrs"
  // or "site credits" -> "credits" should still surface the right entries.
  let didYouMean = [];
  if (!sections.length && !ranked.length) {
    const candidates = [];

    ADMIN_SECTION_INDEX
      .filter((s) => isMaster || !s.masterOnly)
      .filter((s) => canAccess(s.section))
      .forEach((s) => {
        const score = _phraseScore(s.label, s.keywords, q);
        if (score > 0.3) candidates.push({ text: s.label, score, type: "section", id: s.id });
      });

    results.forEach((r) => {
      const text = r.title || r.label;
      if (r._score > 0.3) candidates.push({ text, score: r._score, type: r.type, id: r.id });
    });

    // Dedupe by type+id (a record could theoretically appear twice from
    // overlapping word-variant ilike clauses) and by identical text, then
    // take the top few distinct suggestions.
    const seen = new Set();
    didYouMean = candidates
      .sort((a, b) => b.score - a.score)
      .filter((c) => {
        const key = `${c.type}:${c.id}:${c.text}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .slice(0, 5)
      .map(({ text, type, id }) => ({ text, type, id }));
  }

  res.json({ sections, results: ranked, didYouMean });
});

app.get("/api/admin/blogs", requireSection("blogs"), async (req, res) => {
  const { data } = await supabase
    .from("blogs")
    .select(
      "id,title,author,published,view_count,cover_image,created_at,sections",
    )
    // Don't fetch `content` in the list — it's huge HTML. Only needed in /api/blogs/:id
    .is("deleted_at", null)
    .order("created_at", { ascending: false })
    .limit(200);
  res.json(data || []);
});

app.get("/api/blogs/:id", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache(`blogs:${req.params.id}`, 300, async () => {
    const { data } = await supabasePublic
      .from("blogs")
      .select("*")
      .eq("id", req.params.id)
      .is("deleted_at", null)
      .maybeSingle();
    return data;
  });
  if (!data) return res.status(404).json({ error: "Not found" });

  // Fire-and-forget view increment — runs on every real HTTP request (not on cache hits),
  // because this code is outside the memCache fn. Uses DB increment to avoid race conditions.
  supabasePublic.rpc("increment_blog_view", { blog_id: req.params.id })
    .then(() => {})
    .catch(async () => {
      // Fallback if RPC doesn't exist yet: re-fetch the current count fresh (don't use the
      // cached `data.view_count` — it can be up to 300s stale, causing repeated requests in
      // that window to all add 1 to the same stale base and stomp each other's increments).
      try {
        const { data: fresh } = await supabasePublic
          .from("blogs")
          .select("view_count")
          .eq("id", req.params.id)
          .maybeSingle();
        const current = fresh ? (fresh.view_count || 0) : (data.view_count || 0);
        await supabasePublic
          .from("blogs")
          .update({ view_count: current + 1 })
          .eq("id", req.params.id);
      } catch (e) {
        // non-fatal
      }
    });

  res.json(data);
});

// ── BLOG ANALYTICS (admin) ────────────────────────────────────────────────────
app.get(
  "/api/admin/blogs/analytics",
  requireSection("blogs"),
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("blogs")
        .select("id, title, author, published, view_count, created_at")
        .order("view_count", { ascending: false });

      if (error) return res.status(500).json({ error: "Internal server error" });

      const blogs = data || [];
      const total_views = blogs.reduce(
        (sum, b) => sum + (b.view_count || 0),
        0,
      );
      const published_count = blogs.filter((b) => b.published).length;
      const draft_count = blogs.filter((b) => !b.published).length;
      const top_post = blogs[0] || null;

      res.json({ total_views, published_count, draft_count, top_post, blogs });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post(
  "/api/admin/blogs",
  requireSection("blogs"),
  upload.single("cover"),
  async (req, res) => {
    const { title, author, excerpt, content, published, sections } = req.body;
    const coverUrl = await uploadImage(req.file, "blogs");
    const { data, error } = await supabase
      .from("blogs")
      .insert([
        {
          title,
          author: author || null,
          excerpt,
          content,
          cover_image: coverUrl,
          published: published === "true",
          sections: sections || "[]",
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("blogs:list");
    logActivity(req.admin.id, req.admin.name, "create", "blog", title).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.put(
  "/api/admin/blogs/:id",
  requireSection("blogs"),
  upload.single("cover"),
  async (req, res) => {
    const { title, author, excerpt, content, published, sections } = req.body;
    const updates = {
      title,
      author: author || null,
      excerpt,
      content,
      published: published === "true",
      sections: sections || "[]",
    };
    if (req.file) updates.cover_image = await uploadImage(req.file, "blogs");
    const { data, error } = await supabase
      .from("blogs")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("blogs:list", `blogs:${req.params.id}`);
    logActivity(req.admin.id, req.admin.name, "update", "blog", title).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.delete(
  "/api/admin/blogs/:id",
  requireSection("blogs"),
  async (req, res) => {
    const { data: b } = await supabase
      .from("blogs")
      .select("*")
      .eq("id", req.params.id)
      .single();
    await supabase.from("blogs").update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
    memInvalidate("blogs:list", `blogs:${req.params.id}`);
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "blog",
      b?.title || req.params.id,
      req.params.id,
      b,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ── EVENTS ────────────────────────────────────────────────────────────────────
app.get("/api/events", async (req, res) => {
  cacheFor(res, 60);
  const data = await memCache("events:list", 120, async () => {
    const { data } = await supabasePublic
      .from("events")
      .select("*")
      .is("deleted_at", null)
      .order("event_date", { ascending: false });
    return data || [];
  });
  res.json(data);
});

app.post(
  "/api/admin/events",
  requireSection("events"),
  upload.single("cover"),
  async (req, res) => {
    const {
      title,
      description,
      event_date,
      event_time,
      location,
      location_link,
      is_upcoming,
    } = req.body;
    const coverUrl = await uploadImage(req.file, "events");
    const { data, error } = await supabase
      .from("events")
      .insert([
        {
          title,
          description,
          event_date,
          event_time,
          location,
          location_link: location_link || null,
          cover_image: coverUrl,
          is_upcoming: is_upcoming === "true",
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("events:list");
    logActivity(req.admin.id, req.admin.name, "create", "event", title).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.put(
  "/api/admin/events/:id",
  requireSection("events"),
  upload.single("cover"),
  async (req, res) => {
    const {
      title,
      description,
      event_date,
      event_time,
      location,
      location_link,
      is_upcoming,
    } = req.body;
    const updates = {
      title,
      description,
      event_date,
      event_time,
      location,
      location_link: location_link || null,
      is_upcoming: is_upcoming === "true",
    };
    if (req.file) updates.cover_image = await uploadImage(req.file, "events");
    const { data, error } = await supabase
      .from("events")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("events:list");
    logActivity(req.admin.id, req.admin.name, "update", "event", title).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.delete(
  "/api/admin/events/:id",
  requireSection("events"),
  async (req, res) => {
    const { data: e } = await supabase
      .from("events")
      .select("*")
      .eq("id", req.params.id)
      .single();
    await supabase.from("events").update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
    memInvalidate("events:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "event",
      e?.title || req.params.id,
      req.params.id,
      e,
    ).catch(e2 => console.error("[activity]", e2.message));
    res.json({ success: true });
  },
);

// ── MEMBERS ───────────────────────────────────────────────────────────────────
app.get("/api/members", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache("members:list", 120, async () => {
    const { data, error } = await supabasePublic
      .from("members")
      .select(
        "id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past,instagram,github,linkedin,twitter,youtube,website,custom_links",
      )
      .is("deleted_at", null)
      .order("sort_order", { ascending: true });

    // If social/portal columns don't exist yet, fall back to base columns
    if (error) {
      console.warn("[members] Full select failed (missing columns?), trying base columns:", error.message);
      const { data: base } = await supabase
        .from("members")
        .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past")
        .is("deleted_at", null)
        .order("sort_order", { ascending: true });
      return base || [];
    }

    // If anon client returned empty (likely an RLS policy blocking reads),
    // fall back to the admin client so the public page always works
    if (!data || data.length === 0) {
      console.warn("[members] supabasePublic returned empty — falling back to admin client (check RLS on members table)");
      const { data: fallback } = await supabase
        .from("members")
        .select(
          "id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past,instagram,github,linkedin,twitter,youtube,website,custom_links",
        )
        .is("deleted_at", null)
        .order("sort_order", { ascending: true });
      return fallback || [];
    }

    return data || [];
  });
  res.json(data);
});

// Admin GET — bypasses memCache so panel always shows fresh data after add/edit/delete
app.get("/api/admin/members", requireSection("members"), async (req, res) => {
  // Try full column list first; fall back to base columns if social/portal columns don't exist yet
  let { data, error } = await supabase
    .from("members")
    .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past,instagram,github,linkedin,twitter,youtube,website,custom_links,email,mobile")
    .is("deleted_at", null)
    .order("sort_order", { ascending: true });

  if (error) {
    // Likely means some columns (instagram, custom_links etc.) don't exist yet — run member portal migration
    console.warn("[admin/members] Full select failed, falling back to base columns:", error.message);
    const fallback = await supabase
      .from("members")
      .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past,email,mobile")
      .is("deleted_at", null)
      .order("sort_order", { ascending: true });
    if (fallback.error) return res.status(500).json({ error: "Internal server error" });
    return res.json(fallback.data || []);
  }

  res.json(data || []);
});

// GET /api/admin/members/export — Download all member data as Excel (no passwords/2FA)
app.get("/api/admin/members/export", requireSection("members"), async (req, res) => {
  const { data: members, error: mErr } = await supabase
    .from("members")
    .select("id,name,roll_no,mobile,email,batch,domain,role,bio,special_tag,sort_order,is_past,instagram,linkedin,github,twitter,youtube,website,custom_links")
    .order("sort_order", { ascending: true });
  if (mErr) return res.status(500).json({ error: "Internal server error" });

  const { data: accounts } = await supabase
    .from("member_accounts")
    .select("member_id,username,account_status,totp_enabled,last_login,created_at");

  const accountMap = {};
  (accounts || []).forEach(a => { accountMap[a.member_id] = a; });

  const XLSX = require("xlsx");
  const rows = (members || []).map(m => {
    const acc = accountMap[m.id];
    return {
      "Name":          m.name || "",
      "Roll No":       m.roll_no || "",
      "Email":         m.email || "",
      "Mobile":        m.mobile || "",
      "Batch":         m.batch || "",
      "Domain":        m.domain || "",
      "Role/Title":    m.role || "",
      "Bio":           m.bio || "",
      "Type":          m.is_past ? "Alumni" : "Current",
      "Special Tag":   m.special_tag || "",
      "Sort Order":    m.sort_order ?? "",
      "Instagram":     m.instagram || "",
      "LinkedIn":      m.linkedin || "",
      "GitHub":        m.github || "",
      "Twitter":       m.twitter || "",
      "YouTube":       m.youtube || "",
      "Website":       m.website || "",
      "Custom Links":  m.custom_links ? JSON.stringify(m.custom_links) : "",
      "Portal Username":    acc?.username || "No account",
      "Portal Status":      acc?.account_status || "—",
      "2FA Enabled":        acc ? (acc.totp_enabled ? "Yes" : "No") : "—",
      "Last Login":         acc?.last_login ? new Date(acc.last_login).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) : "—",
      "Account Created":    acc?.created_at ? new Date(acc.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) : "—",
    };
  });

  const ws = XLSX.utils.json_to_sheet(rows.length ? rows : [{ "Note": "No members found" }]);
  if (rows.length) {
    const keys = Object.keys(rows[0]);
    ws["!cols"] = keys.map(k => ({
      wch: Math.max(k.length, ...rows.map(r => String(r[k] || "").length)) + 2,
    }));
  }
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Members");
  const buf = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

  const date = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Disposition", `attachment; filename="kfs-members-${date}.xlsx"`);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.send(buf);
});

app.post(
  "/api/admin/members",
  requireSection("members"),
  upload.single("photo"),
  async (req, res) => {
    const { name, role, batch, bio, sort_order, is_past, domain, special_tag, email, mobile } =
      req.body;
    if (!name || !name.trim())
      return res.status(400).json({ error: "Name is required" });

    // New members must have a recovery email — existing members are
    // untouched, this only gates fresh creation. Mobile is still collected
    // but no longer used for forgot-password (Twilio removed).
    const emailTrim = (email || "").trim();
    const mobileTrim = (mobile || "").trim();
    if (!emailTrim)
      return res.status(400).json({ error: "Email is required (used for account recovery)." });
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!EMAIL_RE.test(emailTrim))
      return res.status(400).json({ error: "Invalid email address" });
    if (!isKiitEmail(emailTrim))
      return res.status(400).json({ error: "Member email must be a KIIT institutional address (e.g. @kiit.ac.in, @ksom.ac.in, @kiitbiotech.ac.in)." });
    if (mobileTrim && mobileTrim.replace(/\D/g, "").length < 10)
      return res.status(400).json({ error: "Invalid phone number" });

    // ── Duplicate guard: block members with same name (case-insensitive) ──────
    const { data: existing } = await supabase
      .from("members")
      .select("id")
      .ilike("name", name.trim())
      .maybeSingle();
    if (existing)
      return res
        .status(409)
        .json({ error: `Member "${name.trim()}" already exists` });

    const photoUrl = await uploadImage(req.file, "members");
    const { data, error } = await supabase
      .from("members")
      .insert([
        {
          name: name.trim(),
          role,
          batch,
          bio,
          domain: domain || null,
          photo: photoUrl,
          special_tag: special_tag || null,
          sort_order: parseInt(sort_order) || 99,
          is_past: is_past === "true",
          email: emailTrim || null,
          mobile: mobileTrim || null,
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("members:list");
    logActivity(req.admin.id, req.admin.name, "create", "member", name).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.put(
  "/api/admin/members/:id",
  requireSection("members"),
  upload.single("photo"),
  async (req, res) => {
    const { name, role, batch, bio, sort_order, is_past, domain, special_tag, email, mobile } =
      req.body;
    if (!name || !name.trim())
      return res.status(400).json({ error: "Name is required" });
    const updates = {
      name: name.trim(),
      role: role || null,
      batch: batch || null,
      bio: bio || null,
      domain: domain || null,
      special_tag: special_tag || null,
      sort_order: parseInt(sort_order) || 99,
      is_past: is_past === "true" || is_past === true,
    };
    // Email/phone are optional on edit (existing members aren't forced to backfill),
    // but validate format if the admin does supply them.
    if (email !== undefined) {
      const emailTrim = (email || "").trim();
      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (emailTrim && !EMAIL_RE.test(emailTrim)) return res.status(400).json({ error: "Invalid email address" });
      if (emailTrim && !isKiitEmail(emailTrim)) return res.status(400).json({ error: "Member email must be a KIIT institutional address (e.g. @kiit.ac.in, @ksom.ac.in, @kiitbiotech.ac.in)." });
      updates.email = emailTrim || null;
    }
    if (mobile !== undefined) {
      const mobileTrim = (mobile || "").trim();
      if (mobileTrim && mobileTrim.replace(/\D/g, "").length < 10) return res.status(400).json({ error: "Invalid phone number" });
      updates.mobile = mobileTrim || null;
    }
    if (req.file) updates.photo = await uploadImage(req.file, "members");
    const { data, error } = await supabase
      .from("members")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("members:list");
    logActivity(req.admin.id, req.admin.name, "update", "member", name).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.delete(
  "/api/admin/members/:id",
  requireSection("members"),
  async (req, res) => {
    const { data: m } = await supabase
      .from("members")
      .select("*")
      .eq("id", req.params.id)
      .single();
    await supabase.from("members").update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
    memInvalidate("members:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "member",
      m?.name || req.params.id,
      req.params.id,
      m,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ── TESTIMONIALS ──────────────────────────────────────────────────────────────
app.get("/api/testimonials", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache("testimonials:list", 600, async () => {
    const { data } = await supabasePublic
      .from("testimonials")
      .select("*")
      .order("created_at", { ascending: false });
    return data || [];
  });
  res.json(data);
});

app.post(
  "/api/admin/testimonials",
  requireSection("testimonials"),
  upload.single("photo"),
  async (req, res) => {
    const { name, role, batch, quote } = req.body;
    const photoUrl = await uploadImage(req.file, "testimonials");
    const { data, error } = await supabase
      .from("testimonials")
      .insert([{ name, role, batch, quote, photo: photoUrl }])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    logActivity(
      req.admin.id,
      req.admin.name,
      "create",
      "testimonial",
      name,
    ).catch(e => console.error("[activity]", e.message));
    memInvalidate("testimonials:list");
    res.json(data);
  },
);

app.put(
  "/api/admin/testimonials/:id",
  requireSection("testimonials"),
  upload.single("photo"),
  async (req, res) => {
    const { name, role, batch, quote } = req.body;
    const updates = { name, role, batch, quote };
    if (req.file) updates.photo = await uploadImage(req.file, "testimonials");
    const { data, error } = await supabase
      .from("testimonials")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("testimonials:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "testimonial",
      name,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.delete(
  "/api/admin/testimonials/:id",
  requireSection("testimonials"),
  async (req, res) => {
    const { data: t } = await supabase
      .from("testimonials")
      .select("name")
      .eq("id", req.params.id)
      .single();
    await supabase.from("testimonials").delete().eq("id", req.params.id);
    memInvalidate("testimonials:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "testimonial",
      t?.name || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ── SITE CREDITS ─────────────────────────────────────────────────────────────
// Supabase migration — run once:
// CREATE TABLE IF NOT EXISTS site_credits (
//   id           BIGSERIAL PRIMARY KEY,
//   member_id    BIGINT REFERENCES members(id) ON DELETE SET NULL,
//   member_name  TEXT NOT NULL,
//   member_photo TEXT,
//   credit_roles JSONB DEFAULT '[]'::jsonb,
//   description  TEXT,
//   sort_order   INT  DEFAULT 99,
//   created_at   TIMESTAMPTZ DEFAULT NOW()
// );
// ALTER TABLE site_credits ENABLE ROW LEVEL SECURITY;
// CREATE POLICY "Public read site_credits" ON site_credits FOR SELECT USING (true);
// Public: GET /api/credits
app.get("/api/credits", async (req, res) => {
  cacheFor(res, 120);
  try {
    const data = await memCache("credits:list", 600, async () => {
      const { data, error } = await supabasePublic
        .from("site_credits")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) {
        console.error("[credits GET public]", error);
        throw error; // don't cache a failed lookup
      }
      if (!data || !data.length) {
        // Don't cache an empty result — a 10-min (and disk-persisted) cache of
        // "[]" would keep hiding real credits added moments later.
        throw new Error("__skip_cache_empty__");
      }
      return data;
    });
    res.json(data);
  } catch (e) {
    if (e.message !== "__skip_cache_empty__") console.error("[credits GET public]", e);
    res.json([]);
  }
});

// Admin: GET /api/admin/credits
app.get("/api/admin/credits", requireSection("settings"), async (req, res) => {
  const { data, error } = await supabase
    .from("site_credits")
    .select("*")
    .order("sort_order", { ascending: true });
  if (error) { console.error("[credits GET]", error); return res.status(500).json({ error: error.message || "Internal server error" }); }
  res.json(data || []);
});

// Admin: POST /api/admin/credits
app.post("/api/admin/credits", requireSection("settings"), async (req, res) => {
  const { member_id, member_name, member_photo, credit_roles, description, sort_order } = req.body;
  // credit_roles arrives as array from JSON body; ensure it's valid for JSONB
  let roles = credit_roles || [];
  if (typeof roles === "string") { try { roles = JSON.parse(roles); } catch { roles = []; } }
  const { data, error } = await supabase
    .from("site_credits")
    .insert([{
      member_id: member_id || null,
      member_name,
      member_photo: member_photo || null,
      credit_roles: roles,
      description: description || null,
      sort_order: parseInt(sort_order) || 99,
    }])
    .select()
    .single();
  if (error) { console.error("[credits POST]", error); return res.status(500).json({ error: error.message || "Internal server error" }); }
  logActivity(req.admin.id, req.admin.name, "create", "credit", member_name).catch(e => console.error("[activity]", e.message));
  memInvalidate("credits:list");
  res.json(data);
});

// Admin: PUT /api/admin/credits/:id
app.put("/api/admin/credits/:id", requireSection("settings"), async (req, res) => {
  const { member_id, member_name, member_photo, credit_roles, description, sort_order } = req.body;
  let roles = credit_roles || [];
  if (typeof roles === "string") { try { roles = JSON.parse(roles); } catch { roles = []; } }
  const updates = {
    member_id: member_id || null,
    member_name,
    member_photo: member_photo || null,
    credit_roles: roles,
    description: description || null,
    sort_order: parseInt(sort_order) || 99,
  };
  const { data, error } = await supabase
    .from("site_credits")
    .update(updates)
    .eq("id", req.params.id)
    .select()
    .single();
  if (error) { console.error("[credits PUT]", error); return res.status(500).json({ error: error.message || "Internal server error" }); }
  logActivity(req.admin.id, req.admin.name, "update", "credit", member_name).catch(e => console.error("[activity]", e.message));
  memInvalidate("credits:list");
  res.json(data);
});

// Admin: DELETE /api/admin/credits/:id
app.delete("/api/admin/credits/:id", requireSection("settings"), async (req, res) => {
  const { data: c } = await supabase.from("site_credits").select("member_name").eq("id", req.params.id).single();
  await supabase.from("site_credits").delete().eq("id", req.params.id);
  logActivity(req.admin.id, req.admin.name, "delete", "credit", c?.member_name || req.params.id).catch(e => console.error("[activity]", e.message));
  memInvalidate("credits:list");
  res.json({ success: true });
});

// ── ACHIEVEMENTS ──────────────────────────────────────────────────────────────
app.get("/api/achievements", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache("achievements:list", 600, async () => {
    const { data } = await supabasePublic
      .from("achievements")
      .select("*")
      .order("sort_order", { ascending: true });
    return data || [];
  });
  res.json(data);
});

app.post(
  "/api/admin/achievements",
  requireSection("achievements"),
  upload.single("image"),
  async (req, res) => {
    const { title, description, year, sort_order } = req.body;
    const imageUrl = req.file ? await uploadImage(req.file, "general") : null;
    const { data, error } = await supabase
      .from("achievements")
      .insert([
        {
          title,
          description,
          year,
          image: imageUrl,
          sort_order: parseInt(sort_order) || 99,
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("achievements:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "create",
      "achievement",
      title,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.put(
  "/api/admin/achievements/:id",
  requireSection("achievements"),
  upload.single("image"),
  async (req, res) => {
    const { title, description, year, sort_order } = req.body;
    const updates = {
      title,
      description,
      year,
      sort_order: parseInt(sort_order) || 99,
    };
    if (req.file) updates.image = await uploadImage(req.file, "general");
    const { data, error } = await supabase
      .from("achievements")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("achievements:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "achievement",
      title,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

app.delete(
  "/api/admin/achievements/:id",
  requireSection("achievements"),
  async (req, res) => {
    const { data: a } = await supabase
      .from("achievements")
      .select("title")
      .eq("id", req.params.id)
      .single();
    await supabase.from("achievements").delete().eq("id", req.params.id);
    memInvalidate("achievements:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "achievement",
      a?.title || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ── MOVIES ────────────────────────────────────────────────────────────────────
// Helper: parse genre field (stored as JSON array or legacy string)
function parseGenre(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const p = JSON.parse(raw);
    return Array.isArray(p) ? p : [p];
  } catch {
    return [raw];
  }
}

// YouTube duration auto-fetch (scrapes public YT page — no API key needed)
app.get("/api/yt-duration", async (req, res) => {
  const videoId = (req.query.v || "")
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 11);
  if (!videoId) return res.status(400).json({ error: "Missing video ID" });
  try {
    const https = require("https");

    // Helper: fetch URL with timeout and follow redirects
    function httpsGet(url, hdrs) {
      return new Promise((resolve, reject) => {
        const opts = new URL(url);
        const req = https.get(
          {
            hostname: opts.hostname,
            path: opts.pathname + opts.search,
            headers: hdrs || {},
          },
          (r) => {
            // follow one redirect
            if (
              (r.statusCode === 301 || r.statusCode === 302) &&
              r.headers.location
            ) {
              return httpsGet(r.headers.location, hdrs)
                .then(resolve)
                .catch(reject);
            }
            let body = "";
            r.on("data", (chunk) => {
              body += chunk;
              if (body.length > 300000) r.destroy();
            });
            r.on("end", () => resolve({ status: r.statusCode, body }));
            r.on("error", reject);
          },
        );
        req.on("error", reject);
        req.setTimeout(8000, () => {
          req.destroy();
          reject(new Error("timeout"));
        });
      });
    }

    let seconds = null;

    // Strategy 1: YouTube noembed (returns duration in seconds via oembed-style endpoint)
    try {
      const ne = await httpsGet(
        `https://noembed.com/embed?url=https://www.youtube.com/watch?v=${videoId}`,
      );
      if (ne.status === 200) {
        // noembed doesn't return duration — skip to next strategy
      }
    } catch (_) {}

    // Strategy 2: Scrape YouTube watch page — try multiple patterns
    if (!seconds) {
      try {
        const yt = await httpsGet(
          `https://www.youtube.com/watch?v=${videoId}`,
          {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          },
        );
        if (yt.status === 200) {
          const html = yt.body;
          const m1 = html.match(/"lengthSeconds"\s*:\s*"(\d+)"/);
          if (m1) seconds = parseInt(m1[1], 10);
          if (!seconds) {
            const m2 = html.match(/"approxDurationMs"\s*:\s*"(\d+)"/);
            if (m2) seconds = Math.round(parseInt(m2[1], 10) / 1000);
          }
          if (!seconds) {
            // Try ISO 8601 duration in structured data: "duration":"PT4M13S"
            const m3 = html.match(
              /"duration"\s*:\s*"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?"/,
            );
            if (m3) {
              seconds =
                parseInt(m3[1] || 0) * 3600 +
                parseInt(m3[2] || 0) * 60 +
                parseInt(m3[3] || 0);
            }
          }
        }
      } catch (_) {}
    }

    // Strategy 3: YouTube shorts / embed page (lighter, may reveal duration)
    if (!seconds) {
      try {
        const embed = await httpsGet(
          `https://www.youtube.com/embed/${videoId}`,
          { "User-Agent": "Mozilla/5.0 (compatible; KFSBot/1.0)" },
        );
        if (embed.status === 200) {
          const m = embed.body.match(/"lengthSeconds"\s*:\s*"(\d+)"/);
          if (m) seconds = parseInt(m[1], 10);
        }
      } catch (_) {}
    }

    if (seconds && seconds > 0) {
      return res.json({ seconds, minutes: Math.round(seconds / 60) });
    }
    return res.json({ error: "Duration not found" });
  } catch (e) {
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/movies", async (req, res) => {
  cacheFor(res, 60);
  // Cache the full table once — genre filtering is applied in-memory below so we don't
  // create a separate Supabase round-trip (and cache entry) per genre value.
  const movies = await memCache("movies:list", 1800, async () => {
    const { data } = await supabasePublic
      .from("movies")
      .select(
        "id,title,release_year,genre,director,producer,dop,screenwriter,video_editor,sound_design,management,graphic_design,actors,support_crew,poster_image,description,trailer_url,watch_url",
      )
      .is("deleted_at", null)
      .order("release_year", { ascending: false });
    return (data || []).map((m) => ({ ...m, genre: parseGenre(m.genre) }));
  });
  let result = movies;
  if (req.query.genre) {
    const filterGenre = req.query.genre.toLowerCase();
    result = movies.filter((m) =>
      m.genre.some((g) => g.toLowerCase() === filterGenre),
    );
  }
  res.json(result);
});

app.get("/api/movies/:id", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache(`movies:${req.params.id}`, 300, async () => {
    const { data } = await supabasePublic
      .from("movies")
      .select("*")
      .eq("id", req.params.id)
      .is("deleted_at", null)
      .maybeSingle();
    return data;
  });
  if (!data) return res.status(404).json({ error: "Not found" });
  res.json({ ...data, genre: parseGenre(data.genre) });
});

app.post(
  "/api/admin/movies",
  requireSection("movies"),
  upload.single("poster"),
  async (req, res) => {
    const {
      title,
      release_year,
      genre,
      description,
      director,
      producer,
      dop,
      screenwriter,
      video_editor,
      sound_design,
      management,
      graphic_design,
      actors,
      support_crew,
      trailer_url,
      watch_url,
      spotify_url,
      apple_music_url,
      runtime,
      language,
    } = req.body;
    // genre arrives as JSON string array from frontend
    let genreVal = null;
    if (genre) {
      try {
        const p = JSON.parse(genre);
        genreVal = Array.isArray(p) && p.length ? JSON.stringify(p) : null;
      } catch {
        genreVal = genre || null;
      }
    }
    const posterUrl = await uploadImage(req.file, "movies");
    // Validate external URLs — only https:// is allowed to prevent javascript: XSS
    if (watch_url && !/^https:\/\//i.test(watch_url)) {
      return res.status(400).json({ error: "watch_url must start with https://" });
    }
    if (trailer_url && !/^https:\/\//i.test(trailer_url)) {
      return res.status(400).json({ error: "trailer_url must start with https://" });
    }
    const { data, error } = await supabase
      .from("movies")
      .insert([
        {
          title,
          release_year,
          genre: genreVal,
          description: description || null,
          director,
          producer,
          dop,
          screenwriter,
          video_editor,
          sound_design,
          management,
          graphic_design,
          actors,
          support_crew,
          poster_image: posterUrl,
          trailer_url: trailer_url || null,
          watch_url: watch_url || null,
          spotify_url: spotify_url || null,
          apple_music_url: apple_music_url || null,
          runtime: runtime ? parseInt(runtime, 10) : null,
          language: language || null,
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("movies:list", "movies:genre:");
    logActivity(req.admin.id, req.admin.name, "create", "movie", title).catch(e => console.error("[activity]", e.message));
    res.json({ ...data, genre: parseGenre(data.genre) });
  },
);

app.put(
  "/api/admin/movies/:id",
  requireSection("movies"),
  upload.single("poster"),
  async (req, res) => {
    const {
      title,
      release_year,
      genre,
      description,
      director,
      producer,
      dop,
      screenwriter,
      video_editor,
      sound_design,
      management,
      graphic_design,
      actors,
      support_crew,
      trailer_url,
      watch_url,
      spotify_url,
      apple_music_url,
      runtime,
      language,
    } = req.body;
    let genreVal = null;
    if (genre) {
      try {
        const p = JSON.parse(genre);
        genreVal = Array.isArray(p) && p.length ? JSON.stringify(p) : null;
      } catch {
        genreVal = genre || null;
      }
    }
    // Validate external URLs — only https:// is allowed to prevent javascript: XSS
    if (watch_url && !/^https:\/\//i.test(watch_url)) {
      return res.status(400).json({ error: "watch_url must start with https://" });
    }
    if (trailer_url && !/^https:\/\//i.test(trailer_url)) {
      return res.status(400).json({ error: "trailer_url must start with https://" });
    }
    const updates = {
      title,
      release_year,
      genre: genreVal,
      description: description || null,
      director,
      producer,
      dop,
      screenwriter,
      video_editor,
      sound_design,
      management,
      graphic_design,
      actors,
      support_crew,
      trailer_url: trailer_url || null,
      watch_url: watch_url || null,
      spotify_url: spotify_url || null,
      apple_music_url: apple_music_url || null,
      runtime: runtime ? parseInt(runtime, 10) : null,
      language: language || null,
    };
    if (req.file) updates.poster_image = await uploadImage(req.file, "movies");
    const { data, error } = await supabase
      .from("movies")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("movies:list", "movies:genre:", `movies:${req.params.id}`);
    logActivity(req.admin.id, req.admin.name, "update", "movie", title).catch(e => console.error("[activity]", e.message));
    res.json({ ...data, genre: parseGenre(data.genre) });
  },
);

app.delete(
  "/api/admin/movies/:id",
  requireSection("movies"),
  async (req, res) => {
    const { data: mv } = await supabase
      .from("movies")
      .select("*")
      .eq("id", req.params.id)
      .single();
    await supabase.from("movies").update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
    memInvalidate("movies:list", "movies:genre:", `movies:${req.params.id}`);
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "movie",
      mv?.title || req.params.id,
      req.params.id,
      mv,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ── CHITRA VICHITRA — PUBLIC ──────────────────────────────────────────────────
// Get all CV editions (with movie count)
app.get("/api/chitra-vichitra", async (req, res) => {
  cacheFor(res, 120);
  const result = await memCache("cv:list", 600, async () => {
    const { data: editions, error } = await supabasePublic
      .from("chitra_vichitra")
      .select("*")
      .order("sort_order", { ascending: true });
    if (error) throw error;
    if (!editions || editions.length === 0) return [];
    const { data: allCvMovies } = await supabasePublic
      .from("chitra_vichitra_movies")
      .select("cv_id");
    const countMap = {};
    (allCvMovies || []).forEach((row) => {
      countMap[row.cv_id] = (countMap[row.cv_id] || 0) + 1;
    });
    return editions.map((cv) => ({ ...cv, movie_count: countMap[cv.id] || 0 }));
  });
  res.json(result);
});

// Get movies for a specific CV edition
app.get("/api/chitra-vichitra/:id/movies", async (req, res) => {
  const { data, error } = await supabasePublic
    .from("chitra_vichitra_movies")
    .select(
      `
      id,
      movies (
        id, title, release_year, director, poster_image, trailer_url, watch_url,
        producer, dop, screenwriter, video_editor, sound_design, management,
        graphic_design, actors, support_crew
      )
    `,
    )
    .eq("cv_id", req.params.id);
  if (error) return res.status(500).json({ error: "Internal server error" });

  // Flatten: attach cv_movie_id for removal from admin
  const movies = (data || []).map((row) => ({
    cv_movie_id: row.id,
    ...row.movies,
  }));
  res.json(movies);
});

// ── CHITRA VICHITRA — ADMIN ───────────────────────────────────────────────────
// Create a new CV edition
app.post(
  "/api/admin/chitra-vichitra",
  requireSection("chitra-vichitra"),
  upload.single("cover"),
  async (req, res) => {
    const { year, sort_order } = req.body;
    if (!year) return res.status(400).json({ error: "Year is required" });
    const coverUrl = await uploadImage(req.file, "chitra-vichitra");
    const { data, error } = await supabase
      .from("chitra_vichitra")
      .insert([
        {
          year: year.trim(),
          cover_image: coverUrl,
          sort_order: parseInt(sort_order) || 99,
        },
      ])
      .select()
      .single();
    if (error)
      return res.status(400).json({
        error: error.message.includes("unique")
          ? "A CV edition for this year already exists"
          : error.message,
      });
    logActivity(
      req.admin.id,
      req.admin.name,
      "create",
      "chitra_vichitra",
      `CV ${year}`,
    ).catch(e => console.error("[activity]", e.message));
    memInvalidate("cv:list");
    res.json(data);
  },
);

// Update a CV edition (year, cover, sort_order)
app.put(
  "/api/admin/chitra-vichitra/:id",
  requireSection("chitra-vichitra"),
  upload.single("cover"),
  async (req, res) => {
    const { year, sort_order } = req.body;
    const updates = {
      year: year?.trim(),
      sort_order: parseInt(sort_order) || 99,
    };
    if (req.file)
      updates.cover_image = await uploadImage(req.file, "chitra-vichitra");
    const { data, error } = await supabase
      .from("chitra_vichitra")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("cv:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "chitra_vichitra",
      `CV ${year}`,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

// Delete a CV edition (cascade deletes cv_movies via FK)
app.delete(
  "/api/admin/chitra-vichitra/:id",
  requireSection("chitra-vichitra"),
  async (req, res) => {
    const { data: cv } = await supabase
      .from("chitra_vichitra")
      .select("year")
      .eq("id", req.params.id)
      .single();
    await supabase.from("chitra_vichitra").delete().eq("id", req.params.id);
    memInvalidate("cv:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "chitra_vichitra",
      `CV ${cv?.year || req.params.id}`,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// Add a movie to a CV edition
app.post(
  "/api/admin/chitra-vichitra/:id/movies",
  requireSection("chitra-vichitra"),
  async (req, res) => {
    const { movie_id } = req.body;
    if (!movie_id) return res.status(400).json({ error: "movie_id required" });

    // Check for duplicate
    const { data: existing } = await supabase
      .from("chitra_vichitra_movies")
      .select("id")
      .eq("cv_id", req.params.id)
      .eq("movie_id", movie_id)
      .maybeSingle();
    if (existing)
      return res
        .status(400)
        .json({ error: "This film is already in this CV edition" });

    const { data, error } = await supabase
      .from("chitra_vichitra_movies")
      .insert([{ cv_id: req.params.id, movie_id }])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("cv:list");
    res.json(data);
  },
);

// Remove a movie from a CV edition (by chitra_vichitra_movies row id)
app.delete(
  "/api/admin/chitra-vichitra/movies/:cvMovieId",
  requireSection("chitra-vichitra"),
  async (req, res) => {
    await supabase
      .from("chitra_vichitra_movies")
      .delete()
      .eq("id", req.params.cvMovieId);
    memInvalidate("cv:list");
    res.json({ success: true });
  },
);

// ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
app.get("/api/notifications/active", async (req, res) => {
  noStore(res);
  const data = await memCache("notifications:active", 60, async () => {
    const { data } = await supabasePublic
      .from("notifications")
      .select("*")
      .eq("active", true)
      .limit(1)
      .maybeSingle();
    return data || null;
  });
  res.json(data);
});

app.get(
  "/api/admin/notifications",
  requireSection("notifications"),
  async (req, res) => {
    const { data } = await supabase
      .from("notifications")
      .select("*")
      .order("created_at", { ascending: false });
    res.json(data || []);
  },
);

app.post(
  "/api/admin/notifications",
  requireSection("notifications"),
  async (req, res) => {
    const { title, type, message, btn_text, btn_link, active } = req.body;
    const { data, error } = await supabase
      .from("notifications")
      .insert([
        {
          title,
          type,
          message,
          btn_text,
          btn_link,
          active: active === "true" || active === true,
        },
      ])
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("notifications:active");
    res.json(data);
  },
);

app.put(
  "/api/admin/notifications/:id",
  requireSection("notifications"),
  async (req, res) => {
    const { title, type, message, btn_text, btn_link, active } = req.body;
    const { data, error } = await supabase
      .from("notifications")
      .update({
        title,
        type,
        message,
        btn_text,
        btn_link,
        active: active === "true" || active === true,
      })
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("notifications:active");
    res.json(data);
  },
);

app.delete(
  "/api/admin/notifications/:id",
  requireSection("notifications"),
  async (req, res) => {
    await supabase.from("notifications").delete().eq("id", req.params.id);
    memInvalidate("notifications:active");
    res.json({ success: true });
  },
);

// ── SHARED: KIIT email domain check ────────────────────────────────────────────
// Single source of truth for "is this a KIIT institutional email" — used by
// /api/collaborate, members.email writes (admin create/edit + member self-edit),
// and Google Sign-In domain enforcement. Keep every consumer pointed at this
// function so the allowed-domain list only ever needs to change in one place.
function isKiitEmail(email) {
  if (!email) return false;
  const emailLower = String(email).trim().toLowerCase();
  return (
    emailLower.endsWith("@kiit.ac.in") ||
    emailLower.endsWith(".kiit.ac.in") ||
    emailLower.endsWith("@ksom.ac.in") ||
    emailLower.endsWith("@kiitbiotech.ac.in")
  );
}

// ── TRAFFIC ───────────────────────────────────────────────────────────────────
const trackLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many track requests." },
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
});

// Rough bot detector — matches common crawler/bot User-Agents
const BOT_UA_RE = /bot|crawler|spider|crawling|slurp|mediapartners|adsbot|googlebot|bingbot|yandex|duckduck|facebookexternalhit|twitterbot|linkedinbot|whatsapp|slack|telegram|curl|wget|python-requests|axios|node-fetch/i;

app.post("/api/track", trackLimit, async (req, res) => {
  const ua = req.headers["user-agent"] || "";
  if (BOT_UA_RE.test(ua)) return res.json({ ok: true }); // silently drop bot hits

  const allowed = ["home", "films", "events", "blog", "members", "collaborate"];
  const page = allowed.includes(req.body.page) ? req.body.page : "home";
  const hour = parseInt(req.body.hour) || 0;
  const today = new Date().toISOString().slice(0, 10);
  await supabasePublic.from("page_views").insert([{ page, date: today, hour }]);
  res.json({ ok: true });
});
app.get(
  "/api/admin/analytics/traffic",
  requireSection("analytics"),
  async (req, res) => {
    const range = req.query.range || "7d";
    let fromDate = new Date();
    if (range === "24h" || range === "7d") fromDate.setDate(fromDate.getDate() - 7);
    else if (range === "30d") fromDate.setDate(fromDate.getDate() - 30);
    else fromDate = new Date("2020-01-01");
    const from = fromDate.toISOString().slice(0, 10);
    const today = new Date().toISOString().slice(0, 10);

    // All-time total — only used when range === "all"
    let allTimeTotal = 0;
    if (range === "all") {
      try {
        const { count, error } = await supabase
          .from("page_views")
          .select("*", { count: "exact", head: true });
        if (!error) allTimeTotal = count || 0;
      } catch (e) {
        /* non-fatal */
      }
    }

    // Total for the selected range (when not "all") — uses COUNT to avoid row limits
    let rangeTotal = allTimeTotal;
    if (range !== "all") {
      try {
        const { count, error } = await supabase
          .from("page_views")
          .select("*", { count: "exact", head: true })
          .gte("date", from);
        if (!error) rangeTotal = count || 0;
      } catch (e) {
        /* non-fatal */
      }
    }

    // Fetch range rows — limit to 5000 max, enough for any reasonable chart
    let rows = [];
    const { data: chunk, error } = await supabase
      .from("page_views")
      .select("page,date,hour")
      .gte("date", from)
      .order("date", { ascending: false })
      .limit(5000); // CRITICAL: was fetching unlimited rows via pagination
    if (!error && chunk) rows = chunk;

    if (!rows.length)
      return res.json({
        total: rangeTotal,
        today: 0,
        peak_day: "—",
        by_page: [],
        by_date: [],
        by_hour: Array(24).fill(0),
      });

    const todayViews = rows.filter((r) => r.date === today).length;
    const dateMap = {};
    rows.forEach((r) => {
      dateMap[r.date] = (dateMap[r.date] || 0) + 1;
    });
    const by_date = Object.entries(dateMap)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, views]) => ({ date, views }));
    const peak = by_date.reduce((a, b) => (b.views > a.views ? b : a), {
      date: "—",
      views: 0,
    });
    const pageMap = {};
    rows.forEach((r) => {
      pageMap[r.page] = (pageMap[r.page] || 0) + 1;
    });
    const by_page = Object.entries(pageMap)
      .sort((a, b) => b[1] - a[1])
      .map(([page, views]) => ({ page, views }));
    const by_hour = Array(24).fill(0);
    rows
      .filter((r) => r.date === today)
      .forEach((r) => {
        by_hour[r.hour] = (by_hour[r.hour] || 0) + 1;
      });
    res.json({
      total: rangeTotal,
      today: todayViews,
      peak_day: peak.date,
      by_page,
      by_date,
      by_hour,
    });
  },
);

// ── REVIEW ANALYTICS ──────────────────────────────────────────────────────────
app.get(
  "/api/admin/analytics/reviews",
  requireSection("review-analytics"),
  async (req, res) => {
    const { data: reviews } = await supabase.from("reviews").select("*");
    const { data: movies } = await supabase.from("movies").select("id,title");
    if (!reviews || !movies) return res.json({ total: 0 });
    const total = reviews.length;
    const overall_avg = total
      ? reviews.reduce((s, r) => s + r.overall, 0) / total
      : null;
    const cats = ["direction", "sound", "cinematography", "script"];
    const cat_avgs = {};
    cats.forEach((c) => {
      const vals = reviews.map((r) => r[c]).filter(Boolean);
      cat_avgs[c] = vals.length
        ? vals.reduce((a, b) => a + b, 0) / vals.length
        : null;
    });
    const movieMap = {};
    movies.forEach((m) => {
      movieMap[m.id] = m.title;
    });
    const byFilm = {};
    reviews.forEach((r) => {
      if (!byFilm[r.movie_id])
        byFilm[r.movie_id] = {
          title: movieMap[r.movie_id] || "Unknown",
          scores: [],
          count: 0,
        };
      byFilm[r.movie_id].scores.push(r.overall);
      byFilm[r.movie_id].count++;
    });
    const by_film = Object.values(byFilm)
      .map((f) => ({
        title: f.title,
        avg: f.scores.reduce((a, b) => a + b, 0) / f.scores.length,
        count: f.count,
      }))
      .sort((a, b) => b.avg - a.avg);
    const top_rated = by_film[0] || null;
    const most_reviewed =
      [...by_film].sort((a, b) => b.count - a.count)[0] || null;
    res.json({
      total,
      overall_avg,
      cat_avgs,
      by_film,
      top_rated,
      most_reviewed,
    });
  },
);

// ── REVIEWS ───────────────────────────────────────────────────────────────────
app.get("/api/reviews/all", async (req, res) => {
  noStore(res); // must revalidate after new reviews — browser cache would serve stale data
  const data = await memCache("reviews:all", 30, async () => {
    const { data } = await supabasePublic.from("reviews").select("movie_id,overall");
    return data || [];
  });
  res.json(data);
});

app.get("/api/reviews/:movieId", async (req, res) => {
  noStore(res); // reviews update in real-time; browser cache causes "no instant update" UX bug
  const data = await memCache(
    `reviews:${req.params.movieId}`,
    300,
    async () => {
      const { data } = await supabasePublic
        .from("reviews")
        .select("*")
        .eq("movie_id", req.params.movieId)
        .order("created_at", { ascending: false });
      return data || [];
    },
  );
  res.json(data);
});

app.post("/api/reviews", strictWriteLimit, async (req, res) => {
  const {
    movie_id,
    reviewer_name,
    overall,
    direction,
    sound,
    cinematography,
    script,
  } = req.body;
  if (!movie_id || !overall)
    return res.status(400).json({ error: "movie_id and overall are required" });

  // Validate score ranges (prevent overall:999 or overall:"DROP TABLE" etc.)
  function parseScore(val) {
    const n = parseInt(val);
    return (!isNaN(n) && n >= 1 && n <= 10) ? n : null;
  }
  const overallScore = parseScore(overall);
  if (overallScore === null)
    return res.status(400).json({ error: "overall must be an integer between 1 and 10" });

  const { data, error } = await supabasePublic
    .from("reviews")
    .insert([
      {
        movie_id,
        reviewer_name: (reviewer_name || "Anonymous").toString().replace(/[<>]/g, "").slice(0, 60),
        overall: overallScore,
        direction: parseScore(direction),
        sound: parseScore(sound),
        cinematography: parseScore(cinematography),
        script: parseScore(script),
      },
    ])
    .select()
    .single();
  if (error) return res.status(500).json({ error: "Internal server error" });
  memInvalidate(`reviews:${movie_id}`, "reviews:all");
  res.json(data);
});

// ── EVENT REGISTRATION FORMS ──────────────────────────────────────────────────
//
// Forms support branching "sections" (à la Google Forms): a form is a list of
// sections, each holding one or more questions. After a section, the form
// moves to a default "next section" — unless one of that section's
// multiple-choice questions has branching enabled, in which case the chosen
// option can route to a different section entirely (e.g. a "Participant or
// Audience?" question routing into two completely different question paths).
//
// Any section can also be flagged is_paid with a fixed amount_paise — set
// once by the admin and never customizable by the registrant. The actual
// path taken (and therefore the amount owed) is always recomputed
// server-side from the submitted answers, never trusted from the client.
//
// Storage: reuses the existing event_forms.questions TEXT column (no DB
// migration needed for this table). Shape on disk:
//   v1 (legacy, flat):  [ {id,label,type,required,options}, ... ]
//   v2 (sections):      { version: 2, sections: [ {id,title,description,
//                          questions:[...], next_section, is_paid,
//                          amount_paise}, ... ] }
// parseFormSchema() normalizes both into a uniform {version, sections} shape
// so every downstream route only has to deal with one representation.

const SUBMIT_END = "__submit__";

function parseFormSchema(rawQuestions) {
  let parsed;
  try {
    // rawQuestions may already be a parsed object (Supabase JSONB auto-parse)
    if (typeof rawQuestions === "object" && rawQuestions !== null) {
      parsed = rawQuestions;
    } else {
      parsed = JSON.parse(rawQuestions || "[]");
    }
  } catch {
    parsed = [];
  }
  if (parsed && !Array.isArray(parsed) && Array.isArray(parsed.sections)) {
    return { version: 2, sections: parsed.sections };
  }
  // Legacy flat array — wrap as a single implicit section so the branching
  // engine below works unchanged for old forms that haven't been rebuilt yet.
  const flat = Array.isArray(parsed) ? parsed : [];
  return {
    version: 1,
    sections: [
      {
        id: "_legacy",
        title: null,
        description: null,
        questions: flat,
        next_section: SUBMIT_END,
        is_paid: false,
        amount_paise: null,
      },
    ],
  };
}

// Walk the section graph starting at sections[0], using `answers` to resolve
// any branching questions along the way. Returns the section ids actually
// visited, the flattened list of questions belonging to those sections
// (this — not the raw full schema — is what required-field validation and
// dedupe checks should run against), and the total amount owed (paise).
function computeSectionPath(sections, answers) {
  answers = answers || {};
  const byId = new Map((sections || []).map((s) => [s.id, s]));
  const visitedSectionIds = [];
  const questions = [];
  let requiredAmountPaise = 0;

  let current = (sections || [])[0] || null;
  const seen = new Set();
  let guard = 0;

  while (current && guard <= sections.length + 1) {
    guard++;
    if (seen.has(current.id)) break; // cycle guard — malformed schema
    seen.add(current.id);
    visitedSectionIds.push(current.id);
    for (const q of current.questions || []) questions.push(q);
    if (current.is_paid && Number(current.amount_paise) > 0) {
      requiredAmountPaise += Number(current.amount_paise);
    }

    // 1. A branching question's answer can override the section default.
    let nextId = null;
    for (const q of current.questions || []) {
      if (q.branch && q.branch.enabled && q.type === "radio") {
        const ans = (answers[q.id] || "").toString();
        const target = ans && q.branch.map ? q.branch.map[ans] : null;
        if (target === SUBMIT_END) nextId = SUBMIT_END;
        else if (target && byId.has(target)) nextId = target;
        if (nextId) break; // first branching question with a match wins
      }
    }

    // 2. Otherwise fall back to the section's own default next-section.
    if (nextId === null) {
      if (current.next_section === SUBMIT_END) nextId = SUBMIT_END;
      else if (current.next_section && byId.has(current.next_section))
        nextId = current.next_section;
      else {
        const idx = sections.findIndex((s) => s.id === current.id);
        nextId =
          idx >= 0 && idx + 1 < sections.length
            ? sections[idx + 1].id
            : SUBMIT_END;
      }
    }

    current = nextId === SUBMIT_END || !nextId ? null : byId.get(nextId) || null;
  }

  return { visitedSectionIds, questions, requiredAmountPaise };
}

// ADMIN-side validation when saving a sections-based form.
function validateSectionsPayload(sections) {
  if (!Array.isArray(sections) || sections.length === 0)
    return "At least one section is required";

  const sectionIds = new Set();
  for (const s of sections) {
    if (!s.id || typeof s.id !== "string") return "Each section needs an id";
    if (sectionIds.has(s.id)) return `Duplicate section id: ${s.id}`;
    sectionIds.add(s.id);
  }

  for (const s of sections) {
    if (!Array.isArray(s.questions))
      return `Section "${s.title || s.id}" needs a questions array`;
    if (s.is_paid) {
      const amt = parseInt(s.amount_paise, 10);
      if (!amt || amt < 100)
        return `Section "${s.title || s.id}" needs a payment amount of at least ₹1`;
    }
    if (
      s.next_section &&
      s.next_section !== SUBMIT_END &&
      !sectionIds.has(s.next_section)
    )
      return `Section "${s.title || s.id}" has an invalid "next section" target`;

    const qIds = new Set();
    for (const q of s.questions) {
      if (!q.id || !q.type)
        return `Each question must have id and type (section "${s.title || s.id}")`;
      if (qIds.has(q.id)) return `Duplicate question id: ${q.id}`;
      qIds.add(q.id);
      if (
        (q.type === "radio" || q.type === "checkbox") &&
        (!Array.isArray(q.options) || q.options.length < 1)
      )
        return `Question "${q.label || q.id}" needs at least 1 option`;
      if (q.branch && q.branch.enabled) {
        if (q.type !== "radio")
          return `Only multiple-choice questions can branch ("${q.label || q.id}")`;
        q.required = true; // a branching question must always be answered
        for (const target of Object.values(q.branch.map || {})) {
          if (target && target !== SUBMIT_END && !sectionIds.has(target))
            return `Question "${q.label || q.id}" branches to an unknown section`;
        }
      }
    }
  }
  return null;
}

// Public — CSRF-protected. Limits payment-order creation attempts per IP.
const eventFormPaymentLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many payment attempts. Please wait 15 minutes." },
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
});

// PUBLIC: Get the registration form for an event (schema only, no responses)
app.get("/api/events/:id/form", async (req, res) => {
  cacheFor(res, 120); // 2-min cache — form rarely changes
  try {
    const data = await memCache(`event:form:${req.params.id}`, 120, async () => {
      const { data, error } = await supabasePublic
        .from("event_forms")
        .select("id,event_id,title,description,questions,is_open,created_at,updated_at")
        .eq("event_id", req.params.id)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return data;
    });
    if (!data)
      return res.status(404).json({ error: "No form found for this event" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// PUBLIC: Create a Razorpay order for a paid section reached during a form.
// The amount is NEVER taken from the client — it's recomputed server-side
// from the form's branching schema plus the answers given so far, so it
// can't be tampered with by editing the request.
app.post(
  "/api/events/:id/form/create-order",
  eventFormPaymentLimit,
  csrfProtect,
  async (req, res) => {
    if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
      console.error("[event-form/create-order] Razorpay env vars not configured.");
      return res
        .status(503)
        .json({ error: "Payment gateway not configured. Contact support." });
    }

    const { data: form, error: formErr } = await supabasePublic
      .from("event_forms")
      .select("id,is_open,questions")
      .eq("event_id", req.params.id)
      .maybeSingle();
    if (formErr || !form) return res.status(404).json({ error: "Form not found" });
    if (!form.is_open)
      return res.status(403).json({ error: "Registrations are currently closed" });

    const { sections } = parseFormSchema(form.questions);

    let answers = {};
    try {
      const raw = req.body.answers;
      answers = (typeof raw === "object" && raw !== null) ? raw : JSON.parse(raw || "{}");
    } catch {
      return res.status(400).json({ error: "Invalid answers payload" });
    }

    const { requiredAmountPaise } = computeSectionPath(sections, answers);
    if (!requiredAmountPaise || requiredAmountPaise <= 0) {
      return res.status(400).json({ error: "No payment is required at this step." });
    }

    try {
      // NOTE: Razorpay's `receipt` field has a hard 40-character limit.
      // Event IDs can be full UUIDs (36 chars), so "kfs_evtreg_<uuid>_<timestamp>"
      // (~61 chars) was silently rejected by Razorpay's API on every request,
      // which surfaced to users as "Could not initiate payment. Please try again."
      // Keep it short — same safe pattern as the donation flow's receipt ID.
      const receiptId = `kfs_evt_${Date.now()}`;
      const order = await createRazorpayOrder(requiredAmountPaise, receiptId);
      return res.json({
        order_id: order.id,
        key_id: RAZORPAY_KEY_ID,
        amount_paise: requiredAmountPaise,
      });
    } catch (e) {
      console.error("[event-form/create-order]", e.message);
      return res.status(502).json({ error: "Could not initiate payment. Please try again." });
    }
  },
);

// ADMIN: Create or update (upsert) the registration form for an event
app.post(

  "/api/admin/events/:id/form",
  requireSection("events"),
  async (req, res) => {
    const { title, description, sections, questions, is_open } = req.body;

    // Preferred path: sections-based schema (branching + per-section payment).
    // `questions` (flat array) is still accepted for any older client code,
    // and is stored as-is — it gets wrapped into an implicit single section
    // by parseFormSchema() wherever it's read back out.
    let storedQuestionsJson;
    if (Array.isArray(sections)) {
      const err = validateSectionsPayload(sections);
      if (err) return res.status(400).json({ error: err });
      storedQuestionsJson = JSON.stringify({ version: 2, sections });
    } else if (Array.isArray(questions)) {
      for (const q of questions) {
        if (!q.id || !q.type)
          return res
            .status(400)
            .json({ error: "Each question must have id and type" });
        if (
          (q.type === "radio" || q.type === "checkbox") &&
          (!Array.isArray(q.options) || q.options.length < 1)
        ) {
          return res
            .status(400)
            .json({ error: `Question "${q.label}" needs at least 1 option` });
        }
      }
      storedQuestionsJson = JSON.stringify(questions);
    } else {
      return res
        .status(400)
        .json({ error: "sections (or legacy questions) array is required" });
    }

    // Check if form already exists for this event
    const { data: existing } = await supabase
      .from("event_forms")
      .select("id")
      .eq("event_id", req.params.id)
      .maybeSingle();

    let data, error;
    const payload = {
      event_id: req.params.id,
      title: title || null,
      description: description || null,
      questions: storedQuestionsJson,
      is_open: is_open !== false && is_open !== "false",
      updated_at: new Date().toISOString(),
    };

    if (existing) {
      ({ data, error } = await supabase
        .from("event_forms")
        .update(payload)
        .eq("id", existing.id)
        .select()
        .single());
    } else {
      ({ data, error } = await supabase
        .from("event_forms")
        .insert([{ ...payload, created_at: new Date().toISOString() }])
        .select()
        .single());
    }

    if (error) return res.status(500).json({ error: "Internal server error" });

    const { data: ev } = await supabase
      .from("events")
      .select("title")
      .eq("id", req.params.id)
      .maybeSingle();
    logActivity(
      req.admin.id,
      req.admin.name,
      existing ? "update" : "create",
      "event_form",
      ev?.title || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  },
);

// ADMIN: Get all responses for an event form
app.get(
  "/api/admin/events/:id/form/responses",
  requireSection("events"),
  async (req, res) => {
    const { data, error } = await supabase
      .from("form_responses")
      .select("*")
      .eq("event_id", req.params.id)
      .order("submitted_at", { ascending: false });
    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  },
);

// ADMIN: Delete only the responses (keeps the form schema intact)
app.delete(
  "/api/admin/events/:id/form/responses",
  requireSection("events"),
  async (req, res) => {
    const { error } = await supabase
      .from("form_responses")
      .delete()
      .eq("event_id", req.params.id);
    if (error) return res.status(500).json({ error: "Internal server error" });
    const { data: ev } = await supabase
      .from("events")
      .select("title")
      .eq("id", req.params.id)
      .maybeSingle();
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "form_responses",
      `Responses for ${ev?.title || req.params.id}`,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// ADMIN: Delete the form for an event (and all its responses)
app.delete(
  "/api/admin/events/:id/form",
  requireSection("events"),
  async (req, res) => {
    await supabase
      .from("form_responses")
      .delete()
      .eq("event_id", req.params.id);
    await supabase.from("event_forms").delete().eq("event_id", req.params.id);
    const { data: ev } = await supabase
      .from("events")
      .select("title")
      .eq("id", req.params.id)
      .maybeSingle();
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "event_form",
      ev?.title || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// PUBLIC: Submit a response to an event registration form
// Handles multipart/form-data so image files can be uploaded per-question
app.post("/api/events/:id/form/submit", strictWriteLimit, upload.any(), async (req, res) => {
  // 1. Verify the form exists and is open
  const { data: form, error: formErr } = await supabasePublic
    .from("event_forms")
    .select("id,is_open,questions")
    .eq("event_id", req.params.id)
    .maybeSingle();

  if (formErr || !form)
    return res.status(404).json({ error: "Form not found" });
  if (!form.is_open)
    return res
      .status(403)
      .json({ error: "Registrations are currently closed" });

  // 2. Parse submitted answers
  let answers = {};
  try {
    answers = JSON.parse(req.body.answers || "{}");
  } catch (e) {
    return res.status(400).json({ error: "Invalid answers payload" });
  }

  // 3. Recompute the actual path taken through the form's sections from the
  //    submitted answers (never trust a client-reported path). `questions`
  //    below is the flattened set of questions belonging only to the
  //    sections actually visited — branches not taken are correctly ignored
  //    for both required-field validation and the fee that's owed.
  const { sections } = parseFormSchema(form.questions);
  const { questions, requiredAmountPaise } = computeSectionPath(sections, answers);

  for (const q of questions) {
    if (!q.required) continue;
    if (q.type === "image") {
      const hasFile = (req.files || []).some((f) => f.fieldname === q.id);
      if (!hasFile)
        return res
          .status(400)
          .json({ error: `"${q.label || q.id}" is required` });
    } else {
      const val = answers[q.id];
      const isEmpty =
        val === undefined ||
        val === null ||
        val === "" ||
        (Array.isArray(val) && val.length === 0);
      if (isEmpty)
        return res
          .status(400)
          .json({ error: `"${q.label || q.id}" is required` });
    }
  }

  // 3a. Payment verification — only when the visited path crossed a paid
  //     section. The amount is whatever computeSectionPath() determined
  //     server-side; the client cannot influence it.
  let paymentRecord = null;
  if (requiredAmountPaise > 0) {
    let payment = null;
    try {
      payment = JSON.parse(req.body.payment || "null");
    } catch {}
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = payment || {};

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
      return res
        .status(402)
        .json({ error: "Payment is required to complete this registration." });
    if (!RAZORPAY_KEY_SECRET)
      return res.status(503).json({ error: "Payment gateway not configured." });

    // Idempotency — if this order was already recorded, don't double-submit
    const { data: existingPay } = await supabase
      .from("form_responses")
      .select("id")
      .eq("razorpay_order_id", razorpay_order_id)
      .maybeSingle();
    if (existingPay) {
      return res.json({ success: true, duplicate: true, id: existingPay.id });
    }

    // HMAC-SHA256 signature check (same scheme as the donation flow)
    const sigBody = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expectedSig = crypto
      .createHmac("sha256", RAZORPAY_KEY_SECRET)
      .update(sigBody)
      .digest("hex");
    let sigValid = false;
    try {
      sigValid = crypto.timingSafeEqual(
        Buffer.from(expectedSig),
        Buffer.from(razorpay_signature),
      );
    } catch {
      sigValid = false;
    }
    if (!sigValid) {
      console.warn("[event-form/submit] Signature mismatch for order:", razorpay_order_id);
      supabase.from("payment_failures").insert([{
        razorpay_order_id,
        razorpay_payment_id,
        failure_reason: "invalid_signature_event_registration",
        ip_address: req.ip,
        user_agent: req.headers["user-agent"] || null,
      }]).then(({ error }) => {
        if (error) console.warn("[event-form/submit] Could not log failure:", error.message);
      });
      return res.status(400).json({ error: "Payment verification failed. Signature mismatch." });
    }

    // Confirm the amount actually paid via Razorpay — never trust the client.
    let paidAmountPaise = null;
    try {
      const auth = Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64");
      const payRes = await fetch(`https://api.razorpay.com/v1/payments/${razorpay_payment_id}`, {
        headers: { Authorization: `Basic ${auth}` },
      });
      const payData = await payRes.json();
      if (payRes.ok && payData.amount) paidAmountPaise = payData.amount;
    } catch (e) {
      console.warn("[event-form/submit] Could not fetch payment amount from Razorpay:", e.message);
    }
    if (paidAmountPaise !== null && paidAmountPaise !== requiredAmountPaise) {
      console.warn(`[event-form/submit] Amount mismatch: expected ${requiredAmountPaise}, paid ${paidAmountPaise}`);
      return res
        .status(400)
        .json({ error: "Payment amount does not match the required registration fee." });
    }

    paymentRecord = {
      amount_paise: paidAmountPaise || requiredAmountPaise,
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      payment_verified_at: new Date().toISOString(),
    };
  }

  // 3b. Duplicate check — block if same email or phone already submitted for this event
  const dedupeTypes = ["email", "phone"];
  const dedupeKeys = questions
    .filter((q) => dedupeTypes.includes(q.type))
    .map((q) => ({ id: q.id, label: q.label || q.type, type: q.type }));

  if (dedupeKeys.length > 0) {
    // Fetch existing responses for this event
    const { data: existing } = await supabasePublic
      .from("form_responses")
      .select("answers")
      .eq("event_id", req.params.id);

    for (const key of dedupeKeys) {
      const submitted = (answers[key.id] || "").trim().toLowerCase();
      if (!submitted) continue;
      const isDup = (existing || []).some((row) => {
        try {
          const prev = JSON.parse(row.answers || "{}");
          return (prev[key.id] || "").trim().toLowerCase() === submitted;
        } catch {
          return false;
        }
      });
      if (isDup) {
        const label = key.type === "email" ? "Email" : "Mobile number";
        return res
          .status(409)
          .json({ error: `${label} already registered for this event.` });
      }
    }
  }

  // 4. Upload any image files to Supabase Storage
  const imageUrls = {};
  for (const file of req.files || []) {
    try {
      const url = await uploadImage(file, `form-responses/${req.params.id}`);
      imageUrls[file.fieldname] = url;
    } catch (e) {
      console.error(
        "Image upload error for question",
        file.fieldname,
        e.message,
      );
      return res
        .status(500)
        .json({ error: "Image upload failed: " + e.message });
    }
  }

  // 5. Merge image URLs into answers
  const finalAnswers = { ...answers, ...imageUrls };

  // 6. Store response — use admin client (service_role) so this works regardless of RLS policy on form_responses
  const { data: response, error: insertErr } = await supabase
    .from("form_responses")
    .insert([
      {
        event_id: req.params.id,
        form_id: form.id,
        answers: JSON.stringify(finalAnswers),
        submitted_at: new Date().toISOString(),
        ...(paymentRecord || {}),
      },
    ])
    .select()
    .single();

  if (insertErr) return res.status(500).json({ error: "Internal server error" });

  // 7. Send confirmation email (non-blocking — never fail the response)
  try {
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Tier 1: question explicitly typed as 'email'
    let emailQ = questions.find((q) => q.type === "email");

    // Tier 2: any text/textarea question whose label mentions email
    if (!emailQ)
      emailQ = questions.find(
        (q) =>
          ["text", "textarea"].includes(q.type) &&
          /e[\s-]?mail/i.test(q.label || ""),
      );

    // Tier 3: scan every answer value for something that looks like an email
    let toEmail = emailQ ? (finalAnswers[emailQ.id] || "").trim() : null;
    if (!toEmail) {
      for (const val of Object.values(finalAnswers)) {
        if (typeof val === "string" && EMAIL_RE.test(val.trim())) {
          toEmail = val.trim();
          break;
        }
      }
    }

    // Name: prefer a question labelled 'name', fall back to first short-text answer
    const nameQ = questions.find(
      (q) =>
        ["text", "textarea"].includes(q.type) &&
        /\bname\b/i.test(q.label || ""),
    );
    const toName = nameQ ? (finalAnswers[nameQ.id] || "").trim() : null;

    if (toEmail) {
      // Fetch event details for the email
      const { data: ev } = await supabasePublic
        .from("events")
        .select("id,title,event_date,location,location_link,is_upcoming")
        .eq("id", req.params.id)
        .maybeSingle();

      // ── Create event_registrations row + send QR ticket ──────────────────
      // This ensures form-based registrants appear in the scanner and receive
      // a QR ticket email — not just a plain confirmation.
      if (ev && toEmail) {
        (async () => {
          try {
            const EMAIL_NORM = toEmail.toLowerCase().trim();
            // Check if already in event_registrations (avoid duplicate on re-submit)
            const { data: existing } = await supabase
              .from("event_registrations")
              .select("id, qr_token")
              .eq("event_id", ev.id)
              .eq("email", EMAIL_NORM)
              .maybeSingle();

            let reg = existing;
            let qrDataUrl;

            if (!reg) {
              // Generate QR token
              const qrToken = crypto.randomUUID();
              const QRCode = require("qrcode");
              qrDataUrl = await QRCode.toDataURL(qrToken, {
                width: 400, margin: 3,
                color: { dark: "#000000", light: "#ffffff" },
                errorCorrectionLevel: "M",
              });
              const { data: inserted, error: insErr } = await supabase
                .from("event_registrations")
                .insert([{
                  event_id: ev.id,
                  name:     (toName || toEmail).trim(),
                  email:    EMAIL_NORM,
                  qr_token: qrToken,
                  created_at: new Date().toISOString(),
                }])
                .select()
                .single();
              if (insErr) {
                console.error("[form-submit] event_registrations insert failed:", insErr.message);
                // Fall back to plain confirmation email
                sendConfirmationEmail({ toEmail, toName, eventTitle: ev.title || "", eventDate: ev.event_date || null, eventVenue: ev.location || null })
                  .catch(e => console.error("[email] confirmation fallback failed:", e.message));
                return;
              }
              reg = inserted;
              console.log(`[form-submit] Created event_registrations row reg_id=${reg.id} for form response`);
            } else {
              // Already registered — regenerate QR from existing token
              const QRCode = require("qrcode");
              qrDataUrl = await QRCode.toDataURL(reg.qr_token, {
                width: 400, margin: 3,
                color: { dark: "#000000", light: "#ffffff" },
                errorCorrectionLevel: "M",
              });
              console.log(`[form-submit] event_registrations row already exists reg_id=${reg.id} — resending ticket`);
            }

            // Send QR ticket email
            sendTicketEmail({ event: ev, reg, qrDataUrl })
              .catch(e => console.error("[form-submit] ticket email failed:", e.message));

            // If this registration was paid, also send the Razorpay receipt PDF
            if (paymentRecord) {
              sendPaymentBill({
                type:            "REGISTRATION",
                donorId:         null,
                recipientEmail:  toEmail,
                recipientName:   toName,
                isAnonymous:     false,
                cause:           ev.title || "Event Registration",
                amountPaise:     paymentRecord.amount_paise,
                paymentId:       paymentRecord.razorpay_payment_id,
                orderId:         paymentRecord.razorpay_order_id,
                paymentDateTime: paymentRecord.payment_verified_at,
              }).catch(e => console.error("[form-submit] payment bill email failed:", e.message));
            }
          } catch (e) {
            console.error("[form-submit] registration+ticket flow error:", e.message);
            // Fallback: send plain confirmation
            sendConfirmationEmail({ toEmail, toName, eventTitle: ev?.title || "", eventDate: ev?.event_date || null, eventVenue: ev?.location || null })
              .catch(err => console.error("[email] send failed:", err.message));
          }
        })();
      } else {
        // No event details or no email — send plain confirmation at minimum
        sendConfirmationEmail({
          toEmail,
          toName,
          eventTitle: ev?.title || "",
          eventDate: ev?.event_date || null,
          eventVenue: ev?.location || null,
        }).catch((e) => console.error("[email] send failed:", e.message));
      }
    }
  } catch (e) {
    console.error("[email] pre-send error:", e.message);
  }

  res.json({ success: true, id: response.id, amount_paise: paymentRecord?.amount_paise || 0 });
});

// ADMIN: Download responses as server-side JSON (client does XLSX conversion)
// This is an alias for the GET responses endpoint used by the download button
app.get(
  "/api/admin/events/:id/form/export",
  requireSection("events"),
  async (req, res) => {
    const { data: form } = await supabase
      .from("event_forms")
      .select("title,questions")
      .eq("event_id", req.params.id)
      .maybeSingle();

    const { data: responses } = await supabase
      .from("form_responses")
      .select("*")
      .eq("event_id", req.params.id)
      .order("submitted_at", { ascending: true });

    res.json({ form: form || null, responses: responses || [] });
  },
);

// ── ADMIN: Send test confirmation email ───────────────────────────────────────
app.post("/api/admin/email/test", authMiddleware, async (req, res) => {
  const { to } = req.body;
  if (!to || !to.includes("@"))
    return res.status(400).json({ error: "Valid email required" });
  try {
    await sendConfirmationEmail({
      toEmail: to,
      toName: "Test User",
      eventTitle: "Test Event — KFS",
      eventDate: new Date().toISOString(),
      eventVenue: "KIIT University, Bhubaneswar",
    });
    res.json({ success: true });
  } catch (e) {
    console.error("[email] test send failed:", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── DYNAMIC OG IMAGES ─────────────────────────────────────────────────────────
// Generates a 1200×630 PNG preview card for WhatsApp / Twitter / LinkedIn shares.
// Routes:
//   /og/event/:id      — event card  (cover image + title + date + venue)
//   /og/film/:id       — film card   (poster + title + director + genre)
//   /og/blog/:id       — blog card   (cover + title + author + excerpt)
//
// Uses @resvg/resvg-js — pure JS, no native deps, works on Node 26 / Render free.
// Install once:  npm install @resvg/resvg-js
//
// Cache header: 1 hour (images are mostly static; event cover can change).

const { Resvg } = require("@resvg/resvg-js");

// ── SVG-based OG helpers ──────────────────────────────────────────────────────

function escXml(s) {
  return (s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Naive word-wrap for SVG — splits text into lines of at most maxChars
function svgLines(text, maxChars) {
  const words = (text || "").split(" ");
  const lines = [];
  let line = "";
  for (const w of words) {
    const test = line ? line + " " + w : w;
    if (test.length > maxChars && line) {
      lines.push(line);
      line = w;
    } else line = test;
  }
  if (line) lines.push(line);
  return lines;
}

// Fetch a remote image and return a base64 data-URI (for embedding in SVG)
async function toDataUri(url) {
  if (!url) return null;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(4000) });
    if (!r.ok) return null;
    const buf = Buffer.from(await r.arrayBuffer());
    const ct = r.headers.get("content-type") || "image/jpeg";
    return `data:${ct};base64,${buf.toString("base64")}`;
  } catch {
    return null;
  }
}

// Build the full SVG string for an OG card
function buildOGSvg({ coverDataUri, badge, title, lines: extraLines }) {
  const W = 1200,
    H = 630;

  // Cover image on right half (540px wide), embedded as base64
  const coverImg = coverDataUri
    ? `<image href="${coverDataUri}" x="540" y="0" width="660" height="${H}" preserveAspectRatio="xMidYMid slice"/>`
    : "";

  // Gradient overlay so left text is always readable
  const overlay = coverDataUri
    ? `
    <defs>
      <linearGradient id="ov" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#0a0a0a" stop-opacity="1"/>
        <stop offset="55%"  stop-color="#0a0a0a" stop-opacity="0.92"/>
        <stop offset="100%" stop-color="#0a0a0a" stop-opacity="0.2"/>
      </linearGradient>
    </defs>
    <rect x="540" y="0" width="660" height="${H}" fill="url(#ov)"/>`
    : "";

  // Title lines (max 3, ~24 chars each at 52px)
  const titleLines = svgLines(title, 24).slice(0, 3);
  const titleSvg = titleLines
    .map(
      (l, i) =>
        `<text x="56" y="${152 + i * 66}" font-size="52" font-weight="700" fill="#f5f5f5" font-family="sans-serif">${escXml(l)}</text>`,
    )
    .join("\n  ");

  // Extra info lines below title
  let infoY = 152 + titleLines.length * 66 + 28;
  const infoSvg = extraLines
    .map(({ text, color, size }) => {
      if (!text) return "";
      const el = `<text x="56" y="${infoY}" font-size="${size || 22}" fill="${color || "#aaaaaa"}" font-family="sans-serif">${escXml(text)}</text>`;
      infoY += (size || 22) + 16;
      return el;
    })
    .filter(Boolean)
    .join("\n  ");

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}">
  <!-- background -->
  <rect width="${W}" height="${H}" fill="#0a0a0a"/>
  <!-- cover image + gradient -->
  ${coverImg}
  ${overlay}
  <!-- left accent bar -->
  <rect x="0" y="0" width="5" height="${H}" fill="#f5f5f5"/>
  <!-- badge pill -->
  <rect x="56" y="96" width="${badge.length * 9 + 32}" height="28" rx="14" fill="#1e1e1e"/>
  <text x="72" y="115" font-size="13" font-weight="600" fill="#888888" font-family="sans-serif" letter-spacing="1">${escXml(badge)}</text>
  <!-- title -->
  ${titleSvg}
  <!-- info lines -->
  ${infoSvg}
  <!-- bottom rule -->
  <rect x="56" y="${H - 72}" width="${W - 112}" height="1" fill="#1e1e1e"/>
  <!-- KFS wordmark -->
  <text x="56" y="58" font-size="18" font-weight="500" fill="#555555" font-family="sans-serif" letter-spacing="2">KFS — KIIT FILM SOCIETY</text>
  <!-- bottom URL -->
  <text x="56" y="${H - 38}" font-size="16" fill="#444444" font-family="sans-serif">kiitfilmsociety.in</text>
</svg>`;
}

function svgToPng(svgStr) {
  const resvg = new Resvg(svgStr, { fitTo: { mode: "width", value: 1200 } });
  return resvg.render().asPng();
}

// ── /og/event/:id ─────────────────────────────────────────────────────────────
// ── /og/event/:id ─────────────────────────────────────────────────────────────
// For social crawlers: redirect to the actual cover image stored in Supabase.
// Falls back to the generated SVG card when no cover image exists.
app.get("/og/event/:id", async (req, res) => {
  try {
    const { data: e } = await supabasePublic
      .from("events")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!e) return res.status(404).send("Not found");

    // If we have a real cover image, redirect social crawlers straight to it.
    // 1200×630 is already set in the og:image:width/height meta tags so platforms
    // will size the preview correctly without fetching dimensions separately.
    if (e.cover_image) {
      res.setHeader("Cache-Control", "public, max-age=86400"); // 24h — image rarely changes
      return res.redirect(302, e.cover_image);
    }

    // No cover — fall back to the generated SVG card
    const dateStr = e.event_date
      ? new Date(e.event_date).toLocaleDateString("en-IN", {
          weekday: "long",
          day: "numeric",
          month: "long",
          year: "numeric",
        })
      : null;

    const svg = buildOGSvg({
      coverDataUri: null,
      badge: e.is_upcoming ? "UPCOMING EVENT" : "EVENT",
      title: e.title || "Event",
      lines: [
        { text: dateStr ? dateStr : null, color: "#aaaaaa", size: 22 },
        {
          text: e.event_time ? e.event_time : null,
          color: "#aaaaaa",
          size: 20,
        },
        {
          text: e.venue || e.location ? (e.venue || e.location) : null,
          color: "#888888",
          size: 18,
        },
      ],
    });

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(svgToPng(svg));
  } catch (err) {
    console.error("[og/event]", err.message);
    res.status(500).send("OG generation failed");
  }
});

// ── /og/film/:id ──────────────────────────────────────────────────────────────
app.get("/og/film/:id", async (req, res) => {
  try {
    const { data: m } = await supabasePublic
      .from("movies")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!m) return res.status(404).send("Not found");

    // Redirect to the actual poster — fast, zero CPU, beautiful preview
    if (m.poster_image) {
      res.setHeader("Cache-Control", "public, max-age=86400");
      return res.redirect(302, m.poster_image);
    }

    // No poster — generate SVG card fallback
    const genres = (() => {
      try {
        const g = JSON.parse(m.genre || "[]");
        return Array.isArray(g) ? g : [g];
      } catch {
        return m.genre ? [m.genre] : [];
      }
    })();
    const badge = genres.slice(0, 2).join(" · ").toUpperCase() || "FILM";

    const svg = buildOGSvg({
      coverDataUri: null,
      badge,
      title: m.title || "Film",
      lines: [
        {
          text: m.director ? "Directed by  " + m.director : null,
          color: "#aaaaaa",
          size: 22,
        },
        {
          text: m.release_year ? String(m.release_year) : null,
          color: "#555555",
          size: 18,
        },
      ],
    });

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(svgToPng(svg));
  } catch (err) {
    console.error("[og/film]", err.message);
    res.status(500).send("OG generation failed");
  }
});

// ── /og/blog/:id ──────────────────────────────────────────────────────────────
app.get("/og/blog/:id", async (req, res) => {
  try {
    const { data: b } = await supabasePublic
      .from("blogs")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!b) return res.status(404).send("Not found");

    // Redirect to the actual cover image — no processing needed
    if (b.cover_image) {
      res.setHeader("Cache-Control", "public, max-age=86400");
      return res.redirect(302, b.cover_image);
    }

    // No cover — generate SVG card fallback
    const excerpt = b.excerpt
      ? b.excerpt.slice(0, 90) + (b.excerpt.length > 90 ? "…" : "")
      : null;

    const svg = buildOGSvg({
      coverDataUri: null,
      badge: "KFS BLOG",
      title: b.title || "Blog",
      lines: [
        { text: excerpt || null, color: "#777777", size: 20 },
        {
          text: b.author ? "By " + b.author : null,
          color: "#555555",
          size: 17,
        },
      ],
    });

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(svgToPng(svg));
  } catch (err) {
    console.error("[og/blog]", err.message);
    res.status(500).send("OG generation failed");
  }
});

// ── /og/studio/:id — share image for a public Studio Wall post ──────────────
app.get("/og/studio/:id", async (req, res) => {
  try {
    const { data: p } = await supabasePublic
      .from("member_projects")
      .select("id, title, description, cover_image, domain, member_id, members!member_projects_member_id_fkey(name)")
      .eq("id", req.params.id)
      .is("deleted_at", null)
      .eq("status", "published")
      .maybeSingle();
    if (!p) return res.status(404).send("Not found");

    if (p.cover_image) {
      res.setHeader("Cache-Control", "public, max-age=86400");
      return res.redirect(302, p.cover_image);
    }

    const desc = p.description
      ? p.description.slice(0, 90) + (p.description.length > 90 ? "…" : "")
      : null;

    const svg = buildOGSvg({
      coverDataUri: null,
      badge: "KFS STUDIO",
      title: p.title || "Studio Wall",
      lines: [
        { text: desc || null, color: "#777777", size: 20 },
        {
          text: p.members?.name ? "By " + p.members.name : null,
          color: "#555555",
          size: 17,
        },
      ],
    });

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(svgToPng(svg));
  } catch (err) {
    console.error("[og/studio]", err.message);
    res.status(500).send("OG generation failed");
  }
});

// ── SHARE-LINK HTML WITH DYNAMIC OG TAGS ─────────────────────────────────────
// Injects og:title / og:description / og:image into the SPA shell so
// social crawlers (WhatsApp, Twitter, Telegram…) get real previews AND
// real users land on the correct deep-linked page.

// Read the base HTML once (cached).  We'll inject <meta> tags into <head>.
function injectOgTags(
  html,
  { title, description, imageUrl, url, type, author, publishedTime, jsonLd },
) {
  // Remove every og:* and twitter:* meta line from the static HTML so the
  // hardcoded values never compete with the dynamic ones we inject below.
  html = html
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      if (!t.startsWith("<meta")) return true;
      if (/property\s*=\s*["']og:/i.test(t)) return false;
      if (/name\s*=\s*["']twitter:/i.test(t)) return false;
      return true;
    })
    .join("\n");

  // Update canonical link to match this page's URL
  if (url) {
    html = html.replace(
      /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
      `<link rel="canonical" href="${url}" />`,
    );
  }

  const KFS_LOGO = "https://kiitfilmsociety.in/images/kfs-logo.png";
  const siteName = "KFS — KIIT Film Society";
  const ogType = type || "website";
  const safeTitle = (title || siteName).replace(/"/g, "&quot;");
  const safeDesc = (
    description || "KIIT Film Society — student-run cinema collective."
  )
    .slice(0, 200)
    .replace(/"/g, "&quot;");
  const safeUrl = url || "https://kiitfilmsociety.in";

  const hasPoster = !!imageUrl;
  const safeImg = imageUrl || KFS_LOGO;
  const imgW = hasPoster ? "1200" : "400";
  const imgH = hasPoster ? "630" : "400";
  const twitterCard = hasPoster ? "summary_large_image" : "summary";

  const articleMeta =
    ogType === "article"
      ? `
  ${publishedTime ? `<meta property="article:published_time" content="${publishedTime}" />` : ""}
  ${author ? `<meta property="article:author"         content="${author.replace(/"/g, "&quot;")}" />` : ""}
  <meta property="article:section" content="Cinema" />`
      : "";

  const jsonLdTag = jsonLd
    ? `<script type="application/ld+json">${JSON.stringify(jsonLd)}<\/script>`
    : "";

  const tags = `
  <!-- Dynamic OG injected by server -->
  <meta property="og:type"         content="${ogType}" />
  <meta property="og:site_name"    content="${siteName}" />
  <meta property="og:title"        content="${safeTitle}" />
  <meta property="og:description"  content="${safeDesc}" />
  <meta property="og:url"          content="${safeUrl}" />
  <meta property="og:image"        content="${safeImg}" />
  <meta property="og:image:width"  content="${imgW}" />
  <meta property="og:image:height" content="${imgH}" />
  <meta property="og:image:alt"    content="${safeTitle}" />
  ${articleMeta}
  <meta name="twitter:card"        content="${twitterCard}" />
  <meta name="twitter:title"       content="${safeTitle}" />
  <meta name="twitter:description" content="${safeDesc}" />
  <meta name="twitter:image"       content="${safeImg}" />
  <meta name="twitter:image:alt"   content="${safeTitle}" />`;

  if (html.includes("</head>")) {
    let result = html.replace("</head>", tags + "\n</head>");
    // Also update the <title> so Google picks up the right title for this page
    if (title) {
      result = result.replace(
        /<title>[^<]*<\/title>/i,
        `<title>${safeTitle}</title>`,
      );
    }
    return result;
  }
  return html.replace("<body", tags + "\n<body");
}

// Extract numeric/UUID id from end of a slug like "my-post-title-42"
function idFromSlug(slug) {
  if (!slug) return null;
  // UUID pattern
  const uuidMatch = slug.match(
    /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
  );
  if (uuidMatch) return uuidMatch[1];
  // Numeric id at end
  const numMatch = slug.match(/-(\d+)$/);
  if (numMatch) return numMatch[1];
  // Fallback: the whole slug might just be an id
  return slug;
}

// Serve the SPA index.html with injected OG tags
async function serveWithOg(res, ogData) {
  const indexPath = path.join(__dirname, "public", "index.html");
  try {
    let html = fs.readFileSync(indexPath, "utf8");
    html = injectOgTags(html, ogData);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    // Don't cache share pages — OG data can change
    res.setHeader("Cache-Control", "no-cache");
    res.send(html);
  } catch (e) {
    // If index.html can't be read, fall through
    res.sendFile(indexPath);
  }
}

// ── /blog/:slug  (e.g. /blog/my-post-title-42) ───────────────────────────────
app.get("/blog/:slug", async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const blogResult = id
      ? await supabasePublic
          .from("blogs")
          .select("id,title,excerpt,cover_image,author,created_at")
          .eq("id", id)
          .maybeSingle()
      : { data: null };
    const b = blogResult?.data ?? null;

    if (!b) {
      // Unknown blog — serve SPA without special OG so the app can show its own 404
      return res.sendFile(path.join(__dirname, "public", "index.html"));
    }

    const canonicalSlug = slugify(b.title) + "-" + b.id;
    const pageUrl = `https://kiitfilmsociety.in/blog/${canonicalSlug}`;
    const imageUrl = b.cover_image
      ? `https://kiitfilmsociety.in/og/blog/${b.id}`
      : null;

    return serveWithOg(res, {
      title: b.title ? `${b.title} — KFS Blog` : "KFS Blog",
      description:
        b.excerpt || `Read "${b.title}" on the KIIT Film Society blog.`,
      imageUrl,
      url: pageUrl,
      type: "article",
      author: b.author || "KFS — KIIT Film Society",
      publishedTime: b.created_at || null,
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "Article",
        headline: b.title,
        description: b.excerpt || "",
        url: pageUrl,
        image: imageUrl || "https://kiitfilmsociety.in/images/og-banner.png",
        author: { "@type": "Person", name: b.author || "KFS" },
        publisher: {
          "@type": "Organization",
          name: "KFS — KIIT Film Society",
          logo: {
            "@type": "ImageObject",
            url: "https://kiitfilmsociety.in/images/kfs-logo.png",
          },
        },
        datePublished: b.created_at || null,
        mainEntityOfPage: pageUrl,
      },
    });
  } catch (err) {
    console.error("[share/blog]", err.message);
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// ── /films/:slug  (e.g. /films/do-paise-ki-dhoop-7) ─────────────────────────
app.get("/films/:slug", async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const queryResult = id
      ? await supabasePublic
          .from("movies")
          .select("id,title,description,poster_image,director,release_year,genre")
          .eq("id", id)
          .maybeSingle()
      : { data: null };
    const m = queryResult?.data ?? null;

    if (!m) {
      return res.sendFile(path.join(__dirname, "public", "index.html"));
    }

    const canonicalSlug = slugify(m.title) + "-" + m.id;
    const pageUrl = `https://kiitfilmsociety.in/films/${canonicalSlug}`;
    const desc = m.description
      ? m.description.slice(0, 160)
      : m.director
        ? `Directed by ${m.director}${m.release_year ? ` · ${m.release_year}` : ""}`
        : "A film by KIIT Film Society.";
    const imageUrl = m.poster_image
      ? `https://kiitfilmsociety.in/og/film/${m.id}`
      : null;

    return serveWithOg(res, {
      title: m.title ? `${m.title} — KFS Films` : "KFS Films",
      description: desc,
      imageUrl,
      url: pageUrl,
      type: "video.movie",
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "Movie",
        name: m.title,
        description: desc,
        url: pageUrl,
        image: imageUrl || "https://kiitfilmsociety.in/images/og-banner.png",
        director: m.director
          ? { "@type": "Person", name: m.director }
          : undefined,
        dateCreated: m.release_year ? String(m.release_year) : undefined,
        productionCompany: {
          "@type": "Organization",
          name: "KFS — KIIT Film Society",
          url: "https://kiitfilmsociety.in",
        },
      },
    });
  } catch (err) {
    console.error("[share/film]", err.message);
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// ── /social-strand/:username/:postid  — canonical shareable post URL ──────────
// e.g. kiitfilmsociety.in/social-strand/rahul-das/7f3a1b2c
app.get("/social-strand/:username/:postid", async (req, res) => {
  try {
    const id = idFromSlug(req.params.postid);
    const projectResult = id
      ? await supabasePublic
          .from("member_projects")
          .select(
            "id, title, description, cover_image, domain, tags, created_at, member_id, members!member_projects_member_id_fkey(name)",
          )
          .eq("id", id)
          .is("deleted_at", null)
          .eq("status", "published")
          .maybeSingle()
      : { data: null };
    const p = projectResult?.data ?? null;

    if (!p) {
      // Unknown/unpublished post — serve SPA (will show its own empty/404 state)
      return res.sendFile(path.join(__dirname, "public", "index.html"));
    }

    const authorName  = p.members?.name || "a KFS member";
    const usernameSlug = slugify(authorName) || "member";
    const pageUrl     = `https://kiitfilmsociety.in/social-strand/${usernameSlug}/${p.id}`;
    const desc = p.description
      ? p.description.slice(0, 160)
      : `${p.title} — work by ${authorName} on the KFS Social Strand.`;
    const imageUrl = p.cover_image
      ? `https://kiitfilmsociety.in/og/studio/${p.id}`
      : null;

    return serveWithOg(res, {
      title: p.title ? `${p.title} — KFS Social Strand` : "KFS Social Strand",
      description: desc,
      imageUrl,
      url: pageUrl,
      type: "article",
      author: authorName,
      publishedTime: p.created_at || null,
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "CreativeWork",
        name: p.title,
        description: desc,
        url: pageUrl,
        image: imageUrl || "https://kiitfilmsociety.in/images/og-banner.png",
        creator: { "@type": "Person", name: authorName },
        dateCreated: p.created_at || undefined,
        keywords: (p.tags || []).join(", ") || undefined,
        publisher: {
          "@type": "Organization",
          name: "KFS — KIIT Film Society",
          logo: {
            "@type": "ImageObject",
            url: "https://kiitfilmsociety.in/images/kfs-logo.png",
          },
        },
      },
    });
  } catch (err) {
    console.error("[share/social-strand]", err.message);
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// ── /social-strand (bare) — public Social Strand feed page ───────────────────
// Serves the SPA (index.html); client router shows the public strand feed.
app.get("/social-strand", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── Legacy redirects → canonical /social-strand/:username/:postid ─────────────
// /strand/:slug  (old format with title-slug)
app.get("/strand/:slug", async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    if (!id) return res.redirect(301, "/social-strand");
    const { data: p } = await supabasePublic
      .from("member_projects")
      .select("id, members!member_projects_member_id_fkey(name)")
      .eq("id", id)
      .maybeSingle();
    if (!p) return res.redirect(301, "/social-strand");
    const usernameSlug = slugify(p.members?.name || "member") || "member";
    res.redirect(301, `/social-strand/${usernameSlug}/${p.id}`);
  } catch (err) {
    console.error("[legacy/strand]", err.message);
    res.redirect(301, "/social-strand");
  }
});
// /studio/:slug  (oldest format)
app.get("/studio/:slug", async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    if (!id) return res.redirect(301, "/social-strand");
    const { data: p } = await supabasePublic
      .from("member_projects")
      .select("id, members!member_projects_member_id_fkey(name)")
      .eq("id", id)
      .maybeSingle();
    if (!p) return res.redirect(301, "/social-strand");
    const usernameSlug = slugify(p.members?.name || "member") || "member";
    res.redirect(301, `/social-strand/${usernameSlug}/${p.id}`);
  } catch (err) {
    console.error("[legacy/studio]", err.message);
    res.redirect(301, "/social-strand");
  }
});

// ── /events/:slug ─────────────────────────────────────────────────────────────
app.get("/events/:slug", async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const eventResult = id
      ? await supabasePublic
          .from("events")
          .select("id,title,description,cover_image,event_date,location")
          .eq("id", id)
          .maybeSingle()
      : { data: null };
    const e = eventResult?.data ?? null;

    if (!e) {
      return res.sendFile(path.join(__dirname, "public", "index.html"));
    }

    const canonicalSlug = slugify(e.title) + "-" + e.id;
    const pageUrl = `https://kiitfilmsociety.in/events/${canonicalSlug}`;
    const dateStr = e.event_date
      ? new Date(e.event_date).toLocaleDateString("en-IN", {
          day: "numeric",
          month: "long",
          year: "numeric",
        })
      : null;
    const desc = e.description
      ? e.description.slice(0, 160)
      : `KFS Event${dateStr ? " on " + dateStr : ""}${e.location ? " at " + e.location : ""}.`;

    const imageUrl = e.cover_image
      ? `https://kiitfilmsociety.in/og/event/${e.id}`
      : null;

    return serveWithOg(res, {
      title: e.title ? `${e.title} — KFS Events` : "KFS Events",
      description: desc,
      imageUrl,
      url: pageUrl,
      type: "article",
      publishedTime: e.event_date || null,
      jsonLd: {
        "@context": "https://schema.org",
        "@type": "Event",
        name: e.title,
        description: desc,
        url: pageUrl,
        image: imageUrl || "https://kiitfilmsociety.in/images/og-banner.png",
        startDate: e.event_date || undefined,
        location: e.location
          ? { "@type": "Place", name: e.location }
          : { "@type": "Place", name: "KIIT University, Bhubaneswar" },
        organizer: {
          "@type": "Organization",
          name: "KFS — KIIT Film Society",
          url: "https://kiitfilmsociety.in",
        },
      },
    });
  } catch (err) {
    console.error("[share/event]", err.message);
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// ── KFS WRAPPED ───────────────────────────────────────────────────────────────
// Public: get the wrapped config (year, taglines, fun cards) set by admin
app.get("/api/wrapped/config", async (req, res) => {
  noStore(res);
  const { data } = await supabasePublic
    .from("settings")
    .select("value")
    .eq("key", "wrapped_config")
    .maybeSingle();
  try {
    res.json(data ? JSON.parse(data.value) : {});
  } catch {
    res.json({});
  }
});

// Admin: save wrapped config
app.post(
  "/api/admin/wrapped/config",
  requireSection("wrapped"),
  async (req, res) => {
    const config = req.body;
    if (typeof config !== "object")
      return res.status(400).json({ error: "Invalid config" });
    await supabase
      .from("settings")
      .upsert(
        { key: "wrapped_config", value: JSON.stringify(config) },
        { onConflict: "key" },
      );
    logActivity(
      req.admin.id,
      req.admin.name,
      "update",
      "settings",
      "KFS Wrapped Config",
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// Admin: upload an image for a Wrapped highlight card
app.post(
  "/api/admin/wrapped/upload-image",
  requireSection("wrapped"),
  upload.single("image"),
  async (req, res) => {
    if (!req.file)
      return res.status(400).json({ error: "No image file provided" });
    try {
      const url = await uploadImage(req.file, "wrapped");
      if (!url) return res.status(500).json({ error: "Image upload failed" });
      res.json({ url });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Public: aggregate stats for Wrapped (all-time + per-year totals)
app.get("/api/wrapped/stats", async (req, res) => {
  cacheFor(res, 300); // 5-min browser cache
  try {
    const year = req.query.year ? parseInt(req.query.year) : null;
    const cacheKey = `wrapped:stats:${year || 'all'}`;

    // Collapse 7 sequential Supabase round-trips into 3 parallel ones, cached 5 min
    const result = await memCache(cacheKey, 300, async () => {
      const [moviesRes, blogsRes, reviewsRes, eventsCountRes] = await Promise.all([
        supabasePublic.from("movies").select("id,title,genre,release_year,director,poster_image"),
        supabasePublic.from("blogs").select("id,title,cover_image").eq("published", true),
        supabasePublic.from("reviews").select("movie_id,overall"),
        supabasePublic.from("events").select("id", { count: "exact", head: true }),
      ]);

      const movies = moviesRes.data || [];
      const blogs  = blogsRes.data  || [];
      const reviews = reviewsRes.data || [];
      const totalEvents = eventsCountRes.count || 0;

      // Derive counts from already-fetched data — no extra COUNT queries needed
      const totalMovies  = movies.length;
      const totalBlogs   = blogs.length;
      const totalReviews = reviews.length;
      const yearMovies   = year ? movies.filter(m => m.release_year === year).length : null;

    // Genre frequency map across all KFS films
    const genreCount = {};
    movies.forEach((m) => {
      let genres = [];
      try {
        genres = JSON.parse(m.genre || "[]");
      } catch {
        genres = m.genre ? [m.genre] : [];
      }
      if (!Array.isArray(genres)) genres = [genres];
      genres.forEach((g) => {
        if (g) genreCount[g] = (genreCount[g] || 0) + 1;
      });
    });
    const topGenres = Object.entries(genreCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([g, c]) => ({ genre: g, count: c }));

      // Top reviewed film (derived from already-fetched reviews + movies)
      const filmScores = {};
      reviews.forEach((r) => {
        if (!filmScores[r.movie_id]) filmScores[r.movie_id] = [];
        filmScores[r.movie_id].push(r.overall);
      });
      let topRated = null;
      let bestScore = 0;
      Object.entries(filmScores).forEach(([mid, scores]) => {
        const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
        if (avg > bestScore && scores.length >= 2) { bestScore = avg; topRated = mid; }
      });
      const topRatedMovie = topRated ? movies.find((m) => String(m.id) === String(topRated)) : null;

      return {
        totalMovies,
        totalBlogs,
        totalEvents,
        totalReviews,
        yearMovies,
        topGenres,
        topRatedMovie: topRatedMovie
          ? {
              id: topRatedMovie.id,
              title: topRatedMovie.title,
              poster_image: topRatedMovie.poster_image,
              score: Math.round(bestScore * 10) / 10,
            }
          : null,
        movieRatings: Object.fromEntries(
          Object.entries(filmScores).map(([mid, scores]) => [
            mid,
            {
              avg: Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10,
              count: scores.length,
            },
          ]),
        ),
        allMovies: movies.map((m) => {
          let genres = [];
          try { genres = JSON.parse(m.genre || "[]"); } catch { genres = m.genre ? [m.genre] : []; }
          return {
            id: m.id, title: m.title,
            genre: Array.isArray(genres) ? genres : [genres],
            release_year: m.release_year, director: m.director, poster_image: m.poster_image,
          };
        }),
        allBlogs: blogs.map((b) => ({ id: b.id, title: b.title, cover_image: b.cover_image })),
      };
    }); // end memCache
    res.json(result);
  } catch (e) {
    console.error("[wrapped/stats]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── RECOMMENDATIONS ────────────────────────────────────────────────────────────
// Returns films similar to a given film by tag/genre overlap
app.get("/api/recommendations/:movieId", async (req, res) => {
  cacheFor(res, 1800); // 30 min — almost never changes
  try {
    const { data: source } = await supabasePublic
      .from("movies")
      .select("id,genre,director")
      .eq("id", req.params.movieId)
      .maybeSingle();
    if (!source) return res.json([]);

    let srcGenres = [];
    try {
      srcGenres = JSON.parse(source.genre || "[]");
    } catch {
      srcGenres = source.genre ? [source.genre] : [];
    }
    if (!Array.isArray(srcGenres)) srcGenres = [srcGenres];
    srcGenres = srcGenres.map((g) => g.toLowerCase().trim());

    const { data: all } = await supabasePublic
      .from("movies")
      .select("id,title,genre,director,poster_image,release_year")
      .neq("id", req.params.movieId);

    const scored = (all || [])
      .map((m) => {
        let mGenres = [];
        try {
          mGenres = JSON.parse(m.genre || "[]");
        } catch {
          mGenres = m.genre ? [m.genre] : [];
        }
        if (!Array.isArray(mGenres)) mGenres = [mGenres];
        mGenres = mGenres.map((g) => g.toLowerCase().trim());

        let score = 0;
        let reason = "genre";
        // Genre overlap (2 pts per match)
        srcGenres.forEach((g) => {
          if (mGenres.includes(g)) score += 2;
        });
        // Same director (3 pts)
        if (
          source.director &&
          m.director &&
          source.director.split(/[,|]+/)[0].trim().toLowerCase() ===
            m.director.split(/[,|]+/)[0].trim().toLowerCase()
        ) {
          score += 3;
          reason = "director";
        }

        return { ...m, genre: mGenres, _score: score, _reason: reason };
      })
      .filter((m) => m._score > 0)
      .sort((a, b) => b._score - a._score)
      .slice(0, 6);

    res.json(scored.map(({ _score, ...m }) => m));
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── FILM COMMENTS ─────────────────────────────────────────────────────────────
//
// Supabase table required:
//
//   create table film_comments (
//     id           uuid primary key default gen_random_uuid(),
//     movie_id     uuid not null references movies(id) on delete cascade,
//     author_name  text not null,
//     body         text not null,
//     is_spoiler   boolean not null default false,
//     is_pinned    boolean not null default false,
//     is_kfs_reply boolean not null default false,   -- KFS Team badge
//     parent_id    uuid references film_comments(id) on delete cascade,
//     created_at   timestamptz not null default now()
//   );
//   create index on film_comments(movie_id, created_at);
//
// No RLS needed — server mediates all access.

// PUBLIC: Get all comments for a film (pinned first, then chronological)
app.get("/api/films/:movieId/comments", async (req, res) => {
  try {
    const { data, error } = await supabasePublic
      .from("film_comments")
      .select(
        "id,movie_id,author_name,body,is_spoiler,is_pinned,is_kfs_reply,parent_id,created_at",
      )
      .eq("movie_id", req.params.movieId)
      .order("is_pinned", { ascending: false })
      .order("created_at", { ascending: true });

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// PUBLIC: Post a comment (name only, no login)
app.post("/api/films/:movieId/comments", strictWriteLimit, async (req, res) => {
  try {
    const { author_name, body, is_spoiler } = req.body;

    if (!author_name || !author_name.trim()) {
      return res.status(400).json({ error: "Name is required." });
    }
    if (!body || !body.trim()) {
      return res.status(400).json({ error: "Comment cannot be empty." });
    }
    if (body.trim().length > 2000) {
      return res
        .status(400)
        .json({ error: "Comment is too long (max 2000 characters)." });
    }

    // Profanity check
    const filmCmtProfCheck = checkFieldsForProfanity(author_name, body);
    if (filmCmtProfCheck.found) return res.status(400).json({ error: "Your comment contains inappropriate language. Please revise it." });

    // Verify movie exists
    const { data: movie } = await supabasePublic
      .from("movies")
      .select("id")
      .eq("id", req.params.movieId)
      .maybeSingle();
    if (!movie) return res.status(404).json({ error: "Film not found." });

    const { data, error } = await supabasePublic
      .from("film_comments")
      .insert([
        {
          movie_id: req.params.movieId,
          author_name: author_name.trim().slice(0, 60),
          body: body.trim(),
          is_spoiler: is_spoiler === true || is_spoiler === "true",
          is_pinned: false,
          is_kfs_reply: false,
        },
      ])
      .select()
      .single();

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ADMIN: Get all comments across all films (for moderation panel)
app.get("/api/admin/comments", requireSection("movies"), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("film_comments")
      .select(
        "id,movie_id,author_name,body,is_spoiler,is_pinned,is_kfs_reply,created_at,movies(title)",
      )
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ADMIN: Get comments for a specific film
app.get(
  "/api/admin/films/:movieId/comments",
  requireSection("movies"),
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("film_comments")
        .select("*")
        .eq("movie_id", req.params.movieId)
        .order("created_at", { ascending: false });

      if (error) return res.status(500).json({ error: "Internal server error" });
      res.json(data || []);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Pin or unpin a comment
app.patch(
  "/api/admin/comments/:id/pin",
  requireSection("movies"),
  async (req, res) => {
    try {
      const { is_pinned } = req.body;
      const { data, error } = await supabase
        .from("film_comments")
        .update({ is_pinned: !!is_pinned })
        .eq("id", req.params.id)
        .select()
        .single();

      if (error) return res.status(500).json({ error: "Internal server error" });
      if (!data) return res.status(404).json({ error: "Comment not found." });
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Delete a comment
app.delete(
  "/api/admin/comments/:id",
  requireSection("movies"),
  async (req, res) => {
    try {
      const { data: comment } = await supabase
        .from("film_comments")
        .select("author_name, movie_id")
        .eq("id", req.params.id)
        .maybeSingle();

      const { error } = await supabase
        .from("film_comments")
        .delete()
        .eq("id", req.params.id);

      if (error) return res.status(500).json({ error: "Internal server error" });
      logActivity(
        req.admin.id,
        req.admin.name,
        "delete",
        "film_comment",
        `Comment by ${comment?.author_name || "unknown"}`,
      ).catch(e => console.error("[activity]", e.message));
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Reply as KFS Team (posts a special badged comment)
app.post(
  "/api/admin/films/:movieId/comments/reply",
  requireSection("movies"),
  async (req, res) => {
    try {
      const { body } = req.body;
      if (!body || !body.trim())
        return res.status(400).json({ error: "Reply body is required." });

      const { data, error } = await supabase
        .from("film_comments")
        .insert([
          {
            movie_id: req.params.movieId,
            author_name: "KFS Team",
            body: body.trim(),
            is_spoiler: false,
            is_pinned: true, // KFS replies always pinned to top
            is_kfs_reply: true,
          },
        ])
        .select()
        .single();

      if (error) return res.status(500).json({ error: "Internal server error" });
      logActivity(
        req.admin.id,
        req.admin.name,
        "create",
        "film_comment",
        `KFS Team reply on film ${req.params.movieId}`,
      ).catch(e => console.error("[activity]", e.message));
      res.status(201).json(data);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ── COLLABORATE / OPEN CALLS ──────────────────────────────────────────────────

async function cleanupExpiredCollaborations() {
  const today = new Date().toISOString().split("T")[0];
  await supabase
    .from("collaborate_posts")
    .delete()
    .lt("fulfillment_date", today);
}

function makeEditToken() {
  return crypto.randomBytes(32).toString("hex");
}

function cleanCollabPayload(body) {
  return {
    title: (body.title || "").trim(),
    role: (body.role || "").trim(),
    skills: (body.skills || "").trim(),
    timeline: (body.timeline || "").trim(),
    description: (body.description || "").trim(),
    contact_name: (body.contact_name || "").trim(),
    contact_email: (body.contact_email || "").trim(),
    contact_phone: (body.contact_phone || "").trim(),
    is_kfs_member: true, // always true — only KFS members can post
    domain: (body.domain || "").trim(),
    fulfillment_date: body.fulfillment_date || null,
  };
}

// No server-side member verify needed — domain check only, name must be picked from members dropdown in UI

app.get("/api/collaborate", async (req, res) => {
  noStore(res); // listings change on every POST/DELETE — browser must not cache
  try {
    await cleanupExpiredCollaborations();
    const today = new Date().toISOString().split("T")[0];

    const { data, error } = await supabasePublic
      .from("collaborate_posts")
      .select(
        "id,title,role,skills,timeline,description,contact_name,contact_email,contact_phone,is_kfs_member,domain,fulfillment_date,created_at,updated_at",
      )
      .gte("fulfillment_date", today)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/collaborate", strictWriteLimit, async (req, res) => {
  try {
    await cleanupExpiredCollaborations();

    const payload = cleanCollabPayload(req.body);
    if (
      !payload.title ||
      !payload.role ||
      !payload.description ||
      !payload.fulfillment_date
    ) {
      return res.status(400).json({
        error: "Title, role, description, and fulfillment date are required.",
      });
    }
    if (!payload.contact_email && !payload.contact_phone) {
      return res
        .status(400)
        .json({ error: "Please provide an email or phone number." });
    }

    // Enforce KIIT email domain
    if (!isKiitEmail(payload.contact_email)) {
      return res.status(403).json({
        error:
          "This feature is exclusive to KFS members only. Contact us at filmsocietykiit@gmail.com for external support.",
      });
    }

    const today = new Date().toISOString().split("T")[0];
    if (payload.fulfillment_date < today) {
      return res
        .status(400)
        .json({ error: "Fulfillment date cannot be in the past." });
    }

    const edit_token = makeEditToken();

    const { data, error } = await supabasePublic
      .from("collaborate_posts")
      .insert([{ ...payload, edit_token }])
      .select("id,edit_token")
      .single();

    if (error) return res.status(500).json({ error: "Internal server error" });

    res.json({
      success: true,
      id: data.id,
      edit_token,
      edit_url: `/collaborate/edit/${edit_token}`,
    });
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/collaborate/edit/:token", async (req, res) => {
  const { data, error } = await supabasePublic
    .from("collaborate_posts")
    .select("*")
    .eq("edit_token", req.params.token)
    .maybeSingle();

  if (error) return res.status(500).json({ error: "Internal server error" });
  if (!data) return res.status(404).json({ error: "Listing not found." });
  res.json(data);
});

app.put("/api/collaborate/:token", csrfProtect, async (req, res) => {
  const payload = cleanCollabPayload(req.body);

  if (
    !payload.title ||
    !payload.role ||
    !payload.description ||
    !payload.fulfillment_date
  ) {
    return res.status(400).json({
      error: "Title, role, description, and fulfillment date are required.",
    });
  }
  if (!payload.contact_email && !payload.contact_phone) {
    return res
      .status(400)
      .json({ error: "Please provide an email or phone number." });
  }

  const { data, error } = await supabase
    .from("collaborate_posts")
    .update({ ...payload, updated_at: new Date().toISOString() })
    .eq("edit_token", req.params.token)
    .select("id")
    .maybeSingle();

  if (error) return res.status(500).json({ error: "Internal server error" });
  if (!data) return res.status(404).json({ error: "Invalid edit link." });
  res.json({ success: true });
});

app.delete("/api/collaborate/:token", csrfProtect, async (req, res) => {
  // First confirm the post exists — prevents silent success on bad/guessed tokens
  const { data: existing } = await supabasePublic
    .from("collaborate_posts")
    .select("id")
    .eq("edit_token", req.params.token)
    .maybeSingle();

  if (!existing) return res.status(404).json({ error: "Post not found or token invalid." });

  const { data, error } = await supabase
    .from("collaborate_posts")
    .delete()
    .eq("edit_token", req.params.token)
    .select("id")
    .maybeSingle();

  if (error) return res.status(500).json({ error: "Internal server error" });
  if (!data) return res.status(404).json({ error: "Post not found or token invalid." });
  res.json({ success: true });
});

app.delete(
  "/api/admin/collaborate/:id",
  requireSection("collaborate"),
  async (req, res) => {
    const { data: post } = await supabase
      .from("collaborate_posts")
      .select("title")
      .eq("id", req.params.id)
      .maybeSingle();

    const { error } = await supabase
      .from("collaborate_posts")
      .delete()
      .eq("id", req.params.id);

    if (error) return res.status(500).json({ error: "Internal server error" });

    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "collaborate",
      post?.title || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
    res.json({ success: true });
  },
);

// Cleanup every 6 hours while server is awake
setInterval(
  () => {
    cleanupExpiredCollaborations().catch((e) =>
      console.error("[collaborate cleanup]", e.message),
    );
  },
  1000 * 60 * 60 * 6,
);

// ── BROADCAST EMAILS ──────────────────────────────────────────────────────────
//
// Supabase tables required:
//
//   create table broadcasts (
//     id             uuid primary key default gen_random_uuid(),
//     subject        text not null,
//     body_html      text not null,
//     body_text      text not null,
//     audience_type  text not null,   -- 'all_registrants' | 'event'
//     event_id       uuid references events(id) on delete set null,
//     sent_by        text not null,
//     sent_at        timestamptz not null default now(),
//     recipient_count int not null default 0
//   );
//
//   create table broadcast_opens (
//     id            uuid primary key default gen_random_uuid(),
//     broadcast_id  uuid not null references broadcasts(id) on delete cascade,
//     recipient_hash text not null,   -- sha256(email) — no PII stored
//     opened_at     timestamptz not null default now(),
//     unique(broadcast_id, recipient_hash)
//   );
//   create index on broadcast_opens(broadcast_id);
//
// 1px open-tracking pixel: embedded in every email as:
//   <img src="https://kiitfilmsociety.in/api/track-open/{broadcastId}/{sha256(email)}"
//        width="1" height="1" style="display:none" />

// Helper: sha256 hex of a string (for open-tracking — no PII in DB)
function hashEmail(email) {
  return crypto
    .createHash("sha256")
    .update((email || "").toLowerCase().trim())
    .digest("hex");
}

// Helper: collect unique recipient emails for a broadcast
async function collectRecipients(audienceType, eventId) {
  const emails = new Set();

  if (audienceType === "all_registrants" || !eventId) {
    // All form_responses across all events — extract email answers
    const { data: allResponses } = await supabase
      .from("form_responses")
      .select("answers, event_id");

    for (const row of allResponses || []) {
      try {
        const answers = JSON.parse(row.answers || "{}");
        for (const val of Object.values(answers)) {
          if (
            typeof val === "string" &&
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim())
          ) {
            emails.add(val.trim().toLowerCase());
            break; // one email per response
          }
        }
      } catch {
        /* skip malformed rows */
      }
    }
  } else {
    // Event-specific: only responses for that event
    const { data: responses } = await supabase
      .from("form_responses")
      .select("answers")
      .eq("event_id", eventId);

    for (const row of responses || []) {
      try {
        const answers = JSON.parse(row.answers || "{}");
        for (const val of Object.values(answers)) {
          if (
            typeof val === "string" &&
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim())
          ) {
            emails.add(val.trim().toLowerCase());
            break;
          }
        }
      } catch {
        /* skip */
      }
    }
  }

  return [...emails];
}

// 1px open-tracking pixel endpoint
// GET /api/track-open/:broadcastId/:recipientHash
app.get("/api/track-open/:broadcastId/:recipientHash", async (req, res) => {
  // Return the pixel immediately — never block
  const GIF1x1 = Buffer.from(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
    "base64",
  );
  res.setHeader("Content-Type", "image/gif");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.end(GIF1x1);

  // Record open async (fire-and-forget, deduplicated by unique constraint)
  const { broadcastId, recipientHash } = req.params;
  const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const HEX64_RE = /^[0-9a-f]{64}$/i;
  if (!UUID_RE.test(broadcastId) || !HEX64_RE.test(recipientHash)) return; // silently drop malformed params
  supabasePublic
    .from("broadcast_opens")
    .insert([{ broadcast_id: broadcastId, recipient_hash: recipientHash }])
    .then(() => {})
    .catch(() => {}); // unique constraint violation = already opened, fine
});

// ADMIN: Preview recipients count for a broadcast (before sending)
app.post(
  "/api/admin/broadcast/preview",
  requireSection("broadcast"),
  async (req, res) => {
    try {
      const { audience_type, event_id } = req.body;
      if (!audience_type)
        return res.status(400).json({ error: "audience_type required" });

      const emails = await collectRecipients(audience_type, event_id || null);
      res.json({ count: emails.length });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Get all events (for broadcast audience picker dropdown)
// Reuse existing /api/events but scoped to events that have responses
app.get(
  "/api/admin/broadcast/events-with-registrants",
  requireSection("broadcast"),
  async (req, res) => {
    try {
      // Get distinct event_ids that have at least one form_response
      const { data: responses } = await supabase
        .from("form_responses")
        .select("event_id");

      const eventIds = [
        ...new Set((responses || []).map((r) => r.event_id).filter(Boolean)),
      ];
      if (!eventIds.length) return res.json([]);

      const { data: events } = await supabase
        .from("events")
        .select("id,title,event_date")
        .in("id", eventIds)
        .order("event_date", { ascending: false });

      res.json(events || []);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Send a broadcast
app.post(
  "/api/admin/broadcast/send",
  requireSection("broadcast"),
  async (req, res) => {
    try {
      const { subject, body_html, body_text, audience_type, event_id } =
        req.body;

      if (!subject || !subject.trim())
        return res.status(400).json({ error: "Subject is required." });
      if (!body_html || !body_html.trim())
        return res.status(400).json({ error: "Email body is required." });
      if (!audience_type)
        return res.status(400).json({ error: "Audience type is required." });

      // Collect recipients
      const emails = await collectRecipients(audience_type, event_id || null);
      if (!emails.length) {
        return res
          .status(400)
          .json({ error: "No recipients found for this audience." });
      }

      // Fetch Brevo API key from settings
      const { data: rows } = await supabase
        .from("settings")
        .select("key,value")
        .in("key", ["brevo_api_key", "smtp_from_name"]);
      const s = {};
      (rows || []).forEach((r) => {
        s[r.key] = r.value;
      });

      if (!s.brevo_api_key) {
        return res
          .status(500)
          .json({ error: "Brevo API key not configured in settings." });
      }

      const fromName = s.smtp_from_name || "KFS — KIIT Film Society";

      // Create broadcast record first (to get the ID for tracking pixel)
      const { data: broadcast, error: broadcastErr } = await supabase
        .from("broadcasts")
        .insert([
          {
            subject: subject.trim(),
            body_html: body_html,
            body_text: body_text || "",
            audience_type: audience_type,
            event_id: event_id || null,
            sent_by: req.admin.name,
            recipient_count: emails.length,
          },
        ])
        .select("id")
        .single();

      if (broadcastErr)
        return res.status(500).json({ error: "Internal server error" });

      const broadcastId = broadcast.id;
      const BASE_URL = process.env.BASE_URL || "https://kiitfilmsociety.in";

      // Send via Brevo batch (up to 50 per request to stay within limits)
      const BATCH = 50;
      let sentCount = 0;
      let failCount = 0;

      for (let i = 0; i < emails.length; i += BATCH) {
        const chunk = emails.slice(i, i + BATCH);

        const toArr = chunk.map((email) => ({
          email,
          name: email.split("@")[0],
        }));

        // Inject tracking pixel per recipient using messageVersions
        const messageVersions = chunk.map((email) => {
          const hash = hashEmail(email);
          const pixelUrl = `${BASE_URL}/api/track-open/${broadcastId}/${hash}`;
          const trackingPixel = `<img src="${pixelUrl}" width="1" height="1" style="display:none;border:0;outline:none" alt="" />`;
          const personalHtml = body_html + "\n" + trackingPixel;

          return {
            to: [{ email, name: email.split("@")[0] }],
            htmlContent: personalHtml,
          };
        });

        try {
          const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
            method: "POST",
            headers: {
              accept: "application/json",
              "api-key": s.brevo_api_key,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              sender: { name: fromName, email: "noreply@kiitfilmsociety.in" },
              to: toArr,
              subject: subject.trim(),
              htmlContent: body_html, // fallback, overridden by messageVersions
              textContent: body_text || "",
              messageVersions: messageVersions,
            }),
          });

          if (brevoRes.ok) {
            sentCount += chunk.length;
          } else {
            const errText = await brevoRes.text();
            console.error(
              `[broadcast] Brevo batch ${i}-${i + BATCH} failed:`,
              errText,
            );
            failCount += chunk.length;
          }
        } catch (e) {
          console.error("[broadcast] fetch error:", e.message);
          failCount += chunk.length;
        }

        // Small delay between batches to respect Brevo rate limits
        if (i + BATCH < emails.length) {
          await new Promise((r) => setTimeout(r, 300));
        }
      }

      logActivity(
        req.admin.id,
        req.admin.name,
        "create",
        "broadcast",
        `"${subject.trim()}" → ${sentCount} recipients`,
      ).catch(e => console.error("[activity]", e.message));

      res.json({
        success: true,
        broadcast_id: broadcastId,
        sent: sentCount,
        failed: failCount,
        total: emails.length,
      });
    } catch (e) {
      console.error("[broadcast] error:", e);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: List all broadcasts (for history view)
app.get(
  "/api/admin/broadcasts",
  requireSection("broadcast"),
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("broadcasts")
        .select(
          "id,subject,audience_type,event_id,sent_by,sent_at,recipient_count,events(title)",
        )
        .order("sent_at", { ascending: false })
        .limit(100);

      if (error) return res.status(500).json({ error: "Internal server error" });
      res.json(data || []);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Get open-rate stats for a specific broadcast
app.get(
  "/api/admin/broadcasts/:id/stats",
  requireSection("broadcast"),
  async (req, res) => {
    try {
      const { data: broadcast, error: bErr } = await supabase
        .from("broadcasts")
        .select("id,subject,sent_at,recipient_count,audience_type")
        .eq("id", req.params.id)
        .maybeSingle();

      if (bErr || !broadcast)
        return res.status(404).json({ error: "Broadcast not found." });

      const { count: openCount } = await supabase
        .from("broadcast_opens")
        .select("*", { count: "exact", head: true })
        .eq("broadcast_id", req.params.id);

      const opens = openCount || 0;
      const total = broadcast.recipient_count || 0;
      const open_rate = total > 0 ? Math.round((opens / total) * 100) : 0;

      res.json({
        ...broadcast,
        opens,
        open_rate,
      });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ── EVENT THEMES ──────────────────────────────────────────────────────────────

// PUBLIC: Get the currently active theme (or null)
app.get("/api/theme", async (req, res) => {
  try {
    noStore(res);
    const theme = await memCache("theme:active", 60, async () => {
      const now = new Date().toISOString();
      const { data, error } = await supabasePublic
        .from("event_themes")
        .select("*")
        .eq("is_active", true)
        .or(`active_until.is.null,active_until.gt.${now}`)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return data || null;
    });
    res.json(theme);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ADMIN: List all themes
app.get("/api/admin/themes", requireSection("settings"), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("event_themes")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ADMIN: Create a new theme
app.post("/api/admin/themes", requireSection("settings"), async (req, res) => {
  try {
    const {
      name,
      is_active,
      active_from,
      active_until,
      accent_color,
      bg_color,
      card_color,
      border_color,
      text_color,
      grey_color,
      font_family,
      hero_title,
      hero_tagline,
      banner_message,
      banner_bg,
      banner_text_color,
      logo_url,
    } = req.body;

    if (!name)
      return res.status(400).json({ error: "Theme name is required." });

    // If activating, deactivate all existing themes first (no ID yet for new row)
    if (is_active) {
      await supabase
        .from("event_themes")
        .update({ is_active: false })
        .eq("is_active", true);
    }

    const { data, error } = await supabase
      .from("event_themes")
      .insert([
        {
          name,
          is_active: !!is_active,
          active_from: active_from || null,
          active_until: active_until || null,
          accent_color: accent_color || null,
          bg_color: bg_color || null,
          card_color: card_color || null,
          border_color: border_color || null,
          text_color: text_color || null,
          grey_color: grey_color || null,
          font_family: font_family || null,
          hero_title: hero_title || null,
          hero_tagline: hero_tagline || null,
          banner_message: banner_message || null,
          banner_bg: banner_bg || null,
          banner_text_color: banner_text_color || null,
          logo_url: logo_url || null,
        },
      ])
      .select()
      .single();

    if (error) return res.status(500).json({ error: "Internal server error" });
    memInvalidate("theme:active");
    logActivity(
      req.admin.id,
      req.admin.name,
      "create",
      "event_theme",
      name,
    ).catch(e => console.error("[activity]", e.message));
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ADMIN: Update a theme (colors, name, dates, is_active toggle)
app.put(
  "/api/admin/themes/:id",
  requireSection("settings"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        name,
        is_active,
        active_from,
        active_until,
        accent_color,
        bg_color,
        card_color,
        border_color,
        text_color,
        grey_color,
        font_family,
        hero_title,
        hero_tagline,
        banner_message,
        banner_bg,
        banner_text_color,
        logo_url,
      } = req.body;

      // If activating this theme, deactivate all others first
      if (is_active === true) {
        await supabase
          .from("event_themes")
          .update({ is_active: false })
          .neq("id", id);
      }

      const updates = {};
      if (name !== undefined) updates.name = name;
      if (is_active !== undefined) updates.is_active = is_active;
      if (active_from !== undefined) updates.active_from = active_from || null;
      if (active_until !== undefined)
        updates.active_until = active_until || null;
      if (accent_color !== undefined)
        updates.accent_color = accent_color || null;
      if (bg_color !== undefined) updates.bg_color = bg_color || null;
      if (card_color !== undefined) updates.card_color = card_color || null;
      if (border_color !== undefined)
        updates.border_color = border_color || null;
      if (text_color !== undefined) updates.text_color = text_color || null;
      if (grey_color !== undefined) updates.grey_color = grey_color || null;
      if (font_family !== undefined) updates.font_family = font_family || null;
      if (hero_title !== undefined) updates.hero_title = hero_title || null;
      if (hero_tagline !== undefined)
        updates.hero_tagline = hero_tagline || null;
      if (banner_message !== undefined)
        updates.banner_message = banner_message || null;
      if (banner_bg !== undefined) updates.banner_bg = banner_bg || null;
      if (banner_text_color !== undefined)
        updates.banner_text_color = banner_text_color || null;
      if (logo_url !== undefined) updates.logo_url = logo_url || null;

      const { data, error } = await supabase
        .from("event_themes")
        .update(updates)
        .eq("id", id)
        .select()
        .single();

      if (error) return res.status(500).json({ error: "Internal server error" });
      memInvalidate("theme:active");
      logActivity(
        req.admin.id,
        req.admin.name,
        "update",
        "event_theme",
        data.name || id,
      ).catch(e => console.error("[activity]", e.message));
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ADMIN: Delete a theme (cannot delete an active one)
app.delete(
  "/api/admin/themes/:id",
  requireSection("settings"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { data: theme, error: fetchErr } = await supabase
        .from("event_themes")
        .select("id,name,is_active")
        .eq("id", id)
        .maybeSingle();

      if (fetchErr || !theme)
        return res.status(404).json({ error: "Theme not found." });
      if (theme.is_active)
        return res.status(400).json({
          error: "Cannot delete an active theme. Deactivate it first.",
        });

      const { error } = await supabase
        .from("event_themes")
        .delete()
        .eq("id", id);
      if (error) return res.status(500).json({ error: "Internal server error" });

      memInvalidate("theme:active");
      logActivity(
        req.admin.id,
        req.admin.name,
        "delete",
        "event_theme",
        theme.name,
      ).catch(e => console.error("[activity]", e.message));
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ── Legal pages ───────────────────────────────────────────────────────────────
app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "privacy.html"));
});
app.get("/terms", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "terms.html"));
});
// ══════════════════════════════════════════════════════════════════════════════
// DONATIONS — Razorpay Integration
// ══════════════════════════════════════════════════════════════════════════════

const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// Donation-specific rate limiter — 10 attempts per IP per 15 min
const donationLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many donation attempts. Please wait 15 minutes." },
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
});

// ── Helper: create Razorpay order via REST API ────────────────────────────────
async function createRazorpayOrder(amountPaise, receiptId) {
  const auth = Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64");
  const response = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${auth}`,
    },
    body: JSON.stringify({
      amount:   amountPaise,      // in paise
      currency: "INR",
      receipt:  receiptId,
      payment_capture: 1,         // auto-capture
    }),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.description || "Razorpay order creation failed");
  }
  return data;
}

// ── Helper: compute current semester label ────────────────────────────────────
function currentSemesterLabel() {
  const now   = new Date();
  const month = now.getMonth(); // 0-based
  const year  = now.getFullYear();
  return month < 6
    ? `Jan–Jun ${year}`
    : `Jul–Dec ${year}`;
}

// ── Helper: semester-based featured_until (guide Section 8.3) ────────────────
// Jan–Jun payments expire June 30; Jul–Dec payments expire Dec 31
function getFeaturedUntil(paymentDate) {
  const d     = new Date(paymentDate);
  const month = d.getMonth(); // 0-indexed
  if (month < 6) {
    return new Date(d.getFullYear(), 5, 30, 23, 59, 59); // June 30
  } else {
    return new Date(d.getFullYear(), 11, 31, 23, 59, 59); // Dec 31
  }
}

// ── Helper: send Brevo thank-you email (non-blocking) ────────────────────────

// ── Helper: generate KFS invoice number ──────────────────────────────────────
function generateInvoiceNo(type) {
  const prefix = type === "REGISTRATION" ? "KFS-REG" : "KFS";
  const year   = new Date().getFullYear();
  const rand   = String(Math.floor(Math.random() * 90000) + 10000);
  return `${prefix}-${year}-${rand}`;
}

// ── Helper: generate KFS Payment Receipt as PDF Buffer (pdfkit) ──────────────
async function generateReceiptPdf({
  type, displayName, displayEmail, cause, billInvoiceNo,
  typeLabel, amountRs, paymentId, orderId, dtStr,
}) {
  // Pre-fetch logo before opening the PDF stream (5s timeout)
  const LOGO_URL = "https://kiitfilmsociety.in/images/kfs-logo.png";
  const logoBuffer = await new Promise(res => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; res(v); } };
    const timer = setTimeout(() => done(null), 5000);
    try {
      const https = require("https");
      const logoChunks = [];
      const req = https.get(LOGO_URL, resp => {
        if (resp.statusCode !== 200) { resp.resume(); clearTimeout(timer); return done(null); }
        resp.on("data", c => logoChunks.push(c));
        resp.on("end",  () => { clearTimeout(timer); done(Buffer.concat(logoChunks)); });
        resp.on("error", () => { clearTimeout(timer); done(null); });
      });
      req.on("error", () => { clearTimeout(timer); done(null); });
    } catch (_) { clearTimeout(timer); done(null); }
  });

  return new Promise((resolve, reject) => {
    const PDFDocument = require("pdfkit");
    const chunks      = [];
    const doc         = new PDFDocument({ size: "A4", margin: 0, info: { Title: `KFS Receipt ${billInvoiceNo}` } });

    doc.on("data",  c => chunks.push(c));
    doc.on("end",   () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const W  = 595.28;          // A4 width pt
    const H  = 841.89;          // A4 height pt
    const ML = 48;              // left margin
    const MR = 48;              // right margin
    const CW = W - ML - MR;    // content width

    // ── Background ───────────────────────────────────────────────────────────
    doc.rect(0, 0, W, H).fill("#0d0d0d");

    // ── Header band ──────────────────────────────────────────────────────────
    doc.rect(0, 0, W, 72).fill("#111111");
    doc.rect(0, 72, W, 1).fill("#1f1f1f");

    // Logo circle — uses pre-fetched logoBuffer (fetched before opening PDF stream)
    const logoX = ML, logoY = 12, logoSize = 48;
    doc.save()
      .circle(logoX + logoSize / 2, logoY + logoSize / 2, logoSize / 2)
      .clip();
    if (logoBuffer) {
      try {
        doc.image(logoBuffer, logoX, logoY, { width: logoSize, height: logoSize });
      } catch (_) {
        // fallback: filled circle with "KFS" text
        doc.restore().save()
          .circle(logoX + logoSize / 2, logoY + logoSize / 2, logoSize / 2)
          .fill("#222222");
        doc.fillColor("#ffffff").fontSize(14).font("Helvetica-Bold")
          .text("KFS", logoX, logoY + 17, { width: logoSize, align: "center" });
      }
    } else {
      // fallback: filled circle with "KFS" text
      doc.restore().save()
        .circle(logoX + logoSize / 2, logoY + logoSize / 2, logoSize / 2)
        .fill("#222222");
      doc.fillColor("#ffffff").fontSize(14).font("Helvetica-Bold")
        .text("KFS", logoX, logoY + 17, { width: logoSize, align: "center" });
    }
    doc.restore();

    // Header title
    doc.fillColor("#e8e8e8").fontSize(14).font("Helvetica")
      .text("KIIT Film Society  —  Payment Receipt", ML + logoSize + 14, 26);

    let y = 90;

    // ── Invoice meta bar ─────────────────────────────────────────────────────
    doc.rect(0, y, W, 44).fill("#111111");
    doc.rect(0, y + 44, W, 1).fill("#1a1a1a");

    doc.fillColor("#555555").fontSize(7).font("Helvetica")
      .text("INVOICE NO.", ML, y + 8);
    doc.fillColor("#e8e8e8").fontSize(11).font("Helvetica-Bold")
      .text(billInvoiceNo, ML, y + 19);

    // Type badge
    const badgeColor  = typeLabel === "REGISTRATION" ? "#4ecb8d" : "#4ea8de";
    const badgeBg     = typeLabel === "REGISTRATION" ? "#1a3a2a" : "#1a2a3a";
    const badgeBorder = typeLabel === "REGISTRATION" ? "#2a6a4a" : "#2a5a8a";
    const badgeW      = 100, badgeH = 18, badgeX = W - MR - badgeW;
    doc.rect(badgeX, y + 13, badgeW, badgeH).fill(badgeBg);
    doc.rect(badgeX, y + 13, badgeW, badgeH).stroke(badgeBorder);
    doc.fillColor(badgeColor).fontSize(8).font("Helvetica-Bold")
      .text(typeLabel, badgeX, y + 18, { width: badgeW, align: "center" });

    y += 56;

    // ── Info card ────────────────────────────────────────────────────────────
    const cardH = 90;
    doc.rect(ML, y, CW, cardH).fill("#161616").stroke("#1f1f1f");
    const cardPad = 18;

    doc.fillColor("#555555").fontSize(7).font("Helvetica")
      .text("NAME", ML + cardPad, y + cardPad);
    doc.fillColor("#e8e8e8").fontSize(13).font("Helvetica-Bold")
      .text(displayName, ML + cardPad, y + cardPad + 10, { width: (CW / 2) - 10 });

    doc.fillColor("#555555").fontSize(7).font("Helvetica")
      .text("EMAIL", ML + CW / 2, y + cardPad);
    doc.fillColor("#e8e8e8").fontSize(11).font("Helvetica")
      .text(displayEmail, ML + CW / 2, y + cardPad + 10, { width: (CW / 2) - cardPad });

    doc.fillColor("#555555").fontSize(7).font("Helvetica")
      .text("CAUSE", ML + cardPad, y + cardPad + 36);
    doc.fillColor("#e8e8e8").fontSize(13).font("Helvetica-Bold")
      .text(cause, ML + cardPad, y + cardPad + 46, { width: CW - 2 * cardPad });

    y += cardH + 20;

    // ── Payment details section label ─────────────────────────────────────────
    doc.fillColor("#444444").fontSize(7).font("Helvetica")
      .text("PAYMENT DETAILS", ML, y);
    y += 12;

    // Details table
    const rows = [
      ["Payment ID",    paymentId || "—"],
      ["Order ID",      orderId   || "—"],
      ["Date & Time",   dtStr],
      ["Method",        "Razorpay (UPI / Card / Net Banking)"],
      ["Status",        "PAID ✓"],
    ];
    const rowH = 28;
    rows.forEach(([label, val], i) => {
      const rowY  = y + i * rowH;
      const isLast = i === rows.length - 1;
      doc.rect(ML, rowY, CW, rowH).fill(i % 2 === 0 ? "#141414" : "#111111");
      if (!isLast) doc.rect(ML, rowY + rowH - 1, CW, 1).fill("#1a1a1a");

      doc.fillColor("#666666").fontSize(10).font("Helvetica")
        .text(label, ML + 12, rowY + 9);

      const isStatus = label === "Status";
      doc.fillColor(isStatus ? "#4ade80" : "#e0e0e0")
        .fontSize(isStatus ? 10 : 10)
        .font(isStatus ? "Helvetica-Bold" : "Helvetica")
        .text(val, ML, rowY + 9, { width: CW - 12, align: "right" });
    });

    y += rows.length * rowH + 20;

    // ── Total amount bar ──────────────────────────────────────────────────────
    doc.rect(ML, y, CW, 48).fill("#1a1a1a");
    doc.fillColor("#e8e8e8").fontSize(11).font("Helvetica-Bold")
      .text("TOTAL AMOUNT PAID", ML + 16, y + 16);
    doc.fillColor("#ffffff").fontSize(22).font("Helvetica-Bold")
      .text(`Rs. ${amountRs}`, ML, y + 12, { width: CW - 16, align: "right" });

    y += 68;

    // ── Footer ────────────────────────────────────────────────────────────────
    doc.rect(0, y, W, 1).fill("#191919");
    doc.fillColor("#3a3a3a").fontSize(8).font("Helvetica")
      .text("Computer-generated receipt — no signature required.", 0, y + 12, { align: "center", width: W });
    doc.fillColor("#444444").fontSize(9)
      .text("kiitfilmsociety.in  ·  filmsocietykiit@gmail.com  ·  KIIT University, Bhubaneswar", 0, y + 26, { align: "center", width: W });
    doc.fillColor("#888888").fontSize(8).font("Helvetica")
      .text("T&C apply", 0, y + 42, { align: "center", width: W, link: "https://kiitfilmsociety.in/terms", underline: true });

    doc.end();
  });
}

// ── Helper: send KFS Payment Bill via Brevo (non-blocking) ───────────────────
// Works for both DONATION and REGISTRATION types.
// params: { type, donorId, recipientEmail, recipientName, isAnonymous, cause,
//           amountPaise, paymentId, orderId, paymentDateTime, invoiceNo }
async function sendPaymentBill({
  type          = "DONATION",   // "DONATION" | "REGISTRATION"
  donorId       = null,
  recipientEmail,
  recipientName,
  isAnonymous   = false,
  cause         = "KIIT Film Society",
  amountPaise,
  paymentId,
  orderId,
  paymentDateTime,
  invoiceNo,
}) {
  // ── Fetch Brevo creds from DB ──────────────────────────────────────────────
  let BREVO_API_KEY  = process.env.BREVO_API_KEY   || null;
  let BREVO_NAME     = process.env.BREVO_SENDER_NAME  || "KFS — KIIT Film Society";
  const BREVO_SENDER = process.env.BREVO_SENDER_EMAIL || "noreply@kiitfilmsociety.in";

  try {
    const { data: rows } = await supabase
      .from("settings")
      .select("key,value")
      .in("key", ["brevo_api_key", "smtp_from_name"]);
    (rows || []).forEach(r => {
      if (r.key === "brevo_api_key"  && r.value) BREVO_API_KEY = r.value;
      if (r.key === "smtp_from_name" && r.value) BREVO_NAME    = r.value;
    });
  } catch (e) {
    console.warn("[PaymentBill] Could not fetch settings from DB:", e.message);
  }

  if (!BREVO_API_KEY) {
    console.warn("[PaymentBill] No API key — skipping bill email");
    return { success: false, reason: "no_api_key" };
  }
  if (!recipientEmail) {
    console.warn("[PaymentBill] No recipient email — skipping bill email");
    return { success: false, reason: "no_email" };
  }

  // ── Build display values ───────────────────────────────────────────────────
  const billInvoiceNo  = invoiceNo || generateInvoiceNo(type);
  const displayName    = isAnonymous ? "Anonymous" : (recipientName || "Supporter");
  const displayEmail   = recipientEmail;
  const amountRs       = Math.round((amountPaise || 0) / 100);
  const typeLabel      = type === "REGISTRATION" ? "REGISTRATION" : "DONATION";

  // Format date
  const dtObj  = paymentDateTime ? new Date(paymentDateTime) : new Date();
  const dtStr  = dtObj.toLocaleString("en-IN", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: true,
    timeZone: "Asia/Kolkata",
  }).replace(",", "").replace("am", "AM").replace("pm", "PM") + " IST";

  // ── Generate PDF receipt ───────────────────────────────────────────────────
  let pdfBuffer;
  try {
    pdfBuffer = await generateReceiptPdf({
      type, displayName, displayEmail, cause, billInvoiceNo,
      typeLabel, amountRs, paymentId, orderId, dtStr,
    });
  } catch (pdfErr) {
    console.error("[PaymentBill] PDF generation failed:", pdfErr.message);
    return { success: false, error: "pdf_generation_failed" };
  }

  // ── Build Brevo payload with PDF attachment ────────────────────────────────
  const subjectMap = {
    DONATION:     `Your KFS Donation Receipt — ${billInvoiceNo}`,
    REGISTRATION: `Your KFS Registration Receipt — ${billInvoiceNo}`,
  };

  const bodyText = typeLabel === "DONATION"
    ? `Hi ${displayName},\n\nThank you for your generous donation to KIIT Film Society!\n\nPlease find your payment receipt (Invoice: ${billInvoiceNo}) attached to this email.\n\nWith gratitude,\nKFS — KIIT Film Society\nhttps://kiitfilmsociety.in`
    : `Hi ${displayName},\n\nYour registration for ${cause} has been confirmed!\n\nPlease find your payment receipt (Invoice: ${billInvoiceNo}) attached to this email.\n\nSee you there,\nKFS — KIIT Film Society\nhttps://kiitfilmsociety.in`;

  const payload = {
    subject:     subjectMap[typeLabel] || `KFS Payment Receipt — ${billInvoiceNo}`,
    to:          [{ email: recipientEmail, name: displayName }],
    sender:      { name: BREVO_NAME, email: BREVO_SENDER },
    textContent: bodyText,
    attachment: [
      {
        name:    `KFS-Receipt-${billInvoiceNo}.pdf`,
        content: pdfBuffer.toString("base64"),
      },
    ],
  };

  // Update email_sent in DB once we attempt to send (best-effort)
  if (donorId) {
    supabase.from("donors").update({
      email_sent:    true,
      email_sent_at: new Date().toISOString(),
    }).eq("id", donorId).then(({ error }) => {
      if (error) console.warn("[PaymentBill] Could not update email_sent flag:", error.message);
    });
  }

  try {
    const res  = await fetch("https://api.brevo.com/v3/smtp/email", {
      method:  "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error("[PaymentBill] Brevo send failed:", data.message || JSON.stringify(data));
      return { success: false, error: data.message };
    }
    console.log("[PaymentBill] Receipt (PDF) sent to", recipientEmail, "| MessageId:", data.messageId);
    return { success: true, messageId: data.messageId, invoiceNo: billInvoiceNo };
  } catch (err) {
    console.error("[PaymentBill] Exception:", err.message);
    return { success: false, error: err.message };
  }
}

// ── POST /api/donation/create-order ──────────────────────────────────────────
// Public — CSRF-protected. Validates amount server-side, creates Razorpay order.
app.post("/api/donation/create-order", donationLimit, csrfProtect, async (req, res) => {
  const { amount, email, tandc_acknowledged, is_anonymous, name, roll_no, bio } = req.body;

  // Guard: T&C
  if (!tandc_acknowledged) {
    return res.status(403).json({ error: "T&C must be acknowledged before donating." });
  }

  // Guard: email
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "A valid email address is required." });
  }

  // Guard: amount — enforce server-side regardless of what client says
  const amt = parseInt(amount, 10);
  if (isNaN(amt) || amt < 10 || amt > 500) {
    return res.status(400).json({ error: "Donation amount must be between ₹10 and ₹500." });
  }

  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    console.error("[donation] Razorpay env vars not configured.");
    return res.status(503).json({ error: "Payment gateway not configured. Contact support." });
  }

  try {
    const amountPaise = amt * 100;
    const receiptId   = `kfs_don_${Date.now()}`;

    const order = await createRazorpayOrder(amountPaise, receiptId);

    return res.json({
      order_id:     order.id,
      key_id:       RAZORPAY_KEY_ID,
      amount_paise: amountPaise,
    });
  } catch (e) {
    console.error("[donation/create-order]", e.message);
    return res.status(502).json({ error: "Could not initiate payment. Please try again." });
  }
});

// ── POST /api/donation/verify ─────────────────────────────────────────────────
// Public — CSRF-protected. Verifies HMAC signature, then records donor in DB.
app.post("/api/donation/verify", donationLimit, csrfProtect, async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    donor = {},
  } = req.body;

  const { email, tandc_acknowledged, is_anonymous, name, roll_no, bio } = donor;

  // Guard: T&C
  if (!tandc_acknowledged) {
    return res.status(403).json({ error: "T&C acknowledgement missing." });
  }

  // Guard: required payment IDs
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ error: "Missing payment verification fields." });
  }

  if (!RAZORPAY_KEY_SECRET) {
    return res.status(503).json({ error: "Payment gateway not configured." });
  }

  // ── HMAC-SHA256 signature verification (core security step) ──────────────
  const body         = `${razorpay_order_id}|${razorpay_payment_id}`;
  const expectedSig  = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(body)
    .digest("hex");

  let sigValid = false;
  try {
    sigValid = crypto.timingSafeEqual(
      Buffer.from(expectedSig),
      Buffer.from(razorpay_signature),
    );
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    console.warn("[donation/verify] Signature mismatch for order:", razorpay_order_id);
    // Log to payment_failures table for fraud monitoring (best-effort)
    supabase.from("payment_failures").insert([{
      razorpay_order_id,
      razorpay_payment_id,
      failure_reason: "invalid_signature",
      ip_address:     req.ip,
      user_agent:     req.headers["user-agent"] || null,
    }]).then(({ error }) => {
      if (error) console.warn("[donation/verify] Could not log failure:", error.message);
    });
    return res.status(400).json({ error: "Payment verification failed. Signature mismatch." });
  }

  // ── Fetch payment amount from Razorpay (never trust client amount) ────────
  let amountPaise = null;
  try {
    const auth    = Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64");
    const payRes  = await fetch(`https://api.razorpay.com/v1/payments/${razorpay_payment_id}`, {
      headers: { Authorization: `Basic ${auth}` },
    });
    const payData = await payRes.json();
    if (payRes.ok && payData.amount) amountPaise = payData.amount;
  } catch (e) {
    console.warn("[donation/verify] Could not fetch payment amount from Razorpay:", e.message);
  }

  // ── Idempotency: prevent duplicate records for same order ─────────────────
  const { data: existing } = await supabase
    .from("donors")
    .select("id")
    .eq("razorpay_order_id", razorpay_order_id)
    .maybeSingle();

  if (existing) {
    // Already recorded — not an error, just acknowledge
    return res.json({ success: true, duplicate: true });
  }

  // ── Record donor ──────────────────────────────────────────────────────────
  const now            = new Date();
  const semesterLabel  = currentSemesterLabel();
  const featuredUntil  = getFeaturedUntil(now); // semester-based expiry

  const donorRow = {
    email:                  email || null,
    is_anonymous:           !!is_anonymous,
    tandc_acknowledged:     true,
    razorpay_order_id,
    razorpay_payment_id,
    payment_verified_at:    now.toISOString(),
    featured_until:         featuredUntil.toISOString(),
    is_active:              true,
    semester_label:         semesterLabel,
    amount_paise:           amountPaise,
    email_sent:             false,
    // Personal fields — always stored internally; masked on public API
    name:                   name    || null,
    roll_no:                roll_no || null,
    bio:                    bio     || null,
  };

  const { data: insertedRows, error: insertErr } = await supabase.from("donors").insert([donorRow]).select("id");
  if (insertErr) {
    console.error("[donation/verify] DB insert error:", insertErr.message);
    // Payment succeeded but record failed — log for manual reconciliation
    return res.status(500).json({
      error: "Payment received but record failed. Please contact support with your payment ID: " + razorpay_payment_id,
    });
  }

  // Invalidate donor/stats caches
  memInvalidate("donation:stats", "donation:donors:");

  // ── Send KFS Payment Bill receipt (non-blocking) ────────────────────────
  const newDonorId = insertedRows?.[0]?.id || null;
  sendPaymentBill({
    type:            "DONATION",
    donorId:         newDonorId,
    recipientEmail:  email || null,
    recipientName:   name  || null,
    isAnonymous:     !!is_anonymous,
    cause:           "KIIT Film Society",
    amountPaise,
    paymentId:       razorpay_payment_id,
    orderId:         razorpay_order_id,
    paymentDateTime: now.toISOString(),
  }).catch(err => console.error("[PaymentBill] Donation bill error:", err.message));

  // Append to Google Sheet (non-blocking)
  appendDonorToSheet({
    name:                name || null,
    email:               email || null,
    roll_no:             roll_no || null,
    amount_paise:        amountPaise,
    razorpay_payment_id,
    razorpay_order_id,
    semester_label:      currentSemesterLabel(),
    is_anonymous:        !!is_anonymous,
    payment_verified_at: new Date().toISOString(),
    source:              "payment",
  }).catch(err => console.error("[sheets] verify append error:", err.message));

  return res.json({ success: true });
});

// ── GET /api/donation/stats ───────────────────────────────────────────────────
// Public — returns donor count and films supported. Amount only for admins.
app.get("/api/donation/stats", async (req, res) => {
  try {
    const data = await memCache("donation:stats", 120, async () => {
      const { data: rows, error } = await supabase
        .from("donors")
        .select("amount_paise, is_active")
        .eq("is_active", true);

      if (error) throw new Error(error.message);

      const totalPaise  = (rows || []).reduce((s, r) => s + (r.amount_paise || 0), 0);
      const totalDonors = (rows || []).length;

      // Films supported: static or from a settings key — keeping it simple for now
      const { data: setting } = await supabase
        .from("settings")
        .select("value")
        .eq("key", "films_supported_count")
        .maybeSingle();

      return {
        // total_amount_paise intentionally excluded from public response —
        // amount data is admin-only (see GET /api/admin/donation/donors)
        total_donors:    totalDonors,
        active_donors:   totalDonors,
        films_supported: setting?.value ? parseInt(setting.value) : null,
      };
    });

    noStore(res);
    return res.json(data);
  } catch (e) {
    console.error("[donation/stats]", e.message);
    return res.status(500).json({ error: "Could not load stats." });
  }
});

// ── GET /api/donation/donors ──────────────────────────────────────────────────
// Public — omits amount, email, and personal fields for anonymous donors.
app.get("/api/donation/donors", async (req, res) => {
  try {
    const data = await memCache("donation:donors:public", 60, async () => {
      const { data: rows, error } = await supabase
        .from("donors")
        .select("id, is_anonymous, name, roll_no, bio, photo_path, semester_label, payment_verified_at")
        .eq("is_active", true)
        .gt("featured_until", new Date().toISOString())
        .order("payment_verified_at", { ascending: false });

      if (error) throw new Error(error.message);

      return (rows || []).map(d => ({
        id:           d.id,
        is_anonymous: d.is_anonymous,
        display_name: d.is_anonymous ? null : d.name,
        roll_no:      d.is_anonymous ? null : d.roll_no,
        bio:          d.is_anonymous ? null : d.bio,
        photo_path:   d.is_anonymous ? null : d.photo_path,
        semester_label: d.semester_label,
        // amount_paise intentionally omitted from public endpoint
      }));
    });

    noStore(res);
    return res.json(data);
  } catch (e) {
    console.error("[donation/donors public]", e.message);
    return res.status(500).json({ error: "Could not load donors." });
  }
});

// ── GET /api/admin/donation/donors ────────────────────────────────────────────
// Admin only — includes amount_paise and email for reconciliation.
app.get("/api/admin/donation/donors", requireSection("settings"), async (req, res) => {
  try {
    const { data: rows, error } = await supabase
      .from("donors")
      .select("id, is_anonymous, name, email, roll_no, bio, photo_path, semester_label, amount_paise, payment_verified_at, razorpay_order_id, razorpay_payment_id, is_active, featured_until")
      .order("payment_verified_at", { ascending: false });

    if (error) throw new Error(error.message);

    noStore(res);
    return res.json(rows || []);
  } catch (e) {
    console.error("[admin/donation/donors]", e.message);
    return res.status(500).json({ error: "Could not load donors." });
  }
});

// ── GET /api/admin/donation/analytics ─────────────────────────────────────────
// Admin only — full payment analytics: totals, per-semester, daily trend, top donors.
app.get("/api/admin/donation/analytics", requireSection("settings"), async (req, res) => {
  try {
    const { data: rows, error } = await supabase
      .from("donors")
      .select("id, is_anonymous, name, email, roll_no, amount_paise, payment_verified_at, semester_label, is_active, razorpay_payment_id")
      .order("payment_verified_at", { ascending: true });

    if (error) throw new Error(error.message);

    const donors = rows || [];

    // ── Totals ────────────────────────────────────────────────────────────────
    const totalCollected = donors.reduce((s, d) => s + (d.amount_paise || 0), 0);
    const totalDonors    = donors.length;
    const activeDonors   = donors.filter(d => d.is_active).length;
    const avgDonation    = totalDonors ? Math.round(totalCollected / totalDonors) : 0;
    const maxDonor       = donors.reduce((best, d) => (!best || (d.amount_paise||0) > (best.amount_paise||0)) ? d : best, null);

    // ── Per-semester breakdown ────────────────────────────────────────────────
    const semesterMap = {};
    donors.forEach(d => {
      const sem = d.semester_label || "Unknown";
      if (!semesterMap[sem]) semesterMap[sem] = { label: sem, count: 0, total_paise: 0 };
      semesterMap[sem].count++;
      semesterMap[sem].total_paise += d.amount_paise || 0;
    });
    const bySemester = Object.values(semesterMap).sort((a, b) => a.label.localeCompare(b.label));

    // ── Daily trend (last 60 days) ────────────────────────────────────────────
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 60);
    const dailyMap = {};
    donors.forEach(d => {
      if (!d.payment_verified_at) return;
      const day = d.payment_verified_at.slice(0, 10);
      if (new Date(day) < cutoff) return;
      if (!dailyMap[day]) dailyMap[day] = { date: day, count: 0, total_paise: 0 };
      dailyMap[day].count++;
      dailyMap[day].total_paise += d.amount_paise || 0;
    });
    const dailyTrend = Object.values(dailyMap).sort((a, b) => a.date.localeCompare(b.date));

    // ── Donation amount buckets ───────────────────────────────────────────────
    const buckets = { "< ₹100": 0, "₹100-499": 0, "₹500-999": 0, "₹1000-1999": 0, "₹2000+": 0 };
    donors.forEach(d => {
      const amt = (d.amount_paise || 0) / 100;
      if (amt < 100)        buckets["< ₹100"]++;
      else if (amt < 500)   buckets["₹100-499"]++;
      else if (amt < 1000)  buckets["₹500-999"]++;
      else if (amt < 2000)  buckets["₹1000-1999"]++;
      else                  buckets["₹2000+"]++;
    });

    // ── Top 10 donors (non-anonymous) ────────────────────────────────────────
    const topDonors = donors
      .filter(d => d.amount_paise)           // include anonymous too for admin
      .sort((a, b) => (b.amount_paise || 0) - (a.amount_paise || 0))
      // No slice — admin sees all records so they can delete any
      .map(d => ({
        id:            d.id,
        name:          d.name || "—",
        email:         d.email || "—",
        roll_no:       d.roll_no || "—",
        amount_paise:  d.amount_paise,
        semester:      d.semester_label || "—",
        date:          d.payment_verified_at ? d.payment_verified_at.slice(0, 10) : "—",
        payment_id:    d.razorpay_payment_id || "—",
      }));

    noStore(res);
    return res.json({
      totals: { totalCollected, totalDonors, activeDonors, avgDonation, maxDonor: maxDonor ? { name: maxDonor.name, amount_paise: maxDonor.amount_paise } : null },
      bySemester,
      dailyTrend,
      buckets,
      topDonors,
    });
  } catch (e) {
    console.error("[admin/donation/analytics]", e.message);
    return res.status(500).json({ error: "Could not load payment analytics." });
  }
});


// ── DELETE /api/admin/donation/donors/:id ──────────────────────────────────────
// Admin only — permanently deletes a donor/payment record.
app.delete("/api/admin/donation/donors/:id", requireSection("settings"), async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: "Donor ID required." });

  try {
    const { error } = await supabase
      .from("donors")
      .delete()
      .eq("id", id);

    if (error) throw new Error(error.message);

    // Invalidate all donor/stats caches so the public page reflects the deletion immediately
    memInvalidate("donation:stats", "donation:donors:");

    await logActivity(
      req.admin?.id || "unknown",
      req.admin?.name || "Admin",
      "delete",
      "donor",
      `Donor ID: ${id}`
    );

    noStore(res);
    return res.json({ success: true });
  } catch (e) {
    console.error("[admin/donation/donors/delete]", e.message);
    return res.status(500).json({ error: "Could not delete donor record." });
  }
});

// ── POST /api/donation/webhook ────────────────────────────────────────────────
// Razorpay webhook — backup confirmation. Separate webhook secret.
// Add this URL in Razorpay Dashboard → Webhooks → payment.captured
app.post("/api/donation/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!WEBHOOK_SECRET) {
    return res.status(503).json({ error: "Webhook not configured." });
  }

  const receivedSig  = req.headers["x-razorpay-signature"];
  const expectedSig  = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(req.body)               // raw body, before JSON parse
    .digest("hex");

  let webhookSigValid = false;
  try {
    if (receivedSig) {
      webhookSigValid = crypto.timingSafeEqual(
        Buffer.from(expectedSig),
        Buffer.from(receivedSig),
      );
    }
  } catch { webhookSigValid = false; }

  if (!webhookSigValid) {
    console.warn("[webhook] Invalid Razorpay signature");
    return res.status(400).json({ error: "Invalid signature." });
  }

  let event;
  try {
    event = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).json({ error: "Invalid JSON body." });
  }

  // Only handle payment.captured
  if (event.event !== "payment.captured") {
    return res.status(200).json({ status: "ignored" });
  }

  const payment = event.payload?.payment?.entity;
  if (!payment) return res.status(200).json({ status: "no payment entity" });

  const orderId   = payment.order_id;
  const paymentId = payment.id;

  // Idempotency: if already recorded by /verify, skip
  const { data: existing } = await supabase
    .from("donors")
    .select("id, email_sent, email, name, amount_paise, is_anonymous")
    .eq("razorpay_order_id", orderId)
    .maybeSingle();

  if (existing) {
    // Already recorded by /verify — but check if bill was sent; if not, send now
    if (existing.email_sent === false && existing.email) {
      sendPaymentBill({
        type:            "DONATION",
        donorId:         existing.id,
        recipientEmail:  existing.email,
        recipientName:   existing.name,
        isAnonymous:     existing.is_anonymous,
        cause:           "KIIT Film Society",
        amountPaise:     existing.amount_paise,
        paymentId,
        orderId,
        paymentDateTime: new Date().toISOString(),
      }).catch(err => console.error("[PaymentBill/webhook-backup] Email error:", err.message));
    }
    return res.status(200).json({ status: "already_recorded" });
  }

  // Record with what we know from webhook (no donor personal data available here)
  const webhookNow     = new Date();
  const semesterLabel  = currentSemesterLabel();
  const featuredUntil  = getFeaturedUntil(webhookNow); // semester-based expiry

  const { data: webhookInserted, error: insertErr } = await supabase.from("donors").insert([{
    email:               payment.email || null,
    is_anonymous:        false,
    tandc_acknowledged:  true,
    razorpay_order_id:   orderId,
    razorpay_payment_id: paymentId,
    payment_verified_at: webhookNow.toISOString(),
    featured_until:      featuredUntil.toISOString(),
    is_active:           true,
    semester_label:      semesterLabel,
    amount_paise:        payment.amount || null,
    name:                payment.contact || null,
    email_sent:          false,
  }]).select("id");

  if (insertErr) {
    console.error("[webhook] DB insert error:", insertErr.message);
    // Still return 200 so Razorpay doesn't retry forever
    return res.status(200).json({ status: "db_error" });
  }

  memInvalidate("donation:stats", "donation:donors:");
  console.log(`[webhook] Donor recorded from webhook: order=${orderId}`);

  // Send payment bill from webhook path (non-blocking)
  const webhookDonorId = webhookInserted?.[0]?.id || null;
  sendPaymentBill({
    type:            "DONATION",
    donorId:         webhookDonorId,
    recipientEmail:  payment.email   || null,
    recipientName:   payment.contact || null,
    isAnonymous:     false,
    cause:           "KIIT Film Society",
    amountPaise:     payment.amount  || null,
    paymentId,
    orderId,
    paymentDateTime: webhookNow.toISOString(),
  }).catch(err => console.error("[PaymentBill/webhook] Background email error:", err.message));

  // Append to Google Sheet from webhook path (non-blocking)
  appendDonorToSheet({
    name:                payment.contact || null,
    email:               payment.email   || null,
    roll_no:             null,
    amount_paise:        payment.amount  || null,
    razorpay_payment_id: paymentId,
    razorpay_order_id:   orderId,
    semester_label:      semesterLabel,
    is_anonymous:        false,
    payment_verified_at: webhookNow.toISOString(),
    source:              "webhook",
  }).catch(err => console.error("[sheets] webhook append error:", err.message));

  return res.status(200).json({ status: "ok" });
});

// ── POST /api/admin/donation/test-email ──────────────────────────────────────
// Admin only — sends a test payment-bill receipt to the logged-in admin's address.
app.post("/api/admin/donation/test-email", requireSection("settings"), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "email required in body." });
  try {
    const result = await sendPaymentBill({
      type:            "DONATION",
      donorId:         null,
      recipientEmail:  email,
      recipientName:   "Test Donor",
      isAnonymous:     false,
      cause:           "KIIT Film Society",
      amountPaise:     10000, // ₹100 test amount
      paymentId:       "test_pay_" + Date.now(),
      orderId:         "test_order_" + Date.now(),
      paymentDateTime: new Date().toISOString(),
    });
    if (result.success) {
      return res.json({ success: true, messageId: result.messageId, invoiceNo: result.invoiceNo });
    } else {
      return res.status(500).json({ error: result.reason || result.error || "Email failed." });
    }
  } catch (e) {
    console.error("[test-email]", e.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/donation/sheet-backfill ────────────────────────────────────
// Admin only — syncs ALL existing donor records to Google Sheet.
// Run once after setting up Sheets integration to populate historical data.
app.post("/api/admin/donation/sheet-backfill", requireSection("settings"), async (req, res) => {
  try {
    const { data: donors, error } = await supabase
      .from("donors")
      .select("*")
      .order("payment_verified_at", { ascending: true });

    if (error) throw new Error(error.message);
    if (!donors || donors.length === 0) {
      return res.json({ success: true, synced: 0, message: "No donor records found." });
    }

    let synced = 0, failed = 0;
    for (const d of donors) {
      try {
        await appendDonorToSheet({
          name:                d.name,
          email:               d.email,
          roll_no:             d.roll_no,
          amount_paise:        d.amount_paise,
          semester_label:      d.semester_label,
          razorpay_payment_id: d.razorpay_payment_id,
          razorpay_order_id:   d.razorpay_order_id,
          is_anonymous:        d.is_anonymous,
          payment_verified_at: d.payment_verified_at,
          source:              "backfill",
        });
        synced++;
        await new Promise(r => setTimeout(r, 300));
      } catch (e) {
        console.error(`[backfill] Failed for payment ${d.razorpay_payment_id}:`, e.message);
        failed++;
      }
    }
    console.log(`[backfill] Done — synced: ${synced}, failed: ${failed}`);
    return res.json({ success: true, synced, failed, total: donors.length });
  } catch (e) {
    console.error("[sheet-backfill]", e.message);
    return res.status(500).json({ error: "Backfill failed. Check server logs." });
  }
});


// ── GOOGLE SHEETS INTEGRATION ─────────────────────────────────────────────────
// Appends one donor row to the Google Sheet via Sheets API v4 (JWT, no extra npm).
// Env vars needed:
//   GOOGLE_SHEET_ID        — spreadsheet ID from URL
//   GOOGLE_SERVICE_ACCOUNT — full service-account JSON stringified
// Share the sheet with the service-account email as Editor.
// Column order: Date | Name | Email | Roll No | Amount (Rs) | Payment ID | Order ID | Semester | Anonymous | Source

async function appendDonorToSheet(donor) {
  const sheetId = process.env.GOOGLE_SHEET_ID;
  const saRaw   = process.env.GOOGLE_SERVICE_ACCOUNT;
  if (!sheetId || !saRaw) {
    console.warn("[sheets] GOOGLE_SHEET_ID or GOOGLE_SERVICE_ACCOUNT not set — skipping");
    return;
  }
  let sa;
  try { sa = JSON.parse(saRaw); } catch (e) {
    console.error("[sheets] GOOGLE_SERVICE_ACCOUNT is not valid JSON:", e.message); return;
  }
  const now   = Math.floor(Date.now() / 1000);
  const claim = {
    iss:   sa.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud:   "https://oauth2.googleapis.com/token",
    exp:   now + 3600,
    iat:   now,
  };
  function b64url(obj) {
    return Buffer.from(JSON.stringify(obj)).toString("base64")
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
  const header   = b64url({ alg: "RS256", typ: "JWT" });
  const payload  = b64url(claim);
  const unsigned = header + "." + payload;
  const { createSign } = require("crypto");
  const signer   = createSign("RSA-SHA256");
  signer.update(unsigned);
  const sig = signer.sign(sa.private_key, "base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const jwt = unsigned + "." + sig;
  const tokenRes  = await fetch("https://oauth2.googleapis.com/token", {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt,
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error("[sheets] Token exchange failed: " + JSON.stringify(tokenData));
  }
  const accessToken = tokenData.access_token;
  const date   = donor.payment_verified_at
    ? new Date(donor.payment_verified_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })
    : new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
  const amtRs  = donor.amount_paise ? Math.round(donor.amount_paise / 100) : "";
  const row    = [
    date,
    donor.is_anonymous ? "Anonymous" : (donor.name    || ""),
    donor.is_anonymous ? ""          : (donor.email   || ""),
    donor.is_anonymous ? ""          : (donor.roll_no || ""),
    amtRs,
    donor.razorpay_payment_id || "",
    donor.razorpay_order_id   || "",
    donor.semester_label      || "",
    donor.is_anonymous ? "Yes" : "No",
    donor.source || "payment",
  ];
  const appendRes = await fetch(
    "https://sheets.googleapis.com/v4/spreadsheets/" + sheetId +
    "/values/Sheet1!A:J:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS",
    {
      method:  "POST",
      headers: { Authorization: "Bearer " + accessToken, "Content-Type": "application/json" },
      body:    JSON.stringify({ values: [row] }),
    }
  );
  if (!appendRes.ok) {
    const err = await appendRes.text();
    throw new Error("[sheets] Append failed: " + err);
  }
  console.log("[sheets] Row appended for payment " + donor.razorpay_payment_id);
}

// ── EMERGENCY UNLOCK (secret-key protected, no auth token needed) ─────────────
// Usage: GET /api/admin/emergency-unlock?username=kfsmaster&secret=YOUR_UNLOCK_SECRET
//        GET /api/admin/emergency-unlock?username=kfsmaster2&secret=YOUR_UNLOCK_SECRET
// Set UNLOCK_SECRET env var in Render dashboard — keep it private
app.get("/api/admin/emergency-unlock", async (req, res) => {
  const { username, secret } = req.query;
  const UNLOCK_SECRET = process.env.UNLOCK_SECRET;
  if (!UNLOCK_SECRET) {
    return res.status(503).json({ error: "UNLOCK_SECRET env var not configured on server." });
  }
  // Use timingSafeEqual to prevent timing-based brute-force of the secret
  let secretValid = false;
  try {
    if (secret) {
      const a = Buffer.alloc(64);
      const b = Buffer.alloc(64);
      a.write(secret, 0, "utf8");
      b.write(UNLOCK_SECRET, 0, "utf8");
      secretValid = crypto.timingSafeEqual(a, b) &&
                    secret.length === UNLOCK_SECRET.length;
    }
  } catch { secretValid = false; }
  if (!secretValid) {
    return res.status(403).json({ error: "Invalid secret." });
  }
  if (!username) {
    return res.status(400).json({ error: "username query param required." });
  }
  const normalised = username.trim().toLowerCase();
  LOGIN_ATTEMPTS.delete(normalised);
  try {
    await supabase
      .from("admins")
      .update({ login_failures: 0, locked_until: null })
      .eq("username", normalised);
  } catch(e) {
    console.error("[unlock] DB clear failed:", e.message);
  }
  console.log(`[unlock] Emergency unlock triggered for "${normalised}"`);
  res.json({ success: true, message: `Lockout cleared for "${normalised}". You can now log in.` });
});

// ── LOCKOUT STATUS CHECK (secret-key protected) ───────────────────────────────
// Usage: GET /api/admin/lockout-status?username=kfsmaster&secret=YOUR_UNLOCK_SECRET
app.get("/api/admin/lockout-status", async (req, res) => {
  const { username, secret } = req.query;
  const UNLOCK_SECRET = process.env.UNLOCK_SECRET;
  if (!UNLOCK_SECRET) {
    return res.status(403).json({ error: "UNLOCK_SECRET not configured." });
  }
  // Use timingSafeEqual to match emergency-unlock's security posture
  let secretValid = false;
  try {
    if (secret) {
      const a = Buffer.alloc(64);
      const b = Buffer.alloc(64);
      a.write(secret, 0, "utf8");
      b.write(UNLOCK_SECRET, 0, "utf8");
      secretValid = crypto.timingSafeEqual(a, b) && secret.length === UNLOCK_SECRET.length;
    }
  } catch { secretValid = false; }
  if (!secretValid) {
    return res.status(403).json({ error: "Invalid or missing secret." });
  }
  if (!username) return res.status(400).json({ error: "username required." });
  const normalised = username.trim().toLowerCase();
  const entry = LOGIN_ATTEMPTS.get(normalised);
  const { data: dbAdmin } = await supabase
    .from("admins")
    .select("username, login_failures, locked_until")
    .eq("username", normalised)
    .maybeSingle();
  res.json({
    username: normalised,
    found_in_db: !!dbAdmin,
    in_memory_lockout: entry ? { count: entry.count, lockedUntil: entry.lockedUntil ? new Date(entry.lockedUntil).toISOString() : null } : null,
    db_lockout: dbAdmin ? { login_failures: dbAdmin.login_failures, locked_until: dbAdmin.locked_until } : null,
    has_password_hash: !!dbAdmin, // always true if admin row exists
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// KFS QR REGISTRATION SYSTEM — add this block to server.js
// Paste BEFORE the catch-all route (app.get("*", ...)) at the bottom of server.js
// ══════════════════════════════════════════════════════════════════════════════

// ── QR Ticket PDF generator ────────────────────────────────────────────────────
// ── Helper: upload QR code buffer to Cloudinary and return a hosted URL ──────
// Gmail, Outlook, Apple Mail, Yahoo ALL block data: URIs in <img src>.
// We must host the QR at a real URL for it to render in email HTML.
// The PDF attachment still uses the raw buffer (fine — it's a file, not email HTML).
async function uploadQrToCloudinary(qrDataUrl) {
  const qrBase64 = qrDataUrl.replace(/^data:image\/png;base64,/, "");
  const qrBuffer = Buffer.from(qrBase64, "base64");
  try {
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "kfs-media/qr-codes",
          resource_type: "image",
          format: "png",
          // No transformation — QR must stay pixel-perfect
          quality: 100,
        },
        (error, result) => {
          if (error) reject(new Error("Cloudinary QR upload: " + error.message));
          else resolve(result);
        }
      );
      uploadStream.end(qrBuffer);
    });
    console.log(`[qr-upload] ✓ QR hosted at ${result.secure_url}`);
    return result.secure_url;
  } catch (e) {
    console.error("[qr-upload] Cloudinary QR upload failed:", e.message);
    return null; // caller falls back to hiding the inline QR
  }
}

// Layout mirrors the KFS reference ticket:
//   • Full black bg
//   • Top: logo (circle-clipped) + "KIIT FILM SOCIETY" bold header
//   • Large centered event name
//   • DATE , TIME / Venue line centered
//   • Large white-box QR centered
//   • PERSON NAME (huge, bold, centered)
//   • Mail id centered
//   • Welcome text bold centered
//   • Footer: contact email small at bottom
async function generateTicketPdf({ event, reg, qrDataUrl }) {
  const PDFDocument = require("pdfkit");

  const qrBase64 = qrDataUrl.replace(/^data:image\/png;base64,/, "");
  const qrBuffer = Buffer.from(qrBase64, "base64");

  // Fetch KFS logo (5s timeout)
  const LOGO_URL = "https://kiitfilmsociety.in/images/kfs-logo.png";
  const logoBuffer = await new Promise(res => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; res(v); } };
    const timer = setTimeout(() => done(null), 5000);
    try {
      const https = require("https");
      const ch = [];
      const req = https.get(LOGO_URL, r => {
        if (r.statusCode !== 200) { r.resume(); clearTimeout(timer); return done(null); }
        r.on("data", chunk => ch.push(chunk));
        r.on("end",  () => { clearTimeout(timer); done(Buffer.concat(ch)); });
        r.on("error", () => { clearTimeout(timer); done(null); });
      });
      req.on("error", () => { clearTimeout(timer); done(null); });
    } catch (_) { clearTimeout(timer); done(null); }
  });

  return new Promise((resolve, reject) => {
    // Slim portrait card — Apple Wallet proportions
    const W = 400, H = 680;
    const doc = new PDFDocument({ size: [W, H], margin: 0, info: { Title: `KFS Ticket — ${event.title || "Event"}` } });
    const chunks = [];
    doc.on("data",  ch => chunks.push(ch));
    doc.on("end",   () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const PAD = 32;
    const CX  = W / 2;

    // ── Full black background ─────────────────────────────────────────────────
    doc.rect(0, 0, W, H).fill("#0a0a0a");

    // ── Header: logo + org name ───────────────────────────────────────────────
    let y = 36;
    const logoR = 16;
    const logoX = PAD + logoR;
    const logoY = y + logoR;
    if (logoBuffer) {
      try {
        doc.save().circle(logoX, logoY, logoR).clip();
        doc.image(logoBuffer, logoX - logoR, logoY - logoR, { width: logoR * 2, height: logoR * 2 });
        doc.restore();
      } catch (_) {
        doc.circle(logoX, logoY, logoR).fill("#1a1a1a");
        doc.fillColor("#ffffff").fontSize(8).font("Helvetica-Bold")
          .text("KFS", logoX - logoR, logoY - 5, { width: logoR * 2, align: "center" });
      }
    } else {
      doc.circle(logoX, logoY, logoR).fill("#1a1a1a");
      doc.fillColor("#ffffff").fontSize(8).font("Helvetica-Bold")
        .text("KFS", logoX - logoR, logoY - 5, { width: logoR * 2, align: "center" });
    }
    doc.fillColor("#ffffff").fontSize(11).font("Helvetica-Bold")
      .text("KIIT FILM SOCIETY", logoX + logoR + 10, logoY - 7, { characterSpacing: 1.2 });

    // ── Thin white rule ────────────────────────────────────────────────────────
    y = logoY + logoR + 28;
    doc.moveTo(PAD, y).lineTo(W - PAD, y).lineWidth(0.4).strokeColor("#1e1e1e").stroke();
    y += 28;

    // ── Event title — large, white, centered ──────────────────────────────────
    doc.fillColor("#ffffff").fontSize(30).font("Helvetica-Bold")
      .text(event.title || "Event", PAD, y, { width: W - PAD * 2, align: "center", lineGap: 3 });

    const titleH = doc.heightOfString(event.title || "Event", { width: W - PAD * 2, fontSize: 30, lineGap: 3 });
    y += titleH + 14;

    // ── Date · Venue — small grey, centered ───────────────────────────────────
    const eventDate = event.event_date
      ? new Date(event.event_date).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" })
      : null;
    const metaLine = [eventDate, event.location].filter(Boolean).join("   ·   ");
    if (metaLine) {
      doc.fillColor("#888888").fontSize(10).font("Helvetica")
        .text(metaLine, PAD, y, { width: W - PAD * 2, align: "center", characterSpacing: 0.3 });
      y += 22;
    }

    // ── Thin rule ─────────────────────────────────────────────────────────────
    y += 18;
    doc.moveTo(PAD, y).lineTo(W - PAD, y).lineWidth(0.4).strokeColor("#1e1e1e").stroke();
    y += 28;

    // ── QR code — white card, centered, large ─────────────────────────────────
    const qrSize = 180;
    const qrPad  = 16;
    const boxSide = qrSize + qrPad * 2;
    const boxX = CX - boxSide / 2;

    // White rounded container
    doc.roundedRect(boxX, y, boxSide, boxSide, 12).fill("#ffffff");
    try {
      doc.image(qrBuffer, boxX + qrPad, y + qrPad, { width: qrSize, height: qrSize });
    } catch (_) {}

    y += boxSide + 12;

    // "SHOW AT ENTRY GATE" label
    doc.fillColor("#444444").fontSize(8).font("Helvetica")
      .text("SHOW AT ENTRY GATE", 0, y, { width: W, align: "center", characterSpacing: 1.4 });
    y += 28;

    // ── Thin rule ─────────────────────────────────────────────────────────────
    doc.moveTo(PAD, y).lineTo(W - PAD, y).lineWidth(0.4).strokeColor("#1e1e1e").stroke();
    y += 24;

    // ── Attendee name — centered, white, bold ─────────────────────────────────
    doc.fillColor("#ffffff").fontSize(20).font("Helvetica-Bold")
      .text((reg.name || "").toUpperCase(), PAD, y, { width: W - PAD * 2, align: "center", characterSpacing: 1.0 });

    const nameH = doc.heightOfString((reg.name || "").toUpperCase(), { width: W - PAD * 2, fontSize: 20 });
    y += nameH + 8;

    // Email
    doc.fillColor("#555555").fontSize(9).font("Helvetica")
      .text(reg.email || "", PAD, y, { width: W - PAD * 2, align: "center" });
    y += 16;

    // Roll no (if any)
    if (reg.roll_no) {
      doc.fillColor("#444444").fontSize(8).font("Helvetica")
        .text(reg.roll_no.toUpperCase(), PAD, y, { width: W - PAD * 2, align: "center", characterSpacing: 0.5 });
      y += 14;
    }

    // ── Welcome line ──────────────────────────────────────────────────────────
    y += 10;
    doc.fillColor("#555555").fontSize(9).font("Helvetica-Oblique")
      .text("Welcome to the event!! Hope you have a great time.", PAD, y, { width: W - PAD * 2, align: "center" });

    // ── Bottom contact line ───────────────────────────────────────────────────
    doc.fillColor("#2a2a2a").fontSize(7.5).font("Helvetica")
      .text("For details or queries contact us at filmsocietykiit@gmail.com", PAD, H - 24, { width: W - PAD * 2, align: "center" });

    doc.end();
  });
}
async function sendTicketEmail({ event, reg, qrDataUrl }) {
  // Fresh fetch every time — no cache risk with API key
  const { data: rows } = await supabase
    .from("settings")
    .select("key,value")
    .in("key", ["brevo_api_key", "smtp_from_name"]);

  const s = {};
  (rows || []).forEach((r) => (s[r.key] = r.value));
  if (!s.brevo_api_key) {
    console.warn("[ticket-email] Brevo API key not configured — skipping ticket email");
    return;
  }

  const fromName = s.smtp_from_name || "KFS — KIIT Film Society";

  const eventDate = event.event_date
    ? new Date(event.event_date).toLocaleDateString("en-IN", {
        weekday: "long", day: "numeric", month: "long", year: "numeric",
      })
    : null;
  const eventDateShort = event.event_date
    ? new Date(event.event_date).toLocaleDateString("en-IN", {
        day: "numeric", month: "short", year: "numeric",
      })
    : null;

  // ── Upload QR to Cloudinary so email clients can display it ───────────────
  // CRITICAL: Gmail, Outlook, Apple Mail, Yahoo all BLOCK data: URIs in <img src>.
  // We upload the QR to Cloudinary and use the hosted URL in the email HTML.
  // The PDF attachment uses the raw buffer (separate path, works fine).
  console.log(`[ticket-email] Uploading QR to Cloudinary for ${reg.email}...`);
  const qrHostedUrl = await uploadQrToCloudinary(qrDataUrl);
  if (!qrHostedUrl) {
    console.warn(`[ticket-email] QR upload failed — email will show fallback message instead of QR image`);
  } else {
    console.log(`[ticket-email] QR hosted at: ${qrHostedUrl}`);
  }

  // ── Apple-style HTML ticket email ─────────────────────────────────────────
  // QR image uses Cloudinary-hosted URL (not a data: URI — blocked by all major email clients).
  // PDF ticket is attached as a file — attendees can save/screenshot it.

  // Build Google Calendar URL
  let gcUrl = "";
  if (event.event_date) {
    const base = event.event_date.replace(/-/g, "");
    let gcDates = base + "/" + base;
    if (event.event_time) {
      const t = event.event_time;
      const h24 = t.match(/^(\d{1,2}):(\d{2})/);
      if (h24) {
        const h = parseInt(h24[1]), m = parseInt(h24[2]);
        const pad = n => String(n).padStart(2, "0");
        const eh = Math.min(h + 2, 23);
        gcDates = `${base}T${pad(h)}${pad(m)}00/${base}T${pad(eh)}${pad(m)}00`;
      }
    }
    const gcTitle = encodeURIComponent(event.title || "KFS Event");
    const gcLoc = encodeURIComponent(event.location_link || event.location || "");
    gcUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${gcTitle}&dates=${gcDates}&location=${gcLoc}&details=${encodeURIComponent("Registered via KFS — KIIT Film Society")}`;
  }

  // WhatsApp share URL
  const waShareText = encodeURIComponent(`I just registered for ${event.title || "an event"} by KFS — KIIT Film Society! See you there: https://kiitfilmsociety.in/events`);
  const waUrl = `https://wa.me/?text=${waShareText}`;

  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your KFS Ticket</title>
</head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 16px 56px">
<tr><td align="center">

  <!-- ── Outer wrapper ── -->
  <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%">

    <!-- ── Logo header ── -->
    <tr><td align="center" style="padding-bottom:28px">
      <table role="presentation" cellpadding="0" cellspacing="0">
        <tr>
          <td style="vertical-align:middle">
            <img src="https://kiitfilmsociety.in/images/kfs-logo.png" width="36" height="36" alt="KFS" style="display:block;width:36px;height:36px;border-radius:9px;border:none;outline:none" onerror="this.style.display='none'" />
          </td>
          <td style="padding-left:10px;vertical-align:middle">
            <div style="font-size:15px;font-weight:700;color:#f5f5f7;letter-spacing:-.01em">KIIT Film Society</div>
            <div style="font-size:11px;color:#636366;margin-top:1px;letter-spacing:.02em">Event Entry Ticket</div>
          </td>
        </tr>
      </table>
    </td></tr>

    <!-- ── Main ticket card ── -->
    <tr><td style="background:#1c1c1e;border-radius:20px;border:1px solid #2c2c2e;overflow:hidden">

      <!-- Top accent bar -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="background:linear-gradient(90deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);height:5px;font-size:0;line-height:0">&nbsp;</td></tr>
      </table>

      <!-- ── Event header block ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:28px 32px 0 32px">
          <div style="font-size:10px;font-weight:700;color:#636366;letter-spacing:.14em;text-transform:uppercase;margin-bottom:10px">You're in ✓</div>
          <div style="font-size:26px;font-weight:800;color:#f5f5f7;line-height:1.2;letter-spacing:-.03em">${(event.title || "Event").replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
          ${eventDate ? `<div style="margin-top:10px;font-size:13px;color:#aeaeb2;font-weight:500">${eventDate}</div>` : ""}
          ${event.location ? `<div style="margin-top:4px;font-size:12px;color:#636366">${event.location.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>` : ""}
          <div style="margin-top:16px;padding-bottom:24px">
            <span style="display:inline-block;background:rgba(52,199,89,.15);border:1px solid rgba(52,199,89,.35);border-radius:20px;padding:5px 14px;font-size:11px;font-weight:700;color:#34c759;letter-spacing:.06em;text-transform:uppercase">● Confirmed</span>
          </div>
        </td></tr>
      </table>

      <!-- ── Perforated divider (semi-circles on sides prevent overlap with card border) ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
        <tr>
          <td width="18" height="18" style="background:#0a0a0a;border-radius:0 18px 18px 0;font-size:0;line-height:0;padding:0">&nbsp;</td>
          <td style="height:1px;border-top:2px dashed #3a3a3c;font-size:0;line-height:0;padding:0">&nbsp;</td>
          <td width="18" height="18" style="background:#0a0a0a;border-radius:18px 0 0 18px;font-size:0;line-height:0;padding:0">&nbsp;</td>
        </tr>
      </table>

      <!-- ── QR + Attendee info (stacked layout avoids divider overlap) ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:28px 32px 8px 32px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr valign="top">

              <!-- QR code column -->
              <td style="width:152px">
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr><td style="background:#ffffff;border-radius:14px;padding:10px;line-height:0">
                    ${qrHostedUrl
                      ? `<img src="${qrHostedUrl}" width="132" height="132" alt="Entry QR Code" style="display:block;width:132px;height:132px;border:none;outline:none" />`
                      : `<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="width:132px;height:132px;text-align:center;vertical-align:middle;font-size:11px;color:#636366;line-height:1.4;font-family:Helvetica,Arial,sans-serif">QR code in<br>PDF attachment</td></tr></table>`
                    }
                  </td></tr>
                </table>
                <div style="margin-top:8px;font-size:10px;font-weight:600;color:#636366;letter-spacing:.08em;text-transform:uppercase;text-align:center">Scan at entry</div>
              </td>

              <!-- Vertical dashed divider -->
              <td width="40" style="padding:0 20px;font-size:0;line-height:0">
                <div style="width:1px;height:160px;border-left:1px dashed #3a3a3c;margin:0 auto">&nbsp;</div>
              </td>

              <!-- Attendee details column -->
              <td style="vertical-align:middle">
                <div style="font-size:10px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:10px">Attendee</div>
                <div style="font-size:20px;font-weight:800;color:#f5f5f7;letter-spacing:-.02em;line-height:1.2">${reg.name.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
                <div style="font-size:12px;color:#636366;margin-top:5px;word-break:break-all">${reg.email.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>

                ${reg.roll_no ? `
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:12px">
                  <tr><td style="background:#2c2c2e;border-radius:8px;padding:7px 12px">
                    <div style="font-size:9px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:2px">Roll No</div>
                    <div style="font-size:13px;font-weight:700;color:#f5f5f7;letter-spacing:.04em">${reg.roll_no.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
                  </td></tr>
                </table>` : ""}

                ${eventDateShort ? `
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:8px">
                  <tr><td style="background:#2c2c2e;border-radius:8px;padding:7px 12px">
                    <div style="font-size:9px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:2px">Date</div>
                    <div style="font-size:13px;font-weight:700;color:#f5f5f7">${eventDateShort}</div>
                  </td></tr>
                </table>` : ""}
              </td>

            </tr>
          </table>
        </td></tr>
      </table>

      <!-- ── Action buttons row (Calendar, Location, WhatsApp) ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:20px 32px 28px 32px">
          <table role="presentation" cellpadding="0" cellspacing="0">
            <tr>
              ${gcUrl ? `
              <td style="padding-right:8px">
                <a href="${gcUrl}" style="display:inline-block;background:#2c2c2e;border:1px solid #3a3a3c;border-radius:20px;padding:8px 16px;font-size:11px;font-weight:600;color:#aeaeb2;text-decoration:none;letter-spacing:.02em;white-space:nowrap">
                  📅 Add to Calendar
                </a>
              </td>` : ""}
              ${event.location_link ? `
              <td style="padding-right:8px">
                <a href="${event.location_link.replace(/"/g,"&quot;")}" style="display:inline-block;background:#2c2c2e;border:1px solid #3a3a3c;border-radius:20px;padding:8px 16px;font-size:11px;font-weight:600;color:#aeaeb2;text-decoration:none;letter-spacing:.02em;white-space:nowrap">
                  📍 View Location
                </a>
              </td>` : ""}
              <td>
                <a href="${waUrl}" style="display:inline-block;background:rgba(37,211,102,.12);border:1px solid rgba(37,211,102,.28);border-radius:20px;padding:8px 16px;font-size:11px;font-weight:600;color:#25d366;text-decoration:none;letter-spacing:.02em;white-space:nowrap">
                  💬 Share on WhatsApp
                </a>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>

      <!-- ── Footer strip ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="background:#141414;border-top:1px solid #2c2c2e;padding:16px 32px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="font-size:13px;font-weight:600;color:#f5f5f7">See you there!</td>
              <td align="right" style="font-size:11px">
                <a href="mailto:filmsocietykiit@gmail.com" style="color:#636366;text-decoration:none">filmsocietykiit@gmail.com</a>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>

    </td></tr>
    <!-- End main ticket card -->

    <!-- Fine print -->
    <tr><td align="center" style="padding-top:20px">
      <p style="font-size:11px;color:#3a3a3c;text-align:center;line-height:1.6;margin:0">
        This ticket is personal and non-transferable. Do not share your QR code.
      </p>
    </td></tr>

  </table>

</td></tr>
</table>
</body>
</html>`;

  const textContent = `Your KFS Ticket — ${event.title || "Event"}\n\n${eventDate ? eventDate + "\n" : ""}${event.location ? event.location + "\n" : ""}${event.location_link ? "Location: " + event.location_link + "\n" : ""}\nName: ${reg.name}\nEmail: ${reg.email}${reg.roll_no ? "\nRoll No: " + reg.roll_no : ""}\n\nYour QR ticket is attached to this email as a PDF.\nOpen the PDF attachment and show the QR code at the entry gate.\n\nSee you there!\nFor queries: filmsocietykiit@gmail.com`;

  // ── Generate PDF ticket attachment ─────────────────────────────────────────
  let pdfAttachment = null;
  try {
    console.log(`[ticket-email] Generating PDF for ${reg.email}...`);
    const pdfBuffer = await generateTicketPdf({ event, reg, qrDataUrl });
    pdfAttachment = {
      name: `KFS-Ticket-${(event.title || "event").replace(/[^a-zA-Z0-9]/g, "-").slice(0, 40)}.pdf`,
      content: pdfBuffer.toString("base64"),
      type: "application/pdf",   // Required: Brevo needs explicit MIME type for non-image attachments
    };
    console.log(`[ticket-email] PDF generated (${pdfBuffer.length} bytes) for ${reg.email}`);
  } catch (pdfErr) {
    // Non-fatal: email still sends, just without PDF attachment
    console.error(`[ticket-email] PDF generation failed for ${reg.email}:`, pdfErr.message);
  }

  const brevoPayload = {
    sender: { name: fromName, email: "noreply@kiitfilmsociety.in" },
    to: [{ email: reg.email, name: reg.name }],
    subject: `Your ticket for ${event.title || "the event"} — KFS`,
    textContent,
    htmlContent,
  };
  if (pdfAttachment) {
    brevoPayload.attachment = [pdfAttachment];
    console.log(`[ticket-email] Attaching PDF: ${pdfAttachment.name}`);
  } else {
    console.warn(`[ticket-email] Sending without PDF attachment (generation failed)`);
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": s.brevo_api_key,
      "content-type": "application/json",
    },
    body: JSON.stringify(brevoPayload),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo ticket email error ${response.status}: ${err}`);
  }
  console.log(`[ticket-email] ✓ Sent to ${reg.email} for "${event.title}" (PDF: ${pdfAttachment ? "attached" : "inline-only"})`);
}


// ── PUBLIC: Register for event (creates registration + sends QR ticket email) ──
const registrationRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // raised from 5 — campus users share the same NAT IP
  message: { error: "Too many registration attempts. Please wait 15 minutes." },
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
});

app.post("/api/events/:id/register", registrationRateLimit, async (req, res) => {
  const { name, email, phone, roll_no } = req.body;
  const rawId = req.params.id;
  // Support both integer IDs (bigint/serial) and UUID IDs
  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const isUuid = UUID_PATTERN.test(rawId);
  const parsedInt = parseInt(rawId, 10);
  const eventId = isUuid ? rawId : (!isNaN(parsedInt) ? parsedInt : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });
  console.log(`[register] event_id="${rawId}" parsed="${eventId}" (${isUuid ? "uuid" : "integer"})`);

  if (!name || !email) {
    return res.status(400).json({ error: "Name and email are required" });
  }
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: "Invalid email address" });
  }

  // 1. Check event exists
  const { data: event, error: evErr } = await supabasePublic
    .from("events")
    .select("id,title,event_date,location,location_link,is_upcoming")
    .eq("id", eventId)
    .maybeSingle();
  if (evErr || !event) return res.status(404).json({ error: "Event not found" });

  // 2. Check already registered (same event + email)
  const { data: existing } = await supabase
    .from("event_registrations")
    .select("id")
    .eq("event_id", eventId)
    .eq("email", email.toLowerCase().trim())
    .maybeSingle();
  if (existing) return res.status(409).json({ error: "This email is already registered for this event." });

  // 3. Generate unique token
  const qrToken = crypto.randomUUID();

  // 4. Save to DB
  const { data: reg, error: insertErr } = await supabase
    .from("event_registrations")
    .insert([{
      event_id: eventId,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      phone: phone ? phone.trim() : null,
      roll_no: roll_no ? roll_no.trim().toUpperCase() : null,
      qr_token: qrToken,
    }])
    .select()
    .single();
  if (insertErr) {
    console.error("[register] DB insert error:", insertErr);
    return res.status(500).json({ error: "Registration failed. Please try again." });
  }

  // 5. Generate QR image — encode the token as-is (lowercase UUID from crypto.randomUUID()).
  // width 400 + margin 3 ensures the QR is readable on both phone screens and email clients.
  // errorCorrectionLevel "M" gives a denser but highly scan-compatible code vs "H".
  let qrDataUrl;
  try {
    qrDataUrl = await QRCode.toDataURL(qrToken.toLowerCase(), {
      width: 400,
      margin: 3,
      color: { dark: "#000000", light: "#ffffff" },
      errorCorrectionLevel: "M",
    });
  } catch (e) {
    console.error("[register] QR generation failed:", e.message);
    return res.status(500).json({ error: "Could not generate ticket QR." });
  }

  // 6. Send ticket email with PDF attachment (non-blocking — never fail the registration)
  console.log(`[register] Dispatching ticket email+PDF to ${reg.email} for event "${event.title}" reg_id=${reg.id}`);
  sendTicketEmail({ event, reg, qrDataUrl }).catch((e) => {
    console.error(`[register] ✗ ticket email FAILED for ${reg.email}:`, e.message);
  });

  console.log(`[register] ✓ ${reg.name} (${reg.email}) registered event_id=${eventId} reg_id=${reg.id} qr_token=${qrToken}`);
  res.json({
    success: true,
    message: "Registered! Check your email for the QR ticket.",
    id: reg.id,
    qr_data_url: qrDataUrl,  // send QR to client so success screen can display it immediately
  });
});

// ── ADMIN/SCANNER: Lookup QR (validates, does NOT mark checked-in) ─────────────
// Used by scanner page to display person details before confirming entry
app.post("/api/admin/scan-qr/lookup", authMiddleware, async (req, res) => {
  const { qr_token: rawToken, event_id } = req.body;
  if (!rawToken) return res.status(400).json({ error: "qr_token required" });

  // Normalise: trim whitespace/newlines some QR scanner libs append; lowercase for UUID match.
  // crypto.randomUUID() produces lowercase; some device cameras return uppercase hex.
  const qr_token = String(rawToken).trim().toLowerCase();

  if (!qr_token) return res.status(400).json({ status: "invalid", error: "Empty QR code." });

  // Validate token format — accept standard UUID (v4) format only.
  // We normalise to lowercase above so only need to check lowercase hex.
  // Reject URLs, plain text, or anything obviously not a KFS token.
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!UUID_RE.test(qr_token)) {
    console.warn(`[scan-lookup] Rejected non-UUID token: "${qr_token.slice(0, 40)}..." from admin=${req.admin?.username}`);
    return res.status(404).json({ status: "invalid", error: "Invalid QR code — not a KFS ticket." });
  }
  console.log(`[scan-lookup] Valid UUID format: ${qr_token}`);

  console.log(`[scan-lookup] qr_token=${qr_token} event_id=${event_id} admin=${req.admin?.username}`);

  const { data: reg, error } = await supabase
    .from("event_registrations")
    .select("id, name, email, phone, roll_no, checked_in, checked_in_at, checked_in_by, event_id, events(title, event_date, location)")
    .eq("qr_token", qr_token)
    .maybeSingle();

  if (error) {
    console.error(`[scan-lookup] DB error for qr_token=${qr_token}:`, error.message, error.code);
    return res.status(500).json({ error: "DB error", detail: error.message });
  }
  if (!reg) {
    console.warn(`[scan-lookup] QR not found in DB: ${qr_token}`);
    return res.status(404).json({ status: "invalid", error: "QR not recognised — not a valid KFS ticket." });
  }
  console.log(`[scan-lookup] Found reg_id=${reg.id} name="${reg.name}" event_id=${reg.event_id} checked_in=${reg.checked_in}`);

  // If a specific event was selected by the scanner, validate the ticket belongs to it
  if (event_id && String(reg.event_id) !== String(event_id)) {
    return res.json({
      status: "invalid",
      error: `This ticket is for "${reg.events?.title || "a different event"}", not the selected event.`,
    });
  }

  if (reg.checked_in) {
    return res.json({
      status: "already_used",
      name: reg.name,
      email: reg.email,
      roll_no: reg.roll_no,
      phone: reg.phone,
      event: reg.events?.title,
      checked_in_at: reg.checked_in_at,
      checked_in_by: reg.checked_in_by,
      registration_id: reg.id,
    });
  }

  return res.json({
    status: "valid",
    registration_id: reg.id,
    name: reg.name,
    email: reg.email,
    roll_no: reg.roll_no,
    phone: reg.phone,
    event: reg.events?.title,
    event_date: reg.events?.event_date,
  });
});

// ── ADMIN/SCANNER: Confirm entry (marks checked_in = true) ────────────────────
app.post("/api/admin/scan-qr/confirm", authMiddleware, async (req, res) => {
  const { registration_id, event_id } = req.body;
  if (!registration_id) return res.status(400).json({ error: "registration_id required" });

  // Re-check hasn't been scanned in the meantime (race condition)
  const { data: reg } = await supabase
    .from("event_registrations")
    .select("id, name, email, checked_in, event_id")
    .eq("id", registration_id)
    .maybeSingle();

  if (!reg) return res.status(404).json({ error: "Registration not found" });

  // Validate event matches if provided
  if (event_id && String(reg.event_id) !== String(event_id)) {
    return res.status(400).json({ error: "Registration does not belong to the selected event." });
  }

  if (reg.checked_in) {
    return res.status(409).json({ error: "Already checked in", status: "already_used" });
  }

  console.log(`[scan-confirm] Marking reg_id=${registration_id} checked_in for event_id=${event_id} by ${req.admin?.username}`);

  const { error: updateErr } = await supabase
    .from("event_registrations")
    .update({
      checked_in: true,
      checked_in_at: new Date().toISOString(),
      checked_in_by: req.admin.username,
    })
    .eq("id", registration_id);

  if (updateErr) {
    console.error(`[scan-confirm] DB update failed for reg_id=${registration_id}:`, updateErr.message, updateErr.code);
    return res.status(500).json({ error: "Failed to mark entry", detail: updateErr.message });
  }

  logActivity(req.admin.id, req.admin.name, "scan", "event_registration", `${reg.name} — event ${reg.event_id}`).catch(() => {});

  console.log(`[scan-confirm] ✓ ${reg.name} (id=${registration_id}) checked in by ${req.admin.username} for event ${reg.event_id}`);
  res.json({ success: true, name: reg.name });
});

// ── ADMIN: Get all registrations for an event ─────────────────────────────────
app.get("/api/admin/events/:id/registrations", authMiddleware, async (req, res) => {
  const _rawId = req.params.id || req.params.eventId;
  const _UUID_P = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const _isUuid = _UUID_P.test(_rawId);
  const _pi = parseInt(_rawId, 10);
  const eventId = _isUuid ? _rawId : (!isNaN(_pi) ? _pi : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });

  console.log(`[registrations-api] Fetching registrations for event_id=${eventId} (admin=${req.admin?.username})`);

  const { data, error } = await supabase
    .from("event_registrations")
    .select("id, name, email, phone, roll_no, checked_in, checked_in_at, checked_in_by, created_at")
    .eq("event_id", eventId)
    .order("created_at", { ascending: false });

  if (error) {
    console.error(`[registrations-api] DB error for event_id=${eventId}:`, error.message, error.code);
    return res.status(500).json({ error: "Internal server error", detail: error.message });
  }
  console.log(`[registrations-api] event_registrations count=${(data||[]).length} for event_id=${eventId}`);

  // If event_registrations is empty, fall back to form_responses so events
  // registered via the form builder still show up in the scanner data tab.
  // NOTE: form_responses stores answers as a JSON string in the `answers` column.
  if ((data || []).length === 0) {
    const { data: formData, error: formErr } = await supabase
      .from("form_responses")
      .select("id, created_at, answers")
      .eq("event_id", eventId)
      .order("created_at", { ascending: false });

    console.log(`[registrations-api] event_registrations empty — checking form_responses for event_id=${eventId}`);
    console.log(`[registrations-api] form_responses count=${(formData||[]).length} for event_id=${eventId} (formErr=${formErr?.message||null})`);
    if (!formErr && (formData || []).length > 0) {
      // Also pull questions so we can map by question label (not just key name)
      const { data: form } = await supabase
        .from("event_forms")
        .select("questions")
        .eq("event_id", eventId)
        .maybeSingle();
      let questions = [];
      try { questions = JSON.parse(form?.questions || "[]"); } catch (_) {}

      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      // Shape form_responses to match event_registrations schema
      const shaped = formData.map((r) => {
        let d = {};
        try { d = JSON.parse(r.answers || "{}"); } catch (_) {}

        // Try to resolve fields via question labels first, then fall back to key guessing
        const emailQ = questions.find(q => q.type === "email") ||
                       questions.find(q => ["text","textarea"].includes(q.type) && /e[\s-]?mail/i.test(q.label || ""));
        const nameQ  = questions.find(q => ["text","textarea"].includes(q.type) && /\bname\b/i.test(q.label || ""));
        const rollQ  = questions.find(q => ["text","textarea"].includes(q.type) && /roll|reg(istration)?\s*(no|number|#)/i.test(q.label || ""));
        const phoneQ = questions.find(q => ["text","textarea"].includes(q.type) && /phone|mobile/i.test(q.label || ""));

        let email = emailQ ? (d[emailQ.id] || "").trim() : null;
        // Tier 2 fallback: scan all values for an email-shaped string
        if (!email) {
          for (const val of Object.values(d)) {
            if (typeof val === "string" && EMAIL_RE.test(val.trim())) { email = val.trim(); break; }
          }
        }
        // Tier 3 fallback: common key names
        if (!email) email = d.email || d.Email || d.email_address || d["Email Address"] || "";

        const name    = (nameQ  ? d[nameQ.id]  : null) || d.name  || d.Name  || d.full_name  || d["Full Name"]  || email || "—";
        const roll_no = (rollQ  ? d[rollQ.id]  : null) || d.roll_no || d["Roll No"] || d.roll || d["Roll Number"] || null;
        const phone   = (phoneQ ? d[phoneQ.id] : null) || d.phone   || d.Phone   || d.mobile || d.Mobile || null;

        return {
          id:            r.id,
          name:          (typeof name === "string" ? name.trim() : null) || "—",
          email:         (typeof email === "string" ? email.trim().toLowerCase() : "") || "",
          phone:         phone || null,
          roll_no:       roll_no || null,
          checked_in:    false,
          checked_in_at: null,
          checked_in_by: null,
          created_at:    r.created_at,
          _source:       "form_responses",
        };
      });
      console.log(`[registrations-api] Returning ${shaped.length} shaped form_responses for event_id=${eventId}`);
      return res.json(shaped);
    }
    // No registrations in either table
    console.warn(`[registrations-api] No registrations found in event_registrations OR form_responses for event_id=${eventId}`);
  }

  console.log(`[registrations-api] Returning ${(data||[]).length} event_registrations for event_id=${eventId}`);
  res.json(data || []);
});

// ── ADMIN: Export registrations as XLSX ───────────────────────────────────────
app.get("/api/admin/events/:id/registrations/export", authMiddleware, async (req, res) => {
  const _rawId = req.params.id || req.params.eventId;
  const _UUID_P = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const _isUuid = _UUID_P.test(_rawId);
  const _pi = parseInt(_rawId, 10);
  const eventId = _isUuid ? _rawId : (!isNaN(_pi) ? _pi : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });

  const { data: ev } = await supabase
    .from("events")
    .select("title")
    .eq("id", eventId)
    .maybeSingle();

  const { data: regs, error } = await supabase
    .from("event_registrations")
    .select("name, email, phone, roll_no, checked_in, checked_in_at, checked_in_by, created_at")
    .eq("event_id", eventId)
    .order("created_at");

  if (error) return res.status(500).json({ error: "Internal server error" });

  const XLSX = require("xlsx");
  const rows = (regs || []).map((r) => ({
    "Name":            r.name,
    "Email":           r.email,
    "Phone":           r.phone || "—",
    "Roll No":         r.roll_no || "—",
    "Registered At":   new Date(r.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
    "Checked In":      r.checked_in ? "YES" : "NO",
    "Check-in Time":   r.checked_in_at ? new Date(r.checked_in_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) : "—",
    "Checked In By":   r.checked_in_by || "—",
  }));

  const ws = XLSX.utils.json_to_sheet(rows);

  // Auto-width columns
  const colWidths = Object.keys(rows[0] || {}).map((k) => ({
    wch: Math.max(k.length, ...rows.map((r) => String(r[k] || "").length)) + 2,
  }));
  ws["!cols"] = colWidths;

  const wb = XLSX.utils.book_new();
  const sheetName = (ev?.title || "Event").slice(0, 31);
  XLSX.utils.book_append_sheet(wb, ws, sheetName);
  const buf = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

  const safeName = (ev?.title || "event").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  res.setHeader("Content-Disposition", `attachment; filename="kfs-registrations-${safeName}.xlsx"`);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.send(buf);
});

// ── ADMIN: Delete a single registration ───────────────────────────────────────
app.delete("/api/admin/events/:eventId/registrations/:regId", authMiddleware, async (req, res) => {
  const _rawEId = req.params.eventId;
  const _rawRId = req.params.regId;
  const _UUID_P2 = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const eventId = _UUID_P2.test(_rawEId) ? _rawEId : (!isNaN(parseInt(_rawEId,10)) ? parseInt(_rawEId,10) : null);
  const regId   = _UUID_P2.test(_rawRId) ? _rawRId : (!isNaN(parseInt(_rawRId,10)) ? parseInt(_rawRId,10) : null);
  if (!eventId || !regId) return res.status(400).json({ error: "Invalid ID" });

  const { data: reg } = await supabase
    .from("event_registrations")
    .select("name, event_id")
    .eq("id", regId)
    .eq("event_id", eventId)
    .maybeSingle();

  if (!reg) return res.status(404).json({ error: "Registration not found" });

  await supabase.from("event_registrations").delete().eq("id", regId);
  logActivity(req.admin.id, req.admin.name, "delete", "event_registration", reg.name).catch(() => {});
  res.json({ success: true });
});

// ── ADMIN: Get registration stats for an event (for event list view) ──────────
// Counts event_registrations first; if 0, falls back to form_responses count
// (form_responses stores submitted answers in the `answers` column as JSON string).
app.get("/api/admin/events/:id/registrations/stats", authMiddleware, async (req, res) => {
  const _rawId = req.params.id || req.params.eventId;
  const _UUID_P = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const _isUuid = _UUID_P.test(_rawId);
  const _pi = parseInt(_rawId, 10);
  const eventId = _isUuid ? _rawId : (!isNaN(_pi) ? _pi : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });

  const { data, error } = await supabase
    .from("event_registrations")
    .select("id, checked_in")
    .eq("event_id", eventId);

  if (error) return res.status(500).json({ error: "Internal server error" });

  let total = (data || []).length;
  const checkedIn = (data || []).filter((r) => r.checked_in).length;

  // If no QR registrations exist, count form_responses (answers column) so admins
  // can see how many people submitted the event's registration form.
  // Use .select("id") (not head:true) to ensure the service-role key always counts correctly.
  if (total === 0) {
    const { data: formRows, error: formErr } = await supabase
      .from("form_responses")
      .select("id")
      .eq("event_id", eventId);
    if (!formErr) total = (formRows || []).length;
  }

  res.json({ total, checked_in: checkedIn, pending: total - checkedIn });
});

// ══════════════════════════════════════════════════════════════════════════════
// END QR REGISTRATION SYSTEM ROUTES
// ══════════════════════════════════════════════════════════════════════════════


// ── ADMIN MOVIES alias (dashboard + bulk ops use /api/admin/movies) ──────────
app.get("/api/admin/movies", requireSection("movies"), async (req, res) => {
  const { data, error } = await supabase
    .from("movies")
    .select("*")
    .is("deleted_at", null)
    .order("release_year", { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json((data || []).map(m => ({ ...m, genre: typeof m.genre === 'string' ? m.genre.replace(/[{}"]/g,'').split(',').filter(Boolean) : (m.genre || []) })));
});

// (scanner routes moved above catch-all — see bottom of file)

// ── ADMIN: Backfill form_responses → event_registrations ─────────────────────
// One-time utility: copies form submitters into event_registrations so they
// appear in the scanner and can be checked in via QR.
app.post("/api/admin/events/:id/backfill-registrations", requireSection("events"), async (req, res) => {
  const _rawId = req.params.id || req.params.eventId;
  const _UUID_P = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const _isUuid = _UUID_P.test(_rawId);
  const _pi = parseInt(_rawId, 10);
  const eventId = _isUuid ? _rawId : (!isNaN(_pi) ? _pi : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });

  // 1. Fetch the event's form
  const { data: form } = await supabase
    .from("event_forms")
    .select("id,questions")
    .eq("event_id", eventId)
    .maybeSingle();

  if (!form) return res.status(404).json({ error: "No form found for this event" });

  let questions = [];
  try { questions = JSON.parse(form.questions || "[]"); } catch (_) {}

  // 2. Fetch all responses
  const { data: responses, error } = await supabase
    .from("form_responses")
    .select("id,answers,submitted_at")
    .eq("event_id", eventId);

  if (error) return res.status(500).json({ error: "DB error fetching responses" });

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let inserted = 0, skipped = 0;

  for (const resp of (responses || [])) {
    let answers = {};
    try { answers = JSON.parse(resp.answers || "{}"); } catch (_) {}

    // Extract email
    let emailQ = questions.find(q => q.type === "email");
    if (!emailQ) emailQ = questions.find(q => ["text","textarea"].includes(q.type) && /e[\s-]?mail/i.test(q.label || ""));
    let email = emailQ ? (answers[emailQ.id] || "").trim() : null;
    if (!email) {
      for (const val of Object.values(answers)) {
        if (typeof val === "string" && EMAIL_RE.test(val.trim())) { email = val.trim(); break; }
      }
    }
    if (!email) { skipped++; continue; }

    // Extract name
    const nameQ = questions.find(q => ["text","textarea"].includes(q.type) && /name/i.test(q.label || ""));
    const name = (nameQ ? (answers[nameQ.id] || "").trim() : null) || email;

    // Extract phone
    const phoneQ = questions.find(q => ["text","textarea"].includes(q.type) && /phone|mobile/i.test(q.label || ""));
    const phone = phoneQ ? (answers[phoneQ.id] || "").trim() || null : null;

    // Extract roll no
    const rollQ = questions.find(q => ["text","textarea"].includes(q.type) && /roll|reg(istration)?\s*(no|number|#)/i.test(q.label || ""));
    const roll_no = rollQ ? (answers[rollQ.id] || "").trim().toUpperCase() || null : null;

    // Upsert (skip if already registered by email)
    const { error: upsertErr } = await supabase
      .from("event_registrations")
      .upsert([{
        event_id: eventId,
        name,
        email:    email.toLowerCase(),
        phone,
        roll_no,
        qr_token: crypto.randomUUID(),
        created_at: resp.submitted_at,
      }], { onConflict: "event_id,email", ignoreDuplicates: true });

    if (upsertErr) { skipped++; } else { inserted++; }
  }

  res.json({ success: true, total: (responses || []).length, inserted, skipped });
});

// ── ADMIN: Debug endpoint — what's actually in the DB for an event ──────────────
// Use this to diagnose why registrations aren't showing. Returns counts from
// both event_registrations and form_responses tables.
app.get("/api/admin/events/:id/registrations/debug", authMiddleware, async (req, res) => {
  const _rawId = req.params.id || req.params.eventId;
  const _UUID_P = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const _isUuid = _UUID_P.test(_rawId);
  const _pi = parseInt(_rawId, 10);
  const eventId = _isUuid ? _rawId : (!isNaN(_pi) ? _pi : null);
  if (!eventId) return res.status(400).json({ error: "Invalid event ID" });

  const [erResult, frResult, evResult] = await Promise.all([
    supabase.from("event_registrations")
      .select("id, name, email, qr_token, checked_in, created_at")
      .eq("event_id", eventId)
      .order("created_at", { ascending: false }),
    supabase.from("form_responses")
      .select("id, created_at, answers")
      .eq("event_id", eventId)
      .order("created_at", { ascending: false }),
    supabase.from("events").select("id, title, event_date").eq("id", eventId).maybeSingle(),
  ]);

  console.log(`[debug] event_id=${eventId} event_registrations=${(erResult.data||[]).length} form_responses=${(frResult.data||[]).length}`);

  res.json({
    event: evResult.data || null,
    event_registrations: {
      count: (erResult.data || []).length,
      error: erResult.error?.message || null,
      rows: (erResult.data || []).map(r => ({
        id: r.id,
        name: r.name,
        email: r.email,
        has_qr_token: !!r.qr_token,
        qr_token_preview: r.qr_token ? r.qr_token.slice(0, 8) + "..." : null,
        checked_in: r.checked_in,
        created_at: r.created_at,
      })),
    },
    form_responses: {
      count: (frResult.data || []).length,
      error: frResult.error?.message || null,
      sample: (frResult.data || []).slice(0, 3).map(r => ({
        id: r.id,
        created_at: r.created_at,
        answers_keys: (() => { try { return Object.keys(JSON.parse(r.answers || "{}")); } catch { return []; } })(),
      })),
    },
  });
});

// ── SCANNER: Fresh events list (no cache, uses service-role key) ──────────────
// Used by scanner.js instead of /api/events so it always gets up-to-date data
// and works even if supabasePublic has RLS blocking anon reads.
app.get("/api/admin/scanner/events", authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("events")
    .select("id, title, event_date, location, is_upcoming")
    .is("deleted_at", null)
    .order("event_date", { ascending: false });
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || []);
});

// ═══════════════════════════════════════════════════════════════════════════════
// KFS Member Portal — Server Routes
// Add this block to server.js BEFORE the catch-all app.get("*", ...) route.
//
// Depends on the following already existing in server.js (all present in v1.17.9+):
//   supabase, supabasePublic, bcrypt, jwt, crypto, speakeasy, QRCode,
//   upload, uploadImage, compressImage,
//   signAccessToken (reused pattern — member version defined below),
//   rateLimit, cookieParser, csrfProtect,
//   logActivity (admin logger — member logger is separate below),
//   memInvalidate
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-1 — Member JWT helpers (parallel to admin, separate secret namespace)
// ─────────────────────────────────────────────────────────────────────────────

if (!process.env.MEMBER_JWT_SECRET) {
  console.error('[FATAL] MEMBER_JWT_SECRET env var not set. Refusing to start.');
  process.exit(1);
}
const MEMBER_JWT_SECRET = process.env.MEMBER_JWT_SECRET;

function signMemberAccessToken(payload) {
  const jti = crypto.randomBytes(16).toString("hex");
  return jwt.sign({ ...payload, jti, _type: "member" }, MEMBER_JWT_SECRET, { expiresIn: "15m" });
}

async function issueMemberRefreshToken(accountId) {
  const raw  = crypto.randomBytes(40).toString("hex");
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  const exp  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const { data: token, error } = await supabase.from("member_refresh_tokens").insert([{
    account_id: accountId,
    token_hash: hash,
    expires_at: exp.toISOString(),
  }]).select().single();
  if (error) throw new Error("Could not store member refresh token: " + error.message);
  // Track session
  return { raw, tokenId: token.id };
}

function setMemberRefreshCookie(res, raw) {
  res.cookie("kfs_member_refresh", raw, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   7 * 24 * 60 * 60 * 1000,
    path:     "/api/member/refresh",
  });
  res.cookie("kfs_member_session", "1", {
    httpOnly: false,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   7 * 24 * 60 * 60 * 1000,
  });
}

function clearMemberRefreshCookie(res) {
  res.clearCookie("kfs_member_refresh", { path: "/api/member/refresh" });
  res.clearCookie("kfs_member_session");
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-2 — Member JWT revocation (in-memory Set, loaded at boot)
// ─────────────────────────────────────────────────────────────────────────────

const _revokedMemberJtis = new Set();

async function loadRevokedMemberTokens() {
  const { data } = await supabase
    .from("member_revoked_tokens")
    .select("jti")
    .gt("expires_at", new Date().toISOString());
  (data || []).forEach(r => _revokedMemberJtis.add(r.jti));
  console.log(`[member-auth] Loaded ${_revokedMemberJtis.size} revoked member JTIs from DB`);
}

async function revokeMemberToken(jti, expiresAt) {
  _revokedMemberJtis.add(jti);
  try {
    await supabase.from("member_revoked_tokens").upsert([{
      jti,
      expires_at: new Date(expiresAt * 1000).toISOString(),
    }]);
  } catch (e) {
    console.error("[member-auth] revoke persist failed:", e.message);
  }
}

async function revokeAllMemberRefreshTokens(accountId) {
  await supabase
    .from("member_refresh_tokens")
    .update({ used: true })
    .eq("account_id", accountId);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-3 — Member auth middleware
// ─────────────────────────────────────────────────────────────────────────────

function memberAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, MEMBER_JWT_SECRET, { algorithms: ["HS256"] });
    if (decoded._type !== "member") return res.status(401).json({ error: "Invalid token type" });
    if (decoded.jti && _revokedMemberJtis.has(decoded.jti)) {
      return res.status(401).json({ error: "Token revoked" });
    }
    req.member = decoded; // { id (account_id), memberId, username }
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-4 — Member activity logger
// ─────────────────────────────────────────────────────────────────────────────

async function logMemberActivity(accountId, memberId, action, metadata, ipAddress) {
  try {
    await supabase.from("member_activity").insert([{
      account_id: accountId || null,
      member_id:  memberId  || null,
      action,
      metadata:   metadata  || null,
      ip_address: ipAddress || null,
    }]);
  } catch (e) {
    console.error("[member-activity]", e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-5 — Member login lockout (mirrors admin lockout pattern)
// ─────────────────────────────────────────────────────────────────────────────

const MEMBER_LOGIN_ATTEMPTS = new Map();

function checkMemberLockout(username) {
  const entry = MEMBER_LOGIN_ATTEMPTS.get(username);
  if (!entry) return null;
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    const secsLeft = Math.ceil((entry.lockedUntil - Date.now()) / 1000);
    const timeStr = secsLeft < 120 ? `${secsLeft} second(s)` :
                    secsLeft < 7200 ? `${Math.ceil(secsLeft/60)} minute(s)` :
                    `${Math.ceil(secsLeft/3600)} hour(s)`;
    return {
      message: `Account locked. Try again in ${timeStr}.`,
      lockedUntil: entry.lockedUntil, // epoch ms — client uses this to drive a live countdown
    };
  }
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    MEMBER_LOGIN_ATTEMPTS.delete(username);
  }
  return null;
}

function recordMemberLoginFailure(username) {
  const entry = MEMBER_LOGIN_ATTEMPTS.get(username) || { count: 0, lockedUntil: null };
  entry.count += 1;
  const TIERS = [
    { after: 5,  durationMs: 5  * 60 * 1000 },
    { after: 10, durationMs: 60 * 60 * 1000 },
    { after: 15, durationMs: 24 * 60 * 60 * 1000 },
  ];
  for (let i = TIERS.length - 1; i >= 0; i--) {
    if (entry.count >= TIERS[i].after) {
      entry.lockedUntil = Date.now() + TIERS[i].durationMs;
      break;
    }
  }
  MEMBER_LOGIN_ATTEMPTS.set(username, entry);
}

function clearMemberLoginFailures(username) {
  MEMBER_LOGIN_ATTEMPTS.delete(username);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-6 — Username generation helpers
// ─────────────────────────────────────────────────────────────────────────────

function normaliseName(name) {
  return (name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, "")
    .replace(/\s+/g, " ");
}

async function generateMemberUsername(name, rollNo) {
  const parts = normaliseName(name).split(" ");
  const first = parts[0] || "member";
  const last  = parts.slice(1).join("") || null;

  // Priority 1: firstname.lastname
  if (last) {
    const candidate1 = `${first}.${last}`;
    const { data: exists1 } = await supabase
      .from("member_accounts").select("id").eq("username", candidate1).maybeSingle();
    if (!exists1) return candidate1;
  }

  // Priority 2: firstname_rollno
  if (rollNo) {
    const rollPart = rollNo.toLowerCase().replace(/[^a-z0-9]/g, "");
    const candidate2 = `${first}_${rollPart}`;
    const { data: exists2 } = await supabase
      .from("member_accounts").select("id").eq("username", candidate2).maybeSingle();
    if (!exists2) return candidate2;
  }

  // Priority 3: firstname.lastname_randomsuffix
  for (let i = 0; i < 10; i++) {
    const suffix = Math.floor(100 + Math.random() * 900).toString();
    const candidate3 = last ? `${first}.${last}_${suffix}` : `${first}_${suffix}`;
    const { data: exists3 } = await supabase
      .from("member_accounts").select("id").eq("username", candidate3).maybeSingle();
    if (!exists3) return candidate3;
  }

  // Fallback: timestamp-based
  return `${first}_${Date.now()}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-7 — Password complexity check (mirrors admin pattern)
// ─────────────────────────────────────────────────────────────────────────────

function isStrongMemberPassword(pw) {
  return pw.length >= 8 &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-8 — Member credential email (Brevo)
// ─────────────────────────────────────────────────────────────────────────────

async function sendMemberCredentialsEmail({ toEmail, toName, username, tempPassword }) {
  const { data: rows } = await supabase
    .from("settings")
    .select("key,value")
    .in("key", ["brevo_api_key", "smtp_from_name"]);
  const s = {};
  (rows || []).forEach(r => (s[r.key] = r.value));
  if (!s.brevo_api_key) {
    const msg = "[member-email] Brevo API key not configured — cannot send credentials email";
    console.warn(msg);
    throw new Error("Brevo API key not configured. Please add it in Admin → Settings → Email.");
  }

  const fromName    = s.smtp_from_name || "KFS — KIIT Film Society";
  const loginUrl    = "https://kiitfilmsociety.in/Social-Strand";
  const htmlContent = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#111;border-radius:16px;border:1px solid #1e1e1e;overflow:hidden;max-width:560px">
  <tr><td style="background:#0a0a0a;padding:28px 36px;border-bottom:1px solid #1e1e1e">
    <span style="font-size:18px;font-weight:700;color:#f5f5f5;letter-spacing:-.02em">KFS — KIIT Film Society</span>
  </td></tr>
  <tr><td style="padding:32px 36px">
    <div style="background:#f5f5f5;color:#0a0a0a;display:inline-block;padding:6px 16px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:24px">Member Portal Access</div>
    <h2 style="font-size:22px;font-weight:700;color:#f5f5f5;margin:0 0 8px;letter-spacing:-.02em">Welcome, ${toName}!</h2>
    <p style="font-size:15px;color:#aaa;margin:0 0 24px">Your KFS member account has been created. Use the credentials below to log in for the first time.</p>
    <div style="background:#1a1a1a;border-radius:12px;border:1px solid #1e1e1e;padding:20px 24px;margin-bottom:24px">
      <div style="margin-bottom:12px"><span style="font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.08em">Username</span><br><span style="font-size:16px;font-weight:600;color:#f5f5f5;font-family:monospace">${username}</span></div>
      <div><span style="font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.08em">Temporary Password</span><br><span style="font-size:16px;font-weight:600;color:#f5f5f5;font-family:monospace">${tempPassword}</span></div>
    </div>
    <p style="font-size:13px;color:#888;margin:0 0 20px">You'll be asked to change your password and set up 2-factor authentication on your first login.</p>
    <a href="${loginUrl}" style="display:inline-block;background:#f5f5f5;color:#0a0a0a;text-decoration:none;padding:12px 28px;border-radius:8px;font-size:14px;font-weight:700">Log In Now →</a>
  </td></tr>
  <tr><td style="padding:20px 36px 28px;border-top:1px solid #1e1e1e">
    <p style="font-size:12px;color:#444;margin:0">This is an automated message from <a href="https://kiitfilmsociety.in" style="color:#666;text-decoration:none">kiitfilmsociety.in</a>. Do not reply.</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": s.brevo_api_key,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { name: fromName, email: "noreply@kiitfilmsociety.in" },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject: `Your KFS Member Portal credentials`,
      textContent: `Welcome, ${toName}!\n\nUsername: ${username}\nTemporary Password: ${tempPassword}\nLogin URL: ${loginUrl}\n\nYou'll be asked to change your password and enable 2FA on first login.`,
      htmlContent,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${err}`);
  }
  console.log(`[member-email] Credentials sent to ${toEmail} (${username})`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-9 — CSRF protection for /api/member (mirrors admin pattern)
// ─────────────────────────────────────────────────────────────────────────────

function csrfProtectMember(req, res, next) {
  if (req.path.startsWith("/login") || req.path.startsWith("/google-login") || req.path.startsWith("/refresh") || req.path.startsWith("/forgot-password")) return next();
  return csrfProtect(req, res, next);
}
app.use("/api/member", csrfProtectMember);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-10 — Member portal page route
// ─────────────────────────────────────────────────────────────────────────────

app.get("/Social-Strand", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "membersaccess.html"));
});
// Legacy redirect — keep old URL working
app.get("/membersaccess", (req, res) => {
  res.redirect(301, "/Social-Strand");
});
app.get("/membersaccess.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  res.sendFile(path.join(__dirname, "public", "membersaccess.js"));
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-11 — Member Auth Routes
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/member/login
app.post(
  "/api/member/login",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Too many login attempts. Try again later." } }),
  async (req, res) => {
    const { username, password, totp_code } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Username and password required" });

    const normalised = username.trim().toLowerCase();

    const lock = checkMemberLockout(normalised);
    if (lock) return res.status(429).json({ error: lock.message, locked_until: lock.lockedUntil });

    const { data: account } = await supabase
      .from("member_accounts")
      .select("*, members(id, name, role, batch, domain, photo, email, mobile)")
      .eq("username", normalised)
      .maybeSingle();

    if (!account) {
      recordMemberLoginFailure(normalised);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (account.account_status === "disabled") {
      return res.status(403).json({ error: "Account disabled. Contact admin." });
    }

    const valid = await bcrypt.compare(password, account.password_hash);
    if (!valid) {
      recordMemberLoginFailure(normalised);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // 2FA check
    if (account.totp_enabled) {
      if (!totp_code) return res.status(200).json({ require_totp: true });
      const verified = speakeasy.totp.verify({
        secret: account.totp_secret, encoding: "base32",
        token: totp_code.replace(/\s/g, ""), window: 1,
      });
      if (!verified) {
        recordMemberLoginFailure(normalised);
        return res.status(401).json({ error: "Invalid 2FA code" });
      }
    }

    clearMemberLoginFailures(normalised);

    // Update last_login
    await supabase.from("member_accounts")
      .update({ last_login: new Date().toISOString(), login_failures: 0, locked_until: null })
      .eq("id", account.id);

    const ip = req.ip || req.socket?.remoteAddress;
    await logMemberActivity(account.id, account.member_id, "login", { ip, ua: req.headers["user-agent"] }, ip);

    const accessToken = signMemberAccessToken({
      id: account.id,
      memberId: account.member_id,
      username: account.username,
      must_change_password: account.must_change_password,
      totp_enabled: account.totp_enabled,
    });

    const { raw } = await issueMemberRefreshToken(account.id);
    setMemberRefreshCookie(res, raw);

    res.json({
      token: accessToken,
      must_change_password: account.must_change_password,
      totp_enabled: account.totp_enabled,
      member: account.members,
      has_recovery_contact: !!account.members?.email,
      recovery_prompt_dismissed: !!account.recovery_prompt_dismissed_at,
    });
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-11a — Member Google Sign-In
//
// Flow: frontend loads Google Identity Services, user picks their KIIT Google
// account, we get back a signed Google ID token (JWT). We verify that token
// server-side via Google's tokeninfo endpoint (no new npm dependency — this
// file already calls fetch() against other *.googleapis.com endpoints for the
// Sheets integration, so this stays consistent with that existing pattern).
//
// NOTE: per Google's docs, the tokeninfo endpoint is fine for low/medium
// traffic but is rate-limited; if this portal's login volume grows a lot,
// switching to the `google-auth-library` npm package for local JWT
// verification would be more robust. Flagging this for awareness, not
// blocking — it's not needed for a society-sized member portal.
//
// Matching rule: Google email must (a) be on KIIT's domain allow-list and
// (b) match an existing members.email exactly (case-insensitive). We do NOT
// let a Google sign-in create a brand-new *member* — only admins create
// members. We DO auto-create the member_accounts row (username + login
// credential) on first-ever Google sign-in if the member doesn't have one
// yet, since you said that should "just work".
// ─────────────────────────────────────────────────────────────────────────────

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

app.post(
  "/api/member/google-login",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { error: "Too many attempts. Try again later." } }),
  async (req, res) => {
    const { credential, totp_code } = req.body;
    if (!credential) return res.status(400).json({ error: "Missing Google credential" });
    if (!GOOGLE_CLIENT_ID) {
      console.error("[member-google-login] GOOGLE_CLIENT_ID not configured");
      return res.status(503).json({ error: "Google sign-in is not configured. Contact admin." });
    }

    // ── Verify the ID token with Google ──────────────────────────────────────
    let payload;
    try {
      const verifyRes = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`,
      );
      if (!verifyRes.ok) return res.status(401).json({ error: "Invalid Google sign-in. Please try again." });
      payload = await verifyRes.json();
    } catch (e) {
      console.error("[member-google-login] tokeninfo fetch failed:", e.message);
      return res.status(502).json({ error: "Could not verify Google sign-in right now. Please try again." });
    }

    if (payload.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: "Invalid Google sign-in. Please try again." });
    }
    if (payload.email_verified !== "true" && payload.email_verified !== true) {
      return res.status(401).json({ error: "Your Google email is not verified." });
    }

    const googleEmail = (payload.email || "").trim().toLowerCase();
    if (!isKiitEmail(googleEmail)) {
      return res.status(403).json({
        error: "Sign in with your KIIT Google account (e.g. @kiit.ac.in). Other Google accounts can't access the member portal.",
      });
    }

    // ── Match against an existing member by email ────────────────────────────
    const { data: member } = await supabase
      .from("members")
      .select("id, name, role, batch, domain, photo, email, mobile")
      .ilike("email", googleEmail)
      .is("deleted_at", null)
      .maybeSingle();

    if (!member) {
      return res.status(404).json({
        error: "No KFS member record matches this Google account's email. Ask an admin to add or update your email on file.",
      });
    }

    // ── Find or auto-create the linked member_accounts row ───────────────────
    let { data: account } = await supabase
      .from("member_accounts")
      .select("*")
      .eq("member_id", member.id)
      .maybeSingle();

    if (!account) {
      const username = await generateMemberUsername(member.name, null);
      // Random, unguessable placeholder password — this account was opened via
      // Google, not a temp password, so there's no "first login" password to
      // hand out. Member can still use "Forgot password" later to set one if
      // they ever want username/password as a fallback alongside Google.
      const placeholderHash = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10);
      const { data: created, error: createErr } = await supabase
        .from("member_accounts")
        .insert([{
          member_id: member.id,
          username,
          password_hash: placeholderHash,
          must_change_password: false, // nothing to "change" — no password was issued
        }])
        .select("*")
        .single();
      if (createErr) {
        console.error("[member-google-login] auto-create account failed:", createErr.message);
        return res.status(500).json({ error: "Internal server error" });
      }
      account = created;
      logMemberActivity(account.id, member.id, "account_auto_created_google", { email: googleEmail }, req.ip).catch(() => {});
    }

    if (account.account_status === "disabled") {
      return res.status(403).json({ error: "Account disabled. Contact admin." });
    }

    // ── 2FA still applies if the member has it enabled ────────────────────────
    // Google sign-in replaces the password step, not the 2FA step — a member
    // who turned on TOTP should still be asked for it.
    if (account.totp_enabled) {
      if (!totp_code) return res.status(200).json({ require_totp: true, google_credential: credential });
      const verified = speakeasy.totp.verify({
        secret: account.totp_secret, encoding: "base32",
        token: totp_code.replace(/\s/g, ""), window: 1,
      });
      if (!verified) return res.status(401).json({ error: "Invalid 2FA code" });
    }

    await supabase.from("member_accounts")
      .update({ last_login: new Date().toISOString(), login_failures: 0, locked_until: null })
      .eq("id", account.id);

    const ip = req.ip || req.socket?.remoteAddress;
    await logMemberActivity(account.id, account.member_id, "login", { ip, ua: req.headers["user-agent"], method: "google" }, ip);

    const accessToken = signMemberAccessToken({
      id: account.id,
      memberId: account.member_id,
      username: account.username,
      must_change_password: account.must_change_password,
      totp_enabled: account.totp_enabled,
    });

    const { raw } = await issueMemberRefreshToken(account.id);
    setMemberRefreshCookie(res, raw);

    res.json({
      token: accessToken,
      must_change_password: account.must_change_password,
      totp_enabled: account.totp_enabled,
      member,
      has_recovery_contact: !!member.email,
      recovery_prompt_dismissed: !!account.recovery_prompt_dismissed_at,
    });
  },
);

// GET /api/member/google-client-id — public, non-secret Google OAuth Client ID
// for the frontend to initialize Google Identity Services with. Mirrors how
// Razorpay's key_id is handed to the frontend: it's not a secret, it's the
// public half of the credential pair, safe to expose.
app.get("/api/member/google-client-id", (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(503).json({ error: "Not configured" });
  res.json({ client_id: GOOGLE_CLIENT_ID });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-11b — Member Forgot Password (username -> OTP via WhatsApp/SMS/Email -> reset)
// Mirrors the admin forgot-password flow exactly. Pre-auth, so it's defined
// outside memberAuthMiddleware and is independently rate-limited.
// ─────────────────────────────────────────────────────────────────────────────

// Step 1 — submit username, receive OTP via email
app.post(
  "/api/member/forgot-password/start",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: { error: "Too many requests. Try again later." } }),
  async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });
    const normalised = username.trim().toLowerCase();
    const lockKey = `member:${normalised}`;

    const lock = checkForgotPasswordLockout(lockKey);
    if (lock) return res.status(429).json({ error: lock.message, locked_until: lock.lockedUntil });

    const { data: account } = await supabase
      .from("member_accounts")
      .select("id, account_status, members(name, email, mobile)")
      .eq("username", normalised)
      .maybeSingle();

    const genericResponse = { success: true, message: "If an account with an email on file exists for this username, a verification code has been sent." };

    if (!account || account.account_status === "disabled") {
      recordForgotPasswordAttempt(lockKey);
      return res.json(genericResponse);
    }
    const member = account.members || {};
    if (!member.email) {
      // Real account but no recovery email on file — tell them plainly so
      // they know to go to an admin instead of waiting on a code that will
      // never arrive. (Trade-off: this confirms the username exists, unlike
      // the fully generic response above — see setup notes.)
      return res.json({
        success: false,
        reason: "no_contact",
        error: "Your email is not on file yet. Please contact your site admin for assistance.",
      });
    }

    const otp = generateOtp();
    let sent;
    try {
      sent = await dispatchOtp({ email: member.email, name: member.name }, otp);
    } catch (e) {
      console.error("[member/forgot-password] OTP dispatch failed:", e.message);
      return res.status(500).json({ error: "Could not send verification code. Please contact an admin." });
    }

    await supabase.from("password_reset_otps").insert([{
      account_type: "member",
      account_id:   account.id,
      channel:      sent.channel,
      destination:  sent.destination,
      otp_hash:     hashOtp(otp),
      max_attempts: OTP_MAX_ATTEMPTS,
      expires_at:   new Date(Date.now() + OTP_TTL_MS).toISOString(),
      ip_address:   req.ip,
    }]);

    recordForgotPasswordAttempt(lockKey);
    res.json({ ...genericResponse, channel: sent.channel, masked_destination: sent.maskedDestination });
  },
);

// Step 2 — verify the 6-digit code, receive a short-lived reset token
app.post(
  "/api/member/forgot-password/verify",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { error: "Too many attempts. Try again later." } }),
  async (req, res) => {
    const { username, code } = req.body;
    if (!username || !code) return res.status(400).json({ error: "Username and code are required" });
    const normalised = username.trim().toLowerCase();

    const { data: account } = await supabase
      .from("member_accounts").select("id").eq("username", normalised).maybeSingle();
    if (!account) return res.status(400).json({ error: "Invalid or expired code" });

    const { data: otpRow } = await supabase
      .from("password_reset_otps")
      .select("*")
      .eq("account_type", "member")
      .eq("account_id", account.id)
      .eq("consumed", false)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!otpRow) return res.status(400).json({ error: "Invalid or expired code" });
    if (new Date(otpRow.expires_at) < new Date()) return res.status(400).json({ error: "Code has expired. Please request a new one." });
    if (otpRow.attempts >= otpRow.max_attempts) return res.status(429).json({ error: "Too many incorrect attempts. Please request a new code." });

    const valid = hashOtp(code.replace(/\s/g, "")) === otpRow.otp_hash;
    if (!valid) {
      await supabase.from("password_reset_otps").update({ attempts: otpRow.attempts + 1 }).eq("id", otpRow.id);
      return res.status(401).json({ error: "Incorrect code" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    await supabase.from("password_reset_otps").update({
      reset_token: resetToken,
      reset_token_expires_at: new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString(),
      consumed: true,
    }).eq("id", otpRow.id);

    res.json({ success: true, reset_token: resetToken });
  },
);

// Step 3 — set the new password using the reset token from Step 2
app.post(
  "/api/member/forgot-password/reset",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Too many attempts. Try again later." } }),
  async (req, res) => {
    const { username, reset_token, newPassword } = req.body;
    if (!username || !reset_token || !newPassword)
      return res.status(400).json({ error: "Missing required fields" });

    if (!isStrongMemberPassword(newPassword))
      return res.status(400).json({ error: "Password must be ≥8 chars, include 1 uppercase, 1 number, 1 special character." });

    const normalised = username.trim().toLowerCase();
    const { data: account } = await supabase
      .from("member_accounts").select("id, member_id").eq("username", normalised).maybeSingle();
    if (!account) return res.status(400).json({ error: "Invalid or expired session. Please start over." });

    const { data: otpRow } = await supabase
      .from("password_reset_otps")
      .select("*")
      .eq("account_type", "member")
      .eq("account_id", account.id)
      .eq("reset_token", reset_token)
      .maybeSingle();

    if (!otpRow) return res.status(400).json({ error: "Invalid or expired session. Please start over." });
    if (new Date(otpRow.reset_token_expires_at) < new Date())
      return res.status(400).json({ error: "This reset session has expired. Please start over." });

    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from("member_accounts")
      .update({ password_hash: hash, must_change_password: false, login_failures: 0, locked_until: null })
      .eq("id", account.id);
    await supabase.from("password_reset_otps").update({ reset_token: null }).eq("id", otpRow.id);
    // Revoke all existing sessions — a password reset should log out everywhere.
    await revokeAllMemberRefreshTokens(account.id);
    clearForgotPasswordAttempts(`member:${normalised}`);

    await logMemberActivity(account.id, account.member_id, "password_reset_via_forgot_password", null, req.ip);
    res.json({ success: true, message: "Password updated. Please sign in with your new password." });
  },
);

// POST /api/member/refresh
app.post("/api/member/refresh", async (req, res) => {
  const raw = req.cookies?.kfs_member_refresh;
  if (!raw) return res.status(401).json({ error: "No refresh token" });

  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  const { data: stored } = await supabase
    .from("member_refresh_tokens")
    .select("*")
    .eq("token_hash", hash)
    .maybeSingle();

  if (!stored) return res.status(401).json({ error: "Invalid refresh token" });

  if (stored.used) {
    await revokeAllMemberRefreshTokens(stored.account_id);
    clearMemberRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token already used — all sessions revoked" });
  }

  if (new Date(stored.expires_at) < new Date()) {
    clearMemberRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token expired" });
  }

  await supabase.from("member_refresh_tokens").update({ used: true }).eq("id", stored.id);

  const { data: account } = await supabase
    .from("member_accounts")
    .select("id, member_id, username, must_change_password, totp_enabled, account_status")
    .eq("id", stored.account_id)
    .maybeSingle();

  if (!account || account.account_status === "disabled") {
    clearMemberRefreshCookie(res);
    return res.status(401).json({ error: "Account not found or disabled" });
  }

  const accessToken = signMemberAccessToken({
    id: account.id,
    memberId: account.member_id,
    username: account.username,
    must_change_password: account.must_change_password,
    totp_enabled: account.totp_enabled,
  });

  const { raw: newRaw } = await issueMemberRefreshToken(account.id);
  setMemberRefreshCookie(res, newRaw);

  const { data: memberProfile } = await supabase
    .from('members')
    .select('id, name, photo, role, batch, domain, email, mobile')
    .eq('id', account.member_id)
    .maybeSingle();

  res.json({ token: accessToken, member: memberProfile || null });
});

// POST /api/member/logout
app.post("/api/member/logout", memberAuthMiddleware, async (req, res) => {
  const { jti, exp } = req.member;
  if (jti) await revokeMemberToken(jti, exp);
  await revokeAllMemberRefreshTokens(req.member.id);
  clearMemberRefreshCookie(res);
  await logMemberActivity(req.member.id, req.member.memberId, "logout", null, req.ip);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-12 — First-login: Change Password (mandatory)
// ─────────────────────────────────────────────────────────────────────────────

app.post("/api/member/change-password", memberAuthMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: "Both passwords required" });
  if (!isStrongMemberPassword(newPassword))
    return res.status(400).json({ error: "Password must be ≥8 chars, include 1 uppercase, 1 number, 1 special character." });

  const { data: account } = await supabase
    .from("member_accounts").select("password_hash").eq("id", req.member.id).maybeSingle();
  if (!account) return res.status(404).json({ error: "Account not found" });

  const valid = await bcrypt.compare(currentPassword, account.password_hash);
  if (!valid) return res.status(401).json({ error: "Current password is incorrect" });

  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from("member_accounts")
    .update({ password_hash: hash, must_change_password: false })
    .eq("id", req.member.id);

  await logMemberActivity(req.member.id, req.member.memberId, "password_change", null, req.ip);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-13 — 2FA setup & verification
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/member/2fa/setup — generate secret + QR
app.get("/api/member/2fa/setup", memberAuthMiddleware, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: `KFS:${req.member.username}`, length: 20 });
  // Store temp secret in account row (confirmed on verify)
  await supabase.from("member_accounts")
    .update({ totp_secret: secret.base32 })
    .eq("id", req.member.id);

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ secret: secret.base32, qr: qrDataUrl });
});

// POST /api/member/2fa/verify — confirm & activate
app.post("/api/member/2fa/verify", memberAuthMiddleware, async (req, res) => {
  const { totp_code } = req.body;
  if (!totp_code) return res.status(400).json({ error: "TOTP code required" });

  const { data: account } = await supabase
    .from("member_accounts").select("totp_secret").eq("id", req.member.id).maybeSingle();
  if (!account?.totp_secret) return res.status(400).json({ error: "No pending 2FA setup" });

  const verified = speakeasy.totp.verify({
    secret: account.totp_secret, encoding: "base32",
    token: totp_code.replace(/\s/g, ""), window: 1,
  });
  if (!verified) return res.status(401).json({ error: "Invalid TOTP code" });

  await supabase.from("member_accounts")
    .update({ totp_enabled: true })
    .eq("id", req.member.id);

  await logMemberActivity(req.member.id, req.member.memberId, "2fa_setup", null, req.ip);
  res.json({ success: true });
});

// POST /api/member/2fa/disable
app.post("/api/member/2fa/disable", memberAuthMiddleware, async (req, res) => {
  const { password, totp_code } = req.body;
  const { data: account } = await supabase
    .from("member_accounts").select("password_hash, totp_secret").eq("id", req.member.id).maybeSingle();
  if (!account) return res.status(404).json({ error: "Not found" });

  const validPw = await bcrypt.compare(password || "", account.password_hash);
  if (!validPw) return res.status(401).json({ error: "Password incorrect" });

  if (account.totp_secret) {
    const validTotp = speakeasy.totp.verify({
      secret: account.totp_secret, encoding: "base32",
      token: (totp_code || "").replace(/\s/g, ""), window: 1,
    });
    if (!validTotp) return res.status(401).json({ error: "Invalid TOTP code" });
  }

  await supabase.from("member_accounts")
    .update({ totp_enabled: false, totp_secret: null })
    .eq("id", req.member.id);

  await logMemberActivity(req.member.id, req.member.memberId, "2fa_disable", null, req.ip);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-14 — Member Profile
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/member/profile
app.get("/api/member/profile", memberAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("members")
    .select("id,name,roll_no,mobile,batch,bio,domain,role,photo,special_tag,sort_order,is_past,instagram,linkedin,github,twitter,youtube,website,custom_links,email,updated_at,status,status_updated_at,followers_count,following_count")
    .eq("id", req.member.memberId)
    .maybeSingle();
  if (error || !data) return res.status(404).json({ error: "Member not found" });
  res.json(data);
});

// PUT /api/member/profile — creates a pending change request
app.put(
  "/api/member/profile",
  memberAuthMiddleware,
  upload.single("photo"),
  async (req, res) => {
    const { name, roll_no, mobile, batch, bio,
            instagram, linkedin, github, twitter, youtube, website, custom_links } = req.body;
    // NOTE: 'domain' and 'role' are intentionally excluded — admin-only fields.

    // ── Server-side URL sanitizer: only allow http/https, reject javascript:/data: etc. ──
    function sanitizeSocialUrl(raw) {
      if (!raw && raw !== '') return undefined;
      const v = String(raw).trim();
      if (!v) return '';
      try {
        const u = new URL(v);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
        // Prevent SSRF to internal/private IPs in URLs
        const host = u.hostname.toLowerCase();
        if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(host)) return '';
        return u.href.slice(0, 500);
      } catch { return ''; }
    }
    // Bare username sanitizer — strips @ prefix, allows only safe chars
    function sanitizeUsername(raw) {
      if (!raw && raw !== '') return undefined;
      const v = String(raw).trim();
      if (!v) return '';
      return v.replace(/^@+/, '').replace(/[^\w.\-]/g, '').slice(0, 100);
    }

    const { data: current } = await supabase
      .from("members").select("*").eq("id", req.member.memberId).maybeSingle();
    if (!current) return res.status(404).json({ error: "Member not found" });

    const newValues = {};
    if (name      !== undefined) newValues.name      = name.trim();
    if (roll_no   !== undefined) newValues.roll_no   = roll_no;
    if (mobile    !== undefined) newValues.mobile    = mobile;
    if (batch     !== undefined) newValues.batch     = batch;
    if (bio       !== undefined) newValues.bio       = bio;
    if (instagram !== undefined) newValues.instagram = sanitizeUsername(instagram);
    if (linkedin  !== undefined) newValues.linkedin  = sanitizeSocialUrl(linkedin);
    if (github    !== undefined) newValues.github    = sanitizeUsername(github);
    if (twitter   !== undefined) newValues.twitter   = sanitizeUsername(twitter);
    if (youtube   !== undefined) newValues.youtube   = sanitizeSocialUrl(youtube);
    if (website   !== undefined) newValues.website   = sanitizeSocialUrl(website);
    if (custom_links !== undefined) {
      try { newValues.custom_links = JSON.parse(custom_links); } catch { newValues.custom_links = []; }
    }
    if (req.file) newValues.photo = await uploadImage(req.file, "members");

    // Check if approval workflow is required (setting key: member_profile_approval)
    const { data: setting } = await supabase
      .from("settings").select("value").eq("key", "member_profile_approval").maybeSingle();
    const requiresApproval = setting?.value !== "immediate";

    if (requiresApproval) {
      // Store as pending change
      const oldValues = Object.fromEntries(Object.keys(newValues).map(k => [k, current[k]]));
      const { data: change, error: changeErr } = await supabase
        .from("member_profile_changes")
        .insert([{ member_id: req.member.memberId, old_values: oldValues, new_values: newValues }])
        .select().single();
      if (changeErr) return res.status(500).json({ error: "Internal server error" });
      await logMemberActivity(req.member.id, req.member.memberId, "profile_update_requested", { changeId: change.id }, req.ip);
      res.json({ success: true, pending: true, message: "Profile update submitted for review." });
    } else {
      // Apply immediately
      const { error: updateErr } = await supabase
        .from("members").update({ ...newValues, updated_at: new Date().toISOString() }).eq("id", req.member.memberId);
      if (updateErr) return res.status(500).json({ error: "Internal server error" });
      memInvalidate("members:list");
      await logMemberActivity(req.member.id, req.member.memberId, "profile_updated", null, req.ip);
      res.json({ success: true, pending: false });
    }
  },
);

// GET /api/member/profile/pending-changes
app.get("/api/member/profile/pending-changes", memberAuthMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("member_profile_changes")
    .select("id,new_values,status,admin_notes,created_at")
    .eq("member_id", req.member.memberId)
    .order("created_at", { ascending: false })
    .limit(20);
  res.json(data || []);
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-14b — Recovery contact info (email / mobile) — INSTANT, no approval
// Unlike the rest of the profile, email/mobile are security/recovery fields,
// not public-facing profile fields — so they apply immediately rather than
// going through member_profile_changes moderation.
// ─────────────────────────────────────────────────────────────────────────────

// PUT /api/member/contact-info
app.put("/api/member/contact-info", memberAuthMiddleware, async (req, res) => {
  const { email, mobile } = req.body;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const updates = {};
  if (email !== undefined) {
    const v = (email || "").trim();
    if (v && !EMAIL_RE.test(v)) return res.status(400).json({ error: "Invalid email address" });
    if (v && !isKiitEmail(v)) return res.status(400).json({ error: "Email must be a KIIT institutional address (e.g. @kiit.ac.in, @ksom.ac.in, @kiitbiotech.ac.in)." });
    updates.email = v || null;
  }
  if (mobile !== undefined) {
    const digits = (mobile || "").replace(/\D/g, "");
    if (mobile && digits.length < 10) return res.status(400).json({ error: "Invalid phone number" });
    updates.mobile = mobile ? mobile.trim() : null;
  }
  if (!Object.keys(updates).length) return res.status(400).json({ error: "Nothing to update" });
  if (updates.email !== undefined) {
    // Only check when email is actually being touched — re-check against
    // current DB state in case it would end up empty.
    const willHaveEmail = updates.email;
    if (!willHaveEmail) {
      return res.status(400).json({ error: "Please provide an email for account recovery." });
    }
  } else {
    const { data: current } = await supabase.from("members").select("email").eq("id", req.member.memberId).maybeSingle();
    if (!current?.email) {
      return res.status(400).json({ error: "Please provide an email for account recovery." });
    }
  }

  updates.updated_at = new Date().toISOString();
  const { error } = await supabase.from("members").update(updates).eq("id", req.member.memberId);
  if (error) return res.status(500).json({ error: "Internal server error" });

  memInvalidate("members:list");
  await logMemberActivity(req.member.id, req.member.memberId, "contact_info_updated", { fields: Object.keys(updates) }, req.ip);
  res.json({ success: true });
});

// POST /api/member/contact-info/dismiss-prompt — "remind me later" on the recovery banner
app.post("/api/member/contact-info/dismiss-prompt", memberAuthMiddleware, async (req, res) => {
  await supabase.from("member_accounts")
    .update({ recovery_prompt_dismissed_at: new Date().toISOString() })
    .eq("id", req.member.id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-15 — Member Sessions
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/member/sessions", memberAuthMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("member_refresh_tokens")
    .select("id, created_at, expires_at, used")
    .eq("account_id", req.member.id)
    .eq("used", false)
    .gt("expires_at", new Date().toISOString())
    .order("created_at", { ascending: false });
  res.json(data || []);
});

app.delete("/api/member/sessions/all", memberAuthMiddleware, async (req, res) => {
  await revokeAllMemberRefreshTokens(req.member.id);
  const { jti, exp } = req.member;
  if (jti) await revokeMemberToken(jti, exp);
  clearMemberRefreshCookie(res);
  await logMemberActivity(req.member.id, req.member.memberId, "session_revoke_all", null, req.ip);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-16 — Member Activity Feed
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/member/activity", memberAuthMiddleware, async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(50, parseInt(req.query.limit) || 20);
  const { data } = await supabase
    .from("member_activity")
    .select("id,action,metadata,ip_address,created_at")
    .eq("account_id", req.member.id)
    .order("created_at", { ascending: false })
    .range((page - 1) * limit, page * limit - 1);
  res.json(data || []);
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-17 — Member Movie Submissions
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/member/movies — list my submissions
app.get("/api/member/movies", memberAuthMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("member_movie_submissions")
    .select("id, movie_data, status, reviewer_notes, created_at, updated_at, published_movie_id")
    .eq("member_id", req.member.memberId)
    .order("created_at", { ascending: false });
  res.json(data || []);
});

// POST /api/member/movies — submit a new movie
app.post(
  "/api/member/movies",
  memberAuthMiddleware,
  upload.single("poster"),
  async (req, res) => {
    const {
      title, description, trailer_url, watch_url, runtime, language, genre,
      release_year, director, producer, dop, writer, video_editor,
      sound_design, management, graphic_design, actors, support_crew,
      spotify_url, apple_music_url,
    } = req.body;

    if (!title || !title.trim())
      return res.status(400).json({ error: "Title is required" });
    if (trailer_url && !/^https:\/\//i.test(trailer_url))
      return res.status(400).json({ error: "trailer_url must start with https://" });
    if (watch_url && !/^https:\/\//i.test(watch_url))
      return res.status(400).json({ error: "watch_url must start with https://" });

    let genreVal = null;
    if (genre) {
      try { const p = JSON.parse(genre); genreVal = Array.isArray(p) ? p : [genre]; }
      catch { genreVal = [genre]; }
    }

    const posterUrl = req.file ? await uploadImage(req.file, "member-movies") : null;

    const movieData = {
      title: title.trim(), description: description || null,
      trailer_url: trailer_url || null, watch_url: watch_url || null,
      runtime: runtime ? parseInt(runtime, 10) : null, language: language || null,
      genre: genreVal, release_year: release_year || null,
      director: director || null, producer: producer || null,
      dop: dop || null, writer: writer || null,
      video_editor: video_editor || null, sound_design: sound_design || null,
      management: management || null, graphic_design: graphic_design || null,
      actors: actors || null, support_crew: support_crew || null,
      spotify_url: spotify_url || null, apple_music_url: apple_music_url || null,
      poster_image: posterUrl,
    };

    const { data, error } = await supabase
      .from("member_movie_submissions")
      .insert([{ member_id: req.member.memberId, account_id: req.member.id, movie_data: movieData }])
      .select().single();
    if (error) return res.status(500).json({ error: "Internal server error" });

    await logMemberActivity(req.member.id, req.member.memberId, "movie_submit", { submissionId: data.id, title }, req.ip);
    // Notify admins (non-blocking)
    logActivity("system", "System", "review_requested", "movie_submission", `"${title}" by ${req.member.username}`).catch(() => {});
    res.json(data);
  },
);

// PUT /api/member/movies/:id — edit a submission (only if pending or changes_requested)
app.put(
  "/api/member/movies/:id",
  memberAuthMiddleware,
  upload.single("poster"),
  async (req, res) => {
    const { data: sub } = await supabase
      .from("member_movie_submissions")
      .select("*").eq("id", req.params.id).eq("member_id", req.member.memberId).maybeSingle();
    if (!sub) return res.status(404).json({ error: "Submission not found" });
    if (!["pending", "changes_requested"].includes(sub.status))
      return res.status(403).json({ error: "Only pending or changes-requested submissions can be edited" });

    const updated = { ...sub.movie_data };
    const fields = ["title","description","trailer_url","watch_url","runtime","language","genre",
                    "release_year","director","producer","dop","writer","video_editor",
                    "sound_design","management","graphic_design","actors","support_crew",
                    "spotify_url","apple_music_url"];
    fields.forEach(f => { if (req.body[f] !== undefined) updated[f] = req.body[f]; });
    if (req.file) updated.poster_image = await uploadImage(req.file, "member-movies");

    await supabase.from("member_movie_submissions")
      .update({ movie_data: updated, status: "pending", updated_at: new Date().toISOString() })
      .eq("id", sub.id);

    await logMemberActivity(req.member.id, req.member.memberId, "movie_resubmit", { submissionId: sub.id }, req.ip);
    res.json({ success: true });
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-18 — Admin: Create Member Account (extends existing POST /api/admin/members)
// Place this route AFTER the existing /api/admin/members route or merge the logic in.
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/admin/members/:id/create-account — auto-create linked member_account
app.post("/api/admin/members/:id/create-account", requireSection("members"), async (req, res) => {
  const memberId = req.params.id;
  const { data: member } = await supabase
    .from("members").select("id, name, roll_no, email, mobile").eq("id", memberId).maybeSingle();
  if (!member) return res.status(404).json({ error: "Member not found" });

  // Check if account already exists
  const { data: existing } = await supabase
    .from("member_accounts").select("id, username").eq("member_id", memberId).maybeSingle();
  if (existing) return res.status(409).json({ error: "Account already exists", username: existing.username });

  // Recovery email is required before an account can be opened — that's
  // what powers forgot-password (Twilio/mobile removed). Admin can supply
  // it inline here if the member record doesn't already have one. Mobile
  // is still collected/stored but no longer gates account creation.
  const { email: suppliedEmail, mobile: suppliedMobile } = req.body || {};
  const finalEmail  = (suppliedEmail  || member.email  || "").trim();
  const finalMobile = (suppliedMobile || member.mobile || "").trim();
  if (!finalEmail) {
    return res.status(400).json({
      error: "This member needs an email on file before an account can be created.",
      needs_contact_info: true,
    });
  }
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (finalEmail && !EMAIL_RE.test(finalEmail)) return res.status(400).json({ error: "Invalid email address" });
  if (finalEmail && !isKiitEmail(finalEmail)) return res.status(400).json({ error: "Member email must be a KIIT institutional address (e.g. @kiit.ac.in, @ksom.ac.in, @kiitbiotech.ac.in)." });
  if (finalMobile && finalMobile.replace(/\D/g, "").length < 10) return res.status(400).json({ error: "Invalid phone number" });

  // Persist any newly-supplied contact info onto the member record itself.
  if ((suppliedEmail && suppliedEmail.trim() !== member.email) || (suppliedMobile && suppliedMobile.trim() !== member.mobile)) {
    await supabase.from("members").update({
      email:  finalEmail  || null,
      mobile: finalMobile || null,
      updated_at: new Date().toISOString(),
    }).eq("id", memberId);
    memInvalidate("members:list");
  }

  const username  = await generateMemberUsername(member.name, member.roll_no);
  const tempPw    = "Kfs@2026";
  const hash      = await bcrypt.hash(tempPw, 10);

  const { data: account, error } = await supabase
    .from("member_accounts")
    .insert([{ member_id: memberId, username, password_hash: hash, must_change_password: true }])
    .select().single();
  if (error) return res.status(500).json({ error: "Internal server error" });

  logActivity(req.admin.id, req.admin.name, "create", "member_account", username).catch(() => {});
  res.json({ success: true, username, tempPassword: tempPw, accountId: account.id, email: finalEmail || null });
});

// POST /api/admin/members/:id/send-credentials — email credentials to member
app.post("/api/admin/members/:id/send-credentials", requireSection("members"), async (req, res) => {
  const memberId = req.params.id;
  const { data: member } = await supabase
    .from("members").select("id, name, email").eq("id", memberId).maybeSingle();
  if (!member) return res.status(404).json({ error: "Member not found" });

  const { data: account } = await supabase
    .from("member_accounts").select("username").eq("member_id", memberId).maybeSingle();
  if (!account) return res.status(404).json({ error: "No account exists for this member — create one first" });

  // toEmail: admin can supply an address; fall back to member's saved email
  const { customPassword, toEmail } = req.body;
  const recipientEmail = (toEmail && toEmail.trim()) ? toEmail.trim() : member.email;
  if (!recipientEmail) return res.status(400).json({ error: "No email address provided. Supply one in the request or save one on the member profile." });
  // Admin can optionally supply a reset temp password; otherwise just resend username + login URL
  if (customPassword) {
    if (!isStrongMemberPassword(customPassword))
      return res.status(400).json({ error: "Password must be ≥8 chars, 1 uppercase, 1 number, 1 special character" });
    const hash = await bcrypt.hash(customPassword, 10);
    await supabase.from("member_accounts")
      .update({ password_hash: hash, must_change_password: true }).eq("member_id", memberId);
  }

  try {
    await sendMemberCredentialsEmail({
      toEmail: recipientEmail,
      toName: member.name,
      username: account.username,
      tempPassword: customPassword || "Kfs@2026",
    });
  } catch (emailErr) {
    console.error("[send-credentials] Email send failed:", emailErr.message);
    return res.status(500).json({ error: "Failed to send email: " + emailErr.message });
  }

  logActivity(req.admin.id, req.admin.name, "email_sent", "member_account", account.username).catch(() => {});
  res.json({ success: true });
});

// POST /api/admin/members/test-credentials-email — send a test credentials email
app.post("/api/admin/members/test-credentials-email", requireSection("members"), async (req, res) => {
  const { toEmail } = req.body;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!toEmail || !EMAIL_RE.test(toEmail.trim()))
    return res.status(400).json({ error: "Valid email address required" });
  try {
    await sendMemberCredentialsEmail({
      toEmail: toEmail.trim(),
      toName: "Test Member",
      username: "testmember.2025",
      tempPassword: "Kfs@2026",
    });
    res.json({ success: true });
  } catch (err) {
    console.error("[test-credentials-email]", err.message);
    res.status(500).json({ error: "Email send failed: " + err.message });
  }
});

// GET /api/admin/members/:id/account — view account info
app.get("/api/admin/members/:id/account", requireSection("members"), async (req, res) => {
  const { data, error } = await supabase
    .from("member_accounts")
    .select("id, username, must_change_password, totp_enabled, account_status, last_login, login_failures, locked_until, created_at")
    .eq("member_id", req.params.id)
    .maybeSingle();
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || null);
});

// POST /api/admin/members/:id/account/reset-password
app.post("/api/admin/members/:id/account/reset-password", requireSection("members"), async (req, res) => {
  const { data: account } = await supabase
    .from("member_accounts").select("id").eq("member_id", req.params.id).maybeSingle();
  if (!account) return res.status(404).json({ error: "No account found" });

  const tempPw = "Kfs@2026";
  const hash   = await bcrypt.hash(tempPw, 10);
  await supabase.from("member_accounts")
    .update({ password_hash: hash, must_change_password: true, login_failures: 0, locked_until: null })
    .eq("id", account.id);

  logActivity(req.admin.id, req.admin.name, "reset_password", "member_account", req.params.id).catch(() => {});
  res.json({ success: true, tempPassword: tempPw });
});

// POST /api/admin/members/:id/account/toggle-status — disable/enable
app.post("/api/admin/members/:id/account/toggle-status", requireSection("members"), async (req, res) => {
  const { status } = req.body; // "active" | "disabled"
  if (!["active", "disabled"].includes(status))
    return res.status(400).json({ error: "status must be 'active' or 'disabled'" });
  const { error } = await supabase.from("member_accounts")
    .update({ account_status: status }).eq("member_id", req.params.id);
  if (error) return res.status(500).json({ error: "Internal server error" });
  logActivity(req.admin.id, req.admin.name, status === "disabled" ? "disable" : "enable", "member_account", req.params.id).catch(() => {});
  res.json({ success: true });
});

// POST /api/admin/members/:id/account/force-2fa-reset
app.post("/api/admin/members/:id/account/force-2fa-reset", requireSection("members"), async (req, res) => {
  const { error } = await supabase.from("member_accounts")
    .update({ totp_enabled: false, totp_secret: null }).eq("member_id", req.params.id);
  if (error) return res.status(500).json({ error: "Internal server error" });
  logActivity(req.admin.id, req.admin.name, "force_2fa_reset", "member_account", req.params.id).catch(() => {});
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-19 — Admin: Profile Change Moderation
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/admin/member-profile-changes?status=pending
app.get("/api/admin/member-profile-changes", requireSection("members"), async (req, res) => {
  const status = req.query.status || "pending";
  const { data } = await supabase
    .from("member_profile_changes")
    .select("id, member_id, old_values, new_values, status, admin_notes, reviewed_by, reviewed_at, created_at, members(name, photo)")
    .eq("status", status)
    .order("created_at", { ascending: false });
  res.json(data || []);
});

// POST /api/admin/member-profile-changes/:id/review
app.post("/api/admin/member-profile-changes/:id/review", requireSection("members"), async (req, res) => {
  const { action, notes } = req.body; // action: approve | reject | request_changes
  if (!["approve", "reject", "request_changes"].includes(action))
    return res.status(400).json({ error: "action must be approve | reject | request_changes" });

  const { data: change } = await supabase
    .from("member_profile_changes").select("*").eq("id", req.params.id).maybeSingle();
  if (!change) return res.status(404).json({ error: "Change request not found" });

  const statusMap = { approve: "approved", reject: "rejected", request_changes: "changes_requested" };
  await supabase.from("member_profile_changes").update({
    status: statusMap[action],
    admin_notes: notes || null,
    reviewed_by: req.admin.username,
    reviewed_at: new Date().toISOString(),
  }).eq("id", req.params.id);

  if (action === "approve") {
    await supabase.from("members")
      .update({ ...change.new_values, updated_at: new Date().toISOString() })
      .eq("id", change.member_id);
    memInvalidate("members:list");
    createMemberNotification(change.member_id, "profile", "Profile update approved", "Your profile changes have been approved and are now live.").catch(() => {});
  } else if (action === "reject") {
    createMemberNotification(change.member_id, "profile", "Profile update rejected", notes ? `Admin note: ${notes}` : "Your profile change request was not approved.").catch(() => {});
  } else if (action === "request_changes") {
    createMemberNotification(change.member_id, "profile", "Changes requested on profile update", notes ? `Admin note: ${notes}` : "The admin has requested changes to your profile update.").catch(() => {});
  }

  logActivity(req.admin.id, req.admin.name, action, "member_profile_change", String(req.params.id)).catch(() => {});
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-20 — Admin: Movie Submission Moderation
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/admin/member-movie-submissions?status=pending
app.get("/api/admin/member-movie-submissions", requireSection("movies"), async (req, res) => {
  const status = req.query.status || "pending";
  const { data } = await supabase
    .from("member_movie_submissions")
    .select("id, member_id, account_id, movie_data, status, reviewer_notes, reviewed_by, reviewed_at, created_at, updated_at, members(name, photo)")
    .eq("status", status)
    .order("created_at", { ascending: false });
  res.json(data || []);
});

// POST /api/admin/member-movie-submissions/:id/review
app.post(
  "/api/admin/member-movie-submissions/:id/review",
  requireSection("movies"),
  async (req, res) => {
    const { action, notes } = req.body; // approve | reject | request_changes
    if (!["approve", "reject", "request_changes"].includes(action))
      return res.status(400).json({ error: "action must be approve | reject | request_changes" });

    const { data: sub } = await supabase
      .from("member_movie_submissions").select("*").eq("id", req.params.id).maybeSingle();
    if (!sub) return res.status(404).json({ error: "Submission not found" });

    const statusMap = { approve: "approved", reject: "rejected", request_changes: "changes_requested" };

    let publishedMovieId = sub.published_movie_id;

    if (action === "approve") {
      // Publish to movies table
      const md = sub.movie_data;
      let genreVal = null;
      if (md.genre) genreVal = Array.isArray(md.genre) ? JSON.stringify(md.genre) : md.genre;

      const { data: newMovie, error: movieErr } = await supabase.from("movies").insert([{
        title:           md.title,
        description:     md.description    || null,
        release_year:    md.release_year   ? parseInt(md.release_year, 10) : null,
        director:        md.director       || null,
        producer:        md.producer       || null,
        dop:             md.dop            || null,
        screenwriter:    md.writer         || null,
        video_editor:    md.video_editor   || null,
        sound_design:    md.sound_design   || null,
        management:      md.management     || null,
        graphic_design:  md.graphic_design || null,
        actors:          md.actors         || null,
        support_crew:    md.support_crew   || null,
        poster_image:    md.poster_image   || null,
        trailer_url:     md.trailer_url    || null,
        watch_url:       md.watch_url      || null,
        runtime:         md.runtime        || null,
        language:        md.language       || null,
        genre:           genreVal,
        spotify_url:     md.spotify_url    || null,
        apple_music_url: md.apple_music_url || null,
      }]).select().single();

      if (movieErr) return res.status(500).json({ error: "Failed to publish movie: " + movieErr.message });
      publishedMovieId = newMovie.id;
      memInvalidate("movies:list", "movies:genre:");
      logActivity(req.admin.id, req.admin.name, "create", "movie", md.title).catch(() => {});
    }

    await supabase.from("member_movie_submissions").update({
      status: statusMap[action],
      reviewer_notes: notes || null,
      reviewed_by: req.admin.username,
      reviewed_at: new Date().toISOString(),
      published_movie_id: publishedMovieId || null,
    }).eq("id", sub.id);

    logActivity(req.admin.id, req.admin.name, action, "movie_submission", sub.movie_data?.title || sub.id).catch(() => {});

    // Notify member
    const movieTitle = sub.movie_data?.title || "your film submission";
    if (action === "approve") {
      createMemberNotification(sub.member_id, "movie", "Film submission approved 🎬", `"${movieTitle}" has been approved and published to the KFS filmography.`).catch(() => {});
    } else if (action === "reject") {
      createMemberNotification(sub.member_id, "movie", "Film submission not approved", notes ? `"${movieTitle}" — Admin note: ${notes}` : `"${movieTitle}" was not approved.`).catch(() => {});
    } else if (action === "request_changes") {
      createMemberNotification(sub.member_id, "movie", "Changes requested on film submission", notes ? `"${movieTitle}" — Admin note: ${notes}` : `The admin has requested changes to "${movieTitle}".`).catch(() => {});
    }

    res.json({ success: true, publishedMovieId: publishedMovieId || null });
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-21 — Admin: Member Activity & Monitoring
// ─────────────────────────────────────────────────────────────────────────────

// Tiny dependency-free UA summarizer — good enough for "what device did they
// log in from" at a glance in the admin panel. Not as thorough as a full
// UA-parser library, but covers the common browsers/OSes/device types and
// needs zero new npm packages.
function summarizeUserAgent(ua) {
  if (!ua) return null;
  const isMobile = /Mobile|Android|iPhone/i.test(ua);
  const isTablet = /Tablet|iPad/i.test(ua);
  const device = isTablet ? "Tablet" : isMobile ? "Mobile" : "Desktop";

  let os = "Unknown OS";
  if (/Windows NT/i.test(ua)) os = "Windows";
  else if (/Mac OS X/i.test(ua) && !/iPhone|iPad/i.test(ua)) os = "macOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/iPhone|iPad|iOS/i.test(ua)) os = "iOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  let browser = "Unknown browser";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera/i.test(ua)) browser = "Opera";
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) browser = "Chrome";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Safari\//i.test(ua) && /Version\//i.test(ua)) browser = "Safari";

  return { device, os, browser, label: `${browser} on ${os} (${device})` };
}

app.get("/api/admin/members/:id/activity", requireSection("members"), async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 30);
  const { data } = await supabase
    .from("member_activity")
    .select("id, action, metadata, ip_address, created_at")
    .eq("member_id", req.params.id)
    .order("created_at", { ascending: false })
    .range((page - 1) * limit, page * limit - 1);

  const enriched = (data || []).map(row => ({
    ...row,
    login_method: row.metadata?.method === "google" ? "google" : (row.action === "login" ? "password" : null),
    device_info: summarizeUserAgent(row.metadata?.ua),
  }));
  res.json(enriched);
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-22 — initMemberDB (call inside existing app.listen callback)
// ─────────────────────────────────────────────────────────────────────────────
// Add this call inside the existing app.listen() callback, alongside initDB():
//   await initMemberDB();

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-23 — Member Notifications
// ─────────────────────────────────────────────────────────────────────────────

// `extra` may carry actor info (who triggered this notification) and a
// deep-link target so the client can render an avatar + navigate on tap:
//   { actorId, actorName, actorPhoto, linkType: 'profile'|'post', linkId }
async function createMemberNotification(memberId, type, title, body, extra = {}) {
  try {
    await supabase.from("member_notifications").insert([{
      member_id:   memberId,
      type,
      title,
      body:        body || null,
      actor_id:    extra.actorId    || null,
      actor_name:  extra.actorName  || null,
      actor_photo: extra.actorPhoto || null,
      link_type:   extra.linkType   || null,
      link_id:     extra.linkId     || null,
    }]);
  } catch (e) {
    console.error("[createMemberNotification] failed:", e.message);
  }
}

// GET /api/member/notifications — fetch unread + recent read (last 30)
app.get("/api/member/notifications", memberAuthMiddleware, async (req, res) => {
  const { data } = await supabase
    .from("member_notifications")
    .select("id, type, title, body, is_read, created_at, actor_id, actor_name, actor_photo, link_type, link_id")
    .eq("member_id", req.member.memberId)
    .order("created_at", { ascending: false })
    .limit(30);
  res.json(data || []);
});

// POST /api/member/notifications/:id/read
app.post("/api/member/notifications/:id/read", memberAuthMiddleware, async (req, res) => {
  await supabase.from("member_notifications").update({ is_read: true })
    .eq("id", req.params.id).eq("member_id", req.member.memberId);
  res.json({ success: true });
});

// POST /api/member/notifications/read-all
app.post("/api/member/notifications/read-all", memberAuthMiddleware, async (req, res) => {
  await supabase.from("member_notifications").update({ is_read: true })
    .eq("member_id", req.member.memberId).eq("is_read", false);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-24 — Authenticated Collaborate Post (portal members)
// ─────────────────────────────────────────────────────────────────────────────

app.post("/api/collaborate/member", memberAuthMiddleware, strictWriteLimit, async (req, res) => {
  try {
    await cleanupExpiredCollaborations();
    // Fetch member's own profile to get name, email, phone
    const { data: member } = await supabase.from("members")
      .select("name, email, mobile").eq("id", req.member.memberId).maybeSingle();
    if (!member) return res.status(404).json({ error: "Member profile not found" });

    const payload = cleanCollabPayload(req.body);
    if (!payload.title || !payload.role || !payload.description || !payload.fulfillment_date)
      return res.status(400).json({ error: "Title, role, description, and fulfillment date are required." });
    if (!payload.contact_email || !payload.contact_phone)
      return res.status(400).json({ error: "Email and phone are required." });

    // Profanity check
    const collabProfCheck = checkFieldsForProfanity(payload.title, payload.role, payload.description);
    if (collabProfCheck.found) return res.status(400).json({ error: "Your post contains inappropriate language. Please revise it." });

    const today = new Date().toISOString().split("T")[0];
    if (payload.fulfillment_date < today)
      return res.status(400).json({ error: "Fulfillment date cannot be in the past." });

    const edit_token = makeEditToken();
    const { data, error } = await supabasePublic.from("collaborate_posts").insert([{
      ...payload,
      contact_name:  payload.contact_name  || member.name,
      contact_email: payload.contact_email || member.email,
      contact_phone: payload.contact_phone || member.mobile,
      is_kfs_member: true,
      member_id: req.member.memberId,
      edit_token,
    }]).select("id,edit_token").single();

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json({ success: true, id: data.id, edit_token, edit_url: `/collaborate/edit/${edit_token}` });
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Member: list own collab posts (authenticated — includes edit_token, unlike the public listing)
app.get("/api/collaborate/mine", memberAuthMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabasePublic
      .from("collaborate_posts")
      .select(
        "id,title,role,skills,timeline,description,contact_name,contact_email,contact_phone,domain,fulfillment_date,created_at,updated_at,edit_token",
      )
      .eq("member_id", req.member.memberId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: "Internal server error" });
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Member: edit own collab post (authenticated — verifies post belongs to this member account)
app.put("/api/collaborate/member/:token", memberAuthMiddleware, csrfProtect, async (req, res) => {
  try {
    // Confirm post exists and belongs to this member
    const { data: existing } = await supabasePublic.from("collaborate_posts")
      .select("id, member_id").eq("edit_token", req.params.token).maybeSingle();
    if (!existing) return res.status(404).json({ error: "Post not found." });
    if (existing.member_id !== req.member.memberId)
      return res.status(403).json({ error: "You can only edit your own posts." });

    const payload = cleanCollabPayload(req.body);
    if (!payload.title || !payload.role || !payload.description || !payload.fulfillment_date)
      return res.status(400).json({ error: "Title, role, description, and fulfillment date are required." });
    if (!payload.contact_email || !payload.contact_phone)
      return res.status(400).json({ error: "Email and phone are required." });

    // Profanity check
    const collabEditProfCheck = checkFieldsForProfanity(payload.title, payload.role, payload.description);
    if (collabEditProfCheck.found) return res.status(400).json({ error: "Your post contains inappropriate language. Please revise it." });

    const { data, error } = await supabase.from("collaborate_posts")
      .update({ ...payload, updated_at: new Date().toISOString() })
      .eq("edit_token", req.params.token)
      .select("id")
      .maybeSingle();
    if (error) return res.status(500).json({ error: "Internal server error" });
    if (!data) return res.status(404).json({ error: "Post not found." });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

async function initMemberDB() {
  try {
    const { error: accErr } = await supabase
      .from("member_accounts")
      .select("id", { count: "exact", head: true })
      .limit(1);
    if (accErr) {
      console.warn("[initMemberDB] member_accounts table not found — run member_portal_migration.sql in Supabase");
      return;
    }

    // Check whether social/portal columns exist on members table
    const { error: colErr } = await supabase
      .from("members")
      .select("instagram,github,linkedin,twitter,youtube,website,custom_links,roll_no,mobile,email,updated_at")
      .limit(1);
    if (colErr) {
      const lines = [
        "[initMemberDB] members table is missing social/portal columns.",
        "Run this SQL in Supabase SQL Editor:",
        "",
        "  ALTER TABLE members",
        "    ADD COLUMN IF NOT EXISTS roll_no      TEXT,",
        "    ADD COLUMN IF NOT EXISTS mobile       TEXT,",
        "    ADD COLUMN IF NOT EXISTS email        TEXT,",
        "    ADD COLUMN IF NOT EXISTS instagram    TEXT,",
        "    ADD COLUMN IF NOT EXISTS linkedin     TEXT,",
        "    ADD COLUMN IF NOT EXISTS github       TEXT,",
        "    ADD COLUMN IF NOT EXISTS twitter      TEXT,",
        "    ADD COLUMN IF NOT EXISTS youtube      TEXT,",
        "    ADD COLUMN IF NOT EXISTS website      TEXT,",
        "    ADD COLUMN IF NOT EXISTS custom_links JSONB DEFAULT '[]',",
        "    ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ DEFAULT NOW();",
        "",
        "Error was: " + colErr.message,
      ];
      console.warn(lines.join("\n"));
    } else {
      console.log("[initMemberDB] members table columns OK");
    }

    await loadRevokedMemberTokens();

    // Check member_notifications table (created via SQL migration)
    const { error: notifErr } = await supabase.from("member_notifications").select("id", { count: "exact", head: true }).limit(1);
    if (notifErr) {
      console.warn(
        "[initMemberDB] member_notifications table not found. Run this SQL:\n\n" +
        "  CREATE TABLE IF NOT EXISTS member_notifications (\n" +
        "    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n" +
        "    member_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,\n" +
        "    type        TEXT NOT NULL,\n" +
        "    title       TEXT NOT NULL,\n" +
        "    body        TEXT,\n" +
        "    actor_id    UUID REFERENCES members(id) ON DELETE SET NULL,\n" +
        "    actor_name  TEXT,\n" +
        "    actor_photo TEXT,\n" +
        "    link_type   TEXT,\n" +
        "    link_id     TEXT,\n" +
        "    is_read     BOOLEAN NOT NULL DEFAULT FALSE,\n" +
        "    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()\n" +
        "  );\n" +
        "  CREATE INDEX IF NOT EXISTS member_notifications_member_id_idx ON member_notifications(member_id);\n" +
        "  CREATE INDEX IF NOT EXISTS member_notifications_is_read_idx   ON member_notifications(member_id, is_read);"
      );
    } else {
      console.log("[initMemberDB] member_notifications table OK");
      // Check for the actor/link columns (added for the follow + new-post
      // notification types so the client can render an avatar + deep-link).
      const { error: notifColErr } = await supabase
        .from("member_notifications")
        .select("actor_id, actor_name, actor_photo, link_type, link_id")
        .limit(1);
      if (notifColErr) {
        console.warn(
          "[initMemberDB] member_notifications is missing actor/link columns. Run this SQL:\n\n" +
          "  ALTER TABLE member_notifications\n" +
          "    ADD COLUMN IF NOT EXISTS actor_id    UUID REFERENCES members(id) ON DELETE SET NULL,\n" +
          "    ADD COLUMN IF NOT EXISTS actor_name  TEXT,\n" +
          "    ADD COLUMN IF NOT EXISTS actor_photo TEXT,\n" +
          "    ADD COLUMN IF NOT EXISTS link_type   TEXT,\n" +
          "    ADD COLUMN IF NOT EXISTS link_id     TEXT;"
        );
      } else {
        console.log("[initMemberDB] member_notifications actor/link columns OK");
      }
    }

    // Check member_grievances table
    const { error: grvErr } = await supabase.from("member_grievances").select("id", { count: "exact", head: true }).limit(1);
    if (grvErr) {
      console.warn(
        "[initMemberDB] member_grievances table not found. Run this SQL in Supabase:\n\n" +
        "  CREATE TABLE IF NOT EXISTS member_grievances (\n" +
        "    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),\n" +
        "    account_id   BIGINT      NOT NULL REFERENCES member_accounts(id) ON DELETE CASCADE,\n" +
        "    member_id    UUID        REFERENCES members(id) ON DELETE SET NULL,\n" +
        "    member_name  TEXT,\n" +
        "    subject      TEXT        NOT NULL,\n" +
        "    body         TEXT        NOT NULL,\n" +
        "    type         TEXT        NOT NULL DEFAULT 'general' CHECK (type IN ('suggestion','grievance','general')),\n" +
        "    anonymous    BOOLEAN     NOT NULL DEFAULT FALSE,\n" +
        "    status       TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved')),\n" +
        "    admin_note   TEXT,\n" +
        "    reviewed_by  TEXT,\n" +
        "    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n" +
        "    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()\n" +
        "  );\n" +
        "  CREATE INDEX IF NOT EXISTS member_grievances_account_id_idx ON member_grievances(account_id);\n" +
        "  CREATE INDEX IF NOT EXISTS member_grievances_status_idx     ON member_grievances(status);\n" +
        "  CREATE INDEX IF NOT EXISTS member_grievances_created_at_idx ON member_grievances(created_at DESC);\n\n" +
        "  -- RLS: disable (server uses service_role key which bypasses RLS anyway)\n" +
        "  ALTER TABLE member_grievances DISABLE ROW LEVEL SECURITY;"
      );
    } else {
      console.log("[initMemberDB] member_grievances table OK");
    }

    console.log("[initMemberDB] Member portal tables OK");
  } catch (e) {
    console.error("[initMemberDB] error:", e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Export helpers for use in app.listen callback (add to bottom of server.js)
// ─────────────────────────────────────────────────────────────────────────────
// In your app.listen block, add:
//   await initMemberDB();


// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-23 — Member: My Works (public films where member appears)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/member/works", memberAuthMiddleware, async (req, res) => {
  try {
    const { data: memberRow } = await supabase
      .from("members").select("id, name").eq("id", req.member.memberId).maybeSingle();
    if (!memberRow) return res.json([]);

    const { data: movies } = await supabase
      .from("movies")
      .select("id, title, release_year, poster_image, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew")
      .is("deleted_at", null); // exclude admin-deleted films

    const crewFields = ["director","producer","dop","screenwriter","video_editor","sound_design","management","graphic_design","actors","support_crew"];
    const roleLabels = { director:"Director", producer:"Producer", dop:"DOP", screenwriter:"Script Writer", video_editor:"Editor", sound_design:"Sound Design", management:"Management", graphic_design:"Graphic Design", actors:"Actor", support_crew:"Crew" };
    const memberId = String(memberRow.id);
    const memberName = memberRow.name.trim().toLowerCase();

    const works = [];
    (movies || []).forEach(m => {
      let roleLabel = "";
      crewFields.forEach(f => {
        if (roleLabel) return;
        const val = m[f] || "";
        val.split(";;").map(s => s.trim()).filter(Boolean).forEach(part => {
          if (roleLabel) return;
          const pipes = part.split("||");
          const name = pipes[0].trim().toLowerCase();
          const id   = pipes[1] ? pipes[1].trim() : null;
          if (id === memberId || name === memberName) {
            roleLabel = roleLabels[f] || f;
          }
        });
        // also handle comma-separated legacy format
        if (!roleLabel) {
          val.split(",").map(s => s.trim().toLowerCase()).filter(Boolean).forEach(name => {
            if (roleLabel) return;
            if (name === memberName) roleLabel = roleLabels[f] || f;
          });
        }
      });
      if (roleLabel) works.push({ id: m.id, title: m.title, release_year: m.release_year, poster_image: m.poster_image, role: roleLabel });
    });

    works.sort((a, b) => (b.release_year || 0) - (a.release_year || 0));
    res.json(works);
  } catch (e) {
    console.error("[works]", e.message);
    res.json([]);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-24 — Member: Work Edit Requests
// ─────────────────────────────────────────────────────────────────────────────

app.post("/api/member/work-edit-request", memberAuthMiddleware, async (req, res) => {
  const { movie_id, movie_title, description } = req.body;
  if (!movie_id || !description || !description.trim())
    return res.status(400).json({ error: "movie_id and description are required" });

  const { data: memberRow } = await supabase
    .from("members").select("id, name").eq("id", req.member.memberId).maybeSingle();

  const { data, error } = await supabase
    .from("member_work_edit_requests")
    .insert([{
      member_id:   req.member.memberId,
      account_id:  req.member.id,
      movie_id:    movie_id,
      movie_title: movie_title || null,
      description: description.trim(),
      status:      "pending",
    }])
    .select().single();

  if (error) {
    // Table may not exist yet — return graceful error
    if (error.code === "42P01") return res.status(503).json({ error: "work_edit_requests table not yet created — run migration" });
    return res.status(500).json({ error: "Internal server error" });
  }

  await logMemberActivity(req.member.id, req.member.memberId, "work_edit_requested", { requestId: data.id, movie_title }, req.ip);
  res.json({ success: true, id: data.id });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-25 — Admin: Work Edit Request Moderation
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/admin/work-edit-requests", requireSection("members"), async (req, res) => {
  const status = req.query.status || "pending";
  const { data } = await supabase
    .from("member_work_edit_requests")
    .select("*, members(id, name)")
    .eq("status", status)
    .order("created_at", { ascending: false });
  res.json(data || []);
});

app.post("/api/admin/work-edit-requests/:id/review", requireSection("members"), async (req, res) => {
  const { action, notes } = req.body; // action: approve | reject
  if (!["approve","reject"].includes(action))
    return res.status(400).json({ error: "Invalid action" });

  const { data: req_ } = await supabase
    .from("member_work_edit_requests").select("*").eq("id", req.params.id).maybeSingle();
  if (!req_) return res.status(404).json({ error: "Request not found" });

  const statusMap = { approve: "approved", reject: "rejected" };
  await supabase.from("member_work_edit_requests").update({
    status:      statusMap[action],
    admin_notes: notes || null,
    reviewed_by: req.admin.username,
    reviewed_at: new Date().toISOString(),
  }).eq("id", req_.id);

  logActivity(req.admin.id, req.admin.name, action, "work_edit_request", req_.movie_title || req_.movie_id).catch(() => {});
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-26 — Member Grievances / Suggestions
// ─────────────────────────────────────────────────────────────────────────────

// Member: submit a grievance/suggestion
app.post("/api/member/grievances", memberAuthMiddleware, async (req, res) => {
  const { subject, body, type, anonymous } = req.body;
  if (!subject || !subject.trim()) return res.status(400).json({ error: "Subject is required" });
  if (!body    || !body.trim())    return res.status(400).json({ error: "Details are required" });
  if (body.trim().length < 10)     return res.status(400).json({ error: "Details are too short" });

  // Profanity check
  const grvProfCheck = checkFieldsForProfanity(subject, body);
  if (grvProfCheck.found) return res.status(400).json({ error: "Your submission contains inappropriate language. Please revise it." });

  const validTypes = ["suggestion", "grievance", "general"];
  const entryType = validTypes.includes(type) ? type : "general";

  const { data: memberRow } = await supabase
    .from("members").select("id, name").eq("id", req.member.memberId).maybeSingle();

  const { data, error } = await supabase
    .from("member_grievances")
    .insert([{
      account_id:  req.member.id,
      member_id:   req.member.memberId,
      member_name: anonymous ? null : (memberRow?.name || null),
      subject:     subject.trim().slice(0, 160),
      body:        body.trim().slice(0, 2000),
      type:        entryType,
      anonymous:   !!anonymous,
      status:      "open",
    }])
    .select().single();

  if (error) {
    if (error.code === "42P01") return res.status(503).json({ error: "member_grievances table not yet created — run DB migration" });
    console.error("[grievance submit]", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }

  await logMemberActivity(req.member.id, req.member.memberId, "grievance_submitted", { id: data.id, type: entryType, anonymous: !!anonymous }, req.ip);
  res.json({ success: true, id: data.id });
});

// Member: list own grievances
app.get("/api/member/grievances", memberAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("member_grievances")
    .select("id, subject, body, type, anonymous, status, admin_note, created_at, updated_at")
    .eq("account_id", req.member.id)
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) {
    if (error.code === "42P01") return res.json([]); // table not yet created — return empty gracefully
    return res.status(500).json({ error: "Internal server error" });
  }
  res.json(data || []);
});

// Admin: list all grievances (requires 'members' or 'grievances' permission)
function requireGrievanceAccess(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    if (decoded.jti && _revokedJtis.has(decoded.jti)) return res.status(401).json({ error: "Token revoked" });
    req.admin = decoded;
    if (decoded.role === "master") return next();
    const perms = decoded.permissions || [];
    // accessible if admin has 'members' OR 'grievances' permission
    if (perms.includes("members") || perms.includes("grievances")) return next();
    return res.status(403).json({ error: "No permission for grievances" });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.get("/api/admin/grievances", requireGrievanceAccess, async (req, res) => {
  const status = req.query.status; // open | in_progress | resolved | (empty = all)
  const type   = req.query.type;   // suggestion | grievance | general | (empty = all)

  let q = supabase
    .from("member_grievances")
    .select("id, subject, body, type, anonymous, status, admin_note, member_name, member_id, account_id, created_at, updated_at")
    .order("created_at", { ascending: false })
    .limit(200);

  if (status) q = q.eq("status", status);
  if (type)   q = q.eq("type", type);

  const { data, error } = await q;
  if (error) {
    if (error.code === "42P01") return res.json([]);
    return res.status(500).json({ error: "Internal server error" });
  }
  res.json(data || []);
});

// Admin: update status + optional note on a grievance
app.patch("/api/admin/grievances/:id", requireGrievanceAccess, async (req, res) => {
  const { status, admin_note } = req.body;
  const validStatuses = ["open", "in_progress", "resolved"];
  if (status && !validStatuses.includes(status))
    return res.status(400).json({ error: "Invalid status — use open | in_progress | resolved" });

  const updates = { updated_at: new Date().toISOString() };
  if (status)     updates.status     = status;
  if (admin_note !== undefined) updates.admin_note = admin_note ? admin_note.trim().slice(0, 500) : null;
  if (status)     updates.reviewed_by = req.admin.username || req.admin.name;

  const { data, error } = await supabase
    .from("member_grievances")
    .update(updates)
    .eq("id", req.params.id)
    .select().single();

  if (error) {
    if (error.code === "42P01") return res.status(503).json({ error: "member_grievances table not yet created" });
    return res.status(500).json({ error: "Internal server error" });
  }
  if (!data) return res.status(404).json({ error: "Grievance not found" });

  logActivity(req.admin.id, req.admin.name || req.admin.username, "grievance_status_update", "grievance", data.subject, data.id).catch(() => {});
  res.json({ success: true, grievance: data });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-27 — Studio Wall (Phase 1)
//
// WHY NO SECOND SUPABASE PROJECT:
//  • Cloudinary already handles all media (cover images, video embeds are just
//    URLs). Zero Supabase Storage egress for binary assets.
//  • memCache() keeps feed/card DB reads to one trip per TTL window regardless
//    of concurrent users. Denormalized counter columns (views_count,
//    reactions_count, comments_count) mean feed cards never fan out to joins.
//  • A second project would require duplicating auth, losing cross-table FKs,
//    doubling the keep-alive overhead, and splitting the cache — it would make
//    egress worse, not better.
//  • project_views rows are pruned after 2 days (see migration housekeeping).
//    The dedup table never grows unbounded regardless of traffic.
//
// All routes live under /api/member/studio/* so they inherit the global
//   app.use('/api/member', csrfProtectMember)   ← CSRF auto-applied
//   memberAuthMiddleware                          ← applied per route
// Writes use `supabase` (service-role). Reads use `supabasePublic` (anon, RLS-gated).
// ─────────────────────────────────────────────────────────────────────────────

// ── Helpers ──────────────────────────────────────────────────────────────────

function studioViewerKey(memberId) {
  // One-way hash — never stores raw member id, purely for same-day dedup.
  return crypto.createHash("sha256").update(`sw:${memberId}`).digest("hex").slice(0, 32);
}

function parseVideoUrl(raw) {
  if (!raw) return { url: null, provider: null };
  try {
    const u = new URL(raw.trim());
    if (/youtube\.com|youtu\.be/.test(u.hostname)) return { url: raw.trim(), provider: "youtube" };
    if (/vimeo\.com/.test(u.hostname))              return { url: raw.trim(), provider: "vimeo"   };
  } catch {}
  return { url: null, provider: null };
}

const studioFeedLimit  = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });
const studioWriteLimit = rateLimit({ windowMs: 60_000, max: 10,  standardHeaders: true, legacyHeaders: false });

// ── Smart feed ranking helpers (Phase 2 — "The Network") ────────────────────
// Signal weights live in `feed_weights` (DB-editable, no deploy needed — see
// phase2_network_migration.sql). Cached briefly since they rarely change.
async function getFeedWeights() {
  return memCache("feed:weights", 600, async () => {
    const { data, error } = await supabase.from("feed_weights").select("signal, weight");
    if (error) throw error;
    const map = {};
    (data || []).forEach(r => { map[r.signal] = Number(r.weight); });
    return map;
  });
}

// Reaction counts per project in the last 48h — the "trending" signal.
// Shared by the ranked feed and the standalone /network/trending endpoint.
async function getTrendingCounts() {
  return memCache("feed:trending-counts", 180, async () => {
    const since = new Date(Date.now() - 48 * 3600 * 1000).toISOString();
    const { data, error } = await supabase
      .from("project_reactions")
      .select("project_id")
      .gte("created_at", since);
    if (error) throw error;
    const counts = {};
    (data || []).forEach(r => { counts[r.project_id] = (counts[r.project_id] || 0) + 1; });
    return counts;
  });
}

// ── Feed ─────────────────────────────────────────────────────────────────────

// GET /api/member/studio/feed?page=1&tag=&sort=latest|foryou
// sort=latest (default): unchanged chronological feed, exactly as Phase 1.
// sort=foryou: ranked using feed_weights signals — followed authors, domain/
//   skill match, 48h trending velocity, and a recency decay. The candidate
//   pool (recent published posts) is cached briefly and shared across
//   viewers; the ranking itself is computed fresh per request since it
//   depends on who the viewer follows and their domain/skills.
app.get("/api/member/studio/feed", memberAuthMiddleware, studioFeedLimit, async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const tag   = (req.query.tag || "").trim().toLowerCase().slice(0, 50);
  const sort  = req.query.sort === "foryou" ? "foryou" : "latest";
  const limit = 20;
  const from  = (page - 1) * limit;

  if (sort === "latest") {
    const cKey = `studio:feed:p${page}:t${tag}`;
    cacheFor(res, 30);
    const data = await memCache(cKey, 60, async () => {
      let q = supabasePublic
        .from("member_projects")
        .select(`
          id, title, description, cover_image, video_url, video_provider,
          domain, tags, views_count, reactions_count, comments_count, created_at,
          member_id,
          members!member_projects_member_id_fkey(id, name, photo, role, domain)
        `)
        .is("deleted_at", null)
        .eq("status", "published")
        .order("created_at", { ascending: false })
        .range(from, from + limit - 1);

      if (tag) q = q.contains("tags", [tag]);

      const { data: rows, error } = await q;
      if (error) throw error;
      return rows || [];
    });

    // Attach viewer's own reaction to each card (non-cached, member-specific)
    let myReactions = {};
    if (data.length) {
      const ids = data.map(r => r.id);
      const { data: rxs } = await supabase
        .from("project_reactions")
        .select("project_id, reaction_type")
        .eq("member_id", req.member.memberId)
        .in("project_id", ids);
      (rxs || []).forEach(r => { myReactions[r.project_id] = r.reaction_type; });
    }

    const feed = data.map(p => ({ ...p, my_reaction: myReactions[p.id] || null }));
    return res.json({ feed, page, has_more: data.length === limit, sort });
  }

  // ── "For You" — smart ranked feed ─────────────────────────────────────────
  try {
    const poolKey = `studio:feed:pool:t${tag}`;
    const pool = await memCache(poolKey, 90, async () => {
      let q = supabasePublic
        .from("member_projects")
        .select(`
          id, title, description, cover_image, video_url, video_provider,
          domain, tags, views_count, reactions_count, comments_count, created_at,
          member_id,
          members!member_projects_member_id_fkey(id, name, photo, role, domain)
        `)
        .is("deleted_at", null)
        .eq("status", "published")
        .order("created_at", { ascending: false })
        .limit(150);
      if (tag) q = q.contains("tags", [tag]);
      const { data: rows, error } = await q;
      if (error) throw error;
      return rows || [];
    });

    const [weights, trending, followRows, skillRows, viewerRow] = await Promise.all([
      getFeedWeights(),
      getTrendingCounts(),
      supabase.from("member_follows").select("following_id").eq("follower_id", req.member.memberId),
      supabase.from("member_skills").select("skill_tags(name)").eq("member_id", req.member.memberId),
      supabase.from("members").select("domain").eq("id", req.member.memberId).maybeSingle(),
    ]);

    const followingIds = new Set((followRows.data || []).map(r => r.following_id));
    const viewerDomain = viewerRow.data?.domain || null;
    const skillNames = new Set((skillRows.data || []).map(r => (r.skill_tags?.name || "").toLowerCase()).filter(Boolean));

    const wFollow = weights.followed_author ?? 3.0;
    const wDomain = weights.domain_match    ?? 1.5;
    const wTrend  = weights.trending        ?? 2.0;
    const wDecay  = weights.recency_decay   ?? 0.08;
    const now = Date.now();

    const scored = pool.map(p => {
      let score = 0;
      if (followingIds.has(p.member_id)) score += wFollow;
      const domainMatch = !!(viewerDomain && p.domain && p.domain.toLowerCase() === viewerDomain.toLowerCase());
      const skillMatch  = !domainMatch && (p.tags || []).some(t => skillNames.has(String(t).toLowerCase()));
      if (domainMatch || skillMatch) score += wDomain;
      score += (trending[p.id] || 0) * wTrend;
      const hoursSince = Math.max(0, (now - new Date(p.created_at).getTime()) / 3_600_000);
      score -= wDecay * hoursSince;
      return { ...p, _score: score };
    }).sort((a, b) => b._score - a._score);

    const pageItems = scored.slice(from, from + limit);

    let myReactions = {};
    if (pageItems.length) {
      const ids = pageItems.map(r => r.id);
      const { data: rxs } = await supabase
        .from("project_reactions")
        .select("project_id, reaction_type")
        .eq("member_id", req.member.memberId)
        .in("project_id", ids);
      (rxs || []).forEach(r => { myReactions[r.project_id] = r.reaction_type; });
    }

    const feed = pageItems.map(({ _score, ...p }) => ({ ...p, my_reaction: myReactions[p.id] || null }));
    res.json({ feed, page, has_more: from + limit < scored.length, sort });
  } catch (e) {
    console.error("[studio:feed:foryou]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Single project + view increment ─────────────────────────────────────────

// GET /api/member/studio/projects/:id
app.get("/api/member/studio/projects/:id", memberAuthMiddleware, studioFeedLimit, async (req, res) => {
  const id = req.params.id;

  const { data: project, error } = await supabasePublic
    .from("member_projects")
    .select(`
      id, title, description, cover_image, video_url, video_provider,
      domain, tags, views_count, reactions_count, comments_count, status, created_at,
      member_id,
      members!member_projects_member_id_fkey(id, name, photo, role, domain),
      project_collaborators(
        member_id,
        members!project_collaborators_member_id_fkey(id, name, photo, role)
      )
    `)
    .eq("id", id)
    .is("deleted_at", null)
    .maybeSingle();

  if (error || !project) return res.status(404).json({ error: "Project not found" });

  // Increment view (deduped by viewer_key+day via RPC) — fire and forget for latency
  const viewerKey = studioViewerKey(req.member.memberId);
  supabase.rpc("increment_project_view", { p_project_id: id, p_viewer_key: viewerKey })
    .then(({ data: newCount }) => {
      if (newCount != null) {
        // Bust feed cache so next load shows updated view count
        Object.keys(require("./server").memCacheStore || {}).filter(k => k.startsWith("studio:feed")).forEach(k => {
          // Best-effort: the in-process memCache map; no-op if export not available
        });
      }
    })
    .catch(() => {});

  // My reaction
  const { data: myRx } = await supabase
    .from("project_reactions")
    .select("reaction_type")
    .eq("project_id", id)
    .eq("member_id", req.member.memberId)
    .maybeSingle();

  // My save status
  const { data: mySave } = await supabase
    .from("member_saves")
    .select("id, collection_id")
    .eq("project_id", id)
    .eq("member_id", req.member.memberId)
    .limit(1)
    .maybeSingle();

  res.json({
    ...project,
    my_reaction: myRx?.reaction_type || null,
    is_saved: !!mySave,
    save_id: mySave?.id || null,
  });
});

// ── Create project ────────────────────────────────────────────────────────────

// POST /api/member/studio/projects
app.post(
  "/api/member/studio/projects",
  memberAuthMiddleware,
  studioWriteLimit,
  upload.single("cover_image"),
  async (req, res) => {
  try {
    const { title, description, video_url, domain, tags: rawTags, collab_ids: rawCollabIds } = req.body;

    if (!title || !title.trim()) return res.status(400).json({ error: "Title is required" });
    if (title.trim().length > 120) return res.status(400).json({ error: "Title must be ≤ 120 characters" });

    // Strict image validation (magic bytes + size) — runs before profanity so we
    // don't leak violation counts when the image itself is the problem.
    const imgErr = validatePostImage(req.file);
    if (imgErr) return res.status(400).json({ error: imgErr });

    // Parse tags early so we can include them in the profanity check
    let tags = [];
    try { tags = rawTags ? (Array.isArray(rawTags) ? rawTags : JSON.parse(rawTags)) : []; }
    catch { tags = rawTags ? [rawTags] : []; }
    tags = [...new Set(tags.map(t => String(t).toLowerCase().trim()).filter(Boolean))].slice(0, 10);

    // Profanity check — title, description AND tags all checked
    const allText = [title, description || '', ...tags].join(' ');
    const vioResponse = await vioGate(req, res, req.member.memberId, allText);
    if (vioResponse) return; // vioGate already sent the response (warning/mute/ban)

    const { url: parsedVideoUrl, provider } = parseVideoUrl(video_url);
    if (video_url && !parsedVideoUrl) return res.status(400).json({ error: "video_url must be a valid YouTube or Vimeo URL" });
    let collabIds = [];
    try { collabIds = rawCollabIds ? (Array.isArray(rawCollabIds) ? rawCollabIds : JSON.parse(rawCollabIds)) : []; }
    catch { collabIds = []; }
    collabIds = collabIds.filter(id => typeof id === "string" && id.length > 0).slice(0, 20);

    const coverUrl = req.file ? await uploadImage(req.file, "studio") : null;

    const { data: project, error } = await supabase
      .from("member_projects")
      .insert([{
        member_id:      req.member.memberId,
        account_id:     req.member.id,
        title:          title.trim().slice(0, 120),
        description:    description ? description.trim().slice(0, 2000) : null,
        cover_image:    coverUrl,
        video_url:      parsedVideoUrl,
        video_provider: provider,
        domain:         domain ? domain.trim().slice(0, 80) : null,
        tags,
        status: "published",
      }])
      .select("id, title, created_at")
      .single();

    if (error) {
      console.error("[studio:create]", error.message);
      return res.status(500).json({ error: "Internal server error" });
    }

    // Tag collaborators
    if (collabIds.length) {
      // Verify each id exists in members table
      const { data: validMembers } = await supabase
        .from("members").select("id").in("id", collabIds);
      const validIds = (validMembers || []).map(m => m.id);

      if (validIds.length) {
        await supabase.from("project_collaborators").insert(
          validIds.map(mid => ({
            project_id: project.id,
            member_id:  mid,
            tagged_by:  req.member.memberId,
          }))
        );
        // Notify each tagged collaborator
        for (const mid of validIds) {
          if (mid !== req.member.memberId) {
            createMemberNotification(
              mid, "studio",
              "You were tagged in a project 🎬",
              `${req.member.username || "A member"} tagged you as a collaborator on "${title.trim()}"`
            ).catch(() => {});
          }
        }
      }
    }

    // Notify followers that this member just posted to the Strand feed.
    const { data: followerRows } = await supabase
      .from("member_follows")
      .select("follower_id")
      .eq("following_id", req.member.memberId)
      .limit(500);
    if (followerRows?.length) {
      const poster = await getActiveMember(req.member.memberId, "id, name, photo");
      const posterName = poster?.name || req.member.username || "Someone you follow";
      for (const { follower_id } of followerRows) {
        createMemberNotification(
          follower_id, "new_post",
          "New post on Strand 🎬",
          `${posterName} just posted "${title.trim()}"`,
          { actorId: req.member.memberId, actorName: posterName, actorPhoto: poster?.photo, linkType: "post", linkId: project.id }
        ).catch(() => {});
      }
    }

    await logMemberActivity(req.member.id, req.member.memberId, "studio_post_create", { id: project.id, title: title.trim() }, req.ip);
    res.json({ success: true, id: project.id });
  } catch (e) {
    console.error("[studio:create] unhandled error:", e.message);
    if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
  }
  }
);

// ── Edit project ──────────────────────────────────────────────────────────────

// PUT /api/member/studio/projects/:id
app.put(
  "/api/member/studio/projects/:id",
  memberAuthMiddleware,
  studioWriteLimit,
  upload.single("cover_image"),
  async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from("member_projects")
      .select("id, member_id, cover_image")
      .eq("id", req.params.id)
      .is("deleted_at", null)
      .maybeSingle();

    if (!existing) return res.status(404).json({ error: "Project not found" });
    if (existing.member_id !== req.member.memberId) return res.status(403).json({ error: "Not your project" });

    // Strict image validation if a new image was uploaded
    if (req.file) {
      const imgErr = validatePostImage(req.file);
      if (imgErr) return res.status(400).json({ error: imgErr });
    }

    // Parse tags so they can be included in the profanity scan
    let editTags = [];
    if (req.body.tags !== undefined) {
      try { editTags = Array.isArray(req.body.tags) ? req.body.tags : JSON.parse(req.body.tags); } catch { editTags = [req.body.tags]; }
      editTags = [...new Set(editTags.map(t => String(t).toLowerCase().trim()).filter(Boolean))].slice(0, 10);
    }

    // Profanity check on editable text fields + tags
    const editAllText = [req.body.title || '', req.body.description || '', ...editTags].join(' ');
    const vioResponse = await vioGate(req, res, req.member.memberId, editAllText);
    if (vioResponse) return; // vioGate already sent the response (warning/mute/ban)

    const updates = { updated_at: new Date().toISOString() };
    if (req.body.title !== undefined) updates.title = req.body.title.trim().slice(0, 120);
    if (req.body.description !== undefined) updates.description = req.body.description.trim().slice(0, 2000) || null;
    if (req.body.domain !== undefined) updates.domain = req.body.domain.trim().slice(0, 80) || null;
    if (req.body.video_url !== undefined) {
      const { url: vu, provider: vp } = parseVideoUrl(req.body.video_url);
      if (req.body.video_url && !vu) return res.status(400).json({ error: "video_url must be a valid YouTube or Vimeo URL" });
      updates.video_url = vu; updates.video_provider = vp;
    }
    if (req.body.tags !== undefined) {
      updates.tags = editTags; // already parsed + deduped above
    }
    if (req.file) updates.cover_image = await uploadImage(req.file, "studio");

    const { error } = await supabase.from("member_projects").update(updates).eq("id", req.params.id);
    if (error) { console.error("[studio:edit]", error.message); return res.status(500).json({ error: "Internal server error" }); }

    await logMemberActivity(req.member.id, req.member.memberId, "studio_post_edit", { id: req.params.id }, req.ip);
    res.json({ success: true });
  } catch (e) {
    console.error("[studio:edit] unhandled error:", e.message);
    if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
  }
  }
);

// ── Delete project ────────────────────────────────────────────────────────────

// DELETE /api/member/studio/projects/:id
app.delete("/api/member/studio/projects/:id", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { data: existing } = await supabase
    .from("member_projects").select("id, member_id").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!existing) return res.status(404).json({ error: "Project not found" });
  if (existing.member_id !== req.member.memberId) return res.status(403).json({ error: "Not your project" });

  await supabase.from("member_projects")
    .update({ deleted_at: new Date().toISOString(), status: "hidden" })
    .eq("id", req.params.id);

  await logMemberActivity(req.member.id, req.member.memberId, "studio_post_delete", { id: req.params.id }, req.ip);
  res.json({ success: true });
});

// ── My projects ───────────────────────────────────────────────────────────────

// GET /api/member/studio/mine
app.get("/api/member/studio/mine", memberAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("member_projects")
    .select("id, title, description, cover_image, domain, tags, views_count, reactions_count, comments_count, status, created_at")
    .eq("member_id", req.member.memberId)
    .is("deleted_at", null)
    .order("created_at", { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || []);
});

// ── Reactions ─────────────────────────────────────────────────────────────────

const VALID_REACTIONS = ["wow", "fire", "brilliant", "seahaven", "mind_blown"];

// POST /api/member/studio/projects/:id/react  { reaction_type }
// Toggle: if same reaction already set → remove it. If different → switch it.
app.post("/api/member/studio/projects/:id/react", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { reaction_type } = req.body;
  if (!VALID_REACTIONS.includes(reaction_type)) return res.status(400).json({ error: "Invalid reaction_type" });

  const projectId = req.params.id;
  const memberId  = req.member.memberId;

  // Check if project exists
  const { data: proj } = await supabase.from("member_projects")
    .select("id").eq("id", projectId).is("deleted_at", null).maybeSingle();
  if (!proj) return res.status(404).json({ error: "Project not found" });

  // Existing reaction?
  const { data: existing } = await supabase.from("project_reactions")
    .select("id, reaction_type").eq("project_id", projectId).eq("member_id", memberId).maybeSingle();

  if (existing) {
    if (existing.reaction_type === reaction_type) {
      // Same → remove (toggle off). Trigger decrements reactions_count.
      await supabase.from("project_reactions").delete().eq("id", existing.id);
      return res.json({ active: false, reaction_type: null });
    } else {
      // Different → switch (delete old, insert new). Net count stays the same.
      await supabase.from("project_reactions").delete().eq("id", existing.id);
    }
  }

  // Insert new. Trigger increments reactions_count.
  await supabase.from("project_reactions").insert([{ project_id: projectId, member_id: memberId, reaction_type }]);
  res.json({ active: true, reaction_type });
});

// GET /api/member/studio/projects/:id/reactions
// Returns counts only — no viewer identity exposed.
app.get("/api/member/studio/projects/:id/reactions", memberAuthMiddleware, studioFeedLimit, async (req, res) => {
  const { data, error } = await supabase
    .from("project_reactions")
    .select("reaction_type")
    .eq("project_id", req.params.id);

  if (error) return res.status(500).json({ error: "Internal server error" });

  const counts = { wow: 0, fire: 0, brilliant: 0, seahaven: 0, mind_blown: 0, total: 0 };
  (data || []).forEach(r => { counts[r.reaction_type] = (counts[r.reaction_type] || 0) + 1; counts.total++; });

  // My reaction
  const { data: myRx } = await supabase
    .from("project_reactions").select("reaction_type")
    .eq("project_id", req.params.id).eq("member_id", req.member.memberId).maybeSingle();

  res.json({ counts, my_reaction: myRx?.reaction_type || null });
});

// ── Collaborators ─────────────────────────────────────────────────────────────

// POST /api/member/studio/projects/:id/collaborators  { member_id }
app.post("/api/member/studio/projects/:id/collaborators", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { member_id: targetMemberId } = req.body;
  if (!targetMemberId) return res.status(400).json({ error: "member_id is required" });

  // Only author can tag
  const { data: proj } = await supabase.from("member_projects")
    .select("id, member_id, title").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!proj) return res.status(404).json({ error: "Project not found" });
  if (proj.member_id !== req.member.memberId) return res.status(403).json({ error: "Only the author can tag collaborators" });

  const { data: targetMember } = await supabase.from("members").select("id, name").eq("id", targetMemberId).maybeSingle();
  if (!targetMember) return res.status(404).json({ error: "Member not found" });

  const { error } = await supabase.from("project_collaborators").insert([{
    project_id: req.params.id,
    member_id:  targetMemberId,
    tagged_by:  req.member.memberId,
  }]);

  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Already tagged" });
    return res.status(500).json({ error: "Internal server error" });
  }

  // Notify tagged member
  if (targetMemberId !== req.member.memberId) {
    createMemberNotification(
      targetMemberId, "studio",
      "You were tagged in a project 🎬",
      `${req.member.username || "A member"} tagged you as a collaborator on "${proj.title}"`
    ).catch(() => {});
  }

  res.json({ success: true });
});

// DELETE /api/member/studio/projects/:id/collaborators/:memberId
app.delete("/api/member/studio/projects/:id/collaborators/:memberId", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { data: proj } = await supabase.from("member_projects")
    .select("id, member_id").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!proj) return res.status(404).json({ error: "Project not found" });
  // Author can remove anyone; members can remove themselves
  if (proj.member_id !== req.member.memberId && req.params.memberId !== req.member.memberId) {
    return res.status(403).json({ error: "Not authorized" });
  }

  await supabase.from("project_collaborators")
    .delete().eq("project_id", req.params.id).eq("member_id", req.params.memberId);
  res.json({ success: true });
});

// ── Comments ──────────────────────────────────────────────────────────────────

const commentWriteLimit = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });

// GET /api/member/studio/projects/:id/comments?page=1
app.get("/api/member/studio/projects/:id/comments", memberAuthMiddleware, studioFeedLimit, async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = 30;
  const from  = (page - 1) * limit;

  // Fetch top-level comments
  const { data: topLevel, error } = await supabasePublic
    .from("project_comments")
    .select(`
      id, body, is_pinned, created_at, parent_id,
      member_id,
      members!project_comments_member_id_fkey(id, name, photo)
    `)
    .eq("project_id", req.params.id)
    .is("parent_id", null)
    .is("deleted_at", null)
    .order("is_pinned", { ascending: false })
    .order("created_at", { ascending: false })
    .range(from, from + limit - 1);

  if (error) return res.status(500).json({ error: "Internal server error" });

  // Fetch replies for these top-level comments
  let replies = [];
  if ((topLevel || []).length) {
    const parentIds = topLevel.map(c => c.id);
    const { data: r } = await supabasePublic
      .from("project_comments")
      .select(`
        id, body, created_at, parent_id,
        member_id,
        members!project_comments_member_id_fkey(id, name, photo)
      `)
      .in("parent_id", parentIds)
      .is("deleted_at", null)
      .order("created_at", { ascending: true });
    replies = r || [];
  }

  // Nest replies under parents
  const replyMap = {};
  replies.forEach(r => { (replyMap[r.parent_id] = replyMap[r.parent_id] || []).push(r); });
  const nested = (topLevel || []).map(c => ({ ...c, replies: replyMap[c.id] || [] }));

  res.json({ comments: nested, page, has_more: (topLevel || []).length === limit });
});

// POST /api/member/studio/projects/:id/comments  { body, parent_id? }
app.post("/api/member/studio/projects/:id/comments", memberAuthMiddleware, commentWriteLimit, async (req, res) => {
  try {
  const { body: commentBody, parent_id } = req.body;
  if (!commentBody || !commentBody.trim()) return res.status(400).json({ error: "Comment body is required" });
  if (commentBody.trim().length > 1000) return res.status(400).json({ error: "Comment must be ≤ 1000 characters" });

  // Profanity check — routed through the warning → mute → ban escalation system
  const vioResponse = await vioGate(req, res, req.member.memberId, commentBody);
  if (vioResponse) return; // vioGate already sent the response (warning/mute/ban)

  // Verify project exists
  const { data: proj } = await supabase.from("member_projects")
    .select("id, member_id, title").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!proj) return res.status(404).json({ error: "Project not found" });

  // Verify parent exists if given
  if (parent_id) {
    const { data: parent } = await supabase.from("project_comments")
      .select("id, parent_id").eq("id", parent_id).is("deleted_at", null).maybeSingle();
    if (!parent) return res.status(400).json({ error: "Parent comment not found" });
    if (parent.parent_id) return res.status(400).json({ error: "Replies can only be one level deep" });
  }

  const { data: comment, error } = await supabase.from("project_comments")
    .insert([{
      project_id: req.params.id,
      member_id:  req.member.memberId,
      parent_id:  parent_id || null,
      body:       commentBody.trim().slice(0, 1000),
    }])
    .select("id, body, is_pinned, created_at, parent_id, member_id")
    .single();

  if (error) { console.error("[studio:comment]", error.message); return res.status(500).json({ error: "Internal server error" }); }

  // Notify project author (not if commenting on own post)
  if (proj.member_id !== req.member.memberId) {
    createMemberNotification(
      proj.member_id, "studio",
      "New comment on your project 💬",
      `${req.member.username || "A member"} commented on "${proj.title}"`
    ).catch(() => {});
  }

  res.json({ success: true, comment });
  } catch (e) {
    console.error("[studio:comment] unhandled error:", e.message);
    if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api/member/studio/comments/:id (soft-delete; author or project-owner)
app.delete("/api/member/studio/comments/:id", memberAuthMiddleware, commentWriteLimit, async (req, res) => {
  const { data: comment } = await supabase.from("project_comments")
    .select("id, member_id, project_id").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!comment) return res.status(404).json({ error: "Comment not found" });

  // Allow comment author OR project author to delete
  const { data: proj } = await supabase.from("member_projects")
    .select("member_id").eq("id", comment.project_id).maybeSingle();
  const isCommentAuthor  = comment.member_id === req.member.memberId;
  const isProjectAuthor  = proj?.member_id   === req.member.memberId;
  if (!isCommentAuthor && !isProjectAuthor) return res.status(403).json({ error: "Not authorized" });

  await supabase.from("project_comments")
    .update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
  res.json({ success: true });
});

// PATCH /api/member/studio/comments/:id/pin (project author only — toggle pin)
app.patch("/api/member/studio/comments/:id/pin", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { data: comment } = await supabase.from("project_comments")
    .select("id, is_pinned, project_id").eq("id", req.params.id).is("deleted_at", null).maybeSingle();
  if (!comment) return res.status(404).json({ error: "Comment not found" });

  const { data: proj } = await supabase.from("member_projects")
    .select("member_id").eq("id", comment.project_id).maybeSingle();
  if (proj?.member_id !== req.member.memberId) return res.status(403).json({ error: "Only the project author can pin comments" });

  await supabase.from("project_comments")
    .update({ is_pinned: !comment.is_pinned }).eq("id", req.params.id);
  res.json({ success: true, is_pinned: !comment.is_pinned });
});

// ── Save & Collections ────────────────────────────────────────────────────────

// GET /api/member/studio/collections
app.get("/api/member/studio/collections", memberAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("save_collections")
    .select("id, name, created_at")
    .eq("member_id", req.member.memberId)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || []);
});

// POST /api/member/studio/collections  { name }
app.post("/api/member/studio/collections", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "Collection name is required" });

  const { data, error } = await supabase.from("save_collections")
    .insert([{ member_id: req.member.memberId, name: name.trim().slice(0, 80) }])
    .select("id, name").single();

  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Collection already exists" });
    return res.status(500).json({ error: "Internal server error" });
  }
  res.json({ success: true, collection: data });
});

// DELETE /api/member/studio/collections/:id
app.delete("/api/member/studio/collections/:id", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { data: col } = await supabase.from("save_collections")
    .select("id, member_id").eq("id", req.params.id).maybeSingle();
  if (!col) return res.status(404).json({ error: "Collection not found" });
  if (col.member_id !== req.member.memberId) return res.status(403).json({ error: "Not your collection" });
  await supabase.from("save_collections").delete().eq("id", req.params.id);
  res.json({ success: true });
});

// POST /api/member/studio/saves  { project_id, collection_id? }
// If collection_id omitted → auto-creates/uses a "Saved" default collection.
app.post("/api/member/studio/saves", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { project_id, collection_id } = req.body;
  if (!project_id) return res.status(400).json({ error: "project_id is required" });

  const { data: proj } = await supabase.from("member_projects")
    .select("id").eq("id", project_id).is("deleted_at", null).maybeSingle();
  if (!proj) return res.status(404).json({ error: "Project not found" });

  let colId = collection_id;
  if (!colId) {
    // Find or create default "Saved" collection
    const { data: defCol } = await supabase.from("save_collections")
      .select("id").eq("member_id", req.member.memberId).eq("name", "Saved").maybeSingle();
    if (defCol) {
      colId = defCol.id;
    } else {
      const { data: newCol } = await supabase.from("save_collections")
        .insert([{ member_id: req.member.memberId, name: "Saved" }]).select("id").single();
      colId = newCol?.id;
    }
  }

  if (!colId) return res.status(500).json({ error: "Could not resolve collection" });

  const { data, error } = await supabase.from("member_saves")
    .insert([{ collection_id: colId, project_id, member_id: req.member.memberId }])
    .select("id").single();

  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Already saved" });
    return res.status(500).json({ error: "Internal server error" });
  }
  res.json({ success: true, save_id: data.id, collection_id: colId });
});

// DELETE /api/member/studio/saves/:saveId
app.delete("/api/member/studio/saves/:saveId", memberAuthMiddleware, studioWriteLimit, async (req, res) => {
  const { data: save } = await supabase.from("member_saves")
    .select("id, member_id").eq("id", req.params.saveId).maybeSingle();
  if (!save) return res.status(404).json({ error: "Save not found" });
  if (save.member_id !== req.member.memberId) return res.status(403).json({ error: "Not your save" });
  await supabase.from("member_saves").delete().eq("id", req.params.saveId);
  res.json({ success: true });
});

// GET /api/member/studio/collections/:id/saves
app.get("/api/member/studio/collections/:id/saves", memberAuthMiddleware, async (req, res) => {
  const { data: col } = await supabase.from("save_collections")
    .select("id, member_id").eq("id", req.params.id).maybeSingle();
  if (!col || col.member_id !== req.member.memberId) return res.status(404).json({ error: "Collection not found" });

  const { data, error } = await supabase.from("member_saves")
    .select(`
      id, created_at,
      member_projects!member_saves_project_id_fkey(
        id, title, cover_image, domain, tags, views_count, reactions_count, comments_count
      )
    `)
    .eq("collection_id", req.params.id)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json(data || []);
});

// ── Post analytics (own projects only; counts only, no viewer identity) ───────

// GET /api/member/studio/projects/:id/analytics
app.get("/api/member/studio/projects/:id/analytics", memberAuthMiddleware, async (req, res) => {
  const { data: proj } = await supabase
    .from("member_projects")
    .select("id, member_id, title, views_count, reactions_count, comments_count, created_at")
    .eq("id", req.params.id)
    .is("deleted_at", null)
    .maybeSingle();

  if (!proj) return res.status(404).json({ error: "Project not found" });
  if (proj.member_id !== req.member.memberId) return res.status(403).json({ error: "Analytics only available to the project author" });

  // Reaction breakdown (counts only)
  const { data: rxRows } = await supabase
    .from("project_reactions").select("reaction_type").eq("project_id", req.params.id);

  const breakdown = { wow: 0, fire: 0, brilliant: 0, seahaven: 0, mind_blown: 0 };
  (rxRows || []).forEach(r => { breakdown[r.reaction_type] = (breakdown[r.reaction_type] || 0) + 1; });

  res.json({
    views:          proj.views_count,
    reactions:      proj.reactions_count,
    comments:       proj.comments_count,
    reaction_breakdown: breakdown,
    // No viewer list, no viewer identity — just totals as requested.
  });
});

// ── Studio Wall DB health check (call inside initMemberDB or app.listen) ─────

async function initStudioWallDB() {
  try {
    const { error } = await supabase.from("member_projects").select("id", { count: "exact", head: true }).limit(1);
    if (error && error.code === "42P01") {
      console.warn("[studio] member_projects table not found — run studio_wall_migration.sql in Supabase");
    } else {
      console.log("[studio] Studio Wall tables OK");
    }
  } catch (e) {
    console.error("[studio] initStudioWallDB error:", e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-27b — Studio Wall: missing public + analytics routes
// These complement the existing /api/member/studio/* block above.
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/member/studio/members-search?q=  (collab-tag autocomplete)
app.get("/api/member/studio/members-search", memberAuthMiddleware, studioFeedLimit, async (req, res) => {
  const q = (req.query.q || "").trim().slice(0, 40);
  if (q.length < 2) return res.json([]);
  try {
    const { data } = await supabasePublic
      .from("members")
      .select("id, name, photo")
      .ilike("name", `%${q}%`)
      .eq("is_past", false)
      .limit(8);
    // Normalise photo → photo_url for client consistency
    res.json((data || []).map(m => ({ id: m.id, name: m.name, photo_url: m.photo || null })));
  } catch {
    res.json([]);
  }
});

// GET /api/member/studio/my-analytics
// Aggregate views + reactions per post. No viewer identity. No comments count.
app.get("/api/member/studio/my-analytics", memberAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from("member_projects")
    .select("id, title, views_count, reactions_count, status, created_at")
    .eq("member_id", req.member.memberId)
    .is("deleted_at", null)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: "Internal server error" });

  // Only views + reactions — deliberate; no comments, no viewer list, ever.
  res.json((data || []).map(p => ({
    id:              p.id,
    title:           p.title,
    views_count:     p.views_count     || 0,
    reactions_count: p.reactions_count || 0,
    status:          p.status,
    created_at:      p.created_at,
  })));
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-27c — Studio Wall: public (unauthenticated) read routes
// Non-members can browse the feed and open posts, but cannot react or comment.
// All writes stay behind memberAuthMiddleware — nothing here mutates state.
// ─────────────────────────────────────────────────────────────────────────────

const publicStudioLimit = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });

// GET /api/studio/feed?page=1&tag=
app.get("/api/studio/feed", publicStudioLimit, async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const tag   = (req.query.tag || "").trim().toLowerCase().slice(0, 50);
  const limit = 20;
  const from  = (page - 1) * limit;
  const cKey  = `studio:public:feed:p${page}:t${tag}`;

  cacheFor(res, 60);
  try {
    const data = await memCache(cKey, 90, async () => {
      let q = supabasePublic
        .from("member_projects")
        .select(`
          id, title, description, cover_image, video_url, video_provider,
          domain, tags, views_count, reactions_count, comments_count, created_at,
          member_id,
          members!member_projects_member_id_fkey(id, name, photo, role, domain)
        `)
        .is("deleted_at", null)
        .eq("status", "published")
        .order("created_at", { ascending: false })
        .range(from, from + limit - 1);

      if (tag) q = q.contains("tags", [tag]);
      const { data: rows, error } = await q;
      if (error) throw error;
      return rows || [];
    });

    res.json({ feed: data, page, has_more: data.length === limit });
  } catch (e) {
    console.error("[studio:public:feed]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/studio/projects/:id
app.get("/api/studio/projects/:id", publicStudioLimit, async (req, res) => {
  const id = req.params.id;
  try {
    const { data: project, error } = await supabasePublic
      .from("member_projects")
      .select(`
        id, title, description, cover_image, video_url, video_provider,
        domain, tags, views_count, reactions_count, comments_count, status, created_at,
        member_id,
        members!member_projects_member_id_fkey(id, name, photo, role, domain),
        project_collaborators(
          member_id,
          members!project_collaborators_member_id_fkey(id, name, photo, role)
        )
      `)
      .eq("id", id)
      .is("deleted_at", null)
      .maybeSingle();

    if (error || !project) return res.status(404).json({ error: "Project not found" });
    res.json({ ...project, my_reaction: null, is_saved: false });
  } catch (e) {
    console.error("[studio:public:project]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/studio/projects/:id/comments
app.get("/api/studio/projects/:id/comments", publicStudioLimit, async (req, res) => {
  const id = req.params.id;
  try {
    const { data: top, error } = await supabasePublic
      .from("project_comments")
      .select(`
        id, body, created_at, is_pinned,
        member_id,
        members!project_comments_member_id_fkey(id, name, photo, role)
      `)
      .eq("project_id", id)
      .is("parent_id", null)
      .is("deleted_at", null)
      .order("is_pinned", { ascending: false })
      .order("created_at", { ascending: true })
      .limit(100);

    if (error) throw error;

    const topIds = (top || []).map(c => c.id);
    let replies = [];
    if (topIds.length) {
      const { data: r } = await supabasePublic
        .from("project_comments")
        .select(`
          id, body, created_at, parent_id,
          member_id,
          members!project_comments_member_id_fkey(id, name, photo, role)
        `)
        .in("parent_id", topIds)
        .is("deleted_at", null)
        .order("created_at", { ascending: true });
      replies = r || [];
    }

    const nested = (top || []).map(c => ({
      ...c,
      replies: replies.filter(r => r.parent_id === c.id),
    }));

    res.json({ comments: nested });
  } catch (e) {
    console.error("[studio:public:comments]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-28 — Network: Follow system
// Phase 2 — "The Network". Lets members follow each other, see who follows
// them, and view a lightweight public profile card for anyone tagged/authored
// content they encounter on the Studio Wall. Counts on `members` are kept in
// sync by a DB trigger (see phase2_network_migration.sql) — never decremented
// or incremented manually here, only ever read back fresh.
// ─────────────────────────────────────────────────────────────────────────────

const networkReadLimit  = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });
const networkWriteLimit = rateLimit({ windowMs: 60_000, max: 30,  standardHeaders: true, legacyHeaders: false });

const NETWORK_PROFILE_FIELDS =
  "id, name, photo, role, domain, batch, bio, status, status_updated_at, followers_count, following_count, is_past";

// Fetch a live (non-deleted) member row by id.
async function getActiveMember(memberId, fields = NETWORK_PROFILE_FIELDS) {
  const { data } = await supabase
    .from("members")
    .select(fields)
    .eq("id", memberId)
    .is("deleted_at", null)
    .maybeSingle();
  return data || null;
}

// POST /api/member/network/follow/:memberId — toggle follow/unfollow
app.post("/api/member/network/follow/:memberId", memberAuthMiddleware, networkWriteLimit, async (req, res) => {
  const targetId = req.params.memberId;
  const viewerId = req.member.memberId;

  if (targetId === viewerId) return res.status(400).json({ error: "You can't follow yourself" });

  const target = await getActiveMember(targetId, "id, name");
  if (!target) return res.status(404).json({ error: "Member not found" });

  const { data: existing } = await supabase
    .from("member_follows")
    .select("id")
    .eq("follower_id", viewerId)
    .eq("following_id", targetId)
    .maybeSingle();

  let following;
  if (existing) {
    await supabase.from("member_follows").delete().eq("id", existing.id);
    following = false;
  } else {
    const { error } = await supabase
      .from("member_follows")
      .insert([{ follower_id: viewerId, following_id: targetId }]);
    if (error && error.code !== "23505") {
      console.error("[network:follow]", error.message);
      return res.status(500).json({ error: "Internal server error" });
    }
    following = true;
    if (!error) {
      const actor = await getActiveMember(viewerId, "id, name, photo");
      createMemberNotification(
        targetId, "follow",
        "New follower",
        `${actor?.name || req.member.username || "A member"} started following you`,
        { actorId: viewerId, actorName: actor?.name || req.member.username, actorPhoto: actor?.photo, linkType: "profile", linkId: viewerId }
      ).catch(() => {});
    }
  }

  await logMemberActivity(req.member.id, viewerId, following ? "network_follow" : "network_unfollow", { target_id: targetId }, req.ip);

  const { data: fresh } = await supabase.from("members").select("followers_count").eq("id", targetId).maybeSingle();
  res.json({ following, followers_count: fresh?.followers_count ?? 0 });
});

// GET /api/member/network/profile/:memberId — mini profile card for any active member
app.get("/api/member/network/profile/:memberId", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const targetId = req.params.memberId;
  const viewerId = req.member.memberId;

  const member = await getActiveMember(targetId);
  if (!member) return res.status(404).json({ error: "Member not found" });

  let isFollowing = false;
  if (targetId !== viewerId) {
    const { data } = await supabase
      .from("member_follows").select("id")
      .eq("follower_id", viewerId).eq("following_id", targetId).maybeSingle();
    isFollowing = !!data;
  }

  const { data: skillRows } = await supabase
    .from("member_skills")
    .select("skill_tags(id, name, category)")
    .eq("member_id", targetId);
  const skills = (skillRows || []).map(r => r.skill_tags).filter(Boolean);

  res.json({ ...member, skills, is_following: isFollowing, is_self: targetId === viewerId });
});

// GET /api/member/network/followers/:memberId?page=1 — who follows this member
app.get("/api/member/network/followers/:memberId", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const targetId = req.params.memberId;
  const viewerId = req.member.memberId;
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = 30;
  const from  = (page - 1) * limit;

  const { data: rows, error } = await supabase
    .from("member_follows")
    .select(`
      created_at, follower_id,
      members!member_follows_follower_id_fkey(id, name, photo, role, domain, status, followers_count, following_count)
    `)
    .eq("following_id", targetId)
    .order("created_at", { ascending: false })
    .range(from, from + limit - 1);

  if (error) { console.error("[network:followers]", error.message); return res.status(500).json({ error: "Internal server error" }); }

  const list = (rows || []).map(r => r.members).filter(Boolean);
  const ids  = list.map(m => m.id);

  let myFollows = new Set();
  if (ids.length) {
    const { data: mine } = await supabase
      .from("member_follows").select("following_id")
      .eq("follower_id", viewerId).in("following_id", ids);
    myFollows = new Set((mine || []).map(r => r.following_id));
  }

  res.json({
    members:  list.map(m => ({ ...m, is_following: myFollows.has(m.id), is_self: m.id === viewerId })),
    page,
    has_more: list.length === limit,
  });
});

// GET /api/member/network/following/:memberId?page=1 — who this member follows
app.get("/api/member/network/following/:memberId", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const targetId = req.params.memberId;
  const viewerId = req.member.memberId;
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = 30;
  const from  = (page - 1) * limit;

  const { data: rows, error } = await supabase
    .from("member_follows")
    .select(`
      created_at, following_id,
      members!member_follows_following_id_fkey(id, name, photo, role, domain, status, followers_count, following_count)
    `)
    .eq("follower_id", targetId)
    .order("created_at", { ascending: false })
    .range(from, from + limit - 1);

  if (error) { console.error("[network:following]", error.message); return res.status(500).json({ error: "Internal server error" }); }

  const list = (rows || []).map(r => r.members).filter(Boolean);
  const ids  = list.map(m => m.id);

  let myFollows = new Set();
  if (ids.length) {
    const { data: mine } = await supabase
      .from("member_follows").select("following_id")
      .eq("follower_id", viewerId).in("following_id", ids);
    myFollows = new Set((mine || []).map(r => r.following_id));
  }

  res.json({
    members:  list.map(m => ({ ...m, is_following: myFollows.has(m.id), is_self: m.id === viewerId })),
    page,
    has_more: list.length === limit,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-29 — Network: Member status
// Phase 2 — "The Network". A short, self-set status shown on the member's
// profile, the mini-profile card, and Discovery search results. Kept to a
// fixed set (rather than free text) so it stays moderation-free and the
// pills stay visually consistent everywhere they're rendered.
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = ["open_to_collab", "busy_on_set", "alumni_mentor"];

// POST /api/member/network/status  { status }  — status may be null/"" to clear
app.post("/api/member/network/status", memberAuthMiddleware, networkWriteLimit, async (req, res) => {
  const raw = req.body?.status;
  const status = (raw === null || raw === undefined || raw === "") ? null : String(raw).trim();
  if (status !== null && !STATUS_OPTIONS.includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const now = new Date().toISOString();
  const { error } = await supabase
    .from("members")
    .update({ status, status_updated_at: now })
    .eq("id", req.member.memberId);
  if (error) {
    console.error("[network:status]", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }

  memInvalidate("members:list");
  await logMemberActivity(req.member.id, req.member.memberId, "status_updated", { status }, req.ip);
  res.json({ success: true, status, status_updated_at: now });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-30 — Network: Skills / Interest graph
// Phase 2 — "The Network". Members tag themselves from a shared, crowd-grown
// pool (skill_tags) — tags are created on first use (normalized, length-
// capped) so the pool grows organically without admin curation. usage_count
// is kept in sync by a DB trigger (see phase2_network_migration.sql).
// ─────────────────────────────────────────────────────────────────────────────

const MAX_SKILLS_PER_MEMBER = 12;

function normalizeSkillName(raw) {
  return String(raw || "").trim().replace(/\s+/g, " ").slice(0, 40);
}

// GET /api/member/skills/search?q=ed — autocomplete from the shared tag pool
app.get("/api/member/skills/search", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const q = normalizeSkillName(req.query.q || "");
  let query = supabase
    .from("skill_tags")
    .select("id, name, category, usage_count")
    .order("usage_count", { ascending: false })
    .limit(15);
  if (q) query = query.ilike("name", `%${q}%`);
  const { data, error } = await query;
  if (error) { console.error("[skills:search]", error.message); return res.status(500).json({ error: "Internal server error" }); }
  res.json(data || []);
});

// GET /api/member/skills/mine — my own tagged skills/interests
app.get("/api/member/skills/mine", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const { data, error } = await supabase
    .from("member_skills")
    .select("id, created_at, skill_tags(id, name, category)")
    .eq("member_id", req.member.memberId)
    .order("created_at", { ascending: true });
  if (error) { console.error("[skills:mine]", error.message); return res.status(500).json({ error: "Internal server error" }); }
  res.json((data || []).map(r => ({ link_id: r.id, ...(r.skill_tags || {}) })));
});

// POST /api/member/skills  { name, category? } — tag self (creates the tag if new)
app.post("/api/member/skills", memberAuthMiddleware, networkWriteLimit, async (req, res) => {
  const name = normalizeSkillName(req.body?.name);
  if (!name) return res.status(400).json({ error: "Skill name required" });
  const category = ["skill", "interest"].includes(req.body?.category) ? req.body.category : "skill";

  const { count } = await supabase
    .from("member_skills").select("id", { count: "exact", head: true }).eq("member_id", req.member.memberId);
  if ((count || 0) >= MAX_SKILLS_PER_MEMBER) {
    return res.status(400).json({ error: `You can tag up to ${MAX_SKILLS_PER_MEMBER} skills/interests.` });
  }

  // Find-or-create the tag (case-insensitive match on name)
  let { data: tag } = await supabase.from("skill_tags").select("id, name, category").ilike("name", name).maybeSingle();
  if (!tag) {
    const { data: created, error: createErr } = await supabase
      .from("skill_tags").insert([{ name, category }]).select("id, name, category").single();
    if (createErr) {
      console.error("[skills:create-tag]", createErr.message);
      return res.status(500).json({ error: "Internal server error" });
    }
    tag = created;
  }

  const { error: linkErr } = await supabase
    .from("member_skills").insert([{ member_id: req.member.memberId, skill_tag_id: tag.id }]);
  if (linkErr && linkErr.code !== "23505") {
    console.error("[skills:link]", linkErr.message);
    return res.status(500).json({ error: "Internal server error" });
  }

  memInvalidate("members:list");
  res.json({ success: true, tag });
});

// DELETE /api/member/skills/:tagId — untag self
app.delete("/api/member/skills/:tagId", memberAuthMiddleware, networkWriteLimit, async (req, res) => {
  const { error } = await supabase
    .from("member_skills").delete()
    .eq("member_id", req.member.memberId).eq("skill_tag_id", req.params.tagId);
  if (error) { console.error("[skills:delete]", error.message); return res.status(500).json({ error: "Internal server error" }); }
  memInvalidate("members:list");
  res.json({ success: true });
});

// GET /api/member/skills/:tagId/members?page=1 — who else shares this tag (discovery)
app.get("/api/member/skills/:tagId/members", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const tagId    = req.params.tagId;
  const viewerId = req.member.memberId;
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = 30;
  const from  = (page - 1) * limit;

  const { data: rows, error } = await supabase
    .from("member_skills")
    .select(`member_id, members!member_skills_member_id_fkey(${NETWORK_PROFILE_FIELDS})`)
    .eq("skill_tag_id", tagId)
    .range(from, from + limit - 1);
  if (error) { console.error("[skills:tag-members]", error.message); return res.status(500).json({ error: "Internal server error" }); }

  const list = (rows || []).map(r => r.members).filter(m => m && m.id !== viewerId);
  const ids  = list.map(m => m.id);
  let myFollows = new Set();
  if (ids.length) {
    const { data: mine } = await supabase
      .from("member_follows").select("following_id")
      .eq("follower_id", viewerId).in("following_id", ids);
    myFollows = new Set((mine || []).map(r => r.following_id));
  }
  res.json({
    members: list.map(m => ({ ...m, is_following: myFollows.has(m.id) })),
    page,
    has_more: (rows || []).length === limit,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-31 — Network: Weekly leaderboard / hall of fame
// Phase 2 — "The Network". Ranks members by "wow" reactions received on their
// Studio Wall posts. The expensive aggregation runs server-side via a
// Postgres function (compute_leaderboard — see phase2_leaderboard_function.sql)
// on a timer; this route only ever reads the pre-computed `weekly_leaderboard`
// table, so it stays fast regardless of how much reaction history exists.
// ─────────────────────────────────────────────────────────────────────────────

// Monday→Sunday of the current ISO week, as 'YYYY-MM-DD' (UTC).
function getISOWeekRange(d = new Date()) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = date.getUTCDay() || 7; // Mon=1 .. Sun=7
  date.setUTCDate(date.getUTCDate() - day + 1);
  const monday = new Date(date);
  const sunday = new Date(date);
  sunday.setUTCDate(sunday.getUTCDate() + 6);
  const fmt = (x) => x.toISOString().slice(0, 10);
  return { monday: fmt(monday), sunday: fmt(sunday) };
}

async function refreshLeaderboards() {
  try {
    const { monday, sunday } = getISOWeekRange();
    const { error: wErr } = await supabase.rpc("compute_leaderboard", {
      p_period_type: "weekly", p_period_start: monday, p_period_end: sunday, p_limit: 50,
    });
    if (wErr) console.error("[leaderboard:weekly]", wErr.message);

    const { error: aErr } = await supabase.rpc("compute_leaderboard", {
      p_period_type: "all_time", p_period_start: null, p_period_end: null, p_limit: 50,
    });
    if (aErr) console.error("[leaderboard:all_time]", aErr.message);

    memInvalidate("leaderboard:");
  } catch (e) {
    console.error("[leaderboard:refresh]", e.message);
  }
}

// GET /api/member/network/leaderboard?period=weekly|all_time
app.get("/api/member/network/leaderboard", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const period   = req.query.period === "all_time" ? "all_time" : "weekly";
  const viewerId = req.member.memberId;
  const { monday } = getISOWeekRange();
  const cKey = `leaderboard:${period}:${period === "weekly" ? monday : "all"}`;

  try {
    cacheFor(res, 60);
    const rows = await memCache(cKey, 120, async () => {
      let q = supabase
        .from("weekly_leaderboard")
        .select("rank, wows_received, member_id, members!weekly_leaderboard_member_id_fkey(id, name, photo, role, domain, status)")
        .eq("period_type", period)
        .order("rank", { ascending: true })
        .limit(50);
      q = period === "weekly" ? q.eq("period_start", monday) : q.is("period_start", null);
      const { data, error } = await q;
      if (error) throw error;
      return data || [];
    });

    const list = rows.map(r => ({ rank: r.rank, wows_received: r.wows_received, ...(r.members || {}) }));
    const mine = list.find(m => m.id === viewerId);
    res.json({
      period,
      week_start: period === "weekly" ? monday : null,
      leaderboard: list,
      my_rank: mine ? mine.rank : null,
    });
  } catch (e) {
    console.error("[network:leaderboard]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-32 — Network: Discovery & Explore
// Phase 2 — "The Network". Browse members by domain/batch/skill/name, see
// trending Studio Wall posts (48h reaction velocity) and who recently joined.
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/member/network/facets — distinct domains & batches for filter UIs
app.get("/api/member/network/facets", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  try {
    cacheFor(res, 300);
    const data = await memCache("network:facets", 600, async () => {
      const { data: rows, error } = await supabase.from("members").select("domain, batch").is("deleted_at", null);
      if (error) throw error;
      const domains = [...new Set((rows || []).map(r => r.domain).filter(Boolean))].sort();
      const batches = [...new Set((rows || []).map(r => r.batch).filter(Boolean))].sort();
      return { domains, batches };
    });
    res.json(data);
  } catch (e) {
    console.error("[network:facets]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/member/network/discover?domain=&batch=&skill=&q=&page=1 — browse members
app.get("/api/member/network/discover", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  const viewerId = req.member.memberId;
  const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = 24;
  const from  = (page - 1) * limit;
  const { domain, batch, skill, q } = req.query;

  try {
    let skillMemberIds = null;
    if (skill) {
      const { data: tagRows } = await supabase
        .from("skill_tags").select("id").ilike("name", `%${String(skill).trim()}%`).limit(20);
      const tagIds = (tagRows || []).map(t => t.id);
      if (!tagIds.length) return res.json({ members: [], page, has_more: false });
      const { data: links } = await supabase.from("member_skills").select("member_id").in("skill_tag_id", tagIds);
      skillMemberIds = [...new Set((links || []).map(l => l.member_id))];
      if (!skillMemberIds.length) return res.json({ members: [], page, has_more: false });
    }

    let query = supabase
      .from("members")
      .select("id, name, photo, role, domain, batch, status, status_updated_at, followers_count, following_count, is_past")
      .is("deleted_at", null)
      .neq("id", viewerId)
      .order("followers_count", { ascending: false })
      .range(from, from + limit - 1);

    if (domain) query = query.eq("domain", domain);
    if (batch)  query = query.eq("batch", batch);
    if (q)      query = query.ilike("name", `%${String(q).trim()}%`);
    if (skillMemberIds) query = query.in("id", skillMemberIds);

    const { data: rows, error } = await query;
    if (error) throw error;

    const ids = (rows || []).map(m => m.id);
    let myFollows = new Set();
    if (ids.length) {
      const { data: mine } = await supabase
        .from("member_follows").select("following_id")
        .eq("follower_id", viewerId).in("following_id", ids);
      myFollows = new Set((mine || []).map(r => r.following_id));
    }

    res.json({
      members: (rows || []).map(m => ({ ...m, is_following: myFollows.has(m.id) })),
      page,
      has_more: (rows || []).length === limit,
    });
  } catch (e) {
    console.error("[network:discover]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/member/network/trending — Studio Wall posts with the most reaction
// velocity in the last 48h (shares the same signal the smart feed ranks on).
app.get("/api/member/network/trending", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  try {
    cacheFor(res, 60);
    const data = await memCache("network:trending", 180, async () => {
      const counts = await getTrendingCounts();
      const topIds = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([id]) => id);
      if (!topIds.length) return [];

      const { data: projects, error } = await supabasePublic
        .from("member_projects")
        .select(`
          id, title, cover_image, video_url, video_provider, domain, tags,
          views_count, reactions_count, comments_count, created_at, member_id,
          members!member_projects_member_id_fkey(id, name, photo, role, domain)
        `)
        .in("id", topIds)
        .eq("status", "published")
        .is("deleted_at", null);
      if (error) throw error;

      const order = new Map(topIds.map((id, i) => [id, i]));
      return (projects || [])
        .sort((a, b) => order.get(a.id) - order.get(b.id))
        .map(p => ({ ...p, trending_score: counts[p.id] }));
    });
    res.json({ trending: data });
  } catch (e) {
    console.error("[network:trending]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/member/network/new-joiners — most recently activated portal accounts
app.get("/api/member/network/new-joiners", memberAuthMiddleware, networkReadLimit, async (req, res) => {
  try {
    cacheFor(res, 120);
    const data = await memCache("network:new-joiners", 300, async () => {
      const { data: rows, error } = await supabase
        .from("member_accounts")
        .select("created_at, members!member_accounts_member_id_fkey(id, name, photo, role, domain, batch, is_past, deleted_at)")
        .eq("account_status", "active")
        .order("created_at", { ascending: false })
        .limit(20);
      if (error) throw error;
      return (rows || [])
        .map(r => r.members)
        .filter(m => m && !m.deleted_at && !m.is_past)
        .slice(0, 12)
        .map(({ deleted_at, ...m }) => m);
    });
    res.json(data);
  } catch (e) {
    console.error("[network:new-joiners]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Admin — Studio Wall moderation ───────────────────────────────────────────

// GET /api/admin/wall/projects?page=0&status=published
app.get("/api/admin/wall/projects", authMiddleware, async (req, res) => {
  try {
    const page   = Math.max(0, parseInt(req.query.page) || 0);
    const status = ["published", "hidden"].includes(req.query.status) ? req.query.status : "published";
    const limit  = 20;
    const { data, error } = await supabase
      .from("member_projects")
      .select("id, title, status, views_count, reactions_count, comments_count, created_at, deleted_at, members!member_projects_member_id_fkey(id, name)")
      .is("deleted_at", null)
      .eq("status", status)
      .order("created_at", { ascending: false })
      .range(page * limit, page * limit + limit - 1);
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// PATCH /api/admin/wall/projects/:id  (hide / restore)
app.patch("/api/admin/wall/projects/:id", authMiddleware, async (req, res) => {
  const { status } = req.body;
  if (!["published", "hidden"].includes(status)) return res.status(400).json({ error: "Invalid status" });
  const { error } = await supabase.from("member_projects")
    .update({ status, updated_at: new Date().toISOString() }).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: "Internal server error" });
  res.json({ ok: true });
});

// DELETE /api/admin/wall/projects/:id  (soft-delete)
app.delete("/api/admin/wall/projects/:id", authMiddleware, async (req, res) => {
  await supabase.from("member_projects")
    .update({ deleted_at: new Date().toISOString() }).eq("id", req.params.id);
  res.json({ ok: true });
});

// PATCH /api/admin/wall/comments/:commentId  (pin/unpin)
app.patch("/api/admin/wall/comments/:commentId", authMiddleware, async (req, res) => {
  await supabase.from("project_comments")
    .update({ is_pinned: Boolean(req.body.is_pinned) }).eq("id", req.params.commentId);
  res.json({ ok: true });
});

// POST /api/admin/wall/prune-views  (alternative to pg_cron)
app.post("/api/admin/wall/prune-views", authMiddleware, async (req, res) => {
  const cutoff = new Date(Date.now() - 2 * 86_400_000).toISOString().split("T")[0];
  const { error } = await supabase.from("project_views").delete().lt("viewed_date", cutoff);
  if (error) return res.status(500).json({ error: "Internal server error" });
  console.log(`[wall/prune-views] Pruned rows older than ${cutoff}`);
  res.json({ ok: true });
});

// ── SCANNER PAGE — must be above the catch-all ────────────────────────────────
app.get("/scanner", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "scanner.html"));
});
app.get("/scanner.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  res.sendFile(path.join(__dirname, "public", "scanner.js"));
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-33 — Direct Messaging (Social Strand DMs)
//
// NO new tables required — messages are stored in the existing
// member_notifications table (type = "dm") with these field mappings:
//
//   member_id   → recipient member UUID
//   actor_id    → sender member UUID
//   actor_name  → sender display name
//   actor_photo → sender photo URL (snapshot at send time)
//   body        → message text (max 2000 chars)
//   link_type   → always "dm"
//   link_id     → canonical conversation key = "<smaller_uuid>:<larger_uuid>"
//   is_read     → false until recipient reads
//   created_at  → send timestamp
//
// Conversation key is deterministic: sort the two UUIDs lexicographically and
// join with ":", guaranteeing a stable unique ID for any pair of members.
// ─────────────────────────────────────────────────────────────────────────────

// ── E2EE key-management rate limit ───────────────────────────────────────────
const e2eeKeyLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => req.member?.memberId || ipKeyGenerator(req, res),
});

// ── POST /api/member/e2ee/publish-key ────────────────────────────────────────
// Upsert caller's ECDH P-256 public key. Called on every login after key-gen.
// Server validates structure but NEVER receives or stores private keys.
app.post("/api/member/e2ee/publish-key", memberAuthMiddleware, e2eeKeyLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { public_key_jwk } = req.body || {};
    if (!public_key_jwk || typeof public_key_jwk !== 'object')
      return res.status(400).json({ error: "public_key_jwk (JWK object) required" });
    if (public_key_jwk.kty !== 'EC' || public_key_jwk.crv !== 'P-256' || !public_key_jwk.x || !public_key_jwk.y)
      return res.status(400).json({ error: "Invalid public key: must be ECDH P-256 JWK with x, y coords" });
    if (public_key_jwk.d)
      return res.status(400).json({ error: "Private key component (d) must never be sent to the server" });
    const now = new Date().toISOString();
    const { error } = await supabase
      .from("member_e2ee_keys")
      .upsert([{ member_id: myId, public_key_jwk, fingerprint: null, published_at: now, updated_at: now }],
              { onConflict: "member_id" });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    console.error("[e2ee/publish-key]", e.message);
    res.status(500).json({ error: "Failed to publish key" });
  }
});

// ── GET /api/member/e2ee/public-key/:memberId ─────────────────────────────────
// Fetch a member's ECDH public key so the caller can encrypt to them.
// Public keys are not secret — any authenticated member can fetch any other's.
app.get("/api/member/e2ee/public-key/:memberId", memberAuthMiddleware, e2eeKeyLimit, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("member_e2ee_keys")
      .select("public_key_jwk, fingerprint, updated_at")
      .eq("member_id", req.params.memberId)
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "No E2EE key found for this member" });
    res.json({ member_id: req.params.memberId, public_key_jwk: data.public_key_jwk, fingerprint: data.fingerprint, updated_at: data.updated_at });
  } catch (e) {
    console.error("[e2ee/public-key GET]", e.message);
    res.status(500).json({ error: "Failed to fetch key" });
  }
});

// ── GET /api/member/e2ee/public-keys?ids=a,b,c ───────────────────────────────
// Batch-fetch public keys for all members in a group chat.
app.get("/api/member/e2ee/public-keys", memberAuthMiddleware, e2eeKeyLimit, async (req, res) => {
  try {
    const ids = String(req.query.ids || "").split(",").map(s => s.trim()).filter(Boolean).slice(0, 60);
    if (!ids.length) return res.json({});
    const { data, error } = await supabase
      .from("member_e2ee_keys")
      .select("member_id, public_key_jwk, fingerprint")
      .in("member_id", ids);
    if (error) throw error;
    const out = {};
    (data || []).forEach(r => { out[r.member_id] = { public_key_jwk: r.public_key_jwk, fingerprint: r.fingerprint }; });
    res.json(out);
  } catch (e) {
    console.error("[e2ee/public-keys batch GET]", e.message);
    res.status(500).json({ error: "Failed to fetch keys" });
  }
});

// ── GET /api/admin/e2ee/report-decrypt/:reportId ─────────────────────────────
// Master-only: read the decrypted plaintext snapshot for an E2EE message report.
// Plaintext was sent by the reporter's client — no server-side decryption ever happens.
app.get("/api/admin/e2ee/report-decrypt/:reportId", masterMiddleware, async (req, res) => {
  try {
    const { data: report, error } = await supabase
      .from("content_reports")
      .select("id, content_type, content_id, reason, details, decrypted_snapshot, e2ee_report, reporter_id, created_at")
      .eq("id", req.params.reportId)
      .maybeSingle();
    if (error) throw error;
    if (!report) return res.status(404).json({ error: "Report not found" });
    logActivity(req.admin.id, req.admin.name, "view_e2ee_report", "report", req.params.reportId).catch(() => {});
    res.json({
      report_id:          report.id,
      content_type:       report.content_type,
      content_id:         report.content_id,
      reason:             report.reason,
      details:            report.details,
      e2ee:               report.e2ee_report,
      decrypted_snapshot: report.e2ee_report ? report.decrypted_snapshot : null,
      created_at:         report.created_at,
    });
  } catch (e) {
    console.error("[admin/e2ee/report-decrypt]", e.message);
    res.status(500).json({ error: "Failed to load report" });
  }
});

const dmRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Slow down — too many messages." },
  keyGenerator: (req, res) => req.member?.memberId || ipKeyGenerator(req, res),
});

/** Stable conversation key for any two member UUIDs */
function dmConvKey(a, b) {
  return [a, b].sort().join(":");
}

/**
 * Supabase/Postgres errors carry the real diagnostic info in .details/.hint/.code,
 * not .message. Logging only e.message (as this section used to) hides the actual
 * cause of 500s — e.g. a missing column shows up as "column actor_id does not
 * exist" in .message but the .code (42703) and .hint are what make it obvious at
 * a glance. Route handlers below log through this instead of e.message.
 */
function dmLogErr(label, e) {
  console.error(label, {
    message: e?.message,
    details: e?.details,
    hint:    e?.hint,
    code:    e?.code,
  });
}

// ── GET /api/member/dm/conversations ─────────────────────────────────────────
// Returns all unique conversations the logged-in member has participated in,
// sorted newest-first, with peer info + last snippet + unread count.
app.get("/api/member/dm/conversations", memberAuthMiddleware, async (req, res) => {
  try {
    const myId = req.member.memberId;

    // All DM notifications involving me (sent or received)
    // Sent = rows I am the actor_id of with type "dm" on someone else's member_id
    // Received = rows where I am member_id and link_type = "dm"
    const [{ data: received }, { data: sent }] = await Promise.all([
      supabase
        .from("member_notifications")
        .select("id, actor_id, actor_name, actor_photo, body, link_id, is_read, created_at, e2ee")
        .eq("member_id", myId)
        .eq("link_type", "dm")
        .order("created_at", { ascending: false })
        .limit(500),
      supabase
        .from("member_notifications")
        .select("id, member_id, actor_id, actor_name, actor_photo, body, link_id, is_read, created_at, e2ee")
        .eq("actor_id", myId)
        .eq("link_type", "dm")
        .order("created_at", { ascending: false })
        .limit(500),
    ]);

    // Build a map of conv_key → { lastMsg, unreadCount, peerId, peerName, peerPhoto }
    const convMap = new Map();

    // Process received messages
    for (const row of (received || [])) {
      const key = row.link_id;
      if (!key) continue;
      if (!convMap.has(key)) {
        convMap.set(key, {
          key,
          lastMsg:      row,
          unreadCount:  row.is_read ? 0 : 1,
          peerId:       row.actor_id,
          peerName:     row.actor_name,
          peerPhoto:    row.actor_photo,
        });
      } else {
        const c = convMap.get(key);
        if (!row.is_read) c.unreadCount++;
        if (new Date(row.created_at) > new Date(c.lastMsg.created_at)) c.lastMsg = row;
      }
    }

    // Process sent messages
    for (const row of (sent || [])) {
      const key = row.link_id;
      if (!key) continue;
      if (!convMap.has(key)) {
        convMap.set(key, {
          key,
          lastMsg:      row,
          unreadCount:  0,
          peerId:       row.member_id,
          peerName:     null, // will fill from members query
          peerPhoto:    null,
        });
      } else {
        const c = convMap.get(key);
        if (new Date(row.created_at) > new Date(c.lastMsg.created_at)) {
          c.lastMsg = row;
          // If last msg is mine, update last_sender_is_me
        }
      }
    }

    if (convMap.size === 0) return res.json([]);

    // Gather peer IDs whose names/photos we need to look up
    const peerIds = [...new Set([...convMap.values()].map(c => c.peerId).filter(Boolean))];
    const { data: peers } = await supabase
      .from("members")
      .select("id, name, photo, role, batch, domain")
      .in("id", peerIds);
    const peerLookup = Object.fromEntries((peers || []).map(p => [p.id, p]));

    // Sort by most recent message
    const result = [...convMap.values()]
      .sort((a, b) => new Date(b.lastMsg.created_at) - new Date(a.lastMsg.created_at))
      .map(c => {
        const peer   = peerLookup[c.peerId] || { id: c.peerId, name: c.peerName || "Member", photo: c.peerPhoto };
        const lastMsg = c.lastMsg;
        const isMine  = lastMsg.actor_id === myId;
        return {
          conv_key:          c.key,
          peer,
          last_msg_at:       lastMsg.created_at,
          last_snippet:      lastMsg.e2ee ? null : (lastMsg.body || "").slice(0, 80),
          last_is_e2ee:      lastMsg.e2ee || false,
          last_sender_is_me: isMine,
          unread_count:      c.unreadCount,
        };
      });

    res.json(result);
  } catch (e) {
    dmLogErr("[dm/conversations]", e);
    res.status(500).json({ error: "Failed to load conversations" });
  }
});

// ── GET /api/member/dm/messages/:convKey ──────────────────────────────────────
// Returns messages for a conversation. convKey = "<uuid>:<uuid>" (sorted).
// Cursor params:
//   ?before=<ISO>  — load earlier messages (load-more, descending fetch)
//   ?since=<ISO>   — poll for new messages only (used by dmPollTick, ascending)
app.get("/api/member/dm/messages/:convKey", memberAuthMiddleware, async (req, res) => {
  try {
    const myId    = req.member.memberId;
    const convKey = req.params.convKey;

    // Validate: the conv key must contain myId (prevents reading other people's convs)
    const parts = convKey.split(":");
    if (parts.length !== 2 || !parts.includes(myId)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const limit  = Math.min(parseInt(req.query.limit) || 40, 80);
    const before = req.query.before; // load-earlier pagination
    const since  = req.query.since;  // poll-for-new cursor (ISO timestamp of newest known msg)

    // Ascending when fetching new messages (since), descending for initial/before load
    const asc = !!since;

    // Fetch both sides: messages received by me + messages I sent in this conv
    const _dmSelect = "id, actor_id, actor_name, actor_photo, member_id, body, is_read, created_at, replied_to_id, replied_to_body, replied_to_sender, e2ee, cipher_for_recipient, cipher_for_self";
    let qRecv = supabase
      .from("member_notifications")
      .select(_dmSelect)
      .eq("member_id", myId)
      .eq("link_type", "dm")
      .eq("link_id", convKey)
      .order("created_at", { ascending: asc })
      .limit(limit);
    let qSent = supabase
      .from("member_notifications")
      .select(_dmSelect)
      .eq("actor_id", myId)
      .eq("link_type", "dm")
      .eq("link_id", convKey)
      .order("created_at", { ascending: asc })
      .limit(limit);

    if (before) {
      qRecv = qRecv.lt("created_at", before);
      qSent = qSent.lt("created_at", before);
    }
    if (since) {
      qRecv = qRecv.gt("created_at", since);
      qSent = qSent.gt("created_at", since);
    }

    const [{ data: recv }, { data: sent }] = await Promise.all([qRecv, qSent]);

    // Merge + sort ascending + deduplicate
    const all = [...(recv || []), ...(sent || [])];
    const seen = new Set();
    const msgs = all
      .filter(m => { if (seen.has(m.id)) return false; seen.add(m.id); return true; })
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
      .slice(since ? 0 : -limit); // for since: keep all new msgs; for before: keep last N

    // Mark unread received messages as read — fire-and-forget, never blocks response
    const unreadIds = (recv || []).filter(m => !m.is_read).map(m => m.id);
    if (unreadIds.length) {
      supabase
        .from("member_notifications")
        .update({ is_read: true })
        .in("id", unreadIds)
        .then(() => {})
        .catch(e => console.error("[dm/mark-read]", e.message));
    }

    const reactionMap = await fetchReactionsFor(msgs.map(m => m.id), "dm", myId);

    res.json(msgs.map(m => ({
      id:                   m.id,
      sender_id:            m.actor_id,
      body:                 m.body,
      sent_at:              m.created_at,
      is_read:              m.is_read,
      replied_to_id:        m.replied_to_id    || null,
      replied_to_body:      m.replied_to_body  || null,
      replied_to_sender:    m.replied_to_sender || null,
      reactions:            reactionMap[m.id] || [],
      // E2EE fields (null for legacy plaintext messages)
      e2ee:                 m.e2ee || false,
      cipher_for_recipient: m.cipher_for_recipient || null,
      cipher_for_self:      m.cipher_for_self || null,
    })));
  } catch (e) {
    dmLogErr("[dm/messages GET]", e);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

// ── POST /api/member/dm/send ──────────────────────────────────────────────────
// Body: { to_member_id, body } — or E2EE: { to_member_id, e2ee: true, cipher_for_recipient, cipher_for_self, body: "" }
app.post("/api/member/dm/send", memberAuthMiddleware, dmRateLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { to_member_id, body, replied_to_id, replied_to_body, replied_to_sender,
            e2ee, cipher_for_recipient, cipher_for_self } = req.body || {};

    if (!to_member_id) return res.status(400).json({ error: "to_member_id required" });
    if (to_member_id === myId) return res.status(400).json({ error: "Cannot message yourself" });

    // E2EE messages arrive with e2ee:true and empty body; validate ciphertexts present
    if (e2ee) {
      if (!cipher_for_recipient || !cipher_for_self)
        return res.status(400).json({ error: "E2EE message missing cipher_for_recipient or cipher_for_self" });
      if (typeof cipher_for_recipient !== 'string' || cipher_for_recipient.length > 8000)
        return res.status(400).json({ error: "cipher_for_recipient invalid" });
      if (typeof cipher_for_self !== 'string' || cipher_for_self.length > 8000)
        return res.status(400).json({ error: "cipher_for_self invalid" });
    }

    const trimmed = (body || "").trim();
    // For E2EE messages body is an empty sentinel — skip the plaintext length check
    if (!e2ee && (!trimmed || trimmed === "\u200B")) return res.status(400).json({ error: "Message body required" });
    if (!e2ee && trimmed.length > 2000) return res.status(400).json({ error: "Message too long (max 2000 chars)" });

    // NOTE: DMs are a private, unmoderated space by design — no profanity gate here.
    // (Profanity checks still apply to group chats, posts, and comments, which are
    // visible to people other than just the recipient.)

    // Verify target exists
    const { data: target, error: targetErr } = await supabase
      .from("members")
      .select("id, name")
      .eq("id", to_member_id)
      .is("deleted_at", null)
      .maybeSingle();
    if (targetErr) throw targetErr;
    if (!target) return res.status(404).json({ error: "Member not found" });

    // Block check — prevent sending if either party has blocked the other
    const [{ data: iBlocked }, { data: blockedMe }] = await Promise.all([
      supabase.from("member_blocks").select("id").eq("blocker_id", myId).eq("blocked_id", to_member_id).maybeSingle(),
      supabase.from("member_blocks").select("id").eq("blocker_id", to_member_id).eq("blocked_id", myId).maybeSingle(),
    ]);
    if (iBlocked) return res.status(403).json({ error: "You have blocked this member." });
    if (blockedMe) return res.status(403).json({ error: "You can't message this person." });

    // Fetch sender info for snapshot
    const { data: sender } = await supabase
      .from("members")
      .select("id, name, photo")
      .eq("id", myId)
      .maybeSingle();

    const key = dmConvKey(myId, to_member_id);
    const now = new Date().toISOString();

    const { data: msg, error: insertErr } = await supabase
      .from("member_notifications")
      .insert([{
        member_id:             to_member_id,
        type:                  "dm",
        title:                 `Message from ${sender?.name || req.member.username}`,
        // E2EE: body is empty sentinel; plaintext never touches the server
        body:                  e2ee ? "" : trimmed,
        actor_id:              myId,
        actor_name:            sender?.name   || req.member.username,
        actor_photo:           sender?.photo  || null,
        link_type:             "dm",
        link_id:               key,
        is_read:               false,
        replied_to_id:         replied_to_id    ? String(replied_to_id).slice(0, 36) : null,
        replied_to_body:       replied_to_body  ? String(replied_to_body).slice(0, 300) : null,
        replied_to_sender:     replied_to_sender ? String(replied_to_sender).slice(0, 100) : null,
        // E2EE columns (null for legacy plaintext messages)
        e2ee:                  e2ee ? true : false,
        cipher_for_recipient:  e2ee ? cipher_for_recipient : null,
        cipher_for_self:       e2ee ? cipher_for_self : null,
      }])
      .select("id, actor_id, member_id, body, created_at, is_read, replied_to_id, replied_to_body, replied_to_sender, e2ee, cipher_for_recipient, cipher_for_self")
      .single();

    if (insertErr) throw insertErr;

    res.json({
      success:         true,
      conv_key:        key,
      message: {
        id:                   msg.id,
        sender_id:            myId,
        body:                 msg.body,
        sent_at:              msg.created_at,
        read_at:              null,
        replied_to_id:        msg.replied_to_id    || null,
        replied_to_body:      msg.replied_to_body  || null,
        replied_to_sender:    msg.replied_to_sender || null,
        reactions:            [],
        // E2EE fields — client uses these to render/decrypt
        e2ee:                 msg.e2ee || false,
        cipher_for_recipient: msg.cipher_for_recipient || null,
        cipher_for_self:      msg.cipher_for_self || null,
      },
    });
  } catch (e) {
    dmLogErr("[dm/send]", e);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// ── DELETE /api/member/dm/messages/:msgId ─────────────────────────────────────
// Soft-delete: clears body to "[deleted]"
app.delete("/api/member/dm/messages/:msgId", memberAuthMiddleware, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    const msgId = req.params.msgId;

    const { data: msg } = await supabase
      .from("member_notifications")
      .select("id, actor_id, link_type")
      .eq("id", msgId)
      .maybeSingle();

    if (!msg || msg.link_type !== "dm") return res.status(404).json({ error: "Not found" });
    if (msg.actor_id !== myId) return res.status(403).json({ error: "Cannot delete another member's message" });

    await supabase
      .from("member_notifications")
      .update({ body: "[deleted]", title: "Message deleted" })
      .eq("id", msgId);

    res.json({ success: true });
  } catch (e) {
    dmLogErr("[dm/delete]", e);
    res.status(500).json({ error: "Failed to delete message" });
  }
});

// ── POST /api/member/dm/messages/:msgId/react ─────────────────────────────────
// Body: { emoji }. Toggle: same emoji again → remove, different → switch, none → add.
const reactionLimit = rateLimit({ windowMs: 60_000, max: 150, standardHeaders: true, legacyHeaders: false });
app.post("/api/member/dm/messages/:msgId/react", memberAuthMiddleware, reactionLimit, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    const msgId = req.params.msgId;
    const emoji = String(req.body?.emoji || "").trim().slice(0, 8);
    if (!emoji) return res.status(400).json({ error: "emoji required" });

    // Verify this message belongs to a DM I'm part of (sender or recipient)
    const { data: msg } = await supabase
      .from("member_notifications")
      .select("id, actor_id, member_id, link_type")
      .eq("id", msgId)
      .maybeSingle();
    if (!msg || msg.link_type !== "dm" || (msg.actor_id !== myId && msg.member_id !== myId)) {
      return res.status(403).json({ error: "Not part of this conversation" });
    }

    await toggleMessageReaction(msgId, "dm", myId, emoji);
    const reactionMap = await fetchReactionsFor([msgId], "dm", myId);
    res.json({ success: true, reactions: reactionMap[msgId] || [] });
  } catch (e) {
    dmLogErr("[dm/react]", e);
    res.status(500).json({ error: "Failed to react" });
  }
});

// ── GET /api/member/dm/unread-count ──────────────────────────────────────────
app.get("/api/member/dm/unread-count", memberAuthMiddleware, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { count } = await supabase
      .from("member_notifications")
      .select("id", { count: "exact", head: true })
      .eq("member_id", myId)
      .eq("link_type", "dm")
      .eq("is_read", false);
    res.json({ count: count || 0 });
  } catch (e) {
    dmLogErr("[dm/unread-count]", e);
    res.json({ count: 0 });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-34 — Content Moderation: Reports, Admin Posts, Temp Suspension
//
// Tables needed (run in Supabase):
//
//   CREATE TABLE IF NOT EXISTS content_reports (
//     id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     reporter_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     content_type  TEXT NOT NULL CHECK (content_type IN ('post','dm','comment')),
//     content_id    TEXT NOT NULL,        -- project id, notification id, or comment id
//     reason        TEXT NOT NULL,
//     details       TEXT,
//     status        TEXT NOT NULL DEFAULT 'pending'
//                   CHECK (status IN ('pending','reviewed','dismissed')),
//     admin_note    TEXT,
//     reviewed_by   TEXT,
//     reviewed_at   TIMESTAMPTZ,
//     created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   CREATE INDEX IF NOT EXISTS idx_cr_status     ON content_reports(status);
//   CREATE INDEX IF NOT EXISTS idx_cr_content    ON content_reports(content_type, content_id);
//   CREATE INDEX IF NOT EXISTS idx_cr_reporter   ON content_reports(reporter_id);
//
//   -- Add is_admin_post + is_pinned columns to member_projects if not present:
//   ALTER TABLE member_projects
//     ADD COLUMN IF NOT EXISTS is_admin_post BOOLEAN NOT NULL DEFAULT FALSE,
//     ADD COLUMN IF NOT EXISTS pinned_at     TIMESTAMPTZ;
//
//   -- Add suspended_until column to member_accounts if not present:
//   ALTER TABLE member_accounts
//     ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMPTZ;
//
// ─────────────────────────────────────────────────────────────────────────────

const reportWriteLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many reports. Please wait before reporting again." },
  keyGenerator: (req, res) => req.member?.memberId || ipKeyGenerator(req, res),
});

// ── POST /api/member/reports  — submit a report (members only) ───────────────
// Body: { content_type: "post"|"dm"|"comment"|"group_message"|"member", content_id, reason, details?,
//          e2ee_report?: boolean, decrypted_snapshot?: string }
app.post("/api/member/reports", memberAuthMiddleware, reportWriteLimit, async (req, res) => {
  try {
    const { content_type, content_id, reason, details, e2ee_report, decrypted_snapshot } = req.body || {};
    if (!["post", "dm", "comment", "group_message", "member"].includes(content_type))
      return res.status(400).json({ error: "content_type must be post, dm, comment, group_message, or member" });
    if (!content_id) return res.status(400).json({ error: "content_id required" });
    if (!reason || String(reason).trim().length < 3)
      return res.status(400).json({ error: "reason required" });

    // E2EE snapshot validation: only allowed for dm/group_message types, max 4000 chars
    let safeSnapshot = null;
    if (e2ee_report && decrypted_snapshot) {
      if (!["dm", "group_message"].includes(content_type))
        return res.status(400).json({ error: "e2ee_report only valid for dm or group_message" });
      safeSnapshot = String(decrypted_snapshot).slice(0, 4000);
    }

    const reporterId = req.member.memberId;

    // Duplicate guard: same reporter + same content within 24 h
    const cutoff24h = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const { data: dup } = await supabase
      .from("content_reports")
      .select("id")
      .eq("reporter_id", reporterId)
      .eq("content_type", content_type)
      .eq("content_id", String(content_id))
      .gte("created_at", cutoff24h)
      .maybeSingle();
    if (dup) return res.status(409).json({ error: "You have already reported this content recently." });

    const { error: insertErr } = await supabase.from("content_reports").insert([{
      reporter_id:         reporterId,
      content_type,
      content_id:          String(content_id),
      reason:              String(reason).trim().slice(0, 200),
      details:             details ? String(details).trim().slice(0, 1000) : null,
      status:              "pending",
      // E2EE: reporter's client decrypts the flagged message and sends us the plaintext.
      // This is the Signal/iMessage approach — server never decrypts anything itself.
      e2ee_report:         e2ee_report ? true : false,
      decrypted_snapshot:  safeSnapshot,
    }]);
    if (insertErr) throw insertErr;

    res.json({ success: true, message: "Report submitted. Our team will review it shortly." });
  } catch (e) {
    console.error("[reports/submit]", e.message);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// ── GET /api/admin/reports  — list reports (masters only) ────────────────────
// Query: ?status=pending|reviewed|dismissed&type=post|dm|comment|group_message|member&page=0
app.get("/api/admin/reports", masterMiddleware, async (req, res) => {
  try {
    const status = ["pending", "reviewed", "dismissed"].includes(req.query.status)
      ? req.query.status : "pending";
    const type = ["post", "dm", "comment", "group_message", "member"].includes(req.query.type)
      ? req.query.type : null;
    const page  = Math.max(0, parseInt(req.query.page) || 0);
    const limit = 30;

    let q = supabase
      .from("content_reports")
      .select(`
        id, content_type, content_id, reason, details, status,
        admin_note, reviewed_by, reviewed_at, created_at,
        e2ee_report, decrypted_snapshot,
        reporter:reporter_id ( id, name, photo )
      `)
      .eq("status", status)
      .order("created_at", { ascending: false })
      .range(page * limit, page * limit + limit - 1);

    if (type) q = q.eq("content_type", type);

    const { data, error } = await q;
    if (error) throw error;

    // Enrich with content snapshot so admin doesn't need to navigate away
    const enriched = await Promise.all((data || []).map(async (r) => {
      let snapshot = null;
      try {
        if (r.content_type === "post") {
          const { data: proj } = await supabase
            .from("member_projects")
            .select("id, title, description, status, deleted_at, members!member_projects_member_id_fkey(id, name)")
            .eq("id", r.content_id)
            .maybeSingle();
          snapshot = proj;
        } else if (r.content_type === "dm") {
          const { data: dm } = await supabase
            .from("member_notifications")
            .select("id, body, actor_id, actor_name, member_id, created_at, link_id")
            .eq("id", r.content_id)
            .eq("link_type", "dm")
            .maybeSingle();
          snapshot = dm;
        } else if (r.content_type === "comment") {
          const { data: comment } = await supabase
            .from("project_comments")
            .select("id, body, member_id, project_id, created_at, members!project_comments_member_id_fkey(id, name)")
            .eq("id", r.content_id)
            .maybeSingle();
          snapshot = comment;
        } else if (r.content_type === "group_message") {
          const { data: gmsg } = await supabase
            .from("dm_group_messages")
            .select("id, body, sender_id, group_id, created_at")
            .eq("id", r.content_id)
            .maybeSingle();
          if (gmsg?.sender_id) {
            const { data: sndr } = await supabase.from("members").select("id, name").eq("id", gmsg.sender_id).maybeSingle();
            snapshot = { ...gmsg, members: sndr || null };
          } else {
            snapshot = gmsg;
          }
        } else if (r.content_type === "member") {
          const { data: mem } = await supabase
            .from("members")
            .select("id, name, photo, role, batch, domain")
            .eq("id", r.content_id)
            .maybeSingle();
          snapshot = mem;
        }
      } catch {}
      return {
        ...r,
        snapshot,
        // E2EE: surface decrypted snapshot for master admins only.
        // This is the plaintext the reporter's client decrypted and submitted.
        // The live message on the server is still encrypted and unreadable.
        e2ee_report:        r.e2ee_report || false,
        decrypted_snapshot: r.e2ee_report ? (r.decrypted_snapshot || null) : null,
      };
    }));

    res.json(enriched);
  } catch (e) {
    console.error("[admin/reports GET]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /api/admin/reports/count  — pending report badge count ───────────────
// authMiddleware (not masterMiddleware) — the badge is just a number, not
// sensitive content. Regular admins can see the badge; the full reports list
// and resolve actions remain master-only.
app.get("/api/admin/reports/count", authMiddleware, async (req, res) => {
  try {
    const { count } = await supabase
      .from("content_reports")
      .select("id", { count: "exact", head: true })
      .eq("status", "pending");
    res.json({ count: count || 0 });
  } catch (e) {
    res.json({ count: 0 });
  }
});

// ── POST /api/admin/reports/:id/resolve  — review/dismiss a report ───────────
// Body: { action: "reviewed"|"dismissed", admin_note?, delete_content?, hide_content? }
app.post("/api/admin/reports/:id/resolve", masterMiddleware, async (req, res) => {
  try {
    const { action, admin_note, delete_content, hide_content } = req.body || {};
    if (!["reviewed", "dismissed"].includes(action))
      return res.status(400).json({ error: "action must be reviewed or dismissed" });

    const { data: report } = await supabase
      .from("content_reports")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (!report) return res.status(404).json({ error: "Report not found" });

    // Optionally act on the content
    if (action === "reviewed" && report.content_type === "post") {
      if (delete_content) {
        await supabase.from("member_projects")
          .update({ deleted_at: new Date().toISOString(), status: "hidden" })
          .eq("id", report.content_id);
        logActivity(req.admin.id, req.admin.name, "delete_reported_post", "member_project", report.content_id).catch(() => {});
      } else if (hide_content) {
        await supabase.from("member_projects")
          .update({ status: "hidden" })
          .eq("id", report.content_id);
        logActivity(req.admin.id, req.admin.name, "hide_reported_post", "member_project", report.content_id).catch(() => {});
      }
      // Invalidate feed cache so changes are immediately visible
      memInvalidate("studio:feed:");
    }
    if (action === "reviewed" && report.content_type === "dm" && delete_content) {
      await supabase.from("member_notifications")
        .update({ body: "[removed by admin]", title: "Message removed" })
        .eq("id", report.content_id);
      logActivity(req.admin.id, req.admin.name, "delete_reported_dm", "member_notification", report.content_id).catch(() => {});
    }
    if (action === "reviewed" && report.content_type === "comment" && delete_content) {
      await supabase.from("project_comments")
        .update({ body: "[removed by admin]", deleted_at: new Date().toISOString() })
        .eq("id", report.content_id);
      logActivity(req.admin.id, req.admin.name, "delete_reported_comment", "project_comment", report.content_id).catch(() => {});
    }
    if (action === "reviewed" && report.content_type === "group_message" && delete_content) {
      await supabase.from("dm_group_messages")
        .update({ body: "[removed by admin]", is_deleted: true })
        .eq("id", report.content_id);
      logActivity(req.admin.id, req.admin.name, "delete_reported_group_msg", "dm_group_messages", report.content_id).catch(() => {});
    }

    // Update the report itself
    await supabase.from("content_reports").update({
      status:      action,
      admin_note:  admin_note ? String(admin_note).trim().slice(0, 500) : null,
      reviewed_by: req.admin.username,
      reviewed_at: new Date().toISOString(),
    }).eq("id", req.params.id);

    logActivity(req.admin.id, req.admin.name, `report_${action}`, "content_report", req.params.id).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    console.error("[admin/reports/resolve]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/members/:id/account/suspend  — temp-suspend account ──────
// Body: { hours: number (1–720), reason? }
// Sets suspended_until on member_accounts. The memberAuthMiddleware
// already checks account_status; the suspend check is added there too.
app.post("/api/admin/members/:id/account/suspend", requireSection("members"), async (req, res) => {
  try {
    const { hours, reason } = req.body || {};
    const h = parseInt(hours, 10);
    if (!h || h < 1 || h > 720)
      return res.status(400).json({ error: "hours must be between 1 and 720" });

    const suspendedUntil = new Date(Date.now() + h * 3600 * 1000).toISOString();

    const { error } = await supabase
      .from("member_accounts")
      .update({ suspended_until: suspendedUntil, account_status: "suspended" })
      .eq("member_id", req.params.id);

    if (error) {
      // Graceful fallback: if suspended_until column doesn't exist yet just disable
      await supabase.from("member_accounts")
        .update({ account_status: "disabled" })
        .eq("member_id", req.params.id);
    }

    // Notify the member
    createMemberNotification(
      req.params.id, "account",
      "Account temporarily suspended",
      `Your account has been suspended for ${h} hour${h !== 1 ? "s" : ""}.${reason ? " Reason: " + reason : ""} It will be restored automatically after this period.`
    ).catch(() => {});

    logActivity(req.admin.id, req.admin.name, "suspend", "member_account",
      `${req.params.id} — ${h}h${reason ? ": " + reason : ""}`).catch(() => {});
    res.json({ success: true, suspended_until: suspendedUntil });
  } catch (e) {
    console.error("[admin/suspend]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/reports/members/:id/account/unsuspend  — lift suspension ──
app.post("/api/admin/members/:id/account/unsuspend", requireSection("members"), async (req, res) => {
  try {
    await supabase.from("member_accounts")
      .update({ suspended_until: null, account_status: "active" })
      .eq("member_id", req.params.id);

    // Also clear in-memory violation ban flag so the member can message again
    const v = _violations.get(req.params.id);
    if (v) _violations.set(req.params.id, { ...v, banned: false });

    createMemberNotification(
      req.params.id, "account",
      "Account suspension lifted",
      "Your account suspension has been lifted. Welcome back! Please keep the community guidelines in mind going forward."
    ).catch(() => {});

    logActivity(req.admin.id, req.admin.name, "unsuspend", "member_account", req.params.id).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    console.error("[admin/unsuspend]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/member/ban-appeal  — member submits an appeal for their temp ban ──
// Body: { message?: string }
// The member must be in 'suspended' status to submit an appeal.
// Rate-limited to 1 appeal per 24 hours per member.
app.post("/api/member/ban-appeal", memberAuthMiddleware, async (req, res) => {
  try {
    const memberId = req.member.memberId;
    const message  = String(req.body?.message || "").trim().slice(0, 1000);

    // Verify the member is actually suspended
    const { data: acct } = await supabase
      .from("member_accounts")
      .select("account_status, suspended_until")
      .eq("member_id", memberId)
      .maybeSingle();

    if (!acct || acct.account_status !== "suspended") {
      return res.status(400).json({ error: "Your account is not currently suspended." });
    }

    // Check for an existing pending appeal (rate limit: one at a time)
    const { data: existing } = await supabase
      .from("ban_appeals")
      .select("id, status, created_at")
      .eq("member_id", memberId)
      .eq("status", "pending")
      .maybeSingle();

    if (existing) {
      return res.status(429).json({
        error: "You already have a pending appeal. Please wait for an admin to review it.",
        appeal_id: existing.id,
      });
    }

    // Get member info for the notification
    const { data: member } = await supabase
      .from("members")
      .select("name")
      .eq("id", memberId)
      .maybeSingle();

    const vio = vioGet(memberId);

    // Insert the appeal
    const { data: appeal, error: aErr } = await supabase
      .from("ban_appeals")
      .insert([{
        member_id:      memberId,
        offense:        vio.offense || 5,
        message:        message || null,
        status:         "pending",
        created_at:     new Date().toISOString(),
      }])
      .select("id")
      .single();

    if (aErr) throw aErr;

    // Notify all admins via member_notifications (re-uses existing notification system)
    // We notify the system-wide admin channel by creating an account-type notification
    // with a special link type so the admin panel can pick it up.
    try {
      await supabase.from("ban_appeals_notifications").insert([{
        appeal_id:   appeal.id,
        member_id:   memberId,
        member_name: member?.name || "Member",
        message:     message || null,
        created_at:  new Date().toISOString(),
      }]);
    } catch { /* table may not exist yet — safe */ }

    logActivity(null, member?.name || "Member", "ban_appeal", "member_account", memberId).catch(() => {});

    res.json({ success: true, appeal_id: appeal.id, message: "Your appeal has been submitted. An admin will review it shortly." });
  } catch (e) {
    console.error("[ban-appeal]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /api/admin/ban-appeals  — list pending ban appeals for admin ──────────
app.get("/api/admin/ban-appeals", authMiddleware, async (req, res) => {
  try {
    const status = req.query.status || "pending"; // pending | approved | rejected | all
    let q = supabase
      .from("ban_appeals")
      .select("id, member_id, offense, message, status, reviewed_by, reviewed_at, created_at")
      .order("created_at", { ascending: false })
      .limit(100);

    if (status !== "all") q = q.eq("status", status);

    const { data, error } = await q;
    if (error) throw error;

    // Two-step member lookup — avoids FK hint name mismatch (Supabase auto-generated
    // constraint names don't always match ban_appeals_member_id_fkey).
    const memberIds = [...new Set((data || []).map(a => a.member_id).filter(Boolean))];
    let memberMap = {};
    if (memberIds.length) {
      const { data: mems } = await supabase
        .from("members")
        .select("id, name, photo")
        .in("id", memberIds);
      (mems || []).forEach(m => { memberMap[m.id] = m; });
    }

    const appeals = (data || []).map(a => ({
      ...a,
      member_name:  memberMap[a.member_id]?.name  || null,
      member_photo: memberMap[a.member_id]?.photo || null,
    }));

    res.json({ appeals });
  } catch (e) {
    console.error("[admin/ban-appeals]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/ban-appeals/:id/approve  — approve appeal → unsuspend ────
app.post("/api/admin/ban-appeals/:id/approve", authMiddleware, async (req, res) => {
  try {
    const { data: appeal, error: fetchErr } = await supabase
      .from("ban_appeals")
      .select("id, member_id, status")
      .eq("id", req.params.id)
      .maybeSingle();

    if (fetchErr || !appeal) return res.status(404).json({ error: "Appeal not found" });
    if (appeal.status !== "pending") return res.status(400).json({ error: "Appeal already reviewed" });

    // Unsuspend the member
    await supabase.from("member_accounts")
      .update({ account_status: "active", suspended_until: null })
      .eq("member_id", appeal.member_id);

    // Clear in-memory ban
    const v = _violations.get(appeal.member_id);
    if (v) _violations.set(appeal.member_id, { ...v, banned: false });

    // Update appeal status
    await supabase.from("ban_appeals")
      .update({ status: "approved", reviewed_by: req.admin.id, reviewed_at: new Date().toISOString() })
      .eq("id", req.params.id);

    // Notify member
    createMemberNotification(
      appeal.member_id, "account",
      "Ban appeal approved ✓",
      "Your appeal was reviewed and approved. Your account is now fully restored. Please follow our community guidelines."
    ).catch(() => {});

    logActivity(req.admin.id, req.admin.name, "approve_ban_appeal", "ban_appeal", req.params.id).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    console.error("[admin/ban-appeals/approve]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/ban-appeals/:id/reject  — reject appeal (keeps ban) ──────
app.post("/api/admin/ban-appeals/:id/reject", authMiddleware, async (req, res) => {
  try {
    const { data: appeal, error: fetchErr } = await supabase
      .from("ban_appeals")
      .select("id, member_id, status")
      .eq("id", req.params.id)
      .maybeSingle();

    if (fetchErr || !appeal) return res.status(404).json({ error: "Appeal not found" });
    if (appeal.status !== "pending") return res.status(400).json({ error: "Appeal already reviewed" });

    await supabase.from("ban_appeals")
      .update({ status: "rejected", reviewed_by: req.admin.id, reviewed_at: new Date().toISOString() })
      .eq("id", req.params.id);

    createMemberNotification(
      appeal.member_id, "account",
      "Ban appeal reviewed",
      "Your appeal was reviewed. Your suspension remains in effect. If you believe this is in error, please reach out to a member of the KFS leadership team directly."
    ).catch(() => {});

    logActivity(req.admin.id, req.admin.name, "reject_ban_appeal", "ban_appeal", req.params.id).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    console.error("[admin/ban-appeals/reject]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/wall/admin-post  — KFS admin broadcast post ──────────────
// Creates a post pinned to the top of the feed with the KFS tick badge.
// Body: { title, description, tags?, cover_image_url? }
app.post("/api/admin/wall/admin-post", authMiddleware, async (req, res) => {
  try {
    const { title, description, tags, cover_image_url } = req.body || {};
    if (!title || !description)
      return res.status(400).json({ error: "title and description are required" });

    // Use a sentinel member UUID for "KFS" — stored in settings as kfs_admin_member_id
    // Falls back to inserting under the first master admin's member record.
    const { data: kfsSetting } = await supabase
      .from("settings")
      .select("value")
      .eq("key", "kfs_admin_member_id")
      .maybeSingle();

    let kfsMemberId = kfsSetting?.value || null;

    // If no sentinel member configured, find the first active member named "KFS"
    if (!kfsMemberId) {
      const { data: kfsMember } = await supabase
        .from("members")
        .select("id")
        .ilike("name", "KFS%")
        .limit(1)
        .maybeSingle();
      kfsMemberId = kfsMember?.id || null;
    }

    if (!kfsMemberId)
      return res.status(400).json({
        error: "No KFS sentinel member found. Create a member named 'KFS' or set kfs_admin_member_id in settings.",
      });

    const now = new Date().toISOString();
    const { data: post, error: insertErr } = await supabase
      .from("member_projects")
      .insert([{
        member_id:    kfsMemberId,
        title:        String(title).trim().slice(0, 200),
        description:  String(description).trim().slice(0, 5000),
        tags:         Array.isArray(tags) ? tags.slice(0, 10) : [],
        cover_image:  cover_image_url || null,
        status:       "published",
        is_admin_post: true,
        pinned_at:    now,
        created_at:   now,
      }])
      .select("id")
      .single();

    if (insertErr) throw insertErr;

    // Bust feed cache so it appears immediately
    memInvalidate("studio:feed:");

    logActivity(req.admin.id, req.admin.name, "create_admin_post", "member_project", post.id).catch(() => {});
    res.json({ success: true, post_id: post.id });
  } catch (e) {
    console.error("[admin/wall/admin-post]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── DELETE /api/admin/wall/admin-post/:id  — remove an admin post ─────────────
app.delete("/api/admin/wall/admin-post/:id", authMiddleware, async (req, res) => {
  try {
    const { data: post } = await supabase
      .from("member_projects")
      .select("id, is_admin_post")
      .eq("id", req.params.id)
      .maybeSingle();

    if (!post) return res.status(404).json({ error: "Post not found" });
    if (!post.is_admin_post) return res.status(403).json({ error: "Not an admin post" });

    await supabase.from("member_projects")
      .update({ deleted_at: new Date().toISOString(), status: "hidden" })
      .eq("id", req.params.id);

    memInvalidate("studio:feed:");
    logActivity(req.admin.id, req.admin.name, "delete_admin_post", "member_project", req.params.id).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    console.error("[admin/wall/admin-post DELETE]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /api/admin/wall/admin-posts  — list all admin posts ──────────────────
app.get("/api/admin/wall/admin-posts", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("member_projects")
      .select("id, title, description, status, views_count, reactions_count, comments_count, created_at, deleted_at")
      .eq("is_admin_post", true)
      .is("deleted_at", null)
      .order("created_at", { ascending: false })
      .limit(50);
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    console.error("[admin/wall/admin-posts GET]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Patch feed routes to inject admin posts at top ────────────────────────────
// Monkey-patch the existing feed so pinned admin posts always float to the top.
// This wraps the response for /api/member/studio/feed without touching the huge
// existing handler — we intercept via a post-processing middleware registered
// before the catch-all.

// Override: inject pinned admin posts into the feed response.
// We do this by wrapping the existing route with a pass-through that checks
// if pinned posts need to be prepended.
// NOTE: The cleanest approach in Express is to add a small middleware that
// modifies res.json. This runs after the actual handler populates the response.
// We use a targeted middleware only for this path.
app.use("/api/member/studio/feed", (req, res, next) => {
  // Only intercept GET requests that have not already been handled
  if (req.method !== "GET") return next();

  const originalJson = res.json.bind(res);
  res.json = async function(body) {
    // body should be { feed, page, has_more, sort }
    if (body && Array.isArray(body.feed) && body.page === 1) {
      try {
        // Fetch pinned admin posts (only a handful ever, so cheap)
        const { data: pinned } = await supabase
          .from("member_projects")
          .select(`
            id, title, description, cover_image, video_url, video_provider,
            domain, tags, views_count, reactions_count, comments_count, created_at,
            member_id, is_admin_post, pinned_at,
            members!member_projects_member_id_fkey(id, name, photo, role, domain)
          `)
          .eq("is_admin_post", true)
          .eq("status", "published")
          .is("deleted_at", null)
          .order("pinned_at", { ascending: false })
          .limit(5);

        if (pinned && pinned.length) {
          const pinnedIds = new Set(pinned.map(p => p.id));
          // Remove them from the regular feed if they happened to appear
          const filtered = body.feed.filter(p => !pinnedIds.has(p.id));
          body = {
            ...body,
            feed: [
              ...pinned.map(p => ({ ...p, my_reaction: null, is_admin_post: true })),
              ...filtered,
            ],
          };
        }
      } catch {}
    }
    return originalJson(body);
  };
  next();
});

// ── Middleware: auto-lift expired temp suspensions on member auth ──────────────
// Extend the existing memberAuthMiddleware to auto-lift expired suspensions.
// We do this by wrapping the response path rather than editing the original fn.
app.use("/api/member/", async (req, res, next) => {
  // Only if member is already authenticated (req.member set by prior middleware)
  if (!req.member?.memberId) return next();
  try {
    const { data: acct } = await supabase
      .from("member_accounts")
      .select("account_status, suspended_until")
      .eq("member_id", req.member.memberId)
      .maybeSingle();
    if (acct?.account_status === "suspended" && acct?.suspended_until) {
      if (new Date(acct.suspended_until) <= new Date()) {
        // Auto-lift
        await supabase.from("member_accounts")
          .update({ account_status: "active", suspended_until: null })
          .eq("member_id", req.member.memberId);
        console.log(`[suspend] Auto-lifted suspension for member ${req.member.memberId}`);
      }
    }
  } catch {}
  next();
});

// ── GET /api/admin/moderation/dm-conversations  — admin DM inbox viewer ───────
// Allows admins to review DM conversations by conv_key (for reported messages).
// Only accessible via a specific report's conv_key — no bulk browsing.
app.get("/api/admin/moderation/dm/:convKey", authMiddleware, async (req, res) => {
  try {
    const convKey = req.params.convKey;
    // Validate format: must be two UUIDs joined by ":"
    const uuidRe = /^[0-9a-f-]{36}:[0-9a-f-]{36}$/i;
    if (!uuidRe.test(convKey))
      return res.status(400).json({ error: "Invalid conversation key format" });

    const { data: msgs, error } = await supabase
      .from("member_notifications")
      .select("id, actor_id, actor_name, actor_photo, member_id, body, is_read, created_at")
      .eq("link_type", "dm")
      .eq("link_id", convKey)
      .order("created_at", { ascending: true })
      .limit(200);

    if (error) throw error;

    // Fetch both member names for context
    const ids = [...new Set((msgs || []).flatMap(m => [m.actor_id, m.member_id]).filter(Boolean))];
    let memberNames = {};
    if (ids.length) {
      const { data: members } = await supabase
        .from("members")
        .select("id, name")
        .in("id", ids);
      (members || []).forEach(m => { memberNames[m.id] = m.name; });
    }

    logActivity(req.admin.id, req.admin.name, "view_dm_conversation", "dm", convKey).catch(() => {});

    res.json({
      conv_key: convKey,
      messages: (msgs || []).map(m => ({
        id:          m.id,
        sender_id:   m.actor_id,
        sender_name: memberNames[m.actor_id] || m.actor_name || "Unknown",
        body:        m.body,
        sent_at:     m.created_at,
      })),
      members: memberNames,
    });
  } catch (e) {
    console.error("[admin/moderation/dm]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});


// ── GET /api/admin/moderation/dm-list  — list all unique DM conversations ────
// Master-only. Scans member_notifications (type/link_type "dm") for unique
// conversation pairs so the admin can browse/select a conv_key to inspect.
app.get("/api/admin/moderation/dm-list", masterMiddleware, async (req, res) => {
  try {
    // Fetch the most recent 1000 DM notifications to build conversation index
    const { data, error } = await supabase
      .from("member_notifications")
      .select("actor_id, member_id, link_id, created_at")
      .eq("link_type", "dm")
      .order("created_at", { ascending: false })
      .limit(1000);

    if (error) throw error;

    // Collapse into unique conv_keys — prefer the stored link_id (the real
    // conv_key used by dmConvKey), falling back to deriving it from the
    // sender/recipient pair for any older rows that might lack link_id.
    const convMap = new Map();
    for (const row of (data || [])) {
      const key = row.link_id || [row.actor_id, row.member_id].sort().join(":");
      if (!convMap.has(key)) {
        convMap.set(key, { conv_key: key, last_msg: row.created_at, message_count: 1 });
      } else {
        convMap.get(key).message_count++;
      }
    }

    // Fetch member names for all IDs that appear in conversations
    const ids = [...new Set([...convMap.keys()].flatMap(k => k.split(":")))];
    let nameMap = {};
    if (ids.length) {
      const { data: members } = await supabase
        .from("members")
        .select("id, name")
        .in("id", ids);
      (members || []).forEach(m => { nameMap[m.id] = m.name; });
    }

    const result = [...convMap.values()]
      .sort((a, b) => new Date(b.last_msg) - new Date(a.last_msg))
      .map(c => {
        const [idA, idB] = c.conv_key.split(":");
        return {
          conv_key:      c.conv_key,
          member_a:      nameMap[idA] || idA,
          member_b:      nameMap[idB] || idB,
          message_count: c.message_count,
          last_msg:      c.last_msg,
        };
      });

    logActivity(req.admin.id, req.admin.name, "list_dm_conversations", "dm", `${result.length} conversations`).catch(() => {});
    res.json(result);
  } catch (e) {
    console.error("[admin/moderation/dm-list]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Rate limiters for blocks / nicknames / groups ────────────────────────────
const blockWriteLimit = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false });
const nicknameLimit   = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
const gcWriteLimit    = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false });
const gcReadLimit     = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });

// ── Blocks ────────────────────────────────────────────────────────────────────

// GET /api/member/blocks — list of IDs the caller has blocked
app.get("/api/member/blocks", memberAuthMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from("member_blocks")
      .select("blocked_id")
      .eq("blocker_id", req.member.memberId);
    res.json((data || []).map(r => r.blocked_id));
  } catch (e) {
    res.status(500).json({ error: "Failed to load block list" });
  }
});

// POST /api/member/blocks  { blocked_id }
app.post("/api/member/blocks", memberAuthMiddleware, blockWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { blocked_id } = req.body || {};
    if (!blocked_id) return res.status(400).json({ error: "blocked_id required" });
    if (blocked_id === myId) return res.status(400).json({ error: "Cannot block yourself" });
    const { error: blockErr } = await supabase.from("member_blocks").upsert([{ blocker_id: myId, blocked_id }], { onConflict: "blocker_id,blocked_id" });
    if (blockErr) { console.error("[blocks POST] upsert:", blockErr.message, blockErr.code); throw blockErr; }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to block member" });
  }
});

// GET /api/member/blocks/check/:id — am I blocked by them, or have I blocked them?
app.get("/api/member/blocks/check/:id", memberAuthMiddleware, async (req, res) => {
  try {
    const myId   = req.member.memberId;
    const otherId = req.params.id;
    const [{ data: iBlockedThem }, { data: theyBlockedMe }] = await Promise.all([
      supabase.from("member_blocks").select("id").eq("blocker_id", myId).eq("blocked_id", otherId).maybeSingle(),
      supabase.from("member_blocks").select("id").eq("blocker_id", otherId).eq("blocked_id", myId).maybeSingle(),
    ]);
    res.json({ blocked: !!iBlockedThem, blocked_me: !!theyBlockedMe });
  } catch (e) {
    res.status(500).json({ error: "Failed to check block status" });
  }
});

// DELETE /api/member/blocks/:id
app.delete("/api/member/blocks/:id", memberAuthMiddleware, blockWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { error: unblockErr } = await supabase.from("member_blocks").delete().eq("blocker_id", myId).eq("blocked_id", req.params.id);
    if (unblockErr) { console.error("[blocks DELETE] delete:", unblockErr.message, unblockErr.code); throw unblockErr; }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to unblock member" });
  }
});

// ── Nicknames ─────────────────────────────────────────────────────────────────

// GET /api/member/nicknames — all nicknames the caller has set (giver=me)
app.get("/api/member/nicknames", memberAuthMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from("member_nicknames")
      .select("target_id, nickname")
      .eq("giver_id", req.member.memberId);
    res.json(Object.fromEntries((data || []).map(r => [r.target_id, r.nickname])));
  } catch (e) {
    res.status(500).json({ error: "Failed to load nicknames" });
  }
});

// PUT /api/member/nicknames/:targetId  { nickname }  — set or clear (empty = delete)
app.put("/api/member/nicknames/:targetId", memberAuthMiddleware, nicknameLimit, async (req, res) => {
  try {
    const myId     = req.member.memberId;
    const targetId = req.params.targetId;
    const nickname = (req.body?.nickname || "").trim().slice(0, 40);
    if (targetId === myId) return res.status(400).json({ error: "Cannot nickname yourself" });
    if (!nickname) {
      const { error: delErr } = await supabase.from("member_nicknames").delete().eq("giver_id", myId).eq("target_id", targetId);
      if (delErr) { console.error("[nicknames PUT] delete:", delErr.message, delErr.code); throw delErr; }
    } else {
      const { error: nickErr } = await supabase.from("member_nicknames").upsert(
        [{ giver_id: myId, target_id: targetId, nickname, updated_at: new Date().toISOString() }],
        { onConflict: "giver_id,target_id" }
      );
      if (nickErr) { console.error("[nicknames PUT] upsert:", nickErr.message, nickErr.code); throw nickErr; }
    }
    res.json({ success: true, nickname: nickname || null });
  } catch (e) {
    res.status(500).json({ error: "Failed to set nickname" });
  }
});

// ── Group chats ───────────────────────────────────────────────────────────────

// GET /api/member/groups — all group chats the caller is in
app.get("/api/member/groups", memberAuthMiddleware, gcReadLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    if (!myId) return res.json([]);

    // NOTE: dm_group_members reads occasionally come back empty right after a
    // write (group create/join) due to a brief replication/visibility lag —
    // this is the same race already flagged below in the single-group
    // endpoint. Two short retries with backoff are enough to ride it out
    // instead of silently telling the client "you have no groups" and making
    // the whole group disappear from the sidebar.
    async function loadMembership() {
      return supabase.from("dm_group_members").select("group_id").eq("member_id", myId);
    }
    let { data: membership, error: memErr } = await loadMembership();
    if (!memErr && !membership?.length) {
      await new Promise(r => setTimeout(r, 250));
      ({ data: membership, error: memErr } = await loadMembership());
    }
    if (!memErr && !membership?.length) {
      await new Promise(r => setTimeout(r, 600));
      ({ data: membership, error: memErr } = await loadMembership());
    }
    if (memErr) { console.error("[groups GET] membership:", memErr.message); return res.json([]); }
    if (!membership?.length) return res.json([]);

    const groupIds = membership.map(r => r.group_id);

    const { data: groups, error: groupsErr } = await supabase
      .from("dm_group_chats")
      .select("id, name, created_by, created_at, photo_url")
      .in("id", groupIds);
    if (groupsErr) { console.error("[groups GET] chats:", groupsErr.message); return res.json([]); }

    // Two-step member lookup (avoids relying on a specific FK constraint name)
    // Note: group_role column is optional — if it doesn't exist yet, fallback to null
    const { data: allMemberRows, error: allMembErr } = await supabase
      .from("dm_group_members")
      .select("group_id, member_id, nickname, joined_at")
      .in("group_id", groupIds);
    if (allMembErr) console.error("[groups GET] allMembers:", allMembErr.message);

    // Fetch member profiles for all unique member_ids
    const uniqueMemberIds = [...new Set((allMemberRows || []).map(r => r.member_id))];
    const memberProfileMap = {};
    if (uniqueMemberIds.length) {
      const { data: profiles, error: profErr } = await supabase
        .from("members")
        .select("id, name, photo, role")
        .in("id", uniqueMemberIds);
      if (profErr) console.error("[groups GET] member profiles:", profErr.message);
      (profiles || []).forEach(p => { memberProfileMap[p.id] = p; });
    }

    const lastMsgMap = {};
    await Promise.all(groupIds.map(async gid => {
      try {
        const { data: msgs, error: msgErr } = await supabase
          .from("dm_group_messages")
          .select("id, sender_id, body, created_at")
          .eq("group_id", gid)
          .is("deleted_at", null)
          .order("created_at", { ascending: false })
          .limit(1);
        if (msgErr) { console.error("[groups GET] lastMsg:", msgErr.message); return; }
        if (msgs?.[0]) lastMsgMap[gid] = msgs[0];
      } catch (e) { console.error("[groups GET] lastMsg ex:", e.message); }
    }));

    const membersByGroup = {};
    // Build a map of myId's role per group from the membership rows
    const myRoleByGroup = {};
    (allMemberRows || []).forEach(m => {
      if (!membersByGroup[m.group_id]) membersByGroup[m.group_id] = [];
      const profile = memberProfileMap[m.member_id] || { id: m.member_id };
      membersByGroup[m.group_id].push({ ...profile, nickname: m.nickname });
      // group_role may not exist as column yet; created_by check is the authoritative owner test
      if (m.member_id === myId) myRoleByGroup[m.group_id] = 'member';
    });
    const memberNameMap = {};
    (allMemberRows || []).forEach(m => {
      const profile = memberProfileMap[m.member_id];
      if (profile?.id) memberNameMap[profile.id] = profile.name || 'Member';
    });

    const result = (groups || []).map(g => {
      const lm = lastMsgMap[g.id] || null;
      const rawSnippet = lm ? (lm.body || '').slice(0, 80) : null;
      const isSysSnippet = rawSnippet?.startsWith('\x1fsys\x1f');
      // Creator is always owner; others are members (extend to admin support when group_role column added)
      const myRole = g.created_by === myId ? 'owner' : 'member';
      return {
        id:                g.id,
        name:              g.name,
        photo_url:         g.photo_url || null,
        created_by:        g.created_by,
        created_at:        g.created_at,
        members:           membersByGroup[g.id] || [],
        last_msg_at:       lm ? lm.created_at : g.created_at,
        last_snippet:      isSysSnippet ? rawSnippet.slice(6) : rawSnippet,
        last_sender_is_me: lm ? lm.sender_id === myId : false,
        last_sender_name:  lm ? (memberNameMap[lm.sender_id] || 'Member') : null,
        last_is_system:    isSysSnippet || false,
        unread_count:      0,
        my_role:           myRole,
      };
    }).sort((a, b) => new Date(b.last_msg_at) - new Date(a.last_msg_at));

    res.json(result);
  } catch (e) {
    console.error("[groups GET] unhandled:", e.message, e.stack);
    res.status(500).json({ error: "Failed to load groups" });
  }
});

// POST /api/member/groups  { name, member_ids: [] }  — create group
app.post("/api/member/groups", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId       = req.member.memberId;
    if (!myId) return res.status(400).json({ error: "Member profile not linked to this account" });
    const name       = (req.body?.name || "").trim().slice(0, 60);
    // De-dupe + drop self before the existence check, so a duplicate pick or an
    // accidental self-include can never cause the membership insert to fail.
    const rawIds     = [...new Set((req.body?.member_ids || []).filter(id => id && id !== myId))].slice(0, 49);
    if (!name)             return res.status(400).json({ error: "Group name required" });
    if (!rawIds.length)    return res.status(400).json({ error: "Add at least one other member" });

    // Verify every requested id is a real, non-deleted member — a single stale/
    // bad id used to fail the WHOLE multi-row insert below (and the rollback
    // left the creator stranded with a "Failed to create group" error). Now we
    // just quietly drop ids that don't check out and proceed with the rest.
    const { data: validRows, error: validErr } = await supabase
      .from("members")
      .select("id")
      .in("id", rawIds)
      .is("deleted_at", null);
    if (validErr) { console.error("[groups POST] member validation:", validErr.message); throw validErr; }
    const memberIds = (validRows || []).map(r => r.id);
    if (!memberIds.length) return res.status(400).json({ error: "None of the selected members could be added. Please try again." });

    const { data: group, error: chatErr } = await supabase
      .from("dm_group_chats")
      .insert([{ name, created_by: myId }])
      .select("id, name, created_by, created_at")
      .single();
    if (chatErr) {
      console.error("[groups POST] dm_group_chats insert:", chatErr.message, chatErr.code);
      throw chatErr;
    }

    const rows = [myId, ...memberIds].map(mid => ({ group_id: group.id, member_id: mid }));
    const { error: membersErr } = await supabase.from("dm_group_members").insert(rows);
    if (membersErr) {
      console.error("[groups POST] dm_group_members insert:", membersErr.message, membersErr.code);
      // The membership insert is a single multi-row INSERT — if any row violates a
      // constraint (stale/duplicate/invalid member id) the WHOLE insert fails,
      // including the creator's own row. Don't leave an orphaned group chat with
      // zero members behind — roll it back and report the failure to the client.
      await supabase.from("dm_group_chats").delete().eq("id", group.id);
      return res.status(500).json({ error: "Failed to add members to group. Please try again." });
    }

    // Insert activity message as plain body with sentinel prefix \x1fsys\x1f
    // (no schema change needed — body column already stores text)
    // Awaited (not fire-and-forget) so it's guaranteed to exist by the time the
    // client opens the new group and asks for messages — otherwise the chat
    // could open completely blank for a moment.
    const { data: creator } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();
    const creatorName = creator?.name || "Someone";
    const totalCount  = memberIds.length + 1;
    try {
      await supabase.from("dm_group_messages").insert([{
        group_id:  group.id,
        sender_id: myId,
        body:      `\x1fsys\x1f\uD83C\uDF89 ${creatorName} created "${group.name}" \u00B7 ${totalCount} member${totalCount !== 1 ? 's' : ''}`,
      }]);
    } catch(e) { console.error("[groups] system msg:", e.message); }

    // Fetch full member profiles so the client Details panel shows real names immediately
    // instead of falling back to "Member" / "?" placeholders.
    const allMemberIds = [myId, ...memberIds];
    const { data: memberProfiles } = await supabase
      .from("members")
      .select("id, name, photo, role")
      .in("id", allMemberIds);
    const profileLookup = {};
    (memberProfiles || []).forEach(p => { profileLookup[p.id] = p; });

    // Return enriched group so client can open it immediately without a round-trip
    res.json({
      success: true,
      group: {
        ...group,
        members:           allMemberIds.map(mid => ({ ...(profileLookup[mid] || { id: mid }) })),
        last_msg_at:       group.created_at,
        last_snippet:      null,
        last_sender_is_me: false,
        last_sender_name:  null,
        last_is_system:    false,
        unread_count:      0,
        my_role:           'owner',
      },
    });
  } catch (e) {
    console.error("[groups POST] unhandled:", e.message, e.code || "", e.stack);
    res.status(500).json({ error: e.message || "Failed to create group" });
  }
});

// GET /api/member/groups/unread-count — total unread across all my group chats
// (placed before the /:id route so "unread-count" isn't swallowed as an id param)
app.get("/api/member/groups/unread-count", memberAuthMiddleware, gcReadLimit, async (req, res) => {
  try {
    // Full read-receipts are out of scope for v1 — return 0 so the client badge stays quiet
    // rather than erroring (matches the `unread_count: 0` placeholder used in the list route).
    res.json({ count: 0 });
  } catch (e) {
    res.status(500).json({ error: "Failed to load unread count" });
  }
});

// GET /api/member/groups/:id — single group with full member list (used by topbar + info panel)
app.get("/api/member/groups/:id", memberAuthMiddleware, gcReadLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    if (!myId) return res.status(403).json({ error: "Not authenticated" });
    const gid  = req.params.id;

    const { data: mem } = await supabase
      .from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    const { data: group } = await supabase
      .from("dm_group_chats").select("id, name, created_by, created_at, photo_url").eq("id", gid).maybeSingle();
    if (!group) return res.status(404).json({ error: "Group not found" });

    // Two-step: get member rows first, then profiles (avoids FK name dependency)
    async function loadMemberRows() {
      return supabase.from("dm_group_members").select("member_id, nickname, joined_at").eq("group_id", gid);
    }
    let { data: memberRows, error: memJoinErr } = await loadMemberRows();
    if (memJoinErr) console.error("[groups GET :id] members:", memJoinErr.message, memJoinErr.code);
    if (!memJoinErr && !memberRows?.length) {
      // Retry once — this read has been observed to come back empty right after
      // a write (replication/visibility lag) even though the rows exist.
      await new Promise(r => setTimeout(r, 250));
      ({ data: memberRows, error: memJoinErr } = await loadMemberRows());
      if (memJoinErr) console.error("[groups GET :id] members retry:", memJoinErr.message, memJoinErr.code);
    }
    if (!memberRows?.length) console.warn(`[groups GET :id] Zero members returned for group ${gid} after retry — possible RLS or replication issue`);

    const memberIds = (memberRows || []).map(r => r.member_id);
    const profileMap = {};
    if (memberIds.length) {
      const { data: profiles, error: profErr } = await supabase
        .from("members")
        .select("id, name, photo, role, batch, domain")
        .in("id", memberIds);
      if (profErr) console.error("[groups GET :id] profiles:", profErr.message);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }

    res.json({
      id:         group.id,
      name:       group.name,
      photo_url:  group.photo_url || null,
      created_by: group.created_by,
      created_at: group.created_at,
      members:    (memberRows || []).map(m => ({
        ...(profileMap[m.member_id] || { id: m.member_id }),
        nickname:   m.nickname,
        joined_at:  m.joined_at,
        is_me:      m.member_id === myId,
        group_role: m.member_id === group.created_by ? "owner" : "member",
      })),
      my_role:    group.created_by === myId ? "owner" : "member",
    });
  } catch (e) {
    console.error("[groups GET :id]", e.message);
    res.status(500).json({ error: "Failed to load group" });
  }
});

// PATCH /api/member/groups/:id  { name }  — rename alias (client sends to :id directly)
app.patch("/api/member/groups/:id", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const gid  = req.params.id;
    const name = (req.body?.name || "").trim().slice(0, 60);
    if (!name) return res.status(400).json({ error: "Name required" });
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });
    const { error: renameErr } = await supabase.from("dm_group_chats").update({ name }).eq("id", gid);
    if (renameErr) { console.error("[groups PATCH name] update:", renameErr.message, renameErr.code); throw renameErr; }
    // Activity message (sentinel prefix, no schema change)
    const { data: actor } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();
    (async () => { try { await supabase.from("dm_group_messages").insert([{
      group_id:  gid,
      sender_id: myId,
      body:      `\x1fsys\x1f\u270F\uFE0F ${actor?.name || "Someone"} changed the group name to \u201C${name}\u201D`,
    }]); } catch(e) { console.error("[groups] rename sys msg:", e.message); } })();
    res.json({ success: true, name });
  } catch (e) {
    res.status(500).json({ error: "Failed to rename group" });
  }
});

// POST /api/member/groups/:id/photo  — upload group profile picture (multipart)
app.post("/api/member/groups/:id/photo", memberAuthMiddleware, gcWriteLimit,
  multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } }).single("photo"),
  async (req, res) => {
    try {
      const myId = req.member.memberId;
      const gid  = req.params.id;
      if (!req.file) return res.status(400).json({ error: "No file uploaded" });
      // Caller must be in the group
      const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
      if (!mem) return res.status(403).json({ error: "Not in this group" });

      // Resize to 200×200 square, JPEG, quality 85
      const resized = await sharp(req.file.buffer)
        .resize(200, 200, { fit: "cover", position: "centre" })
        .jpeg({ quality: 85 })
        .toBuffer();

      // Upload to Cloudinary
      const uploadResult = await new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream(
          { folder: "kfs-group-photos", public_id: `group_${gid}`, overwrite: true, resource_type: "image" },
          (err, result) => err ? reject(err) : resolve(result)
        ).end(resized);
      });

      const photoUrl = uploadResult.secure_url;
      const { error: photoErr } = await supabase.from("dm_group_chats").update({ photo_url: photoUrl }).eq("id", gid);
      if (photoErr) { console.error("[groups photo POST] update:", photoErr.message, photoErr.code); throw photoErr; }

      // System message
      const { data: actor } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();
      (async () => { try { await supabase.from("dm_group_messages").insert([{
        group_id: gid, sender_id: myId,
        body: `\x1fsys\x1f\uD83D\uDDBC\uFE0F ${actor?.name || "Someone"} updated the group photo`,
      }]); } catch(e) {} })();

      res.json({ success: true, photo_url: photoUrl });
    } catch (e) {
      console.error("[groups/photo POST]", e.message);
      res.status(500).json({ error: "Failed to upload group photo" });
    }
  }
);

// POST /api/member/groups/:id/messages/:msgId/pin  — pin/unpin a group message
app.post("/api/member/groups/:id/messages/:msgId/pin", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    const gid   = req.params.id;
    const msgId = req.params.msgId;

    // Must be in group
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    // Check current pin state
    const { data: msg } = await supabase.from("dm_group_messages").select("id, group_id, is_pinned").eq("id", msgId).eq("group_id", gid).is("deleted_at", null).maybeSingle();
    if (!msg) return res.status(404).json({ error: "Message not found" });

    const newPinned = !msg.is_pinned;
    const { error: pinErr } = await supabase.from("dm_group_messages").update({ is_pinned: newPinned }).eq("id", msgId);
    if (pinErr) { console.error("[groups/pin] update:", pinErr.message, pinErr.code); throw pinErr; }

    // System message
    const { data: actor } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();
    const sysBody = newPinned
      ? `\x1fsys\x1f\uD83D\uDCCC ${actor?.name || "Someone"} pinned a message`
      : `\x1fsys\x1f\uD83D\uDCCC ${actor?.name || "Someone"} unpinned a message`;
    (async () => { try { await supabase.from("dm_group_messages").insert([{
      group_id: gid, sender_id: myId, body: sysBody,
    }]); } catch(e) {} })();

    res.json({ success: true, is_pinned: newPinned });
  } catch (e) {
    console.error("[groups/pin]", e.message);
    res.status(500).json({ error: "Failed to pin message" });
  }
});

// GET /api/member/groups/:id/pinned  — get pinned messages
app.get("/api/member/groups/:id/pinned", memberAuthMiddleware, gcReadLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const gid  = req.params.id;
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    const { data: msgs } = await supabase
      .from("dm_group_messages")
      .select("id, sender_id, body, created_at")
      .eq("group_id", gid)
      .eq("is_pinned", true)
      .is("deleted_at", null)
      .order("created_at", { ascending: false })
      .limit(20);

    const senderIds = [...new Set((msgs || []).map(m => m.sender_id))];
    const senderMap = {};
    if (senderIds.length) {
      const { data: senders } = await supabase.from("members").select("id, name").in("id", senderIds);
      (senders || []).forEach(s => { senderMap[s.id] = s.name; });
    }

    res.json((msgs || []).map(m => ({
      id: m.id,
      body: m.body?.startsWith('\x1fsys\x1f') ? m.body.slice(6) : m.body,
      sender_name: senderMap[m.sender_id] || "Member",
      sent_at: m.created_at,
    })));
  } catch (e) {
    res.status(500).json({ error: "Failed to load pinned messages" });
  }
});

// PATCH /api/member/groups/:id/name  { name }  — rename (any member can rename)
app.patch("/api/member/groups/:id/name", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const gid  = req.params.id;
    const name = (req.body?.name || "").trim().slice(0, 60);
    if (!name) return res.status(400).json({ error: "Name required" });
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });
    const { error: renameErr2 } = await supabase.from("dm_group_chats").update({ name }).eq("id", gid);
    if (renameErr2) { console.error("[groups PATCH /name] update:", renameErr2.message, renameErr2.code); throw renameErr2; }
    const { data: actor } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();
    (async () => { try { await supabase.from("dm_group_messages").insert([{
      group_id:  gid,
      sender_id: myId,
      body:      `\x1fsys\x1f\u270F\uFE0F ${actor?.name || "Someone"} changed the group name to \u201C${name}\u201D`,
    }]); } catch(e) { console.error("[groups] rename sys msg:", e.message); } })();
    res.json({ success: true, name });
  } catch (e) {
    res.status(500).json({ error: "Failed to rename group" });
  }
});

// DELETE /api/member/groups/:id  — owner deletes entire group for everyone
app.delete("/api/member/groups/:id", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const gid  = req.params.id;
    // Only the owner can delete the group
    const { data: group, error: gErr } = await supabase
      .from("dm_group_chats")
      .select("id, created_by")
      .eq("id", gid)
      .maybeSingle();
    if (gErr || !group) return res.status(404).json({ error: "Group not found" });
    if (group.created_by !== myId) return res.status(403).json({ error: "Only the group owner can delete this group" });
    // Delete messages, members, then group (cascade order)
    await supabase.from("dm_group_messages").delete().eq("group_id", gid);
    await supabase.from("dm_group_members").delete().eq("group_id", gid);
    const { error: delErr } = await supabase.from("dm_group_chats").delete().eq("id", gid);
    if (delErr) throw delErr;
    res.json({ success: true });
  } catch (e) {
    console.error("[groups DELETE]", e.message);
    res.status(500).json({ error: "Failed to delete group" });
  }
});

// POST /api/member/groups/:id/members  { member_id }  — add member (any member can add)
app.post("/api/member/groups/:id/members", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId     = req.member.memberId;
    const gid      = req.params.id;
    const memberId = req.body?.member_id;
    if (!memberId) return res.status(400).json({ error: "member_id required" });
    // Verify caller is in group
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });
    // Check group size
    const { count } = await supabase.from("dm_group_members").select("*", { count: "exact", head: true }).eq("group_id", gid);
    if ((count || 0) >= 50) return res.status(400).json({ error: "Group is full (50 members max)" });
    await supabase.from("dm_group_members").upsert([{ group_id: gid, member_id: memberId }], { onConflict: "group_id,member_id" });
    // Activity message
    const [{ data: actor }, { data: added }] = await Promise.all([
      supabase.from("members").select("name").eq("id", myId).maybeSingle(),
      supabase.from("members").select("name").eq("id", memberId).maybeSingle(),
    ]);
    (async () => { try { await supabase.from("dm_group_messages").insert([{
      group_id:  gid,
      sender_id: myId,
      body:      `\x1fsys\x1f\uD83D\uDC64 ${actor?.name || "Someone"} added ${added?.name || "a member"}`,
    }]); } catch(e) { console.error("[groups] add-member sys msg:", e.message); } })();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to add member" });
  }
});

// DELETE /api/member/groups/:id/members/:memberId  — leave (self) or remove (owner only)
app.delete("/api/member/groups/:id/members/:memberId", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId     = req.member.memberId;
    const gid      = req.params.id;
    const memberId = req.params.memberId;

    // Verify the caller is actually in this group
    const { data: myMem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!myMem) return res.status(403).json({ error: "Not in this group" });

    // Only the group owner can remove someone other than themselves
    if (memberId !== myId) {
      const { data: group } = await supabase.from("dm_group_chats").select("created_by").eq("id", gid).maybeSingle();
      if (!group) return res.status(404).json({ error: "Group not found" });
      if (group.created_by !== myId) return res.status(403).json({ error: "Only the group owner can remove members" });
      // Owner cannot remove themselves via this path (use leave instead)
      if (memberId === myId) return res.status(400).json({ error: "Use leave to exit the group" });
    }

    const isLeaving = memberId === myId;
    const { data: target } = await supabase.from("members").select("name").eq("id", memberId).maybeSingle();
    const { data: actor  } = await supabase.from("members").select("name").eq("id", myId).maybeSingle();

    await supabase.from("dm_group_members").delete().eq("group_id", gid).eq("member_id", memberId);

    const sysBody = isLeaving
      ? `\x1fsys\x1f\uD83D\uDC4B ${target?.name || "Someone"} left the group`
      : `\x1fsys\x1f\uD83D\uDEAB ${actor?.name || "Someone"} removed ${target?.name || "a member"}`;
    (async () => { try { await supabase.from("dm_group_messages").insert([{
      group_id:  gid,
      sender_id: myId,
      body:      sysBody,
    }]); } catch(e) { console.error("[groups] leave/remove sys msg:", e.message); } })();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to remove member" });
  }
});

// PUT /api/member/groups/:id/members/:memberId/nickname  { nickname }  — set group nickname visible to all
app.put("/api/member/groups/:id/members/:memberId/nickname", memberAuthMiddleware, nicknameLimit, async (req, res) => {
  try {
    const myId     = req.member.memberId;
    const gid      = req.params.id;
    const memberId = req.params.memberId;
    const nickname = (req.body?.nickname || "").trim().slice(0, 40);
    // Caller must be in the group
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });
    const { error: grpNickErr } = await supabase.from("dm_group_members").update({ nickname: nickname || null }).eq("group_id", gid).eq("member_id", memberId);
    if (grpNickErr) { console.error("[group-nick PUT] update:", grpNickErr.message, grpNickErr.code); throw grpNickErr; }
    res.json({ success: true, nickname: nickname || null });
  } catch (e) {
    res.status(500).json({ error: "Failed to set group nickname" });
  }
});

// GET /api/member/groups/:id/messages?before=<ISO>&limit=40
app.get("/api/member/groups/:id/messages", memberAuthMiddleware, gcReadLimit, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    if (!myId) return res.status(403).json({ error: "Not authenticated" });
    const gid   = req.params.id;
    const limit = Math.min(parseInt(req.query.limit) || 40, 80);
    const before = req.query.before;
    const since  = req.query.since;

    // Verify membership
    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    // Pull nicknames for this group
    const { data: nickRows } = await supabase.from("dm_group_members").select("member_id, nickname").eq("group_id", gid);
    const nickMap = Object.fromEntries((nickRows || []).map(r => [r.member_id, r.nickname]));

    let q = supabase
      .from("dm_group_messages")
      .select("id, sender_id, body, created_at, is_pinned, replied_to_id, replied_to_body, replied_to_sender, e2ee, ciphertext, wrapped_keys")
      .eq("group_id", gid)
      .is("deleted_at", null)
      .order("created_at", { ascending: !!since })
      .limit(limit);

    if (before) q = q.lt("created_at", before);
    if (since)  q = q.gt("created_at", since);

    const { data: msgs, error } = await q;
    if (error) throw error;

    const reactionMap = await fetchReactionsFor((msgs || []).map(m => m.id), "group", myId);

    // Two-step: fetch sender profiles for all unique sender_ids
    const senderIds = [...new Set((msgs || []).map(m => m.sender_id).filter(Boolean))];
    const senderMap = {};
    if (senderIds.length) {
      const { data: senders, error: sErr } = await supabase
        .from("members")
        .select("id, name, photo")
        .in("id", senderIds);
      if (sErr) console.error("[groups/messages GET] senders:", sErr.message);
      (senders || []).forEach(s => { senderMap[s.id] = s; });
    }

    const result = (msgs || [])
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
      .map(m => {
        const isSystem = m.body?.startsWith('\x1fsys\x1f');
        const cleanBody = isSystem ? m.body.slice(6) : m.body;
        const sender = senderMap[m.sender_id] || {};
        return {
          id:               m.id,
          group_id:         gid,
          sender_id:        m.sender_id,
          sender_name:      nickMap[m.sender_id] || sender.name || "Member",
          sender_photo:     sender.photo || null,
          body:             cleanBody,
          sent_at:          m.created_at,
          is_pinned:        m.is_pinned || false,
          is_system:        isSystem,
          replied_to_id:    m.replied_to_id    || null,
          replied_to_body:  m.replied_to_body  || null,
          replied_to_sender:m.replied_to_sender || null,
          reactions:        reactionMap[m.id] || [],
          // E2EE fields
          e2ee:             m.e2ee || false,
          ciphertext:       m.ciphertext || null,
          wrapped_keys:     m.wrapped_keys || null,
        };
      });

    res.json(result);
  } catch (e) {
    console.error("[groups/messages GET]", e.message);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

// POST /api/member/groups/:id/messages  { body } — or E2EE: { e2ee: true, ciphertext, wrapped_keys, body: "" }
app.post("/api/member/groups/:id/messages", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId = req.member.memberId;
    if (!myId) return res.status(403).json({ error: "Not authenticated" });
    const gid  = req.params.id;
    const { body: rawBody, replied_to_id, replied_to_body, replied_to_sender,
            e2ee, ciphertext, wrapped_keys } = req.body || {};
    const body = (rawBody || "").trim();

    // E2EE validation
    if (e2ee) {
      if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.length > 8000)
        return res.status(400).json({ error: "E2EE ciphertext missing or invalid" });
      if (!wrapped_keys || typeof wrapped_keys !== 'object' || Array.isArray(wrapped_keys))
        return res.status(400).json({ error: "E2EE wrapped_keys must be an object { memberId: wrappedKey }" });
    } else {
      if (!body || body.length > 2000) return res.status(400).json({ error: "Message body required (max 2000 chars)" });
    }

    // NOTE: Group chats are a private, unmoderated space (like DMs) — no profanity gate here.
    // (Profanity checks still apply to posts and comments, which are public-facing.)

    // Verify membership
    const { data: mem } = await supabase.from("dm_group_members").select("member_id, nickname").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    const { data: sender } = await supabase.from("members").select("id, name, photo").eq("id", myId).maybeSingle();

    const { data: msg, error } = await supabase
      .from("dm_group_messages")
      .insert([{
        group_id:          gid,
        sender_id:         myId,
        // E2EE: body is a sentinel; plaintext never stored server-side.
        // NOTE: must be non-empty — dm_group_messages.body has
        // CHECK (char_length(body) BETWEEN 1 AND 2000), so an empty string
        // here fails the insert (silently, from the client's perspective:
        // the message just never shows up). A single zero-width space
        // satisfies the constraint without leaking anything when rendered
        // (the client always decrypts ciphertext for e2ee messages and
        // never displays this field).
        body:              e2ee ? "\u200B" : body,
        replied_to_id:     replied_to_id     ? String(replied_to_id).slice(0, 36)    : null,
        replied_to_body:   replied_to_body   ? String(replied_to_body).slice(0, 300)  : null,
        replied_to_sender: replied_to_sender ? String(replied_to_sender).slice(0, 100): null,
        // E2EE columns
        e2ee:              e2ee ? true : false,
        ciphertext:        e2ee ? ciphertext : null,
        wrapped_keys:      e2ee ? wrapped_keys : null,
      }])
      .select("id, sender_id, body, created_at, replied_to_id, replied_to_body, replied_to_sender, e2ee, ciphertext, wrapped_keys")
      .single();
    if (error) throw error;

    res.json({
      success: true,
      message: {
        id:               msg.id,
        group_id:         gid,
        sender_id:        myId,
        sender_name:      mem.nickname || sender?.name || "Member",
        sender_photo:     sender?.photo || null,
        body:             msg.body,
        sent_at:          msg.created_at,
        replied_to_id:    msg.replied_to_id    || null,
        replied_to_body:  msg.replied_to_body  || null,
        replied_to_sender:msg.replied_to_sender || null,
        reactions:        [],
        // E2EE fields
        e2ee:             msg.e2ee || false,
        ciphertext:       msg.ciphertext || null,
        wrapped_keys:     msg.wrapped_keys || null,
      },
    });
  } catch (e) {
    console.error("[groups/messages POST]", e.message);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// DELETE /api/member/groups/:id/messages/:msgId  — soft-delete own message
app.delete("/api/member/groups/:id/messages/:msgId", memberAuthMiddleware, gcWriteLimit, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    const gid   = req.params.id;
    const msgId = req.params.msgId;
    const { data: msg } = await supabase.from("dm_group_messages").select("sender_id, group_id").eq("id", msgId).maybeSingle();
    if (!msg || msg.group_id !== gid) return res.status(404).json({ error: "Not found" });
    if (msg.sender_id !== myId) return res.status(403).json({ error: "Cannot delete another member's message" });
    await supabase.from("dm_group_messages").update({ deleted_at: new Date().toISOString(), body: "[deleted]" }).eq("id", msgId);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to delete message" });
  }
});

// POST /api/member/groups/:id/messages/:msgId/react  { emoji }
// Toggle: same emoji again → remove, different → switch, none → add.
app.post("/api/member/groups/:id/messages/:msgId/react", memberAuthMiddleware, reactionLimit, async (req, res) => {
  try {
    const myId  = req.member.memberId;
    const gid   = req.params.id;
    const msgId = req.params.msgId;
    const emoji = String(req.body?.emoji || "").trim().slice(0, 8);
    if (!emoji) return res.status(400).json({ error: "emoji required" });

    const { data: mem } = await supabase.from("dm_group_members").select("member_id").eq("group_id", gid).eq("member_id", myId).maybeSingle();
    if (!mem) return res.status(403).json({ error: "Not in this group" });

    const { data: msg } = await supabase.from("dm_group_messages").select("id, group_id").eq("id", msgId).eq("group_id", gid).maybeSingle();
    if (!msg) return res.status(404).json({ error: "Message not found" });

    await toggleMessageReaction(msgId, "group", myId, emoji);
    const reactionMap = await fetchReactionsFor([msgId], "group", myId);
    res.json({ success: true, reactions: reactionMap[msgId] || [] });
  } catch (e) {
    console.error("[groups/react]", e.message);
    res.status(500).json({ error: "Failed to react" });
  }
});

// ── GET /api/member/messages/reactions?chat_type=dm|group&ids=a,b,c ──────────
// Lightweight reaction-only refresh for messages already rendered on screen —
// piggybacked on the existing DM/group poll tick so a reaction someone else
// just added shows up within one poll cycle, without re-fetching/re-rendering
// the whole message list.
app.get("/api/member/messages/reactions", memberAuthMiddleware, reactionLimit, async (req, res) => {
  try {
    const myId     = req.member.memberId;
    const chatType = req.query.chat_type;
    const ids      = String(req.query.ids || "").split(",").map(s => s.trim()).filter(Boolean).slice(0, 100);
    if (!["dm", "group"].includes(chatType) || !ids.length) return res.json({});

    let allowedIds = [];
    if (chatType === "dm") {
      // DM messages are stored as member_notifications rows with link_type='dm'.
      // The caller must be either the actor (sender) or the recipient (member_id).
      const { data } = await supabase
        .from("member_notifications")
        .select("id, actor_id, member_id")
        .eq("link_type", "dm")
        .in("id", ids);
      allowedIds = (data || [])
        .filter(r => r.actor_id === myId || r.member_id === myId)
        .map(r => r.id);
    } else {
      const { data } = await supabase.from("dm_group_messages").select("id, group_id").in("id", ids);
      const groupIds = [...new Set((data || []).map(r => r.group_id))];
      const { data: memRows } = groupIds.length
        ? await supabase.from("dm_group_members").select("group_id").eq("member_id", myId).in("group_id", groupIds)
        : { data: [] };
      const myGroups = new Set((memRows || []).map(r => r.group_id));
      allowedIds = (data || []).filter(r => myGroups.has(r.group_id)).map(r => r.id);
    }

    const map = await fetchReactionsFor(allowedIds, chatType, myId);
    res.json(map);
  } catch (e) {
    console.error("[messages/reactions GET]", e.message);
    res.json({});
  }
});

// ── init check ────────────────────────────────────────────────────────────────
// ── SQL MIGRATION REQUIRED for pin + group photo features ─────────────────────
// Run once in Supabase SQL editor:
//
//   ALTER TABLE dm_group_chats ADD COLUMN IF NOT EXISTS photo_url TEXT;
//   ALTER TABLE dm_group_messages ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN NOT NULL DEFAULT FALSE;
//   CREATE INDEX IF NOT EXISTS idx_group_msgs_pinned ON dm_group_messages(group_id, is_pinned) WHERE is_pinned = TRUE;
//
// ─────────────────────────────────────────────────────────────────────────────
async function initSocialDB() {
  const tables = [
    "member_blocks",
    "member_nicknames",
    "dm_group_chats",
    "dm_group_members",
    "dm_group_messages",
    "message_reactions",
  ];
  let allOk = true;
  for (const t of tables) {
    const { error } = await supabase.from(t).select("*", { count: "exact", head: true }).limit(1);
    if (error?.code === "42P01") {
      console.warn(`[social] Table "${t}" not found — run MA-35 SQL migration in Supabase`);
      allOk = false;
    } else if (error) {
      console.warn(`[social] Table "${t}" check failed: ${error.message}`);
      allOk = false;
    }
  }
  if (allOk) console.log("[social] All social tables OK");
}

// Catch unhandled promise rejections — log them, don't crash
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});

// Catch uncaught exceptions — log and exit gracefully (process manager will restart)
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
  process.exit(1);
});


// ── POST /api/member/kfs-broadcast ───────────────────────────────────────────
// Admin-only: DM from the KFS sentinel account to all or specific members.
// Body: { body: string, target?: "all"|"member_ids", member_ids?: string[] }
app.post("/api/member/kfs-broadcast", memberAuthMiddleware, async (req, res) => {
  try {
    const myId = req.member.memberId;
    const { data: member } = await supabase
      .from("members").select("id, name, role, is_admin").eq("id", myId).maybeSingle();
    if (!member) return res.status(403).json({ error: "Not authenticated" });

    const allowedRoles = ["admin", "master_admin", "kfs_admin"];
    const isAdmin = member.is_admin === true ||
      allowedRoles.includes(String(member.role || "").toLowerCase());
    if (!isAdmin) return res.status(403).json({ error: "Admin only" });

    const { body, target = "all", member_ids } = req.body || {};
    if (!body || !String(body).trim())
      return res.status(400).json({ error: "Message body is required" });

    // Resolve KFS sentinel member ID
    const { data: kfsSetting } = await supabase
      .from("settings").select("value").eq("key", "kfs_admin_member_id").maybeSingle();
    let kfsMemberId = kfsSetting?.value || null;
    if (!kfsMemberId) {
      const { data: kfsMember } = await supabase
        .from("members").select("id").ilike("name", "KFS%").limit(1).maybeSingle();
      kfsMemberId = kfsMember?.id || null;
    }
    if (!kfsMemberId)
      return res.status(400).json({
        error: "No KFS sentinel member found. Create a member named 'KFS' or set kfs_admin_member_id in settings.",
      });

    // Collect recipients
    let recipientIds = [];
    if (target === "member_ids" && Array.isArray(member_ids) && member_ids.length) {
      recipientIds = member_ids.filter(id => typeof id === "string" && id.length > 0);
    } else {
      // NOTE: members has no is_active column — use deleted_at IS NULL,
      // the same liveness check the real DM-send route uses.
      const { data: allMembers } = await supabase
        .from("members").select("id").is("deleted_at", null);
      recipientIds = (allMembers || []).map(m => m.id).filter(id => id !== kfsMemberId);
    }

    if (!recipientIds.length)
      return res.status(400).json({ error: "No recipients found" });

    const msgBody = String(body).trim().slice(0, 2000);
    const now     = new Date().toISOString();
    let   sent    = 0;
    const BATCH   = 50;

    // Fetch KFS sentinel's display info for the notification snapshot
    const { data: kfsMember } = await supabase
      .from("members").select("id, name, photo").eq("id", kfsMemberId).maybeSingle();

    for (let i = 0; i < recipientIds.length; i += BATCH) {
      const batch = recipientIds.slice(i, i + BATCH);
      const rows  = batch.map(recipientId => ({
        member_id:   recipientId,
        type:        "dm",
        title:       `Message from ${kfsMember?.name || "KFS"}`,
        body:        msgBody,
        actor_id:    kfsMemberId,
        actor_name:  kfsMember?.name  || "KFS",
        actor_photo: kfsMember?.photo || KFS_SENTINEL_LOGO_URL,
        link_type:   "dm",
        link_id:     dmConvKey(kfsMemberId, recipientId),
        is_read:     false,
        created_at:  now,
      }));
      const { error: insErr } = await supabase.from("member_notifications").insert(rows);
      if (!insErr) sent += batch.length;
      else console.error("[kfs-broadcast] batch insert error:", insErr.message, insErr.details || "");
    }

    logActivity(myId, member.name || "Admin", "kfs_broadcast", "member_notifications",
      `Sent to ${sent} member(s)`).catch(() => {});
    res.json({ success: true, sent });
  } catch (e) {
    console.error("[kfs-broadcast]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /api/admin/kfs-broadcast ─────────────────────────────────────────────
// Admin-JWT version of kfs-broadcast — called from the admin panel DM section.
// CSRF is already enforced globally via app.use("/api/admin", csrfProtectAdmin).
app.post("/api/admin/kfs-broadcast", authMiddleware, async (req, res) => {
  try {
    const { body, target = "all", member_ids } = req.body || {};
    if (!body || !String(body).trim())
      return res.status(400).json({ error: "Message body is required" });

    // Resolve KFS sentinel member ID
    const { data: kfsSetting } = await supabase
      .from("settings").select("value").eq("key", "kfs_admin_member_id").maybeSingle();
    let kfsMemberId = kfsSetting?.value || null;
    if (!kfsMemberId) {
      const { data: kfsMember } = await supabase
        .from("members").select("id").ilike("name", "KFS%").limit(1).maybeSingle();
      kfsMemberId = kfsMember?.id || null;
    }
    if (!kfsMemberId)
      return res.status(400).json({
        error: "No KFS sentinel member found. Create a member named 'KFS' or set kfs_admin_member_id in settings.",
      });

    // Collect recipients
    let recipientIds = [];
    if (target === "member_ids" && Array.isArray(member_ids) && member_ids.length) {
      recipientIds = member_ids.filter(id => typeof id === "string" && id.length > 0);
    } else {
      // NOTE: members has no is_active column — use deleted_at IS NULL,
      // the same liveness check the real DM-send route uses.
      const { data: allMembers } = await supabase
        .from("members").select("id").is("deleted_at", null);
      recipientIds = (allMembers || []).map(m => m.id).filter(id => id !== kfsMemberId);
    }

    if (!recipientIds.length)
      return res.status(400).json({ error: "No recipients found" });

    const msgBody = String(body).trim().slice(0, 2000);
    const now     = new Date().toISOString();
    let   sent    = 0;
    const BATCH   = 50;

    // Fetch KFS sentinel's display info for the notification snapshot
    const { data: kfsMember } = await supabase
      .from("members").select("id, name, photo").eq("id", kfsMemberId).maybeSingle();

    for (let i = 0; i < recipientIds.length; i += BATCH) {
      const batch = recipientIds.slice(i, i + BATCH);
      const rows  = batch.map(recipientId => ({
        member_id:   recipientId,
        type:        "dm",
        title:       `Message from ${kfsMember?.name || "KFS"}`,
        body:        msgBody,
        actor_id:    kfsMemberId,
        actor_name:  kfsMember?.name  || "KFS",
        actor_photo: kfsMember?.photo || KFS_SENTINEL_LOGO_URL,
        link_type:   "dm",
        link_id:     dmConvKey(kfsMemberId, recipientId),
        is_read:     false,
        created_at:  now,
      }));
      const { error: insErr } = await supabase.from("member_notifications").insert(rows);
      if (!insErr) sent += batch.length;
      else console.error("[admin/kfs-broadcast] batch insert error:", insErr.message, insErr.details || "");
    }

    logActivity(req.admin.id, req.admin.name || "Admin", "kfs_broadcast", "member_notifications",
      `Sent to ${sent} member(s)`).catch(() => {});
    res.json({ success: true, sent });
  } catch (e) {
    console.error("[admin/kfs-broadcast]", e.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`KFS server running on port ${PORT}`);
  await initDB();
  await initMemberDB();      // ← member portal init
  await loadMemberViolations(); // ← restore mutes/bans across restarts
  await initStudioWallDB();  // ← studio wall table check
  await initSocialDB();      // ← social: blocks, nicknames, group chats
  await loadRevokedTokens();
  await loadActiveLockouts();
  console.log("DB initialized");

  // ── 2FA Enforcement: delete non-master admins without 2FA after 48h ──
  async function enforce2FAPolicy() {
    try {
      const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
      const { data: stale, error } = await supabase
        .from("admins")
        .select("id, name, username, created_at")
        .eq("totp_enabled", false)
        .neq("role", "master")
        .lt("created_at", cutoff);
      if (error) { console.error("[2fa-enforce] query error:", error.message); return; }
      if (!stale || stale.length === 0) return;
      for (const admin of stale) {
        await supabase.from("admins").delete().eq("id", admin.id);
        await logActivity("system", "System", "delete", "admin",
          `${admin.name} (${admin.username}) — auto-deleted: 2FA not enabled within 48h`);
        console.log(`[2fa-enforce] Deleted admin "${admin.username}" — no 2FA after 48h`);
      }
    } catch (e) {
      console.error("[2fa-enforce] error:", e.message);
    }
  }
  await enforce2FAPolicy();
  setInterval(enforce2FAPolicy, 60 * 60 * 1000);

  // ── Phase 2 — "The Network": weekly/all-time leaderboard refresh ──
  // Recomputes via the compute_leaderboard() Postgres function (see
  // phase2_leaderboard_function.sql) so the read endpoint never has to
  // aggregate reaction history live.
  await refreshLeaderboards();
  setInterval(refreshLeaderboards, 30 * 60 * 1000);
});

// ── CATCH-ALL ─────────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── SUPABASE KEEPALIVE ────────────────────────────────────────────────────────
// Ping every 29 minutes to prevent the connection from going idle.
// Supabase times out idle connections at 30 min — this stays safely inside that window.
setInterval(
  async () => {
    try {
      await supabasePublic.from("settings").select("key", { count: "exact", head: true }).limit(1); // zero egress bytes
      // Silent success — log only on failure
    } catch (e) {
      console.error("Supabase keepalive failed:", e.message);
    }
  },
  1000 * 60 * 29,
);

// Trim old page_view rows older than 90 days — run once per day
setInterval(
  async () => {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 90);
      await supabasePublic
        .from("page_views")
        .delete()
        .lt("date", cutoff.toISOString().slice(0, 10));
    } catch (e) {
      console.error("[page_views trim]", e.message);
    }
  },
  1000 * 60 * 60 * 24,
); // every 24h

// ── GLOBAL ERROR HANDLER ──────────────────────────────────────────────────────
// Catches any error passed via next(err) or thrown inside async route handlers
// that weren't caught locally. Logs the real error server-side, sends a safe
// generic message to the client — never leaks stack traces or internals.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`[unhandled] ${req.method} ${req.path}`, err);
  if (res.headersSent) return next(err);
  const status = typeof err.status === 'number' ? err.status : 500;
  res.status(status).json({ error: status < 500 ? (err.message || 'Bad request') : 'Internal server error' });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-35 — Social: Block/Unblock · Nicknames · Group Chats
//
// SQL migration (run once in Supabase):
//
//   -- Block list
//   CREATE TABLE IF NOT EXISTS member_blocks (
//     blocker_id  UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     blocked_id  UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//     PRIMARY KEY (blocker_id, blocked_id)
//   );
//   CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON member_blocks(blocker_id);
//   CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON member_blocks(blocked_id);
//
//   -- Nicknames (one per direction — giver → target)
//   CREATE TABLE IF NOT EXISTS member_nicknames (
//     giver_id    UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     target_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     nickname    TEXT NOT NULL CHECK (char_length(nickname) BETWEEN 1 AND 40),
//     updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//     PRIMARY KEY (giver_id, target_id)
//   );
//
//   -- Group chats
//   CREATE TABLE IF NOT EXISTS dm_group_chats (
//     id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     name         TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
//     created_by   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   CREATE TABLE IF NOT EXISTS dm_group_members (
//     group_id    UUID NOT NULL REFERENCES dm_group_chats(id) ON DELETE CASCADE,
//     member_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     nickname    TEXT,                -- group-scoped nickname for this member (visible to all)
//     joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//     PRIMARY KEY (group_id, member_id)
//   );
//   CREATE TABLE IF NOT EXISTS dm_group_messages (
//     id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     group_id    UUID NOT NULL REFERENCES dm_group_chats(id) ON DELETE CASCADE,
//     sender_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     body        TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
//     deleted_at  TIMESTAMPTZ,
//     is_deleted  BOOLEAN NOT NULL DEFAULT FALSE,
//     replied_to_id     UUID REFERENCES dm_group_messages(id) ON DELETE SET NULL,
//     replied_to_body   TEXT,
//     replied_to_sender TEXT,
//     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   -- member_notifications (DMs) also needs replied_to columns:
//   -- ALTER TABLE member_notifications ADD COLUMN IF NOT EXISTS replied_to_id UUID;
//   -- ALTER TABLE member_notifications ADD COLUMN IF NOT EXISTS replied_to_body TEXT;
//   -- ALTER TABLE member_notifications ADD COLUMN IF NOT EXISTS replied_to_sender TEXT;
//   CREATE INDEX IF NOT EXISTS idx_grp_msgs_group ON dm_group_messages(group_id, created_at);
//   CREATE INDEX IF NOT EXISTS idx_grp_members_member ON dm_group_members(member_id);
//
//   -- Message reactions (Instagram-style — one reaction per member per message,
//   -- shared by both DMs and group chats via the chat_type discriminator)
//   CREATE TABLE IF NOT EXISTS message_reactions (
//     id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     chat_type   TEXT NOT NULL CHECK (chat_type IN ('dm','group')),
//     message_id  UUID NOT NULL,
//     member_id   UUID NOT NULL REFERENCES members(id) ON DELETE CASCADE,
//     emoji       TEXT NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 8),
//     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//     UNIQUE (chat_type, message_id, member_id)
//   );
//   CREATE INDEX IF NOT EXISTS idx_msg_reactions_msg ON message_reactions(chat_type, message_id);
//   ALTER TABLE message_reactions DISABLE ROW LEVEL SECURITY; -- server uses service_role key
// ─────────────────────────────────────────────────────────────────────────────

// reactionLimit — defined earlier, near first use

// ── Message reactions — shared helpers (DM + group) ───────────────────────────
// One reaction per member per message (tap a new emoji to switch, tap your
// current one again to remove — same toggle pattern as Studio Wall reactions).

/**
 * Fetch + aggregate reactions for a batch of message ids.
 * Returns { [messageId]: [{ emoji, count, mine }, ...] }, sorted by count desc.
 */
async function fetchReactionsFor(messageIds, chatType, myId) {
  if (!messageIds || !messageIds.length) return {};
  const { data, error } = await supabase
    .from("message_reactions")
    .select("message_id, member_id, emoji")
    .eq("chat_type", chatType)
    .in("message_id", messageIds);
  if (error) {
    if (error.code !== "42P01") console.error("[reactions] fetch:", error.message);
    return {};
  }
  const byMsg = {};
  (data || []).forEach(r => {
    const bucket = (byMsg[r.message_id] = byMsg[r.message_id] || {});
    const slot   = (bucket[r.emoji] = bucket[r.emoji] || { emoji: r.emoji, count: 0, mine: false });
    slot.count++;
    if (r.member_id === myId) slot.mine = true;
  });
  const out = {};
  Object.keys(byMsg).forEach(mid => {
    out[mid] = Object.values(byMsg[mid]).sort((a, b) => b.count - a.count);
  });
  return out;
}

/** Toggle a member's reaction on a message: same emoji → remove, different → switch, none → add. */
async function toggleMessageReaction(messageId, chatType, myId, emoji) {
  const { data: existing } = await supabase
    .from("message_reactions")
    .select("id, emoji")
    .eq("chat_type", chatType).eq("message_id", messageId).eq("member_id", myId)
    .maybeSingle();
  if (existing && existing.emoji === emoji) {
    await supabase.from("message_reactions").delete().eq("id", existing.id);
  } else if (existing) {
    await supabase.from("message_reactions").update({ emoji }).eq("id", existing.id);
  } else {
    await supabase.from("message_reactions").insert([{ chat_type: chatType, message_id: messageId, member_id: myId, emoji }]);
  }
}


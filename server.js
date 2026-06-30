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
   
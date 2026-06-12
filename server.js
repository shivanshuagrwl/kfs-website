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

  const bodyHtml = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
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
      scriptSrc: ["'self'", "'sha256-+66rGdTLpDfofX3X9tPnOXG2mk883HeaJVj/Zy2m7VQ='", "'sha256-2asVaJiBS57Wr2ER9jyWn0odi19ZVJql169KxTpB7d4='", "'sha256-BA2H1D/U01IDrFsnrXJATwOAqtE8Q6nevz3CatpZuww='", "https://cdnjs.cloudflare.com", "https://checkout.razorpay.com", "https://cdn.razorpay.com"],
      scriptSrcAttr: ["'unsafe-inline'"], // required: movie/blog cards use onclick in JS templates
      imgSrc: [
        "'self'", "data:",
        "https://res.cloudinary.com",
        "https://*.supabase.co",
        "https://img.youtube.com",       // YouTube thumbnails
        "https://i.ytimg.com",           // YouTube thumbnails (alternate CDN)
        "https://*.razorpay.com",        // Razorpay checkout images
      ],
      connectSrc: [
        "'self'",
        "https://api.brevo.com",
        "https://*.supabase.co",         // Supabase realtime + API calls
        "https://api.razorpay.com",      // Razorpay order/payment API
        "https://lumberjack.razorpay.com", // Razorpay analytics/logging
      ],
      frameSrc: [
        "https://www.youtube.com",       // YouTube embeds
        "https://open.spotify.com",      // Spotify embeds
        "https://embed.music.apple.com", // Apple Music embeds
        "https://api.razorpay.com",      // Razorpay checkout iframe
        "https://*.razorpay.com",        // Razorpay checkout modal
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
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
async function logActivity(adminId, adminName, action, entity, entityName) {
  try {
    await supabase.from("admin_activity").insert([
      {
        admin_id: adminId,
        admin_name: adminName,
        action,
        entity,
        entity_name: entityName,
      },
    ]);
  } catch (e) {
    console.error("Activity log error:", e);
  }
}

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
    return `Account locked. Try again in ${timeStr}.`;
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
    const lockMsg = checkLoginLockout(normalised);
    if (lockMsg) return res.status(429).json({ error: lockMsg });

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
    });
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

// Protect all admin and master write routes.
// /login and /refresh are exempt — login uses rate-limit+bcrypt, refresh uses httpOnly cookie.
// When mounted at /api/admin, req.path is the remainder e.g. "/login", "/refresh".
function csrfProtectAdmin(req, res, next) {
  // login and refresh have their own protections — exempt from CSRF
  if (req.path.startsWith("/login") || req.path.startsWith("/refresh")) return next();
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
    // Token reuse detected — possible theft, revoke ALL tokens for this admin
    await revokeAllForAdmin(stored.admin_id);
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token already used — all sessions revoked" });
  }

  if (new Date(stored.expires_at) < new Date()) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Refresh token expired" });
  }

  // Mark as used (single-use)
  await supabase
    .from("refresh_tokens")
    .update({ used: true })
    .eq("id", stored.id);

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

  console.log(`[refresh] ${admin.username} — role: ${admin.role}`);
  res.json({ token: accessToken, name: admin.name, role: admin.role, permissions: perms });
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
  const { name, username, password, permissions } = req.body;
  if (!name || !username || !password)
    return res
      .status(400)
      .json({ error: "Name, username and password required" });
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
      },
    ])
    .select("id,name,username,role,permissions,created_at")
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

// ── SETTINGS ──────────────────────────────────────────────────────────────────
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
  const data = await memCache("blogs:list", 120, async () => {
    const { data } = await supabasePublic
      .from("blogs")
      .select(
        "id,title,author,excerpt,cover_image,published,created_at,sections,view_count",
      )
      .eq("published", true)
      .order("created_at", { ascending: false });
    return data || [];
  });
  res.json(data);
});

app.get("/api/admin/blogs", requireSection("blogs"), async (req, res) => {
  const { data } = await supabase
    .from("blogs")
    .select(
      "id,title,author,published,view_count,cover_image,created_at,sections",
    )
    // Don't fetch `content` in the list — it's huge HTML. Only needed in /api/blogs/:id
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
      .maybeSingle();
    return data;
  });
  if (!data) return res.status(404).json({ error: "Not found" });

  // Fire-and-forget view increment — runs on every real HTTP request (not on cache hits),
  // because this code is outside the memCache fn. Uses DB increment to avoid race conditions.
  supabasePublic.rpc("increment_blog_view", { blog_id: req.params.id })
    .then(() => {})
    .catch(() => {
      // Fallback if RPC doesn't exist yet: raw update still better than nothing
      supabasePublic
        .from("blogs")
        .update({ view_count: (data.view_count || 0) + 1 })
        .eq("id", req.params.id)
        .then(() => {}).catch(() => {});
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
      .select("title")
      .eq("id", req.params.id)
      .single();
    await supabase.from("blogs").delete().eq("id", req.params.id);
    memInvalidate("blogs:list", `blogs:${req.params.id}`);
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "blog",
      b?.title || req.params.id,
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
      is_upcoming,
    } = req.body;
    const updates = {
      title,
      description,
      event_date,
      event_time,
      location,
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
      .select("title")
      .eq("id", req.params.id)
      .single();
    await supabase.from("events").delete().eq("id", req.params.id);
    memInvalidate("events:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "event",
      e?.title || req.params.id,
    ).catch(e => console.error("[activity]", e.message));
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
      .order("sort_order", { ascending: true });

    // If social/portal columns don't exist yet, fall back to base columns
    if (error) {
      console.warn("[members] Full select failed (missing columns?), trying base columns:", error.message);
      const { data: base } = await supabase
        .from("members")
        .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past")
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
    .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past,instagram,github,linkedin,twitter,youtube,website,custom_links")
    .order("sort_order", { ascending: true });

  if (error) {
    // Likely means some columns (instagram, custom_links etc.) don't exist yet — run member portal migration
    console.warn("[admin/members] Full select failed, falling back to base columns:", error.message);
    const fallback = await supabase
      .from("members")
      .select("id,name,role,batch,bio,domain,photo,special_tag,sort_order,is_past")
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
    const { name, role, batch, bio, sort_order, is_past, domain, special_tag } =
      req.body;
    if (!name || !name.trim())
      return res.status(400).json({ error: "Name is required" });

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
    const { name, role, batch, bio, sort_order, is_past, domain, special_tag } =
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
      .select("name")
      .eq("id", req.params.id)
      .single();
    await supabase.from("members").delete().eq("id", req.params.id);
    memInvalidate("members:list");
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "member",
      m?.name || req.params.id,
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
  // genre filter busts the general cache key
  const cacheKey = req.query.genre
    ? `movies:genre:${req.query.genre}`
    : "movies:list";
  const movies = await memCache(cacheKey, 300, async () => {
    let query = supabasePublic
      .from("movies")
      .select(
        "id,title,release_year,genre,director,producer,dop,screenwriter,video_editor,sound_design,management,graphic_design,actors,support_crew,poster_image,description,trailer_url,watch_url",
      )
      .order("release_year", { ascending: false });
    const { data } = await query;
    let result = data || [];
    if (req.query.genre) {
      const filterGenre = req.query.genre.toLowerCase();
      result = result.filter((m) =>
        parseGenre(m.genre).some((g) => g.toLowerCase() === filterGenre),
      );
    }
    return result.map((m) => ({ ...m, genre: parseGenre(m.genre) }));
  });
  res.json(movies);
});

app.get("/api/movies/:id", async (req, res) => {
  cacheFor(res, 120);
  const data = await memCache(`movies:${req.params.id}`, 300, async () => {
    const { data } = await supabasePublic
      .from("movies")
      .select("*")
      .eq("id", req.params.id)
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
      .select("title")
      .eq("id", req.params.id)
      .single();
    await supabase.from("movies").delete().eq("id", req.params.id);
    memInvalidate("movies:list", "movies:genre:", `movies:${req.params.id}`);
    logActivity(
      req.admin.id,
      req.admin.name,
      "delete",
      "movie",
      mv?.title || req.params.id,
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
    const range = req.query.range || "24h";
    let fromDate = new Date();
    if (range === "24h") fromDate.setDate(fromDate.getDate() - 7);
    else if (range === "30d") fromDate.setDate(fromDate.getDate() - 30);
    else fromDate = new Date("2020-01-01");
    const from = fromDate.toISOString().slice(0, 10);
    const today = new Date().toISOString().slice(0, 10);

    // All-time total — always fetched regardless of range, using COUNT to avoid row limits
    let allTimeTotal = 0;
    try {
      const { count, error } = await supabase
        .from("page_views")
        .select("*", { count: "exact", head: true });
      if (!error) allTimeTotal = count || 0;
    } catch (e) {
      /* non-fatal */
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
        total: allTimeTotal,
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
      total: allTimeTotal,
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

// ADMIN: Create or update (upsert) the registration form for an event
app.post(
  "/api/admin/events/:id/form",
  requireSection("events"),
  async (req, res) => {
    const { title, description, questions, is_open } = req.body;
    if (!Array.isArray(questions))
      return res.status(400).json({ error: "questions must be an array" });

    // Validate each question minimally
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
      questions: JSON.stringify(questions),
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

  // 3. Validate required fields against schema
  let questions = [];
  try {
    questions = JSON.parse(form.questions || "[]");
  } catch (e) {}

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
        .select("id,title,event_date,location,is_upcoming")
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

  res.json({ success: true, id: response.id });
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
    const emailLower = payload.contact_email.toLowerCase();
    const isKiitDomain =
      emailLower.endsWith("@kiit.ac.in") ||
      emailLower.includes(".kiit.ac.in") ||
      emailLower.endsWith("@ksom.ac.in") ||
      emailLower.endsWith("@kiitbiotech.ac.in");
    if (!isKiitDomain) {
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

  const { data, error } = await supabasePublic
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

  const { error } = await supabasePublic
    .from("collaborate_posts")
    .delete()
    .eq("edit_token", req.params.token);

  if (error) return res.status(500).json({ error: "Internal server error" });
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
  requireSection("settings"),
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
  requireSection("settings"),
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
  requireSection("settings"),
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
  requireSection("settings"),
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
  requireSection("settings"),
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

  <!-- ── Outer card ── -->
  <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%">

    <!-- Logo row -->
    <tr><td align="center" style="padding-bottom:24px">
      <table role="presentation" cellpadding="0" cellspacing="0">
        <tr>
          <td style="background:#fff;border-radius:12px;width:40px;height:40px;text-align:center;vertical-align:middle;font-size:12px;font-weight:900;color:#000;letter-spacing:-.5px;line-height:40px">KFS</td>
          <td style="padding-left:10px;vertical-align:middle">
            <div style="font-size:14px;font-weight:700;color:#f5f5f7;letter-spacing:-.01em">KIIT Film Society</div>
            <div style="font-size:11px;color:#636366;margin-top:1px">Event Entry Ticket</div>
          </td>
        </tr>
      </table>
    </td></tr>

    <!-- Main ticket card -->
    <tr><td style="background:#1c1c1e;border-radius:20px;overflow:hidden;border:1px solid #2c2c2e">

      <!-- ── Accent bar ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="background:linear-gradient(90deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);height:6px;font-size:0;line-height:0">&nbsp;</td></tr>
      </table>

      <!-- ── Event header ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:28px 32px 24px">
          <div style="font-size:10px;font-weight:700;color:#636366;letter-spacing:.14em;text-transform:uppercase;margin-bottom:10px">You're in ✓</div>
          <div style="font-size:28px;font-weight:800;color:#f5f5f7;line-height:1.15;letter-spacing:-.03em">${(event.title || "Event").replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
          ${eventDate ? `<div style="margin-top:12px;font-size:14px;color:#aeaeb2;font-weight:500">${eventDate}</div>` : ""}
          ${event.location ? `<div style="margin-top:4px;font-size:13px;color:#636366">${event.location.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>` : ""}
          <!-- CONFIRMED badge -->
          <div style="margin-top:16px">
            <span style="display:inline-block;background:rgba(52,199,89,.15);border:1px solid rgba(52,199,89,.35);border-radius:20px;padding:5px 14px;font-size:11px;font-weight:700;color:#34c759;letter-spacing:.06em;text-transform:uppercase">● Confirmed</span>
          </div>
        </td></tr>
      </table>

      <!-- ── Perforated tear line ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="20" style="background:#0a0a0a;border-radius:0 20px 20px 0;font-size:0;line-height:0">&nbsp;</td>
          <td style="border-top:2px dashed #3a3a3c;height:0;font-size:0;line-height:0;padding:0">&nbsp;</td>
          <td width="20" style="background:#0a0a0a;border-radius:20px 0 0 20px;font-size:0;line-height:0">&nbsp;</td>
        </tr>
      </table>

      <!-- ── QR + Attendee section ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:28px 32px 32px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr>

              <!-- QR code — Cloudinary-hosted URL (data: URIs are blocked by Gmail/Outlook/Apple Mail) -->
              <td align="center" style="width:148px;vertical-align:top">
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr><td style="background:#fff;border-radius:14px;padding:10px;display:inline-block">
                    ${qrHostedUrl
                      ? `<img src="${qrHostedUrl}" width="128" height="128" alt="Entry QR Code" style="display:block;width:128px;height:128px;border:none;outline:none" />`
                      : `<div style="width:128px;height:128px;display:flex;align-items:center;justify-content:center;text-align:center;font-size:11px;color:#636366;font-family:Helvetica,Arial,sans-serif;line-height:1.4">QR code in<br>PDF attachment</div>`
                    }
                  </td></tr>
                </table>
                <div style="margin-top:10px;font-size:10px;font-weight:600;color:#636366;letter-spacing:.08em;text-transform:uppercase;text-align:center">Scan at entry</div>
              </td>

              <!-- Divider -->
              <td width="1" style="border-left:1px dashed #3a3a3c;padding:0 20px;font-size:0;line-height:0">&nbsp;</td>

              <!-- Attendee details -->
              <td style="padding-left:24px;vertical-align:middle">
                <div style="font-size:10px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:12px">Attendee</div>
                <div style="font-size:22px;font-weight:800;color:#f5f5f7;letter-spacing:-.02em;line-height:1.2">${reg.name.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
                <div style="font-size:12px;color:#636366;margin-top:6px;word-break:break-all">${reg.email.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>

                ${reg.roll_no ? `
                <!-- Roll No pill -->
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:14px">
                  <tr><td style="background:#2c2c2e;border-radius:9px;padding:8px 14px">
                    <div style="font-size:9px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:3px">Roll No</div>
                    <div style="font-size:14px;font-weight:700;color:#f5f5f7;letter-spacing:.04em">${reg.roll_no.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>
                  </td></tr>
                </table>` : ""}

                ${eventDateShort ? `
                <!-- Date pill -->
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:8px">
                  <tr><td style="background:#2c2c2e;border-radius:9px;padding:8px 14px">
                    <div style="font-size:9px;font-weight:700;color:#636366;letter-spacing:.12em;text-transform:uppercase;margin-bottom:3px">Date</div>
                    <div style="font-size:14px;font-weight:700;color:#f5f5f7">${eventDateShort}</div>
                  </td></tr>
                </table>` : ""}
              </td>

            </tr>
          </table>
        </td></tr>
      </table>

      <!-- ── Footer strip ── -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="background:#111;border-top:1px solid #2c2c2e;padding:18px 32px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="font-size:13px;font-weight:600;color:#f5f5f7">See you there!</td>
              <td align="right" style="font-size:11px;color:#48484a">
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
      <div style="font-size:11px;color:#3a3a3c;text-align:center;line-height:1.6">
        This ticket is personal and non-transferable.<br>
        Do not share your QR code with others.
      </div>
    </td></tr>

  </table>
  <!-- End outer card -->

</td></tr>
</table>
</body>
</html>`;

  const textContent = `Your KFS Ticket — ${event.title || "Event"}\n\n${eventDate ? eventDate + "\n" : ""}${event.location ? event.location + "\n" : ""}\nName: ${reg.name}\nEmail: ${reg.email}${reg.roll_no ? "\nRoll No: " + reg.roll_no : ""}\n\nYour QR ticket is attached to this email as a PDF.\nOpen the PDF attachment and show the QR code at the entry gate.\n\nSee you there!\nFor queries: filmsocietykiit@gmail.com`;

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
  keyGenerator: (req) => req.ip,
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
    .select("id,title,event_date,location,is_upcoming")
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

const MEMBER_JWT_SECRET = process.env.MEMBER_JWT_SECRET || process.env.JWT_SECRET + "_member";
// NOTE: Set MEMBER_JWT_SECRET as its own env var in Render for proper isolation.

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
    return `Account locked. Try again in ${timeStr}.`;
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
  const loginUrl    = "https://kiitfilmsociety.in/membersaccess";
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
  if (req.path.startsWith("/login") || req.path.startsWith("/refresh")) return next();
  return csrfProtect(req, res, next);
}
app.use("/api/member", csrfProtectMember);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-10 — Member portal page route
// ─────────────────────────────────────────────────────────────────────────────

app.get("/membersaccess", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "membersaccess.html"));
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

    const lockMsg = checkMemberLockout(normalised);
    if (lockMsg) return res.status(429).json({ error: lockMsg });

    const { data: account } = await supabase
      .from("member_accounts")
      .select("*, members(id, name, role, batch, domain, photo)")
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
    });
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

  res.json({ token: accessToken });
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
    .select("id,name,roll_no,mobile,batch,bio,domain,role,photo,special_tag,sort_order,is_past,instagram,linkedin,github,twitter,youtube,website,custom_links,email,updated_at")
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
    .from("members").select("id, name, roll_no, email").eq("id", memberId).maybeSingle();
  if (!member) return res.status(404).json({ error: "Member not found" });

  // Check if account already exists
  const { data: existing } = await supabase
    .from("member_accounts").select("id, username").eq("member_id", memberId).maybeSingle();
  if (existing) return res.status(409).json({ error: "Account already exists", username: existing.username });

  const username  = await generateMemberUsername(member.name, member.roll_no);
  const tempPw    = "Kfs@2026";
  const hash      = await bcrypt.hash(tempPw, 10);

  const { data: account, error } = await supabase
    .from("member_accounts")
    .insert([{ member_id: memberId, username, password_hash: hash, must_change_password: true }])
    .select().single();
  if (error) return res.status(500).json({ error: "Internal server error" });

  logActivity(req.admin.id, req.admin.name, "create", "member_account", username).catch(() => {});
  res.json({ success: true, username, tempPassword: tempPw, accountId: account.id, email: member.email || null });
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
    res.json({ success: true, publishedMovieId: publishedMovieId || null });
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-21 — Admin: Member Activity & Monitoring
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/admin/members/:id/activity", requireSection("members"), async (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 30);
  const { data } = await supabase
    .from("member_activity")
    .select("id, action, metadata, ip_address, created_at")
    .eq("member_id", req.params.id)
    .order("created_at", { ascending: false })
    .range((page - 1) * limit, page * limit - 1);
  res.json(data || []);
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION MA-22 — initMemberDB (call inside existing app.listen callback)
// ─────────────────────────────────────────────────────────────────────────────
// Add this call inside the existing app.listen() callback, alongside initDB():
//   await initMemberDB();

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
      .select("id, title, release_year, poster_image, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew");

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

// ── SCANNER PAGE — must be above the catch-all ────────────────────────────────
app.get("/scanner", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "scanner.html"));
});
app.get("/scanner.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  res.sendFile(path.join(__dirname, "public", "scanner.js"));
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

// Catch unhandled promise rejections — log them, don't crash
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});

// Catch uncaught exceptions — log and exit gracefully (process manager will restart)
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
  process.exit(1);
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`KFS server running on port ${PORT}`);
  await initDB();
  await initMemberDB();   // ← member portal init
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
});

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Supabase ──────────────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false },
  db: { schema: 'public' },
  global: {
    headers: { 'x-application-name': 'kfs-server' },
  },
});

// Retry wrapper for transient Supabase failures (network blips, cold starts)
async function sbQuery(fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (e) {
      const isLast = i === retries - 1;
      if (isLast) throw e;
      await new Promise(r => setTimeout(r, 300 * (i + 1)));
    }
  }
}

// ── Email helper (Brevo HTTP API — works on all hosts) ────────────────────────
async function sendConfirmationEmail({ toEmail, toName, eventTitle, eventDate, eventVenue }) {
  const { data: rows } = await supabase.from('settings').select('key,value')
    .in('key', ['brevo_api_key','smtp_from_name','email_confirmation_body']);
  const s = {};
  (rows || []).forEach(r => s[r.key] = r.value);

  if (!s.brevo_api_key) {
    console.warn('[email] Brevo API key not configured — skipping confirmation email');
    return;
  }

  const defaultBody = `Hi {{name}},\n\nYou're confirmed for {{event}}!{{date_line}}{{venue_line}}\n\nSee you there!\n\nWarm regards,\nKFS — KIIT Film Society`;
  let bodyTemplate = s.email_confirmation_body || defaultBody;
  const dateLine  = eventDate  ? `\n\nDate: ${new Date(eventDate).toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}` : '';
  const venueLine = eventVenue ? `\nVenue: ${eventVenue}` : '';

  const bodyText = bodyTemplate
    .replace(/{{name}}/g,       toName || 'there')
    .replace(/{{event}}/g,      eventTitle || '')
    .replace(/{{date_line}}/g,  dateLine)
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
    <h2 style="font-size:22px;font-weight:700;color:#f5f5f5;margin:0 0 20px;letter-spacing:-.02em">${eventTitle || 'Event'}</h2>
    <div style="font-size:15px;line-height:1.7;color:#aaa;white-space:pre-line">${bodyText.split('\n').join('<br>')}</div>
    ${dateLine || venueLine ? `<div style="margin:24px 0;padding:16px 20px;background:#1a1a1a;border-radius:12px;border:1px solid #1e1e1e;font-size:13px;color:#888">
      ${eventDate ? `<div style="margin-bottom:6px">📅 <span style="color:#f5f5f5">${new Date(eventDate).toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}</span></div>` : ''}
      ${eventVenue ? `<div>📍 <span style="color:#f5f5f5">${eventVenue}</span></div>` : ''}
    </div>` : ''}
  </td></tr>
  <tr><td style="padding:20px 36px 28px;border-top:1px solid #1e1e1e">
    <p style="font-size:12px;color:#444;margin:0">This is an automated confirmation from <a href="https://kiitfilmsociety.in" style="color:#666;text-decoration:none">kiitfilmsociety.in</a>. Please do not reply to this email.</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;

  const fromName = s.smtp_from_name || 'KFS — KIIT Film Society';

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': s.brevo_api_key,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: { name: fromName, email: 'noreply@kiitfilmsociety.in' },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject: `You're registered for ${eventTitle || 'the event'} — KFS`,
      textContent: bodyText,
      htmlContent: bodyHtml,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${err}`);
  }
  console.log(`[email] Confirmation sent to ${toEmail} for event "${eventTitle}"`);
}


const JWT_SECRET = process.env.JWT_SECRET;

// ── File uploads ──────────────────────────────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

async function uploadImage(file, folder = 'general') {
  if (!file) return null;
  const ext = path.extname(file.originalname) || '.jpg';
  const filename = `${folder}/${Date.now()}${ext}`;
  const { data, error } = await supabase.storage
    .from('kfs-media')
    .upload(filename, file.buffer, { contentType: file.mimetype, upsert: true });
  if (error) {
    const msg = error.message || JSON.stringify(error);
    console.error('Storage error:', msg);
    throw new Error('Supabase storage: ' + msg);
  }
  const { data: urlData } = supabase.storage.from('kfs-media').getPublicUrl(filename);
  return urlData.publicUrl;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// Master-only middleware
function masterMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('masterMiddleware decoded role:', decoded.role, 'username:', decoded.username);
    if (decoded.role !== 'master') return res.status(403).json({ error: 'Master access only' });
    req.admin = decoded;
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

// Section permission middleware — master bypasses, regular admins checked
function requireSection(section) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.admin = decoded;
      if (decoded.role === 'master') return next(); // master always passes
      const perms = decoded.permissions || [];
      // Empty array = legacy admin with no permissions set yet = full access
      if (perms.length === 0 || perms.includes(section)) return next();
      return res.status(403).json({ error: `No permission for section: ${section}` });
    } catch { res.status(401).json({ error: 'Invalid token' }); }
  };
}

// ── Activity logger ───────────────────────────────────────────────────────────
async function logActivity(adminId, adminName, action, entity, entityName) {
  try {
    await supabase.from('admin_activity').insert([{
      admin_id: adminId,
      admin_name: adminName,
      action,
      entity,
      entity_name: entityName,
    }]);
  } catch(e) { console.error('Activity log error:', e); }
}

// ── DB Init ───────────────────────────────────────────────────────────────────
async function initDB() {
  try {
    // Use maybeSingle() — returns null (not an error) when no row exists
    const { data: master, error: masterErr } = await supabase
      .from('admins').select('id').eq('role', 'master').maybeSingle();
    if (masterErr) throw new Error('admins table query failed: ' + masterErr.message);

    if (!master) {
      const hash = await bcrypt.hash('KFS@master2024!', 10);
      const { error: insertErr } = await supabase.from('admins').insert([{
        name: 'KFS Master',
        username: 'kfsmaster',
        password_hash: hash,
        role: 'master',
      }]);
      if (insertErr) throw new Error('Master admin insert failed: ' + insertErr.message);
      console.log('Master admin created: username=kfsmaster password=KFS@master2024!');
    }

    // Check if settings are seeded (use maybeSingle to avoid crash on missing row)
    const { data: tagline } = await supabase
      .from('settings').select('key').eq('key', 'site_tagline').maybeSingle();
    if (!tagline) {
      await supabase.from('settings').insert([
        { key: 'site_tagline', value: 'Lights. Camera. KFS.' },
        { key: 'about_text', value: 'KIIT Film Society is a student-run collective passionate about cinema.' },
        { key: 'instagram', value: '' },
        { key: 'youtube', value: '' },
        { key: 'email', value: 'kfs@kiit.ac.in' },
      ]).then(() => {}).catch(() => {});
    }
  } catch (e) {
    console.error('initDB error:', e.message);
    // Don't crash the server — Supabase may be temporarily unreachable
  }
}

// ── ROBOTS.TXT ────────────────────────────────────────────────────────────────
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(
    'User-agent: *\n' +
    'Allow: /\n' +
    'Disallow: /api/\n' +
    '\n' +
    'Sitemap: https://kiitfilmsociety.in/sitemap.xml\n'
  );
});

// ── SHARED UTILITIES ──────────────────────────────────────────────────────────
// Turn a title into a URL slug — mirrors the frontend slugify helper
function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ── SITEMAP.XML ───────────────────────────────────────────────────────────────
app.get('/sitemap.xml', async (req, res) => {
  const today = new Date().toISOString().split('T')[0];

  // ── Movies ────────────────────────────────────────────────────────────────
  let movieUrls = '';
  try {
    const { data: movies } = await supabase
      .from('movies')
      .select('id, title, updated_at')
      .order('release_year', { ascending: false })
      .limit(200);
    if (movies && movies.length > 0) {
      movieUrls = movies.map(mv => {
        const slug = slugify(mv.title) + '-' + mv.id;
        const lastmod = mv.updated_at ? mv.updated_at.split('T')[0] : today;
        return `  <url>\n    <loc>https://kiitfilmsociety.in/films/${slug}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.8</priority>\n  </url>`;
      }).join('\n');
    }
  } catch (e) { /* non-fatal */ }

  // ── Blogs ─────────────────────────────────────────────────────────────────
  let blogUrls = '';
  try {
    const { data: blogs } = await supabase
      .from('blogs')
      .select('id, title, updated_at')
      .eq('published', true)
      .order('created_at', { ascending: false })
      .limit(200);
    if (blogs && blogs.length > 0) {
      blogUrls = blogs.map(b => {
        const slug = slugify(b.title) + '-' + b.id;
        const lastmod = b.updated_at ? b.updated_at.split('T')[0] : today;
        return `  <url>\n    <loc>https://kiitfilmsociety.in/blog/${slug}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.7</priority>\n  </url>`;
      }).join('\n');
    }
  } catch (e) { /* non-fatal */ }

  res.header('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
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
</urlset>`);
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  const start = Date.now();
  try {
    const { error } = await supabase.from('settings').select('key').limit(1);
    if (error) throw new Error(error.message);
    res.json({ status: 'ok', db: 'connected', latencyMs: Date.now() - start });
  } catch (e) {
    res.status(503).json({ status: 'error', db: 'unreachable', error: e.message, latencyMs: Date.now() - start });
  }
});

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const { data: admin } = await supabase.from('admins').select('*').eq('username', username.trim()).maybeSingle();
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const perms = (() => { try { return JSON.parse(admin.permissions || '[]'); } catch { return []; } })();
  const token = jwt.sign(
    { id: admin.id, name: admin.name, username: admin.username, role: admin.role, permissions: perms },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({ token, name: admin.name, role: admin.role, permissions: perms });
});

app.post('/api/admin/change-password', authMiddleware, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password too short' });
  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from('admins').update({ password_hash: hash }).eq('id', req.admin.id);
  res.json({ success: true });
});

// ── TOKEN REFRESH ─────────────────────────────────────────────────────────────
app.post('/api/admin/refresh', authMiddleware, async (req, res) => {
  const { data: admin, error } = await supabase
    .from('admins').select('id,name,username,role,permissions').eq('id', req.admin.id).maybeSingle();
  if (error || !admin) return res.status(401).json({ error: 'Admin not found' });
  const perms = (() => { try { return JSON.parse(admin.permissions || '[]'); } catch { return []; } })();
  const token = jwt.sign(
    { id: admin.id, name: admin.name, username: admin.username, role: admin.role, permissions: perms },
    JWT_SECRET, { expiresIn: '7d' }
  );
  console.log(`[refresh] ${admin.username} — role: ${admin.role}`);
  res.json({ token, name: admin.name, role: admin.role, permissions: perms });
});

// ── MASTER: Admin management ──────────────────────────────────────────────────
app.get('/api/master/admins', masterMiddleware, async (req, res) => {
  const { data } = await supabase.from('admins').select('id,name,username,role,permissions,created_at').order('created_at');
  res.json((data || []).map(a => ({
    ...a,
    permissions: (() => { try { return JSON.parse(a.permissions || '[]'); } catch { return []; } })()
  })));
});

app.post('/api/master/admins', masterMiddleware, async (req, res) => {
  const { name, username, password, permissions } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, 10);
  const permsArr = Array.isArray(permissions) ? permissions : [];
  const { data, error } = await supabase.from('admins').insert([{
    name, username: username.trim().toLowerCase(), password_hash: hash, role: 'admin',
    permissions: JSON.stringify(permsArr)
  }]).select('id,name,username,role,permissions,created_at').single();
  if (error) return res.status(400).json({ error: error.message.includes('unique') ? 'Username already taken' : error.message });
  res.json({ ...data, permissions: permsArr });
});

app.delete('/api/master/admins/:id', masterMiddleware, async (req, res) => {
  const { data: target } = await supabase.from('admins').select('role').eq('id', req.params.id).maybeSingle();
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (target.role === 'master') return res.status(403).json({ error: 'Cannot delete master admin' });
  await supabase.from('admins').delete().eq('id', req.params.id);
  res.json({ success: true });
});

app.put('/api/master/admins/:id/permissions', masterMiddleware, async (req, res) => {
  const { permissions } = req.body;
  if (!Array.isArray(permissions)) return res.status(400).json({ error: 'permissions must be an array' });
  const { data: target } = await supabase.from('admins').select('role').eq('id', req.params.id).maybeSingle();
  if (!target) return res.status(404).json({ error: 'Admin not found' });
  if (target.role === 'master') return res.status(403).json({ error: 'Cannot modify master permissions' });
  const { error } = await supabase.from('admins').update({ permissions: JSON.stringify(permissions) }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'admin_permissions', `Permissions for admin ${req.params.id}`);
  res.json({ success: true, permissions });
});

// ── MASTER: Activity log ──────────────────────────────────────────────────────
app.get('/api/master/activity', masterMiddleware, async (req, res) => {
  const { data } = await supabase.from('admin_activity')
    .select('*')
    .neq('admin_id', req.admin.id)
    .order('created_at', { ascending: false }).limit(200);
  res.json(data || []);
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
app.get('/api/settings', async (req, res) => {
  const { data } = await supabase.from('settings').select('*').neq('key', 'admin_password');
  const obj = {};
  (data || []).forEach(r => obj[r.key] = r.value);
  res.json(obj);
});

app.post('/api/admin/settings', requireSection('settings'), (req, res, next) => {
  upload.fields([{ name: 'team_photo', maxCount: 1 }, { name: 'easter_egg_img', maxCount: 1 }])(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Photo too large — please use an image under 20MB' });
      return res.status(400).json({ error: 'Upload error: ' + err.message });
    }
    next();
  });
}, async (req, res) => {
  try {
    const files = req.files || {};
    // Team photo
    if (files.team_photo && files.team_photo[0]) {
      const f = files.team_photo[0];
      console.log('[settings] uploading team photo:', f.originalname, f.size);
      const photoUrl = await uploadImage(f, 'general');
      console.log('[settings] photo upload result:', photoUrl);
      if (photoUrl) {
        await supabase.from('settings').upsert({ key: 'team_photo', value: photoUrl }, { onConflict: 'key' });
      } else {
        return res.status(500).json({ error: 'Photo upload to storage failed — check Supabase storage bucket permissions' });
      }
    }
    // Easter egg image
    if (files.easter_egg_img && files.easter_egg_img[0]) {
      const f = files.easter_egg_img[0];
      console.log('[settings] uploading easter egg img:', f.originalname, f.size);
      const eggUrl = await uploadImage(f, 'general');
      if (eggUrl) {
        await supabase.from('settings').upsert({ key: 'easter_egg_img', value: eggUrl }, { onConflict: 'key' });
      }
    }
    const body = req.body || {};
    // Handle easter egg clear
    if (body.easter_egg_img_clear === '1') {
      await supabase.from('settings').delete().eq('key', 'easter_egg_img');
      delete body.easter_egg_img_clear;
    }
    const entries = Object.entries(body);
    for (const [key, value] of entries) {
      if (value === '' || value === null || value === undefined) continue;
      await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
    }
    try { await logActivity(req.admin.id, req.admin.name, 'update', 'settings', 'Site Settings'); } catch(e) {}
    res.json({ success: true });
  } catch(e) {
    console.error('[settings] error:', e);
    res.status(500).json({ error: e.message || 'Internal server error' });
  }
});

// ── CUSTOM SEARCH EASTER EGGS ─────────────────────────────────────────────────
// Get all custom eggs
app.get('/api/settings/custom-eggs', async (req, res) => {
  const { data } = await supabase.from('settings').select('value').eq('key', 'custom_search_eggs').maybeSingle();
  try { res.json(JSON.parse(data?.value || '[]')); } catch { res.json([]); }
});

// ADMIN: Upload an image for a custom search easter egg (does NOT touch easter_egg_img setting)
app.post('/api/admin/settings/custom-egg-upload', requireSection('settings'), upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image file provided' });
  try {
    const url = await uploadImage(req.file, 'general');
    if (!url) return res.status(500).json({ error: 'Image upload to storage failed' });
    res.json({ url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Save all custom eggs (admin only)
app.post('/api/admin/settings/custom-eggs', requireSection('settings'), async (req, res) => {
  const { eggs } = req.body;
  if (!Array.isArray(eggs)) return res.status(400).json({ error: 'eggs must be an array' });
  const value = JSON.stringify(eggs);
  await supabase.from('settings').upsert({ key: 'custom_search_eggs', value }, { onConflict: 'key' });
  await logActivity(req.admin.id, req.admin.name, 'update', 'settings', 'Custom Search Easter Eggs');
  res.json({ success: true });
});


app.get('/api/blogs', async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').eq('published', true).order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/admin/blogs', requireSection('blogs'), async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/blogs/:id', async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').eq('id', req.params.id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

app.post('/api/admin/blogs', requireSection('blogs'), upload.single('cover'), async (req, res) => {
  const { title, author, excerpt, content, published, sections } = req.body;
  const coverUrl = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').insert([{
    title, author: author||null, excerpt, content, cover_image: coverUrl, published: published === 'true',
    sections: sections || '[]',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'blog', title);
  res.json(data);
});

app.put('/api/admin/blogs/:id', requireSection('blogs'), upload.single('cover'), async (req, res) => {
  const { title, author, excerpt, content, published, sections } = req.body;
  const updates = { title, author: author||null, excerpt, content, published: published === 'true', sections: sections || '[]' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'blog', title);
  res.json(data);
});

app.delete('/api/admin/blogs/:id', requireSection('blogs'), async (req, res) => {
  const { data: b } = await supabase.from('blogs').select('title').eq('id', req.params.id).single();
  await supabase.from('blogs').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'blog', b?.title || req.params.id);
  res.json({ success: true });
});

// ── EVENTS ────────────────────────────────────────────────────────────────────
app.get('/api/events', async (req, res) => {
  const { data } = await supabase.from('events').select('*').order('event_date', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/events', requireSection('events'), upload.single('cover'), async (req, res) => {
  const { title, description, event_date, event_time, location, is_upcoming } = req.body;
  const coverUrl = await uploadImage(req.file, 'events');
  const { data, error } = await supabase.from('events').insert([{
    title, description, event_date, event_time, location, cover_image: coverUrl, is_upcoming: is_upcoming === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'event', title);
  res.json(data);
});

app.put('/api/admin/events/:id', requireSection('events'), upload.single('cover'), async (req, res) => {
  const { title, description, event_date, event_time, location, is_upcoming } = req.body;
  const updates = { title, description, event_date, event_time, location, is_upcoming: is_upcoming === 'true' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'events');
  const { data, error } = await supabase.from('events').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'event', title);
  res.json(data);
});

app.delete('/api/admin/events/:id', requireSection('events'), async (req, res) => {
  const { data: e } = await supabase.from('events').select('title').eq('id', req.params.id).single();
  await supabase.from('events').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'event', e?.title || req.params.id);
  res.json({ success: true });
});

// ── MEMBERS ───────────────────────────────────────────────────────────────────
app.get('/api/members', async (req, res) => {
  const { data } = await supabase.from('members').select('*').order('sort_order', { ascending: true });
  res.json(data || []);
});

app.post('/api/admin/members', requireSection('members'), upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order, is_past, domain, special_tag } = req.body;
  const photoUrl = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').insert([{
    name, role, batch, bio, domain: domain||null, photo: photoUrl,
    special_tag: special_tag || null,
    sort_order: parseInt(sort_order) || 99, is_past: is_past === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'member', name);
  res.json(data);
});

app.put('/api/admin/members/:id', requireSection('members'), upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order, is_past, domain, special_tag } = req.body;
  const updates = { name, role, batch, bio, domain: domain||null, special_tag: special_tag || null, sort_order: parseInt(sort_order) || 99, is_past: is_past === 'true' };
  if (req.file) updates.photo = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'member', name);
  res.json(data);
});

app.delete('/api/admin/members/:id', requireSection('members'), async (req, res) => {
  const { data: m } = await supabase.from('members').select('name').eq('id', req.params.id).single();
  await supabase.from('members').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'member', m?.name || req.params.id);
  res.json({ success: true });
});

// ── TESTIMONIALS ──────────────────────────────────────────────────────────────
app.get('/api/testimonials', async (req, res) => {
  const { data } = await supabase.from('testimonials').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/testimonials', requireSection('testimonials'), upload.single('photo'), async (req, res) => {
  const { name, role, batch, quote } = req.body;
  const photoUrl = await uploadImage(req.file, 'testimonials');
  const { data, error } = await supabase.from('testimonials').insert([{ name, role, batch, quote, photo: photoUrl }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'testimonial', name);
  res.json(data);
});

app.put('/api/admin/testimonials/:id', requireSection('testimonials'), upload.single('photo'), async (req, res) => {
  const { name, role, batch, quote } = req.body;
  const updates = { name, role, batch, quote };
  if (req.file) updates.photo = await uploadImage(req.file, 'testimonials');
  const { data, error } = await supabase.from('testimonials').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'testimonial', name);
  res.json(data);
});

app.delete('/api/admin/testimonials/:id', requireSection('testimonials'), async (req, res) => {
  const { data: t } = await supabase.from('testimonials').select('name').eq('id', req.params.id).single();
  await supabase.from('testimonials').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'testimonial', t?.name || req.params.id);
  res.json({ success: true });
});

// ── ACHIEVEMENTS ──────────────────────────────────────────────────────────────
app.get('/api/achievements', async (req, res) => {
  const { data } = await supabase.from('achievements').select('*').order('sort_order', { ascending: true });
  res.json(data || []);
});

app.post('/api/admin/achievements', requireSection('achievements'), upload.single('image'), async (req, res) => {
  const { title, description, year, sort_order } = req.body;
  const imageUrl = req.file ? await uploadImage(req.file, 'general') : null;
  const { data, error } = await supabase.from('achievements').insert([{
    title, description, year, image: imageUrl, sort_order: parseInt(sort_order) || 99
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'achievement', title);
  res.json(data);
});

app.put('/api/admin/achievements/:id', requireSection('achievements'), upload.single('image'), async (req, res) => {
  const { title, description, year, sort_order } = req.body;
  const updates = { title, description, year, sort_order: parseInt(sort_order) || 99 };
  if (req.file) updates.image = await uploadImage(req.file, 'general');
  const { data, error } = await supabase.from('achievements').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'achievement', title);
  res.json(data);
});

app.delete('/api/admin/achievements/:id', requireSection('achievements'), async (req, res) => {
  const { data: a } = await supabase.from('achievements').select('title').eq('id', req.params.id).single();
  await supabase.from('achievements').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'achievement', a?.title || req.params.id);
  res.json({ success: true });
});

// ── MOVIES ────────────────────────────────────────────────────────────────────
// Helper: parse genre field (stored as JSON array or legacy string)
function parseGenre(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try { const p = JSON.parse(raw); return Array.isArray(p) ? p : [p]; } catch { return [raw]; }
}

app.get('/api/movies', async (req, res) => {
  let query = supabase.from('movies').select('*').order('release_year', { ascending: false });
  const { data } = await query;
  let movies = data || [];
  // Genre filter: ?genre=Drama
  if (req.query.genre) {
    const filterGenre = req.query.genre.toLowerCase();
    movies = movies.filter(m => parseGenre(m.genre).some(g => g.toLowerCase() === filterGenre));
  }
  // Parse genre array for each movie before sending
  movies = movies.map(m => ({ ...m, genre: parseGenre(m.genre) }));
  res.json(movies);
});

app.get('/api/movies/:id', async (req, res) => {
  const { data } = await supabase.from('movies').select('*').eq('id', req.params.id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json({ ...data, genre: parseGenre(data.genre) });
});

app.post('/api/admin/movies', requireSection('movies'), upload.single('poster'), async (req, res) => {
  const { title, release_year, genre, description, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew, trailer_url, watch_url, spotify_url } = req.body;
  // genre arrives as JSON string array from frontend
  let genreVal = null;
  if (genre) { try { const p = JSON.parse(genre); genreVal = Array.isArray(p) && p.length ? JSON.stringify(p) : null; } catch { genreVal = genre || null; } }
  const posterUrl = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').insert([{
    title, release_year, genre: genreVal, description: description||null,
    director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew,
    poster_image: posterUrl, trailer_url: trailer_url || null, watch_url: watch_url || null, spotify_url: spotify_url || null,
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'movie', title);
  res.json({ ...data, genre: parseGenre(data.genre) });
});

app.put('/api/admin/movies/:id', requireSection('movies'), upload.single('poster'), async (req, res) => {
  const { title, release_year, genre, description, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew, trailer_url, watch_url, spotify_url } = req.body;
  let genreVal = null;
  if (genre) { try { const p = JSON.parse(genre); genreVal = Array.isArray(p) && p.length ? JSON.stringify(p) : null; } catch { genreVal = genre || null; } }
  const updates = { title, release_year, genre: genreVal, description: description||null,
    director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew,
    trailer_url: trailer_url || null, watch_url: watch_url || null, spotify_url: spotify_url || null };
  if (req.file) updates.poster_image = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'movie', title);
  res.json({ ...data, genre: parseGenre(data.genre) });
});

app.delete('/api/admin/movies/:id', requireSection('movies'), async (req, res) => {
  const { data: mv } = await supabase.from('movies').select('title').eq('id', req.params.id).single();
  await supabase.from('movies').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'movie', mv?.title || req.params.id);
  res.json({ success: true });
});

// ── CHITRA VICHITRA — PUBLIC ──────────────────────────────────────────────────
// Get all CV editions (with movie count)
app.get('/api/chitra-vichitra', async (req, res) => {
  const { data: editions, error } = await supabase
    .from('chitra_vichitra')
    .select('*')
    .order('sort_order', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });

  if (!editions || editions.length === 0) return res.json([]);

  // Fetch all CV-movie rows in one query instead of N+1 individual count queries
  const { data: allCvMovies } = await supabase
    .from('chitra_vichitra_movies')
    .select('cv_id');

  const countMap = {};
  (allCvMovies || []).forEach(row => {
    countMap[row.cv_id] = (countMap[row.cv_id] || 0) + 1;
  });

  const result = editions.map(cv => ({ ...cv, movie_count: countMap[cv.id] || 0 }));
  res.json(result);
});

// Get movies for a specific CV edition
app.get('/api/chitra-vichitra/:id/movies', async (req, res) => {
  const { data, error } = await supabase
    .from('chitra_vichitra_movies')
    .select(`
      id,
      movies (
        id, title, release_year, director, poster_image, trailer_url, watch_url,
        producer, dop, screenwriter, video_editor, sound_design, management,
        graphic_design, actors, support_crew
      )
    `)
    .eq('cv_id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });

  // Flatten: attach cv_movie_id for removal from admin
  const movies = (data || []).map(row => ({
    cv_movie_id: row.id,
    ...row.movies,
  }));
  res.json(movies);
});

// ── CHITRA VICHITRA — ADMIN ───────────────────────────────────────────────────
// Create a new CV edition
app.post('/api/admin/chitra-vichitra', requireSection('chitra-vichitra'), upload.single('cover'), async (req, res) => {
  const { year, sort_order } = req.body;
  if (!year) return res.status(400).json({ error: 'Year is required' });
  const coverUrl = await uploadImage(req.file, 'chitra-vichitra');
  const { data, error } = await supabase.from('chitra_vichitra').insert([{
    year: year.trim(),
    cover_image: coverUrl,
    sort_order: parseInt(sort_order) || 99,
  }]).select().single();
  if (error) return res.status(400).json({ error: error.message.includes('unique') ? 'A CV edition for this year already exists' : error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'chitra_vichitra', `CV ${year}`);
  res.json(data);
});

// Update a CV edition (year, cover, sort_order)
app.put('/api/admin/chitra-vichitra/:id', requireSection('chitra-vichitra'), upload.single('cover'), async (req, res) => {
  const { year, sort_order } = req.body;
  const updates = {
    year: year?.trim(),
    sort_order: parseInt(sort_order) || 99,
  };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'chitra-vichitra');
  const { data, error } = await supabase.from('chitra_vichitra').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'chitra_vichitra', `CV ${year}`);
  res.json(data);
});

// Delete a CV edition (cascade deletes cv_movies via FK)
app.delete('/api/admin/chitra-vichitra/:id', requireSection('chitra-vichitra'), async (req, res) => {
  const { data: cv } = await supabase.from('chitra_vichitra').select('year').eq('id', req.params.id).single();
  await supabase.from('chitra_vichitra').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'chitra_vichitra', `CV ${cv?.year || req.params.id}`);
  res.json({ success: true });
});

// Add a movie to a CV edition
app.post('/api/admin/chitra-vichitra/:id/movies', requireSection('chitra-vichitra'), async (req, res) => {
  const { movie_id } = req.body;
  if (!movie_id) return res.status(400).json({ error: 'movie_id required' });

  // Check for duplicate
  const { data: existing } = await supabase
    .from('chitra_vichitra_movies')
    .select('id')
    .eq('cv_id', req.params.id)
    .eq('movie_id', movie_id)
    .maybeSingle();
  if (existing) return res.status(400).json({ error: 'This film is already in this CV edition' });

  const { data, error } = await supabase.from('chitra_vichitra_movies').insert([{
    cv_id: req.params.id,
    movie_id,
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Remove a movie from a CV edition (by chitra_vichitra_movies row id)
app.delete('/api/admin/chitra-vichitra/movies/:cvMovieId', requireSection('chitra-vichitra'), async (req, res) => {
  await supabase.from('chitra_vichitra_movies').delete().eq('id', req.params.cvMovieId);
  res.json({ success: true });
});

// ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
app.get('/api/notifications/active', async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').eq('active', true).limit(1).maybeSingle();
  res.json(data || null);
});

app.get('/api/admin/notifications', requireSection('notifications'), async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/notifications', requireSection('notifications'), async (req, res) => {
  const { title, type, message, btn_text, btn_link, active } = req.body;
  const { data, error } = await supabase.from('notifications').insert([{
    title, type, message, btn_text, btn_link, active: active === 'true' || active === true
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/notifications/:id', requireSection('notifications'), async (req, res) => {
  const { title, type, message, btn_text, btn_link, active } = req.body;
  const { data, error } = await supabase.from('notifications').update({
    title, type, message, btn_text, btn_link, active: active === 'true' || active === true
  }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/notifications/:id', requireSection('notifications'), async (req, res) => {
  await supabase.from('notifications').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ── TRAFFIC ───────────────────────────────────────────────────────────────────
app.post('/api/track', async (req, res) => {
  const { page, hour } = req.body;
  const today = new Date().toISOString().slice(0,10);
  await supabase.from('page_views').insert([{ page: page||'home', date: today, hour: hour||0 }]);
  res.json({ ok: true });
});

app.get('/api/admin/analytics/traffic', requireSection('analytics'), async (req, res) => {
  const range = req.query.range || '7d';
  let fromDate = new Date();
  if (range === '7d') fromDate.setDate(fromDate.getDate()-7);
  else if (range === '30d') fromDate.setDate(fromDate.getDate()-30);
  else fromDate = new Date('2020-01-01');
  const from = fromDate.toISOString().slice(0,10);
  const today = new Date().toISOString().slice(0,10);
  const { data: rows } = await supabase.from('page_views').select('*').gte('date', from);
  if (!rows) return res.json({ total:0, today:0, peak_day:'—', by_page:[], by_date:[], by_hour:Array(24).fill(0) });
  const total = rows.length;
  const todayViews = rows.filter(r=>r.date===today).length;
  const dateMap = {};
  rows.forEach(r => { dateMap[r.date] = (dateMap[r.date]||0)+1; });
  const by_date = Object.entries(dateMap).sort((a,b)=>a[0].localeCompare(b[0])).map(([date,views])=>({date,views}));
  const peak = by_date.reduce((a,b)=>b.views>a.views?b:a, {date:'—',views:0});
  const pageMap = {};
  rows.forEach(r => { pageMap[r.page] = (pageMap[r.page]||0)+1; });
  const by_page = Object.entries(pageMap).sort((a,b)=>b[1]-a[1]).map(([page,views])=>({page,views}));
  const by_hour = Array(24).fill(0);
  rows.filter(r=>r.date===today).forEach(r => { by_hour[r.hour] = (by_hour[r.hour]||0)+1; });
  res.json({ total, today: todayViews, peak_day: peak.date, by_page, by_date, by_hour });
});

// ── REVIEW ANALYTICS ──────────────────────────────────────────────────────────
app.get('/api/admin/analytics/reviews', requireSection('review-analytics'), async (req, res) => {
  const { data: reviews } = await supabase.from('reviews').select('*');
  const { data: movies } = await supabase.from('movies').select('id,title');
  if (!reviews || !movies) return res.json({ total:0 });
  const total = reviews.length;
  const overall_avg = total ? reviews.reduce((s,r)=>s+r.overall,0)/total : null;
  const cats = ['direction','sound','cinematography','script'];
  const cat_avgs = {};
  cats.forEach(c => {
    const vals = reviews.map(r=>r[c]).filter(Boolean);
    cat_avgs[c] = vals.length ? vals.reduce((a,b)=>a+b,0)/vals.length : null;
  });
  const movieMap = {};
  movies.forEach(m => { movieMap[m.id] = m.title; });
  const byFilm = {};
  reviews.forEach(r => {
    if (!byFilm[r.movie_id]) byFilm[r.movie_id] = { title: movieMap[r.movie_id]||'Unknown', scores:[], count:0 };
    byFilm[r.movie_id].scores.push(r.overall);
    byFilm[r.movie_id].count++;
  });
  const by_film = Object.values(byFilm).map(f=>({ title:f.title, avg:f.scores.reduce((a,b)=>a+b,0)/f.scores.length, count:f.count })).sort((a,b)=>b.avg-a.avg);
  const top_rated = by_film[0]||null;
  const most_reviewed = [...by_film].sort((a,b)=>b.count-a.count)[0]||null;
  res.json({ total, overall_avg, cat_avgs, by_film, top_rated, most_reviewed });
});

// ── REVIEWS ───────────────────────────────────────────────────────────────────
app.get('/api/reviews/all', async (req, res) => {
  const { data } = await supabase.from('reviews').select('movie_id,overall');
  res.json(data || []);
});

app.get('/api/reviews/:movieId', async (req, res) => {
  const { data } = await supabase.from('reviews').select('*').eq('movie_id', req.params.movieId).order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/reviews', async (req, res) => {
  const { movie_id, reviewer_name, overall, direction, sound, cinematography, script, review_text } = req.body;
  if (!movie_id || !overall) return res.status(400).json({ error: 'movie_id and overall are required' });
  const { data, error } = await supabase.from('reviews').insert([{
    movie_id, reviewer_name: reviewer_name || 'Anonymous',
    overall: parseInt(overall),
    direction: direction ? parseInt(direction) : null,
    sound: sound ? parseInt(sound) : null,
    cinematography: cinematography ? parseInt(cinematography) : null,
    script: script ? parseInt(script) : null,
    review_text: review_text || null,
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── EVENT REGISTRATION FORMS ──────────────────────────────────────────────────

// PUBLIC: Get the registration form for an event (schema only, no responses)
app.get('/api/events/:id/form', async (req, res) => {
  const { data, error } = await supabase
    .from('event_forms')
    .select('id,event_id,title,description,questions,is_open,created_at,updated_at')
    .eq('event_id', req.params.id)
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(404).json({ error: 'No form found for this event' });
  res.json(data);
});

// ADMIN: Create or update (upsert) the registration form for an event
app.post('/api/admin/events/:id/form', requireSection('events'), async (req, res) => {
  const { title, description, questions, is_open } = req.body;
  if (!Array.isArray(questions)) return res.status(400).json({ error: 'questions must be an array' });

  // Validate each question minimally
  for (const q of questions) {
    if (!q.id || !q.type) return res.status(400).json({ error: 'Each question must have id and type' });
    if ((q.type === 'radio' || q.type === 'checkbox') && (!Array.isArray(q.options) || q.options.length < 1)) {
      return res.status(400).json({ error: `Question "${q.label}" needs at least 1 option` });
    }
  }

  // Check if form already exists for this event
  const { data: existing } = await supabase
    .from('event_forms')
    .select('id')
    .eq('event_id', req.params.id)
    .maybeSingle();

  let data, error;
  const payload = {
    event_id: req.params.id,
    title: title || null,
    description: description || null,
    questions: JSON.stringify(questions),
    is_open: is_open !== false && is_open !== 'false',
    updated_at: new Date().toISOString(),
  };

  if (existing) {
    ({ data, error } = await supabase
      .from('event_forms')
      .update(payload)
      .eq('id', existing.id)
      .select()
      .single());
  } else {
    ({ data, error } = await supabase
      .from('event_forms')
      .insert([{ ...payload, created_at: new Date().toISOString() }])
      .select()
      .single());
  }

  if (error) return res.status(500).json({ error: error.message });

  const { data: ev } = await supabase.from('events').select('title').eq('id', req.params.id).maybeSingle();
  await logActivity(req.admin.id, req.admin.name, existing ? 'update' : 'create', 'event_form', ev?.title || req.params.id);
  res.json(data);
});

// ADMIN: Get all responses for an event form
app.get('/api/admin/events/:id/form/responses', requireSection('events'), async (req, res) => {
  const { data, error } = await supabase
    .from('form_responses')
    .select('*')
    .eq('event_id', req.params.id)
    .order('submitted_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// ADMIN: Delete only the responses (keeps the form schema intact)
app.delete('/api/admin/events/:id/form/responses', requireSection('events'), async (req, res) => {
  const { error } = await supabase.from('form_responses').delete().eq('event_id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  const { data: ev } = await supabase.from('events').select('title').eq('id', req.params.id).maybeSingle();
  await logActivity(req.admin.id, req.admin.name, 'delete', 'form_responses', `Responses for ${ev?.title || req.params.id}`);
  res.json({ success: true });
});

// ADMIN: Delete the form for an event (and all its responses)
app.delete('/api/admin/events/:id/form', requireSection('events'), async (req, res) => {
  await supabase.from('form_responses').delete().eq('event_id', req.params.id);
  await supabase.from('event_forms').delete().eq('event_id', req.params.id);
  const { data: ev } = await supabase.from('events').select('title').eq('id', req.params.id).maybeSingle();
  await logActivity(req.admin.id, req.admin.name, 'delete', 'event_form', ev?.title || req.params.id);
  res.json({ success: true });
});

// PUBLIC: Submit a response to an event registration form
// Handles multipart/form-data so image files can be uploaded per-question
app.post('/api/events/:id/form/submit', upload.any(), async (req, res) => {
  // 1. Verify the form exists and is open
  const { data: form, error: formErr } = await supabase
    .from('event_forms')
    .select('id,is_open,questions')
    .eq('event_id', req.params.id)
    .maybeSingle();

  if (formErr || !form) return res.status(404).json({ error: 'Form not found' });
  if (!form.is_open) return res.status(403).json({ error: 'Registrations are currently closed' });

  // 2. Parse submitted answers
  let answers = {};
  try { answers = JSON.parse(req.body.answers || '{}'); } catch(e) {
    return res.status(400).json({ error: 'Invalid answers payload' });
  }

  // 3. Validate required fields against schema
  let questions = [];
  try { questions = JSON.parse(form.questions || '[]'); } catch(e) {}

  for (const q of questions) {
    if (!q.required) continue;
    if (q.type === 'image') {
      const hasFile = (req.files || []).some(f => f.fieldname === q.id);
      if (!hasFile) return res.status(400).json({ error: `"${q.label || q.id}" is required` });
    } else {
      const val = answers[q.id];
      const isEmpty = val === undefined || val === null || val === '' || (Array.isArray(val) && val.length === 0);
      if (isEmpty) return res.status(400).json({ error: `"${q.label || q.id}" is required` });
    }
  }

  // 3b. Duplicate check — block if same email or phone already submitted for this event
  const dedupeTypes = ['email', 'phone'];
  const dedupeKeys = questions
    .filter(q => dedupeTypes.includes(q.type))
    .map(q => ({ id: q.id, label: q.label || q.type, type: q.type }));

  if (dedupeKeys.length > 0) {
    // Fetch existing responses for this event
    const { data: existing } = await supabase
      .from('form_responses')
      .select('answers')
      .eq('event_id', req.params.id);

    for (const key of dedupeKeys) {
      const submitted = (answers[key.id] || '').trim().toLowerCase();
      if (!submitted) continue;
      const isDup = (existing || []).some(row => {
        try {
          const prev = JSON.parse(row.answers || '{}');
          return (prev[key.id] || '').trim().toLowerCase() === submitted;
        } catch { return false; }
      });
      if (isDup) {
        const label = key.type === 'email' ? 'Email' : 'Mobile number';
        return res.status(409).json({ error: `${label} already registered for this event.` });
      }
    }
  }

  // 4. Upload any image files to Supabase Storage
  const imageUrls = {};
  for (const file of (req.files || [])) {
    try {
      const url = await uploadImage(file, `form-responses/${req.params.id}`);
      imageUrls[file.fieldname] = url;
    } catch(e) {
      console.error('Image upload error for question', file.fieldname, e.message);
      return res.status(500).json({ error: 'Image upload failed: ' + e.message });
    }
  }

  // 5. Merge image URLs into answers
  const finalAnswers = { ...answers, ...imageUrls };

  // 6. Store response
  const { data: response, error: insertErr } = await supabase
    .from('form_responses')
    .insert([{
      event_id: req.params.id,
      form_id: form.id,
      answers: JSON.stringify(finalAnswers),
      submitted_at: new Date().toISOString(),
    }])
    .select()
    .single();

  if (insertErr) return res.status(500).json({ error: insertErr.message });

  // 7. Send confirmation email (non-blocking — never fail the response)
  try {
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Tier 1: question explicitly typed as 'email'
    let emailQ = questions.find(q => q.type === 'email');

    // Tier 2: any text/textarea question whose label mentions email
    if (!emailQ)
      emailQ = questions.find(q =>
        ['text','textarea'].includes(q.type) && /e[\s-]?mail/i.test(q.label || '')
      );

    // Tier 3: scan every answer value for something that looks like an email
    let toEmail = emailQ ? (finalAnswers[emailQ.id] || '').trim() : null;
    if (!toEmail) {
      for (const val of Object.values(finalAnswers)) {
        if (typeof val === 'string' && EMAIL_RE.test(val.trim())) {
          toEmail = val.trim();
          break;
        }
      }
    }

    // Name: prefer a question labelled 'name', fall back to first short-text answer
    const nameQ = questions.find(q =>
      ['text','textarea'].includes(q.type) && /\bname\b/i.test(q.label || '')
    );
    const toName = nameQ ? (finalAnswers[nameQ.id] || '').trim() : null;

    if (toEmail) {
      // Fetch event details for the email
      const { data: ev } = await supabase.from('events').select('title,event_date,venue').eq('id', req.params.id).maybeSingle();
      sendConfirmationEmail({
        toEmail,
        toName,
        eventTitle: ev?.title || '',
        eventDate:  ev?.event_date || null,
        eventVenue: ev?.venue || null,
      }).catch(e => console.error('[email] send failed:', e.message));
    }
  } catch(e) { console.error('[email] pre-send error:', e.message); }

  res.json({ success: true, id: response.id });
});

// ADMIN: Download responses as server-side JSON (client does XLSX conversion)
// This is an alias for the GET responses endpoint used by the download button
app.get('/api/admin/events/:id/form/export', requireSection('events'), async (req, res) => {
  const { data: form } = await supabase
    .from('event_forms')
    .select('title,questions')
    .eq('event_id', req.params.id)
    .maybeSingle();

  const { data: responses } = await supabase
    .from('form_responses')
    .select('*')
    .eq('event_id', req.params.id)
    .order('submitted_at', { ascending: true });

  res.json({ form: form || null, responses: responses || [] });
});

// ── ADMIN: Send test confirmation email ───────────────────────────────────────
app.post('/api/admin/email/test', authMiddleware, async (req, res) => {
  const { to } = req.body;
  if (!to || !to.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  try {
    await sendConfirmationEmail({
      toEmail: to,
      toName: 'Test User',
      eventTitle: 'Test Event — KFS',
      eventDate: new Date().toISOString(),
      eventVenue: 'KIIT University, Bhubaneswar',
    });
    res.json({ success: true });
  } catch(e) {
    console.error('[email] test send failed:', e.message);
    res.status(500).json({ error: e.message });
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

const { Resvg } = require('@resvg/resvg-js');

// ── SVG-based OG helpers ──────────────────────────────────────────────────────

function escXml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Naive word-wrap for SVG — splits text into lines of at most maxChars
function svgLines(text, maxChars) {
  const words = (text || '').split(' ');
  const lines = [];
  let line = '';
  for (const w of words) {
    const test = line ? line + ' ' + w : w;
    if (test.length > maxChars && line) { lines.push(line); line = w; }
    else line = test;
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
    const ct  = r.headers.get('content-type') || 'image/jpeg';
    return `data:${ct};base64,${buf.toString('base64')}`;
  } catch { return null; }
}

// Build the full SVG string for an OG card
function buildOGSvg({ coverDataUri, badge, title, lines: extraLines }) {
  const W = 1200, H = 630;

  // Cover image on right half (540px wide), embedded as base64
  const coverImg = coverDataUri
    ? `<image href="${coverDataUri}" x="540" y="0" width="660" height="${H}" preserveAspectRatio="xMidYMid slice"/>`
    : '';

  // Gradient overlay so left text is always readable
  const overlay = coverDataUri ? `
    <defs>
      <linearGradient id="ov" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#0a0a0a" stop-opacity="1"/>
        <stop offset="55%"  stop-color="#0a0a0a" stop-opacity="0.92"/>
        <stop offset="100%" stop-color="#0a0a0a" stop-opacity="0.2"/>
      </linearGradient>
    </defs>
    <rect x="540" y="0" width="660" height="${H}" fill="url(#ov)"/>` : '';

  // Title lines (max 3, ~24 chars each at 52px)
  const titleLines = svgLines(title, 24).slice(0, 3);
  const titleSvg = titleLines.map((l, i) =>
    `<text x="56" y="${152 + i * 66}" font-size="52" font-weight="700" fill="#f5f5f5" font-family="sans-serif">${escXml(l)}</text>`
  ).join('\n  ');

  // Extra info lines below title
  let infoY = 152 + titleLines.length * 66 + 28;
  const infoSvg = extraLines.map(({ text, color, size }) => {
    if (!text) return '';
    const el = `<text x="56" y="${infoY}" font-size="${size || 22}" fill="${color || '#aaaaaa'}" font-family="sans-serif">${escXml(text)}</text>`;
    infoY += (size || 22) + 16;
    return el;
  }).filter(Boolean).join('\n  ');

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
  const resvg = new Resvg(svgStr, { fitTo: { mode: 'width', value: 1200 } });
  return resvg.render().asPng();
}

// ── /og/event/:id ─────────────────────────────────────────────────────────────
app.get('/og/event/:id', async (req, res) => {
  try {
    const { data: e } = await supabase.from('events').select('*').eq('id', req.params.id).maybeSingle();
    if (!e) return res.status(404).send('Not found');

    const coverDataUri = await toDataUri(e.cover_image);
    const dateStr = e.event_date
      ? new Date(e.event_date).toLocaleDateString('en-IN', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
      : null;

    const svg = buildOGSvg({
      coverDataUri,
      badge: e.is_upcoming ? 'UPCOMING EVENT' : 'EVENT',
      title: e.title || 'Event',
      lines: [
        { text: dateStr ? '📅  ' + dateStr : null, color: '#aaaaaa', size: 22 },
        { text: e.event_time ? '🕐  ' + e.event_time : null, color: '#aaaaaa', size: 20 },
        { text: (e.venue || e.location) ? '📍  ' + (e.venue || e.location) : null, color: '#888888', size: 18 },
      ],
    });

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.end(svgToPng(svg));
  } catch (err) {
    console.error('[og/event]', err.message);
    res.status(500).send('OG generation failed');
  }
});

// ── /og/film/:id ──────────────────────────────────────────────────────────────
app.get('/og/film/:id', async (req, res) => {
  try {
    const { data: m } = await supabase.from('movies').select('*').eq('id', req.params.id).maybeSingle();
    if (!m) return res.status(404).send('Not found');

    const coverDataUri = await toDataUri(m.poster_image);
    const genres = (() => { try { const g = JSON.parse(m.genre || '[]'); return Array.isArray(g) ? g : [g]; } catch { return m.genre ? [m.genre] : []; }})();
    const badge = genres.slice(0, 2).join(' · ').toUpperCase() || 'FILM';

    const svg = buildOGSvg({
      coverDataUri,
      badge,
      title: m.title || 'Film',
      lines: [
        { text: m.director ? 'Directed by  ' + m.director : null, color: '#aaaaaa', size: 22 },
        { text: m.release_year ? String(m.release_year) : null, color: '#555555', size: 18 },
      ],
    });

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.end(svgToPng(svg));
  } catch (err) {
    console.error('[og/film]', err.message);
    res.status(500).send('OG generation failed');
  }
});

// ── /og/blog/:id ──────────────────────────────────────────────────────────────
app.get('/og/blog/:id', async (req, res) => {
  try {
    const { data: b } = await supabase.from('blogs').select('*').eq('id', req.params.id).maybeSingle();
    if (!b) return res.status(404).send('Not found');

    const coverDataUri = await toDataUri(b.cover_image);
    const excerpt = b.excerpt ? b.excerpt.slice(0, 90) + (b.excerpt.length > 90 ? '…' : '') : null;

    const svg = buildOGSvg({
      coverDataUri,
      badge: 'KFS BLOG',
      title: b.title || 'Blog',
      lines: [
        { text: excerpt || null, color: '#777777', size: 20 },
        { text: b.author ? 'By ' + b.author : null, color: '#555555', size: 17 },
      ],
    });

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.end(svgToPng(svg));
  } catch (err) {
    console.error('[og/blog]', err.message);
    res.status(500).send('OG generation failed');
  }
});

// ── SHARE-LINK HTML WITH DYNAMIC OG TAGS ─────────────────────────────────────
// Injects og:title / og:description / og:image into the SPA shell so
// social crawlers (WhatsApp, Twitter, Telegram…) get real previews AND
// real users land on the correct deep-linked page.

const fs = require('fs');

// Read the base HTML once (cached).  We'll inject <meta> tags into <head>.
function injectOgTags(html, { title, description, imageUrl, url }) {
  const siteName = 'KFS — KIIT Film Society';
  const safeTitle = (title || siteName).replace(/"/g, '&quot;');
  const safeDesc  = (description || 'KIIT Film Society — student-run cinema collective.').slice(0, 200).replace(/"/g, '&quot;');
  const safeImg   = imageUrl || '';
  const safeUrl   = url || 'https://kiitfilmsociety.in';

  const tags = `
  <!-- Dynamic OG tags injected by server -->
  <meta property="og:type"        content="website" />
  <meta property="og:site_name"   content="${siteName}" />
  <meta property="og:title"       content="${safeTitle}" />
  <meta property="og:description" content="${safeDesc}" />
  <meta property="og:url"         content="${safeUrl}" />
  ${safeImg ? `<meta property="og:image"       content="${safeImg}" />
  <meta property="og:image:width"  content="1200" />
  <meta property="og:image:height" content="630" />` : ''}
  <meta name="twitter:card"        content="summary_large_image" />
  <meta name="twitter:title"       content="${safeTitle}" />
  <meta name="twitter:description" content="${safeDesc}" />
  ${safeImg ? `<meta name="twitter:image"       content="${safeImg}" />` : ''}
  <link rel="canonical"            href="${safeUrl}" />`;

  // Insert just before </head>; fallback: prepend to <body>
  if (html.includes('</head>')) {
    return html.replace('</head>', tags + '\n</head>');
  }
  return html.replace('<body', tags + '\n<body');
}

// Extract numeric/UUID id from end of a slug like "my-post-title-42"
function idFromSlug(slug) {
  if (!slug) return null;
  // UUID pattern
  const uuidMatch = slug.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i);
  if (uuidMatch) return uuidMatch[1];
  // Numeric id at end
  const numMatch = slug.match(/-(\d+)$/);
  if (numMatch) return numMatch[1];
  // Fallback: the whole slug might just be an id
  return slug;
}

// Serve the SPA index.html with injected OG tags
async function serveWithOg(res, ogData) {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  try {
    let html = fs.readFileSync(indexPath, 'utf8');
    html = injectOgTags(html, ogData);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    // Don't cache share pages — OG data can change
    res.setHeader('Cache-Control', 'no-cache');
    res.send(html);
  } catch (e) {
    // If index.html can't be read, fall through
    res.sendFile(indexPath);
  }
}

// ── /blog/:slug  (e.g. /blog/my-post-title-42) ───────────────────────────────
app.get('/blog/:slug', async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const { data: b } = id
      ? await supabase.from('blogs').select('id,title,excerpt,cover_image,author').eq('id', id).maybeSingle()
      : null;

    if (!b) {
      // Unknown blog — serve SPA without special OG so the app can show its own 404
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    const canonicalSlug = slugify(b.title) + '-' + b.id;
    const pageUrl = `https://kiitfilmsociety.in/blog/${canonicalSlug}`;

    return serveWithOg(res, {
      title:       b.title ? `${b.title} — KFS Blog` : 'KFS Blog',
      description: b.excerpt || `Read "${b.title}" on the KIIT Film Society blog.`,
      imageUrl:    b.cover_image ? `https://kiitfilmsociety.in/og/blog/${b.id}` : null,
      url:         pageUrl,
    });
  } catch (err) {
    console.error('[share/blog]', err.message);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ── /films/:slug  (e.g. /films/do-paise-ki-dhoop-7) ─────────────────────────
app.get('/films/:slug', async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const { data: m } = id
      ? await supabase.from('movies').select('id,title,description,poster_image,director,release_year').eq('id', id).maybeSingle()
      : null;

    if (!m) {
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    const canonicalSlug = slugify(m.title) + '-' + m.id;
    const pageUrl = `https://kiitfilmsociety.in/films/${canonicalSlug}`;
    const desc = m.description
      ? m.description.slice(0, 160)
      : (m.director ? `Directed by ${m.director}${m.release_year ? ` · ${m.release_year}` : ''}` : 'A film by KIIT Film Society.');

    return serveWithOg(res, {
      title:       m.title ? `${m.title} — KFS Films` : 'KFS Films',
      description: desc,
      imageUrl:    m.poster_image ? `https://kiitfilmsociety.in/og/film/${m.id}` : null,
      url:         pageUrl,
    });
  } catch (err) {
    console.error('[share/film]', err.message);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ── /events/:slug ─────────────────────────────────────────────────────────────
app.get('/events/:slug', async (req, res) => {
  try {
    const id = idFromSlug(req.params.slug);
    const { data: e } = id
      ? await supabase.from('events').select('id,title,description,cover_image,event_date,location').eq('id', id).maybeSingle()
      : null;

    if (!e) {
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    const canonicalSlug = slugify(e.title) + '-' + e.id;
    const pageUrl = `https://kiitfilmsociety.in/events/${canonicalSlug}`;
    const dateStr = e.event_date
      ? new Date(e.event_date).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })
      : null;
    const desc = e.description
      ? e.description.slice(0, 160)
      : `KFS Event${dateStr ? ' on ' + dateStr : ''}${e.location ? ' at ' + e.location : ''}.`;

    return serveWithOg(res, {
      title:       e.title ? `${e.title} — KFS Events` : 'KFS Events',
      description: desc,
      imageUrl:    e.cover_image ? `https://kiitfilmsociety.in/og/event/${e.id}` : null,
      url:         pageUrl,
    });
  } catch (err) {
    console.error('[share/event]', err.message);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ── KFS WRAPPED ───────────────────────────────────────────────────────────────
// Public: get the wrapped config (year, taglines, fun cards) set by admin
app.get('/api/wrapped/config', async (req, res) => {
  const { data } = await supabase.from('settings').select('value').eq('key', 'wrapped_config').maybeSingle();
  try {
    res.json(data ? JSON.parse(data.value) : {});
  } catch { res.json({}); }
});

// Admin: save wrapped config
app.post('/api/admin/wrapped/config', requireSection('settings'), async (req, res) => {
  const config = req.body;
  if (typeof config !== 'object') return res.status(400).json({ error: 'Invalid config' });
  await supabase.from('settings').upsert({ key: 'wrapped_config', value: JSON.stringify(config) }, { onConflict: 'key' });
  await logActivity(req.admin.id, req.admin.name, 'update', 'settings', 'KFS Wrapped Config');
  res.json({ success: true });
});

// Public: aggregate stats for Wrapped (all-time + per-year totals)
app.get('/api/wrapped/stats', async (req, res) => {
  try {
    const year = req.query.year ? parseInt(req.query.year) : null;

    // All movies
    const { data: movies } = await supabase.from('movies').select('id,title,genre,release_year,director,poster_image');

    // All published blogs (for personalized blog-read cards)
    const { data: blogs } = await supabase.from('blogs').select('id,title,cover_image').eq('published', true);

    // Genre frequency map across all KFS films
    const genreCount = {};
    (movies || []).forEach(m => {
      let genres = [];
      try { genres = JSON.parse(m.genre || '[]'); } catch { genres = m.genre ? [m.genre] : []; }
      if (!Array.isArray(genres)) genres = [genres];
      genres.forEach(g => { if (g) genreCount[g] = (genreCount[g] || 0) + 1; });
    });
    const topGenres = Object.entries(genreCount).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([g,c])=>({genre:g,count:c}));

    // Total counts
    const { count: totalMovies } = await supabase.from('movies').select('id', { count: 'exact', head: true });
    const { count: totalBlogs  } = await supabase.from('blogs').select('id', { count: 'exact', head: true }).eq('published', true);
    const { count: totalEvents } = await supabase.from('events').select('id', { count: 'exact', head: true });
    const { count: totalReviews} = await supabase.from('reviews').select('id', { count: 'exact', head: true });

    // Year-specific counts (films released that year)
    let yearMovies = null;
    if (year) {
      const { count } = await supabase.from('movies').select('id', { count: 'exact', head: true }).eq('release_year', year);
      yearMovies = count;
    }

    // Top reviewed film
    const { data: reviews } = await supabase.from('reviews').select('movie_id,overall');
    const filmScores = {};
    (reviews || []).forEach(r => {
      if (!filmScores[r.movie_id]) filmScores[r.movie_id] = [];
      filmScores[r.movie_id].push(r.overall);
    });
    let topRated = null;
    let bestScore = 0;
    Object.entries(filmScores).forEach(([mid, scores]) => {
      const avg = scores.reduce((a,b)=>a+b,0)/scores.length;
      if (avg > bestScore && scores.length >= 2) { bestScore = avg; topRated = mid; }
    });
    const topRatedMovie = topRated ? (movies||[]).find(m=>String(m.id)===String(topRated)) : null;

    res.json({
      totalMovies: totalMovies || 0,
      totalBlogs: totalBlogs || 0,
      totalEvents: totalEvents || 0,
      totalReviews: totalReviews || 0,
      yearMovies,
      topGenres,
      topRatedMovie: topRatedMovie ? { id: topRatedMovie.id, title: topRatedMovie.title, poster_image: topRatedMovie.poster_image, score: Math.round(bestScore*10)/10 } : null,
      allMovies: (movies || []).map(m => {
        let genres = [];
        try { genres = JSON.parse(m.genre || '[]'); } catch { genres = m.genre ? [m.genre] : []; }
        return { id: m.id, title: m.title, genre: Array.isArray(genres) ? genres : [genres], release_year: m.release_year, director: m.director, poster_image: m.poster_image };
      }),
      allBlogs: (blogs || []).map(b => ({ id: b.id, title: b.title, cover_image: b.cover_image })),
    });
  } catch(e) {
    console.error('[wrapped/stats]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── RECOMMENDATIONS ────────────────────────────────────────────────────────────
// Returns films similar to a given film by tag/genre overlap
app.get('/api/recommendations/:movieId', async (req, res) => {
  try {
    const { data: source } = await supabase.from('movies').select('id,genre,director').eq('id', req.params.movieId).maybeSingle();
    if (!source) return res.json([]);

    let srcGenres = [];
    try { srcGenres = JSON.parse(source.genre || '[]'); } catch { srcGenres = source.genre ? [source.genre] : []; }
    if (!Array.isArray(srcGenres)) srcGenres = [srcGenres];
    srcGenres = srcGenres.map(g => g.toLowerCase().trim());

    const { data: all } = await supabase.from('movies').select('id,title,genre,director,poster_image,release_year').neq('id', req.params.movieId);

    const scored = (all || []).map(m => {
      let mGenres = [];
      try { mGenres = JSON.parse(m.genre || '[]'); } catch { mGenres = m.genre ? [m.genre] : []; }
      if (!Array.isArray(mGenres)) mGenres = [mGenres];
      mGenres = mGenres.map(g => g.toLowerCase().trim());

      let score = 0;
      let reason = 'genre';
      // Genre overlap (2 pts per match)
      srcGenres.forEach(g => { if (mGenres.includes(g)) score += 2; });
      // Same director (3 pts)
      if (source.director && m.director && source.director.split(/[,|]+/)[0].trim().toLowerCase() === m.director.split(/[,|]+/)[0].trim().toLowerCase()) {
        score += 3; reason = 'director';
      }

      return { ...m, genre: mGenres, _score: score, _reason: reason };
    }).filter(m => m._score > 0).sort((a,b) => b._score - a._score).slice(0, 6);

    res.json(scored.map(({ _score, ...m }) => m));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── CATCH-ALL ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── SUPABASE KEEPALIVE ────────────────────────────────────────────────────────
// Ping every 4 minutes to prevent connection from going cold
setInterval(async () => {
  try {
    await supabase.from('settings').select('key').limit(1);
    // Silent success — log only on failure
  } catch (e) {
    console.error('Supabase keepalive failed:', e.message);
  }
}, 1000 * 60 * 4);

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`KFS server running on port ${PORT}`);
  await initDB();
  console.log('DB initialized');
});

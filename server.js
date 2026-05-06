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
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://agxsilmugsrzxgerpaqm.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFneHNpbG11Z3NyenhnZXJwYXFtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3Nzc3NzYwNSwiZXhwIjoyMDkzMzUzNjA1fQ.CUZSCcBFdJn_XWuzqbPLA4dOZGjd8QuikaRRXlajUDI';
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

const JWT_SECRET = process.env.JWT_SECRET || 'kfs@KIIT#filmSociety$2024!secret';

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
  const { title, excerpt, content, published, sections } = req.body;
  const coverUrl = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').insert([{
    title, excerpt, content, cover_image: coverUrl, published: published === 'true',
    sections: sections || '[]',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'blog', title);
  res.json(data);
});

app.put('/api/admin/blogs/:id', requireSection('blogs'), upload.single('cover'), async (req, res) => {
  const { title, excerpt, content, published, sections } = req.body;
  const updates = { title, excerpt, content, published: published === 'true', sections: sections || '[]' };
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

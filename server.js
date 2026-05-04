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
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const JWT_SECRET = process.env.JWT_SECRET || 'kfs@KIIT#filmSociety$2024!secret';

// ── File uploads ──────────────────────────────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

async function uploadImage(file, folder = 'general') {
  if (!file) return null;
  const ext = path.extname(file.originalname) || '.jpg';
  const filename = `${folder}/${Date.now()}${ext}`;
  const { data, error } = await supabase.storage
    .from('kfs-media')
    .upload(filename, file.buffer, { contentType: file.mimetype, upsert: true });
  if (error) { console.error('Storage error:', error); return null; }
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

// ── Activity logger ───────────────────────────────────────────────────────────
async function logActivity(adminId, adminName, action, entity, entityName) {
  try {
    await supabase.from('admin_activity').insert([{
      admin_id: adminId,
      admin_name: adminName,
      action,       // 'create' | 'update' | 'delete'
      entity,       // 'movie' | 'blog' | 'event' | 'member' | etc.
      entity_name: entityName,
    }]);
  } catch(e) { console.error('Activity log error:', e); }
}

// ── DB Init ───────────────────────────────────────────────────────────────────
async function initDB() {
  // Ensure master admin exists
  const { data: master } = await supabase.from('admins').select('id').eq('role', 'master').single();
  if (!master) {
    const hash = await bcrypt.hash('KFS@master2024!', 10);
    await supabase.from('admins').insert([{
      name: 'KFS Master',
      username: 'kfsmaster',
      password_hash: hash,
      role: 'master',
    }]);
    console.log('Master admin created: username=kfsmaster password=KFS@master2024!');
  }

  // Migrate old settings-based admin password into admins table as a regular admin (once)
  const { data: settings } = await supabase.from('settings').select('*').eq('key', 'admin_password').single();
  if (!settings) {
    await supabase.from('settings').insert([
      { key: 'site_tagline', value: 'Lights. Camera. KFS.' },
      { key: 'about_text', value: 'KIIT Film Society is a student-run collective passionate about cinema.' },
      { key: 'instagram', value: '' },
      { key: 'youtube', value: '' },
      { key: 'email', value: 'kfs@kiit.ac.in' },
    ]).then(() => {}).catch(() => {});
  }
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const { data: admin } = await supabase.from('admins').select('*').eq('username', username.trim()).single();
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: admin.id, name: admin.name, username: admin.username, role: admin.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({ token, name: admin.name, role: admin.role });
});

// Change own password (any admin)
app.post('/api/admin/change-password', authMiddleware, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password too short' });
  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from('admins').update({ password_hash: hash }).eq('id', req.admin.id);
  res.json({ success: true });
});

// ── TOKEN REFRESH ─────────────────────────────────────────────────────────────
// Re-issues a JWT with the CURRENT role from the DB.
// Called on every page load — this is the fix for "add admin not working":
// old tokens have role:'admin' baked in even after DB was fixed to 'master'.
app.post('/api/admin/refresh', authMiddleware, async (req, res) => {
  const { data: admin, error } = await supabase
    .from('admins').select('id,name,username,role').eq('id', req.admin.id).single();
  if (error || !admin) return res.status(401).json({ error: 'Admin not found' });
  const token = jwt.sign(
    { id: admin.id, name: admin.name, username: admin.username, role: admin.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
  console.log(`[refresh] ${admin.username} — role: ${admin.role}`);
  res.json({ token, name: admin.name, role: admin.role });
});

// ── MASTER: Admin management ──────────────────────────────────────────────────
app.get('/api/master/admins', masterMiddleware, async (req, res) => {
  const { data } = await supabase.from('admins').select('id,name,username,role,created_at').order('created_at');
  res.json(data || []);
});

app.post('/api/master/admins', masterMiddleware, async (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('admins').insert([{
    name, username: username.trim().toLowerCase(), password_hash: hash, role: 'admin'
  }]).select('id,name,username,role,created_at').single();
  if (error) return res.status(400).json({ error: error.message.includes('unique') ? 'Username already taken' : error.message });
  res.json(data);
});

app.delete('/api/master/admins/:id', masterMiddleware, async (req, res) => {
  // Prevent deleting the master account
  const { data: target } = await supabase.from('admins').select('role').eq('id', req.params.id).single();
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (target.role === 'master') return res.status(403).json({ error: 'Cannot delete master admin' });
  await supabase.from('admins').delete().eq('id', req.params.id);
  res.json({ success: true });
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

app.post('/api/admin/upload-team-photo', authMiddleware, upload.single('photo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const url = await uploadImage(req.file, 'general');
  if (!url) return res.status(500).json({ error: 'Upload failed' });
  res.json({ url });
});

app.post('/api/admin/settings', authMiddleware, async (req, res) => {
  const entries = Object.entries(req.body);
  for (const [key, value] of entries) {
    // Skip empty strings so they don't overwrite existing values (e.g. team_photo)
    if (value === '' || value === null || value === undefined) continue;
    await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
  }
  await logActivity(req.admin.id, req.admin.name, 'update', 'settings', 'Site Settings');
  res.json({ success: true });
});

// ── BLOGS ─────────────────────────────────────────────────────────────────────
app.get('/api/blogs', async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').eq('published', true).order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/admin/blogs', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/blogs/:id', async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

app.post('/api/admin/blogs', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, excerpt, content, published } = req.body;
  const coverUrl = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').insert([{
    title, excerpt, content, cover_image: coverUrl, published: published === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'blog', title);
  res.json(data);
});

app.put('/api/admin/blogs/:id', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, excerpt, content, published } = req.body;
  const updates = { title, excerpt, content, published: published === 'true' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'blog', title);
  res.json(data);
});

app.delete('/api/admin/blogs/:id', authMiddleware, async (req, res) => {
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

app.post('/api/admin/events', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, description, event_date, event_time, location, is_upcoming } = req.body;
  const coverUrl = await uploadImage(req.file, 'events');
  const { data, error } = await supabase.from('events').insert([{
    title, description, event_date, event_time, location, cover_image: coverUrl, is_upcoming: is_upcoming === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'event', title);
  res.json(data);
});

app.put('/api/admin/events/:id', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, description, event_date, event_time, location, is_upcoming } = req.body;
  const updates = { title, description, event_date, event_time, location, is_upcoming: is_upcoming === 'true' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'events');
  const { data, error } = await supabase.from('events').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'event', title);
  res.json(data);
});

app.delete('/api/admin/events/:id', authMiddleware, async (req, res) => {
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

app.post('/api/admin/members', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order, is_past, domain } = req.body;
  const photoUrl = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').insert([{
    name, role, batch, bio, domain: domain||null, photo: photoUrl,
    sort_order: parseInt(sort_order) || 99, is_past: is_past === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'member', name);
  res.json(data);
});

app.put('/api/admin/members/:id', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order, is_past, domain } = req.body;
  const updates = { name, role, batch, bio, domain: domain||null, sort_order: parseInt(sort_order) || 99, is_past: is_past === 'true' };
  if (req.file) updates.photo = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'member', name);
  res.json(data);
});

app.delete('/api/admin/members/:id', authMiddleware, async (req, res) => {
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

app.post('/api/admin/testimonials', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, quote } = req.body;
  const photoUrl = await uploadImage(req.file, 'testimonials');
  const { data, error } = await supabase.from('testimonials').insert([{ name, role, batch, quote, photo: photoUrl }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'testimonial', name);
  res.json(data);
});

app.put('/api/admin/testimonials/:id', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, quote } = req.body;
  const updates = { name, role, batch, quote };
  if (req.file) updates.photo = await uploadImage(req.file, 'testimonials');
  const { data, error } = await supabase.from('testimonials').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'testimonial', name);
  res.json(data);
});

app.delete('/api/admin/testimonials/:id', authMiddleware, async (req, res) => {
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

app.post('/api/admin/achievements', authMiddleware, async (req, res) => {
  const { title, description, year, icon, sort_order } = req.body;
  const { data, error } = await supabase.from('achievements').insert([{
    title, description, year, icon: icon || '🏆', sort_order: parseInt(sort_order) || 99
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'achievement', title);
  res.json(data);
});

app.put('/api/admin/achievements/:id', authMiddleware, async (req, res) => {
  const { title, description, year, icon, sort_order } = req.body;
  const { data, error } = await supabase.from('achievements').update({
    title, description, year, icon, sort_order: parseInt(sort_order) || 99
  }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'achievement', title);
  res.json(data);
});

app.delete('/api/admin/achievements/:id', authMiddleware, async (req, res) => {
  const { data: a } = await supabase.from('achievements').select('title').eq('id', req.params.id).single();
  await supabase.from('achievements').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'achievement', a?.title || req.params.id);
  res.json({ success: true });
});

// ── MOVIES ────────────────────────────────────────────────────────────────────
app.get('/api/movies', async (req, res) => {
  const { data } = await supabase.from('movies').select('*').order('release_year', { ascending: false });
  res.json(data || []);
});

app.get('/api/movies/:id', async (req, res) => {
  const { data } = await supabase.from('movies').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});

app.post('/api/admin/movies', authMiddleware, upload.single('poster'), async (req, res) => {
  const { title, release_year, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew, trailer_url, watch_url } = req.body;
  const posterUrl = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').insert([{
    title, release_year, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew,
    poster_image: posterUrl, trailer_url: trailer_url || null, watch_url: watch_url || null,
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'create', 'movie', title);
  res.json(data);
});

app.put('/api/admin/movies/:id', authMiddleware, upload.single('poster'), async (req, res) => {
  const { title, release_year, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew, trailer_url, watch_url } = req.body;
  const updates = { title, release_year, director, producer, dop, screenwriter, video_editor, sound_design, management, graphic_design, actors, support_crew,
    trailer_url: trailer_url || null, watch_url: watch_url || null };
  if (req.file) updates.poster_image = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.admin.id, req.admin.name, 'update', 'movie', title);
  res.json(data);
});

app.delete('/api/admin/movies/:id', authMiddleware, async (req, res) => {
  const { data: mv } = await supabase.from('movies').select('title').eq('id', req.params.id).single();
  await supabase.from('movies').delete().eq('id', req.params.id);
  await logActivity(req.admin.id, req.admin.name, 'delete', 'movie', mv?.title || req.params.id);
  res.json({ success: true });
});

// ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
app.get('/api/notifications/active', async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').eq('active', true).limit(1).single();
  res.json(data || null);
});

app.get('/api/admin/notifications', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/notifications', authMiddleware, async (req, res) => {
  const { title, type, message, btn_text, btn_link, active } = req.body;
  const { data, error } = await supabase.from('notifications').insert([{
    title, type, message, btn_text, btn_link, active: active === 'true' || active === true
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/notifications/:id', authMiddleware, async (req, res) => {
  const { title, type, message, btn_text, btn_link, active } = req.body;
  const { data, error } = await supabase.from('notifications').update({
    title, type, message, btn_text, btn_link, active: active === 'true' || active === true
  }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/notifications/:id', authMiddleware, async (req, res) => {
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

app.get('/api/admin/analytics/traffic', authMiddleware, async (req, res) => {
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
app.get('/api/admin/analytics/reviews', authMiddleware, async (req, res) => {
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

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`KFS server running on port ${PORT}`);
  await initDB();
  console.log('DB initialized');
});

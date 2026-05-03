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

// ── File uploads (Supabase Storage) ──────────────────────────────────────────
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

// ── DB Init ───────────────────────────────────────────────────────────────────
async function initDB() {
  const { data: settings } = await supabase.from('settings').select('*').eq('key', 'admin_password').single();
  if (!settings) {
    const hash = await bcrypt.hash('kfs@admin2024', 10);
    await supabase.from('settings').insert([
      { key: 'admin_password', value: hash },
      { key: 'site_tagline', value: 'Lights. Camera. KFS.' },
      { key: 'about_text', value: 'KIIT Film Society is a student-run collective passionate about cinema — from production to appreciation. We screen films, host workshops, produce original content, and celebrate storytelling in every form.' },
      { key: 'instagram', value: '' },
      { key: 'youtube', value: '' },
      { key: 'email', value: 'kfs@kiit.ac.in' },
    ]);
  }
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  const { data } = await supabase.from('settings').select('value').eq('key', 'admin_password').single();
  if (!data) return res.status(500).json({ error: 'DB error' });
  const valid = await bcrypt.compare(password, data.value);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.post('/api/admin/change-password', authMiddleware, async (req, res) => {
  const { newPassword } = req.body;
  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from('settings').update({ value: hash }).eq('key', 'admin_password');
  res.json({ success: true });
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
app.get('/api/settings', async (req, res) => {
  const { data } = await supabase.from('settings').select('*').neq('key', 'admin_password');
  const obj = {};
  (data || []).forEach(r => obj[r.key] = r.value);
  res.json(obj);
});

app.post('/api/admin/settings', authMiddleware, async (req, res) => {
  const entries = Object.entries(req.body);
  for (const [key, value] of entries) {
    await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
  }
  res.json({ success: true });
});

// ── BLOGS ─────────────────────────────────────────────────────────────────────
app.get('/api/blogs', async (req, res) => {
  const { data } = await supabase.from('blogs').select('*').eq('published', true).order('created_at', { ascending: false });
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
    title, excerpt, content,
    cover_image: coverUrl,
    published: published === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/blogs/:id', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, excerpt, content, published } = req.body;
  const updates = { title, excerpt, content, published: published === 'true' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'blogs');
  const { data, error } = await supabase.from('blogs').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/blogs/:id', authMiddleware, async (req, res) => {
  await supabase.from('blogs').delete().eq('id', req.params.id);
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
    title, description, event_date, event_time, location,
    cover_image: coverUrl,
    is_upcoming: is_upcoming === 'true',
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/events/:id', authMiddleware, upload.single('cover'), async (req, res) => {
  const { title, description, event_date, event_time, location, is_upcoming } = req.body;
  const updates = { title, description, event_date, event_time, location, is_upcoming: is_upcoming === 'true' };
  if (req.file) updates.cover_image = await uploadImage(req.file, 'events');
  const { data, error } = await supabase.from('events').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/events/:id', authMiddleware, async (req, res) => {
  await supabase.from('events').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ── MEMBERS ───────────────────────────────────────────────────────────────────
app.get('/api/members', async (req, res) => {
  const { data } = await supabase.from('members').select('*').order('sort_order', { ascending: true });
  res.json(data || []);
});

app.post('/api/admin/members', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order } = req.body;
  const photoUrl = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').insert([{
    name, role, batch, bio, photo: photoUrl, sort_order: parseInt(sort_order) || 99
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/members/:id', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, bio, sort_order } = req.body;
  const updates = { name, role, batch, bio, sort_order: parseInt(sort_order) || 99 };
  if (req.file) updates.photo = await uploadImage(req.file, 'members');
  const { data, error } = await supabase.from('members').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/members/:id', authMiddleware, async (req, res) => {
  await supabase.from('members').delete().eq('id', req.params.id);
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
  const { data, error } = await supabase.from('testimonials').insert([{
    name, role, batch, quote, photo: photoUrl
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/testimonials/:id', authMiddleware, upload.single('photo'), async (req, res) => {
  const { name, role, batch, quote } = req.body;
  const updates = { name, role, batch, quote };
  if (req.file) updates.photo = await uploadImage(req.file, 'testimonials');
  const { data, error } = await supabase.from('testimonials').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/testimonials/:id', authMiddleware, async (req, res) => {
  await supabase.from('testimonials').delete().eq('id', req.params.id);
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
  res.json(data);
});

app.put('/api/admin/achievements/:id', authMiddleware, async (req, res) => {
  const { title, description, year, icon, sort_order } = req.body;
  const { data, error } = await supabase.from('achievements').update({
    title, description, year, icon, sort_order: parseInt(sort_order) || 99
  }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/achievements/:id', authMiddleware, async (req, res) => {
  await supabase.from('achievements').delete().eq('id', req.params.id);
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
  const { title, release_year, director, producer, dop, graphic_design, actors, support_crew } = req.body;
  const posterUrl = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').insert([{
    title, release_year, director, producer, dop, graphic_design, actors, support_crew,
    poster_image: posterUrl,
  }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/movies/:id', authMiddleware, upload.single('poster'), async (req, res) => {
  const { title, release_year, director, producer, dop, graphic_design, actors, support_crew } = req.body;
  const updates = { title, release_year, director, producer, dop, graphic_design, actors, support_crew };
  if (req.file) updates.poster_image = await uploadImage(req.file, 'movies');
  const { data, error } = await supabase.from('movies').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/admin/movies/:id', authMiddleware, async (req, res) => {
  await supabase.from('movies').delete().eq('id', req.params.id);
  res.json({ success: true });
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

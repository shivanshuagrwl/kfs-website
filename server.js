const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kfs-secret-key-change-in-production';

// ─── Database Setup ────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db', 'kfs.db');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS blogs (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    excerpt TEXT,
    content TEXT NOT NULL,
    cover_image TEXT,
    author TEXT DEFAULT 'KFS Team',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    published INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    date TEXT NOT NULL,
    time TEXT,
    location TEXT,
    cover_image TEXT,
    is_upcoming INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    batch TEXT,
    photo TEXT,
    bio TEXT,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS testimonials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT,
    batch TEXT,
    quote TEXT NOT NULL,
    photo TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS achievements (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    year TEXT,
    icon TEXT DEFAULT '🏆',
    sort_order INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS site_settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Seed admin if not exists
const adminExists = db.prepare('SELECT id FROM admin LIMIT 1').get();
if (!adminExists) {
  const hash = bcrypt.hashSync('kfs@admin2024', 10);
  db.prepare('INSERT INTO admin (username, password) VALUES (?, ?)').run('admin', hash);
  console.log('✅ Default admin created: admin / kfs@admin2024');
}

// Seed default settings
const settingsDefaults = {
  hero_tagline: 'Where Stories Come to Life',
  hero_subtitle: 'KIIT\'s premier film society — celebrating cinema, storytelling, and the art of moving images since 2018.',
  about_text: 'KFS (KIIT Film Society) is a student-run organization dedicated to the appreciation, discussion, and creation of cinema. We screen films, host workshops, organize fests, and nurture the next generation of storytellers at KIIT University.',
  instagram: 'https://instagram.com',
  youtube: 'https://youtube.com',
  email: 'kfs@kiit.ac.in',
};
for (const [key, value] of Object.entries(settingsDefaults)) {
  db.prepare('INSERT OR IGNORE INTO site_settings (key, value) VALUES (?, ?)').run(key, value);
}

// Seed sample achievements
const achieveCount = db.prepare('SELECT COUNT(*) as c FROM achievements').get().c;
if (achieveCount === 0) {
  const achievements = [
    { id: uuidv4(), title: 'Best Film Society', description: 'Awarded at KIIT Fest 2023', year: '2023', icon: '🏆', sort_order: 1 },
    { id: uuidv4(), title: 'National Screenplay Winner', description: 'Our member won the All India Screenplay Competition', year: '2022', icon: '✍️', sort_order: 2 },
    { id: uuidv4(), title: '500+ Screenings', description: 'Crossed 500 curated film screenings on campus', year: '2023', icon: '🎬', sort_order: 3 },
    { id: uuidv4(), title: 'Cine Fest Organizer', description: 'Hosted KIIT\'s first dedicated film festival with 2000+ attendees', year: '2022', icon: '🎥', sort_order: 4 },
  ];
  for (const a of achievements) {
    db.prepare('INSERT INTO achievements VALUES (@id,@title,@description,@year,@icon,@sort_order)').run(a);
  }
}

// ─── Multer Storage ────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'public', 'uploads')),
  destination(req, file, cb) {
    const dir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  },
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function authRequired(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Slug helper
function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

function getSettings() {
  const rows = db.prepare('SELECT key, value FROM site_settings').all();
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

// ─── PUBLIC API ────────────────────────────────────────────────────────────────
// Settings
app.get('/api/settings', (req, res) => res.json(getSettings()));

// Blogs
app.get('/api/blogs', (req, res) => {
  const blogs = db.prepare('SELECT id,title,slug,excerpt,cover_image,author,created_at FROM blogs WHERE published=1 ORDER BY created_at DESC').all();
  res.json(blogs);
});
app.get('/api/blogs/:slug', (req, res) => {
  const blog = db.prepare('SELECT * FROM blogs WHERE slug=? AND published=1').get(req.params.slug);
  if (!blog) return res.status(404).json({ error: 'Not found' });
  res.json(blog);
});

// Events
app.get('/api/events', (req, res) => {
  const { type } = req.query;
  let query = 'SELECT * FROM events ORDER BY date DESC';
  if (type === 'upcoming') query = 'SELECT * FROM events WHERE is_upcoming=1 ORDER BY date ASC';
  if (type === 'past') query = 'SELECT * FROM events WHERE is_upcoming=0 ORDER BY date DESC';
  res.json(db.prepare(query).all());
});

// Members
app.get('/api/members', (req, res) => {
  res.json(db.prepare('SELECT * FROM members ORDER BY sort_order ASC, created_at ASC').all());
});

// Testimonials
app.get('/api/testimonials', (req, res) => {
  res.json(db.prepare('SELECT * FROM testimonials ORDER BY created_at DESC').all());
});

// Achievements
app.get('/api/achievements', (req, res) => {
  res.json(db.prepare('SELECT * FROM achievements ORDER BY sort_order ASC').all());
});

// ─── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const admin = db.prepare('SELECT * FROM admin WHERE username=?').get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: admin.username });
});

app.post('/api/auth/change-password', authRequired, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const admin = db.prepare('SELECT * FROM admin WHERE id=?').get(req.admin.id);
  if (!bcrypt.compareSync(oldPassword, admin.password)) {
    return res.status(400).json({ error: 'Old password incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE admin SET password=? WHERE id=?').run(hash, req.admin.id);
  res.json({ success: true });
});

// ─── ADMIN API ─────────────────────────────────────────────────────────────────
// Upload image
app.post('/api/admin/upload', authRequired, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Settings
app.put('/api/admin/settings', authRequired, (req, res) => {
  for (const [key, value] of Object.entries(req.body)) {
    db.prepare('INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)').run(key, String(value));
  }
  res.json({ success: true });
});

// --- Blogs CRUD ---
app.get('/api/admin/blogs', authRequired, (req, res) => {
  res.json(db.prepare('SELECT * FROM blogs ORDER BY created_at DESC').all());
});
app.post('/api/admin/blogs', authRequired, (req, res) => {
  const { title, excerpt, content, cover_image, author, published } = req.body;
  const id = uuidv4();
  let slug = slugify(title);
  // ensure unique slug
  let existing = db.prepare('SELECT id FROM blogs WHERE slug=?').get(slug);
  if (existing) slug = slug + '-' + Date.now();
  db.prepare('INSERT INTO blogs (id,title,slug,excerpt,content,cover_image,author,published) VALUES (?,?,?,?,?,?,?,?)')
    .run(id, title, slug, excerpt || '', content, cover_image || '', author || 'KFS Team', published ? 1 : 0);
  res.json({ success: true, id, slug });
});
app.put('/api/admin/blogs/:id', authRequired, (req, res) => {
  const { title, excerpt, content, cover_image, author, published } = req.body;
  db.prepare('UPDATE blogs SET title=?,excerpt=?,content=?,cover_image=?,author=?,published=? WHERE id=?')
    .run(title, excerpt || '', content, cover_image || '', author || 'KFS Team', published ? 1 : 0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/admin/blogs/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM blogs WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- Events CRUD ---
app.get('/api/admin/events', authRequired, (req, res) => {
  res.json(db.prepare('SELECT * FROM events ORDER BY date DESC').all());
});
app.post('/api/admin/events', authRequired, (req, res) => {
  const { title, description, date, time, location, cover_image, is_upcoming } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO events (id,title,description,date,time,location,cover_image,is_upcoming) VALUES (?,?,?,?,?,?,?,?)')
    .run(id, title, description || '', date, time || '', location || '', cover_image || '', is_upcoming ? 1 : 0);
  res.json({ success: true, id });
});
app.put('/api/admin/events/:id', authRequired, (req, res) => {
  const { title, description, date, time, location, cover_image, is_upcoming } = req.body;
  db.prepare('UPDATE events SET title=?,description=?,date=?,time=?,location=?,cover_image=?,is_upcoming=? WHERE id=?')
    .run(title, description || '', date, time || '', location || '', cover_image || '', is_upcoming ? 1 : 0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/admin/events/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM events WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- Members CRUD ---
app.get('/api/admin/members', authRequired, (req, res) => {
  res.json(db.prepare('SELECT * FROM members ORDER BY sort_order ASC').all());
});
app.post('/api/admin/members', authRequired, (req, res) => {
  const { name, role, batch, photo, bio, sort_order } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO members (id,name,role,batch,photo,bio,sort_order) VALUES (?,?,?,?,?,?,?)')
    .run(id, name, role, batch || '', photo || '', bio || '', sort_order || 0);
  res.json({ success: true, id });
});
app.put('/api/admin/members/:id', authRequired, (req, res) => {
  const { name, role, batch, photo, bio, sort_order } = req.body;
  db.prepare('UPDATE members SET name=?,role=?,batch=?,photo=?,bio=?,sort_order=? WHERE id=?')
    .run(name, role, batch || '', photo || '', bio || '', sort_order || 0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/admin/members/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM members WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- Testimonials CRUD ---
app.get('/api/admin/testimonials', authRequired, (req, res) => {
  res.json(db.prepare('SELECT * FROM testimonials ORDER BY created_at DESC').all());
});
app.post('/api/admin/testimonials', authRequired, (req, res) => {
  const { name, role, batch, quote, photo } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO testimonials (id,name,role,batch,quote,photo) VALUES (?,?,?,?,?,?)')
    .run(id, name, role || '', batch || '', quote, photo || '');
  res.json({ success: true, id });
});
app.put('/api/admin/testimonials/:id', authRequired, (req, res) => {
  const { name, role, batch, quote, photo } = req.body;
  db.prepare('UPDATE testimonials SET name=?,role=?,batch=?,quote=?,photo=? WHERE id=?')
    .run(name, role || '', batch || '', quote, photo || '', req.params.id);
  res.json({ success: true });
});
app.delete('/api/admin/testimonials/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM testimonials WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- Achievements CRUD ---
app.get('/api/admin/achievements', authRequired, (req, res) => {
  res.json(db.prepare('SELECT * FROM achievements ORDER BY sort_order ASC').all());
});
app.post('/api/admin/achievements', authRequired, (req, res) => {
  const { title, description, year, icon, sort_order } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO achievements (id,title,description,year,icon,sort_order) VALUES (?,?,?,?,?,?)')
    .run(id, title, description || '', year || '', icon || '🏆', sort_order || 0);
  res.json({ success: true, id });
});
app.put('/api/admin/achievements/:id', authRequired, (req, res) => {
  const { title, description, year, icon, sort_order } = req.body;
  db.prepare('UPDATE achievements SET title=?,description=?,year=?,icon=?,sort_order=? WHERE id=?')
    .run(title, description || '', year || '', icon || '🏆', sort_order || 0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/admin/achievements/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM achievements WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎬 KFS Server running on port ${PORT}`);
});

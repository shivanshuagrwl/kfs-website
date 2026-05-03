# KFS — KIIT Film Society Website

A full-stack, production-ready website for KIIT Film Society with a hidden admin CMS.

## 🚀 Features

- **Home Page** — Hero, Stats, About, Achievements, Upcoming Events, Blog Preview, Testimonials
- **Events Page** — Upcoming & Past events
- **Blog** — Full posts with rich text, cover images
- **Members Page** — Photo grid with name, role, batch
- **Admin CMS** (hidden at `/admin`) — Manage everything without touching code:
  - ✍️ Write & publish blog posts (rich text editor)
  - 🎬 Add/edit/delete events
  - 👥 Add members with photos
  - 💬 Add testimonials
  - 🏆 Manage achievements
  - ⚙️ Edit site settings (tagline, about text, social links)
  - 🔐 Change admin password

## 📦 Local Setup

```bash
npm install
node server.js
```

Visit `http://localhost:3000`

Admin: `http://localhost:3000/admin`
Default credentials: `admin` / `kfs@admin2024`

**Change the default password immediately after first login.**

## 🌐 Deploy to Render

1. Push this code to a GitHub repository
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Set:
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Add a Disk**: Mount path `/opt/render/project/src`, size 1GB (to persist the SQLite database and uploads)
5. Add environment variable: `JWT_SECRET` = any long random string
6. Deploy!

> ⚠️ **Important**: You MUST add a persistent disk on Render for the database and uploaded images to survive restarts. Go to your service → Disks → Add Disk.

## 🗂 Project Structure

```
kfs/
├── server.js          # Express server + all API routes
├── public/
│   ├── index.html     # SPA frontend (all pages in one file)
│   ├── images/        # Logo and static images
│   └── uploads/       # User-uploaded images (auto-created)
├── db/                # SQLite database (auto-created)
├── render.yaml        # Render deployment config
└── package.json
```

## 🔐 Security Notes

- The admin login page is NOT linked anywhere on the public site
- Only someone who knows the `/admin` URL can access it
- JWT tokens expire after 7 days
- **Change the default password** (`kfs@admin2024`) on first login
- Set `JWT_SECRET` as a strong random string in Render environment variables

## 🎨 Design

- Black & white theme matching the KFS logo aesthetic
- Helvetica Neue throughout
- Apple-style smooth animations and transitions
- Fully responsive (mobile-first)

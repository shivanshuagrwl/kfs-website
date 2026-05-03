# KFS — KIIT Film Society

Official website for KIIT Film Society. A full-stack, single-page web application for managing and showcasing the society's films, events, blog, and members.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript (no framework) |
| Backend | Node.js + Express |
| Database | Supabase (PostgreSQL) |
| File Storage | Supabase Storage (`kfs-media` bucket) |
| Auth | JWT + bcrypt |

---

## Project Structure

```
kfs/
├── public/
│   └── index.html        # Entire frontend SPA
├── server.js             # Express backend + all API routes
├── .env                  # Environment variables (not committed)
└── package.json
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- A Supabase project with the tables listed below

### Installation

```bash
git clone https://github.com/your-org/kfs.git
cd kfs
npm install
```

### Environment Variables

Create a `.env` file in the root:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_service_role_key
JWT_SECRET=your_jwt_secret
PORT=3000
```

### Database Setup

Run the following in the Supabase SQL editor to create all required tables:

```sql
create table settings (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  value text
);

create table blogs (
  id uuid primary key default gen_random_uuid(),
  title text,
  excerpt text,
  content text,
  cover_image text,
  published boolean default false,
  created_at timestamptz default now()
);

create table events (
  id uuid primary key default gen_random_uuid(),
  title text,
  description text,
  event_date date,
  event_time text,
  location text,
  cover_image text,
  is_upcoming boolean default true
);

create table members (
  id uuid primary key default gen_random_uuid(),
  name text,
  role text,
  domain text,
  batch text,
  bio text,
  photo text,
  sort_order int default 99,
  is_past boolean default false
);

create table movies (
  id uuid primary key default gen_random_uuid(),
  title text,
  release_year text,
  director text,
  producer text,
  dop text,
  screenwriter text,
  video_editor text,
  sound_design text,
  management text,
  graphic_design text,
  actors text,
  support_crew text,
  poster_image text,
  trailer_url text,
  watch_url text
);

create table testimonials (
  id uuid primary key default gen_random_uuid(),
  name text,
  role text,
  batch text,
  quote text,
  photo text,
  created_at timestamptz default now()
);

create table achievements (
  id uuid primary key default gen_random_uuid(),
  title text,
  description text,
  year text,
  icon text default '🏆',
  sort_order int default 99
);

create table reviews (
  id uuid primary key default gen_random_uuid(),
  movie_id uuid references movies(id) on delete cascade,
  reviewer_name text default 'Anonymous',
  overall int,
  direction int,
  sound int,
  cinematography int,
  script int,
  review_text text,
  created_at timestamptz default now()
);

create table page_views (
  id uuid primary key default gen_random_uuid(),
  page text,
  date date,
  hour int
);
```

Also create a public storage bucket named `kfs-media` in your Supabase project.

### Run Locally

```bash
node server.js
# Server starts on http://localhost:3000
```

### Admin Access

Navigate to `/admin` in the browser. Default password on first run: `kfs@admin2024`. Change it immediately from the Settings section after logging in.

---

## Public Pages

### Home
Full-viewport hero with animated background, live stats counters (members, events, films, years active), about section, upcoming events strip, recent films strip, recent blog posts strip, member spotlight, and a testimonials carousel. A visitor notification popup and an event countdown popup appear automatically when active content exists in the database.

### Events
All events listed in descending date order, toggled between Upcoming and Past. Each card shows cover image, title, date, time, and location.

### Films
Responsive poster grid. Clicking a poster opens the film detail page.

### Film Detail
Full poster, trailer embed (YouTube autoplay modal, supports `youtube.com/watch?v=` and `youtu.be/` formats), Watch Now external link, complete crew credits, cast and support crew tags, star rating system with category breakdowns (Direction, Sound, Cinematography, Script), public review submission, and all submitted reviews listed below. Share button uses the Web Share API with clipboard fallback.

### Blog
Grid of published posts with cover image, title, excerpt, and date.

### Blog Detail
Full cover image, post content rendered from rich HTML, estimated reading time, and share button.

### Members
Toggles between Current and Alumni. President and Vice Presidents shown as individual photo cards. Core Members and Leads shown in a 5-column responsive photo card grid (greyscale to colour on hover). General members shown in a compact 3-column list. Domain shown for all photo-card roles when set.

### Global Search
Full-screen search overlay accessible from the nav bar. Searches across films, blogs, events, and members simultaneously, with results grouped by category.

---

## Admin Panel

Access at `/admin`. JWT session persists across refreshes.

| Section | What you can do |
|---|---|
| Blog Posts | Create, edit, delete, bulk delete posts. Rich-text editor with cover image upload. Draft/published toggle. |
| Events | Create, edit, delete events. Cover image upload, upcoming/past toggle. |
| Members | Create, edit, delete, bulk delete members. Live search by name, role, domain, or batch. Role, domain, batch year, sort order, current/alumni toggle, photo upload. |
| Films | Create, edit, delete, bulk delete films. Full crew fields, cast, trailer URL, Watch Now URL, poster upload. |
| Testimonials | Create, edit, delete testimonials. Photo upload. |
| Achievements | Create, edit, delete achievements with icon, year, and sort order. |
| Notifications | Create site-wide visitor popups with type, message, and optional CTA button. Active/inactive toggle. |
| Traffic Analytics | Views over time (7d / 30d / all), per-page leaderboard, and peak hours chart for today. |
| Review Analytics | Aggregate ratings across all films: overall average, category averages, per-film breakdown. |
| Settings | Edit hero tagline, about text, stats counters, member spotlight, social links, and contact email. Change admin password. |

### Bulk Delete
Films, Blog Posts, and Members tables each have a checkbox per row and a master checkbox in the header. Selecting any row reveals a Delete Selected bar showing the count. Deletions run in parallel.

---

## API Reference

### Public Endpoints

```
GET  /api/settings
GET  /api/blogs
GET  /api/blogs/:id
GET  /api/events
GET  /api/members
GET  /api/testimonials
GET  /api/achievements
GET  /api/movies
GET  /api/movies/:id
GET  /api/reviews/:movieId
POST /api/reviews
POST /api/track
```

### Protected Endpoints (Bearer JWT required)

```
POST   /api/admin/login
POST   /api/admin/change-password
POST   /api/admin/settings

POST   /api/admin/blogs
PUT    /api/admin/blogs/:id
DELETE /api/admin/blogs/:id

POST   /api/admin/events
PUT    /api/admin/events/:id
DELETE /api/admin/events/:id

POST   /api/admin/members
PUT    /api/admin/members/:id
DELETE /api/admin/members/:id

POST   /api/admin/movies
PUT    /api/admin/movies/:id
DELETE /api/admin/movies/:id

POST   /api/admin/testimonials
PUT    /api/admin/testimonials/:id
DELETE /api/admin/testimonials/:id

POST   /api/admin/achievements
PUT    /api/admin/achievements/:id
DELETE /api/admin/achievements/:id

GET    /api/admin/analytics/traffic?range=7d|30d|all
GET    /api/admin/analytics/reviews
```

All write endpoints for blogs, events, members, movies, and testimonials accept `multipart/form-data` to support file uploads alongside other fields.

---

## File Uploads

Images are uploaded to Supabase Storage in the `kfs-media` bucket, organised into subfolders:

```
kfs-media/
├── blogs/
├── events/
├── members/
├── movies/
└── testimonials/
```

Files are served as public URLs directly from Supabase CDN. Maximum file size is 10 MB.

---

## Routing

The site uses `history.pushState` for client-side navigation with no framework. All paths (`/events`, `/movies`, `/members`, `/blog`, `/movies/:id`, `/admin`) are handled client-side. The Express catch-all route returns `index.html` for every path so direct URL access and browser refresh work correctly.

---

## Member Roles and Domains

**Roles:** President, Vice President, Lead, Core Member, Member

**Domains:** Cinematography, Direction, Screenwriting, Sound Design, Graphic Design, Photography, Production Management, Video Editing, HR and PR, Acting, Other

---

*Built and maintained by KIIT Film Society.*

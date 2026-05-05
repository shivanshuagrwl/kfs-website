# KFS — KIIT Film Society

Official website for KIIT Film Society. A full-stack single-page web application for managing and showcasing the society's films, events, blog, and members.

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
├── README.md
└── package.json
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- A Supabase project with the tables listed below

### Installation

```bash
git clone https://github.com/ShivanshuAgarwal/kfs-website.git
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

Run the following in the Supabase SQL editor:

```sql
CREATE TABLE settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key text UNIQUE NOT NULL,
  value text
);

CREATE TABLE admins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'admin',
  created_at timestamptz DEFAULT now()
);

CREATE TABLE admin_activity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id uuid,
  admin_name text,
  action text,
  entity text,
  entity_name text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE blogs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  excerpt text,
  content text,
  cover_image text,
  published boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  description text,
  event_date date,
  event_time text,
  location text,
  cover_image text,
  is_upcoming boolean DEFAULT true
);

CREATE TABLE members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text,
  role text,
  domain text,
  batch text,
  bio text,
  photo text,
  sort_order int DEFAULT 99,
  is_past boolean DEFAULT false
);

CREATE TABLE movies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  release_year text,
  genre text,
  description text,
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

CREATE TABLE testimonials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text,
  role text,
  batch text,
  quote text,
  photo text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE achievements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  description text,
  year text,
  icon text DEFAULT '🏆',
  sort_order int DEFAULT 99
);

CREATE TABLE notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  type text,
  message text,
  btn_text text,
  btn_link text,
  active boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  movie_id uuid REFERENCES movies(id) ON DELETE CASCADE,
  reviewer_name text DEFAULT 'Anonymous',
  overall int,
  direction int,
  sound int,
  cinematography int,
  script int,
  review_text text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE page_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  page text,
  date date,
  hour int
);

CREATE TABLE chitra_vichitra (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  year text UNIQUE NOT NULL,
  cover_image text,
  sort_order int DEFAULT 99
);

CREATE TABLE chitra_vichitra_movies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cv_id uuid REFERENCES chitra_vichitra(id) ON DELETE CASCADE,
  movie_id uuid REFERENCES movies(id) ON DELETE CASCADE
);
```

Also create a public storage bucket named `kfs-media` in your Supabase project with subfolders: `blogs/`, `events/`, `members/`, `movies/`, `testimonials/`, `chitra-vichitra/`, `general/`.

### Run Locally

```bash
node server.js
```

On first start, the master admin account is created automatically. Log in at `/admin` with:

```
Username: kfsmaster
Password: KFS@master2024!
```

Change the master password immediately from Settings after first login.

---

## Admin System

The site uses a two-tier admin system.

### Master Admin

There is exactly one master admin. The master account is created automatically on first server start and cannot be deleted. The master can:

- Do everything a regular admin can
- Add new admin accounts (name, username, password)
- Remove any admin account
- View the full Activity Log showing every change made by every admin
- The master password can only be changed by the master themselves from the Settings page

### Regular Admins

Regular admins are created by the master. Each has their own username and password. They can:

- Create, edit, and delete all content (films, blogs, events, members, testimonials, achievements, notifications, settings)
- Change their own password only from the Settings page
- They cannot see the Manage Admins or Activity Log sections
- They cannot view or change anyone else's password

### Activity Log

Every create, update, and delete action across all content types is automatically recorded with the admin's name, action type, content category, item name, and exact timestamp. Only the master can view this log.

---

## Public Pages

### Home
Full-viewport hero with animated scroll-reveal text ("Lights. Camera. KFS."), pulsing glow orb effect, live stats counters (members, events, films, years active), about section with team photo, latest blog posts strip, recent films strip, achievements, upcoming events strip, member spotlight, and a testimonials carousel. A visitor notification popup and live event countdown popup appear automatically when active content exists in the database.

### Events
Toggles between Upcoming and Past tabs. Each card shows cover image, title, date, time, and location. The Past tab also surfaces the Chitra Vichitra (CV) section with edition cards and their linked films.

### Films
Responsive 4-column poster grid. Clicking a poster opens the film detail page.

### Film Detail
Full poster, trailer embed (YouTube autoplay modal, supports both `youtube.com/watch?v=` and `youtu.be/` formats), Watch Now external link, complete crew credits with clickable member links, cast and support crew tags, Mark as Watched toggle (persisted in localStorage), star rating system with category breakdowns (Direction, Sound, Cinematography, Script), public review submission, and all submitted reviews listed below. Share button uses the Web Share API with clipboard fallback.

### Blog
Grid of published posts with cover image, title, excerpt, and date. Drafts are not visible to the public.

### Blog Detail
Full cover image, post content rendered from rich HTML, estimated reading time, and share button.

### Members
Toggles between Current and Alumni. President and Vice Presidents shown as individual photo cards. Core Members and Leads shown in a responsive photo card grid (greyscale to colour on hover, domain label shown). General members shown in a compact list. Clicking any member card opens their **Member Profile** showing bio and all films they are credited in.

### Member Profile
Opened by clicking any member card anywhere on the site. Shows photo, name, role, domain, batch, bio, and a 3-column grid of every film they are linked to with their role in each film. Clicking a film opens the film detail page.

### Global Search
Full-screen glassmorphic search overlay accessible from the nav bar. Searches across films, blogs, events, and members simultaneously with results grouped by category. Member results show their film count. Searching a person's name finds all films they are credited in, even if they are not the director.

---

## Admin Panel

Access at `/admin`. JWT session persists across browser refreshes (7-day expiry, auto-refreshed on load). The logged-in admin's name and role are shown at the top of the sidebar.

| Section | Description | Access |
|---|---|---|
| Blog Posts | Create, edit, delete, bulk delete. Rich-text editor, cover image upload, draft/published toggle. | All admins |
| Events | Create, edit, delete. Cover image upload, upcoming/past toggle. | All admins |
| Members | Create, edit, delete, bulk delete. Live search by name, role, domain, or batch. Role, domain, batch, sort order, photo upload. | All admins |
| Films | Create, edit, delete, bulk delete. Full crew fields with member picker (link crew to member profiles), trailer URL, Watch Now URL, poster upload. | All admins |
| Chitra Vichitra | Create CV editions by year with cover image. Add films from the Films database to each edition. | All admins |
| Testimonials | Create, edit, delete. Photo upload. | All admins |
| Achievements | Create, edit, delete. Icon, year, description, sort order. | All admins |
| Notifications | Create site-wide visitor popups with type, message, and optional CTA button. Active/inactive toggle. | All admins |
| Traffic Analytics | Views over time (7d / 30d / all), per-page leaderboard, peak hours chart for today. | All admins |
| Review Analytics | Overall average rating, category averages, per-film breakdown sorted by rating. | All admins |
| Settings | Hero tagline, about text, stats counters, member spotlight, social links, contact email, team photo. Change own password. | All admins |
| Manage Admins | Add new admins with name, username, and password. Remove existing admins. | Master only |
| Activity Log | Full timestamped history of every create, update, and delete action by every admin. | Master only |

### Bulk Delete

Films, Blog Posts, and Members tables each have a checkbox per row and a master select-all checkbox in the header. Selecting any row reveals a Delete Selected bar showing the count. Deletions run in parallel.

---

## Member Linking

Crew fields in films support linked members using the format `Name||memberId` stored in the existing `text` columns — no schema change required.

When a member is linked to a film:
- Their name appears as a **clickable link** in the film detail page
- Their Member Profile shows all films they are credited in with their role
- Universal search finds films by searching crew names
- Member search results show their film count

### How to link in the Admin panel
Each crew field in the Films form has a **live-search member picker**. Type a name to search the members list — results show photo and role. Click a member to tag them. You can also type a free-text name and press Enter for people not in the members database. Multiple tags are supported for Actors and Support Crew fields.

---

## Member Roles and Domains

**Roles:** President, Vice President, Lead, Core Member, Member

**Domains:** Direction, Cinematography, Scriptwriting, Video Editing, Sound Design, Graphic Design, Animation, Acting, Photography, Content Creation, Social Media, HR and PR, Production Management

---

## Themes

Toggle between **dark mode** (default) and **light mode** via the ☀️ icon in the navbar. The class `body.light-mode` drives all light-theme overrides. In light mode the hero displays a pulsing black radial glow and the scroll indicator sits at the bottom-right corner.

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
GET  /api/notifications/active
GET  /api/reviews/:movieId
GET  /api/chitra-vichitra
GET  /api/chitra-vichitra/:id/movies
POST /api/reviews
POST /api/track
```

### Admin Endpoints (Bearer JWT required)

```
POST   /api/admin/login
POST   /api/admin/refresh
POST   /api/admin/change-password

GET    /api/admin/blogs
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

GET    /api/admin/notifications
POST   /api/admin/notifications
PUT    /api/admin/notifications/:id
DELETE /api/admin/notifications/:id

POST   /api/admin/settings
GET    /api/admin/analytics/traffic?range=7d|30d|all
GET    /api/admin/analytics/reviews

POST   /api/admin/chitra-vichitra
PUT    /api/admin/chitra-vichitra/:id
DELETE /api/admin/chitra-vichitra/:id
POST   /api/admin/chitra-vichitra/:id/movies
DELETE /api/admin/chitra-vichitra/movies/:cvMovieId
```

### Master-Only Endpoints (Bearer JWT, role: master required)

```
GET    /api/master/admins
POST   /api/master/admins
DELETE /api/master/admins/:id
GET    /api/master/activity
```

All write endpoints for content accept `multipart/form-data` to support file uploads alongside other fields.

---

## File Storage

Images are uploaded to Supabase Storage in the `kfs-media` bucket:

```
kfs-media/
├── blogs/
├── events/
├── members/
├── movies/
├── testimonials/
├── chitra-vichitra/
└── general/
```

Files are served as public URLs from Supabase CDN. Maximum upload size is 20 MB.

---

## Routing

The site uses `history.pushState` for client-side navigation with no framework. The Express catch-all route returns `index.html` for every path so direct URL access and browser refresh work correctly across all routes (`/events`, `/movies`, `/members`, `/blog`, `/admin`).

---

## Deployment

```bash
git add .
git commit -m "your message"
git push
```

The server reads from Supabase on every request — no restart needed for content changes made via the admin panel.

---

*Managed by KIIT Film Society.*

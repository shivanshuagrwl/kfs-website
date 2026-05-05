# KFS — KIIT Film Society Website

Official website for KIIT Film Society. A full-stack single-page web application for managing and showcasing the society's films, events, blog, and members. Built with zero frontend frameworks — pure HTML, CSS, and JavaScript on the client, with Node.js + Express on the server.

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript | No React, no Vue — single `index.html` SPA |
| Backend | Node.js + Express | All API routes in `server.js` |
| Database | Supabase (PostgreSQL) | Hosted Postgres with REST + realtime |
| File Storage | Supabase Storage | `kfs-media` bucket, CDN-served public URLs |
| Auth | JWT + bcrypt | 7-day tokens, auto-refreshed on load |

---

## Project Structure

```
kfs/
├── public/
│   └── index.html        # Entire frontend SPA (all pages, modals, JS)
├── server.js             # Express backend — all API routes + middleware
├── .env                  # Environment variables (never commit this)
├── README.md
└── package.json
```

Everything the visitor sees lives inside `public/index.html`. Every API route the frontend calls lives inside `server.js`. There are no build steps, no bundlers, and no transpilation.

---

## Getting Started

### Prerequisites

- Node.js 18+
- A Supabase project (free tier is sufficient)
- The database tables listed in the **Database Setup** section below

### Installation

```bash
git clone https://github.com/ShivanshuAgarwal/kfs-website.git
cd kfs
npm install
```

### Environment Variables

Create a `.env` file in the project root. Never commit this file.

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_service_role_key
JWT_SECRET=your_jwt_secret_min_32_chars
PORT=3000
```

| Variable | Where to find it | Notes |
|---|---|---|
| `SUPABASE_URL` | Supabase Dashboard → Project Settings → API | Looks like `https://xxxx.supabase.co` |
| `SUPABASE_KEY` | Supabase Dashboard → Project Settings → API → `service_role` key | Use the **service_role** key, not the anon key — it bypasses Row Level Security |
| `JWT_SECRET` | Choose any random 32+ character string | Used to sign and verify admin session tokens |
| `PORT` | Optional | Defaults to `3000` if not set |

### Database Setup

Run the following SQL in the **Supabase SQL Editor** (Dashboard → SQL Editor → New Query). Copy the entire block and run it once.

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
  sections text DEFAULT '[]',
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

> **If you already have the database from an earlier version** and are missing the `sections` column on `blogs`, run this migration:
> ```sql
> ALTER TABLE blogs ADD COLUMN IF NOT EXISTS sections text DEFAULT '[]';
> ```

### File Storage Setup

In the Supabase Dashboard:

1. Go to **Storage** → **New Bucket**
2. Name it `kfs-media`
3. Set it to **Public**
4. Inside the bucket, create these folders (just upload a placeholder file in each):
   - `blogs/`
   - `events/`
   - `members/`
   - `movies/`
   - `testimonials/`
   - `chitra-vichitra/`
   - `general/`

Files uploaded through the admin panel are stored here and served via Supabase's CDN as permanent public URLs.

### Run Locally

```bash
node server.js
```

The server starts on `http://localhost:3000` (or whatever `PORT` you set).

On first start, the master admin is created automatically. Log in at `/admin` with:

```
Username: kfsmaster
Password: KFS@master2024!
```

**Change the master password immediately** from the Settings section after first login.

---

## Admin System

The site has a two-tier admin system. Access the admin panel at `/admin`. The logged-in admin's name and role are shown at the top of the sidebar.

### Master Admin

There is exactly one master admin. The account is auto-created on first server start and can never be deleted. Master capabilities:

- Everything a regular admin can do
- Add and remove regular admin accounts
- View the full Activity Log (every change by every admin, timestamped)
- Change their own password (from Settings)

### Regular Admins

Created by the master. Each has their own username and password. They can:

- Create, edit, and delete all content (films, blogs, events, members, testimonials, achievements, notifications, settings)
- Change only their own password from Settings
- They cannot see Manage Admins or Activity Log
- They cannot view or modify any other admin's credentials

### Session Management

JWT tokens are stored in `localStorage`. They expire after 7 days. On every page load, the frontend attempts a silent token refresh via `/api/admin/refresh`. If the token is invalid or expired, the admin is redirected to the login screen.

### Activity Log

Every create, update, and delete action across all content types is recorded automatically. Each log entry stores: admin name, action type (created / updated / deleted), content category (blog / film / event / etc.), item name, and exact timestamp. Only the master can view this log.

---

## Public Pages

### Home (`/`)

The homepage is built in distinct full-width sections, each separated by a hairline divider.

**Hero** — Full-viewport section with animated scroll-reveal text ("Lights. Camera. KFS." by default, customisable from Settings). Words light up sequentially using a pulsing glow effect driven by `requestAnimationFrame`. The tagline supports multi-line formatting — separate lines with `|` in the Settings field. A radial gradient orb pulses behind the text. In light mode this becomes a dark radial glow. In dark mode it is a lighter atmospheric glow. A scroll indicator appears in the bottom-right corner with vertical text that reads "Scroll".

**Stats** — Four animated counters: Members, Events, Films, and Years Active. Values are set in the Settings panel. Numbers count up from zero on first scroll into view using `IntersectionObserver`.

**About** — A short paragraph from Settings (`about_text`) alongside the team photo (`team_photo` in Settings). Text can be multiline.

**Latest Posts** — Horizontal scroll carousel of blog posts, sorted by unread-first. Cards are large (`78vw` on mobile, `420–480px` on wider screens) with a `16:9` cover image, read/unread badge, title, date, and excerpt. Unread cards show the image in full colour; read cards go greyscale (reverts to colour on hover). Clicking a card opens the blog detail view and marks it as read. The carousel shows up to 6 posts.

**Films** — Horizontal scroll carousel of films in `2:3` poster ratio. Cards are `42vw` on mobile, `220–260px` on wider screens — 3–4 visible at once. Each card shows the poster, title, genre, release year, and average star rating (if reviews exist). Up to 8 films shown.

**Events** — Three upcoming event cards showing cover image, title, date, time, and location. If no upcoming events exist, this section is hidden.

**Achievements** — A 3-column Apple-style grid of achievement tiles, each with an icon, title, year, and description.

**Member Spotlight** — A single featured member card, chosen from Settings. Shows their photo, name, role, and domain.

**Testimonials** — An auto-playing carousel of testimonial cards. Each card shows the quote, name, role, and batch. Auto-advances every 5 seconds; pauses on hover.

**Popups** — Two automatic popups appear on the homepage:
- **Notification popup**: Shown if any notification is marked active in the database. Shows title, message, optional CTA button. Dismissed on close.
- **Live event countdown popup**: Shown if an upcoming event exists. Counts down to the nearest upcoming event in real time (days, hours, minutes, seconds).

### Hover Glow Effects

All interactive cards across the site have a hover glow effect:
- **Dark mode**: A soft `rgba(255,255,255,~0.07)` white glow with a thin `1px` white ring, giving cards a lifted luminous look against the dark background.
- **Light mode**: A `rgba(0,0,0,~0.13)` shadow for depth without washing out the light surface.
This applies to home carousel cards, film grid cards, blog grid cards, member cards, achievement cards, and CV year cards.

### Events (`/events`)

Two tabs: **Upcoming** and **Past**.

Each event card shows the cover image, title, formatted date, time, and location.

The Past tab also contains the **Chitra Vichitra** (CV) section — KFS's flagship annual film festival. Each CV edition is displayed as a year card with a cover image. Clicking a year card expands into a detail view showing all films screened in that edition. Clicking a film opens the film detail page.

### Films (`/movies`)

Responsive grid of film poster cards, 4 columns on desktop. Each card shows the poster in greyscale (transitions to colour on hover), title, year, and genre. If the film has reviews, a star rating badge appears in the corner. Clicking any card opens the film detail view.

### Film Detail

Opened by clicking a film card anywhere on the site (home carousel, films grid, member profile, search results, CV detail).

- **Poster** — Full-width poster image
- **Trailer** — YouTube embed in an autoplay modal. Supports both `youtube.com/watch?v=` and `youtu.be/` URL formats. Modal opens on clicking a Play button.
- **Watch Now** — External link to the full film (if a watch URL is set)
- **Crew Credits** — Full crew list: Director, Producer, DoP, Screenwriter, Video Editor, Sound Design, Management, Graphic Design. If a crew member is linked to a member profile (using the `Name||memberId` format), their name appears as a clickable link that opens their Member Profile.
- **Cast & Support Crew** — Tag pills for actors and support crew. Linked members are clickable.
- **Mark as Watched** — Toggle button. State persists in `localStorage` per browser. When marked watched, the film poster on the Films page turns greyscale.
- **Star Rating System** — Visitors can rate the film across five categories: Overall, Direction, Sound, Cinematography, and Script. Each category has an interactive 5-star picker. Ratings are averaged across all submissions and shown as a composite score. Category breakdowns appear as a bar chart.
- **Reviews** — A public review form (name optional, defaults to "Anonymous") with free text and the rating picker. Submitted reviews are listed below in reverse chronological order.
- **Share** — Uses the Web Share API on supported devices. Falls back to copying the URL to clipboard.

### Blog (`/blog`)

A responsive 3-column grid of published blog posts. Each card shows the cover image (greyscale when read, colour when unread), title, excerpt, and publication date. Draft posts are never visible to the public. Clicking a card marks it as read and opens the blog detail view.

### Blog Detail

Full-page reading view for a single post.

- **Hero image** — Full-width cover image at the top
- **Back link** — Returns to the blog list
- **Share button** — Web Share API with clipboard fallback
- **Date and title** — Publication date and full post title
- **Section nav** — If the post has extra sections (Review, Our Take, Industry Insider, Behind the Scenes, Interview, Analysis), a tab bar appears below the title. Clicking a tab switches between the Overview (main content) and the extra sections. Each section has its own rich-text content set in the admin panel.
- **Reading time** — Estimated reading time shown above the content
- **Content** — Full rich HTML content rendered as-is (supports headings, bold, italic, lists, blockquotes, links, images)
- **Recently Viewed** — Below the content, a list of up to 5 other posts the visitor has previously read (stored in `localStorage`)

### Members (`/members`)

Two tabs: **Current** and **Alumni** (`is_past = true`).

Within each tab, members are displayed in role-based groupings:

| Group | Display format |
|---|---|
| President | Large solo photo card |
| Vice Presidents | Large solo photo card |
| Leads | Photo card grid (greyscale → colour on hover, domain label shown) |
| Core Members | Photo card grid (same treatment) |
| Members with photos | Compact photo card grid |
| Members without photos | Text list with role and batch |

Clicking any member card anywhere on the site opens their **Member Profile**.

### Member Profile

A full-screen overlay (slide-in panel) showing:

- Photo, name, role, domain, batch
- Bio text
- A 3-column grid of every film they are credited in, with the specific role (e.g. Director, DoP, Actor) shown under each poster

Clicking a film from the Member Profile opens the Film Detail page. Navigating back closes the profile overlay.

### Global Search

Full-screen frosted-glass overlay triggered from the navbar search icon. Searches across films, blogs, events, and members simultaneously as you type (debounced, 300ms). Results are grouped by category. Key behaviours:

- Searching a person's name finds all films they are credited in, even if they are not the director
- Member results show their total film count
- All results are clickable and navigate directly to the relevant detail view

---

## Admin Panel

Access at `/admin`. The sidebar shows all sections the logged-in admin has access to.

### Blog Posts

- **List view** — Table with title, status (Published / Draft), date, and Edit / Delete buttons
- **Bulk delete** — Checkbox per row, select-all in header, "Delete Selected (N)" bar appears when any are checked
- **Create / Edit modal** — Fields: Title, Excerpt, Cover Image (file upload), rich-text Content editor, Status (Published / Draft), and Extra Sections
- **Rich-text editor** — Toolbar buttons for Bold, Italic, H2, H3, Bullet List, Numbered List, Blockquote, and Link
- **Extra Sections** — A dropdown lets you add named sections (Review, Our Take, Industry Insider, Behind the Scenes, Interview, Analysis). Each added section gets its own rich-text editor block. Sections are saved as a JSON array in the `sections` column. When a blog with sections is opened on the public site, a tab nav appears automatically.

### Events

- Fields: Title, Description, Date, Time, Location, Cover Image, Status (Upcoming / Past)
- Events marked as Past no longer appear in the Upcoming tab on the public Events page

### Members

- Fields: Name, Role, Domain, Batch, Bio, Photo, Sort Order, Alumni toggle (`is_past`)
- **Live search** by name, role, domain, or batch directly in the admin table
- **Sort Order** — Lower numbers appear first within each role group. Default is 99.
- **Bulk delete** — Same checkbox pattern as Blog Posts

### Films

- Fields: Title, Release Year, Genre, Description, Director, Producer, DoP, Screenwriter, Video Editor, Sound Design, Management, Graphic Design, Actors, Support Crew, Poster Image, Trailer URL, Watch Now URL
- **Member Picker** — Each crew text field has a live-search member picker. Type a name to see matching members with their photo and role. Click to tag a member (stored as `Name||memberId`). You can also type a free-text name and press Enter for people not in the members database.
- **Actors and Support Crew** support multiple tags
- **Bulk delete** — Checkbox pattern

### Chitra Vichitra

- Create a CV edition: choose a year and upload a cover image
- Add films to an edition from the existing Films database
- Remove films from an edition without deleting them from the database

### Testimonials

- Fields: Name, Role, Batch, Quote, Photo

### Achievements

- Fields: Title, Description, Year, Icon (emoji), Sort Order

### Notifications

- Fields: Title, Type, Message, Button Text (optional), Button Link (optional), Active toggle
- Only one notification should be active at a time (the system shows the first active one found)
- Active notifications appear as a popup on the homepage for all visitors

### Traffic Analytics

- Views over time (last 7 days / 30 days / all time) as a bar chart
- Per-page leaderboard sorted by total views
- Peak hours chart for today (which hours get the most traffic)
- Page views are tracked automatically via the `/api/track` endpoint, called on every page navigation

### Review Analytics

- Overall average rating across all films
- Average per category (Direction, Sound, Cinematography, Script)
- Per-film breakdown sorted by rating, with total review count

### Settings

Editable fields (saved to the `settings` table):

| Key | Description |
|---|---|
| `site_tagline` | Hero text. Use `\|` to separate lines (e.g. `Lights.\|Camera.\|KFS.`) |
| `about_text` | Text shown in the About section on the homepage |
| `stats_members` | Number shown in the Members counter |
| `stats_events` | Number shown in the Events counter |
| `stats_films` | Number shown in the Films counter |
| `stats_years` | Number shown in the Years Active counter |
| `team_photo` | URL of the team photo shown in the About section |
| `spotlight_member_id` | UUID of the member to feature in the Member Spotlight section |
| `instagram_url` | Instagram profile link (shown in footer) |
| `youtube_url` | YouTube channel link (shown in footer) |
| `contact_email` | Contact email shown in footer |

Each admin can also change their own password from Settings. The master's password can only be changed by the master.

### Manage Admins (Master only)

- Add new admins: enter name, username, and password. Username must be unique.
- Remove existing admins. The master account cannot be removed.

### Activity Log (Master only)

Paginated table of every create, update, and delete action by every admin. Each row shows: admin name, action, content category, item name, and exact timestamp. Sorted newest-first.

---

## Member Linking in Films

Crew fields in the `movies` table store text. To link a crew credit to a member profile, use this format:

```
Name||memberUUID
```

For example: `Arjun Mehta||3f8a2b1c-...`

You never need to type this manually — the **Member Picker** in the Films admin modal handles it. But knowing the format helps if you ever need to edit the database directly.

When a member is linked:
- Their name is a clickable link on the Film Detail page
- Their Member Profile lists all films they appear in with their credited role
- Global search finds those films when you search the member's name
- Member search results show their film count

---

## Member Roles and Domains

**Roles (controls display grouping on the Members page):**

`President` → `Vice President` → `Lead` → `Core Member` → `Member`

**Domains (informational tag shown on member cards):**

Direction, Cinematography, Scriptwriting, Video Editing, Sound Design, Graphic Design, Animation, Acting, Photography, Content Creation, Social Media, HR and PR, Production Management

---

## Themes

A sun/moon icon in the navbar toggles between **dark mode** (default) and **light mode**. The class `body.light-mode` is applied to `<body>` and drives all light-theme CSS overrides.

Dark mode: near-black background (`#0a0a0a`), white text, grey borders, white card glow on hover.
Light mode: off-white background (`#f0f0f0`), dark text, dark borders, dark shadow on hover. Hero uses a pulsing black radial glow.

Theme preference is stored in `localStorage` and restored on every load.

---

## Read / Watched State

Blog post read state and film watched state are both stored in `localStorage` under the key `kfs-read-state` and `kfs-watchlist` respectively. These are browser-local and not synced to any server or user account. Clearing browser data resets them.

### Blog Read State
- Unread posts show in **full colour** with a "New" badge
- Read posts show in **greyscale** with a "✓ Read" badge
- Opening a post marks it as read immediately; the home carousel card updates live without a reload
- The blog list re-sorts with unread posts first

### Film Watched State
- Marking a film as Watched makes its poster **greyscale** on the Films grid
- Marking as Unwatched restores it to **full colour**
- The toggle is on the Film Detail page

---

## Routing

The site uses `history.pushState` for client-side navigation. There is no router library. The Express catch-all route serves `index.html` for every path so that direct URL access and browser refreshes work correctly:

```
/              → Home
/events        → Events page
/movies        → Films page
/blog          → Blog page
/members       → Members page
/blog/:id      → Blog detail (opened via pushState, restored on refresh)
/admin         → Admin panel (login required)
```

On popstate (browser back/forward), the frontend reads the current URL and navigates to the appropriate page.

---

## API Reference

All endpoints return JSON. Write endpoints accept `multipart/form-data` (to support file uploads alongside text fields).

### Public Endpoints (no auth required)

```
GET  /api/settings                        → Site-wide settings object
GET  /api/blogs                           → All published blogs (array)
GET  /api/blogs/:id                       → Single blog by ID
GET  /api/events                          → All events
GET  /api/members                         → All members
GET  /api/testimonials                    → All testimonials
GET  /api/achievements                    → All achievements, sorted by sort_order
GET  /api/movies                          → All films
GET  /api/movies/:id                      → Single film by ID
GET  /api/notifications/active            → First active notification (or null)
GET  /api/reviews/:movieId                → All reviews for a film
GET  /api/reviews/all                     → All reviews (used for home rating aggregation)
GET  /api/chitra-vichitra                 → All CV editions
GET  /api/chitra-vichitra/:id/movies      → Films in a specific CV edition

POST /api/reviews                         → Submit a new review
POST /api/track                           → Track a page view { page: "/movies" }
```

### Admin Endpoints (Bearer JWT required)

All admin endpoints require an `Authorization: Bearer <token>` header.

```
POST   /api/admin/login                   → { username, password } → { token }
POST   /api/admin/refresh                 → Refresh token → { token }
POST   /api/admin/change-password         → { currentPassword, newPassword }

GET    /api/admin/blogs                   → All blogs including drafts
POST   /api/admin/blogs                   → Create blog (multipart)
PUT    /api/admin/blogs/:id               → Update blog (multipart)
DELETE /api/admin/blogs/:id               → Delete blog

POST   /api/admin/events                  → Create event (multipart)
PUT    /api/admin/events/:id              → Update event (multipart)
DELETE /api/admin/events/:id              → Delete event

POST   /api/admin/members                 → Create member (multipart)
PUT    /api/admin/members/:id             → Update member (multipart)
DELETE /api/admin/members/:id             → Delete member

POST   /api/admin/movies                  → Create film (multipart)
PUT    /api/admin/movies/:id              → Update film (multipart)
DELETE /api/admin/movies/:id              → Delete film

POST   /api/admin/testimonials            → Create testimonial (multipart)
PUT    /api/admin/testimonials/:id        → Update testimonial (multipart)
DELETE /api/admin/testimonials/:id        → Delete testimonial

POST   /api/admin/achievements            → Create achievement
PUT    /api/admin/achievements/:id        → Update achievement
DELETE /api/admin/achievements/:id        → Delete achievement

GET    /api/admin/notifications           → All notifications
POST   /api/admin/notifications           → Create notification
PUT    /api/admin/notifications/:id       → Update notification
DELETE /api/admin/notifications/:id       → Delete notification

POST   /api/admin/settings                → Upsert settings (key/value pairs)

GET    /api/admin/analytics/traffic?range=7d|30d|all  → Traffic data
GET    /api/admin/analytics/reviews                   → Review aggregates

POST   /api/admin/chitra-vichitra                     → Create CV edition (multipart)
PUT    /api/admin/chitra-vichitra/:id                 → Update CV edition (multipart)
DELETE /api/admin/chitra-vichitra/:id                 → Delete CV edition
POST   /api/admin/chitra-vichitra/:id/movies          → Add film to CV edition { movieId }
DELETE /api/admin/chitra-vichitra/movies/:cvMovieId   → Remove film from CV edition
```

### Master-Only Endpoints (Bearer JWT, role: master)

```
GET    /api/master/admins                 → List all admins
POST   /api/master/admins                 → Create admin { name, username, password }
DELETE /api/master/admins/:id             → Delete admin
GET    /api/master/activity               → Full activity log (paginated)
```

---

## File Storage

All images are uploaded to Supabase Storage in the `kfs-media` bucket. The server-side upload flow:

1. Multer receives the file as a buffer in memory (no disk write)
2. The buffer is uploaded to the appropriate Supabase Storage subfolder via the Supabase JS client
3. The public CDN URL is returned and stored in the relevant database column

```
kfs-media/
├── blogs/            → Blog cover images
├── events/           → Event cover images
├── members/          → Member profile photos
├── movies/           → Film poster images
├── testimonials/     → Testimonial author photos
├── chitra-vichitra/  → CV edition cover images
└── general/          → Misc (team photo, etc.)
```

Maximum upload size: **20 MB** per file. Images are served from Supabase's global CDN with permanent URLs — no expiry, no signed URL required (bucket is public).

---

## Deployment

The site is a straightforward Node.js app. Any platform that runs Node (Railway, Render, Fly.io, DigitalOcean App Platform, etc.) works.

### Push to Git

```bash
git add .
git commit -m "your message"
git push
```

### Environment Variables on Host

Set the same four variables from your `.env` on your hosting platform:
- `SUPABASE_URL`
- `SUPABASE_KEY`
- `JWT_SECRET`
- `PORT` (usually set automatically by the platform)

### No Restart Needed for Content Changes

All content (films, blogs, events, members, etc.) is fetched from Supabase on every request. Admins can make changes via the admin panel and they appear on the public site immediately — no server restart, no redeploy.

### Static Assets

There are no static assets beyond `public/index.html`. The server serves this single file for all non-API routes. All CSS, JavaScript, fonts referenced via CDN, and SVG icons are embedded directly in `index.html`.

---

## Frontend Architecture

`index.html` is structured as a single-page application with the following patterns:

### Pages

Each page is a `<div class="page" id="page-X">` element. Only one page has the `active` class at a time. The `navigate(pageName)` function switches pages by toggling this class and updates the URL via `history.pushState`.

### State

Global state is minimal:
- `adminToken` — JWT for the current admin session
- `currentAdminRole` — `"master"` or `"admin"`
- `allEvents` — Cached events list for filtering
- `window._allBlogs` — Cached blogs for recently-viewed lookups
- `window._allMoviesCache` — Cached films for search
- `window._movieRatings` — Pre-computed rating averages keyed by film ID
- `window._blogSections` — Sections array for the currently-open blog modal

### API Calls

All public API calls go through `apiFetch(path, method, body)` — a thin wrapper around `fetch` that handles JSON parsing and basic error logging. Admin calls use raw `fetch` with `Authorization` headers and `FormData` bodies.

### Read / History State

Blog read state: stored under `kfs-read-${id}` keys in `localStorage`. Functions: `markBlogRead(id)`, `getBlogReadState()`, `getBlogHistory()`.

Film watched state: stored under `kfs-watchlist` as a JSON object in `localStorage`. Functions: `toggleWatched(id)`, `isWatched(id)`.

### Scroll Progress

A thin progress bar at the top of the screen tracks reading position on Blog Detail and Film Detail pages. It appears only on those two views and hides on navigation.

### Recently Viewed

After opening a blog post, the post is prepended to a history array stored in `localStorage` under `kfs-blog-history`. The five most recent posts (excluding the current one) are shown at the bottom of every blog detail view.

---

*Maintained by KIIT Film Society.*

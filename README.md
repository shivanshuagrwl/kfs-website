# KFS — KIIT Film Society Website

Official website for KIIT Film Society. A full-stack single-page web application for managing and showcasing the society's films, events, blog, members, and more. Built with zero frontend frameworks — pure HTML, CSS, and JavaScript on the client, with Node.js + Express on the server.

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript | No React, no Vue — single `index.html` SPA |
| Backend | Node.js + Express | All API routes in `server.js` |
| Database | Supabase (PostgreSQL) | Hosted Postgres with REST client |
| File Storage | Cloudinary | `kfs-media/` folder tree, CDN-served public URLs |
| Image Processing | sharp | Auto-compress + convert to WebP before upload |
| Auth | JWT + bcrypt | 7-day tokens, auto-refreshed on load |
| OG Images | @resvg/resvg-js | Server-side SVG→PNG for social share previews |
| Email | Brevo HTTP API | Confirmation emails + broadcast campaigns |
| Security | helmet, express-rate-limit | CSP disabled; custom rate limiters per route |

---

## Project Structure

```
kfs/
├── public/
│   ├── index.html        # Entire frontend SPA (all pages, modals, JS, CSS)
│   ├── privacy.html      # Privacy policy static page
│   └── terms.html        # Terms of service static page
├── server.js             # Express backend — all API routes + middleware
├── .memcache.json        # Auto-generated server-side cache (do not edit)
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
- A Cloudinary account (free tier is sufficient)
- A Brevo account (optional — only needed for confirmation emails and broadcast campaigns)
- The database tables listed in the **Database Setup** section below

### Installation

```bash
git clone <your-repo-url>
cd kfs
npm install
```

### Environment Variables

Create a `.env` file in the project root. Never commit this file.

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_service_role_key
JWT_SECRET=your_jwt_secret_min_32_chars
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
MASTER_DEFAULT_PW=your_initial_master_password
BASE_URL=https://yourdomain.com
PORT=3000
```

| Variable | Where to find it | Notes |
|---|---|---|
| `SUPABASE_URL` | Supabase Dashboard → Project Settings → API | Looks like `https://xxxx.supabase.co` |
| `SUPABASE_KEY` | Supabase Dashboard → Project Settings → API → `service_role` key | Use **service_role**, not anon — it bypasses Row Level Security |
| `JWT_SECRET` | Generate any random 32+ character string | Signs and verifies all admin session tokens |
| `CLOUDINARY_CLOUD_NAME` | Cloudinary Dashboard → Settings → Account | Your cloud name |
| `CLOUDINARY_API_KEY` | Cloudinary Dashboard → Settings → API Keys | |
| `CLOUDINARY_API_SECRET` | Cloudinary Dashboard → Settings → API Keys | Keep this secret — never expose client-side |
| `MASTER_DEFAULT_PW` | Choose a strong password | Used once to create the master admin on first boot. Change it from the admin panel immediately after. |
| `BASE_URL` | Your production domain | Used in open-tracking pixel URLs inside broadcast emails. Defaults to `https://kiitfilmsociety.in` if not set. |
| `PORT` | Optional | Defaults to `3000` |

### Database Setup

Run the following SQL in the **Supabase SQL Editor** (Dashboard → SQL Editor → New Query). Copy the entire block and run it once.

```sql
-- Core content
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
  permissions text DEFAULT '[]',
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
  author text,
  excerpt text,
  content text,
  sections text DEFAULT '[]',
  cover_image text,
  published boolean DEFAULT false,
  view_count int DEFAULT 0,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text,
  description text,
  event_date date,
  event_time text,
  location text,
  cover_image text,
  is_upcoming boolean DEFAULT true,
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text,
  role text,
  domain text,
  batch text,
  bio text,
  photo text,
  special_tag text,
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
  watch_url text,
  spotify_url text,
  apple_music_url text,
  runtime int,
  language text,
  updated_at timestamptz DEFAULT now()
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
  image text,
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

-- Event registration forms
CREATE TABLE event_forms (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES events(id) ON DELETE CASCADE,
  title text,
  description text,
  questions text DEFAULT '[]',
  is_open boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE form_responses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES events(id) ON DELETE CASCADE,
  form_id uuid REFERENCES event_forms(id) ON DELETE CASCADE,
  answers text DEFAULT '{}',
  submitted_at timestamptz DEFAULT now()
);

-- Film comments
CREATE TABLE film_comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  movie_id uuid NOT NULL REFERENCES movies(id) ON DELETE CASCADE,
  author_name text NOT NULL,
  body text NOT NULL,
  is_spoiler boolean NOT NULL DEFAULT false,
  is_pinned boolean NOT NULL DEFAULT false,
  is_kfs_reply boolean NOT NULL DEFAULT false,
  parent_id uuid REFERENCES film_comments(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON film_comments(movie_id, created_at);

-- Collaborate / open calls
CREATE TABLE collaborate_posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  role text NOT NULL,
  skills text,
  timeline text,
  description text NOT NULL,
  contact_name text,
  contact_email text,
  contact_phone text,
  is_kfs_member boolean DEFAULT true,
  domain text,
  fulfillment_date date,
  edit_token text UNIQUE NOT NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- Email broadcasts
CREATE TABLE broadcasts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject text NOT NULL,
  body_html text NOT NULL,
  body_text text NOT NULL,
  audience_type text NOT NULL,
  event_id uuid REFERENCES events(id) ON DELETE SET NULL,
  sent_by text NOT NULL,
  sent_at timestamptz NOT NULL DEFAULT now(),
  recipient_count int NOT NULL DEFAULT 0
);

CREATE TABLE broadcast_opens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  broadcast_id uuid NOT NULL REFERENCES broadcasts(id) ON DELETE CASCADE,
  recipient_hash text NOT NULL,
  opened_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(broadcast_id, recipient_hash)
);
CREATE INDEX ON broadcast_opens(broadcast_id);

-- Event themes
CREATE TABLE event_themes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  is_active boolean DEFAULT false,
  active_from timestamptz,
  active_until timestamptz,
  accent_color text,
  bg_color text,
  card_color text,
  border_color text,
  text_color text,
  grey_color text,
  font_family text,
  hero_title text,
  hero_tagline text,
  banner_message text,
  banner_bg text,
  banner_text_color text,
  logo_url text,
  created_at timestamptz DEFAULT now()
);
```

#### Supabase RPC for atomic blog view increments

Run this in the SQL Editor to avoid race conditions on the `view_count` column:

```sql
CREATE OR REPLACE FUNCTION increment_blog_view(blog_id uuid)
RETURNS void AS $$
  UPDATE blogs SET view_count = COALESCE(view_count, 0) + 1 WHERE id = blog_id;
$$ LANGUAGE sql;
```

#### Page view trimming

The server automatically trims `page_views` rows older than 90 days every 24 hours. No manual cleanup needed.

### Cloudinary Setup

1. Log in to [Cloudinary](https://cloudinary.com)
2. From the Dashboard, copy your **Cloud Name**, **API Key**, and **API Secret** into `.env`
3. No bucket or folder pre-creation needed — the server creates paths on first upload

Images are uploaded to `kfs-media/<folder>/` (e.g. `kfs-media/movies/`, `kfs-media/blogs/`). All uploads are automatically:
- Resized to a maximum of **1800px** on the longest edge (no upscaling)
- Converted to **WebP** at quality **82** (visually lossless for photos)
- Compressed before upload (sharp processes the buffer before it leaves the server)

SVG and GIF files skip compression and are uploaded as-is.

### Run Locally

```bash
node server.js
```

The server starts on `http://localhost:3000` (or whatever `PORT` you set).

On first start, the master admin is created automatically using the `MASTER_DEFAULT_PW` env var. Log in at `/admin` with:

```
Username: kfsmaster
Password: <your MASTER_DEFAULT_PW value>
```

**Change the master password immediately** from the Settings section after first login. If `MASTER_DEFAULT_PW` is not set at startup, the server will log a fatal warning and skip creating the master account.

---

## Admin System

The site has a two-tier admin system. Access the admin panel at `/admin`.

### Master Admin

There is exactly one master admin (`role: "master"`). The account is auto-created on first server start and can never be deleted. Master capabilities:

- Everything a regular admin can do, across all sections
- Create and delete regular admin accounts
- Grant or restrict section permissions for each admin
- View the full Activity Log (every change by every admin, timestamped)

### Regular Admins

Created by the master. Each has their own username and password (minimum 8 characters). On creation, the master assigns section-level permissions. An admin with no permissions set has full access (legacy behaviour). Available permission sections:

`blogs`, `events`, `members`, `movies`, `chitra-vichitra`, `testimonials`, `achievements`, `notifications`, `analytics`, `review-analytics`, `settings`, `collaborate`, `wrapped`

### Session Management

JWT tokens (`HS256`, 7-day expiry) are stored in `localStorage`. On every page load, the frontend attempts a silent token refresh via `/api/admin/refresh`. If the token is invalid or expired, the admin is redirected to the login screen.

### Login Security

- **IP-based rate limit**: 10 attempts per 15-minute window per IP (via `express-rate-limit`)
- **Account lockout**: 5 consecutive failed attempts for a username locks that account for 15 minutes. Implemented in-memory — no schema change needed. Resets automatically on lock expiry or successful login.

### Activity Log

Every create, update, and delete action across all content types is recorded in `admin_activity`. Each entry stores: admin ID, admin name, action type, content category, item name, and timestamp. Only the master can view the log (from the Manage Admins section).

---

## Public Pages

### Home (`/`)

The homepage is built in distinct full-width sections separated by hairline dividers.

**Hero** — Full-viewport section with animated scroll-reveal text (default "Lights. Camera. KFS.", customisable from Settings). Words light up sequentially with a pulsing glow effect. Separate lines with `|` in the `site_tagline` setting. A radial gradient orb pulses behind the text. A scroll indicator appears bottom-right.

**Stats** — Four animated counters: Members, Events, Films, Years Active. Count up from zero on first scroll into view (`IntersectionObserver`). Values editable from Settings.

**About** — Short paragraph (`about_text` setting) alongside the team photo (`team_photo` setting).

**Latest Posts** — Horizontal scroll carousel of up to 6 blog posts, sorted unread-first. Cards show cover image, title, date, excerpt, and a read/unread badge. Unread cards show in full colour; read cards are greyscale (colour on hover).

**Films** — Horizontal scroll carousel of up to 8 film posters. Each card shows poster, title, genre, year, and average star rating if reviews exist.

**Events** — Up to 3 upcoming event cards. Section hidden if no upcoming events exist.

**Achievements** — 3-column grid of achievement tiles with icon, title, year, and description.

**Member Spotlight** — A single featured member card (ID set in Settings).

**Testimonials** — Auto-playing carousel (5s interval, pauses on hover).

**Popups** — Two automatic homepage popups:
- **Notification popup**: Shown if any notification is marked active. Dismissed on close.
- **Live event countdown**: Shown if an upcoming event exists. Real-time countdown in days/hours/minutes/seconds.

### Events (`/events`)

Two tabs: **Upcoming** and **Past**.

Each event card shows cover image, title, formatted date, time, and location. Upcoming events with a registration form show a **Register** button that opens the inline form modal.

The Past tab contains the **Chitra Vichitra** section — KFS's flagship annual film festival. Each CV edition is a year card with a cover image. Clicking a year expands to show all films screened in that edition. Clicking a film opens the Film Detail page.

### Event Registration Forms

Public users can register for events that have an open form. The form is built from a schema defined in the admin panel and supports the following question types: `text`, `textarea`, `email`, `phone`, `number`, `date`, `radio`, `checkbox`, `select`, `image`. Required fields are enforced both client- and server-side.

**Duplicate prevention**: If a form has an `email` or `phone` type question, the server checks all existing responses before inserting — a duplicate email or phone returns a `409` with a human-readable error.

**Confirmation email**: After successful submission, the server looks for an email address in the answers (first by question type, then by label, then by scanning values) and sends a confirmation email via Brevo. Non-blocking — a failed email never fails the form submission.

**Rate limit**: 5 submissions per IP per 15 minutes (`strictWriteLimit`).

### Films (`/films`)

Responsive grid of film poster cards. Each card shows the poster (greyscale → colour on hover), title, year, genre, and average star rating badge if reviews exist. Clicking a card opens the Film Detail view.

### Film Detail

- **Poster** — Full-width poster image
- **Trailer** — YouTube embed modal. Supports `youtube.com/watch?v=` and `youtu.be/` URLs.
- **Watch Now** — External link. Only rendered if the URL starts with `https://` (XSS protection).
- **Soundtrack** — Spotify and Apple Music links if set.
- **Runtime and Language** — Shown as metadata pills if set.
- **Crew Credits** — Full crew list. Linked member names are clickable (opens Member Profile).
- **Cast & Support Crew** — Tag pills. Linked members are clickable.
- **Film Recommendations** — Up to 6 related films scored by genre overlap (2 pts/match) and same director (3 pts). Shown at the bottom of the detail view.
- **Mark as Watched** — Toggle. State persists in `localStorage`.
- **Star Rating System** — 5 categories: Overall, Direction, Sound, Cinematography, Script. Averaged across all submissions. Category breakdown shown as a bar chart.
- **Comments** — Public threaded comment section. Name required (max 60 chars), body max 2000 chars, spoiler toggle. KFS Team replies are pinned with a badge. Rate limited at 5 posts per IP per 15 minutes.
- **Share** — Web Share API with clipboard fallback.

### Blog (`/blog`)

3-column responsive grid of published posts. Cards are greyscale when read, colour when unread. Clicking marks as read and opens Blog Detail.

### Blog Detail

- Hero cover image, back link, share button, publication date
- **Section nav** — If the post has extra sections (Review, Our Take, Industry Insider, Behind the Scenes, Interview, Analysis), a tab bar appears. Each tab has its own rich-text content.
- Estimated reading time
- Full HTML content (supports headings, bold, italic, lists, blockquotes, links, images)
- **Recently Viewed** — Up to 5 previously-read posts shown below the content

### Members (`/members`)

Two tabs: **Current** and **Alumni**.

Members are displayed in role-based groupings:

| Group | Display format |
|---|---|
| President | Large solo photo card |
| Vice Presidents | Large solo photo card |
| Leads | Photo card grid (greyscale → colour on hover, domain label) |
| Core Members | Photo card grid |
| Members with photos | Compact photo card grid |
| Members without photos | Text list with role and batch |

### Member Profile

Full-screen overlay showing photo, name, role, domain, batch, bio, and a grid of every film they are credited in (with their specific role shown under each poster).

### Collaborate (`/collaborate`)

A public board for KFS members to post open collaboration calls (looking for actors, editors, crew, etc.).

- **Post a call**: KIIT email required (`@kiit.ac.in`, `@ksom.ac.in`, `@kiitbiotech.ac.in`). A unique `edit_token` is returned on creation — this is the only way to edit or delete the post later, so the user is told to save it.
- **Edit / Delete**: Token-authenticated. No login required — the token is the credential.
- **Auto-expiry**: Posts are deleted server-side when their `fulfillment_date` passes. Cleanup runs on every `GET /api/collaborate` request and on a 6-hour interval.
- **Rate limited**: 5 new posts per IP per 15 minutes.

### Global Search

Full-screen overlay (navbar search icon). Searches films, blogs, events, and members simultaneously as you type (debounced, 300ms). Results are grouped by category. Searching a name finds all films that person is credited in, even if not the director.

### KFS Wrapped

An interactive year-in-review experience at `/wrapped`. Animated card sequence showing stats: total films, blogs, events, reviews, top genre, top-rated film, and more. Configurable from the admin panel (year, taglines, highlight cards with custom images). Works standalone — no login required.

---

## Social Sharing & OG Images

### Dynamic OG Meta Tags

Server-rendered OG tags are injected into `index.html` for three URL patterns:

| Route | Data source | OG type |
|---|---|---|
| `/blog/:slug` | `blogs` table | `article` |
| `/films/:slug` | `movies` table | `video.movie` |
| `/events/:slug` | `events` table | `article` |

Slugs are `{kebab-title}-{uuid}` (e.g. `the-last-frame-3f8a2b1c`). The server extracts the ID from the trailing UUID or number, looks up the record, and injects appropriate `og:title`, `og:description`, `og:image`, `og:url`, `twitter:card`, and JSON-LD structured data into the HTML before serving. Social crawlers get full previews; regular visitors get the standard SPA.

### OG Image Endpoints

If a record has a cover image, the OG image endpoint redirects directly to it (fast, zero CPU, cached 24h). If no cover image exists, a server-generated SVG card is rendered to PNG via `@resvg/resvg-js` and returned.

```
GET /og/event/:id   → Event cover image or generated card (1200×630 PNG)
GET /og/film/:id    → Film poster or generated card
GET /og/blog/:id    → Blog cover or generated card
```

Generated cards include: KFS wordmark, content badge pill, title (word-wrapped), and metadata lines (date, director, author, etc.).

---

## Email System

All email is sent via the [Brevo](https://brevo.com) HTTP API. The API key is stored in the `settings` table (key: `brevo_api_key`) and editable from the admin Settings panel — no server restart needed to update it.

### Confirmation Emails

Sent automatically after a successful event form submission. Template is customisable from Settings (`email_confirmation_body`). Supports `{{name}}`, `{{event}}`, `{{date_line}}`, and `{{venue_line}}` placeholders. Sender name customisable via `smtp_from_name` setting.

### Broadcast Campaigns

Admins can send a one-time email blast to all registrants or to registrants of a specific event.

- **Audience**: `all_registrants` or a specific event. The server scans `form_responses` to collect unique email addresses.
- **Sending**: Batched in groups of 50 with a 300ms delay between batches to respect Brevo rate limits.
- **Open tracking**: A 1×1 GIF pixel (`/api/track-open/:broadcastId/:recipientHash`) is embedded in each email. The hash is `sha256(email)` — no PII stored. Unique constraint on `(broadcast_id, recipient_hash)` prevents duplicate open counts.
- **History**: All broadcasts are stored in the `broadcasts` table with recipient count and open-rate stats viewable from the admin panel.

---

## Event Themes

The admin can create named visual themes that override the site's default CSS variables globally. Useful for seasonal events (e.g. a film festival week with a custom colour palette and banner).

Configurable per theme:
- CSS variable overrides: `accent_color`, `bg_color`, `card_color`, `border_color`, `text_color`, `grey_color`, `font_family`
- Hero text: `hero_title`, `hero_tagline`
- Announcement banner: `banner_message`, `banner_bg`, `banner_text_color`
- Logo URL (replaces the default KFS wordmark)
- Schedule: `active_from`, `active_until` (ISO timestamps)

Only one theme can be active at a time. Activating a theme via the API automatically deactivates all others. The `GET /api/theme` endpoint returns the active theme (or `null`) and is polled on page load.

---

## Admin Panel Sections

### Blog Posts

- **List**: Table with title, author, status, date, view count, Edit / Delete
- **Bulk delete**: Checkbox per row, select-all header
- **Create / Edit**: Title, Author, Excerpt, Cover Image, rich-text Content editor, Published toggle, Extra Sections
- **Rich-text editor**: Bold, Italic, H2, H3, Bullet list, Numbered list, Blockquote, Link
- **Extra Sections**: Add named sections (Review, Our Take, Industry Insider, etc.), each with its own rich-text editor. Saved as JSON in the `sections` column.
- **Blog Analytics**: Total views, published/draft counts, top post, per-post view leaderboard

### Events

- Fields: Title, Description, Date, Time, Location, Cover Image, Status (Upcoming / Past)
- **Registration Form Builder**: Visual drag-and-drop form builder. Supported question types: Short Text, Long Text, Email, Phone, Number, Date, Single Choice (radio), Multiple Choice (checkbox), Dropdown, Image Upload. Questions can be marked required or optional. Form can be toggled open/closed without deleting it.
- **Responses**: View all submissions in a table. Export to XLSX (client-side conversion). Delete all responses while keeping the form schema. Duplicate email/phone detection shown in the response view.

### Members

- Fields: Name, Role, Domain, Batch, Bio, Photo, Special Tag, Sort Order, Alumni toggle
- Live search by name, role, domain, or batch
- Sort Order: lower numbers appear first within role groups (default 99)
- Bulk delete

### Films

- Fields: Title, Year, Genre (multi-select), Description, Director, Producer, DoP, Screenwriter, Video Editor, Sound Design, Management, Graphic Design, Actors, Support Crew, Poster, Trailer URL, Watch Now URL, Spotify URL, Apple Music URL, Runtime, Language
- **Member Picker**: Each crew field has a live-search picker that tags a member as `Name||memberId`. Free-text names (not in the members DB) can also be entered.
- **Auto-fetch Runtime**: Pasting a YouTube URL into Watch Now or Trailer URL auto-fetches the video duration from the YouTube page (no API key needed) and fills the Runtime field.
- **Comments Panel**: View, pin/unpin, delete comments and post KFS Team replies from within the film edit modal.
- Bulk delete

### Chitra Vichitra

- Create a CV edition: year + cover image
- Add films from the existing Films database
- Remove films from an edition without deleting them from the database

### Testimonials, Achievements, Notifications

Standard CRUD. See field details in the **Database Setup** section above.

### Traffic Analytics

- Views over time (7d / 30d / all time) as a bar chart
- Per-page leaderboard by total views
- Peak-hour chart for today
- All-time total (counted via `COUNT` query — not limited by row fetch cap)
- Rate limited: 30 page-view inserts per IP per 15 minutes. Bot UAs (googlebot, curl, python-requests, etc.) are silently dropped.

### Review Analytics

- Overall average rating across all films
- Average per category (Direction, Sound, Cinematography, Script)
- Per-film breakdown sorted by rating, with review count

### Collaborate (Admin)

- View all open collaboration posts
- Delete any post as a moderator action

### Broadcasts

- Compose and send an email campaign (subject, rich HTML body, audience selector)
- Preview recipient count before sending
- View send history with open rates

### KFS Wrapped (Admin)

- Set the year, custom taglines, and individual highlight cards (each with a title, stat, description, and optional uploaded image)
- Config saved to the `settings` table as JSON under key `wrapped_config`

### Settings

Editable key/value pairs saved to the `settings` table:

| Key | Description |
|---|---|
| `site_tagline` | Hero text. Use `\|` to separate lines |
| `about_text` | Text in the About section on the homepage |
| `stats_members` | Members counter value |
| `stats_events` | Events counter value |
| `stats_films` | Films counter value |
| `stats_years` | Years Active counter value |
| `team_photo` | Team photo URL (upload from Settings) |
| `spotlight_member_id` | UUID of the member to feature in Member Spotlight |
| `instagram` | Instagram profile link (footer) |
| `youtube` | YouTube channel link (footer) |
| `email` | Contact email (footer) |
| `brevo_api_key` | Brevo API key for sending emails |
| `smtp_from_name` | Sender name shown in email From field |
| `email_confirmation_body` | Custom template for registration confirmation emails |
| `custom_search_eggs` | JSON array of custom search easter egg configs |
| `easter_egg_img` | Image shown in the search easter egg popup |
| `wrapped_config` | JSON config for KFS Wrapped |

### Manage Admins (Master only)

- Create admin: name, username, password (min 8 chars), section permissions
- Update permissions for existing admins
- Delete admins (master account cannot be deleted)
- View the full activity log

---

## Security

### Rate Limiting

| Endpoint | Limit | Window |
|---|---|---|
| `POST /api/admin/login` | 10 req / IP | 15 min |
| `POST /api/reviews` | 5 req / IP | 15 min |
| `POST /api/films/:id/comments` | 5 req / IP | 15 min |
| `POST /api/collaborate` | 5 req / IP | 15 min |
| `POST /api/events/:id/form/submit` | 5 req / IP | 15 min |
| `POST /api/track` | 30 req / IP | 15 min |
| All `/api/*` routes | 100 req / IP | 15 min |

### Login Lockout

After 5 consecutive failed login attempts for a username, the account is locked for 15 minutes. State is in-memory (per server process). Lock is lifted automatically on expiry, or immediately after a successful login.

### JWT

All JWTs are signed and verified with `{ algorithms: ["HS256"] }` — the `alg: "none"` bypass is closed.

### File Uploads

Multer enforces an allowlist of MIME types: `image/jpeg`, `image/png`, `image/webp`, `image/gif`, `image/svg+xml`. Any other MIME type is rejected with a `400` before the file reaches Cloudinary. Maximum file size: 20 MB.

### URL Injection

`watch_url` and `trailer_url` are validated server-side on save — only `https://` URLs are accepted. On the client, `watch_url` is also checked before being injected into an `<a href>` tag, preventing stored XSS via `javascript:` URIs.

### Headers

`helmet` is applied to all responses (CSP disabled to avoid conflicts with the inline SPA). CORS is open.

---

## File Storage (Cloudinary)

All images are uploaded to Cloudinary inside the `kfs-media/` folder. The server-side upload flow:

1. Multer receives the file as a buffer (no disk write)
2. `compressImage()` (sharp) resizes to ≤1800px and converts to WebP at quality 82
3. Buffer is streamed to Cloudinary via `upload_stream`
4. The `secure_url` is stored in the relevant database column

```
kfs-media/
├── blogs/                  → Blog cover images
├── events/                 → Event cover images
├── members/                → Member profile photos
├── movies/                 → Film poster images
├── testimonials/           → Testimonial photos
├── chitra-vichitra/        → CV edition cover images
├── form-responses/:eventId → Images uploaded via event registration forms
├── wrapped/                → KFS Wrapped highlight card images
└── general/                → Misc (team photo, easter egg images, custom egg images)
```

---

## Server-Side Caching

The server keeps a `Map`-based in-memory cache (`_memStore`) to reduce Supabase query volume. Cache entries have a TTL in seconds.

```javascript
await memCache('key', ttlSeconds, () => supabase.from(...).select(...))
```

Cache is persisted to `.memcache.json` on disk (debounced write every 2 seconds) and restored on server restart. Sensitive keys (`settings`, `settings:email`) are excluded from disk writes.

### TTLs

| Cache key | TTL |
|---|---|
| `events:list` | 120s |
| `blogs:list` | 120s |
| `blogs:<id>` | 300s |
| `movies:list` | 300s |
| `movies:<id>` | 300s |
| `members:list` | 600s |
| `testimonials:list` | 600s |
| `achievements:list` | 600s |
| `notifications:active` | 60s |
| `settings` | 300s |
| `theme:active` | 60s |
| `cv:list` | 600s |

All write endpoints call `memInvalidate(key)` immediately after a successful DB mutation, so changes appear on the public site without waiting for TTL expiry. Prefix invalidation is supported: `memInvalidate('movies:genre:')` clears all genre-filtered caches at once.

---

## Routing

The site uses `history.pushState` for client-side navigation. Express serves `index.html` as a catch-all for all non-API routes so direct URL access and refreshes work correctly.

```
/                   → Home
/events             → Events page
/films              → Films page
/blog               → Blog page
/members            → Members page
/collaborate        → Collaborate page
/wrapped            → KFS Wrapped
/blog/:slug         → Blog detail (OG tags injected server-side)
/films/:slug        → Film detail (OG tags injected server-side)
/events/:slug       → Event detail (OG tags injected server-side)
/admin              → Admin panel (login required)
/privacy            → Privacy policy
/terms              → Terms of service
/robots.txt         → Disallows /api/ and /admin
/sitemap.xml        → Auto-generated XML sitemap (films, blogs, events)
/api/health         → DB connectivity check { status, latencyMs }
```

---

## API Reference

All endpoints return JSON. Write endpoints accept `multipart/form-data` (to support file uploads alongside text fields) unless noted otherwise.

### Public Endpoints (no auth required)

```
GET  /api/settings                          → Site-wide settings object
GET  /api/settings/custom-eggs              → Custom search easter egg configs

GET  /api/blogs                             → All published blogs
GET  /api/blogs/:id                         → Single blog by ID (increments view_count)

GET  /api/events                            → All events
GET  /api/events/:id/form                   → Registration form schema for an event

POST /api/events/:id/form/submit            → Submit a registration response (multipart, rate limited)

GET  /api/members                           → All members
GET  /api/testimonials                      → All testimonials
GET  /api/achievements                      → All achievements

GET  /api/movies                            → All films (?genre=X for filter)
GET  /api/movies/:id                        → Single film by ID
GET  /api/yt-duration?v=<videoId>           → Fetch YouTube video duration (no API key)
GET  /api/recommendations/:movieId          → Up to 6 related films by genre/director score

GET  /api/reviews/all                       → All reviews (movie_id + overall only)
GET  /api/reviews/:movieId                  → All reviews for a film
POST /api/reviews                           → Submit a review (rate limited)

GET  /api/films/:movieId/comments           → All comments for a film (pinned first)
POST /api/films/:movieId/comments           → Post a public comment (rate limited)

GET  /api/notifications/active              → First active notification (or null)

GET  /api/chitra-vichitra                   → All CV editions (with movie counts)
GET  /api/chitra-vichitra/:id/movies        → Films in a CV edition

GET  /api/collaborate                       → All active (non-expired) collaborate posts
POST /api/collaborate                       → Create a collaborate post (KIIT email required, rate limited)
GET  /api/collaborate/edit/:token           → Fetch a post by edit token
PUT  /api/collaborate/:token                → Update a post by edit token
DELETE /api/collaborate/:token              → Delete a post by edit token

GET  /api/wrapped/config                    → KFS Wrapped config object
GET  /api/wrapped/stats                     → Aggregate stats for Wrapped

GET  /api/theme                             → Currently active event theme (or null)

POST /api/track                             → Track a page view { page, hour } (rate limited, bot-filtered)
GET  /api/track-open/:broadcastId/:hash     → 1×1 GIF open-tracking pixel for broadcast emails

GET  /api/health                            → Health check { status, db, latencyMs }
```

### Admin Endpoints (Bearer JWT required)

```
POST   /api/admin/login                         → { username, password } → { token, role, permissions }
POST   /api/admin/refresh                       → Refresh token (re-reads current permissions from DB)
POST   /api/admin/change-password               → { newPassword } (min 8 chars)

GET    /api/admin/blogs                         → All blogs including drafts
GET    /api/admin/blogs/analytics               → Blog view stats
POST   /api/admin/blogs                         → Create blog (multipart)
PUT    /api/admin/blogs/:id                     → Update blog (multipart)
DELETE /api/admin/blogs/:id                     → Delete blog

POST   /api/admin/events                        → Create event (multipart)
PUT    /api/admin/events/:id                    → Update event (multipart)
DELETE /api/admin/events/:id                    → Delete event
POST   /api/admin/events/:id/form               → Create or update registration form (JSON)
GET    /api/admin/events/:id/form/responses     → All responses for an event
GET    /api/admin/events/:id/form/export        → All responses + form schema for XLSX export
DELETE /api/admin/events/:id/form/responses     → Delete all responses (keeps form schema)
DELETE /api/admin/events/:id/form               → Delete form + all responses

POST   /api/admin/members                       → Create member (multipart)
PUT    /api/admin/members/:id                   → Update member (multipart)
DELETE /api/admin/members/:id                   → Delete member

POST   /api/admin/movies                        → Create film (multipart)
PUT    /api/admin/movies/:id                    → Update film (multipart)
DELETE /api/admin/movies/:id                    → Delete film
GET    /api/admin/films/:movieId/comments       → All comments for a film
DELETE /api/admin/comments/:id                  → Delete a comment
PATCH  /api/admin/comments/:id/pin              → Pin or unpin a comment { is_pinned }
GET    /api/admin/comments                      → All comments across all films (moderation view)
POST   /api/admin/films/:movieId/comments/reply → Post a KFS Team reply

POST   /api/admin/testimonials                  → Create testimonial (multipart)
PUT    /api/admin/testimonials/:id              → Update testimonial (multipart)
DELETE /api/admin/testimonials/:id              → Delete testimonial

POST   /api/admin/achievements                  → Create achievement (multipart)
PUT    /api/admin/achievements/:id              → Update achievement (multipart)
DELETE /api/admin/achievements/:id              → Delete achievement

GET    /api/admin/notifications                 → All notifications
POST   /api/admin/notifications                 → Create notification
PUT    /api/admin/notifications/:id             → Update notification
DELETE /api/admin/notifications/:id             → Delete notification

POST   /api/admin/chitra-vichitra               → Create CV edition (multipart)
PUT    /api/admin/chitra-vichitra/:id           → Update CV edition (multipart)
DELETE /api/admin/chitra-vichitra/:id           → Delete CV edition
POST   /api/admin/chitra-vichitra/:id/movies    → Add film to CV edition { movie_id }
DELETE /api/admin/chitra-vichitra/movies/:cvMovieId → Remove film from CV edition

POST   /api/admin/settings                      → Upsert settings (multipart, supports file fields)
POST   /api/admin/settings/custom-egg-upload    → Upload a custom easter egg image
POST   /api/admin/settings/custom-eggs          → Save custom easter egg configs { eggs: [] }

GET    /api/admin/analytics/traffic?range=7d|30d|all → Traffic data
GET    /api/admin/analytics/reviews                  → Review aggregates

DELETE /api/admin/collaborate/:id               → Delete a collaborate post (admin override)

POST   /api/admin/email/test                    → Send a test confirmation email { to }
POST   /api/admin/broadcast/preview             → Count recipients { audience_type, event_id }
POST   /api/admin/broadcast/send                → Send a broadcast campaign
GET    /api/admin/broadcasts                    → Broadcast history
GET    /api/admin/broadcasts/:id/stats          → Open-rate stats for a broadcast
GET    /api/admin/broadcast/events-with-registrants → Events that have form responses

GET    /api/admin/themes                        → All event themes
POST   /api/admin/themes                        → Create a theme
PUT    /api/admin/themes/:id                    → Update a theme
DELETE /api/admin/themes/:id                    → Delete a theme (cannot delete active theme)

POST   /api/admin/wrapped/config                → Save KFS Wrapped config (JSON body)
POST   /api/admin/wrapped/upload-image          → Upload a Wrapped highlight card image
```

### Master-Only Endpoints (Bearer JWT, `role: "master"`)

```
GET    /api/master/admins                       → List all admins
POST   /api/master/admins                       → Create admin { name, username, password, permissions[] }
DELETE /api/master/admins/:id                   → Delete admin (cannot delete master)
PUT    /api/master/admins/:id/permissions       → Update admin section permissions { permissions[] }
GET    /api/master/activity                     → Full activity log (last 200 entries)
```

---

## Member Linking in Films

Crew fields in the `movies` table store text. To link a crew credit to a member profile, use this format:

```
Name||memberUUID
```

Example: `Arjun Mehta||3f8a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c`

You never need to type this manually — the **Member Picker** in the Films admin modal handles it. But knowing the format is useful for direct database edits.

When a member is linked:
- Their name is a clickable link on Film Detail
- Their Member Profile lists every film they appear in with their credited role
- Global search finds those films when searching the member's name

---

## Member Roles and Domains

**Roles** (controls display grouping on the Members page):

`President` → `Vice President` → `Lead` → `Core Member` → `Member`

**Domains** (informational tag shown on member cards):

Direction, Cinematography, Scriptwriting, Video Editing, Sound Design, Graphic Design, Animation, Acting, Photography, Content Creation, Social Media, HR and PR, Production Management

---

## Themes (Light / Dark Mode)

A sun/moon icon in the navbar toggles between **dark mode** (default) and **light mode**. `body.light-mode` drives all light-theme overrides.

- **Dark mode**: `#0a0a0a` background, white text, grey borders, white card glow on hover
- **Light mode**: `#f0f0f0` background, dark text, dark shadow on hover

Theme preference is stored in `localStorage` and restored on every load.

---

## Read / Watched State

Both stored in `localStorage`. Clearing browser data resets them.

### Blog Read State
- Stored under `kfs-read-${id}` keys
- Unread posts: full colour with "New" badge
- Read posts: greyscale with "✓ Read" badge
- Opening a post marks it read immediately; the home carousel updates live

### Film Watched State
- Stored under `kfs-watchlist` as a JSON object
- Watched films: poster greyscale on the Films grid
- Toggle on the Film Detail page

### Recently Viewed Blogs
- Stored under `kfs-blog-history` as a JSON array
- Up to 5 most recent posts shown at the bottom of every Blog Detail view

---

## Frontend Architecture

`index.html` is structured as a single-page application:

**Pages**: Each page is a `<div class="page" id="page-X">`. Only one has `active` at a time. `navigate(pageName)` switches pages and calls `history.pushState`. Browser back/forward is handled via `popstate`.

**State** (global JS variables):
- `adminToken` — JWT for the current admin session
- `currentAdminRole` — `"master"` or `"admin"`
- `currentAdminPermissions` — Array of section strings
- `allEvents` — Cached events list for filtering
- `window._allBlogs` — Cached blogs for recently-viewed lookups
- `window._allMoviesCache` — Cached films for search and member profiles
- `window._movieRatings` — Pre-computed rating averages keyed by film ID
- `window._blogSections` — Sections array for the currently-open blog modal

**API calls**: Public calls go through `apiFetch(path, method, body)` — a thin `fetch` wrapper. Admin calls use raw `fetch` with `Authorization: Bearer` headers and `FormData` bodies.

**Scroll progress bar**: Thin bar at top of screen tracks reading progress on Blog Detail and Film Detail pages. Hidden on all other views.

---

## Deployment

Any Node.js host works (Render, Railway, Fly.io, DigitalOcean App Platform, etc.).

```bash
git add .
git commit -m "your message"
git push
```

Set all environment variables from your `.env` on your hosting platform. The server has no start script dependencies — `node server.js` is sufficient.

**No restart needed for content changes**: all content is fetched from Supabase on every request. Admin changes appear on the live site immediately.

**No static asset pipeline**: all CSS, JS, fonts, and SVGs are embedded directly in `index.html`. There is nothing to build.

### Keepalive

The server pings Supabase every 29 minutes to prevent idle connection timeouts (Supabase disconnects idle connections at 30 minutes).

---

*Maintained by KIIT Film Society.*

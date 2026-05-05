# KFS — KIIT Film Society

Official website for KIIT Film Society. A single-page web application for managing and showcasing the society's films, events, blog, and members.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML, CSS, JavaScript (no framework) |
| Backend | Node.js + Express |
| Storage | JSON flat files in `/data/` |
| Auth | Admin PIN stored in `data/settings.json` |

---

## Project Structure

```
kfs/
├── public/
│   └── index.html        # Entire frontend SPA
├── server.js             # Express backend + all API routes
├── data/
│   ├── settings.json     # Site config, admin PIN
│   ├── events.json
│   ├── blog.json
│   ├── members.json
│   ├── films.json
│   └── cv.json           # Chitra Vichitra episodes
├── images/               # Uploaded images served statically
└── package.json
```

---

## Getting Started

### Prerequisites

- Node.js 18+

### Installation

```bash
git clone https://github.com/ShivanshuAgarwal/kfs-website.git
cd kfs
npm install
```

### Run Locally

```bash
node server.js
```

Opens on `http://localhost:3000` by default. JSON files are read on each request — no restart needed for content changes made via the admin panel.

---

## Public Pages

### Home
Full-viewport hero with animated scroll-reveal text ("Lights. Camera. KFS."), live stats counters (members, events, films, years active), about section with team photo, and an upcoming events strip.

### Events
Toggles between Upcoming and Past tabs. Each card shows cover image, title, date, time, and location. The Past tab also surfaces the Chitra Vichitra (CV) section with its episode cards.

### Films
Responsive poster grid. Clicking a poster opens the film detail modal with full crew credits, trailer embed, and Watch Now link.

### Blog
Grid of published posts with cover image, title, excerpt, and date.

### Members
Toggles between Current and Alumni. Cards show photo, name, role, and domain.

### Global Search
Full-screen search overlay accessible from the nav bar. Searches across films, blogs, events, and members simultaneously with results grouped by category.

---

## Admin Panel

Access via the Admin link in the footer (PIN protected).

| Section | Description |
|---|---|
| Settings | Site name, about text, team photo, stat counters, social links |
| Events | Add / edit / delete events with cover image upload |
| Blog | Add / edit / delete posts with cover image and draft/publish toggle |
| Members | Add / edit / delete member cards with photo upload |
| Films | Add films with full crew fields, poster, trailer URL, Watch Now URL |
| Chitra Vichitra | Upload CV poster and manage episode cards |

---

## Themes

Toggle between **dark mode** (default) and **light mode** via the ☀️ icon in the navbar. The class `body.light-mode` drives all light-theme overrides in the CSS. In light mode, the hero displays a pulsing black radial glow behind the text, and the scroll indicator sits at the bottom-right corner instead of centred.

---

## Routing

Client-side navigation via `navigate(page)` updates the URL hash. The Express catch-all returns `index.html` for every path so direct URL access and browser refresh work correctly.

---

## Bug Fix Changelog

| # | Bug | Fix |
|---|---|---|
| 1 | Hero `</section>` missing — entire page nested inside hero | Added closing tag + `<span>Scroll</span>` |
| 2 | `filterEvents()` matched Members page tabs | Scoped to `#page-events .events-tab` |
| 3 | Past tab never showed CV section | Added `cvWrap.style.display='block'` and `loadCVCards()` call |
| 4 | `loadAdminData()` had no `'chitra-vichitra'` case | Added missing `else if` branch |
| 5 | Stray `}` in `<style>` block corrupting CSS | Removed the stray brace |
| 6 | Watchlist badge invisible in light mode | Replaced inline styles with `.watched-active` CSS class |
| 7 | Hero text too large at 100% zoom | Reduced to `clamp(3.2rem, 8.5vw, 7.8rem)` |
| 8 | Light mode scroll indicator barely visible | Changed to `#333` with `font-weight: 600` |
| 9 | Large gap between stats and About Us | Set stats section `padding-bottom: 0`, `margin-top: 0` on grid |
| 10 | Scroll indicator centred in light mode | Repositioned to `bottom: 40px; right: 48px` |

---

*Built and maintained by KIIT Film Society.*

---

## Member Linking

Crew fields in films (Director, Producer, DOP, etc.) support linked members using the format:

```
Name||memberId
```

For example: `Abhinav Mishra||uuid-of-member`

When a member is linked:
- Their name appears as a **clickable link** in the film detail page
- Their member profile shows all films they are part of
- Universal search finds films by searching crew member names
- Search results for members show their film count

**No database schema change is required.** The `||` format is stored in the existing `text` columns of the `movies` table.

### How to link in the Admin panel
In the Films form, each crew field has a live-search member picker. Type a name to search members — click one to tag them. You can also type a free-text name (press Enter) for people not in the members list.

# KFS — KIIT Film Society Website

A single-file, no-framework website for the KIIT Film Society. Everything lives in `index.html` and is served by `server.js`.

---

## Stack

- **Frontend** — Vanilla HTML/CSS/JS, single `index.html`, no build step
- **Backend** — Node.js + Express (`server.js`)
- **Storage** — JSON flat files in `/data/` (settings, events, blog, members, films)
- **Auth** — Simple admin PIN stored in `data/settings.json`

---

## Running Locally

```bash
npm install
node server.js
```

Opens on `http://localhost:3000` by default.

---

## Pages

| Route (SPA) | Description |
|---|---|
| `#home` | Hero, stats, about, testimonials |
| `#events` | Upcoming & past events + CV (Chitra Vichitra) |
| `#blog` | Blog posts |
| `#members` | Member cards |
| `#films` | Film library with watchlist |

All navigation is client-side (`navigate(page)` function). The URL hash updates so deep links work.

---

## Admin Panel

Access via the **Admin** link in the footer (PIN protected).

### Sidebar sections

| Section | What it controls |
|---|---|
| Settings | Site name, about text, team photo, stat numbers |
| Events | Add / edit / delete events |
| Blog | Add / edit / delete posts |
| Members | Add / edit / delete member cards |
| Films | Add films to the library |
| Chitra Vichitra | Upload CV poster and episode cards |

---

## Key Files

```
index.html      — entire frontend (HTML + CSS + JS)
server.js       — Express API + static file serving
data/
  settings.json — site config, admin PIN
  events.json
  blog.json
  members.json
  films.json
  cv.json       — Chitra Vichitra episodes
public/
  images/       — uploaded images served statically
```

---

## Themes

Toggle between **dark mode** (default) and **light mode** via the ☀️ icon in the navbar. The class `body.light-mode` drives all light-theme overrides in the CSS.

---

## Known Fixes Applied (latest build)

1. Hero `</section>` was missing — entire page was nested inside hero
2. `filterEvents()` was matching Members page tabs — scoped to `#page-events`
3. Past tab now shows CV section and calls `loadCVCards()`
4. `loadAdminData()` now handles `'chitra-vichitra'` case
5. Watchlist button was white-on-white in light mode — replaced inline styles with `.watched-active` CSS class
6. Stray `}` in `<style>` block removed
7. Hero font size reduced (`clamp(3.2rem, 8.5vw, 7.8rem)`) to fit at 100% zoom
8. Light mode scroll indicator now dark (`#333`) and clearly visible
9. Gap between stats and About Us removed (`padding-bottom:0` on stats section, `margin-top:0` on grid)

---

## Deployment

```bash
git add public/index.html
git commit -m "your message"
git push
```

The server auto-reads JSON files on each request — no restart needed for content changes made via the admin panel.

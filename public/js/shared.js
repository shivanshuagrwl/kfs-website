(function () {
  const page = document.body.dataset.page || "home";
  const endpointMap = {
    home: ["/api/movies", "/api/events", "/api/blogs", "/api/members"],
    films: ["/api/movies"],
    events: ["/api/events"],
    blog: ["/api/blogs"],
    members: ["/api/members"],
    wrapped: ["/api/wrapped/stats", "/api/wrapped/config"],
    collaborate: ["/api/collaborate"],
  };
  const endpointLabel = {
    "/api/movies": "Films",
    "/api/events": "Events",
    "/api/blogs": "Blog",
    "/api/members": "Members",
    "/api/wrapped/stats": "Wrapped Stats",
    "/api/wrapped/config": "Wrapped Config",
    "/api/collaborate": "Collaborate",
  };
  const routeLink = {
    home: "/",
    films: "/films",
    events: "/events",
    blog: "/blog",
    members: "/members",
    wrapped: "/wrapped",
    collaborate: "/collaborate",
  };

  const state = { index: [] };

  markActive();
  bindSearchUi();
  load();

  function markActive() {
    document.querySelectorAll(".links a").forEach((a) => {
      if (a.dataset.page === page) a.classList.add("active");
    });
  }

  function bindSearchUi() {
    const overlay = document.getElementById("search-overlay");
    const opener = document.getElementById("search-open");
    const input = document.getElementById("search-input");
    opener?.addEventListener("click", () => {
      overlay?.classList.add("open");
      input?.focus();
    });
    overlay?.addEventListener("click", (ev) => {
      if (ev.target === overlay) overlay.classList.remove("open");
    });
    window.addEventListener("keydown", (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
        ev.preventDefault();
        overlay?.classList.add("open");
        input?.focus();
      } else if (ev.key === "Escape") {
        overlay?.classList.remove("open");
      }
    });
    input?.addEventListener("input", debounce((ev) => search(ev.target.value || ""), 180));
  }

  async function load() {
    const list = endpointMap[page] || endpointMap.home;
    const root = document.getElementById("cards");
    if (!root) return;
    root.innerHTML = `<article class="card"><h3>Loading</h3><p>Fetching latest data from API...</p></article>`;
    const rows = await Promise.all(list.map(getEndpointData));
    root.innerHTML = "";
    rows.forEach((row) => {
      const card = document.createElement("article");
      card.className = "card";
      const title = endpointLabel[row.url] || row.url;
      if (!row.ok) {
        card.innerHTML = `<h3>${esc(title)}</h3><p>Could not load now.</p>`;
      } else {
        card.innerHTML = `<h3>${esc(title)}</h3><p>${row.items.length} item(s) loaded from ${esc(row.url)}.</p>`;
      }
      root.appendChild(card);
    });
    buildSearchIndex(rows);
    search("");
  }

  async function getEndpointData(url) {
    try {
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const data = await res.json();
      return { url, ok: true, items: Array.isArray(data) ? data : [data] };
    } catch {
      return { url, ok: false, items: [] };
    }
  }

  function buildSearchIndex(rows) {
    state.index = [];
    rows.forEach((row) => {
      const group = endpointLabel[row.url] || row.url;
      row.items.forEach((item, i) => {
        const title = String(item.title || item.name || item.slug || `Item ${i + 1}`);
        const blob = [title, item.description, item.excerpt, item.content].filter(Boolean).join(" ").toLowerCase();
        state.index.push({ title, group, page: guessPage(row.url), blob });
      });
    });
  }

  function guessPage(url) {
    if (url.includes("movies")) return "films";
    if (url.includes("events")) return "events";
    if (url.includes("blogs")) return "blog";
    if (url.includes("members")) return "members";
    if (url.includes("wrapped")) return "wrapped";
    if (url.includes("collaborate")) return "collaborate";
    return "home";
  }

  function search(q) {
    const root = document.getElementById("search-results");
    if (!root) return;
    const text = q.trim().toLowerCase();
    if (!text) {
      root.innerHTML = `<div class="s-item"><small>Type to search. Shortcuts: Ctrl/Cmd + K</small></div>`;
      return;
    }
    const hits = state.index.filter((x) => x.blob.includes(text) || x.title.toLowerCase().includes(text)).slice(0, 18);
    if (!hits.length) {
      root.innerHTML = `<div class="s-item"><small>No results for "${esc(q)}".</small></div>`;
      return;
    }
    root.innerHTML = hits.map((h) => {
      const href = routeLink[h.page] || "/";
      return `<a class="s-item" href="${href}"><strong>${esc(h.title)}</strong><br><small>${esc(h.group)}</small></a>`;
    }).join("");
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }
  function esc(v) {
    return String(v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
  }
})();

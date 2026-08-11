// migrate-cloudinary-account.js
//
// One-time cleanup: finds every image URL in the DB that still points at the
// OLD (locked-out) Cloudinary account, re-uploads it to the NEW Cloudinary
// account, and rewrites every row/field that referenced it.
//
// This reuses the exact same table/column map as migrate-legacy-images.js,
// because that script already wrote all Cloudinary URLs into these same
// spots — so we know exactly where to look.
//
// Old URLs are PUBLIC and downloadable without login, so no old Cloudinary
// credentials are needed at all. Only the NEW account's credentials go in .env.
//
// USAGE:
//   node migrate-cloudinary-account.js               -> dry run, prints what it WOULD do
//   node migrate-cloudinary-account.js --apply        -> actually uploads + updates rows
//
// Requires env vars:
//   SUPABASE_URL, SUPABASE_KEY (service role key — needed for writes)
//   CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
//     -> these MUST already be your NEW account's credentials before running

require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const cloudinary = require("cloudinary").v2;

const APPLY = process.argv.includes("--apply");

// Old cloud name — the compromised/inaccessible account whose public URLs
// we're migrating away from. Change this if it's ever different.
const OLD_CLOUD_NAME = "dgxciw7up";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

if (process.env.CLOUDINARY_CLOUD_NAME === OLD_CLOUD_NAME) {
  console.error(
    `!! CLOUDINARY_CLOUD_NAME in your .env is still "${OLD_CLOUD_NAME}" (the OLD/locked account).\n` +
    `   Update .env with your NEW account's cloud_name/api_key/api_secret before running this.`
  );
  process.exit(1);
}

const URL_RE = new RegExp(
  `https:\\/\\/res\\.cloudinary\\.com\\/${OLD_CLOUD_NAME}\\/[^\\s"',)]+`,
  "g"
);

// Same table/column map as migrate-legacy-images.js, since that script
// already funneled every Cloudinary URL into these exact spots.
const SIMPLE_TARGETS = [
  { table: "movies",               column: "poster_image", folder: "movies" },
  { table: "blogs",                column: "cover_image",  folder: "blogs" },
  { table: "events",               column: "cover_image",  folder: "events" },
  { table: "testimonials",         column: "photo",        folder: "general" },
  { table: "achievements",         column: "image",        folder: "general" },
  { table: "donors",               column: "photo_path",   folder: "general" },
  { table: "site_credits",         column: "member_photo", folder: "members" },
  { table: "chitra_vichitra",      column: "cover_image",  folder: "chitra-vichitra" },
  { table: "event_themes",         column: "logo_url",     folder: "general" },
  { table: "member_projects",      column: "cover_image",  folder: "general" },
  { table: "members",              column: "photo",        folder: "members" },
  { table: "dm_group_chats",       column: "photo_url",    folder: "general" },
  { table: "member_notifications", column: "actor_photo",  folder: "members" },
  { table: "member_notifications", column: "attachment_url", folder: "general" },
  { table: "dm_group_messages",    column: "attachment_url", folder: "general" },
];

const SETTINGS_JSON_KEYS = ["wrapped_config", "custom_search_eggs"];
const SETTINGS_PLAIN_KEYS = ["team_photo", "easter_egg_img"];

const urlCache = new Map(); // old url -> new cloudinary url

async function migrateUrl(oldUrl, folder) {
  if (urlCache.has(oldUrl)) return urlCache.get(oldUrl);
  console.log(`  downloading ${oldUrl}`);
  const resp = await fetch(oldUrl);
  if (!resp.ok) {
    console.warn(`  !! failed to fetch (${resp.status}), leaving as-is`);
    urlCache.set(oldUrl, oldUrl);
    return oldUrl;
  }
  const buf = Buffer.from(await resp.arrayBuffer());

  if (!APPLY) {
    console.log(`  [dry-run] would upload ${(buf.length / 1024).toFixed(0)}KB to NEW Cloudinary folder kfs-media/${folder}`);
    urlCache.set(oldUrl, oldUrl);
    return oldUrl;
  }

  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: `kfs-media/${folder}`, resource_type: "image", format: "webp" },
      (err, res) => (err ? reject(err) : resolve(res)),
    );
    stream.end(buf);
  });
  console.log(`  -> ${result.secure_url}`);
  urlCache.set(oldUrl, result.secure_url);
  return result.secure_url;
}

async function processSimple({ table, column, folder }) {
  const { data, error } = await supabase.from(table).select(`id, ${column}`);
  if (error) {
    console.warn(`skip ${table}.${column}: ${error.message}`);
    return;
  }
  const rows = (data || []).filter(
    r => typeof r[column] === "string" && r[column].includes(`res.cloudinary.com/${OLD_CLOUD_NAME}`)
  );
  if (!rows.length) return;
  console.log(`\n== ${table}.${column} (${rows.length} rows) ==`);
  for (const row of rows) {
    const newUrl = await migrateUrl(row[column], folder);
    if (APPLY && newUrl !== row[column]) {
      const { error: updErr } = await supabase.from(table).update({ [column]: newUrl }).eq("id", row.id);
      if (updErr) console.warn(`  !! failed to update ${table} id=${row.id}: ${updErr.message}`);
    }
  }
}

async function processSettingsPlain(key) {
  const { data, error } = await supabase.from("settings").select("key, value").eq("key", key).maybeSingle();
  if (error || !data || !data.value || !data.value.includes(`res.cloudinary.com/${OLD_CLOUD_NAME}`)) return;
  console.log(`\n== settings.${key} ==`);
  const newUrl = await migrateUrl(data.value, "general");
  if (APPLY && newUrl !== data.value) {
    await supabase.from("settings").upsert({ key, value: newUrl }, { onConflict: "key" });
  }
}

async function processSettingsJson(key) {
  const { data, error } = await supabase.from("settings").select("key, value").eq("key", key).maybeSingle();
  if (error || !data || !data.value) return;
  if (!URL_RE.test(data.value)) return;
  URL_RE.lastIndex = 0;
  console.log(`\n== settings.${key} (JSON) ==`);

  const urls = [...new Set(data.value.match(URL_RE) || [])];
  let newValue = data.value;
  for (const oldUrl of urls) {
    const newUrl = await migrateUrl(oldUrl, key === "wrapped_config" ? "wrapped" : "general");
    newValue = newValue.split(oldUrl).join(newUrl);
  }
  if (APPLY && newValue !== data.value) {
    await supabase.from("settings").upsert({ key, value: newValue }, { onConflict: "key" });
  }
}

(async () => {
  console.log(APPLY
    ? "*** APPLY MODE — this will upload to your NEW Cloudinary account and write to the DB ***"
    : "*** DRY RUN — nothing will be changed. Re-run with --apply when ready. ***");
  console.log(`Migrating FROM res.cloudinary.com/${OLD_CLOUD_NAME}/... TO ${process.env.CLOUDINARY_CLOUD_NAME}\n`);

  for (const target of SIMPLE_TARGETS) {
    await processSimple(target);
  }
  for (const key of SETTINGS_PLAIN_KEYS) {
    await processSettingsPlain(key);
  }
  for (const key of SETTINGS_JSON_KEYS) {
    await processSettingsJson(key);
  }

  console.log(`\nDone. ${urlCache.size} unique legacy file(s) processed.`);
  if (!APPLY) {
    console.log("This was a dry run — re-run with `node migrate-cloudinary-account.js --apply` to actually migrate.");
  } else {
    console.log("All images are now on your new Cloudinary account. Old account can be abandoned — nothing in your DB points at it anymore.");
  }
})().catch(e => {
  console.error("Fatal error:", e);
  process.exit(1);
});

// migrate-legacy-images.js
//
// One-time cleanup: finds every image URL in the DB that still points at
// Supabase Storage (kfs-media bucket), re-uploads it to Cloudinary, and
// rewrites every row/field that referenced it. Dedupes by URL first, so if
// 60 notification rows share one actor_photo URL, that file is only
// downloaded + uploaded once.
//
// USAGE:
//   npm install @supabase/supabase-js cloudinary   (both already deps in server.js)
//   node migrate-legacy-images.js               -> dry run, prints what it WOULD do
//   node migrate-legacy-images.js --apply       -> actually uploads + updates rows
//
// Requires the same env vars server.js already uses:
//   SUPABASE_URL, SUPABASE_KEY (service role key — needed for writes),
//   CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET

require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const cloudinary = require("cloudinary").v2;

const APPLY = process.argv.includes("--apply");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const URL_RE = /https:\/\/[a-z0-9]+\.supabase\.co\/storage\/v1\/object\/public\/[^\s"',)]+/g;

// Simple columns: one row = one URL. { table, column, idColumn, folder }
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

// JSON-in-text columns: settings.value holds JSON with nested image_url fields
const SETTINGS_JSON_KEYS = ["wrapped_config", "custom_search_eggs"];
// settings.value holding a bare URL (not JSON)
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
    console.log(`  [dry-run] would upload ${(buf.length / 1024).toFixed(0)}KB to Cloudinary folder kfs-media/${folder}`);
    urlCache.set(oldUrl, oldUrl); // dry run: keep old url in output for review
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
  const rows = (data || []).filter(r => typeof r[column] === "string" && r[column].includes("supabase.co/storage"));
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
  if (error || !data || !data.value || !data.value.includes("supabase.co/storage")) return;
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
  console.log(APPLY ? "*** APPLY MODE — this will upload to Cloudinary and write to the DB ***" : "*** DRY RUN — nothing will be changed. Re-run with --apply when ready. ***");

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
    console.log("This was a dry run — re-run with `node migrate-legacy-images.js --apply` to actually migrate.");
  } else {
    console.log("Next step: go to Supabase Dashboard -> Storage -> kfs-media bucket, confirm nothing references it anymore, then delete the bucket contents (or set it private) to fully stop the cached egress.");
  }
})().catch(e => {
  console.error("Fatal error:", e);
  process.exit(1);
});

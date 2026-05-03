const crypto = require("crypto");
const fsSync = require("fs");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const { promisify } = require("util");
const zlib = require("zlib");

const ROOT = __dirname;

function loadEnvFile(filePath = path.join(ROOT, ".env")) {
  if (!fsSync.existsSync(filePath)) return;
  const lines = fsSync.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;
    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadEnvFile();

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const PUBLIC_POSTS_FILE = path.join(DATA_DIR, "public-posts.json");
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, "subscriptions.json");
const EMAIL_DELIVERIES_FILE = path.join(DATA_DIR, "email-deliveries.json");
const DB_TABLES = {
  users: "mind_archive_users",
  feedSubscriptions: "mind_archive_feed_subscriptions",
  publicPosts: "mind_archive_public_posts",
  emailDeliveries: "mind_archive_email_deliveries"
};
const SESSION_COOKIE = "mind_archive_session";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-this-session-secret";
const DATABASE_URL = process.env.DATABASE_URL || "";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const APP_URL = String(process.env.APP_URL || "").replace(/\/$/, "");
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const gzip = promisify(zlib.gzip);
const brotliCompress = promisify(zlib.brotliCompress);
let pool = null;
let indexCache = null;
const feedXmlCache = new Map();
let emailQueueRunning = false;
let emailQueueScheduled = false;
const configErrors = [];

if (IS_PRODUCTION && (!process.env.SESSION_SECRET || SESSION_SECRET.length < 32)) {
  configErrors.push("SESSION_SECRET must be set to at least 32 characters in production.");
}

if (IS_PRODUCTION && !DATABASE_URL) {
  configErrors.push("DATABASE_URL must be set in production.");
}

if (IS_PRODUCTION && (!RESEND_API_KEY || !EMAIL_FROM)) {
  configErrors.push("RESEND_API_KEY and EMAIL_FROM must be set in production for subscriber emails.");
}

if (IS_PRODUCTION && RESEND_API_KEY && EMAIL_FROM && !APP_URL) {
  configErrors.push("APP_URL must be set in production for email links.");
}

if (DATABASE_URL) {
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
  });
}

const rateBuckets = new Map();
const RATE_LIMITS = {
  auth: { windowMs: 15 * 60 * 1000, max: 20 },
  write: { windowMs: 60 * 1000, max: 60 },
  general: { windowMs: 60 * 1000, max: 180 }
};
const PUBLIC_POST_LIMIT = 50;
const PUBLIC_BODY_LIMIT = 50000;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function escapeXml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function securityHeaders(extra = {}) {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "same-origin",
    ...extra
  };
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...securityHeaders(headers)
  });
  res.end(JSON.stringify(body));
}

function text(res, status, body) {
  res.writeHead(status, securityHeaders({ "content-type": "text/plain; charset=utf-8" }));
  res.end(body);
}

function acceptsEncoding(req, encoding) {
  return String(req.headers["accept-encoding"] || "")
    .split(",")
    .some((part) => part.trim().toLowerCase().split(";")[0] === encoding);
}

async function getIndexAsset() {
  const filePath = path.join(ROOT, "index.html");
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(ROOT)) {
    const error = new Error("Forbidden");
    error.statusCode = 403;
    throw error;
  }

  const stat = await fs.stat(resolved);
  if (!stat.isFile()) {
    const error = new Error("Not found");
    error.statusCode = 404;
    throw error;
  }

  if (indexCache && indexCache.size === stat.size && indexCache.mtimeMs === stat.mtimeMs) {
    return indexCache;
  }

  const body = await fs.readFile(resolved);
  indexCache = {
    body,
    br: await brotliCompress(body, {
      params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 }
    }),
    gzip: await gzip(body, { level: 6 }),
    etag: `W/"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`,
    mtimeMs: stat.mtimeMs,
    size: stat.size
  };
  return indexCache;
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

function limitKind(req, pathname) {
  if (pathname === "/api/signup" || pathname === "/api/signin" || pathname === "/api/user-salt") return "auth";
  if (req.method === "PUT" && (pathname === "/api/vault" || pathname === "/api/public-feed")) return "write";
  return "general";
}

function checkRateLimit(req, pathname) {
  const kind = limitKind(req, pathname);
  const config = RATE_LIMITS[kind];
  const key = `${kind}:${getClientIp(req)}`;
  const now = Date.now();
  const bucket = rateBuckets.get(key);

  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + config.windowMs });
    return { ok: true };
  }

  bucket.count += 1;
  if (bucket.count <= config.max) return { ok: true };

  return {
    ok: false,
    retryAfter: Math.ceil((bucket.resetAt - now) / 1000)
  };
}

function cleanRateBuckets() {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets.entries()) {
    if (now > bucket.resetAt) rateBuckets.delete(key);
  }
}

async function ensureData() {
  if (pool) {
    await pool.query(`
      create table if not exists ${DB_TABLES.users} (
        email text primary key,
        login_salt text not null,
        login_hash text not null,
        client_salt text not null,
        recovery_salt text,
        wrapped_key jsonb,
        recovery_wrapped_key jsonb,
        vault jsonb not null,
        feed_id text unique,
        public_feed jsonb,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )
    `);
    await pool.query(`alter table ${DB_TABLES.users} add column if not exists feed_id text unique`);
    await pool.query(`alter table ${DB_TABLES.users} add column if not exists public_feed jsonb`);
    await pool.query(`
      create table if not exists ${DB_TABLES.feedSubscriptions} (
        feed_id text not null references ${DB_TABLES.users}(feed_id) on delete cascade,
        subscriber_email text not null references ${DB_TABLES.users}(email) on delete cascade,
        unsubscribe_token text unique,
        created_at timestamptz not null default now(),
        primary key (feed_id, subscriber_email)
      )
    `);
    await pool.query(`alter table ${DB_TABLES.feedSubscriptions} add column if not exists unsubscribe_token text unique`);
    await pool.query(`
      create table if not exists ${DB_TABLES.publicPosts} (
        feed_id text not null references ${DB_TABLES.users}(feed_id) on delete cascade,
        post_id text not null,
        title text not null,
        body text not null,
        mood text,
        place text,
        collections jsonb not null default '[]'::jsonb,
        series text,
        created_at timestamptz not null,
        updated_at timestamptz not null,
        synced_at timestamptz not null default now(),
        primary key (feed_id, post_id)
      )
    `);
    await pool.query(`
      create table if not exists ${DB_TABLES.emailDeliveries} (
        feed_id text not null,
        post_id text not null,
        subscriber_email text not null,
        status text not null,
        provider_id text,
        error text,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        primary key (feed_id, post_id, subscriber_email)
      )
    `);
    return;
  }

  await fs.mkdir(DATA_DIR, { recursive: true });
  for (const file of [USERS_FILE, PUBLIC_POSTS_FILE, SUBSCRIPTIONS_FILE, EMAIL_DELIVERIES_FILE]) {
    try {
      await fs.access(file);
    } catch {
      await fs.writeFile(file, "{}\n", "utf8");
    }
  }
}

async function loadJsonFile(file, fallback = {}) {
  await ensureData();
  try {
    const raw = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(raw || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return fallback;
  }
}

async function saveJsonFile(file, value) {
  await ensureData();
  await fs.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function loadUsers() {
  return loadJsonFile(USERS_FILE);
}

async function saveUsers(users) {
  await saveJsonFile(USERS_FILE, users);
}

async function loadPublicPosts() {
  return loadJsonFile(PUBLIC_POSTS_FILE);
}

async function savePublicPosts(posts) {
  await saveJsonFile(PUBLIC_POSTS_FILE, posts);
}

async function loadSubscriptionsStore() {
  return loadJsonFile(SUBSCRIPTIONS_FILE);
}

async function saveSubscriptionsStore(subscriptions) {
  await saveJsonFile(SUBSCRIPTIONS_FILE, subscriptions);
}

async function loadDeliveries() {
  return loadJsonFile(EMAIL_DELIVERIES_FILE);
}

async function saveDeliveries(deliveries) {
  await saveJsonFile(EMAIL_DELIVERIES_FILE, deliveries);
}

function parseFeedId(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const direct = raw.match(/^[A-Za-z0-9_-]+$/);
  if (direct) return raw;
  try {
    const url = new URL(raw, "http://localhost");
    const match = url.pathname.match(/^\/feed\/([A-Za-z0-9_-]+)\.xml$/);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

function rowToUser(row) {
  if (!row) return null;
  return {
    loginSalt: row.login_salt,
    loginHash: row.login_hash,
    clientSalt: row.client_salt,
    recoverySalt: row.recovery_salt,
    wrappedKey: typeof row.wrapped_key === "string" ? JSON.parse(row.wrapped_key) : row.wrapped_key,
    recoveryWrappedKey: typeof row.recovery_wrapped_key === "string" ? JSON.parse(row.recovery_wrapped_key) : row.recovery_wrapped_key,
    vault: typeof row.vault === "string" ? JSON.parse(row.vault) : row.vault,
    feedId: row.feed_id || "",
    publicFeed: typeof row.public_feed === "string" ? JSON.parse(row.public_feed) : row.public_feed,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function getUser(email) {
  await ensureData();
  if (pool) {
    const result = await pool.query(`select * from ${DB_TABLES.users} where email = $1`, [email]);
    return rowToUser(result.rows[0]);
  }

  const users = await loadUsers();
  return users[email] || null;
}

async function createUser(email, user) {
  await ensureData();
  if (pool) {
    try {
      await pool.query(
        `insert into ${DB_TABLES.users} (email, login_salt, login_hash, client_salt, recovery_salt, wrapped_key, recovery_wrapped_key, vault, feed_id)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          email,
          user.loginSalt,
          user.loginHash,
          user.clientSalt,
          user.recoverySalt || null,
          user.wrappedKey ? JSON.stringify(user.wrappedKey) : null,
          user.recoveryWrappedKey ? JSON.stringify(user.recoveryWrappedKey) : null,
          JSON.stringify(user.vault),
          user.feedId
        ]
      );
    } catch (error) {
      if (error.code === "23505") error.code = "USER_EXISTS";
      throw error;
    }
    return;
  }

  const users = await loadUsers();
  if (users[email]) {
    const error = new Error("User already exists.");
    error.code = "USER_EXISTS";
    throw error;
  }
  users[email] = user;
  await saveUsers(users);
}

async function ensureFeedId(email, user) {
  if (user.feedId) return user.feedId;
  const feedId = randomToken(16);

  if (pool) {
    await pool.query(`update ${DB_TABLES.users} set feed_id = $2, updated_at = now() where email = $1`, [email, feedId]);
    user.feedId = feedId;
    return feedId;
  }

  const users = await loadUsers();
  if (!users[email]) return "";
  users[email].feedId = feedId;
  users[email].updatedAt = new Date().toISOString();
  await saveUsers(users);
  user.feedId = feedId;
  return feedId;
}

async function updateUserVault(email, vault) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `update ${DB_TABLES.users} set vault = $2, updated_at = now() where email = $1`,
      [email, JSON.stringify(vault)]
    );
    return result.rowCount > 0;
  }

  const users = await loadUsers();
  if (!users[email]) return false;
  users[email].vault = vault;
  users[email].updatedAt = new Date().toISOString();
  await saveUsers(users);
  return true;
}

async function getPublicPosts(feedId) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `select post_id, title, body, mood, place, collections, series, created_at, updated_at
       from ${DB_TABLES.publicPosts}
       where feed_id = $1
       order by created_at desc
       limit $2`,
      [feedId, PUBLIC_POST_LIMIT]
    );
    if (!result.rows.length) {
      const legacy = await pool.query(`select public_feed from ${DB_TABLES.users} where feed_id = $1`, [feedId]);
      const publicFeed = typeof legacy.rows[0]?.public_feed === "string" ? JSON.parse(legacy.rows[0].public_feed) : legacy.rows[0]?.public_feed;
      return Array.isArray(publicFeed?.posts) ? publicFeed.posts.slice(0, PUBLIC_POST_LIMIT) : [];
    }
    return result.rows.map((row) => ({
      id: row.post_id,
      title: row.title,
      body: row.body,
      mood: row.mood || "",
      place: row.place || "",
      collections: typeof row.collections === "string" ? JSON.parse(row.collections) : row.collections || [],
      series: row.series || "",
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  const store = await loadPublicPosts();
  const posts = Array.isArray(store[feedId]) ? store[feedId] : [];
  if (!posts.length) {
    const users = await loadUsers();
    const entry = Object.values(users).find((user) => user && user.feedId === feedId);
    if (Array.isArray(entry?.publicFeed?.posts)) {
      return entry.publicFeed.posts.slice(0, PUBLIC_POST_LIMIT);
    }
  }
  return posts
    .slice()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, PUBLIC_POST_LIMIT);
}

async function getFeedOwner(feedId) {
  await ensureData();
  if (pool) {
    const result = await pool.query(`select email, feed_id from ${DB_TABLES.users} where feed_id = $1`, [feedId]);
    const row = result.rows[0];
    return row ? { ownerEmail: row.email, feedId: row.feed_id } : null;
  }

  const users = await loadUsers();
  const entry = Object.entries(users).find(([, item]) => item && item.feedId === feedId);
  return entry ? { ownerEmail: entry[0], feedId } : null;
}

async function setPublicPosts(email, feedId, posts) {
  await ensureData();
  const previousIds = new Set((await getPublicPosts(feedId)).map((post) => post.id));
  feedXmlCache.delete(feedId);

  if (pool) {
    await pool.query("begin");
    try {
      const currentIds = posts.map((post) => post.id);
      if (currentIds.length) {
        await pool.query(`delete from ${DB_TABLES.publicPosts} where feed_id = $1 and not (post_id = any($2))`, [feedId, currentIds]);
      } else {
        await pool.query(`delete from ${DB_TABLES.publicPosts} where feed_id = $1`, [feedId]);
      }
      for (const post of posts) {
        await pool.query(
          `insert into ${DB_TABLES.publicPosts} (feed_id, post_id, title, body, mood, place, collections, series, created_at, updated_at, synced_at)
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
           on conflict (feed_id, post_id) do update set
             title = excluded.title,
             body = excluded.body,
             mood = excluded.mood,
             place = excluded.place,
             collections = excluded.collections,
             series = excluded.series,
             created_at = excluded.created_at,
             updated_at = excluded.updated_at,
             synced_at = now()`,
          [
            feedId,
            post.id,
            post.title,
            post.body,
            post.mood || null,
            post.place || null,
            JSON.stringify(post.collections || []),
            post.series || null,
            post.createdAt,
            post.updatedAt
          ]
        );
      }
      await pool.query(`update ${DB_TABLES.users} set updated_at = now() where email = $1`, [email]);
      await pool.query("commit");
    } catch (error) {
      await pool.query("rollback");
      throw error;
    }
  } else {
    const store = await loadPublicPosts();
    store[feedId] = posts;
    await savePublicPosts(store);
    const users = await loadUsers();
    if (users[email]) {
      users[email].updatedAt = new Date().toISOString();
      delete users[email].publicFeed;
      await saveUsers(users);
    }
  }

  return posts.filter((post) => !previousIds.has(post.id));
}

async function getPublicFeed(feedId) {
  const owner = await getFeedOwner(feedId);
  if (!owner) return null;
  const posts = await getPublicPosts(feedId);
  const updatedAt = posts.reduce((latest, post) => {
    const time = new Date(post.updatedAt || post.createdAt).getTime();
    return Number.isNaN(time) || time <= latest ? latest : time;
  }, 0);
  return {
    ...owner,
    publicFeed: {
      updatedAt: updatedAt ? new Date(updatedAt).toISOString() : new Date().toISOString(),
      posts
    }
  };
}

async function subscribeToFeed(subscriberEmail, feedId) {
  const feed = await getPublicFeed(feedId);
  if (!feed) {
    const error = new Error("Feed not found.");
    error.statusCode = 404;
    throw error;
  }

  if (pool) {
    const token = randomToken(18);
    await pool.query(
      `insert into ${DB_TABLES.feedSubscriptions} (feed_id, subscriber_email, unsubscribe_token)
       values ($1, $2, $3)
       on conflict (feed_id, subscriber_email) do update set
         unsubscribe_token = coalesce(${DB_TABLES.feedSubscriptions}.unsubscribe_token, excluded.unsubscribe_token)`,
      [feedId, subscriberEmail, token]
    );
    return feed;
  }

  const users = await loadUsers();
  if (!users[subscriberEmail]) {
    const error = new Error("Subscriber account not found.");
    error.statusCode = 404;
    throw error;
  }
  const subscriptions = await loadSubscriptionsStore();
  subscriptions[subscriberEmail] = Array.isArray(subscriptions[subscriberEmail]) ? subscriptions[subscriberEmail] : [];
  const existing = subscriptions[subscriberEmail].find((item) => (typeof item === "string" ? item : item.feedId) === feedId);
  let changed = false;
  if (!existing) {
    subscriptions[subscriberEmail].push({ feedId, token: randomToken(18), createdAt: new Date().toISOString() });
    changed = true;
  } else if (typeof existing === "object" && !existing.token) {
    existing.token = randomToken(18);
    changed = true;
  }
  if (changed) await saveSubscriptionsStore(subscriptions);
  return feed;
}

async function getSubscriptions(subscriberEmail) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `select s.feed_id, s.created_at
       from ${DB_TABLES.feedSubscriptions} s
       where s.subscriber_email = $1
       order by s.created_at desc`,
      [subscriberEmail]
    );
    return result.rows.map((row) => ({ feedId: row.feed_id, createdAt: row.created_at }));
  }

  const subscriptions = await loadSubscriptionsStore();
  return (Array.isArray(subscriptions[subscriberEmail]) ? subscriptions[subscriberEmail] : [])
    .map((item) => typeof item === "string" ? { feedId: item, createdAt: "" } : item)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
}

async function getFeedSubscribers(feedId) {
  await ensureData();
  if (pool) {
    const result = await pool.query(`select subscriber_email, unsubscribe_token from ${DB_TABLES.feedSubscriptions} where feed_id = $1`, [feedId]);
    return result.rows.map((row) => ({ email: row.subscriber_email, token: row.unsubscribe_token || "" }));
  }

  const subscriptions = await loadSubscriptionsStore();
  return Object.entries(subscriptions)
    .filter(([, items]) => Array.isArray(items) && items.some((item) => (typeof item === "string" ? item : item.feedId) === feedId))
    .map(([email, items]) => {
      const item = items.find((entry) => (typeof entry === "string" ? entry : entry.feedId) === feedId);
      return { email, token: typeof item === "object" ? item.token || "" : "" };
    });
}

async function unsubscribeByToken(token) {
  const cleanToken = String(token || "");
  if (!cleanToken) return false;

  if (pool) {
    const result = await pool.query(`delete from ${DB_TABLES.feedSubscriptions} where unsubscribe_token = $1`, [cleanToken]);
    return result.rowCount > 0;
  }

  const subscriptions = await loadSubscriptionsStore();
  let changed = false;
  for (const [email, items] of Object.entries(subscriptions)) {
    if (!Array.isArray(items)) continue;
    const nextItems = items.filter((item) => !(typeof item === "object" && item.token === cleanToken));
    if (nextItems.length !== items.length) {
      subscriptions[email] = nextItems;
      changed = true;
    }
  }
  if (changed) await saveSubscriptionsStore(subscriptions);
  return changed;
}

async function updateUserLogin(email, loginSecret, wrappedKey) {
  await ensureData();
  const loginSalt = randomToken(18);
  const loginHash = hashLoginSecret(loginSecret, loginSalt);

  if (pool) {
    const result = await pool.query(
      `update ${DB_TABLES.users} set login_salt = $2, login_hash = $3, wrapped_key = $4, updated_at = now() where email = $1`,
      [email, loginSalt, loginHash, JSON.stringify(wrappedKey)]
    );
    return result.rowCount > 0;
  }

  const users = await loadUsers();
  if (!users[email]) return false;
  users[email].loginSalt = loginSalt;
  users[email].loginHash = loginHash;
  users[email].wrappedKey = wrappedKey;
  users[email].updatedAt = new Date().toISOString();
  await saveUsers(users);
  return true;
}

function hashLoginSecret(loginSecret, salt) {
  return crypto.pbkdf2Sync(String(loginSecret), salt, 310000, 32, "sha256").toString("base64");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return Object.fromEntries(
    header.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
      const index = part.indexOf("=");
      return index === -1 ? [part, ""] : [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
    })
  );
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}

function createSessionToken(email) {
  const payload = Buffer.from(JSON.stringify({
    e: email,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 30,
    n: randomToken(10)
  })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) return "";
  const [payload, signature] = token.split(".");
  const expected = sign(payload);
  if (signature.length !== expected.length) return "";
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return "";
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!decoded.e || Date.now() > decoded.exp) return "";
    return normalizeEmail(decoded.e);
  } catch {
    return "";
  }
}

function isHttps(req) {
  return req.headers["x-forwarded-proto"] === "https" || req.socket.encrypted;
}

function sessionHeaders(req, token) {
  const secure = isHttps(req) ? "; Secure" : "";
  return {
    "set-cookie": `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`
  };
}

function clearSessionHeaders() {
  return {
    "set-cookie": `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
  };
}

async function readJson(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 5_000_000) throw new Error("Request body is too large.");
  }
  return body ? JSON.parse(body) : {};
}

function validateVault(vault) {
  return vault
    && typeof vault === "object"
    && typeof vault.iv === "string"
    && typeof vault.data === "string"
    && vault.iv.length < 200
    && vault.data.length < 4_500_000;
}

function validateWrappedKey(value) {
  return value
    && typeof value === "object"
    && typeof value.iv === "string"
    && typeof value.data === "string"
    && value.iv.length < 200
    && value.data.length < 2000;
}

function normalizePublicPosts(posts) {
  if (!Array.isArray(posts) || posts.length > PUBLIC_POST_LIMIT) {
    const error = new Error(`RSS feed can include up to ${PUBLIC_POST_LIMIT} posts.`);
    error.statusCode = 400;
    throw error;
  }

  return posts.map((post) => {
    const id = String(post.id || "").slice(0, 120);
    const title = String(post.title || "Untitled").trim().slice(0, 160) || "Untitled";
    const body = String(post.body || "").slice(0, PUBLIC_BODY_LIMIT);
    const createdDate = new Date(post.createdAt || Date.now());
    const updatedDate = post.updatedAt ? new Date(post.updatedAt) : createdDate;
    const createdAt = Number.isNaN(createdDate.getTime()) ? new Date().toISOString() : createdDate.toISOString();
    const updatedAt = Number.isNaN(updatedDate.getTime()) ? createdAt : updatedDate.toISOString();
    const mood = String(post.mood || "").slice(0, 80);
    const place = String(post.place || "").slice(0, 120);
    const collections = Array.isArray(post.collections) ? post.collections.map((name) => String(name).slice(0, 80)).slice(0, 20) : [];
    const series = String(post.series || "").slice(0, 120);

    if (!id || !body) {
      const error = new Error("RSS posts need an id and body.");
      error.statusCode = 400;
      throw error;
    }

    return { id, title, body, createdAt, updatedAt, mood, place, collections, series };
  });
}

function renderPublicFeedXml(req, feedId, publicFeed) {
  const origin = `${isHttps(req) ? "https" : "http"}://${req.headers.host || "localhost"}`;
  const feedUrl = `${origin}/feed/${encodeURIComponent(feedId)}.xml`;
  const posts = Array.isArray(publicFeed.posts) ? publicFeed.posts : [];
  const items = posts.map((post) => {
    const postUrl = `${feedUrl}#post-${encodeURIComponent(post.id)}`;
    return `
  <item>
    <title>${escapeXml(post.title)}</title>
    <link>${escapeXml(postUrl)}</link>
    <guid>${escapeXml(post.id)}</guid>
    <pubDate>${new Date(post.createdAt).toUTCString()}</pubDate>
    <description>${escapeXml(post.body)}</description>
  </item>`;
  }).join("");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>Mind Archive</title>
  <link>${escapeXml(feedUrl)}</link>
  <description>Shared thoughts and opinions</description>
  <lastBuildDate>${new Date(publicFeed.updatedAt || Date.now()).toUTCString()}</lastBuildDate>${items}
</channel>
</rss>`;
}

function publicPostEmail(feedId, post, unsubscribeToken = "") {
  const title = post.title || "New thought";
  const baseUrl = APP_URL || "";
  const feedPath = `/feed/${feedId}.xml`;
  const feedUrl = baseUrl ? `${baseUrl}${feedPath}` : feedPath;
  const unsubscribePath = unsubscribeToken ? `/unsubscribe/${unsubscribeToken}` : "";
  const unsubscribeUrl = unsubscribePath && baseUrl ? `${baseUrl}${unsubscribePath}` : unsubscribePath;
  return {
    subject: title,
    text: `${title}\n\n${post.body}\n\nFeed: ${feedUrl}${unsubscribeUrl ? `\nUnsubscribe: ${unsubscribeUrl}` : ""}`,
    html: `
      <h1>${escapeHtml(title)}</h1>
      <p style="white-space:pre-wrap">${escapeHtml(post.body)}</p>
      <p><small>Feed: <a href="${escapeHtml(feedUrl)}">${escapeHtml(feedUrl)}</a></small></p>
      ${unsubscribeUrl ? `<p><small><a href="${escapeHtml(unsubscribeUrl)}">Unsubscribe</a></small></p>` : ""}
    `
  };
}

async function createPendingDeliveries(feedId, posts, subscribers) {
  if (!posts.length || !subscribers.length) return [];
  if (!RESEND_API_KEY || !EMAIL_FROM) return [];
  const entries = [];

  if (pool) {
    for (const post of posts) {
      for (const subscriber of subscribers) {
        const result = await pool.query(
          `insert into ${DB_TABLES.emailDeliveries} (feed_id, post_id, subscriber_email, status)
           values ($1, $2, $3, 'pending')
           on conflict do nothing
           returning feed_id, post_id, subscriber_email`,
          [feedId, post.id, subscriber.email]
        );
        if (result.rows[0]) {
          entries.push({ feedId, postId: post.id, subscriberEmail: subscriber.email });
        }
      }
    }
    return entries;
  }

  const deliveries = await loadDeliveries();
  for (const post of posts) {
    for (const subscriber of subscribers) {
      const key = `${feedId}:${post.id}:${subscriber.email}`;
      if (!deliveries[key]) {
        deliveries[key] = {
          feedId,
          postId: post.id,
          subscriberEmail: subscriber.email,
          status: "pending",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        entries.push({ feedId, postId: post.id, subscriberEmail: subscriber.email });
      }
    }
  }
  await saveDeliveries(deliveries);
  return entries;
}

async function getPendingDeliveries(limit = 100) {
  if (!RESEND_API_KEY || !EMAIL_FROM) return [];

  if (pool) {
    const result = await pool.query(
      `select d.feed_id, d.post_id, d.subscriber_email, s.unsubscribe_token,
              p.title, p.body, p.mood, p.place, p.collections, p.series, p.created_at, p.updated_at
       from ${DB_TABLES.emailDeliveries} d
       join ${DB_TABLES.publicPosts} p on p.feed_id = d.feed_id and p.post_id = d.post_id
       left join ${DB_TABLES.feedSubscriptions} s on s.feed_id = d.feed_id and s.subscriber_email = d.subscriber_email
       where d.status = 'pending'
       order by d.created_at
       limit $1`,
      [limit]
    );
    return result.rows.map((row) => ({
      feedId: row.feed_id,
      postId: row.post_id,
      subscriberEmail: row.subscriber_email,
      unsubscribeToken: row.unsubscribe_token || "",
      post: {
        id: row.post_id,
        title: row.title,
        body: row.body,
        mood: row.mood || "",
        place: row.place || "",
        collections: typeof row.collections === "string" ? JSON.parse(row.collections) : row.collections || [],
        series: row.series || "",
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    }));
  }

  const deliveries = await loadDeliveries();
  const publicPosts = await loadPublicPosts();
  const subscriptions = await loadSubscriptionsStore();
  const pending = [];
  for (const delivery of Object.values(deliveries)) {
    if (!delivery || delivery.status !== "pending") continue;
    const post = (publicPosts[delivery.feedId] || []).find((item) => item.id === delivery.postId);
    if (!post) continue;
    const subscription = (subscriptions[delivery.subscriberEmail] || [])
      .find((item) => (typeof item === "string" ? item : item.feedId) === delivery.feedId);
    pending.push({
      feedId: delivery.feedId,
      postId: delivery.postId,
      subscriberEmail: delivery.subscriberEmail,
      unsubscribeToken: typeof subscription === "object" ? subscription.token || "" : "",
      post
    });
    if (pending.length >= limit) break;
  }
  return pending;
}

async function recordDelivery(entry, status, details = {}) {
  if (pool) {
    await pool.query(
      `update ${DB_TABLES.emailDeliveries}
       set status = $4, provider_id = $5, error = $6, updated_at = now()
       where feed_id = $1 and post_id = $2 and subscriber_email = $3`,
      [entry.feedId, entry.postId, entry.subscriberEmail, status, details.providerId || null, details.error || null]
    );
    return;
  }

  const deliveries = await loadDeliveries();
  const key = `${entry.feedId}:${entry.postId}:${entry.subscriberEmail}`;
  if (deliveries[key]) {
    deliveries[key].status = status;
    deliveries[key].providerId = details.providerId || "";
    deliveries[key].error = details.error || "";
    deliveries[key].updatedAt = new Date().toISOString();
    await saveDeliveries(deliveries);
  }
}

async function sendDeliveryBatch(entries) {
  if (!entries.length) return { sent: 0, skipped: 0, failed: 0 };

  const payload = entries.map((entry) => {
    const email = publicPostEmail(entry.feedId, entry.post, entry.unsubscribeToken);
    return {
      from: EMAIL_FROM,
      to: [entry.subscriberEmail],
      subject: email.subject,
      text: email.text,
      html: email.html,
      headers: entry.unsubscribeToken && APP_URL ? {
        "List-Unsubscribe": `<${APP_URL || ""}/unsubscribe/${entry.unsubscribeToken}>`
      } : undefined
    };
  });

  const response = await fetch("https://api.resend.com/emails/batch", {
    method: "POST",
    headers: {
      authorization: `Bearer ${RESEND_API_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const error = await response.text().catch(() => "");
    for (const entry of entries) {
      await recordDelivery(entry, "failed", { error });
    }
    return { sent: 0, skipped: 0, failed: entries.length };
  }

  const body = await response.json().catch(() => ({}));
  const ids = Array.isArray(body.data) ? body.data : [];
  for (let index = 0; index < entries.length; index += 1) {
    await recordDelivery(entries[index], "sent", { providerId: ids[index]?.id || "" });
  }
  return { sent: entries.length, skipped: 0, failed: 0 };
}

async function notifyFeedSubscribers(feedId, posts) {
  if (!posts.length) return { attempted: 0, queued: 0, skipped: 0 };
  const subscribers = await getFeedSubscribers(feedId);
  if (!RESEND_API_KEY || !EMAIL_FROM) {
    return { attempted: subscribers.length * posts.length, queued: 0, skipped: subscribers.length * posts.length };
  }
  const pending = await createPendingDeliveries(feedId, posts, subscribers);
  scheduleEmailQueue();
  return { attempted: subscribers.length * posts.length, queued: pending.length, skipped: 0 };
}

function scheduleEmailQueue(delayMs = 100) {
  if (emailQueueScheduled || emailQueueRunning || !RESEND_API_KEY || !EMAIL_FROM) return;
  emailQueueScheduled = true;
  setTimeout(() => {
    emailQueueScheduled = false;
    processEmailQueue().catch(() => {});
  }, delayMs).unref();
}

async function processEmailQueue() {
  if (emailQueueRunning || !RESEND_API_KEY || !EMAIL_FROM) return;
  emailQueueRunning = true;
  try {
    while (true) {
      const entries = await getPendingDeliveries(100);
      if (!entries.length) break;
      await sendDeliveryBatch(entries);
      if (entries.length < 100) break;
    }
  } finally {
    emailQueueRunning = false;
  }
}

async function requireUser(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const email = verifySessionToken(token);
  if (!email) {
    json(res, 401, { error: "Not signed in." });
    return null;
  }
  const user = await getUser(email);
  if (!user) {
    json(res, 401, { error: "Session no longer exists." }, clearSessionHeaders());
    return null;
  }
  await ensureFeedId(email, user);
  return { email, user };
}

async function handleApi(req, res, pathname) {
  try {
    if (configErrors.length) {
      const status = pathname === "/api/health" ? 503 : 500;
      json(res, status, {
        ok: false,
        error: "Server is missing required production configuration.",
        details: configErrors
      });
      return;
    }

    const limit = checkRateLimit(req, pathname);
    if (!limit.ok) {
      json(res, 429, { error: "Too many requests. Try again later." }, { "retry-after": String(limit.retryAfter) });
      return;
    }

    if (req.method === "GET" && pathname === "/api/health") {
      json(res, 200, { ok: true, storage: pool ? "postgres" : "local" });
      return;
    }

    if (req.method === "POST" && pathname === "/api/signup") {
      const body = await readJson(req);
      const email = normalizeEmail(body.email);
      const loginSecret = String(body.loginSecret || "");

      if (!isValidEmail(email)) {
        json(res, 400, { error: "Enter a valid email address." });
        return;
      }
      if (loginSecret.length < 32) {
        json(res, 400, { error: "Missing login verifier." });
        return;
      }
      if (!validateVault(body.vault)) {
        json(res, 400, { error: "Missing encrypted vault." });
        return;
      }
      if (!validateWrappedKey(body.wrappedKey) || !validateWrappedKey(body.recoveryWrappedKey)) {
        json(res, 400, { error: "Missing recovery metadata." });
        return;
      }

      if (await getUser(email)) {
        json(res, 409, { error: "That email already has an archive." });
        return;
      }

      const loginSalt = randomToken(18);
      const user = {
        loginSalt,
        loginHash: hashLoginSecret(loginSecret, loginSalt),
        clientSalt: String(body.clientSalt || ""),
        recoverySalt: String(body.recoverySalt || ""),
        wrappedKey: body.wrappedKey,
        recoveryWrappedKey: body.recoveryWrappedKey,
        vault: body.vault,
        feedId: randomToken(16),
        createdAt: new Date().toISOString()
      };
      try {
        await createUser(email, user);
      } catch (error) {
        if (error.code === "USER_EXISTS") {
          json(res, 409, { error: "That email already has an archive." });
          return;
        }
        throw error;
      }

      const token = createSessionToken(email);
      json(res, 201, {
        email,
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt,
        vault: user.vault,
        wrappedKey: user.wrappedKey,
        recoveryWrappedKey: user.recoveryWrappedKey,
        feedId: user.feedId
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "GET" && pathname === "/api/user-salt") {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const email = normalizeEmail(url.searchParams.get("email"));
      const user = email ? await getUser(email) : null;
      if (!user) {
        json(res, 404, { error: "Wrong email or password." });
        return;
      }
      json(res, 200, {
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt || "",
        vault: user.vault,
        recoveryWrappedKey: user.recoveryWrappedKey || null
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/signin") {
      const body = await readJson(req);
      const email = normalizeEmail(body.email);
      const loginSecret = String(body.loginSecret || "");
      const user = await getUser(email);

      if (!user || hashLoginSecret(loginSecret, user.loginSalt) !== user.loginHash) {
        json(res, 401, { error: "Wrong email or password." });
        return;
      }

      const token = createSessionToken(email);
      json(res, 200, {
        email,
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt || "",
        vault: user.vault,
        wrappedKey: user.wrappedKey || null,
        recoveryWrappedKey: user.recoveryWrappedKey || null,
        feedId: await ensureFeedId(email, user)
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/recover") {
      const body = await readJson(req);
      const email = normalizeEmail(body.email);
      const loginSecret = String(body.loginSecret || "");
      const user = await getUser(email);

      if (!user || loginSecret.length < 32) {
        json(res, 401, { error: "Recovery failed." });
        return;
      }
      if (!validateWrappedKey(body.wrappedKey) || !validateWrappedKey(body.recoveryWrappedKey)) {
        json(res, 400, { error: "Missing recovery metadata." });
        return;
      }
      if (JSON.stringify(body.recoveryWrappedKey) !== JSON.stringify(user.recoveryWrappedKey || null)) {
        json(res, 401, { error: "Recovery failed." });
        return;
      }

      await updateUserLogin(email, loginSecret, body.wrappedKey);
      const updated = await getUser(email);
      const token = createSessionToken(email);
      json(res, 200, {
        email,
        clientSalt: updated.clientSalt,
        recoverySalt: updated.recoverySalt || "",
        vault: updated.vault,
        wrappedKey: updated.wrappedKey || null,
        recoveryWrappedKey: updated.recoveryWrappedKey || null,
        feedId: await ensureFeedId(email, updated)
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/logout") {
      json(res, 200, { ok: true }, clearSessionHeaders());
      return;
    }

    if (req.method === "GET" && pathname === "/api/session") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, {
        email: auth.email,
        clientSalt: auth.user.clientSalt,
        recoverySalt: auth.user.recoverySalt || "",
        vault: auth.user.vault,
        wrappedKey: auth.user.wrappedKey || null,
        recoveryWrappedKey: auth.user.recoveryWrappedKey || null,
        feedId: auth.user.feedId
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/subscriptions") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, { subscriptions: await getSubscriptions(auth.email) });
      return;
    }

    if (req.method === "POST" && pathname === "/api/subscribe-feed") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      const feedId = parseFeedId(body.feedUrl || body.feedId);
      if (!feedId) {
        json(res, 400, { error: "Paste a valid RSS feed URL." });
        return;
      }
      const feed = await subscribeToFeed(auth.email, feedId);
      json(res, 200, {
        ok: true,
        feedId,
        subscribedEmail: auth.email,
        postCount: Array.isArray(feed.publicFeed?.posts) ? feed.publicFeed.posts.length : 0,
        emailConfigured: Boolean(RESEND_API_KEY && EMAIL_FROM)
      });
      return;
    }

    if (req.method === "PUT" && pathname === "/api/public-feed") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      const posts = normalizePublicPosts(body.posts || []);
      const publicFeed = { updatedAt: new Date().toISOString(), posts };
      const newPosts = await setPublicPosts(auth.email, auth.user.feedId, publicFeed.posts);
      const emailResult = await notifyFeedSubscribers(auth.user.feedId, newPosts);
      json(res, 200, {
        ok: true,
        feedId: auth.user.feedId,
        postCount: posts.length,
        newPostCount: newPosts.length,
        email: emailResult
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/vault") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, { vault: auth.user.vault });
      return;
    }

    if (req.method === "PUT" && pathname === "/api/vault") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      if (!validateVault(body.vault)) {
        json(res, 400, { error: "Invalid encrypted vault." });
        return;
      }
      await updateUserVault(auth.email, body.vault);
      json(res, 200, { ok: true });
      return;
    }

    json(res, 404, { error: "Not found." });
  } catch (error) {
    json(res, 500, { error: error.message || "Server error." });
  }
}

async function serveStatic(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    text(res, 405, "Method not allowed");
    return;
  }

  try {
    const asset = await getIndexAsset();
    const baseHeaders = {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=0, must-revalidate",
      "etag": asset.etag,
      "vary": "Accept-Encoding"
    };

    if (req.headers["if-none-match"] === asset.etag) {
      res.writeHead(304, securityHeaders(baseHeaders));
      res.end();
      return;
    }

    const headers = { ...baseHeaders };
    let body = asset.body;
    if (acceptsEncoding(req, "br")) {
      body = asset.br;
      headers["content-encoding"] = "br";
    } else if (acceptsEncoding(req, "gzip")) {
      body = asset.gzip;
      headers["content-encoding"] = "gzip";
    }
    headers["content-length"] = String(body.length);

    res.writeHead(200, securityHeaders(headers));
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    res.end(body);
  } catch (error) {
    text(res, error.statusCode || 404, error.message || "Not found");
  }
}

async function handlePublicFeed(req, res, feedId) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    text(res, 405, "Method not allowed");
    return;
  }

  const record = await getPublicFeed(feedId);
  if (!record) {
    text(res, 404, "Feed not found");
    return;
  }

  const cacheKey = `${isHttps(req) ? "https" : "http"}://${req.headers.host || "localhost"}:${feedId}`;
  const updatedAt = record.publicFeed.updatedAt || "";
  let cached = feedXmlCache.get(cacheKey);
  if (!cached || cached.updatedAt !== updatedAt) {
    const body = renderPublicFeedXml(req, feedId, record.publicFeed);
    cached = {
      body,
      etag: `W/"${crypto.createHash("sha256").update(body).digest("base64url").slice(0, 24)}"`,
      updatedAt
    };
    feedXmlCache.set(cacheKey, cached);
  }
  if (req.headers["if-none-match"] === cached.etag) {
    res.writeHead(304, securityHeaders({
      "cache-control": "public, max-age=60",
      etag: cached.etag
    }));
    res.end();
    return;
  }

  const headers = securityHeaders({
    "content-type": "application/rss+xml; charset=utf-8",
    "cache-control": "public, max-age=60",
    etag: cached.etag,
    "content-length": String(Buffer.byteLength(cached.body))
  });
  res.writeHead(200, headers);
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  res.end(cached.body);
}

async function handleUnsubscribe(req, res, token) {
  if (req.method !== "GET" && req.method !== "POST") {
    text(res, 405, "Method not allowed");
    return;
  }

  const removed = await unsubscribeByToken(token);
  text(res, removed ? 200 : 404, removed ? "Unsubscribed." : "Subscription not found.");
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname);
    return;
  }
  const feedMatch = url.pathname.match(/^\/feed\/([A-Za-z0-9_-]+)\.xml$/);
  if (feedMatch) {
    await handlePublicFeed(req, res, feedMatch[1]);
    return;
  }
  const unsubscribeMatch = url.pathname.match(/^\/unsubscribe\/([A-Za-z0-9_-]+)$/);
  if (unsubscribeMatch) {
    await handleUnsubscribe(req, res, unsubscribeMatch[1]);
    return;
  }
  await serveStatic(req, res, url.pathname);
}

if (require.main === module) {
  const server = http.createServer(handleRequest);

  setInterval(cleanRateBuckets, 5 * 60 * 1000).unref();
  setInterval(() => processEmailQueue().catch(() => {}), 30 * 1000).unref();
  scheduleEmailQueue(1000);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Mind Archive running on http://localhost:${PORT}`);
  });
}

module.exports = handleRequest;
module.exports.handleRequest = handleRequest;

const fsSync = require("fs");
const path = require("path");
const { promisify } = require("util");
const zlib = require("zlib");

const ROOT = path.resolve(__dirname, "..");

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
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${Number(process.env.PORT || 3000)}/api/auth/google/callback`;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const gzip = promisify(zlib.gzip);
const brotliCompress = promisify(zlib.brotliCompress);
const PUBLIC_POST_LIMIT = 50;
const PUBLIC_BODY_LIMIT = 50000;
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

let pool = null;
if (DATABASE_URL) {
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 15000,
    connectionTimeoutMillis: 5000
  });
  pool.on("error", (err) => console.error("Idle pool client error:", err));
}

module.exports = {
  ROOT,
  PORT,
  DATA_DIR,
  USERS_FILE,
  PUBLIC_POSTS_FILE,
  SUBSCRIPTIONS_FILE,
  EMAIL_DELIVERIES_FILE,
  DB_TABLES,
  SESSION_COOKIE,
  SESSION_SECRET,
  DATABASE_URL,
  RESEND_API_KEY,
  EMAIL_FROM,
  APP_URL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  IS_PRODUCTION,
  gzip,
  brotliCompress,
  pool,
  configErrors,
  PUBLIC_POST_LIMIT,
  PUBLIC_BODY_LIMIT
};

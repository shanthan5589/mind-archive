const crypto = require("crypto");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const { promisify } = require("util");
const zlib = require("zlib");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSION_COOKIE = "mind_archive_session";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-this-session-secret";
const DATABASE_URL = process.env.DATABASE_URL || "";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const gzip = promisify(zlib.gzip);
const brotliCompress = promisify(zlib.brotliCompress);
let pool = null;
let indexCache = null;
const configErrors = [];

if (IS_PRODUCTION && (!process.env.SESSION_SECRET || SESSION_SECRET.length < 32)) {
  configErrors.push("SESSION_SECRET must be set to at least 32 characters in production.");
}

if (IS_PRODUCTION && !DATABASE_URL) {
  configErrors.push("DATABASE_URL must be set in production.");
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

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
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
  if (req.method === "PUT" && pathname === "/api/vault") return "write";
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
      create table if not exists users (
        username text primary key,
        login_salt text not null,
        login_hash text not null,
        client_salt text not null,
        recovery_salt text,
        wrapped_key jsonb,
        recovery_wrapped_key jsonb,
        vault jsonb not null,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )
    `);
    return;
  }

  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, "{}\n", "utf8");
  }
}

async function loadUsers() {
  await ensureData();
  try {
    const raw = await fs.readFile(USERS_FILE, "utf8");
    const parsed = JSON.parse(raw || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function saveUsers(users) {
  await ensureData();
  await fs.writeFile(USERS_FILE, `${JSON.stringify(users, null, 2)}\n`, "utf8");
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
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function getUser(username) {
  await ensureData();
  if (pool) {
    const result = await pool.query("select * from users where username = $1", [username]);
    return rowToUser(result.rows[0]);
  }

  const users = await loadUsers();
  return users[username] || null;
}

async function createUser(username, user) {
  await ensureData();
  if (pool) {
    try {
      await pool.query(
        `insert into users (username, login_salt, login_hash, client_salt, recovery_salt, wrapped_key, recovery_wrapped_key, vault)
         values ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          username,
          user.loginSalt,
          user.loginHash,
          user.clientSalt,
          user.recoverySalt || null,
          user.wrappedKey ? JSON.stringify(user.wrappedKey) : null,
          user.recoveryWrappedKey ? JSON.stringify(user.recoveryWrappedKey) : null,
          JSON.stringify(user.vault)
        ]
      );
    } catch (error) {
      if (error.code === "23505") error.code = "USER_EXISTS";
      throw error;
    }
    return;
  }

  const users = await loadUsers();
  if (users[username]) {
    const error = new Error("User already exists.");
    error.code = "USER_EXISTS";
    throw error;
  }
  users[username] = user;
  await saveUsers(users);
}

async function updateUserVault(username, vault) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      "update users set vault = $2, updated_at = now() where username = $1",
      [username, JSON.stringify(vault)]
    );
    return result.rowCount > 0;
  }

  const users = await loadUsers();
  if (!users[username]) return false;
  users[username].vault = vault;
  users[username].updatedAt = new Date().toISOString();
  await saveUsers(users);
  return true;
}

async function updateUserLogin(username, loginSecret, wrappedKey) {
  await ensureData();
  const loginSalt = randomToken(18);
  const loginHash = hashLoginSecret(loginSecret, loginSalt);

  if (pool) {
    const result = await pool.query(
      "update users set login_salt = $2, login_hash = $3, wrapped_key = $4, updated_at = now() where username = $1",
      [username, loginSalt, loginHash, JSON.stringify(wrappedKey)]
    );
    return result.rowCount > 0;
  }

  const users = await loadUsers();
  if (!users[username]) return false;
  users[username].loginSalt = loginSalt;
  users[username].loginHash = loginHash;
  users[username].wrappedKey = wrappedKey;
  users[username].updatedAt = new Date().toISOString();
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

function createSessionToken(username) {
  const payload = Buffer.from(JSON.stringify({
    u: username,
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
    if (!decoded.u || Date.now() > decoded.exp) return "";
    return normalizeUsername(decoded.u);
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

async function requireUser(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const username = verifySessionToken(token);
  if (!username) {
    json(res, 401, { error: "Not signed in." });
    return null;
  }
  const user = await getUser(username);
  if (!user) {
    json(res, 401, { error: "Session no longer exists." }, clearSessionHeaders());
    return null;
  }
  return { username, user };
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
      const username = normalizeUsername(body.username);
      const loginSecret = String(body.loginSecret || "");

      if (!/^[a-z0-9_.@-]{3,40}$/.test(username)) {
        json(res, 400, { error: "Username must be 3-40 characters: letters, numbers, dot, underscore, dash, or @." });
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

      if (await getUser(username)) {
        json(res, 409, { error: "That username already exists." });
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
        createdAt: new Date().toISOString()
      };
      try {
        await createUser(username, user);
      } catch (error) {
        if (error.code === "USER_EXISTS") {
          json(res, 409, { error: "That username already exists." });
          return;
        }
        throw error;
      }

      const token = createSessionToken(username);
      json(res, 201, {
        username,
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt,
        vault: user.vault,
        wrappedKey: user.wrappedKey,
        recoveryWrappedKey: user.recoveryWrappedKey
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "GET" && pathname === "/api/user-salt") {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const username = normalizeUsername(url.searchParams.get("username"));
      const user = username ? await getUser(username) : null;
      if (!user) {
        json(res, 404, { error: "Wrong username or password." });
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
      const username = normalizeUsername(body.username);
      const loginSecret = String(body.loginSecret || "");
      const user = await getUser(username);

      if (!user || hashLoginSecret(loginSecret, user.loginSalt) !== user.loginHash) {
        json(res, 401, { error: "Wrong username or password." });
        return;
      }

      const token = createSessionToken(username);
      json(res, 200, {
        username,
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt || "",
        vault: user.vault,
        wrappedKey: user.wrappedKey || null,
        recoveryWrappedKey: user.recoveryWrappedKey || null
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/recover") {
      const body = await readJson(req);
      const username = normalizeUsername(body.username);
      const loginSecret = String(body.loginSecret || "");
      const user = await getUser(username);

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

      await updateUserLogin(username, loginSecret, body.wrappedKey);
      const updated = await getUser(username);
      const token = createSessionToken(username);
      json(res, 200, {
        username,
        clientSalt: updated.clientSalt,
        recoverySalt: updated.recoverySalt || "",
        vault: updated.vault,
        wrappedKey: updated.wrappedKey || null,
        recoveryWrappedKey: updated.recoveryWrappedKey || null
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
        username: auth.username,
        clientSalt: auth.user.clientSalt,
        recoverySalt: auth.user.recoverySalt || "",
        vault: auth.user.vault,
        wrappedKey: auth.user.wrappedKey || null,
        recoveryWrappedKey: auth.user.recoveryWrappedKey || null
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
      await updateUserVault(auth.username, body.vault);
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

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname);
    return;
  }
  await serveStatic(req, res, url.pathname);
}

if (require.main === module) {
  const server = http.createServer(handleRequest);

  setInterval(cleanRateBuckets, 5 * 60 * 1000).unref();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Mind Archive running on http://localhost:${PORT}`);
  });
}

module.exports = handleRequest;
module.exports.handleRequest = handleRequest;

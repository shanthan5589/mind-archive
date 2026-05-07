const crypto = require("crypto");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");

const {
  ROOT, PORT, SESSION_COOKIE, SESSION_SECRET,
  configErrors, gzip, brotliCompress, pool,
  PUBLIC_POST_LIMIT, PUBLIC_BODY_LIMIT, RESEND_API_KEY, EMAIL_FROM
} = require("./lib/config");
const { normalizeEmail, isValidEmail, escapeXml, escapeHtml, randomToken, hashLoginSecret } = require("./lib/utils");
const {
  getUser, createUser, ensureFeedId, updateUserVault, updateUserLogin, updateUserProfile,
  getPublicFeed, setPublicPosts, getSubscriptions, getSubscribedPosts,
  subscribeToFeed, unsubscribeByToken, parseFeedId
} = require("./lib/db");
const { notifyFeedSubscribers, scheduleEmailQueue, processEmailQueue } = require("./lib/email");

const RATE_LIMITS = {
  auth: { windowMs: 15 * 60 * 1000, max: 20 },
  write: { windowMs: 60 * 1000, max: 60 },
  general: { windowMs: 60 * 1000, max: 180 }
};

const rateBuckets = new Map();
const sessionCache = new Map();
const feedXmlCache = new Map();

// --- HTTP helpers ---

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

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

// --- Rate limiting ---

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

  return { ok: false, retryAfter: Math.ceil((bucket.resetAt - now) / 1000) };
}

function cleanRateBuckets() {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets.entries()) {
    if (now > bucket.resetAt) rateBuckets.delete(key);
  }
  for (const [key, entry] of sessionCache.entries()) {
    if (now > entry.expiresAt) sessionCache.delete(key);
  }
}

// --- Static asset serving ---

let indexCache = null;

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
    br: await brotliCompress(body, { params: { [require("zlib").constants.BROTLI_PARAM_QUALITY]: 5 } }),
    gzip: await gzip(body, { level: 6 }),
    etag: `W/"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`,
    mtimeMs: stat.mtimeMs,
    size: stat.size
  };
  return indexCache;
}

async function serveStatic(req, res) {
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
    if (req.method === "HEAD") { res.end(); return; }
    res.end(body);
  } catch (error) {
    text(res, error.statusCode || 404, error.message || "Not found");
  }
}

// --- Session helpers ---

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

// --- Request / validation helpers ---

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

// --- Auth middleware ---

async function requireUser(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const email = verifySessionToken(token);
  if (!email) {
    json(res, 401, { error: "Not signed in." });
    return null;
  }
  const cacheKey = token.slice(-32);
  const cached = sessionCache.get(cacheKey);
  if (cached && cached.email === email && Date.now() < cached.expiresAt) {
    return { email, user: cached.user };
  }
  const user = await getUser(email);
  if (!user) {
    json(res, 401, { error: "Session no longer exists." }, clearSessionHeaders());
    sessionCache.delete(cacheKey);
    return null;
  }
  await ensureFeedId(email, user);
  sessionCache.set(cacheKey, { email, user, expiresAt: Date.now() + 2 * 60 * 1000 });
  return { email, user };
}

// --- RSS feed rendering ---

function renderPublicFeedXml(req, feedId, publicFeed, ownerName = "") {
  const origin = `${isHttps(req) ? "https" : "http"}://${req.headers.host || "localhost"}`;
  const feedUrl = `${origin}/feed/${encodeURIComponent(feedId)}.xml`;
  const feedTitle = ownerName ? `${ownerName}'s Archive` : "Mind Archive";
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
  <title>${escapeXml(feedTitle)}</title>
  <link>${escapeXml(feedUrl)}</link>
  <description>Shared thoughts and opinions</description>
  <lastBuildDate>${new Date(publicFeed.updatedAt || Date.now()).toUTCString()}</lastBuildDate>${items}
</channel>
</rss>`;
}

// --- Request handlers ---

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
    const ownerName = [record.firstName || "", record.lastName || ""].filter(Boolean).join(" ");
    const body = renderPublicFeedXml(req, feedId, record.publicFeed, ownerName);
    cached = {
      body,
      etag: `W/"${crypto.createHash("sha256").update(body).digest("base64url").slice(0, 24)}"`,
      updatedAt
    };
    feedXmlCache.set(cacheKey, cached);
  }

  if (req.headers["if-none-match"] === cached.etag) {
    res.writeHead(304, securityHeaders({ "cache-control": "public, max-age=60", etag: cached.etag }));
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
  if (req.method === "HEAD") { res.end(); return; }
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

async function handleApi(req, res, pathname) {
  try {
    if (configErrors.length) {
      const status = pathname === "/api/health" ? 503 : 500;
      json(res, status, { ok: false, error: "Server is missing required production configuration.", details: configErrors });
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
      const firstName = String(body.firstName || "").trim().slice(0, 80);
      const lastName = String(body.lastName || "").trim().slice(0, 80);

      if (!firstName) { json(res, 400, { error: "First name is required." }); return; }
      if (!lastName) { json(res, 400, { error: "Last name is required." }); return; }
      if (!isValidEmail(email)) { json(res, 400, { error: "Enter a valid email address." }); return; }
      if (loginSecret.length < 32) { json(res, 400, { error: "Missing login verifier." }); return; }
      if (!validateVault(body.vault)) { json(res, 400, { error: "Missing encrypted vault." }); return; }
      if (!validateWrappedKey(body.wrappedKey) || !validateWrappedKey(body.recoveryWrappedKey)) {
        json(res, 400, { error: "Missing recovery metadata." });
        return;
      }

      if (await getUser(email)) { json(res, 409, { error: "That email already has an archive." }); return; }

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
        firstName,
        lastName,
        createdAt: new Date().toISOString()
      };
      try {
        await createUser(email, user);
      } catch (error) {
        if (error.code === "USER_EXISTS") { json(res, 409, { error: "That email already has an archive." }); return; }
        throw error;
      }

      const token = createSessionToken(email);
      json(res, 201, {
        email,
        firstName: user.firstName,
        lastName: user.lastName,
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
      if (!user) { json(res, 404, { error: "Wrong email or password." }); return; }
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
        firstName: user.firstName || "",
        lastName: user.lastName || "",
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

      if (!user || loginSecret.length < 32) { json(res, 401, { error: "Recovery failed." }); return; }
      if (!validateWrappedKey(body.wrappedKey) || !validateWrappedKey(body.recoveryWrappedKey)) {
        json(res, 400, { error: "Missing recovery metadata." });
        return;
      }
      if (JSON.stringify(body.recoveryWrappedKey) !== JSON.stringify(user.recoveryWrappedKey || null)) {
        json(res, 401, { error: "Recovery failed." });
        return;
      }

      await updateUserLogin(email, loginSecret, body.wrappedKey);
      const token = createSessionToken(email);
      const feedId = await ensureFeedId(email, user);
      json(res, 200, {
        email,
        firstName: user.firstName || "",
        lastName: user.lastName || "",
        clientSalt: user.clientSalt,
        recoverySalt: user.recoverySalt || "",
        vault: user.vault,
        wrappedKey: body.wrappedKey,
        recoveryWrappedKey: user.recoveryWrappedKey || null,
        feedId
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/logout") {
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(token.slice(-32));
      json(res, 200, { ok: true }, clearSessionHeaders());
      return;
    }

    if (req.method === "GET" && pathname === "/api/session") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, {
        email: auth.email,
        firstName: auth.user.firstName || "",
        lastName: auth.user.lastName || "",
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

    if (req.method === "GET" && pathname === "/api/subscribed-posts") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, { posts: await getSubscribedPosts(auth.email) });
      return;
    }

    if (req.method === "POST" && pathname === "/api/subscribe-feed") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      const feedId = parseFeedId(body.feedUrl || body.feedId);
      if (!feedId) { json(res, 400, { error: "Paste a valid RSS feed URL." }); return; }
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
      const newPosts = await setPublicPosts(auth.email, auth.user.feedId, posts);
      feedXmlCache.delete(auth.user.feedId);
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
      if (!validateVault(body.vault)) { json(res, 400, { error: "Invalid encrypted vault." }); return; }
      await updateUserVault(auth.email, body.vault);
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(token.slice(-32));
      json(res, 200, { ok: true });
      return;
    }

    if (req.method === "PUT" && pathname === "/api/account") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      const firstName = String(body.firstName || "").trim().slice(0, 80);
      const lastName = String(body.lastName || "").trim().slice(0, 80);
      if (!firstName) { json(res, 400, { error: "First name is required." }); return; }
      if (!lastName) { json(res, 400, { error: "Last name is required." }); return; }
      await updateUserProfile(auth.email, firstName, lastName);
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(token.slice(-32));
      json(res, 200, { ok: true, firstName, lastName });
      return;
    }

    json(res, 404, { error: "Not found." });
  } catch (error) {
    json(res, error.statusCode || 500, { error: error.message || "Server error." });
  }
}

const STATIC_FILES = {
  "/favicon-16.png": { file: "favicon-16.png", type: "image/png" },
  "/favicon-32.png": { file: "favicon-32.png", type: "image/png" },
  "/favicon-192.png": { file: "favicon-192.png", type: "image/png" },
  "/apple-touch-icon.png": { file: "apple-touch-icon.png", type: "image/png" }
};

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname);
    return;
  }
  const staticFile = STATIC_FILES[url.pathname];
  if (staticFile) {
    if (req.method !== "GET" && req.method !== "HEAD") { text(res, 405, "Method not allowed"); return; }
    try {
      const body = await fs.readFile(path.join(ROOT, staticFile.file));
      res.writeHead(200, securityHeaders({ "content-type": staticFile.type, "cache-control": "public, max-age=31536000, immutable", "content-length": String(body.length) }));
      if (req.method !== "HEAD") res.end(body);
      else res.end();
    } catch { text(res, 404, "Not found"); }
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
  await serveStatic(req, res);
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

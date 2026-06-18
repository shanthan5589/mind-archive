const crypto = require("crypto");
const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const { constants: zlibConstants } = require("zlib");

const {
  ROOT, PORT, SESSION_COOKIE, SESSION_SECRET,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
  RESEND_API_KEY, EMAIL_FROM, APP_URL,
  configErrors, gzip, brotliCompress, pool
} = require("./lib/config");
const { normalizeEmail, isValidEmail, escapeHtml, randomToken, hashLoginSecret } = require("./lib/utils");
const {
  getUser, getUserByGoogleId, createUser, linkGoogleId,
  ensureFeedId, updateUserVault, updateUserProfile
} = require("./lib/db");

const SESSION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

const RATE_LIMITS = {
  auth: { windowMs: 15 * 60 * 1000, max: 20 },
  write: { windowMs: 60 * 1000, max: 60 },
  general: { windowMs: 60 * 1000, max: 180 }
};

const rateBuckets = new Map();
const sessionCache = new Map();

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
  if (pathname === "/api/signup" || pathname === "/api/signin") return "auth";
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
    br: await brotliCompress(body, { params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 5 } }),
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
    exp: Date.now() + SESSION_EXPIRY_MS,
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
    if (body.length > 5_000_000) { const e = new Error("Request body is too large."); e.statusCode = 400; throw e; }
  }
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    const e = new Error("Invalid request body.");
    e.statusCode = 400;
    throw e;
  }
}

function isValidVault(v) {
  return Array.isArray(v) && JSON.stringify(v).length < 4_500_000;
}

// --- Auth middleware ---

const sessionCacheKey = (token) => token.slice(-32);

function parseNames(body, res) {
  const firstName = String(body.firstName || "").trim().slice(0, 80);
  const lastName = String(body.lastName || "").trim().slice(0, 80);
  if (!firstName) { json(res, 400, { error: "First name is required." }); return null; }
  if (!lastName) { json(res, 400, { error: "Last name is required." }); return null; }
  return { firstName, lastName };
}

async function requireUser(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  const email = verifySessionToken(token);
  if (!email) {
    json(res, 401, { error: "Not signed in." });
    return null;
  }
  const key = sessionCacheKey(token);
  const cached = sessionCache.get(key);
  if (cached && cached.email === email && Date.now() < cached.expiresAt) {
    return { email, user: cached.user };
  }
  const user = await getUser(email);
  if (!user) {
    json(res, 401, { error: "Session no longer exists." }, clearSessionHeaders());
    sessionCache.delete(key);
    return null;
  }
  await ensureFeedId(email, user);
  sessionCache.set(key, { email, user, expiresAt: Date.now() + 2 * 60 * 1000 });
  return { email, user };
}

// --- AI proxy ---

const GROQ_API_KEY = process.env.GROQ_API_KEY || "";
const GROQ_MODEL = "llama-3.3-70b-versatile";
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";

const AI_MAX_TOKENS = {
  suggest: 25, continue: 300, rephrase: 250, grammar: 1200,
  spark: 120, brainstorm: 220, digest: 350, insight: 250, onthisday: 100
};

function buildAiPrompt(feature, payload) {
  const t = (s, max) => String(s || "").slice(0, max);
  switch (feature) {
    case "suggest":
      return `You are an inline writing assistant for a personal journal.
Suggest the single most natural next 3-6 words to continue the text.
Rules:
- Match the writer's voice, tense, and topic precisely
- Never repeat phrases or fragments already present in the text
- Never return partial words or word fragments
- Do not start a new idea or add dramatic emotion
- If nothing natural fits, return nothing at all — silence is better than a bad suggestion
Return only whole words. No quotes, no punctuation at the end unless it flows naturally.

Text:
${t(payload.tail, 800)}`;
    case "continue":
      return `This is a personal journal entry. Continue it naturally with a new paragraph (around 100-150 words). Same voice, same train of thought. Return only the new paragraph, no preamble:\n\n${t(payload.body, 5000)}`;
    case "rephrase":
      return `Rewrite the following sentence or passage 3 different ways. Same meaning, different phrasing. Keep the personal, reflective journal tone. Return only the 3 alternatives, one per line, no numbering or labels:\n\n${t(payload.text, 600)}`;
    case "grammar":
      return `Fix the grammar, spelling, and punctuation in the following text. Keep every idea, fact, and detail exactly as written — do not add, remove, or rephrase the content. Only correct errors. Return only the corrected text, nothing else:\n\n${t(payload.text, 2000)}`;
    case "spark":
      return `Based on these recent journal entries, write ONE specific journaling question that would help this person reflect further on their life right now. Make it personal, not generic.
If a previous question is provided, choose a clearly different emotional angle, topic, time horizon, or perspective. Do not rephrase the previous question.
Return only the question.

Previous question to avoid:
${t(payload.previous, 500) || "(none)"}

Variety cue:
${t(payload.variety, 80)}

Recent entries:
${t(payload.context, 4000)}`;
    case "brainstorm":
      return `Give 5 different angles or aspects someone could explore when journaling about: ${t(payload.topic, 200)}. One per line, 8-12 words each. No preamble, no numbering.`;
    case "digest":
      return `You are reading someone's private journal. Summarize these entries from the past 7 days in 3-4 warm, observational sentences. Focus on themes and emotional arc. Address the writer as "you". Be personal, not clinical:\n\n${t(payload.entries, 8000)}`;
    case "insight":
      return `Based only on these journal entry titles and opening lines, identify 3-4 recurring themes in this person's life. Be specific and personal. Format as brief bullet points, one per line, no preamble:\n\n${t(payload.entries, 7000)}`;
    case "onthisday":
      return `In one warm sentence, note what's interesting about returning to these journal entries written on this date in past years. Focus on continuity or growth. Just the sentence:\n\n${t(payload.entries, 2500)}`;
    default:
      return null;
  }
}

// --- Google OAuth helpers ---

function generateOAuthState() {
  const nonce = randomToken(16);
  const ts = Date.now().toString(36);
  const data = `${nonce}.${ts}`;
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verifyOAuthState(state) {
  if (!state || typeof state !== "string") return false;
  const last = state.lastIndexOf(".");
  const prev = state.lastIndexOf(".", last - 1);
  if (last === -1 || prev === -1) return false;
  const data = state.slice(0, last);
  const sig = state.slice(last + 1);
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
  if (sig.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)); } catch { return false; }
}

function googleAuthUrl(state) {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    access_type: "online",
    state
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

async function exchangeGoogleCode(code) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: "authorization_code"
    }),
    signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) throw new Error("Failed to exchange Google code.");
  return res.json();
}

async function getGoogleUserInfo(accessToken) {
  const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) throw new Error("Failed to get Google user info.");
  return res.json();
}

// --- Welcome email ---

async function sendWelcomeEmail(email, firstName) {
  if (!RESEND_API_KEY || !EMAIL_FROM) return;
  const name = firstName || "there";
  const html = `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;color:#1a1a1a;line-height:1.7;font-size:15px">
      <p style="margin:0 0 20px">Hi ${escapeHtml(name)},</p>
      <p style="margin:0 0 20px">This isn't an app that wants your attention. It doesn't have a feed, a follower count, or a reason to keep you scrolling. It's just a place to put your thoughts down and come back to them when you need to.</p>
      <p style="margin:0 0 20px">Some days you'll write a lot. Some days a single line. Some days nothing at all — and that's fine too. There's no streak to protect here. Your entries are yours. Only yours. Nobody else will read them, recommend them, or react to them. Just you, your words, and time.</p>
      <p style="margin:0 0 20px">Various AI tools have been deeply integrated into this product to give you more ways to write and reflect.</p>
      <p style="margin:0 0 20px">I built this because I wanted a place to express myself without any judgement. I hope this becomes a place for you to open up and be yourself.</p>
      <p style="margin:0 0 20px">If anything feels off or you just want to share feedback, drop me a mail at <a href="mailto:shanthan.yxo@gmail.com" style="color:#1a1a1a">shanthan.yxo@gmail.com</a>. I'd love to hear from you.</p>
      <p style="margin:0">— Shanthan</p>
    </div>
  `;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: EMAIL_FROM, to: email, subject: "Some thoughts aren't meant to be shared 🌿", html }),
    signal: AbortSignal.timeout(8000)
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    console.error(`[welcome-email] Resend error ${res.status} for ${email}: ${body}`);
  }
}

// --- Request handlers ---

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
      const password = String(body.password || "");
      const names = parseNames(body, res);
      if (!names) return;
      const { firstName, lastName } = names;

      if (!isValidEmail(email)) { json(res, 400, { error: "Enter a valid email address." }); return; }
      if (password.length < 8) { json(res, 400, { error: "Password must be at least 8 characters." }); return; }
      if (await getUser(email)) { json(res, 409, { error: "That email already has an account." }); return; }

      const passwordSalt = randomToken(18);
      const passwordHash = await hashLoginSecret(password, passwordSalt);
      const user = {
        passwordSalt,
        passwordHash,
        googleId: null,
        vault: [],
        feedId: randomToken(16),
        firstName,
        lastName
      };
      try {
        await createUser(email, user);
      } catch (error) {
        if (error.code === "USER_EXISTS") { json(res, 409, { error: "That email already has an account." }); return; }
        throw error;
      }

      await sendWelcomeEmail(email, user.firstName).catch((err) => console.error("[welcome-email] signup error:", err));
      const token = createSessionToken(email);
      json(res, 201, {
        email,
        firstName: user.firstName,
        lastName: user.lastName,
        vault: [],
        feedId: user.feedId
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/signin") {
      const body = await readJson(req);
      const email = normalizeEmail(body.email);
      const password = String(body.password || "");
      const user = await getUser(email);

      if (!user || !user.passwordHash || await hashLoginSecret(password, user.passwordSalt) !== user.passwordHash) {
        json(res, 401, { error: "Wrong email or password." });
        return;
      }

      const token = createSessionToken(email);
      json(res, 200, {
        email,
        firstName: user.firstName || "",
        lastName: user.lastName || "",
        vault: Array.isArray(user.vault) ? user.vault : [],
        feedId: await ensureFeedId(email, user)
      }, sessionHeaders(req, token));
      return;
    }

    if (req.method === "POST" && pathname === "/api/logout") {
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(sessionCacheKey(token));
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
        vault: Array.isArray(auth.user.vault) ? auth.user.vault : [],
        feedId: auth.user.feedId
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/vault") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, { vault: Array.isArray(auth.user.vault) ? auth.user.vault : [] });
      return;
    }

    if (req.method === "PUT" && pathname === "/api/vault") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      if (!isValidVault(body.vault)) { json(res, 400, { error: "Invalid vault." }); return; }
      await updateUserVault(auth.email, body.vault);
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(sessionCacheKey(token));
      json(res, 200, { ok: true });
      return;
    }

    if (req.method === "PUT" && pathname === "/api/account") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      const body = await readJson(req);
      const names = parseNames(body, res);
      if (!names) return;
      const { firstName, lastName } = names;
      await updateUserProfile(auth.email, firstName, lastName);
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) sessionCache.delete(sessionCacheKey(token));
      json(res, 200, { ok: true, firstName, lastName });
      return;
    }

    // --- Google OAuth ---

    if (req.method === "GET" && pathname === "/api/auth/google") {
      if (!GOOGLE_CLIENT_ID) { text(res, 503, "Google OAuth not configured."); return; }
      const oauthState = generateOAuthState();
      res.writeHead(302, { location: googleAuthUrl(oauthState), "set-cookie": `oauth_state=${oauthState}; HttpOnly; SameSite=Lax; Max-Age=300${isHttps(req) ? "; Secure" : ""}` });
      res.end();
      return;
    }

    if (req.method === "GET" && pathname === "/api/auth/google/callback") {
      if (!GOOGLE_CLIENT_ID) { text(res, 503, "Google OAuth not configured."); return; }
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      const cookieState = parseCookies(req)["oauth_state"];
      if (!code) { text(res, 400, "Missing code."); return; }
      if (!verifyOAuthState(returnedState) || returnedState !== cookieState) { text(res, 400, "Invalid OAuth state."); return; }

      try {
        const tokens = await exchangeGoogleCode(code);
        const info = await getGoogleUserInfo(tokens.access_token);
        const googleId = String(info.sub || "");
        const email = normalizeEmail(info.email || "");
        if (!googleId || !email) { text(res, 400, "Invalid Google account."); return; }

        let user = await getUserByGoogleId(googleId);
        if (!user) {
          user = await getUser(email);
          if (user) {
            await linkGoogleId(email, googleId);
            user.googleId = googleId;
          } else {
            const newUser = {
              passwordSalt: null,
              passwordHash: null,
              googleId,
              vault: [],
              feedId: randomToken(16),
              firstName: String(info.given_name || "").slice(0, 80),
              lastName: String(info.family_name || "").slice(0, 80)
            };
            let isNewUser = true;
            try {
              await createUser(email, newUser);
            } catch (err) {
              if (err.code !== "USER_EXISTS") throw err;
              isNewUser = false;
            }
            user = await getUser(email);
            if (isNewUser) await sendWelcomeEmail(email, newUser.firstName).catch((err) => console.error("[welcome-email] google signup error:", err));
          }
        }

        const token = createSessionToken(email);
        res.writeHead(302, {
          location: "/",
          ...sessionHeaders(req, token)
        });
        res.end();
      } catch (err) {
        text(res, 500, err.message || "Google sign-in failed.");
      }
      return;
    }

    // --- AI proxy ---

    if (req.method === "GET" && pathname === "/api/ai/status") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      json(res, 200, { ok: Boolean(GROQ_API_KEY) });
      return;
    }

    if (req.method === "POST" && pathname === "/api/ai") {
      const auth = await requireUser(req, res);
      if (!auth) return;
      if (!GROQ_API_KEY) { json(res, 503, { error: "AI features not configured." }); return; }
      const body = await readJson(req);
      const feature = String(body.feature || "");
      const prompt = buildAiPrompt(feature, body.payload || {});
      if (!prompt) { json(res, 400, { error: "Unknown AI feature." }); return; }
      const groqRes = await fetch(GROQ_API_URL, {
        method: "POST",
        headers: { "Authorization": `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: GROQ_MODEL,
          messages: [{ role: "user", content: prompt }],
          max_tokens: AI_MAX_TOKENS[feature] || 200,
          temperature: feature === "suggest" ? 0.15 : 0.7
        }),
        signal: AbortSignal.timeout(15000)
      });
      if (!groqRes.ok) {
        const errBody = await groqRes.json().catch(() => ({}));
        json(res, 502, { error: errBody.error?.message || "AI request failed." });
        return;
      }
      const groqData = await groqRes.json();
      const text = groqData.choices?.[0]?.message?.content || "";
      json(res, 200, { text: text.trim(), usage: groqData.usage || null });
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
  await serveStatic(req, res);
}

setInterval(cleanRateBuckets, 5 * 60 * 1000).unref();

if (require.main === module) {
  const server = http.createServer(handleRequest);

  server.listen(PORT, "0.0.0.0", () => {
    const port = server.address().port;
    console.log(`Mind Archive running on http://localhost:${port}`);
  });
}

module.exports = handleRequest;

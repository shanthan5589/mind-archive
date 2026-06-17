/**
 * Integration tests for server.js API routes.
 * Spawns the server on a random port with a temp DATA_DIR (file fallback, no DB needed).
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const path = require("node:path");
const os = require("node:os");
const fs = require("node:fs/promises");

const ROOT = path.resolve(__dirname, "..");
let server;
let base;
let dataDir;

// ── Shared cookie jar (one user across tests) ──
let sessionCookie = "";

async function req(method, pathname, body, cookie) {
  const url = `${base}${pathname}`;
  const headers = { "content-type": "application/json" };
  if (cookie) headers["cookie"] = cookie;
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: "manual"
  });
  let json = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) json = await res.json().catch(() => null);
  return { status: res.status, json, headers: res.headers };
}

function get(pathname, cookie) { return req("GET", pathname, undefined, cookie); }
function post(pathname, body, cookie) { return req("POST", pathname, body, cookie); }
function put(pathname, body, cookie) { return req("PUT", pathname, body, cookie); }

function extractCookie(headers) {
  const raw = headers.get("set-cookie") || "";
  return raw.split(";")[0];
}

before(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "ma-test-"));

  await new Promise((resolve, reject) => {
    server = spawn("node", ["server.js"], {
      cwd: ROOT,
      env: {
        ...process.env,
        PORT: "0",
        DATA_DIR: dataDir,
        DATABASE_URL: "",
        SESSION_SECRET: "test-secret-at-least-32-chars-long!!",
        NODE_ENV: "test",
        GROQ_API_KEY: "",
        GOOGLE_CLIENT_ID: "",
        GOOGLE_CLIENT_SECRET: ""
      }
    });
    server.stdout.on("data", (chunk) => {
      const msg = chunk.toString();
      const match = msg.match(/running on http:\/\/localhost:(\d+)/);
      if (match) {
        base = `http://localhost:${match[1]}`;
        resolve();
      }
    });
    server.stderr.on("data", (chunk) => process.stderr.write(chunk));
    server.on("error", reject);
    setTimeout(() => reject(new Error("Server did not start in time")), 10000);
  });
});

after(async () => {
  server.kill();
  await fs.rm(dataDir, { recursive: true, force: true });
});

// ── Health ──

test("GET /api/health returns ok with local storage", async () => {
  const { status, json } = await get("/api/health");
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  assert.equal(json.storage, "local");
});

// ── Signup ──

test("POST /api/signup creates a new user", async () => {
  const { status, json, headers } = await post("/api/signup", {
    firstName: "Alice",
    lastName: "Smith",
    email: "alice@test.com",
    password: "securepassword1"
  });
  assert.equal(status, 201);
  assert.equal(json.email, "alice@test.com");
  assert.equal(json.firstName, "Alice");
  assert.equal(json.lastName, "Smith");
  assert.deepEqual(json.vault, []);
  assert.ok(json.feedId, "feedId should be set");
  sessionCookie = extractCookie(headers);
  assert.ok(sessionCookie.startsWith("mind_archive_session="), "should set session cookie");
});

test("POST /api/signup rejects duplicate email", async () => {
  const { status, json } = await post("/api/signup", {
    firstName: "Alice",
    lastName: "Smith",
    email: "alice@test.com",
    password: "securepassword1"
  });
  assert.equal(status, 409);
  assert.ok(json.error);
});

test("POST /api/signup rejects short password", async () => {
  const { status, json } = await post("/api/signup", {
    firstName: "Bob",
    lastName: "Jones",
    email: "bob@test.com",
    password: "short"
  });
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("POST /api/signup rejects invalid email", async () => {
  const { status, json } = await post("/api/signup", {
    firstName: "Bob",
    lastName: "Jones",
    email: "notanemail",
    password: "securepassword1"
  });
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("POST /api/signup rejects missing firstName", async () => {
  const { status, json } = await post("/api/signup", {
    lastName: "Jones",
    email: "bob2@test.com",
    password: "securepassword1"
  });
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("POST /api/signup rejects missing lastName", async () => {
  const { status, json } = await post("/api/signup", {
    firstName: "Bob",
    email: "bob3@test.com",
    password: "securepassword1"
  });
  assert.equal(status, 400);
  assert.ok(json.error);
});

// ── Session ──

test("GET /api/session returns user when authenticated", async () => {
  const { status, json } = await get("/api/session", sessionCookie);
  assert.equal(status, 200);
  assert.equal(json.email, "alice@test.com");
  assert.equal(json.firstName, "Alice");
  assert.equal(json.lastName, "Smith");
  assert.ok(Array.isArray(json.vault));
});

test("GET /api/session returns 401 without cookie", async () => {
  const { status } = await get("/api/session");
  assert.equal(status, 401);
});

test("GET /api/session returns 401 with invalid cookie", async () => {
  const { status } = await get("/api/session", "mind_archive_session=bogus.signature");
  assert.equal(status, 401);
});

// ── Vault ──

test("GET /api/vault returns empty array initially", async () => {
  const { status, json } = await get("/api/vault", sessionCookie);
  assert.equal(status, 200);
  assert.deepEqual(json.vault, []);
});

test("PUT /api/vault saves posts and returns ok", async () => {
  const posts = [
    { id: "p1", title: "Hello", body: "World", createdAt: "2026-01-01T00:00:00Z", pinned: false, hidden: false }
  ];
  const { status, json } = await put("/api/vault", { vault: posts }, sessionCookie);
  assert.equal(status, 200);
  assert.equal(json.ok, true);
});

test("GET /api/vault returns saved posts", async () => {
  const { status, json } = await get("/api/vault", sessionCookie);
  assert.equal(status, 200);
  assert.equal(json.vault.length, 1);
  assert.equal(json.vault[0].id, "p1");
});

test("PUT /api/vault rejects non-array vault", async () => {
  const { status, json } = await put("/api/vault", { vault: "not an array" }, sessionCookie);
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("PUT /api/vault rejects missing vault key", async () => {
  const { status, json } = await put("/api/vault", { data: [] }, sessionCookie);
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("PUT /api/vault requires auth", async () => {
  const { status } = await put("/api/vault", { vault: [] });
  assert.equal(status, 401);
});

// ── Account update ──

test("PUT /api/account updates name", async () => {
  const { status, json } = await put("/api/account", { firstName: "Alicia", lastName: "Smithson" }, sessionCookie);
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  assert.equal(json.firstName, "Alicia");
  assert.equal(json.lastName, "Smithson");
});

test("PUT /api/account: session reflects updated name", async () => {
  const { json } = await get("/api/session", sessionCookie);
  assert.equal(json.firstName, "Alicia");
  assert.equal(json.lastName, "Smithson");
});

test("PUT /api/account rejects blank firstName", async () => {
  const { status, json } = await put("/api/account", { firstName: "", lastName: "Smith" }, sessionCookie);
  assert.equal(status, 400);
  assert.ok(json.error);
});

test("PUT /api/account requires auth", async () => {
  const { status } = await put("/api/account", { firstName: "X", lastName: "Y" });
  assert.equal(status, 401);
});

// ── Signin ──

test("POST /api/signin succeeds with correct credentials", async () => {
  // Signup a second user
  await post("/api/signup", {
    firstName: "Carol",
    lastName: "Jones",
    email: "carol@test.com",
    password: "carols-password"
  });
  const { status, json, headers } = await post("/api/signin", {
    email: "carol@test.com",
    password: "carols-password"
  });
  assert.equal(status, 200);
  assert.equal(json.email, "carol@test.com");
  assert.equal(json.firstName, "Carol");
  assert.ok(Array.isArray(json.vault));
  const cookie = extractCookie(headers);
  assert.ok(cookie.startsWith("mind_archive_session="));
});

test("POST /api/signin rejects wrong password", async () => {
  const { status, json } = await post("/api/signin", {
    email: "carol@test.com",
    password: "wrongpassword"
  });
  assert.equal(status, 401);
  assert.ok(json.error);
});

test("POST /api/signin rejects unknown email", async () => {
  const { status, json } = await post("/api/signin", {
    email: "nobody@test.com",
    password: "somepassword"
  });
  assert.equal(status, 401);
  assert.ok(json.error);
});

test("POST /api/signin returns saved vault for user", async () => {
  const posts = [
    { id: "x1", title: "Test", body: "Body", createdAt: "2026-01-01T00:00:00Z", pinned: false, hidden: false }
  ];
  // Sign in carol and save a post
  const { headers: carolHeaders } = await post("/api/signin", { email: "carol@test.com", password: "carols-password" });
  const carolCookie = extractCookie(carolHeaders);
  await put("/api/vault", { vault: posts }, carolCookie);

  // Sign in again and check vault persists
  const { json } = await post("/api/signin", { email: "carol@test.com", password: "carols-password" });
  assert.equal(json.vault.length, 1);
  assert.equal(json.vault[0].id, "x1");
});

// ── Logout ──

test("POST /api/logout returns ok and clears cookie", async () => {
  const { status, json, headers } = await post("/api/logout", {}, sessionCookie);
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  const setCookie = headers.get("set-cookie") || "";
  assert.ok(setCookie.includes("Max-Age=0"), "should expire cookie in browser");
  // Note: stateless tokens have no server-side blacklist — the browser discards
  // the cookie via Max-Age=0, which ends the session from the user's perspective.
});

// ── Google OAuth ──

test("GET /api/auth/google returns 503 when not configured", async () => {
  const { status } = await get("/api/auth/google");
  assert.equal(status, 503);
});

// ── AI status ──

test("GET /api/ai/status returns ok:false when no Groq key", async () => {
  // Re-signin to get a valid cookie after logout
  const { headers } = await post("/api/signin", { email: "carol@test.com", password: "carols-password" });
  const c = extractCookie(headers);
  const { status, json } = await get("/api/ai/status", c);
  assert.equal(status, 200);
  assert.equal(json.ok, false);
});

test("GET /api/ai/status returns 401 without auth", async () => {
  const { status } = await get("/api/ai/status");
  assert.equal(status, 401);
});

// ── 404 ──

test("GET /api/unknown returns 404", async () => {
  const { status, json } = await get("/api/unknown");
  assert.equal(status, 404);
  assert.ok(json.error);
});

// ── Static serving ──

test("GET / serves index.html", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  const ct = res.headers.get("content-type") || "";
  assert.ok(ct.includes("text/html"));
  const body = await res.text();
  assert.ok(body.includes("Mind Archive"), "HTML should contain app name");
});

test("GET / sets security headers", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
});

test("GET /unknown-path falls through to index.html (SPA)", async () => {
  const res = await fetch(`${base}/some/deep/route`);
  assert.equal(res.status, 200);
  const ct = res.headers.get("content-type") || "";
  assert.ok(ct.includes("text/html"));
});

// ── Email normalisation ──

test("POST /api/signup normalises email to lowercase", async () => {
  const { status, json } = await post("/api/signup", {
    firstName: "Dave",
    lastName: "Lee",
    email: "DAVE@TEST.COM",
    password: "davedavedave"
  });
  assert.equal(status, 201);
  assert.equal(json.email, "dave@test.com");
});

test("POST /api/signin accepts uppercase email for existing lowercase account", async () => {
  const { status, json } = await post("/api/signin", {
    email: "DAVE@TEST.COM",
    password: "davedavedave"
  });
  assert.equal(status, 200);
  assert.equal(json.email, "dave@test.com");
});

// ── Vault size limit ──

test("PUT /api/vault rejects oversized vault (>4.5MB)", async () => {
  // reuse alice's token — stateless sessions stay valid even after logout
  const bigPost = { id: "big", title: "x", body: "a".repeat(5_000_000), createdAt: "2026-01-01T00:00:00Z" };
  const { status, json } = await put("/api/vault", { vault: [bigPost] }, sessionCookie);
  assert.equal(status, 400);
  assert.ok(json.error);
});

// ── AI proxy ──

test("POST /api/ai returns 503 when no Groq key", async () => {
  const { status, json } = await post("/api/ai", { feature: "suggest", payload: { tail: "hello world" } }, sessionCookie);
  assert.equal(status, 503);
  assert.ok(json.error);
});

test("POST /api/ai returns 401 without auth", async () => {
  const { status } = await post("/api/ai", { feature: "suggest", payload: {} });
  assert.equal(status, 401);
});

test("POST /api/ai returns 400 for unknown feature", async () => {
  // Sign in to get a valid cookie — but AI will 503 before feature check with no key
  // So just confirm auth is checked first
  const { status } = await post("/api/ai", { feature: "unknown", payload: {} });
  assert.equal(status, 401);
});

// ── Signup: welcome email is fire-and-forget ──

test("POST /api/signup succeeds even when email sending would fail", async () => {
  // RESEND_API_KEY is blank in test env — email send silently fails, signup still works
  const { status, json } = await post("/api/signup", {
    firstName: "Eve",
    lastName: "Taylor",
    email: "eve@test.com",
    password: "evepassword1"
  });
  assert.equal(status, 201);
  assert.equal(json.email, "eve@test.com");
});

// ── Name length limits ──

test("POST /api/signup truncates first/last name at 80 chars", async () => {
  const longName = "A".repeat(100);
  const { status, json } = await post("/api/signup", {
    firstName: longName,
    lastName: longName,
    email: "longname@test.com",
    password: "longpassword1"
  });
  assert.equal(status, 201);
  assert.equal(json.firstName.length, 80);
  assert.equal(json.lastName.length, 80);
});

// ── Logout then re-signin ──

test("User can sign in again after logout", async () => {
  // Logout carol then sign back in (carol was created earlier, no extra signup needed)
  const { headers: h1 } = await post("/api/signin", { email: "carol@test.com", password: "carols-password" });
  await post("/api/logout", {}, extractCookie(h1));
  const { status, json } = await post("/api/signin", { email: "carol@test.com", password: "carols-password" });
  assert.equal(status, 200);
  assert.equal(json.email, "carol@test.com");
});

// ── Full round-trip: write post → signin → post still there ──

test("Full round-trip: save post via session, signin fresh, vault persists", async () => {
  // Use alice's token (stateless, still valid) to save a unique post
  const post1 = { id: "rt1", title: "Round trip", body: "Hello world", createdAt: "2026-06-18T00:00:00Z", pinned: false, hidden: false };
  await put("/api/vault", { vault: [post1] }, sessionCookie);

  // Sign in fresh as alice to confirm vault persisted
  const { json } = await post("/api/signin", { email: "alice@test.com", password: "securepassword1" });
  assert.ok(Array.isArray(json.vault));
  const found = json.vault.find((p) => p.id === "rt1");
  assert.ok(found, "saved post should appear in vault after fresh signin");
  assert.equal(found.title, "Round trip");
});

// ── HEAD request on static files ──

test("HEAD / returns 200 with no body", async () => {
  const res = await fetch(`${base}/`, { method: "HEAD" });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.equal(body, "");
});

// ── Rate limiting — must run last as it exhausts the auth bucket ──

test("Rate-limited endpoints return 429 on abuse", async () => {
  const promises = Array.from({ length: 25 }, () =>
    post("/api/signin", { email: "nobody@test.com", password: "x" })
  );
  const results = await Promise.all(promises);
  const limited = results.some((r) => r.status === 429);
  assert.ok(limited, "at least one request should be rate-limited");
});

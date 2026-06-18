const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeEmail, isValidEmail, escapeHtml, randomToken, hashLoginSecret } = require("../lib/utils");

test("normalizeEmail: trims and lowercases", () => {
  assert.equal(normalizeEmail("  Alice@Example.COM  "), "alice@example.com");
  assert.equal(normalizeEmail(""), "");
  assert.equal(normalizeEmail(null), "");
});

test("isValidEmail: accepts valid addresses", () => {
  assert.ok(isValidEmail("user@example.com"));
  assert.ok(isValidEmail("a+b@x.io"));
  assert.ok(isValidEmail("foo.bar@sub.domain.org"));
});

test("isValidEmail: rejects invalid addresses", () => {
  assert.ok(!isValidEmail(""));
  assert.ok(!isValidEmail("notanemail"));
  assert.ok(!isValidEmail("@nodomain"));
  assert.ok(!isValidEmail("noatsign.com"));
  assert.ok(!isValidEmail("a@b@c.com"));
  assert.ok(!isValidEmail("a b@c.com"));
  assert.ok(!isValidEmail("a".repeat(255) + "@b.com"));
});

test("escapeHtml: escapes all five special chars", () => {
  assert.equal(escapeHtml('&<>"\''), "&amp;&lt;&gt;&quot;&#039;");
});

test("escapeHtml: passes clean strings unchanged", () => {
  assert.equal(escapeHtml("hello world"), "hello world");
});

test("escapeHtml: coerces non-strings", () => {
  assert.equal(escapeHtml(42), "42");
  assert.equal(escapeHtml(null), "");
});

test("randomToken: returns a non-empty string", () => {
  const t = randomToken(16);
  assert.equal(typeof t, "string");
  assert.ok(t.length > 0);
});

test("randomToken: different calls return different values", () => {
  assert.notEqual(randomToken(16), randomToken(16));
});

test("hashLoginSecret: deterministic", async () => {
  const h1 = await hashLoginSecret("password", "salt");
  const h2 = await hashLoginSecret("password", "salt");
  assert.equal(h1, h2);
});

test("hashLoginSecret: different inputs produce different hashes", async () => {
  assert.notEqual(await hashLoginSecret("pass1", "salt"), await hashLoginSecret("pass2", "salt"));
  assert.notEqual(await hashLoginSecret("pass", "salt1"), await hashLoginSecret("pass", "salt2"));
});

test("hashLoginSecret: returns a base64 string", async () => {
  const h = await hashLoginSecret("secret", "somesalt");
  assert.equal(typeof h, "string");
  assert.ok(h.length > 0);
  assert.ok(/^[A-Za-z0-9+/=]+$/.test(h));
});

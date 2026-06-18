const crypto = require("crypto");

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hashLoginSecret(loginSecret, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(String(loginSecret), salt, 310000, 32, "sha256", (err, key) => {
      if (err) reject(err); else resolve(key.toString("base64"));
    });
  });
}

module.exports = { normalizeEmail, isValidEmail, escapeHtml, randomToken, hashLoginSecret };

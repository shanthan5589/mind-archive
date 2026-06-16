const fs = require("fs/promises");
const {
  pool, DB_TABLES, DATA_DIR, USERS_FILE
} = require("./config");
const { randomToken, hashLoginSecret } = require("./utils");

let ensureDataPromise = null;

async function ensureData() {
  if (ensureDataPromise) return ensureDataPromise;
  ensureDataPromise = _ensureData();
  return ensureDataPromise;
}

async function _ensureData() {
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
        first_name text,
        last_name text,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      );
      alter table ${DB_TABLES.users} add column if not exists feed_id text unique;
      alter table ${DB_TABLES.users} add column if not exists first_name text;
      alter table ${DB_TABLES.users} add column if not exists last_name text;
      create index if not exists idx_users_feed_id on ${DB_TABLES.users}(feed_id)
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

async function loadUsers() { return loadJsonFile(USERS_FILE); }
async function saveUsers(users) { await saveJsonFile(USERS_FILE, users); }

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
    firstName: row.first_name || "",
    lastName: row.last_name || "",
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
        `insert into ${DB_TABLES.users} (email, login_salt, login_hash, client_salt, recovery_salt, wrapped_key, recovery_wrapped_key, vault, feed_id, first_name, last_name)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          email,
          user.loginSalt,
          user.loginHash,
          user.clientSalt,
          user.recoverySalt || null,
          user.wrappedKey ? JSON.stringify(user.wrappedKey) : null,
          user.recoveryWrappedKey ? JSON.stringify(user.recoveryWrappedKey) : null,
          JSON.stringify(user.vault),
          user.feedId,
          user.firstName || null,
          user.lastName || null
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

async function updateUserProfile(email, firstName, lastName) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `update ${DB_TABLES.users} set first_name = $2, last_name = $3, updated_at = now() where email = $1`,
      [email, firstName, lastName]
    );
    return result.rowCount > 0;
  }
  const users = await loadUsers();
  if (!users[email]) return false;
  users[email].firstName = firstName;
  users[email].lastName = lastName;
  users[email].updatedAt = new Date().toISOString();
  await saveUsers(users);
  return true;
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

if (pool) ensureDataPromise = _ensureData();

module.exports = {
  ensureData,
  getUser, createUser, ensureFeedId, updateUserVault, updateUserLogin, updateUserProfile
};

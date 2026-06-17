const fs = require("fs/promises");
const {
  pool, DB_TABLES, DATA_DIR, USERS_FILE
} = require("./config");
const { randomToken, hashLoginSecret } = require("./utils");

const jsonOrNull = (val) => (val != null ? JSON.stringify(val) : null);

let ensureDataPromise = null;

async function ensureData() {
  if (ensureDataPromise) return ensureDataPromise;
  ensureDataPromise = _ensureData().catch(err => {
    ensureDataPromise = null;
    throw err;
  });
  return ensureDataPromise;
}

async function _ensureData() {
  if (pool) {
    await pool.query(`
      create table if not exists ${DB_TABLES.users} (
        email text primary key,
        password_salt text,
        password_hash text,
        google_id text unique,
        vault jsonb not null default '[]',
        feed_id text unique,
        first_name text,
        last_name text,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      );
      alter table ${DB_TABLES.users} add column if not exists password_salt text;
      alter table ${DB_TABLES.users} add column if not exists password_hash text;
      alter table ${DB_TABLES.users} add column if not exists google_id text;
      alter table ${DB_TABLES.users} add column if not exists feed_id text;
      alter table ${DB_TABLES.users} add column if not exists first_name text;
      alter table ${DB_TABLES.users} add column if not exists last_name text;
      alter table ${DB_TABLES.users} alter column vault set default '[]';
      alter table ${DB_TABLES.users} alter column vault drop not null;
      create index if not exists idx_users_feed_id on ${DB_TABLES.users}(feed_id);
      create unique index if not exists idx_users_google_id on ${DB_TABLES.users}(google_id) where google_id is not null
    `);
    // Drop NOT NULL from old columns that may exist from a previous schema version
    for (const col of ["login_salt", "login_hash", "client_salt"]) {
      try {
        await pool.query(`alter table ${DB_TABLES.users} alter column ${col} drop not null`);
      } catch { /* column doesn't exist on fresh installs — safe to ignore */ }
    }
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
    passwordSalt: row.password_salt || "",
    passwordHash: row.password_hash || "",
    googleId: row.google_id || "",
    vault: typeof row.vault === "string" ? JSON.parse(row.vault) : (row.vault ?? []),
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

async function getUserByGoogleId(googleId) {
  await ensureData();
  if (pool) {
    const result = await pool.query(`select * from ${DB_TABLES.users} where google_id = $1`, [googleId]);
    return rowToUser(result.rows[0]);
  }
  const users = await loadUsers();
  return Object.values(users).find((u) => u.googleId === googleId) || null;
}

async function createUser(email, user) {
  await ensureData();
  if (pool) {
    try {
      await pool.query(
        `insert into ${DB_TABLES.users} (email, password_salt, password_hash, google_id, vault, feed_id, first_name, last_name)
         values ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          email,
          user.passwordSalt || null,
          user.passwordHash || null,
          user.googleId || null,
          JSON.stringify(user.vault ?? []),
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

async function linkGoogleId(email, googleId) {
  await ensureData();
  if (pool) {
    await pool.query(
      `update ${DB_TABLES.users} set google_id = $2, updated_at = now() where email = $1`,
      [email, googleId]
    );
    return;
  }
  const users = await loadUsers();
  if (!users[email]) return;
  users[email].googleId = googleId;
  users[email].updatedAt = new Date().toISOString();
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

async function updateUserPassword(email, passwordSalt, passwordHash) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `update ${DB_TABLES.users} set password_salt = $2, password_hash = $3, updated_at = now() where email = $1`,
      [email, passwordSalt, passwordHash]
    );
    return result.rowCount > 0;
  }
  const users = await loadUsers();
  if (!users[email]) return false;
  users[email].passwordSalt = passwordSalt;
  users[email].passwordHash = passwordHash;
  users[email].updatedAt = new Date().toISOString();
  await saveUsers(users);
  return true;
}


module.exports = {
  ensureData,
  getUser, getUserByGoogleId, createUser, linkGoogleId,
  ensureFeedId, updateUserVault, updateUserProfile, updateUserPassword
};

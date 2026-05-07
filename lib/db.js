const fs = require("fs/promises");
const {
  pool, DB_TABLES, DATA_DIR,
  USERS_FILE, PUBLIC_POSTS_FILE, SUBSCRIPTIONS_FILE, EMAIL_DELIVERIES_FILE,
  PUBLIC_POST_LIMIT, RESEND_API_KEY, EMAIL_FROM
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
        public_feed jsonb,
        first_name text,
        last_name text,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      );
      alter table ${DB_TABLES.users} add column if not exists feed_id text unique;
      alter table ${DB_TABLES.users} add column if not exists public_feed jsonb;
      alter table ${DB_TABLES.users} add column if not exists first_name text;
      alter table ${DB_TABLES.users} add column if not exists last_name text;
      create table if not exists ${DB_TABLES.feedSubscriptions} (
        feed_id text not null references ${DB_TABLES.users}(feed_id) on delete cascade,
        subscriber_email text not null references ${DB_TABLES.users}(email) on delete cascade,
        unsubscribe_token text unique,
        created_at timestamptz not null default now(),
        primary key (feed_id, subscriber_email)
      );
      alter table ${DB_TABLES.feedSubscriptions} add column if not exists unsubscribe_token text unique;
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
      );
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
      );
      create index if not exists idx_public_posts_feed_id on ${DB_TABLES.publicPosts}(feed_id);
      create index if not exists idx_subscriptions_feed_id on ${DB_TABLES.feedSubscriptions}(feed_id);
      create index if not exists idx_subscriptions_subscriber on ${DB_TABLES.feedSubscriptions}(subscriber_email);
      create index if not exists idx_users_feed_id on ${DB_TABLES.users}(feed_id);
      create index if not exists idx_email_deliveries_status on ${DB_TABLES.emailDeliveries}(status) where status = 'pending'
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

async function loadUsers() { return loadJsonFile(USERS_FILE); }
async function saveUsers(users) { await saveJsonFile(USERS_FILE, users); }
async function loadPublicPosts() { return loadJsonFile(PUBLIC_POSTS_FILE); }
async function savePublicPosts(posts) { await saveJsonFile(PUBLIC_POSTS_FILE, posts); }
async function loadSubscriptionsStore() { return loadJsonFile(SUBSCRIPTIONS_FILE); }
async function saveSubscriptionsStore(s) { await saveJsonFile(SUBSCRIPTIONS_FILE, s); }
async function loadDeliveries() { return loadJsonFile(EMAIL_DELIVERIES_FILE); }
async function saveDeliveries(d) { await saveJsonFile(EMAIL_DELIVERIES_FILE, d); }

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
    firstName: row.first_name || "",
    lastName: row.last_name || "",
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
    const result = await pool.query(`select email, feed_id, first_name, last_name from ${DB_TABLES.users} where feed_id = $1`, [feedId]);
    const row = result.rows[0];
    return row ? { ownerEmail: row.email, feedId: row.feed_id, firstName: row.first_name || "", lastName: row.last_name || "" } : null;
  }
  const users = await loadUsers();
  const entry = Object.entries(users).find(([, item]) => item && item.feedId === feedId);
  return entry ? { ownerEmail: entry[0], feedId, firstName: entry[1].firstName || "", lastName: entry[1].lastName || "" } : null;
}

async function setPublicPosts(email, feedId, posts) {
  await ensureData();

  if (pool) {
    const existingRows = await pool.query(`select post_id from ${DB_TABLES.publicPosts} where feed_id = $1`, [feedId]);
    const previousIds = new Set(existingRows.rows.map((r) => r.post_id));
    await pool.query("begin");
    try {
      const currentIds = posts.map((post) => post.id);
      if (currentIds.length) {
        await pool.query(`delete from ${DB_TABLES.publicPosts} where feed_id = $1 and not (post_id = any($2))`, [feedId, currentIds]);
      } else {
        await pool.query(`delete from ${DB_TABLES.publicPosts} where feed_id = $1`, [feedId]);
      }
      if (posts.length > 0) {
        const placeholders = posts.map((_, i) => {
          const b = i * 10;
          return `($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9},$${b+10},now())`;
        });
        const values = posts.flatMap((post) => [
          feedId, post.id, post.title, post.body,
          post.mood || null, post.place || null,
          JSON.stringify(post.collections || []),
          post.series || null, post.createdAt, post.updatedAt
        ]);
        await pool.query(
          `insert into ${DB_TABLES.publicPosts} (feed_id,post_id,title,body,mood,place,collections,series,created_at,updated_at,synced_at)
           values ${placeholders.join(",")}
           on conflict (feed_id,post_id) do update set
             title=excluded.title, body=excluded.body, mood=excluded.mood, place=excluded.place,
             collections=excluded.collections, series=excluded.series,
             created_at=excluded.created_at, updated_at=excluded.updated_at, synced_at=now()`,
          values
        );
      }
      await pool.query(`update ${DB_TABLES.users} set updated_at = now() where email = $1`, [email]);
      await pool.query("commit");
    } catch (error) {
      await pool.query("rollback");
      throw error;
    }
    return posts.filter((post) => !previousIds.has(post.id));
  }

  const previousIds = new Set((await getPublicPosts(feedId)).map((post) => post.id));
  const store = await loadPublicPosts();
  store[feedId] = posts;
  await savePublicPosts(store);
  const users = await loadUsers();
  if (users[email]) {
    users[email].updatedAt = new Date().toISOString();
    delete users[email].publicFeed;
    await saveUsers(users);
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
      `select s.feed_id, s.created_at, u.first_name, u.last_name
       from ${DB_TABLES.feedSubscriptions} s
       join ${DB_TABLES.users} u on u.feed_id = s.feed_id
       where s.subscriber_email = $1
       order by s.created_at desc`,
      [subscriberEmail]
    );
    return result.rows.map((row) => ({
      feedId: row.feed_id,
      createdAt: row.created_at,
      authorFirstName: row.first_name || "",
      authorLastName: row.last_name || ""
    }));
  }

  const subscriptions = await loadSubscriptionsStore();
  const users = await loadUsers();
  return (Array.isArray(subscriptions[subscriberEmail]) ? subscriptions[subscriberEmail] : [])
    .map((item) => {
      const feedId = typeof item === "string" ? item : item.feedId;
      const createdAt = typeof item === "object" ? item.createdAt || "" : "";
      const ownerEntry = Object.entries(users).find(([, u]) => u && u.feedId === feedId);
      return {
        feedId,
        createdAt,
        authorFirstName: ownerEntry?.[1]?.firstName || "",
        authorLastName: ownerEntry?.[1]?.lastName || ""
      };
    })
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

async function getSubscribedPosts(subscriberEmail) {
  await ensureData();
  if (pool) {
    const result = await pool.query(
      `select p.feed_id, p.post_id, p.title, p.body, p.mood, p.place, p.collections, p.series, p.created_at, p.updated_at,
              u.first_name, u.last_name
       from ${DB_TABLES.feedSubscriptions} s
       join ${DB_TABLES.publicPosts} p on p.feed_id = s.feed_id
       join ${DB_TABLES.users} u on u.feed_id = s.feed_id
       where s.subscriber_email = $1
       order by p.created_at desc
       limit 100`,
      [subscriberEmail]
    );
    return result.rows.map((row) => ({
      feedId: row.feed_id,
      postId: row.post_id,
      title: row.title,
      body: row.body,
      mood: row.mood || "",
      place: row.place || "",
      collections: typeof row.collections === "string" ? JSON.parse(row.collections) : row.collections || [],
      series: row.series || "",
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      authorFirstName: row.first_name || "",
      authorLastName: row.last_name || ""
    }));
  }

  const subscriptions = await loadSubscriptionsStore();
  const publicPosts = await loadPublicPosts();
  const users = await loadUsers();
  const userSubs = (Array.isArray(subscriptions[subscriberEmail]) ? subscriptions[subscriberEmail] : [])
    .map((item) => (typeof item === "string" ? item : item.feedId));

  const posts = [];
  for (const feedId of userSubs) {
    const feedPosts = Array.isArray(publicPosts[feedId]) ? publicPosts[feedId] : [];
    const ownerEntry = Object.entries(users).find(([, u]) => u && u.feedId === feedId);
    const authorFirstName = ownerEntry?.[1]?.firstName || "";
    const authorLastName = ownerEntry?.[1]?.lastName || "";
    for (const post of feedPosts) {
      posts.push({ ...post, feedId, authorFirstName, authorLastName });
    }
  }
  return posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 100);
}

async function createPendingDeliveries(feedId, posts, subscribers) {
  if (!posts.length || !subscribers.length) return [];
  if (!RESEND_API_KEY || !EMAIL_FROM) return [];
  const entries = [];

  if (pool) {
    const placeholders = [];
    const values = [];
    posts.forEach((post) => {
      subscribers.forEach((subscriber) => {
        const b = values.length;
        placeholders.push(`($${b+1},$${b+2},$${b+3},'pending')`);
        values.push(feedId, post.id, subscriber.email);
      });
    });
    const result = await pool.query(
      `insert into ${DB_TABLES.emailDeliveries} (feed_id,post_id,subscriber_email,status)
       values ${placeholders.join(",")}
       on conflict do nothing
       returning feed_id, post_id, subscriber_email`,
      values
    );
    return result.rows.map((row) => ({ feedId: row.feed_id, postId: row.post_id, subscriberEmail: row.subscriber_email }));
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

if (pool) ensureDataPromise = _ensureData();

module.exports = {
  ensureData,
  parseFeedId,
  getUser, createUser, ensureFeedId, updateUserVault, updateUserLogin, updateUserProfile,
  getPublicPosts, getFeedOwner, setPublicPosts, getPublicFeed,
  subscribeToFeed, getSubscriptions, getFeedSubscribers, unsubscribeByToken,
  getSubscribedPosts,
  createPendingDeliveries, getPendingDeliveries, recordDelivery
};

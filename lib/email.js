const { pool, DB_TABLES, RESEND_API_KEY, EMAIL_FROM, APP_URL } = require("./config");
const { escapeHtml } = require("./utils");
const { getFeedSubscribers, createPendingDeliveries, getPendingDeliveries, recordDelivery } = require("./db");

let emailQueueRunning = false;
let emailQueueScheduled = false;

function publicPostEmail(feedId, post, unsubscribeToken = "") {
  const title = post.title || "New thought";
  const baseUrl = APP_URL || "";
  const feedPath = `/feed/${feedId}.xml`;
  const feedUrl = baseUrl ? `${baseUrl}${feedPath}` : feedPath;
  const unsubscribePath = unsubscribeToken ? `/unsubscribe/${unsubscribeToken}` : "";
  const unsubscribeUrl = unsubscribePath && baseUrl ? `${baseUrl}${unsubscribePath}` : unsubscribePath;
  return {
    subject: title,
    text: `${title}\n\n${post.body}\n\nFeed: ${feedUrl}${unsubscribeUrl ? `\nUnsubscribe: ${unsubscribeUrl}` : ""}`,
    html: `
      <h1>${escapeHtml(title)}</h1>
      <p style="white-space:pre-wrap">${escapeHtml(post.body)}</p>
      <p><small>Feed: <a href="${escapeHtml(feedUrl)}">${escapeHtml(feedUrl)}</a></small></p>
      ${unsubscribeUrl ? `<p><small><a href="${escapeHtml(unsubscribeUrl)}">Unsubscribe</a></small></p>` : ""}
    `
  };
}

async function sendDeliveryBatch(entries) {
  if (!entries.length) return { sent: 0, skipped: 0, failed: 0 };

  const payload = entries.map((entry) => {
    const email = publicPostEmail(entry.feedId, entry.post, entry.unsubscribeToken);
    return {
      from: EMAIL_FROM,
      to: [entry.subscriberEmail],
      subject: email.subject,
      text: email.text,
      html: email.html,
      headers: entry.unsubscribeToken && APP_URL ? {
        "List-Unsubscribe": `<${APP_URL}/unsubscribe/${entry.unsubscribeToken}>`
      } : undefined
    };
  });

  const response = await fetch("https://api.resend.com/emails/batch", {
    method: "POST",
    headers: {
      authorization: `Bearer ${RESEND_API_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const error = await response.text().catch(() => "");
    if (pool) {
      const keys = entries.map((e) => [e.feedId, e.postId, e.subscriberEmail]);
      await pool.query(
        `update ${DB_TABLES.emailDeliveries} set status='failed', error=$1, updated_at=now()
         where (feed_id,post_id,subscriber_email) in (${keys.map((_, i) => `($${i*3+2},$${i*3+3},$${i*3+4})`).join(",")})`,
        [error, ...keys.flat()]
      );
    } else {
      for (const entry of entries) await recordDelivery(entry, "failed", { error });
    }
    return { sent: 0, skipped: 0, failed: entries.length };
  }

  const body = await response.json().catch(() => ({}));
  const ids = Array.isArray(body.data) ? body.data : [];
  if (pool) {
    for (let index = 0; index < entries.length; index += 1) {
      await pool.query(
        `update ${DB_TABLES.emailDeliveries} set status='sent', provider_id=$4, updated_at=now()
         where feed_id=$1 and post_id=$2 and subscriber_email=$3`,
        [entries[index].feedId, entries[index].postId, entries[index].subscriberEmail, ids[index]?.id || null]
      );
    }
  } else {
    for (let index = 0; index < entries.length; index += 1) {
      await recordDelivery(entries[index], "sent", { providerId: ids[index]?.id || "" });
    }
  }
  return { sent: entries.length, skipped: 0, failed: 0 };
}

async function notifyFeedSubscribers(feedId, posts) {
  if (!posts.length) return { attempted: 0, queued: 0, skipped: 0 };
  const subscribers = await getFeedSubscribers(feedId);
  if (!RESEND_API_KEY || !EMAIL_FROM) {
    return { attempted: subscribers.length * posts.length, queued: 0, skipped: subscribers.length * posts.length };
  }
  const pending = await createPendingDeliveries(feedId, posts, subscribers);
  scheduleEmailQueue();
  return { attempted: subscribers.length * posts.length, queued: pending.length, skipped: 0 };
}

function scheduleEmailQueue(delayMs = 100) {
  if (emailQueueScheduled || emailQueueRunning || !RESEND_API_KEY || !EMAIL_FROM) return;
  emailQueueScheduled = true;
  setTimeout(() => {
    emailQueueScheduled = false;
    processEmailQueue().catch(() => {});
  }, delayMs).unref();
}

async function processEmailQueue() {
  if (emailQueueRunning || !RESEND_API_KEY || !EMAIL_FROM) return;
  emailQueueRunning = true;
  try {
    while (true) {
      const entries = await getPendingDeliveries(100);
      if (!entries.length) break;
      await sendDeliveryBatch(entries);
      if (entries.length < 100) break;
    }
  } finally {
    emailQueueRunning = false;
  }
}

module.exports = { notifyFeedSubscribers, scheduleEmailQueue, processEmailQueue };

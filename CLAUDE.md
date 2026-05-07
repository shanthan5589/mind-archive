# foffie — Claude Code guide

## File map

| File | Lines | Contents |
|------|-------|----------|
| `lib/config.js` | ~95 | env loading, all constants, pool init, configErrors |
| `lib/utils.js` | ~30 | pure helpers: normalizeEmail, isValidEmail, escapeXml, escapeHtml, randomToken, hashLoginSecret |
| `lib/db.js` | ~640 | all data access: users, posts, subscriptions, deliveries (pg + file fallback) |
| `lib/email.js` | ~110 | email pipeline: publicPostEmail, sendDeliveryBatch, notifyFeedSubscribers, queue |
| `server.js` | ~595 | HTTP helpers, rate limiting, session/auth, routes, static serving, startup |
| `index.html` | 2837 | single-file SPA — see section map below |
| `api/index.js` | 4 | Vercel serverless entrypoint |

## server.js section map

| Lines | Section |
|-------|---------|
| 1–20 | Imports |
| 22–36 | Rate limit config + shared state (rateBuckets, sessionCache, feedXmlCache) |
| 38–65 | HTTP helpers (securityHeaders, json, text, acceptsEncoding, getClientIp) |
| 67–96 | Rate limiting (limitKind, checkRateLimit, cleanRateBuckets) |
| 98–155 | Static asset serving (getIndexAsset, serveStatic) |
| 157–215 | Session helpers (parseCookies, sign, createSessionToken, verifySessionToken, isHttps, sessionHeaders, clearSessionHeaders) |
| 217–270 | Request/validation helpers (readJson, validateVault, validateWrappedKey, normalizePublicPosts) |
| 272–291 | Auth middleware (requireUser) |
| 293–325 | RSS rendering (renderPublicFeedXml) |
| 327–377 | handlePublicFeed |
| 379–384 | handleUnsubscribe |
| 386–555 | handleApi — all routes |
| 557–572 | handleRequest router |
| 574–595 | Server startup + exports |

## index.html section map

| Lines | Section |
|-------|---------|
| 1–6 | HTML head |
| 7–1033 | `<style>` — all CSS |
| 1034–1493 | HTML body markup |
| 1494–1535 | JS constants & state |
| 1536–1674 | Crypto / utility helpers |
| 1675–1768 | API calls + feed/subscriptions |
| 1769–1902 | Auth (signUp, signIn, recover, logout, tryRestoreSession) |
| 1903–2055 | Lock screen / session management |
| 2056–2120 | View switching (showAuth, showApp, showPrivacy, showRecovery) |
| 2121–2260 | Rendering utils (escapeHtml, markdown, formatDate, sortedPosts) |
| 2260–2410 | Post helpers + rendering (filteredPosts, setView, renderPost, renderPosts) |
| 2424–2590 | Sidebar, timeline, collections, export |
| 2590–2750 | Editor (clearEditor, editPost, saveDraft, openPost, deletePost) |
| 2750–2837 | Event binding (bindEvents) |

## Stack

- Node.js HTTP server (no framework)
- PostgreSQL via `pg` (pool), with JSON file fallback for local dev
- Sessions: HMAC-signed cookies (`mind_archive_session`)
- Email: Resend API (batch delivery, queue in DB)
- Frontend: single-page app served from `index.html`

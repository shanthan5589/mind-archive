# foffie — Claude Code guide

## File map

| File | Lines | Contents |
|------|-------|----------|
| `lib/config.js` | ~110 | env loading, all constants, pool init, configErrors |
| `lib/utils.js` | ~30 | pure helpers: normalizeEmail, isValidEmail, escapeHtml, randomToken, hashLoginSecret |
| `lib/db.js` | ~245 | all data access: users (pg + file fallback) |
| `server.js` | ~660 | HTTP helpers, rate limiting, session/auth, routes, AI proxy, Google OAuth, static serving, startup |
| `index.html` | ~5230 | single-file SPA — see section map below |
| `api/index.js` | 4 | Vercel serverless entrypoint |

## server.js section map

| Lines | Section |
|-------|---------|
| 1–17 | Imports |
| 19–26 | Rate limit config + shared state (rateBuckets, sessionCache) |
| 29–65 | HTTP helpers (securityHeaders, json, text, acceptsEncoding, getClientIp) |
| 67–99 | Rate limiting (limitKind, checkRateLimit, cleanRateBuckets) |
| 101–174 | Static asset serving (getIndexAsset, serveStatic) |
| 176–231 | Session helpers (parseCookies, sign, createSessionToken, verifySessionToken, isHttps, sessionHeaders, clearSessionHeaders) |
| 233–280 | Request/validation helpers (readJson, isValidVault, parseNames) |
| 260–281 | Auth middleware (requireUser) |
| 283–380 | AI proxy (buildAiPrompt, /api/ai/status, /api/ai) |
| 342–380 | Google OAuth helpers (googleAuthUrl, exchangeGoogleCode, getGoogleUserInfo) |
| 382–620 | handleApi — all routes |
| 622–659 | handleRequest router + static files map |
| 649–660 | Server startup + exports |

## index.html section map

| Lines | Section |
|-------|---------|
| 1–6 | HTML head |
| 7–2726 | `<style>` — all CSS |
| 2728–3219 | HTML body markup |
| 3221–3260 | JS constants & state |
| 3261–3280 | Theme helpers (getSavedTheme, applyTheme, uid, normalizeEmail) |
| 3265–3350 | API calls (api, savePosts, scheduleSave) |
| 3290–3385 | Auth (signUp, signIn, logout, tryRestoreSession, unlock, showAuth, showApp, setAuthMode) |
| 3386–3500 | Rendering utils (escapeHtml, inlineMarkdown, renderMarkdown, formatDate) |
| 3500–3620 | Post helpers (sortedPosts, getCollections, wordsIn, readTime, relativeDate, filteredPosts, setView) |
| 3620–3800 | Post rendering (renderPost, renderPosts, renderSidebar, renderTimeline, renderCollections) |
| 3800–4030 | Editor + export (clearEditor, editPost, saveDraft, openPost, deletePost, renderPreview, renderAll) |
| 4030–4580 | AI helpers (ghost text, continue, rephrase, grammar, spark, brainstorm, digest, insights) |
| 4580–5220 | Event binding (bindEvents) |

## Auth model

- **Email + password**: pbkdf2 hash via `hashLoginSecret(password, salt)` — same function as old login, now used for passwords
- **Google OAuth**: optional, `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI` env vars; inactive if not set
- **Sessions**: 30-day HMAC-signed cookies (`mind_archive_session`)
- **Vault**: plain JSON array of posts, stored in `vault` column (was encrypted blob)

## Stack

- Node.js HTTP server (no framework)
- PostgreSQL via `pg` (pool), with JSON file fallback for local dev
- Sessions: HMAC-signed cookies (`mind_archive_session`)
- AI: Groq API (`GROQ_API_KEY`), optional — features hidden if not configured
- Frontend: single-page app served from `index.html`

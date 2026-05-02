# Mind Archive

Old-school private writing site with accounts, encrypted personal vaults, Markdown posts, pinned thoughts, collections, RSS export, and backups.

## Run locally

```powershell
npm install
npm start
```

Open `http://localhost:3000`.

Without `DATABASE_URL`, the server uses `data/users.json` for local development only.

## Production setup

Use PostgreSQL for real users. File storage is not reliable on most app hosts because files can disappear on deploys or restarts.

Required environment variables:

```text
DATABASE_URL=postgres://...
SESSION_SECRET=use-a-long-random-secret
NODE_ENV=production
```

Start command:

```text
npm start
```

Build command:

```text
npm install
```

## Deploy on Railway

1. Push this repo to GitHub.
2. Create a Railway project.
3. Add a PostgreSQL database to the project.
4. Add this GitHub repo as a Node service.
5. Set the app service variables:

```text
DATABASE_URL=${{Postgres.DATABASE_URL}}
SESSION_SECRET=generate-a-long-random-secret
NODE_ENV=production
```

Railway will provide the public URL after the deploy finishes.

## Public launch checklist

- Use PostgreSQL through `DATABASE_URL`.
- Set a long `SESSION_SECRET`.
- Keep `data/` out of git.
- Read `/api/health` after deploy to confirm the server is up.
- Tell users that forgotten passwords cannot be recovered.
- Use provider database backups before inviting people you do not know.

## Privacy model

The browser derives two values from the user's password:

- A login secret sent to the server for authentication.
- A separate vault key that never leaves the browser.

Posts are encrypted in the browser before being uploaded. The server stores encrypted vault blobs and cannot decrypt posts without the user's password.

If a user forgets their password, their archive cannot be recovered.

## Built-in protections

- Signed HTTP-only session cookie.
- Basic IP-based rate limits for login, signup, and vault writes.
- Security headers for browser responses.
- Static server only exposes the app page, not backend data files.

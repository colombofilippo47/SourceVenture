# Backend

FastAPI server for SourceVenture. It's the only part of the system that holds
secrets or writes to the shared database — the frontend is a static page that
talks to it over HTTP.

## What it does

- **Accounts** — email + password signup/login. Passwords are hashed
  (PBKDF2-HMAC-SHA256, 200k iterations, random salt per user) and never
  stored or logged in plain text. A successful login sets an httpOnly,
  `SameSite=Lax` session cookie tied to a row in `sessions` — JavaScript
  never touches the token itself, which limits what an XSS bug could steal.
- **Projects** — a founder's pitch + GitHub repo, stored as a JSON blob plus
  a few indexed columns (`owner_user_id`, `status`, timestamps) so the API
  can filter without deserializing everything. Only the owner can update
  their own project (checked server-side, not just hidden in the UI).
- **AI coach** — the frontend never talks to Anthropic directly. It posts
  `{system, messages}` to `/api/coach`, which attaches the server-side
  `ANTHROPIC_API_KEY` and forwards the request. This is the load-bearing
  reason the backend exists at all: an API key embedded in frontend
  JavaScript would be public the moment the page loads.
- **Rate limiting** — an in-memory sliding-window limiter caps signup (5 /
  10 min per IP), login (10 / 10 min per IP) and the coach proxy (30 / hour
  per account), so a single process can't be used for credential stuffing
  or to run up your Anthropic bill. It resets if the process restarts and
  doesn't share state across multiple instances — fine for one server,
  not for a scaled-out deployment (see below).
- **Security headers** — every response gets `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy` and a minimal `Permissions-Policy`;
  `Strict-Transport-Security` is added automatically once requests arrive
  over HTTPS.

## Data model (SQLite, `data.db`)

| table      | purpose                                            |
|------------|-----------------------------------------------------|
| `users`    | id, email (unique), name, password_hash, created_at |
| `sessions` | session cookie value → user_id, with an expiry       |
| `projects` | id, owner_user_id, status, timestamps, JSON `data`   |

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then paste your ANTHROPIC_API_KEY into .env
uvicorn main:app --reload --port 8000
```

`CORS_ORIGINS` in `.env` must list the exact origin(s) the frontend is
served from (default `http://localhost:5500`) — cookie-based auth requires
an explicit origin, `*` won't work. Set `COOKIE_SECURE=true` once you're
serving both sides over HTTPS.

## Endpoints

| method | path              | auth | purpose                          |
|--------|-------------------|------|-----------------------------------|
| POST   | `/api/auth/signup`| no   | create an account, sets the session cookie |
| POST   | `/api/auth/login` | no   | sets the session cookie           |
| POST   | `/api/auth/logout`| yes  | invalidates and clears the cookie |
| GET    | `/api/auth/me`    | yes  | current user                      |
| GET    | `/api/projects`   | no   | published projects (public)       |
| GET    | `/api/projects/mine` | yes | the current user's own projects |
| GET    | `/api/projects/{id}` | no | one project                      |
| PUT    | `/api/projects/{id}` | yes | create/update (owner only)       |
| POST   | `/api/coach`      | yes  | proxies one turn to Claude        |

## Before this goes anywhere public

This is a working prototype, not a hardened production service. What's
already handled: server-side auth checks, hashed passwords, httpOnly
session cookies, rate limiting on the sensitive endpoints, security
headers, and per-owner access control on projects. Still missing, in the
order you'd actually hit them:

1. **HTTPS everywhere.** Set `COOKIE_SECURE=true` and put this behind a
   reverse proxy (Caddy, nginx, or your host's built-in TLS) before it's
   reachable outside your laptop — cookies without `Secure` are readable
   on the network path over plain HTTP.
2. **CSRF protection.** Cookie-based sessions need it for state-changing
   requests (`PUT /api/projects/*`, `POST /api/coach`) once this is
   reachable from more than one trusted origin — add a CSRF token or
   double-submit cookie pattern.
3. **Shared rate-limit storage.** The current limiter is in-process memory;
   move it to Redis (or similar) if you ever run more than one backend
   instance, otherwise each instance gets its own separate quota.
4. **Password policy + email verification.** Signup enforces an 8-char
   minimum but there's no email confirmation loop — anyone can register an
   address they don't own.
5. **Secrets management.** `.env` is fine locally; in production use your
   host's secret store (not a committed file, not a plain environment
   variable visible in `ps` output where avoidable).
6. **Back up `data.db`.** SQLite is fine at this scale, but there's no
   automated backup — losing the file loses every account and project.
   A managed Postgres instance removes this concern if the project grows.
7. **Structured logging + error monitoring.** Right now failures only show
   up in the uvicorn console. Add real logging and something like Sentry
   before you need to debug a production incident blind.
8. **Dependency scanning.** Run `pip list --outdated` / `pip-audit`
   periodically — nothing here does it automatically yet.

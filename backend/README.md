# Backend

FastAPI server for SourceVenture. It's the only part of the system that holds
secrets or writes to the shared database — the frontend is a static page that
talks to it over HTTP.

## What it does

- **Accounts** — email + password signup/login. Passwords are hashed
  (PBKDF2-HMAC-SHA256, 200k iterations, random salt per user) and never
  stored or logged in plain text. A successful login returns a bearer token
  tied to a row in `sessions`; the frontend sends it back as
  `Authorization: Bearer <token>` on every request that needs to know who's
  asking.
- **Projects** — a founder's pitch + GitHub repo, stored as a JSON blob plus
  a few indexed columns (`owner_user_id`, `status`, timestamps) so the API
  can filter without deserializing everything. Only the owner can update
  their own project (checked server-side, not just hidden in the UI).
- **AI coach** — the frontend never talks to Anthropic directly. It posts
  `{system, messages}` to `/api/coach`, which attaches the server-side
  `ANTHROPIC_API_KEY` and forwards the request. This is the load-bearing
  reason the backend exists at all: an API key embedded in frontend
  JavaScript would be public the moment the page loads.

## Data model (SQLite, `data.db`)

| table      | purpose                                            |
|------------|-----------------------------------------------------|
| `users`    | id, email (unique), name, password_hash, created_at |
| `sessions` | bearer token → user_id, with an expiry              |
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

## Endpoints

| method | path              | auth | purpose                          |
|--------|-------------------|------|-----------------------------------|
| POST   | `/api/auth/signup`| no   | create an account, returns a token |
| POST   | `/api/auth/login` | no   | returns a token                   |
| POST   | `/api/auth/logout`| yes  | invalidates the current token     |
| GET    | `/api/auth/me`    | yes  | current user                      |
| GET    | `/api/projects`   | no   | published projects (public)       |
| GET    | `/api/projects/mine` | yes | the current user's own projects |
| GET    | `/api/projects/{id}` | no | one project                      |
| PUT    | `/api/projects/{id}` | yes | create/update (owner only)       |
| POST   | `/api/coach`      | yes  | proxies one turn to Claude        |

## Before this goes anywhere public

This is a working prototype, not a hardened production service. In the order
you'd actually hit them:

1. **HTTPS everywhere.** Bearer tokens over plain HTTP are readable by
   anyone on the network path. Put this behind a reverse proxy (Caddy,
   nginx, or your host's built-in TLS) before it's reachable outside your
   laptop.
2. **Lock down CORS.** `CORS_ORIGINS=*` (the default) is fine for local
   dev; in production set it to your actual frontend origin.
3. **Rate-limit `/api/auth/*` and `/api/coach`.** Nothing currently stops
   someone from hammering the login endpoint (credential stuffing) or
   running your Anthropic bill up through the coach proxy. Add per-IP and
   per-account limits.
4. **Session hardening.** Bearer tokens in `localStorage` are simple and
   fine for a prototype, but are readable by any script on the page (XSS
   risk). A production build would move to `httpOnly` cookies with
   `SameSite` set, plus CSRF protection on state-changing requests.
5. **Password policy + email verification.** There's currently no minimum
   password length check server-side and no email confirmation loop — an
   account can be created with any string as a password and an unowned
   email address.
6. **Secrets management.** `.env` is fine locally; in production use your
   host's secret store (not a committed file, not a plain environment
   variable visible in `ps` output where avoidable).
7. **Back up `data.db`.** SQLite is fine at this scale, but there's no
   automated backup — losing the file loses every account and project.
   A managed Postgres instance removes this concern if the project grows.
8. **Structured logging + error monitoring.** Right now failures only show
   up in the uvicorn console. Add real logging and something like Sentry
   before you need to debug a production incident blind.

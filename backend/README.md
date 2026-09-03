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
- **AI coach** — the frontend never talks to an AI provider directly. It
  posts `{system, messages}` to `/api/coach`, which attaches the
  server-side key and forwards the request. This is the load-bearing
  reason the backend exists at all: an API key embedded in frontend
  JavaScript would be public the moment the page loads.
- **Business rating council** — `POST /api/projects/{id}/rate` runs three
  independently-prompted evaluators (a VC, a technical due-diligence
  engineer, a growth analyst) in parallel, takes the median score per
  dimension so one outlier judge can't swing the result, then a fourth
  "chairman" call reviews all three panelists' full reasoning and
  synthesizes one final, informed verdict (falling back to the median if
  that call fails). Saving a project with real pitch changes re-runs this
  automatically in the background — no button needed.
- **Real investor gating** — `investor_applications` table + a threshold
  check enforce access server-side (was a pure frontend localStorage flag
  before, with zero backend enforcement). `investorSummary` is stripped
  from every public response unless the caller is the project owner or an
  approved investor.
- **Rate limiting** — an in-memory sliding-window limiter caps signup (5 /
  10 min per IP), login (10 / 10 min per IP), the coach proxy (25 / rolling
  24h per account, matching the disclosed free-tier cap), rating (10/hour)
  and investor matching (20/hour), so a single process can't be used for
  credential stuffing or to run up your AI provider bill. It resets if the
  process restarts and doesn't share state across multiple instances —
  fine for one server, not for a scaled-out deployment (see below).
- **CSRF protection** — a double-submit cookie (`csrf_token`, not
  httpOnly) that every state-changing request must echo back as an
  `X-CSRF-Token` header. The frontend's `csrfHeaders()` helper does this
  automatically.
- **Security headers** — every response gets `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy` and a minimal `Permissions-Policy`;
  `Strict-Transport-Security` is added automatically once requests arrive
  over HTTPS.
- **Email verification** — signup sends a verification link in the
  background; without `RESEND_API_KEY` set it's just logged to the console
  (fully testable on localhost with zero email setup). Nothing is gated on
  `email_verified` yet — see below.

## Data model (SQLite, `data.db`)

| table                  | purpose                                                        |
|------------------------|-----------------------------------------------------------------|
| `users`                | id, email (unique), name, password_hash, created_at, email_verified, verify_token |
| `sessions`             | session cookie value → user_id, with an expiry                  |
| `projects`             | id, owner_user_id, status, timestamps, JSON `data`               |
| `investor_applications`| id, user_id (unique), name, firm, status (pending/approved), timestamps |
| `project_ratings`      | project_id → last council rating (scores, verdict, risk, improvements) |
| `analytics_events`     | event name, optional project_id, timestamp — no IP, no user agent, no per-user row |

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then paste your API key(s) into .env
uvicorn main:app --reload --port 8000
```

`CORS_ORIGINS` in `.env` must list the exact origin(s) the frontend is
served from (default `http://localhost:5500`) — cookie-based auth requires
an explicit origin, `*` won't work. Set `COOKIE_SECURE=true` once you're
serving both sides over HTTPS.

**AI provider**: Gemini (free tier) is the primary provider for the coach,
the rating council, and investor matching — `GEMINI_API_KEY` /
`GEMINI_MODEL` (default `gemini-2.5-flash`). Anthropic is only reached as a
paid last-resort fallback if Gemini is unset or a call fails
(`ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL`). Set neither and every AI route
returns a 503 with a clear message instead of erroring confusingly.

## Endpoints

| method | path              | auth | purpose                          |
|--------|-------------------|------|-----------------------------------|
| POST   | `/api/auth/signup`| no   | create an account, sets the session cookie |
| POST   | `/api/auth/login` | no   | sets the session cookie           |
| POST   | `/api/auth/logout`| yes + CSRF | invalidates and clears the cookie |
| GET    | `/api/auth/me`    | yes  | current user                      |
| GET    | `/api/auth/verify/{token}` | no | confirms an account's email |
| GET    | `/api/projects`   | no   | published projects (public) — `investorSummary` stripped unless owner/approved investor |
| GET    | `/api/projects/mine` | yes | the current user's own projects |
| GET    | `/api/projects/{id}` | no | one project — same `investorSummary` stripping |
| PUT    | `/api/projects/{id}` | yes + CSRF | create/update (owner only); fires an automatic re-rate in the background on real pitch changes |
| POST   | `/api/projects/{id}/rate` | yes + CSRF | 3-judge council + chairman synthesis, stored server-side |
| GET    | `/api/projects/{id}/rating` | no | the last stored council rating |
| POST   | `/api/coach`      | yes + CSRF | proxies one turn to the AI, 25 msgs / rolling 24h free tier |
| POST   | `/api/investors/apply` | yes + CSRF | submit an investor application (starts `pending`) |
| GET    | `/api/investors/me` | yes | current user's application status |
| GET    | `/api/investors/directory` | yes | full published-project list — 403 unless the threshold is met AND the caller is `approved` |
| POST   | `/api/investors/match` | yes + CSRF | AI-ranks published projects against an investor's stated interest/amount |
| POST   | `/api/analytics/event` | no   | records one allowlisted event name (+ optional project id). Rate-limited per IP; stores nothing identifying |
| GET    | `/api/analytics/summary` | yes | platform-wide event totals + per-project counts **for the caller's own projects only** |

**Approving an investor application**: no admin UI exists yet — approve
manually: `sqlite3 data.db "UPDATE investor_applications SET
status='approved', decided_at=strftime('%s','now') WHERE user_id='<id>'"`.

**Backups**: `python backup_db.py` copies `data.db` into `backups/` with a
timestamp, keeping the 14 most recent by default (`--keep N` to change).
No scheduler is wired up — run it manually, or point your host's own cron
at it once this is actually deployed somewhere.

## Security checklist status

Tracked against [finehq/vibe-coding-checklist](https://github.com/finehq/vibe-coding-checklist).

**Done**: server-side input validation with length caps · parameterized
queries everywhere · passwords hashed with PBKDF2 + per-user salt ·
httpOnly `Secure` `SameSite=Lax` session cookies · CSRF double-submit on
every state-changing route · rate limiting per IP **and** per target
account on login (blunts distributed brute force) · account-scoped
authorization checks server-side (never UI-only) · security response
headers · CSP in the frontend pinning which origins the page may contact ·
secrets only in `.env`, which is gitignored · AI provider fallback chain ·
AI output parsed defensively (allowlisted ids, JSON extraction with
fallbacks) · first-party analytics that collects no personal data ·
dependency lockfiles committed.

**Knowingly not done yet** (each is a real gap, not an oversight): MFA ·
password reset flow · email verification is issued but not enforced ·
account lockout beyond rate limiting · encryption at rest · HTTPS (needs a
real host) · automated dependency scanning in CI · SAST/DAST · privacy
policy and consent UI · secrets manager instead of `.env`. Anything below
in "Before this goes anywhere public" is the ordered version of this list.

## Before this goes anywhere public

What's now handled: server-side auth checks, hashed passwords, httpOnly
session cookies, CSRF (double-submit cookie) on every state-changing
route, rate limiting on the sensitive endpoints, security headers,
per-owner access control on projects, real server-enforced investor
gating, `investorSummary` stripped from public responses, structured
logging, a manual DB backup script, email verification (link sent, no
enforcement yet), and a real free-tier AI provider. Still missing, in the
order you'd actually hit them:

1. **HTTPS everywhere.** Set `COOKIE_SECURE=true` and put this behind a
   reverse proxy (Caddy, nginx, or your host's built-in TLS) before it's
   reachable outside your laptop.
2. **Shared rate-limit storage.** The current limiter is in-process memory;
   move it to Redis if you ever run more than one backend instance.
3. **Enforce email verification.** The link/endpoint exist, but nothing
   gates on `email_verified` yet.
4. **Secrets management.** `.env` is fine locally; in production use your
   host's secret store.
5. **Automated backups.** `backup_db.py` exists but nothing calls it on a
   schedule yet.
6. **Error monitoring.** Logging goes to stdout; not shipped anywhere yet.
7. **Dependency scanning.** Run `pip list --outdated` / `pip-audit`
   periodically.
8. **Investor-application admin UI.** Approving one is a direct SQL update
   today (see above).

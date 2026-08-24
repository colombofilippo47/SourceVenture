# CHANGES.md — SourceVenture

## Backend production-hardening pass + business rating + frontend motion/glass/theme

**Backend** (`backend/main.py`):
- Real server-enforced investor gating — new `investor_applications` table
  + `/api/investors/apply` · `/api/investors/me` · `/api/investors/directory`.
  Access requires BOTH a published-project threshold AND per-investor
  approval; neither was enforced server-side before — `investorApplied`
  only ever lived in frontend localStorage, and `GET /api/projects` was
  fully public with zero gating.
- `investorSummary` — content a founder explicitly approves for investor
  eyes only — was riding along in the public `GET /api/projects` and
  `GET /api/projects/{id}` responses regardless of any gate. Stripped
  unless the caller is the project owner or an approved investor.
- CSRF protection (double-submit cookie) on every state-changing route.
- Coach rate limit set to 25/rolling-24h, matching the disclosed free-tier
  cap shown on the landing page and billing tab exactly.
- New `POST /api/projects/{id}/rate` — a 3-judge council (VC, technical
  due-diligence, growth analyst) scores the project independently, median
  per dimension, then a chairman call reviews all three panelists' full
  reasoning and synthesizes one final verdict rather than a blind average.
  Falls back to the median-based aggregate if the chairman call fails.
  Saving a project with real pitch changes re-runs this automatically in
  the background — no button needed.
- Gemini (free tier) is now the primary AI provider for the coach, the
  rating council, and investor matching. Anthropic is only reached as a
  paid last-resort fallback if Gemini is unset or a call fails.
- Basic email verification: signup sends a link in the background (logged
  to console without `RESEND_API_KEY`, sent via Resend with it),
  `GET /api/auth/verify/{token}` confirms it. Not enforced anywhere yet.
- Basic structured logging (was raw uvicorn console output only).
- `backup_db.py` — manual `data.db` backup script, no scheduler wired.

**Frontend** (`frontend/index.html`, single file, no build step):
- Light/dark theme toggle — CSS-variable re-point, toggle in both nav
  bars, icon-spin + page-wide smooth color transition on switch,
  flash-of-wrong-theme guard in `<head>`.
- Investor apply/directory UI wired to the real backend endpoints (was
  fully fake before — "approved instantly" copy, localStorage only).
- Business rating scorecard UI on the coach page — shows the council's
  median scores, judge count, and improvement notes; fetches the
  server-stored rating on load, re-rates on demand.
- CSRF token echoed automatically on every mutating request via a
  `csrfHeaders()` helper.

**Repo**: `CODEOWNERS` + `CONTRIBUTING.md` for the founder/collaborator
backend-frontend split.

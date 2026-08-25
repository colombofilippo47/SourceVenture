# CHANGES.md — SourceVenture

## 2026-08-25 — Full-screen sign-in/sign-up + email verification wired up

Denis: integrate a full-screen sign-in flow design; "do what you think is
best" on how to fit it into this project's zero-build architecture; "keep
light and dark mode and some subtle green."

- **Full-screen `#/signin` / `#/signup`** replace the old modal-based auth
  UI — dark, ambient canvas dot-reveal background (hand-rolled 2D canvas,
  not three.js/WebGL — this project has no build step, so no npm/React
  toolchain was introduced for one component), subtle green accent, both
  theme modes preserved. All 5 old `openAuthModal(...)` call sites now
  route here; other non-auth modals (investor apply, project preview,
  clear-data confirm) are untouched.
- **`#/verify/:token` route** — the backend has emailed a
  `/#/verify/<token>` magic link since the verification columns existed,
  but the frontend never had a route to handle it. Now it calls the real
  verify endpoint and shows a success/error state.
- **`POST /api/auth/resend-verification`** (new, session-gated,
  rate-limited 3/10min per user) — powers a "check your email" step
  shown right after signup, with a working resend button.
- `emailVerified` now included in `/api/auth/login` and `/api/auth/me`
  responses (previously only present on the signup response) — additive,
  non-breaking.
- Tested end-to-end against a live local backend via curl: signup →
  resend (confirms old token invalidated) → verify with fresh token →
  `emailVerified` flips true → already-verified resend no-ops → login
  payload shape. Browser visual QA **not performed** — Chrome extension
  unavailable in this environment; worth a look before merge, especially
  the canvas background at mobile widths.
- Built on a fresh `frontend/sign-in-flow-redesign` branch off
  `origin/main` in an isolated git worktree, to avoid touching the
  uncommitted backend-hardening work sitting in the main checkout.
  Pushed; PR not yet opened (the repo's push token isn't scoped for the
  API) — open one from the link `git push` printed.

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

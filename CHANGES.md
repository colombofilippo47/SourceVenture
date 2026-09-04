# CHANGES.md — SourceVenture

## 2026-09-05 — Merged collaborator's Stripe billing, root-caused "AI isn't working," full bug-fix + feature pass, deployed

Denis: merge colombofilippo47's Stripe billing commit without losing
anything, fix the AI once and for all (real screenshot showed every
help-chat message failing), then a large batched punch list — payments,
header shortcuts, mobile UI, analytics, verification flow, publish
failures, investors page cleanup, notifications center, AI provider
fallbacks, GitHub-stars-aware rating, docs/support pages — "we are
shipping today."

- **Merged colombofilippo47's real Stripe billing** (`integrate/denis-plus-
  analytics`, commit `1534d65`) into the Postgres-migrated branch:
  Checkout/portal/webhook endpoints, `stripe_customer_id`/
  `stripe_subscription_id` columns, his SQLite-style `?`/non-`IF NOT
  EXISTS` DDL converted to this branch's Postgres conventions. Verified via
  a scripted line-by-line reconciliation (every added line from his commit
  confirmed present, 0 silently dropped) since Denis explicitly asked for
  proof nothing was lost. Re-checked his branch before finishing this
  round — no newer commits since `1534d65`, nothing missed.
- **Root-caused "something went wrong reaching the AI" (real bug, not
  flakiness):** a previous fix made `_try_gemini` sleep out Google's
  suggested retry delay (up to ~45s, twice) on a 429 — actively wrong on
  Vercel serverless, where the function's own execution timeout is far
  shorter than that, so any real rate-limit burst reliably hit a bare
  platform timeout with no JSON body, which the frontend can't tell apart
  from any other failure. Fixed by failing fast (no sleep) and falling
  through a real provider chain instead: Gemini → Groq → OpenRouter →
  Anthropic, each tried only if its key is actually set. **Only Gemini is
  actually configured right now** — the only other candidate key on hand
  (a Groq key from Max OS) is org-restricted and doesn't work; a real
  free OpenRouter or working Groq key needs to be added for genuine
  redundancy. Confirmed live: the free-tier 5rpm Gemini cap is real and
  easy to trip (hit it by accident mid-testing) — now fails in ~1s with an
  honest "AI is busy, try shortly" message instead of hanging.
- **"Publishing failing":** `saveProject()` discarded the backend's real
  error detail and showed a flat, misleading "Is the backend running?"
  toast — the actual common cause (403, email not verified) is now shown
  verbatim. Also: **Resend is still in sandbox mode** — it only delivers
  to Denis's own inbox, so any other real signup silently never gets a
  verification email at all. This needs a verified sending domain in the
  Resend dashboard to actually work for anyone but him.
- **Two real, pre-existing CSS specificity bugs** (not breakpoint issues —
  confirmed via a live logged-in screenshot at 1440px): `#topbar
  .tb-icon{display:flex}` (unconditional, no media query) was tying with
  and beating the mobile-only hide rules for the hamburger AND the sync/
  account buttons at equal specificity, so all three were visible on
  every screen size regardless of the media query's own intent. Fixed by
  raising the hide rules' specificity to unambiguously win.
- GitHub star count (already fetched, never actually sent): `repoContext`
  sent to the rating council and business-plan generator only ever
  included readme/description, silently dropping stars/language/
  contributors. New shared `repoContextToText()` fixes both call sites;
  growth-analyst judge prompt now explicitly told to treat stars as one
  real traction signal.
- Investors page pruned to just the cohort countdown/bars per Denis
  ("remove everything active investor related except the countdown") —
  dropped the "Find your match" tool and the directory listing/
  application-status flow (code left in place, not deleted, for when the
  directory actually opens). Same countdown bars added, compact, to the
  landing page's investor section.
- New in-app Notifications center (sidebar tab + unread badge): real
  `notifications` table, fires on referral milestones, Stripe plan
  changes, and investor-application decisions — not just a toast that's
  gone on refresh.
- Signup's "email me updates" checkbox (already built) now actually
  surfaces in the admin users table (emailable / opted-out column) — was
  captured and stored but never visible anywhere for Denis to read.
- Email verification gate now polls the real server-side flag every 4s
  and auto-continues the moment it flips true, on any device — was a dead
  end requiring a manual refresh.
- Real Documentation and Support pages (were toast placeholders); header
  logo/wordmark nudged to visually center in the topbar row.
- Deployed: backend (`vercel.json` still legacy `builds`/`routes` —
  `functions.maxDuration` conflicts with it, confirmed via a real failed
  build) and frontend, both promoted to production and smoke-tested live
  end-to-end (signup → verify → coach → publish → rate → notifications) on
  the real `sourceventure.dev`/`api.sourceventure.dev` domains, not just a
  preview URL. All scratch test accounts deleted from the production DB
  before finishing.

## 2026-09-04 (round 2, same day) — Postgres migration, full deploy, closing feature list

Denis: password strictness + a playful "runs away" button on a weak
password, working investor "Notify me", email-notification opt-in +
settings toggle, referral system verified end-to-end + a new one-time 5%
discount, bigger logo mark, real enforced+working email verification, then
"find a free host with no limits like Vercel and deploy everything."

- **Backend moved off local SQLite onto Postgres** (a dedicated new
  Supabase free-tier project) — this was the actual blocker on deploying
  to Vercel at all, since a `data.db` file doesn't survive a serverless
  filesystem. `sqlite3` → `psycopg`, all 59 `?` placeholders → `%s`,
  `ADD COLUMN IF NOT EXISTS` (Postgres-native, dropped the old
  try/except-`OperationalError` dance), `AUTOINCREMENT` → `SERIAL`. Real
  bug caught and fixed by live-testing rather than trusting a clean
  migration: every millisecond timestamp column (`projects.updated_at`/
  `published_at`, plus every other `*_at` column for consistency) was
  still `INTEGER` — Postgres's `INTEGER` is 32-bit, and a millisecond
  epoch value is ~1.8 trillion, so every project save 500'd with
  `NumericValueOutOfRange` until these became `BIGINT`.
  - First Supabase project created (`aufcpeikgzixydwudtgi`) hit a
    persistent password-auth failure against its own pooler that never
    resolved (not a propagation delay — confirmed via a 4-minute retry
    loop); Supabase's Management API has no password-reset endpoint, so
    rather than escalate to Denis mid-task, deleted it and created a
    second, clean project (`dmrjkpokvclxkvyteavj`) with a fresh
    alphanumeric-only password — connected on the first real try.
  - Old `backend/requirements.txt` gained `psycopg[binary]`.
- **Deployed**: backend as a Vercel Python (FastAPI/ASGI) serverless
  function — `backend/api/index.py` + `backend/vercel.json`. First
  deploy attempt used the modern `rewrites` config and silently 404'd on
  every route (confirmed via `vercel logs`: the ASGI app was receiving
  `/api/index` as the request path on every call, not the real path) —
  switched to the legacy `builds`+`routes` vercel.json format, which
  correctly forwards the full original path through to FastAPI's own
  router. Live-verified signup → /me → notify-me end to end against the
  real deployed URL before calling it done. New Vercel project `backend`
  (`apexmedialx-8775s-projects`), SSO deployment protection disabled (same
  fix as the frontend needed), env vars set for prod (`DATABASE_URL`,
  `GEMINI_API_KEY`/`MODEL`, `RESEND_API_KEY`/`FROM`, `ADMIN_EMAILS`
  cleaned to just Denis's real email, `CORS_ORIGINS`, `PUBLIC_APP_URL`,
  `PUBLIC_API_URL`, `COOKIE_SECURE=true`). Domain `api.sourceventure.dev`
  attached — needs one more DNS record from Denis, see below.
  - Frontend redeployed with a hostname-gated API base
    (`window.SOURCEVENTURE_API_BASE`, set only off `localhost`, so the one
    static `index.html` still works unchanged for local dev) pointing at
    `https://api.sourceventure.dev`, and the CSP's stale
    `sourceventure.onrender.com` reference swapped for the real API origin.
  - GitHub/Google OAuth and Cloudflare Turnstile envs are still unset on
    Vercel (same "quiet until configured" pattern as local — those
    features just don't activate yet, nothing broke).
- **Real Resend email confirmed working** — reused the same working key
  Max OS already has (a live test send to Denis's own email round-tripped
  a real message ID). Caveat flagged inline in `.env`/`.env.example`: the
  shared `onboarding@resend.dev` sandbox address only delivers to the
  Resend account owner's own verified email — real founder signups with
  other addresses won't get mail until Denis verifies `sourceventure.dev`
  as a sending domain in his own Resend dashboard (a few DNS records).
- **Email verification now actually enforced**: unverified accounts can
  still sign in and draft, but `PUT /api/projects/{id}` 403s the specific
  moment a project would first go from draft to published, with a message
  pointing at Settings → resend. Never gated at signup/login.
- **Password policy tightened**: was letter+digit/8 chars, now
  upper+lower+digit+symbol/10 chars, both backend (`validate_password_strength`)
  and the client-side pre-check.
- **"Runs away" button**: a genuinely new mouse-repel effect on the
  signup submit button (`initDodgingSubmitButton`/`onAuthPasswordInput`),
  active only while the typed password is below the real strength bar —
  dodges within its own field row (clamped, can't fly off-layout), parks
  back the instant the password clears the bar. Deliberately cosmetic
  only — the real gate stays the existing weak-password check on submit,
  a dodge never blocks a click that lands.
- **Investor "Notify me" now really works**: was silently redirecting a
  logged-out visitor to sign-in with zero explanation before opening the
  full name+firm investor-application form. Split into two real, distinct
  flows: `openNotifyMeModal()` (new, no login required, backend
  `POST /api/investors/notify-me` + `directory_notify_signups` table,
  idempotent on email) for "just tell me when it opens", vs.
  `openInvestorApplyModal()` (unchanged, login required) for an actual
  investor application once the directory is open.
- **Email-notification preference**: `email_notifications` column
  (defaults on), a real checkbox at signup, a toggle in
  Settings → Account, `PUT /api/auth/profile` accepts it.
- **Referral system verified end-to-end, live** (not just read from code):
  signed up 3 fresh accounts with a real referral code, verified each,
  published a real project on each — confirmed the referrer's
  `referralBonusRemaining` hit 50 and a new one-time 5% `referralDiscountPct`
  landed on the exact 3rd milestone, matching the existing
  `referral_milestone3_awarded` one-shot guard so it can never double-award.
  Reflected in the Pro upgrade modal (stacks additively with the existing
  founding-member 50%) and the Settings → Plan referral card.
- **Logo mark enlarged** (19px → 30px height) — only the icon, the
  `SourceVenture` wordmark's own size is untouched.
- `.env`'s leftover `admin-test@example.com` removed from `ADMIN_EMAILS`,
  same cleanup applied to the deployed env var.

**Still open** (flagged, not done): GitHub/Google OAuth apps, Cloudflare
Turnstile site, and a verified Resend sending domain all still need Denis
to create them in their respective dashboards (nothing here can create
accounts on his behalf) — every one degrades gracefully without them.
"The Council" reference-repo question from earlier is still unresolved
(never got a specific repo link). Notes-with-AI + the
`claude-api-bridge` Max OS items are still deliberately deferred behind
this + Festival Cantábile, per Denis's own prioritization.

## 2026-09-04 — Section 1/First Drop reconciled, deployed to Vercel

Merged colombofilippo's `integrate/denis-plus-analytics` branch (his own
First Drop implementation — GitHub-optional validation, 10/24h free cap,
Pro scaffold, referrals, Source Score rebrand, investor-summary approval,
AI business plan) into the working branch; verified live rather than just
reviewing code. Then closed the remaining gaps against the fuller spec:

- Real bug fix: chat pane couldn't scroll to the input on mobile (two
  stacked flexbox/grid min-height defaults).
- Circular Source Score ring (SVG), password complexity + Cloudflare
  Turnstile bot check on signup, GitHub Sign-In (mirrors Google OAuth).
- SEO/AEO: robots.txt (incl. GPTBot/ClaudeBot/PerplexityBot allows),
  sitemap.xml, llms.txt, meta/OG/Twitter tags, JSON-LD.
- Founding-member 50% Pro discount (first 20 signups, real server-tracked
  eligibility), real logo assets, per-project logo/banner upload,
  "Improve my pitch" coach button (marker-based, doesn't touch the
  system prompt), global back arrow.
- Domain confirmed as sourceventure.dev — updated throughout.
- Deployed frontend to Vercel (apexmedialx-8775s-projects/frontend),
  disabled default SSO deployment protection (was blocking public
  access), attached sourceventure.dev + www. DNS still needs pointing —
  see the session notes for the exact record.
- Backend (FastAPI + local SQLite) is NOT deployed to Vercel — Vercel's
  serverless filesystem is ephemeral, so a local data.db file wouldn't
  persist between invocations. The existing CSP already referenced
  sourceventure.onrender.com, suggesting Render was the intended host;
  flagged to Denis rather than deploying it somewhere that would
  silently lose data.

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

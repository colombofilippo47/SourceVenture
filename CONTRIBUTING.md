# Working as two people on one repo

The frontend only ever talks to the backend over HTTP (see
`frontend/README.md`), so the two sides can move independently as long as
the API contract in `backend/README.md`'s endpoint table doesn't change
without a heads-up.

## Day to day

1. **Branch per change**, not commits straight to `main`:
   - `git checkout -b backend/<short-description>`
   - `git checkout -b frontend/<short-description>`
2. **Open a PR into `main`**, don't push directly. `CODEOWNERS` auto-requests
   the other person's review only when a PR touches *their* folder.
3. **If you change an API endpoint's shape** (new field, renamed field,
   different status code) — say so in the PR description explicitly.
   There are no integration tests yet (see `backend/README.md`'s "Before
   this goes anywhere public" list), so this is the one place a backend
   change can silently break the frontend.
4. Keep `backend/.env.example` and `frontend/README.md`'s
   `window.SOURCEVENTURE_API_BASE` note up to date if local setup changes.

## Branch protection (set once, in GitHub repo Settings → Branches)

Recommended for `main`, once both people are added as collaborators:
- Require a pull request before merging.
- Require 1 approval.
- (Optional, once there's CI) require status checks to pass.

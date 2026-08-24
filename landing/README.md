# Landing

A standalone marketing hero page — React + Vite + Framer Motion (`motion`),
plain CSS, no Tailwind. Separate from `frontend/` (the actual app, a
no-build-step single HTML file): this is only the animated hero/footer
section, not wired into the app's routing.

## Run locally

```bash
cd landing
npm install
npm run dev
```

Opens on http://localhost:5600.

## Notes

- The background video is loaded from an external CDN URL. Swap
  `VIDEO_URL` in `src/App.jsx` for your own asset if you'd rather not
  depend on it.
- `npm run build` outputs a static `dist/` you can host anywhere (e.g. as
  the actual marketing page in front of the app, or folded into
  `frontend/` later if you want a single deploy).

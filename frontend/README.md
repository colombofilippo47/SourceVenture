# Frontend

Single-page app in `index.html` — no build step. It talks to the [backend](../backend) for the AI coach and for storing published projects; everything else (your name, drafts, coach chat history) lives in the browser's `localStorage`.

## Run locally

```bash
cd frontend
python3 -m http.server 5500
```

Then open http://localhost:5500. Make sure the [backend](../backend) is running on port 8000 first (or set `window.SOURCEVENTURE_API_BASE` before the app loads if it's hosted elsewhere).

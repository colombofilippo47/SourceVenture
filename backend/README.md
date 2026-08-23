# Backend

FastAPI server for SourceVenture. Holds the Anthropic API key server-side (never exposed to the browser) and stores published projects in SQLite.

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

- `GET /api/health`
- `GET /api/projects` — list published projects
- `GET /api/projects/{id}` — get one project
- `PUT /api/projects/{id}` — create/update a project
- `POST /api/coach` — proxies a chat turn to the Anthropic API

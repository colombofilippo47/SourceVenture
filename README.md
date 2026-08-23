# SourceVenture
Connecting investors to developers.

## Project structure

- `frontend/` — single-page app (see [frontend/README.md](frontend/README.md))
- `backend/` — Python/FastAPI server that holds the Anthropic API key and stores published projects (see [backend/README.md](backend/README.md))

## Running locally

Start the backend first, then the frontend, in two terminals:

```bash
# terminal 1
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # paste your ANTHROPIC_API_KEY into .env
uvicorn main:app --reload --port 8000
```

```bash
# terminal 2
cd frontend
python3 -m http.server 5500
```

Then open http://localhost:5500.

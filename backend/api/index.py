# Vercel Python entrypoint. Vercel's Python runtime looks under api/ for a
# file exporting an ASGI `app` object and serves it directly — this file is
# the whole adapter, no rewrite of main.py's own routes/logic needed.
import sys
from pathlib import Path

# main.py lives one directory up (backend/), not inside api/ — add it to
# the import path so `from main import app` resolves the same way it does
# when running `uvicorn main:app` locally from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import app  # noqa: E402

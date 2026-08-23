import json
import os
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
DB_PATH = Path(__file__).parent / "data.db"

app = FastAPI(title="SourceVenture API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            published_at INTEGER,
            updated_at INTEGER NOT NULL,
            data TEXT NOT NULL
        )"""
    )
    return conn


class ProjectIn(BaseModel):
    id: str
    status: str = "draft"
    publishedAt: Optional[int] = None

    class Config:
        extra = "allow"


class CoachMessage(BaseModel):
    role: str
    content: str


class CoachRequest(BaseModel):
    system: str
    messages: List[CoachMessage]
    maxTokens: Optional[int] = 1200


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/projects")
def list_projects():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT data FROM projects WHERE status = 'published' ORDER BY published_at DESC"
        ).fetchall()
        return [json.loads(r[0]) for r in rows]
    finally:
        conn.close()


@app.get("/api/projects/{project_id}")
def get_project(project_id: str):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT data FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        return json.loads(row[0])
    finally:
        conn.close()


@app.put("/api/projects/{project_id}")
def upsert_project(project_id: str, project: ProjectIn):
    if project.id != project_id:
        raise HTTPException(status_code=400, detail="id mismatch")
    now = int(time.time() * 1000)
    payload = project.model_dump()
    payload["updatedAt"] = now
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO projects (id, status, published_at, updated_at, data)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 status=excluded.status,
                 published_at=excluded.published_at,
                 updated_at=excluded.updated_at,
                 data=excluded.data""",
            (project_id, payload.get("status", "draft"), payload.get("publishedAt"), now, json.dumps(payload)),
        )
        conn.commit()
        return payload
    finally:
        conn.close()


@app.post("/api/coach")
async def coach(req: CoachRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY is not configured on the server")

    async with httpx.AsyncClient(timeout=60) as client:
        res = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": req.maxTokens or 1200,
                "system": req.system,
                "messages": [m.model_dump() for m in req.messages],
            },
        )
    if res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Anthropic API error ({res.status_code})")

    data = res.json()
    text = next((b["text"] for b in data.get("content", []) if b.get("type") == "text"), "")
    return {"text": text}

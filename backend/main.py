"""
SourceVenture backend.

What this app does
-------------------
SourceVenture lets a founder publish a project (pitch + a public GitHub repo),
talk privately to an AI coach that reads the real repo, and optionally publish
an investor-facing summary into a gated directory.

This server is the only thing that ever holds secrets (the Anthropic API key)
or writes to the shared database — the frontend is a static single-page app
that talks to these HTTP endpoints. See README.md for the full endpoint list
and how to run everything locally.

Data model (SQLite, one file: data.db)
---------------------------------------
- users:    one row per account (email + salted/hashed password)
- sessions: one row per login, referenced by the `session_token` cookie
- projects: one row per project, JSON blob in `data` plus a few indexed
            columns (owner, status, timestamps) used for filtering

Auth
----
Simple email/password accounts. Passwords are hashed with PBKDF2-HMAC-SHA256
(200k iterations) plus a random salt — never stored or logged in plain text.
Logging in sets an httpOnly, SameSite=Lax session cookie (`session_token`)
that identifies a row in `sessions`; JavaScript never reads the token
directly, which limits the blast radius of an XSS bug. There is no
OAuth/SSO and no email verification — see README.md for what a real
production hardening pass would still add.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
DB_PATH = Path(__file__).parent / "data.db"
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days
PBKDF2_ITERATIONS = 200_000
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
COOKIE_NAME = "session_token"

CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5500").split(",") if o.strip()]

app = FastAPI(title="SourceVenture API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            owner_user_id TEXT,
            status TEXT NOT NULL,
            published_at INTEGER,
            updated_at INTEGER NOT NULL,
            data TEXT NOT NULL
        )"""
    )
    return conn


# ------------------------------------------------------------- rate limiting
# In-memory sliding-window limiter, keyed by (bucket, client ip). Good enough
# for a single-process deployment; a real multi-instance deployment would
# move this to Redis.
_rate_limit_hits: dict = {}


def check_rate_limit(bucket: str, key: str, limit: int, window_seconds: int):
    now = time.time()
    slot = _rate_limit_hits.setdefault((bucket, key), [])
    cutoff = now - window_seconds
    while slot and slot[0] < cutoff:
        slot.pop(0)
    if len(slot) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts — try again later")
    slot.append(now)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def user_public(row) -> dict:
    return {"id": row[0], "email": row[1], "name": row[2]}


def set_session_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


# ------------------------------------------------------------------- models
class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class ProjectIn(BaseModel):
    id: str
    status: str = "draft"
    publishedAt: Optional[int] = None

    class Config:
        extra = "allow"


class CoachMessage(BaseModel):
    role: str
    content: str = Field(max_length=8000)


class CoachRequest(BaseModel):
    system: str
    messages: List[CoachMessage]
    maxTokens: Optional[int] = 1200


# --------------------------------------------------------------------- auth
def get_current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not signed in")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row or row[1] < int(time.time()):
            raise HTTPException(status_code=401, detail="Session expired or invalid")
        user = conn.execute(
            "SELECT id, email, name FROM users WHERE id = ?", (row[0],)
        ).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user_public(user)
    finally:
        conn.close()


def create_session(conn, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now, now + SESSION_TTL_SECONDS),
    )
    return token


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/signup")
def signup(req: SignupRequest, request: Request, response: Response):
    check_rate_limit("signup", client_ip(request), limit=5, window_seconds=600)
    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (req.email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        user_id = secrets.token_hex(12)
        conn.execute(
            "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, req.email, req.name, hash_password(req.password), int(time.time())),
        )
        token = create_session(conn, user_id)
        conn.commit()
        set_session_cookie(response, token)
        return {"user": {"id": user_id, "email": req.email, "name": req.name}}
    finally:
        conn.close()


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    check_rate_limit("login", client_ip(request), limit=10, window_seconds=600)
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email, name, password_hash FROM users WHERE email = ?", (req.email,)
        ).fetchone()
        if not row or not verify_password(req.password, row[3]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_session(conn, row[0])
        conn.commit()
        set_session_cookie(response, token)
        return {"user": {"id": row[0], "email": row[1], "name": row[2]}}
    finally:
        conn.close()


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        conn = get_db()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(current_user=Depends(get_current_user)):
    return current_user


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


@app.get("/api/projects/mine")
def list_my_projects(current_user=Depends(get_current_user)):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT data FROM projects WHERE owner_user_id = ? ORDER BY updated_at DESC",
            (current_user["id"],),
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
def upsert_project(project_id: str, project: ProjectIn, current_user=Depends(get_current_user)):
    if project.id != project_id:
        raise HTTPException(status_code=400, detail="id mismatch")
    now = int(time.time() * 1000)
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT owner_user_id FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if existing and existing[0] and existing[0] != current_user["id"]:
            raise HTTPException(status_code=403, detail="You don't own this project")

        payload = project.model_dump()
        payload["updatedAt"] = now
        payload["ownerUserId"] = current_user["id"]
        conn.execute(
            """INSERT INTO projects (id, owner_user_id, status, published_at, updated_at, data)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 status=excluded.status,
                 published_at=excluded.published_at,
                 updated_at=excluded.updated_at,
                 data=excluded.data""",
            (project_id, current_user["id"], payload.get("status", "draft"), payload.get("publishedAt"), now, json.dumps(payload)),
        )
        conn.commit()
        return payload
    finally:
        conn.close()


@app.post("/api/coach")
async def coach(req: CoachRequest, request: Request, current_user=Depends(get_current_user)):
    check_rate_limit("coach", current_user["id"], limit=30, window_seconds=3600)
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY is not configured on the server")
    if len(req.messages) > 60:
        raise HTTPException(status_code=400, detail="Conversation too long")

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
                "max_tokens": min(req.maxTokens or 1200, 4096),
                "system": req.system,
                "messages": [m.model_dump() for m in req.messages],
            },
        )
    if res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Anthropic API error ({res.status_code})")

    data = res.json()
    text = next((b["text"] for b in data.get("content", []) if b.get("type") == "text"), "")
    return {"text": text}

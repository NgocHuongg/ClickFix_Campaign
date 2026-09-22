"""Password hashing, cookie sessions and the `current_user` dependency."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request

from .db import get_db, now

COOKIE_NAME = "soc_session"
PBKDF2_ITERATIONS = 390_000
SESSION_SHORT = timedelta(hours=12)
SESSION_REMEMBER = timedelta(days=30)
TS = "%Y-%m-%d %H:%M:%S"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(dk.hex(), hash_hex)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: sqlite3.Connection, user_id: int, remember: bool) -> tuple[str, timedelta]:
    token = secrets.token_urlsafe(32)
    ttl = SESSION_REMEMBER if remember else SESSION_SHORT
    expires = (datetime.now() + ttl).strftime(TS)
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
    db.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)",
               (_token_hash(token), user_id, now(), expires))
    db.execute("UPDATE users SET last_login=? WHERE id=?", (now(), user_id))
    db.commit()
    return token, ttl


def delete_session(db: sqlite3.Connection, token: str | None) -> None:
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
        db.commit()


def public_user(u: sqlite3.Row | dict) -> dict:
    return {k: u[k] for k in ("id", "username", "email", "full_name", "role", "created_at")}


def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Not authenticated")
    u = db.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash=? AND s.expires_at > ?",
        (_token_hash(token), now())).fetchone()
    if not u:
        raise HTTPException(401, "Session expired")
    return public_user(u)


def ensure_demo_user(db: sqlite3.Connection) -> None:
    """Training convenience: a known analyst account when no users exist yet."""
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute("INSERT INTO users(username,email,full_name,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
                   ("analyst", "analyst@soc.local", "SOC Analyst", hash_password("Analyst@123"), "Tier 1 Analyst", now()))
        db.commit()

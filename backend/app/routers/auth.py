"""Authentication: register, login, logout, current user."""
from __future__ import annotations

import os
import re
import sqlite3
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from ..auth import (COOKIE_NAME, create_session, delete_session, get_current_user, hash_password, public_user,
                    verify_password)
from ..db import get_db, now

router = APIRouter(prefix="/auth", tags=["auth"])
SECURE_COOKIE = os.environ.get("SOC_SECURE_COOKIE", "0") == "1"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# naive in-memory brute-force protection: 5 failures / 5 minutes per client IP
FAIL_WINDOW, FAIL_LIMIT = 300, 5
_failures: dict[str, deque] = defaultdict(deque)


def _check_rate(ip: str) -> None:
    q = _failures[ip]
    while q and q[0] < time.time() - FAIL_WINDOW:
        q.popleft()
    if len(q) >= FAIL_LIMIT:
        wait = int(FAIL_WINDOW - (time.time() - q[0])) + 1
        raise HTTPException(429, f"Too many failed attempts. Try again in {wait} seconds.")


class RegisterBody(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=80)
    username: str
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Full name is too short")
        return v

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3-32 characters: letters, digits, _ . -")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        if len(v) < 8 or not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password must be at least 8 characters and contain letters and digits")
        return v


class LoginBody(BaseModel):
    login: str = Field(..., max_length=254)        # username or email
    password: str = Field(..., max_length=128)
    remember: bool = False


def _set_cookie(resp: Response, token: str, ttl, remember: bool) -> None:
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", secure=SECURE_COOKIE, path="/",
                    max_age=int(ttl.total_seconds()) if remember else None)


@router.post("/register", status_code=201)
def register(body: RegisterBody, resp: Response, db: sqlite3.Connection = Depends(get_db)):
    taken = db.execute("SELECT username = ? COLLATE NOCASE FROM users WHERE username = ? COLLATE NOCASE "
                       "OR email = ? COLLATE NOCASE", (body.username, body.username, body.email)).fetchone()
    if taken:
        field = "username" if taken[0] else "email"
        raise HTTPException(409, {"message": f"That {field} is already registered", "field": field})
    cur = db.execute("INSERT INTO users(username,email,full_name,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
                     (body.username, body.email, body.full_name, hash_password(body.password), "Tier 1 Analyst", now()))
    db.commit()
    token, ttl = create_session(db, cur.lastrowid, remember=False)
    _set_cookie(resp, token, ttl, remember=False)
    return public_user(db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())


@router.post("/login")
def login(body: LoginBody, request: Request, resp: Response, db: sqlite3.Connection = Depends(get_db)):
    ip = request.client.host if request.client else "?"
    _check_rate(ip)
    u = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                   (body.login.strip(), body.login.strip())).fetchone()
    if not u or not verify_password(body.password, u["password_hash"]):
        _failures[ip].append(time.time())
        raise HTTPException(401, "Invalid username or password")
    _failures.pop(ip, None)
    token, ttl = create_session(db, u["id"], body.remember)
    _set_cookie(resp, token, ttl, body.remember)
    return public_user(u)


@router.post("/logout", status_code=204)
def logout(request: Request, resp: Response, db: sqlite3.Connection = Depends(get_db)):
    delete_session(db, request.cookies.get(COOKIE_NAME))
    resp.delete_cookie(COOKIE_NAME, path="/")


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return user

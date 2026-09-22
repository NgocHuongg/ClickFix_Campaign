"""SQLite access layer."""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
DB_DIR = ROOT / "database"
DB_PATH = Path(os.environ.get("SOC_DB_PATH", DB_DIR / "soc.db"))


def ensure_database() -> None:
    """Create and seed the database on first start; apply idempotent schema (new tables) on every start."""
    if not DB_PATH.exists():
        spec = importlib.util.spec_from_file_location("soc_seed", DB_DIR / "seed.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.seed(DB_PATH)
    from .auth import ensure_demo_user   # local import: auth depends on this module

    con = connect()
    try:
        con.executescript((DB_DIR / "schema.sql").read_text(encoding="utf-8"))
        ensure_demo_user(con)
    finally:
        con.close()


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI dependency: one connection per request."""
    con = connect()
    try:
        yield con
    finally:
        con.close()


def row(r: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for f in json_fields:
        if f in d and isinstance(d[f], str):
            d[f] = json.loads(d[f])
    return d


def rows(rs, json_fields: tuple[str, ...] = ()) -> list[dict]:
    return [row(r, json_fields) for r in rs]


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def paginate(page: int, page_size: int) -> tuple[int, int]:
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    return page_size, (page - 1) * page_size

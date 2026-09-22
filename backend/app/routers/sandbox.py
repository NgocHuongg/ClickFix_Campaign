"""Sandbox: dynamic analysis reports."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from ..db import get_db, row, rows

router = APIRouter(prefix="/sandbox", tags=["sandbox"])
JSON = ("report",)


@router.get("")
def list_reports(search: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    where, params = "1=1", []
    if search:
        s = search.strip()
        where = "(file_name LIKE ? OR sha256 = ? COLLATE NOCASE OR md5 = ? COLLATE NOCASE)"
        params = [f"%{s}%", s, s]
    return rows(db.execute(f"SELECT * FROM sandbox_reports WHERE {where} ORDER BY submitted_at DESC", params), JSON)


@router.get("/{report_id}")
def get_report(report_id: int, db: sqlite3.Connection = Depends(get_db)):
    r = row(db.execute("SELECT * FROM sandbox_reports WHERE id=?", (report_id,)).fetchone(), JSON)
    if not r:
        raise HTTPException(404, "Report not found")
    return r

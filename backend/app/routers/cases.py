"""Case Management."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import get_current_user
from ..db import get_db, now, row, rows

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    alert_id: int | None = None
    title: str = Field(..., min_length=3, max_length=300)
    severity: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    description: str = Field("", max_length=8000)


class CaseUpdate(BaseModel):
    status: Literal["Open", "In Progress", "Closed"] | None = None
    verdict: Literal["True Positive", "False Positive"] | None = None
    assignee: str | None = Field(None, max_length=100)
    description: str | None = Field(None, max_length=8000)


class NoteCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=8000)


def _get(db, case_id: int) -> dict:
    c = row(db.execute(
        "SELECT c.*, a.rule_name AS alert_rule, a.event_id AS alert_event_id FROM cases c "
        "LEFT JOIN alerts a ON a.id = c.alert_id WHERE c.id=?", (case_id,)).fetchone())
    if not c:
        raise HTTPException(404, "Case not found")
    c["notes"] = rows(db.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at", (case_id,)))
    return c


@router.get("")
def list_cases(status: str | None = None, search: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    where, params = ["1=1"], []
    if status:
        where.append("c.status = ?"); params.append(status)
    if search:
        where.append("(c.title LIKE ? OR c.description LIKE ?)"); params += [f"%{search}%"] * 2
    return rows(db.execute(
        "SELECT c.*, a.event_id AS alert_event_id, (SELECT COUNT(*) FROM case_notes n WHERE n.case_id=c.id) AS note_count "
        f"FROM cases c LEFT JOIN alerts a ON a.id=c.alert_id WHERE {' AND '.join(where)} ORDER BY c.updated_at DESC",
        params))


@router.post("", status_code=201)
def create_case(body: CaseCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    if body.alert_id is not None:
        if not db.execute("SELECT 1 FROM alerts WHERE id=?", (body.alert_id,)).fetchone():
            raise HTTPException(404, "Alert not found")
        existing = db.execute("SELECT id FROM cases WHERE alert_id=?", (body.alert_id,)).fetchone()
        if existing:
            raise HTTPException(409, {"message": "A case already exists for this alert", "case_id": existing[0]})
    ts = now()
    cur = db.execute("INSERT INTO cases(alert_id,title,severity,status,assignee,description,created_at,updated_at) "
                     "VALUES (?,?,?,?,?,?,?,?)",
                     (body.alert_id, body.title, body.severity, "Open", user["full_name"], body.description, ts, ts))
    db.execute("INSERT INTO case_notes(case_id,author,body,created_at) VALUES (?,?,?,?)",
               (cur.lastrowid, user["full_name"], "Case created.", ts))
    db.commit()
    return _get(db, cur.lastrowid)


@router.get("/{case_id}")
def get_case(case_id: int, db: sqlite3.Connection = Depends(get_db)):
    return _get(db, case_id)


@router.patch("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    before = _get(db, case_id)
    changes = body.model_dump(exclude_none=True)
    if not changes:
        return before
    sets = ", ".join(f"{k}=?" for k in changes)   # keys constrained by the pydantic model
    db.execute(f"UPDATE cases SET {sets}, updated_at=? WHERE id=?", [*changes.values(), now(), case_id])
    summary = ", ".join(f"{k}: {before.get(k) or '-'} → {v}" for k, v in changes.items() if k != "description")
    if summary:
        db.execute("INSERT INTO case_notes(case_id,author,body,created_at) VALUES (?,?,?,?)",
                   (case_id, user["full_name"], f"Updated {summary}", now()))
    db.commit()
    return _get(db, case_id)


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    _get(db, case_id)
    db.execute("INSERT INTO case_notes(case_id,author,body,created_at) VALUES (?,?,?,?)",
               (case_id, user["full_name"], body.body, now()))
    db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now(), case_id))
    db.commit()
    return _get(db, case_id)

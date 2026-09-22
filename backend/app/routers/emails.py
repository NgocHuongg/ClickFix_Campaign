"""Email Security: mailbox view and response actions."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db import get_db, row, rows

router = APIRouter(prefix="/emails", tags=["emails"])
JSON = ("attachments",)


class ActionBody(BaseModel):
    action: Literal["Allowed", "Blocked", "Quarantined", "Deleted"]


@router.get("")
def list_emails(search: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    where, params = "1=1", []
    if search:
        where = "(sender LIKE ? OR recipient LIKE ? OR subject LIKE ? OR smtp_ip LIKE ?)"
        params = [f"%{search}%"] * 4
    return rows(db.execute(f"SELECT * FROM emails WHERE {where} ORDER BY received_at DESC", params), JSON)


@router.get("/{email_id}")
def get_email(email_id: int, db: sqlite3.Connection = Depends(get_db)):
    e = row(db.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone(), JSON)
    if not e:
        raise HTTPException(404, "Email not found")
    return e


@router.post("/{email_id}/action")
def set_action(email_id: int, body: ActionBody, db: sqlite3.Connection = Depends(get_db)):
    get_email(email_id, db)
    db.execute("UPDATE emails SET action=? WHERE id=?", (body.action, email_id))
    db.commit()
    return get_email(email_id, db)

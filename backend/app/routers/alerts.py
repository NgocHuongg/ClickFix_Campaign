"""Monitoring: alert queue (Main / Investigation / Closed channels)."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import get_current_user
from ..db import get_db, now, paginate, row, rows

router = APIRouter(prefix="/alerts", tags=["alerts"])
JSON = ("details",)


class CloseBody(BaseModel):
    verdict: Literal["True Positive", "False Positive"]
    note: str = Field("", max_length=4000)


def _get(db, alert_id: int) -> dict:
    a = row(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone(), JSON)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@router.get("")
def list_alerts(status: Literal["main", "investigation", "closed"] = "main", page: int = 1, page_size: int = 10,
                severity: str | None = None, type: str | None = None, search: str | None = None,
                db: sqlite3.Connection = Depends(get_db)):
    where, params = ["status = ?"], [status]
    if severity:
        sev = [s for s in severity.split(",") if s]
        where.append(f"severity IN ({','.join('?' * len(sev))})"); params += sev
    if type:
        where.append("type = ?"); params.append(type)
    if search:
        where.append("(rule_name LIKE ? OR CAST(event_id AS TEXT) LIKE ? OR details LIKE ?)")
        params += [f"%{search}%"] * 3
    w = " AND ".join(where)
    limit, offset = paginate(page, page_size)
    total = db.execute(f"SELECT COUNT(*) FROM alerts WHERE {w}", params).fetchone()[0]
    order = "closed_at DESC" if status == "closed" else "created_at DESC"
    items = rows(db.execute(f"SELECT * FROM alerts WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?",
                            params + [limit, offset]).fetchall(), JSON)
    return {"total": total, "page": page, "pages": max(1, -(-total // limit)), "items": items}


@router.get("/stats")
def stats(db: sqlite3.Connection = Depends(get_db)):
    counts = {r["status"]: r["c"] for r in db.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status")}
    types = [r[0] for r in db.execute("SELECT DISTINCT type FROM alerts ORDER BY type")]
    by_sev: dict[str, dict[str, int]] = {s: {} for s in ("main", "investigation", "closed")}
    for r in db.execute("SELECT status, severity, COUNT(*) c FROM alerts GROUP BY status, severity"):
        by_sev[r["status"]][r["severity"]] = r["c"]
    return {"main": counts.get("main", 0), "investigation": counts.get("investigation", 0),
            "closed": counts.get("closed", 0), "types": types, "by_severity": by_sev}


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: sqlite3.Connection = Depends(get_db)):
    a = _get(db, alert_id)
    a["case"] = row(db.execute("SELECT id, title, status FROM cases WHERE alert_id=?", (alert_id,)).fetchone())
    return a


@router.post("/{alert_id}/take")
def take_ownership(alert_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    a = _get(db, alert_id)
    if a["status"] != "main":
        raise HTTPException(409, "Alert is not in the main channel")
    db.execute("UPDATE alerts SET status='investigation', owner=? WHERE id=?", (user["full_name"], alert_id))
    db.commit()
    return _get(db, alert_id)


@router.post("/{alert_id}/release")
def release(alert_id: int, db: sqlite3.Connection = Depends(get_db)):
    a = _get(db, alert_id)
    if a["status"] != "investigation":
        raise HTTPException(409, "Alert is not under investigation")
    db.execute("UPDATE alerts SET status='main', owner=NULL WHERE id=?", (alert_id,))
    db.commit()
    return _get(db, alert_id)


@router.post("/{alert_id}/close")
def close_alert(alert_id: int, body: CloseBody, db: sqlite3.Connection = Depends(get_db),
                user: dict = Depends(get_current_user)):
    a = _get(db, alert_id)
    if a["status"] == "closed":
        raise HTTPException(409, "Alert already closed")
    db.execute("UPDATE alerts SET status='closed', owner=COALESCE(owner, ?), verdict=?, close_note=?, closed_at=? "
               "WHERE id=?", (user["full_name"], body.verdict, body.note, now(), alert_id))
    db.execute("UPDATE cases SET status='Closed', verdict=?, updated_at=? WHERE alert_id=? AND status != 'Closed'",
               (body.verdict, now(), alert_id))
    db.commit()
    return _get(db, alert_id)

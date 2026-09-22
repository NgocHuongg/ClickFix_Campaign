"""Endpoint Security: host inventory, telemetry derived from logs, containment."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db import get_db, row, rows

router = APIRouter(prefix="/endpoints", tags=["endpoints"])
SHELLS = ("%powershell.exe", "%cmd.exe", "/bin/bash", "/bin/sh", "/usr/bin/sudo")


class ContainBody(BaseModel):
    contained: bool


def _get(db, ep_id: int) -> dict:
    e = row(db.execute("SELECT * FROM endpoints WHERE id=?", (ep_id,)).fetchone(), ("browser_history",))
    if not e:
        raise HTTPException(404, "Endpoint not found")
    e["contained"] = bool(e["contained"])
    return e


@router.get("")
def list_endpoints(search: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    where, params = "1=1", []
    if search:
        where = "(hostname LIKE ? OR ip_address LIKE ? OR primary_user LIKE ?)"
        params = [f"%{search}%"] * 3
    out = rows(db.execute(
        "SELECT e.id, e.hostname, e.ip_address, e.os, e.primary_user, e.domain, e.last_seen, e.contained, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.details LIKE '%' || e.hostname || '%' AND a.status != 'closed') "
        f"AS open_alerts FROM endpoints e WHERE {where} ORDER BY e.hostname", params))
    for e in out:
        e["contained"] = bool(e["contained"])
    return out


@router.get("/{ep_id}")
def get_endpoint(ep_id: int, db: sqlite3.Connection = Depends(get_db)):
    e = _get(db, ep_id)
    h = e["hostname"]
    e["processes"] = rows(db.execute(
        "SELECT id, timestamp, process, command_line, username, raw_log FROM logs "
        "WHERE hostname=? AND type='OS' AND process IS NOT NULL ORDER BY timestamp DESC LIMIT 100", (h,)))
    e["network"] = rows(db.execute(
        "SELECT id, timestamp, type, source_address, source_port, destination_address, destination_port, "
        "process, action FROM logs WHERE hostname=? AND type IN ('Network','Proxy','DNS') "
        "ORDER BY timestamp DESC LIMIT 100", (h,)))
    shell_clause = " OR ".join("process LIKE ?" for _ in SHELLS)
    e["terminal_history"] = rows(db.execute(
        f"SELECT id, timestamp, process, command_line, username FROM logs WHERE hostname=? AND type='OS' "
        f"AND command_line IS NOT NULL AND ({shell_clause}) ORDER BY timestamp DESC LIMIT 50", (h, *SHELLS)))
    e["alerts"] = rows(db.execute(
        "SELECT id, event_id, rule_name, severity, status, created_at FROM alerts "
        "WHERE details LIKE ? ORDER BY created_at DESC", (f"%{h}%",)))
    return e


@router.post("/{ep_id}/containment")
def set_containment(ep_id: int, body: ContainBody, db: sqlite3.Connection = Depends(get_db)):
    _get(db, ep_id)
    db.execute("UPDATE endpoints SET contained=? WHERE id=?", (int(body.contained), ep_id))
    db.commit()
    return _get(db, ep_id)

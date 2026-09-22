"""Threat Intel: IOC lookup."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from ..db import get_db, rows

router = APIRouter(prefix="/intel", tags=["intel"])


@router.get("")
def search_iocs(search: str | None = None, ioc_type: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    where, params = ["1=1"], []
    if search:
        where.append("(value LIKE ? OR tags LIKE ? OR threat LIKE ? OR source LIKE ?)")
        params += [f"%{search.strip()}%"] * 4
    if ioc_type:
        where.append("ioc_type = ?"); params.append(ioc_type)
    items = rows(db.execute(f"SELECT * FROM iocs WHERE {' AND '.join(where)} ORDER BY first_seen DESC", params))
    # How often each IOC shows up in our own telemetry - helps pivot to Log Management.
    for i in items:
        i["log_hits"] = db.execute("SELECT COUNT(*) FROM logs WHERE raw_log LIKE ?",
                                   (f"%{i['value']}%",)).fetchone()[0]
    return items

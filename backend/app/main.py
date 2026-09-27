"""SOC Simulation API - FastAPI entry point."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from .auth import get_current_user
from .db import ROOT, ensure_database
from .routers import alerts, auth, cases, clickfix, emails, endpoints, intel, logs, sandbox

FRONTEND_DIR = Path(os.environ.get("SOC_FRONTEND_DIR", ROOT / "frontend"))

ensure_database()

app = FastAPI(title="SOC Simulation API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("SOC_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")

app.include_router(clickfix.router)

# Everything else requires a logged-in analyst.
for r in (alerts.router, logs.router, cases.router, endpoints.router, intel.router, emails.router, sandbox.router):
    app.include_router(r, prefix="/api", dependencies=[Depends(get_current_user)])


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the (build-less) frontend from the same origin for convenience.
# Mounted last so /api/* routes take precedence. The SPA uses hash routing (#/logs).
# JS/CSS files get no-cache headers so the browser always fetches the latest version.
if FRONTEND_DIR.exists():
    _static = StaticFiles(directory=FRONTEND_DIR, html=True)

    @app.middleware("http")
    async def no_cache_js(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.endswith(".js") or path.endswith(".css"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

    app.mount("/", _static, name="frontend")
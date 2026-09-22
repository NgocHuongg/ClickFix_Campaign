@echo off
REM SOC Simulation - install deps (first run) and start API + UI on http://127.0.0.1:8000
cd /d "%~dp0"
python -m pip install -q -r backend\requirements.txt
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

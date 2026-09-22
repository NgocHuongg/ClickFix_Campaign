// When the frontend is served by the FastAPI backend (same origin) leave API_BASE empty.
// When served separately (e.g. `python -m http.server 5173` in /frontend), point it at the API.
const sameOrigin = location.port !== "5173";
export const API_BASE = window.SOC_API_BASE ?? (sameOrigin ? "" : "http://127.0.0.1:8000");
export const PLATFORM_TZ = "+03:00";

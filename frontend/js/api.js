import { API_BASE } from "./config.js";

export class ApiError extends Error {
  constructor(status, detail) {
    let msg;
    if (typeof detail === "string") msg = detail;
    else if (Array.isArray(detail)) msg = detail.map((d) => String(d.msg).replace(/^Value error, /, "")).join(". ");
    else msg = detail?.message || `Request failed (${status})`;
    super(msg);
    this.status = status;
    this.detail = detail;
    // pydantic validation errors -> { field: message }
    this.fields = Array.isArray(detail)
      ? Object.fromEntries(detail.map((d) => [d.loc?.[d.loc.length - 1], String(d.msg).replace(/^Value error, /, "")]))
      : detail?.field ? { [detail.field]: detail.message } : {};
  }
}

async function request(method, path, { params, body, signal } = {}) {
  const url = new URL(API_BASE + "/api" + path, location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    }
  }
  const res = await fetch(url, {
    method,
    signal,
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("soc:unauthorized"));
  }
  if (!res.ok) throw new ApiError(res.status, data?.detail ?? data);
  return data;
}

export const api = {
  get: (path, params, signal) => request("GET", path, { params, signal }),
  post: (path, body) => request("POST", path, { body: body ?? {} }),
  patch: (path, body) => request("PATCH", path, { body }),
};

/* ---------- session ---------- */
export const session = { user: null };

export async function loadSession() {
  try { session.user = await api.get("/auth/me"); } catch { session.user = null; }
  return session.user;
}

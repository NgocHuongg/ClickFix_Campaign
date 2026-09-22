# SOC Simulation

A Security Operations Center training platform with a dark UI: alert triage, log hunting with a query language,
case management, EDR, threat intel, email security and sandbox reports.

```
SOC_Simulation/
├── backend/            FastAPI (Python) REST API
│   ├── app/main.py             app + router registration, also serves /frontend
│   ├── app/query_parser.py     SOC Query Language → parameterized SQL
│   ├── app/routers/            alerts, logs, cases, endpoints, intel, emails, sandbox
│   └── tests/                  query parser unit tests
├── frontend/           Vanilla JS (ES modules, no build step) + CSS
│   ├── index.html · css/styles.css
│   └── js/app.js (router) · api.js · utils.js · views/*.js
└── database/           SQLite
    ├── schema.sql
    └── seed.py                 deterministic training data (20 alerts, 3907 events)
```

## Run

```bat
run.bat
```
or manually:
```bash
python -m pip install -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --port 8000
```
Open http://127.0.0.1:8000 · API docs at http://127.0.0.1:8000/docs.
The database is created and seeded automatically on first start. Reset it with `python database/seed.py`.

To serve the frontend separately: `cd frontend && python -m http.server 5173` (it then calls the API on port 8000).

Tests: `python -m unittest discover -s backend/tests`

## Accounts & pages

- `#/` Landing page · `#/login` · `#/register`. Every console page and every `/api/*` route except `/api/auth/*`
  requires you to be signed in.
- Demo account: **analyst / Analyst@123**. It is created automatically when the database has no users.
- Passwords are hashed with PBKDF2-SHA256 (390k iterations). Sessions use a random token in an HttpOnly,
  SameSite=Lax cookie, and only its SHA-256 hash is stored. Login is rate-limited to 5 failures per 5 minutes per IP.
  Set `SOC_SECURE_COOKIE=1` when you serve the app over HTTPS.

Severity colours: **Critical** red · **High** orange · **Medium** yellow · **Low** green (CSS tokens `--critical`, `--high`, `--medium`, `--low` in `styles.css`).

## Log Management query

**Basic mode**: click a field on the left to see its top values, then **+** (include) or **−** (exclude) to add a
filter chip. Click the chip's operator to flip include/exclude. Type a keyword + Enter to search the raw log text.

**Pro mode** uses a query language with syntax highlighting, autocomplete (Tab), and errors that show the exact position:

| Syntax | Meaning |
|---|---|
| `field=value`, `field!=value` | equals / not equals, case-insensitive; `*` wildcard |
| `> >= < <=` | numbers (ports, id) and `timestamp` |
| `field IN (a,b)`, `field NOT IN (…)` | list match |
| `CONTAINS`, `STARTSWITH`, `ENDSWITH`, `EXISTS` | substring / presence |
| `AND`, `OR`, `NOT` / `!`, `( )` | boolean logic (whitespace means AND) |
| `keyword`, `"a phrase"` | full-text search on `raw_log` |
| `\| sort field [asc\|desc]`, `\| head N` | pipe commands |

Examples:
```
source_address="172.16.20.69" AND type=OS
process=*powershell* NOT destination_address=172.16.20.69
(type=Web OR type=Firewall) AND source_address STARTSWITH 198.51.100 | sort timestamp asc
```
Field names come from a whitelist and every value is a bound SQL parameter, so queries can't inject SQL.
Other features: time ranges (presets or custom), a histogram (click a bar to zoom in), a page size and sort
menu, and the query is kept in the URL, so alerts, endpoints, intel and email can link straight to a log search.

## Monitoring workflow
Main Channel → **Take ownership** (user-plus icon) → Investigation Channel → **Create case** / **Close alert**
(True/False Positive + note) → Closed Alerts. Expand any alert to see its details and links to the related
logs and endpoint.

> Seed scenarios are sanitized for training: attacker infrastructure uses documentation IP ranges and `.example`
> domains, and exploit parameters are replaced with `<redacted>`.

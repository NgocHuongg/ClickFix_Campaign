-- SOC Simulation - SQLite schema
-- All timestamps are stored as 'YYYY-MM-DD HH:MM:SS' in platform local time (UTC+03:00)
-- so that lexicographic comparison == chronological comparison.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL UNIQUE,
    severity        TEXT    NOT NULL CHECK (severity IN ('Low','Medium','High','Critical')),
    created_at      TEXT    NOT NULL,
    rule_name       TEXT    NOT NULL,
    type            TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'main' CHECK (status IN ('main','investigation','closed')),
    owner           TEXT,
    verdict         TEXT    CHECK (verdict IN ('True Positive','False Positive')),
    close_note      TEXT,
    closed_at       TEXT,
    details         TEXT    NOT NULL DEFAULT '{}'   -- JSON: hostname, ip, file, hash, command line...
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    type                TEXT    NOT NULL,
    source_address      TEXT,
    source_port         INTEGER,
    destination_address TEXT,
    destination_port    INTEGER,
    hostname            TEXT,
    username            TEXT,
    process             TEXT,
    command_line        TEXT,
    action              TEXT,
    raw_log             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_ts   ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type);
CREATE INDEX IF NOT EXISTS idx_logs_src  ON logs(source_address);
CREATE INDEX IF NOT EXISTS idx_logs_dst  ON logs(destination_address);

CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','In Progress','Closed')),
    verdict     TEXT,
    assignee    TEXT,
    description TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author      TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL UNIQUE,
    ip_address      TEXT NOT NULL,
    os              TEXT NOT NULL,
    primary_user    TEXT,
    domain          TEXT,
    last_seen       TEXT,
    contained       INTEGER NOT NULL DEFAULT 0,
    browser_history TEXT NOT NULL DEFAULT '[]'  -- JSON list of {time,url}
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('ip','domain','url','md5','sha256')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    tags        TEXT,
    threat      TEXT,
    confidence  INTEGER NOT NULL DEFAULT 50,
    first_seen  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

CREATE TABLE IF NOT EXISTS emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    smtp_ip     TEXT,
    body        TEXT NOT NULL,
    attachments TEXT NOT NULL DEFAULT '[]',   -- JSON list of {name,size,md5}
    action      TEXT NOT NULL DEFAULT 'Allowed' CHECK (action IN ('Allowed','Blocked','Quarantined','Deleted'))
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name       TEXT NOT NULL,
    password_hash   TEXT NOT NULL,              -- pbkdf2_sha256$iterations$salt$hash
    role            TEXT NOT NULL DEFAULT 'Analyst',
    created_at      TEXT NOT NULL,
    last_login      TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,               -- sha256 of the cookie token (raw token never stored)
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS sandbox_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name   TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    md5         TEXT NOT NULL,
    file_type   TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('Malicious','Suspicious','Clean')),
    score       INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    report      TEXT NOT NULL DEFAULT '{}'   -- JSON: processes, network, mitre, signatures
);

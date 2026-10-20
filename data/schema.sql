-- sigtool — lược đồ cơ sở dữ liệu SQLite
-- Sinh lại từ đầu:  sqlite3 data/sigtool.db < data/schema.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS key_pair (
    key_id           TEXT PRIMARY KEY,
    alg              TEXT NOT NULL CHECK (alg IN ('rsa_pss_2048','rsa_pss_3072','ecdsa_p256','ed25519')),
    public_key_pem   TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    fingerprint      TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','rotating','revoked','expired')),
    owner            TEXT
);

CREATE TABLE IF NOT EXISTS trust_list (
    version    INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    note       TEXT,
    sha256     TEXT
);

CREATE TABLE IF NOT EXISTS trust_list_entry (
    entry_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    trust_list_version  INTEGER NOT NULL REFERENCES trust_list(version),
    key_id              TEXT    NOT NULL REFERENCES key_pair(key_id),
    valid_from          TEXT    NOT NULL,
    valid_to            TEXT,
    UNIQUE (trust_list_version, key_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE IF NOT EXISTS artifact (
    artifact_id TEXT PRIMARY KEY,
    path        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('binary','document','manifest')),
    size_bytes  INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    is_tampered INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS manifest (
    manifest_id TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    key_id      TEXT REFERENCES key_pair(key_id),
    sha256      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_entry (
    entry_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_id    TEXT NOT NULL REFERENCES manifest(manifest_id),
    artifact_id    TEXT NOT NULL REFERENCES artifact(artifact_id),
    sha256_at_time TEXT NOT NULL,
    size_at_time   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signature (
    signature_id    TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL,
    target_kind     TEXT NOT NULL CHECK (target_kind IN ('artifact','manifest')),
    key_id          TEXT NOT NULL REFERENCES key_pair(key_id),
    alg             TEXT NOT NULL,
    sig_path        TEXT NOT NULL,
    sig_size_bytes  INTEGER NOT NULL,
    signed_at       TEXT NOT NULL,
    timestamp_token TEXT
);

CREATE TABLE IF NOT EXISTS verification_log (
    log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id       TEXT NOT NULL REFERENCES signature(signature_id),
    verified_at        TEXT NOT NULL,
    result             TEXT NOT NULL CHECK (result IN ('pass','fail')),
    reason_code        TEXT NOT NULL,
    trust_list_version INTEGER,
    verifier           TEXT,
    duration_ms        REAL
);

CREATE TABLE IF NOT EXISTS revocation (
    revocation_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id              TEXT NOT NULL UNIQUE REFERENCES key_pair(key_id),
    revoked_at          TEXT NOT NULL,
    reason              TEXT NOT NULL,
    action_taken        TEXT,
    affected_signatures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS benchmark_run (
    run_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    alg                TEXT NOT NULL,
    operation          TEXT NOT NULL CHECK (operation IN ('sign','verify')),
    iteration          INTEGER NOT NULL,
    payload_size_bytes INTEGER NOT NULL,
    key_size_bytes     INTEGER,
    sig_size_bytes     INTEGER,
    duration_ms        REAL NOT NULL,
    run_at             TEXT NOT NULL,
    machine            TEXT
);

CREATE INDEX IF NOT EXISTS idx_sig_key  ON signature(key_id);
CREATE INDEX IF NOT EXISTS idx_log_sig  ON verification_log(signature_id);
CREATE INDEX IF NOT EXISTS idx_bench    ON benchmark_run(alg, operation);

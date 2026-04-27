CREATE TABLE IF NOT EXISTS identity (
    public_key      TEXT PRIMARY KEY,
    private_key     BLOB NOT NULL,
    onion_address   TEXT NOT NULL,
    alias           TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    default_ttl     INTEGER DEFAULT 604800
);

CREATE TABLE IF NOT EXISTS relay_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    onion_address   TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    enabled         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS contacts (
    public_key      TEXT PRIMARY KEY,
    onion_address   TEXT NOT NULL,
    alias           TEXT,
    trusted_since   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY,
    from_key        TEXT NOT NULL,
    to_key          TEXT NOT NULL,
    payload         BLOB NOT NULL,
    signature       BLOB NOT NULL,
    timestamp       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    status          TEXT NOT NULL
        CHECK (status IN ('queued', 'sent', 'delivered', 'failed')),
    read_at         INTEGER DEFAULT NULL,
    file_name       TEXT DEFAULT NULL,
    mime_type       TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    group_key       BLOB NOT NULL,
    admin_key       TEXT NOT NULL,
    is_admin        INTEGER DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_read_at    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id        TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    onion_address   TEXT NOT NULL DEFAULT '',
    alias_hint      TEXT NOT NULL DEFAULT '',
    added_at        INTEGER NOT NULL,
    PRIMARY KEY (group_id, public_key)
);

CREATE TABLE IF NOT EXISTS group_posts (
    id              TEXT PRIMARY KEY,
    group_id        TEXT NOT NULL,
    author_key      TEXT NOT NULL,
    payload         BLOB NOT NULL,
    signature       BLOB NOT NULL,
    timestamp       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_queue (
    id                  TEXT PRIMARY KEY,
    message_id          TEXT NOT NULL,
    destination_key     TEXT NOT NULL,
    destination_onion   TEXT NOT NULL,
    message_json        TEXT NOT NULL DEFAULT '',
    next_retry_at       INTEGER NOT NULL,
    retry_count         INTEGER DEFAULT 0,
    via_relay           INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS relay_identity (
    public_key      TEXT PRIMARY KEY,
    private_key     BLOB NOT NULL,
    onion_address   TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS authorized_senders (
    public_key      TEXT PRIMARY KEY,
    alias           TEXT,
    added_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stored_messages (
    id                  TEXT PRIMARY KEY,
    sender_key          TEXT NOT NULL,
    for_key             TEXT NOT NULL,
    destination_onion   TEXT NOT NULL,
    payload             BLOB NOT NULL,
    received_at         INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    next_retry_at       INTEGER NOT NULL,
    retry_count         INTEGER DEFAULT 0,
    status              TEXT NOT NULL
        CHECK (status IN ('queued', 'delivered', 'failed'))
);

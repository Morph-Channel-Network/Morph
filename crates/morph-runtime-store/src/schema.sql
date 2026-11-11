CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    store_id BLOB NOT NULL CHECK (length(store_id) = 32),
    encrypted INTEGER NOT NULL CHECK (encrypted IN (0, 1)),
    key_check BLOB NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
CREATE TABLE commits (
    operation_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER UNIQUE NOT NULL CHECK (revision > 0),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    intent BLOB NOT NULL,
    UNIQUE(operation_id, revision)
) STRICT;
CREATE TABLE records (
    family TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL REFERENCES commits(revision),
    payload BLOB NOT NULL,
    PRIMARY KEY (family, record_id)
) STRICT;
CREATE TABLE outbox (
    event_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES commits(operation_id),
    revision INTEGER NOT NULL REFERENCES commits(revision),
    payload BLOB NOT NULL,
    FOREIGN KEY(operation_id, revision) REFERENCES commits(operation_id, revision)
) STRICT;
CREATE INDEX outbox_revision ON outbox(revision, event_id);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES commits(operation_id),
    revision INTEGER NOT NULL REFERENCES commits(revision),
    payload BLOB NOT NULL,
    FOREIGN KEY(operation_id, revision) REFERENCES commits(operation_id, revision)
) STRICT;
CREATE INDEX attempts_revision ON attempts(revision, attempt_id);

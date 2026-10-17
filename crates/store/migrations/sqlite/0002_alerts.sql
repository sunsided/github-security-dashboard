-- Current state of every alert ever seen, one row per repository, source
-- and alert number.
CREATE TABLE alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id        INTEGER NOT NULL REFERENCES repos (id),
    source         TEXT    NOT NULL,
    number         INTEGER NOT NULL,
    state          TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    location       TEXT,
    html_url       TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    closed_at      TEXT,
    estimated      INTEGER NOT NULL DEFAULT 0,
    first_seen_run INTEGER NOT NULL REFERENCES runs (id),
    last_seen_run  INTEGER NOT NULL REFERENCES runs (id),
    UNIQUE (repo_id, source, number)
);

CREATE INDEX alerts_open_by_repo ON alerts (repo_id, state);

-- Append-only audit log of alert state changes. Never updated or deleted.
CREATE TABLE alert_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts (id),
    run_id   INTEGER NOT NULL REFERENCES runs (id),
    at       TEXT    NOT NULL,
    kind     TEXT    NOT NULL,
    old      TEXT,
    new      TEXT
);

CREATE INDEX alert_events_by_alert ON alert_events (alert_id, id);
CREATE INDEX alert_events_by_time ON alert_events (at);

CREATE TRIGGER alert_events_no_update BEFORE UPDATE ON alert_events
BEGIN
    SELECT RAISE(ABORT, 'alert_events is append-only');
END;

CREATE TRIGGER alert_events_no_delete BEFORE DELETE ON alert_events
BEGIN
    SELECT RAISE(ABORT, 'alert_events is append-only');
END;

-- Whether each alert source could be read for a repository, as of the
-- last time it was checked.
CREATE TABLE repo_sources (
    repo_id    INTEGER NOT NULL REFERENCES repos (id),
    source     TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    message    TEXT,
    checked_at TEXT    NOT NULL,
    run_id     INTEGER NOT NULL REFERENCES runs (id),
    PRIMARY KEY (repo_id, source)
);

CREATE TRIGGER repo_snapshots_no_update BEFORE UPDATE ON repo_snapshots
BEGIN
    SELECT RAISE(ABORT, 'repo_snapshots is append-only');
END;

CREATE TRIGGER repo_snapshots_no_delete BEFORE DELETE ON repo_snapshots
BEGIN
    SELECT RAISE(ABORT, 'repo_snapshots is append-only');
END;

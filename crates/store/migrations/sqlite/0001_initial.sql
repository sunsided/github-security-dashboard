CREATE TABLE runs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at           TEXT    NOT NULL,
    finished_at          TEXT,
    status               TEXT    NOT NULL,
    rate_limit_remaining INTEGER,
    errors               TEXT    NOT NULL DEFAULT '[]'
);

CREATE TABLE repos (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner          TEXT    NOT NULL COLLATE NOCASE,
    name           TEXT    NOT NULL COLLATE NOCASE,
    kind           TEXT    NOT NULL,
    url            TEXT    NOT NULL,
    description    TEXT,
    archived       INTEGER NOT NULL,
    fork           INTEGER NOT NULL,
    private        INTEGER NOT NULL,
    language       TEXT,
    default_branch TEXT,
    first_seen_run INTEGER NOT NULL REFERENCES runs (id),
    last_seen_run  INTEGER NOT NULL REFERENCES runs (id),
    UNIQUE (owner, name)
);

-- Append-only time series; one row per repository and collector run.
CREATE TABLE repo_snapshots (
    repo_id        INTEGER NOT NULL REFERENCES repos (id),
    run_id         INTEGER NOT NULL REFERENCES runs (id),
    taken_at       TEXT    NOT NULL,
    open_issues    INTEGER NOT NULL,
    open_prs       INTEGER NOT NULL,
    contributors   INTEGER,
    commits        INTEGER,
    tags           INTEGER NOT NULL,
    releases       INTEGER NOT NULL,
    stars          INTEGER NOT NULL,
    forks          INTEGER NOT NULL,
    pushed_at      TEXT,
    last_commit_at TEXT,
    PRIMARY KEY (repo_id, run_id)
);

CREATE INDEX repo_snapshots_by_repo_time ON repo_snapshots (repo_id, taken_at DESC);

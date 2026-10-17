-- PostgreSQL schema; mirrors the SQLite migrations 0001-0003 in one step.

CREATE TABLE runs (
    id                   BIGSERIAL   PRIMARY KEY,
    started_at           TIMESTAMPTZ NOT NULL,
    finished_at          TIMESTAMPTZ,
    status               TEXT        NOT NULL,
    rate_limit_remaining BIGINT,
    errors               JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE repos (
    id             BIGSERIAL PRIMARY KEY,
    owner          TEXT      NOT NULL,
    name           TEXT      NOT NULL,
    kind           TEXT      NOT NULL,
    url            TEXT      NOT NULL,
    description    TEXT,
    archived       BOOLEAN   NOT NULL,
    fork           BOOLEAN   NOT NULL,
    private        BOOLEAN   NOT NULL,
    language       TEXT,
    default_branch TEXT,
    first_seen_run BIGINT    NOT NULL REFERENCES runs (id),
    last_seen_run  BIGINT    NOT NULL REFERENCES runs (id)
);

-- GitHub treats owner and repository names case-insensitively.
CREATE UNIQUE INDEX repos_owner_name ON repos (lower(owner), lower(name));

-- Append-only time series; one row per repository and collector run.
CREATE TABLE repo_snapshots (
    repo_id        BIGINT      NOT NULL REFERENCES repos (id),
    run_id         BIGINT      NOT NULL REFERENCES runs (id),
    taken_at       TIMESTAMPTZ NOT NULL,
    open_issues    BIGINT      NOT NULL,
    open_prs       BIGINT      NOT NULL,
    contributors   BIGINT,
    commits        BIGINT,
    tags           BIGINT      NOT NULL,
    releases       BIGINT      NOT NULL,
    stars          BIGINT      NOT NULL,
    forks          BIGINT      NOT NULL,
    pushed_at      TIMESTAMPTZ,
    last_commit_at TIMESTAMPTZ,
    PRIMARY KEY (repo_id, run_id)
);

CREATE INDEX repo_snapshots_by_repo_time ON repo_snapshots (repo_id, taken_at DESC);

-- Current state of every alert ever seen.
CREATE TABLE alerts (
    id             BIGSERIAL   PRIMARY KEY,
    repo_id        BIGINT      NOT NULL REFERENCES repos (id),
    source         TEXT        NOT NULL,
    number         BIGINT      NOT NULL,
    state          TEXT        NOT NULL,
    severity       TEXT        NOT NULL,
    title          TEXT        NOT NULL,
    location       TEXT,
    html_url       TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    closed_at      TIMESTAMPTZ,
    estimated      BOOLEAN     NOT NULL DEFAULT FALSE,
    first_seen_run BIGINT      NOT NULL REFERENCES runs (id),
    last_seen_run  BIGINT      NOT NULL REFERENCES runs (id),
    UNIQUE (repo_id, source, number)
);

CREATE INDEX alerts_open_by_repo ON alerts (repo_id, state);

-- Append-only audit log of alert state changes.
CREATE TABLE alert_events (
    id       BIGSERIAL   PRIMARY KEY,
    alert_id BIGINT      NOT NULL REFERENCES alerts (id),
    run_id   BIGINT      NOT NULL REFERENCES runs (id),
    at       TIMESTAMPTZ NOT NULL,
    kind     TEXT        NOT NULL,
    old      TEXT,
    new      TEXT,
    baseline BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX alert_events_by_alert ON alert_events (alert_id, id);
CREATE INDEX alert_events_by_time ON alert_events (at);

-- Whether each alert source could be read for a repository.
CREATE TABLE repo_sources (
    repo_id      BIGINT      NOT NULL REFERENCES repos (id),
    source       TEXT        NOT NULL,
    status       TEXT        NOT NULL,
    message      TEXT,
    checked_at   TIMESTAMPTZ NOT NULL,
    run_id       BIGINT      NOT NULL REFERENCES runs (id),
    first_ok_run BIGINT      REFERENCES runs (id),
    PRIMARY KEY (repo_id, source)
);

-- The audit tables reject UPDATE, DELETE and TRUNCATE below the
-- application, so the history holds even against a careless query.
CREATE FUNCTION reject_audit_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$;

CREATE TRIGGER alert_events_append_only
    BEFORE UPDATE OR DELETE ON alert_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_change();
CREATE TRIGGER alert_events_no_truncate
    BEFORE TRUNCATE ON alert_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_change();

CREATE TRIGGER repo_snapshots_append_only
    BEFORE UPDATE OR DELETE ON repo_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_audit_change();
CREATE TRIGGER repo_snapshots_no_truncate
    BEFORE TRUNCATE ON repo_snapshots
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_change();

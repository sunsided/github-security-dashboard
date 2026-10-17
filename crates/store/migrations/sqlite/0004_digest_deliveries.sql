-- Digests sent (or attempted) per target. A target's watermark is the
-- highest last_event_id of its successful deliveries.
CREATE TABLE digest_deliveries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    attempted_at   TEXT    NOT NULL,
    first_event_id INTEGER NOT NULL,
    last_event_id  INTEGER NOT NULL,
    events         INTEGER NOT NULL,
    succeeded      INTEGER NOT NULL,
    error          TEXT
);

CREATE INDEX digest_deliveries_by_target ON digest_deliveries (target, succeeded, last_event_id);

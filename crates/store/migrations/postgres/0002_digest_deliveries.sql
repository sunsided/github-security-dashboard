-- Digests sent (or attempted) per target. A target's watermark is the
-- highest last_event_id of its successful deliveries.
CREATE TABLE digest_deliveries (
    id             BIGSERIAL   PRIMARY KEY,
    target         TEXT        NOT NULL,
    attempted_at   TIMESTAMPTZ NOT NULL,
    first_event_id BIGINT      NOT NULL,
    last_event_id  BIGINT      NOT NULL,
    events         BIGINT      NOT NULL,
    succeeded      BOOLEAN     NOT NULL,
    error          TEXT
);

CREATE INDEX digest_deliveries_by_target ON digest_deliveries (target, succeeded, last_event_id);

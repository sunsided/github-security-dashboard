-- What an alert is an instance of (advisory IDs, rule ID or secret type), and
-- the package ecosystem of dependency alerts. Filled for open alerts on the
-- next collector run.
ALTER TABLE alerts ADD COLUMN advisory_ids JSONB NOT NULL DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN ecosystem TEXT;

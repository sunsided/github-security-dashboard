-- Events recorded the first time a repository's alert source could be read
-- describe pre-existing alerts, not news. They are flagged as baseline.
ALTER TABLE alert_events ADD COLUMN baseline INTEGER NOT NULL DEFAULT 0;

-- First run in which the source was read successfully; kept across later
-- failures so that a flaky run does not restart the baseline.
ALTER TABLE repo_sources ADD COLUMN first_ok_run INTEGER REFERENCES runs (id);

UPDATE repo_sources SET first_ok_run = run_id WHERE status = 'ok';

-- Backfill: until now every source was first read in the run that first
-- recorded any alert event at all, so that run's events are the baseline.
-- The append-only guard is lifted for this one classification update only.
DROP TRIGGER alert_events_no_update;

UPDATE alert_events
SET baseline = 1
WHERE run_id = (SELECT MIN(run_id) FROM alert_events);

CREATE TRIGGER alert_events_no_update BEFORE UPDATE ON alert_events
BEGIN
    SELECT RAISE(ABORT, 'alert_events is append-only');
END;

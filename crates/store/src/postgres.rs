//! PostgreSQL backend, for long-term retention of the audit history.

use crate::alerts::{self, *};
use crate::api::*;
use crate::deliveries::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::types::Json;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connects to `url` (`postgres://user:pass@host/db`) and migrates the
    /// schema. A `search_path` can be passed as connection option, e.g.
    /// `?options=-c%20search_path%3Ddashboard`, to keep the tables in their
    /// own schema.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }
}

// SQL fragments are macros rather than constants so that queries are put
// together with `concat!` at compile time. The result is a `&'static str`,
// which sqlx accepts as safe as-is; a runtime value can't end up in the SQL
// text without a compile error.
macro_rules! repo_columns {
    () => {
        "
    r.id, r.owner, r.name, r.kind, r.url, r.description, r.archived, r.fork,
    r.private, r.language, r.default_branch, r.last_seen_run,
    s.run_id AS s_run_id, s.taken_at AS s_taken_at, s.open_issues AS s_open_issues,
    s.open_prs AS s_open_prs, s.contributors AS s_contributors, s.commits AS s_commits,
    s.tags AS s_tags, s.releases AS s_releases, s.stars AS s_stars, s.forks AS s_forks,
    s.pushed_at AS s_pushed_at, s.last_commit_at AS s_last_commit_at,
    COALESCE(a.critical, 0) AS a_critical, COALESCE(a.high, 0) AS a_high,
    COALESCE(a.medium, 0) AS a_medium, COALESCE(a.low, 0) AS a_low"
    };
}

/// Latest snapshot and open alert counts per repository.
macro_rules! repo_joins {
    () => {
        "
    LEFT JOIN repo_snapshots s
        ON s.repo_id = r.id
       AND s.run_id = (SELECT MAX(run_id) FROM repo_snapshots WHERE repo_id = r.id)
    LEFT JOIN (
        SELECT repo_id,
               COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
               COUNT(*) FILTER (WHERE severity = 'high') AS high,
               COUNT(*) FILTER (WHERE severity = 'medium') AS medium,
               COUNT(*) FILTER (WHERE severity = 'low') AS low
        FROM alerts WHERE state = 'open' GROUP BY repo_id
    ) a ON a.repo_id = r.id"
    };
}

macro_rules! alert_columns {
    () => {
        "
    id, repo_id, source, number, state, severity, title, location, html_url,
    created_at, closed_at, estimated, first_seen_run, last_seen_run"
    };
}

macro_rules! severity_order {
    () => {
        "
    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
    };
}

fn repo_from_row(row: &PgRow) -> Result<RepoOverview> {
    let latest = match row.try_get::<Option<i64>, _>("s_run_id")? {
        None => None,
        Some(run_id) => Some(Snapshot {
            run_id: RunId(run_id),
            taken_at: row.try_get("s_taken_at")?,
            stats: RepoStats {
                open_issues: row.try_get("s_open_issues")?,
                open_prs: row.try_get("s_open_prs")?,
                contributors: row.try_get("s_contributors")?,
                commits: row.try_get("s_commits")?,
                tags: row.try_get("s_tags")?,
                releases: row.try_get("s_releases")?,
                stars: row.try_get("s_stars")?,
                forks: row.try_get("s_forks")?,
                pushed_at: row.try_get("s_pushed_at")?,
                last_commit_at: row.try_get("s_last_commit_at")?,
            },
        }),
    };

    Ok(RepoOverview {
        id: RepoId(row.try_get("id")?),
        info: RepoInfo {
            owner: row.try_get("owner")?,
            name: row.try_get("name")?,
            kind: parse(row, "kind")?,
            url: row.try_get("url")?,
            description: row.try_get("description")?,
            archived: row.try_get("archived")?,
            fork: row.try_get("fork")?,
            private: row.try_get("private")?,
            language: row.try_get("language")?,
            default_branch: row.try_get("default_branch")?,
        },
        last_seen_run: RunId(row.try_get("last_seen_run")?),
        latest,
        open_alerts: SeverityCounts {
            critical: row.try_get("a_critical")?,
            high: row.try_get("a_high")?,
            medium: row.try_get("a_medium")?,
            low: row.try_get("a_low")?,
        },
    })
}

fn parse<T: std::str::FromStr<Err = StoreError>>(row: &PgRow, column: &str) -> Result<T> {
    row.try_get::<String, _>(column)?.parse()
}

fn alert_from_row(row: &PgRow) -> Result<Alert> {
    Ok(Alert {
        id: AlertId(row.try_get("id")?),
        repo_id: RepoId(row.try_get("repo_id")?),
        record: AlertRecord {
            source: parse(row, "source")?,
            number: row.try_get("number")?,
            state: parse(row, "state")?,
            severity: parse(row, "severity")?,
            title: row.try_get("title")?,
            location: row.try_get("location")?,
            html_url: row.try_get("html_url")?,
            created_at: row.try_get("created_at")?,
            closed_at: row.try_get("closed_at")?,
            estimated: row.try_get("estimated")?,
        },
        first_seen_run: RunId(row.try_get("first_seen_run")?),
        last_seen_run: RunId(row.try_get("last_seen_run")?),
    })
}

macro_rules! delivery_columns {
    () => {
        "id, target, attempted_at, first_event_id, last_event_id, events, succeeded, error"
    };
}

fn delivery_from_row(row: &PgRow) -> Result<Delivery> {
    Ok(Delivery {
        id: row.try_get("id")?,
        record: DeliveryRecord {
            target: row.try_get("target")?,
            attempted_at: row.try_get("attempted_at")?,
            first_event_id: row.try_get("first_event_id")?,
            last_event_id: row.try_get("last_event_id")?,
            events: row.try_get("events")?,
            succeeded: row.try_get("succeeded")?,
            error: row.try_get("error")?,
        },
    })
}

#[async_trait]
impl Store for PostgresStore {
    async fn begin_run(&self, started_at: DateTime<Utc>) -> Result<RunId> {
        let id = sqlx::query_scalar(
            "INSERT INTO runs (started_at, status) VALUES ($1, $2) RETURNING id",
        )
        .bind(started_at)
        .bind(RunStatus::Running.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(RunId(id))
    }

    async fn finish_run(
        &self,
        run: RunId,
        finished_at: DateTime<Utc>,
        status: RunStatus,
        rate_limit_remaining: Option<i64>,
        errors: &[String],
    ) -> Result<()> {
        sqlx::query(
            "UPDATE runs SET finished_at = $1, status = $2, rate_limit_remaining = $3, errors = $4
             WHERE id = $5",
        )
        .bind(finished_at)
        .bind(status.as_str())
        .bind(rate_limit_remaining)
        .bind(Json(errors))
        .bind(run.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_runs(&self, limit: u32) -> Result<Vec<Run>> {
        let rows = sqlx::query(
            "SELECT id, started_at, finished_at, status, rate_limit_remaining, errors
             FROM runs ORDER BY id DESC LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let Json(errors): Json<Vec<String>> = row.try_get("errors")?;
                Ok(Run {
                    id: RunId(row.try_get("id")?),
                    started_at: row.try_get("started_at")?,
                    finished_at: row.try_get("finished_at")?,
                    status: parse(row, "status")?,
                    rate_limit_remaining: row.try_get("rate_limit_remaining")?,
                    errors,
                })
            })
            .collect()
    }

    async fn upsert_repo(&self, repo: &RepoInfo, run: RunId) -> Result<RepoId> {
        let id = sqlx::query_scalar(
            "INSERT INTO repos (owner, name, kind, url, description, archived, fork, private,
                                language, default_branch, first_seen_run, last_seen_run)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
             ON CONFLICT ((lower(owner)), (lower(name))) DO UPDATE SET
                 owner = excluded.owner,
                 name = excluded.name,
                 kind = excluded.kind,
                 url = excluded.url,
                 description = excluded.description,
                 archived = excluded.archived,
                 fork = excluded.fork,
                 private = excluded.private,
                 language = excluded.language,
                 default_branch = excluded.default_branch,
                 last_seen_run = excluded.last_seen_run
             RETURNING id",
        )
        .bind(&repo.owner)
        .bind(&repo.name)
        .bind(repo.kind.as_str())
        .bind(&repo.url)
        .bind(&repo.description)
        .bind(repo.archived)
        .bind(repo.fork)
        .bind(repo.private)
        .bind(&repo.language)
        .bind(&repo.default_branch)
        .bind(run.0)
        .fetch_one(&self.pool)
        .await?;
        Ok(RepoId(id))
    }

    async fn insert_snapshot(
        &self,
        repo: RepoId,
        run: RunId,
        taken_at: DateTime<Utc>,
        stats: &RepoStats,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO repo_snapshots (repo_id, run_id, taken_at, open_issues, open_prs,
                                         contributors, commits, tags, releases, stars, forks,
                                         pushed_at, last_commit_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(repo.0)
        .bind(run.0)
        .bind(taken_at)
        .bind(stats.open_issues)
        .bind(stats.open_prs)
        .bind(stats.contributors)
        .bind(stats.commits)
        .bind(stats.tags)
        .bind(stats.releases)
        .bind(stats.stars)
        .bind(stats.forks)
        .bind(stats.pushed_at)
        .bind(stats.last_commit_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_repos(&self, filter: &RepoFilter) -> Result<Vec<RepoOverview>> {
        let sql = concat!(
            "SELECT ",
            repo_columns!(),
            " FROM repos r ",
            repo_joins!(),
            "
             WHERE ($1::text IS NULL OR lower(r.owner) = lower($1))
               AND ($2::text IS NULL OR r.kind = $2)
               AND ($3 OR NOT r.archived)
             ORDER BY lower(r.owner), lower(r.name)"
        );
        let rows = sqlx::query(sql)
            .bind(&filter.owner)
            .bind(filter.kind.map(RepoKind::as_str))
            .bind(filter.include_archived)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(repo_from_row).collect()
    }

    async fn get_repo(&self, owner: &str, name: &str) -> Result<Option<RepoOverview>> {
        let sql = concat!(
            "SELECT ",
            repo_columns!(),
            " FROM repos r ",
            repo_joins!(),
            "
             WHERE lower(r.owner) = lower($1) AND lower(r.name) = lower($2)"
        );
        let row = sqlx::query(sql)
            .bind(owner)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(repo_from_row).transpose()
    }

    async fn snapshot_history(&self, repo: RepoId, limit: u32) -> Result<Vec<Snapshot>> {
        let rows = sqlx::query(
            "SELECT run_id, taken_at, open_issues, open_prs, contributors, commits, tags,
                    releases, stars, forks, pushed_at, last_commit_at
             FROM repo_snapshots WHERE repo_id = $1
             ORDER BY taken_at DESC, run_id DESC LIMIT $2",
        )
        .bind(repo.0)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                Ok(Snapshot {
                    run_id: RunId(row.try_get("run_id")?),
                    taken_at: row.try_get("taken_at")?,
                    stats: RepoStats {
                        open_issues: row.try_get("open_issues")?,
                        open_prs: row.try_get("open_prs")?,
                        contributors: row.try_get("contributors")?,
                        commits: row.try_get("commits")?,
                        tags: row.try_get("tags")?,
                        releases: row.try_get("releases")?,
                        stars: row.try_get("stars")?,
                        forks: row.try_get("forks")?,
                        pushed_at: row.try_get("pushed_at")?,
                        last_commit_at: row.try_get("last_commit_at")?,
                    },
                })
            })
            .collect()
    }

    async fn record_alerts(
        &self,
        repo: RepoId,
        run: RunId,
        at: DateTime<Utc>,
        alerts: &[AlertRecord],
        baseline: bool,
    ) -> Result<usize> {
        let mut tx = self.pool.begin().await?;
        let mut events = 0;

        for alert in alerts {
            let sql = concat!(
                "SELECT ",
                alert_columns!(),
                " FROM alerts
                 WHERE repo_id = $1 AND source = $2 AND number = $3
                 FOR UPDATE"
            );
            let previous = sqlx::query(sql)
                .bind(repo.0)
                .bind(alert.source.as_str())
                .bind(alert.number)
                .fetch_optional(&mut *tx)
                .await?
                .as_ref()
                .map(alert_from_row)
                .transpose()?;

            let id: i64 = sqlx::query_scalar(
                "INSERT INTO alerts (repo_id, source, number, state, severity, title, location,
                                     html_url, created_at, closed_at, estimated,
                                     first_seen_run, last_seen_run)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)
                 ON CONFLICT (repo_id, source, number) DO UPDATE SET
                     state = excluded.state,
                     severity = excluded.severity,
                     title = excluded.title,
                     location = excluded.location,
                     html_url = excluded.html_url,
                     created_at = excluded.created_at,
                     closed_at = excluded.closed_at,
                     estimated = excluded.estimated,
                     last_seen_run = excluded.last_seen_run
                 RETURNING id",
            )
            .bind(repo.0)
            .bind(alert.source.as_str())
            .bind(alert.number)
            .bind(alert.state.as_str())
            .bind(alert.severity.as_str())
            .bind(&alert.title)
            .bind(&alert.location)
            .bind(&alert.html_url)
            .bind(alert.created_at)
            .bind(alert.closed_at)
            .bind(alert.estimated)
            .bind(run.0)
            .fetch_one(&mut *tx)
            .await?;

            for change in alerts::changes(previous.as_ref().map(|a| &a.record), alert) {
                sqlx::query(
                    "INSERT INTO alert_events (alert_id, run_id, at, kind, old, new, baseline)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(id)
                .bind(run.0)
                .bind(at)
                .bind(change.kind.as_str())
                .bind(change.old)
                .bind(change.new)
                .bind(baseline)
                .execute(&mut *tx)
                .await?;
                events += 1;
            }
        }

        tx.commit().await?;
        Ok(events)
    }

    async fn list_alerts(&self, repo: RepoId, filter: &AlertFilter) -> Result<Vec<Alert>> {
        let sql = concat!(
            "SELECT ",
            alert_columns!(),
            " FROM alerts
             WHERE repo_id = $1
               AND ($2::text IS NULL OR source = $2)
               AND ($3::text IS NULL OR state = $3)
             ORDER BY (state = 'open') DESC, ",
            severity_order!(),
            ", created_at DESC, number DESC"
        );
        let rows = sqlx::query(sql)
            .bind(repo.0)
            .bind(filter.source.map(AlertSource::as_str))
            .bind(filter.state.map(AlertState::as_str))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(alert_from_row).collect()
    }

    async fn alert_events(&self, filter: &EventFilter) -> Result<Vec<AlertEvent>> {
        let rows = sqlx::query(
            "SELECT e.id, e.alert_id, e.run_id, e.at, e.kind, e.old, e.new, e.baseline,
                    r.owner, r.name AS repo, a.source, a.number, a.title,
                    a.severity, a.html_url
             FROM alert_events e
             JOIN alerts a ON a.id = e.alert_id
             JOIN repos r ON r.id = a.repo_id
             WHERE ($1::bigint IS NULL OR a.repo_id = $1)
               AND ($2::timestamptz IS NULL OR e.at >= $2)
               AND ($4 OR NOT e.baseline)
               AND ($5::bigint IS NULL OR e.id > $5)
             ORDER BY CASE WHEN $6 THEN e.id END ASC, e.id DESC
             LIMIT $3",
        )
        .bind(filter.repo.map(|r| r.0))
        .bind(filter.since)
        .bind(i64::from(filter.limit))
        .bind(filter.include_baseline)
        .bind(filter.after_id)
        .bind(filter.oldest_first)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                Ok(AlertEvent {
                    id: row.try_get("id")?,
                    alert_id: AlertId(row.try_get("alert_id")?),
                    run_id: RunId(row.try_get("run_id")?),
                    at: row.try_get("at")?,
                    kind: parse(row, "kind")?,
                    old: row.try_get("old")?,
                    new: row.try_get("new")?,
                    baseline: row.try_get("baseline")?,
                    owner: row.try_get("owner")?,
                    repo: row.try_get("repo")?,
                    source: parse(row, "source")?,
                    number: row.try_get("number")?,
                    title: row.try_get("title")?,
                    severity: parse(row, "severity")?,
                    html_url: row.try_get("html_url")?,
                })
            })
            .collect()
    }

    async fn set_source_status(
        &self,
        repo: RepoId,
        source: AlertSource,
        run: RunId,
        at: DateTime<Utc>,
        status: SourceStatus,
        message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO repo_sources (repo_id, source, status, message, checked_at, run_id,
                                      first_ok_run)
             VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $3 = 'ok' THEN $6 END)
             ON CONFLICT (repo_id, source) DO UPDATE SET
                 status = excluded.status,
                 message = excluded.message,
                 checked_at = excluded.checked_at,
                 run_id = excluded.run_id,
                 first_ok_run = COALESCE(repo_sources.first_ok_run, excluded.first_ok_run)",
        )
        .bind(repo.0)
        .bind(source.as_str())
        .bind(status.as_str())
        .bind(message)
        .bind(at)
        .bind(run.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn source_statuses(&self, repo: RepoId) -> Result<Vec<RepoSource>> {
        let rows = sqlx::query(
            "SELECT source, status, message, checked_at, first_ok_run FROM repo_sources
             WHERE repo_id = $1 ORDER BY source",
        )
        .bind(repo.0)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RepoSource {
                    source: parse(row, "source")?,
                    status: parse(row, "status")?,
                    message: row.try_get("message")?,
                    checked_at: row.try_get("checked_at")?,
                    first_collected_run: row.try_get::<Option<i64>, _>("first_ok_run")?.map(RunId),
                })
            })
            .collect()
    }

    async fn record_delivery(&self, delivery: &DeliveryRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO digest_deliveries (target, attempted_at, first_event_id, last_event_id,
                                           events, succeeded, error)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&delivery.target)
        .bind(delivery.attempted_at)
        .bind(delivery.first_event_id)
        .bind(delivery.last_event_id)
        .bind(delivery.events)
        .bind(delivery.succeeded)
        .bind(&delivery.error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn last_delivery(&self, target: &str) -> Result<Option<Delivery>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            delivery_columns!(),
            " FROM digest_deliveries WHERE target = $1 AND succeeded
             ORDER BY last_event_id DESC, id DESC LIMIT 1"
        ))
        .bind(target)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(delivery_from_row).transpose()
    }

    async fn list_deliveries(&self, limit: u32) -> Result<Vec<Delivery>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            delivery_columns!(),
            " FROM digest_deliveries ORDER BY id DESC LIMIT $1"
        ))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(delivery_from_row).collect()
    }
}

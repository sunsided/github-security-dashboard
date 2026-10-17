//! SQLite backend.

use crate::alerts::{self, *};
use crate::api::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use sqlx::{AssertSqlSafe, Row};
use std::str::FromStr;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Opens (and creates, if needed) the database at `url`, then migrates it.
    ///
    /// In-memory URLs (`sqlite::memory:`) use a single connection, since every
    /// connection would otherwise see its own empty database.
    pub async fn connect(url: &str) -> Result<Self> {
        let in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(if in_memory {
                SqliteJournalMode::Memory
            } else {
                SqliteJournalMode::Wal
            });

        let mut pool = SqlitePoolOptions::new();
        if in_memory {
            pool = pool
                .max_connections(1)
                .idle_timeout(None)
                .max_lifetime(None);
        }
        let pool = pool.connect_with(options).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }
}

const REPO_COLUMNS: &str = "
    r.id, r.owner, r.name, r.kind, r.url, r.description, r.archived, r.fork,
    r.private, r.language, r.default_branch, r.last_seen_run,
    s.run_id AS s_run_id, s.taken_at AS s_taken_at, s.open_issues AS s_open_issues,
    s.open_prs AS s_open_prs, s.contributors AS s_contributors, s.commits AS s_commits,
    s.tags AS s_tags, s.releases AS s_releases, s.stars AS s_stars, s.forks AS s_forks,
    s.pushed_at AS s_pushed_at, s.last_commit_at AS s_last_commit_at,
    COALESCE(a.critical, 0) AS a_critical, COALESCE(a.high, 0) AS a_high,
    COALESCE(a.medium, 0) AS a_medium, COALESCE(a.low, 0) AS a_low";

/// Latest snapshot and open alert counts per repository.
const REPO_JOINS: &str = "
    LEFT JOIN repo_snapshots s
        ON s.repo_id = r.id
       AND s.run_id = (SELECT MAX(run_id) FROM repo_snapshots WHERE repo_id = r.id)
    LEFT JOIN (
        SELECT repo_id,
               SUM(severity = 'critical') AS critical,
               SUM(severity = 'high') AS high,
               SUM(severity = 'medium') AS medium,
               SUM(severity = 'low') AS low
        FROM alerts WHERE state = 'open' GROUP BY repo_id
    ) a ON a.repo_id = r.id";

const ALERT_COLUMNS: &str = "
    id, repo_id, source, number, state, severity, title, location, html_url,
    created_at, closed_at, estimated, first_seen_run, last_seen_run";

const SEVERITY_ORDER: &str = "
    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END";

fn repo_from_row(row: &SqliteRow) -> Result<RepoOverview> {
    let kind: String = row.try_get("kind")?;
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
            kind: kind.parse()?,
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

fn parse<T: std::str::FromStr<Err = StoreError>>(row: &SqliteRow, column: &str) -> Result<T> {
    row.try_get::<String, _>(column)?.parse()
}

fn alert_from_row(row: &SqliteRow) -> Result<Alert> {
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

#[async_trait]
impl Store for SqliteStore {
    async fn begin_run(&self, started_at: DateTime<Utc>) -> Result<RunId> {
        let id =
            sqlx::query_scalar("INSERT INTO runs (started_at, status) VALUES (?, ?) RETURNING id")
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
        let errors =
            serde_json::to_string(errors).map_err(|e| StoreError::InvalidData(e.to_string()))?;
        sqlx::query(
            "UPDATE runs SET finished_at = ?, status = ?, rate_limit_remaining = ?, errors = ?
             WHERE id = ?",
        )
        .bind(finished_at)
        .bind(status.as_str())
        .bind(rate_limit_remaining)
        .bind(errors)
        .bind(run.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_runs(&self, limit: u32) -> Result<Vec<Run>> {
        let rows = sqlx::query(
            "SELECT id, started_at, finished_at, status, rate_limit_remaining, errors
             FROM runs ORDER BY id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let status: String = row.try_get("status")?;
                let errors: String = row.try_get("errors")?;
                Ok(Run {
                    id: RunId(row.try_get("id")?),
                    started_at: row.try_get("started_at")?,
                    finished_at: row.try_get("finished_at")?,
                    status: status.parse()?,
                    rate_limit_remaining: row.try_get("rate_limit_remaining")?,
                    errors: serde_json::from_str(&errors)
                        .map_err(|e| StoreError::InvalidData(e.to_string()))?,
                })
            })
            .collect()
    }

    async fn upsert_repo(&self, repo: &RepoInfo, run: RunId) -> Result<RepoId> {
        let id = sqlx::query_scalar(
            "INSERT INTO repos (owner, name, kind, url, description, archived, fork, private,
                                language, default_branch, first_seen_run, last_seen_run)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
             ON CONFLICT (owner, name) DO UPDATE SET
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        let sql = format!(
            "SELECT {REPO_COLUMNS} FROM repos r {REPO_JOINS}
             WHERE (?1 IS NULL OR r.owner = ?1)
               AND (?2 IS NULL OR r.kind = ?2)
               AND (?3 OR r.archived = 0)
             ORDER BY r.owner, r.name"
        );
        // Only compile-time constants are interpolated; values are bound.
        let rows = sqlx::query(AssertSqlSafe(sql))
            .bind(&filter.owner)
            .bind(filter.kind.map(RepoKind::as_str))
            .bind(filter.include_archived)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(repo_from_row).collect()
    }

    async fn get_repo(&self, owner: &str, name: &str) -> Result<Option<RepoOverview>> {
        let sql = format!(
            "SELECT {REPO_COLUMNS} FROM repos r {REPO_JOINS}
             WHERE r.owner = ? AND r.name = ?"
        );
        let row = sqlx::query(AssertSqlSafe(sql))
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
             FROM repo_snapshots WHERE repo_id = ? ORDER BY taken_at DESC, run_id DESC LIMIT ?",
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
    ) -> Result<usize> {
        let mut tx = self.pool.begin().await?;
        let mut events = 0;

        for alert in alerts {
            let sql = format!(
                "SELECT {ALERT_COLUMNS} FROM alerts WHERE repo_id = ? AND source = ? AND number = ?"
            );
            let previous = sqlx::query(AssertSqlSafe(sql))
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
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)
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
                    "INSERT INTO alert_events (alert_id, run_id, at, kind, old, new)
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(id)
                .bind(run.0)
                .bind(at)
                .bind(change.kind.as_str())
                .bind(change.old)
                .bind(change.new)
                .execute(&mut *tx)
                .await?;
                events += 1;
            }
        }

        tx.commit().await?;
        Ok(events)
    }

    async fn list_alerts(&self, repo: RepoId, filter: &AlertFilter) -> Result<Vec<Alert>> {
        // Only compile-time constants are interpolated; values are bound.
        let sql = format!(
            "SELECT {ALERT_COLUMNS} FROM alerts
             WHERE repo_id = ?1 AND (?2 IS NULL OR source = ?2) AND (?3 IS NULL OR state = ?3)
             ORDER BY state = 'open' DESC, {SEVERITY_ORDER}, created_at DESC, number DESC"
        );
        let rows = sqlx::query(AssertSqlSafe(sql))
            .bind(repo.0)
            .bind(filter.source.map(AlertSource::as_str))
            .bind(filter.state.map(AlertState::as_str))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(alert_from_row).collect()
    }

    async fn alert_events(&self, filter: &EventFilter) -> Result<Vec<AlertEvent>> {
        let rows = sqlx::query(
            "SELECT e.id, e.alert_id, e.run_id, e.at, e.kind, e.old, e.new,
                    r.owner, r.name AS repo, a.source, a.number, a.title
             FROM alert_events e
             JOIN alerts a ON a.id = e.alert_id
             JOIN repos r ON r.id = a.repo_id
             WHERE (?1 IS NULL OR a.repo_id = ?1) AND (?2 IS NULL OR e.at >= ?2)
             ORDER BY e.id DESC
             LIMIT ?3",
        )
        .bind(filter.repo.map(|r| r.0))
        .bind(filter.since)
        .bind(i64::from(filter.limit))
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
                    owner: row.try_get("owner")?,
                    repo: row.try_get("repo")?,
                    source: parse(row, "source")?,
                    number: row.try_get("number")?,
                    title: row.try_get("title")?,
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
            "INSERT INTO repo_sources (repo_id, source, status, message, checked_at, run_id)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (repo_id, source) DO UPDATE SET
                 status = excluded.status,
                 message = excluded.message,
                 checked_at = excluded.checked_at,
                 run_id = excluded.run_id",
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
            "SELECT source, status, message, checked_at FROM repo_sources
             WHERE repo_id = ? ORDER BY source",
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
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn audit_tables_reject_updates_and_deletes() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        let now = Utc::now();
        let run = store.begin_run(now).await.unwrap();
        let info = RepoInfo {
            owner: "acme".into(),
            name: "widget".into(),
            kind: RepoKind::Org,
            url: "https://github.com/acme/widget".into(),
            description: None,
            archived: false,
            fork: false,
            private: false,
            language: None,
            default_branch: None,
        };
        let repo = store.upsert_repo(&info, run).await.unwrap();
        store
            .insert_snapshot(repo, run, now, &RepoStats::default())
            .await
            .unwrap();
        let alert = AlertRecord {
            source: AlertSource::Dependabot,
            number: 1,
            state: AlertState::Open,
            severity: Severity::High,
            title: "x".into(),
            location: None,
            html_url: "https://github.com/acme/widget/security/dependabot/1".into(),
            created_at: now,
            closed_at: None,
            estimated: false,
        };
        store.record_alerts(repo, run, now, &[alert]).await.unwrap();

        for sql in [
            "UPDATE alert_events SET kind = 'fixed'",
            "DELETE FROM alert_events",
            "UPDATE repo_snapshots SET open_issues = 99",
            "DELETE FROM repo_snapshots",
        ] {
            let err = sqlx::query(sql).execute(&store.pool).await.unwrap_err();
            assert!(err.to_string().contains("append-only"), "{sql}: {err}");
        }
    }
}

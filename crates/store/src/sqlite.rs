//! SQLite backend.

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
    s.pushed_at AS s_pushed_at, s.last_commit_at AS s_last_commit_at";

const LATEST_SNAPSHOT_JOIN: &str = "
    LEFT JOIN repo_snapshots s
        ON s.repo_id = r.id
       AND s.run_id = (SELECT MAX(run_id) FROM repo_snapshots WHERE repo_id = r.id)";

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
            "SELECT {REPO_COLUMNS} FROM repos r {LATEST_SNAPSHOT_JOIN}
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
            "SELECT {REPO_COLUMNS} FROM repos r {LATEST_SNAPSHOT_JOIN}
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
}

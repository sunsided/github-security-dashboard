//! Backend-independent domain types and the [`Store`] trait.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("unsupported storage URL: {0}")]
    UnsupportedUrl(String),
    #[error("invalid stored value: {0}")]
    InvalidData(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

/// Identifies a collector run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub i64);

/// Identifies a stored repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoId(pub i64);

/// How a repository came to be tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoKind {
    /// Owned by a configured organization.
    Org,
    /// Owned by a configured user account.
    User,
    /// Explicitly listed, owned by someone else.
    External,
}

impl RepoKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::User => "user",
            Self::External => "external",
        }
    }
}

impl fmt::Display for RepoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RepoKind {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "org" => Ok(Self::Org),
            "user" => Ok(Self::User),
            "external" => Ok(Self::External),
            other => Err(StoreError::InvalidData(format!("repo kind {other:?}"))),
        }
    }
}

/// Outcome of a collector run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Succeeded,
    /// Finished, but some owners or repositories could not be collected.
    Partial,
    Failed,
}

impl RunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }
}

impl FromStr for RunStatus {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidData(format!("run status {other:?}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub id: RunId,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: RunStatus,
    pub rate_limit_remaining: Option<i64>,
    pub errors: Vec<String>,
}

/// Mostly static repository metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    pub owner: String,
    pub name: String,
    pub kind: RepoKind,
    pub url: String,
    pub description: Option<String>,
    pub archived: bool,
    pub fork: bool,
    pub private: bool,
    pub language: Option<String>,
    pub default_branch: Option<String>,
}

/// Point-in-time repository health figures.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoStats {
    pub open_issues: i64,
    pub open_prs: i64,
    /// `None` if GitHub could not compute it (e.g. very large repositories).
    pub contributors: Option<i64>,
    /// Commits on the default branch; `None` for empty repositories.
    pub commits: Option<i64>,
    pub tags: i64,
    pub releases: i64,
    pub stars: i64,
    pub forks: i64,
    pub pushed_at: Option<DateTime<Utc>>,
    pub last_commit_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub run_id: RunId,
    pub taken_at: DateTime<Utc>,
    #[serde(flatten)]
    pub stats: RepoStats,
}

/// A repository with its most recent snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoOverview {
    pub id: RepoId,
    #[serde(flatten)]
    pub info: RepoInfo,
    pub last_seen_run: RunId,
    pub latest: Option<Snapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoFilter {
    pub owner: Option<String>,
    pub kind: Option<RepoKind>,
    pub include_archived: bool,
}

/// Persistence boundary of the dashboard.
///
/// Snapshots are append-only: implementations must never update or delete
/// them, so that historical state stays available for audits.
#[async_trait]
pub trait Store: Send + Sync {
    async fn begin_run(&self, started_at: DateTime<Utc>) -> Result<RunId>;

    async fn finish_run(
        &self,
        run: RunId,
        finished_at: DateTime<Utc>,
        status: RunStatus,
        rate_limit_remaining: Option<i64>,
        errors: &[String],
    ) -> Result<()>;

    /// Most recent runs first.
    async fn list_runs(&self, limit: u32) -> Result<Vec<Run>>;

    /// Inserts or updates a repository, keyed by owner and name, and marks it
    /// as seen in `run`.
    async fn upsert_repo(&self, repo: &RepoInfo, run: RunId) -> Result<RepoId>;

    async fn insert_snapshot(
        &self,
        repo: RepoId,
        run: RunId,
        taken_at: DateTime<Utc>,
        stats: &RepoStats,
    ) -> Result<()>;

    async fn list_repos(&self, filter: &RepoFilter) -> Result<Vec<RepoOverview>>;

    async fn get_repo(&self, owner: &str, name: &str) -> Result<Option<RepoOverview>>;

    /// Most recent snapshots first.
    async fn snapshot_history(&self, repo: RepoId, limit: u32) -> Result<Vec<Snapshot>>;
}

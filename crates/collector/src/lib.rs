//! One collection pass: GitHub in, store snapshots out.

use chrono::Utc;
use gh::{GitHub, OwnerKind, Repository};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use store::{RepoInfo, RepoKind, RepoStats, RunId, RunStatus, Store};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] store::StoreError),
}

/// `owner/name` of a repository not covered by a configured owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
}

impl TryFrom<String> for RepoRef {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.split_once('/') {
            Some((owner, name)) if !owner.is_empty() && !name.is_empty() && !name.contains('/') => {
                Ok(Self {
                    owner: owner.into(),
                    name: name.into(),
                })
            }
            _ => Err(format!("expected \"owner/name\", got {value:?}")),
        }
    }
}

impl fmt::Display for RepoRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorConfig {
    /// Organizations and users whose own repositories are tracked.
    pub owners: Vec<String>,
    /// Further repositories, typically dependencies owned by someone else.
    pub external_repos: Vec<RepoRef>,
    /// Repositories per GraphQL page.
    pub page_size: u32,
    /// Parallel REST requests.
    pub concurrency: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            owners: Vec::new(),
            external_repos: Vec::new(),
            page_size: 25,
            concurrency: 8,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run: RunId,
    pub status: RunStatus,
    pub repos: usize,
    pub errors: Vec<String>,
}

pub struct Collector {
    github: Arc<GitHub>,
    store: Arc<dyn Store>,
    config: CollectorConfig,
}

impl Collector {
    pub fn new(github: Arc<GitHub>, store: Arc<dyn Store>, config: CollectorConfig) -> Self {
        Self {
            github,
            store,
            config,
        }
    }

    /// Runs one full collection pass.
    ///
    /// GitHub failures for single owners or repositories are recorded on the
    /// run and do not abort it; storage failures do.
    pub async fn run(&self) -> Result<RunSummary, Error> {
        let run = self.store.begin_run(Utc::now()).await?;
        tracing::info!(run = run.0, "collection started");

        let mut errors = Vec::new();
        let result = self.collect(run, &mut errors).await;

        let (status, repos) = match &result {
            Ok(0) if !errors.is_empty() => (RunStatus::Failed, 0),
            Ok(n) if errors.is_empty() => (RunStatus::Succeeded, *n),
            Ok(n) => (RunStatus::Partial, *n),
            Err(e) => {
                errors.push(e.to_string());
                (RunStatus::Failed, 0)
            }
        };
        self.store
            .finish_run(
                run,
                Utc::now(),
                status,
                self.github.rate_limit_remaining(),
                &errors,
            )
            .await?;
        result?;

        tracing::info!(
            run = run.0,
            ?status,
            repos,
            errors = errors.len(),
            "collection finished"
        );
        Ok(RunSummary {
            run,
            status,
            repos,
            errors,
        })
    }

    async fn collect(&self, run: RunId, errors: &mut Vec<String>) -> Result<usize, Error> {
        let mut repos: Vec<(RepoKind, Repository)> = Vec::new();
        let mut seen = HashSet::new();

        for owner in &self.config.owners {
            match self
                .github
                .owner_repositories(owner, self.config.page_size)
                .await
            {
                Ok(list) => {
                    for repo in list {
                        let kind = match repo.owner_kind {
                            OwnerKind::Organization => RepoKind::Org,
                            OwnerKind::User => RepoKind::User,
                        };
                        if seen.insert(key(&repo.owner, &repo.name)) {
                            repos.push((kind, repo));
                        }
                    }
                }
                Err(e) => record(errors, format!("owner {owner}"), e),
            }
        }

        for external in &self.config.external_repos {
            if seen.contains(&key(&external.owner, &external.name)) {
                continue;
            }
            match self
                .github
                .repository(&external.owner, &external.name)
                .await
            {
                Ok(repo) => {
                    seen.insert(key(&repo.owner, &repo.name));
                    repos.push((RepoKind::External, repo));
                }
                Err(e) => record(errors, format!("repository {external}"), e),
            }
        }

        let contributors = self.contributor_counts(&repos, errors).await;

        let taken_at = Utc::now();
        for ((kind, repo), contributors) in repos.iter().zip(contributors) {
            let id = self.store.upsert_repo(&repo_info(*kind, repo), run).await?;
            self.store
                .insert_snapshot(id, run, taken_at, &repo_stats(repo, contributors))
                .await?;
        }
        Ok(repos.len())
    }

    /// Contributor counts in input order, fetched in parallel.
    async fn contributor_counts(
        &self,
        repos: &[(RepoKind, Repository)],
        errors: &mut Vec<String>,
    ) -> Vec<Option<i64>> {
        let permits = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut tasks = JoinSet::new();
        for (index, (_, repo)) in repos.iter().enumerate() {
            let github = Arc::clone(&self.github);
            let permits = Arc::clone(&permits);
            let (owner, name) = (repo.owner.clone(), repo.name.clone());
            tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .expect("semaphore is never closed");
                (
                    index,
                    owner.clone(),
                    name.clone(),
                    github.contributor_count(&owner, &name).await,
                )
            });
        }

        let mut counts = vec![None; repos.len()];
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, _, _, Ok(count))) => counts[index] = count,
                Ok((_, owner, name, Err(e))) => {
                    record(errors, format!("contributors of {owner}/{name}"), e);
                }
                Err(e) => errors.push(format!("contributor task failed: {e}")),
            }
        }
        counts
    }
}

fn key(owner: &str, name: &str) -> (String, String) {
    (owner.to_lowercase(), name.to_lowercase())
}

fn record(errors: &mut Vec<String>, what: String, error: gh::Error) {
    tracing::warn!(%error, "{what}");
    errors.push(format!("{what}: {error}"));
}

fn repo_info(kind: RepoKind, repo: &Repository) -> RepoInfo {
    RepoInfo {
        owner: repo.owner.clone(),
        name: repo.name.clone(),
        kind,
        url: repo.url.clone(),
        description: repo.description.clone(),
        archived: repo.archived,
        fork: repo.fork,
        private: repo.private,
        language: repo.language.clone(),
        default_branch: repo.default_branch.clone(),
    }
}

fn repo_stats(repo: &Repository, contributors: Option<i64>) -> RepoStats {
    RepoStats {
        open_issues: repo.open_issues,
        open_prs: repo.open_prs,
        contributors,
        commits: repo.commits,
        tags: repo.tags,
        releases: repo.releases,
        stars: repo.stars,
        forks: repo.forks,
        pushed_at: repo.pushed_at,
        last_commit_at: repo.last_commit_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repo_refs() {
        let r = RepoRef::try_from("rust-lang/cargo".to_owned()).unwrap();
        assert_eq!((r.owner.as_str(), r.name.as_str()), ("rust-lang", "cargo"));
        assert_eq!(r.to_string(), "rust-lang/cargo");
        for bad in ["cargo", "/cargo", "rust-lang/", "a/b/c"] {
            assert!(RepoRef::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}

//! Alert collection: fetch open alerts, resolve the ones that disappeared,
//! and hand the observed state to the store.

use crate::{Collector, Error, record};
use chrono::{DateTime, Utc};
use gh::{AlertKind, AlertSeverity, AlertStatus, SecurityAlert};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use store::{
    Alert, AlertFilter, AlertRecord, AlertSource, AlertState, RepoId, RepoKind, RunId, Severity,
    SourceStatus,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertsConfig {
    /// Alert sources to collect.
    pub sources: Vec<AlertSource>,
    /// Skip per-repository requests for archived repositories.
    pub skip_archived: bool,
    /// Skip per-repository requests for forks (Dependabot is off for forks
    /// by default anyway).
    pub skip_forks: bool,
    /// GitHub assigns no severity to leaked secrets.
    pub secret_severity: Severity,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            sources: AlertSource::ALL.to_vec(),
            skip_archived: true,
            skip_forks: true,
            secret_severity: Severity::Critical,
        }
    }
}

/// A repository as stored in this run.
#[derive(Debug, Clone)]
pub(crate) struct Tracked {
    pub id: RepoId,
    pub kind: RepoKind,
    pub owner: String,
    pub name: String,
    pub archived: bool,
    pub fork: bool,
}

/// The GitHub endpoint family of a source; `None` for sources GitHub
/// doesn't report (OSV estimates, see `estimate.rs`).
fn kind_of(source: AlertSource) -> Option<AlertKind> {
    match source {
        AlertSource::Dependabot => Some(AlertKind::Dependabot),
        AlertSource::CodeScanning => Some(AlertKind::CodeScanning),
        AlertSource::SecretScanning => Some(AlertKind::SecretScanning),
        AlertSource::Osv => None,
    }
}

type AlertResult = Result<Vec<SecurityAlert>, gh::Error>;

impl Collector {
    pub(crate) async fn collect_alerts(
        &self,
        run: RunId,
        repos: &[Tracked],
        errors: &mut Vec<String>,
    ) -> Result<(), Error> {
        let mut orgs: HashMap<String, Vec<&Tracked>> = HashMap::new();
        let mut individually: Vec<&Tracked> = Vec::new();
        for repo in repos {
            match repo.kind {
                RepoKind::Org => orgs
                    .entry(repo.owner.to_lowercase())
                    .or_default()
                    .push(repo),
                RepoKind::User | RepoKind::External => individually.push(repo),
            }
        }

        for &source in &self.config.alerts.sources {
            let Some(kind) = kind_of(source) else {
                continue;
            };
            let mut fallback: Vec<&Tracked> = Vec::new();

            for org_repos in orgs.values() {
                let org = &org_repos[0].owner;
                match self.github.org_alerts(org, kind).await {
                    Ok(alerts) => {
                        let mut by_repo: HashMap<String, Vec<SecurityAlert>> = HashMap::new();
                        for alert in alerts {
                            by_repo
                                .entry(alert.repo.to_lowercase())
                                .or_default()
                                .push(alert);
                        }
                        // The org endpoint covers every repository, so no
                        // entry means no open alerts.
                        for repo in org_repos {
                            let open = by_repo
                                .remove(&repo.name.to_lowercase())
                                .unwrap_or_default();
                            self.apply(run, repo, source, kind, open, errors).await?;
                        }
                    }
                    Err(e) if e.is_inaccessible() => {
                        tracing::info!(%org, ?source, error = %e, "org endpoint unavailable, querying repositories");
                        fallback.extend(org_repos.iter().copied());
                    }
                    Err(e) => {
                        let message = e.reason();
                        record(errors, format!("{source} alerts of {org}"), e);
                        for repo in org_repos {
                            self.status(run, repo, source, SourceStatus::Error, Some(&message))
                                .await?;
                        }
                    }
                }
            }

            let mut queried = Vec::new();
            for repo in individually.iter().chain(fallback.iter()) {
                if (repo.archived && self.config.alerts.skip_archived)
                    || (repo.fork && self.config.alerts.skip_forks)
                {
                    let why = if repo.archived { "archived" } else { "fork" };
                    self.status(run, repo, source, SourceStatus::Skipped, Some(why))
                        .await?;
                } else {
                    queried.push(*repo);
                }
            }

            for (repo, result) in self.fetch_per_repo(&queried, kind).await {
                match result {
                    Ok(open) => self.apply(run, repo, source, kind, open, errors).await?,
                    Err(e) if e.is_inaccessible() => {
                        let message = e.reason();
                        self.status(run, repo, source, SourceStatus::Unavailable, Some(&message))
                            .await?;
                    }
                    Err(e) => {
                        let message = e.reason();
                        record(
                            errors,
                            format!("{source} alerts of {}/{}", repo.owner, repo.name),
                            e,
                        );
                        self.status(run, repo, source, SourceStatus::Error, Some(&message))
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Open alerts per repository, fetched in parallel; results keep the
    /// input order.
    async fn fetch_per_repo<'a>(
        &self,
        repos: &[&'a Tracked],
        kind: AlertKind,
    ) -> Vec<(&'a Tracked, AlertResult)> {
        let permits = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut tasks = JoinSet::new();
        for (index, repo) in repos.iter().enumerate() {
            let github = Arc::clone(&self.github);
            let permits = Arc::clone(&permits);
            let (owner, name) = (repo.owner.clone(), repo.name.clone());
            tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .expect("semaphore is never closed");
                (index, github.repo_alerts(&owner, &name, kind).await)
            });
        }

        let mut results: Vec<Option<AlertResult>> = repos.iter().map(|_| None).collect();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, result)) => results[index] = Some(result),
                Err(e) => tracing::error!(error = %e, "alert task failed"),
            }
        }
        repos
            .iter()
            .zip(results)
            .filter_map(|(repo, result)| result.map(|r| (*repo, r)))
            .collect()
    }

    /// Records the open alerts of one source and works out what happened
    /// to previously open alerts that are no longer listed.
    async fn apply(
        &self,
        run: RunId,
        repo: &Tracked,
        source: AlertSource,
        kind: AlertKind,
        open: Vec<SecurityAlert>,
        errors: &mut Vec<String>,
    ) -> Result<(), Error> {
        let listed: HashSet<i64> = open.iter().map(|a| a.number).collect();
        let mut records: Vec<AlertRecord> =
            open.iter().map(|a| self.to_record(source, a)).collect();

        let previously_open = self
            .store
            .list_alerts(
                repo.id,
                &AlertFilter {
                    source: Some(source),
                    state: Some(AlertState::Open),
                },
            )
            .await?;
        for stale in previously_open
            .iter()
            .filter(|a| !listed.contains(&a.record.number))
        {
            match self
                .github
                .repo_alert(&repo.owner, &repo.name, kind, stale.record.number)
                .await
            {
                Ok(current) => records.push(self.to_record(source, &current)),
                Err(e) if e.is_inaccessible() => records.push(gone(stale)),
                Err(e) => record(
                    errors,
                    format!(
                        "{source} alert #{} of {}/{}",
                        stale.record.number, repo.owner, repo.name
                    ),
                    e,
                ),
            }
        }

        // Alerts found the first time a source can be read already existed;
        // their events are flagged so they don't read as news.
        let baseline = !self
            .store
            .source_statuses(repo.id)
            .await?
            .iter()
            .any(|s| s.source == source && s.first_collected_run.is_some());

        let at = Utc::now();
        let events = self
            .store
            .record_alerts(repo.id, run, at, &records, baseline)
            .await?;
        if events > 0 {
            tracing::info!(repo = %format!("{}/{}", repo.owner, repo.name), ?source, events, "alerts changed");
        }
        self.status(run, repo, source, SourceStatus::Ok, None).await
    }

    async fn status(
        &self,
        run: RunId,
        repo: &Tracked,
        source: AlertSource,
        status: SourceStatus,
        message: Option<&str>,
    ) -> Result<(), Error> {
        self.store
            .set_source_status(repo.id, source, run, Utc::now(), status, message)
            .await?;
        Ok(())
    }

    fn to_record(&self, source: AlertSource, alert: &SecurityAlert) -> AlertRecord {
        let severity = match alert.severity {
            Some(AlertSeverity::Critical) => Severity::Critical,
            Some(AlertSeverity::High) => Severity::High,
            Some(AlertSeverity::Medium) => Severity::Medium,
            Some(AlertSeverity::Low) => Severity::Low,
            None if source == AlertSource::SecretScanning => self.config.alerts.secret_severity,
            None => Severity::Low,
        };
        AlertRecord {
            source,
            number: alert.number,
            state: match alert.status {
                AlertStatus::Open => AlertState::Open,
                AlertStatus::Fixed => AlertState::Fixed,
                AlertStatus::Dismissed => AlertState::Dismissed,
            },
            severity,
            title: alert.title.clone(),
            location: alert.location.clone(),
            html_url: alert.html_url.clone(),
            created_at: alert.created_at,
            closed_at: alert.closed_at,
            estimated: false,
        }
    }
}

/// The last known state of an alert GitHub no longer returns.
fn gone(alert: &Alert) -> AlertRecord {
    let closed_at: DateTime<Utc> = Utc::now();
    AlertRecord {
        state: AlertState::Gone,
        closed_at: Some(closed_at),
        ..alert.record.clone()
    }
}

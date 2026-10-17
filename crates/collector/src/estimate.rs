//! Estimated alerts for repositories whose Dependabot alerts can't be
//! read: dependencies from GitHub's SBOM export, checked against OSV.

use crate::alerts::Tracked;
use crate::osv::{Dependency, OsvClient};
use crate::{Collector, Error, record};
use chrono::Utc;
use serde::Deserialize;
use store::{AlertFilter, AlertRecord, AlertSource, AlertState, RepoKind, RunId, SourceStatus};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OsvConfig {
    pub enabled: bool,
    pub api_url: String,
    pub scope: OsvScope,
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_url: "https://api.osv.dev".into(),
            scope: OsvScope::External,
        }
    }
}

/// Which repositories get estimated alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvScope {
    /// External repositories whose Dependabot alerts can't be read.
    External,
    /// Every repository whose Dependabot alerts can't be read, including
    /// tracked ones with Dependabot disabled.
    WithoutDependabot,
}

pub(crate) fn client(config: &OsvConfig) -> Option<OsvClient> {
    config.enabled.then(|| {
        OsvClient::new(
            &config.api_url,
            concat!("github-security-dashboard/", env!("CARGO_PKG_VERSION")),
        )
    })
}

/// Stable alert number for an advisory affecting a package, regardless of
/// version: bumping to another affected version keeps the same alert.
/// FNV-1a, truncated to 53 bits so it survives JSON in browsers.
fn alert_number(advisory: &str, package: &str) -> i64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in advisory.bytes().chain([0]).chain(package.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash & ((1 << 53) - 1)) as i64
}

impl Collector {
    pub(crate) async fn estimate_with_osv(
        &self,
        run: RunId,
        repos: &[Tracked],
        errors: &mut Vec<String>,
    ) -> Result<(), Error> {
        let Some(osv) = &self.osv else {
            return Ok(());
        };
        let source = AlertSource::Osv;

        for repo in repos {
            if (repo.archived && self.config.alerts.skip_archived)
                || (repo.fork && self.config.alerts.skip_forks)
            {
                continue;
            }
            let statuses = self.store.source_statuses(repo.id).await?;
            let dependabot_readable = statuses
                .iter()
                .any(|s| s.source == AlertSource::Dependabot && s.status == SourceStatus::Ok);
            let in_scope = !dependabot_readable
                && match self.config.osv.scope {
                    OsvScope::External => repo.kind == RepoKind::External,
                    OsvScope::WithoutDependabot => true,
                };
            if !in_scope {
                continue;
            }
            let name = format!("{}/{}", repo.owner, repo.name);

            let purls = match self.github.dependency_purls(&repo.owner, &repo.name).await {
                Ok(purls) => purls,
                Err(e) => {
                    let status = if e.is_inaccessible() {
                        SourceStatus::Unavailable
                    } else {
                        SourceStatus::Error
                    };
                    let reason = e.reason();
                    if status == SourceStatus::Error {
                        record(errors, format!("dependency graph of {name}"), e);
                    }
                    self.store
                        .set_source_status(repo.id, source, run, Utc::now(), status, Some(&reason))
                        .await?;
                    continue;
                }
            };
            let deps: Vec<Dependency> = purls.iter().filter_map(|p| Dependency::parse(p)).collect();
            let unresolved = purls.len() - deps.len();

            let affected = match osv.affected(&deps).await {
                Ok(affected) => affected,
                Err(e) => {
                    let reason = e.to_string();
                    errors.push(format!("OSV lookup for {name}: {reason}"));
                    self.store
                        .set_source_status(
                            repo.id,
                            source,
                            run,
                            Utc::now(),
                            SourceStatus::Error,
                            Some(&reason),
                        )
                        .await?;
                    continue;
                }
            };

            let mut records: Vec<AlertRecord> = Vec::new();
            let mut failed = None;
            for (dep, ids) in deps.iter().zip(affected) {
                for id in ids {
                    let advisory = match osv.advisory(&id).await {
                        Ok(advisory) => advisory,
                        Err(e) => {
                            failed = Some(e.to_string());
                            continue;
                        }
                    };
                    let number = alert_number(&advisory.id, &dep.package);
                    let location = format!("{}@{}", dep.package, dep.version);
                    // Several affected versions of one package: one alert.
                    if let Some(existing) = records.iter_mut().find(|r| r.number == number) {
                        if let Some(l) = &mut existing.location
                            && !l.contains(&location)
                        {
                            l.push_str(&format!(", {}", dep.version));
                        }
                        continue;
                    }
                    records.push(AlertRecord {
                        source,
                        number,
                        state: AlertState::Open,
                        severity: advisory.severity,
                        title: format!("{}: {}", advisory.id, advisory.summary),
                        location: Some(format!(
                            "{location} (severity: {})",
                            advisory.severity_basis
                        )),
                        html_url: format!("https://osv.dev/vulnerability/{}", advisory.id),
                        created_at: advisory.published.unwrap_or_else(Utc::now),
                        closed_at: None,
                        estimated: true,
                    });
                }
            }
            if let Some(reason) = failed {
                // Without every advisory the set is incomplete; closing
                // estimates now could be wrong, so keep the stored state.
                errors.push(format!("OSV advisory for {name}: {reason}"));
                self.store
                    .set_source_status(
                        repo.id,
                        source,
                        run,
                        Utc::now(),
                        SourceStatus::Error,
                        Some(&reason),
                    )
                    .await?;
                continue;
            }

            // Estimates that no longer apply: the dependency was updated or
            // removed, which for an estimate is as good as fixed.
            let now = Utc::now();
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
            for stale in previously_open {
                if !records.iter().any(|r| r.number == stale.record.number) {
                    records.push(AlertRecord {
                        state: AlertState::Fixed,
                        closed_at: Some(now),
                        ..stale.record
                    });
                }
            }

            let baseline = !statuses
                .iter()
                .any(|s| s.source == source && s.first_collected_run.is_some());
            let events = self
                .store
                .record_alerts(repo.id, run, now, &records, baseline)
                .await?;
            if events > 0 {
                tracing::info!(repo = %name, events, "estimated alerts changed");
            }
            let message = format!(
                "{} dependencies checked{}",
                deps.len(),
                if unresolved > 0 {
                    format!(", {unresolved} without an exact version skipped")
                } else {
                    String::new()
                }
            );
            self.store
                .set_source_status(repo.id, source, run, now, SourceStatus::Ok, Some(&message))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn alert_numbers_are_stable_and_version_independent() {
        let a = alert_number("GHSA-35jh-r3h4-6jhm", "npm/lodash");
        check!(a == alert_number("GHSA-35jh-r3h4-6jhm", "npm/lodash"));
        check!(a != alert_number("GHSA-35jh-r3h4-6jhm", "npm/lodash-es"));
        check!(a != alert_number("GHSA-29mw-wpgm-hmr9", "npm/lodash"));
        check!(a >= 0 && a < (1 << 53));
    }
}

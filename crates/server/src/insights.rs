//! Where open alerts concentrate: distributions and the issues that affect
//! the most repositories.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use store::{AlertSource, OpenAlert, Severity, SeverityCounts};

/// Issues listed in "most widespread".
pub const TOP_ISSUES: usize = 10;

/// One bar of a distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bucket {
    pub key: String,
    pub counts: SeverityCounts,
    pub total: i64,
    /// Repositories with alerts in this bucket, for filtering the table.
    pub repo_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueAlert {
    pub source: AlertSource,
    pub number: i64,
    pub url: String,
    pub estimated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueRepository {
    pub id: i64,
    pub owner: String,
    pub name: String,
    pub alerts: Vec<IssueAlert>,
}

/// One issue (an advisory under all its IDs, a code scanning rule, or a
/// secret type) and the repositories it has open alerts in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    /// GHSA first, then CVE, then the rest.
    pub ids: Vec<String>,
    pub title: String,
    /// The most severe of its alerts.
    pub severity: Severity,
    pub sources: Vec<AlertSource>,
    /// Only known from estimates, not from GitHub alerts.
    pub estimated_only: bool,
    pub repositories: Vec<IssueRepository>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Insights {
    pub by_source: Vec<Bucket>,
    pub by_ecosystem: Vec<Bucket>,
    pub by_owner: Vec<Bucket>,
    /// Fixed order: `week`, `month`, `quarter`, `older`.
    pub by_age: Vec<Bucket>,
    pub widespread: Vec<Issue>,
}

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

#[derive(Default)]
struct Tally {
    counts: SeverityCounts,
    repos: BTreeSet<i64>,
}

impl Tally {
    fn add(&mut self, alert: &OpenAlert) {
        self.counts.add(alert.alert.record.severity, 1);
        self.repos.insert(alert.alert.repo_id.0);
    }

    fn bucket(self, key: String) -> Bucket {
        Bucket {
            key,
            total: self.counts.total(),
            counts: self.counts,
            repo_ids: self.repos.into_iter().collect(),
        }
    }
}

/// Buckets sorted by total, largest first; ties by key.
fn ranked(tallies: BTreeMap<String, Tally>) -> Vec<Bucket> {
    let mut buckets: Vec<Bucket> = tallies.into_iter().map(|(k, t)| t.bucket(k)).collect();
    buckets.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.key.cmp(&b.key)));
    buckets
}

fn age_bucket(created: DateTime<Utc>, now: DateTime<Utc>) -> &'static str {
    match (now - created).num_days() {
        ..7 => "week",
        7..30 => "month",
        30..90 => "quarter",
        _ => "older",
    }
}

/// Orders IDs so the most recognizable comes first.
fn id_order(id: &str) -> (u8, &str) {
    let class = if id.starts_with("GHSA-") {
        0
    } else if id.starts_with("CVE-") {
        1
    } else {
        2
    };
    (class, id)
}

/// The groups alerts are counted under. Dependency alerts that share any
/// advisory ID (GHSA, CVE, RUSTSEC, ...) belong to one group, whichever
/// source reported them; code scanning rules and secret types group by
/// themselves.
fn group_alerts<'a>(alerts: &[&'a OpenAlert]) -> Vec<Vec<&'a OpenAlert>> {
    let mut groups: Vec<(BTreeSet<String>, Vec<&OpenAlert>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    for &alert in alerts {
        let record = &alert.alert.record;
        if record.advisory_ids.is_empty() {
            continue;
        }
        let keys: Vec<String> = match record.source {
            AlertSource::Dependabot | AlertSource::Osv => record.advisory_ids.clone(),
            AlertSource::CodeScanning => record
                .advisory_ids
                .iter()
                .map(|i| format!("rule:{i}"))
                .collect(),
            AlertSource::SecretScanning => record
                .advisory_ids
                .iter()
                .map(|i| format!("secret:{i}"))
                .collect(),
        };
        let mut targets: Vec<usize> = keys.iter().filter_map(|k| index.get(k).copied()).collect();
        targets.sort_unstable();
        targets.dedup();
        let target = match targets.first() {
            Some(&first) => {
                // This alert links groups that were separate so far: merge.
                for &other in targets[1..].iter().rev() {
                    let (ids, members) = std::mem::take(&mut groups[other]);
                    for id in &ids {
                        index.insert(id.clone(), first);
                    }
                    groups[first].0.extend(ids);
                    groups[first].1.extend(members);
                }
                first
            }
            None => {
                groups.push(Default::default());
                groups.len() - 1
            }
        };
        for key in keys {
            index.insert(key.clone(), target);
            groups[target].0.insert(key);
        }
        groups[target].1.push(alert);
    }
    groups
        .into_iter()
        .map(|(_, members)| members)
        .filter(|m| !m.is_empty())
        .collect()
}

fn issue(members: &[&OpenAlert]) -> Issue {
    let mut ids: Vec<String> = members
        .iter()
        .flat_map(|a| a.alert.record.advisory_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ids.sort_by(|a, b| id_order(a).cmp(&id_order(b)));

    // GitHub's own titles read best; estimates prefix theirs with the ID.
    let title = members
        .iter()
        .find(|a| !a.alert.record.estimated)
        .or_else(|| members.first())
        .map(|a| {
            let title = &a.alert.record.title;
            if a.alert.record.estimated {
                title
                    .split_once(": ")
                    .map_or(title.as_str(), |(_, t)| t)
                    .to_owned()
            } else {
                title.clone()
            }
        })
        .unwrap_or_default();

    let mut repositories: BTreeMap<i64, IssueRepository> = BTreeMap::new();
    for alert in members {
        let entry = repositories
            .entry(alert.alert.repo_id.0)
            .or_insert_with(|| IssueRepository {
                id: alert.alert.repo_id.0,
                owner: alert.owner.clone(),
                name: alert.repo.clone(),
                alerts: Vec::new(),
            });
        entry.alerts.push(IssueAlert {
            source: alert.alert.record.source,
            number: alert.alert.record.number,
            url: alert.alert.record.html_url.clone(),
            estimated: alert.alert.record.estimated,
        });
    }
    let mut repositories: Vec<IssueRepository> = repositories.into_values().collect();
    repositories.sort_by(|a, b| {
        (a.owner.to_lowercase(), a.name.to_lowercase())
            .cmp(&(b.owner.to_lowercase(), b.name.to_lowercase()))
    });

    Issue {
        ids,
        title,
        severity: members
            .iter()
            .map(|a| a.alert.record.severity)
            .min_by_key(|s| rank(*s))
            .unwrap_or(Severity::Low),
        sources: members
            .iter()
            .map(|a| a.alert.record.source)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        estimated_only: members.iter().all(|a| a.alert.record.estimated),
        repositories,
    }
}

/// Computes the insights over the open alerts of repositories for which
/// `counts` returns true (the same set the totals use).
pub fn compute(
    alerts: &[OpenAlert],
    now: DateTime<Utc>,
    counts: impl Fn(&OpenAlert) -> bool,
) -> Insights {
    let alerts: Vec<&OpenAlert> = alerts.iter().filter(|a| counts(a)).collect();

    let mut by_source: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_ecosystem: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_owner: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_age: BTreeMap<&str, Tally> = BTreeMap::new();
    for &alert in &alerts {
        let record = &alert.alert.record;
        by_source
            .entry(record.source.as_str().to_owned())
            .or_default()
            .add(alert);
        if let Some(ecosystem) = &record.ecosystem {
            by_ecosystem
                .entry(ecosystem.clone())
                .or_default()
                .add(alert);
        }
        by_owner.entry(alert.owner.clone()).or_default().add(alert);
        by_age
            .entry(age_bucket(record.created_at, now))
            .or_default()
            .add(alert);
    }
    let by_age = ["week", "month", "quarter", "older"]
        .into_iter()
        .map(|key| {
            by_age
                .remove(key)
                .unwrap_or_default()
                .bucket(key.to_owned())
        })
        .collect();

    let mut widespread: Vec<Issue> = group_alerts(&alerts)
        .iter()
        .map(|members| issue(members))
        .filter(|issue| issue.repositories.len() >= 2)
        .collect();
    widespread.sort_by(|a, b| {
        b.repositories
            .len()
            .cmp(&a.repositories.len())
            .then_with(|| rank(a.severity).cmp(&rank(b.severity)))
            .then_with(|| a.ids.cmp(&b.ids))
    });
    widespread.truncate(TOP_ISSUES);

    Insights {
        by_source: ranked(by_source),
        by_ecosystem: ranked(by_ecosystem),
        by_owner: ranked(by_owner),
        by_age,
        widespread,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use store::{Alert, AlertId, AlertRecord, AlertState, RepoId, RunId};

    fn now() -> DateTime<Utc> {
        "2026-10-17T12:00:00Z".parse().unwrap()
    }

    struct A {
        repo: i64,
        source: AlertSource,
        severity: Severity,
        ids: &'static [&'static str],
        ecosystem: Option<&'static str>,
        days_old: i64,
        estimated: bool,
    }

    fn open(n: i64, a: A) -> OpenAlert {
        OpenAlert {
            owner: if a.repo < 10 {
                "acme".into()
            } else {
                "me".into()
            },
            repo: format!("repo{}", a.repo),
            archived: false,
            repo_last_seen_run: RunId(1),
            alert: Alert {
                id: AlertId(n),
                repo_id: RepoId(a.repo),
                record: AlertRecord {
                    source: a.source,
                    number: n,
                    state: AlertState::Open,
                    severity: a.severity,
                    title: if a.estimated {
                        format!("{}: estimated title", a.ids[0])
                    } else {
                        "GitHub title".into()
                    },
                    location: None,
                    html_url: format!("https://example.org/{n}"),
                    created_at: now() - chrono::Duration::days(a.days_old),
                    closed_at: None,
                    estimated: a.estimated,
                    advisory_ids: a.ids.iter().map(|s| s.to_string()).collect(),
                    ecosystem: a.ecosystem.map(str::to_owned),
                },
                first_seen_run: RunId(1),
                last_seen_run: RunId(1),
            },
        }
    }

    fn dep(repo: i64, severity: Severity, ids: &'static [&'static str]) -> A {
        A {
            repo,
            source: AlertSource::Dependabot,
            severity,
            ids,
            ecosystem: Some("npm"),
            days_old: 1,
            estimated: false,
        }
    }

    #[test]
    fn distributions_count_by_source_ecosystem_owner_and_age() {
        let alerts = vec![
            open(1, dep(1, Severity::Critical, &["GHSA-1"])),
            open(
                2,
                A {
                    days_old: 40,
                    ..dep(2, Severity::High, &["GHSA-2"])
                },
            ),
            open(
                3,
                A {
                    ecosystem: Some("cargo"),
                    days_old: 400,
                    ..dep(11, Severity::Low, &["GHSA-3"])
                },
            ),
            open(
                4,
                A {
                    source: AlertSource::CodeScanning,
                    ecosystem: None,
                    days_old: 10,
                    ..dep(1, Severity::Medium, &["js/xss"])
                },
            ),
        ];
        let insights = compute(&alerts, now(), |_| true);

        let keys = |b: &[Bucket]| {
            b.iter()
                .map(|b| (b.key.clone(), b.total))
                .collect::<Vec<_>>()
        };
        check!(
            keys(&insights.by_source) == [("dependabot".into(), 3), ("code_scanning".into(), 1)]
        );
        check!(keys(&insights.by_ecosystem) == [("npm".into(), 2), ("cargo".into(), 1)]);
        check!(keys(&insights.by_owner) == [("acme".into(), 3), ("me".into(), 1)]);
        check!(
            keys(&insights.by_age)
                == [
                    ("week".into(), 1),
                    ("month".into(), 1),
                    ("quarter".into(), 1),
                    ("older".into(), 1)
                ]
        );
        check!(insights.by_source[0].counts.critical == 1);
        check!(insights.by_source[0].repo_ids == [1, 2, 11]);
    }

    #[test]
    fn an_issue_under_several_ids_counts_once() {
        let alerts = vec![
            open(1, dep(1, Severity::High, &["GHSA-aaaa", "CVE-2026-1"])),
            open(2, dep(2, Severity::Critical, &["CVE-2026-1"])),
            // An estimate linking the RustSec ID to the same GHSA.
            open(
                3,
                A {
                    source: AlertSource::Osv,
                    estimated: true,
                    ..dep(3, Severity::Medium, &["RUSTSEC-2026-1", "GHSA-aaaa"])
                },
            ),
            open(4, dep(4, Severity::Low, &["RUSTSEC-2026-1"])),
            // Two alerts of one repository: one repository.
            open(5, dep(1, Severity::High, &["GHSA-aaaa"])),
        ];
        let insights = compute(&alerts, now(), |_| true);
        check!(insights.widespread.len() == 1);
        let issue = &insights.widespread[0];
        check!(issue.ids == ["GHSA-aaaa", "CVE-2026-1", "RUSTSEC-2026-1"]);
        check!(issue.repositories.len() == 4);
        check!(issue.repositories[0].alerts.len() == 2);
        check!(issue.severity == Severity::Critical);
        check!(issue.sources == [AlertSource::Dependabot, AlertSource::Osv]);
        check!(!issue.estimated_only);
        check!(issue.title == "GitHub title");
    }

    #[test]
    fn widespread_ranks_by_reach_then_severity_and_skips_singletons() {
        let mut alerts = Vec::new();
        let mut n = 0;
        let mut add = |repos: &[i64],
                       severity: Severity,
                       id: &'static [&'static str],
                       alerts: &mut Vec<OpenAlert>| {
            for &repo in repos {
                n += 1;
                alerts.push(open(n, dep(repo, severity, id)));
            }
        };
        add(
            &[1, 2],
            Severity::Critical,
            &["GHSA-two-critical"],
            &mut alerts,
        );
        add(&[1, 2, 3], Severity::Low, &["GHSA-three"], &mut alerts);
        add(&[1, 2], Severity::High, &["GHSA-two-high"], &mut alerts);
        add(&[1], Severity::Critical, &["GHSA-one"], &mut alerts);
        let rule = A {
            source: AlertSource::CodeScanning,
            ecosystem: None,
            ..dep(
                0,
                Severity::Medium,
                &["actions/missing-workflow-permissions"],
            )
        };
        alerts.push(open(100, A { repo: 5, ..rule }));
        alerts.push(open(
            101,
            A {
                repo: 6,
                source: AlertSource::CodeScanning,
                ecosystem: None,
                ..dep(
                    6,
                    Severity::Medium,
                    &["actions/missing-workflow-permissions"],
                )
            },
        ));

        let insights = compute(&alerts, now(), |_| true);
        let order: Vec<_> = insights
            .widespread
            .iter()
            .map(|i| i.ids[0].as_str())
            .collect();
        check!(
            order
                == [
                    "GHSA-three",
                    "GHSA-two-critical",
                    "GHSA-two-high",
                    "actions/missing-workflow-permissions"
                ]
        );
    }

    #[test]
    fn only_counted_repositories_contribute() {
        let alerts = vec![
            open(1, dep(1, Severity::High, &["GHSA-1"])),
            open(2, dep(2, Severity::High, &["GHSA-1"])),
        ];
        let insights = compute(&alerts, now(), |a| a.alert.repo_id.0 != 2);
        check!(insights.by_source[0].total == 1);
        check!(insights.widespread.is_empty());
    }

    #[test]
    fn top_list_is_capped() {
        let alerts: Vec<_> = (0..30)
            .flat_map(|i| {
                let id: &'static str = Box::leak(format!("GHSA-{i:02}").into_boxed_str());
                let ids: &'static [&'static str] = Box::leak(vec![id].into_boxed_slice());
                [
                    open(i * 2, dep(1, Severity::Low, ids)),
                    open(i * 2 + 1, dep(2, Severity::Low, ids)),
                ]
            })
            .collect();
        check!(compute(&alerts, now(), |_| true).widespread.len() == TOP_ISSUES);
    }
}

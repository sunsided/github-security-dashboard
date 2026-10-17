//! Behavior every `Store` backend must satisfy.
//!
//! Each check is a plain async function over `Arc<dyn Store>`; the
//! `contract_tests!` macro instantiates all of them for one backend.

use chrono::{DateTime, Duration, TimeZone, Utc};
use std::sync::Arc;
use store::{
    AlertFilter, AlertRecord, AlertSource, AlertState, EventFilter, EventKind, RepoFilter,
    RepoInfo, RepoKind, RepoStats, RunStatus, Severity, SourceStatus, Store,
};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 17, 12, 0, 0).unwrap()
}

fn repo(owner: &str, name: &str, kind: RepoKind) -> RepoInfo {
    RepoInfo {
        owner: owner.into(),
        name: name.into(),
        kind,
        url: format!("https://github.com/{owner}/{name}"),
        description: Some("test repository".into()),
        archived: false,
        fork: false,
        private: true,
        language: Some("Rust".into()),
        default_branch: Some("main".into()),
    }
}

fn stats(open_issues: i64) -> RepoStats {
    RepoStats {
        open_issues,
        open_prs: 2,
        contributors: Some(3),
        commits: Some(42),
        tags: 4,
        releases: 1,
        stars: 7,
        forks: 0,
        pushed_at: Some(t0() - Duration::days(3)),
        last_commit_at: Some(t0() - Duration::days(5)),
    }
}

pub async fn runs_round_trip(store: Arc<dyn Store>) {
    let first = store.begin_run(t0()).await.unwrap();
    let second = store.begin_run(t0() + Duration::minutes(30)).await.unwrap();
    store
        .finish_run(
            first,
            t0() + Duration::minutes(1),
            RunStatus::Partial,
            Some(4321),
            &["acme: 403".to_owned()],
        )
        .await
        .unwrap();

    let runs = store.list_runs(10).await.unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].id, second, "most recent first");
    assert_eq!(runs[0].status, RunStatus::Running);
    assert_eq!(runs[0].finished_at, None);
    assert_eq!(runs[1].status, RunStatus::Partial);
    assert_eq!(runs[1].rate_limit_remaining, Some(4321));
    assert_eq!(runs[1].errors, vec!["acme: 403".to_owned()]);
    assert_eq!(runs[1].finished_at, Some(t0() + Duration::minutes(1)));

    assert_eq!(store.list_runs(1).await.unwrap().len(), 1);
}

pub async fn upsert_is_keyed_case_insensitively(store: Arc<dyn Store>) {
    let run1 = store.begin_run(t0()).await.unwrap();
    let id1 = store
        .upsert_repo(&repo("Acme", "Widget", RepoKind::Org), run1)
        .await
        .unwrap();

    let run2 = store.begin_run(t0() + Duration::hours(1)).await.unwrap();
    let mut changed = repo("acme", "widget", RepoKind::Org);
    changed.archived = true;
    let id2 = store.upsert_repo(&changed, run2).await.unwrap();

    assert_eq!(id1, id2);
    let stored = store.get_repo("ACME", "WIDGET").await.unwrap().unwrap();
    assert!(stored.info.archived);
    assert_eq!(stored.info.owner, "acme", "takes the latest spelling");
    assert_eq!(stored.last_seen_run, run2);
}

pub async fn overview_carries_latest_snapshot(store: Arc<dyn Store>) {
    let run1 = store.begin_run(t0()).await.unwrap();
    let id = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run1)
        .await
        .unwrap();
    store
        .insert_snapshot(id, run1, t0(), &stats(10))
        .await
        .unwrap();

    let run2 = store.begin_run(t0() + Duration::hours(1)).await.unwrap();
    store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run2)
        .await
        .unwrap();
    store
        .insert_snapshot(id, run2, t0() + Duration::hours(1), &stats(11))
        .await
        .unwrap();

    let overview = store.get_repo("acme", "widget").await.unwrap().unwrap();
    let latest = overview.latest.unwrap();
    assert_eq!(latest.run_id, run2);
    assert_eq!(latest.stats, stats(11));

    let history = store.snapshot_history(id, 10).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].stats.open_issues, 11);
    assert_eq!(history[1].stats.open_issues, 10);
    assert_eq!(history[1].taken_at, t0());
}

pub async fn repo_without_snapshot_has_no_latest(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    store
        .upsert_repo(&repo("acme", "empty", RepoKind::Org), run)
        .await
        .unwrap();
    let overview = store.get_repo("acme", "empty").await.unwrap().unwrap();
    assert!(overview.latest.is_none());
    assert!(store.get_repo("acme", "missing").await.unwrap().is_none());
}

pub async fn snapshots_are_append_only(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    let id = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run)
        .await
        .unwrap();
    store
        .insert_snapshot(id, run, t0(), &stats(1))
        .await
        .unwrap();
    assert!(
        store
            .insert_snapshot(id, run, t0(), &stats(2))
            .await
            .is_err(),
        "a second snapshot for the same run must not overwrite the first"
    );
}

pub async fn list_filters(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    store
        .upsert_repo(&repo("acme", "b", RepoKind::Org), run)
        .await
        .unwrap();
    store
        .upsert_repo(&repo("acme", "a", RepoKind::Org), run)
        .await
        .unwrap();
    store
        .upsert_repo(&repo("me", "dotfiles", RepoKind::User), run)
        .await
        .unwrap();
    store
        .upsert_repo(&repo("rust-lang", "cargo", RepoKind::External), run)
        .await
        .unwrap();
    let mut archived = repo("acme", "old", RepoKind::Org);
    archived.archived = true;
    store.upsert_repo(&archived, run).await.unwrap();

    let names = |repos: Vec<store::RepoOverview>| {
        repos
            .into_iter()
            .map(|r| format!("{}/{}", r.info.owner, r.info.name))
            .collect::<Vec<_>>()
    };

    let all = store.list_repos(&RepoFilter::default()).await.unwrap();
    assert_eq!(
        names(all),
        ["acme/a", "acme/b", "me/dotfiles", "rust-lang/cargo"]
    );

    let with_archived = store
        .list_repos(&RepoFilter {
            include_archived: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(with_archived.len(), 5);

    let acme = store
        .list_repos(&RepoFilter {
            owner: Some("ACME".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(names(acme), ["acme/a", "acme/b"]);

    let external = store
        .list_repos(&RepoFilter {
            kind: Some(RepoKind::External),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(names(external), ["rust-lang/cargo"]);
}

fn alert(number: i64, state: AlertState, severity: Severity) -> AlertRecord {
    AlertRecord {
        source: AlertSource::Dependabot,
        number,
        state,
        severity,
        title: format!("advisory {number}"),
        location: Some("serde_json".into()),
        html_url: format!("https://github.com/acme/widget/security/dependabot/{number}"),
        created_at: t0() - Duration::days(1),
        closed_at: None,
        estimated: false,
    }
}

pub async fn alert_lifecycle_is_audited(store: Arc<dyn Store>) {
    let run1 = store.begin_run(t0()).await.unwrap();
    let repo = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run1)
        .await
        .unwrap();

    let opened = store
        .record_alerts(
            repo,
            run1,
            t0(),
            &[
                alert(1, AlertState::Open, Severity::High),
                alert(2, AlertState::Open, Severity::Low),
            ],
        )
        .await
        .unwrap();
    assert_eq!(opened, 2);

    let overview = store.get_repo("acme", "widget").await.unwrap().unwrap();
    assert_eq!(
        (overview.open_alerts.high, overview.open_alerts.low),
        (1, 1)
    );
    assert_eq!(overview.open_alerts.total(), 2);

    // Seeing the same state again changes nothing.
    let run2 = store.begin_run(t0() + Duration::hours(1)).await.unwrap();
    let unchanged = store
        .record_alerts(
            repo,
            run2,
            t0() + Duration::hours(1),
            &[
                alert(1, AlertState::Open, Severity::High),
                alert(2, AlertState::Open, Severity::Low),
            ],
        )
        .await
        .unwrap();
    assert_eq!(unchanged, 0);

    let run3 = store.begin_run(t0() + Duration::hours(2)).await.unwrap();
    let mut fixed = alert(2, AlertState::Fixed, Severity::Low);
    fixed.closed_at = Some(t0() + Duration::hours(2));
    let changed = store
        .record_alerts(
            repo,
            run3,
            t0() + Duration::hours(2),
            &[alert(1, AlertState::Open, Severity::Critical), fixed],
        )
        .await
        .unwrap();
    assert_eq!(changed, 2);

    let overview = store.get_repo("acme", "widget").await.unwrap().unwrap();
    assert_eq!(overview.open_alerts.critical, 1);
    assert_eq!(overview.open_alerts.total(), 1);

    let open = store
        .list_alerts(
            repo,
            &AlertFilter {
                state: Some(AlertState::Open),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].record.severity, Severity::Critical);
    assert_eq!(open[0].first_seen_run, run1);
    assert_eq!(open[0].last_seen_run, run3);

    let all = store
        .list_alerts(repo, &AlertFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].record.state, AlertState::Open, "open alerts first");
    assert_eq!(all[1].record.closed_at, Some(t0() + Duration::hours(2)));

    let events = store
        .alert_events(&EventFilter {
            repo: Some(repo),
            since: None,
            limit: 10,
        })
        .await
        .unwrap();
    let kinds: Vec<_> = events.iter().map(|e| (e.number, e.kind)).collect();
    assert_eq!(
        kinds,
        [
            (2, EventKind::Fixed),
            (1, EventKind::SeverityChanged),
            (2, EventKind::Opened),
            (1, EventKind::Opened),
        ]
    );
    assert_eq!(events[1].old.as_deref(), Some("high"));
    assert_eq!(events[1].new.as_deref(), Some("critical"));
    assert_eq!(
        (events[0].owner.as_str(), events[0].repo.as_str()),
        ("acme", "widget")
    );

    let recent = store
        .alert_events(&EventFilter {
            repo: None,
            since: Some(t0() + Duration::minutes(90)),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(recent.len(), 2);
}

pub async fn alerts_are_scoped_by_repo_and_source(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    let a = store
        .upsert_repo(&repo("acme", "a", RepoKind::Org), run)
        .await
        .unwrap();
    let b = store
        .upsert_repo(&repo("acme", "b", RepoKind::Org), run)
        .await
        .unwrap();

    let mut secret = alert(1, AlertState::Open, Severity::Critical);
    secret.source = AlertSource::SecretScanning;
    store
        .record_alerts(
            a,
            run,
            t0(),
            &[alert(1, AlertState::Open, Severity::High), secret],
        )
        .await
        .unwrap();
    store
        .record_alerts(
            b,
            run,
            t0(),
            &[alert(1, AlertState::Open, Severity::Medium)],
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .list_alerts(a, &AlertFilter::default())
            .await
            .unwrap()
            .len(),
        2
    );
    let only_secrets = store
        .list_alerts(
            a,
            &AlertFilter {
                source: Some(AlertSource::SecretScanning),
                state: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(only_secrets.len(), 1);
    assert_eq!(only_secrets[0].record.severity, Severity::Critical);

    let repos = store.list_repos(&RepoFilter::default()).await.unwrap();
    assert_eq!(repos[0].open_alerts.total(), 2);
    assert_eq!(repos[1].open_alerts.medium, 1);
}

pub async fn source_status_is_upserted(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    let id = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run)
        .await
        .unwrap();
    store
        .set_source_status(
            id,
            AlertSource::CodeScanning,
            run,
            t0(),
            SourceStatus::Unavailable,
            Some("no analysis"),
        )
        .await
        .unwrap();
    store
        .set_source_status(
            id,
            AlertSource::Dependabot,
            run,
            t0(),
            SourceStatus::Ok,
            None,
        )
        .await
        .unwrap();
    store
        .set_source_status(
            id,
            AlertSource::CodeScanning,
            run,
            t0() + Duration::hours(1),
            SourceStatus::Ok,
            None,
        )
        .await
        .unwrap();

    let statuses = store.source_statuses(id).await.unwrap();
    assert_eq!(statuses.len(), 2);
    let code = statuses
        .iter()
        .find(|s| s.source == AlertSource::CodeScanning)
        .unwrap();
    assert_eq!(code.status, SourceStatus::Ok);
    assert_eq!(code.message, None);
    assert_eq!(code.checked_at, t0() + Duration::hours(1));
}

macro_rules! contract_tests {
    ($backend:ident, $open:expr) => {
        mod $backend {
            use super::*;

            async fn open() -> Arc<dyn Store> {
                $open.await
            }

            #[tokio::test]
            async fn runs_round_trip() {
                super::runs_round_trip(open().await).await
            }

            #[tokio::test]
            async fn upsert_is_keyed_case_insensitively() {
                super::upsert_is_keyed_case_insensitively(open().await).await
            }

            #[tokio::test]
            async fn overview_carries_latest_snapshot() {
                super::overview_carries_latest_snapshot(open().await).await
            }

            #[tokio::test]
            async fn repo_without_snapshot_has_no_latest() {
                super::repo_without_snapshot_has_no_latest(open().await).await
            }

            #[tokio::test]
            async fn snapshots_are_append_only() {
                super::snapshots_are_append_only(open().await).await
            }

            #[tokio::test]
            async fn list_filters() {
                super::list_filters(open().await).await
            }

            #[tokio::test]
            async fn alert_lifecycle_is_audited() {
                super::alert_lifecycle_is_audited(open().await).await
            }

            #[tokio::test]
            async fn alerts_are_scoped_by_repo_and_source() {
                super::alerts_are_scoped_by_repo_and_source(open().await).await
            }

            #[tokio::test]
            async fn source_status_is_upserted() {
                super::source_status_is_upserted(open().await).await
            }
        }
    };
}

#[cfg(feature = "sqlite")]
contract_tests!(sqlite, async {
    store::connect("sqlite::memory:").await.unwrap()
});

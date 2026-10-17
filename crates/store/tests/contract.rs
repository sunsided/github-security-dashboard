//! Behavior every `Store` backend must satisfy.
//!
//! Each check is a plain async function over `Arc<dyn Store>`; the
//! `contract_tests!` macro instantiates all of them for one backend.

use chrono::{DateTime, Duration, TimeZone, Utc};
use std::sync::Arc;
use store::{RepoFilter, RepoInfo, RepoKind, RepoStats, RunStatus, Store};

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
        }
    };
}

#[cfg(feature = "sqlite")]
contract_tests!(sqlite, async {
    store::connect("sqlite::memory:").await.unwrap()
});

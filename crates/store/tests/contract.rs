//! Behavior every `Store` backend must satisfy.
//!
//! Each check is a plain async function over `Arc<dyn Store>`; the
//! `contract_tests!` macro instantiates all of them for one backend.

use assert2::check;
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::sync::Arc;
use store::{
    AlertFilter, AlertRecord, AlertSource, AlertState, DeliveryRecord, EventFilter, EventKind,
    RepoFilter, RepoInfo, RepoKind, RepoStats, RunStatus, Severity, SourceStatus, Store,
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
    check!(runs.len() == 2);
    check!(runs[0].id == second, "most recent first");
    check!(runs[0].status == RunStatus::Running);
    check!(runs[0].finished_at == None);
    check!(runs[1].status == RunStatus::Partial);
    check!(runs[1].rate_limit_remaining == Some(4321));
    check!(runs[1].errors == vec!["acme: 403".to_owned()]);
    check!(runs[1].finished_at == Some(t0() + Duration::minutes(1)));

    check!(store.list_runs(1).await.unwrap().len() == 1);
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

    check!(id1 == id2);
    let stored = store.get_repo("ACME", "WIDGET").await.unwrap().unwrap();
    check!(stored.info.archived);
    check!(stored.info.owner == "acme", "takes the latest spelling");
    check!(stored.last_seen_run == run2);
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
    check!(latest.run_id == run2);
    check!(latest.stats == stats(11));

    let history = store.snapshot_history(id, 10).await.unwrap();
    check!(history.len() == 2);
    check!(history[0].stats.open_issues == 11);
    check!(history[1].stats.open_issues == 10);
    check!(history[1].taken_at == t0());
}

pub async fn repo_without_snapshot_has_no_latest(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    store
        .upsert_repo(&repo("acme", "empty", RepoKind::Org), run)
        .await
        .unwrap();
    let overview = store.get_repo("acme", "empty").await.unwrap().unwrap();
    check!(overview.latest.is_none());
    check!(store.get_repo("acme", "missing").await.unwrap().is_none());
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
    check!(
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
    check!(names(all) == ["acme/a", "acme/b", "me/dotfiles", "rust-lang/cargo"]);

    let with_archived = store
        .list_repos(&RepoFilter {
            include_archived: true,
            ..Default::default()
        })
        .await
        .unwrap();
    check!(with_archived.len() == 5);

    let acme = store
        .list_repos(&RepoFilter {
            owner: Some("ACME".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    check!(names(acme) == ["acme/a", "acme/b"]);

    let external = store
        .list_repos(&RepoFilter {
            kind: Some(RepoKind::External),
            ..Default::default()
        })
        .await
        .unwrap();
    check!(names(external) == ["rust-lang/cargo"]);
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
            false,
        )
        .await
        .unwrap();
    check!(opened == 2);

    let overview = store.get_repo("acme", "widget").await.unwrap().unwrap();
    check!((overview.open_alerts.high, overview.open_alerts.low) == (1, 1));
    check!(overview.open_alerts.total() == 2);

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
            false,
        )
        .await
        .unwrap();
    check!(unchanged == 0);

    let run3 = store.begin_run(t0() + Duration::hours(2)).await.unwrap();
    let mut fixed = alert(2, AlertState::Fixed, Severity::Low);
    fixed.closed_at = Some(t0() + Duration::hours(2));
    let changed = store
        .record_alerts(
            repo,
            run3,
            t0() + Duration::hours(2),
            &[alert(1, AlertState::Open, Severity::Critical), fixed],
            false,
        )
        .await
        .unwrap();
    check!(changed == 2);

    let overview = store.get_repo("acme", "widget").await.unwrap().unwrap();
    check!(overview.open_alerts.critical == 1);
    check!(overview.open_alerts.total() == 1);

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
    check!(open.len() == 1);
    check!(open[0].record.severity == Severity::Critical);
    check!(open[0].first_seen_run == run1);
    check!(open[0].last_seen_run == run3);

    let all = store
        .list_alerts(repo, &AlertFilter::default())
        .await
        .unwrap();
    check!(all.len() == 2);
    check!(all[0].record.state == AlertState::Open, "open alerts first");
    check!(all[1].record.closed_at == Some(t0() + Duration::hours(2)));

    let events = store
        .alert_events(&EventFilter {
            repo: Some(repo),
            after_id: None,
            oldest_first: false,
            since: None,
            limit: 10,
            include_baseline: false,
        })
        .await
        .unwrap();
    let kinds: Vec<_> = events.iter().map(|e| (e.number, e.kind)).collect();
    check!(
        kinds
            == [
                (2, EventKind::Fixed),
                (1, EventKind::SeverityChanged),
                (2, EventKind::Opened),
                (1, EventKind::Opened),
            ]
    );
    check!(events[1].old.as_deref() == Some("high"));
    check!(
        events[3].severity == Severity::Critical,
        "events carry the alert's current severity"
    );
    check!(events[3].html_url.ends_with("/security/dependabot/1"));
    check!(events[1].new.as_deref() == Some("critical"));
    check!((events[0].owner.as_str(), events[0].repo.as_str()) == ("acme", "widget"));

    let recent = store
        .alert_events(&EventFilter {
            repo: None,
            after_id: None,
            oldest_first: false,
            since: Some(t0() + Duration::minutes(90)),
            limit: 10,
            include_baseline: false,
        })
        .await
        .unwrap();
    check!(recent.len() == 2);
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
            false,
        )
        .await
        .unwrap();
    store
        .record_alerts(
            b,
            run,
            t0(),
            &[alert(1, AlertState::Open, Severity::Medium)],
            false,
        )
        .await
        .unwrap();

    check!(
        store
            .list_alerts(a, &AlertFilter::default())
            .await
            .unwrap()
            .len()
            == 2
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
    check!(only_secrets.len() == 1);
    check!(only_secrets[0].record.severity == Severity::Critical);

    let repos = store.list_repos(&RepoFilter::default()).await.unwrap();
    check!(repos[0].open_alerts.total() == 2);
    check!(repos[1].open_alerts.medium == 1);
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
    check!(statuses.len() == 2);
    let code = statuses
        .iter()
        .find(|s| s.source == AlertSource::CodeScanning)
        .unwrap();
    check!(code.status == SourceStatus::Ok);
    check!(code.message == None);
    check!(code.checked_at == t0() + Duration::hours(1));
}

pub async fn baseline_events_are_filtered_on_request(store: Arc<dyn Store>) {
    let run1 = store.begin_run(t0()).await.unwrap();
    let repo = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run1)
        .await
        .unwrap();
    store
        .record_alerts(
            repo,
            run1,
            t0(),
            &[alert(1, AlertState::Open, Severity::High)],
            true,
        )
        .await
        .unwrap();
    let run2 = store.begin_run(t0() + Duration::hours(1)).await.unwrap();
    store
        .record_alerts(
            repo,
            run2,
            t0() + Duration::hours(1),
            &[
                alert(1, AlertState::Open, Severity::High),
                alert(2, AlertState::Open, Severity::Low),
            ],
            false,
        )
        .await
        .unwrap();

    let news = store
        .alert_events(&EventFilter {
            repo: None,
            after_id: None,
            oldest_first: false,
            since: None,
            limit: 10,
            include_baseline: false,
        })
        .await
        .unwrap();
    check!(news.len() == 1);
    check!(news[0].number == 2);
    check!(!news[0].baseline);

    let all = store
        .alert_events(&EventFilter {
            repo: Some(repo),
            after_id: None,
            oldest_first: false,
            since: None,
            limit: 10,
            include_baseline: true,
        })
        .await
        .unwrap();
    check!(all.len() == 2);
    check!(let Some(first) = all.last() && first.baseline && first.number == 1);
}

pub async fn first_collected_run_survives_failures(store: Arc<dyn Store>) {
    let run1 = store.begin_run(t0()).await.unwrap();
    let id = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run1)
        .await
        .unwrap();
    let source = AlertSource::Dependabot;
    store
        .set_source_status(
            id,
            source,
            run1,
            t0(),
            SourceStatus::Unavailable,
            Some("off"),
        )
        .await
        .unwrap();
    let first = |statuses: Vec<store::RepoSource>| statuses[0].first_collected_run;
    check!(first(store.source_statuses(id).await.unwrap()) == None);

    let run2 = store.begin_run(t0() + Duration::hours(1)).await.unwrap();
    store
        .set_source_status(id, source, run2, t0(), SourceStatus::Ok, None)
        .await
        .unwrap();
    let run3 = store.begin_run(t0() + Duration::hours(2)).await.unwrap();
    store
        .set_source_status(id, source, run3, t0(), SourceStatus::Error, Some("503"))
        .await
        .unwrap();
    let run4 = store.begin_run(t0() + Duration::hours(3)).await.unwrap();
    store
        .set_source_status(id, source, run4, t0(), SourceStatus::Ok, None)
        .await
        .unwrap();

    check!(first(store.source_statuses(id).await.unwrap()) == Some(run2));
}

pub async fn deliveries_track_a_watermark_per_target(store: Arc<dyn Store>) {
    let delivery = |target: &str, last: i64, succeeded: bool| DeliveryRecord {
        target: target.into(),
        attempted_at: t0() + Duration::hours(last),
        first_event_id: 1,
        last_event_id: last,
        events: last,
        succeeded,
        error: (!succeeded).then(|| "503".to_owned()),
    };
    check!(store.last_delivery("slack").await.unwrap() == None);

    store
        .record_delivery(&delivery("slack", 5, true))
        .await
        .unwrap();
    store
        .record_delivery(&delivery("slack", 9, false))
        .await
        .unwrap();
    store
        .record_delivery(&delivery("hook", 7, true))
        .await
        .unwrap();

    let slack = store.last_delivery("slack").await.unwrap().unwrap();
    check!(
        slack.record.last_event_id == 5,
        "failed attempts don't move the watermark"
    );
    check!(
        store
            .last_delivery("hook")
            .await
            .unwrap()
            .unwrap()
            .record
            .last_event_id
            == 7
    );

    let all = store.list_deliveries(10).await.unwrap();
    check!(all.len() == 3);
    check!(all[0].record.target == "hook", "most recent first");
    check!(all[1].record.error.as_deref() == Some("503"));
    check!(all[1].record.attempted_at == t0() + Duration::hours(9));
}

pub async fn events_can_be_read_after_an_id(store: Arc<dyn Store>) {
    let run = store.begin_run(t0()).await.unwrap();
    let repo = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run)
        .await
        .unwrap();
    for number in 1..=3 {
        store
            .record_alerts(
                repo,
                run,
                t0(),
                &[alert(number, AlertState::Open, Severity::Low)],
                false,
            )
            .await
            .unwrap();
    }
    let all = store
        .alert_events(&EventFilter {
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    check!(all.len() == 3);
    let after = store
        .alert_events(&EventFilter {
            after_id: Some(all[2].id),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    check!(after.iter().map(|e| e.number).collect::<Vec<_>>() == [3, 2]);

    // Capped and oldest first: the events right after the watermark.
    let next = store
        .alert_events(&EventFilter {
            after_id: Some(all[2].id),
            limit: 1,
            oldest_first: true,
            ..Default::default()
        })
        .await
        .unwrap();
    check!(next.iter().map(|e| e.number).collect::<Vec<_>>() == [2]);
}

/// Instantiates every contract check for one backend. `$open` receives the
/// test's name, so backends can give each test its own database, and
/// returns `None` to skip (a backend without a database to test against).
macro_rules! contract_tests {
    ($backend:ident, $open:path) => {
        contract_tests!(@tests $backend, $open, runs_round_trip, upsert_is_keyed_case_insensitively, overview_carries_latest_snapshot, repo_without_snapshot_has_no_latest, snapshots_are_append_only, list_filters, alert_lifecycle_is_audited, alerts_are_scoped_by_repo_and_source, source_status_is_upserted, baseline_events_are_filtered_on_request, first_collected_run_survives_failures, deliveries_track_a_watermark_per_target, events_can_be_read_after_an_id);
    };
    (@tests $backend:ident, $open:path, $($test:ident),+) => {
        mod $backend {
            use super::*;
            $(
                #[tokio::test]
                async fn $test() {
                    let Some(store) = $open(stringify!($test)).await else {
                        return;
                    };
                    super::$test(store).await
                }
            )+
        }
    };
}

#[cfg(feature = "sqlite")]
async fn open_sqlite(_test: &str) -> Option<Arc<dyn Store>> {
    Some(store::connect("sqlite::memory:").await.unwrap())
}

#[cfg(feature = "sqlite")]
contract_tests!(sqlite, open_sqlite);

/// PostgreSQL connection for the contract tests, from `DATABASE_URL_PG`
/// (`task test:postgres` sets it). Without it the PostgreSQL tests are
/// skipped: the server enables the `postgres` feature by default, so a
/// plain `cargo test --workspace` builds them too.
#[cfg(feature = "postgres")]
fn postgres_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL_PG")
        .ok()
        .filter(|u| !u.is_empty());
    if url.is_none() {
        eprintln!("skipped: DATABASE_URL_PG is not set (task db:up && task test:postgres)");
    }
    url
}

/// Each test gets a fresh schema of its own, recreated on every run.
#[cfg(feature = "postgres")]
async fn postgres_schema(test: &str) -> Option<String> {
    use sqlx::Connection;

    let url = postgres_url()?;
    let schema = format!("contract_{test}");
    // Test function names are plain identifiers; anything else is a bug here.
    assert2::assert!(
        schema
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "unexpected schema name {schema:?}"
    );
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for ddl in [
        format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"),
        format!("CREATE SCHEMA \"{schema}\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(ddl))
            .execute(&mut admin)
            .await
            .unwrap();
    }
    admin.close().await.unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    Some(format!(
        "{url}{separator}options=-c%20search_path%3D{schema}"
    ))
}

#[cfg(feature = "postgres")]
async fn open_postgres(test: &str) -> Option<Arc<dyn Store>> {
    let url = postgres_schema(test).await?;
    // Configured but unreachable is a failure, not a skip.
    Some(store::connect(&url).await.unwrap())
}

#[cfg(feature = "postgres")]
contract_tests!(postgres, open_postgres);

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_audit_tables_reject_changes() {
    let Some(url) = postgres_schema("audit_triggers").await else {
        return;
    };
    let store = store::connect(&url).await.unwrap();
    let run = store.begin_run(t0()).await.unwrap();
    let id = store
        .upsert_repo(&repo("acme", "widget", RepoKind::Org), run)
        .await
        .unwrap();
    store
        .insert_snapshot(id, run, t0(), &stats(1))
        .await
        .unwrap();
    store
        .record_alerts(
            id,
            run,
            t0(),
            &[alert(1, AlertState::Open, Severity::High)],
            false,
        )
        .await
        .unwrap();

    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    for sql in [
        "UPDATE alert_events SET kind = 'fixed'",
        "DELETE FROM alert_events",
        "TRUNCATE alert_events",
        "UPDATE repo_snapshots SET open_issues = 99",
        "DELETE FROM repo_snapshots",
        "TRUNCATE repo_snapshots",
    ] {
        let err = sqlx::query(sql).execute(&pool).await.unwrap_err();
        check!(err.to_string().contains("append-only"), "{sql}: {err}");
    }
}

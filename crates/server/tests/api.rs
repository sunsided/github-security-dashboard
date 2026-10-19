use assert2::check;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use collector::{Collector, CollectorConfig};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use serde_json::Value;
use server::api::AppState;
use server::config::Scoring;
use server::guard::{AllowedHosts, CSRF_HEADER};
use server::realtime::{Hub, RealtimeConfig};
use server::scheduler::Scheduler;
use std::sync::Arc;
use store::{
    AlertRecord, AlertSource, AlertState, RepoInfo, RepoKind, RepoStats, RunStatus, Severity,
};
use tower::ServiceExt;

async fn seeded_state() -> AppState {
    let store = store::connect("sqlite::memory:").await.unwrap();
    let now = Utc::now();
    let run = store.begin_run(now).await.unwrap();

    for (name, days, issues) in [("fresh", 2, 3), ("dusty", 400, 1)] {
        let info = RepoInfo {
            owner: "acme".into(),
            name: name.into(),
            kind: RepoKind::Org,
            url: format!("https://github.com/acme/{name}"),
            description: None,
            archived: false,
            fork: false,
            private: true,
            language: None,
            default_branch: Some("main".into()),
        };
        let id = store.upsert_repo(&info, run).await.unwrap();
        let stats = RepoStats {
            open_issues: issues,
            open_prs: 1,
            last_commit_at: Some(now - Duration::days(days)),
            ..RepoStats::default()
        };
        store.insert_snapshot(id, run, now, &stats).await.unwrap();
        if name == "dusty" {
            let alert = |number, severity| AlertRecord {
                source: AlertSource::Dependabot,
                number,
                state: AlertState::Open,
                severity,
                title: format!("advisory {number}"),
                location: Some("npm/lodash".into()),
                html_url: format!("https://github.com/acme/dusty/security/dependabot/{number}"),
                created_at: now,
                closed_at: None,
                estimated: false,
                advisory_ids: Vec::new(),
                ecosystem: None,
            };
            store
                .record_alerts(
                    id,
                    run,
                    now,
                    &[alert(1, Severity::Critical), alert(2, Severity::Low)],
                    false,
                )
                .await
                .unwrap();
        }
    }
    store
        .finish_run(run, now, RunStatus::Succeeded, Some(4999), &[])
        .await
        .unwrap();

    // Never contacted: the scheduler is not started in these tests.
    let github = Arc::new(
        GitHub::new(
            ClientConfig {
                api_url: "http://127.0.0.1:9".into(),
                ..ClientConfig::default()
            },
            Arc::new(PatProvider::new(Secret::new("unused"))),
        )
        .unwrap(),
    );
    let collector = Collector::new(
        Arc::clone(&github),
        Arc::clone(&store),
        CollectorConfig::default(),
    );
    let hub = Arc::new(Hub::new(
        RealtimeConfig::default(),
        b"test signing key",
        AllowedHosts::new(&[]),
    ));
    let scheduler = Arc::new(Scheduler::new(
        collector,
        std::time::Duration::from_secs(3600),
        Arc::clone(&store),
        Arc::clone(&hub),
    ));
    AppState {
        store,
        github,
        scheduler,
        scoring: Scoring::default(),
        auth: "personal access token",
        digest: None,
        realtime: hub,
    }
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = server::app(
        state,
        AllowedHosts::new(&[]),
        Arc::new(server::login::Login::none()),
    )
    .oneshot(request)
    .await
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// A same-origin request as the dashboard UI sends it.
async fn call(state: AppState, method: &str, uri: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header(CSRF_HEADER, "1")
        .body(Body::empty())
        .unwrap();
    send(state, request).await
}

#[tokio::test]
async fn lists_repositories_with_staleness() {
    let (status, body) = call(seeded_state().await, "GET", "/api/repos").await;
    check!(status == StatusCode::OK);
    let repos = body.as_array().unwrap();
    check!(repos.len() == 2);

    let dusty = &repos[0];
    check!(dusty["name"] == "dusty");
    check!(dusty["kind"] == "org");
    check!(dusty["stale"] == true);
    check!(dusty["days_since_commit"] == 400);
    check!(dusty["latest"]["open_issues"] == 1);
    check!(dusty["open_alerts"]["critical"] == 1);
    check!(dusty["risk_score"] == 11);

    check!(repos[1]["stale"] == false);
}

#[tokio::test]
async fn filters_by_kind() {
    let (status, body) = call(seeded_state().await, "GET", "/api/repos?kind=external").await;
    check!(status == StatusCode::OK);
    check!(body.as_array().unwrap().len() == 0);
}

#[tokio::test]
async fn repository_detail_and_not_found() {
    let state = seeded_state().await;
    let (status, body) = call(state.clone(), "GET", "/api/repos/ACME/fresh").await;
    check!(status == StatusCode::OK);
    check!(body["name"] == "fresh");
    check!(body["history"].as_array().unwrap().len() == 1);
    check!(body["alerts"].as_array().unwrap().len() == 0);

    let (status, _) = call(state, "GET", "/api/repos/acme/nope").await;
    check!(status == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn summary_aggregates_latest_snapshots() {
    let (status, body) = call(seeded_state().await, "GET", "/api/summary").await;
    check!(status == StatusCode::OK);
    check!(body["repos"] == 2);
    check!(body["stale_repos"] == 1);
    check!(body["open_issues"] == 4);
    check!(body["open_prs"] == 2);
    check!(body["open_alerts"]["critical"] == 1);
    check!(body["open_alerts"]["low"] == 1);
    check!(body["repos_with_alerts"] == 1);
    check!(body["collecting"] == false);
    check!(body["auth"] == "personal access token");
    check!(body["last_run"]["status"] == "succeeded");
    check!(body["last_run"]["rate_limit_remaining"] == 4999);
}

#[tokio::test]
async fn refresh_is_accepted() {
    let (status, _) = call(seeded_state().await, "POST", "/api/refresh").await;
    check!(status == StatusCode::ACCEPTED);
}

#[tokio::test]
async fn unknown_api_paths_are_404_not_spa() {
    let (status, _) = call(seeded_state().await, "GET", "/api/nope").await;
    check!(status == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_foreign_host_names() {
    // DNS rebinding: evil.example resolves to 127.0.0.1, the Host stays.
    let request = Request::builder()
        .uri("/api/repos")
        .header("host", "evil.example:8080")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(seeded_state().await, request).await;
    check!(status == StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn refresh_requires_custom_header() {
    let request = Request::builder()
        .method("POST")
        .uri("/api/refresh")
        .header("host", "127.0.0.1:8080")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(seeded_state().await, request).await;
    check!(status == StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn repository_detail_lists_alerts_and_events() {
    let (status, body) = call(seeded_state().await, "GET", "/api/repos/acme/dusty").await;
    check!(status == StatusCode::OK);
    let alerts = body["alerts"].as_array().unwrap();
    check!(alerts.len() == 2);
    check!(alerts[0]["severity"] == "critical", "most severe first");
    check!(alerts[0]["source"] == "dependabot");
    check!(body["events"].as_array().unwrap().len() == 2);
    check!(body["events"][0]["kind"] == "opened");
}

#[tokio::test]
async fn event_feed_spans_repositories() {
    // The seeded alerts are ordinary (non-baseline) events.
    let (status, body) = call(seeded_state().await, "GET", "/api/events?limit=1").await;
    check!(status == StatusCode::OK);
    let events = body.as_array().unwrap();
    check!(events.len() == 1);
    check!(events[0]["repo"] == "dusty");

    let (_, none) = call(
        seeded_state().await,
        "GET",
        "/api/events?since=2999-01-01T00:00:00Z",
    )
    .await;
    check!(none.as_array().unwrap().len() == 0);
}

#[tokio::test]
async fn repositories_missing_from_the_latest_run_are_marked_and_left_out_of_totals() {
    let state = seeded_state().await;
    // A later run sees only "fresh"; "dusty" (with its alerts) drops out.
    let later = Utc::now() + Duration::hours(1);
    let run = state.store.begin_run(later).await.unwrap();
    let fresh = state
        .store
        .get_repo("acme", "fresh")
        .await
        .unwrap()
        .unwrap();
    state.store.upsert_repo(&fresh.info, run).await.unwrap();
    state
        .store
        .finish_run(run, later, RunStatus::Succeeded, None, &[])
        .await
        .unwrap();

    let (_, repos) = call(state.clone(), "GET", "/api/repos").await;
    let refreshed = |name: &str| {
        repos
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()["refreshed"]
            .clone()
    };
    check!(refreshed("fresh") == true);
    check!(refreshed("dusty") == false);

    let (_, summary) = call(state.clone(), "GET", "/api/summary").await;
    check!(summary["repos"] == 1);
    check!(summary["not_refreshed"] == 1);
    check!(
        summary["repos_with_alerts"] == 0,
        "dusty's alerts are no longer counted"
    );
    check!(summary["open_alerts"]["critical"] == 0);

    // A run still in progress does not make anything look outdated.
    state
        .store
        .begin_run(later + Duration::hours(1))
        .await
        .unwrap();
    let (_, summary) = call(state, "GET", "/api/summary").await;
    check!(summary["not_refreshed"] == 1);
}

#[tokio::test]
async fn digest_endpoints_answer_404_when_disabled() {
    let (status, body) = call(seeded_state().await, "GET", "/api/digest/preview").await;
    check!(status == StatusCode::NOT_FOUND);
    check!(body["error"] == "digest not enabled");
}

#[tokio::test]
async fn digest_preview_shows_the_next_digest_without_sending() {
    let mut state = seeded_state().await;
    let config = daily_digest::DigestConfig {
        enabled: true,
        targets: vec![daily_digest::TargetConfig {
            name: "slack".into(),
            kind: daily_digest::TargetKind::Slack,
            url_env: "SLACK".into(),
        }],
        ..daily_digest::DigestConfig::default()
    };
    // The URL is never contacted: previews don't send.
    let service = daily_digest::DigestService::new(Arc::clone(&state.store), config, |_| {
        Some("http://127.0.0.1:9/never".into())
    })
    .unwrap();
    state.digest = Some(Arc::new(service));

    let (status, body) = call(state.clone(), "GET", "/api/digest/preview").await;
    check!(status == StatusCode::OK);
    check!(body["headline"] == "2 new alerts (1 critical)");
    check!(body["digest"]["new"][0]["repository"] == "acme/dusty");

    let (status, _) = call(state.clone(), "GET", "/api/digest/preview?target=nope").await;
    check!(status == StatusCode::NOT_FOUND);

    let (status, deliveries) = call(state, "GET", "/api/digest/deliveries").await;
    check!(status == StatusCode::OK);
    check!(
        deliveries.as_array().unwrap().is_empty(),
        "a preview records nothing"
    );
}

#[tokio::test]
async fn insights_summarize_open_alerts() {
    let (status, body) = call(seeded_state().await, "GET", "/api/insights").await;
    check!(status == StatusCode::OK);
    check!(body["by_source"][0]["key"] == "dependabot");
    check!(body["by_source"][0]["total"] == 2);
    check!(body["by_age"].as_array().unwrap().len() == 4);
    // Both seeded alerts are in one repository: nothing is widespread.
    check!(body["widespread"].as_array().unwrap().is_empty());
}

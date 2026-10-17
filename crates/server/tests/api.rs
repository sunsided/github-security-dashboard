use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use collector::{Collector, CollectorConfig};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use serde_json::Value;
use server::api::AppState;
use server::guard::{AllowedHosts, CSRF_HEADER};
use server::scheduler::Scheduler;
use std::sync::Arc;
use store::{RepoInfo, RepoKind, RepoStats, RunStatus};
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
    let scheduler = Arc::new(Scheduler::new(
        collector,
        std::time::Duration::from_secs(3600),
    ));
    AppState {
        store,
        github,
        scheduler,
    }
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = server::app(state, AllowedHosts::new(&[]))
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
    assert_eq!(status, StatusCode::OK);
    let repos = body.as_array().unwrap();
    assert_eq!(repos.len(), 2);

    let dusty = &repos[0];
    assert_eq!(dusty["name"], "dusty");
    assert_eq!(dusty["kind"], "org");
    assert_eq!(dusty["stale"], true);
    assert_eq!(dusty["days_since_commit"], 400);
    assert_eq!(dusty["latest"]["open_issues"], 1);

    assert_eq!(repos[1]["stale"], false);
}

#[tokio::test]
async fn filters_by_kind() {
    let (status, body) = call(seeded_state().await, "GET", "/api/repos?kind=external").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn repository_detail_and_not_found() {
    let state = seeded_state().await;
    let (status, body) = call(state.clone(), "GET", "/api/repos/ACME/fresh").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "fresh");
    assert_eq!(body["history"].as_array().unwrap().len(), 1);

    let (status, _) = call(state, "GET", "/api/repos/acme/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn summary_aggregates_latest_snapshots() {
    let (status, body) = call(seeded_state().await, "GET", "/api/summary").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"], 2);
    assert_eq!(body["stale_repos"], 1);
    assert_eq!(body["open_issues"], 4);
    assert_eq!(body["open_prs"], 2);
    assert_eq!(body["collecting"], false);
    assert_eq!(body["last_run"]["status"], "succeeded");
    assert_eq!(body["last_run"]["rate_limit_remaining"], 4999);
}

#[tokio::test]
async fn refresh_is_accepted() {
    let (status, _) = call(seeded_state().await, "POST", "/api/refresh").await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn unknown_api_paths_are_404_not_spa() {
    let (status, _) = call(seeded_state().await, "GET", "/api/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
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
    assert_eq!(status, StatusCode::FORBIDDEN);
}

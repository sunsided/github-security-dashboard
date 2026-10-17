use assert2::check;
use chrono::{Duration, Utc};
use daily_digest::{DigestConfig, DigestService, Outcome, TargetConfig, TargetKind};
use serde_json::Value;
use std::sync::Arc;
use store::{
    AlertRecord, AlertSource, AlertState, RepoId, RepoInfo, RepoKind, RunId, Severity, Store,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn store_with_repo() -> (Arc<dyn Store>, RepoId, RunId) {
    let store = store::connect("sqlite::memory:").await.unwrap();
    let run = store.begin_run(Utc::now()).await.unwrap();
    let info = RepoInfo {
        owner: "acme".into(),
        name: "api".into(),
        kind: RepoKind::Org,
        url: "https://github.com/acme/api".into(),
        description: None,
        archived: false,
        fork: false,
        private: true,
        language: None,
        default_branch: Some("main".into()),
    };
    let repo = store.upsert_repo(&info, run).await.unwrap();
    (store, repo, run)
}

fn alert(number: i64, severity: Severity) -> AlertRecord {
    AlertRecord {
        source: AlertSource::Dependabot,
        number,
        state: AlertState::Open,
        severity,
        title: format!("advisory {number}"),
        location: None,
        html_url: format!("https://github.com/acme/api/security/dependabot/{number}"),
        created_at: Utc::now(),
        closed_at: None,
        estimated: false,
    }
}

async fn open(
    store: &Arc<dyn Store>,
    repo: RepoId,
    run: RunId,
    number: i64,
    severity: Severity,
    baseline: bool,
) {
    store
        .record_alerts(repo, run, Utc::now(), &[alert(number, severity)], baseline)
        .await
        .unwrap();
}

fn config(server: &MockServer) -> (DigestConfig, impl Fn(&str) -> Option<String>) {
    let config = DigestConfig {
        enabled: true,
        dashboard_url: Some("https://dashboard.example".into()),
        targets: vec![
            TargetConfig {
                name: "slack".into(),
                kind: TargetKind::Slack,
                url_env: "SLACK_URL".into(),
            },
            TargetConfig {
                name: "knative".into(),
                kind: TargetKind::Json,
                url_env: "HOOK_URL".into(),
            },
        ],
        ..DigestConfig::default()
    };
    let base = server.uri();
    let env = move |name: &str| match name {
        "SLACK_URL" => Some(format!("{base}/slack")),
        "HOOK_URL" => Some(format!("{base}/hook")),
        _ => None,
    };
    (config, env)
}

fn bodies(requests: &[Request], at: &str) -> Vec<Value> {
    requests
        .iter()
        .filter(|r| r.url.path() == at)
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

#[tokio::test]
async fn delivers_cloudevents_and_keeps_a_watermark_per_target() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/slack"))
        .and(header("ce-specversion", "1.0"))
        .and(header(
            "ce-type",
            "io.github.sunsided.security-dashboard.digest.slack.v1",
        ))
        .and(header("ce-source", "/github-security-dashboard"))
        .and(header("ce-subject", "slack"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header(
            "ce-type",
            "io.github.sunsided.security-dashboard.digest.v1",
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let (store, repo, run) = store_with_repo().await;
    open(&store, repo, run, 1, Severity::Low, true).await; // first seen: not news
    open(&store, repo, run, 2, Severity::Critical, false).await;
    open(&store, repo, run, 3, Severity::High, false).await;

    let (config, env) = config(&server);
    let service = DigestService::new(Arc::clone(&store), config, env).unwrap();

    let outcomes = service.send_now(Utc::now()).await;
    check!(
        outcomes
            == [
                Outcome::Sent {
                    target: "slack".into(),
                    events: 2
                },
                Outcome::Sent {
                    target: "knative".into(),
                    events: 2
                },
            ]
    );

    let requests = server.received_requests().await.unwrap();
    let ce_id = requests[0].headers.get("ce-id").unwrap().to_str().unwrap();
    check!(
        ce_id == "slack-2-3",
        "ID derived from target and event range"
    );
    check!(requests[0].headers.contains_key("ce-time"));

    let slack = &bodies(&requests, "/slack")[0];
    check!(slack["text"] == "Security digest: 2 new alerts (1 critical)");
    let hook = &bodies(&requests, "/hook")[0];
    check!(hook["schema_version"] == 1);
    let new: Vec<_> = hook["new"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["severity"].clone())
        .collect();
    check!(new == ["critical", "high"]);
    check!(hook["dashboard_url"] == "https://dashboard.example");

    // Nothing new: nothing sent, but the round is recorded.
    let quiet = service.send_now(Utc::now()).await;
    check!(
        quiet
            == [
                Outcome::Quiet {
                    target: "slack".into()
                },
                Outcome::Quiet {
                    target: "knative".into()
                },
            ]
    );
    check!(server.received_requests().await.unwrap().len() == 2);

    // Only what happened since the last digest.
    open(&store, repo, run, 4, Severity::Medium, false).await;
    service.send_now(Utc::now()).await;
    let requests = server.received_requests().await.unwrap();
    let latest = bodies(&requests, "/hook").pop().unwrap();
    check!(latest["events"] == 1);
    check!(latest["new"][0]["title"] == "advisory 4");
}

#[tokio::test]
async fn failed_deliveries_are_repeated_with_the_same_event_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(3)
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (store, repo, run) = store_with_repo().await;
    open(&store, repo, run, 1, Severity::High, false).await;
    let (mut config, env) = config(&server);
    config.targets.retain(|t| t.name == "knative");
    let service = DigestService::new(Arc::clone(&store), config, env)
        .unwrap()
        .with_retry_backoff(std::time::Duration::ZERO);

    let first = service.send_now(Utc::now()).await;
    check!(let [Outcome::Failed { error, .. }] = first.as_slice() && error.contains("503"));
    let deliveries = store.list_deliveries(5).await.unwrap();
    check!(!deliveries[0].record.succeeded);

    let second = service.send_now(Utc::now()).await;
    check!(
        second
            == [Outcome::Sent {
                target: "knative".into(),
                events: 1
            }]
    );
    let requests = server.received_requests().await.unwrap();
    let ids: Vec<_> = requests
        .iter()
        .map(|r| r.headers.get("ce-id").unwrap().to_str().unwrap().to_owned())
        .collect();
    check!(ids.iter().all(|id| id == "knative-1-1"), "{ids:?}");
}

#[tokio::test]
async fn due_digests_respect_the_schedule() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let (store, repo, run) = store_with_repo().await;
    open(&store, repo, run, 1, Severity::High, false).await;
    let (config, env) = config(&server);
    let service = DigestService::new(Arc::clone(&store), config, env).unwrap();
    let now = Utc::now();

    // Fresh targets wait for the first slot after start-up.
    check!(
        service.send_due(now).await.is_empty(),
        "no digest just for starting"
    );
    let after_next_slot = service.slot().next(now) + Duration::minutes(1);
    check!(service.send_due(after_next_slot).await.len() == 2);
    // Done for that slot, also after a restart.
    check!(
        service
            .send_due(after_next_slot + Duration::hours(1))
            .await
            .is_empty()
    );
    // A missed slot is caught up on.
    let two_days_later = after_next_slot + Duration::days(2);
    check!(service.send_due(two_days_later).await.len() == 2);
}

#[tokio::test]
async fn missing_webhook_urls_fail_at_startup() {
    let store = store::connect("sqlite::memory:").await.unwrap();
    let config = DigestConfig {
        enabled: true,
        targets: vec![TargetConfig {
            name: "slack".into(),
            kind: TargetKind::Slack,
            url_env: "NOPE".into(),
        }],
        ..DigestConfig::default()
    };
    let err = DigestService::new(store, config, |_| None).err().unwrap();
    check!(err.contains("NOPE") && err.contains("slack"));
}

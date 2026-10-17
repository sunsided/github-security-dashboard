use assert2::check;
use collector::{Collector, CollectorConfig};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use store::{
    AlertFilter, AlertSource, AlertState, EventFilter, EventKind, RepoFilter, RunStatus, Severity,
    SourceStatus,
};
use wiremock::matchers::{body_partial_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn repo_node(owner: &str, typename: &str, name: &str, fork: bool) -> Value {
    json!({
        "name": name,
        "owner": { "login": owner, "__typename": typename },
        "url": format!("https://github.com/{owner}/{name}"),
        "description": null, "isArchived": false, "isFork": fork, "isPrivate": true,
        "primaryLanguage": null, "stargazerCount": 0, "forkCount": 0,
        "pushedAt": "2026-10-01T10:00:00Z",
        "defaultBranchRef": { "name": "main", "target": {
            "committedDate": "2026-09-30T08:00:00Z", "history": { "totalCount": 10 } } },
        "issues": { "totalCount": 0 }, "pullRequests": { "totalCount": 0 },
        "refs": { "totalCount": 0 }, "releases": { "totalCount": 0 }
    })
}

fn dependabot(repo: &str, number: i64, state: &str, severity: &str) -> Value {
    json!({
        "number": number, "state": state,
        "html_url": format!("https://github.com/{repo}/security/dependabot/{number}"),
        "created_at": "2026-09-01T00:00:00Z",
        "fixed_at": if state == "fixed" { json!("2026-10-17T09:00:00Z") } else { Value::Null },
        "dismissed_at": null, "auto_dismissed_at": null,
        "dependency": { "package": { "ecosystem": "cargo", "name": "time" }, "manifest_path": "Cargo.lock" },
        "security_advisory": { "summary": format!("advisory {number}"), "severity": severity },
        "repository": { "name": repo.split('/').nth(1).unwrap(), "owner": { "login": repo.split('/').next().unwrap() } }
    })
}

async fn mount_repos(server: &MockServer) {
    let page = |login: &str, nodes: Vec<Value>| {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_partial_json(
                json!({ "variables": { "login": login } }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "repositoryOwner": { "repositories": {
                    "pageInfo": { "hasNextPage": false, "endCursor": null }, "nodes": nodes
                }}}
            })))
    };
    page(
        "acme",
        vec![
            repo_node("acme", "Organization", "api", false),
            repo_node("acme", "Organization", "web", false),
        ],
    )
    .mount(server)
    .await;
    page(
        "me",
        vec![
            repo_node("me", "User", "app", false),
            repo_node("me", "User", "forked", true),
        ],
    )
    .mount(server)
    .await;
    Mock::given(method("GET"))
        .and(path_regex("/contributors$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

fn json_get(p: &str, body: Value) -> Mock {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
}

fn status_get(p: &str, status: u16, message: &str) -> Mock {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "message": message })))
}

fn github(server: &MockServer) -> Arc<GitHub> {
    let config = ClientConfig {
        api_url: server.uri(),
        graphql_url: format!("{}/graphql", server.uri()),
        backoff: Duration::ZERO,
        ..ClientConfig::default()
    };
    Arc::new(GitHub::new(config, Arc::new(PatProvider::new(Secret::new("t")))).unwrap())
}

#[tokio::test]
async fn tracks_alert_lifecycle_across_runs() {
    let server = MockServer::start().await;
    let store = store::connect("sqlite::memory:").await.unwrap();
    let config = CollectorConfig {
        owners: vec!["acme".into(), "me".into()],
        ..CollectorConfig::default()
    };
    let collector = Collector::new(github(&server), Arc::clone(&store), config);

    // Run 1.
    mount_repos(&server).await;
    json_get(
        "/orgs/acme/dependabot/alerts",
        json!([
            dependabot("acme/api", 1, "open", "high"),
            dependabot("acme/api", 2, "open", "low")
        ]),
    )
    .mount(&server)
    .await;
    // No security manager rights on the org: falls back to per-repo requests.
    status_get(
        "/orgs/acme/code-scanning/alerts",
        403,
        "Must have admin rights",
    )
    .mount(&server)
    .await;
    json_get(
        "/repos/acme/api/code-scanning/alerts",
        json!([{
            "number": 5, "state": "open", "html_url": "https://github.com/acme/api/security/code-scanning/5",
            "created_at": "2026-09-01T00:00:00Z", "fixed_at": null, "dismissed_at": null,
            "rule": { "id": "rust/sql-injection", "severity": "error", "security_severity_level": "critical",
                      "description": "SQL injection" },
            "most_recent_instance": { "location": { "path": "src/db.rs" } }
        }]),
    )
    .mount(&server)
    .await;
    status_get(
        "/repos/acme/web/code-scanning/alerts",
        403,
        "Code scanning is not enabled",
    )
    .mount(&server)
    .await;
    json_get("/orgs/acme/secret-scanning/alerts", json!([]))
        .mount(&server)
        .await;
    json_get(
        "/repos/me/app/dependabot/alerts",
        json!([dependabot("me/app", 9, "open", "critical")]),
    )
    .mount(&server)
    .await;
    // Everything else (me/app code and secret scanning) answers 404.

    let first = collector.run().await.unwrap();
    check!(first.status == RunStatus::Succeeded, "{:?}", first.errors);

    let repos = store.list_repos(&RepoFilter::default()).await.unwrap();
    let counts = |name: &str| {
        repos
            .iter()
            .find(|r| r.info.name == name)
            .unwrap()
            .open_alerts
    };
    check!(
        (
            counts("api").critical,
            counts("api").high,
            counts("api").low
        ) == (1, 1, 1)
    );
    check!(counts("web").total() == 0);
    check!(counts("app").critical == 1);
    check!(counts("forked").total() == 0);

    let app = store.get_repo("me", "app").await.unwrap().unwrap();
    let statuses = store.source_statuses(app.id).await.unwrap();
    let status_of = |source| statuses.iter().find(|s| s.source == source).unwrap().status;
    check!(status_of(AlertSource::Dependabot) == SourceStatus::Ok);
    check!(status_of(AlertSource::CodeScanning) == SourceStatus::Unavailable);

    let forked = store.get_repo("me", "forked").await.unwrap().unwrap();
    let skipped = store.source_statuses(forked.id).await.unwrap();
    check!(skipped.iter().all(|s| s.status == SourceStatus::Skipped));

    let web = store.get_repo("acme", "web").await.unwrap().unwrap();
    let web_status = store.source_statuses(web.id).await.unwrap();
    let code = web_status
        .iter()
        .find(|s| s.source == AlertSource::CodeScanning)
        .unwrap();
    check!(code.status == SourceStatus::Unavailable);
    check!(code.message.as_deref() == Some("Code scanning is not enabled"));

    // Run 2: alert #2 is no longer listed; GitHub says it was fixed.
    server.reset().await;
    mount_repos(&server).await;
    json_get(
        "/orgs/acme/dependabot/alerts",
        json!([dependabot("acme/api", 1, "open", "high")]),
    )
    .mount(&server)
    .await;
    json_get(
        "/repos/acme/api/dependabot/alerts/2",
        dependabot("acme/api", 2, "fixed", "low"),
    )
    .expect(1)
    .mount(&server)
    .await;
    status_get(
        "/orgs/acme/code-scanning/alerts",
        403,
        "Must have admin rights",
    )
    .mount(&server)
    .await;
    // A transient failure must not close the code scanning alert.
    status_get("/repos/acme/api/code-scanning/alerts", 500, "boom")
        .mount(&server)
        .await;
    json_get("/orgs/acme/secret-scanning/alerts", json!([]))
        .mount(&server)
        .await;
    json_get(
        "/repos/me/app/dependabot/alerts",
        json!([dependabot("me/app", 9, "open", "critical")]),
    )
    .mount(&server)
    .await;

    let second = collector.run().await.unwrap();
    check!(second.status == RunStatus::Partial);
    check!(
        second
            .errors
            .iter()
            .any(|e| e.contains("code_scanning alerts of acme/api"))
    );

    let api = store.get_repo("acme", "api").await.unwrap().unwrap();
    check!(api.open_alerts.low == 0, "fixed alert is no longer open");
    check!(
        api.open_alerts.critical == 1,
        "code scanning alert survives the failed fetch"
    );

    let fixed = store
        .list_alerts(
            api.id,
            &AlertFilter {
                source: Some(AlertSource::Dependabot),
                state: Some(AlertState::Fixed),
            },
        )
        .await
        .unwrap();
    check!(fixed.len() == 1);
    check!(fixed[0].record.number == 2);
    check!(fixed[0].record.closed_at.is_some());

    let events = store
        .alert_events(&EventFilter {
            repo: Some(api.id),
            after_id: None,
            since: None,
            limit: 10,
            include_baseline: true,
        })
        .await
        .unwrap();
    check!(events[0].kind == EventKind::Fixed);
    check!(events[0].number == 2);
    check!(!events[0].baseline, "a fix in a later run is news");
    check!(
        events
            .iter()
            .filter(|e| e.kind == EventKind::Opened)
            .all(|e| e.baseline),
        "alerts found on the first read are baseline"
    );
    check!(
        events
            .iter()
            .filter(|e| e.kind == EventKind::Opened)
            .count()
            == 3
    );

    let code = store
        .list_alerts(
            api.id,
            &AlertFilter {
                source: Some(AlertSource::CodeScanning),
                state: None,
            },
        )
        .await
        .unwrap();
    check!(code[0].record.severity == Severity::Critical);
    check!(code[0].record.location.as_deref() == Some("rust/sql-injection in src/db.rs"));
}

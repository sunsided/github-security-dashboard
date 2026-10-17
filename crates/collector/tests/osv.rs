use assert2::check;
use collector::{Collector, CollectorConfig, OsvConfig, RepoRef};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::{
    AlertFilter, AlertSource, AlertState, EventFilter, EventKind, RunStatus, Severity, SourceStatus,
};
use wiremock::matchers::{body_partial_json, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn repo_node() -> Value {
    json!({
        "name": "lib", "owner": { "login": "acme", "__typename": "Organization" },
        "url": "https://github.com/acme/lib", "description": null,
        "isArchived": false, "isFork": false, "isPrivate": false, "primaryLanguage": null,
        "stargazerCount": 0, "forkCount": 0, "pushedAt": "2026-10-01T10:00:00Z",
        "defaultBranchRef": { "name": "main", "target": {
            "committedDate": "2026-09-30T08:00:00Z", "history": { "totalCount": 1 } } },
        "issues": { "totalCount": 0 }, "pullRequests": { "totalCount": 0 },
        "refs": { "totalCount": 0 }, "releases": { "totalCount": 0 }
    })
}

fn sbom(purls: &[&str]) -> Value {
    let packages: Vec<Value> = purls
        .iter()
        .map(|p| json!({ "externalRefs": [{ "referenceType": "purl", "referenceLocator": p }] }))
        .collect();
    json!({ "sbom": { "packages": packages } })
}

/// OSV querybatch: lodash below 4.17.21 is affected by GHSA-test-0001.
struct Osv {
    queried: Mutex<Vec<String>>,
}

impl Respond for Osv {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let results: Vec<Value> = body["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                let purl = q["package"]["purl"].as_str().unwrap().to_owned();
                self.queried.lock().unwrap().push(purl.clone());
                if purl.starts_with("pkg:npm/lodash@4.17.1") || purl == "pkg:npm/lodash@4.17.20" {
                    json!({ "vulns": [{ "id": "GHSA-test-0001", "modified": "2026-01-01T00:00:00Z" }] })
                } else {
                    json!({})
                }
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "results": results }))
    }
}

/// `advisory_fetches`: how often the advisory details may be requested.
async fn mount_github(server: &MockServer, purls: &[&str], advisory_fetches: u64) {
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(
            json!({ "variables": { "owner": "acme", "name": "lib" } }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": { "repository": repo_node() } })),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/contributors$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/lib/dependency-graph/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sbom(purls)))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-test-0001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "GHSA-test-0001",
            "summary": "Prototype pollution in lodash",
            "published": "2025-05-01T00:00:00Z",
            "database_specific": { "severity": "HIGH" },
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
        })))
        .expect(advisory_fetches)
        .mount(server)
        .await;
    // External repository: no access to its alerts.
    Mock::given(method("GET"))
        .and(path_regex(
            "/repos/acme/lib/(dependabot|code-scanning|secret-scanning)/alerts$",
        ))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "message": "Must have admin rights" })),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn external_repositories_get_estimated_alerts() {
    let server = MockServer::start().await;
    let osv = Arc::new(Osv {
        queried: Mutex::default(),
    });
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ArcResponder(Arc::clone(&osv)))
        .mount(&server)
        .await;
    mount_github(
        &server,
        &[
            "pkg:npm/lodash@4.17.20",
            "pkg:npm/lodash@4.17.19",
            "pkg:npm/vite@catalog:",
            "pkg:cargo/safe@1.0.0",
            "pkg:github/acme/lib@main",
        ],
        1,
    )
    .await;

    let store = store::connect("sqlite::memory:").await.unwrap();
    let config = CollectorConfig {
        external_repos: vec![RepoRef::try_from("acme/lib".to_owned()).unwrap()],
        osv: OsvConfig {
            api_url: server.uri(),
            ..OsvConfig::default()
        },
        ..CollectorConfig::default()
    };
    let github = Arc::new(
        GitHub::new(
            ClientConfig {
                api_url: server.uri(),
                graphql_url: format!("{}/graphql", server.uri()),
                backoff: Duration::ZERO,
                ..ClientConfig::default()
            },
            Arc::new(PatProvider::new(Secret::new("t"))),
        )
        .unwrap(),
    );
    let collector = Collector::new(github, Arc::clone(&store), config);

    let first = collector.run().await.unwrap();
    check!(first.status == RunStatus::Succeeded, "{:?}", first.errors);
    check!(
        *osv.queried.lock().unwrap()
            == [
                "pkg:npm/lodash@4.17.20",
                "pkg:npm/lodash@4.17.19",
                "pkg:cargo/safe@1.0.0"
            ],
        "unresolved versions and the repository itself are not queried"
    );

    let repo = store.get_repo("acme", "lib").await.unwrap().unwrap();
    check!(repo.open_alerts.high == 1);
    let alerts = store
        .list_alerts(
            repo.id,
            &AlertFilter {
                source: Some(AlertSource::Osv),
                state: None,
            },
        )
        .await
        .unwrap();
    check!(
        alerts.len() == 1,
        "two affected versions of one package are one alert"
    );
    let alert = &alerts[0].record;
    check!(alert.estimated);
    check!(
        alert.severity == Severity::High,
        "GitHub's label wins over the CVSS score"
    );
    check!(alert.title == "GHSA-test-0001: Prototype pollution in lodash");
    check!(alert.html_url == "https://osv.dev/vulnerability/GHSA-test-0001");
    check!(let Some(location) = &alert.location && location.contains("4.17.20") && location.contains("4.17.19"));

    let statuses = store.source_statuses(repo.id).await.unwrap();
    let status = |source| statuses.iter().find(|s| s.source == source).unwrap();
    check!(status(AlertSource::Dependabot).status == SourceStatus::Unavailable);
    check!(status(AlertSource::Osv).status == SourceStatus::Ok);
    check!(
        status(AlertSource::Osv).message.as_deref()
            == Some("3 dependencies checked, 2 without an exact version skipped")
    );

    // Run 2: lodash was updated to a fixed version.
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ArcResponder(Arc::clone(&osv)))
        .mount(&server)
        .await;
    // Nothing affected any more, and the advisory would be cached anyway.
    mount_github(
        &server,
        &["pkg:npm/lodash@4.17.21", "pkg:cargo/safe@1.0.0"],
        0,
    )
    .await;

    let second = collector.run().await.unwrap();
    check!(second.status == RunStatus::Succeeded, "{:?}", second.errors);
    let repo = store.get_repo("acme", "lib").await.unwrap().unwrap();
    check!(repo.open_alerts.total() == 0);
    let events = store
        .alert_events(&EventFilter {
            repo: Some(repo.id),
            after_id: None,
            oldest_first: false,
            since: None,
            limit: 10,
            include_baseline: true,
        })
        .await
        .unwrap();
    check!(events[0].kind == EventKind::Fixed);
    check!(!events[0].baseline);
    check!(events[1].kind == EventKind::Opened);
    check!(
        events[1].baseline,
        "estimates found on the first look are baseline"
    );
    let fixed = store
        .list_alerts(
            repo.id,
            &AlertFilter {
                source: Some(AlertSource::Osv),
                state: Some(AlertState::Fixed),
            },
        )
        .await
        .unwrap();
    check!(fixed.len() == 1);
}

/// wiremock wants an owned responder; share the recording one.
struct ArcResponder(Arc<Osv>);

impl Respond for ArcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.0.respond(request)
    }
}
